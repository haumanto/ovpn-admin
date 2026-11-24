package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

// Auth hardening of the panel.
//
//   - validateNoAuthConfig: the panel does not start without credentials unless --insecure-no-auth says so.
//   - authGuard: failed logins are counted per source address AND user name (the lock key is
//     "address|hash of the user name"); a pair that reaches --auth.max-failures within --auth.fail-window is
//     locked (429 + Retry-After) for 15 min, 1 h, 4 h, 24 h for repeat offences within 24 h. Failures against
//     one account never lock another account from the same address. The lock is checked before the
//     credentials are compared. A correct login clears that pair. The state survives a restart
//     (OVPN_STATE_DIR/auth-throttle.json, 0600, replaced atomically). /ping is exempt; the metrics path is
//     counted like every other path. A source inside --admin.allow-cidr is trusted: never locked, never
//     counted. More than authFloodSources distinct sources failing within the window is reported once
//     (CRITICAL log line + one Telegram line); it never locks the account.
//   - adminAllowlistMiddleware: --admin.allow-cidr, checked before authentication.
//
// The source address is the direct peer address; with --admin.trust-proxy it is the last X-Forwarded-For
// value instead (behind a reverse proxy, or a published Docker port, the peer is the proxy or the bridge
// gateway, and one attacker would otherwise lock out everybody who comes in through it). Both the lock and
// the allowlist use the same address. The user name is stored only as a short hash: what was typed in the
// user name field (it may be a password) never reaches the state file.

const (
	authThrottleFileName   = "auth-throttle.json"
	authThrottleDefaultDir = "/var/lib/ovpn-admin/state"
	authRepeatWindow       = 24 * time.Hour // offences within this long of the previous lock are repeat offences
	authFloodSources       = 20             // "more than" this many distinct failing sources is reported
	authFloodListMax       = 40             // addresses named in the one Telegram line (then "and N more")
	authMaxSources         = 4096           // entries kept; the oldest go first
	authSaveWarnEvery      = time.Minute

	auditActLoginLocked   = "auth.login.locked"
	auditActAllowlistDeny = "admin.allowlist.deny"
	auditActRehash        = "auth.rehash"

	// rehashNoticePrefix starts the line that openvpn-user prints after it replaced an old hash.
	rehashNoticePrefix = "openvpn-user: rehash "
)

var authLockSteps = []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, 24 * time.Hour}

var (
	insecureNoAuth  = kingpin.Flag("insecure-no-auth", "start the panel although --basic.username and --basic.password are both empty: the panel is then open to everyone who can reach it. Without this flag the panel refuses to start without credentials").Default("false").Envar("OVPN_INSECURE_NO_AUTH").Bool()
	authMaxFailures = kingpin.Flag("auth.max-failures", "failed Basic Auth logins from one source address within --auth.fail-window that lock that address (429 with Retry-After; 15 min, 1 h, 4 h, 24 h for repeat offences within 24 h); the lock is kept in OVPN_STATE_DIR/auth-throttle.json").Default("5").Envar("OVPN_AUTH_MAX_FAILURES").Int()
	authFailWindow  = kingpin.Flag("auth.fail-window", "window in which --auth.max-failures failed logins from one source address lock it").Default("15m").Envar("OVPN_AUTH_FAIL_WINDOW").Duration()
	adminAllowCIDR  = kingpin.Flag("admin.allow-cidr", "source network that may reach the panel (IPv4 or IPv6 CIDR); repeatable, env OVPN_ADMIN_ALLOW_CIDR is comma separated. Other sources get 403 before authentication, /ping and the metrics path included. Empty = no restriction").Envar("OVPN_ADMIN_ALLOW_CIDR").Strings()
	adminTrustProxy = kingpin.Flag("admin.trust-proxy", "take the source address from the last value of the X-Forwarded-For header instead of the peer address, for the allowlist and the login lock. Only behind a reverse proxy that sets the header; otherwise any client could name its own address").Default("false").Envar("OVPN_ADMIN_TRUST_PROXY").Bool()
)

// validateNoAuthConfig refuses a panel without credentials unless the operator asked for it by name.
func validateNoAuthConfig(username, password string, insecure bool) error {
	if username == "" && password == "" && !insecure {
		return errors.New("--basic.username and --basic.password are both empty: the panel would be open to everyone who can reach it " +
			"(they could create, revoke and delete VPN users and download client configurations). " +
			"Set both (BASIC_USERNAME and BASIC_PASSWORD), or pass --insecure-no-auth (OVPN_INSECURE_NO_AUTH=true) to run it open on purpose")
	}
	return nil
}

// authConfig is what the flags say, parsed and checked. It performs no I/O.
type authConfig struct {
	maxFailures int
	window      time.Duration
	allow       []netip.Prefix
	trustProxy  bool
}

func parseAuthConfig(maxFailures int, window time.Duration, cidrs []string, trustProxy bool) (authConfig, error) {
	if maxFailures < 1 {
		return authConfig{}, errors.New("--auth.max-failures must be at least 1")
	}
	if window <= 0 {
		return authConfig{}, errors.New("--auth.fail-window must be longer than zero")
	}
	allow, err := parseAllowCIDRs(cidrs)
	if err != nil {
		return authConfig{}, err
	}
	return authConfig{maxFailures: maxFailures, window: window, allow: allow, trustProxy: trustProxy}, nil
}

// parseAllowCIDRs reads the values of --admin.allow-cidr; each value may hold several comma separated CIDRs
// (the environment variable does). An unparsable entry is an error naming it: a typo must not silently widen
// or narrow the list.
func parseAllowCIDRs(values []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("--admin.allow-cidr: %q is not a CIDR such as 192.0.2.0/24 or 2001:db8::/32", part)
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

// ---- the source address ----

// peerAddr is the address of the TCP peer.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return parseAddrLoose(host)
}

// parseAddrLoose reads an address with or without port, brackets or zone; an IPv4 address in IPv6 notation
// is returned as IPv4, so that it matches an IPv4 prefix.
func parseAddrLoose(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.WithZone("").Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone("").Unmap(), true
	}
	if t := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"); t != s {
		if a, err := netip.ParseAddr(t); err == nil {
			return a.WithZone("").Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// clientAddr is the address the allowlist and the lock go by. Without trustProxy it is the peer and the
// X-Forwarded-For header is not read at all. With it, it is the last value of the header (the one the
// nearest proxy appended); no header means the request did not come through the proxy, so the peer. A last
// value that is not an address gives ok == false: the allowlist refuses it.
func clientAddr(r *http.Request, trustProxy bool) (netip.Addr, bool) {
	if trustProxy {
		if vals := r.Header.Values("X-Forwarded-For"); len(vals) > 0 {
			last := vals[len(vals)-1]
			if i := strings.LastIndex(last, ","); i >= 0 {
				last = last[i+1:]
			}
			return parseAddrLoose(last)
		}
	}
	return peerAddr(r)
}

// ---- allowlist ----

// adminAllowlistMiddleware answers 403 without any detail to a source outside allow, before anything else
// looks at the request. An empty list is no restriction and returns next unchanged.
func adminAllowlistMiddleware(next http.Handler, allow []netip.Prefix, trustProxy bool) http.Handler {
	if len(allow) == 0 {
		return next
	}
	var seen adminLoginThrottle
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr, ok := clientAddr(r, trustProxy)
		if ok && slices.ContainsFunc(allow, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			next.ServeHTTP(w, r)
			return
		}
		shown := auditSource(r)
		if ok {
			shown = addr.String()
		}
		recordAuthRefusal(&seen, auditActAllowlistDeny, "", shown,
			"source outside --admin.allow-cidr: "+r.Method+" "+truncateRunes(r.URL.Path, 80))
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// recordAuthRefusal writes a refusal to the admin audit trail, once per source per throttle window (a flood of
// refused requests is one event in substance); the next line says how many were left out. No credentials
// are ever passed in.
func recordAuthRefusal(th *adminLoginThrottle, action, user, src, detail string) {
	if adminAudit == nil {
		return
	}
	rec, skipped := th.shouldRecordFail(src, adminAudit.now())
	if !rec {
		return
	}
	if skipped > 0 {
		detail = fmt.Sprintf("%s; %d more from this source in the last %s not recorded", detail, skipped, adminAuditLoginFailWindow)
	}
	_ = adminAudit.loginEvent(action, user, src, adminAuditResultFail, detail)
}

// ---- failure throttle ----

// throttleEntry is what is known about one source. Times are Unix seconds.
type throttleEntry struct {
	Fails       []int64 `json:"fails,omitempty"` // failures inside the window, oldest first
	LastFail    int64   `json:"last_fail"`
	Strikes     int     `json:"strikes"`      // locks within the repeat window, 0..len(steps)
	LastLock    int64   `json:"last_lock"`    // start of the newest lock
	LockedUntil int64   `json:"locked_until"` // 0 = not locked
}

type throttleFile struct {
	Version int                       `json:"version"`
	Sources map[string]*throttleEntry `json:"sources"`
}

type authGuard struct {
	mu          sync.Mutex
	now         func() time.Time
	maxFailures int
	window      time.Duration
	steps       []time.Duration
	path        string // "" = memory only
	entries     map[string]*throttleEntry
	floodActive bool
	lastSaveLog time.Time

	// alert is called (outside the lock) once when more than authFloodSources distinct sources fail within
	// the window. Tests replace it.
	alert func(window time.Duration, addrs []string)

	lockedSeen adminLoginThrottle // audit throttle of the 429 lines
}

func newAuthGuard(cfg authConfig, stateDir string) *authGuard {
	if stateDir == "" {
		stateDir = authThrottleDefaultDir
	}
	return &authGuard{
		now:         time.Now,
		maxFailures: cfg.maxFailures,
		window:      cfg.window,
		steps:       authLockSteps,
		path:        filepath.Join(stateDir, authThrottleFileName),
		entries:     map[string]*throttleEntry{},
		alert:       sendFloodAlert,
	}
}

// authStateDirFromFlags is OVPN_STATE_DIR, or the default of the compose layout.
func authStateDirFromFlags() string {
	if *stateDir != "" {
		return filepath.Clean(*stateDir)
	}
	return authThrottleDefaultDir
}

// load reads the state of an earlier run. A missing file is a first start. A file that cannot be read or
// parsed is moved aside (so that the evidence stays) and the guard starts empty: the owner must not be
// locked out of the panel by a damaged file, and nobody but the panel's own user can write it.
func (g *authGuard) load() error {
	if g.path == "" {
		return nil
	}
	f, err := os.OpenFile(g.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var tf throttleFile
	if err == nil {
		err = json.NewDecoder(&limitedFile{f: f, left: 8 << 20}).Decode(&tf)
		_ = f.Close()
	}
	if err != nil || tf.Version != 1 {
		aside := g.path + ".corrupt-" + strconv.FormatInt(g.now().Unix(), 10)
		_ = os.Rename(g.path, aside)
		if err == nil {
			err = fmt.Errorf("unknown version %d", tf.Version)
		}
		return fmt.Errorf("%s was not usable (%v), moved aside to %s, the failure counters start empty", g.path, err, aside)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().Unix()
	for src, e := range tf.Sources {
		if e == nil || !validSourceKey(src) || e.Strikes < 0 || e.Strikes > len(g.steps) {
			continue
		}
		if g.expiredLocked(e, now) {
			continue
		}
		g.entries[src] = e
	}
	return nil
}

type limitedFile struct {
	f    *os.File
	left int64
}

func (l *limitedFile) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("file too large")
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.f.Read(p)
	l.left -= int64(n)
	return n, err
}

// lockKey is the key of one (source, account) pair: "<address>|<first 16 hex of sha256(user name)>".
func lockKey(src, user string) string {
	sum := sha256.Sum256([]byte(user))
	return src + "|" + hex.EncodeToString(sum[:8])
}

// keySource is the address part of a lock key.
func keySource(key string) string {
	src, _, _ := strings.Cut(key, "|")
	return src
}

// validSourceKey accepts the keys lockKey makes. An entry of the earlier format (the bare address) is not
// valid: it belonged to the lock that covered everybody behind one address, and is dropped at load.
func validSourceKey(s string) bool {
	src, h, ok := strings.Cut(s, "|")
	if !ok || len(h) != 16 {
		return false
	}
	if _, err := hex.DecodeString(h); err != nil {
		return false
	}
	if src == "unknown" {
		return true
	}
	_, err := netip.ParseAddr(src)
	return err == nil
}

// expiredLocked: nothing in e matters any more.
func (g *authGuard) expiredLocked(e *throttleEntry, now int64) bool {
	if e.LockedUntil > now {
		return false
	}
	if len(e.Fails) > 0 && now-e.LastFail < int64(g.window/time.Second) {
		return false
	}
	return e.LastLock == 0 || now-e.LastLock >= int64(authRepeatWindow/time.Second)
}

// save replaces the state file atomically (0600, temporary file in the same directory, fsync, rename). Called
// with g.mu held. A failure is logged (at most once a minute) and never changes an answer: the counters stay
// in memory.
func (g *authGuard) saveLocked() {
	if g.path == "" {
		return
	}
	if err := g.writeFileLocked(); err != nil {
		if now := g.now(); now.Sub(g.lastSaveLog) >= authSaveWarnEvery {
			g.lastSaveLog = now
			log.Warnf("auth throttle: the state cannot be saved to %s, a restart forgets the failure counters: %v", g.path, err)
		}
	}
}

func (g *authGuard) writeFileLocked() error {
	tf := throttleFile{Version: 1, Sources: g.entries}
	data, err := json.Marshal(tf)
	if err != nil {
		return err
	}
	dir := filepath.Dir(g.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+authThrottleFileName+".tmp-*") // created 0600
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, g.path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// buildAuthChain is the part of the handler chain that decides who gets to the application, outermost first:
// the source allowlist (403 before anything else), the login lock (429 before the credentials are compared;
// pingPath and metricsPath exempt), Basic Auth. guard is nil when no credentials are configured.
func buildAuthChain(app http.Handler, username, password string, guard *authGuard, cfg authConfig, pingPath, metricsPath string) http.Handler {
	authed := basicAuthMiddleware(app, username, password, pingPath)
	if guard != nil {
		authed = guard.middleware(authed, cfg.trustProxy, cfg.allow, pingPath, metricsPath)
	}
	return adminAllowlistMiddleware(authed, cfg.allow, cfg.trustProxy)
}

// flush writes the state once (at start: it shows whether the file can be written).
func (g *authGuard) flush() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.saveLocked()
}

// check says whether src is locked and for how long. It is the first thing a request meets, before the
// credentials are looked at.
func (g *authGuard) check(src string) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[src]
	if e == nil {
		return false, 0
	}
	if wait := time.Unix(e.LockedUntil, 0).Sub(g.now()); e.LockedUntil != 0 && wait > 0 {
		return true, wait
	}
	return false, 0
}

type lockResult struct {
	locked  bool
	dur     time.Duration
	strikes int
}

// fail counts one failed login of src. It returns the lock this failure caused, if any.
func (g *authGuard) fail(src string) lockResult {
	var alertAddrs []string
	var res lockResult

	g.mu.Lock()
	now := g.now()
	nowU := now.Unix()
	e := g.entries[src]
	if e == nil {
		g.makeRoomLocked(nowU)
		e = &throttleEntry{}
		g.entries[src] = e
	}
	if e.LockedUntil > nowU {
		// a request that was already past the lock check when the lock was set: no second count
		g.mu.Unlock()
		return lockResult{}
	}
	windowS := int64(g.window / time.Second)
	if windowS < 1 {
		windowS = 1
	}
	kept := e.Fails[:0]
	for _, t := range e.Fails {
		if nowU-t < windowS {
			kept = append(kept, t)
		}
	}
	e.Fails = append(kept, nowU)
	e.LastFail = nowU
	if len(e.Fails) >= g.maxFailures {
		if e.LastLock != 0 && nowU-e.LastLock >= int64(authRepeatWindow/time.Second) {
			e.Strikes = 0
		}
		if e.Strikes < len(g.steps) {
			e.Strikes++
		}
		res = lockResult{locked: true, dur: g.steps[e.Strikes-1], strikes: e.Strikes}
		e.LockedUntil = nowU + int64(res.dur/time.Second)
		e.LastLock = nowU
		e.Fails = nil
	}
	alertAddrs = g.floodCheckLocked(nowU, windowS)
	g.saveLocked()
	g.mu.Unlock()

	if alertAddrs != nil && g.alert != nil {
		g.alert(g.window, alertAddrs)
	}
	return res
}

// floodCheckLocked returns the addresses once when more than authFloodSources distinct sources have failed
// within the window, and nil otherwise; it re-arms when the number is back under the limit.
func (g *authGuard) floodCheckLocked(nowU, windowS int64) []string {
	seen := map[string]bool{}
	var addrs []string
	for key, e := range g.entries {
		if e.LastFail != 0 && nowU-e.LastFail < windowS {
			if src := keySource(key); !seen[src] {
				seen[src] = true
				addrs = append(addrs, src)
			}
		}
	}
	if len(addrs) <= authFloodSources {
		g.floodActive = false
		return nil
	}
	if g.floodActive {
		return nil
	}
	g.floodActive = true
	sort.Strings(addrs)
	return addrs
}

// makeRoomLocked drops what no longer matters and, when the table is still full, the entry that failed longest ago.
func (g *authGuard) makeRoomLocked(nowU int64) {
	if len(g.entries) < authMaxSources {
		return
	}
	for src, e := range g.entries {
		if g.expiredLocked(e, nowU) {
			delete(g.entries, src)
		}
	}
	for len(g.entries) >= authMaxSources {
		var oldest string
		var oldestT int64 = 1<<63 - 1
		for src, e := range g.entries {
			if e.LastFail < oldestT {
				oldest, oldestT = src, e.LastFail
			}
		}
		delete(g.entries, oldest)
	}
}

// succeeded clears everything known about src: a correct login ends the failure count and the repeat history.
func (g *authGuard) succeeded(src string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.entries[src]; !ok {
		return
	}
	delete(g.entries, src)
	g.saveLocked()
}

// failureCount is the number of failures inside the window that count towards the next lock (tests, metrics).
func (g *authGuard) failureCount(src string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e := g.entries[src]; e != nil {
		return len(e.Fails)
	}
	return 0
}

// sourceKey is the address of a request: the address of clientAddr, or the peer text when the address is not one.
func (g *authGuard) sourceKey(r *http.Request, trustProxy bool) string {
	if a, ok := clientAddr(r, trustProxy); ok {
		return a.String()
	}
	if a, ok := peerAddr(r); ok {
		return a.String()
	}
	return "unknown"
}

type authAttemptKey struct{}

// authAttempt travels in the context of a request that is subject to the lock; basicAuthMiddleware reports
// the outcome of the credential comparison to it. key is the (source, account) pair, src the address alone
// (for the log).
type authAttempt struct {
	g   *authGuard
	key string
	src string
}

func authAttemptFrom(r *http.Request) *authAttempt {
	at, _ := r.Context().Value(authAttemptKey{}).(*authAttempt)
	return at
}

// failed is called for an attempt that sent credentials and was refused.
func (at *authAttempt) failed(r *http.Request, user string) {
	if at == nil {
		return
	}
	res := at.g.fail(at.key)
	if res.locked {
		log.Warnf("auth locked remote=%s for %s after %d failed logins (lock number %d within 24h)", at.src, res.dur, at.g.maxFailures, res.strikes)
		if adminAudit != nil {
			_ = adminAudit.loginEvent(auditActLoginLocked, user, at.src, adminAuditResultFail,
				fmt.Sprintf("source locked for %s after %d failed logins within %s (lock %d within 24h)", res.dur, at.g.maxFailures, at.g.window, res.strikes))
		}
	}
}

func (at *authAttempt) succeeded() {
	if at != nil {
		at.g.succeeded(at.key)
	}
}

// middleware answers 429 to a locked (source, account) pair before anything else looks at the request, and
// hands the outcome of the credential comparison to the guard. Requests for the exempt paths (/ping) pass
// untouched and are not counted; so do requests from a source inside allow (trusted: never locked, never
// counted).
func (g *authGuard) middleware(next http.Handler, trustProxy bool, allow []netip.Prefix, exempt ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(exempt, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if addr, ok := clientAddr(r, trustProxy); ok && slices.ContainsFunc(allow, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			next.ServeHTTP(w, r)
			return
		}
		src := g.sourceKey(r, trustProxy)
		user, _, _ := r.BasicAuth()
		key := lockKey(src, user)
		if locked, wait := g.check(key); locked {
			secs := int((wait + time.Second - 1) / time.Second)
			if secs < 1 {
				secs = 1
			}
			recordAuthRefusal(&g.lockedSeen, auditActLoginLocked, user, src,
				fmt.Sprintf("request refused, source is locked for another %ds", secs))
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, "Too many failed logins for this account from this address. Try again in %s.\n", waitText(secs))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authAttemptKey{}, &authAttempt{g: g, key: key, src: src})))
	})
}

// waitText says how long a lock lasts, rounded up to whole minutes and carried into the hours, so that the
// sentence never reads "3 hours 60 minutes" (14395 s is 4 hours 0 minutes).
func waitText(secs int) string {
	if secs < 60 {
		return plural(secs, "second")
	}
	mins := (secs + 59) / 60
	if mins < 60 {
		return plural(mins, "minute")
	}
	return plural(mins/60, "hour") + " " + plural(mins%60, "minute")
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// ---- flood alert ----

// floodAlertText is the one Telegram line. Counts and addresses are allowed in it (owner decision of 2026-11-23);
// no user name that was tried, no password.
func floodAlertText(window time.Duration, addrs []string) string {
	shown := addrs
	more := 0
	if len(shown) > authFloodListMax {
		more = len(shown) - authFloodListMax
		shown = shown[:authFloodListMax]
	}
	list := strings.Join(shown, ", ")
	if more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	return fmt.Sprintf("ovpn-admin: failed panel logins from %d distinct sources within %s, the account is not locked: %s", len(addrs), window, list)
}

var floodTelegramTimeout = 15 * time.Second

// sendFloodAlert logs CRITICAL and sends the Telegram line, when Telegram is configured. It does not block the request.
func sendFloodAlert(window time.Duration, addrs []string) {
	text := floodAlertText(window, addrs)
	log.Errorf("CRITICAL: %s", text)
	cfg, why := telegramConfigFromEnv()
	if !cfg.enabled {
		log.Warnf("auth throttle: no Telegram line sent: %s", why)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), floodTelegramTimeout)
		defer cancel()
		if err := telegramSend(ctx, cfg, text); err != nil {
			log.Errorf("auth throttle: the Telegram line was not sent: %v", err)
		}
	}()
}

// ---- openvpn-user rehash notice ----

// auditRehashNotice writes the audit line for a re-hash that openvpn-user reported on its output. The user
// is the one the panel asked about, never a name read from the output; nothing but the costs is taken from it.
func auditRehashNotice(user, output string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, rehashNoticePrefix) {
			continue
		}
		detail := "password hash re-made at bcrypt cost 12"
		if from, ok := strings.CutPrefix(line, rehashNoticePrefix+"cost "); ok {
			if i := strings.Index(from, " "); i > 0 {
				if _, err := strconv.Atoi(from[:i]); err == nil {
					detail = "password hash re-made at bcrypt cost 12, was cost " + from[:i]
				}
			}
		}
		_ = adminAudit.system(auditActRehash, user, true, detail)
		return
	}
}
