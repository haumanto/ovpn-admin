package main

// Self-test: proves, on the running box, that the protections of v0.1.11 and v0.1.12 are in place, so that a later change
// which silently undoes one of them turns this red. Three ways to run it, one set of checks:
//
//	ovpn-admin --selftest      every check, one line each, a verdict, exit 0 (no FAIL; WARN is allowed), 1 (a FAIL), 2 (internal error).
//	                           Run it with the environment of the panel: docker compose exec ovpn-admin /app/ovpn-admin --selftest
//	GET /api/selftest          the same checks as JSON, for an authenticated admin only (403 otherwise, like /api/audit/verify)
//	scheduled                  10 minutes after the start and every 24 hours, unless OVPN_SELFTEST_ENABLED=false; on a FAIL one
//	                           Telegram message (check names and details) and an error line in the log
//
// The checks, in this order (each one independent: a failure never hides another):
//
//	admin_fence      iptables -C INPUT -i tun+ -p tcp --dport PANEL_PORT -j DROP (and ip6tables with IPv6 on)
//	ban_jail         the ban chain and its INPUT jump in iptables -S (OVPN_BAN, and OVPN_BAN6 with IPv6 on); bans.tsv readable
//	crl_age          nextUpdate of pki/crl.pem
//	cert_expiry      every client certificate, the server certificate and the CA (the scan of the expiry notices)
//	key_modes        ca.key and server.key 0600 and root-owned; index.txt not world readable (FAIL); users.db: WARN when world
//	                 readable (measured: openvpn-user creates it 0644 and the login hook, user nobody, reads it), FAIL when world writable
//	credentials      BASIC_USERNAME and BASIC_PASSWORD both set
//	control_channel  the newest "Control Channel:" line of the OpenVPN log names TLS 1.2 or 1.3
//	audit_chain      the hash chain of the admin audit trail
//	sync             no sync token, or a token with plain HTTP refused
//	versions         the panel, OpenVPN and easy-rsa versions
//	pki_readable     index.txt parses, users.db opens read-only
//
// Reading the firewall needs CAP_NET_ADMIN in the container that runs the checks; without it iptables answers "Permission
// denied" and the two firewall checks are WARN ("cannot read"), never PASS and never a false FAIL: a rule that is not
// there is FAIL only when iptables says so ("Bad rule"), a missing iptables binary is FAIL.
//
// Nothing in an answer holds a token, a password, a key or a certificate body: the details are built from counts,
// names, paths and dates, and every detail is passed through selfTestSanitize, which masks the configured secrets.
// The checks read; none of them writes a file, a rule or the audit trail (the panel records the run itself as
// selftest.run, the command line does not touch the trail).

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

const (
	selfTestPass = "PASS"
	selfTestWarn = "WARN"
	selfTestFail = "FAIL"

	selfTestFirstDelay = 10 * time.Minute
	selfTestInterval   = 24 * time.Hour

	selfTestMaxDetail = 400

	// below this many days a CRL or a certificate is FAIL, below the second WARN
	selfTestFailDays = 7
	selfTestWarnDays = 30
	// a ban list not written for this long is WARN (a quiet box writes it only when a ban starts or ends)
	selfTestBansStale = 30 * 24 * time.Hour

	selfTestAuditAction = "selftest.run"
)

var (
	selfTestCLI = kingpin.Flag("selftest", "run the self-test (the protections of v0.1.11 and v0.1.12 are in place) and exit: 0 no check failed (WARN is allowed), 1 a check failed, 2 internal error; run it with the environment of the panel").Default("false").Bool()
	// a string and not a Bool: the contract is "not false", so any other value (empty, true, 1) leaves it on
	selfTestEnabledFlag  = kingpin.Flag("selftest.enabled", "run the self-test 10 minutes after the start and every 24 hours (Telegram message and error log on a FAIL); only the value false switches it off").Default("true").Envar("OVPN_SELFTEST_ENABLED").String()
	selfTestIptablesBin  = kingpin.Flag("selftest.iptables-bin", "iptables binary of the self-test (the openvpn container's OVPN_IPTABLES_BIN)").Default("iptables").Envar("OVPN_IPTABLES_BIN").String()
	selfTestIp6tablesBin = kingpin.Flag("selftest.ip6tables-bin", "ip6tables binary of the self-test (the openvpn container's OVPN_IP6TABLES_BIN)").Default("ip6tables").Envar("OVPN_IP6TABLES_BIN").String()
	selfTestOpenvpnLog   = kingpin.Flag("selftest.openvpn-log", "OpenVPN log read by the self-test (control channel check); empty = openvpn.log in the state directory (--state.dir), else next to --audit.path").Default("").Envar("OVPN_SELFTEST_OPENVPN_LOG").String()

	selfTestControlRe = regexp.MustCompile(`Control Channel: ([A-Za-z0-9._-]+), cipher ([A-Za-z0-9._ -]+?)(?:,|$)`)
	selfTestIndexRe   = regexp.MustCompile(`^[VRE]$`)
	selfTestEasyrsaRe = regexp.MustCompile(`(?m)^Version:\s+(\S+)`)
	selfTestApkRe     = regexp.MustCompile(`easy-rsa-([0-9][^\s]*)`)
	selfTestOvpnRe    = regexp.MustCompile(`^OpenVPN\s+(\S+)`)
	selfTestPEMRe     = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`)

	// how long a firewall or version command may run (a variable: a test shortens it)
	selfTestCmdTimeout = 10 * time.Second

	// the two seams of the tests: the list of checks, and what builds the selfTest of a run
	selfTestRegistry = selfTestChecks
	newSelfTestFor   = newSelfTest

	// one run at a time: the scheduled run and a request must not both walk the audit trail and start the firewall tools
	selfTestMu sync.Mutex
)

type selfTestCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type selfTestReport struct {
	Verdict     string          `json:"verdict"`
	Checks      []selfTestCheck `json:"checks"`
	GeneratedAt string          `json:"generatedAt"`

	// internal is set when the harness itself failed (a check panicked): exit status 2, HTTP 500
	internal bool
}

// counts returns the number of PASS, WARN and FAIL lines.
func (r selfTestReport) counts() (pass, warn, fail int) {
	for _, c := range r.Checks {
		switch c.Status {
		case selfTestPass:
			pass++
		case selfTestWarn:
			warn++
		default:
			fail++
		}
	}
	return
}

func (r selfTestReport) failed() []selfTestCheck {
	var out []selfTestCheck
	for _, c := range r.Checks {
		if c.Status == selfTestFail {
			out = append(out, c)
		}
	}
	return out
}

// selfTest holds everything a check reads from the outside, so that the tests put a fixture directory and stub
// commands behind it. A zero value is not usable: newSelfTest fills the production values.
type selfTest struct {
	now func() time.Time
	// run starts a command and returns its combined output and exit status; err is set when it could not be
	// started (not found, timeout, killed) and the status is then -1
	run func(ctx context.Context, name string, args ...string) (out string, code int, err error)
	// ownerUID is the user that must own the private keys (root)
	ownerUID int
	// scanCerts lists the certificates (the scan of the expiry notices)
	scanCerts func() ([]certInfo, error)
	// audit is the trail of the running panel; nil on the command line, which then reads the files without opening a writer
	audit *adminAuditLog
	// mgmtVersion asks the running OpenVPN server for its version; "" when it cannot be asked
	mgmtVersion func() string
	appVersion  func() string
	sleep       func(time.Duration)
}

// newSelfTest builds the production seams. oAdmin is nil on the command line.
func newSelfTest(oAdmin *OvpnAdmin) *selfTest {
	s := &selfTest{
		now:        time.Now,
		run:        selfTestExec,
		ownerUID:   0,
		audit:      adminAudit,
		sleep:      time.Sleep,
		appVersion: func() string { return version },
	}
	if oAdmin != nil {
		s.scanCerts = oAdmin.scanCerts
	} else {
		s.scanCerts = scanCertsLocked
	}
	s.mgmtVersion = selfTestMgmtVersion
	return s
}

// selfTestExec runs a command with a timeout and no shell; output is bounded.
func selfTestExec(ctx context.Context, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, selfTestCmdTimeout)
	defer cancel()
	var buf limitedBuffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.WaitDelay = 2 * time.Second // a child that keeps the pipe open after the kill must not hold the run
	err := cmd.Run()
	if err == nil {
		return buf.String(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ctx.Err() == nil {
		return buf.String(), ee.ExitCode(), nil
	}
	if ctx.Err() != nil {
		return buf.String(), -1, fmt.Errorf("%s timed out after %s", name, selfTestCmdTimeout)
	}
	return buf.String(), -1, err
}

// limitedBuffer keeps at most 1 MiB; the rest is dropped (a firewall listing is a few KiB).
type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	const max = 1 << 20
	if room := max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func selfTestMgmtVersion() string {
	if len(*mgmtAddress) == 0 {
		return ""
	}
	parts := strings.SplitN((*mgmtAddress)[0], "=", 2)
	out, err := mgmtCommand(parts[len(parts)-1], "version", isMgmtEnd)
	if err != nil {
		return ""
	}
	return parseMgmtVersion(out)
}

func selfTestEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(*selfTestEnabledFlag), "false")
}

// ---------------------------------------------------------------------------------------------------------------
// the run

type selfTestEntry struct {
	name string
	fn   func(*selfTest) (string, string)
}

func selfTestChecks() []selfTestEntry {
	return []selfTestEntry{
		{"admin_fence", (*selfTest).checkAdminFence},
		{"ban_jail", (*selfTest).checkBanJail},
		{"crl_age", (*selfTest).checkCrlAge},
		{"cert_expiry", (*selfTest).checkCertExpiry},
		{"key_modes", (*selfTest).checkKeyModes},
		{"credentials", (*selfTest).checkCredentials},
		{"control_channel", (*selfTest).checkControlChannel},
		{"audit_chain", (*selfTest).checkAuditChain},
		{"sync", (*selfTest).checkSync},
		{"versions", (*selfTest).checkVersions},
		{"pki_readable", (*selfTest).checkPkiReadable},
	}
}

// Run executes every check. A check that panics is FAIL with the reason, the others still run, and the report is
// marked internal (exit status 2).
func (s *selfTest) Run() selfTestReport {
	rep := selfTestReport{GeneratedAt: s.now().UTC().Format(time.RFC3339)}
	for _, c := range selfTestRegistry() {
		status, detail := s.runOne(c, &rep)
		rep.Checks = append(rep.Checks, selfTestCheck{Name: c.name, Status: status, Detail: selfTestSanitize(detail)})
	}
	rep.Verdict = selfTestPass
	for _, c := range rep.Checks {
		if c.Status == selfTestFail {
			rep.Verdict = selfTestFail
		}
	}
	return rep
}

func (s *selfTest) runOne(c selfTestEntry, rep *selfTestReport) (status, detail string) {
	defer func() {
		if r := recover(); r != nil {
			rep.internal = true
			status, detail = selfTestFail, fmt.Sprintf("internal error: the check panicked: %v", r)
		}
	}()
	return c.fn(s)
}

// selfTestSanitize makes a detail one bounded line and masks what must never leave: the configured secrets and
// anything that looks like key or certificate material.
func selfTestSanitize(detail string) string {
	detail = strings.Join(strings.Fields(detail), " ")
	if selfTestPEMRe.MatchString(detail) {
		return "[withheld: the text held key or certificate material]"
	}
	for _, secret := range selfTestSecrets() {
		detail = strings.ReplaceAll(detail, secret, "***")
	}
	if utf8.RuneCountInString(detail) > selfTestMaxDetail {
		detail = string([]rune(detail)[:selfTestMaxDetail-3]) + "..."
	}
	return detail
}

// selfTestSecrets are the values that must not appear in an answer. Very short values are left out: masking "ab"
// would damage every word that holds it.
func selfTestSecrets() []string {
	var out []string
	for _, v := range []string{
		*basicPassword, *masterSyncToken, *masterBasicAuthPassword,
		os.Getenv("OVPN_TELEGRAM_BOT_TOKEN"),
	} {
		if v = strings.TrimSpace(v); len(v) >= 4 {
			out = append(out, v)
		}
	}
	return out
}

func worstStatus(statuses ...string) string {
	out := selfTestPass
	for _, st := range statuses {
		switch {
		case st == selfTestFail:
			return selfTestFail
		case st == selfTestWarn:
			out = selfTestWarn
		}
	}
	return out
}

func selfTestKubernetes() bool { return *storageBackend == "kubernetes.secrets" }

const selfTestK8sDetail = "not checked: with --storage.backend=kubernetes.secrets the PKI is kept in secrets, not in files"

// ---------------------------------------------------------------------------------------------------------------
// admin_fence and ban_jail: the firewall of the network namespace the panel shares with the openvpn container

func selfTestIPv6() bool { return ovpnNetworkV6.IsValid() }

// firewall runs one iptables command. state: "ok" (exit 0), "bad" (the rule or chain is not there), "missing" (no
// such binary), "unknown" (permission, timeout, anything else).
func (s *selfTest) firewall(bin string, args ...string) (state, out, why string) {
	out, code, err := s.run(context.Background(), bin, args...)
	switch {
	case err != nil && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)):
		return "missing", out, fmt.Sprintf("%s is not installed in this container", bin)
	case err != nil:
		return "unknown", out, fmt.Sprintf("%s did not run: %s", bin, firstLine(err.Error()))
	case code == 0:
		return "ok", out, ""
	case code == 1 && (strings.Contains(out, "Bad rule") || strings.Contains(out, "matching rule exist") || strings.Contains(out, "No chain/target/match")):
		return "bad", out, ""
	}
	reason := firstLine(out)
	if strings.Contains(out, "Permission denied") || strings.Contains(out, "Operation not permitted") {
		reason = "permission denied"
	} else if len(reason) > 80 {
		reason = reason[:77] + "..."
	}
	return "unknown", out, fmt.Sprintf("%s cannot read the firewall (exit %d, %s): the container that runs the self-test needs CAP_NET_ADMIN in the network namespace of the openvpn container", bin, code, reason)
}

func (s *selfTest) fenceOne(bin, port string) (string, string) {
	state, _, why := s.firewall(bin, "-C", "INPUT", "-i", "tun+", "-p", "tcp", "--dport", port, "-j", "DROP")
	switch state {
	case "ok":
		return selfTestPass, fmt.Sprintf("%s: INPUT drops tcp/%s from tun+", bin, port)
	case "bad":
		return selfTestFail, fmt.Sprintf("%s: INPUT has no rule \"-i tun+ -p tcp --dport %s -j DROP\": VPN clients can reach the admin panel", bin, port)
	case "missing":
		return selfTestFail, why
	}
	return selfTestWarn, why
}

func (s *selfTest) checkAdminFence() (string, string) {
	port := strings.TrimSpace(*listenPort)
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return selfTestFail, fmt.Sprintf("the panel port %q (--listen.port) is not a port number", port)
	}
	st, detail := s.fenceOne(*selfTestIptablesBin, port)
	if !selfTestIPv6() {
		return st, detail
	}
	st6, d6 := s.fenceOne(*selfTestIp6tablesBin, port)
	return mergeFamilies(st, detail, st6, d6)
}

// mergeFamilies joins the IPv4 and the IPv6 answer; two warnings that say the same thing are said once.
func mergeFamilies(st4, d4, st6, d6 string) (string, string) {
	if st4 == selfTestWarn && st6 == selfTestWarn {
		return selfTestWarn, d4 + " (ip6tables: the same)"
	}
	return worstStatus(st4, st6), d4 + "; " + d6
}

// jumpOK reports whether an "iptables -S" listing holds the chain and an INPUT rule that jumps to it.
func selfTestJump(listing, chain string) (chainOK, jumpOK bool) {
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "-N" && f[1] == chain {
			chainOK = true
		}
		if len(f) >= 4 && f[0] == "-A" && f[1] == "INPUT" {
			for i := 2; i+1 < len(f); i++ {
				if f[i] == "-j" && f[i+1] == chain {
					jumpOK = true
				}
			}
		}
	}
	return
}

func (s *selfTest) jailOne(bin, chain string) (string, string) {
	state, out, why := s.firewall(bin, "-S")
	switch state {
	case "ok":
		chainOK, jumpOK := selfTestJump(out, chain)
		switch {
		case !chainOK:
			return selfTestFail, fmt.Sprintf("%s: the ban chain %s does not exist: addresses are not banned", bin, chain)
		case !jumpOK:
			return selfTestFail, fmt.Sprintf("%s: INPUT has no jump to %s: the ban chain is never reached", bin, chain)
		}
		return selfTestPass, fmt.Sprintf("%s: chain %s and its INPUT jump exist", bin, chain)
	case "bad":
		return selfTestFail, fmt.Sprintf("%s -S: %s", bin, firstLine(out))
	case "missing":
		return selfTestFail, why
	}
	return selfTestWarn, why
}

func (s *selfTest) checkBanJail() (string, string) {
	var statuses, details []string
	if strings.EqualFold(strings.TrimSpace(os.Getenv("OVPN_BAN_ENABLED")), "false") {
		statuses, details = append(statuses, selfTestWarn), append(details, "the ban engine is switched off (OVPN_BAN_ENABLED=false): no chain is checked")
	} else {
		st, d := s.jailOne(*selfTestIptablesBin, "OVPN_BAN")
		if selfTestIPv6() {
			st6, d6 := s.jailOne(*selfTestIp6tablesBin, "OVPN_BAN6")
			st, d = mergeFamilies(st, d, st6, d6)
		}
		statuses, details = append(statuses, st), append(details, d)
	}
	st, d := s.bansFile()
	statuses, details = append(statuses, st), append(details, d)
	return worstStatus(statuses...), strings.Join(details, "; ")
}

func (s *selfTest) bansFile() (string, string) {
	path := banListPath()
	if path == "" {
		return selfTestWarn, "no state directory is configured (--state.dir or --audit.path): bans.tsv is not checked"
	}
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return selfTestWarn, "bans.tsv does not exist: no ban has ever been written (or the state directory is not the one of the ban engine)"
	case err != nil:
		return selfTestFail, fmt.Sprintf("bans.tsv is not readable: %v", pathErr(err))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return selfTestFail, fmt.Sprintf("bans.tsv is not readable: %v", pathErr(err))
	}
	now := s.now()
	age := now.Sub(fi.ModTime())
	active, _ := parseBans(data, now)
	if age >= selfTestBansStale {
		return selfTestWarn, fmt.Sprintf("bans.tsv was last written %d days ago (%d active ban(s)): no ban started or ended since", int(age.Hours()/24), len(active))
	}
	return selfTestPass, fmt.Sprintf("bans.tsv readable, %d active ban(s), written %s ago", len(active), selfTestAgo(age))
}

// pathErr drops the path from an *fs.PathError, whose text repeats it.
func pathErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func selfTestAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// ---------------------------------------------------------------------------------------------------------------
// crl_age and cert_expiry

func (s *selfTest) checkCrlAge() (string, string) {
	if selfTestKubernetes() {
		return selfTestWarn, selfTestK8sDetail
	}
	next, err := crlNextUpdate()
	if err != nil {
		return selfTestFail, fmt.Sprintf("the CRL cannot be read: %v", pathErr(err))
	}
	days := crlExpireDays(next, s.now())
	when := next.UTC().Format("2006-01-02")
	switch {
	case days <= 0:
		return selfTestFail, fmt.Sprintf("the CRL expired on %s: OpenVPN refuses every client", when)
	case days < selfTestFailDays:
		return selfTestFail, fmt.Sprintf("the CRL expires on %s (%.1f days): OpenVPN refuses every client after that", when, days)
	case days < selfTestWarnDays:
		return selfTestWarn, fmt.Sprintf("the CRL expires on %s (%.1f days), the daily rebuild should have renewed it", when, days)
	}
	return selfTestPass, fmt.Sprintf("the CRL is valid until %s (%.0f days)", when, days)
}

func (s *selfTest) checkCertExpiry() (string, string) {
	if selfTestKubernetes() {
		return selfTestWarn, selfTestK8sDetail
	}
	certs, err := s.scanCerts()
	if err != nil {
		return selfTestFail, fmt.Sprintf("the certificates cannot be scanned: %v", pathErr(err))
	}
	now := s.now()
	var clients, servers, cas int
	var bad, soon []string
	var soonest *certInfo
	for i := range certs {
		c := certs[i]
		switch c.Kind {
		case certKindServer:
			servers++
		case certKindCA:
			cas++
		default:
			clients++
		}
		left := c.NotAfter.Sub(now)
		label := fmt.Sprintf("%s (%s)", c.Name, selfTestLeft(left))
		switch {
		case left < selfTestFailDays*24*time.Hour:
			bad = append(bad, label)
		case left < selfTestWarnDays*24*time.Hour:
			soon = append(soon, label)
		}
		if soonest == nil || c.NotAfter.Before(soonest.NotAfter) {
			soonest = &certs[i]
		}
	}
	var missing []string
	if cas == 0 {
		missing = append(missing, "no CA certificate")
	}
	if servers == 0 {
		missing = append(missing, "no server certificate")
	}
	switch {
	case len(bad) > 0 || len(missing) > 0:
		parts := append([]string{}, missing...)
		if len(bad) > 0 {
			parts = append(parts, fmt.Sprintf("expired or under %d days: %s", selfTestFailDays, selfTestList(bad)))
		}
		return selfTestFail, strings.Join(parts, "; ")
	case len(soon) > 0:
		return selfTestWarn, fmt.Sprintf("under %d days: %s", selfTestWarnDays, selfTestList(soon))
	}
	return selfTestPass, fmt.Sprintf("%d certificates (%d client, %d server, %d CA), soonest: %s, %s",
		len(certs), clients, servers, cas, soonest.Name, selfTestLeft(soonest.NotAfter.Sub(now)))
}

func selfTestLeft(d time.Duration) string {
	if d <= 0 {
		return fmt.Sprintf("expired %s ago", selfTestAgo(-d))
	}
	return fmt.Sprintf("%.1f days left", d.Hours()/24)
}

// selfTestList joins at most five names; the rest is counted.
func selfTestList(items []string) string {
	if len(items) <= 5 {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:5], ", ") + fmt.Sprintf(" and %d more", len(items)-5)
}

// ---------------------------------------------------------------------------------------------------------------
// key_modes and pki_readable

func (s *selfTest) checkKeyModes() (string, string) {
	if selfTestKubernetes() {
		return selfTestWarn, selfTestK8sDetail
	}
	var bad, warn, good []string
	// a private key: 0600 (0400 is stricter and accepted), owned by root
	for _, key := range []string{"ca.key", "server.key"} {
		path := pkiFile("private", key)
		fi, err := os.Stat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist) && key == "ca.key" && *serverRole == "slave":
			good = append(good, "ca.key absent (a slave holds no CA key)")
			continue
		case errors.Is(err, fs.ErrNotExist):
			bad = append(bad, "private/"+key+" does not exist")
			continue
		case err != nil:
			bad = append(bad, fmt.Sprintf("private/%s: %v", key, pathErr(err)))
			continue
		}
		uid, ok := fileOwner(fi)
		switch {
		case fi.Mode().Perm()&0o177 != 0:
			bad = append(bad, fmt.Sprintf("private/%s has mode %04o, expected 0600", key, fi.Mode().Perm()))
		case !ok:
			bad = append(bad, fmt.Sprintf("private/%s: the owner cannot be read", key))
		case uid != s.ownerUID:
			bad = append(bad, fmt.Sprintf("private/%s is owned by uid %d, expected root", key, uid))
		default:
			good = append(good, fmt.Sprintf("%s %04o root", key, fi.Mode().Perm()))
		}
	}
	// the certificate index and the password database: not readable by everybody
	for _, f := range []struct{ name, path string }{{"index.txt", selfTestIndexPath()}, {"users.db", *authDatabase}} {
		fi, err := os.Stat(f.path)
		switch {
		case errors.Is(err, fs.ErrNotExist) && f.name == "users.db" && !*authByPassword:
			good = append(good, "users.db absent (password authentication is off)")
		case errors.Is(err, fs.ErrNotExist):
			bad = append(bad, f.name+" does not exist")
		case err != nil:
			bad = append(bad, fmt.Sprintf("%s: %v", f.name, pathErr(err)))
		case fi.Mode().Perm()&0o002 != 0:
			bad = append(bad, fmt.Sprintf("%s has mode %04o: writable by everybody", f.name, fi.Mode().Perm()))
		case fi.Mode().Perm()&0o004 != 0 && f.name == "users.db":
			// measured: easy-rsa leaves index.txt 0600, but openvpn-user creates users.db 0644, and the login hook runs as
			// "nobody" (user nobody in openvpn.conf) and reads it, so a stock installation is world readable and cannot
			// be 0600 without breaking password logins. The way out is root:nogroup 0640, which configure.sh does not set
			// yet: a warning until it does, a FAIL for index.txt and the keys.
			warn = append(warn, fmt.Sprintf("users.db has mode %04o: readable by everybody (the login hook runs as nobody and reads it; root:nogroup 0640 keeps logins working)", fi.Mode().Perm()))
		case fi.Mode().Perm()&0o004 != 0:
			bad = append(bad, fmt.Sprintf("%s has mode %04o: readable by everybody", f.name, fi.Mode().Perm()))
		default:
			good = append(good, fmt.Sprintf("%s %04o", f.name, fi.Mode().Perm()))
		}
	}
	if len(bad) > 0 {
		return selfTestFail, strings.Join(append(bad, warn...), "; ")
	}
	if len(warn) > 0 {
		return selfTestWarn, strings.Join(warn, "; ")
	}
	return selfTestPass, strings.Join(good, ", ")
}

// fileOwner is the uid of a file; ok is false on a platform that has none.
func fileOwner(fi os.FileInfo) (uid int, ok bool) {
	st, isStat := fi.Sys().(*syscall.Stat_t)
	if !isStat {
		return 0, false
	}
	return int(st.Uid), true
}

func selfTestIndexPath() string {
	if *indexTxtPath != "" {
		return *indexTxtPath
	}
	return pkiFile("index.txt")
}

// sqliteMagic is the first 16 bytes of every SQLite 3 database.
const sqliteMagic = "SQLite format 3\x00"

func (s *selfTest) checkPkiReadable() (string, string) {
	if selfTestKubernetes() {
		return selfTestWarn, selfTestK8sDetail
	}
	var statuses, details []string

	// index.txt: every non-empty line is "flag \t expiry \t revocation \t serial \t file \t subject"
	raw, err := os.ReadFile(selfTestIndexPath())
	if err != nil {
		statuses, details = append(statuses, selfTestFail), append(details, fmt.Sprintf("index.txt is not readable: %v", pathErr(err)))
	} else {
		rows, badLine := 0, 0
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			rows++
			f := strings.Split(line, "\t")
			if badLine == 0 && (len(f) < 6 || !selfTestIndexRe.MatchString(f[0])) {
				badLine = i + 1
			}
		}
		if badLine > 0 {
			statuses, details = append(statuses, selfTestFail), append(details, fmt.Sprintf("index.txt does not parse: line %d is not a certificate record", badLine))
		} else {
			statuses, details = append(statuses, selfTestPass), append(details, fmt.Sprintf("index.txt parses (%d records)", rows))
		}
	}

	// users.db: opened read-only; with the sqlite3 command a real query, the header alone otherwise
	db := *authDatabase
	f, err := os.Open(db)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !*authByPassword:
		statuses, details = append(statuses, selfTestPass), append(details, "users.db absent (password authentication is off)")
	case errors.Is(err, fs.ErrNotExist):
		statuses, details = append(statuses, selfTestFail), append(details, "users.db does not exist but password authentication is on")
	case err != nil:
		statuses, details = append(statuses, selfTestFail), append(details, fmt.Sprintf("users.db cannot be opened: %v", pathErr(err)))
	default:
		head := make([]byte, len(sqliteMagic))
		_, rerr := io.ReadFull(f, head)
		f.Close()
		if rerr != nil || string(head) != sqliteMagic {
			statuses, details = append(statuses, selfTestFail), append(details, "users.db is not an SQLite database")
			break
		}
		out, code, qerr := s.run(context.Background(), "sqlite3", "-readonly", db, "SELECT count(*) FROM users;")
		switch {
		case qerr != nil && (errors.Is(qerr, exec.ErrNotFound) || errors.Is(qerr, fs.ErrNotExist)):
			statuses, details = append(statuses, selfTestPass), append(details, "users.db is an SQLite database (the sqlite3 command is not installed: header checked only)")
		case qerr != nil || code != 0:
			statuses, details = append(statuses, selfTestFail), append(details, fmt.Sprintf("users.db does not open read-only: %s", firstLine(out)))
		default:
			statuses, details = append(statuses, selfTestPass), append(details, fmt.Sprintf("users.db opens read-only (%s user rows)", strings.TrimSpace(firstLine(out))))
		}
	}
	return worstStatus(statuses...), strings.Join(details, "; ")
}

// ---------------------------------------------------------------------------------------------------------------
// credentials and sync: the settings of this process

func (s *selfTest) checkCredentials() (string, string) {
	user, pass := *basicUsername != "", *basicPassword != ""
	switch {
	case user && pass:
		return selfTestPass, "BASIC_USERNAME and BASIC_PASSWORD are both set"
	case user != pass:
		return selfTestFail, "only one of BASIC_USERNAME and BASIC_PASSWORD is set: the panel refuses to start with half of the credentials"
	case *insecureNoAuth:
		// the flag is an explicit decision, so the panel runs; it is still an open panel, which a PASS would hide
		return selfTestWarn, "BASIC_USERNAME and BASIC_PASSWORD are empty and --insecure-no-auth is set: the panel has no authentication by explicit choice"
	}
	return selfTestFail, "BASIC_USERNAME and BASIC_PASSWORD are empty and --insecure-no-auth is not set: the panel has no authentication"
}

func (s *selfTest) checkSync() (string, string) {
	if strings.TrimSpace(*masterSyncToken) == "" {
		return selfTestPass, "the sync token is empty: the sync is off, no PKI archive is served"
	}
	if *masterAllowInsecureHTTP {
		return selfTestFail, "a sync token is set and --master.allow-insecure-http serves the PKI archive over plain HTTP"
	}
	return selfTestPass, "a sync token is set, plain HTTP from a non-loopback address is refused (426)"
}

// ---------------------------------------------------------------------------------------------------------------
// control_channel

func selfTestOpenvpnLogPath() string {
	if *selfTestOpenvpnLog != "" {
		return *selfTestOpenvpnLog
	}
	if base := banStateBase(); base != "" {
		return filepath.Join(base, "openvpn.log")
	}
	return ""
}

// lastControlChannel returns the newest "Control Channel:" line of a log: the TLS version and the cipher.
func lastControlChannel(path string) (version, cipher string, found bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 256<<10)
	for {
		line, rerr := br.ReadString('\n')
		if i := strings.Index(line, "Control Channel:"); i >= 0 {
			if m := selfTestControlRe.FindStringSubmatch(line[i:]); m != nil {
				version, cipher, found = m[1], strings.TrimSpace(m[2]), true
			} else if f := strings.Fields(line[i+len("Control Channel:"):]); len(f) > 0 {
				version, cipher, found = strings.TrimRight(f[0], ","), "", true
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return version, cipher, found, nil
			}
			return version, cipher, found, rerr
		}
	}
}

func (s *selfTest) checkControlChannel() (string, string) {
	path := selfTestOpenvpnLogPath()
	if path == "" {
		return selfTestWarn, "no OpenVPN log is configured (--selftest.openvpn-log, --state.dir or --audit.path)"
	}
	// the log is rotated in place: when the newest file is empty or has no handshake yet, the rotated copies still hold one
	candidates := []string{path}
	for n := 1; n <= 9; n++ {
		candidates = append(candidates, path+"."+strconv.Itoa(n))
	}
	existed := false
	for _, p := range candidates {
		version, cipher, found, err := lastControlChannel(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		existed = true
		if err != nil {
			return selfTestFail, fmt.Sprintf("the OpenVPN log %s cannot be read: %v", filepath.Base(p), pathErr(err))
		}
		if !found {
			continue
		}
		what := version
		if cipher != "" {
			what += ", cipher " + cipher
		}
		switch version {
		case "TLSv1.2", "TLSv1.3":
			return selfTestPass, "the newest control channel is " + what
		case "TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2":
			return selfTestFail, fmt.Sprintf("the newest control channel is %s: the TLS floor of the server is not in force", what)
		}
		return selfTestWarn, fmt.Sprintf("the newest control channel line names %q, which is not a known TLS version", version)
	}
	if !existed {
		return selfTestWarn, fmt.Sprintf("the OpenVPN log %s does not exist: no handshake can be shown", filepath.Base(path))
	}
	return selfTestWarn, "no client has connected since the log started: no control channel line yet"
}

// ---------------------------------------------------------------------------------------------------------------
// audit_chain

// auditView is the trail as a reader outside the panel process sees it: no writer, nothing is opened for appending
// and nothing is created. Verify compares the end of the files with the newest line "this process wrote"; here that
// is the end of the files themselves (read first), so what is checked is the chain of every line, the checkpoint and
// the findings of earlier starts, not the memory of the running panel.
func selfTestAuditView(path string) *adminAuditLog {
	a := &adminAuditLog{path: filepath.Clean(path), maxBytes: adminAuditMaxBytes, now: time.Now, lastHash: adminAuditZeroHash}
	files := a.files()
	for i := len(files) - 1; i >= 0; i-- {
		f, err := openAuditRead(files[i])
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil || fi.Size() == 0 {
			f.Close()
			continue
		}
		_, last, err := scanAuditTail(f, fi.Size())
		f.Close()
		if err == nil {
			a.seq, a.lastHash = last.Seq, last.Hash
		}
		break
	}
	return a
}

func (s *selfTest) checkAuditChain() (string, string) {
	a, live := s.audit, s.audit != nil
	var path string
	if live {
		path = a.path
	} else {
		path = *adminAuditFileFlag
		if strings.TrimSpace(path) == "" {
			return selfTestFail, "no admin audit trail is configured (--admin-audit.file)"
		}
	}
	verify := func() (*adminAuditVerifyOK, *adminAuditVerifyBroken) {
		if live {
			return a.Verify()
		}
		v := selfTestAuditView(path)
		a = v
		return v.Verify()
	}
	okRes, bad := verify()
	if bad != nil && !live {
		// another process (the panel) may have been appending while the files were read: look once more
		s.sleep(300 * time.Millisecond)
		okRes, bad = verify()
	}
	switch {
	case bad != nil && bad.State == adminAuditStateUnverified:
		return selfTestFail, "the audit trail cannot be verified: " + bad.Reason
	case bad != nil:
		where := selfTestAuditLineOf(a, bad.BrokenAt)
		return selfTestFail, fmt.Sprintf("the audit chain is broken at seq %d%s: %s", bad.BrokenAt, where, bad.Reason)
	case okRes == nil:
		return selfTestFail, "the audit trail gave no result"
	}
	detail := fmt.Sprintf("the chain of %d lines is intact (seq %d to %d, checkpoint at %d)", okRes.Lines, okRes.FirstSeq, okRes.LastSeq, okRes.CheckpointSeq)
	if okRes.Unanchored > 0 {
		detail = fmt.Sprintf("the chain of %d lines is intact (seq %d to %d; checkpoint at seq %d, %d newer line(s) after it)", okRes.Lines, okRes.FirstSeq, okRes.LastSeq, okRes.CheckpointSeq, okRes.Unanchored)
	}
	if okRes.Lines == 0 {
		detail = "the trail holds no record yet: nothing to verify, the checkpoint agrees"
	}
	if okRes.Gaps > 0 || okRes.Unrecorded > 0 {
		return selfTestWarn, fmt.Sprintf("%s; %d audit.gap record(s) (first at seq %d), %d record(s) not written since the start: admin actions are missing from the trail", detail, okRes.Gaps, okRes.FirstGapSeq, okRes.Unrecorded)
	}
	return selfTestPass, detail
}

// selfTestAuditLineOf names the file and the line number of the record that carries seq, " (line 3 of admin-audit.log)".
// It finds the line by the seq it states, so a line whose seq was changed is not found and the answer has the seq only.
func selfTestAuditLineOf(a *adminAuditLog, seq int64) string {
	if a == nil || seq < 1 {
		return ""
	}
	for _, p := range a.files() {
		n := 0
		hit := 0
		_ = eachAuditLine(p, func(line []byte, terminated bool) bool {
			n++
			if looseSeq(line) == seq {
				hit = n
				return false
			}
			return true
		})
		if hit > 0 {
			return fmt.Sprintf(" (line %d of %s)", hit, filepath.Base(p))
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------------------------
// versions

func (s *selfTest) checkVersions() (string, string) {
	var statuses, details []string

	switch app := strings.TrimSpace(s.appVersion()); app {
	case "", "dev":
		statuses, details = append(statuses, selfTestFail), append(details, fmt.Sprintf("the panel version is %q: this is not a release build", app))
	default:
		statuses, details = append(statuses, selfTestPass), append(details, "ovpn-admin "+app)
	}

	// OpenVPN: the running server first, then the binary of this image
	ovpn, source := "", ""
	if s.mgmtVersion != nil {
		if v := s.mgmtVersion(); v != "" {
			ovpn, source = v, " (running server)"
		}
	}
	if ovpn == "" {
		out, code, err := s.run(context.Background(), "openvpn", "--version")
		if err == nil && code == 0 {
			if m := selfTestOvpnRe.FindStringSubmatch(firstLine(out)); m != nil {
				ovpn, source = m[1], " (binary of this image)"
			}
		}
	}
	if ovpn == "" {
		statuses, details = append(statuses, selfTestWarn), append(details, "OpenVPN version unknown (no management answer, no openvpn binary)")
	} else {
		statuses, details = append(statuses, selfTestPass), append(details, "OpenVPN "+ovpn+source)
	}

	// easy-rsa: its own version line, and where the distribution leaves the placeholder, the package version
	ersa := ""
	out, code, err := s.run(context.Background(), *easyrsaBinPath, "--version")
	if err == nil && code == 0 {
		if m := selfTestEasyrsaRe.FindStringSubmatch(out); m != nil && !strings.HasPrefix(m[1], "~") {
			ersa = m[1]
		}
	}
	if ersa == "" {
		if out, code, err := s.run(context.Background(), "apk", "list", "-I", "easy-rsa"); err == nil && code == 0 {
			if m := selfTestApkRe.FindStringSubmatch(out); m != nil {
				ersa = m[1]
			}
		}
	}
	if ersa == "" {
		statuses, details = append(statuses, selfTestWarn), append(details, "easy-rsa version unknown")
	} else {
		statuses, details = append(statuses, selfTestPass), append(details, "easy-rsa "+ersa)
	}
	return worstStatus(statuses...), strings.Join(details, ", ")
}

// ---------------------------------------------------------------------------------------------------------------
// command line

// selfTestLabelWidth is the widest check name, for the aligned columns.
func selfTestLabelWidth(r selfTestReport) int {
	w := 0
	for _, c := range r.Checks {
		w = max(w, len(c.Name))
	}
	return w
}

// printSelfTestReport writes one aligned line per check and the verdict.
func printSelfTestReport(w io.Writer, r selfTestReport) {
	fmt.Fprintf(w, "ovpn-admin %s self-test, %s\n", version, r.GeneratedAt)
	width := selfTestLabelWidth(r)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "%-*s  %-4s  %s\n", width, c.Name, c.Status, c.Detail)
	}
	pass, warn, fail := r.counts()
	fmt.Fprintf(w, "verdict: %s (%d PASS, %d WARN, %d FAIL)\n", r.Verdict, pass, warn, fail)
}

// selfTestExitCode: 0 no FAIL (WARN is allowed), 1 a FAIL, 2 an internal error.
func selfTestExitCode(r selfTestReport) int {
	switch {
	case r.internal:
		return 2
	case r.Verdict == selfTestFail:
		return 1
	}
	return 0
}

// selfTestPrepare reads the settings the checks need the way the panel does (the networks, the index path). It starts
// nothing: no listener, no scheduler, and the audit trail is read, never opened for writing.
func selfTestPrepare() error {
	if err := initNetworkConfig(); err != nil {
		return err
	}
	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}
	return nil
}

// runSelfTestCLI is --selftest: the report on stdout, the exit status as selfTestExitCode says.
func runSelfTestCLI(stdout io.Writer, s *selfTest) int {
	rep := s.Run()
	printSelfTestReport(stdout, rep)
	return selfTestExitCode(rep)
}

// ---------------------------------------------------------------------------------------------------------------
// the panel: endpoint and schedule

// runLocked runs the checks one run at a time.
func (s *selfTest) runLocked() selfTestReport {
	selfTestMu.Lock()
	defer selfTestMu.Unlock()
	return s.Run()
}

func (oAdmin *OvpnAdmin) selfTestHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !auditEndpointGate(w, r) {
		return
	}
	if !auditGetOnly(w, r) {
		return
	}
	rep := newSelfTestFor(oAdmin).runLocked()
	pass, warn, fail := rep.counts()
	_ = adminAudit.fromRequest(r, selfTestAuditAction, "selftest", rep.Verdict == selfTestPass,
		fmt.Sprintf("verdict=%s pass=%d warn=%d fail=%d", rep.Verdict, pass, warn, fail))
	code := http.StatusOK
	if rep.internal {
		code = http.StatusInternalServerError
	}
	certJSON(w, code, rep)
}

// selfTestScheduled is one scheduled run: the log line, and on a FAIL the error log and one Telegram message.
func (oAdmin *OvpnAdmin) selfTestScheduled() selfTestReport {
	rep := newSelfTestFor(oAdmin).runLocked()
	pass, warn, fail := rep.counts()
	_ = adminAudit.system(selfTestAuditAction, "selftest", rep.Verdict == selfTestPass,
		fmt.Sprintf("verdict=%s pass=%d warn=%d fail=%d", rep.Verdict, pass, warn, fail))
	if rep.Verdict == selfTestPass {
		log.Infof("self-test: %s (%d PASS, %d WARN, %d FAIL)", rep.Verdict, pass, warn, fail)
		for _, c := range rep.Checks {
			if c.Status == selfTestWarn {
				log.Warnf("self-test: %s WARN: %s", c.Name, c.Detail)
			}
		}
		return rep
	}
	for _, c := range rep.failed() {
		log.Errorf("self-test: %s FAIL: %s", c.Name, c.Detail)
	}
	log.Errorf("self-test: %s (%d PASS, %d WARN, %d FAIL)", rep.Verdict, pass, warn, fail)
	selfTestNotify(context.Background(), rep)
	return rep
}

// selfTestMessage is the Telegram text: the failed checks with their details, nothing else.
func selfTestMessage(rep selfTestReport) string {
	failed := rep.failed()
	lines := []string{fmt.Sprintf("\u26d4 ovpn-admin self-test FAILED: %d of %d checks", len(failed), len(rep.Checks))}
	for _, c := range failed {
		lines = append(lines, c.Name+": "+c.Detail)
	}
	return splitTelegramText(strings.Join(lines, "\n"), telegramMaxText)[0]
}

func selfTestNotify(ctx context.Context, rep selfTestReport) {
	cfg, why := telegramConfigFromEnv()
	if !cfg.enabled {
		log.Infof("self-test: no Telegram message: %s", why)
		return
	}
	if err := telegramSend(ctx, cfg, selfTestMessage(rep)); err != nil {
		log.Errorf("self-test: the Telegram message was not sent: %v", err)
		return
	}
	log.Info("self-test: Telegram message sent")
}

// selfTestLoop runs the first self-test firstDelay after the start (the openvpn container sets the firewall up
// while the panel starts) and then every interval. It ends when stop is closed (a nil stop never ends).
func (oAdmin *OvpnAdmin) selfTestLoop(firstDelay, interval time.Duration, stop <-chan struct{}) {
	if !selfTestEnabled() {
		log.Info("self-test: the scheduled run is off (OVPN_SELFTEST_ENABLED=false)")
		return
	}
	timer := time.NewTimer(firstDelay)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			oAdmin.selfTestScheduled()
			timer.Reset(interval)
		case <-stop:
			return
		}
	}
}
