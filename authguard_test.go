package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	guardUser   = "operator"
	guardPing   = "/ping"
	guardMetric = "/metrics"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type guardRig struct {
	t       *testing.T
	pass    string
	clock   *fakeClock
	guard   *authGuard
	handler http.Handler
	reached int
	alerts  [][]string
	dir     string
}

type rigOpts struct {
	cfg  authConfig
	dir  string
	hook func(*authGuard)
}

// newGuardRig builds the chain of main() around a handler that counts the requests that reach it.
func newGuardRig(t *testing.T, o rigOpts) *guardRig {
	t.Helper()
	if o.cfg.maxFailures == 0 {
		o.cfg.maxFailures = 5
	}
	if o.cfg.window == 0 {
		o.cfg.window = 15 * time.Minute
	}
	r := &guardRig{t: t, pass: randomSecret(t, "pw-"), dir: o.dir}
	if r.dir == "" {
		r.dir = t.TempDir()
	}
	r.clock = &fakeClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	r.guard = newAuthGuard(o.cfg, r.dir)
	r.guard.now = r.clock.now
	r.guard.alert = func(_ time.Duration, addrs []string) { r.alerts = append(r.alerts, addrs) }
	if o.hook != nil {
		o.hook(r.guard)
	}
	app := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.reached++
		_, _ = w.Write([]byte("app"))
	})
	r.handler = buildAuthChain(app, guardUser, r.pass, r.guard, o.cfg, guardPing, guardMetric)
	return r
}

type answer struct {
	code       int
	retryAfter string
	body       string
}

func (r *guardRig) do(remote, path, user, pass string, hdr ...string) answer {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Add(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return answer{rec.Code, rec.Header().Get("Retry-After"), rec.Body.String()}
}

func (r *guardRig) wrong(remote string) answer {
	return r.do(remote, "/api/users/list", guardUser, "not-"+r.pass)
}

func (r *guardRig) right(remote string) answer {
	return r.do(remote, "/api/users/list", guardUser, r.pass)
}

func TestValidateNoAuthConfig(t *testing.T) {
	err := validateNoAuthConfig("", "", false)
	if err == nil {
		t.Fatal("both credentials empty and no --insecure-no-auth was accepted")
	}
	for _, want := range []string{"--basic.username", "--basic.password", "--insecure-no-auth", "open to everyone"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if err := validateNoAuthConfig("", "", true); err != nil {
		t.Errorf("--insecure-no-auth refused: %v", err)
	}
	if err := validateNoAuthConfig("u", "p", false); err != nil {
		t.Errorf("credentials refused: %v", err)
	}
	// the one-of-two rule is still validateBasicAuthConfig's, and --insecure-no-auth does not excuse it
	if err := validateBasicAuthConfig("u", ""); err == nil || !strings.Contains(err.Error(), "must be set together") {
		t.Errorf("one-of-two error changed: %v", err)
	}
}

func TestParseAuthConfig(t *testing.T) {
	if _, err := parseAuthConfig(0, time.Minute, nil, false); err == nil {
		t.Error("--auth.max-failures=0 accepted")
	}
	if _, err := parseAuthConfig(5, 0, nil, false); err == nil {
		t.Error("--auth.fail-window=0 accepted")
	}
	cfg, err := parseAuthConfig(5, time.Minute, []string{"10.0.0.0/8, 2001:db8::/32", "192.0.2.7/24", ""}, true)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range cfg.allow {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "10.0.0.0/8 2001:db8::/32 192.0.2.0/24" {
		t.Errorf("allow = %v (comma separated values split, host bits masked)", got)
	}
	for _, bad := range []string{"10.0.0.1", "10.0.0.0/33", "nonsense", "10.0.0.0/8;1.1.1.1/32"} {
		if _, err := parseAuthConfig(5, time.Minute, []string{bad}, false); err == nil || !strings.Contains(err.Error(), "--admin.allow-cidr") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

// Five wrong passwords from one address give 401, the sixth 429 with Retry-After, and the right password from
// that address gets 429 too until the lock has expired (injected clock). The handler is not reached by any of it.
func TestFiveFailuresThenLocked(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	const src = "198.51.100.7:40001"
	for i := 1; i <= 5; i++ {
		if a := r.wrong(src); a.code != 401 {
			t.Fatalf("wrong password %d: %d, want 401", i, a.code)
		}
	}
	a := r.wrong(src)
	if a.code != 429 {
		t.Fatalf("sixth wrong password: %d, want 429", a.code)
	}
	if a.retryAfter != "900" {
		t.Errorf("Retry-After = %q, want 900 (15 minutes)", a.retryAfter)
	}
	if !strings.Contains(a.body, "Too many failed logins") || strings.Contains(a.body, r.pass) {
		t.Errorf("body = %q", a.body)
	}
	if a := r.right(src); a.code != 429 {
		t.Fatalf("right password while locked: %d, want 429 (lock is checked before the comparison)", a.code)
	}
	if r.reached != 0 {
		t.Errorf("the handler was reached %d times", r.reached)
	}
	// Retry-After shrinks with the clock
	r.clock.advance(10 * time.Minute)
	if a := r.right(src); a.code != 429 || a.retryAfter != "300" {
		t.Errorf("after 10 min: %d Retry-After=%q, want 429 and 300", a.code, a.retryAfter)
	}
	r.clock.advance(5*time.Minute + time.Second)
	if a := r.right(src); a.code != 200 {
		t.Fatalf("after the lock: %d, want 200", a.code)
	}
	if r.reached != 1 {
		t.Errorf("handler reached %d times, want 1", r.reached)
	}
}

func TestWrongUserWithRightPasswordCountsToo(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	for i := 0; i < 5; i++ {
		if a := r.do("198.51.100.8:1", "/api/x", "somebody-else", r.pass); a.code != 401 {
			t.Fatalf("%d: %d", i, a.code)
		}
	}
	if a := r.right("198.51.100.8:1"); a.code != 429 {
		t.Fatalf("locked: %d", a.code)
	}
}

// The key is the source, never the user name: an attacker cannot lock the owner out by guessing at the account.
func TestLockIsPerSourceNotPerUser(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	for i := 0; i < 6; i++ {
		r.wrong("198.51.100.9:5")
	}
	if a := r.wrong("198.51.100.9:6"); a.code != 429 {
		t.Fatalf("same address, other port: %d, want 429", a.code)
	}
	if a := r.right("203.0.113.1:5"); a.code != 200 {
		t.Fatalf("the owner from another address: %d, want 200", a.code)
	}
	if a := r.wrong("203.0.113.2:5"); a.code != 401 {
		t.Fatalf("another attacker: %d, want 401", a.code)
	}
}

func TestSuccessfulLoginClearsTheCount(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	const src = "198.51.100.10:1"
	for i := 0; i < 4; i++ {
		r.wrong(src)
	}
	if n := r.guard.failureCount("198.51.100.10"); n != 4 {
		t.Fatalf("count = %d, want 4", n)
	}
	if a := r.right(src); a.code != 200 {
		t.Fatalf("right password: %d", a.code)
	}
	if n := r.guard.failureCount("198.51.100.10"); n != 0 {
		t.Fatalf("count after a correct login = %d, want 0", n)
	}
	for i := 0; i < 4; i++ { // four more would have been the ninth failure without the clear
		if a := r.wrong(src); a.code != 401 {
			t.Fatalf("wrong %d after the clear: %d", i, a.code)
		}
	}
	if a := r.right(src); a.code != 200 {
		t.Fatalf("not locked: %d", a.code)
	}
}

func TestFailuresOutsideTheWindowDoNotAdd(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	const src = "198.51.100.11:1"
	for i := 0; i < 4; i++ {
		r.wrong(src)
	}
	r.clock.advance(15*time.Minute + time.Second)
	for i := 0; i < 4; i++ {
		if a := r.wrong(src); a.code != 401 {
			t.Fatalf("%d: %d", i, a.code)
		}
	}
	if a := r.right(src); a.code != 200 {
		t.Fatalf("old failures were counted: %d", a.code)
	}
}

// The browser challenge (no Authorization header) is not a failed login.
func TestChallengeWithoutCredentialsIsNotCounted(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	for i := 0; i < 30; i++ {
		if a := r.do("198.51.100.12:1", "/", "", ""); a.code != 401 {
			t.Fatalf("%d: %d", i, a.code)
		}
	}
	if a := r.right("198.51.100.12:1"); a.code != 200 {
		t.Fatalf("locked by challenges: %d", a.code)
	}
}

func TestLockStepsEscalateAndReset(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	const src = "198.51.100.13:1"
	steps := []struct {
		retry string
		wait  time.Duration
	}{{"900", 15 * time.Minute}, {"3600", time.Hour}, {"14400", 4 * time.Hour}, {"86400", 24 * time.Hour}}
	for i, s := range steps {
		for j := 0; j < 5; j++ {
			if a := r.wrong(src); a.code != 401 {
				t.Fatalf("step %d, wrong %d: %d", i, j, a.code)
			}
		}
		a := r.right(src)
		if a.code != 429 || a.retryAfter != s.retry {
			t.Fatalf("step %d: %d Retry-After=%q, want 429 and %s", i, a.code, a.retryAfter, s.retry)
		}
		r.clock.advance(s.wait)
	}
	// the last lock ran for 24 h: the history of offences within 24 h is empty, the next offence is the first again
	for j := 0; j < 5; j++ {
		r.wrong(src)
	}
	if a := r.right(src); a.code != 429 || a.retryAfter != "900" {
		t.Fatalf("a day after the previous offence: %d Retry-After=%q, want 429 and 900", a.code, a.retryAfter)
	}
}

func TestExemptPathsAreNeverThrottled(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	const src = "198.51.100.14:1"
	// wrong credentials at /metrics are refused (401) but never counted or locked
	for i := 0; i < 50; i++ {
		if a := r.do(src, guardMetric, guardUser, "not-"+r.pass); a.code != 401 {
			t.Fatalf("metrics wrong %d: %d", i, a.code)
		}
	}
	if a := r.right(src); a.code != 200 {
		t.Fatalf("metrics failures locked the source: %d", a.code)
	}
	// a source that is locked still gets /ping and /metrics with the configured credentials
	for i := 0; i < 5; i++ {
		r.wrong(src)
	}
	if a := r.right(src); a.code != 429 {
		t.Fatalf("setup: not locked: %d", a.code)
	}
	if a := r.do(src, guardPing, "", ""); a.code != 200 {
		t.Errorf("/ping of a locked source: %d", a.code)
	}
	if a := r.do(src, guardMetric, guardUser, r.pass); a.code != 200 {
		t.Errorf("/metrics with the right credentials of a locked source: %d", a.code)
	}
}

func TestLockSurvivesARestartAndTheFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	r := newGuardRig(t, rigOpts{dir: dir})
	const src = "198.51.100.15:1"
	for i := 0; i < 5; i++ {
		r.wrong(src)
	}
	for i := 0; i < 3; i++ {
		r.wrong("198.51.100.16:1")
	}
	path := filepath.Join(dir, authThrottleFileName)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("the state dir holds %d entries, want just the file (no temporary file left)", len(ents))
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), r.pass) || strings.Contains(string(raw), guardUser) {
		t.Errorf("the state file holds a credential or a user name")
	}

	// a new process: same directory, same clock
	r2 := newGuardRig(t, rigOpts{dir: dir})
	r2.pass = r.pass
	r2.clock.t = r.clock.t
	r2.handler = buildAuthChain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { r2.reached++ }),
		guardUser, r.pass, r2.guard, authConfig{maxFailures: 5, window: 15 * time.Minute}, guardPing, guardMetric)
	if err := r2.guard.load(); err != nil {
		t.Fatal(err)
	}
	if a := r2.right(src); a.code != 429 {
		t.Fatalf("after the restart: %d, want 429", a.code)
	}
	if n := r2.guard.failureCount("198.51.100.16"); n != 3 {
		t.Errorf("failure count after the restart = %d, want 3", n)
	}
	r2.clock.advance(16 * time.Minute)
	if a := r2.right(src); a.code != 200 {
		t.Errorf("after the lock ran out: %d", a.code)
	}
}

func TestDamagedStateFileIsMovedAsideAndTheGuardStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, authThrottleFileName)
	if err := os.WriteFile(path, []byte(`{"version":1,"sources":{ nope`), 0600); err != nil {
		t.Fatal(err)
	}
	r := newGuardRig(t, rigOpts{dir: dir})
	err := r.guard.load()
	if err == nil || !strings.Contains(err.Error(), "moved aside") {
		t.Fatalf("load: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the damaged file is still in place")
	}
	if a := r.right("198.51.100.17:1"); a.code != 200 {
		t.Errorf("owner locked out by a damaged file: %d", a.code)
	}
}

func TestUnwritableStateKeepsTheLockInMemory(t *testing.T) {
	// the state "directory" is a file, so nothing can be written under it
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	r := newGuardRig(t, rigOpts{dir: blocker})
	for i := 0; i < 5; i++ {
		r.wrong("198.51.100.18:1")
	}
	if a := r.right("198.51.100.18:1"); a.code != 429 {
		t.Fatalf("without persistence the lock is gone: %d", a.code)
	}
}

// More than 20 distinct sources failing within the window is reported once with the number and the addresses,
// and never locks the account: the owner still gets in.
func TestFloodOfSourcesAlertsOnceAndDoesNotLockTheAccount(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	addr := func(i int) string { return "203.0.113." + itoa(i) }
	for i := 1; i <= 20; i++ {
		r.wrong(addr(i) + ":1")
	}
	if len(r.alerts) != 0 {
		t.Fatalf("an alert at 20 sources: %v", r.alerts)
	}
	r.wrong(addr(21) + ":1")
	if len(r.alerts) != 1 || len(r.alerts[0]) != 21 {
		t.Fatalf("alerts = %v, want one alert with 21 addresses", r.alerts)
	}
	for i := 22; i <= 40; i++ {
		r.wrong(addr(i) + ":1")
	}
	r.wrong(addr(1) + ":1")
	if len(r.alerts) != 1 {
		t.Errorf("%d alerts, want exactly one for the flood", len(r.alerts))
	}
	if a := r.right("192.0.2.1:1"); a.code != 200 {
		t.Errorf("the owner is locked out by the flood: %d", a.code)
	}
	// once the window has gone by and the flood is over, a new flood is a new alert
	r.clock.advance(16 * time.Minute)
	r.wrong(addr(1) + ":1")
	for i := 2; i <= 22; i++ {
		r.wrong(addr(i) + ":1")
	}
	if len(r.alerts) != 2 {
		t.Errorf("%d alerts after a second flood, want 2", len(r.alerts))
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestFloodAlertGoesToTelegramWithCountAndAddresses(t *testing.T) {
	m := startTgMock(t)
	useTelegram(t, m)
	addrs := []string{}
	for i := 1; i <= 25; i++ {
		addrs = append(addrs, "203.0.113."+itoa(i))
	}
	sendFloodAlert(15*time.Minute, addrs)
	deadline := time.Now().Add(5 * time.Second)
	for len(m.texts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	texts := m.texts()
	if len(texts) != 1 {
		t.Fatalf("%d Telegram messages, want 1", len(texts))
	}
	txt := texts[0]
	if strings.Contains(txt, "\n") || !strings.Contains(txt, "25 distinct sources") || !strings.Contains(txt, "203.0.113.1,") || !strings.Contains(txt, "203.0.113.25") || !strings.Contains(txt, "not locked") {
		t.Errorf("text = %q", txt)
	}
	if strings.Contains(txt, testBotToken) {
		t.Errorf("the token is in the text")
	}
	// a flood of thousands is one line that names how many it leaves out
	var many []string
	for i := 0; i < 500; i++ {
		many = append(many, "2001:db8::"+itoa(i))
	}
	long := floodAlertText(time.Minute, many)
	if !strings.Contains(long, "500 distinct sources") || !strings.Contains(long, "and 460 more") || len(long) > 4000 {
		t.Errorf("long text: %d bytes, %q...", len(long), long[:120])
	}
}

func TestAllowlistDeniesBeforeAuthAndTheHandler(t *testing.T) {
	cfg, err := parseAuthConfig(5, 15*time.Minute, []string{"192.0.2.0/24", "2001:db8:1::/48"}, false)
	if err != nil {
		t.Fatal(err)
	}
	r := newGuardRig(t, rigOpts{cfg: cfg})
	cases := []struct {
		remote string
		want   int
	}{
		{"192.0.2.55:1234", 200},
		{"[2001:db8:1:7::9]:1234", 200},
		{"[::ffff:192.0.2.9]:1234", 200}, // IPv4 in IPv6 notation
		{"198.51.100.1:1234", 403},
		{"[2001:db8:2::1]:1234", 403},
		{"[::1]:1234", 403},
	}
	for _, c := range cases {
		a := r.right(c.remote)
		if a.code != c.want {
			t.Errorf("%s: %d, want %d", c.remote, a.code, c.want)
		}
		if c.want == 403 && strings.TrimSpace(a.body) != "Forbidden" {
			t.Errorf("%s: the 403 says more than the status: %q", c.remote, a.body)
		}
	}
	before := r.reached
	// outside the list nothing is looked at: not the credentials, not /ping, not the metrics path
	for _, p := range []string{guardPing, guardMetric, "/api/users/list"} {
		if a := r.do("198.51.100.1:1", p, guardUser, r.pass); a.code != 403 {
			t.Errorf("%s from outside: %d", p, a.code)
		}
	}
	if r.reached != before {
		t.Errorf("the handler was reached from outside the list")
	}
	// and wrong credentials from outside are not counted against the lock either
	for i := 0; i < 10; i++ {
		r.do("198.51.100.1:1", "/api/x", guardUser, "wrong")
	}
	if n := r.guard.failureCount("198.51.100.1"); n != 0 {
		t.Errorf("a refused source was counted: %d", n)
	}
}

func TestXForwardedForIsIgnoredWithoutTrustProxy(t *testing.T) {
	cfg, _ := parseAuthConfig(5, time.Minute, []string{"192.0.2.0/24"}, false)
	r := newGuardRig(t, rigOpts{cfg: cfg})
	// an outside peer naming an allowed address in the header is still outside
	if a := r.do("198.51.100.1:1", "/api/x", guardUser, r.pass, "X-Forwarded-For", "192.0.2.5"); a.code != 403 {
		t.Errorf("outside peer with an allowed XFF: %d, want 403", a.code)
	}
	// an inside peer is not turned away by an outside header
	if a := r.do("192.0.2.9:1", "/api/x", guardUser, r.pass, "X-Forwarded-For", "198.51.100.1"); a.code != 200 {
		t.Errorf("inside peer with an outside XFF: %d, want 200", a.code)
	}
}

func TestTrustProxyUsesTheLastForwardedValue(t *testing.T) {
	cfg, _ := parseAuthConfig(5, time.Minute, []string{"192.0.2.0/24"}, true)
	r := newGuardRig(t, rigOpts{cfg: cfg})
	proxy := "10.9.9.9:4000" // the peer is the proxy, outside the list
	cases := []struct {
		name string
		hdr  []string
		want int
	}{
		{"last value inside", []string{"X-Forwarded-For", "198.51.100.1, 192.0.2.5"}, 200},
		{"first value inside, last outside: a client's own claim does not count", []string{"X-Forwarded-For", "192.0.2.5, 198.51.100.1"}, 403},
		{"two header lines: the last line, its last value", []string{"X-Forwarded-For", "192.0.2.5", "X-Forwarded-For", "198.51.100.1"}, 403},
		{"two header lines inside", []string{"X-Forwarded-For", "198.51.100.1", "X-Forwarded-For", "10.0.0.1, 192.0.2.77"}, 200},
		{"value with a port", []string{"X-Forwarded-For", "192.0.2.5:5555"}, 200},
		{"garbage as the last value is refused", []string{"X-Forwarded-For", "192.0.2.5, not-an-address"}, 403},
		{"empty last value is refused", []string{"X-Forwarded-For", "192.0.2.5,"}, 403},
		{"no header: the peer decides", nil, 403},
	}
	for _, c := range cases {
		if a := r.do(proxy, "/api/x", guardUser, r.pass, c.hdr...); a.code != c.want {
			t.Errorf("%s: %d, want %d", c.name, a.code, c.want)
		}
	}
	// no header and the peer inside the list
	if a := r.do("192.0.2.1:1", "/api/x", guardUser, r.pass); a.code != 200 {
		t.Errorf("peer inside without header: %d", a.code)
	}
}

// Behind a proxy the lock is per client (the forwarded address), not per proxy.
func TestTrustProxyLocksTheClientNotTheProxy(t *testing.T) {
	cfg, _ := parseAuthConfig(5, 15*time.Minute, nil, true)
	r := newGuardRig(t, rigOpts{cfg: cfg})
	proxy := "10.9.9.9:4000"
	for i := 0; i < 5; i++ {
		r.do(proxy, "/api/x", guardUser, "bad", "X-Forwarded-For", "198.51.100.50")
	}
	if a := r.do(proxy, "/api/x", guardUser, r.pass, "X-Forwarded-For", "198.51.100.50"); a.code != 429 {
		t.Errorf("the attacker behind the proxy: %d, want 429", a.code)
	}
	if a := r.do(proxy, "/api/x", guardUser, r.pass, "X-Forwarded-For", "203.0.113.60"); a.code != 200 {
		t.Errorf("the owner behind the same proxy: %d, want 200", a.code)
	}
}

func TestEmptyAllowlistChangesNothing(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	if a := r.do("198.51.100.1:1", "/api/x", guardUser, r.pass, "X-Forwarded-For", "garbage"); a.code != 200 {
		t.Errorf("%d", a.code)
	}
}

func TestClientAddr(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		return req
	}
	for _, c := range []struct {
		remote, xff string
		trust       bool
		want        string
		ok          bool
	}{
		{"192.0.2.1:80", "", false, "192.0.2.1", true},
		{"192.0.2.1:80", "198.51.100.1", false, "192.0.2.1", true},
		{"192.0.2.1:80", "198.51.100.1", true, "198.51.100.1", true},
		{"[fe80::1%eth0]:80", "", false, "fe80::1", true},
		{"[::ffff:192.0.2.1]:80", "", false, "192.0.2.1", true},
		{"@", "", false, "", false},
		{"192.0.2.1:80", "[2001:db8::1]", true, "2001:db8::1", true},
		{"192.0.2.1:80", "x", true, "", false},
	} {
		a, ok := clientAddr(mk(c.remote, c.xff), c.trust)
		if ok != c.ok || (ok && a != netip.MustParseAddr(c.want)) {
			t.Errorf("%+v: got %v %v", c, a, ok)
		}
	}
}

// The refusals and locks are written to the admin audit trail; no password or token is.
func TestRefusalsAreAudited(t *testing.T) {
	trail := useAdminAudit(t, "")
	cfg, _ := parseAuthConfig(5, 15*time.Minute, []string{"192.0.2.0/24"}, false)
	r := newGuardRig(t, rigOpts{cfg: cfg})
	wrongPass := "audit-wrong-" + randomSecret(t, "")
	for i := 0; i < 5; i++ {
		r.do("192.0.2.30:1", "/api/x", guardUser, wrongPass)
	}
	for i := 0; i < 3; i++ {
		r.right("192.0.2.30:1") // locked: 429
	}
	for i := 0; i < 3; i++ {
		r.do("198.51.100.99:1", "/api/x", guardUser, r.pass) // outside
	}
	trail.Close()
	var all string
	actions := map[string]int{}
	for _, l := range readAuditFile(t, trail.path) {
		all += l + "\n"
		rec, err := parseAdminAuditLine([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		actions[rec.Action]++
		if rec.Action == auditActLoginLocked && rec.Source != "192.0.2.30" {
			t.Errorf("locked line source %q", rec.Source)
		}
		if rec.Action == auditActAllowlistDeny && (rec.Source != "198.51.100.99" || rec.Result != "fail") {
			t.Errorf("deny line %+v", rec)
		}
	}
	if actions["auth.login.fail"] != 1 || actions["auth.login.locked"] != 2 || actions["admin.allowlist.deny"] != 1 {
		t.Errorf("actions = %v, want auth.login.fail 1 (throttled per source), auth.login.locked 2 (the lock, then the throttled refusals), admin.allowlist.deny 1", actions)
	}
	for _, secret := range []string{wrongPass, r.pass, "Authorization", "Basic "} {
		if strings.Contains(all, secret) {
			t.Errorf("the trail holds %q", secret)
		}
	}
}

func TestRehashNoticeIsAudited(t *testing.T) {
	trail := useAdminAudit(t, "")
	auditRehashNotice("carol", "noise\nopenvpn-user: rehash cost 4 -> 12\n")
	auditRehashNotice("dave", "no notice here\n")
	auditRehashNotice("erin", "openvpn-user: rehash cost 12; DROP -> 12\n")
	trail.Close()
	var got []adminAuditRecord
	for _, l := range readAuditFile(t, trail.path) {
		rec, _ := parseAdminAuditLine([]byte(l))
		if rec.Action == auditActRehash {
			got = append(got, rec)
		}
	}
	if len(got) != 2 || got[0].Target != "carol" || !strings.Contains(got[0].Detail, "was cost 4") || got[1].Target != "erin" || strings.Contains(got[1].Detail, "DROP") {
		t.Errorf("rehash lines = %+v", got)
	}
}

func TestManySourcesStayBounded(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	r.guard.alert = nil
	r.guard.path = "" // memory only: 4000 fsynced writes would test the disk
	for i := 0; i < authMaxSources+50; i++ {
		r.guard.fail("10." + itoa(i/65536) + "." + itoa(i/256%256) + "." + itoa(i%256))
	}
	if n := len(r.guard.entries); n > authMaxSources {
		t.Errorf("%d entries, limit %d", n, authMaxSources)
	}
}

var _ = sync.Mutex{}
