package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The pair (address, account) is the key: five failures of the owner's account from one address lock that
// pair; the same account from another address, and another account from the same address, are not locked.
func TestLockIsPerSourceAndAccount(t *testing.T) {
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

// A lock for user A does not refuse user B from the same address.
func TestLockForUserADoesNotRefuseUserBFromTheSameAddress(t *testing.T) {
	r := newGuardRig(t, rigOpts{})
	const src = "172.31.190.1:5555"
	for i := 0; i < 5; i++ {
		if a := r.do(src, "/api/users/list", "user-a", "wrong"); a.code != 401 {
			t.Fatalf("failure %d: %d", i, a.code)
		}
	}
	if a := r.do(src, "/api/users/list", "user-a", "wrong"); a.code != 429 {
		t.Fatalf("user A after five failures: %d, want 429", a.code)
	}
	if a := r.do(src, "/api/users/list", "user-a", r.pass); a.code != 429 {
		t.Fatalf("user A with whatever credential: %d, want 429", a.code)
	}
	if a := r.right(src); a.code != 200 {
		t.Fatalf("the owner (user %q) from the same address: %d, want 200", guardUser, a.code)
	}
	if a := r.do(src, "/api/users/list", "user-b", "wrong"); a.code != 401 {
		t.Fatalf("user B, first failure: %d, want 401 (counted on its own)", a.code)
	}
}

// Many distinct names from one address are one source for the flood alert, and the state file holds the
// names only as hashes.
func TestStateFileHoldsNoUserNamesAndFloodCountsSources(t *testing.T) {
	dir := t.TempDir()
	r := newGuardRig(t, rigOpts{dir: dir})
	for i := 0; i < 30; i++ {
		r.do("203.0.113.5:1", "/api/users/list", "typed-secret-"+itoa(i), "x")
	}
	if len(r.alerts) != 0 {
		t.Fatalf("30 names from one address raised the flood alert: %v", r.alerts)
	}
	raw, err := os.ReadFile(filepath.Join(dir, authThrottleFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "typed-secret") {
		t.Errorf("a typed user name reached the state file")
	}
	if !strings.Contains(string(raw), "203.0.113.5|") {
		t.Errorf("state keys are not address|hash: %.120s", raw)
	}
}

// An entry of the earlier format (the bare address, the lock that covered everybody) is dropped at load.
func TestOldFormatEntriesAreDroppedAtLoad(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC).Unix()
	old := `{"version":1,"sources":{"172.31.190.1":{"strikes":1,"last_lock":` + itoa(int(now)) + `,"locked_until":` + itoa(int(now)+900) + `}}}`
	if err := os.WriteFile(filepath.Join(dir, authThrottleFileName), []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	r := newGuardRig(t, rigOpts{dir: dir})
	if err := r.guard.load(); err != nil {
		t.Fatal(err)
	}
	if n := len(r.guard.entries); n != 0 {
		t.Errorf("%d entries loaded from the old format, want 0", n)
	}
	if a := r.right("172.31.190.1:1"); a.code != 200 {
		t.Errorf("owner locked by an old-format entry: %d", a.code)
	}
}

// A source inside --admin.allow-cidr is trusted: never locked, never counted.
func TestAllowlistedSourceIsNeverLockedNorCounted(t *testing.T) {
	allow, err := parseAllowCIDRs([]string{"198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	r := newGuardRig(t, rigOpts{cfg: authConfig{allow: allow}})
	const src = "198.51.100.50:4000"
	for i := 0; i < 30; i++ {
		if a := r.wrong(src); a.code != 401 {
			t.Fatalf("wrong %d from the trusted source: %d, want 401 (never 429)", i, a.code)
		}
	}
	if a := r.right(src); a.code != 200 {
		t.Fatalf("the owner from the trusted source: %d, want 200", a.code)
	}
	if n := len(r.guard.entries); n != 0 {
		t.Errorf("%d entries for a trusted source, want 0 (never counted)", n)
	}
	// behind a proxy the trusted address is the one in X-Forwarded-For
	rp := newGuardRig(t, rigOpts{cfg: authConfig{allow: allow, trustProxy: true}})
	for i := 0; i < 10; i++ {
		if a := rp.do("198.51.100.2:1", "/api/x", guardUser, "bad", "X-Forwarded-For", "198.51.100.77"); a.code != 401 {
			t.Fatalf("trust-proxy, trusted client %d: %d", i, a.code)
		}
	}
	if n := len(rp.guard.entries); n != 0 {
		t.Errorf("trust-proxy: %d entries for a trusted client, want 0", n)
	}
}

// Only the allowlisted sources are exempt: the middleware by itself still locks a source outside the list.
func TestOnlyAllowlistedSourcesAreExemptFromTheLock(t *testing.T) {
	allow, _ := parseAllowCIDRs([]string{"198.51.100.0/24"})
	r := newGuardRig(t, rigOpts{})
	h := r.guard.middleware(basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}), guardUser, r.pass, guardPing),
		false, allow, guardPing)
	do := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		req.RemoteAddr = remote
		req.SetBasicAuth(guardUser, "bad")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 5; i++ {
		do("203.0.113.9:1")
		do("198.51.100.9:1")
	}
	if c := do("203.0.113.9:1"); c != 429 {
		t.Errorf("source outside the list after five failures: %d, want 429", c)
	}
	if c := do("198.51.100.9:1"); c != 401 {
		t.Errorf("source inside the list after five failures: %d, want 401", c)
	}
}
