package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

const syncTestToken = "a-sync-token-for-the-test"

// syncMaster is a master with a servable PKI and CCD directory and the sync token syncTestToken.
func syncMaster(t *testing.T) *OvpnAdmin {
	t.Helper()
	oAdmin, pki := setupFakeEasyrsa(t)
	writePki(t, pki)
	setupCcdDir(t, map[string]string{"alice": "ifconfig-push 192.168.100.10 255.255.255.0\n"})
	oAdmin.role = "master"
	oAdmin.masterSyncToken = syncTestToken
	setFlag(t, storageBackend, "filesystem")
	setFlag(t, masterAllowInsecureHTTP, false)
	return oAdmin
}

// syncRequest is a GET of a sync endpoint from remote (host:port) with the given headers.
func syncRequest(path, remote string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

const (
	certsPath = "/api/data/certs/download"
	ccdPath   = "/api/data/ccd/download"
	loopback  = "127.0.0.1:40000"
	remoteNet = "198.51.100.20:40000"
)

// loopbackGet is a GET that arrives from the loopback address, where the sync is served over plain HTTP.
func loopbackGet(target string) *http.Request {
	return syncRequest(target, loopback, nil)
}

func syncHandlers(oAdmin *OvpnAdmin) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{certsPath: oAdmin.downloadCertsHandler, ccdPath: oAdmin.downloadCcdHandler}
}

// hookLog collects what the panel logs (warnings and up) while the test runs.
func hookLog(t *testing.T) *logtest.Hook {
	t.Helper()
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	return hook
}

func logText(hook *logtest.Hook) string {
	var b strings.Builder
	for _, e := range hook.AllEntries() {
		b.WriteString(e.Message)
		b.WriteString("\n")
	}
	return b.String()
}

// A sync download with Authorization: Bearer or X-OVPN-Token works without a query string, on both endpoints.
func TestSyncDownloadWithTheTokenInAHeader(t *testing.T) {
	oAdmin := syncMaster(t)
	for path, h := range syncHandlers(oAdmin) {
		for name, headers := range map[string]map[string]string{
			"bearer":                      {"Authorization": "Bearer " + syncTestToken},
			"bearer lowercase":            {"Authorization": "bearer " + syncTestToken},
			"x-ovpn-token":                {"X-OVPN-Token": syncTestToken},
			"x-ovpn-token and basic auth": {"Authorization": "Basic dTpw", "X-OVPN-Token": syncTestToken},
		} {
			rec := callHandler(h, syncRequest(path, loopback, headers))
			if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
				t.Errorf("%s %s: status %d, %d bytes", path, name, rec.Code, rec.Body.Len())
			}
		}
	}
}

// A wrong token is 403 in every form, an absent one too.
func TestSyncDownloadWrongTokenIs403InEveryForm(t *testing.T) {
	oAdmin := syncMaster(t)
	for path, h := range syncHandlers(oAdmin) {
		for name, req := range map[string]*http.Request{
			"bearer":       syncRequest(path, loopback, map[string]string{"Authorization": "Bearer wrong-token"}),
			"x-ovpn-token": syncRequest(path, loopback, map[string]string{"X-OVPN-Token": "wrong-token"}),
			"query":        syncRequest(path+"?token=wrong-token", loopback, nil),
			"empty bearer": syncRequest(path, loopback, map[string]string{"Authorization": "Bearer  "}),
			"empty header": syncRequest(path, loopback, map[string]string{"X-OVPN-Token": ""}),
			"basic only":   syncRequest(path, loopback, map[string]string{"Authorization": "Basic " + syncTestToken}),
			"none":         syncRequest(path, loopback, nil),
		} {
			if rec := callHandler(h, req); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: status %d, want 403", path, name, rec.Code)
			}
		}
	}
	// a master without a token has the sync off: nothing is accepted, the empty token included
	oAdmin.masterSyncToken = ""
	for path, h := range syncHandlers(oAdmin) {
		if rec := callHandler(h, syncRequest(path+"?token=", loopback, map[string]string{"X-OVPN-Token": ""})); rec.Code != http.StatusForbidden {
			t.Errorf("%s without a configured token: %d, want 403", path, rec.Code)
		}
	}
}

// The header wins when both are present: a wrong header is refused although the query is right, and a right header is
// accepted although the query is wrong.
func TestSyncHeaderWinsOverTheQuery(t *testing.T) {
	oAdmin := syncMaster(t)
	h := oAdmin.downloadCertsHandler
	if rec := callHandler(h, syncRequest(certsPath+"?token="+syncTestToken, loopback, map[string]string{"X-OVPN-Token": "wrong"})); rec.Code != http.StatusForbidden {
		t.Errorf("wrong header, right query: %d, want 403", rec.Code)
	}
	if rec := callHandler(h, syncRequest(certsPath+"?token=wrong", loopback, map[string]string{"X-OVPN-Token": syncTestToken})); rec.Code != http.StatusOK {
		t.Errorf("right header, wrong query: %d, want 200", rec.Code)
	}
	if rec := callHandler(h, syncRequest(certsPath+"?token=wrong", loopback, map[string]string{"Authorization": "Bearer " + syncTestToken, "X-OVPN-Token": "wrong"})); rec.Code != http.StatusOK {
		t.Errorf("bearer wins over X-OVPN-Token: %d, want 200", rec.Code)
	}
}

// ?token= still works for this release and logs the deprecation at most once an hour, never the value.
func TestSyncQueryTokenWorksAndWarnsOncePerHour(t *testing.T) {
	oAdmin := syncMaster(t)
	hook := hookLog(t)
	clock := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	old := syncQueryWarning
	syncQueryWarning = &syncQueryWarner{now: func() time.Time { return clock }}
	t.Cleanup(func() { syncQueryWarning = old })

	count := func() int {
		n := 0
		for _, e := range hook.AllEntries() {
			if strings.Contains(e.Message, "deprecated") && strings.Contains(e.Message, "?token=") {
				n++
			}
		}
		return n
	}
	get := func() int {
		return callHandler(oAdmin.downloadCertsHandler, syncRequest(certsPath+"?token="+syncTestToken, loopback, nil)).Code
	}
	for i := 0; i < 5; i++ {
		if code := get(); code != http.StatusOK {
			t.Fatalf("query token: %d, want 200", code)
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("%d deprecation lines after 5 requests in the same minute, want 1", n)
	}
	clock = clock.Add(59 * time.Minute)
	get()
	if n := count(); n != 1 {
		t.Fatalf("%d deprecation lines after 59 minutes, want 1", n)
	}
	clock = clock.Add(2 * time.Minute)
	get()
	if n := count(); n != 2 {
		t.Fatalf("%d deprecation lines after 61 minutes, want 2", n)
	}
	// a header request does not warn
	callHandler(oAdmin.downloadCertsHandler, syncRequest(certsPath, loopback, map[string]string{"X-OVPN-Token": syncTestToken}))
	clock = clock.Add(3 * time.Hour)
	callHandler(oAdmin.downloadCertsHandler, syncRequest(certsPath, loopback, map[string]string{"X-OVPN-Token": syncTestToken}))
	if n := count(); n != 2 {
		t.Fatalf("a header request logged a deprecation: %d lines", n)
	}
	if strings.Contains(logText(hook), syncTestToken) {
		t.Error("the token is in the log")
	}
}

// Whatever the form, neither a right nor a wrong token is written to the log or to the audit trail.
func TestSyncTokenIsNeverLogged(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin := syncMaster(t)
	hook := hookLog(t)
	wrong := randomSecret(t, "wrong-")
	for _, req := range []*http.Request{
		syncRequest(certsPath, loopback, map[string]string{"Authorization": "Bearer " + wrong}),
		syncRequest(certsPath, loopback, map[string]string{"X-OVPN-Token": wrong}),
		syncRequest(certsPath+"?token="+wrong, loopback, nil),
		syncRequest(certsPath, loopback, map[string]string{"X-OVPN-Token": syncTestToken}),
		syncRequest(certsPath+"?token="+syncTestToken, loopback, nil),
		syncRequest(certsPath, remoteNet, map[string]string{"X-OVPN-Token": syncTestToken}),
	} {
		callHandler(oAdmin.downloadCertsHandler, req)
	}
	data, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{wrong, syncTestToken} {
		if strings.Contains(string(data), secret) || strings.Contains(logText(hook), secret) {
			t.Errorf("a token value %q... is in the audit file or the log", secret[:8])
		}
	}
	if !strings.Contains(string(data), "sync token rejected (X-OVPN-Token header)") {
		t.Errorf("the audit line does not say which form was refused: %s", data)
	}
}

// Plain HTTP from a non-loopback address is 426 with a one line explanation; the flag lets it through; loopback and
// TLS always work. The token form does not matter for the refusal.
func TestSyncPlainHTTPIs426FromANonLoopbackPeer(t *testing.T) {
	oAdmin := syncMaster(t)
	header := map[string]string{"X-OVPN-Token": syncTestToken}
	for path, h := range syncHandlers(oAdmin) {
		rec := callHandler(h, syncRequest(path, remoteNet, header))
		if rec.Code != http.StatusUpgradeRequired {
			t.Fatalf("%s from a non-loopback peer over plain HTTP: %d, want 426", path, rec.Code)
		}
		body := strings.TrimSpace(rec.Body.String())
		if strings.Contains(body, "\n") || !strings.Contains(body, "--master.allow-insecure-http") || !strings.Contains(body, "HTTPS") {
			t.Errorf("426 body is not one explaining line: %q", body)
		}
		if rec.Header().Get("Upgrade") == "" {
			t.Errorf("426 without an Upgrade header")
		}
		if strings.Contains(rec.Body.String(), syncTestToken) {
			t.Error("the 426 answer carries the token")
		}
		// the query form is refused the same way (the token already crossed the wire; it is not answered with the archive)
		if rec := callHandler(h, syncRequest(path+"?token="+syncTestToken, remoteNet, nil)); rec.Code != http.StatusUpgradeRequired {
			t.Errorf("%s query token over plain HTTP: %d, want 426", path, rec.Code)
		}
		// loopback, IPv4 and IPv6, and the IPv4-mapped form
		for _, peer := range []string{"127.0.0.1:1", "127.8.9.10:1", "[::1]:1", "[::ffff:127.0.0.1]:1"} {
			if rec := callHandler(h, syncRequest(path, peer, header)); rec.Code != http.StatusOK {
				t.Errorf("%s from loopback %s: %d, want 200", path, peer, rec.Code)
			}
		}
		// TLS (r.TLS set): served from anywhere
		req := syncRequest(path, remoteNet, header)
		req.TLS = &tls.ConnectionState{}
		if rec := callHandler(h, req); rec.Code != http.StatusOK {
			t.Errorf("%s over TLS: %d, want 200", path, rec.Code)
		}
		// headers that name another peer do not make a loopback one: X-Forwarded-For is not trusted
		spoof := map[string]string{"X-OVPN-Token": syncTestToken, "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https", "Forwarded": "for=127.0.0.1;proto=https"}
		if rec := callHandler(h, syncRequest(path, remoteNet, spoof)); rec.Code != http.StatusUpgradeRequired {
			t.Errorf("%s with forged forwarding headers: %d, want 426", path, rec.Code)
		}
		// a peer that is no address fails closed
		if rec := callHandler(h, syncRequest(path, "not-an-address", header)); rec.Code != http.StatusUpgradeRequired {
			t.Errorf("%s from an unparsable peer: %d, want 426", path, rec.Code)
		}
		// with the flag, plain HTTP from the network works, and a wrong token is still 403
		setFlag(t, masterAllowInsecureHTTP, true)
		if rec := callHandler(h, syncRequest(path, remoteNet, header)); rec.Code != http.StatusOK {
			t.Errorf("%s with --master.allow-insecure-http: %d, want 200", path, rec.Code)
		}
		if rec := callHandler(h, syncRequest(path, remoteNet, map[string]string{"X-OVPN-Token": "wrong"})); rec.Code != http.StatusForbidden {
			t.Errorf("%s with the flag and a wrong token: %d, want 403", path, rec.Code)
		}
		setFlag(t, masterAllowInsecureHTTP, false)
	}
}

// The refusal is audited, and a master with no token (sync off) is not turned into a 426: it stays 403.
func TestSyncPlainHTTPRefusalIsAuditedAndNeedsTheSyncOn(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin := syncMaster(t)
	callHandler(oAdmin.downloadCertsHandler, syncRequest(certsPath, remoteNet, map[string]string{"X-OVPN-Token": syncTestToken}))
	data, err := os.ReadFile(a.path)
	if err != nil || !strings.Contains(string(data), "refused: plain HTTP from a non-loopback address") {
		t.Fatalf("no audit line for the refusal (%v): %s", err, data)
	}
	oAdmin.masterSyncToken = ""
	if rec := callHandler(oAdmin.downloadCertsHandler, syncRequest(certsPath, remoteNet, nil)); rec.Code != http.StatusForbidden {
		t.Errorf("sync off, plain HTTP: %d, want 403", rec.Code)
	}
}

// The slave sends the token in X-OVPN-Token and keeps it out of the URL.
func TestSlaveSendsTheTokenInAHeaderNotInTheURL(t *testing.T) {
	var gotURL, gotToken, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL, gotToken, gotAuth = r.URL.String(), r.Header.Get("X-OVPN-Token"), r.Header.Get("Authorization")
		_, _ = w.Write([]byte("archive"))
	}))
	defer srv.Close()
	setFlag(t, masterHost, srv.URL)
	setFlag(t, listenBaseUrl, "/")
	setFlag(t, masterBasicAuthUser, "m")
	setFlag(t, masterBasicAuthPassword, "p")
	dir := t.TempDir()
	setArchivePaths(t, dir)
	oAdmin := &OvpnAdmin{masterSyncToken: syncTestToken, masterHostBasicAuth: true}
	if !oAdmin.downloadCerts() {
		t.Fatal("downloadCerts failed")
	}
	if strings.Contains(gotURL, "token") || strings.Contains(gotURL, syncTestToken) {
		t.Errorf("the token is in the URL: %s", gotURL)
	}
	if gotToken != syncTestToken {
		t.Errorf("X-OVPN-Token %q, want the token", gotToken)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("the Basic credentials of the master were not sent: %q", gotAuth)
	}
	if !oAdmin.downloadCcd() || strings.Contains(gotURL, "token") {
		t.Errorf("ccd download: url %s", gotURL)
	}
}

// A slave whose master answers 426 gets an error that says what to do, and no token in the message.
func TestSlaveExplains426(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, syncPlainHTTPRefusal, http.StatusUpgradeRequired)
	}))
	defer srv.Close()
	err := fDownload(t.TempDir()+"/x", srv.URL+certsPath, false, syncRequestHeader(syncTestToken))
	if err == nil || !strings.Contains(err.Error(), "426") || !strings.Contains(err.Error(), "--master.allow-insecure-http") {
		t.Fatalf("error %v", err)
	}
	if strings.Contains(err.Error(), syncTestToken) {
		t.Error("the error carries the token")
	}
}

func TestSyncTokenFromRequestForms(t *testing.T) {
	cases := []struct {
		name   string
		req    *http.Request
		token  string
		source string
	}{
		{"bearer", syncRequest("/x", loopback, map[string]string{"Authorization": "Bearer abc"}), "abc", syncTokenSourceBearer},
		{"bearer with padding", syncRequest("/x", loopback, map[string]string{"Authorization": "Bearer   abc  "}), "abc", syncTokenSourceBearer},
		{"x-ovpn-token", syncRequest("/x", loopback, map[string]string{"X-OVPN-Token": " abc "}), "abc", syncTokenSourceHeader},
		{"query", syncRequest("/x?token=abc", loopback, nil), "abc", syncTokenSourceQuery},
		{"basic is not a token", syncRequest("/x", loopback, map[string]string{"Authorization": "Basic abc"}), "", syncTokenSourceNone},
		{"bearer beats header beats query", syncRequest("/x?token=q", loopback, map[string]string{"Authorization": "Bearer b", "X-OVPN-Token": "h"}), "b", syncTokenSourceBearer},
		{"header beats query", syncRequest("/x?token=q", loopback, map[string]string{"X-OVPN-Token": "h"}), "h", syncTokenSourceHeader},
		{"basic then header", syncRequest("/x?token=q", loopback, map[string]string{"Authorization": "Basic zzz", "X-OVPN-Token": "h"}), "h", syncTokenSourceHeader},
		{"nothing", syncRequest("/x", loopback, nil), "", syncTokenSourceNone},
	}
	for _, c := range cases {
		token, source := syncTokenFromRequest(c.req)
		if token != c.token || source != c.source {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, token, source, c.token, c.source)
		}
	}
}

func TestWarnSyncTransport(t *testing.T) {
	hook := hookLog(t)
	warnSyncTransport("master", "tok", "http://127.0.0.1", false)
	warnSyncTransport("slave", "tok", "https://master.example", false)
	warnSyncTransport("slave", "tok", "http://127.0.0.1:8080", false)
	warnSyncTransport("slave", "tok", "http://localhost:8080", false)
	if n := len(hook.AllEntries()); n != 0 {
		t.Fatalf("%d warnings for safe settings: %s", n, logText(hook))
	}
	warnSyncTransport("slave", "tok", "http://172.20.0.1:8080", false)
	warnSyncTransport("master", "tok", "http://127.0.0.1", true)
	warnSyncTransport("master", "", "http://127.0.0.1", true)
	if n := len(hook.AllEntries()); n != 2 {
		t.Fatalf("%d warnings, want 2: %s", n, logText(hook))
	}
}
