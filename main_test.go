package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	log "github.com/sirupsen/logrus"
)

func TestCacheControlWrapper(t *testing.T) {
	files := fstest.MapFS{
		"index.html":         {Data: []byte("<div id=app></div>")},
		"dist/bundle.min.js": {Data: []byte("console.log(1)")},
	}
	handler := CacheControlWrapper(http.FileServer(http.FS(files)), files)

	for _, path := range []string{"/", "/dist/bundle.min.js"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("GET %s: Cache-Control = %q, want no-cache", path, got)
		}
		etag := rec.Header().Get("ETag")
		if etag == "" {
			t.Fatalf("GET %s: no ETag", path)
		}

		// revalidation of an unchanged file
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("If-None-Match", etag)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotModified {
			t.Errorf("GET %s with If-None-Match = %d, want 304", path, rec.Code)
		}
	}

	// a changed file gets a different ETag
	other := fstest.MapFS{"index.html": {Data: []byte("<div id=app>v2</div>")}}
	if staticETags(files)["index.html"] == staticETags(other)["index.html"] {
		t.Error("different content has the same ETag")
	}
}

func TestStaticFilePath(t *testing.T) {
	tests := map[string]string{
		"/":                   "index.html",
		"":                    "index.html",
		"/dist/bundle.min.js": "dist/bundle.min.js",
		"/dist/":              "dist/index.html",
		"/../index.html":      "index.html",
	}
	for in, want := range tests {
		if got := staticFilePath(in); got != want {
			t.Errorf("staticFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// With explicit --ovpn.server hosts the Kubernetes LoadBalancer discovery must
// not override them; it is only the fallback when no host is configured.
func TestRenderClientConfigHostsPriority(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pki", "issued"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pki", "private"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"pki/index.txt":         "V\t351231235959Z\t\t01\tunknown\t/CN=alice\n",
		"pki/ca.crt":            "CA",
		"pki/ta.key":            "TA",
		"pki/issued/alice.crt":  "CERT",
		"pki/private/alice.key": "KEY",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setFlag(t, easyrsaDirPath, dir)
	setFlag(t, indexTxtPath, filepath.Join(dir, "pki", "index.txt"))
	setFlag(t, storageBackend, "filesystem")
	setFlag(t, clientConfigTemplatePath, "")
	setFlag(t, openvpnServerBehindLB, true)

	oldServers := ovpnServers
	t.Cleanup(func() { ovpnServers = oldServers })

	ovpnServers = []OpenvpnServer{{Host: "vpn.example.org", Port: "1194", Protocol: "udp"}}
	got := (&OvpnAdmin{}).renderClientConfig("alice")
	if !strings.Contains(got, "remote vpn.example.org 1194 udp") {
		t.Errorf("configured host missing from config:\n%s", got)
	}
	if strings.Contains(got, "kubernetes services not found") {
		t.Errorf("Kubernetes discovery overrode the configured host:\n%s", got)
	}

	// no configured host: discovery is the fallback (outside a cluster it reports "not found")
	ovpnServers = nil
	got = (&OvpnAdmin{}).renderClientConfig("alice")
	if !strings.Contains(got, "kubernetes services not found") {
		t.Errorf("Kubernetes discovery not used as fallback:\n%s", got)
	}
}

// authTestServer serves the routes that matter for the auth boundary behind the middleware.
func authTestServer(username, password string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ui")) })
	mux.HandleFunc("/api/users/list", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("users")) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("metrics")) })
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("pong")) })
	return basicAuthMiddleware(mux, username, password, "/ping")
}

func TestBasicAuthMiddleware(t *testing.T) {
	const wantChallengeHeader = `Basic realm="ovpn-admin", charset="UTF-8"`

	tests := []struct {
		name          string
		serverUser    string
		serverPass    string
		path          string
		authUser      string
		authPass      string
		sendAuth      bool
		wantStatus    int
		wantBody      string
		wantChallenge bool
	}{
		{name: "disabled lets everything through", path: "/api/users/list", wantStatus: 200, wantBody: "users"},
		{name: "disabled lets metrics through", path: "/metrics", wantStatus: 200, wantBody: "metrics"},
		{name: "no header", serverUser: "admin", serverPass: "s3cret", path: "/api/users/list", wantStatus: 401, wantChallenge: true},
		{name: "no header on UI", serverUser: "admin", serverPass: "s3cret", path: "/", wantStatus: 401, wantChallenge: true},
		{name: "wrong user", serverUser: "admin", serverPass: "s3cret", path: "/api/users/list", sendAuth: true, authUser: "root", authPass: "s3cret", wantStatus: 401, wantChallenge: true},
		{name: "wrong password", serverUser: "admin", serverPass: "s3cret", path: "/api/users/list", sendAuth: true, authUser: "admin", authPass: "nope", wantStatus: 401, wantChallenge: true},
		{name: "prefix of the password", serverUser: "admin", serverPass: "s3cret", path: "/api/users/list", sendAuth: true, authUser: "admin", authPass: "s3cre", wantStatus: 401, wantChallenge: true},
		{name: "empty credentials", serverUser: "admin", serverPass: "s3cret", path: "/api/users/list", sendAuth: true, wantStatus: 401, wantChallenge: true},
		{name: "correct credentials", serverUser: "admin", serverPass: "s3cret", path: "/api/users/list", sendAuth: true, authUser: "admin", authPass: "s3cret", wantStatus: 200, wantBody: "users"},
		{name: "correct credentials on UI", serverUser: "admin", serverPass: "s3cret", path: "/", sendAuth: true, authUser: "admin", authPass: "s3cret", wantStatus: 200, wantBody: "ui"},
		{name: "ping is open", serverUser: "admin", serverPass: "s3cret", path: "/ping", wantStatus: 200, wantBody: "pong"},
		{name: "metrics without credentials", serverUser: "admin", serverPass: "s3cret", path: "/metrics", wantStatus: 401, wantChallenge: true},
		{name: "metrics with correct credentials", serverUser: "admin", serverPass: "s3cret", path: "/metrics", sendAuth: true, authUser: "admin", authPass: "s3cret", wantStatus: 200, wantBody: "metrics"},
		{name: "ping lookalike is protected", serverUser: "admin", serverPass: "s3cret", path: "/ping/", wantStatus: 401, wantChallenge: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.sendAuth {
				req.SetBasicAuth(tt.authUser, tt.authPass)
			}
			rec := httptest.NewRecorder()
			authTestServer(tt.serverUser, tt.serverPass).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
			got := rec.Header().Get("WWW-Authenticate")
			if tt.wantChallenge && got != wantChallengeHeader {
				t.Errorf("WWW-Authenticate = %q, want %q", got, wantChallengeHeader)
			}
			if !tt.wantChallenge && got != "" {
				t.Errorf("unexpected WWW-Authenticate %q", got)
			}
			if tt.wantStatus == 401 && strings.Contains(rec.Body.String(), "users") {
				t.Errorf("401 response leaks protected content: %q", rec.Body.String())
			}
		})
	}
}

func TestValidateBasicAuthConfig(t *testing.T) {
	tests := []struct {
		user, pass string
		wantErr    bool
	}{
		{"", "", false},
		{"admin", "s3cret", false},
		{"admin", "", true},
		{"", "s3cret", true},
	}
	for _, tt := range tests {
		err := validateBasicAuthConfig(tt.user, tt.pass)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateBasicAuthConfig(%q, %q) error = %v, wantErr %v", tt.user, tt.pass, err, tt.wantErr)
		}
	}
}

// Passwords, tokens and user names travel in the query string: the access log of a handler must
// only contain the path.
func TestHandlersDoNotLogTheQueryString(t *testing.T) {
	oAdmin := &OvpnAdmin{role: "slave", createUserMutex: &sync.Mutex{}}
	handlers := map[string]http.HandlerFunc{
		"/api/user/create":          oAdmin.userCreateHandler,
		"/api/user/rotate":          oAdmin.userRotateHandler,
		"/api/user/delete":          oAdmin.userDeleteHandler,
		"/api/user/revoke":          oAdmin.userRevokeHandler,
		"/api/user/unrevoke":        oAdmin.userUnrevokeHandler,
		"/api/user/change-password": oAdmin.userChangePasswordHandler,
		"/api/user/ccd/apply":       oAdmin.userApplyCcdHandler,
		"/api/data/certs/download":  oAdmin.downloadCertsHandler,
		"/api/data/ccd/download":    oAdmin.downloadCcdHandler,
	}

	var buf bytes.Buffer
	oldOut, oldLevel := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetLevel(oldLevel) })

	const secret = "s3cr3t-Pa55w0rd"
	for path, h := range handlers {
		buf.Reset()
		req := httptest.NewRequest(http.MethodPost, path+"?username=alice&password="+secret+"&token="+secret, nil)
		h(httptest.NewRecorder(), req)
		out := buf.String()
		if !strings.Contains(out, path) {
			t.Errorf("%s: the request was not logged: %q", path, out)
		}
		for _, leaked := range []string{secret, "password=", "token=", "username="} {
			if strings.Contains(out, leaked) {
				t.Errorf("%s: log line contains %q: %q", path, leaked, out)
			}
		}
	}
}

// The slave only mirrors the master: every call that changes users is refused with 423.
func TestSlaveRefusesUserChanges(t *testing.T) {
	setupUsers(t, "alice")
	setFlag(t, authByPassword, true)
	oAdmin := &OvpnAdmin{role: "slave", createUserMutex: &sync.Mutex{}}
	handlers := map[string]http.HandlerFunc{
		"create":          oAdmin.userCreateHandler,
		"rotate":          oAdmin.userRotateHandler,
		"delete":          oAdmin.userDeleteHandler,
		"revoke":          oAdmin.userRevokeHandler,
		"unrevoke":        oAdmin.userUnrevokeHandler,
		"change-password": oAdmin.userChangePasswordHandler,
		"ccd-apply":       oAdmin.userApplyCcdHandler,
	}
	for name, h := range handlers {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/api/user/"+name+"?username=alice&password=x", nil))
		if rec.Code != http.StatusLocked || strings.TrimSpace(rec.Body.String()) != `{"status":"error"}` {
			t.Errorf("%s on a slave: %d %q, want 423 {\"status\":\"error\"}", name, rec.Code, rec.Body.String())
		}
	}
}

// userChangePasswordHandler: the slave guard comes before the --auth.password check, so a slave
// answers 423 whatever the flag says (the master answers 501 when password auth is off).
func TestChangePasswordHandlerSlaveGuard(t *testing.T) {
	for _, authOn := range []bool{true, false} {
		setFlag(t, authByPassword, authOn)

		slave := &OvpnAdmin{role: "slave", createUserMutex: &sync.Mutex{}}
		rec := httptest.NewRecorder()
		slave.userChangePasswordHandler(rec, httptest.NewRequest(http.MethodPost, "/api/user/change-password?username=alice&password=x", nil))
		if rec.Code != http.StatusLocked || strings.TrimSpace(rec.Body.String()) != `{"status":"error"}` {
			t.Errorf("slave, authByPassword=%v: %d %q, want 423", authOn, rec.Code, rec.Body.String())
		}
	}

	setFlag(t, authByPassword, false)
	master := &OvpnAdmin{role: "master", createUserMutex: &sync.Mutex{}}
	rec := httptest.NewRecorder()
	master.userChangePasswordHandler(rec, httptest.NewRequest(http.MethodPost, "/api/user/change-password?username=alice&password=x", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("master with password auth off: %d, want 501", rec.Code)
	}
}

// No handler may log r.RequestURI (it carries the query string).
func TestNoRequestURIInSources(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "RequestURI") {
			t.Errorf("%s uses RequestURI, log r.URL.Path instead", f)
		}
	}
}

// F01: the sync token of the example files and the former built-in default are public.
func TestValidateSyncTokenConfig(t *testing.T) {
	cases := []struct {
		name, role, token string
		wantErr           string // substring of the error, empty = accepted
	}{
		{"example token rejected", "master", "TOKEN", "example value"},
		{"example token rejected on a slave", "slave", "TOKEN", "example value"},
		{"example token rejected whatever the case", "master", " token ", "example value"},
		{"built-in fallback rejected", "master", "VerySecureToken", "built-in default"},
		{"built-in fallback rejected on a slave", "slave", "VerySecureToken", "built-in default"},
		{"empty token rejected on a slave", "slave", "", "is empty"},
		{"blank token rejected on a slave", "slave", "   ", "is empty"},
		{"strong token accepted on a master", "master", "k7Qe-0p2xT9vN4mZs8LwUa3dRb6HcY1j", ""},
		{"strong token accepted on a slave", "slave", "k7Qe-0p2xT9vN4mZs8LwUa3dRb6HcY1j", ""},
		{"sync disabled (master, no token) accepted", "master", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateSyncTokenConfig(c.role, c.token)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("validateSyncTokenConfig(%q, %q) = %v, want nil", c.role, c.token, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("validateSyncTokenConfig(%q, %q) = %v, want an error containing %q", c.role, c.token, err, c.wantErr)
			}
			// the message names the kind of value, never the token itself
			for _, secret := range []string{"TOKEN", "VerySecureToken"} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Errorf("the error prints the token %q: %v", secret, err)
				}
			}
		})
	}
}

// The built-in default is gone: an unset --master.sync-token is the empty token (sync disabled).
func TestSyncTokenFlagHasNoBuiltInDefault(t *testing.T) {
	if *masterSyncToken == syncTokenBuiltinFallback || *masterSyncToken == syncTokenExample {
		t.Fatalf("--master.sync-token defaults to a public value")
	}
}

// A master without a sync token serves no archive, the empty request token included; before, the
// empty token matched an empty configuration.
func TestDownloadHandlersFailClosedWithoutSyncToken(t *testing.T) {
	for _, tc := range []struct{ configured, given string }{{"", ""}, {"  ", "%20%20"}, {"", "TOKEN"}, {"strong-secret-value", ""}, {"strong-secret-value", "wrong"}} {
		oAdmin := &OvpnAdmin{role: "master", masterSyncToken: tc.configured}
		for name, h := range map[string]http.HandlerFunc{"certs": oAdmin.downloadCertsHandler, "ccd": oAdmin.downloadCcdHandler} {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(http.MethodGet, "/api/data/"+name+"/download?token="+tc.given, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with configured %q, given %q: %d, want 403", name, tc.configured, tc.given, rec.Code)
			}
		}
	}
	if !syncTokenMatches("strong-secret-value", "strong-secret-value") {
		t.Error("the configured token does not match itself")
	}
	if syncTokenMatches("", "") {
		t.Error("the empty token matches the empty token")
	}
}

// the handlers that change state (disconnect included, it only echoes today)
func mutationHandlers(oAdmin *OvpnAdmin) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/api/user/create":          oAdmin.userCreateHandler,
		"/api/user/rotate":          oAdmin.userRotateHandler,
		"/api/user/delete":          oAdmin.userDeleteHandler,
		"/api/user/revoke":          oAdmin.userRevokeHandler,
		"/api/user/unrevoke":        oAdmin.userUnrevokeHandler,
		"/api/user/change-password": oAdmin.userChangePasswordHandler,
		"/api/user/disconnect":      oAdmin.userDisconnectHandler,
		"/api/user/ccd/apply":       oAdmin.userApplyCcdHandler,
	}
}

func formPost(path, user string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("username="+user+"&password="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// F02: every mutation route answers 405 to anything but POST, and does nothing.
func TestMutationRoutesRejectOtherMethods(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	if ok, msg := oAdmin.userCreate("alice", ""); !ok {
		t.Fatal(msg)
	}
	before := strings.Join(indexLines(t), ", ")

	for path, h := range mutationHandlers(oAdmin) {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
			rec := httptest.NewRecorder()
			h(rec, httptest.NewRequest(method, path+"?username=alice&password=", nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: %d, want 405", method, path, rec.Code)
			}
			if rec.Header().Get("Allow") != http.MethodPost {
				t.Errorf("%s %s: Allow = %q, want POST", method, path, rec.Header().Get("Allow"))
			}
			if method != http.MethodHead && (rec.Body.Len() == 0 || rec.Body.Len() > 100) {
				t.Errorf("%s %s: body %q, want a short message", method, path, rec.Body.String())
			}
		}
	}
	if got := strings.Join(indexLines(t), ", "); got != before {
		t.Errorf("index.txt changed: %s, want %s", got, before)
	}
}

// The method comes before the slave rule: a GET on a slave is 405, a POST is 423 as before.
func TestMutationRoutesMethodCheckComesBeforeSlaveRule(t *testing.T) {
	oAdmin := &OvpnAdmin{role: "slave", createUserMutex: &sync.Mutex{}}
	for path, h := range mutationHandlers(oAdmin) {
		if path == "/api/user/disconnect" {
			continue // no slave rule
		}
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s on a slave: %d, want 405", path, rec.Code)
		}
		rec = httptest.NewRecorder()
		h(rec, formPost(path, "alice", nil))
		if rec.Code != http.StatusLocked {
			t.Errorf("POST %s on a slave: %d, want 423", path, rec.Code)
		}
	}
}

// F02: a browser that names a foreign origin gets 403 and nothing happens.
func TestCrossSitePostIsRefusedAndChangesNothing(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	setNetworks(t, "172.16.100.0/24", "")
	ccdPath := setupCcdDir(t, nil)
	setFlag(t, ccdEnabled, true)
	if ok, msg := oAdmin.userCreate("alice", ""); !ok {
		t.Fatal(msg)
	}
	before := strings.Join(indexLines(t), ", ")

	foreign := []map[string]string{
		{"Origin": "https://evil.example"},
		{"Origin": "http://example.com:8081"}, // same host, other port
		{"Origin": "null"},                    // opaque origin (sandboxed frame, redirect)
		{"Origin": ""},                        // present but empty
		{"Origin": "garbage"},
		{"Referer": "https://evil.example/attack.html"},
		{"Referer": "https://example.com.evil.example/"},
		{"Origin": "http://example.com", "Referer": "https://evil.example/"}, // one good header does not excuse the other
		{"Origin": "https://evil.example", "Referer": "http://example.com/"},
	}
	for path, h := range mutationHandlers(oAdmin) {
		for _, headers := range foreign {
			req := formPost(path, "alice", headers)
			if _, set := headers["Origin"]; set && headers["Origin"] == "" {
				req.Header["Origin"] = []string{""} // Set("") keeps the key, make it explicit
			}
			if path == "/api/user/ccd/apply" {
				req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"User":"alice","ClientAddress":"172.16.100.77"}`))
				for k, v := range headers {
					req.Header.Set(k, v)
				}
			}
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s with %v: %d %q, want 403", path, headers, rec.Code, rec.Body.String())
			}
		}
	}

	// a new user, a revoke, a rotation, a delete, a ccd: none of it happened
	if got := strings.Join(indexLines(t), ", "); got != before {
		t.Errorf("index.txt changed: %s, want %s", got, before)
	}
	mustExist(t, pki, "issued/alice.crt", "private/alice.key")
	if _, err := os.Stat(filepath.Join(ccdPath, "alice")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a cross-site request wrote the ccd of alice: %v", err)
	}
}

// F02: same-origin and header-less requests keep working.
func TestSameOriginAndHeaderlessPostsSucceed(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	cases := []struct {
		user    string
		headers map[string]string
	}{
		{"noheaders", nil},
		{"origin", map[string]string{"Origin": "http://example.com"}},
		{"originupper", map[string]string{"Origin": "HTTP://EXAMPLE.COM"}},
		{"referer", map[string]string{"Referer": "http://example.com/some/page?x=1"}},
		{"both", map[string]string{"Origin": "https://example.com", "Referer": "https://example.com/"}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		oAdmin.userCreateHandler(rec, formPost("/api/user/create", c.user, c.headers))
		if rec.Code != http.StatusOK {
			t.Errorf("create %s with %v: %d %q, want 200", c.user, c.headers, rec.Code, rec.Body.String())
		}
	}
	want := "V both, V noheaders, V origin, V originupper, V referer"
	if got := strings.Join(indexLines(t), ", "); got != want {
		t.Errorf("index.txt = %s, want %s", got, want)
	}

	// a state change through the same gate: revoke, same origin then no origin
	rec := httptest.NewRecorder()
	oAdmin.userRevokeHandler(rec, formPost("/api/user/revoke", "origin", map[string]string{"Origin": "http://example.com"}))
	if rec.Code != http.StatusOK {
		t.Errorf("same-origin revoke: %d %q, want 200", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	oAdmin.userUnrevokeHandler(rec, formPost("/api/user/unrevoke", "origin", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("header-less unrevoke: %d %q, want 200", rec.Code, rec.Body.String())
	}

	// Host with a port
	req := formPost("/api/user/create", "ported", map[string]string{"Origin": "http://admin.local:8080"})
	req.Host = "admin.local:8080"
	rec = httptest.NewRecorder()
	oAdmin.userCreateHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("same-origin create on host:port: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

// the read-only routes the frontend polls stay open to GET
func TestReadRoutesStillAnswerGet(t *testing.T) {
	oAdmin := &OvpnAdmin{role: "master", lastSyncTime: "unknown", lastSuccessfulSyncTime: "unknown", modules: []string{"core"}}
	for path, h := range map[string]http.HandlerFunc{
		"/api/server/settings":      oAdmin.serverSettingsHandler,
		"/api/sync/last/try":        oAdmin.lastSyncTimeHandler,
		"/api/sync/last/successful": oAdmin.lastSuccessfulSyncTimeHandler,
	} {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", path, rec.Code)
		}
	}
}
