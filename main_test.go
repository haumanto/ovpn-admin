package main

import (
	"bytes"
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
