package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
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
