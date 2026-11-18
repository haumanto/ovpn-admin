package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// useControlDir points --audit.path at a temp dir that has a control subdirectory, as the watcher creates it.
func useControlDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	setFlag(t, auditPath, filepath.Join(dir, "audit.tsv"))
	ctl := filepath.Join(dir, banControlDirName)
	if err := os.Mkdir(ctl, 0o700); err != nil {
		t.Fatal(err)
	}
	return ctl
}

// fakeWatcher answers every <id>.req of dir with the given result until the test ends and reports the requests.
func fakeWatcher(t *testing.T, dir string, ok bool, message string) <-chan banControlRequest {
	t.Helper()
	seen := make(chan banControlRequest, 16)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			names, _ := filepath.Glob(filepath.Join(dir, "*.req"))
			for _, name := range names {
				data, err := os.ReadFile(name)
				if err != nil {
					continue
				}
				var req banControlRequest
				if json.Unmarshal(data, &req) != nil {
					continue
				}
				_ = os.Remove(name)
				out, _ := json.Marshal(banControlResult{OK: ok, Message: message})
				_ = os.WriteFile(filepath.Join(dir, req.ID+".result"), out, 0o600)
				seen <- req
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
	return seen
}

func postControl(t *testing.T, role, method, path string, form url.Values) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a := &OvpnAdmin{role: role}
	if strings.HasSuffix(path, "unban") {
		a.unbanHandler(rec, req)
	} else {
		a.banManualHandler(rec, req)
	}
	return rec.Code, rec.Body.String(), rec.Header()
}

func TestValidateBanIP(t *testing.T) {
	good := map[string]string{
		"198.51.100.7":       "198.51.100.7",
		"2001:db8::1":        "2001:db8::1",
		"2001:DB8:0:0:0::1":  "2001:db8::1",
		"::ffff:203.0.113.9": "203.0.113.9",
	}
	for in, want := range good {
		got, err := validateBanIP(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", " ", "not-an-ip", "1.2.3", "1.2.3.4.5", "1.2.3.4/32", "1.2.3.4;reboot", "1.2.3.4 ", " 1.2.3.4", "1.2.3.4\n", "999.1.1.1",
		"127.0.0.1", "127.8.8.8", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "224.0.0.1", "239.255.255.250", "ff02::1", "ff00::1",
		"169.254.1.1", "fe80::1", "fe80::1%eth0", "../../etc/passwd", "a.b.c.d",
	}
	for _, in := range bad {
		if got, err := validateBanIP(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestValidateBanReason(t *testing.T) {
	for _, ok := range []string{"", "scanner", "port scan, see ticket #42 (x)", strings.Repeat("a", 120)} {
		if err := validateBanReason(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{strings.Repeat("a", 121), "tab\there", "line\nbreak", "cr\rhere", "nul\x00", "del\x7f", "caf\u00e9", "\u2603"} {
		if err := validateBanReason(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBanControlIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id, err := newBanControlID()
		if err != nil || len(id) != 32 || !validBanControlID(id) || seen[id] {
			t.Fatalf("id %q err %v dup %v", id, err, seen[id])
		}
		seen[id] = true
	}
	for _, ok := range []string{"a", "A_b-9", strings.Repeat("x", 64)} {
		if !validBanControlID(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", strings.Repeat("x", 65), "../x", "a/b", `a\b`, "a.b", "..", ".", "a b", "a\x00b", "x.req", "\u00e9", "a\n"} {
		if validBanControlID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWriteBanControlRequestPathTraversal(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "control")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../evil", "../../evil", "a/b", "/etc/passwd", "..", "", "x\x00y"} {
		if err := writeBanControlRequest(dir, banControlRequest{ID: id, Action: "ban", IP: "198.51.100.1"}); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	entries, _ := os.ReadDir(base)
	if len(entries) != 1 || entries[0].Name() != "control" {
		t.Errorf("files outside the control dir: %v", entries)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("files in the control dir: %v", left)
	}
}

func TestWriteBanControlRequestFormat(t *testing.T) {
	dir := t.TempDir()
	req := banControlRequest{ID: "abc123", Action: "ban", IP: "198.51.100.1", Reason: "note"}
	if err := writeBanControlRequest(dir, req); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "abc123.req"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v %v", st, err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "abc123.req"))
	if string(data) != `{"id":"abc123","action":"ban","ip":"198.51.100.1","reason":"note"}` {
		t.Errorf("body %s", data)
	}
	if tmp, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(tmp) != 0 {
		t.Errorf("temporary file left: %v", tmp)
	}
	// a missing directory is a write failure, never created here
	if err := writeBanControlRequest(filepath.Join(dir, "missing"), req); err == nil {
		t.Error("write into a missing directory succeeded")
	}
}

func TestReadBanControlResult(t *testing.T) {
	dir := t.TempDir()
	put := func(id, content string) {
		if err := os.WriteFile(filepath.Join(dir, id+".result"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := readBanControlResult(dir, "none"); found || err != nil {
		t.Errorf("missing: found %v err %v", found, err)
	}
	put("ok", `{"ok":true,"message":"banned 198.51.100.1 permanently"}`)
	if res, found, err := readBanControlResult(dir, "ok"); !found || err != nil || !res.OK || res.Message != "banned 198.51.100.1 permanently" {
		t.Errorf("ok: %+v %v %v", res, found, err)
	}
	put("no", `{"ok":false,"message":"nope"}`)
	if res, found, err := readBanControlResult(dir, "no"); !found || err != nil || res.OK || res.Message != "nope" {
		t.Errorf("no: %+v %v %v", res, found, err)
	}
	put("junk", `not json`)
	if _, found, err := readBanControlResult(dir, "junk"); !found || !errors.Is(err, errBanControlResult) {
		t.Errorf("junk: found %v err %v", found, err)
	}
	put("big", `{"ok":true,"message":"`+strings.Repeat("a", 5000)+`"}`)
	if _, found, err := readBanControlResult(dir, "big"); !found || !errors.Is(err, errBanControlResult) {
		t.Errorf("big: found %v err %v", found, err)
	}
	// a symlink is never followed
	if err := os.Symlink(filepath.Join(dir, "ok.result"), filepath.Join(dir, "link.result")); err != nil {
		t.Fatal(err)
	}
	if _, found, err := readBanControlResult(dir, "link"); !found || !errors.Is(err, errBanControlResult) {
		t.Errorf("link: found %v err %v", found, err)
	}
}

func TestSubmitBanControlTimeout(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	_, err := submitBanControl(context.Background(), dir, "ban", "198.51.100.1", "", 300*time.Millisecond)
	if !errors.Is(err, errBanControlTimeout) {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 3*time.Second {
		t.Errorf("waited %v", d)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("request left behind after timeout: %v", left)
	}
}

func TestSubmitBanControlCleansResult(t *testing.T) {
	dir := t.TempDir()
	seen := fakeWatcher(t, dir, true, "done")
	res, err := submitBanControl(context.Background(), dir, "unban", "198.51.100.1", "", 3*time.Second)
	if err != nil || !res.OK || res.Message != "done" {
		t.Fatalf("%+v %v", res, err)
	}
	req := <-seen
	if req.Action != "unban" || req.IP != "198.51.100.1" || !validBanControlID(req.ID) {
		t.Errorf("request %+v", req)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("files left: %v", left)
	}
}

func TestBanManualEndpoint(t *testing.T) {
	ctl := useControlDir(t)
	seen := fakeWatcher(t, ctl, true, "banned 198.51.100.77 permanently")
	code, body, hdr := postControl(t, "master", http.MethodPost, "/api/ban/manual", url.Values{"ip": {"198.51.100.77"}, "reason": {"port scan"}})
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") || !strings.Contains(body, `"status":"ok"`) {
		t.Fatalf("code %d body %s", code, body)
	}
	req := <-seen
	if req.Action != "ban" || req.IP != "198.51.100.77" || req.Reason != "port scan" {
		t.Errorf("request %+v", req)
	}
	if left, _ := filepath.Glob(filepath.Join(ctl, "*")); len(left) != 0 {
		t.Errorf("files left: %v", left)
	}
}

func TestUnbanEndpoint(t *testing.T) {
	ctl := useControlDir(t)
	seen := fakeWatcher(t, ctl, true, "unbanned")
	// a note on unban is ignored: unban always carries an empty reason
	code, _, _ := postControl(t, "master", http.MethodPost, "/api/unban", url.Values{"ip": {"2001:db8::5"}, "reason": {"x"}})
	if code != http.StatusOK {
		t.Fatalf("code %d", code)
	}
	req := <-seen
	if req.Action != "unban" || req.IP != "2001:db8::5" || req.Reason != "" {
		t.Errorf("request %+v", req)
	}
}

func TestBanControlEndpointRejected(t *testing.T) {
	ctl := useControlDir(t)
	fakeWatcher(t, ctl, false, "ovpn-ban: failed")
	code, body, _ := postControl(t, "master", http.MethodPost, "/api/ban/manual", url.Values{"ip": {"198.51.100.1"}})
	if code != http.StatusBadRequest || !strings.Contains(body, `"message":"ovpn-ban: failed"`) {
		t.Errorf("code %d body %s", code, body)
	}
}

func TestBanControlEndpointInvalidInput(t *testing.T) {
	ctl := useControlDir(t)
	cases := []url.Values{
		{},
		{"ip": {""}},
		{"ip": {"nonsense"}},
		{"ip": {"127.0.0.1"}},
		{"ip": {"0.0.0.0"}},
		{"ip": {"224.0.0.5"}},
		{"ip": {"169.254.0.9"}},
		{"ip": {"fe80::1"}},
		{"ip": {"1.2.3.4"}, "reason": {strings.Repeat("a", 121)}},
		{"ip": {"1.2.3.4"}, "reason": {"a\tb"}},
		{"ip": {"1.2.3.4"}, "reason": {"a\nb"}},
	}
	for _, form := range cases {
		code, body, _ := postControl(t, "master", http.MethodPost, "/api/ban/manual", form)
		if code != http.StatusBadRequest || !strings.Contains(body, `"status":"error"`) {
			t.Errorf("%v: code %d body %s", form, code, body)
		}
	}
	// nothing was queued
	if left, _ := filepath.Glob(filepath.Join(ctl, "*")); len(left) != 0 {
		t.Errorf("requests queued for invalid input: %v", left)
	}
	if code, _, _ := postControl(t, "master", http.MethodPost, "/api/unban", url.Values{"ip": {"::1"}}); code != http.StatusBadRequest {
		t.Errorf("unban loopback: code %d", code)
	}
}

func TestBanControlEndpointSlave(t *testing.T) {
	ctl := useControlDir(t)
	for _, path := range []string{"/api/ban/manual", "/api/unban"} {
		code, body, _ := postControl(t, "slave", http.MethodPost, path, url.Values{"ip": {"198.51.100.1"}})
		if code != http.StatusBadRequest || body != `{"status":"error"}`+"\n" {
			t.Errorf("%s: code %d body %q", path, code, body)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(ctl, "*")); len(left) != 0 {
		t.Errorf("slave queued: %v", left)
	}
}

func TestBanControlEndpointMethods(t *testing.T) {
	useControlDir(t)
	for _, path := range []string{"/api/ban/manual", "/api/unban"} {
		for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			code, _, hdr := postControl(t, "master", m, path, url.Values{"ip": {"198.51.100.1"}})
			if code != http.StatusMethodNotAllowed || hdr.Get("Allow") != "POST" {
				t.Errorf("%s %s: code %d Allow %q", m, path, code, hdr.Get("Allow"))
			}
		}
	}
}

func TestBanControlEndpointCrossSite(t *testing.T) {
	useControlDir(t)
	req := httptest.NewRequest(http.MethodPost, "/api/unban", strings.NewReader("ip=198.51.100.1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	(&OvpnAdmin{role: "master"}).unbanHandler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("code %d", rec.Code)
	}
}

func TestBanControlEndpointNoAuditPathAndNoDir(t *testing.T) {
	setFlag(t, auditPath, "")
	if code, _, _ := postControl(t, "master", http.MethodPost, "/api/unban", url.Values{"ip": {"198.51.100.1"}}); code != http.StatusInternalServerError {
		t.Errorf("no audit path: code %d", code)
	}
	// audit dir without a control subdirectory: local write failure, the path is not leaked
	dir := t.TempDir()
	setFlag(t, auditPath, filepath.Join(dir, "audit.tsv"))
	code, body, _ := postControl(t, "master", http.MethodPost, "/api/unban", url.Values{"ip": {"198.51.100.1"}})
	if code != http.StatusInternalServerError || strings.Contains(body, dir) {
		t.Errorf("missing dir: code %d body %s", code, body)
	}
}

func TestBanControlEndpointTimeout(t *testing.T) {
	ctl := useControlDir(t)
	setFlag(t, &banControlWait, 200*time.Millisecond)
	start := time.Now()
	code, body, _ := postControl(t, "master", http.MethodPost, "/api/ban/manual", url.Values{"ip": {"198.51.100.1"}})
	if code != http.StatusGatewayTimeout || !strings.Contains(body, `"status":"error"`) {
		t.Errorf("code %d body %s", code, body)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 3*time.Second {
		t.Errorf("waited %v", d)
	}
	if left, _ := filepath.Glob(filepath.Join(ctl, "*")); len(left) != 0 {
		t.Errorf("request left after 504: %v", left)
	}
}

func TestParseBansPermanent(t *testing.T) {
	now := time.Unix(banNow, 0)
	data := strings.Join([]string{
		banRow("198.51.100.1", banNow-100, 0, "0", "manual"),
		banRow("198.51.100.2", banNow-200, banNow+100, "1", "auth-failed"),
		banRow("198.51.100.3", banNow-300, banNow-1, "1", "expired"),
		banRow("198.51.100.4", banNow-400, -1, "1", "negative"),
	}, "\n")
	bans, skipped := parseBans([]byte(data), now)
	if skipped != 1 || len(bans) != 2 {
		t.Fatalf("bans %+v skipped %d", bans, skipped)
	}
	if !bans[0].permanent() || bans[0].IP != "198.51.100.1" || bans[1].permanent() {
		t.Errorf("bans %+v", bans)
	}
	// permanent even with a very late clock
	late, _ := parseBans([]byte(data), time.Unix(banNow*3, 0))
	if len(late) != 1 || late[0].IP != "198.51.100.1" {
		t.Errorf("late %+v", late)
	}
}

func TestBansEndpointPermanentRow(t *testing.T) {
	now := time.Now().Unix()
	useBans(t, banRow("198.51.100.1", now-60, 0, "0", "manual")+"\n"+banRow("198.51.100.2", now-30, now+600, "2", "auth-failed")+"\n")
	code, resp, body, _ := getBans(t, http.MethodGet)
	if code != http.StatusOK || len(resp.Bans) != 2 {
		t.Fatalf("code %d body %s", code, body)
	}
	temp, perm := resp.Bans[0], resp.Bans[1]
	if temp.IP != "198.51.100.2" || temp.Permanent || temp.ExpiresAt != auditTimeString(now+600) {
		t.Errorf("temporary %+v", temp)
	}
	if perm.IP != "198.51.100.1" || !perm.Permanent || perm.ExpiresAt != "" || perm.Reason != "manual" {
		t.Errorf("permanent %+v", perm)
	}
	for _, key := range []string{`"permanent":true`, `"permanent":false`, `"expires_at":""`} {
		if !strings.Contains(body, key) {
			t.Errorf("body %s lacks %s", body, key)
		}
	}
}
