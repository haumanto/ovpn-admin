package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 2026-11-17T14:05:00Z
const auditT0 int64 = 1794924300

func auditLine(event string, ts int64, user, ip, port, v4, v6, rx, tx string) string {
	return strings.Join([]string{event, fmt.Sprint(ts), user, ip, port, v4, v6, rx, tx}, "\t")
}

// auditFixture covers every event type, "-" fields, dotted/hyphenated/underscored names and malformed lines.
func auditFixture() string {
	lines := []string{
		auditLine("auth_ok", auditT0-600, "alice", "203.0.113.4", "50000", "-", "-", "-", "-"),
		auditLine("connect", auditT0-500, "alice", "203.0.113.4", "50000", "172.16.100.10", "-", "-", "-"),
		auditLine("disconnect", auditT0-100, "alice", "203.0.113.4", "50000", "172.16.100.10", "-", "1234", "5678"),
		"this line is not an audit event",
		auditLine("connect", auditT0, "alice", "203.0.113.5", "50001", "172.16.100.10", "-", "-", "-"),
		auditLine("auth_fail", auditT0-50, "bob.smith", "198.51.100.7", "40000", "-", "-", "-", "-"),
		auditLine("auth_ok", auditT0-40, "bob.smith", "198.51.100.8", "40001", "-", "-", "-", "-"),
		auditLine("auth_ok", auditT0-30, "bob.smith", "198.51.100.9", "40002", "-", "-", "-", "-"),
		auditLine("connect", auditT0-20, "carol-jones", "192.0.2.1", "1194", "-", "fd00:16:100::5", "0", "0"),
		auditLine("connect", auditT0-10, "dave_x", "192.0.2.2", "1194", "172.16.100.20", "fd00:16:100::6", "-", "-"),
		"connect\tx\teve\t-\t-\t-\t-\t-\t-",     // bad time
		"connect\t1794924300\tfrank\t192.0.2.3", // too few fields
		auditLine("bogus", auditT0, "grace", "-", "-", "-", "-", "-", "-"),
		auditLine("connect", auditT0, "-", "192.0.2.4", "1", "-", "-", "-", "-"),          // no username
		auditLine("disconnect", auditT0, "heidi", "192.0.2.5", "1", "-", "-", "abc", "1"), // bad bytes
		"",
	}
	return strings.Join(lines, "\n") + "\n"
}

func writeAudit(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.tsv")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// useAudit points the handlers at path with a fresh cache.
func useAudit(t *testing.T, path string) {
	t.Helper()
	old := defaultAuditLog
	setFlag(t, auditPath, path)
	defaultAuditLog = newAuditLog(func() string { return *auditPath })
	t.Cleanup(func() { defaultAuditLog = old })
}

func getAudit(t *testing.T, query string) (int, auditResponse, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	(&OvpnAdmin{}).userAuditHandler(rec, httptest.NewRequest(http.MethodGet, "/api/user/audit"+query, nil))
	var resp auditResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("bad JSON %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, resp, rec.Body.String()
}

func TestParseAuditLine(t *testing.T) {
	ev, err := parseAuditLine(auditLine("disconnect", 100, "a.b-c_d", "203.0.113.1", "1", "172.16.100.2", "-", "10", "20"))
	if err != nil {
		t.Fatal(err)
	}
	want := auditEvent{Time: 100, Event: "disconnect", Username: "a.b-c_d", IP: "203.0.113.1", VirtualIP: "172.16.100.2", BytesReceived: 10, BytesSent: 20}
	if ev != want {
		t.Errorf("got %+v, want %+v", ev, want)
	}

	// "-" fields become empty / zero; an IPv6-only virtual address is used when there is no IPv4
	ev, err = parseAuditLine(auditLine("connect", 5, "u", "-", "-", "-", "fd00::1", "-", "-"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.IP != "" || ev.VirtualIP != "fd00::1" || ev.BytesReceived != 0 || ev.BytesSent != 0 {
		t.Errorf("unexpected %+v", ev)
	}

	for name, line := range map[string]string{
		"empty":         "",
		"garbage":       "hello",
		"few fields":    "connect\t1\tu",
		"extra field":   auditLine("connect", 1, "u", "-", "-", "-", "-", "-", "-") + "\textra",
		"unknown event": auditLine("login", 1, "u", "-", "-", "-", "-", "-", "-"),
		"bad time":      "connect\tx\tu\t-\t-\t-\t-\t-\t-",
		"negative time": "connect\t-5\tu\t-\t-\t-\t-\t-\t-",
		"no username":   auditLine("connect", 1, "-", "-", "-", "-", "-", "-", "-"),
		"bad bytes":     auditLine("disconnect", 1, "u", "-", "-", "-", "-", "x", "-"),
	} {
		if _, err := parseAuditLine(line); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestAuditIndexSkipsMalformedLines(t *testing.T) {
	idx, skipped := buildAuditIndex([]byte(auditFixture()))
	// garbage, bad time, too few fields, unknown event, no username, bad bytes; the blank line is ignored
	if skipped != 6 {
		t.Errorf("skipped = %d, want 6", skipped)
	}
	for _, u := range []string{"alice", "bob.smith", "carol-jones", "dave_x"} {
		if len(idx.byUser[u]) == 0 {
			t.Errorf("no events for %s", u)
		}
	}
	for _, u := range []string{"eve", "frank", "grace", "-", "heidi"} {
		if len(idx.byUser[u]) != 0 {
			t.Errorf("malformed line produced events for %q", u)
		}
	}
}

func TestLastLoginSelection(t *testing.T) {
	idx, _ := buildAuditIndex([]byte(auditFixture()))

	// newest connect wins over a (newer or older) auth_ok
	ev, ok := idx.lastLogin("alice")
	if !ok || ev.Time != auditT0 || ev.Event != "connect" || ev.IP != "203.0.113.5" {
		t.Errorf("alice: %+v %v", ev, ok)
	}
	newerAuth := auditLine("connect", 100, "zed", "192.0.2.1", "1", "-", "-", "-", "-") + "\n" +
		auditLine("auth_ok", 200, "zed", "192.0.2.99", "1", "-", "-", "-", "-") + "\n"
	idx2, _ := buildAuditIndex([]byte(newerAuth))
	if ev, ok := idx2.lastLogin("zed"); !ok || ev.Event != "connect" || ev.IP != "192.0.2.1" {
		t.Errorf("connect must win over a newer auth_ok: %+v %v", ev, ok)
	}

	// auth_fail does not count; auth_ok is the fallback and the newest one is used
	ev, ok = idx.lastLogin("bob.smith")
	if !ok || ev.Event != "auth_ok" || ev.IP != "198.51.100.9" || ev.Time != auditT0-30 {
		t.Errorf("bob.smith: %+v %v", ev, ok)
	}

	// only disconnect / auth_fail: no login
	idx3, _ := buildAuditIndex([]byte(
		auditLine("disconnect", 1, "x", "-", "-", "-", "-", "-", "-") + "\n" +
			auditLine("auth_fail", 2, "x", "-", "-", "-", "-", "-", "-") + "\n"))
	if _, ok := idx3.lastLogin("x"); ok {
		t.Error("disconnect/auth_fail must not count as login")
	}
	if _, ok := idx.lastLogin("nobody"); ok {
		t.Error("unknown user has a login")
	}
	if _, ok := (*auditIndex)(nil).lastLogin("alice"); ok {
		t.Error("nil index has a login")
	}
}

func TestUsersListHandlerLastLogin(t *testing.T) {
	useAudit(t, writeAudit(t, auditFixture()))
	oAdmin := &OvpnAdmin{clients: []OpenvpnClient{
		{Identity: "alice", AccountStatus: "Active", Connections: 2},
		{Identity: "bob.smith"},
		{Identity: "carol-jones"},
		{Identity: "dave_x"},
		{Identity: "nobody"},
	}}
	rec := httptest.NewRecorder()
	oAdmin.userListHandler(rec, httptest.NewRequest(http.MethodGet, "/api/users/list", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var got []OpenvpnClient
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"alice":       {auditTimeString(auditT0), "203.0.113.5"},
		"bob.smith":   {auditTimeString(auditT0 - 30), "198.51.100.9"},
		"carol-jones": {auditTimeString(auditT0 - 20), "192.0.2.1"},
		"dave_x":      {auditTimeString(auditT0 - 10), "192.0.2.2"},
		"nobody":      {"", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d users", len(got))
	}
	for _, c := range got {
		w := want[c.Identity]
		if c.LastLogin != w[0] || c.LastLoginIP != w[1] {
			t.Errorf("%s: LastLogin=%q LastLoginIP=%q, want %q %q", c.Identity, c.LastLogin, c.LastLoginIP, w[0], w[1])
		}
	}
	if got[0].AccountStatus != "Active" || got[0].Connections != 2 {
		t.Errorf("existing fields changed: %+v", got[0])
	}
	if got[0].LastLogin != "2026-11-17T14:05:00Z" {
		t.Errorf("RFC3339 UTC expected, got %q", got[0].LastLogin)
	}
	// the cached client list itself is not modified
	if oAdmin.clients[0].LastLogin != "" {
		t.Error("handler mutated oAdmin.clients")
	}
	// the JSON keys are present even when empty
	if !strings.Contains(rec.Body.String(), `"Identity":"nobody","AccountStatus":"","ExpirationDate":"","RevocationDate":"","ConnectionStatus":"","Connections":0,"LastLogin":"","LastLoginIP":""`) {
		t.Errorf("unexpected JSON for empty history: %s", rec.Body.String())
	}
}

func TestUsersListHandlerMissingAuditFile(t *testing.T) {
	useAudit(t, filepath.Join(t.TempDir(), "does-not-exist.tsv"))
	oAdmin := &OvpnAdmin{clients: []OpenvpnClient{{Identity: "alice"}}}
	rec := httptest.NewRecorder()
	oAdmin.userListHandler(rec, httptest.NewRequest(http.MethodGet, "/api/users/list", nil))
	var got []OpenvpnClient
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || len(got) != 1 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if got[0].LastLogin != "" || got[0].LastLoginIP != "" {
		t.Errorf("missing file must give empty fields: %+v", got[0])
	}
}

func TestAuditEndpointOrderingAndFields(t *testing.T) {
	useAudit(t, writeAudit(t, auditFixture()))

	code, resp, _ := getAudit(t, "?username=alice")
	if code != http.StatusOK || resp.Username != "alice" {
		t.Fatalf("code %d resp %+v", code, resp)
	}
	wantEvents := []auditEventJSON{
		{Time: auditTimeString(auditT0), Event: "connect", IP: "203.0.113.5", VirtualIP: "172.16.100.10"},
		{Time: auditTimeString(auditT0 - 100), Event: "disconnect", IP: "203.0.113.4", VirtualIP: "172.16.100.10", BytesReceived: 1234, BytesSent: 5678},
		{Time: auditTimeString(auditT0 - 500), Event: "connect", IP: "203.0.113.4", VirtualIP: "172.16.100.10"},
		{Time: auditTimeString(auditT0 - 600), Event: "auth_ok", IP: "203.0.113.4"},
	}
	if len(resp.Events) != len(wantEvents) {
		t.Fatalf("got %d events: %+v", len(resp.Events), resp.Events)
	}
	for i, w := range wantEvents {
		if resp.Events[i] != w {
			t.Errorf("event %d = %+v, want %+v", i, resp.Events[i], w)
		}
	}

	// auth_fail carries the IP and an empty virtual IP; names with dots work
	_, resp, _ = getAudit(t, "?username=bob.smith")
	if len(resp.Events) != 3 || resp.Events[2].Event != "auth_fail" || resp.Events[2].IP != "198.51.100.7" ||
		resp.Events[2].VirtualIP != "" || resp.Events[2].BytesReceived != 0 {
		t.Errorf("bob.smith: %+v", resp.Events)
	}

	// IPv6 virtual address when no IPv4; hyphenated and underscored names
	_, resp, _ = getAudit(t, "?username=carol-jones")
	if len(resp.Events) != 1 || resp.Events[0].VirtualIP != "fd00:16:100::5" {
		t.Errorf("carol-jones: %+v", resp.Events)
	}
	_, resp, _ = getAudit(t, "?username=dave_x")
	if len(resp.Events) != 1 || resp.Events[0].VirtualIP != "172.16.100.20" {
		t.Errorf("dave_x: %+v", resp.Events)
	}

	// exact wire format
	_, _, body := getAudit(t, "?username=carol-jones")
	wantBody := `{"username":"carol-jones","events":[{"Time":"` + auditTimeString(auditT0-20) +
		`","Event":"connect","IP":"192.0.2.1","VirtualIP":"fd00:16:100::5","BytesReceived":0,"BytesSent":0}]}`
	if body != wantBody {
		t.Errorf("body\n got %s\nwant %s", body, wantBody)
	}
}

func TestAuditEndpointSortsOutOfOrderLines(t *testing.T) {
	content := auditLine("connect", 300, "u", "192.0.2.3", "1", "-", "-", "-", "-") + "\n" +
		auditLine("connect", 100, "u", "192.0.2.1", "1", "-", "-", "-", "-") + "\n" +
		auditLine("connect", 200, "u", "192.0.2.2", "1", "-", "-", "-", "-") + "\n" +
		auditLine("connect", 200, "u", "192.0.2.22", "1", "-", "-", "-", "-") + "\n"
	useAudit(t, writeAudit(t, content))
	_, resp, _ := getAudit(t, "?username=u")
	var ips []string
	for _, e := range resp.Events {
		ips = append(ips, e.IP)
	}
	if got := strings.Join(ips, ","); got != "192.0.2.3,192.0.2.22,192.0.2.2,192.0.2.1" {
		t.Errorf("order = %s", got)
	}
}

func TestAuditEndpointLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 600; i++ {
		sb.WriteString(auditLine("connect", int64(1000+i), "busy", "192.0.2.1", "1", "-", "-", "-", "-") + "\n")
	}
	useAudit(t, writeAudit(t, sb.String()))

	for query, want := range map[string]int{
		"?username=busy":                50,
		"?username=busy&limit=":         50,
		"?username=busy&limit=3":        3,
		"?username=busy&limit=500":      500,
		"?username=busy&limit=501":      500,
		"?username=busy&limit=99999999": 500,
		"?username=busy&limit=1":        1,
	} {
		code, resp, _ := getAudit(t, query)
		if code != http.StatusOK || len(resp.Events) != want {
			t.Errorf("%s: code %d, %d events, want %d", query, code, len(resp.Events), want)
		}
	}
	// newest first under a limit
	_, resp, _ := getAudit(t, "?username=busy&limit=2")
	if resp.Events[0].Time != auditTimeString(1599) || resp.Events[1].Time != auditTimeString(1598) {
		t.Errorf("limit must keep the newest: %+v", resp.Events)
	}
	for _, q := range []string{"?username=busy&limit=0", "?username=busy&limit=-1", "?username=busy&limit=abc"} {
		if code, _, _ := getAudit(t, q); code != http.StatusBadRequest {
			t.Errorf("%s: code %d, want 400", q, code)
		}
	}
}

func TestAuditEndpointUnknownAndMissingUser(t *testing.T) {
	useAudit(t, writeAudit(t, auditFixture()))

	code, _, body := getAudit(t, "?username=nobody")
	if code != http.StatusOK || body != `{"username":"nobody","events":[]}` {
		t.Errorf("unknown user: %d %s", code, body)
	}
	for _, q := range []string{"", "?username=", "?username=%20%20", "?limit=5"} {
		if code, _, _ := getAudit(t, q); code != http.StatusBadRequest {
			t.Errorf("%q: code %d, want 400", q, code)
		}
	}

	// only GET/HEAD
	rec := httptest.NewRecorder()
	(&OvpnAdmin{}).userAuditHandler(rec, httptest.NewRequest(http.MethodPost, "/api/user/audit?username=alice", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}

func TestAuditEndpointMissingFile(t *testing.T) {
	useAudit(t, filepath.Join(t.TempDir(), "nope", "audit.tsv"))
	code, _, body := getAudit(t, "?username=alice")
	if code != http.StatusOK || body != `{"username":"alice","events":[]}` {
		t.Errorf("missing file: %d %s", code, body)
	}
	// empty path (audit disabled) is also an empty history
	useAudit(t, "")
	code, _, body = getAudit(t, "?username=alice")
	if code != http.StatusOK || body != `{"username":"alice","events":[]}` {
		t.Errorf("empty path: %d %s", code, body)
	}
}

func TestAuditEndpointOnlyMalformedFile(t *testing.T) {
	useAudit(t, writeAudit(t, "garbage\n\x00\x01\x02\n\t\t\t\n"))
	code, _, body := getAudit(t, "?username=alice")
	if code != http.StatusOK || body != `{"username":"alice","events":[]}` {
		t.Errorf("%d %s", code, body)
	}
}

func TestAuditReadsOnlyLastTwoMiB(t *testing.T) {
	old := auditLine("connect", 1, "ancient", "192.0.2.1", "1", "-", "-", "-", "-") + "\n"
	filler := auditLine("auth_fail", 2, "noise", "192.0.2.9", "1", "-", "-", "-", "-") + "\n"
	recent := auditLine("connect", 3, "recent", "192.0.2.2", "1", "-", "-", "-", "-") + "\n"

	var sb strings.Builder
	sb.WriteString(old)
	for sb.Len() < auditMaxReadBytes+len(old)+1000 {
		sb.WriteString(filler)
	}
	sb.WriteString(recent)
	path := writeAudit(t, sb.String())

	data, info, err := readAuditTail(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > auditMaxReadBytes {
		t.Errorf("read %d bytes, limit %d", len(data), auditMaxReadBytes)
	}
	if info.Size() != int64(sb.Len()) {
		t.Errorf("info size %d", info.Size())
	}
	idx, skipped := buildAuditIndex(data)
	if skipped != 0 {
		t.Errorf("truncation left a partial line: %d malformed", skipped)
	}
	if len(idx.byUser["ancient"]) != 0 {
		t.Error("line before the 2 MiB window was read")
	}
	if len(idx.byUser["recent"]) != 1 {
		t.Error("newest line missing")
	}
}

func TestAuditTailWindowOnLineBoundary(t *testing.T) {
	// every line is exactly 64 bytes (the real port field is padding), so the 2 MiB window starts
	// exactly at the beginning of line k: that line must be kept, the one before must not
	mk := func(user string) string {
		base := auditLine("auth_fail", 2, user, "192.0.2.9", "", "-", "-", "-", "-") + "\n"
		return auditLine("auth_fail", 2, user, "192.0.2.9", strings.Repeat("7", 64-len(base)), "-", "-", "-", "-") + "\n"
	}
	const k = 10
	lines := auditMaxReadBytes/64 + k
	var sb strings.Builder
	for i := 0; i < lines; i++ {
		switch i {
		case k - 1:
			sb.WriteString(mk("before"))
		case k:
			sb.WriteString(mk("boundary"))
		default:
			sb.WriteString(mk("noise"))
		}
	}
	if len(mk("boundary")) != 64 || sb.Len() != auditMaxReadBytes+k*64 {
		t.Fatalf("fixture sizes: line %d total %d", len(mk("boundary")), sb.Len())
	}
	data, _, err := readAuditTail(writeAudit(t, sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	idx, skipped := buildAuditIndex(data)
	if skipped != 0 || len(idx.byUser["boundary"]) != 1 || len(idx.byUser["before"]) != 0 {
		t.Errorf("skipped=%d boundary=%d before=%d", skipped, len(idx.byUser["boundary"]), len(idx.byUser["before"]))
	}
}

func TestAuditCache(t *testing.T) {
	path := writeAudit(t, auditLine("connect", 10, "alice", "192.0.2.1", "1", "-", "-", "-", "-")+"\n")
	clock := time.Unix(1_800_000_000, 0)
	a := newAuditLog(func() string { return path })
	a.now = func() time.Time { return clock }

	idx1 := a.index()
	if a.reads != 1 || len(idx1.byUser["alice"]) != 1 {
		t.Fatalf("first call: reads=%d", a.reads)
	}
	// unchanged file inside the TTL: no re-read, same index
	clock = clock.Add(4 * time.Second)
	if idx2 := a.index(); idx2 != idx1 || a.reads != 1 {
		t.Errorf("second call within 5s re-read the file (reads=%d)", a.reads)
	}

	// TTL expiry refreshes even if the key is unchanged
	clock = clock.Add(2 * time.Second)
	a.index()
	if a.reads != 2 {
		t.Errorf("after TTL: reads=%d, want 2", a.reads)
	}

	// changed mtime (same size) invalidates inside the TTL
	st, _ := os.Stat(path)
	newTime := st.ModTime().Add(time.Hour)
	if err := os.Chtimes(path, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	a.index()
	if a.reads != 3 {
		t.Errorf("changed mtime did not invalidate: reads=%d", a.reads)
	}
	a.index()
	if a.reads != 3 {
		t.Errorf("unchanged file re-read: reads=%d", a.reads)
	}

	// an append (changed size) invalidates and shows the new event
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(f, auditLine("connect", 20, "alice", "192.0.2.2", "1", "-", "-", "-", "-")+"\n")
	f.Close()
	idx := a.index()
	if a.reads != 4 || len(idx.byUser["alice"]) != 2 {
		t.Errorf("append: reads=%d events=%d", a.reads, len(idx.byUser["alice"]))
	}

	// the file disappears: empty history, no error; it comes back: read again
	os.Remove(path)
	if got := a.index(); len(got.byUser) != 0 {
		t.Error("deleted file still has events")
	}
	if err := os.WriteFile(path, []byte(auditLine("connect", 30, "bob", "192.0.2.3", "1", "-", "-", "-", "-")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := a.index(); len(got.byUser["bob"]) != 1 {
		t.Error("recreated file not read")
	}
}

func TestAuditCacheFollowsPathChange(t *testing.T) {
	p1 := writeAudit(t, auditLine("connect", 10, "one", "192.0.2.1", "1", "-", "-", "-", "-")+"\n")
	p2 := writeAudit(t, auditLine("connect", 10, "two", "192.0.2.2", "1", "-", "-", "-", "-")+"\n")
	path := p1
	a := newAuditLog(func() string { return path })
	if len(a.index().byUser["one"]) != 1 {
		t.Fatal("p1 not read")
	}
	path = p2
	if idx := a.index(); len(idx.byUser["two"]) != 1 || len(idx.byUser["one"]) != 0 {
		t.Error("cache served the old path")
	}
}

func TestAuditCacheConcurrent(t *testing.T) {
	path := writeAudit(t, auditFixture())
	a := newAuditLog(func() string { return path })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, ok := a.index().lastLogin("alice"); !ok {
					t.Error("alice has no login")
					return
				}
			}
		}()
	}
	wg.Wait()
	if a.reads != 1 {
		t.Errorf("reads = %d, want 1 inside the TTL", a.reads)
	}
}
