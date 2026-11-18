package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 2026-11-17T15:30:00Z
const banNow int64 = 1794929400

func banRow(ip string, bannedAt, expiresAt int64, failures, reason string) string {
	return strings.Join([]string{ip, fmt.Sprint(bannedAt), fmt.Sprint(expiresAt), failures, reason}, "\t")
}

// useBans writes content to bans.tsv next to a fake audit log and points --audit.path at it.
func useBans(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	setFlag(t, auditPath, filepath.Join(dir, "audit.tsv"))
	path := filepath.Join(dir, "bans.tsv")
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func getBans(t *testing.T, method string) (int, bansResponse, string, http.Header) {
	t.Helper()
	rec := httptest.NewRecorder()
	(&OvpnAdmin{}).bansHandler(rec, httptest.NewRequest(method, "/api/bans", nil))
	var resp bansResponse
	if rec.Code == http.StatusOK && method == http.MethodGet {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("bad JSON %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, resp, rec.Body.String(), rec.Header()
}

func TestBanListPath(t *testing.T) {
	setFlag(t, auditPath, "/var/log/openvpn-audit/audit.tsv")
	if got := banListPath(); got != "/var/log/openvpn-audit/bans.tsv" {
		t.Errorf("banListPath = %q", got)
	}
	setFlag(t, auditPath, "")
	if got := banListPath(); got != "" {
		t.Errorf("banListPath with empty audit path = %q", got)
	}
}

func TestParseBanLine(t *testing.T) {
	good, err := parseBanLine(banRow("146.70.195.37", banNow, banNow+3600, "3", "certificate revoked or auth failure"))
	if err != nil {
		t.Fatal(err)
	}
	want := banEntry{IP: "146.70.195.37", BannedAt: banNow, ExpiresAt: banNow + 3600, Failures: 3, Reason: "certificate revoked or auth failure"}
	if good != want {
		t.Errorf("got %+v, want %+v", good, want)
	}

	// empty reason and IPv6 are fine; CRLF is tolerated
	if b, err := parseBanLine(banRow("2001:db8::1", 1, 2, "0", "") + "\r"); err != nil || b.IP != "2001:db8::1" || b.Reason != "" {
		t.Errorf("ipv6/empty reason: %+v, %v", b, err)
	}

	bad := map[string]string{
		"empty":            "",
		"too few fields":   "1.2.3.4\t1\t2\t3",
		"bad ip":           banRow("not-an-ip", 1, 2, "1", "x"),
		"shell in ip":      banRow("1.2.3.4;rm", 1, 2, "1", "x"),
		"bad banned_at":    banRow("1.2.3.4", 0, 2, "1", "x"),
		"text banned_at":   "1.2.3.4\tyesterday\t2\t1\tx",
		"bad expires_at":   "1.2.3.4\t1\tsoon\t1\tx",
		"negative expires": banRow("1.2.3.4", 1, -5, "1", "x"),
		"bad failures":     banRow("1.2.3.4", 1, 2, "many", "x"),
		"negative count":   banRow("1.2.3.4", 1, 2, "-1", "x"),
	}
	for name, line := range bad {
		if b, err := parseBanLine(line); err == nil {
			t.Errorf("%s: accepted %q as %+v", name, line, b)
		}
	}
}

func TestBansEndpointValidRows(t *testing.T) {
	now := time.Now().Unix()
	useBans(t, banRow("146.70.195.37", now-600, now+3000, "3", "certificate revoked or auth failure")+"\n")

	code, resp, body, hdr := getBans(t, http.MethodGet)
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("code %d, content-type %q", code, hdr.Get("Content-Type"))
	}
	want := banJSON{
		IP:        "146.70.195.37",
		BannedAt:  auditTimeString(now - 600),
		ExpiresAt: auditTimeString(now + 3000),
		Failures:  3,
		Reason:    "certificate revoked or auth failure",
	}
	if len(resp.Bans) != 1 || resp.Bans[0] != want {
		t.Fatalf("got %+v, want [%+v]", resp.Bans, want)
	}
	// wire keys are exactly the contract's names
	for _, key := range []string{`"bans":[{`, `"ip":"146.70.195.37"`, `"banned_at":"`, `"expires_at":"`, `"permanent":false`, `"failures":3`, `"reason":"certificate revoked or auth failure"`} {
		if !strings.Contains(body, key) {
			t.Errorf("body %s lacks %s", body, key)
		}
	}
}

func TestBansEndpointMissingFile(t *testing.T) {
	useBans(t, "")
	code, _, body, _ := getBans(t, http.MethodGet)
	if code != http.StatusOK || body != `{"bans":[]}` {
		t.Errorf("code %d body %q", code, body)
	}
}

func TestBansEndpointEmptyAuditPath(t *testing.T) {
	setFlag(t, auditPath, "")
	code, _, body, _ := getBans(t, http.MethodGet)
	if code != http.StatusOK || body != `{"bans":[]}` {
		t.Errorf("code %d body %q", code, body)
	}
}

func TestBansEndpointEmptyAndMalformedOnlyFile(t *testing.T) {
	useBans(t, "\n\n")
	if code, _, body, _ := getBans(t, http.MethodGet); code != http.StatusOK || body != `{"bans":[]}` {
		t.Errorf("blank file: code %d body %q", code, body)
	}
	useBans(t, "garbage\nmore garbage\t\t\n")
	if code, _, body, _ := getBans(t, http.MethodGet); code != http.StatusOK || body != `{"bans":[]}` {
		t.Errorf("malformed-only file: code %d body %q", code, body)
	}
}

func TestBansEndpointSkipsMalformedRows(t *testing.T) {
	now := time.Now().Unix()
	useBans(t, strings.Join([]string{
		"not a ban row",
		banRow("198.51.100.1", now-100, now+3000, "3", "first"),
		"198.51.100.2\tx\ty\tz\tbroken",
		"198.51.100.3\t1",
		banRow("bogus", now-90, now+3000, "3", "bad ip"),
		banRow("198.51.100.4", now-80, now+3000, "-2", "bad count"),
		banRow("198.51.100.5", now-70, now+3000, "5", "last"),
		"",
	}, "\n"))

	code, resp, _, _ := getBans(t, http.MethodGet)
	if code != http.StatusOK || len(resp.Bans) != 2 || resp.Bans[0].IP != "198.51.100.5" || resp.Bans[1].IP != "198.51.100.1" {
		t.Fatalf("code %d bans %+v", code, resp.Bans)
	}
}

func TestBansEndpointFiltersExpired(t *testing.T) {
	now := time.Now().Unix()
	useBans(t, strings.Join([]string{
		banRow("198.51.100.1", now-7200, now-3600, "3", "expired an hour ago"),
		banRow("198.51.100.2", now-3600, now-1, "3", "expired a second ago"),
		banRow("198.51.100.3", now-3600, now, "3", "expires right now"),
		banRow("198.51.100.4", now-60, now+3540, "3", "active"),
	}, "\n")+"\n")

	_, resp, _, _ := getBans(t, http.MethodGet)
	if len(resp.Bans) != 1 || resp.Bans[0].IP != "198.51.100.4" {
		t.Fatalf("got %+v", resp.Bans)
	}
}

func TestParseBansSorting(t *testing.T) {
	now := time.Unix(banNow, 0)
	data := strings.Join([]string{
		banRow("198.51.100.1", banNow-300, banNow+100, "1", "oldest"),
		banRow("198.51.100.3", banNow-100, banNow+100, "1", "newest"),
		banRow("198.51.100.2", banNow-200, banNow+100, "1", "middle"),
		banRow("198.51.100.9", banNow-200, banNow+100, "1", "same time, higher ip"),
		banRow("198.51.100.7", banNow-1000, banNow-1, "1", "expired"),
	}, "\n")
	bans, skipped := parseBans([]byte(data), now)
	if skipped != 0 {
		t.Errorf("skipped %d", skipped)
	}
	var got []string
	for _, b := range bans {
		got = append(got, b.IP)
	}
	want := "198.51.100.3 198.51.100.2 198.51.100.9 198.51.100.1"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

func TestParseBansCountsMalformed(t *testing.T) {
	data := "junk\n" + banRow("198.51.100.1", banNow, banNow+10, "1", "ok") + "\n\n1.2.3.4\tx\n"
	bans, skipped := parseBans([]byte(data), time.Unix(banNow, 0))
	if len(bans) != 1 || skipped != 2 {
		t.Errorf("bans %+v skipped %d", bans, skipped)
	}
}

func TestBansEndpointFixtureThreeRows(t *testing.T) {
	now := time.Now().Unix()
	useBans(t, strings.Join([]string{
		banRow("198.51.100.10", now-300, now+3300, "3", "certificate revoked or auth failure"),
		banRow("198.51.100.11", now-7200, now-3600, "4", "expired"),
		"this row is malformed",
		banRow("198.51.100.12", now-60, now+3540, "5", "repeated auth failures"),
	}, "\n")+"\n")

	_, resp, _, _ := getBans(t, http.MethodGet)
	if len(resp.Bans) != 2 || resp.Bans[0].IP != "198.51.100.12" || resp.Bans[1].IP != "198.51.100.10" {
		t.Fatalf("got %+v", resp.Bans)
	}
}

func TestBansEndpointMethods(t *testing.T) {
	useBans(t, banRow("198.51.100.1", time.Now().Unix(), time.Now().Unix()+3600, "1", "x")+"\n")

	if code, resp, _, _ := getBans(t, http.MethodGet); code != http.StatusOK || len(resp.Bans) != 1 {
		t.Errorf("GET: code %d bans %+v", code, resp.Bans)
	}
	// the real server drops the HEAD body; httptest.ResponseRecorder does not, so only the status is checked
	if code, _, _, _ := getBans(t, http.MethodHead); code != http.StatusOK {
		t.Errorf("HEAD: code %d", code)
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		code, _, _, hdr := getBans(t, m)
		if code != http.StatusMethodNotAllowed || hdr.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: code %d, Allow %q", m, code, hdr.Get("Allow"))
		}
	}
}
