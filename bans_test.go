package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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

// The split layout: the event file stays in the audit tree, the ban list and the ban queue are in the state tree. An empty state
// directory (the default) keeps the earlier behaviour, tested above.
func TestBanListPathAndControlDirFollowTheStateDirectory(t *testing.T) {
	setFlag(t, auditPath, "/mnt/audit/audit.tsv")
	setFlag(t, stateDir, "/var/lib/ovpn-admin/")
	if got := banListPath(); got != "/var/lib/ovpn-admin/bans.tsv" {
		t.Errorf("banListPath = %q", got)
	}
	if got := banControlDir(); got != "/var/lib/ovpn-admin/"+banControlDirName {
		t.Errorf("banControlDir = %q", got)
	}
	// the state directory alone is enough
	setFlag(t, auditPath, "")
	if got := banListPath(); got != "/var/lib/ovpn-admin/bans.tsv" {
		t.Errorf("banListPath without audit path = %q", got)
	}
	// without a state directory the audit directory is used
	setFlag(t, stateDir, "")
	setFlag(t, auditPath, "/mnt/audit/audit.tsv")
	if got := banListPath(); got != "/mnt/audit/bans.tsv" {
		t.Errorf("banListPath fallback = %q", got)
	}
	if got := banControlDir(); got != "/mnt/audit/"+banControlDirName {
		t.Errorf("banControlDir fallback = %q", got)
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

func TestParseBanLineNetwork(t *testing.T) {
	// an IPv6 ban of a prefix is listed with the network and the prefix length it was banned with
	b, err := parseBanLine(banRow("2001:db8:1:2::/64", banNow, banNow+600, "3", "auth-failed"))
	if err != nil || b.IP != "2001:db8:1:2::/64" || b.ExpiresAt != banNow+600 {
		t.Errorf("/64 row: %+v, %v", b, err)
	}
	// host bits are dropped, the text is canonical, the unban of the row names exactly this text
	if b, err := parseBanLine(banRow("2001:DB8:1:2:ffff::7/64", banNow, 0, "3", "x")); err != nil || b.IP != "2001:db8:1:2::/64" || !b.permanent() {
		t.Errorf("host bits: %+v, %v", b, err)
	}
	for _, bad := range []string{"2001:db8::/129", "2001:db8::/", "/64", "1.2.3.4/33", "2001:db8::/abc", "2001:db8::/64/64"} {
		if b, err := parseBanLine(banRow(bad, banNow, 0, "3", "x")); err == nil {
			t.Errorf("%q accepted as %+v", bad, b)
		}
	}
	useBans(t, banRow("2001:db8:1:2::/64", time.Now().Unix()-10, time.Now().Unix()+590, "3", "auth-failed")+"\n")
	code, resp, _, _ := getBans(t, http.MethodGet)
	if code != http.StatusOK || len(resp.Bans) != 1 || resp.Bans[0].IP != "2001:db8:1:2::/64" || resp.Bans[0].Permanent {
		t.Errorf("GET /api/bans: %d %+v", code, resp.Bans)
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

// ---- the ban engine script (setup/ovpn-ban.sh) against a fake firewall ------------------------------------------------------------
//
// Nothing here touches the host firewall: iptables and ip6tables are a fake binary on PATH that keeps its rules in a file, and so is
// date (a file holds the "now" of the script). The state files live in a temporary directory. The tests are skipped without bash, python3
// and flock (the golang:alpine image has none of them).

const fakeIptables = `#!/usr/bin/env bash
set -u
fam=4
case "$(basename "$0")" in ip6tables*) fam=6 ;; esac
f="$FAKE_FW_DIR/rules$fam"
touch "$f"
echo "$(basename "$0") $*" >> "$FAKE_FW_DIR/calls"
[ "${1:-}" = "-w" ] && shift 2
host=32; [ "$fam" = 6 ] && host=128
norm() {
  local out="" prev="" a
  for a in "$@"; do
    if [ "$prev" = "-s" ] && [[ "$a" != */* ]]; then a="$a/$host"; fi
    out="${out:+$out }$a"; prev="$a"
  done
  echo "$out"
}
has_chain() { [ "$1" = INPUT ] || grep -qxF -- "-N $1" "$f"; }
case "${1:-}" in
  -N) has_chain "$2" && exit 1; echo "-N $2" >> "$f" ;;
  -X) has_chain "$2" || exit 1; grep -vxF -- "-N $2" "$f" > "$f.new"; cat "$f.new" > "$f"; rm -f "$f.new" ;;
  -F) has_chain "$2" || exit 1; grep -v -- "^-A $2 " "$f" > "$f.new"; cat "$f.new" > "$f"; rm -f "$f.new" ;;
  -n) has_chain "$3" || exit 1 ;;
  -S)
    if [ -n "${2:-}" ]; then has_chain "$2" || exit 1; echo "-N $2"; grep -- "^-A $2 " "$f"; true
    else echo "-P INPUT ACCEPT"; cat "$f"; fi ;;
  -C) chain="$2"; shift 2; has_chain "$chain" || exit 1; grep -qxF -- "-A $chain $(norm "$@")" "$f" ;;
  -A) chain="$2"; shift 2; has_chain "$chain" || exit 1; echo "-A $chain $(norm "$@")" >> "$f" ;;
  -I) chain="$2"; shift 3; has_chain "$chain" || exit 1; echo "-A $chain $(norm "$@")" >> "$f" ;;
  -D) chain="$2"; shift 2; rule="-A $chain $(norm "$@")"
      grep -qxF -- "$rule" "$f" || exit 1
      awk -v r="$rule" '$0 == r && !d { d = 1; next } { print }' "$f" > "$f.new"; cat "$f.new" > "$f"; rm -f "$f.new" ;;
  *) echo "fake iptables: unsupported: $*" >&2; exit 2 ;;
esac
`

const fakeDate = `#!/usr/bin/env bash
if [ "${1:-}" = "+%s" ] && [ -n "${FAKE_NOW_FILE:-}" ] && [ -r "$FAKE_NOW_FILE" ]; then cat "$FAKE_NOW_FILE"; exit 0; fi
exec /usr/bin/date "$@"
`

const fakeNotify = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_NOTIFY_LOG"
`

// banRig is one disposable ban engine: fake binaries, state directory, environment and a controllable clock.
type banRig struct {
	t      *testing.T
	dir    string
	script string
	env    []string
}

const rigStart int64 = 1800000000

func newBanRig(t *testing.T, extra ...string) *banRig {
	t.Helper()
	for _, tool := range []string{"bash", "python3", "flock"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	script, err := filepath.Abs(filepath.Join("setup", "ovpn-ban.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, d := range []string{"bin", "fw", "audit", "events"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"iptables": fakeIptables, "ip6tables": fakeIptables, "date": fakeDate, "fake-notify": fakeNotify} {
		if err := os.WriteFile(filepath.Join(dir, "bin", name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := &banRig{t: t, dir: dir, script: script}
	r.env = append(os.Environ(),
		"PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_FW_DIR="+filepath.Join(dir, "fw"),
		"FAKE_NOW_FILE="+filepath.Join(dir, "now"),
		"FAKE_NOTIFY_LOG="+filepath.Join(dir, "notify.log"),
		"OVPN_BAN_STATE="+filepath.Join(dir, "audit", "bans.tsv"),
		"OVPN_BAN_EVENTS_LOG="+filepath.Join(dir, "events", "ban-events.log"),
		"OVPN_BAN_LOG="+filepath.Join(dir, "audit", "openvpn.log"),
		"OVPN_BAN_NOTIFY_BIN="+filepath.Join(dir, "bin", "fake-notify"),
		"OVPN_BAN_PORT=1194", "OVPN_BAN_PROTOS=udp", "OVPN_BAN_IPV6=true", "OVPN_BAN_IPV6_REQUIRED=true",
		"OVPN_BAN_IGNOREIP=127.0.0.0/8 ::1 172.20.0.0/24",
		"OVPN_BAN_OWN_NETS=172.16.100.0/255.255.255.0 fd00:16:100::/64",
		"OVPN_TELEGRAM_ENABLED=false",
		// the settings of the surrounding environment must not reach the script
		"OVPN_BAN_ESCALATION=", "OVPN_BAN_BANTIME=", "OVPN_BAN_REPEAT_COUNT=", "OVPN_BAN_DECAY_DAYS=", "OVPN_BAN_IPV6_PREFIX=",
		"OVPN_BAN_MAX_ENTRIES=", "OVPN_TELEGRAM_INCLUDE_ADDRESS=", "OVPN_NETWORK=", "OVPN_NETWORK_IPV6=",
	)
	r.env = append(r.env, extra...)
	r.setNow(rigStart)
	r.must("init")
	r.must("setup")
	return r
}

func (r *banRig) setNow(sec int64) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, "now"), []byte(fmt.Sprint(sec)+"\n"), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// run runs the script with extra environment entries; it returns the combined output and the exit status.
func (r *banRig) run(extra []string, args ...string) (string, int) {
	r.t.Helper()
	cmd := exec.Command("bash", append([]string{r.script}, args...)...)
	cmd.Env = append(append([]string{}, r.env...), extra...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		r.t.Fatalf("running ovpn-ban.sh %v: %v", args, err)
	}
	return string(out), code
}

func (r *banRig) must(args ...string) string {
	r.t.Helper()
	out, code := r.run(nil, args...)
	if code != 0 {
		r.t.Fatalf("ovpn-ban.sh %v: exit %d: %s", args, code, out)
	}
	return out
}

func (r *banRig) read(rel string) string {
	b, err := os.ReadFile(filepath.Join(r.dir, rel))
	if err != nil && !os.IsNotExist(err) {
		r.t.Fatal(err)
	}
	return string(b)
}

// rules returns the DROP rules of one family ("4" or "6"), one string per rule.
func (r *banRig) rules(fam string) []string {
	var out []string
	for _, l := range strings.Split(r.read("fw/rules"+fam), "\n") {
		if strings.HasPrefix(l, "-A OVPN_BAN") {
			out = append(out, l)
		}
	}
	return out
}

// stateRow returns the ban list row of an entry ("" when there is none), split into its tab separated fields.
func (r *banRig) stateRow(entry string) []string {
	for _, l := range strings.Split(r.read("audit/bans.tsv"), "\n") {
		if f := strings.Split(l, "\t"); len(f) == 5 && f[0] == entry {
			return f
		}
	}
	return nil
}

func (r *banRig) events() []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(r.read("events/ban-events.log")), "\n") {
		if l == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			r.t.Fatalf("ban-events.log line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

func (r *banRig) lastEvent(action string) map[string]any {
	evs := r.events()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i]["action"] == action {
			return evs[i]
		}
	}
	return nil
}

func TestBanScriptEscalation(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	now := rigStart
	// the first three bans last 600 s, 3600 s and 86400 s; the fourth is permanent
	want := []int64{600, 3600, 86400, 0}
	for i, secs := range want {
		r.setNow(now)
		out := r.must("ban", "1.2.3.4", "3")
		row := r.stateRow("1.2.3.4")
		if row == nil {
			t.Fatalf("offence %d: no ban list row: %s", i+1, out)
		}
		expires := int64(0)
		if secs > 0 {
			expires = now + secs
		}
		if row[1] != fmt.Sprint(now) || row[2] != fmt.Sprint(expires) {
			t.Errorf("offence %d: banned_at/expires_at = %s/%s, want %d/%d", i+1, row[1], row[2], now, expires)
		}
		if ev := r.lastEvent("ban"); ev["offence"] != float64(i+1) || ev["ban_seconds"] != float64(secs) || ev["address"] != "1.2.3.4" || ev["prefix"] != float64(32) {
			t.Errorf("offence %d: event %v", i+1, ev)
		}
		if got := r.rules("4"); len(got) != 1 || got[0] != "-A OVPN_BAN -s 1.2.3.4/32 -j DROP" {
			t.Fatalf("offence %d: rules %v", i+1, got)
		}
		if secs > 0 {
			// ten minutes before the end an unban (fail2ban's own bantime) does not lift it; after the end it does
			r.setNow(now + secs - 1)
			if r.must("unban", "1.2.3.4"); len(r.rules("4")) != 1 {
				t.Errorf("offence %d: lifted one second before its end", i+1)
			}
			r.setNow(now + secs)
			r.must("unban", "1.2.3.4")
			if len(r.rules("4")) != 0 || r.stateRow("1.2.3.4") != nil {
				t.Errorf("offence %d: not lifted at its end: %v", i+1, r.rules("4"))
			}
		}
		now += secs + 5
	}
	hist := strings.Split(strings.TrimSpace(r.read("audit/bans-history.tsv")), "\n")
	if len(hist) != 4 {
		t.Fatalf("history has %d rows: %q", len(hist), hist)
	}
	for i, secs := range want {
		f := strings.Split(hist[i], "\t")
		if len(f) != 6 || f[1] != "1.2.3.4" || f[2] != "32" || f[3] != "fail2ban" || f[4] != fmt.Sprint(i+1) || f[5] != fmt.Sprint(secs) {
			t.Errorf("history row %d = %q", i+1, hist[i])
		}
	}
	// the fourth ban is permanent: an unban does nothing, and 40 days (OVPN_BAN_DECAY_DAYS is 30) later it is still there after a restart
	r.setNow(now + 1000)
	r.must("unban", "1.2.3.4")
	if len(r.rules("4")) != 1 {
		t.Errorf("a permanent ban was lifted by a plain unban")
	}
	r.setNow(now + 40*86400)
	r.must("init")
	if len(r.rules("4")) != 0 {
		t.Errorf("init left a rule")
	}
	r.must("setup")
	r.must("check")
	if len(r.rules("4")) != 1 || r.stateRow("1.2.3.4") == nil || r.stateRow("1.2.3.4")[2] != "0" {
		t.Errorf("permanent ban not restored after the decay window: rules %v row %v", r.rules("4"), r.stateRow("1.2.3.4"))
	}
	if h := r.read("audit/bans-history.tsv"); !strings.Contains(h, "\t4\t0\n") || strings.Count(h, "\n") != 1 {
		t.Errorf("history after pruning keeps the permanent row only: %q", h)
	}
	// --force starts the address clean
	r.must("unban", "1.2.3.4", "--force")
	if len(r.rules("4")) != 0 || r.read("audit/bans-history.tsv") != "" {
		t.Errorf("force unban left rules %v history %q", r.rules("4"), r.read("audit/bans-history.tsv"))
	}
	r.must("ban", "1.2.3.4", "3")
	if ev := r.lastEvent("ban"); ev["offence"] != float64(1) {
		t.Errorf("after a force unban the next offence is %v, want 1", ev["offence"])
	}
}

func TestBanScriptDecay(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.must("ban", "1.2.3.4", "3")
	r.setNow(rigStart + 29*86400)
	r.must("unban", "1.2.3.4")
	r.must("ban", "1.2.3.4", "3") // inside the window: offence 2
	if ev := r.lastEvent("ban"); ev["offence"] != float64(2) || ev["ban_seconds"] != float64(3600) {
		t.Errorf("inside the window: %v", ev)
	}
	r.setNow(rigStart + 29*86400 + 3600)
	r.must("unban", "1.2.3.4")
	r.setNow(rigStart + 29*86400 + 31*86400) // 31 days without an offence: the count starts again
	r.must("ban", "1.2.3.4", "3")
	if ev := r.lastEvent("ban"); ev["offence"] != float64(1) || ev["ban_seconds"] != float64(600) {
		t.Errorf("after the decay window: %v", ev)
	}
	if h := strings.Count(r.read("audit/bans-history.tsv"), "\n"); h != 1 {
		t.Errorf("decayed offences were not pruned: %q", r.read("audit/bans-history.tsv"))
	}
}

func TestBanScriptConfig(t *testing.T) {
	t.Parallel()
	// OVPN_BAN_ESCALATION with units, and an offence past the end of a list without a permanent step
	r := newBanRig(t, "OVPN_BAN_ESCALATION=90s, 2h,3d")
	for i, want := range []float64{90, 7200, 259200, 259200} {
		r.setNow(rigStart + int64(i)*1000000)
		r.must("ban", "1.2.3.4", "3")
		if ev := r.lastEvent("ban"); ev["ban_seconds"] != want {
			t.Errorf("offence %d: %v, want %v", i+1, ev["ban_seconds"], want)
		}
		r.setNow(rigStart + int64(i)*1000000 + 400000)
		r.must("unban", "1.2.3.4")
	}
	// the earlier OVPN_BAN_BANTIME / OVPN_BAN_REPEAT_COUNT still mean "BANTIME, then the REPEAT_COUNT-th ban permanent"
	l := newBanRig(t, "OVPN_BAN_BANTIME=120", "OVPN_BAN_REPEAT_COUNT=3")
	for i, want := range []float64{120, 120, 0} {
		l.setNow(rigStart + int64(i)*1000)
		l.must("ban", "1.2.3.4", "3")
		if ev := l.lastEvent("ban"); ev["ban_seconds"] != want {
			t.Errorf("legacy offence %d: %v, want %v", i+1, ev["ban_seconds"], want)
		}
		l.setNow(rigStart + int64(i)*1000 + 500)
		l.must("unban", "1.2.3.4")
	}
	if out := l.must("jail-bantime"); strings.TrimSpace(out) != "120" {
		t.Errorf("jail-bantime = %q", out)
	}
	if out := newBanRig(t).must("jail-bantime"); strings.TrimSpace(out) != "600" {
		t.Errorf("default jail-bantime = %q", out)
	}
	// invalid settings stop the script before anything is changed
	before := strings.Join(r.rules("4"), "|") + r.read("audit/bans.tsv") + r.read("audit/bans-history.tsv")
	for _, bad := range [][]string{
		{"OVPN_BAN_ESCALATION=10m,,1h"}, {"OVPN_BAN_ESCALATION=ten minutes"}, {"OVPN_BAN_ESCALATION=0m,1h,0x"}, {"OVPN_BAN_ESCALATION=99999999999"},
		{"OVPN_BAN_IPV6_PREFIX=47"}, {"OVPN_BAN_IPV6_PREFIX=129"}, {"OVPN_BAN_IPV6_PREFIX=64x"}, {"OVPN_BAN_DECAY_DAYS=0"}, {"OVPN_BAN_MAX_ENTRIES=-1"},
		{"OVPN_TELEGRAM_INCLUDE_ADDRESS=yes"}, {"OVPN_BAN_BANTIME=0"}, {"OVPN_BAN_REPEAT_COUNT=x"},
	} {
		if out, code := r.run(bad, "ban", "1.2.3.4", "3"); code == 0 {
			t.Errorf("%v accepted: %s", bad, out)
		}
	}
	if after := strings.Join(r.rules("4"), "|") + r.read("audit/bans.tsv") + r.read("audit/bans-history.tsv"); after != before {
		t.Errorf("state changed by the invalid settings: %q -> %q", before, after)
	}
}

func TestBanScriptIPv6Prefix(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.must("ban", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "3")
	r.must("ban", "2001:db8:9:9::1", "3")
	if got := strings.Join(r.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8:1:2::/64 -j DROP|-A OVPN_BAN6 -s 2001:db8:9:9::/64 -j DROP" {
		t.Fatalf("rules: %s", got)
	}
	if row := r.stateRow("2001:db8:1:2::/64"); row == nil || row[2] != fmt.Sprint(rigStart+600) {
		t.Errorf("the state does not record the /64: %v", r.read("audit/bans.tsv"))
	}
	if ev := r.lastEvent("ban"); ev["prefix"] != float64(64) {
		t.Errorf("event %v", ev)
	}
	// a second address of the same /64 is the same offender: offence 2, still one rule
	r.setNow(rigStart + 700)
	r.must("unban", "2001:db8:1:2::77")
	r.setNow(rigStart + 800)
	r.must("ban", "2001:db8:1:2:1::5", "3")
	if ev := r.lastEvent("ban"); ev["offence"] != float64(2) || ev["ban_seconds"] != float64(3600) {
		t.Errorf("same /64, other address: %v", ev)
	}
	r.must("ban", "2001:db8:1:2:1::6", "3")
	// the /64 of 9:9 ran out at +600 and was lifted by the ban at +800
	if got := r.rules("6"); len(got) != 1 || got[0] != "-A OVPN_BAN6 -s 2001:db8:1:2::/64 -j DROP" {
		t.Errorf("one rule per prefix: %v", got)
	}
	r.must("ban", "2001:db8:9:9::1", "3")
	if got := r.rules("6"); len(got) != 2 {
		t.Errorf("two prefixes, two rules: %v", got)
	}
	// the unban of the /64 removes that rule only, by the network text of the ban list or by any address inside it
	r.must("unban", "2001:db8:1:2::/64", "--force")
	if got := strings.Join(r.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8:9:9::/64 -j DROP" {
		t.Errorf("rules after the unban: %s", got)
	}
	if r.stateRow("2001:db8:1:2::/64") != nil || r.stateRow("2001:db8:9:9::/64") == nil {
		t.Errorf("ban list after the unban: %q", r.read("audit/bans.tsv"))
	}
	r.must("unban", "2001:db8:9:9:ffff::1", "--force")
	if len(r.rules("6")) != 0 {
		t.Errorf("rules: %v", r.rules("6"))
	}
	// a /128 is allowed for a single address
	s := newBanRig(t, "OVPN_BAN_IPV6_PREFIX=128")
	s.must("ban", "2001:db8:1:2::9", "3")
	if got := strings.Join(s.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8:1:2::9/128 -j DROP" || s.stateRow("2001:db8:1:2::9") == nil {
		t.Errorf("/128: rules %s state %q", got, s.read("audit/bans.tsv"))
	}
	// a prefix that would also cover an address of the ignore list is narrowed to the single address
	n := newBanRig(t, "OVPN_BAN_IGNOREIP=::1 2001:db8:5:5::1")
	n.must("ban", "2001:db8:5:5::99", "3")
	if got := strings.Join(n.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8:5:5::99/128 -j DROP" {
		t.Errorf("ignore list inside the prefix: %s", got)
	}
	// IPv4 stays a single address
	r.must("ban", "198.51.100.200", "3")
	if got := r.rules("4"); len(got) != 1 || !strings.Contains(got[0], "198.51.100.200/32") {
		t.Errorf("IPv4 rules %v", got)
	}
}

func TestBanScriptManualGuard(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	refused := map[string]string{
		"127.0.0.1":      "loopback",
		"::1":            "loopback",
		"172.20.0.5":     "ignore list",
		"172.16.100.9":   "VPN client network",
		"fd00:16:100::7": "VPN client network",
		"10.1.2.3":       "private range",
		"192.168.1.1":    "private range",
		"172.31.255.255": "private range",
		"100.64.0.1":     "private range",
		"fc00::1":        "private range",
	}
	for addr, why := range refused {
		out, code := r.run(nil, "ban-manual", addr)
		if code != 4 || !strings.Contains(out, "refused") || !strings.Contains(out, why) || !strings.Contains(out, "force=true") {
			t.Errorf("%s: exit %d: %s", addr, code, out)
		}
	}
	if len(r.rules("4"))+len(r.rules("6")) != 0 || r.read("audit/bans.tsv") != "" || r.read("audit/bans-history.tsv") != "" {
		t.Errorf("a refused ban changed the state: %v %v %q", r.rules("4"), r.rules("6"), r.read("audit/bans.tsv"))
	}
	if ev := r.lastEvent("refuse"); ev == nil || ev["reason"] == "" {
		t.Errorf("refusal event %v", ev)
	}
	if n := len(r.events()); n != len(refused) {
		t.Errorf("%d events for %d refusals", n, len(refused))
	}
	// the other networks of the environment count as the VPN client network too
	n := newBanRig(t, "OVPN_NETWORK=203.0.113.0/24", "OVPN_NETWORK_IPV6=2001:db8:77::/64")
	for _, a := range []string{"203.0.113.50", "2001:db8:77::5"} {
		if out, code := n.run(nil, "ban-manual", a); code != 4 || !strings.Contains(out, "VPN client network") {
			t.Errorf("%s: exit %d: %s", a, code, out)
		}
	}
	// force applies it, and logs it
	out, code := r.run(nil, "ban-manual", "--force", "127.0.0.1", "operator test")
	if code != 0 {
		t.Fatalf("forced ban: exit %d: %s", code, out)
	}
	if got := r.rules("4"); len(got) != 1 || got[0] != "-A OVPN_BAN -s 127.0.0.1/32 -j DROP" {
		t.Errorf("forced ban rules %v", got)
	}
	if row := r.stateRow("127.0.0.1"); row == nil || row[2] != "0" || row[4] != "manual: operator test" {
		t.Errorf("forced ban row %v", row)
	}
	if ev := r.lastEvent("ban"); ev["forced"] != true || ev["address"] != "127.0.0.1" || ev["ban_seconds"] != float64(0) || ev["reason"] != "manual: operator test" {
		t.Errorf("forced ban event %v", ev)
	}
	// a public address needs no force; minutes 1..525600, default permanent
	if out, code := r.run(nil, "ban-manual", "--minutes", "30", "5.6.7.8", "spam"); code != 0 {
		t.Fatalf("minutes: %d %s", code, out)
	}
	if row := r.stateRow("5.6.7.8"); row == nil || row[2] != fmt.Sprint(rigStart+1800) {
		t.Errorf("30 minutes: %v", row)
	}
	r.must("ban-manual", "--minutes", "525600", "5.6.7.9")
	if row := r.stateRow("5.6.7.9"); row == nil || row[2] != fmt.Sprint(rigStart+525600*60) {
		t.Errorf("525600 minutes: %v", row)
	}
	r.must("ban-manual", "5.6.7.10")
	if row := r.stateRow("5.6.7.10"); row == nil || row[2] != "0" {
		t.Errorf("default is permanent: %v", row)
	}
	for _, bad := range []string{"0", "525601", "-5", "1.5", "abc", "", "99999999"} {
		if out, code := r.run(nil, "ban-manual", "--minutes", bad, "5.6.7.11"); code == 0 || r.stateRow("5.6.7.11") != nil {
			t.Errorf("minutes %q accepted: %s", bad, out)
		}
	}
	// a manual temporary ban is lifted when it runs out
	r.setNow(rigStart + 1800)
	r.must("expire")
	if r.stateRow("5.6.7.8") != nil || r.stateRow("5.6.7.9") == nil {
		t.Errorf("expire: %q", r.read("audit/bans.tsv"))
	}
	if ev := r.lastEvent("expire"); ev == nil || ev["address"] != "5.6.7.8" {
		t.Errorf("expire event %v", ev)
	}
	// a manual ban does not raise the offence number of the automatic escalation
	r.must("ban", "5.6.7.8", "3")
	if ev := r.lastEvent("ban"); ev["offence"] != float64(1) || ev["ban_seconds"] != float64(600) {
		t.Errorf("auto ban after a manual one: %v", ev)
	}
}

func TestBanScriptRuleCap(t *testing.T) {
	t.Parallel()
	r := newBanRig(t, "OVPN_BAN_MAX_ENTRIES=3")
	for i, a := range []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"} {
		r.setNow(rigStart + int64(i))
		r.must("ban", a, "3")
	}
	r.setNow(rigStart + 10)
	r.must("ban", "1.1.1.4", "3") // full: the oldest temporary ban (1.1.1.1) goes
	if r.stateRow("1.1.1.1") != nil || r.stateRow("1.1.1.4") == nil || len(r.rules("4")) != 3 {
		t.Errorf("after the cap: rules %v state %q", r.rules("4"), r.read("audit/bans.tsv"))
	}
	if strings.TrimSpace(r.read("audit/bans.tsv.caphits")) != "1" {
		t.Errorf("cap hits = %q", r.read("audit/bans.tsv.caphits"))
	}
	if ev := r.lastEvent("cap-evict"); ev == nil || ev["address"] != "1.1.1.1" {
		t.Errorf("cap event %v", ev)
	}
	// a permanent ban is never the one that goes
	r.must("ban-manual", "9.9.9.9")
	r.must("ban-manual", "9.9.9.8")
	r.must("ban-manual", "9.9.9.7")
	if r.stateRow("9.9.9.9") == nil || r.stateRow("9.9.9.8") == nil || r.stateRow("9.9.9.7") == nil || len(r.rules("4")) != 3 {
		t.Errorf("permanent bans pushed out: %q", r.read("audit/bans.tsv"))
	}
	// a list full of permanent bans refuses the new ban, drops nothing, and counts the hit
	out, code := r.run(nil, "ban", "8.8.8.8", "3")
	if code == 0 || r.stateRow("8.8.8.8") != nil || len(r.rules("4")) != 3 || !strings.Contains(out, "full of permanent bans") {
		t.Errorf("full of permanent bans: exit %d: %s", code, out)
	}
	if strings.TrimSpace(r.read("audit/bans.tsv.caphits")) != "5" {
		t.Errorf("cap hits = %q", r.read("audit/bans.tsv.caphits"))
	}
	// re-banning an entry that has a row needs no room
	r.must("ban-manual", "9.9.9.9")
}

func TestBanScriptExistingBehaviour(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	// an address of the ignore list is not banned
	if out, code := r.run(nil, "ban", "172.20.0.7", "3"); code != 0 || len(r.rules("4")) != 0 || !strings.Contains(out, "ignore list") {
		t.Errorf("ignore list: exit %d rules %v: %s", code, r.rules("4"), out)
	}
	// loopback, link-local, multicast and nonsense are refused outright
	for _, a := range []string{"127.0.0.1", "169.254.1.1", "224.0.0.1", "0.1.2.3", "::1", "fe80::1", "nonsense", "1.2.3.4/32", "1.2.3.4; reboot"} {
		if out, code := r.run(nil, "ban", a, "3"); code == 0 {
			t.Errorf("%q accepted: %s", a, out)
		}
	}
	// one rule per address, however often it is banned
	r.must("ban", "1.2.3.4", "3")
	r.must("ban", "1.2.3.4", "3")
	r.must("ban", "1.2.3.4", "4")
	if got := r.rules("4"); len(got) != 1 {
		t.Errorf("rules %v", got)
	}
	// the unban removes the rule and the row
	r.setNow(rigStart + 100000)
	r.must("unban", "1.2.3.4")
	if len(r.rules("4")) != 0 || r.stateRow("1.2.3.4") != nil {
		t.Errorf("unban left %v %q", r.rules("4"), r.read("audit/bans.tsv"))
	}
	r.must("unban", "1.2.3.4") // neither exists: success
	// fail closed: an unknown action, a bad listener port, an IPv6 chain that cannot be built
	if _, code := r.run(nil, "frobnicate"); code == 0 {
		t.Errorf("unknown action accepted")
	}
	if _, code := r.run([]string{"OVPN_BAN_PORT=8080"}, "ban", "1.2.3.4", "3"); code == 0 {
		t.Errorf("the admin port was accepted as the ban port")
	}
	if _, code := r.run([]string{"OVPN_BAN_PORT="}, "check"); code == 0 {
		t.Errorf("check without a listener port")
	}
	// state survives a restart: init empties the chains and the list, setup puts back from the history the permanent bans and the
	// temporary bans that have not run out (5.5.5.5 runs until +100600, original end); the history stays
	r.must("ban", "5.5.5.5", "3")
	r.must("ban-manual", "6.6.6.6")
	r.setNow(rigStart + 100010)
	r.must("init")
	if len(r.rules("4")) != 0 || r.read("audit/bans.tsv") != "" {
		t.Errorf("init: rules %v state %q", r.rules("4"), r.read("audit/bans.tsv"))
	}
	r.must("setup")
	r.must("check")
	if got := strings.Join(r.rules("4"), "|"); got != "-A OVPN_BAN -s 6.6.6.6/32 -j DROP|-A OVPN_BAN -s 5.5.5.5/32 -j DROP" {
		t.Errorf("after the restart: %s", got)
	}
	if row := r.stateRow("5.5.5.5"); row == nil || row[1] != fmt.Sprint(rigStart+100000) || row[2] != fmt.Sprint(rigStart+100600) {
		t.Errorf("the restored temporary ban keeps its time and its end: %v", row)
	}
	// a ban that fail2ban re-derives right after the start, while the old one would still run, is the same ban: not a new offence
	r.setNow(rigStart + 100030)
	r.must("ban", "5.5.5.5", "3")
	if ev := r.lastEvent("ban"); ev["address"] == "5.5.5.5" && ev["offence"] != float64(1) {
		t.Errorf("a re-derived ban after a restart counted as offence %v", ev["offence"])
	}
	if h := r.read("audit/bans-history.tsv"); strings.Count(h, "5.5.5.5") != 1 {
		t.Errorf("history rows of 5.5.5.5: %q", h)
	}
	// the files are private
	for _, f := range []string{"audit/bans.tsv", "audit/bans-history.tsv", "events/ban-events.log"} {
		if st, err := os.Stat(filepath.Join(r.dir, f)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
}

func TestBanScriptLegacyHistoryMigration(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	legacy := filepath.Join(r.dir, "audit", "ban-history.tsv")
	rows := "1.2.3.4\t3\t10\t20\t1\tauth-failed\t3\n2001:db8::9\t1\t10\t30\t0\tfail2ban\t3\n"
	if err := os.WriteFile(legacy, []byte(rows), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(r.dir, "audit", "bans-history.tsv")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	r.must("setup")
	if got := strings.Join(r.rules("4"), "|"); got != "-A OVPN_BAN -s 1.2.3.4/32 -j DROP" {
		t.Errorf("the permanent legacy ban was not restored: %s", got)
	}
	if _, err := os.Stat(legacy + ".migrated"); err != nil {
		t.Errorf("the legacy file is not kept: %v", err)
	}
	if h := r.read("audit/bans-history.tsv"); !strings.Contains(h, "1.2.3.4\t32\tauth-failed\t3\t0") {
		t.Errorf("history %q", h)
	}
}

// mockTelegram records the text of every sendMessage request.
func mockTelegram(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var texts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(body, &p)
		mu.Lock()
		texts = append(texts, p.Text)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, texts...) }
}

// writeBanAudit writes an audit log (setup/audit.sh format) and returns its path.
func writeBanAudit(t *testing.T, rows ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.tsv")
	if err := os.WriteFile(p, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// auditRow is one audit.tsv line: event time username real_ip real_port virtual_ip4 virtual_ip6 bytes_received bytes_sent
func auditRow(event string, at int64, user, ip string) string {
	return strings.Join([]string{event, fmt.Sprint(at), user, ip, "40000", "-", "-", "-", "-"}, "\t")
}

func tgEnv(srv *httptest.Server) []string {
	return []string{
		"OVPN_TELEGRAM_ENABLED=true", "OVPN_TELEGRAM_BOT_TOKEN=123456:TESTTOKENTESTTOKEN", "OVPN_TELEGRAM_CHAT_ID=42",
		"OVPN_TELEGRAM_API_BASE=" + srv.URL, "OVPN_TELEGRAM_ALLOW_HTTP=true",
	}
}

// realNotifier installs a wrapper of the real notifier in the rig and returns the environment entry that selects it.
func realNotifier(t *testing.T, r *banRig) []string {
	t.Helper()
	notifier, err := filepath.Abs(filepath.Join("setup", "ovpn-telegram-notify.py"))
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(r.dir, "bin", "real-notify")
	if err := os.WriteFile(wrapper, []byte("#!/usr/bin/env bash\nexec python3 "+notifier+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{"OVPN_BAN_NOTIFY_BIN=" + wrapper}
}

// msgLines splits a Telegram message into its lines.
func msgLines(msg string) []string { return strings.Split(msg, "\n") }

func lastLine(msg string) string { l := msgLines(msg); return l[len(l)-1] }

func hasLinePrefix(msg, prefix string) bool {
	for _, l := range msgLines(msg) {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func TestBanScriptTelegramMessage(t *testing.T) {
	t.Parallel()
	srv, texts := mockTelegram(t)
	audit := writeBanAudit(t, auditRow("auth_fail", rigStart-30, "alice", "203.0.113.7"))
	// the default of OVPN_TELEGRAM_INCLUDE_ADDRESS is true: the rig leaves it empty
	r := newBanRig(t, append(tgEnv(srv), "OVPN_AUDIT_LOG="+audit)...)
	withNotifier := realNotifier(t, r)
	logLine := "2026-11-23 20:00:00 203.0.113.7:5555 [alice] PLUGIN_CALL: POST /etc/openvpn/auth.sh status=1\n2026-11-23 20:00:01 203.0.113.7:5555 AUTH_FAILED alice\n"
	if err := os.WriteFile(filepath.Join(r.dir, "audit", "openvpn.log"), []byte(logLine), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := r.run(withNotifier, "ban", "203.0.113.7", "3"); code != 0 {
		t.Fatalf("ban: %d %s", code, out)
	}
	got := texts()
	if len(got) != 1 {
		t.Fatalf("%d messages: %q", len(got), got)
	}
	// the literal text, line by line (the end of the ban is now + 600 s, the host is the machine's)
	lines := msgLines(got[0])
	if len(lines) != 7 || lines[0] != "\U0001F6AB ovpn-admin: banned 203.0.113.7" || lines[1] != "Reason: auth-failed" || lines[2] != "User: alice" ||
		lines[3] != "Offence: 1" || lines[4] != "Duration: 10 minutes" || !strings.HasPrefix(lines[5], "Until: 20") || !strings.HasSuffix(lines[5], " UTC") ||
		!strings.HasPrefix(lines[6], "Server: ") {
		t.Errorf("ban message %q", got[0])
	}
	if strings.Contains(got[0], "123456") {
		t.Errorf("the token is in the message: %q", got[0])
	}
	// the unban message names the address and no user
	if out, code := r.run(withNotifier, "unban", "203.0.113.7", "--force"); code != 0 {
		t.Fatalf("unban: %d %s", code, out)
	}
	got = texts()
	if len(got) != 2 || got[1] != "\u2705 ovpn-admin: ban lifted for 203.0.113.7\nServer: "+strings.TrimPrefix(lastLine(got[0]), "Server: ") {
		t.Errorf("unban message %q", got)
	}
	// the fourth ban says permanent twice, a manual ban only "manual", never its note, and no user line
	for i := 0; i < 3; i++ {
		r.setNow(rigStart + int64(i+1)*200000)
		r.run(withNotifier, "ban", "203.0.113.7", "3")
		r.setNow(rigStart + int64(i+1)*200000 + 100000)
		r.run(withNotifier, "unban", "203.0.113.7")
	}
	r.setNow(rigStart + 1000000)
	r.run(withNotifier, "ban", "203.0.113.7", "3")
	all := texts()
	if last := all[len(all)-1]; !strings.Contains(last, "Duration: permanent\nUntil: permanent\n") || !strings.Contains(last, "Offence: 4") {
		t.Errorf("no permanent message in %q", last)
	}
	n := len(all)
	if out, code := r.run(withNotifier, "ban-manual", "5.6.7.8", "call alice back"); code != 0 {
		t.Fatalf("manual: %d %s", code, out)
	}
	all = texts()
	if len(all) != n+1 || !strings.Contains(all[n], "banned 5.6.7.8\nReason: manual\n") || strings.Contains(all[n], "alice") || hasLinePrefix(all[n], "User:") {
		t.Errorf("manual message %q", all[n:])
	}

	// OVPN_TELEGRAM_INCLUDE_ADDRESS=false: the same ban, a message with neither the address nor the user name
	srv2, texts2 := mockTelegram(t)
	off := newBanRig(t, append(tgEnv(srv2), "OVPN_AUDIT_LOG="+audit, "OVPN_TELEGRAM_INCLUDE_ADDRESS=false")...)
	offNotifier := realNotifier(t, off)
	if out, code := off.run(offNotifier, "ban", "203.0.113.7", "3"); code != 0 {
		t.Fatalf("ban: %d %s", code, out)
	}
	if out, code := off.run(offNotifier, "unban", "203.0.113.7", "--force"); code != 0 {
		t.Fatalf("unban: %d %s", code, out)
	}
	got = texts2()
	if len(got) != 2 {
		t.Fatalf("%d messages: %q", len(got), got)
	}
	for _, m := range got {
		for _, leak := range []string{"203.0.113.7", "alice", "User:", "123456"} {
			if strings.Contains(m, leak) {
				t.Errorf("address-free message contains %q: %q", leak, m)
			}
		}
	}
	if !strings.HasPrefix(got[0], "\U0001F6AB ovpn-admin: banned\nReason: ") || !strings.HasPrefix(got[1], "\u2705 ovpn-admin: ban lifted\nServer: ") {
		t.Errorf("address-free messages %q", got)
	}
	// explicit true is the same as the default
	srv3, texts3 := mockTelegram(t)
	on := newBanRig(t, append(tgEnv(srv3), "OVPN_AUDIT_LOG="+audit, "OVPN_TELEGRAM_INCLUDE_ADDRESS=true")...)
	if out, code := on.run(realNotifier(t, on), "ban", "203.0.113.7", "3"); code != 0 {
		t.Fatalf("ban: %d %s", code, out)
	}
	if got := texts3(); len(got) != 1 || !strings.Contains(got[0], "banned 203.0.113.7\n") || !strings.Contains(got[0], "\nUser: alice\n") {
		t.Errorf("with true: %q", got)
	}
}

// the arguments of the notifier, the queue line and the event line for the name cases
const fakeQueueNotify = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_NOTIFY_LOG"
cat "${OVPN_BAN_STATE}".notify.* >> "$FAKE_QUEUE_LOG" 2>/dev/null
`

func TestBanScriptUserNameLookup(t *testing.T) {
	t.Parallel()
	const ip = "203.0.113.7"
	at := rigStart
	longOK := strings.Repeat("a", 64)
	cases := []struct {
		name string
		rows []string
		ban  string // the address to ban, default ip
		want string // the user name, "-" for none
		as   string // the entry that is banned, default ip
	}{
		{name: "newest auth_fail row", rows: []string{auditRow("auth_fail", at-30, "alice", ip)}, want: "alice"},
		{name: "newest of several rows wins", rows: []string{auditRow("auth_fail", at-100, "alice", ip), auditRow("auth_fail", at-20, "bob", ip), auditRow("auth_fail", at-60, "carol", ip)}, want: "bob"},
		{name: "a newer row of another address is not used", rows: []string{auditRow("auth_fail", at-100, "alice", ip), auditRow("auth_fail", at-10, "mallory", "203.0.113.8")}, want: "alice"},
		{name: "row exactly 600 s old", rows: []string{auditRow("auth_fail", at-600, "alice", ip)}, want: "alice"},
		{name: "row 601 s old is ignored", rows: []string{auditRow("auth_fail", at-601, "alice", ip)}, want: "-"},
		{name: "old row ignored, newer inside the window used", rows: []string{auditRow("auth_fail", at-5000, "alice", ip), auditRow("auth_fail", at-5, "bob", ip)}, want: "bob"},
		{name: "no row for the address", rows: []string{auditRow("auth_fail", at-30, "alice", "203.0.113.8")}, want: "-"},
		{name: "auth_ok and connect rows are not failures", rows: []string{auditRow("auth_ok", at-30, "alice", ip), auditRow("connect", at-20, "alice", ip)}, want: "-"},
		{name: "dash user", rows: []string{auditRow("auth_fail", at-30, "-", ip)}, want: "-"},
		{name: "newest row has no user: no guess from an older row", rows: []string{auditRow("auth_fail", at-90, "alice", ip), auditRow("auth_fail", at-30, "-", ip)}, want: "-"},
		{name: "space in the name", rows: []string{auditRow("auth_fail", at-30, "ali ce", ip)}, want: "-"},
		{name: "newline in the name splits the row", rows: []string{"auth_fail\t" + fmt.Sprint(at-30) + "\tali\nce\t" + ip + "\t1\t-\t-\t-\t-"}, want: "-"},
		{name: "shell metacharacters", rows: []string{auditRow("auth_fail", at-30, "$(touch${IFS}x)", ip)}, want: "-"},
		{name: "semicolon", rows: []string{auditRow("auth_fail", at-30, "a;b", ip)}, want: "-"},
		{name: "leading dash", rows: []string{auditRow("auth_fail", at-30, "-alice", ip)}, want: "-"},
		{name: "non-ASCII", rows: []string{auditRow("auth_fail", at-30, "ali\u00e7e", ip)}, want: "-"},
		{name: "65 characters", rows: []string{auditRow("auth_fail", at-30, longOK+"a", ip)}, want: "-"},
		{name: "64 characters", rows: []string{auditRow("auth_fail", at-30, longOK, ip)}, want: longOK},
		{name: "dots, dashes and underscores", rows: []string{auditRow("auth_fail", at-30, "a.b_c-d9", ip)}, want: "a.b_c-d9"},
		{name: "time is not a number", rows: []string{"auth_fail\tsoon\talice\t" + ip + "\t1\t-\t-\t-\t-"}, want: "-"},
		{name: "too few fields", rows: []string{"auth_fail\t" + fmt.Sprint(at-30) + "\talice"}, want: "-"},
		{name: "invalid UTF-8 row", rows: []string{"auth_fail\t" + fmt.Sprint(at-30) + "\t\xff\xfe\t" + ip + "\t1\t-\t-\t-\t-"}, want: "-"},
		{name: "real_ip is not an address", rows: []string{auditRow("auth_fail", at-30, "alice", "not-an-ip")}, want: "-"},
		{name: "IPv4-mapped real_ip is the IPv4 address", rows: []string{auditRow("auth_fail", at-30, "alice", "::ffff:"+ip)}, want: "alice"},
		{name: "IPv6 /64 ban: a row inside the prefix", rows: []string{auditRow("auth_fail", at-30, "alice", "2001:db8:1:2:aaaa::1")}, ban: "2001:db8:1:2::5", as: "2001:db8:1:2::/64", want: "alice"},
		{name: "IPv6 /64 ban: a row outside the prefix", rows: []string{auditRow("auth_fail", at-30, "alice", "2001:db8:1:3::1")}, ban: "2001:db8:1:2::5", as: "2001:db8:1:2::/64", want: "-"},
		{name: "IPv6 /64 ban: newest row inside the prefix wins", rows: []string{auditRow("auth_fail", at-80, "alice", "2001:db8:1:2::1"), auditRow("auth_fail", at-40, "bob", "2001:db8:1:2:1::9")}, ban: "2001:db8:1:2::5", as: "2001:db8:1:2::/64", want: "bob"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, entry := ip, ip
			if tc.ban != "" {
				addr, entry = tc.ban, tc.as
			}
			audit := writeBanAudit(t, tc.rows...)
			r := newBanRig(t, "OVPN_TELEGRAM_ENABLED=true", "OVPN_AUDIT_LOG="+audit)
			if err := os.WriteFile(filepath.Join(r.dir, "bin", "fake-notify"), []byte(fakeQueueNotify), 0o755); err != nil {
				t.Fatal(err)
			}
			r.env = append(r.env, "FAKE_QUEUE_LOG="+filepath.Join(r.dir, "queue.log"))
			if out, code := r.run(nil, "ban", addr, "3"); code != 0 {
				t.Fatalf("the ban failed (exit %d): %s", code, out)
			}
			if got := r.rules("4"); entry == ip && len(got) != 1 {
				t.Errorf("rules %v", got)
			}
			argv := "ban " + entry + " fail2ban 1 600"
			queue := "ban\t" + entry + "\tfail2ban\t1\t600\t" + tc.want + "\n"
			if tc.want != "-" {
				argv += " " + tc.want
			}
			if got := r.read("notify.log"); got != argv+"\n" {
				t.Errorf("notifier argv %q, want %q", got, argv)
			}
			if got := r.read("queue.log"); got != queue {
				t.Errorf("queue line %q, want %q", got, queue)
			}
			ev := r.lastEvent("ban")
			if ev == nil || ev["user"] != tc.want {
				t.Fatalf("event %v, want user %q", ev, tc.want)
			}
			// the new field is the last one of the line and the earlier ones are where they were
			line := strings.TrimSpace(r.read("events/ban-events.log"))
			wantTail := `"action":"ban","user":"` + tc.want + `"}`
			if !strings.HasSuffix(line, wantTail) || !strings.Contains(line, `"address":"`+strings.SplitN(addr, "/", 2)[0]+`","prefix":`) {
				t.Errorf("event line %q", line)
			}
		})
	}
}

func TestBanScriptUserNameEdges(t *testing.T) {
	t.Parallel()
	const ip = "203.0.113.7"
	banWith := func(t *testing.T, audit string, extra ...string) *banRig {
		t.Helper()
		r := newBanRig(t, append([]string{"OVPN_TELEGRAM_ENABLED=true", "OVPN_AUDIT_LOG=" + audit}, extra...)...)
		if out, code := r.run(nil, "ban", ip, "3"); code != 0 {
			t.Fatalf("the ban failed (exit %d): %s", code, out)
		}
		if len(r.rules("4")) != 1 {
			t.Errorf("rules %v", r.rules("4"))
		}
		return r
	}
	plain := "ban " + ip + " fail2ban 1 600\n"
	row := auditRow("auth_fail", rigStart-30, "alice", ip) + "\n"
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		r := banWith(t, filepath.Join(dir, "missing.tsv"))
		if got := r.read("notify.log"); got != plain {
			t.Errorf("argv %q", got)
		}
		if ev := r.lastEvent("ban"); ev["user"] != "-" {
			t.Errorf("event %v", ev)
		}
	})
	t.Run("a directory in its place", func(t *testing.T) {
		t.Parallel()
		d := filepath.Join(t.TempDir(), "audit.tsv")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if got := banWith(t, d).read("notify.log"); got != plain {
			t.Errorf("argv %q", got)
		}
	})
	t.Run("a link to a file with a matching row", func(t *testing.T) {
		t.Parallel()
		target := writeBanAudit(t, strings.TrimSpace(row))
		link := filepath.Join(t.TempDir(), "audit.tsv")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if got := banWith(t, link).read("notify.log"); got != plain {
			t.Errorf("argv %q: the link was followed", got)
		}
	})
	t.Run("a named pipe in its place does not block the ban", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "audit.tsv")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		done := make(chan string, 1)
		go func() { done <- banWith(t, p).read("notify.log") }()
		select {
		case got := <-done:
			if got != plain {
				t.Errorf("argv %q", got)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("the ban waited for the pipe")
		}
	})
	t.Run("an unreadable file", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() == 0 {
			t.Skip("root reads any file; the missing-file, directory and pipe cases cover the open failures")
		}
		p := writeBanAudit(t, strings.TrimSpace(row))
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		if got := banWith(t, p).read("notify.log"); got != plain {
			t.Errorf("argv %q", got)
		}
	})
	t.Run("a huge log is read from its tail", func(t *testing.T) {
		t.Parallel()
		// 6 MB of rows of other addresses, then the matching one: found; the first (cut) line of the tail is never used
		var b strings.Builder
		filler := auditRow("auth_fail", rigStart-30, "noise", "198.51.100.9") + "\n"
		for b.Len() < 6<<20 {
			b.WriteString(filler)
		}
		b.WriteString(row)
		p := filepath.Join(t.TempDir(), "audit.tsv")
		if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := banWith(t, p).read("notify.log"); got != plain[:len(plain)-1]+" alice\n" {
			t.Errorf("argv %q", got)
		}
	})
	t.Run("OVPN_TELEGRAM_INCLUDE_ADDRESS=false: no address, no user in the argv, the event keeps the name", func(t *testing.T) {
		t.Parallel()
		r := banWith(t, writeBanAudit(t, strings.TrimSpace(row)), "OVPN_TELEGRAM_INCLUDE_ADDRESS=false")
		if got := r.read("notify.log"); got != "ban - fail2ban 1 600\n" {
			t.Errorf("argv %q", got)
		}
		if ev := r.lastEvent("ban"); ev["user"] != "alice" {
			t.Errorf("event %v", ev)
		}
	})
	t.Run("default and true pass the address and the user", func(t *testing.T) {
		t.Parallel()
		for _, extra := range [][]string{nil, {"OVPN_TELEGRAM_INCLUDE_ADDRESS=true"}} {
			r := banWith(t, writeBanAudit(t, strings.TrimSpace(row)), extra...)
			if got := r.read("notify.log"); got != plain[:len(plain)-1]+" alice\n" {
				t.Errorf("%v: argv %q", extra, got)
			}
		}
	})
	t.Run("a queue line of the earlier format is sent without a name", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_TELEGRAM_ENABLED=true", "OVPN_AUDIT_LOG="+filepath.Join(dir, "missing.tsv"))
		if err := os.WriteFile(filepath.Join(r.dir, "audit", "bans.tsv.notify"), []byte("ban\t"+ip+"\tfail2ban\t2\t3600\nunban\t"+ip+"\t\t\t\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r.must("expire")
		if got := r.read("notify.log"); got != "ban "+ip+" fail2ban 2 3600\nunban "+ip+"\n" {
			t.Errorf("argv %q", got)
		}
	})
	t.Run("a bad name in a queue line is dropped", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_TELEGRAM_ENABLED=true", "OVPN_AUDIT_LOG="+filepath.Join(dir, "missing.tsv"))
		if err := os.WriteFile(filepath.Join(r.dir, "audit", "bans.tsv.notify"), []byte("ban\t"+ip+"\tfail2ban\t2\t3600\tali ce\nban\t"+ip+"\tfail2ban\t2\t3600\t$(x)\nban\t"+ip+"\tfail2ban\t2\t3600\tbob\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r.must("expire")
		want := "ban " + ip + " fail2ban 2 3600\n"
		if got := r.read("notify.log"); got != want+want+want[:len(want)-1]+" bob\n" {
			t.Errorf("argv %q", got)
		}
	})
}

// notifierRun runs the real notifier with the mock Telegram API; it returns the exit status and the stderr text.
func notifierRun(t *testing.T, srv *httptest.Server, extraEnv []string, args ...string) (int, string) {
	t.Helper()
	notifier, err := filepath.Abs(filepath.Join("setup", "ovpn-telegram-notify.py"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", append([]string{notifier}, args...)...)
	cmd.Env = append(append(os.Environ(), "OVPN_TELEGRAM_INCLUDE_ADDRESS="), tgEnv(srv)...)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, stderr.String()
}

func TestTelegramNotifierUser(t *testing.T) {
	t.Parallel()
	srv, texts := mockTelegram(t)
	// a valid name: its own line between Reason and Offence
	if code, errText := notifierRun(t, srv, nil, "ban", "203.0.113.7", "auth-failed", "2", "3600", "alice"); code != 0 || errText != "" {
		t.Fatalf("exit %d: %s", code, errText)
	}
	got := texts()
	if len(got) != 1 {
		t.Fatalf("%q", got)
	}
	l := msgLines(got[0])
	if len(l) != 7 || l[0] != "\U0001F6AB ovpn-admin: banned 203.0.113.7" || l[1] != "Reason: auth-failed" || l[2] != "User: alice" || l[3] != "Offence: 2" ||
		l[4] != "Duration: 1 hour" || !strings.HasPrefix(l[5], "Until: 20") || !strings.HasPrefix(l[6], "Server: ") {
		t.Errorf("message %q", got[0])
	}
	// "-" and no sixth argument: no User line; offence 0 is left out
	for _, args := range [][]string{
		{"ban", "203.0.113.7", "auth-failed", "2", "3600", "-"}, {"ban", "203.0.113.7", "auth-failed", "2", "3600"},
	} {
		n := len(texts())
		if code, errText := notifierRun(t, srv, nil, args...); code != 0 || errText != "" {
			t.Fatalf("%v: exit %d: %s", args, code, errText)
		}
		if m := texts()[n]; strings.Contains(m, "User:") || !strings.Contains(m, "banned 203.0.113.7\n") || !strings.Contains(m, "Offence: 2\n") {
			t.Errorf("%v: %q", args, m)
		}
	}
	// permanent: Until says so; a manual ban of an address without offences
	n := len(texts())
	if code, _ := notifierRun(t, srv, nil, "ban", "2001:db8:1:2::/64", "manual: call alice back", "0", "0", "alice"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if m := texts()[n]; m != "\U0001F6AB ovpn-admin: banned 2001:db8:1:2::/64\nReason: manual\nUser: alice\nDuration: permanent\nUntil: permanent\nServer: "+strings.TrimPrefix(lastLine(got[0]), "Server: ") {
		t.Errorf("manual message %q", m)
	}
	// OVPN_TELEGRAM_INCLUDE_ADDRESS=false: neither the address nor the user name, even when both are given
	n = len(texts())
	if code, errText := notifierRun(t, srv, []string{"OVPN_TELEGRAM_INCLUDE_ADDRESS=false"}, "ban", "203.0.113.7", "auth-failed", "2", "3600", "alice"); code != 0 || errText != "" {
		t.Fatalf("exit %d: %s", code, errText)
	}
	if m := texts()[n]; strings.Contains(m, "203.0.113.7") || strings.Contains(m, "alice") || strings.Contains(m, "User:") || !strings.HasPrefix(m, "\U0001F6AB ovpn-admin: banned\nReason: auth-failed\nOffence: 2\n") {
		t.Errorf("address-free message %q", m)
	}
	// unban: the address, never a name, and no sixth argument
	n = len(texts())
	if code, _ := notifierRun(t, srv, nil, "unban", "203.0.113.7"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if m := texts()[n]; !strings.HasPrefix(m, "\u2705 ovpn-admin: ban lifted for 203.0.113.7\nServer: ") {
		t.Errorf("unban message %q", m)
	}
	n = len(texts())
	if code, _ := notifierRun(t, srv, []string{"OVPN_TELEGRAM_INCLUDE_ADDRESS=false"}, "unban", "203.0.113.7"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if m := texts()[n]; strings.Contains(m, "203.0.113.7") || !strings.HasPrefix(m, "\u2705 ovpn-admin: ban lifted\nServer: ") {
		t.Errorf("address-free unban message %q", m)
	}
	n = len(texts())
	if code, errText := notifierRun(t, srv, nil, "unban", "203.0.113.7", "alice"); code != 2 || len(texts()) != n || !strings.Contains(errText, "WARNING") {
		t.Errorf("unban with a user: exit %d %q", code, errText)
	}
	// a bad sixth argument: exit 2, one line on stderr, the name never echoed, nothing sent
	for _, bad := range []string{"ali ce", "ali\nce", "alice\n", "", "-alice", ".alice", "a;b", "$(id)", "ali\u00e7e", strings.Repeat("a", 65), "al\tice"} {
		n := len(texts())
		code, errText := notifierRun(t, srv, nil, "ban", "203.0.113.7", "auth-failed", "2", "3600", bad)
		if code != 2 || len(texts()) != n {
			t.Errorf("name %q: exit %d, sent %d messages", bad, code, len(texts())-n)
		}
		if strings.Count(errText, "\n") != 1 || !strings.HasPrefix(errText, "ovpn-telegram-notify: WARNING: notification (ban) not sent: USER") || (bad != "" && strings.Contains(errText, bad)) {
			t.Errorf("name %q: stderr %q", bad, errText)
		}
	}
	// a 64 character name is fine; the sixth argument is checked before the address and also with the address left out
	if code, errText := notifierRun(t, srv, nil, "ban", "203.0.113.7", "auth-failed", "2", "3600", strings.Repeat("a", 64)); code != 0 || errText != "" {
		t.Errorf("64 characters: exit %d %q", code, errText)
	}
	n = len(texts())
	if code, _ := notifierRun(t, srv, []string{"OVPN_TELEGRAM_INCLUDE_ADDRESS=false"}, "ban", "-", "auth-failed", "2", "3600", "ali ce"); code != 2 || len(texts()) != n {
		t.Errorf("a bad name with the address left out: exit %d", code)
	}
	// seven arguments are a usage error
	if code, _ := notifierRun(t, srv, nil, "ban", "203.0.113.7", "auth-failed", "2", "3600", "alice", "bob"); code != 2 {
		t.Errorf("six extra arguments: exit %d", code)
	}
	// --check-api-base stays
	if code, _ := notifierRun(t, srv, nil, "--check-api-base", "https://api.telegram.org"); code != 0 {
		t.Errorf("--check-api-base: exit %d", code)
	}
	if code, _ := notifierRun(t, srv, nil, "--check-api-base", "ftp://x"); code != 2 {
		t.Errorf("--check-api-base ftp: exit %d", code)
	}
}

func TestBanScriptNotifierArgument(t *testing.T) {
	t.Parallel()
	// the default is true: the address goes to the notifier
	r := newBanRig(t, "OVPN_TELEGRAM_ENABLED=true", "OVPN_AUDIT_LOG="+filepath.Join(t.TempDir(), "missing.tsv"))
	r.must("ban", "1.2.3.4", "3")
	r.must("unban", "1.2.3.4", "--force")
	if got := r.read("notify.log"); got != "ban 1.2.3.4 fail2ban 1 600\nunban 1.2.3.4\n" {
		t.Errorf("notifier calls %q", got)
	}
	// false is the escape hatch: "-" instead of the address
	f := newBanRig(t, "OVPN_TELEGRAM_ENABLED=true", "OVPN_TELEGRAM_INCLUDE_ADDRESS=false")
	f.must("ban", "1.2.3.4", "3")
	f.must("unban", "1.2.3.4", "--force")
	if got := f.read("notify.log"); got != "ban - fail2ban 1 600\nunban -\n" {
		t.Errorf("notifier calls %q", got)
	}
	i := newBanRig(t, "OVPN_TELEGRAM_ENABLED=true", "OVPN_TELEGRAM_INCLUDE_ADDRESS=true")
	i.must("ban", "1.2.3.4", "3")
	if got := i.read("notify.log"); got != "ban 1.2.3.4 fail2ban 1 600\n" {
		t.Errorf("notifier calls %q", got)
	}
}

// TestBanWatcherManualBan drives the real watcher (setup/ovpn-ban-control.py) and the real script through the queue the admin uses.
func TestBanWatcherManualBan(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	watcher, err := filepath.Abs(filepath.Join("setup", "ovpn-ban-control.py"))
	if err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(r.dir, "control")
	if err := os.Mkdir(ctl, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", watcher, ctl)
	cmd.Env = append(append([]string{}, r.env...), "OVPN_BAN_TOOL="+r.script, "OVPN_BAN_CONTROL_POLL=0.05", "OVPN_BAN_SWEEP_SECONDS=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	submit := func(req banControlRequest) banControlResult {
		t.Helper()
		res, err := submitBanControlRequest(context.Background(), ctl, req, 20*time.Second)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		return res
	}
	// 127.0.0.1 without force is refused, with the reason, and nothing changes
	res := submit(banControlRequest{Action: "ban", IP: "127.0.0.1"})
	if res.OK || !strings.Contains(res.Message, "refused") || !strings.Contains(res.Message, "loopback") {
		t.Errorf("without force: %+v", res)
	}
	if len(r.rules("4")) != 0 {
		t.Errorf("refused ban left rules %v", r.rules("4"))
	}
	// with force it is applied and logged
	res = submit(banControlRequest{Action: "ban", IP: "127.0.0.1", Force: true, Reason: "operator test"})
	if !res.OK || len(r.rules("4")) != 1 {
		t.Errorf("with force: %+v rules %v", res, r.rules("4"))
	}
	if ev := r.lastEvent("ban"); ev == nil || ev["forced"] != true || ev["address"] != "127.0.0.1" {
		t.Errorf("event %v", ev)
	}
	// minutes: temporary, and the sweep of the watcher lifts it once it ran out
	res = submit(banControlRequest{Action: "ban", IP: "5.6.7.8", Minutes: 5})
	if !res.OK || !strings.Contains(res.Message, "5 minutes") || r.stateRow("5.6.7.8") == nil {
		t.Errorf("minutes: %+v %q", res, r.read("audit/bans.tsv"))
	}
	r.setNow(rigStart + 301)
	deadline := time.Now().Add(15 * time.Second)
	for r.stateRow("5.6.7.8") != nil && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if r.stateRow("5.6.7.8") != nil {
		t.Errorf("the watcher did not lift the expired ban: %q", r.read("audit/bans.tsv"))
	}
	// out-of-range minutes and a non-boolean force never reach the tool
	for _, bad := range []string{`{"id":"%s","action":"ban","ip":"5.6.7.9","minutes":0}`, `{"id":"%s","action":"ban","ip":"5.6.7.9","minutes":525601}`,
		`{"id":"%s","action":"ban","ip":"5.6.7.9","minutes":"5"}`, `{"id":"%s","action":"ban","ip":"5.6.7.9","force":"yes"}`,
		`{"id":"%s","action":"unban","ip":"5.6.7.9","force":true}`} {
		id := fmt.Sprintf("bad%d", time.Now().UnixNano())
		if err := os.WriteFile(filepath.Join(ctl, ".tmp-"+id), []byte(fmt.Sprintf(bad, id)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(ctl, ".tmp-"+id), filepath.Join(ctl, id+".req")); err != nil {
			t.Fatal(err)
		}
		var got banControlResult
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if g, found, _ := readBanControlResult(ctl, id); found {
				got = g
				break
			}
		}
		if got.OK || got.Message == "" {
			t.Errorf("%s: %+v", bad, got)
		}
	}
	if r.stateRow("5.6.7.9") != nil {
		t.Errorf("an invalid request banned 5.6.7.9")
	}
	// an unban may name the network of a row; a forced loopback ban can be lifted
	res = submit(banControlRequest{Action: "unban", IP: "127.0.0.1"})
	if !res.OK || len(r.rules("4")) != 0 {
		t.Errorf("unban: %+v %v", res, r.rules("4"))
	}
	if res = submit(banControlRequest{Action: "ban", IP: "2001:db8:1:2::5"}); !res.OK || len(r.rules("6")) != 1 {
		t.Fatalf("ipv6 manual ban: %+v", res)
	}
	if res = submit(banControlRequest{Action: "unban", IP: "2001:db8:1:2::/64"}); !res.OK || len(r.rules("6")) != 0 {
		t.Errorf("unban of the network: %+v %v", res, r.rules("6"))
	}
}
