package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// Tests of the admin audit trail (auditlog.go). They run against real files in temporary directories, the
// real handlers with the fake easyrsa of user_ops_test.go, and real loopback HTTP servers for the webhook.

// randomSecret is a credential made for one test: never a real one.
func randomSecret(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + hex.EncodeToString(b)
}

// openTestAudit opens a trail in a fresh directory; the file is <dir>/audit/admin-audit.log.
func openTestAudit(t *testing.T, webhook string) *adminAuditLog {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit", "admin-audit.log")
	a, err := openAdminAuditLog(path, webhook)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

// useAdminAudit installs a trail as the panel's for the test.
func useAdminAudit(t *testing.T, webhook string) *adminAuditLog {
	t.Helper()
	asAdmin(t)
	a := openTestAudit(t, webhook)
	old := adminAudit
	adminAudit = a
	t.Cleanup(func() { adminAudit = old })
	return a
}

func readAuditFile(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		t.Fatalf("%s does not end with a newline", path)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func parseAuditLines(t *testing.T, lines []string) []adminAuditRecord {
	t.Helper()
	var out []adminAuditRecord
	for i, l := range lines {
		rec, err := parseAdminAuditLine([]byte(l))
		if err != nil {
			t.Fatalf("line %d: %v: %s", i+1, err, l)
		}
		out = append(out, rec)
	}
	return out
}

func mustRecord(t *testing.T, a *adminAuditLog, action, target string) adminAuditRecord {
	t.Helper()
	rec, err := a.Record("basic-auth:admin", action, target, "192.0.2.10", adminAuditResultOK, "test line")
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustVerifyOK(t *testing.T, a *adminAuditLog) *adminAuditVerifyOK {
	t.Helper()
	ok, bad := a.Verify()
	if bad != nil {
		t.Fatalf("verify: broken at %d: %s", bad.BrokenAt, bad.Reason)
	}
	return ok
}

// flipByteAt flips one bit of the byte at column col of line (1-based) of the file.
func flipByteAt(t *testing.T, path string, line, col int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	off := 0
	for i := 1; i < line; i++ {
		off += bytes.IndexByte(data[off:], '\n') + 1
	}
	data[off+col] ^= 0x01
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// ---- the line format and the chain ----

var auditKeyOrder = regexp.MustCompile(`^\{"seq":\d+,"ts":"[^"]*","actor":"[^"]*","action":"[^"]*","target":"[^"]*","source":"[^"]*","result":"[^"]*","detail":"[^"]*","prev":"[0-9a-f]{64}","hash":"[0-9a-f]{64}"\}$`)
var auditTs = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

func TestAdminAuditLineFormatAndChain(t *testing.T) {
	a := openTestAudit(t, "")
	a.now = func() time.Time { return time.Date(2026, 11, 23, 12, 30, 45, 999, time.FixedZone("WIB", 7*3600)) }
	mustRecord(t, a, auditActUserCreate, "alice")
	mustRecord(t, a, auditActUserRevoke, "alice")
	mustRecord(t, a, auditActUserDelete, "alice")

	lines := readAuditFile(t, a.path)
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3", len(lines))
	}
	prev := adminAuditZeroHash
	for i, l := range lines {
		if !auditKeyOrder.MatchString(l) {
			t.Errorf("line %d: keys are not seq, ts, actor, action, target, source, result, detail, prev, hash in this order: %s", i+1, l)
		}
		rec := parseAuditLines(t, []string{l})[0]
		if rec.Seq != int64(i+1) {
			t.Errorf("line %d: seq %d", i+1, rec.Seq)
		}
		if rec.Ts != "2026-11-23T05:30:45Z" || !auditTs.MatchString(rec.Ts) {
			t.Errorf("line %d: ts %q, want UTC RFC3339 with seconds", i+1, rec.Ts)
		}
		if rec.Prev != prev {
			t.Errorf("line %d: prev %s, want %s", i+1, rec.Prev, prev)
		}
		// the hash, computed here from the text of the line: drop the hash key, hash what is left
		idx := strings.LastIndex(l, `,"hash":"`)
		sum := sha256.Sum256([]byte(l[:idx] + "}"))
		if want := hex.EncodeToString(sum[:]); rec.Hash != want {
			t.Errorf("line %d: hash %s, want sha256 of the line without hash %s", i+1, rec.Hash, want)
		}
		prev = rec.Hash
	}
	if first := parseAuditLines(t, lines[:1])[0]; first.Prev != strings.Repeat("0", 64) {
		t.Errorf("first prev is %s", first.Prev)
	}
	res := mustVerifyOK(t, a)
	if res.Lines != 3 || res.LastHash != prev {
		t.Errorf("verify: %+v, want 3 lines and last hash %s", res, prev)
	}
	b, _ := json.Marshal(res)
	if string(b) != fmt.Sprintf(`{"ok":true,"state":"verified","lines":3,"lastSeq":3,"lastHash":"%s","checkpointSeq":0,"unanchored":3,"firstSeq":1,"since":"%s","gaps":0}`, prev, parseAuditLines(t, lines[:1])[0].Ts) {
		t.Errorf("verify JSON: %s", b)
	}
}

func TestAdminAuditFileAndDirectoryModes(t *testing.T) {
	a := openTestAudit(t, "")
	mustRecord(t, a, auditActUserCreate, "alice")
	di, err := os.Stat(filepath.Dir(a.path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0700 {
		t.Errorf("directory mode %04o, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(a.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("file mode %04o, want 0600", fi.Mode().Perm())
	}
}

func TestAdminAuditEmptyFileVerifies(t *testing.T) {
	a := openTestAudit(t, "")
	res := mustVerifyOK(t, a)
	if res.Lines != 0 || res.LastHash != adminAuditZeroHash {
		t.Errorf("an empty trail: %+v", res)
	}
}

func TestAdminAuditReopenContinuesTheChain(t *testing.T) {
	a := openTestAudit(t, "")
	mustRecord(t, a, auditActUserCreate, "a")
	last := mustRecord(t, a, auditActUserCreate, "b")
	a.Close()

	b, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Lines() != 2 {
		t.Errorf("lines after reopen: %d", b.Lines())
	}
	next := mustRecord(t, b, auditActUserCreate, "c")
	if next.Seq != last.Seq+1 || next.Prev != last.Hash {
		t.Errorf("after reopen: seq %d prev %s, want %d and %s", next.Seq, next.Prev, last.Seq+1, last.Hash)
	}
	if res := mustVerifyOK(t, b); res.Lines != 3 {
		t.Errorf("verify: %+v", res)
	}
}

func TestAdminAuditConcurrentWritersKeepOneChain(t *testing.T) {
	a := openTestAudit(t, "")
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				if _, err := a.Record("system", auditActUserCreate, fmt.Sprintf("u%d-%d", g, i), "local", "ok", "x"); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	res := mustVerifyOK(t, a)
	if res.Lines != 640 {
		t.Errorf("%d lines, want 640", res.Lines)
	}
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	for i, r := range recs {
		if r.Seq != int64(i+1) {
			t.Fatalf("line %d has seq %d", i+1, r.Seq)
		}
	}
}

// ---- tamper detection ----

func fillAudit(t *testing.T, a *adminAuditLog, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		mustRecord(t, a, auditActUserCreate, fmt.Sprintf("user%d", i))
	}
}

// Flipping any single byte of line 3 is reported at seq 3.
func TestAdminAuditTamperEveryByteOfLineThree(t *testing.T) {
	a := openTestAudit(t, "")
	fillAudit(t, a, 5)
	lines := readAuditFile(t, a.path)
	orig, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	for col := 0; col < len(lines[2]); col++ {
		flipByteAt(t, a.path, 3, col)
		ok, bad := a.Verify()
		if ok != nil || bad == nil || bad.BrokenAt != 3 || bad.OK {
			t.Fatalf("byte %d of line 3 flipped: ok=%v bad=%+v, want brokenAt 3", col, ok, bad)
		}
		if err := os.WriteFile(a.path, orig, 0600); err != nil {
			t.Fatal(err)
		}
	}
	mustVerifyOK(t, a)
}

func TestAdminAuditTamperKinds(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(lines []string) []string
		brokenAt int64
	}{
		{"line 2 deleted", func(l []string) []string { return append(l[:1:1], l[2:]...) }, 2},
		{"lines 2 and 3 swapped", func(l []string) []string { l[1], l[2] = l[2], l[1]; return l }, 2},
		{"a line inserted", func(l []string) []string {
			return append(l[:2:2], append([]string{l[1]}, l[2:]...)...)
		}, 3},
		{"whitespace added inside a line", func(l []string) []string { l[2] = strings.Replace(l[2], `"seq":3,`, `"seq":3, `, 1); return l }, 3},
		{"key order changed", func(l []string) []string {
			r := parseAuditLines(t, []string{l[2]})[0]
			b, _ := json.Marshal(map[string]any{"seq": r.Seq, "ts": r.Ts, "actor": r.Actor, "action": r.Action, "target": r.Target, "source": r.Source, "result": r.Result, "detail": r.Detail, "prev": r.Prev, "hash": r.Hash})
			l[2] = string(b)
			return l
		}, 3},
		{"an empty line", func(l []string) []string { return append(l[:2:2], append([]string{""}, l[2:]...)...) }, 3},
		{"a duplicated last line", func(l []string) []string { return append(l, l[len(l)-1]) }, 6},
		{"a rewritten line with a correct own hash but a wrong successor", func(l []string) []string {
			r := parseAuditLines(t, []string{l[1]})[0]
			r.Result = "fail"
			r.Hash = r.hashOf()
			b, _ := json.Marshal(r)
			l[1] = string(b)
			return l
		}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := openTestAudit(t, "")
			fillAudit(t, a, 5)
			lines := c.mutate(readAuditFile(t, a.path))
			if err := os.WriteFile(a.path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ok, bad := a.Verify()
			if ok != nil || bad == nil || bad.BrokenAt != c.brokenAt {
				t.Fatalf("ok=%v bad=%+v, want brokenAt %d", ok, bad, c.brokenAt)
			}
			if bad.Reason == "" {
				t.Error("no reason")
			}
		})
	}
}

func TestAdminAuditTornLastLineIsBroken(t *testing.T) {
	a := openTestAudit(t, "")
	fillAudit(t, a, 3)
	data, _ := os.ReadFile(a.path)
	if err := os.WriteFile(a.path, data[:len(data)-20], 0600); err != nil {
		t.Fatal(err)
	}
	ok, bad := a.Verify()
	if ok != nil || bad == nil || bad.BrokenAt != 3 {
		t.Fatalf("ok=%v bad=%+v", ok, bad)
	}
	// and the panel refuses to start on it instead of appending after a broken line
	a.Close()
	if _, err := openAdminAuditLog(a.path, ""); err == nil || !strings.Contains(err.Error(), "move the file aside") {
		t.Errorf("open on a torn file: %v", err)
	}
}

func TestAdminAuditVerifyBrokenJSONShape(t *testing.T) {
	a := openTestAudit(t, "")
	fillAudit(t, a, 4)
	flipByteAt(t, a.path, 3, 40)
	_, bad := a.Verify()
	b, _ := json.Marshal(bad)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["ok"] != false || m["state"] != "broken" || m["brokenAt"] != float64(3) || m["reason"] == "" || len(m) != 4 {
		t.Errorf("verify JSON: %s", b)
	}
	if !strings.HasPrefix(string(b), `{"ok":false,"state":"broken","brokenAt":3,"reason":"`) {
		t.Errorf("key order: %s", b)
	}
}

// ---- rotation ----

func gens(a *adminAuditLog) (present []int) {
	for n := 1; n <= 8; n++ {
		if _, err := os.Stat(a.generation(n)); err == nil {
			present = append(present, n)
		}
	}
	return
}

func TestAdminAuditRotationKeepsTheChainAndFiveGenerations(t *testing.T) {
	a := openTestAudit(t, "")
	a.maxBytes = 2000
	var total int
	for i := 0; i < 400; i++ {
		mustRecord(t, a, auditActUserCreate, fmt.Sprintf("user%03d", i))
		total++
	}
	if got := gens(a); fmt.Sprint(got) != "[1 2 3 4 5]" {
		t.Fatalf("generations present: %v, want .1 to .5 and nothing beyond", got)
	}
	fi, _ := os.Stat(a.path)
	if fi.Size() > 2000+400 {
		t.Errorf("the current file is %d bytes with a limit of 2000", fi.Size())
	}

	// the current file starts with audit.rotate, chained to the last line of .1
	cur := parseAuditLines(t, readAuditFile(t, a.path))
	if cur[0].Action != adminAuditRotateAction || cur[0].Actor != "system" || cur[0].Result != "ok" {
		t.Fatalf("first line of the current file: %+v", cur[0])
	}
	if !strings.Contains(cur[0].Detail, "admin-audit.log") || !strings.Contains(cur[0].Detail, "admin-audit.log.1") {
		t.Errorf("rotate detail %q does not name the file", cur[0].Detail)
	}
	g1 := parseAuditLines(t, readAuditFile(t, a.generation(1)))
	if cur[0].Prev != g1[len(g1)-1].Hash || cur[0].Seq != g1[len(g1)-1].Seq+1 {
		t.Errorf("rotate line: prev %s seq %d, last of .1 is %s seq %d", cur[0].Prev, cur[0].Seq, g1[len(g1)-1].Hash, g1[len(g1)-1].Seq)
	}
	// every generation after the oldest starts with the rotate line of its own rotation
	for n := 4; n >= 1; n-- {
		older := parseAuditLines(t, readAuditFile(t, a.generation(n+1)))
		newer := parseAuditLines(t, readAuditFile(t, a.generation(n)))
		if newer[0].Action != adminAuditRotateAction || newer[0].Prev != older[len(older)-1].Hash {
			t.Errorf(".%d does not continue .%d", n, n+1)
		}
	}
	res := mustVerifyOK(t, a)
	last := cur[len(cur)-1]
	if res.LastHash != last.Hash {
		t.Errorf("last hash %s, want %s", res.LastHash, last.Hash)
	}
	var onDisk int64
	for _, p := range a.files() {
		onDisk += int64(len(readAuditFile(t, p)))
	}
	if res.Lines != onDisk {
		t.Errorf("verify counted %d lines, the files hold %d", res.Lines, onDisk)
	}
	if last.Seq != int64(total+(len(gens(a))+3)) && last.Seq < int64(total) {
		t.Errorf("seq %d after %d records", last.Seq, total)
	}

	// a flipped byte inside an older generation is found, with its seq
	older := parseAuditLines(t, readAuditFile(t, a.generation(3)))
	flipByteAt(t, a.generation(3), 4, 30)
	ok, bad := a.Verify()
	if ok != nil || bad == nil || bad.BrokenAt != older[3].Seq {
		t.Errorf("tamper in .3 line 4: ok=%v bad=%+v, want brokenAt %d", ok, bad, older[3].Seq)
	}
}

// (the old test of the default limit only compared two constants: TestAuditRotatesAtTenMiBForReal writes 10 MiB
// through a trail with the default limit and looks at the rotation it causes)

// A deleted generation in the middle breaks the chain where the gap is.
func TestAdminAuditMissingGenerationIsDetected(t *testing.T) {
	a := openTestAudit(t, "")
	a.maxBytes = 1500
	for i := 0; i < 120; i++ {
		mustRecord(t, a, auditActUserCreate, fmt.Sprintf("u%d", i))
	}
	mustVerifyOK(t, a)
	if err := os.Remove(a.generation(2)); err != nil {
		t.Fatal(err)
	}
	ok, bad := a.Verify()
	if ok != nil || bad == nil {
		t.Fatalf("a missing .2 was not detected: %+v", ok)
	}
}

// The rotation that was cut off between the rename and the first line is finished by the next start.
func TestAdminAuditInterruptedRotationIsFinishedAtStart(t *testing.T) {
	a := openTestAudit(t, "")
	fillAudit(t, a, 4)
	last := parseAuditLines(t, readAuditFile(t, a.path))[3]
	a.Close()
	if err := os.Rename(a.path, a.generation(1)); err != nil {
		t.Fatal(err)
	}
	b, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rec := mustRecord(t, b, auditActUserDelete, "x")
	lines := parseAuditLines(t, readAuditFile(t, b.path))
	if len(lines) != 2 || lines[0].Action != adminAuditRotateAction || lines[0].Prev != last.Hash || lines[1].Seq != rec.Seq || lines[1].Seq != last.Seq+2 {
		t.Fatalf("after an interrupted rotation: %+v", lines)
	}
	mustVerifyOK(t, b)
}

// ---- refusing links, failing closed ----

func TestAdminAuditRefusesSymlinkedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.log")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin-audit.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLog(path, ""); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked file was accepted or the error does not say why: %v", err)
	}
	if fi, _ := os.Stat(target); fi.Size() != 0 {
		t.Error("the symlink target was written")
	}
	// a dangling link is refused too, not created through
	dangling := filepath.Join(dir, "dangling.log")
	if err := os.Symlink(filepath.Join(dir, "never"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLog(dangling, ""); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a dangling symlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "never")); err == nil {
		t.Error("the dangling link target was created")
	}
}

func TestAdminAuditRefusesSymlinkedDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLog(filepath.Join(link, "admin-audit.log"), ""); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("a symlinked directory: %v", err)
	}
	if entries, _ := os.ReadDir(real); len(entries) != 0 {
		t.Error("a file was created through the symlinked directory")
	}
}

func TestAdminAuditRefusesSymlinkedRotationTarget(t *testing.T) {
	a := openTestAudit(t, "")
	a.maxBytes = 300
	fillAudit(t, a, 1)
	victim := filepath.Join(t.TempDir(), "victim")
	// someone plants a link where the new file will be created, after the rename: the creation must not follow it
	if err := os.Rename(a.path, a.generation(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, a.path); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	_ = a.f.Close()
	a.f, a.size, a.lines, a.pendingRotate = nil, 0, 0, true
	a.mu.Unlock()
	if _, err := a.Record("system", auditActUserCreate, "x", "local", "ok", ""); err == nil {
		t.Fatal("the record was written through a planted symlink")
	}
	if _, err := os.Stat(victim); err == nil {
		t.Fatal("the planted symlink was followed and its target created")
	}
}

func TestAdminAuditStartupFailsWhenTheFileCannotBeOpened(t *testing.T) {
	dir := t.TempDir()
	// a regular file where the directory should be
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLog(filepath.Join(blocker, "admin-audit.log"), ""); err == nil {
		t.Error("a path below a regular file was accepted")
	}
	// a directory where the file should be
	if _, err := openAdminAuditLog(dir, ""); err == nil {
		t.Error("a directory as the audit file was accepted")
	}
	if _, err := openAdminAuditLog("  ", ""); err == nil {
		t.Error("an empty path was accepted")
	}
}

func TestAdminAuditStartupFailsOnAReadOnlyFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	path := filepath.Join(t.TempDir(), "admin-audit.log")
	a, err := openAdminAuditLog(path, "")
	if err != nil {
		t.Fatal(err)
	}
	mustRecord(t, a, auditActUserCreate, "x")
	a.Close()
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLog(path, ""); err == nil || !strings.Contains(err.Error(), "cannot be opened for appending") {
		t.Fatalf("a read-only file: %v", err)
	}
	// and an unwritable directory with no file yet
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0500); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLog(filepath.Join(dir, "admin-audit.log"), ""); err == nil {
		t.Error("an unwritable directory was accepted")
	}
}

func TestAdminAuditStartLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "admin-audit.log")
	setFlag(t, adminAuditFileFlag, path)
	setFlag(t, adminAuditWebhookFlag, "")
	var buf bytes.Buffer
	oldOut := log.StandardLogger().Out
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldOut) })
	old := adminAudit
	t.Cleanup(func() { adminAudit.Close(); adminAudit = old })

	if err := initAdminAudit(); err != nil {
		t.Fatal(err)
	}
	mustRecord(t, adminAudit, auditActUserCreate, "x")
	adminAudit.Close()
	if err := initAdminAudit(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "file="+path+" lines=0") || !strings.Contains(out, "file="+path+" lines=1") {
		t.Errorf("start lines missing the path and the line count:\n%s", out)
	}
	adminAudit.Close()

	setFlag(t, adminAuditFileFlag, filepath.Join(path, "below-a-file"))
	if err := initAdminAudit(); err == nil {
		t.Error("initAdminAudit succeeded on an impossible path")
	}
}

// ---- redaction ----

func TestAdminAuditRecordMasksSecretsAndKeyMaterial(t *testing.T) {
	a := openTestAudit(t, "")
	secret := randomSecret(t, "pw-")
	if _, err := a.Record("basic-auth:admin", auditActUserCreate, "alice", "192.0.2.1", "fail",
		"bad request, the password was "+secret+" which is not allowed", secret); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Record("system", auditActUserRotate, "alice", "local", "fail",
		"-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Record("system", auditActUserRotate, "bob\nnewline\t\x00ctl", "local", "ok", strings.Repeat("x", 1000)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(a.path)
	if bytes.Contains(data, []byte(secret)) {
		t.Error("the secret is in the file")
	}
	if bytes.Contains(data, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(data, []byte("MIIBVQ")) {
		t.Error("key material is in the file")
	}
	lines := readAuditFile(t, a.path)
	if len(lines) != 3 {
		t.Fatalf("%d lines: control characters in a value split a line", len(lines))
	}
	recs := parseAuditLines(t, lines)
	if !strings.Contains(recs[0].Detail, adminAuditRedacted) {
		t.Errorf("detail %q", recs[0].Detail)
	}
	if recs[1].Detail != adminAuditRedacted {
		t.Errorf("key material detail %q", recs[1].Detail)
	}
	if n := len([]rune(recs[2].Detail)); n > adminAuditMaxDetail {
		t.Errorf("detail is %d characters", n)
	}
	mustVerifyOK(t, a)
}

// A request carries credentials; none of them reaches the file, whatever the handler writes as detail.
func TestAdminAuditHandlerRequestsNeverWriteCredentials(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, _ := setupFakeEasyrsa(t)
	setupFakeOpenvpnUser(t)
	setFlag(t, authByPassword, true)

	adminPass := randomSecret(t, "admin-")
	setFlag(t, basicUsername, "root")
	setFlag(t, basicPassword, adminPass)
	userPass := randomSecret(t, "Zq9-")
	shortPass := randomSecret(t, "")[:6]

	post := func(h http.HandlerFunc, path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("root", adminPass)
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	if rec := post(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"alice"}, "password": {userPass}}); rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := post(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"bob"}, "password": {shortPass}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("create with a short password: %d %s", rec.Code, rec.Body)
	}
	if rec := post(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {"alice"}, "password": {shortPass}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("change-password with a short password: %d %s", rec.Code, rec.Body)
	}
	newPass := randomSecret(t, "New-")
	if rec := post(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {"alice"}, "password": {newPass}}); rec.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", rec.Code, rec.Body)
	}
	rotPass := randomSecret(t, "Rot-")
	if rec := post(oAdmin.userRotateHandler, "/api/user/rotate", url.Values{"username": {"alice"}, "password": {rotPass}}); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body)
	}

	data, _ := os.ReadFile(a.path)
	for name, secret := range map[string]string{"admin password": adminPass, "user password": userPass, "short password": shortPass, "new password": newPass, "rotate password": rotPass,
		"Authorization value": base64.StdEncoding.EncodeToString([]byte("root:" + adminPass))} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("the %s is in the audit file", name)
		}
	}
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	var actions []string
	for _, r := range recs {
		actions = append(actions, r.Action+":"+r.Target+":"+r.Result)
		if r.Actor != "basic-auth:root" || r.Source != "192.0.2.1" {
			t.Errorf("actor %q source %q", r.Actor, r.Source)
		}
	}
	want := []string{"user.create:alice:ok", "user.create:bob:fail", "user.change-password:alice:fail", "user.change-password:alice:ok", "user.rotate:alice:ok"}
	if strings.Join(actions, " ") != strings.Join(want, " ") {
		t.Errorf("actions\n got %v\nwant %v", actions, want)
	}
}

// ---- the panel actions ----

func authedRequest(method, path string, form url.Values, user string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, honestAdminPass)
	}
	return req
}

func TestAdminAuditCreateRevokeRotateEachAddOneLine(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, pki := setupFakeEasyrsa(t)
	_ = pki
	easyrsaGenCrl()
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})

	do := func(h http.HandlerFunc, path, name string) int {
		rec := httptest.NewRecorder()
		h(rec, authedRequest(http.MethodPost, path, url.Values{"username": {name}}, "operator"))
		return rec.Code
	}
	count := func() int { return int(a.Lines()) }

	before := count()
	if code := do(oAdmin.userCreateHandler, "/api/user/create", "alice"); code != http.StatusOK {
		t.Fatalf("create: %d", code)
	}
	if count() != before+1 {
		t.Fatalf("create added %d lines", count()-before)
	}
	before = count()
	if code := do(oAdmin.userRevokeHandler, "/api/user/revoke", "alice"); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if count() != before+1 {
		t.Fatalf("revoke added %d lines", count()-before)
	}
	before = count()
	if code := do(oAdmin.userRotateHandler, "/api/user/rotate", "alice"); code != http.StatusOK {
		t.Fatalf("rotate: %d", code)
	}
	if count() != before+1 {
		t.Fatalf("rotate added %d lines", count()-before)
	}
	// failures are recorded as well: an unknown user
	before = count()
	if code := do(oAdmin.userRevokeHandler, "/api/user/revoke", "nobody"); code == http.StatusOK {
		t.Fatalf("revoke of an unknown user: %d", code)
	}
	if count() != before+1 {
		t.Fatalf("a failed revoke added %d lines", count()-before)
	}
	before = count()
	if code := do(oAdmin.userDeleteHandler, "/api/user/delete", "alice"); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	if count() != before+1 {
		t.Fatalf("delete added %d lines", count()-before)
	}

	var got []string
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		got = append(got, r.Action+" "+r.Target+" "+r.Result)
		if r.Actor != "basic-auth:operator" || r.Source != "192.0.2.1" || r.Detail == "" {
			t.Errorf("%+v", r)
		}
	}
	want := []string{"user.create alice ok", "user.revoke alice ok", "user.rotate alice ok", "user.revoke nobody fail", "user.delete alice ok"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
	mustVerifyOK(t, a)
}

func TestAdminAuditOtherActions(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, _ := setupFakeEasyrsa(t)
	setupCcdDir(t, nil)
	setFlag(t, ccdEnabled, true)
	oAdmin.masterSyncToken = randomSecret(t, "tok-")

	// unrevoke of an unknown user fails
	rec := httptest.NewRecorder()
	oAdmin.userUnrevokeHandler(rec, authedRequest(http.MethodPost, "/api/user/unrevoke", url.Values{"username": {"ghost"}}, "operator"))
	// disconnect
	rec = httptest.NewRecorder()
	oAdmin.userDisconnectHandler(rec, authedRequest(http.MethodPost, "/api/user/disconnect", url.Values{"username": {"ghost"}}, "operator"))
	// config download of an unknown user, with the sentence of the panel in the answer
	rec = httptest.NewRecorder()
	oAdmin.userShowConfigHandler(rec, authedRequest(http.MethodGet, "/api/user/config/show?username=ghost", url.Values{"username": {"ghost"}}, "operator"))
	// sync export with the wrong token must not record the token
	rec = httptest.NewRecorder()
	badTok := randomSecret(t, "wrong-")
	oAdmin.downloadCertsHandler(rec, authedRequest(http.MethodGet, "/api/data/certs/download?token="+badTok, nil, ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("download with a wrong token: %d", rec.Code)
	}
	// ccd apply
	rec = httptest.NewRecorder()
	body := strings.NewReader(`{"User":"ghost","ClientAddress":"dynamic"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/user/ccd/apply", body)
	req.SetBasicAuth(honestAdminUser, honestAdminPass)
	oAdmin.userApplyCcdHandler(rec, req)

	data, _ := os.ReadFile(a.path)
	if bytes.Contains(data, []byte(badTok)) || bytes.Contains(data, []byte(oAdmin.masterSyncToken)) {
		t.Error("a sync token is in the audit file")
	}
	got := map[string]string{}
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		got[r.Action] = r.Target + "/" + r.Result
	}
	for action, want := range map[string]string{
		"user.unrevoke":        "ghost/fail",
		"user.disconnect":      "ghost/fail",
		"user.config.download": "ghost/fail",
		"sync.export":          "certs.tar.gz/fail",
	} {
		if got[action] != want {
			t.Errorf("%s: %q, want %q (all: %v)", action, got[action], want, got)
		}
	}
	if _, ok := got["user.ccd.apply"]; !ok {
		t.Errorf("user.ccd.apply is not recorded: %v", got)
	}
}

func TestAdminAuditCrlRebuildIsRecordedAsSystem(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, pki := setupFakeEasyrsa(t)
	// no CRL on disk but a PKI that is not new: the daily check reads it, cannot, and rebuilds
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), []byte("not a crl"), 0644); err != nil {
		t.Fatal(err)
	}
	oAdmin.role = "master"
	oAdmin.crlRefresh(time.Now())
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	if len(recs) != 1 || recs[0].Action != "pki.crl.rebuild" || recs[0].Actor != "system" || recs[0].Source != "local" {
		t.Fatalf("%+v", recs)
	}
	if recs[0].Result != "ok" && recs[0].Result != "fail" {
		t.Errorf("result %q", recs[0].Result)
	}
}

func TestAdminAuditLoginEvents(t *testing.T) {
	a := useAdminAudit(t, "")
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	secret := randomSecret(t, "panel-")
	wrong := randomSecret(t, "guess-")
	h := basicAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), "root", secret, "/ping")

	get := func(user, pass, path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "198.51.100.7:51000"
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		if user != "" || pass != "" {
			req.SetBasicAuth(user, pass)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// no credentials: the browser challenge, not an event; /ping is open
	get("", "", "/api/users/list")
	get("", "", "/ping")
	// guesses: the first is recorded, the rest of the window is counted
	for i := 0; i < 5; i++ {
		if code := get("root", wrong, "/api/users/list"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", code)
		}
	}
	now = now.Add(11 * time.Second)
	get("mallory\n", wrong, "/api/users/list")
	// the right password: one line however many requests follow
	for i := 0; i < 4; i++ {
		if code := get("root", secret, "/api/users/list"); code != http.StatusOK {
			t.Fatalf("right password: %d", code)
		}
	}

	data, _ := os.ReadFile(a.path)
	for _, s := range []string{secret, wrong, base64.StdEncoding.EncodeToString([]byte("root:" + secret)), base64.StdEncoding.EncodeToString([]byte("root:" + wrong)), "203.0.113.99"} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("%q is in the audit file", s)
		}
	}
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	var got []string
	for _, r := range recs {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%s", r.Action, r.Actor, r.Target, r.Source, r.Result))
	}
	want := []string{
		"auth.login.fail|unverified:root|root|198.51.100.7|fail",
		"auth.login.fail|unverified:mallory|mallory|198.51.100.7|fail",
		"auth.login.ok|basic-auth:root|root|198.51.100.7|ok",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("login events\n got %q\nwant %q", got, want)
	}
	if len(recs) == 3 && !strings.Contains(recs[1].Detail, "4 more from this source") {
		t.Errorf("the suppressed attempts are not counted: %q", recs[1].Detail)
	}
}

func TestAdminAuditLoginThrottleStaysBounded(t *testing.T) {
	var th adminLoginThrottle
	now := time.Now()
	for i := 0; i < 3*adminAuditThrottleMaxKeys; i++ {
		th.shouldRecordFail(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), now)
		th.shouldRecordOK(fmt.Sprintf("u%d", i), now)
	}
	if len(th.failSeen) > adminAuditThrottleMaxKeys || len(th.okSeen) > adminAuditThrottleMaxKeys {
		t.Errorf("throttle maps grew to %d and %d", len(th.failSeen), len(th.okSeen))
	}
	// after the window the same source is recorded again
	if ok, _ := th.shouldRecordFail("a", now); !ok {
		t.Fatal("first failure not recorded")
	}
	if ok, _ := th.shouldRecordFail("a", now.Add(time.Second)); ok {
		t.Fatal("second failure inside the window recorded")
	}
	if ok, n := th.shouldRecordFail("a", now.Add(adminAuditLoginFailWindow+time.Second)); !ok || n != 1 {
		t.Fatalf("after the window: %v %d", ok, n)
	}
}

// ---- reading it back ----

func getJSON(t *testing.T, h http.HandlerFunc, target string) (int, []byte) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.SetBasicAuth(honestAdminUser, honestAdminPass)
	h(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestAdminAuditListEndpoint(t *testing.T) {
	a := useAdminAudit(t, "")
	a.maxBytes = 20000 // a few generations, so that paging crosses files
	for i := 1; i <= 150; i++ {
		mustRecord(t, a, auditActUserCreate, fmt.Sprintf("u%d", i))
	}
	oAdmin := &OvpnAdmin{}
	list := func(q string) []adminAuditRecord {
		code, body := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin"+q)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", q, code, body)
		}
		var recs []adminAuditRecord
		if err := json.Unmarshal(body, &recs); err != nil {
			t.Fatalf("%s: %v: %s", q, err, body)
		}
		return recs
	}
	newest := list("")
	if len(newest) != 100 {
		t.Fatalf("default limit: %d records", len(newest))
	}
	for i := 1; i < len(newest); i++ {
		if newest[i].Seq != newest[i-1].Seq-1 {
			t.Fatalf("not newest first without gaps at %d: %d then %d", i, newest[i-1].Seq, newest[i].Seq)
		}
	}
	top := newest[0].Seq
	// every read is itself a line (audit.read), so the newest line now is the one the first list wrote
	if n := list("?limit=7"); len(n) != 7 || n[0].Seq != top+1 || n[0].Action != auditActAuditRead {
		t.Errorf("limit=7: %d records, first %v", len(n), n)
	}
	// the cap itself is TestAuditListCapAndDefaultAreEnforced: 150 lines cannot show a cap of 500
	if n := list("?limit=100000"); len(n) < 150 {
		t.Errorf("a large limit gave %d records, the trail holds at least 150", len(n))
	}
	// paging with before walks the whole trail, generations included, exactly once
	var onDisk int
	for _, p := range a.files() {
		onDisk += len(readAuditFile(t, p))
	}
	seen := map[int64]bool{}
	before := ""
	for page := 0; page < 40; page++ {
		recs := list("?limit=20" + before)
		if len(recs) == 0 {
			break
		}
		for _, r := range recs {
			if seen[r.Seq] {
				t.Fatalf("seq %d twice", r.Seq)
			}
			seen[r.Seq] = true
		}
		before = fmt.Sprintf("&before=%d", recs[len(recs)-1].Seq)
	}
	if len(seen) != onDisk {
		t.Errorf("paging saw %d records, the files hold %d", len(seen), onDisk)
	}
	if recs := list("?before=1"); len(recs) != 0 {
		t.Errorf("before=1: %d records", len(recs))
	}
	if code, body := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin?limit=0"); code != http.StatusBadRequest {
		t.Errorf("limit=0: %d %s", code, body)
	}
	if code, _ := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin?limit=abc"); code != http.StatusBadRequest {
		t.Errorf("limit=abc: %d", code)
	}
	if code, _ := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin?before=-3"); code != http.StatusBadRequest {
		t.Errorf("before=-3: %d", code)
	}
	rec := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/api/audit/admin", nil)
	postReq.SetBasicAuth(honestAdminUser, honestAdminPass)
	oAdmin.adminAuditListHandler(rec, postReq)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
	// the records come back with the keys of the file, in its order
	code, body := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin?limit=1")
	if code != http.StatusOK || !strings.HasPrefix(string(body), `[{"seq":`) || !auditKeyOrder.MatchString(strings.Trim(string(body), "[]\n")) {
		t.Errorf("record JSON: %s", body)
	}
	// an empty trail is an empty array, not null
	useAdminAudit(t, "")
	if code, body := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin"); code != 200 || strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("empty trail: %d %s", code, body)
	}
}

func TestAdminAuditVerifyEndpoint(t *testing.T) {
	a := useAdminAudit(t, "")
	fillAudit(t, a, 5)
	oAdmin := &OvpnAdmin{}

	code, body := getJSON(t, oAdmin.adminAuditVerifyHandler, "/api/audit/verify")
	var ok adminAuditVerifyOK
	if code != 200 || json.Unmarshal(body, &ok) != nil || !ok.OK || ok.Lines != 5 || len(ok.LastHash) != 64 {
		t.Fatalf("clean file: %d %s", code, body)
	}
	if !strings.HasPrefix(string(body), `{"ok":true,"state":"verified","lines":5,"lastSeq":5,"lastHash":"`) {
		t.Errorf("shape: %s", body)
	}
	// the check is itself in the trail: line 6, audit.verify, ok
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	if last := recs[len(recs)-1]; last.Action != "audit.verify" || last.Result != "ok" || last.Actor != "basic-auth:operator" || last.Seq != 6 {
		t.Errorf("audit.verify line: %+v", last)
	}

	flipByteAt(t, a.path, 3, 25)
	code, body = getJSON(t, oAdmin.adminAuditVerifyHandler, "/api/audit/verify")
	if code != 200 || !strings.HasPrefix(string(body), `{"ok":false,"state":"broken","brokenAt":3,"reason":"`) {
		t.Fatalf("tampered file: %d %s", code, body)
	}
	recs2, _ := a.List(1, 0)
	if len(recs2) != 1 || recs2[0].Action != "audit.verify" || recs2[0].Result != "fail" {
		t.Errorf("a failed check is recorded as fail: %+v", recs2)
	}
}

func TestAdminAuditEndpointsWithoutATrail(t *testing.T) {
	asAdmin(t)
	old := adminAudit
	adminAudit = nil
	t.Cleanup(func() { adminAudit = old })
	oAdmin := &OvpnAdmin{}
	if code, _ := getJSON(t, oAdmin.adminAuditListHandler, "/api/audit/admin"); code != http.StatusServiceUnavailable {
		t.Errorf("list: %d", code)
	}
	if code, _ := getJSON(t, oAdmin.adminAuditVerifyHandler, "/api/audit/verify"); code != http.StatusServiceUnavailable {
		t.Errorf("verify: %d", code)
	}
	// and the hooks do nothing, not even panic
	var nilLog *adminAuditLog
	nilLog.fromRequest(httptest.NewRequest(http.MethodGet, "/", nil), auditActUserCreate, "x", true, "")
	nilLog.system(auditActCrlRebuild, "x", true, "")
	if _, err := nilLog.Record("system", "x", "y", "z", "ok", ""); err != nil {
		t.Error(err)
	}
}

func TestAdminAuditSourceIsThePeerWithoutPort(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.5:4711":     "192.0.2.5",
		"[2001:db8::1]:4711": "2001:db8::1",
		"[fe80::1%eth0]:80":  "fe80::1%eth0",
		"203.0.113.1":        "203.0.113.1",
		"":                   "local",
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = in
		r.Header.Set("X-Forwarded-For", "10.9.9.9")
		r.Header.Set("X-Real-IP", "10.9.9.9")
		if got := auditSource(r); got != want {
			t.Errorf("auditSource(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- the webhook ----

func TestAdminAuditWebhookURLRules(t *testing.T) {
	for _, ok := range []string{
		"https://logs.example.com/ingest", "https://203.0.113.5:8443/x", "HTTPS://logs.example.com",
		"http://127.0.0.1:9000/hook", "http://localhost:9000/hook", "http://[::1]:9000/hook", "http://127.5.5.5/x",
	} {
		if _, err := validateAuditWebhookURL(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://logs.example.com/ingest", "http://203.0.113.5/x", "http://127.0.0.1.example.com/x", "http://localhost.example.com/x",
		"ftp://127.0.0.1/x", "file:///etc/passwd", "gopher://localhost/", "logs.example.com/ingest", "https://", "", "http://0.0.0.0/x",
		"http://[::ffff:203.0.113.5]/x",
	} {
		if _, err := validateAuditWebhookURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// the panel does not start with a refused URL
	if _, err := openAdminAuditLog(filepath.Join(t.TempDir(), "a.log"), "http://logs.example.com/x"); err == nil {
		t.Error("openAdminAuditLog accepted a plain http webhook")
	}
}

type hookServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
	ctype  []string
	status int
	hold   chan struct{} // when set, handlers wait for it
	hits   atomic.Int64
}

func newHookServer(t *testing.T, status int) *hookServer {
	t.Helper()
	h := &hookServer{status: status}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		// the body is read first: only then does the server notice that the client hung up
		var b bytes.Buffer
		_, _ = b.ReadFrom(r.Body)
		if h.hold != nil {
			select {
			case <-h.hold:
			case <-r.Context().Done():
				return
			}
		}
		h.mu.Lock()
		h.bodies = append(h.bodies, b.String())
		h.ctype = append(h.ctype, r.Header.Get("Content-Type"))
		h.mu.Unlock()
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.Close)
	return h
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestAdminAuditWebhookDeliversEveryLineAsWritten(t *testing.T) {
	srv := newHookServer(t, 200)
	a := openTestAudit(t, srv.URL+"/hook")
	fillAudit(t, a, 5)
	waitFor(t, "5 posts", func() bool { srv.mu.Lock(); defer srv.mu.Unlock(); return len(srv.bodies) == 5 })
	lines := readAuditFile(t, a.path)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for i := range lines {
		if srv.bodies[i] != lines[i] {
			t.Errorf("post %d differs from the line in the file:\n%s\n%s", i+1, srv.bodies[i], lines[i])
		}
		if srv.ctype[i] != "application/json" {
			t.Errorf("content type %q", srv.ctype[i])
		}
	}
}

// A receiver that answers 500 changes nothing for the caller: the panel action keeps its result, the line
// is in the file.
func TestAdminAuditWebhook500DoesNotChangeTheHTTPResult(t *testing.T) {
	srv := newHookServer(t, 500)
	a := useAdminAudit(t, srv.URL)
	oAdmin, _ := setupFakeEasyrsa(t)

	rec := httptest.NewRecorder()
	oAdmin.userCreateHandler(rec, authedRequest(http.MethodPost, "/api/user/create", url.Values{"username": {"alice"}}, "operator"))
	if rec.Code != http.StatusOK {
		t.Fatalf("create with a failing webhook: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	oAdmin.userCreateHandler(rec, authedRequest(http.MethodPost, "/api/user/create", url.Values{"username": {"alice"}}, "operator"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate create: %d %s", rec.Code, rec.Body)
	}
	waitFor(t, "two posts", func() bool { return srv.hits.Load() == 2 })
	waitFor(t, "two failures counted", func() bool { return a.hook.failed.Load() == 2 })
	if a.Lines() != 2 {
		t.Errorf("%d lines in the file", a.Lines())
	}
	mustVerifyOK(t, a)
}

// A receiver that never answers: Record stays fast, the queue is bounded, the rest is dropped and counted.
func TestAdminAuditWebhookQueueIsBoundedAndNeverBlocks(t *testing.T) {
	srv := newHookServer(t, 200)
	srv.hold = make(chan struct{})
	a := openTestAudit(t, srv.URL)
	runtime.GC()
	goroutinesBefore := runtime.NumGoroutine()

	const n = 600
	start := time.Now()
	for i := 0; i < n; i++ {
		if _, err := a.Record("system", auditActUserCreate, "x", "local", "ok", ""); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Fatalf("%d records took %s with a stuck receiver", n, d)
	}
	waitFor(t, "the worker to take one", func() bool { return srv.hits.Load() >= 1 })
	if q := len(a.hook.queue); q > adminAuditWebhookQueue {
		t.Fatalf("queue length %d, bound %d", q, adminAuditWebhookQueue)
	}
	// every line is in the queue, dropped, or taken by the worker (one in flight, one more each time a post times out)
	dropped := a.hook.dropped.Load()
	taken := a.hook.failed.Load() + 1
	if min := int64(n-adminAuditWebhookQueue) - taken - 3; dropped < min || dropped > int64(n-adminAuditWebhookQueue) {
		t.Errorf("dropped %d of %d lines, expected between %d and %d (queue %d)", dropped, n, min, n-adminAuditWebhookQueue, adminAuditWebhookQueue)
	}
	goroutinesAfter := runtime.NumGoroutine()
	// 256 queued copies is all the memory the webhook holds, however long it lasts
	var peak uint64
	var ms runtime.MemStats
	for i := 0; i < 4; i++ {
		for j := 0; j < 200; j++ {
			_, _ = a.Record("system", auditActUserCreate, "x", "local", "ok", "")
		}
		runtime.GC()
		runtime.ReadMemStats(&ms)
		if i == 0 {
			peak = ms.HeapAlloc
		} else if ms.HeapAlloc > peak+4<<20 {
			t.Errorf("heap grew from %d to %d bytes while the webhook was stuck", peak, ms.HeapAlloc)
		}
	}
	if len(a.hook.queue) > adminAuditWebhookQueue {
		t.Errorf("queue length %d", len(a.hook.queue))
	}
	// a post that timed out leaves its connection goroutines for a moment: give them time before judging
	for i := 0; i < 40 && runtime.NumGoroutine() > goroutinesAfter+2; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > goroutinesAfter+2 {
		var stacks bytes.Buffer
		_ = pprof.Lookup("goroutine").WriteTo(&stacks, 1)
		t.Errorf("goroutines grew from %d to %d while the receiver was stuck:\n%s", goroutinesAfter, g, stacks.String())
	}
	_ = goroutinesBefore
	mustVerifyOK(t, a)
	close(srv.hold)
}

// The 3 s timeout: a receiver that hangs costs three seconds of the worker and one counted failure.
func TestAdminAuditWebhookTimesOutAfterThreeSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 3 s")
	}
	srv := newHookServer(t, 200)
	srv.hold = make(chan struct{})
	defer close(srv.hold)
	a := openTestAudit(t, srv.URL)
	start := time.Now()
	mustRecord(t, a, auditActUserCreate, "x")
	if d := time.Since(start); d > time.Second {
		t.Errorf("Record took %s", d)
	}
	waitFor(t, "the post to time out", func() bool { return a.hook.failed.Load() == 1 })
	if d := time.Since(start); d < 2900*time.Millisecond || d > 4500*time.Millisecond {
		t.Errorf("the post gave up after %s, want about 3s", d)
	}
}

func TestAdminAuditWebhookLogsOneLinePerPeriod(t *testing.T) {
	srv := newHookServer(t, 200)
	srv.hold = make(chan struct{})
	defer close(srv.hold)

	var mu sync.Mutex
	var buf bytes.Buffer
	oldOut := log.StandardLogger().Out
	log.SetOutput(&lockedWriter{mu: &mu, w: &buf})
	t.Cleanup(func() { log.SetOutput(oldOut) })

	w, err := newAdminAuditWebhookEvery(srv.URL+"/secret-path-token", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < adminAuditWebhookQueue+400; i++ {
		w.Enqueue([]byte(`{"x":1}`))
	}
	waitFor(t, "a drop line", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(buf.String(), "lines dropped")
	})
	time.Sleep(350 * time.Millisecond) // more periods pass; nothing new is dropped
	mu.Lock()
	out := buf.String()
	mu.Unlock()
	if n := strings.Count(out, "lines dropped"); n != 1 {
		t.Errorf("%d drop lines, want exactly 1 for a burst:\n%s", n, out)
	}
	if strings.Contains(out, "secret-path-token") {
		t.Errorf("the webhook path is in the log:\n%s", out)
	}
	if !strings.Contains(out, "http://127.0.0.1:") {
		t.Errorf("the line does not name the receiver:\n%s", out)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestAdminAuditWebhookDoesNotFollowRedirects(t *testing.T) {
	target := newHookServer(t, 200)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	a := openTestAudit(t, redirector.URL)
	mustRecord(t, a, auditActUserCreate, "x")
	waitFor(t, "the redirect to count as a failure", func() bool { return a.hook.failed.Load() == 1 })
	if target.hits.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

func TestAdminAuditWebhookGoneReceiverIsHarmless(t *testing.T) {
	srv := newHookServer(t, 200)
	url := srv.URL
	srv.Close()
	a := openTestAudit(t, url)
	for i := 0; i < 20; i++ {
		mustRecord(t, a, auditActUserCreate, "x")
	}
	waitFor(t, "20 failures", func() bool { return a.hook.failed.Load() == 20 })
	mustVerifyOK(t, a)
}

// ---- the ban handlers ----

// auditBanWatcher answers every request of the control directory with the given result, like the ban watcher
// of the openvpn container does. It is its own helper so that this file does not depend on the ban tests.
func auditBanWatcher(t *testing.T, ok bool) {
	t.Helper()
	dir := t.TempDir()
	ctl := filepath.Join(dir, banControlDirName)
	if err := os.Mkdir(ctl, 0o700); err != nil {
		t.Fatal(err)
	}
	setFlag(t, auditPath, filepath.Join(dir, "audit.tsv"))
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			names, _ := filepath.Glob(filepath.Join(ctl, "*.req"))
			for _, name := range names {
				data, err := os.ReadFile(name)
				if err != nil {
					continue
				}
				var req struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(data, &req) != nil {
					continue
				}
				_ = os.Remove(name)
				out, _ := json.Marshal(banControlResult{OK: ok, Message: "ovpn-ban said so"})
				_ = os.WriteFile(filepath.Join(ctl, req.ID+".result"), out, 0o600)
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
}

func TestAdminAuditBanAndUnban(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin := &OvpnAdmin{role: "master"}
	post := func(h http.HandlerFunc, path string, form url.Values) int {
		rec := httptest.NewRecorder()
		h(rec, authedRequest(http.MethodPost, path, form, "operator"))
		return rec.Code
	}
	auditBanWatcher(t, true)
	if code := post(oAdmin.banManualHandler, "/api/ban/manual", url.Values{"ip": {"198.51.100.77"}, "reason": {"port scan, do not log me"}}); code != http.StatusOK {
		t.Fatalf("ban: %d", code)
	}
	if code := post(oAdmin.unbanHandler, "/api/unban", url.Values{"ip": {"198.51.100.77"}}); code != http.StatusOK {
		t.Fatalf("unban: %d", code)
	}
	if code := post(oAdmin.banManualHandler, "/api/ban/manual", url.Values{"ip": {"nonsense"}}); code != http.StatusBadRequest {
		t.Fatalf("ban of nonsense: %d", code)
	}
	auditBanWatcher(t, false)
	if code := post(oAdmin.banManualHandler, "/api/ban/manual", url.Values{"ip": {"198.51.100.78"}}); code != http.StatusBadRequest {
		t.Fatalf("ban refused by the watcher: %d", code)
	}
	var got []string
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		got = append(got, r.Action+" "+r.Target+" "+r.Result)
		if strings.Contains(r.Detail, "do not log me") {
			t.Errorf("the free-text reason is in the trail: %q", r.Detail)
		}
	}
	want := []string{"ban.manual 198.51.100.77 ok", "unban 198.51.100.77 ok", "ban.manual nonsense fail", "ban.manual 198.51.100.78 fail"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

// The real limit: 10 MiB per file, five generations kept, the chain valid across all of them.
func TestAdminAuditRotatesAtTenMiBAndKeepsFiveGenerations(t *testing.T) {
	if testing.Short() {
		t.Skip("writes about 70 MiB")
	}
	a := openTestAudit(t, "")
	a.noSync = true // 150000 fsyncs would only test the disk
	detail := strings.Repeat("d", 150)
	var rotations int
	var lastSeq, prevLines int64
	for i := 0; rotations < 6; i++ {
		rec, err := a.Record("basic-auth:admin", auditActUserCreate, fmt.Sprintf("user%07d", i), "192.0.2.10", "ok", detail)
		if err != nil {
			t.Fatal(err)
		}
		lastSeq = rec.Seq
		if a.lines < prevLines { // the file was replaced by a new one
			rotations++
		}
		prevLines = a.lines
		if i > 400000 {
			t.Fatal("no rotation after 400000 records")
		}
	}
	if got := gens(a); fmt.Sprint(got) != "[1 2 3 4 5]" {
		t.Fatalf("generations: %v", got)
	}
	for n := 1; n <= 5; n++ {
		fi, err := os.Stat(a.generation(n))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() < adminAuditMaxBytes || fi.Size() > adminAuditMaxBytes+1024 {
			t.Errorf(".%d is %d bytes, want just over %d", n, fi.Size(), adminAuditMaxBytes)
		}
	}
	res := mustVerifyOK(t, a)
	t.Logf("%d records written, %d rotations, chain valid over %d lines in %d files", lastSeq, rotations, res.Lines, len(a.files()))
	first := parseAuditLines(t, readAuditFile(t, a.path)[:1])[0]
	if first.Action != adminAuditRotateAction {
		t.Errorf("the current file starts with %s", first.Action)
	}
}
