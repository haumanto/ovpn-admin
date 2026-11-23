package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---- the tests below use what this card added (state, checkpoint, fault seam, the required switch) ----

func verifyState(t *testing.T) (int, map[string]any) {
	t.Helper()
	code, m := honestVerify(t)
	if code != 200 {
		t.Fatalf("verify answered %d", code)
	}
	return code, m
}

func fileSums(t *testing.T, paths []string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		out[filepath.Base(p)] = hex.EncodeToString(sum[:])
	}
	return out
}

// A green answer says which of the three states it is, and carries the anchor it was held against.
func TestAuditVerifyStatesAreExplicit(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	for i := 0; i < 5; i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	_, m := verifyState(t)
	if m["ok"] != true || m["state"] != "verified" {
		t.Fatalf("clean trail: %v", m)
	}
	// no checkpoint: the chain is intact but nothing shows the newest lines still exist -> unverified, not ok
	if err := os.Remove(a.checkpointPath()); err != nil {
		t.Fatal(err)
	}
	_, m = verifyState(t)
	if m["ok"] != false || m["state"] != "unverified" || !strings.Contains(m["reason"].(string), "no checkpoint") {
		t.Fatalf("missing checkpoint: %v", m)
	}
	// a damaged checkpoint is not a checkpoint either
	if err := os.WriteFile(a.checkpointPath(), []byte(`{"v":1,"seq":5,"hash":"x","ts":"t","sum":"y"}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, m = verifyState(t)
	if m["ok"] != false || m["state"] != "unverified" {
		t.Fatalf("damaged checkpoint: %v", m)
	}
	// a concrete break stays "broken"
	flipByteAt(t, a.path, 2, 20)
	_, m = verifyState(t)
	if m["ok"] != false || m["state"] != "broken" || m["brokenAt"] == nil {
		t.Fatalf("byte edit: %v", m)
	}
}

// (c) the checkpoint outlives the process: a trail cut short while the panel was down is found at the next start
func TestAuditCheckpointCatchesTruncationAcrossARestart(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	for i := 0; i < 40; i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	a.Close() // the final checkpoint: seq 40
	lines := readAuditFile(t, a.path)
	keep := strings.Join(lines[:25], "\n") + "\n"
	if err := os.WriteFile(a.path, []byte(keep), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatalf("the panel must still start: %v", err)
	}
	t.Cleanup(b.Close)
	old := adminAudit
	adminAudit = b
	t.Cleanup(func() { adminAudit = old })
	_, m := verifyState(t)
	if m["ok"] != false || m["state"] != "broken" {
		t.Fatalf("15 records are missing but verify says %v", m)
	}
	if ns := b.readNotices(); len(ns) != 1 || ns[0].Kind != adminAuditNoticeBroken || !strings.Contains(ns[0].Reason, "checkpoint names seq 40") {
		t.Fatalf("the start did not record the finding: %+v", ns)
	}
	// the finding survives another restart
	b.Close()
	c, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	adminAudit = c
	if _, m = verifyState(t); m["ok"] != false || m["state"] != "broken" {
		t.Fatalf("the finding was forgotten at the second start: %v", m)
	}
	// an operator moves the notice away: only then is the answer about the files again
	if err := os.Remove(c.noticePath()); err != nil {
		t.Fatal(err)
	}
}

// A start must not take .1 for the tip of an interrupted rotation when the checkpoint names a newer line.
func TestAuditRestartDoesNotResumeFromGenerationWhenCheckpointSaysOtherwise(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	a.maxBytes = 2000
	for len(gens(a)) < 1 {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	for i := 0; i < 6; i++ { // some lines in the new file, then more than the checkpoint interval
		mustRecord(t, a, auditActUserCreate, "u")
	}
	a.Close()
	if err := os.Remove(a.path); err != nil { // the active file is lost, .1 is intact
		t.Fatal(err)
	}
	b, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if ns := b.readNotices(); len(ns) != 1 || ns[0].Kind != adminAuditNoticeBroken || !strings.Contains(ns[0].Reason, "missing") {
		t.Fatalf("notices: %+v", ns)
	}
	if ok, bad := b.Verify(); ok != nil || bad == nil || bad.State != adminAuditStateBroken {
		t.Fatalf("verify after the start: %+v %+v", ok, bad)
	}
}

// ... and a rotation that really was cut off (the checkpoint names the last line of .1) is finished, quietly.
func TestAuditRestartFinishesAnInterruptedRotation(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	a.maxBytes = 2000
	fail := false
	a.fault = func(op string) error {
		if fail && op == "write" {
			return errors.New("injected: the marker write fails")
		}
		return nil
	}
	for a.size < a.maxBytes {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	fail = true
	if _, err := a.Record("system", auditActUserCreate, "x", "local", "ok", ""); err == nil {
		t.Fatal("the rotation marker could not be written but Record succeeded")
	}
	if !a.pendingRotate {
		t.Fatal("pendingRotate was cleared before the marker was written")
	}
	a.Close()
	b, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if ns := b.readNotices(); len(ns) != 0 {
		t.Fatalf("an honest interrupted rotation produced notices: %+v", ns)
	}
	if !b.pendingRotate {
		t.Fatal("the start did not resume the rotation")
	}
	if _, err := b.Record("system", auditActUserCreate, "y", "local", "ok", ""); err != nil {
		t.Fatal(err)
	}
	first := parseAuditLines(t, readAuditFile(t, b.path))[0]
	if first.Action != adminAuditRotateAction {
		t.Fatalf("the new file starts with %s", first.Action)
	}
	mustVerifyOK(t, b)
}

// The marker write fails: nothing clears pendingRotate, the next record starts the file with the marker.
func TestAuditRotationMarkerIsRetriedUntilWritten(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	a.maxBytes = 2000
	failOnce := false
	a.fault = func(op string) error {
		if failOnce && op == "write" {
			failOnce = false
			return syscall.ENOSPC
		}
		return nil
	}
	for a.size < a.maxBytes {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	failOnce = true
	if _, err := a.Record("system", auditActUserCreate, "lost", "local", "ok", ""); err == nil {
		t.Fatal("expected the failed marker write to be reported")
	}
	if !a.pendingRotate || a.lost.n != 1 {
		t.Fatalf("pendingRotate=%v lost=%d", a.pendingRotate, a.lost.n)
	}
	mustRecord(t, a, auditActUserCreate, "next")
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	got := []string{recs[0].Action, recs[1].Action, recs[2].Action}
	if strings.Join(got, ",") != "audit.rotate,audit.gap,user.create" {
		t.Fatalf("the new file starts with %v", got)
	}
	if !strings.Contains(recs[1].Detail, "1 audit record(s) could not be written") || !strings.Contains(recs[1].Detail, "no space left on device") {
		t.Errorf("the gap line does not say what happened: %s", recs[1].Detail)
	}
	res := mustVerifyOK(t, a)
	if res.Gaps != 1 {
		t.Errorf("verify counted %d gaps", res.Gaps)
	}
}

// A rename that fails during the shift of the generations leaves every file where it was.
func TestAuditRotationRollsBackWhenARenameFails(t *testing.T) {
	for _, failing := range []string{"admin-audit.log.2 admin-audit.log.3", "admin-audit.log admin-audit.log.1"} {
		t.Run(failing, func(t *testing.T) {
			a := openTestAudit(t, "")
			a.noSync = true
			a.maxBytes = 1500
			for len(gens(a)) < 5 {
				mustRecord(t, a, auditActUserCreate, "u")
			}
			for a.size < a.maxBytes-200 {
				mustRecord(t, a, auditActUserCreate, "u")
			}
			gensBefore := fileSums(t, []string{a.generation(1), a.generation(2), a.generation(3), a.generation(4), a.generation(5)})
			a.fault = func(op string) error {
				if op == "rename "+failing {
					return errors.New("injected rename failure")
				}
				return nil
			}
			for a.size < a.maxBytes {
				mustRecord(t, a, auditActUserCreate, "u")
			}
			mustRecord(t, a, auditActUserCreate, "after") // the rotation is attempted here and fails
			if !a.rotateRetryAt.After(a.now()) {
				t.Fatal("a failed rotation is retried at once")
			}
			if got := fileSums(t, []string{a.generation(1), a.generation(2), a.generation(3), a.generation(4), a.generation(5)}); fmt.Sprint(got) != fmt.Sprint(gensBefore) {
				t.Fatalf("the generations changed although the rotation failed:\n before %v\n after  %v", gensBefore, got)
			}
			if g := gens(a); fmt.Sprint(g) != "[1 2 3 4 5]" {
				t.Fatalf("generations %v (.5 was dropped?)", g)
			}
			if ok, bad := a.Verify(); ok == nil {
				t.Fatalf("the trail after a failed rotation does not verify: %+v", bad)
			}
			// the disk recovers, the retry time comes: the rotation happens and the chain still holds
			a.fault = nil
			now := a.now()
			a.now = func() time.Time { return now.Add(2 * time.Minute) }
			for i := 0; i < 3 && a.pendingRotate == false && len(readAuditFile(t, a.generation(1))) > 0 && fileSums(t, []string{a.generation(1)})["admin-audit.log.1"] == gensBefore["admin-audit.log.1"]; i++ {
				mustRecord(t, a, auditActUserCreate, "again")
			}
			if fileSums(t, []string{a.generation(1)})["admin-audit.log.1"] == gensBefore["admin-audit.log.1"] {
				t.Fatal("the rotation did not happen after the retry time")
			}
			mustVerifyOK(t, a)
		})
	}
}

// Durability: the line is synced before the counters move, the directory is synced after a rename, and a
// failed sync takes the line back.
func TestAuditDurabilityOrderAndFailedSync(t *testing.T) {
	a := openTestAudit(t, "") // real fsync
	a.maxBytes = 1200
	var mu sync.Mutex
	var ops []string
	a.fault = func(op string) error {
		mu.Lock()
		defer mu.Unlock()
		ops = append(ops, op)
		return nil
	}
	for len(gens(a)) < 1 {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	mu.Lock()
	seq := strings.Join(ops, ",")
	mu.Unlock()
	if !strings.Contains(seq, "write,sync,write,sync") {
		t.Errorf("a line is not synced right after its write: %s", seq)
	}
	// the rename of the active file is followed by a directory sync, before the marker is written
	i := strings.Index(seq, "rename admin-audit.log admin-audit.log.1")
	if i < 0 {
		t.Fatalf("no rotation in %s", seq)
	}
	rest := seq[i:]
	if d, w := strings.Index(rest, "syncdir"), strings.Index(rest, "write"); d < 0 || w < 0 || d > w {
		t.Errorf("the directory is not synced between the rename and the marker: %s", rest)
	}

	// a sync that fails: the line is not claimed, the counters stay, the file is cut back, the gap is told
	before, size := a.seq, a.size
	fi, _ := os.Stat(a.path)
	a.fault = func(op string) error {
		if op == "sync" {
			return syscall.EIO
		}
		return nil
	}
	if _, err := a.Record("system", auditActUserCreate, "x", "local", "ok", ""); err == nil {
		t.Fatal("a failed fsync was reported as written")
	}
	if a.seq != before || a.size != size {
		t.Errorf("counters moved: seq %d->%d size %d->%d", before, a.seq, size, a.size)
	}
	if fi2, _ := os.Stat(a.path); fi2.Size() != fi.Size() {
		t.Errorf("the unsynced line stayed in the file: %d -> %d bytes", fi.Size(), fi2.Size())
	}
	a.fault = nil
	mustRecord(t, a, auditActUserCreate, "y")
	mustVerifyOK(t, a)
}

// ENOSPC: the action is not stopped by default, the trail says afterwards that a record is missing; with
// OVPN_ADMIN_AUDIT_REQUIRED on the request answers 500.
func TestAuditRequiredSwitch(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	h := func(w http.ResponseWriter, r *http.Request) {
		_ = adminAudit.fromRequest(r, auditActUserCreate, "alice", true, "created")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
	run := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/user/create", nil)
		req.SetBasicAuth(honestAdminUser, honestAdminPass)
		auditRequiredMiddleware(http.HandlerFunc(h)).ServeHTTP(rec, req)
		return rec
	}
	enospc := func(op string) error {
		if op == "write" {
			return &os.PathError{Op: "write", Path: a.path, Err: syscall.ENOSPC}
		}
		return nil
	}
	if def := *adminAuditRequiredFlag; def {
		t.Fatalf("OVPN_ADMIN_AUDIT_REQUIRED defaults to %v, want false", def)
	}
	// off (default): the answer is the handler's, the failure is logged and counted
	a.fault = enospc
	if rec := run(); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("switch off, ENOSPC: %d %s", rec.Code, rec.Body)
	}
	if a.lost.n != 1 {
		t.Fatalf("the lost record was not counted: %d", a.lost.n)
	}
	if ok, _ := a.Verify(); ok == nil || ok.Unrecorded != 1 {
		t.Fatalf("a green verify does not say that a record is missing: %+v", ok)
	}
	// on: the same failure is a 500 and the body is the error, not the handler's answer
	setFlag(t, adminAuditRequiredFlag, true)
	if rec := run(); rec.Code != 500 || strings.Contains(rec.Body.String(), `"ok"`) || !strings.Contains(rec.Body.String(), "audit record could not be written") {
		t.Fatalf("switch on, ENOSPC: %d %s", rec.Code, rec.Body)
	}
	// on, and the disk is fine: the answer is the handler's
	a.fault = nil
	if rec := run(); rec.Code != 200 {
		t.Fatalf("switch on, healthy disk: %d %s", rec.Code, rec.Body)
	}
	// the trail says what happened: an audit.gap that names the two lost records and the cause
	var gap adminAuditRecord
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		if r.Action == auditActAuditGap {
			gap = r
		}
	}
	if gap.Seq == 0 || !strings.Contains(gap.Detail, "2 audit record(s) could not be written") || !strings.Contains(gap.Detail, "no space left on device") || gap.Result != "fail" {
		t.Fatalf("gap line: %+v", gap)
	}
	if res := mustVerifyOK(t, a); res.Gaps != 1 {
		t.Errorf("gaps %d", res.Gaps)
	}
}

// The login middleware, with the switch on, refuses a login that cannot be recorded.
func TestAuditRequiredSwitchOnTheLogin(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	setFlag(t, adminAuditRequiredFlag, true)
	a.fault = func(op string) error {
		if op == "write" {
			return syscall.ENOSPC
		}
		return nil
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := basicAuthMiddleware(next, honestAdminUser, honestAdminPass, "/ping")
	req := httptest.NewRequest(http.MethodGet, "/api/users/list", nil)
	req.SetBasicAuth(honestAdminUser, honestAdminPass)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 500 {
		t.Fatalf("login that could not be recorded: %d", rec.Code)
	}
}

// audit.read: reading the trail is in the trail, and with the right credentials only.
func TestAuditReadIsRecorded(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	mustRecord(t, a, auditActUserCreate, "alice")
	code, _ := callAudit(t, (&OvpnAdmin{}).adminAuditListHandler, "/api/audit/admin?limit=5", true)
	if code != 200 {
		t.Fatalf("list: %d", code)
	}
	recs := parseAuditLines(t, readAuditFile(t, a.path))
	last := recs[len(recs)-1]
	if last.Action != auditActAuditRead || last.Actor != "basic-auth:"+honestAdminUser || last.Result != "ok" || !strings.Contains(last.Detail, "returned=") {
		t.Fatalf("last line: %+v", last)
	}
}

// user.config.download says whether a configuration was produced: a template failure is a fail
func TestAuditConfigDownloadTemplateFailureIsAFailure(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, _ := setupFakeEasyrsa(t)
	easyrsaGenCrl()
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	rec := httptest.NewRecorder()
	oAdmin.userCreateHandler(rec, authedRequest(http.MethodPost, "/api/user/create", url.Values{"username": {"alice"}}, "operator"))
	if rec.Code != 200 {
		t.Fatalf("create: %d", rec.Code)
	}
	show := func() adminAuditRecord {
		rec := httptest.NewRecorder()
		oAdmin.userShowConfigHandler(rec, authedRequest(http.MethodGet, "/api/user/config/show?username=alice", url.Values{"username": {"alice"}}, "operator"))
		recs := parseAuditLines(t, readAuditFile(t, a.path))
		return recs[len(recs)-1]
	}
	if r := show(); r.Action != auditActUserConfigDownload || r.Result != "ok" {
		t.Fatalf("a good rendering: %+v", r)
	}
	bad := filepath.Join(t.TempDir(), "bad.tpl")
	if err := os.WriteFile(bad, []byte("remote {{.NoSuchField}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setFlag(t, clientConfigTemplatePath, bad)
	r := show()
	if r.Action != auditActUserConfigDownload || r.Result != "fail" || !strings.Contains(r.Detail, "template failed") {
		t.Fatalf("a template failure was recorded as %+v", r)
	}
}

// The contract at the top of auditlog.go lists exactly the names the code can record.
func TestAuditContractListsOnlyWhatIsRecorded(t *testing.T) {
	src, err := os.ReadFile("auditlog.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	head := text[:strings.Index(text, "const (\n\tadminAuditDefaultFile")]
	names := regexp.MustCompile(`auditAct\w+\s+=\s+"([^"]+)"`).FindAllStringSubmatch(text, -1)
	if len(names) < 15 {
		t.Fatalf("found %d action names", len(names))
	}
	for _, m := range names {
		if !strings.Contains(head, m[1]) {
			t.Errorf("the contract does not mention %s", m[1])
		}
	}
	for _, gone := range []string{`"auth.login.locked"`, `"settings.change"`} {
		if strings.Contains(text, gone) {
			t.Errorf("%s is a name without an emitter and must not be reserved", gone)
		}
	}
	// every other name has an emitter outside its own definition and outside the tests
	files, _ := filepath.Glob("*.go")
	var prod strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		prod.Write(b)
	}
	allProd := prod.String()
	consts := regexp.MustCompile(`(auditAct\w+)\s+=\s+"[^"]+"`).FindAllStringSubmatch(text, -1)
	for _, c := range consts {
		if c[1] == "auditActServerRenew" || c[1] == "auditActServerRenewConfirm" || c[1] == "auditActAuditGap" {
			continue // names of the certificate lifecycle code / written by the trail itself
		}
		if strings.Count(allProd, c[1]) < 2 {
			t.Errorf("%s has no emitter", c[1])
		}
	}
}

// ---- rotation at the real limit and the list cap ----

// A trail with the default limit rotates when the file reaches 10 MiB, and not before.
func TestAuditRotatesAtTenMiBForReal(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	if a.maxBytes != 10<<20 {
		t.Fatalf("a new trail rotates at %d", a.maxBytes)
	}
	detail := strings.Repeat("d", 190)
	target := strings.Repeat("t", 120)
	for i := 0; i < 40000 && len(gens(a)) == 0; i++ {
		if _, err := a.Record("basic-auth:admin", auditActUserCreate, target, "192.0.2.10", "ok", detail); err != nil {
			t.Fatal(err)
		}
	}
	if g := gens(a); fmt.Sprint(g) != "[1]" {
		t.Fatalf("no rotation after writing %d bytes: %v", a.size, g)
	}
	fi, _ := os.Stat(a.generation(1))
	if fi.Size() < 10<<20 || fi.Size() > 10<<20+1000 {
		t.Errorf(".1 is %d bytes, want 10 MiB plus at most one line", fi.Size())
	}
	cur := parseAuditLines(t, readAuditFile(t, a.path))
	if len(cur) != 2 || cur[0].Action != adminAuditRotateAction || cur[1].Action != auditActUserCreate {
		t.Fatalf("the new file holds %d lines, first %v", len(cur), cur[0].Action)
	}
	res := mustVerifyOK(t, a)
	t.Logf("rotated: .1 = %d bytes, verify lines=%d lastSeq=%d", fi.Size(), res.Lines, res.LastSeq)
}

// The cap of 500 and the default of 100 are observable: with 700 lines in the trail they are the sizes.
func TestAuditListCapAndDefaultAreEnforced(t *testing.T) {
	a := useAdminAudit(t, "")
	a.noSync = true
	for i := 0; i < 700; i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	o := &OvpnAdmin{}
	count := func(q string) int {
		code, m := getJSON(t, o.adminAuditListHandler, "/api/audit/admin"+q)
		if code != 200 {
			t.Fatalf("%s: %d", q, code)
		}
		var recs []adminAuditRecord
		if err := json.Unmarshal(m, &recs); err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}
	for q, want := range map[string]int{"": 100, "?limit=500": 500, "?limit=501": 500, "?limit=100000": 500, "?limit=3": 3} {
		if got := count(q); got != want {
			t.Errorf("%q returned %d records, want %d", q, got, want)
		}
	}
}

// TestAuditRealRun is the evidence run of the card, not a unit test: it only runs when OVPN_AUDIT_REAL_DIR
// names a directory, with OVPN_AUDIT_REAL_MODE=rotate (10 MiB through a trail with the default limit and a
// real fsync per line) or enospc (a directory on a full file system; the card runs it on a 256 KiB tmpfs).
func TestAuditRealRun(t *testing.T) {
	dir := os.Getenv("OVPN_AUDIT_REAL_DIR")
	if dir == "" {
		t.Skip("OVPN_AUDIT_REAL_DIR is not set")
	}
	asAdmin(t)
	a, err := openAdminAuditLog(filepath.Join(dir, "audit", "admin-audit.log"), "")
	if err != nil {
		t.Fatal(err)
	}
	old := adminAudit
	adminAudit = a
	t.Cleanup(func() { adminAudit = old; a.Close() })
	show := func(label string) {
		_, m := verifyState(t)
		b, _ := json.Marshal(m)
		t.Logf("%s: GET /api/audit/verify -> %s", label, b)
	}
	tail := func(n int) {
		lines := readAuditFile(t, a.path)
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		for _, l := range lines {
			t.Logf("   %s", l)
		}
	}
	switch os.Getenv("OVPN_AUDIT_REAL_MODE") {
	case "rotate":
		detail := strings.Repeat("d", 190)
		target := strings.Repeat("t", 120)
		start := time.Now()
		n := 0
		for len(gens(a)) == 0 {
			if _, err := a.Record("basic-auth:admin", auditActUserCreate, target, "192.0.2.10", "ok", detail); err != nil {
				t.Fatal(err)
			}
			n++
		}
		fi1, _ := os.Stat(a.generation(1))
		fi0, _ := os.Stat(a.path)
		t.Logf("%d records, %s with a real fsync per line: .1 = %d bytes (limit %d), active = %d bytes", n, time.Since(start).Round(time.Millisecond), fi1.Size(), 10<<20, fi0.Size())
		tail(2)
		show("after the rotation")
		cp, _ := os.ReadFile(a.checkpointPath())
		t.Logf("checkpoint file: %s", strings.TrimSpace(string(cp)))
	case "enospc":
		filler := filepath.Join(dir, "filler")
		fb := make([]byte, 64<<10)
		var kept []string
		for i := 0; ; i++ { // take the free space, keep about 6 KiB for the trail
			p := fmt.Sprintf("%s.%d", filler, i)
			if err := os.WriteFile(p, fb, 0600); err != nil {
				_ = os.Remove(p)
				break
			}
			kept = append(kept, p)
		}
		small := make([]byte, 512)
		for i := 0; ; i++ {
			p := fmt.Sprintf("%s.s%d", filler, i)
			if err := os.WriteFile(p, small, 0600); err != nil {
				_ = os.Remove(p)
				break
			}
			kept = append(kept, p)
			if i > 100000 {
				break
			}
		}
		if len(kept) == 0 {
			t.Fatal("no filler written")
		}
		// leave room for a few lines only (tmpfs counts 4 KiB pages): give back the last two small files
		for i := 0; i < 2 && len(kept) > 0; i++ {
			_ = os.Remove(kept[len(kept)-1])
			kept = kept[:len(kept)-1]
		}
		var firstErr error
		ok, failed := 0, 0
		for i := 0; i < 60; i++ {
			if _, err := a.Record("basic-auth:admin", auditActUserCreate, "alice", "192.0.2.10", "ok", strings.Repeat("d", 150)); err != nil {
				failed++
				if firstErr == nil {
					firstErr = err
				}
			} else {
				ok++
			}
		}
		t.Logf("disk full: %d records written, %d refused; first error: %v", ok, failed, firstErr)
		if failed == 0 {
			t.Fatal("the file system never filled up")
		}
		show("while the disk is full")
		// the admin handler answers 500 with the switch on and 200 with it off, the trail is untouched either way
		h := func(w http.ResponseWriter, r *http.Request) {
			_ = adminAudit.fromRequest(r, auditActUserDelete, "bob", true, "deleted")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}
		call := func() (int, string) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/user/delete", nil)
			req.SetBasicAuth(honestAdminUser, honestAdminPass)
			auditRequiredMiddleware(http.HandlerFunc(h)).ServeHTTP(rec, req)
			return rec.Code, strings.TrimSpace(rec.Body.String())
		}
		c, b := call()
		t.Logf("OVPN_ADMIN_AUDIT_REQUIRED=false: HTTP %d %s", c, b)
		setFlag(t, adminAuditRequiredFlag, true)
		c, b = call()
		t.Logf("OVPN_ADMIN_AUDIT_REQUIRED=true:  HTTP %d %s", c, b)
		setFlag(t, adminAuditRequiredFlag, false)
		for _, p := range kept {
			_ = os.Remove(p)
		}
		if _, err := a.Record("basic-auth:admin", auditActUserCreate, "carol", "192.0.2.10", "ok", "space is back"); err != nil {
			t.Fatalf("after freeing the space: %v", err)
		}
		t.Logf("space freed; the last lines of the trail:")
		tail(3)
		show("after the space came back")
	default:
		t.Fatal("OVPN_AUDIT_REAL_MODE must be rotate or enospc")
	}
}

// ---- card "audit verify must never go green after the records are gone": sentinel and clean stop ----

func cutNewestLines(t *testing.T, path string, n int) {
	t.Helper()
	lines := readAuditFile(t, path)
	if len(lines) <= n {
		t.Fatalf("%s has %d lines, cannot cut %d", path, len(lines), n)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-n], "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// The sentinel is created before the first line, 0600, outside the trail directory, and nothing removes it:
// not the rotation, not a restart, not Close.
func TestAuditSentinelLifecycle(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	a.maxBytes = 1500
	s := sentinelOf(a.path)
	if filepath.Dir(s) == filepath.Dir(a.path) {
		t.Fatalf("the sentinel %s is inside the trail directory", s)
	}
	if _, err := os.Lstat(s); err == nil {
		t.Fatal("the sentinel exists before any line")
	}
	mustRecord(t, a, auditActUserCreate, "u")
	fi, err := os.Lstat(s)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
		t.Fatalf("sentinel after the first line: %v %v", fi, err)
	}
	for len(gens(a)) < 2 {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	a.Close()
	b, err := openAdminAuditLog(a.path, "")
	if err != nil {
		t.Fatal(err)
	}
	mustRecord(t, b, auditActUserCreate, "u")
	b.Close()
	if _, err := os.Lstat(s); err != nil {
		t.Fatalf("the sentinel is gone after rotation, restart and close: %v", err)
	}
	if ns := b.readNotices(); len(ns) != 0 {
		t.Fatalf("an ordinary restart wrote findings: %+v", ns)
	}
}

// A trail from before the sentinel existed gets one at the first start, without a finding.
func TestAuditSentinelIsAddedToAnOlderTrail(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	for i := 0; i < 5; i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	a.Close()
	if err := os.Remove(sentinelOf(a.path)); err != nil {
		t.Fatal(err)
	}
	b := restartAuditNoCleanup(t, a.path)
	if _, err := os.Lstat(sentinelOf(a.path)); err != nil {
		t.Fatalf("an older trail was not anchored at its start: %v", err)
	}
	if ns := b.readNotices(); len(ns) != 0 {
		t.Fatalf("anchoring an older trail is not a finding: %+v", ns)
	}
}

func restartAuditNoCleanup(t *testing.T, path string) *adminAuditLog {
	t.Helper()
	b, err := openAdminAuditLog(path, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// Without a sentinel that can be created there is no first line (the record is counted as lost, the file
// stays empty), and with a trail that exists the panel does not start.
func TestAuditSentinelCannotBeCreated(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	a.fault = func(op string) error {
		if op == "sentinel" {
			return errors.New("injected: read-only file system")
		}
		return nil
	}
	if _, err := a.Record("x", auditActUserCreate, "u", "s", adminAuditResultOK, "d"); err == nil || !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("a line was written without the sentinel, or the error does not say why: %v", err)
	}
	if fi, _ := os.Stat(a.path); fi.Size() != 0 {
		t.Fatalf("a line is in the file although the sentinel could not be created (%d bytes)", fi.Size())
	}
	a.fault = nil
	mustRecord(t, a, auditActUserCreate, "u")
	if _, err := os.Lstat(sentinelOf(a.path)); err != nil {
		t.Fatal(err)
	}
	// the writer says what the gap was, as for any record that could not be written
	if rs := parseAuditLines(t, readAuditFile(t, a.path)); len(rs) != 2 || rs[0].Action != auditActAuditGap || rs[1].Action != auditActUserCreate {
		t.Fatalf("expected audit.gap then user.create, got %+v", rs)
	}

	// a trail with lines and no sentinel, in a place where none can be made: refused at the start
	b := openTestAudit(t, "")
	b.noSync = true
	mustRecord(t, b, auditActUserCreate, "u")
	b.Close()
	if err := os.Remove(sentinelOf(b.path)); err != nil {
		t.Fatal(err)
	}
	if _, err := openAdminAuditLogWithSentinel(b.path, "", filepath.Join(t.TempDir(), "no-such-dir", "sentinel")); err == nil || !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("started without being able to anchor the trail: %v", err)
	}
}

// A start with nothing at all and no sentinel does not write a checkpoint that a later start could use to
// call itself continuous with a trail that was never there; and with the sentinel it writes none either.
func TestAuditStartWithNothingWritesNoAuthorisingCheckpoint(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	for i := 0; i < 20; i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	a.Close()
	all, _ := filepath.Glob(a.path + "*")
	for _, p := range all {
		_ = os.Remove(p)
	}
	b := restartAuditNoCleanup(t, a.path)
	if _, err := os.Lstat(b.checkpointPath()); err == nil {
		t.Fatal("a start that lost its whole past wrote a checkpoint")
	}
	if ns := b.readNotices(); len(ns) != 1 || ns[0].Kind != adminAuditNoticeUnverified || !strings.Contains(ns[0].Reason, "cannot establish continuity") {
		t.Fatalf("finding: %+v", ns)
	}
}

// After Close nothing is written, not even by a rotation that was left pending.
func TestAuditClosedTrailWritesNothing(t *testing.T) {
	a := openTestAudit(t, "")
	a.noSync = true
	mustRecord(t, a, auditActUserCreate, "u")
	a.Close()
	a.Close() // idempotent
	if _, err := a.Record("x", auditActUserCreate, "u", "s", adminAuditResultOK, "d"); err == nil {
		t.Fatal("a record was accepted after Close")
	}
	if n := len(readAuditFile(t, a.path)); n != 1 {
		t.Fatalf("%d lines after Close, want 1", n)
	}
	// the checkpoint names the line that was there at Close
	cp, st, _ := readAdminAuditCheckpoint(a.checkpointPath())
	if st != adminAuditCheckpointOK || cp.Seq != 1 {
		t.Fatalf("checkpoint after Close: %v %+v", st, cp)
	}
}

// ---- a real signal to a real process ----

// TestAuditHelperProcessServe is not a test: it is the process TestAuditCleanStopWithARealSignal starts. It
// returns at once when the variables are not set.
func TestAuditHelperProcessServe(t *testing.T) {
	dir, addr := os.Getenv("OVPN_AUDIT_HELPER_DIR"), os.Getenv("OVPN_AUDIT_HELPER_ADDR")
	if dir == "" || addr == "" {
		return
	}
	n, _ := strconv.Atoi(os.Getenv("OVPN_AUDIT_HELPER_LINES"))
	a, err := openAdminAuditLog(filepath.Join(dir, "audit", "admin-audit.log"), "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: open:", err)
		os.Exit(2)
	}
	adminAudit = a
	for i := 0; i < n; i++ {
		if _, err := a.Record("basic-auth:helper", auditActUserCreate, "u", "192.0.2.1", adminAuditResultOK, "helper line"); err != nil {
			fmt.Fprintln(os.Stderr, "helper: record:", err)
			os.Exit(2)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "pong") })
	err = serveUntilStopped(addr, mux)
	fmt.Fprintln(os.Stderr, "helper: serve returned:", err)
	os.Exit(3)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

// runHelperAndStop starts the panel's serve loop in a child process with n records in its trail, waits until
// it answers, sends sig and returns the exit code.
func runHelperAndStop(t *testing.T, dir string, n int, sig syscall.Signal) int {
	t.Helper()
	addr := freeAddr(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditHelperProcessServe$")
	cmd.Env = append(os.Environ(), "OVPN_AUDIT_HELPER_DIR="+dir, "OVPN_AUDIT_HELPER_ADDR="+addr, "OVPN_AUDIT_HELPER_LINES="+strconv.Itoa(n))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	up := false
	for i := 0; i < 200 && !up; i++ {
		if resp, err := http.Get("http://" + addr + "/ping"); err == nil {
			resp.Body.Close()
			up = true
			break
		}
		select {
		case <-exited:
			t.Fatalf("the helper ended before it served:\n%s", out.String())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !up {
		_ = cmd.Process.Kill()
		t.Fatalf("the helper never answered:\n%s", out.String())
	}
	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the helper did not stop after %v:\n%s", sig, out.String())
	}
	t.Logf("helper output after %v:\n%s", sig, out.String())
	return cmd.ProcessState.ExitCode()
}

// SIGTERM and SIGINT close the trail: the checkpoint names the newest line, so a trail that was cut after
// the stop (1, 3 or 15 whole records) is found at the next start, and so is a trail that is gone.
func TestAuditCleanStopWithARealSignal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("signals are tested on linux")
	}
	for _, tc := range []struct {
		sig  syscall.Signal
		code int
		cut  int
	}{
		{syscall.SIGTERM, 143, 0},
		{syscall.SIGTERM, 143, 1},
		{syscall.SIGTERM, 143, 3},
		{syscall.SIGTERM, 143, 15},
		{syscall.SIGINT, 130, 1},
	} {
		t.Run(fmt.Sprintf("%v/cut %d", tc.sig, tc.cut), func(t *testing.T) {
			asAdmin(t)
			dir := t.TempDir()
			const lines = 20 // one checkpoint at 16: only the stop can anchor 17..20
			if code := runHelperAndStop(t, dir, lines, tc.sig); code != tc.code {
				t.Fatalf("exit code %d, want %d", code, tc.code)
			}
			path := filepath.Join(dir, "audit", "admin-audit.log")
			cp, st, err := readAdminAuditCheckpoint(path + ".checkpoint")
			if st != adminAuditCheckpointOK || cp.Seq != lines {
				t.Fatalf("checkpoint after the stop: %v %v %+v: the stop did not write it at seq %d", st, err, cp, lines)
			}
			if tc.cut > 0 {
				cutNewestLines(t, path, tc.cut)
			}
			b := restartAudit(t, path)
			_, m := honestVerify(t)
			if tc.cut == 0 {
				if m["ok"] != true || m["state"] != "verified" || m["checkpointSeq"] != float64(lines) {
					t.Fatalf("an untouched trail after a clean stop: %v", m)
				}
				return
			}
			if m["ok"] != false || m["state"] != "broken" {
				t.Fatalf("%d newest records were cut after a clean stop and verify says %v", tc.cut, m)
			}
			ns := b.readNotices()
			if len(ns) != 1 || ns[0].Kind != adminAuditNoticeBroken || !strings.Contains(ns[0].Reason, fmt.Sprintf("the newest %d records are missing", tc.cut)) {
				t.Fatalf("the start did not say what is missing: %+v", ns)
			}
		})
	}
}
