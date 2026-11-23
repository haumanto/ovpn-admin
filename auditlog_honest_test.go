package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tests of this file only use what the trail had at b781022 (handlers, files, helpers of
// auditlog_test.go), so that they run unchanged against the old commit: they are the red/green pair of the
// card "make verify honest and lock the endpoints".

const (
	honestAdminUser = "operator"
	honestAdminPass = "panel-test-pass"
)

// asAdmin makes the panel's Basic credentials the ones of authedAdmin.
func asAdmin(t *testing.T) {
	t.Helper()
	setFlag(t, basicUsername, honestAdminUser)
	setFlag(t, basicPassword, honestAdminPass)
}

// callAudit calls an audit handler the way the mux would after authentication.
func callAudit(t *testing.T, h http.HandlerFunc, target string, withCreds bool) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if withCreds {
		req.SetBasicAuth(honestAdminUser, honestAdminPass)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func honestVerify(t *testing.T) (int, map[string]any) {
	t.Helper()
	return callAudit(t, (&OvpnAdmin{}).adminAuditVerifyHandler, "/api/audit/verify", true)
}

// fillRotating writes records until the trail holds the given number of closed generations and some lines of
// the active file.
func fillRotating(t *testing.T, a *adminAuditLog, wantGens int) {
	t.Helper()
	a.maxBytes = 2000
	a.noSync = true
	for i := 0; i < 2000 && (len(gens(a)) < wantGens || a.Lines() < 3); i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	if len(gens(a)) != wantGens {
		t.Fatalf("generations %v, wanted %d", gens(a), wantGens)
	}
}

// (a) the active file is deleted while an intact .1 remains: that is not an empty trail
func TestAuditVerifyActiveFileMissingWhileGenerationsRemain(t *testing.T) {
	asAdmin(t)
	a := useAdminAudit(t, "")
	fillRotating(t, a, 2)
	if code, m := honestVerify(t); code != 200 || m["ok"] != true {
		t.Fatalf("before the deletion: %d %v", code, m)
	}
	if err := os.Remove(a.path); err != nil {
		t.Fatal(err)
	}
	code, m := honestVerify(t)
	if code != 200 || m["ok"] != false {
		t.Fatalf("the active file is gone but verify says %d %v", code, m)
	}
	t.Logf("verify answered: %v", m)
}

// (b) no file at all: zero lines and a zero hash is not "ok"
func TestAuditVerifyNoFilesAtAll(t *testing.T) {
	asAdmin(t)
	a := useAdminAudit(t, "")
	fillRotating(t, a, 2)
	// everything of the trail: the files, the generations, whatever sits next to them
	all, _ := filepath.Glob(a.path + "*")
	for _, p := range all {
		_ = os.Remove(p)
	}
	if left, _ := filepath.Glob(a.path + "*"); len(left) != 0 {
		t.Fatalf("files left: %v", left)
	}
	code, m := honestVerify(t)
	if code != 200 || m["ok"] != false {
		t.Fatalf("no file exists but verify says %d %v", code, m)
	}
	t.Logf("verify answered: %v", m)
}

// (c) the newest records are cut off, the rest is an intact chain
func TestAuditVerifyTruncatedSuffix(t *testing.T) {
	asAdmin(t)
	a := useAdminAudit(t, "")
	a.noSync = true
	for i := 0; i < 20; i++ {
		mustRecord(t, a, auditActUserCreate, "u")
	}
	lines := readAuditFile(t, a.path)
	keep := strings.Join(lines[:len(lines)-3], "\n") + "\n"
	if err := os.WriteFile(a.path, []byte(keep), 0600); err != nil {
		t.Fatal(err)
	}
	code, m := honestVerify(t)
	if code != 200 || m["ok"] != false {
		t.Fatalf("three records were cut off but verify says %d %v", code, m)
	}
	t.Logf("verify answered: %v", m)
}

// (d) a clean rotation across six files (the active one and five generations) verifies
func TestAuditVerifyCleanRotationAcrossSixFiles(t *testing.T) {
	asAdmin(t)
	a := useAdminAudit(t, "")
	fillRotating(t, a, 5)
	if n := len(a.files()); n != 6 {
		t.Fatalf("%d files, wanted 6", n)
	}
	total := 0
	for _, p := range a.files() {
		total += len(readAuditFile(t, p))
	}
	code, m := honestVerify(t)
	if code != 200 || m["ok"] != true {
		t.Fatalf("a clean rotation does not verify: %d %v", code, m)
	}
	// the verify of the response is the snapshot before its own audit.verify line
	if got := int(m["lines"].(float64)); got != total {
		t.Errorf("lines %d, files hold %d", got, total)
	}
}

// (e) one changed byte is found
func TestAuditVerifyByteEdit(t *testing.T) {
	asAdmin(t)
	a := useAdminAudit(t, "")
	fillRotating(t, a, 2)
	p := a.generation(1)
	flipByteAt(t, p, 2, 40)
	code, m := honestVerify(t)
	if code != 200 || m["ok"] != false {
		t.Fatalf("a byte was changed but verify says %d %v", code, m)
	}
	if reason, _ := m["reason"].(string); !strings.Contains(reason, filepath.Base(p)) {
		t.Errorf("the reason does not name the file: %v", m)
	}
}

// (f) without admin credentials configured the audit endpoints refuse, whoever asks
func TestAuditEndpointsRefuseWithoutAdminCredentials(t *testing.T) {
	a := useAdminAudit(t, "")     // installs the credentials of authedAdmin ...
	setFlag(t, basicUsername, "") // ... which the panel in this test does not have
	setFlag(t, basicPassword, "")
	mustRecord(t, a, auditActUserCreate, "alice")
	o := &OvpnAdmin{}
	for name, h := range map[string]http.HandlerFunc{"/api/audit/admin": o.adminAuditListHandler, "/api/audit/verify": o.adminAuditVerifyHandler} {
		for _, creds := range []bool{false, true} {
			before := a.Lines()
			code, m := callAudit(t, h, name, creds)
			if code != http.StatusForbidden {
				t.Errorf("%s (basic header %v) with no credentials configured: %d, want 403 (%v)", name, creds, code, m)
			}
			if _, leaked := m["lines"]; leaked {
				t.Errorf("%s answered with trail data: %v", name, m)
			}
			if a.Lines() != before {
				t.Errorf("%s: a refused request wrote %d line(s) into the trail", name, a.Lines()-before)
			}
		}
	}
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		if strings.HasPrefix(r.Action, "audit.") {
			t.Errorf("the refusals were recorded in the trail: %+v", r)
		}
	}
}
