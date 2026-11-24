package src

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The login runs on a connection that may not write (mode=ro gives "attempt to write a readonly database", the
// error the hook user of the real stack gets); the applier runs on a read-write connection, like the panel does.

type spoolRig struct {
	rw    *OpenvpnUser // the root side: writes, applies
	login *OpenvpnUser // the hook side: read only, spools
	dir   string
	log   *strings.Builder
}

func newSpoolRig(t *testing.T) *spoolRig {
	t.Helper()
	base := t.TempDir()
	dbFile := filepath.Join(base, "users.db")
	rwDB, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rwDB.Close() })
	rw := &OpenvpnUser{Database: rwDB, SpoolDir: SpoolDirFor(dbFile)}
	rw.InitDb()
	rw.MigrateDb()
	if err := os.Mkdir(rw.SpoolDir, 0700); err != nil {
		t.Fatal(err)
	}
	roDB, err := sql.Open("sqlite3", "file:"+dbFile+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = roDB.Close() })
	var sb strings.Builder
	old := rehashLog
	rehashLog = &sb
	t.Cleanup(func() { rehashLog = old })
	spoolWarnOnce = sync.Once{}
	return &spoolRig{rw: rw, login: &OpenvpnUser{Database: roDB, SpoolDir: rw.SpoolDir}, dir: rw.SpoolDir, log: &sb}
}

func (r *spoolRig) entries(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestSpoolCost4RowBecomesCost12ThroughTheApplier(t *testing.T) {
	for _, blob := range []bool{false, true} {
		r := newSpoolRig(t)
		const pw = "throwaway-spool-pw"
		before := insertHash(t, r.rw, "alice", pw, 4, blob)
		if ok, err := r.login.AuthUser("alice", pw, ""); !ok || err != nil {
			t.Fatalf("blob=%v: login as the user who cannot write: %v, %v", blob, ok, err)
		}
		if got := storedHash(t, r.rw, "alice"); got != before {
			t.Fatalf("blob=%v: the read-only login changed the stored hash", blob)
		}
		if n := len(r.entries(t)); n != 1 {
			t.Fatalf("blob=%v: %d spool entries after the login, want 1 (log: %q)", blob, n, r.log.String())
		}
		if strings.Contains(r.log.String(), "warning") {
			t.Errorf("blob=%v: the login warned although the entry was spooled: %q", blob, r.log.String())
		}
		res, err := r.rw.ApplySpool()
		if err != nil || len(res) != 1 || !res[0].Applied || res[0].User != "alice" || res[0].OldCost != 4 {
			t.Fatalf("blob=%v: ApplySpool = %+v, %v", blob, res, err)
		}
		after := storedHash(t, r.rw, "alice")
		if !cost12Prefix.MatchString(after) {
			t.Fatalf("blob=%v: stored hash starts with %q, want cost 12", blob, after[:7])
		}
		if n := len(r.entries(t)); n != 0 {
			t.Errorf("blob=%v: %d entries left after the apply", blob, n)
		}
		var out strings.Builder
		PrintSpoolResults(&out, res)
		if out.String() != "openvpn-user: rehash applied user=\"alice\" cost 4 -> 12\n" {
			t.Errorf("blob=%v: result line %q", blob, out.String())
		}
		// the same secret still works against the new hash, and a wrong one does not
		if ok, err := r.rw.AuthUser("alice", pw, ""); !ok || err != nil {
			t.Errorf("blob=%v: the secret no longer works: %v, %v", blob, ok, err)
		}
		if ok, _ := r.rw.AuthUser("alice", pw+"x", ""); ok {
			t.Errorf("blob=%v: a wrong secret works", blob)
		}
		// nothing left to apply: an idle round changes nothing
		if res, err := r.rw.ApplySpool(); err != nil || len(res) != 0 {
			t.Errorf("blob=%v: second ApplySpool = %+v, %v", blob, res, err)
		}
	}
}

func TestStaleSpoolEntryIsDroppedAndTheCurrentHashIsUntouched(t *testing.T) {
	r := newSpoolRig(t)
	insertHash(t, r.rw, "bob", "old-password-1", 4, false)
	if ok, err := r.login.AuthUser("bob", "old-password-1", ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if len(r.entries(t)) != 1 {
		t.Fatalf("setup: no entry")
	}
	// the password is changed before the applier runs
	if _, err := r.rw.ChangeUserPassword("bob", "new-password-2"); err != nil {
		t.Fatal(err)
	}
	changed := storedHash(t, r.rw, "bob")
	res, err := r.rw.ApplySpool()
	if err != nil || len(res) != 1 || res[0].Applied || res[0].Dropped == "" {
		t.Fatalf("ApplySpool = %+v, %v; want one dropped entry", res, err)
	}
	if now := storedHash(t, r.rw, "bob"); now != changed {
		t.Fatalf("the stale entry overwrote the hash that was stored meanwhile")
	}
	if n := len(r.entries(t)); n != 0 {
		t.Errorf("%d entries left, the stale one must be gone", n)
	}
	if ok, err := r.rw.AuthUser("bob", "new-password-2", ""); !ok || err != nil {
		t.Errorf("the new password no longer works: %v, %v", ok, err)
	}
	if ok, _ := r.rw.AuthUser("bob", "old-password-1", ""); ok {
		t.Errorf("the old password works again")
	}
	var out strings.Builder
	PrintSpoolResults(&out, res)
	if !strings.HasPrefix(out.String(), "openvpn-user: rehash dropped user=\"bob\": ") || strings.Contains(out.String(), changed) {
		t.Errorf("result line %q", out.String())
	}
}

func TestSpoolEntryNeverContainsThePlaintext(t *testing.T) {
	r := newSpoolRig(t)
	const pw = "plaintext-that-must-not-be-written"
	before := insertHash(t, r.rw, "carol", pw, 4, false)
	if ok, err := r.login.AuthUser("carol", pw, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
	names := r.entries(t)
	if len(names) != 1 {
		t.Fatalf("entries %v, want exactly one and no temporary file", names)
	}
	path := filepath.Join(r.dir, names[0])
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), pw) || strings.Contains(r.log.String(), pw) {
		t.Fatalf("the plaintext reached the spool or the log")
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0600 {
		t.Errorf("entry mode %v, want 0600", fi.Mode().Perm())
	}
	var e spoolEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if e.User != "carol" || e.Old != before || !cost12Prefix.MatchString(e.New) || e.Time == 0 || e.Version != 1 {
		t.Errorf("entry fields: user=%q oldOK=%v new=%q... time=%d version=%d", e.User, e.Old == before, e.New[:7], e.Time, e.Version)
	}
	if names[0] != spoolFileName("carol") {
		t.Errorf("file name %q is not the name of the user", names[0])
	}
}

func TestSecondLoginDoesNotCreateASecondEntryForTheSameUser(t *testing.T) {
	r := newSpoolRig(t)
	const pw = "two-logins-pw"
	insertHash(t, r.rw, "dave", pw, 4, false)
	if ok, err := r.login.AuthUser("dave", pw, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
	names := r.entries(t)
	first, _ := os.ReadFile(filepath.Join(r.dir, names[0]))
	fi1, _ := os.Stat(filepath.Join(r.dir, names[0]))
	time.Sleep(20 * time.Millisecond)
	if ok, err := r.login.AuthUser("dave", pw, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
	names2 := r.entries(t)
	if len(names2) != 1 || names2[0] != names[0] {
		t.Fatalf("entries after the second login: %v, want the same single entry", names2)
	}
	second, _ := os.ReadFile(filepath.Join(r.dir, names2[0]))
	fi2, _ := os.Stat(filepath.Join(r.dir, names2[0]))
	if string(first) != string(second) || !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Errorf("the second login rewrote the entry")
	}
	// another user gets an entry of their own
	insertHash(t, r.rw, "erin", pw, 4, false)
	if ok, err := r.login.AuthUser("erin", pw, ""); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if n := len(r.entries(t)); n != 2 {
		t.Errorf("%d entries for two users, want 2", n)
	}
}

// A stale entry (the hash changed after it was written) is replaced by a login that sees the hash that is stored now.
func TestEntryForAnOldHashIsReplacedByANewerLogin(t *testing.T) {
	r := newSpoolRig(t)
	insertHash(t, r.rw, "fay", "pw-one", 4, false)
	if ok, _ := r.login.AuthUser("fay", "pw-one", ""); !ok {
		t.Fatal("login 1")
	}
	// the stored hash is replaced by another cost 4 hash (the change tool of an older release), the entry is stale
	if _, err := r.rw.Database.Exec("UPDATE users SET password = ? WHERE username = ?", mustHash(t, "pw-two", 4), "fay"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.login.AuthUser("fay", "pw-two", ""); !ok {
		t.Fatal("login 2")
	}
	res, err := r.rw.ApplySpool()
	if err != nil || len(res) != 1 || !res[0].Applied {
		t.Fatalf("ApplySpool = %+v, %v", res, err)
	}
	if ok, err := r.rw.AuthUser("fay", "pw-two", ""); !ok || err != nil {
		t.Errorf("the secret of the second login does not work: %v, %v", ok, err)
	}
	if h := storedHash(t, r.rw, "fay"); !cost12Prefix.MatchString(h) {
		t.Errorf("not re-made")
	}
}

func TestUnusableSpoolDoesNotFailTheLoginAndWarnsOnce(t *testing.T) {
	r := newSpoolRig(t)
	insertHash(t, r.rw, "gil", "pw-gil", 4, false)
	insertHash(t, r.rw, "hal", "pw-hal", 4, false)
	r.login.SpoolDir = filepath.Join(r.dir, "does", "not", "exist")
	for _, u := range []string{"gil", "hal"} {
		if ok, err := r.login.AuthUser(u, "pw-"+u[:3], ""); !ok || err != nil {
			t.Fatalf("login %s: %v, %v; an unusable spool must not fail the login", u, ok, err)
		}
	}
	if n := strings.Count(r.log.String(), "\n"); n != 1 || !strings.Contains(r.log.String(), "warning") {
		t.Errorf("want one warning line for the process, got %q", r.log.String())
	}
	if strings.Contains(r.log.String(), "pw-gil") || strings.Contains(r.log.String(), "$2") {
		t.Errorf("the warning leaks a secret or a hash: %q", r.log.String())
	}
	// no spool configured at all behaves the same
	r.login.SpoolDir = ""
	if ok, err := r.login.AuthUser("gil", "pw-gil", ""); !ok || err != nil {
		t.Errorf("login without a spool directory: %v, %v", ok, err)
	}
}

// The hook user can write anything into the spool directory: the applier believes none of it.
func TestApplierRefusesForgedEntries(t *testing.T) {
	r := newSpoolRig(t)
	const pw = "victim-pw"
	before := insertHash(t, r.rw, "ivy", pw, 4, false)
	good12 := mustHash(t, "attacker-pw", 12)
	low4 := mustHash(t, "attacker-pw", 4)
	write := func(name string, e any) {
		raw, _ := json.Marshal(e)
		if s, ok := e.(string); ok {
			raw = []byte(s)
		}
		if err := os.WriteFile(filepath.Join(r.dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// 1 wrong file name for the user, 2 new hash below the target cost, 3 not JSON, 4 unknown field, 5 junk name,
	// 6 a symlink to a good entry, 7 too large
	write(spoolFileName("someone-else"), spoolEntry{Version: 1, User: "ivy", Old: before, New: good12, Time: 1})
	write(spoolFileName("ivy"), spoolEntry{Version: 1, User: "ivy", Old: before, New: low4, Time: 1})
	write(spoolFileName("ivy2"), "{ nope")
	write(spoolFileName("ivy3"), `{"version":1,"user":"ivy3","old":"x","new":"y","time":1,"extra":true}`)
	write("not-an-entry.txt", "x")
	target := filepath.Join(t.TempDir(), "target.json")
	raw, _ := json.Marshal(spoolEntry{Version: 1, User: "ivy", Old: before, New: good12, Time: 1})
	if err := os.WriteFile(target, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(r.dir, spoolFileName("ivy4"))); err != nil {
		t.Fatal(err)
	}
	write(spoolFileName("ivy5"), strings.Repeat("a", spoolMaxEntry+10))

	res, err := r.rw.ApplySpool()
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 7 {
		t.Fatalf("%d results, want 7: %+v", len(res), res)
	}
	for _, x := range res {
		if x.Applied || x.Dropped == "" {
			t.Errorf("a forged entry was not dropped: %+v", x)
		}
	}
	if now := storedHash(t, r.rw, "ivy"); now != before {
		t.Fatalf("a forged entry changed the stored hash")
	}
	if n := len(r.entries(t)); n != 0 {
		t.Errorf("%d entries left, all forged ones must be removed", n)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the target of the symlink is gone: %v", err)
	}
}

// A database that cannot be written now keeps the entry for the next round.
func TestEntryStaysWhenTheDatabaseRefusesTheUpdate(t *testing.T) {
	r := newSpoolRig(t)
	insertHash(t, r.rw, "jon", "pw-jon", 4, false)
	if ok, _ := r.login.AuthUser("jon", "pw-jon", ""); !ok {
		t.Fatal("login")
	}
	if _, err := r.rw.Database.Exec("CREATE TRIGGER no_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, 'refused for the test'); END"); err != nil {
		t.Fatal(err)
	}
	res, err := r.rw.ApplySpool()
	if err != nil || len(res) != 1 || res[0].Err == nil || res[0].Applied {
		t.Fatalf("ApplySpool = %+v, %v", res, err)
	}
	if n := len(r.entries(t)); n != 1 {
		t.Fatalf("%d entries, the unapplied one must stay", n)
	}
	if _, err := r.rw.Database.Exec("DROP TRIGGER no_update"); err != nil {
		t.Fatal(err)
	}
	res, err = r.rw.ApplySpool()
	if err != nil || len(res) != 1 || !res[0].Applied {
		t.Fatalf("second round: %+v, %v", res, err)
	}
}

func TestApplySpoolWithoutADirectoryDoesNothing(t *testing.T) {
	r := newSpoolRig(t)
	if err := os.Remove(r.dir); err != nil {
		t.Fatal(err)
	}
	if res, err := r.rw.ApplySpool(); err != nil || len(res) != 0 {
		t.Errorf("missing directory: %+v, %v", res, err)
	}
	if res, err := (&OpenvpnUser{Database: r.rw.Database}).ApplySpool(); err != nil || len(res) != 0 {
		t.Errorf("no directory configured: %+v, %v", res, err)
	}
}

func TestStaleTemporaryFilesAreCleanedUpFreshOnesKept(t *testing.T) {
	r := newSpoolRig(t)
	oldTmp := filepath.Join(r.dir, spoolTempPrefix+"old")
	freshTmp := filepath.Join(r.dir, spoolTempPrefix+"fresh")
	for _, p := range []string{oldTmp, freshTmp} {
		if err := os.WriteFile(p, []byte("{"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldTmp, past, past); err != nil {
		t.Fatal(err)
	}
	if res, err := r.rw.ApplySpool(); err != nil || len(res) != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	if _, err := os.Stat(oldTmp); !os.IsNotExist(err) {
		t.Errorf("the old temporary file is still there")
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Errorf("a fresh temporary file (a hook may be writing it) was removed")
	}
}

func mustHash(t *testing.T, password string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}
