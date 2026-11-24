package src

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// These tests need cgo (go-sqlite3): in golang:1.26-alpine install gcc and musl-dev first.

var cost12Prefix = regexp.MustCompile(`^\$2[ab]\$12\$`)

func newTestUsers(t *testing.T) *OpenvpnUser {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	u := &OpenvpnUser{Database: db}
	u.InitDb()
	u.MigrateDb()
	return u
}

// insertHash stores a row with a hash made at the given cost, the way an old database holds it.
func insertHash(t *testing.T, u *OpenvpnUser, user, password string, cost int, asBlob bool) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		t.Fatal(err)
	}
	var stored any = string(h)
	if asBlob {
		stored = h // change-password stores its hash as a BLOB
	}
	if _, err := u.Database.Exec("INSERT INTO users(username, password, secret, revoked, deleted, app_configured) VALUES (?, ?, '', 0, 0, 0)", user, stored); err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func storedHash(t *testing.T, u *OpenvpnUser, user string) string {
	t.Helper()
	var h string
	if err := u.Database.QueryRow("SELECT password FROM users WHERE username = ?", user).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

func captureRehashLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := rehashLog
	rehashLog = &buf
	t.Cleanup(func() { rehashLog = old })
	return &buf
}

func TestAuthUserRehashesCost4ToCost12(t *testing.T) {
	u := newTestUsers(t)
	out := captureRehashLog(t)
	const pw = "throwaway-pw-for-cost-4"
	before := insertHash(t, u, "alice", pw, 4, false)
	if c, _ := bcrypt.Cost([]byte(before)); c != 4 {
		t.Fatalf("setup: cost %d, want 4", c)
	}

	ok, err := u.AuthUser("alice", pw, "")
	if err != nil || !ok {
		t.Fatalf("AuthUser = %v, %v; want true, nil", ok, err)
	}
	after := storedHash(t, u, "alice")
	t.Logf("stored hash before: %s...  after: %s...", before[:7], after[:7])
	if !cost12Prefix.MatchString(after) {
		t.Fatalf("stored hash starts with %q, want $2a$12$ or $2b$12$", after[:7])
	}
	if got := out.String(); got != "openvpn-user: rehash cost 4 -> 12\n" {
		t.Errorf("notice = %q", got)
	}
	// the same password still works, now against the new hash, and nothing is rewritten again
	ok, err = u.AuthUser("alice", pw, "")
	if err != nil || !ok {
		t.Fatalf("second AuthUser = %v, %v; want true, nil", ok, err)
	}
	if again := storedHash(t, u, "alice"); again != after {
		t.Errorf("a cost 12 hash was rewritten")
	}
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("second login printed a second notice: %q", out.String())
	}
	// a wrong password is refused and changes nothing
	if ok, err := u.AuthUser("alice", pw+"x", ""); ok || err == nil {
		t.Errorf("wrong password accepted: %v, %v", ok, err)
	}
	if now := storedHash(t, u, "alice"); now != after {
		t.Errorf("a failed login changed the stored hash")
	}
	if strings.Contains(out.String(), pw) {
		t.Errorf("the password reached the log")
	}
}

func TestAuthUserRehashesABlobHash(t *testing.T) {
	u := newTestUsers(t)
	captureRehashLog(t)
	insertHash(t, u, "bob", "blob-row-pw", 4, true)
	if ok, err := u.AuthUser("bob", "blob-row-pw", ""); !ok || err != nil {
		t.Fatalf("AuthUser = %v, %v", ok, err)
	}
	if h := storedHash(t, u, "bob"); !cost12Prefix.MatchString(h) {
		t.Fatalf("a BLOB cost 4 hash was not re-made: %q", h[:7])
	}
}

func TestAuthUserLeavesCost12Alone(t *testing.T) {
	u := newTestUsers(t)
	out := captureRehashLog(t)
	if _, err := u.CreateUser("carol", "cost-12-pw"); err != nil {
		t.Fatal(err)
	}
	before := storedHash(t, u, "carol")
	if !cost12Prefix.MatchString(before) {
		t.Fatalf("CreateUser stored %q", before[:7])
	}
	if ok, err := u.AuthUser("carol", "cost-12-pw", ""); !ok || err != nil {
		t.Fatalf("AuthUser = %v, %v", ok, err)
	}
	if after := storedHash(t, u, "carol"); after != before {
		t.Errorf("a cost 12 hash was rewritten")
	}
	if out.Len() != 0 {
		t.Errorf("a cost 12 login printed %q", out.String())
	}
}

func TestRehashFailureWarnsOnceAndLoginSucceeds(t *testing.T) {
	u := newTestUsers(t)
	out := captureRehashLog(t)
	const pw = "pw-that-must-not-be-logged"
	before := insertHash(t, u, "dave", pw, 4, false)
	if _, err := u.Database.Exec("CREATE TRIGGER no_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, 'read only for the test'); END"); err != nil {
		t.Fatal(err)
	}
	ok, err := u.AuthUser("dave", pw, "")
	if err != nil || !ok {
		t.Fatalf("AuthUser = %v, %v; a failed re-hash must not fail the login", ok, err)
	}
	if after := storedHash(t, u, "dave"); after != before {
		t.Errorf("the hash changed although the update was refused")
	}
	log := out.String()
	if n := strings.Count(log, "\n"); n != 1 || !strings.Contains(log, "warning") {
		t.Errorf("want exactly one warning line, got %q", log)
	}
	if strings.Contains(log, pw) || strings.Contains(log, before) {
		t.Errorf("the warning leaks the password or the hash: %q", log)
	}
	if strings.Contains(log, "rehash cost") {
		t.Errorf("a notice was printed for a re-hash that did not happen: %q", log)
	}
}

// A password change between the read and the update must win: the re-hash of the old password may not overwrite it.
func TestRehashDoesNotOverwriteAChangedPassword(t *testing.T) {
	u := newTestUsers(t)
	out := captureRehashLog(t)
	old := insertHash(t, u, "erin", "old-password", 4, false)
	if _, err := u.ChangeUserPassword("erin", "new-password"); err != nil {
		t.Fatal(err)
	}
	changed := storedHash(t, u, "erin")
	u.rehashAfterLogin("erin", old, "old-password") // the login that read the old hash finishes late
	if now := storedHash(t, u, "erin"); now != changed {
		t.Fatalf("the late re-hash overwrote the changed password")
	}
	if ok, err := u.AuthUser("erin", "new-password", ""); !ok || err != nil {
		t.Errorf("new password no longer works: %v, %v", ok, err)
	}
	if ok, _ := u.AuthUser("erin", "old-password", ""); ok {
		t.Errorf("old password works again")
	}
	if out.Len() != 0 {
		t.Errorf("printed %q", out.String())
	}
}
