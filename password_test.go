package main

import (
	"strings"
	"testing"
)

// The password limit is in bytes (bcrypt hashes at most 72 bytes), the minimum in characters.
func TestValidatePasswordLength(t *testing.T) {
	cases := []struct {
		name    string
		pw      string
		wantErr string // "" = accepted, otherwise a part of the message
	}{
		{"empty", "", "too short"},
		{"6 bytes (the old minimum)", strings.Repeat("a", 6), "too short"},
		{"11 bytes", strings.Repeat("a", 11), "too short"},
		{"12 bytes", strings.Repeat("a", 12), ""},
		{"11 two-byte characters (22 bytes)", strings.Repeat("é", 11), "too short"},
		{"12 two-byte characters (24 bytes)", strings.Repeat("é", 12), ""},
		{"71 bytes", strings.Repeat("a", 71), ""},
		{"72 bytes", strings.Repeat("a", 72), ""},
		{"73 bytes", strings.Repeat("a", 73), "too long"},
		{"1000 bytes", strings.Repeat("a", 1000), "too long"},
		{"36 two-byte characters = 72 bytes", strings.Repeat("é", 36), ""},
		{"37 two-byte characters = 74 bytes", strings.Repeat("é", 37), "too long"},
		{"24 three-byte characters = 72 bytes", strings.Repeat("€", 24), ""},
		{"25 three-byte characters = 75 bytes", strings.Repeat("€", 25), "too long"},
		{"18 four-byte characters = 72 bytes", strings.Repeat("😀", 18), ""},
		{"71 bytes + one two-byte character = 73 bytes", strings.Repeat("a", 71) + "é", "too long"},
		{"70 bytes + one two-byte character = 72 bytes", strings.Repeat("a", 70) + "é", ""},
	}
	for _, c := range cases {
		err := validatePassword(c.pw)
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: rejected: %v", c.name, err)
		case c.wantErr != "" && err == nil:
			t.Errorf("%s: accepted, want an error containing %q", c.name, c.wantErr)
		case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
			t.Errorf("%s: error %q does not contain %q", c.name, err.Error(), c.wantErr)
		}
	}
}

func TestValidatePasswordMessages(t *testing.T) {
	if got := validatePassword(strings.Repeat("a", 11)).Error(); got != "Password too short, password length must be greater or equal 12" {
		t.Errorf("short message changed: %q", got)
	}
	if got := validatePassword(strings.Repeat("a", 73)).Error(); got != "Password too long, the hash accepts at most 72 bytes" {
		t.Errorf("long message: %q", got)
	}
}

// A rotate with a password that cannot be stored must change nothing: the certificate is not revoked
// and the old password row is not deleted (openvpn-user is not needed, the check comes first).
func TestRotateRejectsLongPasswordBeforeChangingAnything(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	if ok, msg := oAdmin.userCreate("alice", ""); !ok {
		t.Fatal(msg)
	}
	before := strings.Join(indexLines(t), ", ")
	setFlag(t, authByPassword, true)

	for _, pw := range []string{strings.Repeat("a", 73), "12345"} {
		err, msg := oAdmin.userRotate("alice", pw)
		if err == nil {
			t.Fatalf("rotate with a %d-byte password was accepted", len(pw))
		}
		if !strings.Contains(msg, "Password too") {
			t.Errorf("message %q does not name the password", msg)
		}
		if got := strings.Join(indexLines(t), ", "); got != before {
			t.Errorf("index.txt changed by a rejected rotate: %q -> %q", before, got)
		}
	}
}
