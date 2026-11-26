package src

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestReadPasswordLine(t *testing.T) {
	cases := []struct {
		name, in, want string
		err            error
	}{
		{"lf", "secret-pass-1\n", "secret-pass-1", nil},
		{"crlf", "secret-pass-1\r\n", "secret-pass-1", nil},
		{"no line end", "secret-pass-1", "secret-pass-1", nil},
		{"only the first line", "first\nsecond\n", "first", nil},
		{"spaces and dashes kept", "  -a b-  \n", "  -a b-  ", nil},
		{"empty line", "\n", "", nil},
		{"no input", "", "", errPasswordNoLine},
		{"too long", strings.Repeat("x", maxPasswordLine+1) + "\n", "", errPasswordLong},
		{"too long without line end", strings.Repeat("x", maxPasswordLine+10), "", errPasswordLong},
		{"exactly the limit", strings.Repeat("x", maxPasswordLine) + "\n", strings.Repeat("x", maxPasswordLine), nil},
	}
	for _, c := range cases {
		got, err := ReadPasswordLine(strings.NewReader(c.in))
		if !errors.Is(err, c.err) || got != c.want {
			t.Errorf("%s: got len %d, %v; want len %d, %v", c.name, len(got), err, len(c.want), c.err)
		}
	}
}

func TestResolvePassword(t *testing.T) {
	var warn bytes.Buffer
	// stdin wins, no warning
	pw, err := ResolvePassword("", false, true, strings.NewReader("from-stdin\n"), &warn, true, false)
	if err != nil || pw != "from-stdin" || warn.Len() != 0 {
		t.Fatalf("stdin: %q %v warn=%q", pw, err, warn.String())
	}
	// --password still works and prints exactly one line on stderr
	warn.Reset()
	pw, err = ResolvePassword("from-flag", true, false, strings.NewReader(""), &warn, true, false)
	if err != nil || pw != "from-flag" {
		t.Fatalf("flag: %q %v", pw, err)
	}
	if got := warn.String(); got != PasswordFlagDeprecation+"\n" || strings.Count(got, "\n") != 1 {
		t.Fatalf("deprecation line: %q", got)
	}
	if strings.Contains(warn.String(), "from-flag") {
		t.Fatal("the deprecation line carries the password")
	}
	// an empty --password= is a given password (as before)
	if pw, err = ResolvePassword("", true, false, strings.NewReader(""), io.Discard, true, false); err != nil || pw != "" {
		t.Fatalf("empty flag: %q %v", pw, err)
	}
	// both, neither
	if _, err = ResolvePassword("a", true, true, strings.NewReader("b\n"), io.Discard, true, false); !errors.Is(err, errPasswordBoth) {
		t.Fatalf("both: %v", err)
	}
	if _, err = ResolvePassword("", false, false, strings.NewReader("b\n"), io.Discard, true, false); !errors.Is(err, errPasswordMissing) {
		t.Fatalf("neither: %v", err)
	}
	if pw, err = ResolvePassword("", false, false, strings.NewReader("b\n"), io.Discard, false, true); err != nil || pw != "" {
		t.Fatalf("neither, not required: %q %v", pw, err)
	}
	// an empty line: refused for create/change-password, passed on for auth
	if _, err = ResolvePassword("", false, true, strings.NewReader("\n"), io.Discard, true, false); !errors.Is(err, errPasswordEmpty) {
		t.Fatalf("empty stdin: %v", err)
	}
	if pw, err = ResolvePassword("", false, true, strings.NewReader("\n"), io.Discard, false, true); err != nil || pw != "" {
		t.Fatalf("empty stdin for auth: %q %v", pw, err)
	}
}

// The 72 byte limit holds on the stdin path: the password read from stdin goes through CreateUser and
// ChangeUserPassword like a --password value, and nothing is written.
func TestStdinPasswordKeeps72ByteLimit(t *testing.T) {
	u := newTestUsers(t)
	long := strings.Repeat("p", 73)
	pw, err := ResolvePassword("", false, true, strings.NewReader(long+"\n"), io.Discard, true, false)
	if err != nil || pw != long {
		t.Fatalf("read: %v", err)
	}
	if _, err := u.CreateUser("alice", pw); !errors.Is(err, errPasswordTooLong) {
		t.Fatalf("create with 73 bytes: %v", err)
	}
	if u.CheckUserExistent("alice") {
		t.Fatal("a row was written for the refused password")
	}
	ok72 := strings.Repeat("p", 72)
	pw, _ = ResolvePassword("", false, true, strings.NewReader(ok72+"\n"), io.Discard, true, false)
	if _, err := u.CreateUser("alice", pw); err != nil {
		t.Fatalf("create with 72 bytes: %v", err)
	}
	if _, err := u.ChangeUserPassword("alice", pw+"x"); !errors.Is(err, errPasswordTooLong) {
		t.Fatalf("change-password with 73 bytes: %v", err)
	}
	var stored string
	if err := u.Database.QueryRow("SELECT password FROM users WHERE username = 'alice'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(ok72)) != nil {
		t.Fatal("the stored hash is not the one of the 72 byte password")
	}
}
