package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// writeTestClient makes what build-client-full writes for a user: the certificate, its private key and
// its request, all three of the same key pair.
func writeTestClient(t *testing.T, cn string, serial int64) (string, []byte, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	return fmt.Sprintf("%X", serial), enc("CERTIFICATE", certDER), enc("PRIVATE KEY", keyDER), enc("CERTIFICATE REQUEST", csrDER)
}

const fakeOpenvpnUser = `#!/bin/sh
cmd=$1; shift
db=""; user=""; pw=""
for a in "$@"; do
  case "$a" in
    --db.path=*) db="${a#--db.path=}" ;;
    --user=*) user="${a#--user=}" ;;
    --password=*) pw="${a#--password=}" ;;
  esac
done
[ -f "$db.fail" ] && grep -qx "$cmd" "$db.fail" && { echo "injected failure of $cmd" >&2; exit 1; }
[ "$cmd" = list ] && [ -f "$db.failafterchange" ] && [ -f "$db.changed" ] && { echo "injected failure of list after change-password" >&2; exit 1; }
touch "$db"
case "$cmd" in
  list)
    if [ ! -s "$db" ]; then echo "No users created yet"; exit 0; fi
    echo "id | username | revoked | deleted | app_configured"
    i=0
    while IFS='|' read -r n p r; do i=$((i+1)); echo "$i  | $n | $r | false | false"; done < "$db" ;;
  create)
    if grep -q "^$user|" "$db"; then echo "user exists" >&2; exit 1; fi
    echo "$user|$pw|false" >> "$db" ;;
  delete)
    grep -v "^$user|" "$db" > "$db.new"; mv "$db.new" "$db" ;;
  revoke)
    grep -q "^$user|" "$db" || exit 1
    sed -i "s/^\($user|.*|\)false\$/\1true/" "$db" ;;
  restore)
    sed -i "s/^\($user|.*|\)true\$/\1false/" "$db" ;;
  change-password)
    grep -q "^$user|" "$db" || exit 1
    sed -i "s/^$user|[^|]*|/$user|$pw|/" "$db"; touch "$db.changed" ;;
  auth)
    grep -q "^$user|$pw|false$" "$db" || exit 1 ;;
  *) echo "unknown command $cmd" >&2; exit 1 ;;
esac
`

// setupFakeOpenvpnUser puts a fake openvpn-user first in PATH and turns --auth.password on. The database
// is a text file "user|password|revoked"; "<db>.fail" holds the name of a command that must fail.
func setupFakeOpenvpnUser(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openvpn-user"), []byte(fakeOpenvpnUser), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	db := filepath.Join(dir, "users.db")
	setFlag(t, authDatabase, db)
	setFlag(t, authByPassword, true)
	return db
}

func failOpenvpnUser(t *testing.T, db, command string) {
	t.Helper()
	if err := os.WriteFile(db+".fail", []byte(command+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func readDB(t *testing.T, db string) string {
	t.Helper()
	data, err := os.ReadFile(db)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

// dbRow returns "password|revoked" of user in the fake database ("" when there is no row).
func dbRow(t *testing.T, db, user string) string {
	t.Helper()
	for _, line := range strings.Split(readDB(t, db), "\n") {
		if strings.HasPrefix(line, user+"|") {
			return strings.TrimPrefix(line, user+"|")
		}
	}
	return ""
}

// snapshotPKI reads every file below the easy-rsa directory (except the fake's switches).
func snapshotPKI(t *testing.T, pki string) map[string]string {
	t.Helper()
	root := filepath.Dir(pki)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".fake-") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertSamePKI(t *testing.T, before, after map[string]string) {
	t.Helper()
	var diffs []string
	for p, b := range before {
		if a, ok := after[p]; !ok {
			diffs = append(diffs, "missing after: "+p)
		} else if a != b {
			diffs = append(diffs, "changed: "+p)
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			diffs = append(diffs, "new after: "+p)
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("the PKI is not as before the failed rotation:\n  %s", strings.Join(diffs, "\n  "))
	}
}

// forEasyrsaLayouts runs fn against both ways easy-rsa lays out the files of a revoked certificate.
func forEasyrsaLayouts(t *testing.T, fn func(t *testing.T, oAdmin *OvpnAdmin, pki string)) {
	t.Helper()
	for _, layout := range []struct {
		name string
		keep bool
	}{
		{"easyrsa 3.2 keeps request and key in place", true},
		{"older easyrsa moves request and key to revoked/", false},
	} {
		t.Run(layout.name, func(t *testing.T) {
			oAdmin, pki := setupFakeEasyrsa(t)
			if layout.keep {
				if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-layout"), []byte("keep"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			easyrsaGenCrl() // a real PKI always has a CRL
			fn(t, oAdmin, pki)
		})
	}
}

func readFile(t *testing.T, pki, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pki, rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return string(data)
}

func mustCreate(t *testing.T, oAdmin *OvpnAdmin, user, password string) {
	t.Helper()
	if ok, msg := oAdmin.userCreate(user, password); !ok {
		t.Fatalf("userCreate(%s): %s", user, msg)
	}
}

// a certificate of the user in index.txt with that serial exists, with that flag
func assertIndexEntry(t *testing.T, serial, flag string) {
	t.Helper()
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if line.SerialNumber == serial {
			if line.Flag != flag {
				t.Errorf("certificate %s has flag %s in index.txt, want %s", serial, line.Flag, flag)
			}
			return
		}
	}
	t.Errorf("certificate %s is not in index.txt", serial)
}

func TestRotateActiveUserIssuesNewCertificateAndPassword(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		db := setupFakeOpenvpnUser(t)
		mustCreate(t, oAdmin, "alice", "Old-password-1")
		mustCreate(t, oAdmin, "bob", "Bob-password-1")
		oldSerial := serialOf(t, "alice")
		oldKey := readFile(t, pki, "private/alice.key")
		oldReq := readFile(t, pki, "reqs/alice.req")
		oldCert := readFile(t, pki, "issued/alice.crt")
		bobBefore := map[string]string{}
		for _, f := range []string{"issued/bob.crt", "private/bob.key", "reqs/bob.req"} {
			bobBefore[f] = readFile(t, pki, f)
		}

		if err, msg := oAdmin.userRotate("alice", "New-password-2"); err != nil {
			t.Fatalf("userRotate: %v (%s)", err, msg)
		}

		if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-alice, V alice, V bob" {
			t.Errorf("index.txt = %s", got)
		}
		assertIndexEntry(t, oldSerial, "R")
		newSerial := serialOf(t, "alice")
		if newSerial == oldSerial {
			t.Fatal("alice has the old serial")
		}
		assertIndexEntry(t, newSerial, "V")
		mustExist(t, pki, "issued/alice.crt", "private/alice.key", "reqs/alice.req", "certs_by_serial/"+newSerial+".pem")
		if readFile(t, pki, "private/alice.key") == oldKey || readFile(t, pki, "issued/alice.crt") == oldCert {
			t.Error("alice still has the old key or certificate")
		}
		// the files of the old certificate are kept where easy-rsa keeps those of a revoked one
		if got := readFile(t, pki, "revoked/private_by_serial/"+oldSerial+".key"); got != oldKey {
			t.Error("the old key is not in revoked/private_by_serial")
		}
		if got := readFile(t, pki, "revoked/reqs_by_serial/"+oldSerial+".req"); got != oldReq {
			t.Error("the old request is not in revoked/reqs_by_serial")
		}
		if got := readFile(t, pki, "revoked/certs_by_serial/"+oldSerial+".crt"); got != oldCert {
			t.Error("the old certificate is not in revoked/certs_by_serial")
		}
		if got := dbRow(t, db, "alice"); got != "New-password-2|false" {
			t.Errorf("password row of alice = %q, want the new password, not revoked", got)
		}
		// another user is untouched
		for f, want := range bobBefore {
			if readFile(t, pki, f) != want {
				t.Errorf("%s of another user changed", f)
			}
		}
		if got := dbRow(t, db, "bob"); got != "Bob-password-1|false" {
			t.Errorf("password row of bob = %q", got)
		}
	})
}

func TestRotateTwiceInARow(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		db := setupFakeOpenvpnUser(t)
		mustCreate(t, oAdmin, "alice", "Old-password-1")
		serials := []string{serialOf(t, "alice")}
		for i, pw := range []string{"Password-two-2", "Pass-three-3"} {
			if err, msg := oAdmin.userRotate("alice", pw); err != nil {
				t.Fatalf("rotation %d: %v (%s)", i+1, err, msg)
			}
			serials = append(serials, serialOf(t, "alice"))
			if got := dbRow(t, db, "alice"); got != pw+"|false" {
				t.Errorf("after rotation %d the row is %q", i+1, got)
			}
		}
		if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-alice, R REVOKED-alice, V alice" {
			t.Errorf("index.txt = %s", got)
		}
		for i, s := range serials {
			flag := "R"
			if i == len(serials)-1 {
				flag = "V"
			}
			assertIndexEntry(t, s, flag)
		}
		for _, s := range serials[:2] {
			mustExist(t, pki, "revoked/private_by_serial/"+s+".key", "revoked/reqs_by_serial/"+s+".req", "revoked/certs_by_serial/"+s+".crt")
		}
	})
}

// A user whose certificate is revoked is rotated like an active one: it gets a new certificate and its
// password row is active again (rotate is the way to give a revoked user a new certificate).
func TestRotateRevokedUserGetsNewCertificateAndIsActiveAgain(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		db := setupFakeOpenvpnUser(t)
		mustCreate(t, oAdmin, "bob", "Old-password-1")
		oldSerial := serialOf(t, "bob")
		if err, msg := oAdmin.userRevoke("bob"); err != nil {
			t.Fatal(msg)
		}
		if got := dbRow(t, db, "bob"); got != "Old-password-1|true" {
			t.Fatalf("revoked row = %q", got)
		}

		if err, msg := oAdmin.userRotate("bob", "New-password-2"); err != nil {
			t.Fatalf("userRotate: %v (%s)", err, msg)
		}
		if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-bob, V bob" {
			t.Errorf("index.txt = %s", got)
		}
		assertIndexEntry(t, oldSerial, "R")
		assertIndexEntry(t, serialOf(t, "bob"), "V")
		mustExist(t, pki, "issued/bob.crt", "private/bob.key", "reqs/bob.req")
		if got := dbRow(t, db, "bob"); got != "New-password-2|false" {
			t.Errorf("password row = %q, want the new password and active", got)
		}
	})
}

// A certificate that expired (flag E) is rotated.
func TestRotateExpiredUser(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		db := setupFakeOpenvpnUser(t)
		mustCreate(t, oAdmin, "carol", "Old-password-1")
		oldSerial := serialOf(t, "carol")
		lines := indexTxtParser(fRead(*indexTxtPath))
		lines[0].Flag, lines[0].ExpirationDate = "E", "200101000000Z"
		if err := fWrite(*indexTxtPath, renderIndexTxt(lines)); err != nil {
			t.Fatal(err)
		}

		if err, msg := oAdmin.userRotate("carol", "New-password-2"); err != nil {
			t.Fatalf("userRotate: %v (%s)", err, msg)
		}
		if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-carol, V carol" {
			t.Errorf("index.txt = %s", got)
		}
		assertIndexEntry(t, oldSerial, "R")
		mustExist(t, pki, "issued/carol.crt", "private/carol.key", "reqs/carol.req")
		if got := dbRow(t, db, "carol"); got != "New-password-2|false" {
			t.Errorf("password row = %q", got)
		}
	})
}

// A user without a password row (the password login was switched on later) gets one by the rotation.
func TestRotateUserWithoutPasswordRow(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		mustCreate(t, oAdmin, "dave", "")
		db := setupFakeOpenvpnUser(t)
		if err, msg := oAdmin.userRotate("dave", "New-password-2"); err != nil {
			t.Fatalf("userRotate: %v (%s)", err, msg)
		}
		if got := dbRow(t, db, "dave"); got != "New-password-2|false" {
			t.Errorf("password row = %q", got)
		}
	})
}

// The request file of the user is still there when easyrsa builds the new certificate: it is the request
// of the revoked certificate and goes to revoked/reqs_by_serial. A request that is not the one of the
// replaced certificate is never moved: the rotation stops and everything is as before.
func TestRotateStopsOnARequestThatIsNotTheOldOnes(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-layout"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	easyrsaGenCrl()
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	mustCreate(t, oAdmin, "bob", "Bob-password-1")
	// the request of alice is replaced by the request of bob
	if err := os.WriteFile(filepath.Join(pki, "reqs/alice.req"), []byte(readFile(t, pki, "reqs/bob.req")), 0600); err != nil {
		t.Fatal(err)
	}
	before, dbBefore := snapshotPKI(t, pki), readDB(t, db)

	err, msg := oAdmin.userRotate("alice", "New-password-2")
	if err == nil {
		t.Fatal("rotate succeeded with a request that is not the old one")
	}
	if !strings.Contains(msg, "as before") {
		t.Errorf("message %q does not say that nothing changed", msg)
	}
	assertSamePKI(t, before, snapshotPKI(t, pki))
	if got := readDB(t, db); got != dbBefore {
		t.Errorf("password database changed:\n%s\nwas:\n%s", got, dbBefore)
	}
	if userCertRevoked("alice") {
		t.Error("alice is left revoked")
	}
}

// A rotation that fails leaves the user as it was: index.txt, every file of the PKI, the password row.
func TestRotateFailureRestoresEverything(t *testing.T) {
	type state struct {
		name  string
		setup func(t *testing.T, oAdmin *OvpnAdmin, pki string)
	}
	states := []state{
		{"active", func(t *testing.T, oAdmin *OvpnAdmin, pki string) {}},
		{"revoked", func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
			if err, msg := oAdmin.userRevoke("alice"); err != nil {
				t.Fatal(msg)
			}
		}},
		{"expired", func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
			lines := indexTxtParser(fRead(*indexTxtPath))
			lines[0].Flag, lines[0].ExpirationDate = "E", "200101000000Z"
			if err := fWrite(*indexTxtPath, renderIndexTxt(lines)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	failures := []struct {
		name   string
		inject func(t *testing.T, pki, db string)
	}{
		{"easyrsa fails before it writes anything", func(t *testing.T, pki, db string) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-fail-build"), []byte("clean"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"easyrsa fails after the request and the key are written", func(t *testing.T, pki, db string) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-fail-build"), []byte("partial"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"the password cannot be changed after the certificate is issued", func(t *testing.T, pki, db string) {
			failOpenvpnUser(t, db, "change-password")
		}},
	}
	for _, st := range states {
		for _, fail := range failures {
			t.Run(st.name+", "+fail.name, func(t *testing.T) {
				forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
					db := setupFakeOpenvpnUser(t)
					mustCreate(t, oAdmin, "alice", "Old-password-1")
					mustCreate(t, oAdmin, "bob", "Bob-password-1")
					st.setup(t, oAdmin, pki)
					easyrsaGenCrl()
					before, dbBefore, indexBefore := snapshotPKI(t, pki), readDB(t, db), fRead(*indexTxtPath)
					wasRevoked := userCertRevoked("alice")
					fail.inject(t, pki, db)

					err, msg := oAdmin.userRotate("alice", "New-password-2")
					if err == nil {
						t.Fatal("userRotate succeeded although easyrsa or openvpn-user failed")
					}
					if !strings.Contains(msg, "as before") {
						t.Errorf("message %q does not say that nothing changed", msg)
					}
					if got := fRead(*indexTxtPath); got != indexBefore {
						t.Errorf("index.txt changed:\n%s\nwas:\n%s", got, indexBefore)
					}
					assertSamePKI(t, before, snapshotPKI(t, pki))
					if got := readDB(t, db); got != dbBefore {
						t.Errorf("password database changed:\n%s\nwas:\n%s", got, dbBefore)
					}
					if userCertRevoked("alice") != wasRevoked {
						t.Errorf("revoked flag of alice is now %v", !wasRevoked)
					}
					if !checkUserExist("alice") {
						t.Error("alice is not a user any more")
					}
				})
			})
		}
	}
}

func postForm(h http.HandlerFunc, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// Input errors are HTTP 400 with the message of the check, on create, change-password and rotate; a valid
// request is 200.
func TestPasswordInputErrorsAreBadRequests(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")

	short, long := strings.Repeat("a", 11), strings.Repeat("a", 73)
	cases := []struct {
		name, password, message string
	}{
		{"11 bytes", short, "Password too short, password length must be greater or equal 12"},
		{"73 bytes", long, "Password too long, the hash accepts at most 72 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := postForm(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"newuser"}, "password": {c.password}})
			if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != c.message {
				t.Errorf("create: %d %q, want 400 %q", rec.Code, rec.Body.String(), c.message)
			}
			if checkCommonNameExist("newuser") {
				t.Error("create left a certificate behind")
			}

			rec = postForm(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {"alice"}, "password": {c.password}})
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("change-password body %q: %v", rec.Body.String(), err)
			}
			if rec.Code != http.StatusBadRequest || body["message"] != c.message || body["status"] != "error" {
				t.Errorf("change-password: %d %v, want 400 %q", rec.Code, body, c.message)
			}

			rec = postForm(oAdmin.userRotateHandler, "/api/user/rotate", url.Values{"username": {"alice"}, "password": {c.password}})
			if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != c.message {
				t.Errorf("rotate: %d %q, want 400 %q", rec.Code, rec.Body.String(), c.message)
			}
		})
	}

	// an invalid user name is an input error too
	rec := postForm(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"bad name!"}, "password": {"Valid-pass-1"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Username can only contains") {
		t.Errorf("create with a bad user name: %d %q", rec.Code, rec.Body.String())
	}

	// valid requests: 200
	rec = postForm(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"okuser"}, "password": {"Valid-pass-1"}})
	if rec.Code != http.StatusOK {
		t.Errorf("valid create: %d %q", rec.Code, rec.Body.String())
	}
	rec = postForm(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {"alice"}, "password": {"Valid-pass-2"}})
	if rec.Code != http.StatusOK {
		t.Errorf("valid change-password: %d %q", rec.Code, rec.Body.String())
	}
	rec = postForm(oAdmin.userRotateHandler, "/api/user/rotate", url.Values{"username": {"alice"}, "password": {"Valid-pass-3"}})
	if rec.Code != http.StatusOK {
		t.Errorf("valid rotate: %d %q", rec.Code, rec.Body.String())
	}
	// 72 bytes is the longest password
	rec = postForm(oAdmin.userRotateHandler, "/api/user/rotate", url.Values{"username": {"alice"}, "password": {strings.Repeat("b", 72)}})
	if rec.Code != http.StatusOK {
		t.Errorf("rotate with a 72-byte password: %d %q", rec.Code, rec.Body.String())
	}
}

// change-password for a user that does not exist (unknown, malformed or empty name) is a refused request:
// HTTP 400 with the "not found" message, and nothing is created or changed.
func TestChangePasswordUnknownUserIsBadRequest(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	dbBefore := readDB(t, db)
	indexBefore := fRead(*indexTxtPath)

	for _, name := range []string{"qa-ghost", "bad name!", "a/b", ""} {
		for _, password := range []string{"Valid-pass-2", strings.Repeat("b", 72)} {
			rec := postForm(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {name}, "password": {password}})
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("user %q body %q: %v", name, rec.Body.String(), err)
			}
			want := fmt.Sprintf("User \"%s\" not found", name)
			if rec.Code != http.StatusBadRequest || body["status"] != "error" || body["message"] != want {
				t.Errorf("user %q: %d %v, want 400 %q", name, rec.Code, body, want)
			}
		}
	}
	if got := readDB(t, db); got != dbBefore {
		t.Errorf("users.db changed: %q, was %q", got, dbBefore)
	}
	if got := fRead(*indexTxtPath); got != indexBefore {
		t.Errorf("index.txt changed: %q, was %q", got, indexBefore)
	}
	if checkCommonNameExist("qa-ghost") {
		t.Error("change-password created a certificate")
	}
}

// The status codes that are not input errors are unchanged: a user that does not exist is not a 5xx
// of create, a failing issue stays 422.
func TestCreateFailureStatusCodes(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")

	rec := postForm(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "already exists") {
		t.Errorf("create of an existing user: %d %q", rec.Code, rec.Body.String())
	}

	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-fail-build"), []byte("clean"), 0644); err != nil {
		t.Fatal(err)
	}
	rec = postForm(oAdmin.userCreateHandler, "/api/user/create", url.Values{"username": {"zoe"}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("create when easyrsa fails: %d %q, want 422", rec.Code, rec.Body.String())
	}
}
