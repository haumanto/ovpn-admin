package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCaIdentity writes a real ca.crt and private/ca.key: the sync archive needs them (the identity of
// the CA signing key) before it builds anything.
func writeCaIdentity(t *testing.T, pki string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"ca.crt":         {Type: "CERTIFICATE", Bytes: der},
		"private/ca.key": {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		p := filepath.Join(pki, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// ---- unrevoke: success only when the files are back and the CRL on disk no longer lists the serial ----

// revokedAlice returns an admin with a revoked user "alice", her serial, and the directory of the
// fake easyrsa (where its switches live).
func revokedAlice(t *testing.T) (*OvpnAdmin, string, string) {
	t.Helper()
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatal(msg)
	}
	if !crlLists(t, serial) {
		t.Fatal("the test needs a CRL that lists the revoked serial")
	}
	return oAdmin, pki, serial
}

func unrevokeRequest(oAdmin *OvpnAdmin) *httptest.ResponseRecorder {
	return postForm(oAdmin.userUnrevokeHandler, "/api/user/unrevoke", url.Values{"username": {"alice"}})
}

func assertNotClaimedUnrevoked(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("%s: status %d (%s), want 500", what, rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "successfully unrevoked") {
		t.Errorf("%s: the failure is worded like a success: %q", what, rec.Body.String())
	}
}

// A certificate, key or request that cannot be put back is a failed unrevoke: 500, the index still says
// revoked (a user that cannot be restored is not valid again) and the CRL still lists the serial.
func TestUnrevokeFailsWhenAFileCannotBeRestored(t *testing.T) {
	for _, missing := range []struct{ name, file string }{
		{"certificate", "revoked/certs_by_serial/%s.crt"},
		{"private key", "revoked/private_by_serial/%s.key"},
		{"request", "revoked/reqs_by_serial/%s.req"},
	} {
		t.Run(missing.name, func(t *testing.T) {
			oAdmin, pki, serial := revokedAlice(t)
			if err := os.Remove(filepath.Join(pki, strings.Replace(missing.file, "%s", serial, 1))); err != nil {
				t.Fatal(err)
			}
			rec := unrevokeRequest(oAdmin)
			assertNotClaimedUnrevoked(t, rec, "unrevoke without the revoked "+missing.name)
			if !strings.Contains(rec.Body.String(), missing.name) {
				t.Errorf("the answer does not name the %s: %q", missing.name, rec.Body.String())
			}
			assertIndexEntry(t, serial, "R")
			if !crlLists(t, serial) {
				t.Error("the CRL does not list the serial any more although the user was not restored")
			}
		})
	}
}

// easy-rsa 3.2 leaves the key and the request in place when it revokes: there is nothing to move back,
// and that is not a failure.
func TestUnrevokeWhenEasyrsaKeptKeyAndRequestInPlace(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-layout"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatal(msg)
	}
	rec := unrevokeRequest(oAdmin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "successfully unrevoked") {
		t.Fatalf("unrevoke: %d %q", rec.Code, rec.Body.String())
	}
	mustExist(t, pki, "issued/alice.crt", "private/alice.key", "reqs/alice.req", "certs_by_serial/"+serial+".pem")
	assertIndexEntry(t, serial, "V")
	if crlLists(t, serial) {
		t.Error("the CRL still lists the serial after a successful unrevoke")
	}
}

// The rebuild fails after index.txt was written: the first call answers 500, and so does every retry
// while the CRL on disk still lists the serial (the index no longer says R, but OpenVPN still refuses
// the certificate). Once the CRL can be rebuilt, the retry rebuilds it and then answers 200.
func TestUnrevokeRetryAfterAFailedRebuildAnswersFromTheCrl(t *testing.T) {
	oAdmin, pki, serial := revokedAlice(t)
	switchOn(t, pki, ".fake-fail-crl")

	assertNotClaimedUnrevoked(t, unrevokeRequest(oAdmin), "first unrevoke, CRL rebuild fails")
	assertIndexEntry(t, serial, "V") // the flag is written, the CRL is the truth now
	assertNotClaimedUnrevoked(t, unrevokeRequest(oAdmin), "retry while the CRL still lists the serial")
	if !crlLists(t, serial) {
		t.Fatal("the test needs the CRL to still list the serial")
	}

	if err := os.Remove(filepath.Join(filepath.Dir(pki), ".fake-fail-crl")); err != nil {
		t.Fatal(err)
	}
	rec := unrevokeRequest(oAdmin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "successfully unrevoked") {
		t.Fatalf("retry once the CRL can be rebuilt: %d %q", rec.Code, rec.Body.String())
	}
	if crlLists(t, serial) {
		t.Error("the retry answered 200 but the CRL on disk still lists the serial")
	}
}

// gen-crl exits 0 and writes nothing: the CRL on disk still lists the serial, so no 200, on the first
// call and on a retry.
func TestUnrevokeAnswersFromTheCrlWhenGenCrlDoesNothing(t *testing.T) {
	oAdmin, pki, serial := revokedAlice(t)
	switchOn(t, pki, ".fake-noop-crl")

	assertNotClaimedUnrevoked(t, unrevokeRequest(oAdmin), "unrevoke, gen-crl is a no-op")
	assertNotClaimedUnrevoked(t, unrevokeRequest(oAdmin), "retry, gen-crl is a no-op")
	if !crlLists(t, serial) {
		t.Fatal("the test needs the CRL to still list the serial")
	}
}

// The user was never revoked: nothing to restore and no CRL entry, a plain 200.
func TestUnrevokeOfAValidUserStillSucceeds(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	easyrsaGenCrl()
	_ = pki
	rec := unrevokeRequest(oAdmin)
	if rec.Code != http.StatusOK {
		t.Errorf("unrevoke of a valid user: %d %q", rec.Code, rec.Body.String())
	}
}

// ---- the sync archive needs the identity of the CA signing key ----

func TestArchiveRefusesWithoutAUsableCaKeyIdentity(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, pki string)
	}{
		{"no ca.crt and no ca.key", func(t *testing.T, pki string) {
			os.Remove(filepath.Join(pki, "ca.crt"))
			os.Remove(filepath.Join(pki, "private/ca.key"))
		}},
		{"ca.key is missing", func(t *testing.T, pki string) { os.Remove(filepath.Join(pki, "private/ca.key")) }},
		{"ca.crt is missing", func(t *testing.T, pki string) { os.Remove(filepath.Join(pki, "ca.crt")) }},
		{"ca.crt does not parse", func(t *testing.T, pki string) {
			os.WriteFile(filepath.Join(pki, "ca.crt"), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0644)
		}},
		{"ca.crt holds no certificate", func(t *testing.T, pki string) {
			os.WriteFile(filepath.Join(pki, "ca.crt"), []byte("not a pem file"), 0644)
		}},
		{"ca.key holds no key", func(t *testing.T, pki string) {
			os.WriteFile(filepath.Join(pki, "private/ca.key"), []byte("not a pem file"), 0600)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oAdmin, pki := setupFakeEasyrsa(t)
			caKeyFixtures(t, pki)
			c.break_(t, pki)
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)

			if archive, err := archiveCerts(); err == nil {
				removeArchive(archive)
				t.Fatal("an archive was built without a usable identity of the CA signing key")
			}

			oAdmin.role = "master"
			oAdmin.masterSyncToken = "a-sync-token-for-the-test"
			rec := httptest.NewRecorder()
			oAdmin.downloadCertsHandler(rec, loopbackGet("/api/data/certs/download?token=a-sync-token-for-the-test"))
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("the sync endpoint answered %d, want 500", rec.Code)
			}
			if bytes.HasPrefix(rec.Body.Bytes(), []byte{0x1f, 0x8b}) {
				t.Error("the sync endpoint served an archive")
			}
			if left := leftovers(t, tmp); len(left) != 0 {
				t.Errorf("temp files left: %v", left)
			}
		})
	}
}

// An archive can still be built from a complete identity (the cases above only take parts away).
func TestArchiveIsBuiltWithACompleteCaKeyIdentity(t *testing.T) {
	_, pki := setupFakeEasyrsa(t)
	caKeyFixtures(t, pki)
	t.Setenv("TMPDIR", t.TempDir())
	archive, err := archiveCerts()
	if err != nil {
		t.Fatal(err)
	}
	removeArchive(archive)
}

// A file above the limit is refused, not read into memory: the archive is not built.
func TestArchiveRefusesAFileAboveTheLimit(t *testing.T) {
	_, pki := setupFakeEasyrsa(t)
	caKeyFixtures(t, pki)
	big, err := os.Create(filepath.Join(pki, "huge.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(maxArchiveFilterBytes + 1); err != nil {
		t.Fatal(err)
	}
	big.Close()
	t.Setenv("TMPDIR", t.TempDir())
	if archive, err := archiveCerts(); err == nil {
		removeArchive(archive)
		t.Fatal("an archive was built with a file above the limit")
	}
}

// ---- a failed rotate describes the password that is there after the rollback ----

// armOneOffListFailure makes the next "list" after a password was stored fail once: the rotation's own
// check of the row fails, and the rollback that follows can read the database again.
func armOneOffListFailure(t *testing.T, db string) {
	t.Helper()
	os.Remove(db + ".stored") // setup stored passwords already
	if err := os.WriteFile(db+".failoncelist", nil, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRotateFailureReplyDescribesThePasswordAfterTheRollback(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, oAdmin *OvpnAdmin) string // returns the db
		wantLive   bool
		wantRow    string
		wantInText string
	}{
		{"row active before: the rollback leaves the new password in place", func(t *testing.T, oAdmin *OvpnAdmin) string {
			db := setupFakeOpenvpnUser(t)
			mustCreate(t, oAdmin, "alice", "Old-password-1")
			return db
		}, true, "New-password-2|false", "is live"},
		{"row revoked before: the rollback revokes it again", func(t *testing.T, oAdmin *OvpnAdmin) string {
			db := setupFakeOpenvpnUser(t)
			mustCreate(t, oAdmin, "alice", "Old-password-1")
			if err, msg := oAdmin.userRevoke("alice"); err != nil {
				t.Fatal(msg)
			}
			return db
		}, false, "New-password-2|true", "revoked"},
		{"no row before: the rollback deletes the new row", func(t *testing.T, oAdmin *OvpnAdmin) string {
			mustCreate(t, oAdmin, "alice", "")
			return setupFakeOpenvpnUser(t)
		}, false, "", "no password row"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oAdmin, _ := setupFakeEasyrsa(t)
			db := c.setup(t, oAdmin)
			armOneOffListFailure(t, db)

			err, msg := oAdmin.userRotate("alice", "New-password-2")
			if err == nil {
				t.Fatal("userRotate succeeded although the check of the password row failed")
			}
			row := dbRow(t, db, "alice")
			if row != c.wantRow {
				t.Fatalf("the test needs the row %q after the rollback, it is %q (reply %q)", c.wantRow, row, msg)
			}
			newWorks := row == "New-password-2|false"
			if newWorks != c.wantLive {
				t.Fatalf("test setup: new password accepted = %v", newWorks)
			}
			if claimsLive := strings.Contains(msg, "is live") && !strings.Contains(msg, "not live"); claimsLive != newWorks {
				t.Errorf("the reply says live=%v but the database accepts the new password=%v: %q", claimsLive, newWorks, msg)
			}
			if !strings.Contains(msg, c.wantInText) {
				t.Errorf("the reply does not say %q: %q", c.wantInText, msg)
			}
		})
	}
}

// When nothing can be proven after the rollback the reply says that it is unknown, and does not claim
// either password.
func TestRotateFailureReplySaysUnknownWhenTheStateCannotBeEstablished(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	if err := os.WriteFile(db+".failafterchange", nil, 0644); err != nil {
		t.Fatal(err)
	}
	failOpenvpnUser(t, db, "auth") // nothing can be asked: not the password, not the row
	err, msg := oAdmin.userRotate("alice", "New-password-2")
	if err == nil {
		t.Fatal("userRotate succeeded")
	}
	if strings.Contains(msg, "is live") || strings.Contains(msg, "are as before") {
		t.Errorf("the reply claims a state it could not check: %q", msg)
	}
	if !strings.Contains(msg, "could not be checked") {
		t.Errorf("the reply does not say that the state is unknown: %q", msg)
	}
}
