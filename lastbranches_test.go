package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- the identity of the CA key counts only reference material that is usable ----

// A ca.key that holds a well formed PEM block of a private key type with a body that is no key: the
// block gives no public key and is not an encrypted key, so there is no reference material, the identity
// is refused and the export answers 500 with nothing built.
func TestArchiveRefusesACaKeyWhoseBlockDoesNotParse(t *testing.T) {
	for _, blockType := range []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"} {
		t.Run(blockType, func(t *testing.T) {
			oAdmin, pki := setupFakeEasyrsa(t)
			caKeyFixtures(t, pki)
			garbage := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: []byte("these bytes are not a key")})
			if err := os.WriteFile(filepath.Join(pki, "private/ca.key"), garbage, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCaKeyIdentity(pki); err == nil {
				t.Fatal("the identity was accepted with a ca.key whose key does not parse")
			}
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			if archive, err := archiveCerts(); err == nil {
				removeArchive(archive)
				t.Fatal("an archive was built")
			}
			oAdmin.role = "master"
			oAdmin.masterSyncToken = "a-sync-token-for-the-test"
			rec := httptest.NewRecorder()
			oAdmin.downloadCertsHandler(rec, httptest.NewRequest("GET", "/api/data/certs/download?token=a-sync-token-for-the-test", nil))
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

// The deliberately supported reference case: an encrypted key cannot be parsed, but it is the CA key and
// a renamed copy of it is recognised by its exact body. Covered by encryptedKeyBlock (pemBodies keeps a
// block that parses OR is a well formed encrypted key).
func TestIdentityKeepsAnEncryptedCaKeyAsReference(t *testing.T) {
	// EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier { OID }, OCTET STRING }
	type algo struct{ Algorithm asn1.ObjectIdentifier }
	type encInfo struct {
		Algorithm algo
		Data      []byte
	}
	der, err := asn1.Marshal(encInfo{algo{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}}, bytes.Repeat([]byte{0xa5}, 48)})
	if err != nil {
		t.Fatal(err)
	}
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})
	legacy := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"},
		Bytes: bytes.Repeat([]byte{0x5a}, 32),
	})
	for name, data := range map[string][]byte{"pkcs8": encrypted, "legacy": legacy} {
		t.Run(name, func(t *testing.T) {
			_, pki := setupFakeEasyrsa(t)
			caKeyFixtures(t, pki)
			if err := os.WriteFile(filepath.Join(pki, "private/ca.key"), data, 0600); err != nil {
				t.Fatal(err)
			}
			id, err := loadCaKeyIdentity(pki)
			if err != nil {
				t.Fatalf("an encrypted ca.key was refused: %v", err)
			}
			if len(id.bodies) != 1 {
				t.Fatalf("%d reference bodies, want 1", len(id.bodies))
			}
			if !id.holdsCaKey(data) {
				t.Error("a renamed copy of the encrypted key is not recognised")
			}
		})
	}
}

// A usable plaintext key still counts, and a block of a key that parses is recognised by body.
func TestIdentityCountsAKeyThatParses(t *testing.T) {
	_, pki := setupFakeEasyrsa(t)
	caKeyFixtures(t, pki)
	id, err := loadCaKeyIdentity(pki)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.bodies) != 1 {
		t.Fatalf("%d reference bodies, want 1", len(id.bodies))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := pemBodies(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); len(got) != 1 {
		t.Errorf("a parsable SEC 1 key gave %d bodies, want 1", len(got))
	}
	if got := pemBodies(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage")})); len(got) != 0 {
		t.Errorf("a garbage block gave %d bodies, want 0", len(got))
	}
}

// ---- unrevoke accepts a regular file in place, not any path ----

// A directory where the key or the request belongs is not a restored file: 500, the index stays revoked.
func TestUnrevokeRefusesADirectoryInPlaceOfTheKeyOrRequest(t *testing.T) {
	for _, c := range []struct{ name, revoked, dest string }{
		{"private key", "revoked/private_by_serial/%s.key", "private/alice.key"},
		{"request", "revoked/reqs_by_serial/%s.req", "reqs/alice.req"},
	} {
		t.Run(c.name, func(t *testing.T) {
			oAdmin, pki, serial := revokedAlice(t)
			if err := os.Remove(filepath.Join(pki, strings.Replace(c.revoked, "%s", serial, 1))); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(pki, c.dest)
			if err := os.RemoveAll(dest); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dest, 0755); err != nil {
				t.Fatal(err)
			}
			rec := unrevokeRequest(oAdmin)
			assertNotClaimedUnrevoked(t, rec, "unrevoke with a directory in place of the "+c.name)
			if !strings.Contains(rec.Body.String(), c.name) {
				t.Errorf("the answer does not name the %s: %q", c.name, rec.Body.String())
			}
			assertIndexEntry(t, serial, "R")
		})
	}
}

// A regular file in place stays accepted, and a failure on one step does not stop the next one.
func TestUnrevokeReportsEveryFailureWithADirectoryInPlace(t *testing.T) {
	oAdmin, pki, serial := revokedAlice(t)
	for _, f := range []string{"revoked/private_by_serial/%s.key", "revoked/reqs_by_serial/%s.req"} {
		if err := os.Remove(filepath.Join(pki, strings.Replace(f, "%s", serial, 1))); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"private/alice.key", "reqs/alice.req"} {
		os.RemoveAll(filepath.Join(pki, d))
		if err := os.MkdirAll(filepath.Join(pki, d), 0755); err != nil {
			t.Fatal(err)
		}
	}
	rec := unrevokeRequest(oAdmin)
	assertNotClaimedUnrevoked(t, rec, "two directories in place")
	if !strings.Contains(rec.Body.String(), "private key") || !strings.Contains(rec.Body.String(), "request") {
		t.Errorf("the answer does not name both failures: %q", rec.Body.String())
	}
}
