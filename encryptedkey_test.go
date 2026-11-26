package main

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// encryptedKeyBlock decides whether a block of a CA key file that does not parse is an encrypted key and so
// still counts as reference material. A legacy block counts only when its encryption is declared: Proc-Type
// "4,ENCRYPTED" and a DEK-Info of a legacy OpenSSL cipher with an IV of its block size. Nothing is decrypted.

func randomBody(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func legacyBlock(t *testing.T, headers map[string]string) *pem.Block {
	t.Helper()
	return &pem.Block{Type: "RSA PRIVATE KEY", Headers: headers, Bytes: randomBody(t, 64)}
}

// (a) Proc-Type that merely contains ENCRYPTED, with no DEK-Info, declares nothing.
func TestEncryptedKeyBlockRejectsProcTypeEncryptedWithoutDEKInfo(t *testing.T) {
	for _, procType := range []string{"ENCRYPTED", "4,ENCRYPTED", "garbage ENCRYPTED garbage", "4,NOT-ENCRYPTED", "3,ENCRYPTED", "4,ENCRYPTED,extra", "encrypted", "4, ENCRYPTED"} {
		if encryptedKeyBlock(legacyBlock(t, map[string]string{"Proc-Type": procType})) {
			t.Errorf("Proc-Type %q without DEK-Info was accepted", procType)
		}
	}
}

// A DEK-Info without the Proc-Type that declares encryption declares nothing either.
func TestEncryptedKeyBlockRejectsDEKInfoWithoutProcType(t *testing.T) {
	dek := "AES-256-CBC,00112233445566778899AABBCCDDEEFF"
	for _, h := range []map[string]string{
		{"DEK-Info": dek},
		{"Proc-Type": "", "DEK-Info": dek},
		{"Proc-Type": "ENCRYPTED", "DEK-Info": dek},
		{"Proc-Type": "garbage ENCRYPTED", "DEK-Info": dek},
	} {
		if encryptedKeyBlock(legacyBlock(t, h)) {
			t.Errorf("headers %v were accepted", h)
		}
	}
}

// (b) A declared legacy envelope over a random body is accepted: the body is not decrypted or inspected.
func TestEncryptedKeyBlockAcceptsADeclaredLegacyEnvelope(t *testing.T) {
	for name, dek := range map[string]string{
		"aes-256":        "AES-256-CBC,00112233445566778899AABBCCDDEEFF",
		"aes-192":        "AES-192-CBC,00112233445566778899aabbccddeeff",
		"aes-128":        "AES-128-CBC,00112233445566778899AABBCCDDEEFF",
		"des-ede3":       "DES-EDE3-CBC,0011223344556677",
		"spaces trimmed": "AES-256-CBC, 00112233445566778899AABBCCDDEEFF ",
	} {
		t.Run(name, func(t *testing.T) {
			if !encryptedKeyBlock(legacyBlock(t, map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": dek})) {
				t.Errorf("a declared legacy envelope %q was rejected", dek)
			}
		})
	}
	if !encryptedKeyBlock(legacyBlock(t, map[string]string{"Proc-Type": " 4,ENCRYPTED ", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"})) {
		t.Error("a Proc-Type with surrounding spaces was rejected")
	}
}

// (c) A DEK-Info with a cipher that legacy OpenSSL does not use for PEM keys is rejected.
func TestEncryptedKeyBlockRejectsAnUnknownCipher(t *testing.T) {
	iv := "00112233445566778899AABBCCDDEEFF"
	for _, cipher := range []string{"ROT13-CBC", "AES-256-ECB", "AES-256-GCM", "DES-CBC", "aes-256-cbc", "AES-512-CBC", "", "NONE"} {
		if encryptedKeyBlock(legacyBlock(t, map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": cipher + "," + iv})) {
			t.Errorf("cipher %q was accepted", cipher)
		}
	}
}

// (d) The IV must be valid hex of the cipher's block size; the form must be <CIPHER>,<HEX-IV>.
func TestEncryptedKeyBlockRejectsABadIV(t *testing.T) {
	for name, dek := range map[string]string{
		"aes iv too short":       "AES-256-CBC,00112233445566778899AABBCCDDEE",
		"aes iv too long":        "AES-256-CBC,00112233445566778899AABBCCDDEEFF00",
		"aes iv with des length": "AES-256-CBC,0011223344556677",
		"des iv with aes length": "DES-EDE3-CBC,00112233445566778899AABBCCDDEEFF",
		"non hex iv":             "AES-256-CBC,ZZ112233445566778899AABBCCDDEEFF",
		"odd length iv":          "AES-256-CBC,00112233445566778899AABBCCDDEEF",
		"empty iv":               "AES-256-CBC,",
		"no iv":                  "AES-256-CBC",
		"empty dek-info":         "",
		"only a comma":           ",",
		"extra field":            "AES-256-CBC,00112233445566778899AABBCCDDEEFF,extra",
	} {
		t.Run(name, func(t *testing.T) {
			if encryptedKeyBlock(legacyBlock(t, map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": dek})) {
				t.Errorf("DEK-Info %q was accepted", dek)
			}
		})
	}
}

// An empty body is never reference material, declared or not.
func TestEncryptedKeyBlockRejectsAnEmptyBody(t *testing.T) {
	b := &pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"}}
	if encryptedKeyBlock(b) {
		t.Error("an empty body was accepted")
	}
}

func fixtureBlock(t *testing.T, name string) *pem.Block {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s holds no PEM block", name)
	}
	return b
}

// (e) Genuine encrypted keys written by openssl (throwaway passphrase, never used here) are still accepted:
// a PKCS #8 EncryptedPrivateKeyInfo by its ASN.1 envelope, a legacy EC key by its declared encryption.
func TestEncryptedKeyBlockStillAcceptsGenuineEncryptedKeys(t *testing.T) {
	pkcs8 := fixtureBlock(t, "encrypted-pkcs8.pem")
	if pkcs8.Type != "ENCRYPTED PRIVATE KEY" || len(pkcs8.Headers) != 0 {
		t.Fatalf("fixture is %q with headers %v", pkcs8.Type, pkcs8.Headers)
	}
	if !encryptedKeyBlock(pkcs8) {
		t.Error("a genuine encrypted PKCS #8 key was rejected")
	}
	legacy := fixtureBlock(t, "encrypted-legacy-ec.pem")
	if legacy.Headers["Proc-Type"] != "4,ENCRYPTED" || !strings.HasPrefix(legacy.Headers["DEK-Info"], "AES-256-CBC,") {
		t.Fatalf("fixture headers %v", legacy.Headers)
	}
	if !encryptedKeyBlock(legacy) {
		t.Error("a genuine legacy encrypted key was rejected")
	}
}

// A genuine PKCS #8 envelope does not need legacy headers, and broken legacy headers on a block that is no
// PKCS #8 envelope do not make it one.
func TestEncryptedKeyBlockPKCS8DoesNotDependOnLegacyHeaders(t *testing.T) {
	pkcs8 := fixtureBlock(t, "encrypted-pkcs8.pem")
	if !encryptedKeyBlock(&pem.Block{Type: pkcs8.Type, Bytes: pkcs8.Bytes, Headers: map[string]string{"Proc-Type": "ENCRYPTED"}}) {
		t.Error("the PKCS #8 envelope was rejected because of a stray header")
	}
	if encryptedKeyBlock(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: randomBody(t, 64), Headers: map[string]string{"Proc-Type": "ENCRYPTED"}}) {
		t.Error("a body that is no PKCS #8 envelope was accepted on a stray Proc-Type")
	}
}

// End to end through the identity and the sync endpoint: a ca.key that only claims to be encrypted is no
// reference material, so the identity is refused and the export answers 500 with nothing built; a declared
// or genuine encrypted ca.key still exports.
func TestArchiveCaKeyEncryptionMetadata(t *testing.T) {
	body := bytes.Repeat([]byte{0x5a}, 48)
	legacy := func(h map[string]string) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: h, Bytes: body})
	}
	genuine, err := os.ReadFile(filepath.Join("testdata", "encrypted-pkcs8.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
		ok   bool
	}{
		{"proc-type ENCRYPTED only", legacy(map[string]string{"Proc-Type": "ENCRYPTED"}), false},
		{"proc-type 4,ENCRYPTED only", legacy(map[string]string{"Proc-Type": "4,ENCRYPTED"}), false},
		{"unknown cipher", legacy(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "ROT13-CBC,00112233445566778899AABBCCDDEEFF"}), false},
		{"wrong iv length", legacy(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233"}), false},
		{"non-hex iv", legacy(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,ZZ112233445566778899AABBCCDDEEFF"}), false},
		{"declared legacy envelope", legacy(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"}), true},
		{"genuine encrypted pkcs8", genuine, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oAdmin, pki := setupFakeEasyrsa(t)
			caKeyFixtures(t, pki)
			if err := os.WriteFile(filepath.Join(pki, "private/ca.key"), c.data, 0600); err != nil {
				t.Fatal(err)
			}
			tmp := t.TempDir()
			t.Setenv("TMPDIR", tmp)
			oAdmin.role = "master"
			oAdmin.masterSyncToken = "a-sync-token-for-the-test"
			rec := httptest.NewRecorder()
			oAdmin.downloadCertsHandler(rec, loopbackGet("/api/data/certs/download?token=a-sync-token-for-the-test"))
			isArchive := bytes.HasPrefix(rec.Body.Bytes(), []byte{0x1f, 0x8b})
			if c.ok {
				if rec.Code != http.StatusOK || !isArchive {
					t.Fatalf("answered %d (archive %v), want 200 and an archive", rec.Code, isArchive)
				}
				return
			}
			if rec.Code != http.StatusInternalServerError || isArchive {
				t.Errorf("answered %d (archive %v), want 500 and no archive", rec.Code, isArchive)
			}
			if left := leftovers(t, tmp); len(left) != 0 {
				t.Errorf("temp files left: %v", left)
			}
		})
	}
}
