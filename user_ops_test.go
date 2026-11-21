package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestFakeEasyrsa is not a test: it is the easyrsa the tests below run (GO_FAKE_EASYRSA=1, the
// easyrsa command line follows "--", the working directory is the easy-rsa dir). It lays out files
// like easyrsa 3.x does for build-client-full, revoke and gen-crl.
func TestFakeEasyrsa(t *testing.T) {
	if os.Getenv("GO_FAKE_EASYRSA") != "1" {
		t.Skip("helper process")
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	if err := fakeEasyrsa(t, args); err != nil {
		fmt.Fprintln(os.Stderr, "fake easyrsa:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func fakeEasyrsa(t *testing.T, args []string) error {
	if len(args) > 0 && args[0] == "--batch" {
		args = args[1:]
	}
	if len(args) == 0 {
		return errors.New("no command")
	}
	index, err := os.ReadFile("pki/index.txt")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(index), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}

	switch args[0] {
	case "build-client-full":
		name := args[1]
		for _, f := range []string{"issued/" + name + ".crt", "private/" + name + ".key", "reqs/" + name + ".req"} {
			if _, err := os.Stat("pki/" + f); err == nil {
				return fmt.Errorf("%s already exists", f)
			}
		}
		serial, cert, key, req := writeTestClient(t, name, int64(0x1000+len(lines)))
		// ".fake-fail-build": "clean" fails before anything is written, "partial" fails after the
		// request and the key are written (easyrsa gen-req is done, sign-req fails)
		if mode, err := os.ReadFile(".fake-fail-build"); err == nil {
			if strings.TrimSpace(string(mode)) == "partial" {
				_ = os.WriteFile("pki/private/"+name+".key", key, 0600)
				_ = os.WriteFile("pki/reqs/"+name+".req", req, 0600)
			}
			return errors.New("injected build failure")
		}
		files := map[string][]byte{
			"issued/" + name + ".crt":            cert,
			"private/" + name + ".key":           key,
			"reqs/" + name + ".req":              req,
			"certs_by_serial/" + serial + ".pem": cert,
		}
		for f, data := range files {
			if err := os.WriteFile("pki/"+f, data, 0600); err != nil {
				return err
			}
		}
		lines = append(lines, "V\t351231235959Z\t\t"+serial+"\tunknown\t/CN="+name)

	case "revoke":
		name := args[1]
		if answer, _ := bufio.NewReader(os.Stdin).ReadString('\n'); strings.TrimSpace(answer) != "yes" {
			return errors.New("not confirmed")
		}
		// ".fake-layout" = "keep": easy-rsa 3.2 (the one of the ovpn-admin image) moves only the certificate
		// and leaves private/<user>.key and reqs/<user>.req where they are
		_, statErr := os.Stat(".fake-layout")
		keepKeyAndReq := statErr == nil
		found := false
		for i, line := range lines {
			f := strings.Split(line, "\t")
			if len(f) == 6 && f[5] == "/CN="+name && (f[0] == "V" || f[0] == "E") {
				serial := f[3]
				lines[i] = strings.Join([]string{"R", f[1], "260101000000Z", serial, f[4], f[5]}, "\t")
				moves := [][2]string{
					{"issued/" + name + ".crt", "revoked/certs_by_serial/" + serial + ".crt"},
				}
				if !keepKeyAndReq {
					moves = append(moves,
						[2]string{"private/" + name + ".key", "revoked/private_by_serial/" + serial + ".key"},
						[2]string{"reqs/" + name + ".req", "revoked/reqs_by_serial/" + serial + ".req"})
				}
				for _, m := range moves {
					if err := os.Rename("pki/"+m[0], "pki/"+m[1]); err != nil {
						return err
					}
				}
				// easyrsa 3.2 keeps certs_by_serial/<serial>.pem on revoke; removing it tests the stricter case
				if err := os.Remove("pki/certs_by_serial/" + serial + ".pem"); err != nil {
					return err
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("no valid certificate for %s", name)
		}

	case "gen-crl":
		return os.WriteFile("pki/crl.pem", []byte("crl"), 0600)

	default:
		return fmt.Errorf("unknown command %q", args[0])
	}

	return os.WriteFile("pki/index.txt", []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// setupFakeEasyrsa creates an empty easy-rsa PKI and points --easyrsa.* to it and to the fake easyrsa.
func setupFakeEasyrsa(t *testing.T) (*OvpnAdmin, string) {
	t.Helper()
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	for _, sub := range []string{"issued", "private", "reqs", "certs_by_serial", "revoked/certs_by_serial", "revoked/private_by_serial", "revoked/reqs_by_serial"} {
		if err := os.MkdirAll(filepath.Join(pki, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(pki, "index.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(t.TempDir(), "easyrsa")
	script := "#!/bin/sh\nGO_FAKE_EASYRSA=1 exec " + strconv.Quote(exe) + " -test.run='^TestFakeEasyrsa$' -- \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	setFlag(t, easyrsaDirPath, dir)
	setFlag(t, easyrsaBinPath, wrapper)
	setFlag(t, indexTxtPath, filepath.Join(pki, "index.txt"))
	setFlag(t, storageBackend, "filesystem")
	setFlag(t, authByPassword, false)
	serverCertCache.Clear()
	t.Cleanup(serverCertCache.Clear)

	return &OvpnAdmin{createUserMutex: &sync.Mutex{}}, pki
}

// indexLines returns "FLAG CN" of every index.txt line, sorted (rotate keeps the position of the user
// in index.txt by swapping the lines of the old and the new certificate).
func indexLines(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		cn := line.Identity
		if strings.HasPrefix(cn, "REVOKED-") {
			cn = cn[:strings.LastIndex(cn, "-")] // drop the random suffix
		}
		out = append(out, line.Flag+" "+cn)
	}
	sort.Strings(out)
	return out
}

func mustExist(t *testing.T, pki string, files ...string) {
	t.Helper()
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(pki, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func serialOf(t *testing.T, cn string) string {
	t.Helper()
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if line.Identity == cn {
			return line.SerialNumber
		}
	}
	t.Fatalf("no certificate for %s", cn)
	return ""
}

func TestRotateActiveUserRevokesTheOldCertificate(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	if ok, msg := oAdmin.userCreate("alice", ""); !ok {
		t.Fatal(msg)
	}

	// failed before: issued/alice.crt etc. were still there, build-client-full refused
	if err, msg := oAdmin.userRotate("alice", ""); err != nil {
		t.Fatalf("userRotate: %v (%s)", err, msg)
	}

	if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-alice, V alice" {
		t.Errorf("index.txt = %s, want the old certificate revoked and a new one", got)
	}
	mustExist(t, pki, "issued/alice.crt", "private/alice.key", "reqs/alice.req", "certs_by_serial/"+serialOf(t, "alice")+".pem")
}

func TestRotateRevokedUser(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	if ok, msg := oAdmin.userCreate("bob", ""); !ok {
		t.Fatal(msg)
	}
	if err, msg := oAdmin.userRevoke("bob"); err != nil {
		t.Fatal(msg)
	}
	if err, msg := oAdmin.userRotate("bob", ""); err != nil {
		t.Fatalf("userRotate: %v (%s)", err, msg)
	}
	if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-bob, V bob" {
		t.Errorf("index.txt = %s", got)
	}
}

func TestDeleteActiveUserRevokesTheCertificate(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	if ok, msg := oAdmin.userCreate("carol", ""); !ok {
		t.Fatal(msg)
	}

	// before: the certificate stayed valid, the user was only hidden
	if err, msg := oAdmin.userDelete("carol"); err != nil {
		t.Fatalf("userDelete: %v (%s)", err, msg)
	}
	if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-carol" {
		t.Errorf("index.txt = %s, want the deleted certificate revoked", got)
	}

	// the name can be used again
	if ok, msg := oAdmin.userCreate("carol", ""); !ok {
		t.Fatalf("userCreate after delete: %s", msg)
	}
}

func TestUnrevokeRestoresAllFiles(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	if ok, msg := oAdmin.userCreate("dave", ""); !ok {
		t.Fatal(msg)
	}
	serial := serialOf(t, "dave")
	if err, msg := oAdmin.userRevoke("dave"); err != nil {
		t.Fatal(msg)
	}

	if err, msg := oAdmin.userUnrevoke("dave"); err != nil {
		t.Fatalf("userUnrevoke: %v (%s)", err, msg)
	}
	if got := strings.Join(indexLines(t), ", "); got != "V dave" {
		t.Errorf("index.txt = %s", got)
	}
	// certs_by_serial/<serial>.pem was not restored before (the revoked certificate was moved twice)
	mustExist(t, pki, "issued/dave.crt", "private/dave.key", "reqs/dave.req", "certs_by_serial/"+serial+".pem")
	for _, f := range []string{"revoked/certs_by_serial/" + serial + ".crt", "revoked/private_by_serial/" + serial + ".key", "revoked/reqs_by_serial/" + serial + ".req"} {
		if _, err := os.Stat(filepath.Join(pki, f)); err == nil {
			t.Errorf("%s is still there", f)
		}
	}
}

// F3: the ccd of a deleted user (static address, routes) must not survive for a user created later
// with the same name.
func TestDeleteUserRemovesCcd(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setNetworks(t, "172.16.100.0/24", "")
	ccdPath := setupCcdDir(t, nil)
	setFlag(t, ccdEnabled, true)

	if ok, msg := oAdmin.userCreate("alice", ""); !ok {
		t.Fatal(msg)
	}
	if ok, msg := oAdmin.modifyCcd(Ccd{User: "alice", ClientAddress: "172.16.100.50", CustomRoutes: []ccdRoute{{Address: "10.9.0.0", Mask: "255.255.0.0", Description: "lan"}}}); !ok {
		t.Fatalf("modifyCcd: %s", msg)
	}
	ccdFile := filepath.Join(ccdPath, "alice")
	if _, err := os.Stat(ccdFile); err != nil {
		t.Fatalf("ccd file was not written: %v", err)
	}
	// an unrelated user keeps its ccd
	if err := os.WriteFile(filepath.Join(ccdPath, "other"), []byte("ifconfig-push 172.16.100.60 255.255.255.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// the certificate is still valid here: delete revokes it, then removes the ccd
	if err, msg := oAdmin.userDelete("alice"); err != nil {
		t.Fatalf("userDelete: %v (%s)", err, msg)
	}
	if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-alice" {
		t.Errorf("index.txt = %s, want the deleted certificate revoked", got)
	}
	if _, err := os.Stat(ccdFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ccd file of the deleted user: Stat err = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(ccdPath, "other")); err != nil {
		t.Errorf("ccd of another user was touched: %v", err)
	}

	// a new alice does not inherit the old static address or routes ...
	if ok, msg := oAdmin.userCreate("alice", ""); !ok {
		t.Fatalf("userCreate after delete: %s", msg)
	}
	got, err := oAdmin.getCcd("alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientAddress != ccdDynamicAddress || len(got.CustomRoutes) != 0 {
		t.Errorf("recreated user inherited the old ccd: %+v", got)
	}
	// ... and the old static address is free again
	if ok, msg := oAdmin.userCreate("bob", ""); !ok {
		t.Fatal(msg)
	}
	if ok, msg := oAdmin.modifyCcd(Ccd{User: "bob", ClientAddress: "172.16.100.50"}); !ok {
		t.Errorf("old static address was not released: %s", msg)
	}
}

// A user without a ccd file (the usual case) and a revoked user can be deleted.
func TestDeleteUserWithoutCcd(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setupCcdDir(t, nil)

	for _, name := range []string{"carol", "dave"} {
		if ok, msg := oAdmin.userCreate(name, ""); !ok {
			t.Fatal(msg)
		}
	}
	if err, msg := oAdmin.userRevoke("dave"); err != nil {
		t.Fatal(msg)
	}
	for _, name := range []string{"carol", "dave"} {
		if err, msg := oAdmin.userDelete(name); err != nil {
			t.Errorf("userDelete(%s): %v (%s)", name, err, msg)
		}
	}
}

func TestRemoveCcdFileRejectsUnsafeNames(t *testing.T) {
	dir := setupCcdDir(t, nil)
	outside := filepath.Join(filepath.Dir(dir), "outside-ccd-test")
	if err := os.WriteFile(outside, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	for _, name := range []string{"", ".", "..", "../outside-ccd-test", "a/b"} {
		if err := removeCcdFile(name); err == nil {
			t.Errorf("removeCcdFile(%q) succeeded", name)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("file outside the ccd dir was removed: %v", err)
	}
}
