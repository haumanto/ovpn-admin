package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCrl builds a real CRL (what easyrsa gen-crl writes) from the lines of index.txt: every line with
// flag R is listed. The CA key is fixed and every time is fixed, so the same index gives the same file
// (the rollback tests compare the PKI byte by byte).
func fakeCrl(lines []string) ([]byte, error) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return fakeCrlAt(lines, notBefore, notBefore.AddDate(30, 0, 0))
}

// fakeCrlAt is fakeCrl with the thisUpdate and nextUpdate of the list chosen by the caller.
func fakeCrlAt(lines []string, thisUpdate, nextUpdate time.Time) ([]byte, error) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake CA"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(30, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	var entries []x509.RevocationListEntry
	for _, line := range lines {
		f := strings.Split(line, "\t")
		if len(f) != 6 || f[0] != "R" {
			continue
		}
		serial, ok := new(big.Int).SetString(f[3], 16)
		if !ok {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: notBefore})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca, priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// fakeMgmt is an OpenVPN management interface: it speaks the welcome line and answers "kill",
// "status 3" and "state" like OpenVPN does. sessions are the common names that are connected, a
// "kill" of one of them removes it. refuse makes it answer every kill with an ERROR that is not
// "not found".
type fakeMgmt struct {
	addr     string
	mu       sync.Mutex
	sessions map[string]bool
	kills    []string
	refuse   bool
	reply    string // when set, the answer to every kill (a reply OpenVPN would not send)
	onKill   func() // runs when a kill arrives (a test hook)
}

func startFakeMgmt(t *testing.T, sessions ...string) *fakeMgmt {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMgmt{addr: l.Addr().String(), sessions: map[string]bool{}}
	for _, s := range sessions {
		m.sessions[s] = true
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m
}

func (m *fakeMgmt) serve(c net.Conn) {
	defer c.Close()
	_, _ = c.Write([]byte(">INFO:OpenVPN Management Interface Version 3 -- type 'help' for more info\r\n"))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.HasPrefix(line, "kill "):
		name := strings.TrimPrefix(line, "kill ")
		m.kills = append(m.kills, name)
		if m.onKill != nil {
			m.onKill()
		}
		switch {
		case m.reply != "":
			_, _ = c.Write([]byte(m.reply + "\r\n"))
		case m.refuse:
			_, _ = c.Write([]byte("ERROR: management kill is disabled\r\n"))
		case m.sessions[name]:
			delete(m.sessions, name)
			_, _ = c.Write([]byte("SUCCESS: common name '" + name + "' found, 1 client(s) killed\r\n"))
		default:
			_, _ = c.Write([]byte("ERROR: common name '" + name + "' not found\r\n"))
		}
	default: // status 3, state
		_, _ = c.Write([]byte("END\r\n"))
	}
}

func (m *fakeMgmt) killed() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.kills...)
}

func (m *fakeMgmt) connected(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[name]
}

// deadMgmtAddr is an address nothing listens on.
func deadMgmtAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func withMgmt(oAdmin *OvpnAdmin, interfaces map[string]string) {
	oAdmin.mgmtInterfaces = interfaces
}

func switchOn(t *testing.T, pki, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), name), nil, 0644); err != nil {
		t.Fatal(err)
	}
}

func crlLists(t *testing.T, serial string) bool {
	t.Helper()
	return confirmSerialInCrl(t, serial) == nil
}

func confirmSerialInCrl(t *testing.T, serial string) error {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(*easyrsaDirPath, "pki", "crl.pem"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return err
	}
	for _, e := range crl.RevokedCertificateEntries {
		if serialMatches(e.SerialNumber, serial) {
			return nil
		}
	}
	return os.ErrNotExist
}

// Fix A: the session is killed although the panel never saw it (activeClients is empty).
func TestRevokeKillsASessionThePanelNeverSaw(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")
	if len(oAdmin.activeClients) != 0 {
		t.Fatal("the panel is meant not to know the session")
	}

	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatalf("userRevoke: %v (%s)", err, msg)
	}
	if mgmt.connected("alice") {
		t.Error("the session of alice survived the revoke")
	}
	if got := mgmt.killed(); len(got) != 1 || got[0] != "alice" {
		t.Errorf("kill commands = %v, want [alice]", got)
	}
	assertIndexEntry(t, serial, "R")
	if !crlLists(t, serial) {
		t.Error("the CRL does not list the revoked serial")
	}
	mustExist(t, pki, "crl.pem")
}

// Every configured management interface gets the kill, the user is connected to one of them only.
func TestRevokeKillsOnEveryManagementInterface(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	a, b := startFakeMgmt(t), startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"a": a.addr, "b": b.addr})
	mustCreate(t, oAdmin, "alice", "")

	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatalf("userRevoke: %v (%s)", err, msg)
	}
	if len(a.killed()) != 1 || len(b.killed()) != 1 || b.connected("alice") {
		t.Errorf("kills a=%v b=%v, session still on b: %t", a.killed(), b.killed(), b.connected("alice"))
	}
}

// "not connected" is success: the user has no session, that is what the revoke wants.
func TestRevokeOfAUserWithoutSessionSucceeds(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t)
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")

	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `user "alice" revoked` {
		t.Errorf("revoke: %d %q", rec.Code, rec.Body.String())
	}
	if got := mgmt.killed(); len(got) != 1 {
		t.Errorf("kill commands = %v, the kill is sent whether or not a session is known", got)
	}
}

// An unreachable management interface is a reported failure, and the revoke itself is done.
func TestRevokeReportsAnUnreachableManagementInterface(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	live := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"a-dead": deadMgmtAddr(t), "b-live": live.addr})
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")

	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("revoke: %d %q, want 500", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "the session of the user could not be killed") || strings.Contains(body, `"status"`) || strings.Contains(body, `user "alice" revoked`) {
		t.Errorf("body %q", body)
	}
	if live.connected("alice") {
		t.Error("the reachable interface was not tried because the first one failed")
	}
	assertIndexEntry(t, serial, "R")
}

func TestRevokeReportsARefusedKill(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t, "alice")
	mgmt.refuse = true
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")

	err, msg := oAdmin.userRevoke("alice")
	if err == nil || !strings.Contains(msg, "could not be killed") {
		t.Errorf("userRevoke: %v %q, want the failed kill reported", err, msg)
	}
	if isInputError(err) {
		t.Error("a failed kill is a server failure, not an input error")
	}
}

// A name the kill command cannot carry is refused, not sent (it could address something else).
func TestKillRefusesANameItCannotCarry(t *testing.T) {
	mgmt := startFakeMgmt(t)
	oAdmin := &OvpnAdmin{mgmtInterfaces: map[string]string{"srv": mgmt.addr}}
	for _, name := range []string{"", "a b", "10.8.0.2:1194", "a\nstatus", "a\tb"} {
		if err := oAdmin.mgmtKillUser(name); err == nil {
			t.Errorf("mgmtKillUser(%q) = nil, want an error", name)
		}
	}
	if got := mgmt.killed(); len(got) != 0 {
		t.Errorf("the management interface got %v", got)
	}
}

// Fix B: a failed gen-crl is a 500, not a revoked user.
func TestRevokeFailsWhenTheCrlCannotBeRebuilt(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")
	switchOn(t, pki, ".fake-fail-crl")

	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "the CRL could not be rebuilt") {
		t.Errorf("revoke: %d %q, want 500 and the CRL named", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `user "alice" revoked`) {
		t.Errorf("the failure is worded like a success: %q", rec.Body.String())
	}
	if mgmt.connected("alice") {
		t.Error("the session is killed although the CRL failed: the user must be cut off in any case")
	}
	if crlLists(t, serial) {
		t.Error("the CRL lists the serial although gen-crl failed")
	}
}

// gen-crl exits 0 but the CRL does not list the serial: caught by reading the CRL.
func TestRevokeFailsWhenTheCrlDoesNotListTheSerial(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	mustCreate(t, oAdmin, "bob", "")
	if err := easyrsaGenCrl(); err != nil {
		t.Fatal(err)
	}
	switchOn(t, pki, ".fake-noop-crl")

	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "the new CRL does not list the revoked certificate") {
		t.Errorf("revoke: %d %q, want 500 and the CRL named", rec.Code, rec.Body.String())
	}
}

func TestRevokeFailsWhenThereIsNoCrl(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	switchOn(t, pki, ".fake-noop-crl") // no CRL was ever written

	err, msg := oAdmin.userRevoke("alice")
	if err == nil || !strings.Contains(msg, "the new CRL does not list the revoked certificate") {
		t.Errorf("userRevoke: %v %q", err, msg)
	}
}

// A revoke that failed can be repeated: the second one does not run easyrsa revoke again (it would
// refuse) but rebuilds the CRL and kills the session.
func TestRevokeCanBeRepeatedAfterAFailure(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": deadMgmtAddr(t)})
	mustCreate(t, oAdmin, "alice", "")

	if err, _ := oAdmin.userRevoke("alice"); err == nil {
		t.Fatal("the first revoke should have failed: the management interface is down")
	}
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatalf("the repeated revoke: %v (%s)", err, msg)
	}
	if mgmt.connected("alice") {
		t.Error("the session survived the repeated revoke")
	}
}

func TestRevokeOfAnUnknownUserIsBadRequest(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t)
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {"ghost"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `User "ghost" not found`) {
		t.Errorf("revoke: %d %q", rec.Code, rec.Body.String())
	}
	if got := mgmt.killed(); len(got) != 0 {
		t.Errorf("a kill was sent for a user that does not exist: %v", got)
	}
}

func TestRevokeReportsAFailedPasswordRowRevoke(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	failOpenvpnUser(t, db, "revoke")

	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "the password of the user could not be revoked") {
		t.Errorf("revoke: %d %q", rec.Code, rec.Body.String())
	}
	if mgmt.connected("alice") {
		t.Error("the session survived")
	}
}

func TestRevokeRevokesThePasswordRow(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatalf("userRevoke: %v (%s)", err, msg)
	}
	if got := dbRow(t, db, "alice"); got != "Old-password-1|true" {
		t.Errorf("row = %q", got)
	}
}

// Rotate and delete cut the session too, on every interface, also for a certificate that is revoked already.
func TestRotateAndDeleteKillTheSession(t *testing.T) {
	for _, op := range []string{"rotate", "delete", "rotate a revoked user", "delete a revoked user"} {
		t.Run(op, func(t *testing.T) {
			oAdmin, _ := setupFakeEasyrsa(t)
			a, b := startFakeMgmt(t, "alice"), startFakeMgmt(t, "alice")
			withMgmt(oAdmin, map[string]string{"a": a.addr, "b": b.addr})
			mustCreate(t, oAdmin, "alice", "")
			if strings.HasSuffix(op, "revoked user") {
				// revoked while no interface was reachable: the revoke is reported as incomplete and the session lives on
				withMgmt(oAdmin, map[string]string{"gone": deadMgmtAddr(t)})
				if err, _ := oAdmin.userRevoke("alice"); err == nil || !userCertRevoked("alice") {
					t.Fatalf("the revoke should be reported as incomplete (err=%v), the certificate revoked", err)
				}
				withMgmt(oAdmin, map[string]string{"a": a.addr, "b": b.addr})
			}
			var err error
			var msg string
			if strings.HasPrefix(op, "rotate") {
				err, msg = oAdmin.userRotate("alice", "")
			} else {
				err, msg = oAdmin.userDelete("alice")
			}
			if err != nil {
				t.Fatalf("%v (%s)", err, msg)
			}
			if a.connected("alice") || b.connected("alice") {
				t.Errorf("session survived: a=%t b=%t", a.connected("alice"), b.connected("alice"))
			}
		})
	}
}

// A rotate that cannot cut the session fails as a whole: the certificate is back, the answer is a 500.
func TestRotateFailsAndRollsBackWhenTheSessionCannotBeKilled(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		db := setupFakeOpenvpnUser(t)
		withMgmt(oAdmin, map[string]string{"srv": deadMgmtAddr(t)})
		mustCreate(t, oAdmin, "alice", "Old-password-1")
		before, dbBefore := snapshotPKI(t, pki), readDB(t, db)

		rec := postForm(oAdmin.userRotateHandler, "/api/user/rotate", url.Values{"username": {"alice"}, "password": {"New-password-2"}})
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "as before") {
			t.Errorf("rotate: %d %q, want 500 and \"as before\"", rec.Code, rec.Body.String())
		}
		assertSamePKI(t, before, snapshotPKI(t, pki))
		if got := readDB(t, db); got != dbBefore {
			t.Errorf("users.db = %q, was %q", got, dbBefore)
		}
	})
}

func TestRotateFailsWhenTheFinalCrlCannotBeRebuilt(t *testing.T) {
	forEasyrsaLayouts(t, func(t *testing.T, oAdmin *OvpnAdmin, pki string) {
		mgmt := startFakeMgmt(t, "alice")
		withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
		mustCreate(t, oAdmin, "alice", "")
		// the revoke inside the rotate rebuilds the CRL (budget 1), the final rebuild fails
		if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-crl-budget"), []byte("1"), 0644); err != nil {
			t.Fatal(err)
		}
		rec := postForm(oAdmin.userRotateHandler, "/api/user/rotate", url.Values{"username": {"alice"}})
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Failed to rotate") {
			t.Errorf("rotate with a failing gen-crl: %d %q, want 500", rec.Code, rec.Body.String())
		}
	})
}

func TestDeleteFailsWhenTheSessionCannotBeKilled(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	withMgmt(oAdmin, map[string]string{"srv": deadMgmtAddr(t)})
	mustCreate(t, oAdmin, "carol", "")

	rec := postForm(oAdmin.userDeleteHandler, "/api/user/delete", url.Values{"username": {"carol"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "could not be killed") {
		t.Errorf("delete: %d %q, want 500", rec.Code, rec.Body.String())
	}
	if !checkUserExist("carol") {
		t.Error("the user is gone although the delete was reported as failed: the repeat would find nothing to kill")
	}
}

func TestDeleteReportsAFailedCleanup(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	withMgmt(oAdmin, map[string]string{"srv": startFakeMgmt(t).addr})
	mustCreate(t, oAdmin, "carol", "Old-password-1")
	failOpenvpnUser(t, db, "delete")

	rec := postForm(oAdmin.userDeleteHandler, "/api/user/delete", url.Values{"username": {"carol"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "the password row of the user could not be deleted") {
		t.Errorf("delete: %d %q, want 500", rec.Code, rec.Body.String())
	}
}

func TestRotateAndDeleteOfAnUnknownUserAreBadRequests(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	for name, h := range map[string]http.HandlerFunc{"rotate": oAdmin.userRotateHandler, "delete": oAdmin.userDeleteHandler} {
		rec := postForm(h, "/api/user/"+name, url.Values{"username": {"ghost"}})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s of an unknown user: %d %q, want 400", name, rec.Code, rec.Body.String())
		}
	}
}

// Fix C: change-password of a revoked user is refused and changes nothing.
func TestChangePasswordOfARevokedUserIsRefused(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	withMgmt(oAdmin, map[string]string{"srv": startFakeMgmt(t).addr})
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatal(msg)
	}
	dbBefore, indexBefore := readDB(t, db), fRead(*indexTxtPath)

	rec := postForm(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {"alice"}, "password": {"Valid-pass-2"}})
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	want := `user "alice" is revoked, unrevoke or rotate it first`
	if rec.Code != http.StatusBadRequest || body["status"] != "error" || body["message"] != want {
		t.Errorf("change-password: %d %v, want 400 %q", rec.Code, body, want)
	}
	if got := readDB(t, db); got != dbBefore {
		t.Errorf("users.db changed: %q, was %q", got, dbBefore)
	}
	if got := fRead(*indexTxtPath); got != indexBefore {
		t.Errorf("index.txt changed")
	}

	// unrevoked, the same request works
	if err, msg := oAdmin.userUnrevoke("alice"); err != nil {
		t.Fatal(msg)
	}
	rec = postForm(oAdmin.userChangePasswordHandler, "/api/user/change-password", url.Values{"username": {"alice"}, "password": {"Valid-pass-2"}})
	if rec.Code != http.StatusOK {
		t.Errorf("change-password of an unrevoked user: %d %q", rec.Code, rec.Body.String())
	}
}
