package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
)

// Tests of the repair of the five findings of the v0.1.11 audit. Each of them fails on 93c74cf.

func (m *fakeMgmt) setReply(reply string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reply = reply
}

func revokeForm(oAdmin *OvpnAdmin, name string) (int, string) {
	rec := postForm(oAdmin.userRevokeHandler, "/api/user/revoke", url.Values{"username": {name}})
	return rec.Code, rec.Body.String()
}

// Fix 1: the session is cut although the certificate revoke failed, and both outcomes are reported.
func TestRevokeCutsTheSessionWhenTheCertificateRevokeFails(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t, "alice")
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")
	switchOn(t, pki, ".fake-fail-revoke")

	code, body := revokeForm(oAdmin, "alice")
	if code != http.StatusInternalServerError {
		t.Errorf("revoke: %d %q, want 500", code, body)
	}
	if !strings.Contains(body, "the certificate could not be revoked") {
		t.Errorf("the failed certificate revoke is not named: %q", body)
	}
	if mgmt.connected("alice") {
		t.Error("the session of alice survived: the kill must be attempted although the certificate revoke failed")
	}
	if !strings.Contains(body, "The sessions of the user were ended") {
		t.Errorf("the answer does not say that the sessions were ended: %q", body)
	}
	assertIndexEntry(t, serial, "V") // the revoke really failed, the answer does not pretend otherwise
}

func TestRevokeReportsBothTheFailedRevokeAndTheFailedKill(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t, "alice")
	mgmt.refuse = true
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")
	switchOn(t, pki, ".fake-fail-revoke")

	_, body := revokeForm(oAdmin, "alice")
	for _, want := range []string{"the certificate could not be revoked", "the session of the user could not be killed"} {
		if !strings.Contains(body, want) {
			t.Errorf("%q is missing from %q", want, body)
		}
	}
	if strings.Contains(body, "The sessions of the user were ended") {
		t.Errorf("the answer claims the sessions were ended: %q", body)
	}
}

// Fix 1: only OpenVPN's own "not found" reply for the name that was sent means "no session".
func TestKillTreatsOnlyTheExactNotFoundReplyAsNoSession(t *testing.T) {
	mgmt := startFakeMgmt(t)
	oAdmin := &OvpnAdmin{mgmtInterfaces: map[string]string{"srv": mgmt.addr}}
	if err := oAdmin.mgmtKillUser("alice"); err != nil {
		t.Fatalf("the reply of OpenVPN for a user without session is not a failure: %v", err)
	}
	for _, reply := range []string{
		"ERROR: management kill is disabled, user not found in the access list",
		"ERROR: common name 'bob' not found",
		"ERROR: command not found",
		"ERROR: common name 'alice' not found: internal failure",
	} {
		mgmt.setReply(reply)
		if err := oAdmin.mgmtKillUser("alice"); err == nil {
			t.Errorf("the reply %q was taken for \"no session\"", reply)
		}
	}
}

// Fix 1: nothing was asked of any server, so nothing is known about the sessions.
func TestKillWithoutAnInterfaceIsAnError(t *testing.T) {
	oAdmin := &OvpnAdmin{}
	if err := oAdmin.mgmtKillUser("alice"); err == nil {
		t.Fatal("mgmtKillUser without a configured interface returned nil")
	}
	pkiAdmin, _ := setupFakeEasyrsa(t)
	pkiAdmin.mgmtInterfaces = map[string]string{}
	mustCreate(t, pkiAdmin, "alice", "")
	err, msg := pkiAdmin.userRevoke("alice")
	if err == nil || !strings.Contains(msg, "could not be killed") {
		t.Errorf("revoke without an interface: %v %q, want the failed kill reported", err, msg)
	}
}

// kubePKI sets up the kubernetes.secrets backend with a real CA, a fake API server and the files on disk.
func kubePKI(t *testing.T) (*OvpnAdmin, string, func(string) *big.Int, *atomic.Bool, *atomic.Bool) {
	t.Helper()
	client, _ := setupKubeTest(t)
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0755); err != nil {
		t.Fatal(err)
	}
	setFlag(t, easyrsaDirPath, dir)
	setFlag(t, indexTxtPath, filepath.Join(pki, "index.txt"))
	setFlag(t, authByPassword, false)
	setFlag(t, clientCertExpirationDays, "3650")

	old := app
	t.Cleanup(func() { app = old })
	var err error
	if app.CAPrivKeyPEM, err = genPrivKey(); err != nil {
		t.Fatal(err)
	}
	if app.CAPrivKeyRSA, err = decodePrivKey(app.CAPrivKeyPEM.Bytes()); err != nil {
		t.Fatal(err)
	}
	if app.CACertPEM, err = genCA(app.CAPrivKeyRSA); err != nil {
		t.Fatal(err)
	}
	if app.CACert, err = decodeCert(app.CACertPEM.Bytes()); err != nil {
		t.Fatal(err)
	}
	app.KubeClient = client
	if err := app.easyrsaBuildClient("alice"); err != nil {
		t.Fatal(err)
	}
	if err := app.easyrsaGenCRL(); err != nil {
		t.Fatal(err)
	}
	if err := app.updateCRLOnDisk(); err != nil {
		t.Fatal(err)
	}

	failCRL, staleCRL := &atomic.Bool{}, &atomic.Bool{}
	fail := func(action clienttesting.Action) (bool, runtime.Object, error) {
		if o, ok := action.(interface{ GetObject() runtime.Object }); ok {
			if s, ok := o.GetObject().(*v1.Secret); ok && s.Name == secretCRL {
				if failCRL.Load() {
					return true, nil, errors.New("injected failure: the CRL secret cannot be written")
				}
				if staleCRL.Load() {
					// a CRL secret that is published without the revoked serial
					old, err := fakeCrl(nil)
					if err != nil {
						t.Error(err)
					}
					s.Data["crl.pem"] = old
				}
			}
		}
		return false, nil, nil
	}
	client.PrependReactor("update", "secrets", fail)
	client.PrependReactor("create", "secrets", fail)

	serialOfUser := func(name string) *big.Int {
		secrets, err := client.CoreV1().Secrets(namespace).List(t.Context(), metav1.ListOptions{LabelSelector: "name=" + name})
		if err != nil || len(secrets.Items) != 1 {
			t.Fatalf("the secret of %s: %v (%d)", name, err, len(secrets.Items))
		}
		cert, err := decodeCert(secrets.Items[0].Data[certFileName])
		if err != nil {
			t.Fatal(err)
		}
		return cert.SerialNumber
	}
	oAdmin := &OvpnAdmin{createUserMutex: &sync.Mutex{}, mgmtInterfaces: map[string]string{"srv": startFakeMgmt(t, "alice").addr}}
	return oAdmin, dir, serialOfUser, failCRL, staleCRL
}

func crlFileLists(t *testing.T, dir string, serial *big.Int) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "pki", "crl.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// Fix 2: a revoke that stopped after the annotation was written leaves a CRL without the serial. The retry
// must publish a CRL that lists it, not answer "already revoked".
func TestKubernetesRevokeRetryRepublishesTheCrl(t *testing.T) {
	oAdmin, dir, serialOf, failCRL, _ := kubePKI(t)
	serial := serialOf("alice")

	failCRL.Store(true)
	if err, _ := oAdmin.userRevoke("alice"); err == nil {
		t.Fatal("the first revoke should fail: the CRL secret cannot be written")
	}
	if crlFileLists(t, dir, serial) {
		t.Fatal("the CRL lists the serial although it could not be published")
	}

	failCRL.Store(false)
	err, msg := oAdmin.userRevoke("alice")
	if err != nil {
		t.Fatalf("the retry: %v (%s)", err, msg)
	}
	if !crlFileLists(t, dir, serial) {
		t.Error("the retry answered success but the CRL OpenVPN reads does not list the revoked serial")
	}
}

// Fix 2: the serial check runs on the kubernetes backend as well: a CRL that does not list the serial is a failure.
func TestKubernetesRevokeChecksTheSerialInTheCrl(t *testing.T) {
	oAdmin, dir, serialOf, _, staleCRL := kubePKI(t)
	serial := serialOf("alice")
	staleCRL.Store(true) // the CRL is published without the revoked serial

	err, msg := oAdmin.userRevoke("alice")
	if err == nil || !strings.Contains(msg, "the new CRL does not list the revoked certificate") {
		t.Errorf("revoke: %v %q, want the CRL without the serial reported", err, msg)
	}
	if crlFileLists(t, dir, serial) {
		t.Error("the test needs a CRL without the serial")
	}
}

// Fix 2: a CRL the daemon cannot read is a failed revoke; the chmod failure is reported.
func TestRevokeReportsACrlThatCannotBeMadeReadable(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	switchOn(t, pki, ".fake-noop-crl") // gen-crl writes nothing: there is no crl.pem to chmod

	err, msg := oAdmin.userRevoke("alice")
	if err == nil || !strings.Contains(msg, "readable") {
		t.Errorf("userRevoke: %v %q, want the CRL permissions reported", err, msg)
	}
}

// Fix 2: delete never rewrites an index it could not read. Needs a user that is not root (root reads a
// file with mode 0200): the management hook turns index.txt write-only right after the revoke inside the delete.
func TestDeleteNeverRewritesAnIndexItCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	oAdmin, pki := setupFakeEasyrsa(t)
	mgmt := startFakeMgmt(t)
	withMgmt(oAdmin, map[string]string{"srv": mgmt.addr})
	mustCreate(t, oAdmin, "alice", "")
	mustCreate(t, oAdmin, "bob", "")
	index := filepath.Join(pki, "index.txt")
	before := fRead(index)
	mgmt.onKill = func() { _ = os.Chmod(index, 0200) }

	rec := postForm(oAdmin.userDeleteHandler, "/api/user/delete", url.Values{"username": {"alice"}})
	if err := os.Chmod(index, 0644); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "index.txt could not be read") {
		t.Errorf("delete: %d %q, want 500 with the unreadable index named", rec.Code, rec.Body.String())
	}
	after := fRead(index)
	if !strings.Contains(after, "/CN=bob") || !strings.Contains(after, "/CN=alice") {
		t.Errorf("index.txt was rewritten from an unreadable index:\n%q\nwas:\n%q", after, before)
	}
}

// Fix 2: unrevoke returns the failure of the CRL rebuild instead of answering success.
func TestUnrevokeReportsAFailedCrlRebuild(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatal(msg)
	}
	switchOn(t, pki, ".fake-fail-crl")

	rec := postForm(oAdmin.userUnrevokeHandler, "/api/user/unrevoke", url.Values{"username": {"alice"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "the CRL could not be rebuilt") {
		t.Errorf("unrevoke: %d %q, want 500 with the CRL named", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "successfully unrevoked") {
		t.Errorf("the failure is worded like a success: %q", rec.Body.String())
	}
}

func TestUnrevokeOfAnUnknownUserIsStillBadRequest(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	rec := postForm(oAdmin.userUnrevokeHandler, "/api/user/unrevoke", url.Values{"username": {"ghost"}})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unrevoke of an unknown user: %d %q, want 400", rec.Code, rec.Body.String())
	}
}

func waitForFile(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(name); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s did not appear", name)
}

// expiringCrl writes a CRL that is about to expire and makes every gen-crl write one that is valid for 180 days.
func expiringCrl(t *testing.T, pki string, now time.Time) {
	t.Helper()
	crl, err := fakeCrlAt(nil, now.AddDate(0, 0, -175), now.AddDate(0, 0, 5))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), crl, 0644); err != nil {
		t.Fatal(err)
	}
	next := now.AddDate(0, 0, 180).UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-crl-next"), []byte(next), 0644); err != nil {
		t.Fatal(err)
	}
}

func crlCalls(t *testing.T, pki string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(pki), ".fake-crl-calls"))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "gen-crl")
}

// Fix 3: a revoke that arrives while the refresh is rebuilding the CRL from the index it read earlier must not
// be overwritten by it. Run with -race.
func TestRevokeAndRefreshRunningTogetherNeverPublishAStaleCrl(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	serial := serialOf(t, "alice")
	now := time.Now()
	expiringCrl(t, pki, now)
	dir := filepath.Dir(pki)
	// the first gen-crl (the refresh's) reads index.txt and then needs 700 ms: a slow easyrsa
	if err := os.WriteFile(filepath.Join(dir, ".fake-crl-slow-first"), []byte("700"), 0644); err != nil {
		t.Fatal(err)
	}

	refreshed := make(chan bool, 1)
	go func() { refreshed <- oAdmin.crlRefresh(now) }()
	waitForFile(t, filepath.Join(dir, ".fake-crl-started"))

	err, msg := oAdmin.userRevoke("alice")
	if err != nil {
		t.Fatalf("userRevoke: %v (%s)", err, msg)
	}
	if !<-refreshed {
		t.Error("the refresh failed")
	}
	assertIndexEntry(t, serial, "R")
	if !crlLists(t, serial) {
		t.Fatal("the published CRL does not list the revoked serial: the refresh overwrote it with a CRL built from the index it read before the revoke")
	}
}

// Fix 3: the refresh decides after it holds the lock: a writer that rebuilt the CRL meanwhile is enough.
func TestRefreshReadsTheExpiryAfterTakingTheLock(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	mustCreate(t, oAdmin, "alice", "")
	now := time.Now()
	expiringCrl(t, pki, now)
	before := crlCalls(t, pki)

	oAdmin.createUserMutex.Lock() // another writer is at work
	refreshed := make(chan bool, 1)
	go func() { refreshed <- oAdmin.crlRefresh(now) }()
	time.Sleep(300 * time.Millisecond)      // the refresh has looked at the CRL and waits for the lock
	if err := easyrsaGenCrl(); err != nil { // the writer publishes a fresh CRL
		t.Fatal(err)
	}
	oAdmin.createUserMutex.Unlock()
	if !<-refreshed {
		t.Fatal("the refresh failed")
	}
	if got := crlCalls(t, pki) - before; got != 1 {
		t.Errorf("gen-crl ran %d times, want 1: the refresh rebuilt a CRL that another writer had refreshed already", got)
	}
}

// Fix 3: revoke, unrevoke and delete all write the PKI under the one lock.
func TestEveryPkiWriterWaitsForTheLock(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	for _, u := range []string{"alice", "bob", "carol"} {
		mustCreate(t, oAdmin, u, "")
	}
	if err, msg := oAdmin.userRevoke("bob"); err != nil {
		t.Fatal(msg)
	}

	oAdmin.createUserMutex.Lock()
	var finished atomic.Int32
	var wg sync.WaitGroup
	for _, op := range []func(){
		func() { oAdmin.userRevoke("alice") },
		func() { oAdmin.userUnrevoke("bob") },
		func() { oAdmin.userDelete("carol") },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op()
			finished.Add(1)
		}()
	}
	time.Sleep(400 * time.Millisecond)
	if n := finished.Load(); n != 0 {
		t.Errorf("%d of 3 writers changed the PKI while another writer held the lock", n)
	}
	oAdmin.createUserMutex.Unlock()
	wg.Wait()
	if got := strings.Join(indexLines(t), ", "); got != "R REVOKED-carol, R alice, V bob" {
		t.Errorf("index.txt = %s", got)
	}
}

// tarMembers returns the content of every member of a tar.gz by name.
func tarMembers(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[h.Name] = content
	}
}

// caKeyFixtures writes a PKI with a real CA, a server and a client and returns the CA key PEM.
func caKeyFixtures(t *testing.T, pki string) (caPEM []byte, clientPEM []byte) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	pemOf := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	caKey, serverKey, clientKey := newKey(), newKey(), newKey()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := func(k *ecdsa.PrivateKey) []byte {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sec1 := func(k *ecdsa.PrivateKey) []byte {
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	write := func(name string, data []byte) {
		p := filepath.Join(pki, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caPEM = pemOf("PRIVATE KEY", pkcs8(caKey))
	clientPEM = pemOf("PRIVATE KEY", pkcs8(clientKey))
	write("ca.crt", pemOf("CERTIFICATE", der))
	write("private/ca.key", caPEM)
	write("private/alice.key", clientPEM)
	write("private/server.key", pemOf("PRIVATE KEY", pkcs8(serverKey)))
	write("ta.key", []byte("-----BEGIN OpenVPN Static key V1-----\n00\n-----END OpenVPN Static key V1-----\n"))
	write("dh.pem", pemOf("DH PARAMETERS", []byte{1, 2, 3}))
	write("crl.pem", []byte("CRL"))
	write("index.txt", []byte("INDEX"))
	write("users.db", []byte("SQLITE"))
	// copies of the CA signing key under names that say nothing
	write("private/backup-20260101.pem", caPEM)                                                                     // the same PEM
	write("reqs/notes.txt", append([]byte("my notes\n"), caPEM...))                                                 // inside another file
	write("issued/server-extra.pem", pemOf("EC PRIVATE KEY", sec1(caKey)))                                          // another encoding of the same key
	write("inline/private/bundle.inline", append(pemOf("CERTIFICATE", der), pemOf("PRIVATE KEY", pkcs8(caKey))...)) // like ca.inline
	write("revoked/private_by_serial/9999.der", pkcs8(caKey))                                                       // bare DER
	return caPEM, clientPEM
}

// Fix 4: the CA signing key stays out of the sync archive under any name; client keys, server.key, ta.key, dh, the
// CRL, index.txt and users.db stay in.
func TestArchiveExcludesTheCaKeyUnderAnyName(t *testing.T) {
	_, pki := setupFakeEasyrsa(t)
	caPEM, clientPEM := caKeyFixtures(t, pki)
	t.Setenv("TMPDIR", t.TempDir())

	archive, err := archiveCerts()
	if err != nil {
		t.Fatal(err)
	}
	defer removeArchive(archive)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	names := tarNames(t, data)
	for _, leaked := range []string{"private/ca.key", "private/backup-20260101.pem", "reqs/notes.txt", "issued/server-extra.pem", "inline/private/bundle.inline", "revoked/private_by_serial/9999.der"} {
		if contains(names, leaked) {
			t.Errorf("%s holds the CA signing key and is in the archive", leaked)
		}
	}
	for _, kept := range []string{"private/alice.key", "private/server.key", "ta.key", "dh.pem", "crl.pem", "index.txt", "users.db", "ca.crt"} {
		if !contains(names, kept) {
			t.Errorf("%s is missing from the archive: %v", kept, names)
		}
	}
	// what was archived: the client key is there byte for byte, the CA key bytes nowhere
	members := tarMembers(t, data)
	if !bytes.Equal(members["private/alice.key"], clientPEM) {
		t.Error("the client key in the archive is not the one on disk")
	}
	for name, content := range members {
		if bytes.Contains(content, caPEM) {
			t.Errorf("the archive member %s carries the CA key", name)
		}
	}
}

// the archive cannot be built when the CA key cannot be read: no archive rather than one that may carry it
func TestArchiveFailsClosedWhenTheCaKeyCannotBeRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	_, pki := setupFakeEasyrsa(t)
	caKeyFixtures(t, pki)
	if err := os.Chmod(filepath.Join(pki, "private/ca.key"), 0); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	archive, err := archiveCerts()
	if err == nil {
		removeArchive(archive)
		t.Fatal("an archive was built without knowing what the CA key is")
	}
}

// Fix 5: the final CRL rebuild fails: the password is never touched, so "as before" is true.
func TestRotateFailureOnTheFinalCrlLeavesTheOldPassword(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	// the revoke inside the rotate rebuilds the CRL (budget 1), the final rebuild fails
	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-crl-budget"), []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	err, msg := oAdmin.userRotate("alice", "New-password-2")
	if err == nil {
		t.Fatal("the rotate succeeded although the final CRL rebuild failed")
	}
	row := dbRow(t, db, "alice")
	if strings.Contains(msg, "password are as before") && row != "Old-password-1|false" {
		t.Errorf("the operator reads %q but the password row is %q", msg, row)
	}
	if row != "Old-password-1|false" {
		t.Errorf("password row = %q, want the old password, not revoked", row)
	}
}

// Fix 5: the new password was stored and a later step failed: the answer says so, and it is true.
func TestRotateSaysWhenThePasswordWasAlreadyChanged(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	// after change-password worked, openvpn-user cannot be asked for the row any more
	if err := os.WriteFile(db+".failafterchange", nil, 0644); err != nil {
		t.Fatal(err)
	}
	err, msg := oAdmin.userRotate("alice", "New-password-2")
	if err == nil {
		t.Fatal("the rotate succeeded although the row could not be verified")
	}
	if got := dbRow(t, db, "alice"); !strings.HasPrefix(got, "New-password-2|") {
		t.Fatalf("the test needs the new password to be stored, the row is %q", got)
	}
	if strings.Contains(msg, "password are as before") {
		t.Errorf("the operator reads that the password is as before, but it is the new one: %q", msg)
	}
	if !strings.Contains(msg, "new password") {
		t.Errorf("the answer does not say that the new password is live: %q", msg)
	}
}

// Fix 5: a failure before the password step never touches the password and says so.
func TestRotateFailureBeforeThePasswordStepLeavesTheOldPassword(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	db := setupFakeOpenvpnUser(t)
	mustCreate(t, oAdmin, "alice", "Old-password-1")
	if err := os.WriteFile(filepath.Join(filepath.Dir(pki), ".fake-fail-build"), []byte("clean"), 0644); err != nil {
		t.Fatal(err)
	}
	err, msg := oAdmin.userRotate("alice", "New-password-2")
	if err == nil || !strings.Contains(msg, "the certificate and the password are as before") {
		t.Errorf("userRotate: %v %q", err, msg)
	}
	if got := dbRow(t, db, "alice"); got != "Old-password-1|false" {
		t.Errorf("password row = %q", got)
	}
}
