package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// gaugeValue reads ovpn_crl_expire_days through a registry, like a scrape does.
func gaugeValue(t *testing.T) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := reg.Register(ovpnCrlExpire); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil || len(families) != 1 {
		t.Fatalf("gather: %v, %d families", err, len(families))
	}
	return families[0].GetMetric()[0].GetGauge().GetValue()
}

// ---- Fix C: the sync archive carries no CA private key and leaves no temp file ----

// writePki lays out the files of a master PKI that matter for the archive.
func writePki(t *testing.T, pki string) {
	t.Helper()
	files := map[string]string{
		"ca.crt":                             "CA CERT",
		"crl.pem":                            "CRL",
		"index.txt":                          "INDEX",
		"ta.key":                             "TLS AUTH KEY",
		"dh.pem":                             "DH",
		"users.db":                           "SQLITE",
		"issued/server.crt":                  "SERVER CERT",
		"issued/alice.crt":                   "ALICE CERT",
		"private/ca.key":                     "CA PRIVATE KEY",
		"inline/private/ca.inline":           "CA PRIVATE KEY INLINE",
		"inline/private/alice.inline":        "ALICE INLINE",
		"private/server.key":                 "SERVER KEY",
		"private/alice.key":                  "ALICE KEY",
		"revoked/private_by_serial/1001.key": "REVOKED ALICE KEY",
		"reqs/alice.req":                     "REQ",
		"certs_by_serial/1001.pem":           "PEM",
		"revoked/certs_by_serial/1002.crt":   "REVOKED CERT",
		"easy-rsa-sample/ca.key.example.is.a.file": "not the CA key, only a similar name",
	}
	for name, content := range files {
		p := filepath.Join(pki, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeCaIdentity(t, pki)
}

// tarNames lists the member names of a tar.gz.
func tarNames(t *testing.T, data []byte) []string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return names
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestCertsArchiveHasNoCaKey(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	_ = oAdmin
	writePki(t, pki)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	archive, err := archiveCerts()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(archive)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("archive mode %v, want 0600 (it holds client keys)", fi.Mode().Perm())
	}
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	names := tarNames(t, data)

	if contains(names, "private/ca.key") || contains(names, "inline/private/ca.inline") {
		t.Fatalf("private/ca.key is in the archive: %v", names)
	}
	if bytes.Contains(data, []byte("CA PRIVATE KEY")) {
		t.Fatal("compressed archive bytes contain the CA key text")
	}
	// what a slave needs stays in: OpenVPN reads ca.crt, issued/server.crt, private/server.key, ta.key, dh and the
	// CRL; the slave panel builds client configs from issued/ and private/<user>.key; auth.sh reads users.db
	for _, want := range []string{"ca.crt", "crl.pem", "index.txt", "ta.key", "dh.pem", "users.db", "issued/server.crt",
		"issued/alice.crt", "inline/private/alice.inline", "private/server.key", "private/alice.key", "revoked/private_by_serial/1001.key", "reqs/alice.req",
		"easy-rsa-sample/ca.key.example.is.a.file"} {
		if !contains(names, want) {
			t.Errorf("%s is missing from the archive: %v", want, names)
		}
	}
	// the CA key is still on the master
	if _, err := os.Stat(filepath.Join(pki, "private/ca.key")); err != nil {
		t.Errorf("the master lost its CA key: %v", err)
	}
}

func TestCertsArchiveSkipsOnlyCaKey(t *testing.T) {
	for rel, want := range map[string]bool{
		"private/ca.key":                   true,
		"inline/private/ca.inline":         true,
		"inline/private/alice.inline":      false,
		"ca.key":                           true,
		"sub/private/ca.key":               true,
		"private/alice.key":                false,
		"private/server.key":               false,
		"private/ca.key.bak":               false, // only the exact file name ca.key is the CA key
		"issued/ca.crt":                    false,
		"private/ca.keyx":                  false,
		"private/my-ca.key":                false,
		"revoked/private_by_serial/12.key": false,
	} {
		if got := certsArchiveSkips(rel); got != want {
			t.Errorf("certsArchiveSkips(%q) = %v, want %v", rel, got, want)
		}
	}
}

// The ccd archive is built the same way and has no filter.
func TestCcdArchiveKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte("ifconfig-push 10.0.0.2 255.255.255.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	setFlag(t, ccdDir, dir)
	t.Setenv("TMPDIR", t.TempDir())
	archive, err := archiveCcd()
	if err != nil {
		t.Fatal(err)
	}
	defer removeArchive(archive)
	data, _ := os.ReadFile(archive)
	if names := tarNames(t, data); len(names) != 1 || names[0] != "alice" {
		t.Errorf("ccd archive members %v", names)
	}
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The sync endpoint answers with the archive and leaves nothing in the temp dir, on success and on a bad token.
func TestDownloadCertsHandlerLeavesNoTempFile(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	writePki(t, pki)
	oAdmin.role = "master"
	oAdmin.masterSyncToken = "a-sync-token-for-the-test"
	setFlag(t, storageBackend, "filesystem")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	rec := httptest.NewRecorder()
	oAdmin.downloadCertsHandler(rec, loopbackGet("/api/data/certs/download?token=a-sync-token-for-the-test"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	names := tarNames(t, rec.Body.Bytes())
	if contains(names, "private/ca.key") || contains(names, "inline/private/ca.inline") || !contains(names, "issued/alice.crt") {
		t.Errorf("served archive: %v", names)
	}
	if got := rec.Header().Get("Content-Disposition"); got != "attachment; filename=certs.tar.gz" {
		t.Errorf("Content-Disposition %q", got)
	}
	if left := leftovers(t, tmp); len(left) != 0 {
		t.Errorf("temp files left after the request: %v", left)
	}

	rec = httptest.NewRecorder()
	oAdmin.downloadCertsHandler(rec, loopbackGet("/api/data/certs/download?token=wrong"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong token: status %d, want 403", rec.Code)
	}
	if left := leftovers(t, tmp); len(left) != 0 {
		t.Errorf("temp files left after a refused request: %v", left)
	}
}

// Two requests at the same time must not share (or delete) one file.
func TestDownloadCertsHandlerConcurrent(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	writePki(t, pki)
	oAdmin.role = "master"
	oAdmin.masterSyncToken = "a-sync-token-for-the-test"
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	done := make(chan *httptest.ResponseRecorder, 8)
	for i := 0; i < 8; i++ {
		go func() {
			rec := httptest.NewRecorder()
			oAdmin.downloadCertsHandler(rec, loopbackGet("/x?token=a-sync-token-for-the-test"))
			done <- rec
		}()
	}
	for i := 0; i < 8; i++ {
		rec := <-done
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		if names := tarNames(t, rec.Body.Bytes()); !contains(names, "issued/alice.crt") {
			t.Errorf("incomplete archive: %v", names)
		}
	}
	if left := leftovers(t, tmp); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

// The slave side: a download is extracted and the downloaded file is removed again.
func TestSlaveSyncRemovesDownloadedArchives(t *testing.T) {
	// master side
	master, pki := setupFakeEasyrsa(t)
	writePki(t, pki)
	master.role = "master"
	master.masterSyncToken = "a-sync-token-for-the-test"
	ccd := t.TempDir()
	if err := os.WriteFile(filepath.Join(ccd, "alice"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	setFlag(t, ccdDir, ccd)
	t.Setenv("TMPDIR", t.TempDir())
	// the master's archives are built before the flags point at the slave's directories (one process, one set of flags)
	certsFile, err := archiveCerts()
	if err != nil {
		t.Fatal(err)
	}
	ccdFile, err := archiveCcd()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+downloadCertsApiUrl, func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, certsFile) })
	mux.HandleFunc("/"+downloadCcdApiUrl, func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, ccdFile) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// slave side, its own directories
	slaveDir := t.TempDir()
	slaveCcd := t.TempDir()
	dl := t.TempDir()
	setFlag(t, masterHost, srv.URL)
	setFlag(t, listenBaseUrl, "/")
	setFlag(t, easyrsaDirPath, slaveDir)
	setFlag(t, ccdDir, slaveCcd)
	setFlag(t, &certsArchivePath, filepath.Join(dl, "certs.tar.gz"))
	setFlag(t, &ccdArchivePath, filepath.Join(dl, "ccd.tar.gz"))
	slave := &OvpnAdmin{role: "slave", masterSyncToken: "a-sync-token-for-the-test", createUserMutex: master.createUserMutex}
	slave.syncDataFromMaster()

	if slave.lastSuccessfulSyncTime == "" || slave.lastSuccessfulSyncTime == "unknown" {
		t.Fatalf("sync did not succeed (last successful %q)", slave.lastSuccessfulSyncTime)
	}
	if left := leftovers(t, dl); len(left) != 0 {
		t.Errorf("downloaded archives left on the slave: %v", left)
	}
	for _, f := range []string{"pki/issued/alice.crt", "pki/private/server.key", "pki/users.db", "pki/crl.pem"} {
		if _, err := os.Stat(filepath.Join(slaveDir, f)); err != nil {
			t.Errorf("slave misses %s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(slaveDir, "pki/private/ca.key")); err == nil {
		t.Error("the slave received private/ca.key")
	}
}

// ---- Fix B: the CRL is rebuilt before it expires, and ovpn_crl_expire_days says how long it is valid ----

func writeCrlExpiring(t *testing.T, pki string, now time.Time, days float64) {
	t.Helper()
	next := now.Add(time.Duration(days * 24 * float64(time.Hour)))
	crl, err := fakeCrlAt(nil, now.AddDate(0, 0, -180), next)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), crl, 0644); err != nil {
		t.Fatal(err)
	}
}

// gen-crl of the fake easyrsa writes a CRL valid for 180 days from now when this file is there.
func fakeRebuildGives(t *testing.T, easyrsaDir string, next time.Time) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(easyrsaDir, ".fake-crl-next"), []byte(next.UTC().Format(time.RFC3339)), 0644); err != nil {
		t.Fatal(err)
	}
}

func crlDaysOnDisk(t *testing.T, now time.Time) float64 {
	t.Helper()
	next, err := crlNextUpdate()
	if err != nil {
		t.Fatal(err)
	}
	return crlExpireDays(next, now)
}

func TestCrlRefreshRebuildsUnder30Days(t *testing.T) {
	for _, tc := range []struct {
		name string
		days float64
	}{{"10 days left", 10}, {"29 days left", 29}, {"expired two days ago", -2}} {
		t.Run(tc.name, func(t *testing.T) {
			oAdmin, pki := setupFakeEasyrsa(t)
			oAdmin.role = "master"
			logs := captureLog(t)
			now := time.Now()
			writeCrlExpiring(t, pki, now, tc.days)
			fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180))
			ovpnCrlExpire.Set(12345)

			oAdmin.crlRefresh(now)

			if got := crlDaysOnDisk(t, now); got < 179 || got > 181 {
				t.Errorf("CRL on disk has %.2f days left after the check, want about 180", got)
			}
			if got := gaugeValue(t); got < 179 || got > 181 {
				t.Errorf("ovpn_crl_expire_days = %.2f after the rebuild, want about 180", got)
			}
			if n := strings.Count(logs.String(), "CRL rebuilt"); n != 1 {
				t.Errorf("%d \"CRL rebuilt\" lines, want 1:\n%s", n, logs.String())
			}
			if strings.Contains(logs.String(), "CRL rebuild failed") {
				t.Errorf("a failure line was logged:\n%s", logs.String())
			}
		})
	}
}

func TestCrlRefreshKeepsAHealthyCrl(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	logs := captureLog(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, 31)
	before, _ := os.ReadFile(filepath.Join(pki, "crl.pem"))
	// a rebuild would fail, so a call of gen-crl would show up in the log
	if err := os.WriteFile(filepath.Join(*easyrsaDirPath, ".fake-fail-crl"), nil, 0644); err != nil {
		t.Fatal(err)
	}

	oAdmin.crlRefresh(now)

	after, _ := os.ReadFile(filepath.Join(pki, "crl.pem"))
	if !bytes.Equal(before, after) {
		t.Error("the CRL changed although 31 days were left")
	}
	if strings.Contains(logs.String(), "CRL rebuild") {
		t.Errorf("rebuild logged for a healthy CRL:\n%s", logs.String())
	}
	if got := gaugeValue(t); got < 30.9 || got > 31.1 {
		t.Errorf("ovpn_crl_expire_days = %.2f, want about 31", got)
	}
}

// A failed rebuild is one error line, the old CRL stays, nothing crashes; the next run (after the repair) works.
func TestCrlRefreshFailureIsLoggedAndSurvivable(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	logs := captureLog(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, 10)
	before, _ := os.ReadFile(filepath.Join(pki, "crl.pem"))
	fail := filepath.Join(*easyrsaDirPath, ".fake-fail-crl")
	if err := os.WriteFile(fail, nil, 0644); err != nil {
		t.Fatal(err)
	}

	if oAdmin.crlRefresh(now) {
		t.Error("a failed rebuild was reported as ok")
	}

	if n := strings.Count(logs.String(), "CRL rebuild failed"); n != 1 {
		t.Errorf("%d failure lines, want 1:\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "CRL rebuilt") {
		t.Errorf("success logged although gen-crl failed:\n%s", logs.String())
	}
	after, _ := os.ReadFile(filepath.Join(pki, "crl.pem"))
	if !bytes.Equal(before, after) {
		t.Error("the CRL changed although gen-crl failed")
	}
	if got := gaugeValue(t); got < 9.9 || got > 10.1 {
		t.Errorf("ovpn_crl_expire_days = %.2f after a failed rebuild, want about 10 (the CRL that is still in use)", got)
	}

	// the cause is fixed: the next run rebuilds
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180))
	oAdmin.crlRefresh(now)
	if got := crlDaysOnDisk(t, now); got < 179 {
		t.Errorf("the repaired run left %.2f days", got)
	}
}

// gen-crl that exits 0 and writes nothing is a failure too: the check reads the file.
func TestCrlRefreshNoopRebuildIsAFailure(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	logs := captureLog(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, 10)
	if err := os.WriteFile(filepath.Join(*easyrsaDirPath, ".fake-noop-crl"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	oAdmin.crlRefresh(now)
	if !strings.Contains(logs.String(), "CRL rebuild failed") || !strings.Contains(logs.String(), "did not move") {
		t.Errorf("no failure line for a rebuild that changed nothing:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "CRL rebuilt") {
		t.Errorf("success logged:\n%s", logs.String())
	}
}

// No crl.pem at all is a PKI that is not built yet (first start of a new stack, the openvpn container is still
// running easyrsa): a warning, no gen-crl, no failure to retry.
func TestCrlRefreshMissingCrlWaitsForThePki(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	logs := captureLog(t)
	now := time.Now()
	fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180))
	if _, err := os.Stat(filepath.Join(pki, "crl.pem")); err == nil {
		t.Fatal("the test PKI already has a CRL")
	}
	if !oAdmin.crlRefresh(now) {
		t.Error("a missing CRL was reported as a failed rebuild")
	}
	if _, err := os.Stat(filepath.Join(pki, "crl.pem")); err == nil {
		t.Error("gen-crl ran although there was no CRL yet")
	}
	if !strings.Contains(logs.String(), "no CRL yet") || strings.Contains(logs.String(), "CRL rebuild") {
		t.Errorf("log:\n%s", logs.String())
	}
}

// A CRL file that exists but is garbage is rebuilt.
func TestCrlRefreshUnreadableCrlIsRebuilt(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	logs := captureLog(t)
	now := time.Now()
	fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180))
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), []byte("not a CRL"), 0644); err != nil {
		t.Fatal(err)
	}
	if !oAdmin.crlRefresh(now) {
		t.Error("rebuild reported as failed")
	}
	if got := crlDaysOnDisk(t, now); got < 179 {
		t.Errorf("%.2f days after rebuilding an unreadable CRL", got)
	}
	if !strings.Contains(logs.String(), "CRL rebuilt") {
		t.Errorf("no rebuild line:\n%s", logs.String())
	}
}

// A slave has no CA key: it never runs gen-crl, it reports (the master rebuilds, the sync brings the new file).
func TestCrlRefreshSlaveOnlyReports(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "slave"
	logs := captureLog(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, 10)
	before, _ := os.ReadFile(filepath.Join(pki, "crl.pem"))
	fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180)) // would change the file if gen-crl ran

	oAdmin.crlRefresh(now)

	after, _ := os.ReadFile(filepath.Join(pki, "crl.pem"))
	if !bytes.Equal(before, after) {
		t.Error("a slave rebuilt the CRL")
	}
	if !strings.Contains(logs.String(), "CRL check on a slave") {
		t.Errorf("no warning on the slave:\n%s", logs.String())
	}
	if got := gaugeValue(t); got < 9.9 || got > 10.1 {
		t.Errorf("slave gauge %.2f, want about 10", got)
	}
}

// The loop checks at start and then every interval; closing stop ends it.
func TestCrlRefreshLoopRunsRepeatedly(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	captureLog(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, 100)
	fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180))

	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() { oAdmin.crlRefreshLoop(0, 40*time.Millisecond, 40*time.Millisecond, stop); close(finished) }()
	defer func() { close(stop); <-finished }()

	time.Sleep(150 * time.Millisecond) // several rounds on a healthy CRL: nothing happens
	if got := crlDaysOnDisk(t, now); got < 99 || got > 101 {
		t.Fatalf("the loop touched a healthy CRL: %.2f days", got)
	}
	// the CRL now runs short: a later round rebuilds it, without a restart
	writeCrlExpiring(t, pki, time.Now(), 5)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if crlDaysOnDisk(t, time.Now()) > 100 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the loop did not rebuild the CRL that had 5 days left: %.2f days", crlDaysOnDisk(t, time.Now()))
}

// syncBuffer is a log sink that the test can read while a goroutine still writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogSafe(t *testing.T) *syncBuffer {
	t.Helper()
	b := &syncBuffer{}
	oldOut, oldLevel := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(b)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetLevel(oldLevel) })
	return b
}

// After a failed rebuild the loop retries after the short retry interval (not a day later) and recovers.
func TestCrlRefreshLoopRetriesAfterAFailure(t *testing.T) {
	oAdmin, pki := setupFakeEasyrsa(t)
	oAdmin.role = "master"
	logs := captureLogSafe(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, 5)
	fail := filepath.Join(*easyrsaDirPath, ".fake-fail-crl")
	if err := os.WriteFile(fail, nil, 0644); err != nil {
		t.Fatal(err)
	}
	fakeRebuildGives(t, *easyrsaDirPath, now.AddDate(0, 0, 180))

	stop := make(chan struct{})
	finished := make(chan struct{})
	// interval one hour, retry 30 ms: only a retry can rebuild within the test
	go func() { oAdmin.crlRefreshLoop(0, time.Hour, 30*time.Millisecond, stop); close(finished) }()
	defer func() { close(stop); <-finished }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && strings.Count(logs.String(), "CRL rebuild failed") < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := strings.Count(logs.String(), "CRL rebuild failed"); n < 2 {
		t.Fatalf("%d failures logged, the loop does not retry:\n%s", n, logs.String())
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) && !strings.Contains(logs.String(), "CRL rebuilt") {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "CRL rebuilt") {
		t.Fatalf("the loop did not recover after the cause was fixed:\n%s", logs.String())
	}
}

// The gauge is registered under its name and exposes a negative value for an expired CRL.
func TestCrlExpireGaugeRegisteredAndNegative(t *testing.T) {
	_, pki := setupFakeEasyrsa(t)
	now := time.Now()
	writeCrlExpiring(t, pki, now, -3)
	setCrlExpireGauge(now)

	reg := prometheus.NewRegistry()
	oAdmin := &OvpnAdmin{promRegistry: reg}
	oAdmin.registerMetrics()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range families {
		if f.GetName() == "ovpn_crl_expire_days" {
			found = true
			if v := f.GetMetric()[0].GetGauge().GetValue(); v > -2.9 || v < -3.1 {
				t.Errorf("gauge %.3f for a CRL expired 3 days ago, want about -3", v)
			}
		}
	}
	if !found {
		t.Error("ovpn_crl_expire_days is not registered")
	}
}
