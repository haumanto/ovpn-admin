package main

// Tests of cert_lifecycle.go. The expiry scan and the notices run on certificates that the tests write with
// the expiry they need; renewal runs against a real easy-rsa (a PKI built in a temporary directory, the real
// CRL, the real index.txt). A test that needs easy-rsa skips when there is none on the host (the golang:alpine
// container of the release gate has it: apk add easy-rsa openssl).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// ---------------------------------------------------------------------------------------------------------------
// helpers

var certT0 = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

func certTestAdmin() *OvpnAdmin {
	return &OvpnAdmin{createUserMutex: &sync.Mutex{}}
}

// setCertClock moves the clock of cert_lifecycle.go for the test.
func setCertClock(t *testing.T, now time.Time) {
	t.Helper()
	old := certNow
	certNow = func() time.Time { return now }
	t.Cleanup(func() { certNow = old })
}

func moveCertClock(now time.Time) { certNow = func() time.Time { return now } }

// writeCertAt writes pki/issued/<name>.crt (pki/ca.crt for a CA) with the given expiry, self-signed: the scan
// reads the file and never checks a chain.
func writeCertAt(t *testing.T, pki, name string, serial int64, notAfter time.Time, kind string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	path := filepath.Join(pki, "issued", name+".crt")
	switch kind {
	case certKindCA:
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
		path = filepath.Join(pki, "ca.crt")
	case certKindServer:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	default:
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
}

// setupScanPKI is an empty PKI directory for the tests that write their own certificates, the clock at certT0.
func setupScanPKI(t *testing.T) (*OvpnAdmin, string) {
	t.Helper()
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(filepath.Join(pki, "issued"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "index.txt"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	setFlag(t, easyrsaDirPath, dir)
	setFlag(t, indexTxtPath, filepath.Join(pki, "index.txt"))
	setFlag(t, storageBackend, "filesystem")
	setCertClock(t, certT0)
	clearTelegram(t)
	t.Setenv("OVPN_NOTIFY_CERT_DAYS", "")
	return certTestAdmin(), pki
}

func days(n int, extra time.Duration) time.Time {
	return certT0.Add(time.Duration(n)*24*time.Hour + extra)
}

type certStateFile struct {
	Version int `json:"version"`
	Certs   map[string]struct {
		Serial   string `json:"serial"`
		NotAfter string `json:"notAfter"`
		Fired    []int  `json:"fired"`
	} `json:"certs"`
}

func readNotifyState(t *testing.T, pki string) certStateFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pki, "cert-notify-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st certStateFile
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("cert-notify-state.json: %v: %s", err, data)
	}
	return st
}

func adminReq(method, target string, form url.Values) *http.Request {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.SetBasicAuth(honestAdminUser, honestAdminPass)
	return req
}

func callHandler(h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("answer is not JSON (%d): %v: %s", rec.Code, err, rec.Body.String())
	}
	return m
}

func auditActions(t *testing.T, a *adminAuditLog) []adminAuditRecord {
	t.Helper()
	return parseAuditLines(t, readAuditFile(t, a.Path()))
}

func countAudit(recs []adminAuditRecord, action string) int {
	n := 0
	for _, r := range recs {
		if r.Action == action {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------------------------------------------
// the scan and the notices

func TestCertNotifyThresholdsParse(t *testing.T) {
	cases := []struct{ env, want string }{
		{"", "30,14,7,3,1"},
		{"  ", "30,14,7,3,1"},
		{"60, 10,10,2", "60,10,2"},
		{"1,7", "7,1"},
		{"7,abc", "30,14,7,3,1"},
		{"0,7", "30,14,7,3,1"},
		{"-3", "30,14,7,3,1"},
		{"99999", "30,14,7,3,1"},
	}
	for _, c := range cases {
		t.Setenv("OVPN_NOTIFY_CERT_DAYS", c.env)
		var parts []string
		for _, d := range certNotifyThresholds() {
			parts = append(parts, fmt.Sprint(d))
		}
		if got := strings.Join(parts, ","); got != c.want {
			t.Errorf("OVPN_NOTIFY_CERT_DAYS=%q: thresholds %s, want %s", c.env, got, c.want)
		}
	}
}

func TestCertDaysLeftIsFlooredAndMayBeNegative(t *testing.T) {
	cases := []struct {
		after time.Duration
		want  int
	}{
		{8*24*time.Hour + 23*time.Hour, 8},
		{24 * time.Hour, 1},
		{24*time.Hour - time.Second, 0},
		{0, 0},
		{-time.Second, -1},
		{-36 * time.Hour, -2},
		{-48 * time.Hour, -2},
	}
	for _, c := range cases {
		ci := certInfo{NotAfter: certT0.Add(c.after)}
		if got := ci.daysLeft(certT0); got != c.want {
			t.Errorf("expires in %v: daysLeft %d, want %d", c.after, got, c.want)
		}
	}
}

func TestCertScanFiresOncePerThresholdAndPersistsState(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	m := startTgMock(t)
	useTelegram(t, m)
	a := useAdminAudit(t, "")

	writeCertAt(t, pki, "alice", 0x10, days(20, 2*time.Hour), certKindClient) // 20 days: crosses 30
	writeCertAt(t, pki, "bob", 0x11, days(400, 0), certKindClient)            // far away
	writeCertAt(t, pki, "server", 0x12, days(5, time.Hour), certKindServer)   // 5 days: crosses 30, 14, 7 -> one notice
	writeCertAt(t, pki, "ca", 0x13, days(2, time.Hour), certKindCA)           // 2 days: crosses 30..3 -> one notice

	rep := oAdmin.certScanAndNotify(context.Background())
	if rep.Certificates != 4 || rep.Notices != 3 || rep.Sent != 3 || rep.Messages != 3 {
		t.Fatalf("first run: %+v, want 4 certificates, 3 notices, 3 sent", rep)
	}
	texts := m.texts()
	if len(texts) != 3 {
		t.Fatalf("%d messages, want 3: %q", len(texts), texts)
	}
	all := strings.Join(texts, "\n---\n")
	for _, want := range []string{
		"Certificate: alice", "Type: client", "Expires: 2026-12-21 (20 days left)",
		"Certificate: server", "Type: server", "Expires: 2026-12-06 (5 days left)",
		"Certificate: ca", "Type: ca", "Expires: 2026-12-03 (2 days left)",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("messages lack %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "bob") {
		t.Errorf("a certificate that is far from its expiry is in the messages:\n%s", all)
	}
	for _, b := range m.bodies {
		if _, has := b["parse_mode"]; has {
			t.Error("parse_mode is set: the notices must be plain text")
		}
	}

	// the same state again: nothing is sent twice
	rep = oAdmin.certScanAndNotify(context.Background())
	if rep.Sent != 0 || len(m.texts()) != 3 {
		t.Fatalf("second run sent again: %+v, %d messages", rep, len(m.texts()))
	}

	// the clock moves 4 days: alice is at 16 days (no new threshold), the server at 1 day (3 and 1 are new), the CA expired
	setCertClock(t, days(4, 0))
	rep = oAdmin.certScanAndNotify(context.Background())
	if rep.Sent != 2 {
		t.Fatalf("after 4 days: %+v, want 2 new messages (server, ca)", rep)
	}
	texts = m.texts()[3:]
	joined := strings.Join(texts, "\n---\n")
	if !strings.Contains(joined, "Certificate: server") || !strings.Contains(joined, "1 day left") {
		t.Errorf("no notice for the server certificate at 1 day:\n%s", joined)
	}
	if !strings.Contains(joined, "Certificate: ca") || !strings.Contains(joined, "expired") {
		t.Errorf("no notice for the expired CA:\n%s", joined)
	}
	if strings.Contains(joined, "alice") {
		t.Errorf("alice has no new threshold at 16 days but is announced:\n%s", joined)
	}
	// alice crosses 14 after 7 more days, and only that one
	setCertClock(t, days(7, 0))
	rep = oAdmin.certScanAndNotify(context.Background())
	if got := m.texts()[5:]; rep.Sent != 1 || len(got) != 1 || !strings.Contains(got[0], "Certificate: alice") || !strings.Contains(got[0], "13 days left") {
		t.Fatalf("after 7 days: %+v %q, want one notice of alice with 13 days left", rep, got)
	}

	// state: 0600, valid JSON, no temporary file left behind
	info, err := os.Stat(filepath.Join(pki, "cert-notify-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("cert-notify-state.json mode %v, want 0600", info.Mode().Perm())
	}
	st := readNotifyState(t, pki)
	if got := st.Certs["client/alice"].Fired; fmt.Sprint(got) != "[30 14]" {
		t.Errorf("alice fired %v, want [30 14]", got)
	}
	if got := st.Certs["server/server"].Fired; fmt.Sprint(got) != "[30 14 7 3 1]" {
		t.Errorf("server fired %v, want [30 14 7 3 1]", got)
	}
	if len(st.Certs["client/bob"].Fired) != 0 {
		t.Errorf("bob fired %v, want none", st.Certs["client/bob"].Fired)
	}
	entries, _ := os.ReadDir(pki)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}

	// audit: one cert.notify per message (6 sent), one cert.scan per run (4)
	recs := auditActions(t, a)
	if n := countAudit(recs, "cert.notify"); n != 6 {
		t.Errorf("%d cert.notify lines, want 6", n)
	}
	if n := countAudit(recs, "cert.scan"); n != 4 {
		t.Errorf("%d cert.scan lines, want 4", n)
	}
	for _, r := range recs {
		if r.Action == "cert.scan" && !strings.Contains(r.Detail, "certificates=4") {
			t.Errorf("cert.scan carries no count of certificates: %q", r.Detail)
		}
	}
}

func TestCertMessagesCarryTheSpecifiedWording(t *testing.T) {
	cases := []struct {
		kind, want string
	}{
		{certKindClient, "Renew in the panel (Users -> Renew) or POST /api/user/renew"},
		{certKindServer, "Renew in the panel (Server certificate -> Renew), then restart the openvpn container in a window and confirm."},
	}
	for _, c := range cases {
		text := certNoticeText(certInfo{Name: "n1", Kind: c.kind, NotAfter: days(8, time.Hour)}, 8)
		for _, want := range []string{"Certificate: n1", "Type: " + c.kind, "Expires: 2026-12-09 (8 days left)", c.want} {
			if !strings.Contains(text, want) {
				t.Errorf("%s message lacks %q:\n%s", c.kind, want, text)
			}
		}
	}
	ca := certNoticeText(certInfo{Name: "ca", Kind: certKindCA, NotAfter: days(8, time.Hour)}, 8)
	if !strings.Contains(ca, "Informational only") || strings.Contains(ca, "POST /api") || strings.Contains(ca, "Renew in the panel") {
		t.Errorf("the CA message is not informational only:\n%s", ca)
	}
	if got := certNoticeText(certInfo{Name: "x", Kind: certKindClient, NotAfter: days(-3, 0)}, -3); !strings.Contains(got, "expired 3 days ago") {
		t.Errorf("an expired certificate is not worded as expired:\n%s", got)
	}
}

func TestCertMessagesCarryNoSecrets(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	m := startTgMock(t)
	useTelegram(t, m)
	writeCertAt(t, pki, "alice", 0x10, days(3, time.Hour), certKindClient)
	oAdmin.certScanAndNotify(context.Background())
	for _, text := range m.texts() {
		for _, secret := range []string{testBotToken, "TESTTOKEN", "127.0.0.1", "bot" + testBotToken} {
			if strings.Contains(text, secret) {
				t.Errorf("a message carries %q: %s", secret, text)
			}
		}
	}
}

func TestCertScanWithNotificationsOffLogsOneLineAndStillSucceeds(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	a := useAdminAudit(t, "")
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	writeCertAt(t, pki, "alice", 0x10, days(2, 0), certKindClient)
	writeCertAt(t, pki, "bob", 0x11, days(2, 0), certKindClient)

	rep := oAdmin.certScanAndNotify(context.Background())
	if !rep.Skipped || rep.Sent != 0 || rep.Certificates != 2 {
		t.Fatalf("report %+v, want skipped, 2 certificates, nothing sent", rep)
	}
	infos := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.InfoLevel && strings.Contains(e.Message, "notifications are off") {
			infos++
		}
		if e.Level <= log.WarnLevel {
			t.Errorf("a switched-off notification logged a %s: %s", e.Level, e.Message)
		}
	}
	if infos != 1 {
		t.Errorf("%d info lines about the switched-off notifications, want exactly 1", infos)
	}
	if n := countAudit(auditActions(t, a), "cert.scan"); n != 1 {
		t.Errorf("%d cert.scan lines, want 1", n)
	}
	// nothing was announced, so nothing is marked fired: switching it on later announces them
	m := startTgMock(t)
	useTelegram(t, m)
	if rep := oAdmin.certScanAndNotify(context.Background()); rep.Sent != 2 {
		t.Errorf("after switching on: %+v, want 2 messages", rep)
	}
}

func TestCertScanInvalidTelegramSettingsDoNotFailTheScan(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	writeCertAt(t, pki, "alice", 0x10, days(2, 0), certKindClient)
	t.Setenv("OVPN_TELEGRAM_ENABLED", "true") // but no token, no chat
	rep := oAdmin.certScanAndNotify(context.Background())
	if !rep.Skipped || rep.Certificates != 1 {
		t.Fatalf("report %+v", rep)
	}
}

func TestCertFailedDeliveryIsTriedAgain(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	m := startTgMock(t)
	useTelegram(t, m)
	a := useAdminAudit(t, "")
	writeCertAt(t, pki, "alice", 0x10, days(2, 0), certKindClient)

	m.setStatus(500)
	rep := oAdmin.certScanAndNotify(context.Background())
	if rep.Sent != 0 || rep.Messages != 1 {
		t.Fatalf("report %+v, want one message tried and none sent", rep)
	}
	st := readNotifyState(t, pki)
	if got := st.Certs["client/alice"].Fired; len(got) != 0 {
		t.Errorf("a message that was not delivered is recorded as fired: %v", got)
	}
	m.setStatus(0)
	if rep := oAdmin.certScanAndNotify(context.Background()); rep.Sent != 1 {
		t.Fatalf("second run %+v, want the message sent now", rep)
	}
	recs := auditActions(t, a)
	failed, ok := 0, 0
	for _, r := range recs {
		if r.Action == "cert.notify" && r.Result == adminAuditResultFail {
			failed++
		}
		if r.Action == "cert.notify" && r.Result == adminAuditResultOK {
			ok++
		}
	}
	if failed != 1 || ok != 1 {
		t.Errorf("cert.notify lines: %d failed, %d ok, want 1 and 1", failed, ok)
	}
}

func TestCertRenewalOfAnExpiredLookingNameResetsItsState(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	m := startTgMock(t)
	useTelegram(t, m)
	writeCertAt(t, pki, "alice", 0x10, days(2, 0), certKindClient)
	oAdmin.certScanAndNotify(context.Background())
	if len(m.texts()) != 1 {
		t.Fatalf("%d messages, want 1", len(m.texts()))
	}
	resetCertNotifyState(certKindClient, "alice")
	if _, ok := readNotifyState(t, pki).Certs["client/alice"]; ok {
		t.Error("the state of alice is still there after the reset")
	}
	// a name that was reset announces its thresholds again
	oAdmin.certScanAndNotify(context.Background())
	if len(m.texts()) != 2 {
		t.Errorf("%d messages after the reset, want 2", len(m.texts()))
	}
	// the new certificate of the name has another serial: a stale entry of the old one never silences it
	writeCertAt(t, pki, "alice", 0x20, days(2, 0), certKindClient)
	oAdmin.certScanAndNotify(context.Background())
	if len(m.texts()) != 3 {
		t.Errorf("%d messages after a new serial, want 3", len(m.texts()))
	}
}

func TestCertManyCertificatesAtOneThresholdAreSummarisedAndSplit(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	m := startTgMock(t)
	useTelegram(t, m)
	a := useAdminAudit(t, "")
	const n = 150
	long := strings.Repeat("x", 70)
	var names []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s-%03d", long, i)
		names = append(names, name)
		writeCertAt(t, pki, name, int64(0x100+i), days(10, time.Hour), certKindClient)
	}
	rep := oAdmin.certScanAndNotify(context.Background())
	if rep.Notices != n {
		t.Fatalf("%d notices, want %d", rep.Notices, n)
	}
	texts := m.texts()
	if len(texts) < 3 {
		t.Fatalf("%d messages for %d certificates, want the payload split", len(texts), n)
	}
	if !strings.Contains(strings.SplitN(texts[0], "\n", 2)[0], fmt.Sprintf("%d certificates cross the 14-day", n)) {
		t.Errorf("the first line is not the summary: %q", strings.SplitN(texts[0], "\n", 2)[0])
	}
	seen := map[string]int{}
	for i, text := range texts {
		if utf8.RuneCountInString(text) > telegramMaxText {
			t.Errorf("message %d has %d characters, more than %d", i, utf8.RuneCountInString(text), telegramMaxText)
		}
		if i > 0 && strings.Contains(strings.SplitN(text, "\n", 2)[0], "certificates cross") {
			t.Errorf("message %d repeats the summary", i)
		}
		for _, line := range strings.Split(text, "\n") {
			for _, name := range names {
				if strings.HasPrefix(line, name+" (client)") {
					seen[name]++
				}
			}
		}
	}
	for _, name := range names {
		if seen[name] != 1 {
			t.Errorf("%s is on %d lines, want exactly 1", name, seen[name])
		}
	}
	if got := countAudit(auditActions(t, a), "cert.notify"); got != len(texts) {
		t.Errorf("%d cert.notify lines for %d messages", got, len(texts))
	}
	// every certificate is marked: a second run is silent
	if rep := oAdmin.certScanAndNotify(context.Background()); rep.Sent != 0 {
		t.Errorf("second run sent %d messages", rep.Sent)
	}
}

func TestCertTenCertificatesAreSentOneByOneElevenAreSummarised(t *testing.T) {
	for _, tc := range []struct {
		count, wantMessages int
		summary             bool
	}{{10, 10, false}, {11, 1, true}} {
		t.Run(fmt.Sprint(tc.count), func(t *testing.T) {
			oAdmin, pki := setupScanPKI(t)
			m := startTgMock(t)
			useTelegram(t, m)
			for i := 0; i < tc.count; i++ {
				writeCertAt(t, pki, fmt.Sprintf("u%02d", i), int64(0x200+i), days(6, time.Hour), certKindClient)
			}
			oAdmin.certScanAndNotify(context.Background())
			texts := m.texts()
			if len(texts) != tc.wantMessages {
				t.Fatalf("%d messages, want %d", len(texts), tc.wantMessages)
			}
			if got := strings.Contains(texts[0], "certificates cross the 7-day"); got != tc.summary {
				t.Errorf("summary line present = %v, want %v:\n%s", got, tc.summary, texts[0])
			}
			if tc.summary {
				lines := strings.Split(texts[0], "\n")
				if !strings.HasPrefix(lines[1], "Client: Renew in the panel") {
					t.Errorf("the summary does not say what to do:\n%s", texts[0])
				}
				if got := strings.Count(texts[0], "(client): expires 2026-12-07, 6 days left"); got != tc.count {
					t.Errorf("%d certificate lines, want %d", got, tc.count)
				}
			}
		})
	}
}

func TestCertSummaryChunksStayUnderTheLimit(t *testing.T) {
	var notices []certNotice
	for i := 0; i < 400; i++ {
		notices = append(notices, certNotice{cert: certInfo{Name: fmt.Sprintf("name-%d-%s", i, strings.Repeat("é", 30)), Kind: certKindClient, NotAfter: days(3, 0)}, days: 3})
	}
	notices = append(notices, certNotice{cert: certInfo{Name: strings.Repeat("n", 5000), Kind: certKindServer, NotAfter: days(3, 0)}, days: 3})
	chunks := summaryChunks(7, notices, telegramMaxText)
	total := 0
	for i, c := range chunks {
		if n := utf8.RuneCountInString(c.text); n > telegramMaxText {
			t.Errorf("chunk %d has %d characters", i, n)
		}
		total += len(c.items)
	}
	if total != len(notices) {
		t.Errorf("the chunks hold %d notices, want %d", total, len(notices))
	}
}

func TestCertGaugesCountClientsServerAndCA(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	writeCertAt(t, pki, "a", 1, days(3, 0), certKindClient)      // 7d and 30d
	writeCertAt(t, pki, "b", 2, days(20, 0), certKindClient)     // 30d
	writeCertAt(t, pki, "c", 3, days(300, 0), certKindClient)    // neither
	writeCertAt(t, pki, "d", 4, days(-5, 0), certKindClient)     // expired counts as expiring
	writeCertAt(t, pki, "server", 5, days(6, 0), certKindServer) // 7d and 30d
	writeCertAt(t, pki, "ca", 6, days(25, 0), certKindCA)        // 30d

	reg := prometheus.NewRegistry()
	registerCertMetrics(reg)
	oAdmin.certScanAndNotify(context.Background())
	got := map[string]float64{}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		got[f.GetName()] = f.GetMetric()[0].GetGauge().GetValue()
	}
	if got["ovpn_certs_expiring_30d"] != 6-1 || got["ovpn_certs_expiring_7d"] != 3 {
		t.Errorf("gauges %v, want ovpn_certs_expiring_30d=5 (a b d server ca) and ovpn_certs_expiring_7d=3 (a d server)", got)
	}
}

func TestCertScanIgnoresRevokedCertificatesAndFilesOfAnOperation(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	writeCertAt(t, pki, "gone", 0x30, days(2, 0), certKindClient)
	writeCertAt(t, pki, "alice.renew-tmp", 0x31, days(2, 0), certKindClient)
	writeCertAt(t, pki, "alice.superseded-32", 0x32, days(2, 0), certKindClient)
	writeCertAt(t, pki, "alice", 0x33, days(100, 0), certKindClient)
	if err := os.WriteFile(filepath.Join(pki, "issued", "notes.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "issued", "broken.crt"), []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "index.txt"), []byte("R\t300101000000Z\t260101000000Z\t30\tunknown\t/CN=gone\nV\t300101000000Z\t\t33\tunknown\t/CN=alice\n"), 0644); err != nil {
		t.Fatal(err)
	}
	certs, err := oAdmin.scanCerts()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range certs {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "alice" {
		t.Errorf("scanned %v, want alice only", names)
	}
}

func TestCertLifecycleLoopScansAfterTheDelayAndEveryInterval(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	m := startTgMock(t)
	useTelegram(t, m)
	a := useAdminAudit(t, "")
	writeCertAt(t, pki, "alice", 0x10, days(2, 0), certKindClient)
	setFlag(t, &certScanFirstDelay, 700*time.Millisecond)
	setFlag(t, &certScanInterval, 150*time.Millisecond)
	setFlag(t, &certGraceInterval, time.Hour)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { oAdmin.certLifecycleLoop(stop); close(done) }()
	time.Sleep(200 * time.Millisecond)
	if n := countAudit(auditActions(t, a), "cert.scan"); n != 0 {
		t.Errorf("a scan ran before the first delay (%d)", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && countAudit(auditActions(t, a), "cert.scan") < 3 {
		time.Sleep(50 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the loop does not end when stop is closed")
	}
	if n := countAudit(auditActions(t, a), "cert.scan"); n < 3 {
		t.Errorf("%d scans, want the first one after the delay and then one per interval", n)
	}
	if len(m.texts()) != 1 {
		t.Errorf("%d messages over several scans, want exactly 1 (once per threshold)", len(m.texts()))
	}
}

func TestCertLifecycleLoopDefaults(t *testing.T) {
	if certScanFirstDelay != 5*time.Minute || certScanInterval != 24*time.Hour {
		t.Errorf("first scan after %v, then every %v; want 5m and 24h", certScanFirstDelay, certScanInterval)
	}
}

func TestCertLifecycleLoopDoesNothingOnASlave(t *testing.T) {
	oAdmin := certTestAdmin()
	oAdmin.role = "slave"
	done := make(chan struct{})
	go func() { oAdmin.certLifecycleLoop(nil); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop of a slave does not return")
	}
}

// ---------------------------------------------------------------------------------------------------------------
// GET /api/certs/expiry

func TestCertsExpiryAnswerShape(t *testing.T) {
	oAdmin, pki := setupScanPKI(t)
	asAdmin(t)
	writeCertAt(t, pki, "alice", 0x10, days(8, 23*time.Hour), certKindClient)
	writeCertAt(t, pki, "bob", 0x11, days(-1, -12*time.Hour), certKindClient)
	writeCertAt(t, pki, "server", 0x12, days(200, 0), certKindServer)
	writeCertAt(t, pki, "ca", 0x13, days(3000, 0), certKindCA)
	if err := saveRenewals(map[string]renewalEntry{"alice": {OldSerial: "0F", OldNotAfter: "2026-12-05T00:00:00Z", GraceEndsAt: "2026-12-04T00:00:00Z", NewSerial: "10"}}); err != nil {
		t.Fatal(err)
	}

	if rec := callHandler(oAdmin.certsExpiryHandler, httptest.NewRequest(http.MethodGet, "/api/certs/expiry", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("without the admin credentials: %d, want 403", rec.Code)
	}
	if rec := callHandler(oAdmin.certsExpiryHandler, adminReq(http.MethodPost, "/api/certs/expiry", url.Values{})); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", rec.Code)
	}
	rec := callHandler(oAdmin.certsExpiryHandler, adminReq(http.MethodGet, "/api/certs/expiry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	var answer struct {
		Certs          []map[string]any `json:"certs"`
		RestartPending *bool            `json:"restartPending"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.RestartPending == nil || *answer.RestartPending {
		t.Errorf("restartPending = %v, want false", answer.RestartPending)
	}
	if len(answer.Certs) != 4 {
		t.Fatalf("%d rows, want 4: %s", len(answer.Certs), rec.Body.String())
	}
	rows := map[string]map[string]any{}
	for _, r := range answer.Certs {
		var keys []string
		for k := range r {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "daysLeft,kind,name,notAfter,renewable,superseded" {
			t.Errorf("row keys %v", keys)
		}
		name := r["name"].(string)
		if rows[name] != nil {
			t.Errorf("%s has two rows", name)
		}
		rows[name] = r
		if _, err := time.Parse(time.RFC3339, r["notAfter"].(string)); err != nil {
			t.Errorf("notAfter %v is not RFC 3339", r["notAfter"])
		}
	}
	check := func(name, kind string, daysLeft float64, renewable, superseded bool) {
		t.Helper()
		r := rows[name]
		if r == nil {
			t.Errorf("no row for %s", name)
			return
		}
		if r["kind"] != kind || r["daysLeft"] != daysLeft || r["renewable"] != renewable || r["superseded"] != superseded {
			t.Errorf("%s: %v, want kind=%s daysLeft=%v renewable=%v superseded=%v", name, r, kind, daysLeft, renewable, superseded)
		}
	}
	check("alice", "client", 8, true, true)
	check("bob", "client", -2, true, false)
	check("server", "server", 200, true, false)
	check("ca", "ca", 3000, false, false)
	if rows["alice"]["notAfter"] != "2026-12-09T23:00:00Z" {
		t.Errorf("alice notAfter %v", rows["alice"]["notAfter"])
	}

	// the kubernetes backend renews nothing
	setFlag(t, storageBackend, "kubernetes.secrets")
	rec = callHandler(oAdmin.certsExpiryHandler, adminReq(http.MethodGet, "/api/certs/expiry", nil))
	var k8s struct {
		Certs []struct {
			Name      string `json:"name"`
			Renewable bool   `json:"renewable"`
		} `json:"certs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &k8s); err != nil || len(k8s.Certs) != 4 {
		t.Fatalf("kubernetes: %v: %s", err, rec.Body.String())
	}
	for _, c := range k8s.Certs {
		if c.Renewable {
			t.Errorf("%s is renewable on the kubernetes backend", c.Name)
		}
	}
}

func TestCertsExpiryWithoutAdminCredentialsConfiguredIsForbidden(t *testing.T) {
	oAdmin, _ := setupScanPKI(t)
	setFlag(t, basicUsername, "")
	setFlag(t, basicPassword, "")
	for name, h := range map[string]http.HandlerFunc{
		"expiry":         oAdmin.certsExpiryHandler,
		"server renew":   oAdmin.serverRenewHandler,
		"server confirm": oAdmin.serverConfirmRenewHandler,
	} {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if name == "expiry" {
			req = httptest.NewRequest(http.MethodGet, "/x", nil)
		}
		if rec := callHandler(h, req); rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------
// renewal, against a real easy-rsa

const wrapperScript = `#!/bin/sh
# runs the real easy-rsa; the switch files in the working directory make a command fail
for a in "$@"; do
  case "$a" in
    build-client-full|build-server-full)
      if [ -f .fake-fail-build ]; then echo "injected build failure" >&2; exit 1; fi
      if [ -f .fake-fail-build-after ]; then REAL "$@"; echo "injected failure after the build" >&2; exit 1; fi ;;
    revoke)
      if [ -f .fake-fail-revoke ]; then echo "injected revoke failure" >&2; exit 1; fi ;;
    gen-crl)
      if [ -f .fake-fail-crl ]; then echo "injected gen-crl failure" >&2; exit 1; fi
      if [ -f .fake-fail-crl-once ]; then rm -f .fake-fail-crl-once; echo "injected gen-crl failure" >&2; exit 1; fi ;;
  esac
done
exec REAL "$@"
`

func findEasyrsa(t *testing.T) string {
	t.Helper()
	for _, c := range []string{"easyrsa", "/usr/share/easy-rsa/easyrsa", "/usr/share/easy-rsa/3/easyrsa", "/usr/bin/easyrsa"} {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	t.Skip("no easy-rsa on this host: the renewal tests need a real one")
	return ""
}

// setupRealPKI builds a PKI with easy-rsa: the CA, the server certificate and one client "alice". algo is the
// key algorithm of easy-rsa ("ec" is quicker, "rsa" is what the panel's image uses).
func setupRealPKI(t *testing.T, algo string) (*OvpnAdmin, string) {
	t.Helper()
	realBin := findEasyrsa(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl on this host")
	}
	dir := t.TempDir()
	t.Setenv("EASYRSA_BATCH", "1")
	t.Setenv("EASYRSA_ALGO", algo)
	t.Setenv("EASYRSA_PKI", "")
	os.Unsetenv("EASYRSA_PKI")
	wrapper := filepath.Join(t.TempDir(), "easyrsa")
	if err := os.WriteFile(wrapper, []byte(strings.ReplaceAll(wrapperScript, "REAL", realBin)), 0755); err != nil {
		t.Fatal(err)
	}
	setFlag(t, easyrsaDirPath, dir)
	setFlag(t, easyrsaBinPath, wrapper)
	setFlag(t, indexTxtPath, filepath.Join(dir, "pki", "index.txt"))
	setFlag(t, storageBackend, "filesystem")
	setFlag(t, authByPassword, false)
	serverCertCache.Clear()
	t.Cleanup(serverCertCache.Clear)
	for _, args := range [][]string{
		{"--batch", "init-pki"},
		{"--batch", "--req-cn=testca", "build-ca", "nopass"},
		{"--batch", "build-server-full", "server", "nopass"},
		{"--batch", "build-client-full", "alice", "nopass"},
		{"--batch", "gen-crl"},
	} {
		if out, err := runCommand(dir, "", wrapper, args...); err != nil {
			t.Fatalf("easyrsa %v: %v\n%s", args, err, out)
		}
	}
	if err := crlFix(); err != nil {
		t.Fatal(err)
	}
	asAdmin(t)
	oAdmin := certTestAdmin()
	oAdmin.mgmtInterfaces = map[string]string{"srv": startFakeMgmt(t).addr}
	return oAdmin, dir
}

func mustRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	if out, err := runCommand(dir, "", *easyrsaBinPath, append([]string{"--batch"}, args...)...); err != nil {
		t.Fatalf("easyrsa %v: %v\n%s", args, err, out)
	}
}

func switchFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), nil, 0644); err != nil {
		t.Fatal(err)
	}
}

func certSerialOnDisk(t *testing.T, dir, rel string) string {
	t.Helper()
	c, err := readCertFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return serialHex(c)
}

func flagOfSerial(t *testing.T, serial string) string {
	t.Helper()
	lines, err := readIndexTxt()
	if err != nil {
		t.Fatal(err)
	}
	f, ok := indexFlagOf(lines, serial)
	if !ok {
		return "absent"
	}
	return f
}

// pkiState is what a failed renewal must leave as it was: index.txt, the files of the users, the directories
// of the operation, the state files, the list of revoked files.
func pkiState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	pki := filepath.Join(dir, "pki")
	err := filepath.WalkDir(pki, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(pki, p)
		switch {
		case rel == ".":
			return nil
		case strings.HasPrefix(rel, "crl.pem"), strings.HasPrefix(rel, "crl.der"), strings.HasPrefix(rel, "index.txt.attr"), strings.HasPrefix(rel, "index.txt.old"),
			strings.HasPrefix(rel, "serial"), strings.HasPrefix(rel, "safessl"), strings.HasPrefix(rel, "extensions"),
			strings.HasPrefix(rel, "openssl"), strings.HasPrefix(rel, "inline"), strings.HasPrefix(rel, "tmp"),
			strings.HasPrefix(rel, "cert-notify-state"), strings.HasPrefix(rel, "ecparams"), strings.HasPrefix(rel, "x509-types"):
			return nil
		}
		if d.IsDir() {
			return nil // an empty directory that easy-rsa or the renewal created is not state
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertPKIState(t *testing.T, before, after map[string]string) {
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
		t.Errorf("the PKI is not as before the failed operation:\n  %s", strings.Join(diffs, "\n  "))
	}
}

func renew(oAdmin *OvpnAdmin, user, grace string) *httptest.ResponseRecorder {
	form := url.Values{"username": {user}}
	if grace != "" {
		form.Set("grace_hours", grace)
	}
	return postForm(oAdmin.userRenewHandler, "/api/user/renew", form)
}

func identities(oAdmin *OvpnAdmin) []string {
	var out []string
	for _, u := range oAdmin.usersList() {
		out = append(out, u.Identity)
	}
	sort.Strings(out)
	return out
}

func TestRenewClientKeepsTheOldCertificateValidDuringTheGrace(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "rsa")
	a := useAdminAudit(t, "")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	oldCrt, _ := os.ReadFile(filepath.Join(dir, "pki/issued/alice.crt"))
	if err := saveCertNotifyStateFor(t, "client/alice", oldSerial, []int{30, 14}); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	rec := renew(oAdmin, "alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON(t, rec)
	msg, _ := body["message"].(string)
	if body["status"] != "ok" || len(body) != 2 {
		t.Errorf("answer %v, want {status, message}", body)
	}
	i := strings.Index(msg, "the old certificate stays valid until ")
	if i < 0 {
		t.Fatalf("message %q does not say until when the old certificate stays valid", msg)
	}
	untilText := strings.Fields(msg[i+len("the old certificate stays valid until "):])[0]
	until, err := time.Parse(time.RFC3339, strings.TrimRight(untilText, ".;,"))
	if err != nil {
		t.Fatalf("the end of the grace in %q is not RFC 3339: %v", msg, err)
	}
	if d := until.Sub(before.Add(72 * time.Hour)); d < -time.Minute || d > time.Minute {
		t.Errorf("the grace ends at %s, want 72 hours after the request", until)
	}

	newSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if newSerial == oldSerial {
		t.Fatal("the live certificate is still the old one")
	}
	if f := flagOfSerial(t, oldSerial); f != "V" {
		t.Errorf("the old certificate is %s in index.txt during its grace, want V", f)
	}
	if f := flagOfSerial(t, newSerial); f != "V" {
		t.Errorf("the new certificate is %s, want V", f)
	}
	if crlLists(t, oldSerial) || crlLists(t, newSerial) {
		t.Error("the CRL lists a certificate of a renewal with a grace")
	}
	kept, err := os.ReadFile(filepath.Join(dir, "pki", "superseded", "alice-"+normSerial(oldSerial), "alice.crt"))
	if err != nil || string(kept) != string(oldCrt) {
		t.Errorf("the old certificate is not kept in pki/superseded: %v", err)
	}
	if info, err := os.Stat(filepath.Join(dir, "pki/private/alice.key")); err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("the new key: %v %v, want mode 0600", info, err)
	}
	if info, err := os.Stat(filepath.Join(dir, "pki/renewals.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("renewals.json: %v %v, want mode 0600", info, err)
	}
	for _, leftover := range []string{"issued/alice.renew-tmp.crt", "private/alice.renew-tmp.key", "reqs/alice.renew-tmp.req"} {
		if fExist(filepath.Join(dir, "pki", leftover)) {
			t.Errorf("%s is left behind", leftover)
		}
	}
	if got := identities(oAdmin); strings.Join(got, ",") != "alice" {
		t.Errorf("the users are %v, want alice once: the superseded certificate is not a second user", got)
	}
	if _, ok := readNotifyState(t, filepath.Join(dir, "pki")).Certs["client/alice"]; ok {
		t.Error("the notified thresholds of alice were not reset by the renewal")
	}
	recs := auditActions(t, a)
	if countAudit(recs, "user.renew") != 1 {
		t.Errorf("audit: %d user.renew lines, want 1", countAudit(recs, "user.renew"))
	}

	// the expiry list: one row for alice, flagged as superseded
	rec = callHandler(oAdmin.certsExpiryHandler, adminReq(http.MethodGet, "/api/certs/expiry", nil))
	var list struct {
		Certs []struct {
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Superseded bool   `json:"superseded"`
			Renewable  bool   `json:"renewable"`
		} `json:"certs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, c := range list.Certs {
		counts[c.Name]++
		if c.Name == "alice" && (!c.Superseded || !c.Renewable || c.Kind != "client") {
			t.Errorf("alice row %+v", c)
		}
	}
	if counts["alice"] != 1 || counts["server"] != 1 || counts["ca"] != 1 || len(list.Certs) != 3 {
		t.Errorf("rows %v, want one each for alice, server and ca", counts)
	}
}

func saveCertNotifyStateFor(t *testing.T, key, serial string, fired []int) error {
	t.Helper()
	certNotifyMu.Lock()
	defer certNotifyMu.Unlock()
	return saveCertNotifyStateLocked(certNotifyState{Version: 1, Certs: map[string]*certNotifyEntry{key: {Serial: serial, Fired: fired}}})
}

func TestRenewClientWithNoGraceRevokesTheOldCertificateAtOnce(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	rec := renew(oAdmin, "alice", "0")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	if msg, _ := decodeJSON(t, rec)["message"].(string); !strings.Contains(msg, "the old certificate was revoked at once") || strings.Contains(msg, "stays valid") {
		t.Errorf("message %q", msg)
	}
	newSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if newSerial == oldSerial {
		t.Fatal("not renewed")
	}
	if f := flagOfSerial(t, oldSerial); f != "R" {
		t.Errorf("old certificate flag %s, want R", f)
	}
	if f := flagOfSerial(t, newSerial); f != "V" {
		t.Errorf("new certificate flag %s, want V", f)
	}
	if !crlLists(t, oldSerial) {
		t.Error("the CRL does not list the old certificate")
	}
	if crlLists(t, newSerial) {
		t.Error("the CRL lists the new certificate")
	}
	if fExist(filepath.Join(dir, "pki", "superseded", "alice-"+normSerial(oldSerial))) {
		t.Error("the superseded directory of a revoked certificate is still there")
	}
	if got := identities(oAdmin); strings.Join(got, ",") != "alice" {
		t.Errorf("users %v, want alice once", got)
	}
	if m, err := loadRenewals(); err != nil || len(m) != 0 {
		t.Errorf("renewals %v %v, want none", m, err)
	}
}

func TestRenewTwiceDuringTheGraceRevokesTheEarlierOneAtOnce(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	first := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rec := renew(oAdmin, "alice", "72"); rec.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rec.Code, rec.Body.String())
	}
	second := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	rec := renew(oAdmin, "alice", "24")
	if rec.Code != http.StatusOK {
		t.Fatalf("second: %d %s", rec.Code, rec.Body.String())
	}
	third := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	msg, _ := decodeJSON(t, rec)["message"].(string)
	if !strings.Contains(msg, "stays valid until") || !strings.Contains(msg, "earlier renewal") {
		t.Errorf("message %q does not state both facts", msg)
	}
	if f := flagOfSerial(t, first); f != "R" || !crlLists(t, first) {
		t.Errorf("the certificate of the first renewal: flag %s, in CRL %v; want revoked and listed", f, crlLists(t, first))
	}
	if f := flagOfSerial(t, second); f != "V" || crlLists(t, second) {
		t.Errorf("the superseded certificate: flag %s, in CRL %v; want valid", f, crlLists(t, second))
	}
	if f := flagOfSerial(t, third); f != "V" {
		t.Errorf("the live certificate: flag %s", f)
	}
	m, _ := loadRenewals()
	if normSerial(m["alice"].OldSerial) != normSerial(second) {
		t.Errorf("renewals.json holds %s, want the superseded serial %s", m["alice"].OldSerial, second)
	}
	if got := identities(oAdmin); strings.Join(got, ",") != "alice" {
		t.Errorf("users %v", got)
	}
}

func TestRenewInputErrorsAreBadRequests(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	before := pkiState(t, dir)
	for name, tc := range map[string]struct{ user, grace, want string }{
		"unknown user": {"nobody", "", "not found"},
		"empty user":   {"", "", "not found"},
		"path user":    {"../x", "", "not found"},
		"negative":     {"alice", "-1", "grace_hours"},
		"too long":     {"alice", "721", "grace_hours"},
		"text":         {"alice", "abc", "grace_hours"},
		"fraction":     {"alice", "1.5", "grace_hours"},
		"plus sign":    {"alice", "+5", "grace_hours"},
		"server name":  {"server", "", "not found"},
	} {
		rec := renew(oAdmin, tc.user, tc.grace)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: %d %s, want 400 mentioning %q", name, rec.Code, rec.Body.String(), tc.want)
		}
	}
	// the bounds are in
	assertPKIState(t, before, pkiState(t, dir)) // the refused requests changed nothing
	for _, g := range []string{"0", "720"} {
		if rec := renew(oAdmin, "alice", g); rec.Code != http.StatusOK {
			t.Errorf("grace_hours=%s: %d %s, want 200", g, rec.Code, rec.Body.String())
		}
	}
	if rec := callHandler(oAdmin.userRenewHandler, httptest.NewRequest(http.MethodGet, "/api/user/renew", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", rec.Code)
	}
}

func TestRenewOfARevokedUserIsRefusedAndChangesNothing(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	mustRun(t, dir, "revoke", "alice")
	mustRun(t, dir, "gen-crl")
	before := pkiState(t, dir)
	rec := renew(oAdmin, "alice", "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unrevoke or rotate first") {
		t.Fatalf("%d %s, want 400 with 'unrevoke or rotate first'", rec.Code, rec.Body.String())
	}
	assertPKIState(t, before, pkiState(t, dir))
}

func TestRenewOnTheKubernetesBackendIsRefused(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	before := pkiState(t, dir)
	setFlag(t, storageBackend, "kubernetes.secrets")
	rec := renew(oAdmin, "alice", "")
	want := "renewal is not supported on the kubernetes backend in this release; use rotate"
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
		t.Errorf("user renew: %d %s", rec.Code, rec.Body.String())
	}
	if rec := callHandler(oAdmin.serverRenewHandler, adminReq(http.MethodPost, "/api/server/renew", url.Values{})); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
		t.Errorf("server renew: %d %s", rec.Code, rec.Body.String())
	}
	if rec := callHandler(oAdmin.serverConfirmRenewHandler, adminReq(http.MethodPost, "/api/server/confirm-renew", url.Values{})); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
		t.Errorf("server confirm: %d %s", rec.Code, rec.Body.String())
	}
	assertPKIState(t, before, pkiState(t, dir))
}

// A failing step leaves the user with the old certificate, valid, exactly as before, and the answer says so.
func TestRenewFailuresLeaveTheOldCertificateLive(t *testing.T) {
	for _, tc := range []struct {
		name, grace, injection string
	}{
		{"easy-rsa cannot issue", "72", ".fake-fail-build"},
		{"easy-rsa fails after it signed", "72", ".fake-fail-build-after"},
		{"revoke fails with no grace", "0", ".fake-fail-revoke"},
		{"the CRL cannot be rebuilt with no grace", "0", ".fake-fail-crl-once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oAdmin, dir := setupRealPKI(t, "ec")
			oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
			before := pkiState(t, dir)
			switchFile(t, dir, tc.injection)
			rec := renew(oAdmin, "alice", tc.grace)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%d %s, want 500", rec.Code, rec.Body.String())
			}
			msg, _ := decodeJSON(t, rec)["message"].(string)
			if !strings.Contains(msg, "Failed to renew user") || !strings.Contains(msg, "old certificate (serial "+oldSerial+") is live and valid") {
				t.Errorf("message %q does not say what is live", msg)
			}
			if strings.Contains(msg, "successfully") || strings.Contains(msg, "renewed (") {
				t.Errorf("a failure that is worded like a success: %q", msg)
			}
			if got := certSerialOnDisk(t, dir, "pki/issued/alice.crt"); got != oldSerial {
				t.Errorf("the live certificate is %s, want the old %s", got, oldSerial)
			}
			if f := flagOfSerial(t, oldSerial); f != "V" {
				t.Errorf("the old certificate is %s in index.txt, want V", f)
			}
			if crlLists(t, oldSerial) {
				t.Error("the CRL lists the old certificate")
			}
			assertPKIState(t, before, pkiState(t, dir))
			if got := identities(oAdmin); strings.Join(got, ",") != "alice" {
				t.Errorf("users %v", got)
			}
			// and the renewal works once the cause is gone
			if err := os.Remove(filepath.Join(dir, tc.injection)); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if rec := renew(oAdmin, "alice", tc.grace); rec.Code != http.StatusOK {
				t.Errorf("the retry: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestRenewalGraceEndRevokesTheOldCertificateOnce(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	a := useAdminAudit(t, "")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rec := renew(oAdmin, "alice", "72"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	newSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")

	setCertClock(t, time.Now().Add(time.Hour))
	if n := oAdmin.renewalGraceTick(); n != 0 || flagOfSerial(t, oldSerial) != "V" {
		t.Fatalf("a tick before the end of the grace revoked %d (flag %s)", n, flagOfSerial(t, oldSerial))
	}
	moveCertClock(time.Now().Add(73 * time.Hour))
	if n := oAdmin.renewalGraceTick(); n != 1 {
		t.Fatalf("the tick after the grace revoked %d, want 1", n)
	}
	if f := flagOfSerial(t, oldSerial); f != "R" || !crlLists(t, oldSerial) {
		t.Errorf("old certificate: flag %s, in CRL %v; want revoked and listed", f, crlLists(t, oldSerial))
	}
	if f := flagOfSerial(t, newSerial); f != "V" || crlLists(t, newSerial) {
		t.Errorf("new certificate: flag %s", f)
	}
	if fExist(filepath.Join(dir, "pki", "superseded", "alice-"+normSerial(oldSerial))) {
		t.Error("the superseded directory is still there")
	}
	if m, _ := loadRenewals(); len(m) != 0 {
		t.Errorf("renewals.json still lists %v", m)
	}
	if got := identities(oAdmin); strings.Join(got, ",") != "alice" {
		t.Errorf("users %v, want alice once and valid", got)
	}
	// the old line has a retired name, so the name belongs to the live certificate alone
	lines, _ := readIndexTxt()
	for _, l := range lines {
		if normSerial(l.SerialNumber) == normSerial(oldSerial) && l.DistinguishedName == "/CN=alice" {
			t.Errorf("the revoked line still carries the name of the user")
		}
	}
	if n := oAdmin.renewalGraceTick(); n != 0 {
		t.Errorf("a second tick revoked %d", n)
	}
	recs := auditActions(t, a)
	if countAudit(recs, "cert.auto_revoke") != 1 {
		t.Errorf("%d cert.auto_revoke lines, want 1", countAudit(recs, "cert.auto_revoke"))
	}
}

// The old certificate is the only one that works while the replacement is not the live file: nothing is revoked.
func TestRenewalGraceEndNeverRevokesWhenTheReplacementIsNotLive(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	a := useAdminAudit(t, "")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rec := renew(oAdmin, "alice", "1"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if err := os.Remove(filepath.Join(dir, "pki/issued/alice.crt")); err != nil {
		t.Fatal(err)
	}
	setCertClock(t, time.Now().Add(5*time.Hour))
	if n := oAdmin.renewalGraceTick(); n != 0 {
		t.Fatalf("the tick revoked %d", n)
	}
	if f := flagOfSerial(t, oldSerial); f != "V" {
		t.Errorf("the old certificate is %s, want V", f)
	}
	var failed bool
	for _, r := range auditActions(t, a) {
		if r.Action == "cert.auto_revoke" && r.Result == adminAuditResultFail {
			failed = true
		}
	}
	if !failed {
		t.Error("the refusal is not in the audit trail")
	}
}

func TestRenewalGraceEndAfterAnAdminRevokeOnlyPublishesTheCrl(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rec := renew(oAdmin, "alice", "1"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// a crash between index.txt and the CRL: the old certificate is revoked in the index, not in the CRL
	if err := revokeSupersededIndexLocked(nil, "alice", mustRenewal(t, "alice")); err != nil {
		t.Fatal(err)
	}
	if crlLists(t, oldSerial) {
		t.Fatal("the test needs a CRL without the serial")
	}
	setCertClock(t, time.Now().Add(5*time.Hour))
	oAdmin.renewalGraceTick()
	if !crlLists(t, oldSerial) {
		t.Error("the tick did not repair the CRL")
	}
}

func mustRenewal(t *testing.T, name string) renewalEntry {
	t.Helper()
	m, err := loadRenewals()
	if err != nil || m[name].OldSerial == "" {
		t.Fatalf("renewals.json: %v %v", m, err)
	}
	return m[name]
}

func TestRevokeOfAUserInGraceRevokesBothCertificates(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rec := renew(oAdmin, "alice", "72"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	newSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if err, msg := oAdmin.userRevoke("alice"); err != nil {
		t.Fatalf("revoke: %v %s", err, msg)
	}
	for _, s := range []string{oldSerial, newSerial} {
		if f := flagOfSerial(t, s); f != "R" || !crlLists(t, s) {
			t.Errorf("serial %s: flag %s, in CRL %v; want revoked and listed", s, f, crlLists(t, s))
		}
	}
	if m, _ := loadRenewals(); len(m) != 0 {
		t.Errorf("renewals.json still lists %v", m)
	}
	if fExist(filepath.Join(dir, "pki", "superseded", "alice-"+normSerial(oldSerial))) {
		t.Error("the superseded directory is still there")
	}
}

func TestRotateOfAUserInGraceRevokesTheSupersededCertificate(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rec := renew(oAdmin, "alice", "72"); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	liveSerial := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if err, msg := oAdmin.userRotate("alice", ""); err != nil {
		t.Fatalf("rotate: %v %s", err, msg)
	}
	rotated := certSerialOnDisk(t, dir, "pki/issued/alice.crt")
	if rotated == liveSerial || rotated == oldSerial {
		t.Fatalf("rotate kept serial %s", rotated)
	}
	for _, s := range []string{oldSerial, liveSerial} {
		if f := flagOfSerial(t, s); f != "R" || !crlLists(t, s) {
			t.Errorf("serial %s: flag %s, in CRL %v; want revoked and listed", s, f, crlLists(t, s))
		}
	}
	if f := flagOfSerial(t, rotated); f != "V" {
		t.Errorf("the rotated certificate is %s", f)
	}
	if got := identities(oAdmin); strings.Join(got, ",") != "alice" {
		t.Errorf("users %v", got)
	}
}

func TestRenewHandlerRecordsTheAudit(t *testing.T) {
	oAdmin, _ := setupRealPKI(t, "ec")
	a := useAdminAudit(t, "")
	renew(oAdmin, "alice", "72")
	renew(oAdmin, "alice", "x")
	renew(oAdmin, "nobody", "")
	var ok, failed int
	for _, r := range auditActions(t, a) {
		if r.Action != "user.renew" {
			continue
		}
		if r.Result == adminAuditResultOK {
			ok++
		} else {
			failed++
		}
	}
	if ok != 1 || failed != 2 {
		t.Errorf("user.renew lines: %d ok, %d failed, want 1 and 2", ok, failed)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// server certificate

func serverRenewReq(oAdmin *OvpnAdmin) *httptest.ResponseRecorder {
	return callHandler(oAdmin.serverRenewHandler, adminReq(http.MethodPost, "/api/server/renew", url.Values{}))
}

func serverConfirmReq(oAdmin *OvpnAdmin) *httptest.ResponseRecorder {
	return callHandler(oAdmin.serverConfirmRenewHandler, adminReq(http.MethodPost, "/api/server/confirm-renew", url.Values{}))
}

func TestServerRenewThenConfirm(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	a := useAdminAudit(t, "")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/server.crt")
	oldCrt, _ := os.ReadFile(filepath.Join(dir, "pki/issued/server.crt"))

	if rec := callHandler(oAdmin.serverRenewHandler, httptest.NewRequest(http.MethodPost, "/api/server/renew", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("without credentials: %d, want 403", rec.Code)
	}
	if rec := callHandler(oAdmin.serverConfirmRenewHandler, httptest.NewRequest(http.MethodPost, "/api/server/confirm-renew", nil)); rec.Code != http.StatusForbidden {
		t.Errorf("confirm without credentials: %d, want 403", rec.Code)
	}
	if rec := serverConfirmReq(oAdmin); rec.Code != http.StatusBadRequest {
		t.Errorf("confirm with nothing pending: %d %s, want 400", rec.Code, rec.Body.String())
	}

	rec := serverRenewReq(oAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", rec.Code, rec.Body.String())
	}
	body := decodeJSON(t, rec)
	if body["status"] != "ok" || body["restartRequired"] != true || body["message"] == "" || len(body) != 3 {
		t.Errorf("answer %v, want {status ok, restartRequired true, message}", body)
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "OpenVPN still serves the previous certificate") {
		t.Errorf("the message does not say what OpenVPN serves: %q", msg)
	}
	newSerial := certSerialOnDisk(t, dir, "pki/issued/server.crt")
	if newSerial == oldSerial {
		t.Fatal("server.crt is the old certificate")
	}
	if f := flagOfSerial(t, oldSerial); f != "V" {
		t.Errorf("the previous server certificate is %s before the confirm, want V (OpenVPN still serves it)", f)
	}
	if info, err := os.Stat(filepath.Join(dir, "pki/private/server.key")); err != nil || info.Mode().Perm() != 0600 {
		t.Errorf("server.key: %v %v", info, err)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "pki", "server-backup-*"))
	if len(backups) != 1 {
		t.Fatalf("backups %v, want 1", backups)
	}
	if kept, err := os.ReadFile(filepath.Join(backups[0], "server.crt")); err != nil || string(kept) != string(oldCrt) {
		t.Errorf("the previous server certificate is not in the backup: %v", err)
	}
	if info, err := os.Stat(backups[0]); err != nil || info.Mode().Perm() != 0700 {
		t.Errorf("backup directory %v %v, want 0700", info, err)
	}

	// pending: shown, renewable false, and a second renew is a 400
	rec = callHandler(oAdmin.certsExpiryHandler, adminReq(http.MethodGet, "/api/certs/expiry", nil))
	var list struct {
		Certs []struct {
			Name      string `json:"name"`
			Renewable bool   `json:"renewable"`
		} `json:"certs"`
		RestartPending bool `json:"restartPending"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || !list.RestartPending {
		t.Fatalf("expiry: %v %s", err, rec.Body.String())
	}
	for _, c := range list.Certs {
		if c.Name == "server" && c.Renewable {
			t.Error("the server certificate is renewable while its restart is pending")
		}
	}
	if rec := serverRenewReq(oAdmin); rec.Code != http.StatusBadRequest {
		t.Errorf("a second renew: %d %s, want 400", rec.Code, rec.Body.String())
	}

	rec = serverConfirmReq(oAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body.String())
	}
	if body := decodeJSON(t, rec); len(body) != 1 || body["status"] != "ok" {
		t.Errorf("confirm answer %v, want {status ok}", body)
	}
	if f := flagOfSerial(t, oldSerial); f != "R" || !crlLists(t, oldSerial) {
		t.Errorf("after the confirm the previous certificate is %s, in CRL %v; want revoked and listed", f, crlLists(t, oldSerial))
	}
	if f := flagOfSerial(t, newSerial); f != "V" || crlLists(t, newSerial) {
		t.Errorf("the new server certificate: %s", f)
	}
	if rec := serverConfirmReq(oAdmin); rec.Code != http.StatusBadRequest {
		t.Errorf("a second confirm: %d, want 400", rec.Code)
	}
	st, _ := loadServerRenewal()
	if st.RestartPending {
		t.Error("restartPending is still true")
	}
	// renew: the ok line and the refused second one; confirm: the refused first, the ok one and the refused repeat
	recs := auditActions(t, a)
	if got := countAudit(recs, "server.renew"); got != 2 {
		t.Errorf("%d server.renew lines, want 2", got)
	}
	if got := countAudit(recs, "server.renew.confirm"); got != 3 {
		t.Errorf("%d server.renew.confirm lines, want 3", got)
	}
}

func TestServerRenewFailureChangesNothing(t *testing.T) {
	for _, injection := range []string{".fake-fail-build", ".fake-fail-build-after"} {
		t.Run(injection, func(t *testing.T) {
			oAdmin, dir := setupRealPKI(t, "ec")
			oldSerial := certSerialOnDisk(t, dir, "pki/issued/server.crt")
			before := pkiState(t, dir)
			switchFile(t, dir, injection)
			rec := serverRenewReq(oAdmin)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%d %s, want 500", rec.Code, rec.Body.String())
			}
			msg, _ := decodeJSON(t, rec)["message"].(string)
			if !strings.Contains(msg, "Nothing changed") || !strings.Contains(msg, oldSerial) {
				t.Errorf("message %q does not say what is live", msg)
			}
			assertPKIState(t, before, pkiState(t, dir))
			if st, _ := loadServerRenewal(); st.RestartPending {
				t.Error("a restart is pending after a failed renewal")
			}
		})
	}
}

func TestServerConfirmFailureKeepsThePreviousCertificateAndCanBeRepeated(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/server.crt")
	if rec := serverRenewReq(oAdmin); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	before := pkiState(t, dir)
	switchFile(t, dir, ".fake-fail-crl-once")
	rec := serverConfirmReq(oAdmin)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("%d %s, want 500", rec.Code, rec.Body.String())
	}
	if msg, _ := decodeJSON(t, rec)["message"].(string); !strings.Contains(msg, "NOT revoked") || !strings.Contains(msg, "restartPending stays true") {
		t.Errorf("message %q", msg)
	}
	if f := flagOfSerial(t, oldSerial); f != "V" || crlLists(t, oldSerial) {
		t.Errorf("the previous certificate is %s, in CRL %v; want valid", f, crlLists(t, oldSerial))
	}
	assertPKIState(t, before, pkiState(t, dir))
	if st, _ := loadServerRenewal(); !st.RestartPending {
		t.Error("restartPending was cleared by a failed confirm")
	}
	if rec := serverConfirmReq(oAdmin); rec.Code != http.StatusOK {
		t.Fatalf("the repeat: %d %s", rec.Code, rec.Body.String())
	}
	if f := flagOfSerial(t, oldSerial); f != "R" || !crlLists(t, oldSerial) {
		t.Errorf("after the repeat: %s, in CRL %v", f, crlLists(t, oldSerial))
	}
}

func TestServerRenewResetsItsNotifiedThresholds(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	oldSerial := certSerialOnDisk(t, dir, "pki/issued/server.crt")
	if err := saveCertNotifyStateFor(t, "server/server", oldSerial, []int{30, 14, 7}); err != nil {
		t.Fatal(err)
	}
	if rec := serverRenewReq(oAdmin); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if _, ok := readNotifyState(t, filepath.Join(dir, "pki")).Certs["server/server"]; ok {
		t.Error("the thresholds of the server certificate were not reset")
	}
}

// With the real certificates of a real PKI the scan finds the CA, the server and the clients, and a
// pending server renewal is announced as a reminder at every run.
func TestScanOfARealPKIAndTheReminderOfAPendingRestart(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	m := startTgMock(t)
	useTelegram(t, m)
	certs, err := oAdmin.scanCerts()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, c := range certs {
		kinds[c.Name] = c.Kind
	}
	if kinds["alice"] != "client" || kinds["server"] != "server" || kinds["ca"] != "ca" || len(kinds) != 3 {
		t.Fatalf("scanned %v", kinds)
	}
	if rec := serverRenewReq(oAdmin); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	_ = dir
	oAdmin.certScanAndNotify(context.Background())
	oAdmin.certScanAndNotify(context.Background())
	texts := m.texts()
	if len(texts) != 2 || !strings.Contains(texts[0], "renewal is pending") || !strings.Contains(texts[0], "Restart the openvpn container") {
		t.Errorf("messages %q, want one reminder per run", texts)
	}
}

// A serial with a leading zero: the files of easy-rsa under pki/revoked keep it. A rollback that removed the
// name without it would leave them, and the repeat of the revoke would be refused (found by a random serial).
func TestRevokedFilesOfKeepTheLeadingZeroOfTheSerial(t *testing.T) {
	setFlag(t, easyrsaDirPath, "/pki-root")
	got := revokedFilesOf("0990098AEAC07245158444C435372AA4")
	want := []string{
		"/pki-root/pki/revoked/certs_by_serial/0990098AEAC07245158444C435372AA4.crt",
		"/pki-root/pki/revoked/private_by_serial/0990098AEAC07245158444C435372AA4.key",
		"/pki-root/pki/revoked/reqs_by_serial/0990098AEAC07245158444C435372AA4.req",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("revokedFilesOf = %v, want %v", got, want)
	}
	if got := revokedFilesOf("990098AEAC07245158444C435372AA4")[0]; !strings.HasSuffix(got, "/0990098AEAC07245158444C435372AA4.crt") {
		t.Errorf("an odd-length serial from index.txt is not padded: %s", got)
	}
}
