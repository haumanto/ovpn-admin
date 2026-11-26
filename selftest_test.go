package main

// Tests of the self-test (selftest.go). They run on a fixture directory (a PKI of generated certificates, a real admin audit
// trail written by the panel's own code, a ban list, an OpenVPN log) and on stub commands: no test touches the firewall of the
// host, starts a container or needs easy-rsa. The one test that runs real processes uses shell scripts of its own as the
// "iptables" binary.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

var stNow = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)

const (
	stFenceCmd4 = "iptables -C INPUT -i tun+ -p tcp --dport 8080 -j DROP"
	stFenceCmd6 = "ip6tables -C INPUT -i tun+ -p tcp --dport 8080 -j DROP"
	stKeyBody   = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-PRIVATE-KEY-BODY"
)

// ---------------------------------------------------------------------------------------------------------------
// stub commands

// stTools stands in for iptables, ip6tables, sqlite3, openvpn, easyrsa and apk. It remembers every command line.
type stTools struct {
	mu      sync.Mutex
	calls   []string
	fence4  bool
	fence6  bool
	chain4  bool
	jump4   bool
	chain6  bool
	jump6   bool
	denied  bool            // "Permission denied (you must be root)", exit 4, like iptables without CAP_NET_ADMIN
	missing map[string]bool // binaries that are not installed
	// sqlite3
	sqliteCode int
	sqliteOut  string
	// versions
	openvpnOut string
	easyrsaOut string
	apkOut     string
}

func newStTools() *stTools {
	return &stTools{
		fence4: true, fence6: true, chain4: true, jump4: true, chain6: true, jump6: true,
		missing:    map[string]bool{},
		sqliteOut:  "3\n",
		openvpnOut: "OpenVPN 2.7.9 x86_64-alpine-linux-musl [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]\nbuilt on Oct 1 2026\n",
		easyrsaOut: "EasyRSA Version Information\nVersion:     ~VER~\nGenerated:   ~DATE~\nSSL Lib:     OpenSSL 3.5.9\nGit Commit:  ~GITHEAD~\n",
		apkOut:     "easy-rsa-3.2.5-r0 x86_64 {easy-rsa} (GPL-2.0-only) [installed]\n",
	}
}

func (f *stTools) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

func (f *stTools) ran(cmd string) bool {
	for _, c := range f.called() {
		if c == cmd {
			return true
		}
	}
	return false
}

func (f *stTools) run(_ context.Context, name string, args ...string) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(append([]string{name}, args...), " "))
	if f.missing[name] {
		return "", -1, &exec.Error{Name: name, Err: exec.ErrNotFound}
	}
	switch name {
	case "iptables", "ip6tables":
		v6 := name == "ip6tables"
		if f.denied {
			return name + ": Could not fetch rule set generation id: Permission denied (you must be root)\n", 4, nil
		}
		fence, chain, jump, cname := f.fence4, f.chain4, f.jump4, "OVPN_BAN"
		if v6 {
			fence, chain, jump, cname = f.fence6, f.chain6, f.jump6, "OVPN_BAN6"
		}
		switch args[0] {
		case "-C":
			if strings.Join(args, " ") == "-C INPUT -i tun+ -p tcp --dport 8080 -j DROP" && fence {
				return "", 0, nil
			}
			return name + ": Bad rule (does a matching rule exist in that chain?).\n", 1, nil
		case "-S":
			var b strings.Builder
			b.WriteString("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n")
			if chain {
				b.WriteString("-N " + cname + "\n")
			}
			b.WriteString("-N OTHER\n-A OTHER -j " + cname + "\n-A INPUT -j " + cname + "_SPARE\n")
			if jump {
				b.WriteString("-A INPUT -p tcp -m tcp --dport 1194 -j " + cname + "\n")
			}
			if fence {
				b.WriteString("-A INPUT -i tun+ -p tcp -m tcp --dport 8080 -j DROP\n")
			}
			return b.String(), 0, nil
		}
	case "sqlite3":
		return f.sqliteOut, f.sqliteCode, nil
	case "openvpn":
		return f.openvpnOut, 0, nil
	case "easyrsa":
		return f.easyrsaOut, 0, nil
	case "apk":
		return f.apkOut, 0, nil
	}
	return "unexpected command\n", 127, nil
}

// ---------------------------------------------------------------------------------------------------------------
// the fixture

type stFixture struct {
	t        *testing.T
	root     string
	pki      string
	state    string
	trail    string
	tools    *stTools
	ownerUID int
}

func stWriteCert(t *testing.T, pki, name string, serial int64, notAfter time.Time, kind string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notAfter.Add(-3 * 365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	path := filepath.Join(pki, "issued", name+".crt")
	switch kind {
	case certKindCA:
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
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
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stWriteCRL(t *testing.T, pki string, nextUpdate time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: stNow.Add(-24 * time.Hour), NotAfter: stNow.Add(3650 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: nextUpdate.Add(-180 * 24 * time.Hour), NextUpdate: nextUpdate,
	}, caCert, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pki, "crl.pem"), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// newStFixture builds a healthy box: every check passes (and none is a WARN).
func newStFixture(t *testing.T) *stFixture {
	t.Helper()
	asAdmin(t)
	root := t.TempDir()
	f := &stFixture{t: t, root: root, pki: filepath.Join(root, "pki"), state: filepath.Join(root, "state"), tools: newStTools(), ownerUID: os.Getuid()}
	f.trail = filepath.Join(f.state, "audit", "admin-audit.log")
	for _, d := range []string{filepath.Join(f.pki, "issued"), filepath.Join(f.pki, "private"), filepath.Join(f.state, "audit")} {
		stMust(t, os.MkdirAll(d, 0o700))
	}
	day := 24 * time.Hour
	stWriteCert(t, f.pki, "ca", 1, stNow.Add(3650*day), certKindCA)
	stWriteCert(t, f.pki, "server", 2, stNow.Add(700*day), certKindServer)
	stWriteCert(t, f.pki, "alice", 3, stNow.Add(300*day), certKindClient)
	stWriteCert(t, f.pki, "bob", 4, stNow.Add(200*day), certKindClient)
	stWriteCRL(t, f.pki, stNow.Add(150*day))
	index := "V\t351231235959Z\t\t02\tunknown\t/CN=server\nV\t351231235959Z\t\t03\tunknown\t/CN=alice\nV\t351231235959Z\t\t04\tunknown\t/CN=bob\n"
	stMust(t, os.WriteFile(filepath.Join(f.pki, "index.txt"), []byte(index), 0o600))
	key := "-----BEGIN PRIVATE KEY-----\n" + stKeyBody + "\n-----END PRIVATE KEY-----\n"
	stMust(t, os.WriteFile(filepath.Join(f.pki, "private", "ca.key"), []byte(key), 0o600))
	stMust(t, os.WriteFile(filepath.Join(f.pki, "private", "server.key"), []byte(key), 0o600))
	stMust(t, os.WriteFile(filepath.Join(f.pki, "users.db"), append([]byte(sqliteMagic), make([]byte, 84)...), 0o640))
	// a ban list with one permanent ban, written now
	stMust(t, os.WriteFile(filepath.Join(f.state, "bans.tsv"), []byte(fmt.Sprintf("203.0.113.9\t%d\t0\t3\tauth-failed\n", stNow.Unix())), 0o600))
	stMust(t, os.Chtimes(filepath.Join(f.state, "bans.tsv"), stNow.Add(-2*time.Hour), stNow.Add(-2*time.Hour)))
	f.writeLog("2026-11-30 10:00:00 tcp6-server:[2001:db8::7]:5555 TLS: Initial packet from [AF_INET6]\n" +
		"2026-11-30 10:00:01 tcp6-server:[2001:db8::7]:5555 Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384, peer certificate: 256 bits EC, signature: ecdsa-with-SHA256, peer temporary key: 253 bits X25519\n")
	f.writeTrail(5)

	setFlag(t, easyrsaDirPath, root)
	setFlag(t, indexTxtPath, filepath.Join(f.pki, "index.txt"))
	setFlag(t, authDatabase, filepath.Join(f.pki, "users.db"))
	setFlag(t, authByPassword, true)
	setFlag(t, listenPort, "8080")
	setFlag(t, stateDir, f.state)
	setFlag(t, adminAuditFileFlag, f.trail)
	setFlag(t, insecureNoAuth, false)
	setFlag(t, masterSyncToken, "")
	setFlag(t, masterAllowInsecureHTTP, false)
	setFlag(t, storageBackend, "filesystem")
	setFlag(t, serverRole, "master")
	setFlag(t, selfTestOpenvpnLog, "")
	setFlag(t, selfTestIptablesBin, "iptables")
	setFlag(t, selfTestIp6tablesBin, "ip6tables")
	setFlag(t, easyrsaBinPath, "easyrsa")
	setFlag(t, mgmtAddress, []string{})
	setNetworks(t, "192.168.100.0/24", "fd00:192:168:100::/64")
	t.Setenv("OVPN_BAN_ENABLED", "")
	clearTelegram(t)
	return f
}

func (f *stFixture) writeLog(content string) {
	f.t.Helper()
	stMust(f.t, os.WriteFile(filepath.Join(f.state, "openvpn.log"), []byte(content), 0o600))
}

// writeTrail writes n records with the panel's own code (hash chain, checkpoint) and closes the trail.
func (f *stFixture) writeTrail(n int) {
	f.t.Helper()
	a, err := openAdminAuditLog(f.trail, "")
	stMust(f.t, err)
	for i := 0; i < n; i++ {
		_, err := a.Record("operator", "user.create", fmt.Sprintf("user%d", i), "127.0.0.1", adminAuditResultOK, "created")
		stMust(f.t, err)
	}
	a.Close()
}

// st is the self-test of the fixture: stub commands, the clock at stNow, no mgmt answer.
func (f *stFixture) st() *selfTest {
	return &selfTest{
		now:         func() time.Time { return stNow },
		run:         f.tools.run,
		ownerUID:    f.ownerUID,
		scanCerts:   scanCertsLocked,
		mgmtVersion: func() string { return "" },
		appVersion:  func() string { return "0.1.12" },
		sleep:       func(time.Duration) {},
	}
}

func (f *stFixture) report() selfTestReport { return f.st().Run() }

func (r selfTestReport) get(t *testing.T, name string) selfTestCheck {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", name, r.Checks)
	return selfTestCheck{}
}

func (r selfTestReport) statuses() map[string]string {
	m := map[string]string{}
	for _, c := range r.Checks {
		m[c.Name] = c.Status
	}
	return m
}

func expectStatus(t *testing.T, r selfTestReport, name, want string, detail ...string) selfTestCheck {
	t.Helper()
	c := r.get(t, name)
	if c.Status != want {
		t.Fatalf("%s: status %s, want %s: %s", name, c.Status, want, c.Detail)
	}
	for _, d := range detail {
		if !strings.Contains(c.Detail, d) {
			t.Fatalf("%s: detail %q does not contain %q", name, c.Detail, d)
		}
	}
	return c
}

func useSelfTest(t *testing.T, s *selfTest) {
	t.Helper()
	old := newSelfTestFor
	newSelfTestFor = func(*OvpnAdmin) *selfTest { return s }
	t.Cleanup(func() { newSelfTestFor = old })
}

var allChecks = []string{"admin_fence", "ban_jail", "crl_age", "cert_expiry", "key_modes", "credentials", "control_channel", "audit_chain", "sync", "versions", "pki_readable"}

// ---------------------------------------------------------------------------------------------------------------
// the report as a whole

func TestSelfTestHealthyFixtureIsAllPass(t *testing.T) {
	f := newStFixture(t)
	r := f.report()
	var names []string
	for _, c := range r.Checks {
		names = append(names, c.Name)
		if c.Status != selfTestPass {
			t.Errorf("%s: %s: %s", c.Name, c.Status, c.Detail)
		}
		if c.Detail == "" {
			t.Errorf("%s has no detail", c.Name)
		}
	}
	if strings.Join(names, ",") != strings.Join(allChecks, ",") {
		t.Fatalf("checks and their order: %v", names)
	}
	if r.Verdict != selfTestPass || selfTestExitCode(r) != 0 {
		t.Fatalf("verdict %s, exit %d", r.Verdict, selfTestExitCode(r))
	}
	if pass, warn, fail := r.counts(); pass != 11 || warn != 0 || fail != 0 {
		t.Fatalf("counts %d/%d/%d", pass, warn, fail)
	}
	if _, err := time.Parse(time.RFC3339, r.GeneratedAt); err != nil {
		t.Fatalf("generatedAt %q: %v", r.GeneratedAt, err)
	}
	// the firewall is asked exactly as the contract says, for both families (IPv6 is on in the fixture)
	for _, want := range []string{stFenceCmd4, stFenceCmd6, "iptables -S", "ip6tables -S"} {
		if !f.tools.ran(want) {
			t.Errorf("command %q was not run; ran %q", want, f.tools.called())
		}
	}
}

func TestSelfTestCLIOutputIsAlignedWithAVerdict(t *testing.T) {
	f := newStFixture(t)
	var out bytes.Buffer
	if code := runSelfTestCLI(&out, f.st()); code != 0 {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1+11+1 {
		t.Fatalf("%d lines:\n%s", len(lines), out.String())
	}
	if !strings.HasPrefix(lines[0], "ovpn-admin ") || !strings.Contains(lines[0], "self-test") {
		t.Fatalf("header: %q", lines[0])
	}
	// "control_channel" is the widest name (15): the status column starts at the same offset on every line
	for i, name := range allChecks {
		line := lines[1+i]
		if !strings.HasPrefix(line, name) || line[15:17] != "  " || line[17:21] != "PASS" || line[21:23] != "  " || len(line) <= 23 {
			t.Errorf("line %d is not aligned: %q", i, line)
		}
	}
	if lines[len(lines)-1] != "verdict: PASS (11 PASS, 0 WARN, 0 FAIL)" {
		t.Fatalf("verdict line: %q", lines[len(lines)-1])
	}
}

func TestSelfTestExitCodes(t *testing.T) {
	f := newStFixture(t)
	var out bytes.Buffer
	// WARN is allowed: 0
	f.tools.denied = true
	if code := runSelfTestCLI(&out, f.st()); code != 0 || !strings.Contains(out.String(), "WARN") || strings.Contains(out.String(), "FAIL ") {
		t.Fatalf("only WARN: exit %d\n%s", code, out.String())
	}
	// a FAIL: 1
	f = newStFixture(t)
	f.tools.fence4 = false
	out.Reset()
	if code := runSelfTestCLI(&out, f.st()); code != 1 || !strings.Contains(out.String(), "verdict: FAIL") {
		t.Fatalf("a FAIL: exit %d\n%s", code, out.String())
	}
	// an internal error (a check that panics): 2, and the other checks still ran
	f = newStFixture(t)
	old := selfTestRegistry
	selfTestRegistry = func() []selfTestEntry {
		return append([]selfTestEntry{{"boom", func(*selfTest) (string, string) { panic("kaboom") }}}, old()...)
	}
	t.Cleanup(func() { selfTestRegistry = old })
	out.Reset()
	if code := runSelfTestCLI(&out, f.st()); code != 2 {
		t.Fatalf("internal error: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "boom") || !strings.Contains(out.String(), "internal error") || !strings.Contains(out.String(), "pki_readable     PASS") {
		t.Fatalf("the panic must show and the rest must run:\n%s", out.String())
	}
}

// ---------------------------------------------------------------------------------------------------------------
// admin_fence

func TestSelfTestFenceRemovedIsFail(t *testing.T) {
	f := newStFixture(t)
	f.tools.fence4 = false
	r := f.report()
	expectStatus(t, r, "admin_fence", selfTestFail, "iptables", "tun+", "8080")
	if r.Verdict != selfTestFail || selfTestExitCode(r) != 1 {
		t.Fatalf("verdict %s exit %d", r.Verdict, selfTestExitCode(r))
	}
	// one failure hides nothing: every other check still ran and passed
	for _, name := range allChecks {
		if name != "admin_fence" {
			expectStatus(t, r, name, selfTestPass)
		}
	}
}

func TestSelfTestFenceIPv6TwinIsRequiredOnlyWithIPv6(t *testing.T) {
	f := newStFixture(t)
	f.tools.fence6 = false
	expectStatus(t, f.report(), "admin_fence", selfTestFail, "ip6tables")

	f = newStFixture(t)
	f.tools.fence6 = false
	setNetworks(t, "192.168.100.0/24", "")
	r := f.report()
	expectStatus(t, r, "admin_fence", selfTestPass)
	for _, c := range f.tools.called() {
		if strings.HasPrefix(c, "ip6tables") {
			t.Fatalf("IPv6 is off, ip6tables must not run: %q", c)
		}
	}
	// the port is the panel's own
	setFlag(t, listenPort, "9090")
	expectStatus(t, f.report(), "admin_fence", selfTestFail)
	if !f.tools.ran("iptables -C INPUT -i tun+ -p tcp --dport 9090 -j DROP") {
		t.Fatalf("the rule of the configured port was not asked: %q", f.tools.called())
	}
	setFlag(t, listenPort, "http")
	expectStatus(t, f.report(), "admin_fence", selfTestFail, "not a port")
}

func TestSelfTestFirewallThatCannotBeReadIsWarnNotPassNotFail(t *testing.T) {
	f := newStFixture(t)
	f.tools.denied = true
	r := f.report()
	c := expectStatus(t, r, "admin_fence", selfTestWarn, "CAP_NET_ADMIN")
	if strings.Contains(c.Detail, "no rule") {
		t.Fatalf("a firewall that cannot be read must not claim the rule is missing: %s", c.Detail)
	}
	expectStatus(t, r, "ban_jail", selfTestWarn, "CAP_NET_ADMIN")
	if r.Verdict != selfTestPass {
		t.Fatalf("verdict %s", r.Verdict)
	}
}

func TestSelfTestMissingIptablesBinaryIsFail(t *testing.T) {
	f := newStFixture(t)
	f.tools.missing["iptables"] = true
	r := f.report()
	expectStatus(t, r, "admin_fence", selfTestFail, "not installed")
	expectStatus(t, r, "ban_jail", selfTestFail, "not installed")
}

func TestSelfTestIptablesBinaryIsTheConfiguredOne(t *testing.T) {
	f := newStFixture(t)
	setFlag(t, selfTestIptablesBin, "iptables-legacy")
	setFlag(t, selfTestIp6tablesBin, "ip6tables-legacy")
	r := f.report()
	// the stub does not know iptables-legacy: exit 127 is "cannot read", not a pass; both families say the same, once
	c := expectStatus(t, r, "admin_fence", selfTestWarn, "iptables-legacy")
	if strings.Count(c.Detail, "cannot read the firewall") != 1 || !strings.Contains(c.Detail, "ip6tables: the same") {
		t.Fatalf("the same warning twice: %s", c.Detail)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// ban_jail

func TestSelfTestBanJail(t *testing.T) {
	t.Run("no ban chain", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.chain4 = false
		expectStatus(t, f.report(), "ban_jail", selfTestFail, "OVPN_BAN", "does not exist")
	})
	t.Run("a chain that INPUT never reaches", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.jump4 = false // the stub lists decoys: a jump from another chain and a jump to OVPN_BAN_SPARE
		expectStatus(t, f.report(), "ban_jail", selfTestFail, "no jump to OVPN_BAN")
	})
	t.Run("IPv6 chain missing", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.chain6 = false
		expectStatus(t, f.report(), "ban_jail", selfTestFail, "OVPN_BAN6")
	})
	t.Run("IPv6 chain is not asked with IPv6 off", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.chain6 = false
		setNetworks(t, "192.168.100.0/24", "")
		expectStatus(t, f.report(), "ban_jail", selfTestPass)
	})
	t.Run("no ban ever written", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.state, "bans.tsv")))
		r := f.report()
		expectStatus(t, r, "ban_jail", selfTestWarn, "no ban has ever been written")
		if r.Verdict != selfTestPass {
			t.Fatalf("WARN must not fail the verdict: %s", r.Verdict)
		}
	})
	t.Run("a ban list nobody has written for 30 days", func(t *testing.T) {
		f := newStFixture(t)
		old := stNow.Add(-31 * 24 * time.Hour)
		stMust(t, os.Chtimes(filepath.Join(f.state, "bans.tsv"), old, old))
		expectStatus(t, f.report(), "ban_jail", selfTestWarn, "31 days ago")
		young := stNow.Add(-29 * 24 * time.Hour)
		stMust(t, os.Chtimes(filepath.Join(f.state, "bans.tsv"), young, young))
		expectStatus(t, f.report(), "ban_jail", selfTestPass)
	})
	t.Run("a ban list that cannot be read", func(t *testing.T) {
		f := newStFixture(t)
		p := filepath.Join(f.state, "bans.tsv")
		stMust(t, os.Remove(p))
		stMust(t, os.Mkdir(p, 0o700)) // reading a directory fails whoever runs the test
		expectStatus(t, f.report(), "ban_jail", selfTestFail, "not readable")
	})
	t.Run("engine switched off", func(t *testing.T) {
		f := newStFixture(t)
		t.Setenv("OVPN_BAN_ENABLED", "false")
		f.tools.chain4 = false
		expectStatus(t, f.report(), "ban_jail", selfTestWarn, "OVPN_BAN_ENABLED=false")
	})
	t.Run("the addresses of the bans are not reported", func(t *testing.T) {
		f := newStFixture(t)
		c := expectStatus(t, f.report(), "ban_jail", selfTestPass, "1 active ban")
		if strings.Contains(c.Detail, "203.0.113.9") {
			t.Fatalf("an address in the detail: %s", c.Detail)
		}
	})
}

// ---------------------------------------------------------------------------------------------------------------
// crl_age and cert_expiry

func TestSelfTestCrlAge(t *testing.T) {
	cases := []struct {
		name string
		next time.Duration
		want string
	}{
		{"half a year", 150 * 24 * time.Hour, selfTestPass},
		{"31 days", 31 * 24 * time.Hour, selfTestPass},
		{"29 days", 29 * 24 * time.Hour, selfTestWarn},
		{"8 days", 8 * 24 * time.Hour, selfTestWarn},
		{"6 days", 6 * 24 * time.Hour, selfTestFail},
		{"a minute", time.Minute, selfTestFail},
		{"expired", -time.Hour, selfTestFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newStFixture(t)
			stWriteCRL(t, f.pki, stNow.Add(c.next))
			r := f.report()
			got := expectStatus(t, r, "crl_age", c.want)
			if c.want == selfTestFail && c.next < 0 && !strings.Contains(got.Detail, "expired") {
				t.Fatalf("detail: %s", got.Detail)
			}
		})
	}
	t.Run("no CRL", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "crl.pem")))
		expectStatus(t, f.report(), "crl_age", selfTestFail, "cannot be read")
	})
	t.Run("not a CRL", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.WriteFile(filepath.Join(f.pki, "crl.pem"), []byte("garbage"), 0o644))
		expectStatus(t, f.report(), "crl_age", selfTestFail)
	})
}

func TestSelfTestCertExpiry(t *testing.T) {
	day := 24 * time.Hour
	t.Run("a certificate moved to within 3 days is FAIL and named", func(t *testing.T) {
		f := newStFixture(t)
		stWriteCert(t, f.pki, "alice", 3, stNow.Add(3*day-time.Minute), certKindClient)
		r := f.report()
		expectStatus(t, r, "cert_expiry", selfTestFail, "alice")
		if r.Verdict != selfTestFail || selfTestExitCode(r) != 1 {
			t.Fatalf("verdict %s exit %d", r.Verdict, selfTestExitCode(r))
		}
		expectStatus(t, r, "key_modes", selfTestPass) // independent
	})
	t.Run("boundaries: 7 days FAIL below, WARN below 30", func(t *testing.T) {
		for _, c := range []struct {
			left time.Duration
			want string
		}{{7*day - time.Second, selfTestFail}, {7*day + time.Second, selfTestWarn}, {30*day - time.Second, selfTestWarn}, {30*day + time.Second, selfTestPass}} {
			f := newStFixture(t)
			stWriteCert(t, f.pki, "bob", 4, stNow.Add(c.left), certKindClient)
			expectStatus(t, f.report(), "cert_expiry", c.want)
		}
	})
	t.Run("expired", func(t *testing.T) {
		f := newStFixture(t)
		stWriteCert(t, f.pki, "bob", 4, stNow.Add(-day), certKindClient)
		expectStatus(t, f.report(), "cert_expiry", selfTestFail, "bob", "expired")
	})
	t.Run("the server certificate and the CA count", func(t *testing.T) {
		f := newStFixture(t)
		stWriteCert(t, f.pki, "server", 2, stNow.Add(2*day), certKindServer)
		expectStatus(t, f.report(), "cert_expiry", selfTestFail, "server")
		f = newStFixture(t)
		stWriteCert(t, f.pki, "ca", 1, stNow.Add(10*day), certKindCA)
		expectStatus(t, f.report(), "cert_expiry", selfTestWarn, "ca")
	})
	t.Run("a revoked certificate does not count", func(t *testing.T) {
		f := newStFixture(t)
		stWriteCert(t, f.pki, "bob", 4, stNow.Add(-day), certKindClient)
		index := "V\t351231235959Z\t\t02\tunknown\t/CN=server\nV\t351231235959Z\t\t03\tunknown\t/CN=alice\nR\t351231235959Z\t261101000000Z\t04\tunknown\t/CN=bob\n"
		stMust(t, os.WriteFile(filepath.Join(f.pki, "index.txt"), []byte(index), 0o600))
		expectStatus(t, f.report(), "cert_expiry", selfTestPass)
	})
	t.Run("no CA, no server certificate", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "ca.crt")))
		expectStatus(t, f.report(), "cert_expiry", selfTestFail, "no CA certificate")
		f = newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "issued", "server.crt")))
		expectStatus(t, f.report(), "cert_expiry", selfTestFail, "no server certificate")
	})
	t.Run("many names are counted, not listed", func(t *testing.T) {
		f := newStFixture(t)
		for i := 0; i < 9; i++ {
			stWriteCert(t, f.pki, fmt.Sprintf("c%d", i), int64(10+i), stNow.Add(day), certKindClient)
		}
		expectStatus(t, f.report(), "cert_expiry", selfTestFail, "and 4 more")
	})
	t.Run("the detail names the soonest certificate", func(t *testing.T) {
		f := newStFixture(t)
		expectStatus(t, f.report(), "cert_expiry", selfTestPass, "4 certificates (2 client, 1 server, 1 CA)", "soonest: bob, 200.0 days left")
	})
}

func TestSelfTestPkiChecksAreSkippedOnKubernetes(t *testing.T) {
	f := newStFixture(t)
	setFlag(t, storageBackend, "kubernetes.secrets")
	r := f.report()
	for _, n := range []string{"crl_age", "cert_expiry", "key_modes", "pki_readable"} {
		expectStatus(t, r, n, selfTestWarn, "kubernetes.secrets")
	}
	expectStatus(t, r, "admin_fence", selfTestPass)
}

// ---------------------------------------------------------------------------------------------------------------
// key_modes and pki_readable

func TestSelfTestKeyModes(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		f := newStFixture(t)
		expectStatus(t, f.report(), "key_modes", selfTestPass, "ca.key 0600 root", "server.key 0600 root", "index.txt 0600", "users.db 0640")
	})
	for _, c := range []struct {
		file, what string
		mode       os.FileMode
	}{
		{"private/ca.key", "private/ca.key has mode 0644", 0o644},
		{"private/server.key", "private/server.key has mode 0640", 0o640},
		{"index.txt", "index.txt has mode 0644", 0o644},
		{"users.db", "users.db has mode 0646: writable by everybody", 0o646},
	} {
		t.Run("mode of "+c.file, func(t *testing.T) {
			f := newStFixture(t)
			stMust(t, os.Chmod(filepath.Join(f.pki, c.file), c.mode))
			expectStatus(t, f.report(), "key_modes", selfTestFail, c.what)
		})
	}
	t.Run("users.db readable by everybody is a warning: the login hook runs as nobody and needs it", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Chmod(filepath.Join(f.pki, "users.db"), 0o644)) // what openvpn-user leaves, measured
		r := f.report()
		expectStatus(t, r, "key_modes", selfTestWarn, "users.db has mode 0644", "root:nogroup 0640")
		if r.Verdict != selfTestPass {
			t.Fatal("a warning must not fail the verdict")
		}
		// a failure in the same check still wins, and names both
		stMust(t, os.Chmod(filepath.Join(f.pki, "index.txt"), 0o644))
		expectStatus(t, f.report(), "key_modes", selfTestFail, "index.txt has mode 0644", "users.db has mode 0644")
	})
	t.Run("a key readable by the group is not 0600", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Chmod(filepath.Join(f.pki, "private", "ca.key"), 0o660))
		expectStatus(t, f.report(), "key_modes", selfTestFail, "0660")
	})
	t.Run("0400 is stricter and accepted", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Chmod(filepath.Join(f.pki, "private", "server.key"), 0o400))
		expectStatus(t, f.report(), "key_modes", selfTestPass)
	})
	t.Run("not owned by root", func(t *testing.T) {
		f := newStFixture(t)
		f.ownerUID = os.Getuid() + 1 // stands for "root": the files belong to somebody else
		expectStatus(t, f.report(), "key_modes", selfTestFail, "owned by uid", "expected root")
	})
	t.Run("a missing key", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "private", "server.key")))
		expectStatus(t, f.report(), "key_modes", selfTestFail, "server.key does not exist")
	})
	t.Run("a slave holds no CA key", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "private", "ca.key")))
		expectStatus(t, f.report(), "key_modes", selfTestFail, "ca.key does not exist")
		setFlag(t, serverRole, "slave")
		expectStatus(t, f.report(), "key_modes", selfTestPass, "slave")
	})
	t.Run("no users.db without password authentication", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "users.db")))
		expectStatus(t, f.report(), "key_modes", selfTestFail, "users.db does not exist")
		setFlag(t, authByPassword, false)
		expectStatus(t, f.report(), "key_modes", selfTestPass, "password authentication is off")
	})
	t.Run("the key itself is never read into the answer", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Chmod(filepath.Join(f.pki, "private", "ca.key"), 0o644))
		r := f.report()
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), stKeyBody) || strings.Contains(string(raw), "BEGIN PRIVATE KEY") {
			t.Fatalf("key material in the answer: %s", raw)
		}
	})
}

func TestSelfTestPkiReadable(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		f := newStFixture(t)
		expectStatus(t, f.report(), "pki_readable", selfTestPass, "index.txt parses (3 records)", "users.db opens read-only (3 user rows)")
		if !f.tools.ran("sqlite3 -readonly " + filepath.Join(f.pki, "users.db") + " SELECT count(*) FROM users;") {
			t.Fatalf("users.db must be opened with -readonly: %q", f.tools.called())
		}
	})
	t.Run("a line of index.txt that is not a record", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.WriteFile(filepath.Join(f.pki, "index.txt"), []byte("V\t351231235959Z\t\t02\tunknown\t/CN=server\nthis is not a record\n"), 0o600))
		expectStatus(t, f.report(), "pki_readable", selfTestFail, "line 2")
	})
	t.Run("index.txt missing", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "index.txt")))
		expectStatus(t, f.report(), "pki_readable", selfTestFail, "index.txt is not readable")
	})
	t.Run("an empty index is a valid index", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.WriteFile(filepath.Join(f.pki, "index.txt"), nil, 0o600))
		expectStatus(t, f.report(), "pki_readable", selfTestPass, "0 records")
	})
	t.Run("users.db that is not a database", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.WriteFile(filepath.Join(f.pki, "users.db"), []byte("not a database at all, just text"), 0o640))
		expectStatus(t, f.report(), "pki_readable", selfTestFail, "not an SQLite database")
	})
	t.Run("sqlite3 cannot open it", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.sqliteCode, f.tools.sqliteOut = 1, "Error: database disk image is malformed\n"
		expectStatus(t, f.report(), "pki_readable", selfTestFail, "does not open read-only", "malformed")
	})
	t.Run("no sqlite3 command: the header decides", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.missing["sqlite3"] = true
		expectStatus(t, f.report(), "pki_readable", selfTestPass, "header checked only")
	})
	t.Run("users.db missing with password authentication on", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.pki, "users.db")))
		expectStatus(t, f.report(), "pki_readable", selfTestFail, "does not exist")
		setFlag(t, authByPassword, false)
		expectStatus(t, f.report(), "pki_readable", selfTestPass, "password authentication is off")
	})
}

// ---------------------------------------------------------------------------------------------------------------
// credentials, sync, versions

func TestSelfTestCredentials(t *testing.T) {
	f := newStFixture(t)
	expectStatus(t, f.report(), "credentials", selfTestPass)
	setFlag(t, basicPassword, "")
	expectStatus(t, f.report(), "credentials", selfTestFail, "only one")
	setFlag(t, basicPassword, "panel-test-pass")
	setFlag(t, basicUsername, "")
	expectStatus(t, f.report(), "credentials", selfTestFail, "only one")
	setFlag(t, basicPassword, "")
	expectStatus(t, f.report(), "credentials", selfTestFail, "no authentication")
	setFlag(t, insecureNoAuth, true)
	r := f.report()
	expectStatus(t, r, "credentials", selfTestWarn, "explicit choice")
	if r.Verdict != selfTestPass {
		t.Fatalf("the explicit flag is allowed: verdict %s", r.Verdict)
	}
}

func TestSelfTestSync(t *testing.T) {
	f := newStFixture(t)
	expectStatus(t, f.report(), "sync", selfTestPass, "sync is off")
	setFlag(t, masterSyncToken, "0123456789abcdef0123456789abcdef")
	expectStatus(t, f.report(), "sync", selfTestPass, "plain HTTP", "refused")
	setFlag(t, masterAllowInsecureHTTP, true)
	c := expectStatus(t, f.report(), "sync", selfTestFail, "plain HTTP")
	if strings.Contains(c.Detail, "0123456789abcdef") {
		t.Fatalf("the token is in the detail: %s", c.Detail)
	}
	// insecure HTTP without a token serves nothing
	setFlag(t, masterSyncToken, "")
	expectStatus(t, f.report(), "sync", selfTestPass)
	setFlag(t, masterSyncToken, "   ")
	expectStatus(t, f.report(), "sync", selfTestPass)
}

func TestSelfTestVersions(t *testing.T) {
	t.Run("all known", func(t *testing.T) {
		f := newStFixture(t)
		expectStatus(t, f.report(), "versions", selfTestPass, "ovpn-admin 0.1.12", "OpenVPN 2.7.9 (binary of this image)", "easy-rsa 3.2.5")
	})
	t.Run("the running server is asked first", func(t *testing.T) {
		f := newStFixture(t)
		s := f.st()
		s.mgmtVersion = func() string { return "2.7.7" }
		r := s.Run()
		expectStatus(t, r, "versions", selfTestPass, "OpenVPN 2.7.7 (running server)")
		if f.tools.ran("openvpn --version") {
			t.Fatal("the binary must not be asked when the server answered")
		}
	})
	t.Run("a dev build or no version is FAIL", func(t *testing.T) {
		for _, v := range []string{"dev", "", "  "} {
			f := newStFixture(t)
			s := f.st()
			s.appVersion = func() string { return v }
			expectStatus(t, s.Run(), "versions", selfTestFail, "not a release build")
		}
	})
	t.Run("easy-rsa prints its own version", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.easyrsaOut = "EasyRSA Version Information\nVersion:     3.1.7\n"
		expectStatus(t, f.report(), "versions", selfTestPass, "easy-rsa 3.1.7")
	})
	t.Run("versions that cannot be found are WARN", func(t *testing.T) {
		f := newStFixture(t)
		f.tools.missing["openvpn"], f.tools.missing["apk"] = true, true
		r := f.report()
		expectStatus(t, r, "versions", selfTestWarn, "OpenVPN version unknown", "easy-rsa version unknown")
		if r.Verdict != selfTestPass {
			t.Fatal("unknown versions are not a failure")
		}
	})
}

// ---------------------------------------------------------------------------------------------------------------
// control_channel

func TestSelfTestControlChannel(t *testing.T) {
	ctl := func(v string) string {
		return "2026-11-30 10:00:01 tcp6-server:[2001:db8::7]:5555 Control Channel: " + v + ", cipher " + v + " TLS_AES_256_GCM_SHA384, peer certificate: 256 bits EC\n"
	}
	t.Run("the newest line decides", func(t *testing.T) {
		f := newStFixture(t)
		f.writeLog(ctl("TLSv1.0") + "noise\n" + ctl("TLSv1.2") + "more noise\n")
		expectStatus(t, f.report(), "control_channel", selfTestPass, "TLSv1.2")
		f.writeLog(ctl("TLSv1.3") + ctl("TLSv1.1") + "noise\n")
		expectStatus(t, f.report(), "control_channel", selfTestFail, "TLSv1.1", "TLS floor")
	})
	t.Run("old versions", func(t *testing.T) {
		for _, v := range []string{"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3"} {
			f := newStFixture(t)
			f.writeLog(ctl(v))
			expectStatus(t, f.report(), "control_channel", selfTestFail, v)
		}
	})
	t.Run("a version nobody knows", func(t *testing.T) {
		f := newStFixture(t)
		f.writeLog(ctl("QUICv9"))
		expectStatus(t, f.report(), "control_channel", selfTestWarn, "QUICv9")
	})
	t.Run("a log without a handshake", func(t *testing.T) {
		f := newStFixture(t)
		f.writeLog("2026-11-30 09:00:00 OpenVPN 2.7.9 started\n2026-11-30 09:00:01 Initialization Sequence Completed\n")
		expectStatus(t, f.report(), "control_channel", selfTestWarn, "no client has connected")
	})
	t.Run("no log", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(filepath.Join(f.state, "openvpn.log")))
		expectStatus(t, f.report(), "control_channel", selfTestWarn, "does not exist")
	})
	t.Run("a log that was just rotated: the copy still holds the handshake", func(t *testing.T) {
		f := newStFixture(t)
		old := ctl("TLSv1.3")
		f.writeLog("")
		stMust(t, os.WriteFile(filepath.Join(f.state, "openvpn.log.1"), []byte(old), 0o600))
		expectStatus(t, f.report(), "control_channel", selfTestPass, "TLSv1.3")
	})
	t.Run("a very long line before it does not hide it", func(t *testing.T) {
		f := newStFixture(t)
		f.writeLog(strings.Repeat("x", 3<<20) + "\n" + ctl("TLSv1.2"))
		expectStatus(t, f.report(), "control_channel", selfTestPass, "TLSv1.2")
	})
	t.Run("the log of the audit directory when there is no state directory", func(t *testing.T) {
		f := newStFixture(t)
		setFlag(t, stateDir, "")
		auditDir := t.TempDir()
		setFlag(t, auditPath, filepath.Join(auditDir, "audit.tsv"))
		stMust(t, os.WriteFile(filepath.Join(auditDir, "openvpn.log"), []byte(ctl("TLSv1.3")), 0o600))
		expectStatus(t, f.report(), "control_channel", selfTestPass, "TLSv1.3")
	})
	t.Run("an explicit log path wins", func(t *testing.T) {
		f := newStFixture(t)
		p := filepath.Join(t.TempDir(), "x.log")
		stMust(t, os.WriteFile(p, []byte(ctl("TLSv1.0")), 0o600))
		setFlag(t, selfTestOpenvpnLog, p)
		expectStatus(t, f.report(), "control_channel", selfTestFail, "TLSv1.0")
	})
	t.Run("the detail holds the version and the cipher, not the line", func(t *testing.T) {
		f := newStFixture(t)
		c := expectStatus(t, f.report(), "control_channel", selfTestPass, "TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384")
		if strings.Contains(c.Detail, "2001:db8") || strings.Contains(c.Detail, "peer certificate") {
			t.Fatalf("the log line leaked: %s", c.Detail)
		}
	})
}

// ---------------------------------------------------------------------------------------------------------------
// audit_chain

func alterAuditLine(t *testing.T, path string, line int, from, to string) {
	t.Helper()
	data, err := os.ReadFile(path)
	stMust(t, err)
	lines := strings.Split(string(data), "\n")
	if !strings.Contains(lines[line-1], from) {
		t.Fatalf("line %d has no %q: %s", line, from, lines[line-1])
	}
	lines[line-1] = strings.Replace(lines[line-1], from, to, 1)
	stMust(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600))
}

func TestSelfTestAuditChain(t *testing.T) {
	t.Run("an intact trail read from outside the panel", func(t *testing.T) {
		f := newStFixture(t)
		expectStatus(t, f.report(), "audit_chain", selfTestPass, "5 lines", "seq 1 to 5")
	})
	t.Run("an intact trail of the running panel", func(t *testing.T) {
		f := newStFixture(t)
		a, err := openAdminAuditLog(f.trail, "")
		stMust(t, err)
		t.Cleanup(a.Close)
		_, err = a.Record("operator", "user.create", "zed", "127.0.0.1", adminAuditResultOK, "created")
		stMust(t, err)
		s := f.st()
		s.audit = a
		expectStatus(t, s.Run(), "audit_chain", selfTestPass, "6 lines")
	})
	t.Run("a new trail with no record yet", func(t *testing.T) {
		f := newStFixture(t)
		for _, p := range []string{f.trail, f.trail + adminAuditCheckpointSuffix, filepath.Join(filepath.Dir(filepath.Dir(f.trail)), adminAuditSentinelName)} {
			stMust(t, os.Remove(p))
		}
		a, err := openAdminAuditLog(f.trail, "")
		stMust(t, err)
		a.Close()
		expectStatus(t, f.report(), "audit_chain", selfTestPass, "no record yet")
	})
	t.Run("the third line altered names the line", func(t *testing.T) {
		f := newStFixture(t)
		alterAuditLine(t, f.trail, 3, `"target":"user2"`, `"target":"mallory"`)
		r := f.report()
		c := expectStatus(t, r, "audit_chain", selfTestFail, "broken at seq 3", "line 3 of admin-audit.log", "hash")
		if strings.Contains(c.Detail, "mallory") {
			t.Fatalf("the altered text is echoed: %s", c.Detail)
		}
		if r.Verdict != selfTestFail || selfTestExitCode(r) != 1 {
			t.Fatalf("verdict %s exit %d", r.Verdict, selfTestExitCode(r))
		}
		// the same through the panel's own trail
		a, err := openAdminAuditLog(f.trail, "")
		if err == nil {
			t.Cleanup(a.Close)
			s := f.st()
			s.audit = a
			expectStatus(t, s.Run(), "audit_chain", selfTestFail, "seq 3")
		}
	})
	t.Run("the last line cut off", func(t *testing.T) {
		f := newStFixture(t)
		data, err := os.ReadFile(f.trail)
		stMust(t, err)
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		stMust(t, os.WriteFile(f.trail, []byte(strings.Join(lines[:4], "\n")+"\n"), 0o600))
		expectStatus(t, f.report(), "audit_chain", selfTestFail, "seq 5")
	})
	t.Run("a line removed from the middle", func(t *testing.T) {
		f := newStFixture(t)
		data, err := os.ReadFile(f.trail)
		stMust(t, err)
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		lines = append(lines[:1], lines[2:]...)
		stMust(t, os.WriteFile(f.trail, []byte(strings.Join(lines, "\n")+"\n"), 0o600))
		expectStatus(t, f.report(), "audit_chain", selfTestFail, "broken at seq 2")
	})
	t.Run("the trail is gone", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(f.trail))
		expectStatus(t, f.report(), "audit_chain", selfTestFail, "missing")
	})
	t.Run("no trail configured", func(t *testing.T) {
		f := newStFixture(t)
		setFlag(t, adminAuditFileFlag, "")
		expectStatus(t, f.report(), "audit_chain", selfTestFail, "no admin audit trail")
	})
	t.Run("a trail that cannot be vouched for is not green", func(t *testing.T) {
		f := newStFixture(t)
		stMust(t, os.Remove(f.trail+adminAuditCheckpointSuffix))
		expectStatus(t, f.report(), "audit_chain", selfTestFail, "cannot be verified", "no checkpoint")
	})
	t.Run("the command line changes nothing on disk", func(t *testing.T) {
		f := newStFixture(t)
		before := dirSnapshot(t, filepath.Dir(f.trail))
		f.report()
		f.report()
		if after := dirSnapshot(t, filepath.Dir(f.trail)); after != before {
			t.Fatalf("the audit directory changed:\nbefore %s\nafter  %s", before, after)
		}
	})
	t.Run("a read that races the writer is repeated once", func(t *testing.T) {
		f := newStFixture(t)
		s := f.st()
		slept := 0
		// the first read sees a half written last line, the second sees it complete
		data, err := os.ReadFile(f.trail)
		stMust(t, err)
		stMust(t, os.WriteFile(f.trail, data[:len(data)-20], 0o600))
		s.sleep = func(time.Duration) {
			slept++
			stMust(t, os.WriteFile(f.trail, data, 0o600))
		}
		expectStatus(t, s.Run(), "audit_chain", selfTestPass)
		if slept != 1 {
			t.Fatalf("slept %d times", slept)
		}
	})
}

func dirSnapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	stMust(t, err)
	var b strings.Builder
	for _, e := range entries {
		info, err := e.Info()
		stMust(t, err)
		data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		fmt.Fprintf(&b, "%s:%d:%d:%x;", e.Name(), info.Size(), info.ModTime().UnixNano(), len(data))
	}
	parent := filepath.Dir(dir)
	pe, _ := os.ReadDir(parent)
	for _, e := range pe {
		fmt.Fprintf(&b, "[%s]", e.Name())
	}
	return b.String()
}

// ---------------------------------------------------------------------------------------------------------------
// nothing secret in an answer

func TestSelfTestAnswerHoldsNoSecret(t *testing.T) {
	f := newStFixture(t)
	const (
		pass   = "Pa55-never-print-XYZ"
		token  = "sync-token-never-print-ABC123"
		mpass  = "master-pass-never-print-QQ77"
		tgtoke = "999999:TG-TOKEN-never-print"
	)
	setFlag(t, basicPassword, pass)
	setFlag(t, masterSyncToken, token)
	setFlag(t, masterBasicAuthPassword, mpass)
	t.Setenv("OVPN_TELEGRAM_BOT_TOKEN", tgtoke)
	// make as many checks as possible say something: a failed fence, a bad key mode, a broken trail, a near certificate
	f.tools.fence4 = false
	f.tools.sqliteOut = "Error: " + pass + " " + token + "\n"
	f.tools.sqliteCode = 1
	stMust(t, os.Chmod(filepath.Join(f.pki, "private", "ca.key"), 0o644))
	stWriteCert(t, f.pki, "alice", 3, stNow.Add(48*time.Hour), certKindClient)
	alterAuditLine(t, f.trail, 3, `"target":"user2"`, `"target":"mallory"`)
	setFlag(t, masterAllowInsecureHTTP, true)

	r := f.report()
	var cli bytes.Buffer
	printSelfTestReport(&cli, r)
	raw, _ := json.Marshal(r)
	ca, err := os.ReadFile(filepath.Join(f.pki, "ca.crt"))
	stMust(t, err)
	caBody := strings.Split(string(ca), "\n")[1]
	for _, text := range []string{cli.String(), string(raw)} {
		for _, secret := range []string{pass, token, mpass, tgtoke, stKeyBody, "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", caBody[:30]} {
			if strings.Contains(text, secret) {
				t.Errorf("%q is in the answer:\n%s", secret, text)
			}
		}
	}
	// the masked value took the place of the secret where a command echoed it
	if !strings.Contains(cli.String(), "***") {
		t.Errorf("the echoed secret was not masked:\n%s", cli.String())
	}
}

func TestSelfTestSanitize(t *testing.T) {
	setFlag(t, basicPassword, "hunter2-long")
	if got := selfTestSanitize("a\n\tb   c hunter2-long d"); got != "a b c *** d" {
		t.Fatalf("got %q", got)
	}
	if got := selfTestSanitize("x -----BEGIN RSA PRIVATE KEY----- MIIE"); strings.Contains(got, "MIIE") || !strings.Contains(got, "withheld") {
		t.Fatalf("PEM not withheld: %q", got)
	}
	long := selfTestSanitize(strings.Repeat("é", 1000))
	if n := len([]rune(long)); n != selfTestMaxDetail || !strings.HasSuffix(long, "...") {
		t.Fatalf("length %d: %q", n, long[len(long)-10:])
	}
	// a short secret would damage the text around it: not masked
	setFlag(t, basicPassword, "ab")
	if got := selfTestSanitize("table"); got != "table" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the endpoint

func selfTestHandlerCall(t *testing.T, method string, creds bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/selftest", nil)
	if creds {
		req.SetBasicAuth(honestAdminUser, honestAdminPass)
	}
	rec := httptest.NewRecorder()
	certTestAdmin().selfTestHandler(rec, req)
	return rec
}

func TestSelfTestEndpointShapeAndAuth(t *testing.T) {
	f := newStFixture(t)
	useSelfTest(t, f.st())

	rec := selfTestHandlerCall(t, http.MethodGet, true)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("%d %s: %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	var body struct {
		Verdict     string `json:"verdict"`
		GeneratedAt string `json:"generatedAt"`
		Checks      []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	stMust(t, json.Unmarshal(rec.Body.Bytes(), &body))
	if body.Verdict != "PASS" || len(body.Checks) != 11 {
		t.Fatalf("%+v", body)
	}
	if _, err := time.Parse(time.RFC3339, body.GeneratedAt); err != nil {
		t.Fatal(err)
	}
	for i, c := range body.Checks {
		if c.Name != allChecks[i] || c.Status != "PASS" || c.Detail == "" {
			t.Errorf("check %d: %+v", i, c)
		}
	}
	var keys map[string]json.RawMessage
	stMust(t, json.Unmarshal(rec.Body.Bytes(), &keys))
	if len(keys) != 3 {
		t.Fatalf("the answer has exactly verdict, checks and generatedAt: %v", keys)
	}

	// admin credentials only
	if rec := selfTestHandlerCall(t, http.MethodGet, false); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "verdict") {
		t.Fatalf("without credentials: %d %s", rec.Code, rec.Body.String())
	}
	if rec := selfTestHandlerCall(t, http.MethodPost, true); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	setFlag(t, basicUsername, "")
	setFlag(t, basicPassword, "")
	if rec := selfTestHandlerCall(t, http.MethodGet, true); rec.Code != http.StatusForbidden {
		t.Fatalf("no credentials configured: %d", rec.Code)
	}
}

func TestSelfTestEndpointGivesTheVerdictOfTheCLI(t *testing.T) {
	for name, mutate := range map[string]func(*stFixture){
		"healthy":       func(*stFixture) {},
		"fence removed": func(f *stFixture) { f.tools.fence4 = false },
		"cert in 3 days": func(f *stFixture) {
			stWriteCert(t, f.pki, "bob", 4, stNow.Add(72*time.Hour-time.Minute), certKindClient)
		},
		"audit altered": func(f *stFixture) { alterAuditLine(t, f.trail, 3, `"target":"user2"`, `"target":"x"`) },
		"warn only":     func(f *stFixture) { f.tools.denied = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newStFixture(t)
			mutate(f)
			useSelfTest(t, f.st())
			var cli bytes.Buffer
			code := runSelfTestCLI(&cli, f.st())

			rec := selfTestHandlerCall(t, http.MethodGet, true)
			var got selfTestReport
			stMust(t, json.Unmarshal(rec.Body.Bytes(), &got))
			want := map[bool]string{true: "FAIL", false: "PASS"}[code == 1]
			if got.Verdict != want {
				t.Fatalf("endpoint %s, CLI exit %d", got.Verdict, code)
			}
			if !strings.Contains(cli.String(), "verdict: "+got.Verdict) {
				t.Fatalf("CLI: %s", cli.String())
			}
			cliRep := f.report()
			if fmt.Sprint(got.statuses()) != fmt.Sprint(cliRep.statuses()) {
				t.Fatalf("statuses differ:\nendpoint %v\ncli      %v", got.statuses(), cliRep.statuses())
			}
		})
	}
}

func TestSelfTestEndpointRecordsTheRunInTheTrail(t *testing.T) {
	f := newStFixture(t)
	a := useAdminAudit(t, "")
	useSelfTest(t, f.st())
	if rec := selfTestHandlerCall(t, http.MethodGet, true); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	recs := auditActions(t, a)
	last := recs[len(recs)-1]
	if last.Action != "selftest.run" || last.Result != adminAuditResultOK || !strings.Contains(last.Detail, "verdict=PASS pass=11 warn=0 fail=0") {
		t.Fatalf("%+v", last)
	}
}

func TestSelfTestEndpointInternalErrorIs500(t *testing.T) {
	f := newStFixture(t)
	old := selfTestRegistry
	selfTestRegistry = func() []selfTestEntry {
		return []selfTestEntry{{"boom", func(*selfTest) (string, string) { panic("x") }}}
	}
	t.Cleanup(func() { selfTestRegistry = old })
	useSelfTest(t, f.st())
	rec := selfTestHandlerCall(t, http.MethodGet, true)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), `"FAIL"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------------------------------------------
// the schedule and the Telegram message

func TestSelfTestScheduledFailSendsOneMessageAndLogsAnError(t *testing.T) {
	f := newStFixture(t)
	m := startTgMock(t)
	useTelegram(t, m)
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	f.tools.fence4 = false
	stWriteCert(t, f.pki, "bob", 4, stNow.Add(48*time.Hour), certKindClient)
	setFlag(t, masterSyncToken, "sync-token-never-print-ABC123")
	useSelfTest(t, f.st())

	rep := certTestAdmin().selfTestScheduled()
	if rep.Verdict != selfTestFail {
		t.Fatalf("verdict %s", rep.Verdict)
	}
	texts := m.texts()
	if len(texts) != 1 {
		t.Fatalf("%d messages: %q", len(texts), texts)
	}
	msg := texts[0]
	for _, want := range []string{"self-test FAILED: 2 of 11", "admin_fence: ", "tun+", "cert_expiry: ", "bob"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	for _, no := range []string{"ban_jail", "versions", testBotToken, "sync-token-never-print", "BEGIN"} {
		if strings.Contains(msg, no) {
			t.Errorf("message holds %q:\n%s", no, msg)
		}
	}
	errs := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.ErrorLevel && strings.Contains(e.Message, "self-test:") {
			errs++
		}
		if strings.Contains(e.Message, testBotToken) {
			t.Errorf("the token is in the log: %s", e.Message)
		}
	}
	if errs < 3 { // one line per failed check and the verdict line
		t.Errorf("error lines: %d", errs)
	}
	// one message per run
	certTestAdmin().selfTestScheduled()
	if n := len(m.texts()); n != 2 {
		t.Fatalf("a second run sends its own message: %d", n)
	}
}

func TestSelfTestScheduledHealthyAndWarnSendNothing(t *testing.T) {
	f := newStFixture(t)
	m := startTgMock(t)
	useTelegram(t, m)
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	useSelfTest(t, f.st())
	if rep := certTestAdmin().selfTestScheduled(); rep.Verdict != selfTestPass {
		t.Fatalf("verdict %s", rep.Verdict)
	}
	f.tools.denied = true
	if rep := certTestAdmin().selfTestScheduled(); rep.Verdict != selfTestPass {
		t.Fatalf("verdict %s", rep.Verdict)
	}
	if n := len(m.texts()); n != 0 {
		t.Fatalf("%d messages for PASS and WARN: %q", n, m.texts())
	}
	for _, e := range hook.AllEntries() {
		if e.Level <= log.ErrorLevel {
			t.Errorf("an error line without a FAIL: %s", e.Message)
		}
	}
}

func TestSelfTestScheduledSurvivesTelegramProblems(t *testing.T) {
	f := newStFixture(t)
	f.tools.fence4 = false
	useSelfTest(t, f.st())
	// Telegram off
	clearTelegram(t)
	if rep := certTestAdmin().selfTestScheduled(); rep.Verdict != selfTestFail {
		t.Fatal(rep.Verdict)
	}
	// Telegram answering 500
	m := startTgMock(t)
	useTelegram(t, m)
	m.setStatus(500)
	if rep := certTestAdmin().selfTestScheduled(); rep.Verdict != selfTestFail {
		t.Fatal(rep.Verdict)
	}
	if len(m.texts()) != 1 {
		t.Fatalf("the failed send was not tried once: %d", len(m.texts()))
	}
}

func TestSelfTestMessageIsBoundedToOneMessage(t *testing.T) {
	rep := selfTestReport{}
	for i := 0; i < 40; i++ {
		rep.Checks = append(rep.Checks, selfTestCheck{Name: fmt.Sprintf("check%d", i), Status: selfTestFail, Detail: strings.Repeat("d", 390)})
	}
	if n := len([]rune(selfTestMessage(rep))); n > telegramMaxText || n < 3000 {
		t.Fatalf("message of %d characters", n)
	}
}

func TestSelfTestLoopRunsAndStops(t *testing.T) {
	f := newStFixture(t)
	var runs atomic.Int32
	s := f.st()
	old := newSelfTestFor
	newSelfTestFor = func(*OvpnAdmin) *selfTest { runs.Add(1); return s }
	t.Cleanup(func() { newSelfTestFor = old })

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { certTestAdmin().selfTestLoop(30*time.Millisecond, 30*time.Millisecond, stop); close(done) }()
	time.Sleep(10 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatal("the first run must wait for the delay (the openvpn container sets the firewall up while the panel starts)")
	}
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runs.Load() < 3 {
		t.Fatalf("only %d runs", runs.Load())
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop")
	}
}

func TestSelfTestEnabledOnlyFalseSwitchesItOff(t *testing.T) {
	for v, want := range map[string]bool{"": true, "true": true, "1": true, "yes": true, "TRUE": true, "false": false, "False": false, " false ": false, "FALSE": false} {
		setFlag(t, selfTestEnabledFlag, v)
		if got := selfTestEnabled(); got != want {
			t.Errorf("OVPN_SELFTEST_ENABLED=%q: enabled=%v, want %v", v, got, want)
		}
	}
	f := newStFixture(t)
	var runs atomic.Int32
	old := newSelfTestFor
	newSelfTestFor = func(*OvpnAdmin) *selfTest { runs.Add(1); return f.st() }
	t.Cleanup(func() { newSelfTestFor = old })
	setFlag(t, selfTestEnabledFlag, "false")
	done := make(chan struct{})
	go func() { certTestAdmin().selfTestLoop(time.Millisecond, time.Millisecond, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a switched off loop must return at once")
	}
	if runs.Load() != 0 {
		t.Fatal("a switched off loop ran")
	}
}

func TestSelfTestOnlyOneRunAtATime(t *testing.T) {
	f := newStFixture(t)
	var cur, peak atomic.Int32
	s := f.st()
	s.run = func(ctx context.Context, name string, args ...string) (string, int, error) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		cur.Add(-1)
		return f.tools.run(ctx, name, args...)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.runLocked() }()
	}
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("%d commands ran at the same time", peak.Load())
	}
}

// ---------------------------------------------------------------------------------------------------------------
// real processes: the exec path with scripts of our own

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	stMust(t, os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return p
}

func TestSelfTestExecPathWithRealProcesses(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	argvFile := filepath.Join(dir, "argv")
	f := newStFixture(t)
	setNetworks(t, "192.168.100.0/24", "")
	s := f.st()
	s.run = selfTestExec

	// exit 0: the rule is there, and the command line is exactly the contract's
	setFlag(t, selfTestIptablesBin, writeScript(t, dir, "ipt-ok", `echo "$@" >> `+argvFile+`; exit 0`))
	expectStatus(t, s.Run(), "admin_fence", selfTestPass)
	argv, err := os.ReadFile(argvFile)
	stMust(t, err)
	if first, _, _ := strings.Cut(string(argv), "\n"); first != "-C INPUT -i tun+ -p tcp --dport 8080 -j DROP" {
		t.Fatalf("argv: %q", argv)
	}
	// exit 1 with iptables' own words: the rule is missing
	setFlag(t, selfTestIptablesBin, writeScript(t, dir, "ipt-bad", `echo "iptables: Bad rule (does a matching rule exist in that chain?)." >&2; exit 1`))
	expectStatus(t, s.Run(), "admin_fence", selfTestFail, "no rule")
	// exit 1 without those words, and exit 4: cannot tell
	setFlag(t, selfTestIptablesBin, writeScript(t, dir, "ipt-odd", `echo "something else" >&2; exit 1`))
	expectStatus(t, s.Run(), "admin_fence", selfTestWarn, "cannot read the firewall")
	setFlag(t, selfTestIptablesBin, writeScript(t, dir, "ipt-perm", `echo "Permission denied (you must be root)" >&2; exit 4`))
	expectStatus(t, s.Run(), "admin_fence", selfTestWarn, "permission denied")
	// no such binary, by name and by path
	setFlag(t, selfTestIptablesBin, "ovpn-admin-no-such-iptables")
	expectStatus(t, s.Run(), "admin_fence", selfTestFail, "not installed")
	setFlag(t, selfTestIptablesBin, filepath.Join(dir, "absent"))
	expectStatus(t, s.Run(), "admin_fence", selfTestFail, "not installed")
	// a hanging command is stopped
	old := selfTestCmdTimeout
	selfTestCmdTimeout = 300 * time.Millisecond
	t.Cleanup(func() { selfTestCmdTimeout = old })
	setFlag(t, selfTestIptablesBin, writeScript(t, dir, "ipt-hang", `exec sleep 30`))
	start := time.Now()
	expectStatus(t, s.Run(), "admin_fence", selfTestWarn, "timed out")
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the hanging command held the run for %s", time.Since(start))
	}
	// the listing for ban_jail, as the real tool prints it
	setFlag(t, selfTestIptablesBin, writeScript(t, dir, "ipt-list", `printf '%s\n' '-P INPUT ACCEPT' '-N OVPN_BAN' '-A INPUT -p udp -m udp --dport 1194 -j OVPN_BAN'`))
	expectStatus(t, s.Run(), "ban_jail", selfTestPass, "OVPN_BAN")
}

func TestSelfTestExecErrorsAreNotShellErrors(t *testing.T) {
	// no shell: an argument with shell syntax is one argument
	out, code, err := selfTestExec(context.Background(), "echo", "a;b", "$(id)")
	if err != nil || code != 0 || strings.TrimSpace(out) != "a;b $(id)" {
		t.Fatalf("%q %d %v", out, code, err)
	}
	_, _, err = selfTestExec(context.Background(), "ovpn-admin-no-such-binary")
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}
