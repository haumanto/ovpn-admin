package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func setArchivePaths(t *testing.T, dir string) {
	t.Helper()
	setFlag(t, &certsArchivePath, filepath.Join(dir, "certs.tar.gz"))
	setFlag(t, &ccdArchivePath, filepath.Join(dir, "ccd.tar.gz"))
}

// ---------------------------------------------------------------------------------------------------------------
// L5 user names

func TestValidateUsernameRules(t *testing.T) {
	cases := []struct {
		name, user string
		rule       string // a part of the message; "" = accepted
	}{
		{"plain", "alice", ""},
		{"digits first", "9lives", ""},
		{"dots dashes underscores inside", "a.b-c_d", ""},
		{"one byte", "a", ""},
		{"64 bytes", strings.Repeat("a", 64), ""},
		{"reserved prefix is fine", "ca2", ""},
		{"reserved as a suffix is fine", "my-server", ""},
		{"empty", "", "1 to 64 bytes"},
		{"65 characters", strings.Repeat("a", 65), "1 to 64 bytes"},
		{"dotdot slash", "../x", "first character"},
		{"dot", ".", "first character"},
		{"dotdot", "..", "first character"},
		{"leading dash", "-x", "first character"},
		{"leading underscore", "_x", "first character"},
		{"leading at", "@x", "first character"},
		{"slash inside", "a/b", "only letters, digits"},
		{"backslash inside", `a\b`, "only letters, digits"},
		{"at inside", "ann@example.org", "only letters, digits"},
		{"space inside", "a b", "only letters, digits"},
		{"newline inside", "a\nb", "only letters, digits"},
		{"nul inside", "a\x00b", "only letters, digits"},
		{"colon inside", "a:b", "only letters, digits"},
		{"non ascii", "jörg", "only letters, digits"},
		{"ca", "ca", "reserved"},
		{"server", "server", "reserved"},
		{"dh", "dh", "reserved"},
		{"ta", "ta", "reserved"},
		{"crl", "crl", "reserved"},
		{"index", "index", "reserved"},
		{"users", "users", "reserved"},
		{"reserved in capitals", "CA", "reserved"},
		{"reserved mixed case", "Server", "reserved"},
	}
	for _, c := range cases {
		err := validateUsername(c.user)
		switch {
		case c.rule == "" && err != nil:
			t.Errorf("%s: %q refused: %v", c.name, c.user, err)
		case c.rule != "" && err == nil:
			t.Errorf("%s: %q accepted", c.name, c.user)
		case c.rule != "":
			if !isInputError(err) {
				t.Errorf("%s: not an inputError (it must be HTTP 400): %T", c.name, err)
			}
			if !strings.Contains(err.Error(), c.rule) {
				t.Errorf("%s: message %q does not name the rule %q", c.name, err.Error(), c.rule)
			}
			if c.user != "" && len(c.user) <= 8 && strings.Contains(err.Error(), c.user) && c.rule != "reserved" {
				t.Errorf("%s: message repeats the value: %q", c.name, err.Error())
			}
		}
	}
}

// The rule is applied on create, renew and the CCD apply path, and a user that exists under the old rule stays
// readable.
func TestUsernameRuleIsAppliedOnCreateRenewAndCcdApply(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setupCcdDir(t, nil)
	setFlag(t, ccdEnabled, true)
	setFlag(t, authByPassword, false)
	for _, bad := range []string{"ca", "../x", "-x", strings.Repeat("a", 65), ""} {
		if ok, msg, code := oAdmin.userCreateStatus(bad, ""); ok || code != http.StatusBadRequest || !strings.Contains(msg, "Username rule") {
			t.Errorf("create %q: ok=%v code=%d msg=%q", bad, ok, code, msg)
		}
		if _, err := oAdmin.userRenew(bad, 0); err == nil || !isInputError(err) || !strings.Contains(err.Error(), "Username rule") {
			t.Errorf("renew %q: %v", bad, err)
		}
		if ok, msg := oAdmin.modifyCcd(Ccd{User: bad, ClientAddress: "dynamic"}); ok || !strings.Contains(msg, "Username rule") {
			t.Errorf("ccd apply %q: ok=%v msg=%q", bad, ok, msg)
		}
	}
	// over HTTP: 400 with the rule
	rec := callHandler(oAdmin.userCreateHandler, formPost("/api/user/create", "ca", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved") {
		t.Errorf("POST create ca: %d %s", rec.Code, rec.Body.String())
	}
	if ok, msg, _ := oAdmin.userCreateStatus("alice", ""); !ok {
		t.Fatalf("create alice: %s", msg)
	}
	// a name that the old rule allowed and exists keeps its CCD readable
	if err := checkCcdUser("alice"); err != nil {
		t.Errorf("checkCcdUser(alice): %v", err)
	}
	if err := validateLegacyUsername("ann@example.org"); err != nil {
		t.Errorf("the legacy rule refuses ann@example.org: %v", err)
	}
	if err := validateLegacyUsername("../x"); err == nil {
		t.Error("the legacy rule accepts ../x")
	}
}

// ---------------------------------------------------------------------------------------------------------------
// L10 certificate lifetime

func TestValidateCertDays(t *testing.T) {
	for _, n := range []int{1, 30, 825, 3650} {
		if err := validateCertDays(n); err != nil {
			t.Errorf("%d refused: %v", n, err)
		}
	}
	for _, n := range []int{0, -1, 3651, 100000} {
		if err := validateCertDays(n); err == nil || !strings.Contains(err.Error(), "1 to 3650") {
			t.Errorf("%d accepted or message without the range: %v", n, err)
		}
	}
	// a process that never parsed the flags (a test) passes the default
	setFlag(t, certDays, 0)
	if got := easyrsaDaysArg(); got != "--days=825" {
		t.Errorf("default argument %q", got)
	}
	setFlag(t, certDays, 90)
	if got := easyrsaDaysArg(); got != "--days=90" {
		t.Errorf("argument %q", got)
	}
}

func readArgvLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no argv log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func issuanceLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, "build-client-full") || strings.Contains(l, "build-server-full") {
			out = append(out, l)
		}
	}
	return out
}

// Unit test, fake easyrsa: the argv of create and rotate carries --days=825 (the default) and --days=<n> when set.
func TestEasyrsaArgvCarriesDaysOnCreateAndRotate(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setFlag(t, authByPassword, false)
	logFile := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("EASYRSA_ARGV_LOG", logFile)
	setFlag(t, certDays, 825)
	ok, msg, _ := oAdmin.userCreateStatus("alice", "")
	if !ok || !strings.Contains(msg, "825 days") {
		t.Fatalf("create: ok=%v %q (the answer must show the lifetime)", ok, msg)
	}
	if err, _ := oAdmin.userRotate("alice", ""); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	issued := issuanceLines(readArgvLog(t, logFile))
	if len(issued) != 2 {
		t.Fatalf("%d issuance command lines, want 2 (create, rotate): %v", len(issued), issued)
	}
	for _, l := range issued {
		t.Logf("easyrsa argv: %s", l)
		if !strings.Contains(" "+l+" ", " --days=825 ") {
			t.Errorf("argv without --days=825: %s", l)
		}
		if strings.Index(l, "--days=") > strings.Index(l, "build-client-full") {
			t.Errorf("--days comes after the command, easy-rsa ignores it there: %s", l)
		}
	}
	setFlag(t, certDays, 90)
	if ok, msg, _ := oAdmin.userCreateStatus("bob", ""); !ok || !strings.Contains(msg, "90 days") {
		t.Fatalf("create bob: %v %q", ok, msg)
	}
	if last := issuanceLines(readArgvLog(t, logFile)); !strings.Contains(last[len(last)-1], "--days=90") {
		t.Errorf("last argv %s", last[len(last)-1])
	}
}

func certNotAfterDays(t *testing.T, file string) float64 {
	t.Helper()
	c, err := readCertFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return time.Until(c.NotAfter).Hours() / 24
}

// Real easy-rsa: create, rotate, renew and the server renew all pass --days, the certificates really have that
// lifetime and the answers say it.
func TestRealEasyrsaIssuesEveryCertificateWithTheLifetime(t *testing.T) {
	oAdmin, dir := setupRealPKI(t, "ec")
	useAdminAudit(t, "")
	logFile := filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("EASYRSA_ARGV_LOG", logFile)
	setFlag(t, certDays, 825)

	ok, msg, _ := oAdmin.userCreateStatus("bob", "")
	if !ok || !strings.Contains(msg, "825 days") {
		t.Fatalf("create: ok=%v %q", ok, msg)
	}
	if d := certNotAfterDays(t, filepath.Join(dir, "pki/issued/bob.crt")); d < 824 || d > 826 {
		t.Errorf("created certificate valid for %.1f days, want 825", d)
	}
	if err, _ := oAdmin.userRotate("bob", ""); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if d := certNotAfterDays(t, filepath.Join(dir, "pki/issued/bob.crt")); d < 824 || d > 826 {
		t.Errorf("rotated certificate valid for %.1f days, want 825", d)
	}
	res, err := oAdmin.userRenew("alice", 0)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !strings.Contains(res.Message, "lifetime 825 days") {
		t.Errorf("renew answer does not show the lifetime: %q", res.Message)
	}
	if d := certNotAfterDays(t, filepath.Join(dir, "pki/issued/alice.crt")); d < 824 || d > 826 {
		t.Errorf("renewed certificate valid for %.1f days, want 825", d)
	}
	sres, err := oAdmin.serverRenew()
	if err != nil {
		t.Fatalf("server renew: %v", err)
	}
	if !strings.Contains(sres.Message, "lifetime 825 days") {
		t.Errorf("server renew answer does not show the lifetime: %q", sres.Message)
	}
	issued := issuanceLines(readArgvLog(t, logFile))
	if len(issued) != 4 {
		t.Fatalf("%d issuance command lines, want 4 (create, rotate, renew, server renew): %v", len(issued), issued)
	}
	for _, l := range issued {
		t.Logf("easyrsa argv: %s", l)
		if !strings.Contains(" "+l+" ", " --days=825 ") {
			t.Errorf("argv without --days=825: %s", l)
		}
	}

	// another value reaches easy-rsa and the certificate
	setFlag(t, certDays, 30)
	if ok, msg, _ := oAdmin.userCreateStatus("carol", ""); !ok || !strings.Contains(msg, "30 days") {
		t.Fatalf("create carol: %v %q", ok, msg)
	}
	if d := certNotAfterDays(t, filepath.Join(dir, "pki/issued/carol.crt")); d < 29 || d > 31 {
		t.Errorf("certificate valid for %.1f days, want 30", d)
	}
}

// The audit line of a renewal carries the lifetime.
func TestRenewAuditLineCarriesTheLifetime(t *testing.T) {
	oAdmin, _ := setupRealPKI(t, "ec")
	a := useAdminAudit(t, "")
	setFlag(t, certDays, 825)
	rec := callHandler(oAdmin.userRenewHandler, adminReq(http.MethodPost, "/api/user/renew", url.Values{"username": {"alice"}, "grace_hours": {"0"}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("renew: %d %s", rec.Code, rec.Body.String())
	}
	data, _ := os.ReadFile(a.path)
	if !strings.Contains(string(data), "days=825") {
		t.Errorf("no days=825 in the audit trail: %s", data)
	}
	if msg, _ := decodeJSON(t, rec)["message"].(string); !strings.Contains(msg, "825 days") {
		t.Errorf("answer %q", msg)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// L7 disconnect

func disconnectRequest(username string) *http.Request {
	return authedRequest(http.MethodPost, "/api/user/disconnect", url.Values{"username": {username}}, "operator")
}

func TestDisconnectKillsTheSessionOfAConnectedUser(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, _ := setupFakeEasyrsa(t)
	setFlag(t, authByPassword, false)
	if ok, msg, _ := oAdmin.userCreateStatus("alice", ""); !ok {
		t.Fatal(msg)
	}
	if ok, msg, _ := oAdmin.userCreateStatus("bob", ""); !ok {
		t.Fatal(msg)
	}
	mgmt := startFakeMgmt(t, "alice", "bob")
	oAdmin.mgmtInterfaces = map[string]string{"srv": mgmt.addr}

	rec := callHandler(oAdmin.userDisconnectHandler, disconnectRequest("alice"))
	if rec.Code != http.StatusOK || rec.Body.String() != "disconnected alice (1 sessions)" {
		t.Fatalf("disconnect alice: %d %q", rec.Code, rec.Body.String())
	}
	if got := mgmt.killed(); len(got) != 1 || got[0] != "alice" {
		t.Errorf("kills sent: %v, want [alice]", got)
	}
	if mgmt.connected("alice") || !mgmt.connected("bob") {
		t.Errorf("alice connected=%v bob connected=%v, want false and true", mgmt.connected("alice"), mgmt.connected("bob"))
	}
	// a user with no session left: the end state is reached, zero sessions
	rec = callHandler(oAdmin.userDisconnectHandler, disconnectRequest("alice"))
	if rec.Code != http.StatusOK || rec.Body.String() != "disconnected alice (0 sessions)" {
		t.Errorf("second disconnect: %d %q", rec.Code, rec.Body.String())
	}
	// an unknown user is 400 and nothing is sent to OpenVPN
	before := len(mgmt.killed())
	rec = callHandler(oAdmin.userDisconnectHandler, disconnectRequest("ghost"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("unknown user: %d %q", rec.Code, rec.Body.String())
	}
	if len(mgmt.killed()) != before {
		t.Error("a kill was sent for an unknown user")
	}
	rec = callHandler(oAdmin.userDisconnectHandler, disconnectRequest("../etc"))
	if rec.Code != http.StatusBadRequest || len(mgmt.killed()) != before {
		t.Errorf("path-like name: %d, kills %v", rec.Code, mgmt.killed())
	}

	got := map[string][]string{}
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		if r.Action == "user.disconnect" {
			got[r.Target] = append(got[r.Target], r.Result+": "+r.Detail)
		}
	}
	if len(got["alice"]) != 2 || !strings.HasPrefix(got["alice"][0], "ok: 1 sessions disconnected") {
		t.Errorf("audit lines of alice: %v", got["alice"])
	}
	if len(got["ghost"]) != 1 || !strings.HasPrefix(got["ghost"][0], "fail:") {
		t.Errorf("audit line of ghost: %v", got["ghost"])
	}
}

func TestDisconnectCountsEverySessionOnEveryInterface(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setFlag(t, authByPassword, false)
	oAdmin.userCreateStatus("alice", "")
	first, second := startFakeMgmt(t), startFakeMgmt(t)
	first.reply = "SUCCESS: common name 'alice' found, 3 client(s) killed"
	second.reply = "SUCCESS: common name 'alice' found, 1 client(s) killed"
	oAdmin.mgmtInterfaces = map[string]string{"a": first.addr, "b": second.addr}
	rec := callHandler(oAdmin.userDisconnectHandler, disconnectRequest("alice"))
	if rec.Code != http.StatusOK || rec.Body.String() != "disconnected alice (4 sessions)" {
		t.Errorf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestDisconnectFailureIsTheRealErrorWith500(t *testing.T) {
	a := useAdminAudit(t, "")
	oAdmin, _ := setupFakeEasyrsa(t)
	setFlag(t, authByPassword, false)
	oAdmin.userCreateStatus("alice", "")

	refusing := startFakeMgmt(t, "alice")
	refusing.refuse = true
	oAdmin.mgmtInterfaces = map[string]string{"srv": refusing.addr}
	rec := callHandler(oAdmin.userDisconnectHandler, disconnectRequest("alice"))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "did not kill the session") || !strings.Contains(rec.Body.String(), "management kill is disabled") {
		t.Errorf("refused kill: %d %q", rec.Code, rec.Body.String())
	}

	oAdmin.mgmtInterfaces = map[string]string{"srv": deadMgmtAddr(t)}
	rec = callHandler(oAdmin.userDisconnectHandler, disconnectRequest("alice"))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "not reachable") {
		t.Errorf("dead interface: %d %q", rec.Code, rec.Body.String())
	}

	oAdmin.mgmtInterfaces = map[string]string{}
	rec = callHandler(oAdmin.userDisconnectHandler, disconnectRequest("alice"))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "no openvpn mgmt interface is configured") {
		t.Errorf("no interface: %d %q", rec.Code, rec.Body.String())
	}
	data, _ := os.ReadFile(a.path)
	if n := bytes.Count(data, []byte("user.disconnect")); n != 3 {
		t.Errorf("%d user.disconnect audit lines, want 3", n)
	}
	for _, r := range parseAuditLines(t, readAuditFile(t, a.path)) {
		if r.Action == "user.disconnect" && r.Result != "fail" {
			t.Errorf("a failed disconnect is audited as %q", r.Result)
		}
	}
}

// The same-origin POST check stays: nothing is sent to OpenVPN for a GET or a cross-site POST.
func TestDisconnectKeepsTheSameOriginPostCheck(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	setFlag(t, authByPassword, false)
	oAdmin.userCreateStatus("alice", "")
	mgmt := startFakeMgmt(t, "alice")
	oAdmin.mgmtInterfaces = map[string]string{"srv": mgmt.addr}

	rec := callHandler(oAdmin.userDisconnectHandler, httptest.NewRequest(http.MethodGet, "/api/user/disconnect?username=alice", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", rec.Code)
	}
	req := disconnectRequest("alice")
	req.Header.Set("Origin", "https://evil.example")
	if rec := callHandler(oAdmin.userDisconnectHandler, req); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d, want 403", rec.Code)
	}
	if len(mgmt.killed()) != 0 || !mgmt.connected("alice") {
		t.Errorf("a refused request still killed: %v", mgmt.killed())
	}
	req = disconnectRequest("alice")
	req.Header.Set("Origin", "http://"+req.Host)
	if rec := callHandler(oAdmin.userDisconnectHandler, req); rec.Code != http.StatusOK {
		t.Errorf("same-origin POST: %d, want 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// L1 password off the command line

// A wrapper in front of the fake openvpn-user that records every command line it gets.
func recordOpenvpnUserArgv(t *testing.T) string {
	t.Helper()
	db := setupFakeOpenvpnUser(t)
	fake := filepath.Join(filepath.Dir(db), "openvpn-user")
	logFile := filepath.Join(t.TempDir(), "ou-argv.log")
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + logFile + "\nexec " + fake + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "openvpn-user"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OU_ARGV_LOG", logFile)
	return db
}

func TestPasswordIsOnStdinNotOnTheCommandLine(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := recordOpenvpnUserArgv(t)
	logFile := os.Getenv("OU_ARGV_LOG")
	pw1, pw2, pw3 := randomSecret(t, "Pw1-"), randomSecret(t, "Pw2-"), randomSecret(t, "Pw3-")

	if ok, msg, _ := oAdmin.userCreateStatus("bob", pw1); !ok {
		t.Fatal(msg)
	}
	if got := dbRow(t, db, "bob"); got != pw1+"|false" {
		t.Fatalf("create stored %q: the password did not reach openvpn-user on stdin", got)
	}
	if err, msg := oAdmin.userChangePassword("bob", pw2); err != nil {
		t.Fatalf("change-password: %v %s", err, msg)
	}
	if got := dbRow(t, db, "bob"); got != pw2+"|false" {
		t.Fatalf("change-password stored %q", got)
	}
	if err, msg := oAdmin.userRotate("bob", pw3); err != nil {
		t.Fatalf("rotate: %v %s", err, msg)
	}
	if got := dbRow(t, db, "bob"); got != pw3+"|false" {
		t.Fatalf("rotate stored %q (the password of a rotation, replaced and checked with auth)", got)
	}

	// the check of a rotation (auth) sends the password on stdin as well
	if got := (&rotation{username: "bob"}).passwordNow(pw3); got != "new" {
		t.Fatalf("passwordNow: %q, want new", got)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	argvText := string(data)
	for _, pw := range []string{pw1, pw2, pw3} {
		if strings.Contains(argvText, pw) {
			t.Errorf("a password is on an openvpn-user command line:\n%s", argvText)
		}
	}
	if strings.Contains(argvText, "--password=") || strings.Contains(argvText, "--password ") {
		t.Errorf("--password is still used:\n%s", argvText)
	}
	for _, want := range []string{"create --db.path=", "change-password --db.path=", "auth --db.path="} {
		var line string
		for _, l := range strings.Split(argvText, "\n") {
			if strings.HasPrefix(l, want) {
				line = l
			}
		}
		if line == "" || !strings.HasSuffix(line, " --password-stdin") {
			t.Errorf("no %q command with --password-stdin at its end in:\n%s", want, argvText)
		}
	}
}

// A password that cannot be one line is refused before anything runs (a newline would end the stdin line early and
// store a different password).
func TestPasswordWithALineBreakIsRefused(t *testing.T) {
	oAdmin, _ := setupFakeEasyrsa(t)
	db := recordOpenvpnUserArgv(t)
	for _, pw := range []string{"first-line-secret\nsecond", "abcdefghijkl\r", "abcdefghijkl\x00x"} {
		ok, msg, code := oAdmin.userCreateStatus("bob", pw)
		if ok || code != http.StatusBadRequest || !strings.Contains(msg, "line break") {
			t.Errorf("create with %q: ok=%v code=%d %q", pw, ok, code, msg)
		}
		if _, err := runOpenvpnUserPassword("create", pw, "--user=bob"); err == nil || !isInputError(err) {
			t.Errorf("runOpenvpnUserPassword accepted %q: %v", pw, err)
		}
	}
	if got := dbRow(t, db, "bob"); got != "" {
		t.Errorf("a row was written: %q", got)
	}
}

// The proof the card asks for: a stub that sleeps while it runs, its /proc/<pid>/cmdline (and that of every process on
// the machine) is read while the panel's create is in flight. With --password the same probe sees the secret.
func TestPasswordNeverAppearsInProcCmdlineDuringCreate(t *testing.T) {
	if _, err := os.Stat("/proc/self/cmdline"); err != nil {
		t.Skip("no /proc")
	}
	dir := t.TempDir()
	pidFile, goFile, stdinFile := filepath.Join(dir, "pid"), filepath.Join(dir, "go"), filepath.Join(dir, "stdin")
	// reads the password line when --password-stdin is given, records its pid, then sleeps until the test says go
	stub := `#!/bin/sh
echo $$ > ` + pidFile + `
case " $* " in *" --password-stdin "*) IFS= read -r pw; printf '%s' "$pw" > ` + stdinFile + ` ;; esac
while [ ! -f ` + goFile + ` ]; do sleep 0.05; done
`
	if err := os.WriteFile(filepath.Join(dir, "openvpn-user"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	setFlag(t, authDatabase, filepath.Join(dir, "users.db"))
	pw := randomSecret(t, "Probe-Secret-")

	waitFile := func(path string) string {
		t.Helper()
		for i := 0; i < 200; i++ {
			if b, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(b)) > 0 {
				return strings.TrimSpace(string(b))
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s did not appear", path)
		return ""
	}
	cmdlines := func() (own string, all string) {
		pid := strings.TrimSpace(waitFile(pidFile))
		b, err := os.ReadFile("/proc/" + pid + "/cmdline")
		if err != nil {
			t.Fatalf("the stub is not running (pid %s): %v", pid, err)
		}
		own = strings.ReplaceAll(string(b), "\x00", " ")
		entries, _ := filepath.Glob("/proc/[0-9]*/cmdline")
		var sb strings.Builder
		for _, e := range entries {
			if b, err := os.ReadFile(e); err == nil {
				sb.WriteString(strings.ReplaceAll(string(b), "\x00", " "))
				sb.WriteString("\n")
			}
		}
		return own, sb.String()
	}

	// the panel's call: runs while the stub sleeps
	var wg sync.WaitGroup
	var runErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, runErr = runOpenvpnUserPassword("create", pw, "--user=bob")
	}()
	waitFile(stdinFile)
	own, all := cmdlines()
	t.Logf("cmdline of the running create: %q", own)
	if !strings.Contains(own, "openvpn-user create") || !strings.Contains(own, "--password-stdin") {
		t.Errorf("not the create command: %q", own)
	}
	if strings.Contains(own, pw) || strings.Contains(all, pw) {
		t.Errorf("the password is in a /proc/<pid>/cmdline while create runs")
	}
	if got := waitFile(stdinFile); got != pw {
		t.Errorf("the stub read %q from stdin, want the password", got)
	}
	if err := os.WriteFile(goFile, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if runErr != nil {
		t.Fatalf("create: %v", runErr)
	}

	// control: the old form is visible to the same probe, so the probe can fail
	for _, f := range []string{pidFile, goFile, stdinFile} {
		_ = os.Remove(f)
	}
	cmd := exec.Command(filepath.Join(dir, "openvpn-user"), "create", "--user=bob", "--password="+pw)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	own, _ = cmdlines()
	if !strings.Contains(own, pw) {
		t.Errorf("control: the probe does not see --password= on the command line (%q): the proof above proves nothing", own)
	}
	if err := os.WriteFile(goFile, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
}

// ---------------------------------------------------------------------------------------------------------------
// W1: the slave compose file carries the Telegram settings

var composeTelegramKey = regexp.MustCompile(`(?m)^\s+(OVPN_TELEGRAM_(?:ENABLED|BOT_TOKEN|BOT_TOKEN_FILE|CHAT_ID|THREAD_ID|API_BASE|ALLOW_HTTP|INCLUDE_ADDRESS)):`)

func composeServiceBlock(t *testing.T, text, service string) string {
	t.Helper()
	start := strings.Index(text, "\n  "+service+":\n")
	if start < 0 {
		t.Fatalf("no service %s", service)
	}
	rest := text[start+1:]
	end := regexp.MustCompile(`(?m)^(  [a-z][a-z-]*:|[a-z]+:)\s*$`).FindStringIndex(rest[len(service)+3:])
	if end == nil {
		return rest
	}
	return rest[:len(service)+3+end[0]]
}

func TestComposeFilesNameAllEightTelegramKeysOnBothServices(t *testing.T) {
	for _, file := range []string{"docker-compose.yaml", "docker-compose-slave.yaml"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, service := range []string{"openvpn", "ovpn-admin"} {
			keys := map[string]bool{}
			for _, m := range composeTelegramKey.FindAllStringSubmatch(composeServiceBlock(t, string(data), service), -1) {
				keys[m[1]] = true
			}
			if len(keys) != 8 {
				t.Errorf("%s service %s names %d of 8 OVPN_TELEGRAM_* keys: %v", file, service, len(keys), keys)
			}
		}
	}
}
