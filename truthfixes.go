package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

// ---------------------------------------------------------------------------------------------------------------
// certificate lifetime (--cert.days)

const (
	defaultCertDays = 825
	minCertDays     = 1
	maxCertDays     = 3650
)

var certDays = kingpin.Flag("cert.days", "validity in days of every certificate that easy-rsa issues here (new client, rotate, renew, server renew), 1 to 3650; the kubernetes.secrets backend issues with --client-cert.expiration-days").Default(strconv.Itoa(defaultCertDays)).Envar("OVPN_CERT_DAYS").Int()

// validateCertDays refuses a lifetime outside 1..3650 days.
func validateCertDays(n int) error {
	if n < minCertDays || n > maxCertDays {
		return fmt.Errorf("--cert.days (OVPN_CERT_DAYS) is %d: it must be a whole number of days from %d to %d", n, minCertDays, maxCertDays)
	}
	return nil
}

// effectiveCertDays is the lifetime passed to easy-rsa. 0 means the flag was never parsed (a test process): the
// default. A real run refuses 0 at start (validateCertDays).
func effectiveCertDays() int {
	if *certDays == 0 {
		return defaultCertDays
	}
	return *certDays
}

// easyrsaDaysArg is the easy-rsa option that sets the validity of the certificate a command issues. It goes before
// the command: easyrsa --batch --days=825 build-client-full <name> nopass.
func easyrsaDaysArg() string {
	return "--days=" + strconv.Itoa(effectiveCertDays())
}

// issuedLifetimeNote is " days=<n>" for the audit line of an issuance by easy-rsa, "" on the kubernetes backend
// (it signs in Go with --client-cert.expiration-days).
func issuedLifetimeNote() string {
	if *storageBackend == "kubernetes.secrets" {
		return ""
	}
	return " days=" + strconv.Itoa(effectiveCertDays())
}

// ---------------------------------------------------------------------------------------------------------------
// user names

const usernameMaxBytes = 64

// reservedUsernames are the names of files and entries easy-rsa and OpenVPN keep in the PKI (ca.crt, server.crt, dh.pem,
// ta.key, crl.pem, index.txt, users.db); a client with one of them would collide with or shadow them. Compared
// without regard to case.
var reservedUsernames = []string{"ca", "server", "dh", "ta", "crl", "index", "users"}

func isUsernameAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// validateUsername is the rule for the name of a client certificate: 1 to 64 bytes, the first character a letter
// or a digit, the others letters, digits, '.', '_' or '-', and none of the reserved names. The error names the rule
// that failed and never repeats the value.
func validateUsername(username string) error {
	if n := len(username); n < 1 || n > usernameMaxBytes {
		return inputError{fmt.Sprintf("Username rule: the name must be 1 to %d bytes long", usernameMaxBytes)}
	}
	if !isUsernameAlnum(username[0]) {
		return inputError{"Username rule: the first character must be a letter or a digit (A-Z, a-z, 0-9)"}
	}
	for i := 1; i < len(username); i++ {
		if c := username[i]; !isUsernameAlnum(c) && c != '.' && c != '_' && c != '-' {
			return inputError{"Username rule: after the first character only letters, digits, '.', '_' and '-' are allowed"}
		}
	}
	for _, reserved := range reservedUsernames {
		if strings.EqualFold(username, reserved) {
			return inputError{fmt.Sprintf("Username rule: the name is reserved (%s)", strings.Join(reservedUsernames, ", "))}
		}
	}
	return nil
}

// usernameLegacyRegexp is the rule before v0.1.13. It still decides what the panel accepts for a user that exists
// already (reading a CCD, the audit lines of a password re-hash): a certificate issued under the old rule, say
// "ann@example.org", stays manageable. Create, renew and the CCD apply path use validateUsername.
const usernameLegacyRegexp = `^([a-zA-Z0-9_.\-@])+$`

var usernameLegacyRe = regexp.MustCompile(usernameLegacyRegexp)

func validateLegacyUsername(username string) error {
	if usernameLegacyRe.MatchString(username) && usernameIsPathSafe(username) {
		return nil
	}
	return inputError{fmt.Sprintf("Username can only contains %s and must not be \".\" or \"..\"", usernameLegacyRegexp)}
}

// ---------------------------------------------------------------------------------------------------------------
// password for openvpn-user on stdin

// runOpenvpnUserPassword runs an openvpn-user command that takes a password (create, change-password, auth) with the
// password as one line on stdin (--password-stdin) instead of --password=<value>: an argument sits in
// /proc/<pid>/cmdline for as long as the process lives. A password with a line break or a NUL byte cannot be sent as
// one line and is refused before anything runs.
func runOpenvpnUserPassword(command, password string, args ...string) (string, error) {
	if err := checkPasswordIsOneLine(password); err != nil {
		return "", err
	}
	return runOpenvpnUserStdin(command, password+"\n", append(append([]string{}, args...), "--password-stdin")...)
}

func checkPasswordIsOneLine(password string) error {
	if strings.ContainsAny(password, "\r\n\x00") {
		return inputError{"Password must not contain a line break or a NUL byte"}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------
// disconnect

// userDisconnect ends every session of username on every management interface and returns how many sessions
// OpenVPN reported killed. An unknown user is an inputError (HTTP 400); a failing management call is the real error
// (HTTP 500), with the number of sessions that were ended before it.
func (oAdmin *OvpnAdmin) userDisconnect(username string) (int, error) {
	if !(usernameIsPathSafe(username) && checkUserExist(username)) {
		return 0, inputError{fmt.Sprintf("user %q not found", username)}
	}
	return oAdmin.mgmtKillUserCounted(username)
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	_ = r.ParseForm()
	username := r.FormValue("username")
	n, err := oAdmin.userDisconnect(username)
	detail := fmt.Sprintf("%d sessions disconnected", n)
	if err != nil {
		detail = auditErrDetail(err, "")
		if n > 0 {
			detail += fmt.Sprintf(" (%d sessions were disconnected before the failure)", n)
		}
	}
	adminAudit.fromRequest(r, auditActUserDisconnect, username, err == nil, detail)
	if err != nil {
		http.Error(w, err.Error(), userOpErrorStatus(err))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "disconnected %s (%d sessions)", username, n)
}
