package main

// Certificate lifecycle: expiry scan and notifications, and the safe renewal of client and server certificates
// (filesystem backend). See the handlers at the end for the API and the comments of userRenewLocked and
// serverRenewLocked for the order of the steps and why it is that order.
//
// Everything that writes to the PKI holds createUserMutex, the lock of create, revoke, rotate and delete.
// The functions whose name ends in Locked expect the caller to hold it.

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

// certNow is the clock of everything in this file. Tests move it.
var certNow = func() time.Time { return time.Now() }

var (
	certScanFirstDelay = 5 * time.Minute
	certScanInterval   = 24 * time.Hour
	certGraceInterval  = 15 * time.Minute
)

const (
	auditActUserRenew          = "user.renew"
	auditActUserRenewSupersede = "user.renew.supersede"
	auditActCertAutoRevoke     = "cert.auto_revoke"
	auditActCertNotify         = "cert.notify"
	auditActCertScan           = "cert.scan"

	certKindClient = "client"
	certKindServer = "server"
	certKindCA     = "ca"

	defaultGraceHours = 72
	maxGraceHours     = 720

	serverCertName = "server"

	// the base names of the files that exist only while an operation runs: the new certificate before it is
	// verified, and a superseded certificate while easy-rsa revokes it. The scan ignores them.
	certTmpSuffix    = ".renew-tmp"
	certStagedMarker = ".superseded-"

	k8sRenewUnsupported = "renewal is not supported on the kubernetes backend in this release; use rotate"
)

var (
	ovpnCertsExpiring30d = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_certs_expiring_30d",
		Help: "certificates (clients, server and CA) that expire within 30 days, expired ones included",
	})
	ovpnCertsExpiring7d = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_certs_expiring_7d",
		Help: "certificates (clients, server and CA) that expire within 7 days, expired ones included",
	})
)

func registerCertMetrics(r *prometheus.Registry) {
	r.MustRegister(ovpnCertsExpiring30d)
	r.MustRegister(ovpnCertsExpiring7d)
}

// ---------------------------------------------------------------------------------------------------------------
// files

// atomicWriteFile replaces path with data: a temporary file in the same directory, written, synced and renamed.
// A reader sees the old or the new content, never a part of it.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func copyFileMode(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// ---------------------------------------------------------------------------------------------------------------
// certificates

type certInfo struct {
	Name     string
	Kind     string
	Serial   string // upper case hex, even number of digits, like openssl prints it
	NotAfter time.Time
}

// daysLeft is floored: 8.9 days left is 8, an expired certificate is negative.
func (c certInfo) daysLeft(now time.Time) int {
	return int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
}

func serialHex(cert *x509.Certificate) string {
	s := strings.ToUpper(cert.SerialNumber.Text(16))
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}

// normSerial makes serials of index.txt, file names and certificates comparable.
func normSerial(s string) string {
	s = strings.ToUpper(strings.TrimLeft(strings.TrimSpace(s), "0"))
	if s == "" {
		return "0"
	}
	return s
}

func readCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, b := range pemBlocks(data) {
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
	return nil, fmt.Errorf("%s holds no certificate", path)
}

func certKindOf(name string, cert *x509.Certificate) string {
	if name == serverCertName {
		return certKindServer
	}
	hasServer, hasClient := false, false
	for _, u := range cert.ExtKeyUsage {
		hasServer = hasServer || u == x509.ExtKeyUsageServerAuth
		hasClient = hasClient || u == x509.ExtKeyUsageClientAuth
	}
	if hasServer && !hasClient {
		return certKindServer
	}
	return certKindClient
}

func isTemporaryCertBase(base string) bool {
	return strings.Contains(base, certTmpSuffix) || strings.Contains(base, certStagedMarker)
}

// scanCertsLocked lists every certificate of pki/issued (one per file, so one per common name: a superseded
// certificate is not in issued/) and pki/ca.crt. A certificate that index.txt says is revoked is left out.
// The caller holds createUserMutex, so that it never sees the files of a renewal half way.
func scanCertsLocked() ([]certInfo, error) {
	revoked := map[string]bool{}
	if lines, err := readIndexTxt(); err == nil {
		for _, l := range lines {
			if l.Flag == "R" {
				revoked[normSerial(l.SerialNumber)] = true
			}
		}
	}
	var out []certInfo
	entries, err := os.ReadDir(pkiFile("issued"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range entries {
		base, isCrt := strings.CutSuffix(e.Name(), ".crt")
		if !isCrt || e.IsDir() || isTemporaryCertBase(base) {
			continue
		}
		cert, err := readCertFile(pkiFile("issued", e.Name()))
		if err != nil {
			log.Warnf("certificate scan: %s: %v", e.Name(), err)
			continue
		}
		serial := serialHex(cert)
		if revoked[normSerial(serial)] {
			continue
		}
		out = append(out, certInfo{Name: base, Kind: certKindOf(base, cert), Serial: serial, NotAfter: cert.NotAfter.UTC()})
	}
	if cert, err := readCertFile(pkiFile("ca.crt")); err == nil {
		out = append(out, certInfo{Name: certKindCA, Kind: certKindCA, Serial: serialHex(cert), NotAfter: cert.NotAfter.UTC()})
	} else if !os.IsNotExist(err) {
		log.Warnf("certificate scan: ca.crt: %v", err)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NotAfter.Equal(out[j].NotAfter) {
			return out[i].NotAfter.Before(out[j].NotAfter)
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (oAdmin *OvpnAdmin) scanCerts() ([]certInfo, error) {
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()
	return scanCertsLocked()
}

func setCertGauges(certs []certInfo, now time.Time) (n30, n7 int) {
	for _, c := range certs {
		if !c.NotAfter.After(now.Add(30 * 24 * time.Hour)) {
			n30++
		}
		if !c.NotAfter.After(now.Add(7 * 24 * time.Hour)) {
			n7++
		}
	}
	ovpnCertsExpiring30d.Set(float64(n30))
	ovpnCertsExpiring7d.Set(float64(n7))
	return n30, n7
}

// refreshCertGauges recomputes the two gauges unless a change of the PKI is running (the next refresh follows).
func (oAdmin *OvpnAdmin) refreshCertGauges() {
	if !oAdmin.createUserMutex.TryLock() {
		return
	}
	defer oAdmin.createUserMutex.Unlock()
	if certs, err := scanCertsLocked(); err == nil {
		setCertGauges(certs, certNow())
	}
}

// ---------------------------------------------------------------------------------------------------------------
// state files

type renewalEntry struct {
	OldSerial   string `json:"oldSerial"`
	OldNotAfter string `json:"oldNotAfter"`
	GraceEndsAt string `json:"graceEndsAt"`
	NewSerial   string `json:"newSerial"`
}

func renewalsPath() string        { return pkiFile("renewals.json") }
func serverRenewalPath() string   { return pkiFile("server-renewal.json") }
func certNotifyStatePath() string { return pkiFile("cert-notify-state.json") }

func supersededDir(name, serial string) string {
	return pkiFile("superseded", name+"-"+normSerial(serial))
}

// loadRenewals reads renewals.json. A file that is missing is an empty set; one that cannot be read or parsed is
// an error and never an empty set: a revoke that goes on without it would leave a superseded certificate valid.
func loadRenewals() (map[string]renewalEntry, error) {
	data, err := os.ReadFile(renewalsPath())
	if os.IsNotExist(err) {
		return map[string]renewalEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading renewals.json: %w", err)
	}
	m := map[string]renewalEntry{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("renewals.json is not valid: %w", err)
	}
	if m == nil {
		m = map[string]renewalEntry{}
	}
	return m, nil
}

func saveRenewals(m map[string]renewalEntry) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(renewalsPath(), append(data, '\n'), 0600)
}

// supersededSerials is the set of serials that renewals.json lists as superseded (normalised).
func supersededSerials() (map[string]bool, error) {
	m, err := loadRenewals()
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(m))
	for _, e := range m {
		set[normSerial(e.OldSerial)] = true
	}
	return set, nil
}

// supersededSerialsQuiet is supersededSerials for the readers that only choose what to show.
func supersededSerialsQuiet() map[string]bool {
	set, err := supersededSerials()
	if err != nil {
		log.Warnf("renewals.json: %v", err)
		return map[string]bool{}
	}
	return set
}

type serverRenewalState struct {
	RestartPending    bool   `json:"restartPending"`
	PreviousSerial    string `json:"previousSerial,omitempty"`
	PreviousNotAfter  string `json:"previousNotAfter,omitempty"`
	PreviousBackupDir string `json:"previousBackupDir,omitempty"`
	NewSerial         string `json:"newSerial,omitempty"`
	NewNotAfter       string `json:"newNotAfter,omitempty"`
	RenewedAt         string `json:"renewedAt,omitempty"`
	ConfirmedAt       string `json:"confirmedAt,omitempty"`
}

func loadServerRenewal() (serverRenewalState, error) {
	var st serverRenewalState
	data, err := os.ReadFile(serverRenewalPath())
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("reading server-renewal.json: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("server-renewal.json is not valid: %w", err)
	}
	return st, nil
}

func saveServerRenewal(st serverRenewalState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(serverRenewalPath(), append(data, '\n'), 0600)
}

// ---------------------------------------------------------------------------------------------------------------
// index.txt helpers

// currentIndexLine is the line of the certificate that a user has now: the newest valid one, not a superseded one.
// A user whose lines are all revoked or expired gets the last of them.
func currentIndexLine(lines []indexTxtLine, username string, skip map[string]bool) (indexTxtLine, bool) {
	best, found, bestRank := indexTxtLine{}, false, -1
	for _, l := range lines {
		if l.DistinguishedName != "/CN="+username {
			continue
		}
		if r := indexLineRank(l, skip); r >= bestRank {
			best, found, bestRank = l, true, r
		}
	}
	return best, found
}

// indexLineRank orders the lines of one common name: a superseded certificate last, then revoked, expired, valid.
func indexLineRank(l indexTxtLine, skip map[string]bool) int {
	if skip[normSerial(l.SerialNumber)] {
		return 0
	}
	switch l.Flag {
	case "V":
		return 3
	case "E":
		return 2
	}
	return 1
}

// withoutSuperseded drops the index lines of certificates that a renewal replaced and that are valid for their
// grace period: they are not a second user. Every other line, duplicates of a name included, is passed through.
func withoutSuperseded(lines []indexTxtLine, skip map[string]bool) []indexTxtLine {
	if len(skip) == 0 {
		return lines
	}
	out := make([]indexTxtLine, 0, len(lines))
	for _, l := range lines {
		if skip[normSerial(l.SerialNumber)] {
			continue
		}
		out = append(out, l)
	}
	return out
}

// retireIndexDN renames the revoked line of serial from /CN=name to /CN=REVOKED-name-<id>, as rotate does with a
// replaced certificate: the name then belongs to the current certificate alone. A line that is not there, not
// revoked or not of that name is left alone.
func retireIndexDN(name, serial string) error {
	lines, err := readIndexTxt()
	if err != nil {
		return err
	}
	for i := range lines {
		if normSerial(lines[i].SerialNumber) == normSerial(serial) && lines[i].DistinguishedName == "/CN="+name && lines[i].Flag == "R" {
			lines[i].DistinguishedName = "/CN=REVOKED-" + name + "-" + strings.ReplaceAll(uuid.New().String(), "-", "")
			return atomicWriteFile(*indexTxtPath, []byte(renderIndexTxt(lines)), 0644)
		}
	}
	return nil
}

func indexFlagOf(lines []indexTxtLine, serial string) (string, bool) {
	for _, l := range lines {
		if normSerial(l.SerialNumber) == normSerial(serial) {
			return l.Flag, true
		}
	}
	return "", false
}

// ensureUniqueSubjectNo makes sure that the CA database accepts a second certificate with the same subject (the
// old one stays valid during the grace). easy-rsa writes "unique_subject = no" itself; this only repairs a file
// that says otherwise.
func ensureUniqueSubjectNo() error {
	p := pkiFile("index.txt.attr")
	data, err := os.ReadFile(p)
	if err == nil && regexp.MustCompile(`(?m)^\s*unique_subject\s*=\s*no\s*$`).Match(data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return atomicWriteFile(p, []byte("unique_subject = no\n"), 0644)
}

// crlMissingRevoked lists the serials that index.txt marks revoked and the CRL does not list.
func crlMissingRevoked() ([]string, error) {
	lines, err := readIndexTxt()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(pkiFile("crl.pem"))
	if err != nil {
		return nil, fmt.Errorf("reading the CRL: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("crl.pem holds no PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the CRL: %w", err)
	}
	listed := map[string]bool{}
	for _, e := range crl.RevokedCertificateEntries {
		listed[normSerial(e.SerialNumber.Text(16))] = true
	}
	var missing []string
	for _, l := range lines {
		if l.Flag == "R" && !listed[normSerial(l.SerialNumber)] {
			missing = append(missing, normSerial(l.SerialNumber))
		}
	}
	return missing, nil
}

// publishCrl rebuilds the CRL and checks that it lists every serial of serials.
func publishCrl(serials ...string) error {
	if err := easyrsaGenCrl(); err != nil {
		return fmt.Errorf("the CRL could not be rebuilt: %w", err)
	}
	if err := crlFix(); err != nil {
		return fmt.Errorf("the CRL could not be made readable for OpenVPN: %w", err)
	}
	for _, s := range serials {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			return fmt.Errorf("the serial %q is not hexadecimal", s)
		}
		if listed, entries, err := crlHasSerial(n); err != nil {
			return err
		} else if !listed {
			return fmt.Errorf("serial %s is not in the new CRL (%d entries)", s, entries)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------
// a change of the PKI that can be undone

// pkiTx records what a renewal changes so that a failing step can put everything back: files that were written
// (undone by restoring their content), files that were moved (moved back), files that were created (removed).
type pkiTx struct {
	undo         []func() error
	crlPublished bool
}

func (tx *pkiTx) addUndo(f func() error) { tx.undo = append(tx.undo, f) }

// snapshotFile restores path as it is now (content, or its absence) on rollback.
func (tx *pkiTx) snapshotFile(path string, perm os.FileMode) {
	data, err := os.ReadFile(path)
	existed := err == nil
	tx.addUndo(func() error {
		if existed {
			return atomicWriteFile(path, data, perm)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}

// removeOnRollback removes the files if they exist then; for what an operation creates.
func (tx *pkiTx) removeOnRollback(paths ...string) {
	for _, p := range paths {
		p := p
		tx.addUndo(func() error {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		})
	}
}

func (tx *pkiTx) rename(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	tx.addUndo(func() error {
		if _, err := os.Stat(to); os.IsNotExist(err) {
			return nil
		}
		return os.Rename(to, from)
	})
	return nil
}

// rollback runs the undo steps, last first, and rebuilds the CRL when one was published.
func (tx *pkiTx) rollback() error {
	var failed []string
	for i := len(tx.undo) - 1; i >= 0; i-- {
		if err := tx.undo[i](); err != nil {
			log.Errorf("renewal rollback: %v", err)
			failed = append(failed, err.Error())
		}
	}
	tx.undo = nil
	if tx.crlPublished {
		if err := rebuildCrl(); err != nil {
			log.Errorf("renewal rollback: rebuilding the CRL: %v", err)
			failed = append(failed, "rebuilding the CRL: "+err.Error())
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------------------------------------------
// revoke by file

// revokedFilesOf are the files that easy-rsa creates under pki/revoked for a revoked certificate. Their names
// keep the leading zero of the serial (a rollback that looked for another name would leave them, and the next
// revoke of the same certificate would be refused).
func revokedFilesOf(serial string) []string {
	u := normSerialFile(serial)
	return []string{
		pkiFile("revoked", "certs_by_serial", u+".crt"),
		pkiFile("revoked", "private_by_serial", u+".key"),
		pkiFile("revoked", "reqs_by_serial", u+".req"),
	}
}

// revokeCertByFile revokes the certificate in certFile, whatever its common name is shared with. easy-rsa revokes
// what it finds in pki/issued/<base>.crt, so the certificate (and the key and request, when given) is copied to a
// base of its own, "<name>.superseded-<serial>", which no other certificate has; easy-rsa then revokes that file,
// and the serial it writes to index.txt is the one of the file. The serial of the file must be the expected one
// and the index must carry it: a file that is not the certificate that is meant to be revoked is refused. The
// copies are removed again. It is idempotent: a serial that index.txt marks revoked already is not revoked again.
// It does not rebuild the CRL. The caller holds createUserMutex.
func revokeCertByFile(tx *pkiTx, name, serial, certFile, keyFile, reqFile string) error {
	lines, err := readIndexTxt()
	if err != nil {
		return err
	}
	flag, found := indexFlagOf(lines, serial)
	if !found {
		return fmt.Errorf("serial %s is not in index.txt", serial)
	}
	if flag == "R" {
		return nil
	}
	cert, err := readCertFile(certFile)
	if err != nil {
		return fmt.Errorf("the certificate file to revoke: %w", err)
	}
	if normSerial(serialHex(cert)) != normSerial(serial) {
		return fmt.Errorf("%s holds serial %s, not %s: it is not revoked", certFile, serialHex(cert), serial)
	}

	base := name + certStagedMarker + normSerial(serial)
	type staged struct{ src, dst string }
	files := []staged{{certFile, pkiFile("issued", base+".crt")}}
	if keyFile != "" && fRegularFile(keyFile) {
		files = append(files, staged{keyFile, pkiFile("private", base+".key")})
	}
	if reqFile != "" && fRegularFile(reqFile) {
		files = append(files, staged{reqFile, pkiFile("reqs", base+".req")})
	}
	leftovers := []string{pkiFile("inline", base+".inline"), pkiFile("inline", "private", base+".inline")}
	cleanup := func() {
		for _, f := range files {
			_ = os.Remove(f.dst)
		}
		for _, p := range leftovers {
			_ = os.Remove(p)
		}
	}
	for _, f := range files {
		if fExist(f.dst) {
			cleanup()
			return fmt.Errorf("%s exists already", f.dst)
		}
	}
	for _, f := range files {
		if err := copyFileMode(f.src, f.dst, 0600); err != nil {
			cleanup()
			return err
		}
	}
	// what easy-rsa creates for a revoked certificate is removed again when this is rolled back
	if tx != nil {
		tx.removeOnRollback(revokedFilesOf(serial)...)
	}
	_, runErr := runCommand(*easyrsaDirPath, "yes\n", *easyrsaBinPath, "revoke", base)
	cleanup()
	after, aerr := readIndexTxt()
	if aerr != nil {
		return aerr
	}
	if f, _ := indexFlagOf(after, serial); f != "R" {
		if runErr != nil {
			return fmt.Errorf("easyrsa revoke failed: %w", runErr)
		}
		return fmt.Errorf("serial %s is not marked revoked in index.txt after the revoke", serial)
	}
	if runErr != nil {
		log.Warnf("easyrsa revoke %s failed after it wrote index.txt: %v", base, runErr)
	}
	return nil
}

// revokeSupersededIndexLocked revokes the superseded certificate of name by its file (index.txt only, no CRL)
// and gives its index line a retired name. The certificate file is the one in the superseded directory, or the
// copy that easy-rsa keeps in certs_by_serial. It returns the entry that it revoked, nil when there is none.
func revokeSupersededIndexLocked(tx *pkiTx, name string, e renewalEntry) error {
	dir := supersededDir(name, e.OldSerial)
	certFile := filepath.Join(dir, name+".crt")
	if !fRegularFile(certFile) {
		certFile = pkiFile("certs_by_serial", normSerialFile(e.OldSerial)+".pem")
	}
	if err := revokeCertByFile(tx, name, e.OldSerial, certFile, filepath.Join(dir, name+".key"), filepath.Join(dir, name+".req")); err != nil {
		return err
	}
	return retireIndexDN(name, e.OldSerial)
}

// normSerialFile is the serial the way easy-rsa names certs_by_serial/<serial>.pem: upper case, even length.
func normSerialFile(serial string) string {
	s := normSerial(serial)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}

func removeSupersededDir(name, serial string) {
	dir := supersededDir(name, serial)
	if !strings.HasPrefix(dir, pkiFile("superseded")+string(os.PathSeparator)) {
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		log.Warnf("removing %s: %v", dir, err)
	}
}

// ---------------------------------------------------------------------------------------------------------------
// verifying a new certificate

// verifyIssued checks a certificate that was just issued before anything is retired for it: it chains to the CA
// for the use it is meant for, its public key is the one of the private key next to it, its common name is the
// expected one, it is valid for at least one more day, and index.txt lists it as valid.
func verifyIssued(certFile, keyFile, wantCN string, usage x509.ExtKeyUsage, now time.Time) (*x509.Certificate, error) {
	cert, err := readCertFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("the new certificate cannot be read: %w", err)
	}
	caData, err := os.ReadFile(pkiFile("ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("the CA certificate cannot be read: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("ca.crt holds no certificate")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, fmt.Errorf("the new certificate does not chain to the CA: %w", err)
	}
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("the new private key cannot be read: %w", err)
	}
	matched := false
	for _, b := range pemBlocks(keyData) {
		if !strings.HasSuffix(b.Type, "PRIVATE KEY") {
			continue
		}
		if encryptedKeyBlock(b) {
			return nil, errors.New("the new private key is encrypted")
		}
		var key any
		if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
			key = k
		} else if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
			key = k
		} else if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
			key = k
		}
		if s, ok := key.(interface{ Public() crypto.PublicKey }); ok {
			if p, ok := s.Public().(interface{ Equal(crypto.PublicKey) bool }); ok && p.Equal(cert.PublicKey) {
				matched = true
			}
		}
	}
	if !matched {
		return nil, errors.New("the public key of the new certificate is not the one of the new private key")
	}
	if cert.Subject.CommonName != wantCN {
		return nil, fmt.Errorf("the new certificate has the common name %q, not %q", cert.Subject.CommonName, wantCN)
	}
	if cert.NotAfter.Before(now.Add(24 * time.Hour)) {
		return nil, fmt.Errorf("the new certificate expires %s, less than a day from now", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	lines, err := readIndexTxt()
	if err != nil {
		return nil, err
	}
	if flag, found := indexFlagOf(lines, serialHex(cert)); !found || flag != "V" {
		return nil, fmt.Errorf("index.txt does not list serial %s as valid", serialHex(cert))
	}
	return cert, nil
}

// ---------------------------------------------------------------------------------------------------------------
// client renewal

type renewResult struct {
	Message          string
	OldSerial        string
	NewSerial        string
	GraceEndsAt      time.Time
	RevokedAtOnce    bool
	SupersededSerial string // a certificate of an earlier renewal that was revoked at once by this one
}

// tmpFiles are the files of the new certificate before it takes the place of the old one.
type certFileSet struct{ crt, key, req, inline, inlinePrivate string }

func certFilesOf(base string) certFileSet {
	return certFileSet{
		crt:           pkiFile("issued", base+".crt"),
		key:           pkiFile("private", base+".key"),
		req:           pkiFile("reqs", base+".req"),
		inline:        pkiFile("inline", base+".inline"),
		inlinePrivate: pkiFile("inline", "private", base+".inline"),
	}
}

func (s certFileSet) all() []string { return []string{s.crt, s.key, s.req, s.inline, s.inlinePrivate} }

func parseGraceHours(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultGraceHours, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > maxGraceHours || strings.TrimLeft(raw, "0123456789") != "" {
		return 0, inputError{fmt.Sprintf("grace_hours must be a whole number from 0 to %d", maxGraceHours)}
	}
	return n, nil
}

// userRenew issues a new certificate for username, keeps the old one valid for graceHours (0: revokes it at once)
// and answers what is true. See userRenewLocked.
func (oAdmin *OvpnAdmin) userRenew(username string, graceHours int) (renewResult, error) {
	if graceHours < 0 || graceHours > maxGraceHours {
		return renewResult{}, inputError{fmt.Sprintf("grace_hours must be a whole number from 0 to %d", maxGraceHours)}
	}
	if *storageBackend == "kubernetes.secrets" {
		return renewResult{}, inputError{k8sRenewUnsupported}
	}
	if err := validateUsername(username); err != nil {
		return renewResult{}, err
	}
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()
	res, err := oAdmin.userRenewLocked(username, graceHours)
	return res, err
}

// userRenewLocked is the renewal of a client certificate (filesystem backend). The order is the point:
//
//  1. Nothing of the user is touched until the new certificate exists and has been verified. It is issued under a
//     temporary file base ("<name>.renew-tmp", with --req-cn=<name> so that the common name is the user's): the
//     old files stay in pki/issued, pki/private and pki/reqs, so the user has a working certificate at every
//     moment and a failing step has nothing to undo but the new files.
//  2. Verified (chain, key, name, a day of validity, index.txt): a certificate of an earlier renewal that is still
//     in its grace is revoked at once (by its file), because there is at most one superseded certificate a name.
//  3. renewals.json is written (the old certificate is tracked from here on), then the old files move to
//     pki/superseded/<name>-<serial>/ and the new ones take their place.
//  4. With a grace of 0 the old certificate is revoked now. One CRL rebuild covers every revoke of the call.
//
// Any failing step puts index.txt, renewals.json, the files and the CRL back and the answer says which certificate
// is live. The password row and the client-config-dir entry are never touched: the name is the same.
func (oAdmin *OvpnAdmin) userRenewLocked(username string, graceHours int) (res renewResult, retErr error) {
	now := certNow()
	if !usernameIsPathSafe(username) || !checkUserExist(username) {
		return res, inputError{fmt.Sprintf("user %q not found", username)}
	}
	renewals, err := loadRenewals()
	if err != nil {
		msg := fmt.Sprintf("Failed to renew user %q: %v. Nothing was changed", username, err)
		return res, errors.New(msg)
	}
	lines, err := readIndexTxt()
	if err != nil {
		return res, fmt.Errorf("Failed to renew user %q: %v. Nothing was changed", username, err)
	}
	cur, _ := currentIndexLine(lines, username, supersededSet(renewals))
	if cur.Flag == "R" {
		return res, inputError{fmt.Sprintf("user %q is revoked, unrevoke or rotate first", username)}
	}
	live := certFilesOf(username)
	oldCert, err := readCertFile(live.crt)
	if err != nil {
		return res, fmt.Errorf("Failed to renew user %q: the certificate file cannot be read (%v). Nothing was changed", username, err)
	}
	oldSerial := serialHex(oldCert)
	if normSerial(oldSerial) != normSerial(cur.SerialNumber) {
		return res, fmt.Errorf("Failed to renew user %q: pki/issued holds serial %s but index.txt lists serial %s as the current one. Nothing was changed", username, oldSerial, cur.SerialNumber)
	}
	prior, hasPrior := renewals[username]
	if hasPrior && normSerial(prior.OldSerial) == normSerial(oldSerial) {
		return res, fmt.Errorf("Failed to renew user %q: renewals.json lists the live certificate as superseded. Nothing was changed", username)
	}
	tmp := certFilesOf(username + certTmpSuffix)
	for _, p := range tmp.all() {
		if fExist(p) {
			return res, fmt.Errorf("Failed to renew user %q: %s exists, an earlier renewal was interrupted. Remove the %s%s files of that user and try again. Nothing was changed", username, p, username, certTmpSuffix)
		}
	}

	tx := &pkiTx{}
	live_ := func() string { // which certificate is live now, measured
		c, err := readCertFile(live.crt)
		if err != nil {
			return "none"
		}
		s := serialHex(c)
		if listed, _, err := crlHasSerial(c.SerialNumber); err == nil && listed {
			return "serial " + s + " (it is listed in the CRL: it does not work)"
		}
		return "serial " + s
	}
	fail := func(step string, cause error) (renewResult, error) {
		log.Errorf("userRenew %s: %s: %v", username, step, cause)
		rbErr := tx.rollback()
		oAdmin.clients = oAdmin.usersList()
		now := live_()
		var msg string
		switch {
		case rbErr != nil:
			msg = fmt.Sprintf("Failed to renew user %q (%s) and the previous state could not be restored completely, check the admin log. The certificate in pki/issued now is %s; if it is not the old serial %s, rotate the user", username, step, now, oldSerial)
		case now == "serial "+oldSerial:
			msg = fmt.Sprintf("Failed to renew user %q (%s). The certificate is as before: the old certificate (serial %s) is live and valid, and a grace period of an earlier renewal is unchanged. The password and the client-config-dir entry were not touched", username, step, oldSerial)
		default:
			msg = fmt.Sprintf("Failed to renew user %q (%s). The previous state was restored but the certificate in pki/issued now is %s, not the old serial %s: check the admin log, rotate the user if it cannot connect", username, step, now, oldSerial)
		}
		return renewResult{}, errors.New(msg)
	}

	tx.snapshotFile(*indexTxtPath, 0644)
	tx.snapshotFile(renewalsPath(), 0600)
	if err := ensureUniqueSubjectNo(); err != nil {
		return fail("index.txt.attr could not be written", err)
	}

	// 1. the new certificate, under a temporary base, the old files untouched
	tx.removeOnRollback(tmp.all()...)
	_, buildErr := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "--batch", easyrsaDaysArg(), "--req-cn="+username, "build-client-full", username+certTmpSuffix, "nopass")
	// whatever easy-rsa left behind, even when it failed after it signed: the entry in index.txt goes with the
	// snapshot, the copy in certs_by_serial is removed here
	if c, rerr := readCertFile(tmp.crt); rerr == nil {
		tx.removeOnRollback(pkiFile("certs_by_serial", normSerialFile(serialHex(c))+".pem"))
	}
	if buildErr != nil {
		return fail("the new certificate could not be issued", buildErr)
	}
	// the clock is read again: easy-rsa dates the new certificate when it signs, which is after the request began
	newCert, err := verifyIssued(tmp.crt, tmp.key, username, x509.ExtKeyUsageClientAuth, certNow())
	if err != nil {
		return fail("the new certificate failed its checks", err)
	}
	newSerial := serialHex(newCert)
	tx.removeOnRollback(pkiFile("certs_by_serial", normSerialFile(newSerial)+".pem"))
	if normSerial(newSerial) == normSerial(oldSerial) {
		return fail("the new certificate has the serial of the old one", errors.New("same serial"))
	}

	// 2. a superseded certificate of an earlier renewal is revoked at once, by its file
	var revokeSerials []string
	if hasPrior {
		if err := revokeSupersededIndexLocked(tx, username, prior); err != nil {
			return fail("the certificate of the earlier renewal could not be revoked", err)
		}
		revokeSerials = append(revokeSerials, normSerial(prior.OldSerial))
		res.SupersededSerial = normSerial(prior.OldSerial)
	}

	// 3. renewals.json first, then the files
	graceEnds := now.Add(time.Duration(graceHours) * time.Hour).UTC()
	renewals[username] = renewalEntry{
		OldSerial:   oldSerial,
		OldNotAfter: oldCert.NotAfter.UTC().Format(time.RFC3339),
		GraceEndsAt: graceEnds.Format(time.RFC3339),
		NewSerial:   newSerial,
	}
	if err := saveRenewals(renewals); err != nil {
		return fail("renewals.json could not be written", err)
	}
	dir := supersededDir(username, oldSerial)
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return fail("the superseded directory could not be created", err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fail("the superseded directory could not be created", err)
	}
	tx.addUndo(func() error {
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
	type move struct{ from, to string }
	var oldToDir, newToLive []move
	for _, m := range []struct{ from, name string }{{live.crt, ".crt"}, {live.key, ".key"}, {live.req, ".req"}, {live.inline, ".inline"}, {live.inlinePrivate, ".inline.private"}} {
		if fExist(m.from) {
			oldToDir = append(oldToDir, move{m.from, filepath.Join(dir, username+m.name)})
		}
	}
	for _, m := range [][2]string{{tmp.crt, live.crt}, {tmp.key, live.key}, {tmp.req, live.req}, {tmp.inline, live.inline}, {tmp.inlinePrivate, live.inlinePrivate}} {
		if fExist(m[0]) {
			newToLive = append(newToLive, move{m[0], m[1]})
		}
	}
	for _, m := range oldToDir {
		if err := tx.rename(m.from, m.to); err != nil {
			return fail("the old certificate files could not be moved to the superseded directory", err)
		}
	}
	for _, m := range newToLive {
		if err := tx.rename(m.from, m.to); err != nil {
			return fail("the new certificate files could not be put in place", err)
		}
	}
	if err := os.Chmod(live.key, 0600); err != nil {
		return fail("the new private key could not be made private", err)
	}

	// 4. a grace of 0: the old certificate goes now
	if graceHours == 0 {
		if err := revokeSupersededIndexLocked(tx, username, renewals[username]); err != nil {
			return fail("the old certificate could not be revoked", err)
		}
		revokeSerials = append(revokeSerials, normSerial(oldSerial))
		delete(renewals, username)
		if err := saveRenewals(renewals); err != nil {
			return fail("renewals.json could not be written", err)
		}
	} else if hasPrior {
		// the entry of the earlier renewal was replaced above
	}
	if len(revokeSerials) > 0 {
		tx.crlPublished = true
		if err := publishCrl(revokeSerials...); err != nil {
			return fail("the CRL could not be published", err)
		}
	}

	// committed: what is left is clean-up, which cannot undo the renewal
	tx.undo = nil
	if hasPrior {
		removeSupersededDir(username, prior.OldSerial)
	}
	if graceHours == 0 {
		removeSupersededDir(username, oldSerial)
	}
	resetCertNotifyState(certKindClient, username)
	oAdmin.clients = oAdmin.usersList()
	if certs, err := scanCertsLocked(); err == nil {
		setCertGauges(certs, now)
	}

	res.OldSerial, res.NewSerial, res.GraceEndsAt = oldSerial, newSerial, graceEnds
	res.RevokedAtOnce = graceHours == 0
	if res.RevokedAtOnce {
		res.Message = fmt.Sprintf("Certificate of user %q renewed (new serial %s, valid until %s, lifetime %d days): the old certificate was revoked at once", username, newSerial, newCert.NotAfter.UTC().Format(time.RFC3339), effectiveCertDays())
	} else {
		res.Message = fmt.Sprintf("Certificate of user %q renewed (new serial %s, valid until %s, lifetime %d days): the old certificate stays valid until %s", username, newSerial, newCert.NotAfter.UTC().Format(time.RFC3339), effectiveCertDays(), graceEnds.Format(time.RFC3339))
	}
	if res.SupersededSerial != "" {
		res.Message += fmt.Sprintf(". The certificate of the earlier renewal (serial %s) was revoked at once", res.SupersededSerial)
	}
	log.Infof("Certificate for user %s renewed: old serial %s, new serial %s, grace ends %s", username, oldSerial, newSerial, graceEnds.Format(time.RFC3339))
	return res, nil
}

func supersededSet(m map[string]renewalEntry) map[string]bool {
	set := make(map[string]bool, len(m))
	for _, e := range m {
		set[normSerial(e.OldSerial)] = true
	}
	return set
}

// ---------------------------------------------------------------------------------------------------------------
// the end of a grace

// renewalGraceTick revokes the superseded certificates whose grace has ended. It runs at the start and every 15
// minutes, on the master of the filesystem backend. For each one: the replacement must be the live certificate
// (otherwise nothing is revoked: the old certificate is all the user has), the old one is revoked by its file, the
// CRL is rebuilt once for all of them, and only when the CRL lists them are the superseded directories removed and
// the entries dropped. A failure leaves the entries, the next run resumes. It returns the number of certificates
// that it has revoked and removed.
func (oAdmin *OvpnAdmin) renewalGraceTick() int {
	if oAdmin.role == "slave" || *storageBackend == "kubernetes.secrets" {
		return 0
	}
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()
	now := certNow()

	// a revoke that a crash left unpublished: index.txt says revoked, the CRL does not list it
	if missing, err := crlMissingRevoked(); err == nil && len(missing) > 0 {
		log.Warnf("certificate lifecycle: %d revoked serial(s) are not in the CRL: rebuilding it", len(missing))
		if err := publishCrl(missing...); err != nil {
			log.Errorf("certificate lifecycle: %v", err)
		}
	} else if err != nil && !os.IsNotExist(errors.Unwrap(err)) && !strings.Contains(err.Error(), "no such file") {
		log.Debugf("certificate lifecycle: CRL consistency check: %v", err)
	}

	renewals, err := loadRenewals()
	if err != nil {
		log.Errorf("certificate lifecycle: %v", err)
		adminAudit.system(auditActCertAutoRevoke, "renewals.json", false, auditErrDetail(err, ""))
		return 0
	}
	var names []string
	for name, e := range renewals {
		ends, perr := time.Parse(time.RFC3339, e.GraceEndsAt)
		if perr != nil {
			log.Errorf("certificate lifecycle: %s: graceEndsAt is not a time: %v", name, perr)
			continue
		}
		if !ends.After(now) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return 0
	}

	var done []string
	var serials []string
	for _, name := range names {
		e := renewals[name]
		detail := func(extra string) string {
			return fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s %s", name, e.OldSerial, e.NewSerial, e.GraceEndsAt, extra)
		}
		cur, err := readCertFile(pkiFile("issued", name+".crt"))
		// an old certificate that index.txt marks revoked already (an admin revoke of the user, a crash) needs no
		// replacement: revoking it again is a no-op and the CRL below is what is left to do
		alreadyRevoked := false
		if lines, lerr := readIndexTxt(); lerr == nil {
			f, _ := indexFlagOf(lines, e.OldSerial)
			alreadyRevoked = f == "R"
		}
		if !alreadyRevoked && (err != nil || normSerial(serialHex(cur)) != normSerial(e.NewSerial)) {
			log.Errorf("certificate lifecycle: %s: the live certificate is not the replacement %s: the old certificate %s is NOT revoked", name, e.NewSerial, e.OldSerial)
			adminAudit.system(auditActCertAutoRevoke, name, false, detail("refused: the replacement is not the live certificate"))
			continue
		}
		if err := revokeSupersededIndexLocked(nil, name, e); err != nil {
			log.Errorf("certificate lifecycle: %s: revoking serial %s: %v", name, e.OldSerial, err)
			adminAudit.system(auditActCertAutoRevoke, name, false, detail("revoke failed"))
			continue
		}
		done = append(done, name)
		serials = append(serials, normSerial(e.OldSerial))
	}
	if len(done) == 0 {
		return 0
	}
	if err := publishCrl(serials...); err != nil {
		log.Errorf("certificate lifecycle: %v: the superseded certificates stay recorded and the next run publishes again", err)
		for _, name := range done {
			e := renewals[name]
			adminAudit.system(auditActCertAutoRevoke, name, false, fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s CRL not published", name, e.OldSerial, e.NewSerial, e.GraceEndsAt))
		}
		return 0
	}
	for _, name := range done {
		e := renewals[name]
		delete(renewals, name)
		if err := saveRenewals(renewals); err != nil {
			log.Errorf("certificate lifecycle: renewals.json: %v", err)
		}
		removeSupersededDir(name, e.OldSerial)
		adminAudit.system(auditActCertAutoRevoke, name, true, fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s old certificate revoked, CRL rebuilt", name, e.OldSerial, e.NewSerial, e.GraceEndsAt))
		log.Infof("grace of user %s ended: old certificate %s revoked, CRL rebuilt", name, e.OldSerial)
	}
	oAdmin.clients = oAdmin.usersList()
	return len(done)
}

// retireSupersededLocked ends the grace of name now (rotate and delete replace the user's certificate anyway).
func (oAdmin *OvpnAdmin) retireSupersededLocked(name string) error {
	renewals, err := loadRenewals()
	if err != nil {
		return err
	}
	e, ok := renewals[name]
	if !ok {
		return nil
	}
	if err := revokeSupersededIndexLocked(nil, name, e); err != nil {
		return fmt.Errorf("the superseded certificate (serial %s) of %q could not be revoked: %w", e.OldSerial, name, err)
	}
	if err := publishCrl(normSerial(e.OldSerial)); err != nil {
		return fmt.Errorf("the superseded certificate (serial %s) of %q is revoked but %w", e.OldSerial, name, err)
	}
	delete(renewals, name)
	if err := saveRenewals(renewals); err != nil {
		return err
	}
	removeSupersededDir(name, e.OldSerial)
	adminAudit.system(auditActCertAutoRevoke, name, true, fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s superseded certificate revoked with the replacement of the certificate", name, e.OldSerial, e.NewSerial, e.GraceEndsAt))
	return nil
}

// revokeSupersededWithUser is the part of an admin revoke that handles a certificate in its grace: it revokes the
// superseded certificate by its file in the lock of the revoke. The CRL is rebuilt by the revoke, once, for both;
// finish is called when the CRL lists them and drops the entry and the directory.
func revokeSupersededWithUser(username string) (serial string, finish func(), err error) {
	renewals, err := loadRenewals()
	if err != nil {
		return "", nil, err
	}
	e, ok := renewals[username]
	if !ok {
		return "", nil, nil
	}
	if err := revokeSupersededIndexLocked(nil, username, e); err != nil {
		return "", nil, err
	}
	return normSerial(e.OldSerial), func() {
		delete(renewals, username)
		if err := saveRenewals(renewals); err != nil {
			log.Errorf("renewals.json: %v", err)
		}
		removeSupersededDir(username, e.OldSerial)
		adminAudit.system(auditActCertAutoRevoke, username, true, fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s superseded certificate revoked by the admin revoke of the user", username, e.OldSerial, e.NewSerial, e.GraceEndsAt))
	}, nil
}

// ---------------------------------------------------------------------------------------------------------------
// server renewal

type serverRenewResult struct {
	Message        string
	PreviousSerial string
	NewSerial      string
}

func (oAdmin *OvpnAdmin) serverRenew() (serverRenewResult, error) {
	if *storageBackend == "kubernetes.secrets" {
		return serverRenewResult{}, inputError{k8sRenewUnsupported}
	}
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()
	return oAdmin.serverRenewLocked()
}

var serverBackupRe = regexp.MustCompile(`^server-backup-[0-9]+$`)

// serverRenewLocked issues a new server certificate and installs it, and leaves the previous one valid and the
// running OpenVPN on it (it reads the files only when it starts). The new one is issued under a temporary base
// like a client certificate, verified, and replaces pki/issued/server.crt and pki/private/server.key one file at
// a time by rename, so neither is ever missing. The previous certificate and key are copied to
// pki/server-backup-<unix>/ first. server-renewal.json records the restart that is pending. Nothing is revoked
// here: that is the confirm, after the restart.
func (oAdmin *OvpnAdmin) serverRenewLocked() (res serverRenewResult, retErr error) {
	now := certNow()
	st, err := loadServerRenewal()
	if err != nil {
		return res, fmt.Errorf("Failed to renew the server certificate: %v. Nothing was changed", err)
	}
	if st.RestartPending {
		return res, inputError{"a server certificate renewal is pending: restart the openvpn container in a window, then confirm it before renewing again"}
	}
	live := certFilesOf(serverCertName)
	oldCert, err := readCertFile(live.crt)
	if err != nil {
		return res, fmt.Errorf("Failed to renew the server certificate: pki/issued/server.crt cannot be read (%v). Nothing was changed", err)
	}
	if !fRegularFile(live.key) {
		return res, errors.New("Failed to renew the server certificate: pki/private/server.key is missing. Nothing was changed")
	}
	oldSerial := serialHex(oldCert)
	tmp := certFilesOf(serverCertName + certTmpSuffix)
	for _, p := range tmp.all() {
		if fExist(p) {
			return res, fmt.Errorf("Failed to renew the server certificate: %s exists, an earlier renewal was interrupted. Remove the server%s files and try again. Nothing was changed", p, certTmpSuffix)
		}
	}
	backupName := fmt.Sprintf("server-backup-%d", now.Unix())
	backup := pkiFile(backupName)
	if fExist(backup) {
		return res, fmt.Errorf("Failed to renew the server certificate: %s exists already. Nothing was changed", backup)
	}

	tx := &pkiTx{}
	fail := func(step string, cause error) (serverRenewResult, error) {
		log.Errorf("serverRenew: %s: %v", step, cause)
		rbErr := tx.rollback()
		served := "unknown"
		if c, err := readCertFile(live.crt); err == nil {
			served = "serial " + serialHex(c)
		}
		var msg string
		switch {
		case rbErr != nil:
			msg = fmt.Sprintf("Failed to renew the server certificate (%s) and the previous state could not be restored completely, check the admin log. pki/issued/server.crt holds %s, the previous serial is %s; the backup is in %s", step, served, oldSerial, backupName)
		default:
			msg = fmt.Sprintf("Failed to renew the server certificate (%s). Nothing changed: the previous certificate (serial %s) is installed, valid, and the one OpenVPN serves", step, oldSerial)
		}
		return serverRenewResult{}, errors.New(msg)
	}

	tx.snapshotFile(*indexTxtPath, 0644)
	tx.snapshotFile(serverRenewalPath(), 0600)
	tx.snapshotFile(live.crt, 0644)
	tx.snapshotFile(live.key, 0600)
	tx.snapshotFile(live.req, 0600)
	tx.snapshotFile(live.inline, 0644)
	tx.snapshotFile(live.inlinePrivate, 0600)
	if err := ensureUniqueSubjectNo(); err != nil {
		return fail("index.txt.attr could not be written", err)
	}

	// 1. the backup of what OpenVPN serves now
	if err := os.Mkdir(backup, 0700); err != nil {
		return fail("the backup directory could not be created", err)
	}
	tx.addUndo(func() error { return os.RemoveAll(backup) })
	if err := os.Chmod(backup, 0700); err != nil {
		return fail("the backup directory could not be made private", err)
	}
	if err := copyFileMode(live.crt, filepath.Join(backup, "server.crt"), 0600); err != nil {
		return fail("the certificate could not be backed up", err)
	}
	if err := copyFileMode(live.key, filepath.Join(backup, "server.key"), 0600); err != nil {
		return fail("the private key could not be backed up", err)
	}
	if fRegularFile(live.req) {
		if err := copyFileMode(live.req, filepath.Join(backup, "server.req"), 0600); err != nil {
			return fail("the request could not be backed up", err)
		}
	}

	// 2. the new certificate, same common name, verified
	tx.removeOnRollback(tmp.all()...)
	_, buildErr := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "--batch", easyrsaDaysArg(), "--req-cn="+serverCertName, "build-server-full", serverCertName+certTmpSuffix, "nopass")
	if c, rerr := readCertFile(tmp.crt); rerr == nil {
		tx.removeOnRollback(pkiFile("certs_by_serial", normSerialFile(serialHex(c))+".pem"))
	}
	if buildErr != nil {
		return fail("the new certificate could not be issued", buildErr)
	}
	newCert, err := verifyIssued(tmp.crt, tmp.key, serverCertName, x509.ExtKeyUsageServerAuth, certNow())
	if err != nil {
		return fail("the new certificate failed its checks", err)
	}
	newSerial := serialHex(newCert)
	if normSerial(newSerial) == normSerial(oldSerial) {
		return fail("the new certificate has the serial of the old one", errors.New("same serial"))
	}

	// 3. installed: the key, then the certificate; each replaced by rename, so none is ever missing
	if err := os.Chmod(tmp.key, 0600); err != nil {
		return fail("the new private key could not be made private", err)
	}
	for _, m := range [][2]string{{tmp.key, live.key}, {tmp.crt, live.crt}, {tmp.req, live.req}, {tmp.inline, live.inline}, {tmp.inlinePrivate, live.inlinePrivate}} {
		if !fExist(m[0]) {
			continue
		}
		if err := os.Rename(m[0], m[1]); err != nil {
			return fail("the new certificate could not be installed", err)
		}
	}
	if err := os.Chmod(live.key, 0600); err != nil {
		return fail("the new private key could not be made private", err)
	}

	// 4. the restart that is pending
	st = serverRenewalState{
		RestartPending:    true,
		PreviousSerial:    oldSerial,
		PreviousNotAfter:  oldCert.NotAfter.UTC().Format(time.RFC3339),
		PreviousBackupDir: backupName,
		NewSerial:         newSerial,
		NewNotAfter:       newCert.NotAfter.UTC().Format(time.RFC3339),
		RenewedAt:         now.UTC().Format(time.RFC3339),
	}
	if err := saveServerRenewal(st); err != nil {
		return fail("server-renewal.json could not be written", err)
	}

	tx.undo = nil
	serverCertCache.Clear()
	resetCertNotifyState(certKindServer, serverCertName)
	oAdmin.clients = oAdmin.usersList()
	if certs, err := scanCertsLocked(); err == nil {
		setCertGauges(certs, now)
	}
	res.PreviousSerial, res.NewSerial = oldSerial, newSerial
	res.Message = fmt.Sprintf("A new server certificate (serial %s, valid until %s, lifetime %d days) is installed on disk. OpenVPN still serves the previous certificate (serial %s, valid until %s) and keeps serving it until the openvpn container is restarted: restart it in a window, check that clients connect, then confirm. The previous certificate stays valid until you confirm", newSerial, newCert.NotAfter.UTC().Format(time.RFC3339), effectiveCertDays(), oldSerial, oldCert.NotAfter.UTC().Format(time.RFC3339))
	log.Infof("Server certificate renewed on disk: previous serial %s, new serial %s; restart of openvpn pending", oldSerial, newSerial)
	return res, nil
}

// serverConfirmRenew revokes the previous server certificate by its file once OpenVPN has been restarted, rebuilds
// the CRL and clears restartPending. It cannot see whether OpenVPN has been restarted: it is the administrator's
// confirmation.
func (oAdmin *OvpnAdmin) serverConfirmRenew() (serverRenewResult, error) {
	if *storageBackend == "kubernetes.secrets" {
		return serverRenewResult{}, inputError{k8sRenewUnsupported}
	}
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()
	now := certNow()

	st, err := loadServerRenewal()
	if err != nil {
		return serverRenewResult{}, fmt.Errorf("Failed to confirm the server renewal: %v. Nothing was changed", err)
	}
	if !st.RestartPending {
		return serverRenewResult{}, inputError{"no server certificate renewal is pending"}
	}
	if !serverBackupRe.MatchString(st.PreviousBackupDir) {
		return serverRenewResult{}, fmt.Errorf("Failed to confirm the server renewal: server-renewal.json names the backup %q, which is not a server-backup directory. Nothing was changed", st.PreviousBackupDir)
	}
	backup := pkiFile(st.PreviousBackupDir)
	certFile := filepath.Join(backup, "server.crt")
	if !fRegularFile(certFile) {
		certFile = pkiFile("certs_by_serial", normSerialFile(st.PreviousSerial)+".pem")
	}

	tx := &pkiTx{}
	tx.snapshotFile(*indexTxtPath, 0644)
	tx.snapshotFile(serverRenewalPath(), 0600)
	fail := func(step string, cause error) (serverRenewResult, error) {
		log.Errorf("serverConfirmRenew: %s: %v", step, cause)
		rbErr := tx.rollback()
		var msg string
		if rbErr != nil {
			msg = fmt.Sprintf("Failed to confirm the server renewal (%s) and the previous state could not be restored completely, check the admin log: the previous server certificate (serial %s) may be revoked; check the CRL before you rely on the new one", step, st.PreviousSerial)
		} else {
			msg = fmt.Sprintf("Failed to confirm the server renewal (%s). The previous server certificate (serial %s) is NOT revoked and still valid, restartPending stays true; the confirm can be repeated", step, st.PreviousSerial)
		}
		return serverRenewResult{}, errors.New(msg)
	}
	if err := revokeCertByFile(tx, serverCertName, st.PreviousSerial, certFile, filepath.Join(backup, "server.key"), filepath.Join(backup, "server.req")); err != nil {
		return fail("the previous certificate could not be revoked", err)
	}
	tx.crlPublished = true
	if err := publishCrl(normSerial(st.PreviousSerial)); err != nil {
		return fail("the CRL could not be published", err)
	}
	st.RestartPending = false
	st.ConfirmedAt = now.UTC().Format(time.RFC3339)
	if err := saveServerRenewal(st); err != nil {
		return fail("server-renewal.json could not be written", err)
	}
	tx.undo = nil
	oAdmin.clients = oAdmin.usersList()
	if certs, err := scanCertsLocked(); err == nil {
		setCertGauges(certs, now)
	}
	return serverRenewResult{
		PreviousSerial: st.PreviousSerial,
		NewSerial:      st.NewSerial,
		Message:        fmt.Sprintf("The previous server certificate (serial %s) is revoked and the CRL is rebuilt", st.PreviousSerial),
	}, nil
}

// ---------------------------------------------------------------------------------------------------------------
// notifications

type certNotifyEntry struct {
	Serial   string `json:"serial"`
	NotAfter string `json:"notAfter"`
	Fired    []int  `json:"fired"`
}

type certNotifyState struct {
	Version int                         `json:"version"`
	Certs   map[string]*certNotifyEntry `json:"certs"`
}

var certNotifyMu sync.Mutex

func certNotifyKey(kind, name string) string { return kind + "/" + name }

func loadCertNotifyStateLocked() certNotifyState {
	st := certNotifyState{Version: 1, Certs: map[string]*certNotifyEntry{}}
	data, err := os.ReadFile(certNotifyStatePath())
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("cert-notify-state.json: %v: starting without it", err)
		}
		return st
	}
	if err := json.Unmarshal(data, &st); err != nil || st.Certs == nil {
		log.Warnf("cert-notify-state.json is not valid: starting without it")
		return certNotifyState{Version: 1, Certs: map[string]*certNotifyEntry{}}
	}
	return st
}

func saveCertNotifyStateLocked(st certNotifyState) error {
	st.Version = 1
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(certNotifyStatePath(), append(data, '\n'), 0600)
}

// resetCertNotifyState forgets which thresholds a certificate name has announced: a renewed certificate starts
// its thresholds again.
func resetCertNotifyState(kind, name string) {
	certNotifyMu.Lock()
	defer certNotifyMu.Unlock()
	st := loadCertNotifyStateLocked()
	if _, ok := st.Certs[certNotifyKey(kind, name)]; !ok {
		return
	}
	delete(st.Certs, certNotifyKey(kind, name))
	if err := saveCertNotifyStateLocked(st); err != nil {
		log.Warnf("cert-notify-state.json: %v", err)
	}
}

// certNotifyThresholds is OVPN_NOTIFY_CERT_DAYS: days, comma separated, largest first. A value that is not
// understood is logged (once per call) and the default 30,14,7,3,1 is used.
func certNotifyThresholds() []int {
	def := []int{30, 14, 7, 3, 1}
	raw := strings.TrimSpace(os.Getenv("OVPN_NOTIFY_CERT_DAYS"))
	if raw == "" {
		return def
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > 3650 {
			log.Warnf("OVPN_NOTIFY_CERT_DAYS is not a list of days from 1 to 3650: using 30,14,7,3,1")
			return def
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

type certNotice struct {
	cert      certInfo
	days      int
	threshold int   // the tightest threshold that the certificate has crossed now
	marks     []int // every threshold that this notice marks as fired
}

func certActionLine(kind string) string {
	switch kind {
	case certKindClient:
		return "Renew in the panel (Users -> Renew) or POST /api/user/renew"
	case certKindServer:
		return "Renew in the panel (Server certificate -> Renew), then restart the openvpn container in a window and confirm."
	}
	return "Informational only: the CA certificate is not renewed by the panel."
}

func expiryPhrase(days int) string {
	switch {
	case days < -1:
		return fmt.Sprintf("expired %d days ago", -days)
	case days == -1:
		return "expired yesterday"
	case days == 0:
		return "less than 1 day left"
	case days == 1:
		return "1 day left"
	}
	return fmt.Sprintf("%d days left", days)
}

// certNoticeText is the message for one certificate: its name, type, expiry date, days left and what to do. No
// address and no user name other than the certificate name.
func certNoticeText(c certInfo, days int) string {
	head := "\u26a0\ufe0f ovpn-admin: certificate expiring"
	if days < 0 {
		head = "\u274c ovpn-admin: certificate expired"
	}
	return strings.Join([]string{
		head,
		"Certificate: " + c.Name,
		"Type: " + c.Kind,
		fmt.Sprintf("Expires: %s (%s)", c.NotAfter.UTC().Format("2006-01-02"), expiryPhrase(days)),
		certActionLine(c.Kind),
	}, "\n")
}

type noticeChunk struct {
	text  string
	items []int // indexes of the notices that are in this message
}

// summaryChunks is the message for more than 10 certificates that cross the same threshold: one summary line
// first (with what to do for each kind), then one line per certificate, in messages of at most limit characters.
func summaryChunks(threshold int, notices []certNotice, limit int) []noticeChunk {
	header := []string{fmt.Sprintf("\u26a0\ufe0f ovpn-admin: %d certificates cross the %d-day expiry threshold", len(notices), threshold)}
	kinds := map[string]bool{}
	for _, n := range notices {
		kinds[n.cert.Kind] = true
	}
	for _, k := range []string{certKindClient, certKindServer, certKindCA} {
		if kinds[k] {
			header = append(header, strings.ToUpper(k[:1])+k[1:]+": "+certActionLine(k))
		}
	}
	var chunks []noticeChunk
	cur := noticeChunk{text: strings.Join(header, "\n")}
	curLen := len([]rune(cur.text))
	for i, n := range notices {
		line := fmt.Sprintf("%s (%s): expires %s, %s", n.cert.Name, n.cert.Kind, n.cert.NotAfter.UTC().Format("2006-01-02"), expiryPhrase(n.days))
		if r := []rune(line); len(r) > limit {
			line = string(r[:limit])
		}
		l := len([]rune(line)) + 1
		if curLen+l > limit {
			chunks = append(chunks, cur)
			cur, curLen = noticeChunk{text: line}, len([]rune(line))
			cur.items = []int{i}
			continue
		}
		cur.text += "\n" + line
		cur.items = append(cur.items, i)
		curLen += l
	}
	return append(chunks, cur)
}

type certScanReport struct {
	Certificates int
	Expiring30d  int
	Expiring7d   int
	Notices      int
	Messages     int
	Sent         int
	Skipped      bool
}

// certScanAndNotify is one run of the daily job: scan, set the gauges, announce the thresholds that certificates
// have crossed since the last run, and (while a server renewal waits for its restart) remind of it. A threshold is
// recorded as fired only after its message was delivered, so a failed delivery is tried again at the next run.
// With Telegram not configured it logs one line and sends nothing; it never returns an error.
func (oAdmin *OvpnAdmin) certScanAndNotify(ctx context.Context) certScanReport {
	var rep certScanReport
	now := certNow()
	oAdmin.createUserMutex.Lock()
	certs, err := scanCertsLocked()
	pending, perr := loadServerRenewal()
	oAdmin.createUserMutex.Unlock()
	if err != nil {
		log.Errorf("certificate scan: %v", err)
		adminAudit.system(auditActCertScan, "pki", false, auditErrDetail(err, ""))
		return rep
	}
	if perr != nil {
		log.Warnf("certificate scan: %v", perr)
	}
	rep.Certificates = len(certs)
	rep.Expiring30d, rep.Expiring7d = setCertGauges(certs, now)

	thresholds := certNotifyThresholds()
	certNotifyMu.Lock()
	st := loadCertNotifyStateLocked()
	certNotifyMu.Unlock()

	var notices []certNotice
	for _, c := range certs {
		days := c.daysLeft(now)
		entry := st.Certs[certNotifyKey(c.Kind, c.Name)]
		fired := map[int]bool{}
		if entry != nil && entry.Serial == c.Serial {
			for _, f := range entry.Fired {
				fired[f] = true
			}
		}
		var marks []int
		for _, t := range thresholds {
			if days <= t && !fired[t] {
				marks = append(marks, t)
			}
		}
		if len(marks) > 0 {
			notices = append(notices, certNotice{cert: c, days: days, threshold: marks[len(marks)-1], marks: marks})
		}
	}
	rep.Notices = len(notices)
	reminder := pending.RestartPending

	delivered := map[int]bool{} // index into notices
	cfg, why := telegramConfigFromEnv()
	if !cfg.enabled {
		// one info line per run, whether or not a threshold was crossed; never an error
		rep.Skipped = true
		log.Infof("certificate expiry notifications are off (%s): %d notice(s) not sent", why, len(notices))
	} else if len(notices) > 0 || reminder {
		send := func(target, detail, text string) bool {
			rep.Messages++
			if err := telegramSend(ctx, cfg, text); err != nil {
				log.Warnf("certificate expiry notification for %s not delivered: %v", target, err)
				adminAudit.system(auditActCertNotify, target, false, detail+" delivery failed: "+err.Error())
				return false
			}
			rep.Sent++
			adminAudit.system(auditActCertNotify, target, true, detail+" sent")
			return true
		}
		byThreshold := map[int][]int{}
		var order []int
		for i, n := range notices {
			if _, ok := byThreshold[n.threshold]; !ok {
				order = append(order, n.threshold)
			}
			byThreshold[n.threshold] = append(byThreshold[n.threshold], i)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(order)))
		for _, t := range order {
			idx := byThreshold[t]
			if len(idx) <= 10 {
				for _, i := range idx {
					n := notices[i]
					if send(n.cert.Name, fmt.Sprintf("threshold=%d days=%d type=%s", t, n.days, n.cert.Kind), certNoticeText(n.cert, n.days)) {
						delivered[i] = true
					}
				}
				continue
			}
			group := make([]certNotice, len(idx))
			for k, i := range idx {
				group[k] = notices[i]
			}
			chunks := summaryChunks(t, group, telegramMaxText)
			for ci, ch := range chunks {
				if send(fmt.Sprintf("threshold-%d", t), fmt.Sprintf("threshold=%d certificates=%d part=%d/%d", t, len(group), ci+1, len(chunks)), ch.text) {
					for _, k := range ch.items {
						delivered[idx[k]] = true
					}
				}
			}
		}
		if reminder {
			prevEnds, _ := time.Parse(time.RFC3339, pending.PreviousNotAfter)
			days := int(math.Floor(prevEnds.Sub(now).Hours() / 24))
			text := strings.Join([]string{
				"\u26a0\ufe0f ovpn-admin: server certificate renewal is pending",
				"Certificate: " + serverCertName,
				"Type: " + certKindServer,
				fmt.Sprintf("OpenVPN still serves the previous certificate, which expires %s (%s).", prevEnds.UTC().Format("2006-01-02"), expiryPhrase(days)),
				"The new certificate is installed on disk. Restart the openvpn container in a window and confirm in the panel (Server certificate -> Confirm).",
			}, "\n")
			send(serverCertName, "server renewal restart pending reminder", splitTelegramText(text, telegramMaxText)[0])
		}
	}

	// record what was delivered, against the state as it is now (a renewal may have reset a name meanwhile)
	certNotifyMu.Lock()
	cur := loadCertNotifyStateLocked()
	next := certNotifyState{Version: 1, Certs: map[string]*certNotifyEntry{}}
	byKey := map[string]int{}
	for i, n := range notices {
		byKey[certNotifyKey(n.cert.Kind, n.cert.Name)] = i
	}
	for _, c := range certs {
		key := certNotifyKey(c.Kind, c.Name)
		entry := cur.Certs[key]
		if entry == nil || entry.Serial != c.Serial {
			entry = &certNotifyEntry{Serial: c.Serial}
		}
		entry.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
		if i, ok := byKey[key]; ok && delivered[i] && notices[i].cert.Serial == c.Serial {
			have := map[int]bool{}
			for _, f := range entry.Fired {
				have[f] = true
			}
			for _, m := range notices[i].marks {
				if !have[m] {
					entry.Fired = append(entry.Fired, m)
				}
			}
			sort.Sort(sort.Reverse(sort.IntSlice(entry.Fired)))
		}
		next.Certs[key] = entry
	}
	if err := saveCertNotifyStateLocked(next); err != nil {
		log.Warnf("cert-notify-state.json: %v", err)
	}
	certNotifyMu.Unlock()

	adminAudit.system(auditActCertScan, "pki", true, fmt.Sprintf("certificates=%d expiring_30d=%d expiring_7d=%d notices=%d messages=%d sent=%d", rep.Certificates, rep.Expiring30d, rep.Expiring7d, rep.Notices, rep.Messages, rep.Sent))
	return rep
}

// certLifecycleLoop runs the grace job at the start and every 15 minutes, and the scan 5 minutes after the start
// and every 24 hours. It ends when stop is closed (a nil stop never ends; only the tests close it).
func (oAdmin *OvpnAdmin) certLifecycleLoop(stop <-chan struct{}) {
	if oAdmin.role == "slave" {
		// a slave holds no CA key and gets the PKI from the master; the master announces and revokes
		return
	}
	oAdmin.renewalGraceTick()
	grace := time.NewTicker(certGraceInterval)
	defer grace.Stop()
	scan := time.NewTimer(certScanFirstDelay)
	defer scan.Stop()
	for {
		select {
		case <-grace.C:
			oAdmin.renewalGraceTick()
		case <-scan.C:
			oAdmin.certScanAndNotify(context.Background())
			scan.Reset(certScanInterval)
		case <-stop:
			return
		}
	}
}

// ---------------------------------------------------------------------------------------------------------------
// HTTP

func certJSON(w http.ResponseWriter, code int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func certError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if isInputError(err) {
		code = http.StatusBadRequest
	}
	certJSON(w, code, map[string]string{"status": "error", "message": err.Error()})
}

// certAdminGate lets an authenticated admin through and nobody else, like the audit endpoints: the answer lists
// every certificate, or replaces the certificate OpenVPN serves, so it is not given on the strength of a middleware
// that is switched off when no credentials are configured. 403 then, and for a request without the credentials.
func certAdminGate(w http.ResponseWriter, r *http.Request) bool {
	if auditAdminProven(r) {
		return true
	}
	why := "the request did not carry the admin credentials"
	if !auditAdminConfigured() {
		why = "no admin credentials are configured (--basic.username and --basic.password)"
	}
	log.Warnf("certificate lifecycle: %s %s from %s refused with 403: %s", r.Method, r.URL.Path, auditSource(r), why)
	certJSON(w, http.StatusForbidden, map[string]string{"status": "error", "message": "this endpoint is for an authenticated admin only: set --basic.username and --basic.password"})
	return false
}

type certExpiryRow struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	NotAfter   string `json:"notAfter"`
	DaysLeft   int    `json:"daysLeft"`
	Renewable  bool   `json:"renewable"`
	Superseded bool   `json:"superseded"`
}

// certsExpiryHandler: GET /api/certs/expiry. One row per common name. "superseded" is true for a name whose old
// certificate is still valid in its grace; that certificate has no row of its own. "renewable" is false for the CA,
// on the kubernetes backend, on a slave, and for the server certificate while its renewal waits for the restart.
func (oAdmin *OvpnAdmin) certsExpiryHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !certAdminGate(w, r) {
		return
	}
	if !auditGetOnly(w, r) {
		return
	}
	certs, err := oAdmin.scanCerts()
	if err != nil {
		log.Errorf("certsExpiryHandler: %v", err)
		certJSON(w, http.StatusInternalServerError, map[string]string{"status": "error", "message": "the certificates could not be read, see the admin log"})
		return
	}
	oAdmin.createUserMutex.Lock()
	renewals, rerr := loadRenewals()
	st, serr := loadServerRenewal()
	oAdmin.createUserMutex.Unlock()
	if rerr != nil {
		log.Warnf("certsExpiryHandler: %v", rerr)
	}
	if serr != nil {
		log.Warnf("certsExpiryHandler: %v", serr)
	}
	now := certNow()
	k8s := *storageBackend == "kubernetes.secrets"
	rows := make([]certExpiryRow, 0, len(certs))
	for _, c := range certs {
		_, sup := renewals[c.Name]
		row := certExpiryRow{
			Name:       c.Name,
			Kind:       c.Kind,
			NotAfter:   c.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft:   c.daysLeft(now),
			Renewable:  c.Kind != certKindCA && !k8s && oAdmin.role != "slave",
			Superseded: c.Kind == certKindClient && sup,
		}
		if c.Kind == certKindServer && st.RestartPending {
			row.Renewable = false
		}
		rows = append(rows, row)
	}
	certJSON(w, http.StatusOK, map[string]any{"certs": rows, "restartPending": st.RestartPending && !k8s})
}

func (oAdmin *OvpnAdmin) userRenewHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	username := r.FormValue("username")
	grace, err := parseGraceHours(r.FormValue("grace_hours"))
	if err != nil {
		adminAudit.fromRequest(r, auditActUserRenew, username, false, auditErrDetail(err, ""))
		certError(w, err)
		return
	}
	res, err := oAdmin.userRenew(username, grace)
	if err != nil {
		adminAudit.fromRequest(r, auditActUserRenew, username, false, auditErrDetail(err, ""))
		certError(w, err)
		return
	}
	if res.SupersededSerial != "" {
		adminAudit.fromRequest(r, auditActUserRenewSupersede, username, true,
			fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s earlier superseded certificate revoked at once", username, res.SupersededSerial, res.NewSerial, res.GraceEndsAt.Format(time.RFC3339)))
	}
	adminAudit.fromRequest(r, auditActUserRenew, username, true,
		fmt.Sprintf("name=%s oldSerial=%s newSerial=%s graceEndsAt=%s%s", username, res.OldSerial, res.NewSerial, res.GraceEndsAt.Format(time.RFC3339), issuedLifetimeNote()))
	certJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": res.Message})
}

func (oAdmin *OvpnAdmin) serverRenewHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !certAdminGate(w, r) {
		return
	}
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	res, err := oAdmin.serverRenew()
	if err != nil {
		adminAudit.fromRequest(r, auditActServerRenew, serverCertName, false, auditErrDetail(err, ""))
		certError(w, err)
		return
	}
	adminAudit.fromRequest(r, auditActServerRenew, serverCertName, true,
		fmt.Sprintf("previousSerial=%s newSerial=%s%s restart of openvpn pending", res.PreviousSerial, res.NewSerial, issuedLifetimeNote()))
	certJSON(w, http.StatusOK, map[string]any{"status": "ok", "restartRequired": true, "message": res.Message})
}

func (oAdmin *OvpnAdmin) serverConfirmRenewHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !certAdminGate(w, r) {
		return
	}
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	res, err := oAdmin.serverConfirmRenew()
	if err != nil {
		adminAudit.fromRequest(r, auditActServerRenewConfirm, serverCertName, false, auditErrDetail(err, ""))
		certError(w, err)
		return
	}
	adminAudit.fromRequest(r, auditActServerRenewConfirm, serverCertName, true,
		fmt.Sprintf("previousSerial=%s newSerial=%s previous certificate revoked, CRL rebuilt", res.PreviousSerial, res.NewSerial))
	certJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
