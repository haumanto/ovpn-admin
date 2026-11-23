package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

// Admin audit trail: who did what in the panel. Append-only, one JSON object per line, hash chained:
// every line carries the hash of the line before it, so an edited, removed or reordered line breaks the
// chain from that point on (GET /api/audit/verify). It is separate from the OpenVPN connection log of
// audit.go (tab separated, written by the hooks of the openvpn container).
//
// A line is the JSON object with the keys below in exactly this order:
//
//	seq, ts, actor, action, target, source, result, detail, prev, hash
//
// hash is the lowercase hex SHA-256 of the same object without the "hash" key. prev is the hash of the
// previous line, 64 zeros for the first line ever written. When the file reaches 10 MiB it is renamed to
// <file>.1 (older generations move up to .5, the oldest is deleted) and the new file starts with an
// "audit.rotate" line whose prev is the last hash of the closed file, so the chain runs across files.
const (
	adminAuditDefaultFile = "/var/lib/ovpn-admin/audit/admin-audit.log"
	adminAuditMaxBytes    = 10 << 20
	adminAuditGenerations = 5
	adminAuditZeroHash    = "0000000000000000000000000000000000000000000000000000000000000000"

	adminAuditDefaultLimit = 100
	adminAuditMaxLimit     = 500
	adminAuditMaxDetail    = 200 // runes
	adminAuditMaxTarget    = 128 // runes

	adminAuditWebhookQueue   = 256
	adminAuditWebhookTimeout = 3 * time.Second
	adminAuditWebhookLogEach = time.Minute

	adminAuditLoginOKWindow     = 30 * time.Minute // one auth.login.ok per user and source per window
	adminAuditLoginFailWindow   = 10 * time.Second // one auth.login.fail per source per window
	adminAuditThrottleMaxKeys   = 4096
	adminAuditSystemActor       = "system"
	adminAuditLocalSource       = "local"
	adminAuditResultOK          = "ok"
	adminAuditResultFail        = "fail"
	adminAuditRotateAction      = "audit.rotate"
	adminAuditRedacted          = "[redacted]"
	adminAuditSymlinkRefusedMsg = "refusing to follow a symlink"
)

// The actions the panel records. server.renew, server.renew.confirm and settings.change are reserved for
// the features that introduce them; auth.login.locked is written by adminAudit.loginLocked.
const (
	auditActUserCreate         = "user.create"
	auditActUserDelete         = "user.delete"
	auditActUserRevoke         = "user.revoke"
	auditActUserUnrevoke       = "user.unrevoke"
	auditActUserRotate         = "user.rotate"
	auditActUserChangePassword = "user.change-password"
	auditActUserConfigDownload = "user.config.download"
	auditActUserCcdApply       = "user.ccd.apply"
	auditActUserDisconnect     = "user.disconnect"
	auditActBanManual          = "ban.manual"
	auditActUnban              = "unban"
	auditActLoginOK            = "auth.login.ok"
	auditActLoginFail          = "auth.login.fail"
	auditActLoginLocked        = "auth.login.locked"
	auditActCrlRebuild         = "pki.crl.rebuild"
	auditActSyncExport         = "sync.export"
	auditActServerRenew        = "server.renew"
	auditActServerRenewConfirm = "server.renew.confirm"
	auditActSettingsChange     = "settings.change"
	auditActAuditVerify        = "audit.verify"
)

var (
	adminAuditFileFlag    = kingpin.Flag("admin-audit.file", "path of the admin audit trail (hash chained JSON lines, 10 MiB per file, 5 generations); the directory is created 0700 and the file 0600, a symlink at either path is refused, and the panel does not start when the file cannot be written").Default(adminAuditDefaultFile).Envar("OVPN_ADMIN_AUDIT_FILE").String()
	adminAuditWebhookFlag = kingpin.Flag("admin-audit.webhook", "optional URL that receives every admin audit line as a JSON POST (3 s timeout, queue of 256, a full queue drops lines); https only, plain http only for a loopback address").Default("").Envar("OVPN_ADMIN_AUDIT_WEBHOOK").String()
)

// adminAudit is the trail of the running panel. nil means "not configured": every method is a no-op, which
// keeps the unit tests of the handlers independent of it. main() sets it and refuses to start without it.
var adminAudit *adminAuditLog

// adminAuditRecord is one line of the trail. The field order is the key order of the file.
type adminAuditRecord struct {
	Seq    int64  `json:"seq"`
	Ts     string `json:"ts"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Source string `json:"source"`
	Result string `json:"result"`
	Detail string `json:"detail"`
	Prev   string `json:"prev"`
	Hash   string `json:"hash"`
}

// adminAuditBody is the record without its hash: the exact thing that is hashed.
type adminAuditBody struct {
	Seq    int64  `json:"seq"`
	Ts     string `json:"ts"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Source string `json:"source"`
	Result string `json:"result"`
	Detail string `json:"detail"`
	Prev   string `json:"prev"`
}

func (r adminAuditRecord) body() adminAuditBody {
	return adminAuditBody{r.Seq, r.Ts, r.Actor, r.Action, r.Target, r.Source, r.Result, r.Detail, r.Prev}
}

// hashOf is the hash a record must carry.
func (r adminAuditRecord) hashOf() string {
	b, _ := json.Marshal(r.body())
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// parseAdminAuditLine parses one line (without its newline) strictly: all ten keys, no others.
func parseAdminAuditLine(line []byte) (adminAuditRecord, error) {
	var rec adminAuditRecord
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, err
	}
	if dec.More() {
		return rec, errors.New("trailing data after the JSON object")
	}
	return rec, nil
}

// adminAuditLog is the open trail. All state is guarded by mu; the file is only ever appended to.
type adminAuditLog struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	seq      int64
	lastHash string
	lines    int64 // lines of the current file
	maxBytes int64
	now      func() time.Time

	// a rotation renamed the file but the audit.rotate line is not written yet (the next record does it)
	pendingRotate bool
	// a failed rotation is not retried at once: it shifts the generations before it can fail
	rotateRetryAt time.Time
	lastWriteErr  error
	noSync        bool // tests only: skip the fsync of every line

	hook     *adminAuditWebhook
	throttle adminLoginThrottle
}

// openAdminAuditLog opens (and on first use creates) the trail. It fails closed: a symlink at the directory
// or the file, a file that is not a regular file, a file that cannot be opened for appending, or a last
// line that is not a valid link of the chain are errors the caller turns into a failed start.
func openAdminAuditLog(path string, webhookURL string) (*adminAuditLog, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("the admin audit file path is empty")
	}
	var hook *adminAuditWebhook
	if strings.TrimSpace(webhookURL) != "" {
		var err error
		hook, err = newAdminAuditWebhook(webhookURL)
		if err != nil {
			return nil, err
		}
	}
	a := &adminAuditLog{path: filepath.Clean(path), maxBytes: adminAuditMaxBytes, now: time.Now, hook: hook}
	if err := a.open(); err != nil {
		if hook != nil {
			hook.Close()
		}
		return nil, err
	}
	return a, nil
}

func (a *adminAuditLog) open() error {
	dir := filepath.Dir(a.path)
	if err := ensureAuditDir(dir); err != nil {
		return err
	}
	f, err := openAuditAppend(a.path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("admin audit file %s: %w", a.path, err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("admin audit file %s is not a regular file", a.path)
	}
	if fi.Mode().Perm()&0077 != 0 {
		log.Warnf("admin audit file %s has mode %04o, expected 0600", a.path, fi.Mode().Perm())
	}
	lines, last, err := scanAuditTail(f, fi.Size())
	if err != nil {
		f.Close()
		return fmt.Errorf("admin audit file %s: %w (move the file aside to start a new trail)", a.path, err)
	}
	a.f, a.size, a.lines = f, fi.Size(), lines
	if lines > 0 {
		a.seq, a.lastHash = last.Seq, last.Hash
		return nil
	}
	a.seq, a.lastHash = 0, adminAuditZeroHash
	// an empty file next to a closed generation: a rotation that was cut off between the rename and the
	// first line. Continue the chain from the generation.
	if g, err := openAuditRead(a.generation(1)); err == nil {
		gfi, serr := g.Stat()
		if serr == nil {
			if _, glast, gerr := scanAuditTail(g, gfi.Size()); gerr == nil && glast.Hash != "" {
				a.seq, a.lastHash, a.pendingRotate = glast.Seq, glast.Hash, true
			}
		}
		g.Close()
	}
	return nil
}

func (a *adminAuditLog) generation(n int) string { return a.path + "." + strconv.Itoa(n) }

// ensureAuditDir creates the directory 0700 when it is missing and refuses a symlink.
func ensureAuditDir(dir string) error {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("admin audit directory %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("admin audit directory %s: %w", dir, err)
		}
		fi, err = os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("admin audit directory %s: %w", dir, err)
		}
	case err != nil:
		return fmt.Errorf("admin audit directory %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("admin audit directory %s: %s", dir, adminAuditSymlinkRefusedMsg)
	}
	if !fi.IsDir() {
		return fmt.Errorf("admin audit directory %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0022 != 0 {
		log.Warnf("admin audit directory %s is writable by group or others (mode %04o), expected 0700", dir, fi.Mode().Perm())
	}
	return nil
}

func auditOpenErr(path string, err error) error {
	if errors.Is(err, syscall.ELOOP) {
		return fmt.Errorf("admin audit file %s: %s", path, adminAuditSymlinkRefusedMsg)
	}
	return fmt.Errorf("admin audit file %s cannot be opened for appending: %w", path, err)
}

// openAuditAppend opens the file for appending, creating it 0600, and never follows a symlink.
func openAuditAppend(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, auditOpenErr(path, err)
	}
	return f, nil
}

// openAuditNew creates a new file (it must not exist), 0600, no symlink.
func openAuditNew(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, auditOpenErr(path, err)
	}
	return f, nil
}

func openAuditRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

// scanAuditTail counts the lines of a file and parses the last one. The last line must end in a newline,
// parse, and carry its own hash; the rest of the chain is checked by verify, not at every start.
func scanAuditTail(f *os.File, size int64) (int64, adminAuditRecord, error) {
	var last adminAuditRecord
	if size == 0 {
		return 0, last, nil
	}
	br := bufio.NewReaderSize(io.NewSectionReader(f, 0, size), 64<<10)
	var lines int64
	var lastLine []byte
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				return 0, last, fmt.Errorf("line %d has no newline (a cut-off write?)", lines+1)
			}
			lines++
			lastLine = line[:len(line)-1]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, last, err
		}
	}
	rec, err := parseAdminAuditLine(lastLine)
	if err != nil {
		return 0, last, fmt.Errorf("the last line (%d) is not valid: %v", lines, err)
	}
	if rec.Hash != rec.hashOf() {
		return 0, last, fmt.Errorf("the last line (%d) does not match its hash", lines)
	}
	return lines, rec, nil
}

// Lines returns the number of lines of the current file.
func (a *adminAuditLog) Lines() int64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lines
}

// Path is the file of the trail.
func (a *adminAuditLog) Path() string { return a.path }

// Close stops the webhook worker and closes the file.
func (a *adminAuditLog) Close() {
	if a == nil {
		return
	}
	if a.hook != nil {
		a.hook.Close()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f != nil {
		_ = a.f.Close()
		a.f = nil
	}
}

// Record appends one line. The returned error means the line is NOT in the file; the webhook never
// influences it. Detail and target are made single-line and bounded; callers pass secrets they handled so
// they are masked even when an error message happens to contain them.
func (a *adminAuditLog) Record(actor, action, target, source, result, detail string, secrets ...string) (adminAuditRecord, error) {
	if a == nil {
		return adminAuditRecord{}, nil
	}
	if result != adminAuditResultOK {
		result = adminAuditResultFail
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil && !a.pendingRotate {
		return adminAuditRecord{}, errors.New("the admin audit file is closed")
	}
	if a.f != nil && a.size >= a.maxBytes && !a.pendingRotate && !a.now().Before(a.rotateRetryAt) {
		if err := a.rotateLocked(); err != nil {
			// the line must not be lost: when the file was not moved, keep appending to it
			log.Errorf("admin audit: rotation failed, the file keeps growing, next try in a minute: %v", err)
			a.rotateRetryAt = a.now().Add(time.Minute)
		}
	}
	if a.pendingRotate {
		if err := a.finishRotateLocked(); err != nil {
			return adminAuditRecord{}, err
		}
	}
	rec := a.appendLocked(actor, action, target, source, result, detail, secrets)
	return rec, a.lastWriteErr
}

// appendLocked writes one line and sets lastWriteErr; a sync error still returns the record, which is in the file.
func (a *adminAuditLog) appendLocked(actor, action, target, source, result, detail string, secrets []string) adminAuditRecord {
	rec := adminAuditRecord{
		Seq:    a.seq + 1,
		Ts:     a.now().UTC().Format(time.RFC3339),
		Actor:  auditText(actor, adminAuditMaxTarget, secrets),
		Action: action,
		Target: auditText(target, adminAuditMaxTarget, secrets),
		Source: auditText(source, adminAuditMaxTarget, nil),
		Result: result,
		Detail: auditText(detail, adminAuditMaxDetail, secrets),
		Prev:   a.lastHash,
	}
	rec.Hash = rec.hashOf()
	line, _ := json.Marshal(rec)
	a.lastWriteErr = nil
	line = append(line, '\n')
	n, err := a.f.Write(line)
	if err != nil || n != len(line) {
		if err == nil {
			err = io.ErrShortWrite
		}
		// a half line would break the chain: take it back, the line is reported as not written
		if n > 0 {
			if terr := a.f.Truncate(a.size); terr != nil {
				log.Errorf("admin audit: cannot remove a partly written line from %s: %v", a.path, terr)
				_ = a.f.Close()
				a.f = nil
			}
		}
		a.lastWriteErr = fmt.Errorf("writing the admin audit file: %w", err)
		return adminAuditRecord{}
	}
	a.size += int64(len(line))
	a.seq, a.lastHash = rec.Seq, rec.Hash
	a.lines++
	if a.noSync {
		// tests that write ten mebibytes
	} else if err := a.f.Sync(); err != nil {
		a.lastWriteErr = fmt.Errorf("syncing the admin audit file: %w", err)
	}
	if a.hook != nil {
		a.hook.Enqueue(line[:len(line)-1])
	}
	return rec
}

// rotateLocked moves the generations up and the file to .1. The new file is opened by finishRotateLocked.
func (a *adminAuditLog) rotateLocked() error {
	if a.f == nil {
		return errors.New("no open file")
	}
	// the oldest generation goes first; a missing one is fine
	if err := os.Remove(a.generation(adminAuditGenerations)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for n := adminAuditGenerations - 1; n >= 1; n-- {
		if err := os.Rename(a.generation(n), a.generation(n+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(a.path, a.generation(1)); err != nil {
		return err
	}
	_ = a.f.Close()
	a.f, a.size, a.lines = nil, 0, 0
	a.pendingRotate = true
	return nil
}

// finishRotateLocked opens the new file and writes its first line, audit.rotate, chained to the closed one.
func (a *adminAuditLog) finishRotateLocked() error {
	if a.f == nil {
		f, err := openAuditNew(a.path)
		if errors.Is(err, os.ErrExist) {
			f, err = openAuditAppend(a.path)
		}
		if err != nil {
			return err
		}
		a.f, a.size, a.lines = f, 0, 0
		if fi, err := f.Stat(); err == nil {
			a.size = fi.Size()
		}
	}
	a.pendingRotate = false
	detail := fmt.Sprintf("rotated %s to %s", filepath.Base(a.path), filepath.Base(a.generation(1)))
	a.appendLocked(adminAuditSystemActor, adminAuditRotateAction, filepath.Base(a.path), adminAuditLocalSource, adminAuditResultOK, detail, nil)
	return a.lastWriteErr
}

// auditText makes a value fit a single JSON line without secrets: valid UTF-8, no control characters,
// bounded, every given secret masked, and anything that looks like key or certificate material dropped.
func auditText(s string, maxRunes int, secrets []string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, adminAuditRedacted)
		}
	}
	if strings.Contains(s, "-----BEGIN") {
		return adminAuditRedacted
	}
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxRunes {
		r := []rune(s)
		s = string(r[:maxRunes-1]) + "…"
	}
	return s
}

// ---- reading: list and verify ----

// files returns the paths of the existing generations, oldest first, the current file last.
func (a *adminAuditLog) files() []string {
	var out []string
	for n := adminAuditGenerations; n >= 1; n-- {
		if _, err := os.Lstat(a.generation(n)); err == nil {
			out = append(out, a.generation(n))
		}
	}
	return append(out, a.path)
}

// eachLine calls fn for every line of the file (without the newline); ok is false when the line had no
// terminating newline. A missing file has no lines.
func eachAuditLine(path string, fn func(line []byte, terminated bool) bool) error {
	f, err := openAuditRead(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("%s: %s", filepath.Base(path), adminAuditSymlinkRefusedMsg)
		}
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			term := line[len(line)-1] == '\n'
			if term {
				line = line[:len(line)-1]
			}
			if !fn(line, term) {
				return nil
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// List returns up to limit records with seq < before (0 = no bound), newest first, reading the current
// file and then the older generations until the limit is met. Lines that do not parse are skipped:
// verify is the place that reports them.
func (a *adminAuditLog) List(limit int, before int64) ([]adminAuditRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	files := a.files()
	out := make([]adminAuditRecord, 0, limit)
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		need := limit - len(out)
		var window []adminAuditRecord // the newest `need` matching records of this file, oldest first
		err := eachAuditLine(files[i], func(line []byte, _ bool) bool {
			rec, err := parseAdminAuditLine(line)
			if err != nil || (before > 0 && rec.Seq >= before) {
				return true
			}
			window = append(window, rec)
			if len(window) > 2*need {
				window = append(window[:0], window[len(window)-need:]...)
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		if len(window) > need {
			window = window[len(window)-need:]
		}
		for j := len(window) - 1; j >= 0; j-- {
			out = append(out, window[j])
		}
	}
	return out, nil
}

// adminAuditVerifyOK and adminAuditVerifyBroken are the two shapes of GET /api/audit/verify.
type adminAuditVerifyOK struct {
	OK       bool   `json:"ok"`
	Lines    int64  `json:"lines"`
	LastHash string `json:"lastHash"`
}

type adminAuditVerifyBroken struct {
	OK       bool   `json:"ok"`
	BrokenAt int64  `json:"brokenAt"`
	Reason   string `json:"reason"`
}

// Verify walks every generation, oldest first, and checks each line: parseable and in canonical form, its
// hash, its prev (the hash of the line before, across files too), and an unbroken seq. A first line of a
// file after the oldest must be audit.rotate. The first problem is reported with the seq the line should
// have; nothing is repaired.
func (a *adminAuditLog) Verify() (okRes *adminAuditVerifyOK, bad *adminAuditVerifyBroken) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var (
		total    int64
		prevHash string
		expect   int64 // seq the next line must have, 0 = not known yet (first line)
		haveAny  bool
	)
	fail := func(seq int64, reason string) {
		if seq < 1 {
			seq = 1
		}
		bad = &adminAuditVerifyBroken{OK: false, BrokenAt: seq, Reason: reason}
	}
	files := a.files()
	for fi, path := range files {
		first := true
		err := eachAuditLine(path, func(line []byte, terminated bool) bool {
			total++
			want := expect
			rec, perr := parseAdminAuditLine(line)
			if want == 0 {
				want = rec.Seq // the very first line: nothing to compare with
				if perr != nil {
					want = looseSeq(line)
				}
			}
			if !terminated {
				fail(want, fmt.Sprintf("%s: the last line has no terminating newline", filepath.Base(path)))
				return false
			}
			if perr != nil {
				fail(want, fmt.Sprintf("%s: the line is not valid: %v", filepath.Base(path), perr))
				return false
			}
			if rec.Hash != rec.hashOf() {
				fail(want, fmt.Sprintf("%s: the line does not match its hash", filepath.Base(path)))
				return false
			}
			if canon, _ := json.Marshal(rec); !bytes.Equal(canon, line) {
				fail(want, fmt.Sprintf("%s: the line is not in canonical form", filepath.Base(path)))
				return false
			}
			if rec.Seq != want {
				fail(want, fmt.Sprintf("%s: seq is %d, expected %d", filepath.Base(path), rec.Seq, want))
				return false
			}
			switch {
			case !haveAny:
				// the oldest file kept: it starts a chain, or continues one whose older files are gone
				if rec.Prev != adminAuditZeroHash && rec.Action != adminAuditRotateAction {
					fail(want, fmt.Sprintf("%s: the first line does not start a chain", filepath.Base(path)))
					return false
				}
			case rec.Prev != prevHash:
				fail(want, fmt.Sprintf("%s: prev does not match the hash of the line before", filepath.Base(path)))
				return false
			case first && fi > 0 && rec.Action != adminAuditRotateAction:
				fail(want, fmt.Sprintf("%s: the first line of a rotated file is not %s", filepath.Base(path), adminAuditRotateAction))
				return false
			}
			haveAny, first = true, false
			prevHash, expect = rec.Hash, rec.Seq+1
			return true
		})
		if bad != nil {
			return nil, bad
		}
		if err != nil {
			fail(expect, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			return nil, bad
		}
	}
	if !haveAny {
		prevHash = adminAuditZeroHash
	}
	return &adminAuditVerifyOK{OK: true, Lines: total, LastHash: prevHash}, nil
}

// looseSeq reads seq out of a line that does not parse as a record, for the report only.
func looseSeq(line []byte) int64 {
	var m struct {
		Seq int64 `json:"seq"`
	}
	_ = json.Unmarshal(line, &m)
	return m.Seq
}

// ---- who and from where ----

// auditSource is the direct peer address without the port. X-Forwarded-For is never used: a client could
// write anything into it.
func auditSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return adminAuditLocalSource
	}
	return host
}

// auditActor names the Basic Auth user of an authenticated request. A request without Basic credentials
// (the panel runs without authentication, or the sync call of a slave) is "system"; its source says where
// it came from.
func auditActor(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		return "basic-auth:" + user
	}
	return adminAuditSystemActor
}

// fromRequest records an action of an authenticated request at the point where its result is known. A
// failed write is logged, never returned: the panel action has happened (or failed) already.
func (a *adminAuditLog) fromRequest(r *http.Request, action, target string, ok bool, detail string, secrets ...string) {
	if a == nil {
		return
	}
	result := adminAuditResultFail
	if ok {
		result = adminAuditResultOK
	}
	// whatever the request carried as credentials must not reach the file, whatever the detail says
	if user, pass, has := r.BasicAuth(); has {
		secrets = append(secrets, pass)
		_ = user
	}
	if h := r.Header.Get("Authorization"); h != "" {
		secrets = append(secrets, h)
		if _, tok, found := strings.Cut(h, " "); found {
			secrets = append(secrets, tok)
		}
	}
	if _, err := a.Record(auditActor(r), action, target, auditSource(r), result, detail, secrets...); err != nil {
		log.Errorf("admin audit: %s %s was NOT recorded: %v", action, result, err)
	}
}

// system records an action nobody asked for in a request (the scheduled CRL rebuild).
func (a *adminAuditLog) system(action, target string, ok bool, detail string) {
	if a == nil {
		return
	}
	result := adminAuditResultFail
	if ok {
		result = adminAuditResultOK
	}
	if _, err := a.Record(adminAuditSystemActor, action, target, adminAuditLocalSource, result, detail); err != nil {
		log.Errorf("admin audit: %s %s was NOT recorded: %v", action, result, err)
	}
}

// firstLine is the first line of an error or answer text, for a detail.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// auditDetail is okText for a success and the first line of failText for a failure.
func auditDetail(ok bool, okText, failText string) string {
	if ok {
		return okText
	}
	return firstLine(failText)
}

// auditErrDetail is okText when err is nil and the first line of the error otherwise.
func auditErrDetail(err error, okText string) string {
	if err == nil {
		return okText
	}
	return firstLine(err.Error())
}

// ---- login events ----

// adminLoginThrottle keeps the trail from being flooded by traffic that is one event in substance: a
// browser sends its credentials with every request, and a password guesser sends thousands. A successful
// login is recorded once per user and source per window; failed logins once per source per window, the
// next line says how many were left out.
type adminLoginThrottle struct {
	mu         sync.Mutex
	okSeen     map[string]time.Time
	failSeen   map[string]time.Time
	suppressed map[string]int
}

func (t *adminLoginThrottle) shouldRecordOK(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.okSeen == nil {
		t.okSeen = map[string]time.Time{}
	}
	if last, ok := t.okSeen[key]; ok && now.Sub(last) < adminAuditLoginOKWindow {
		return false
	}
	pruneSeen(t.okSeen, now, adminAuditLoginOKWindow)
	t.okSeen[key] = now
	return true
}

func (t *adminLoginThrottle) shouldRecordFail(key string, now time.Time) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failSeen == nil {
		t.failSeen, t.suppressed = map[string]time.Time{}, map[string]int{}
	}
	if last, ok := t.failSeen[key]; ok && now.Sub(last) < adminAuditLoginFailWindow {
		t.suppressed[key]++
		return false, 0
	}
	if len(t.failSeen) >= adminAuditThrottleMaxKeys {
		for k, ts := range t.failSeen {
			if now.Sub(ts) >= adminAuditLoginFailWindow {
				delete(t.failSeen, k)
				delete(t.suppressed, k)
			}
		}
		if len(t.failSeen) >= adminAuditThrottleMaxKeys { // a flood from thousands of sources: start over
			t.failSeen, t.suppressed = map[string]time.Time{}, map[string]int{}
		}
	}
	n := t.suppressed[key]
	delete(t.suppressed, key)
	t.failSeen[key] = now
	return true, n
}

func pruneSeen(m map[string]time.Time, now time.Time, window time.Duration) {
	if len(m) < adminAuditThrottleMaxKeys {
		return
	}
	for k, ts := range m {
		if now.Sub(ts) >= window {
			delete(m, k)
		}
	}
	if len(m) >= adminAuditThrottleMaxKeys {
		clear(m)
	}
}

// loginOK records a successful Basic Auth login (throttled per user and source).
func (a *adminAuditLog) loginOK(r *http.Request, user string) {
	if a == nil {
		return
	}
	src := auditSource(r)
	if !a.throttle.shouldRecordOK(user+"\x00"+src, a.now()) {
		return
	}
	a.loginEvent(auditActLoginOK, user, src, adminAuditResultOK, "login accepted")
}

// loginFail records a failed Basic Auth attempt: the user name that was tried and the source, never the
// password (throttled per source).
func (a *adminAuditLog) loginFail(r *http.Request, user string) {
	if a == nil {
		return
	}
	src := auditSource(r)
	rec, skipped := a.throttle.shouldRecordFail(src, a.now())
	if !rec {
		return
	}
	detail := "credentials rejected"
	if skipped > 0 {
		detail = fmt.Sprintf("credentials rejected; %d more from this source in the last %s not recorded", skipped, adminAuditLoginFailWindow)
	}
	a.loginEvent(auditActLoginFail, user, src, adminAuditResultFail, detail)
}

// loginLocked records an attempt that was refused because the account is locked. It is the hook for the
// per-account lockout; it is not throttled, a lockout is rare and worth every line.
func (a *adminAuditLog) loginLocked(r *http.Request, user string) {
	if a == nil {
		return
	}
	a.loginEvent(auditActLoginLocked, user, auditSource(r), adminAuditResultFail, "account is locked")
}

func (a *adminAuditLog) loginEvent(action, user, src, result, detail string) {
	user = auditText(user, 64, nil)
	if _, err := a.Record("basic-auth:"+user, action, user, src, result, detail); err != nil {
		log.Errorf("admin audit: %s was NOT recorded: %v", action, err)
	}
}

// ---- HTTP ----

// adminAuditListHandler serves GET /api/audit/admin?limit=100&before=<seq>: newest first. limit is 1..500
// (default 100, a larger value is cut to 500); before returns only lines with a smaller seq, so the seq of
// the last line of a page is the before of the next.
func (oAdmin *OvpnAdmin) adminAuditListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !auditGetOnly(w, r) {
		return
	}
	limit := adminAuditDefaultLimit
	var before int64
	q := r.URL.Query()
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			http.Error(w, `{"status":"error","message":"limit must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		limit = min(n, adminAuditMaxLimit)
	}
	if raw := strings.TrimSpace(q.Get("before")); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			http.Error(w, `{"status":"error","message":"before must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		before = n
	}
	if adminAudit == nil {
		http.Error(w, `{"status":"error","message":"the admin audit trail is not enabled"}`, http.StatusServiceUnavailable)
		return
	}
	recs, err := adminAudit.List(limit, before)
	if err != nil {
		log.Errorf("admin audit: list: %v", err)
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}
	body, _ := json.Marshal(recs)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// adminAuditVerifyHandler serves GET /api/audit/verify and records the check itself as audit.verify.
func (oAdmin *OvpnAdmin) adminAuditVerifyHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !auditGetOnly(w, r) {
		return
	}
	if adminAudit == nil {
		http.Error(w, `{"status":"error","message":"the admin audit trail is not enabled"}`, http.StatusServiceUnavailable)
		return
	}
	okRes, bad := adminAudit.Verify()
	var body []byte
	if bad != nil {
		body, _ = json.Marshal(bad)
		adminAudit.fromRequest(r, auditActAuditVerify, filepath.Base(adminAudit.path), false,
			fmt.Sprintf("chain broken at seq %d", bad.BrokenAt))
	} else {
		body, _ = json.Marshal(okRes)
		adminAudit.fromRequest(r, auditActAuditVerify, filepath.Base(adminAudit.path), true,
			fmt.Sprintf("chain intact: %d lines", okRes.Lines))
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func auditGetOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, `{"status":"error"}`, http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// ---- webhook ----

// adminAuditWebhook ships every line to a URL, best effort. Lines wait in a queue of 256; a full queue
// drops the new line and counts it. One worker posts them one by one with a 3 s timeout, so a slow or
// failing receiver costs nothing but those lines: Enqueue never blocks, and nothing is retried or kept.
type adminAuditWebhook struct {
	target  string // scheme://host, for the log; the URL itself may carry a secret
	url     string
	client  *http.Client
	queue   chan []byte
	dropped atomic.Int64
	failed  atomic.Int64
	sent    atomic.Int64
	logEach time.Duration
	ctx     context.Context // cancelled by Close: a post in flight does not hold the shutdown
	cancel  context.CancelFunc
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// validateAuditWebhookURL refuses everything but https, except plain http to a loopback address.
func validateAuditWebhookURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, errors.New("the admin audit webhook is not a valid URL")
	}
	host := u.Hostname()
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u, nil
	case "http":
		if isLoopbackHost(host) {
			return u, nil
		}
		return nil, fmt.Errorf("the admin audit webhook %s://%s is refused: plain http is only allowed to a loopback address, use https", u.Scheme, u.Host)
	}
	return nil, fmt.Errorf("the admin audit webhook scheme %q is refused: use https", u.Scheme)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newAdminAuditWebhook(raw string) (*adminAuditWebhook, error) {
	return newAdminAuditWebhookEvery(raw, adminAuditWebhookLogEach)
}

// newAdminAuditWebhookEvery is newAdminAuditWebhook with the period of the counter line; the tests shorten it.
func newAdminAuditWebhookEvery(raw string, logEach time.Duration) (*adminAuditWebhook, error) {
	u, err := validateAuditWebhookURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &adminAuditWebhook{
		ctx:     ctx,
		cancel:  cancel,
		target:  u.Scheme + "://" + u.Host,
		url:     u.String(),
		queue:   make(chan []byte, adminAuditWebhookQueue),
		logEach: logEach,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		client: &http.Client{
			Timeout: adminAuditWebhookTimeout,
			// a redirect could lead from https to plain http or to another host: it is a failure
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	go w.run()
	go w.logLoop()
	return w, nil
}

// Enqueue never blocks; a full queue drops the line.
func (w *adminAuditWebhook) Enqueue(line []byte) {
	cp := make([]byte, len(line))
	copy(cp, line)
	select {
	case w.queue <- cp:
	default:
		w.dropped.Add(1)
	}
}

func (w *adminAuditWebhook) run() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case line := <-w.queue:
			w.post(line)
		}
	}
}

// logLoop is separate from the worker: while the worker waits for a receiver that hangs, the line about the
// dropped lines still comes once per period.
func (w *adminAuditWebhook) logLoop() {
	tick := time.NewTicker(w.logEach)
	defer tick.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-tick.C:
			w.logCounters()
		}
	}
}

// logCounters writes the one line per period: how many lines were dropped or failed since the last one.
func (w *adminAuditWebhook) logCounters() {
	dropped, failed := w.dropped.Swap(0), w.failed.Swap(0)
	if dropped > 0 || failed > 0 {
		log.Warnf("admin audit webhook %s: %d lines dropped (queue full), %d not delivered, in the last %s", w.target, dropped, failed, w.logEach)
	}
}

func (w *adminAuditWebhook) post(line []byte) {
	ctx, cancel := context.WithTimeout(w.ctx, adminAuditWebhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(line))
	if err != nil {
		w.failed.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ovpn-admin-audit/"+version)
	resp, err := w.client.Do(req)
	if err != nil {
		w.failed.Add(1)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		w.failed.Add(1)
		return
	}
	w.sent.Add(1)
}

// Close stops the worker; lines still queued are dropped.
func (w *adminAuditWebhook) Close() {
	w.once.Do(func() {
		close(w.stop)
		w.cancel()
	})
	<-w.done
}

// initAdminAudit opens the trail named by the flags and logs the start line. The caller exits on error.
func initAdminAudit() error {
	a, err := openAdminAuditLog(*adminAuditFileFlag, *adminAuditWebhookFlag)
	if err != nil {
		return err
	}
	adminAudit = a
	hook := "off"
	if a.hook != nil {
		hook = a.hook.target
	}
	log.Infof("admin audit trail: file=%s lines=%d seq=%d webhook=%s", a.path, a.Lines(), a.seq, hook)
	return nil
}
