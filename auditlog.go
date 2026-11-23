package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	"slices"
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
//
// What a green verify means. The chain alone cannot show that the newest lines still exist: a file
// without its last lines is a valid chain. So the panel also keeps a checkpoint, <file>.checkpoint, with
// the seq and hash of the newest line it committed (replaced atomically and synced every
// adminAuditCheckpointEvery lines or adminAuditCheckpointMaxAge, whichever comes first, at every rotation
// and at Close), and verify holds the files against three independent things: the checkpoint, the newest
// line this process wrote (kept in memory) and the identity of the open file. GET /api/audit/verify
// answers one of three states, always with HTTP 200, and `ok` is true only for the first:
//
//	verified    ok:true   the chain is intact and continuous with the checkpoint and with the newest line
//	                      this process wrote
//	broken      ok:false  a concrete break: an edited, removed, reordered or cut-off line, a missing,
//	                      replaced or unfinished active file, a newest line that is gone, a checkpoint that
//	                      names a line the trail does not have, or a start that found one of these
//	unverified  ok:false  continuity cannot be established: no checkpoint, an unreadable one, a trail that
//	                      was taken over without one
//
// A start that finds the trail shorter than its checkpoint (or without a checkpoint, or with an
// unreadable one) keeps the panel running, and writes <file>.continuity-lost so that the finding survives
// further restarts; verify reports it until an operator has looked at it and moved that file away.
//
// Limits that no code here removes. SHA-256 shows consistency, not who wrote a line: anybody who can write
// the files can write a consistent history. The checkpoint sits next to the trail and shares the fate of
// the volume unless it is protected separately (copy it elsewhere, or make the directory append-only). It
// is not written per line: the newest lines after it (at most adminAuditCheckpointEvery, "unanchored" in
// the answer) are covered by the running panel's memory only. A record that could not be written is not in
// the trail: the next line that can be written is an audit.gap saying how many were lost (a restart in
// between forgets the count), and a green verify says how many audit.gap lines it saw and how many records it knows
// are not accounted for yet ("unrecorded"): it vouches for the chain, not for the completeness of what was
// audited.
//
// What is recorded (and nothing else): user.create, user.delete, user.revoke, user.unrevoke, user.rotate,
// user.change-password, user.config.download (ok only when the configuration was rendered), user.ccd.apply,
// user.disconnect (always a failure: the call is not implemented, HTTP 200 notwithstanding), ban.manual,
// unban, auth.login.ok (once per user and source per 30 minutes), auth.login.fail (once per source per
// 10 seconds), pki.crl.rebuild (the scheduled one), sync.export, audit.verify, audit.read (GET
// /api/audit/admin), and the lines the trail writes about itself: audit.rotate and audit.gap. Not
// recorded: requests refused before the handler (wrong method, other origin, slave role), the browser
// challenge without an Authorization header, rebuilds inside user operations, the slave's import of PKI
// and CCD, and the 403 of the audit endpoints when no admin credentials are configured (that would let an
// unauthenticated caller write lines; it goes to the ordinary log). The panel has no account lockout and no
// settings change, so there is no record for them. server.renew and server.renew.confirm exist as names
// for the certificate lifecycle code that is not part of this revision; nothing records them here.
//
// The trail is served to an authenticated admin only: with no Basic credentials configured the audit
// endpoints answer 403 (the middleware cannot protect what it was not given), and the actor of a line is
// "basic-auth:<user>" only when the request carried the configured credentials, otherwise "unverified:<user>".
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

	adminAuditLoginOKWindow   = 30 * time.Minute // one auth.login.ok per user and source per window
	adminAuditLoginFailWindow = 10 * time.Second // one auth.login.fail per source per window
	adminAuditThrottleMaxKeys = 4096

	adminAuditCheckpointSuffix = ".checkpoint"
	adminAuditNoticeSuffix     = ".continuity-lost"
	adminAuditCheckpointEvery  = 16               // lines between two checkpoints
	adminAuditCheckpointMaxAge = 30 * time.Second // or this long, whichever comes first (checked at a write)
	adminAuditUnauthActorMark  = "unverified:"    // the actor prefix of a request that did not prove the admin credentials
	adminAuditMaxNoticeBytes   = 64 << 10
	adminAuditGapActors        = 8 // distinct actions named in one audit.gap line

	adminAuditSystemActor       = "system"
	adminAuditLocalSource       = "local"
	adminAuditResultOK          = "ok"
	adminAuditResultFail        = "fail"
	adminAuditRotateAction      = "audit.rotate"
	adminAuditRedacted          = "[redacted]"
	adminAuditSymlinkRefusedMsg = "refusing to follow a symlink"
)

// The actions the panel records (see the list at the top). Every name here has a production emitter.
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
	auditActCrlRebuild         = "pki.crl.rebuild"
	auditActSyncExport         = "sync.export"
	auditActAuditVerify        = "audit.verify"
	auditActAuditRead          = "audit.read"
	auditActAuditGap           = "audit.gap" // written by the trail itself: records that could not be written

	// Names for the certificate lifecycle code (cert_lifecycle.go, not part of this revision). Nothing in
	// the committed tree records them; they stay so that code compiles against this file, and the
	// contract at the top does not list them as recorded.
	auditActServerRenew        = "server.renew"
	auditActServerRenewConfirm = "server.renew.confirm"
)

var (
	adminAuditFileFlag     = kingpin.Flag("admin-audit.file", "path of the admin audit trail (hash chained JSON lines, 10 MiB per file, 5 generations, plus <file>.checkpoint); the directory is created 0700 and the file 0600, a symlink at either path is refused, and the panel does not start when the file cannot be written").Default(adminAuditDefaultFile).Envar("OVPN_ADMIN_AUDIT_FILE").String()
	adminAuditWebhookFlag  = kingpin.Flag("admin-audit.webhook", "optional URL that receives every admin audit line as a JSON POST (3 s timeout, queue of 256, a full queue drops lines); https only, plain http only for a loopback address").Default("").Envar("OVPN_ADMIN_AUDIT_WEBHOOK").String()
	adminAuditRequiredFlag = kingpin.Flag("admin-audit.required", "when true an admin action whose audit line cannot be written is answered with HTTP 500 (the action itself has been carried out: the answer says so); when false, the default, the failure is only logged").Default("false").Envar("OVPN_ADMIN_AUDIT_REQUIRED").Bool()
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

	// the checkpoint file: the seq it holds, when it was written and how many lines came after it
	cpSeq   int64
	cpAt    time.Time
	sinceCP int64

	// records that could not be written since the last audit.gap line
	lost adminAuditLost

	// fault is a test seam: it is asked before every disk operation ("write", "sync", "truncate",
	// "rename <from> <to>", "syncdir", "checkpoint") and a non-nil answer is the failure of that operation.
	fault func(op string) error

	hook     *adminAuditWebhook
	throttle adminLoginThrottle
}

// adminAuditLost counts the records the trail could not write. It lives in memory only.
type adminAuditLost struct {
	n        int64
	first    time.Time
	last     time.Time
	actions  []string
	firstErr string
}

// openAdminAuditLog opens (and on first use creates) the trail. It fails closed: a symlink at the directory
// or the file, a file that is not a regular file, a file that cannot be opened for appending, a last
// line that is not a valid link of the chain, or a checkpoint that cannot be written are errors the
// caller turns into a failed start.
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

func (a *adminAuditLog) generation(n int) string { return a.path + "." + strconv.Itoa(n) }
func (a *adminAuditLog) checkpointPath() string  { return a.path + adminAuditCheckpointSuffix }
func (a *adminAuditLog) noticePath() string      { return a.path + adminAuditNoticeSuffix }

// injected is the answer of the test seam for one disk operation; nil in production.
func (a *adminAuditLog) injected(op string) error {
	if a.fault == nil {
		return nil
	}
	return a.fault(op)
}

func (a *adminAuditLog) renameFile(from, to string) error {
	if err := a.injected("rename " + filepath.Base(from) + " " + filepath.Base(to)); err != nil {
		return err
	}
	return os.Rename(from, to)
}

// syncDirectory makes the directory entries (a rename, a new file) durable.
func (a *adminAuditLog) syncDirectory() error {
	if a.noSync {
		return nil
	}
	if err := a.injected("syncdir"); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(a.path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (a *adminAuditLog) open() error {
	dir := filepath.Dir(a.path)
	if err := ensureAuditDir(dir); err != nil {
		return err
	}
	// "fresh": no file of the trail exists, so there is nothing a checkpoint could contradict
	fresh := true
	for _, p := range append([]string{a.path}, a.generationPaths()...) {
		if _, err := os.Lstat(p); err == nil {
			fresh = false
		}
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
	fail := func(err error) error {
		f.Close()
		a.f = nil
		return err
	}

	tipSeq, tipHash := int64(0), adminAuditZeroHash
	fromGeneration := false
	if lines > 0 {
		tipSeq, tipHash = last.Seq, last.Hash
	} else if g, gerr := openAuditRead(a.generation(1)); gerr == nil {
		// an empty file next to a closed generation: a rotation that was cut off between the rename and the
		// first line. Whether that is what happened is for the checkpoint to say, below.
		if gfi, serr := g.Stat(); serr == nil {
			if _, glast, gerr := scanAuditTail(g, gfi.Size()); gerr == nil && glast.Hash != "" {
				tipSeq, tipHash, fromGeneration = glast.Seq, glast.Hash, true
			}
		}
		g.Close()
	}

	// the checkpoint is what the panel last said it had committed: the trail must not end before it
	var notices []adminAuditNotice
	cp, cpState, cpErr := readAdminAuditCheckpoint(a.checkpointPath())
	switch cpState {
	case adminAuditCheckpointOK:
		switch {
		case cp.Seq > tipSeq:
			notices = append(notices, adminAuditNotice{Kind: adminAuditNoticeBroken, Reason: fmt.Sprintf(
				"at start the checkpoint names seq %d (hash %s) but the trail ends at seq %d: the newest %d records are missing; the chain continues from the checkpoint",
				cp.Seq, cp.Hash, tipSeq, cp.Seq-tipSeq)})
			tipSeq, tipHash, fromGeneration = cp.Seq, cp.Hash, false
		case cp.Seq == tipSeq && cp.Hash != tipHash:
			notices = append(notices, adminAuditNotice{Kind: adminAuditNoticeBroken, Reason: fmt.Sprintf(
				"at start the checkpoint names seq %d with hash %s but the trail has hash %s at that seq", cp.Seq, cp.Hash, tipHash)})
		}
	case adminAuditCheckpointMissing:
		if !fresh {
			notices = append(notices, adminAuditNotice{Kind: adminAuditNoticeUnverified, Reason: fmt.Sprintf(
				"at start the trail existed (newest seq %d) without a checkpoint: nothing shows whether newer records were lost before this start", tipSeq)})
		}
	default:
		notices = append(notices, adminAuditNotice{Kind: adminAuditNoticeUnverified, Reason: fmt.Sprintf(
			"at start the checkpoint was unreadable (%v): nothing shows whether newer records were lost before this start", cpErr)})
	}
	for _, n := range notices {
		log.Errorf("admin audit: %s", n.Reason)
		if err := a.writeNotice(n); err != nil {
			return fail(fmt.Errorf("admin audit: cannot record the finding in %s: %w", a.noticePath(), err))
		}
	}

	a.seq, a.lastHash, a.pendingRotate = tipSeq, tipHash, fromGeneration
	if cpState == adminAuditCheckpointOK && cp.Seq == tipSeq && cp.Hash == tipHash {
		a.cpSeq, a.cpAt = cp.Seq, a.now()
	} else if err := a.writeCheckpointLocked(); err != nil {
		return fail(fmt.Errorf("admin audit checkpoint %s: %w", a.checkpointPath(), err))
	}
	return nil
}

func (a *adminAuditLog) generationPaths() []string {
	out := make([]string, 0, adminAuditGenerations)
	for n := 1; n <= adminAuditGenerations; n++ {
		out = append(out, a.generation(n))
	}
	return out
}

// ---- the checkpoint and the notices ----

// adminAuditCheckpoint is the content of <file>.checkpoint: the newest line the panel committed. Sum is a
// plain SHA-256 over the other fields, so that a damaged file is told from an honest one; it proves nothing
// about who wrote it.
type adminAuditCheckpoint struct {
	V    int    `json:"v"`
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
	Ts   string `json:"ts"`
	Sum  string `json:"sum"`
}

func (c adminAuditCheckpoint) sum() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("ovpn-admin audit checkpoint v%d\n%d\n%s\n%s", c.V, c.Seq, c.Hash, c.Ts)))
	return hex.EncodeToString(h[:])
}

type adminAuditCheckpointState int

const (
	adminAuditCheckpointOK adminAuditCheckpointState = iota
	adminAuditCheckpointMissing
	adminAuditCheckpointBad
)

func readAdminAuditCheckpoint(path string) (adminAuditCheckpoint, adminAuditCheckpointState, error) {
	var cp adminAuditCheckpoint
	f, err := openAuditRead(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cp, adminAuditCheckpointMissing, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return cp, adminAuditCheckpointBad, fmt.Errorf("%s", adminAuditSymlinkRefusedMsg)
		}
		return cp, adminAuditCheckpointBad, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return cp, adminAuditCheckpointBad, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cp); err != nil {
		return adminAuditCheckpoint{}, adminAuditCheckpointBad, err
	}
	if cp.V != 1 || cp.Sum != cp.sum() || cp.Seq < 0 || len(cp.Hash) != 64 {
		return adminAuditCheckpoint{}, adminAuditCheckpointBad, errors.New("the checkpoint does not match its own sum")
	}
	return cp, adminAuditCheckpointOK, nil
}

// writeCheckpointLocked replaces the checkpoint with the newest line this process committed: a temporary
// file, synced, renamed over the old one, then the directory synced. The old checkpoint stays whole when
// any step fails.
func (a *adminAuditLog) writeCheckpointLocked() error {
	if err := a.injected("checkpoint"); err != nil {
		return err
	}
	cp := adminAuditCheckpoint{V: 1, Seq: a.seq, Hash: a.lastHash, Ts: a.now().UTC().Format(time.RFC3339)}
	cp.Sum = cp.sum()
	data, _ := json.Marshal(cp)
	data = append(data, '\n')
	tmp := a.checkpointPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil && !a.noSync {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, a.checkpointPath())
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := a.syncDirectory(); err != nil {
		return err
	}
	a.cpSeq, a.cpAt, a.sinceCP = cp.Seq, a.now(), 0
	return nil
}

// checkpointDueLocked: every adminAuditCheckpointEvery lines, or when the last one is older than the
// maximum age and something came after it.
func (a *adminAuditLog) checkpointDueLocked() bool {
	return a.sinceCP >= adminAuditCheckpointEvery || (a.sinceCP > 0 && a.now().Sub(a.cpAt) >= adminAuditCheckpointMaxAge)
}

const (
	adminAuditNoticeBroken     = "broken"
	adminAuditNoticeUnverified = "unverified"
)

// adminAuditNotice is a finding of a start: it is kept in <file>.continuity-lost, one JSON object per line,
// until an operator moves the file away.
type adminAuditNotice struct {
	Ts     string `json:"ts"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

func (a *adminAuditLog) writeNotice(n adminAuditNotice) error {
	n.Ts = a.now().UTC().Format(time.RFC3339)
	line, _ := json.Marshal(n)
	f, err := os.OpenFile(a.noticePath(), os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil && !a.noSync {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return a.syncDirectory()
}

// readNotices returns the findings of earlier starts. An unreadable file is itself a finding.
func (a *adminAuditLog) readNotices() []adminAuditNotice {
	f, err := openAuditRead(a.noticePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return []adminAuditNotice{{Kind: adminAuditNoticeBroken, Reason: fmt.Sprintf("%s cannot be read: %v", filepath.Base(a.noticePath()), err)}}
	}
	defer f.Close()
	data, _ := io.ReadAll(io.LimitReader(f, adminAuditMaxNoticeBytes))
	var out []adminAuditNotice
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var n adminAuditNotice
		if json.Unmarshal(line, &n) != nil || (n.Kind != adminAuditNoticeBroken && n.Kind != adminAuditNoticeUnverified) {
			n = adminAuditNotice{Kind: adminAuditNoticeBroken, Reason: filepath.Base(a.noticePath()) + " holds a line that is not a finding"}
		}
		out = append(out, n)
	}
	return out
}

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

// Close stops the webhook worker, writes the final checkpoint and closes the file.
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
		if a.sinceCP > 0 {
			if err := a.writeCheckpointLocked(); err != nil {
				log.Errorf("admin audit: the final checkpoint was not written: %v", err)
			}
		}
		_ = a.f.Close()
		a.f = nil
	}
}

// Record appends one line. The returned error means the line is NOT in the file (it is counted, and the
// next line that can be written is an audit.gap saying so); the webhook never influences it. Detail and
// target are made single-line and bounded; callers pass secrets they handled so they are masked even when an
// error message happens to contain them.
func (a *adminAuditLog) Record(actor, action, target, source, result, detail string, secrets ...string) (adminAuditRecord, error) {
	if a == nil {
		return adminAuditRecord{}, nil
	}
	if result != adminAuditResultOK {
		result = adminAuditResultFail
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	rec, err := a.recordLocked(actor, action, target, source, result, detail, secrets)
	if err != nil {
		a.noteLostLocked(action, err)
	}
	return rec, err
}

func (a *adminAuditLog) recordLocked(actor, action, target, source, result, detail string, secrets []string) (adminAuditRecord, error) {
	if a.f == nil && !a.pendingRotate {
		return adminAuditRecord{}, errors.New("the admin audit file is closed")
	}
	if a.f != nil && a.size >= a.maxBytes && !a.pendingRotate && !a.now().Before(a.rotateRetryAt) {
		if err := a.rotateLocked(); err != nil {
			// the line must not be lost: the file was not moved (every rename is taken back), keep appending to it
			log.Errorf("admin audit: rotation failed, the file keeps growing, next try in a minute: %v", err)
			a.rotateRetryAt = a.now().Add(time.Minute)
		}
	}
	if a.pendingRotate {
		if err := a.finishRotateLocked(); err != nil {
			return adminAuditRecord{}, err
		}
	}
	if a.lost.n > 0 {
		a.writeGapLocked()
	}
	rec := a.appendLocked(actor, action, target, source, result, detail, secrets)
	return rec, a.lastWriteErr
}

// noteLostLocked remembers a record that did not make it into the file.
func (a *adminAuditLog) noteLostLocked(action string, err error) {
	l := &a.lost
	now := a.now()
	if l.n == 0 {
		l.first, l.firstErr = now, lostCause(err)
	}
	l.n++
	l.last = now
	if len(l.actions) < adminAuditGapActors && !slices.Contains(l.actions, action) {
		l.actions = append(l.actions, action)
	}
}

// lostCause is the reason a record was lost without the paths: the operating system's words when there
// are some ("no space left on device"), the first line of the error otherwise.
func lostCause(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		return en.Error()
	}
	return firstLine(err.Error())
}

// writeGapLocked writes the audit.gap line that says how many records are missing before it. A failure keeps
// the count for the next try.
func (a *adminAuditLog) writeGapLocked() {
	l := a.lost
	// the cause comes before the times: the detail is cut at adminAuditMaxDetail runes
	detail := fmt.Sprintf("%d audit record(s) could not be written (%s; first error: %s) between %s and %s",
		l.n, strings.Join(l.actions, ", "), l.firstErr, l.first.UTC().Format(time.RFC3339), l.last.UTC().Format(time.RFC3339))
	rec := a.appendLocked(adminAuditSystemActor, auditActAuditGap, filepath.Base(a.path), adminAuditLocalSource, adminAuditResultFail, detail, nil)
	if a.lastWriteErr == nil && rec.Seq != 0 {
		a.lost = adminAuditLost{}
	}
}

// appendLocked writes one line and syncs it before any counter moves. It sets lastWriteErr and returns the
// zero record when the line is not in the file: a line that was written but could not be synced is taken
// back, so "written" always means "on disk".
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
	line = append(line, '\n')
	a.lastWriteErr = nil
	if err := a.writeLineLocked(line); err != nil {
		a.lastWriteErr = err
		return adminAuditRecord{}
	}
	a.size += int64(len(line))
	a.seq, a.lastHash = rec.Seq, rec.Hash
	a.lines++
	a.sinceCP++
	if a.hook != nil {
		a.hook.Enqueue(line[:len(line)-1])
	}
	if a.checkpointDueLocked() {
		if err := a.writeCheckpointLocked(); err != nil {
			// the line is on disk; only the anchor is older than it should be
			log.Errorf("admin audit: the checkpoint was not written (seq %d is not anchored yet): %v", a.seq, err)
		}
	}
	return rec
}

// writeLineLocked writes and syncs one line; on any failure the file is cut back to its size before.
func (a *adminAuditLog) writeLineLocked(line []byte) error {
	if a.f == nil {
		return errors.New("the admin audit file is closed")
	}
	what := "writing"
	n, err := 0, a.injected("write")
	if err == nil {
		n, err = a.f.Write(line)
		if err == nil && n != len(line) {
			err = io.ErrShortWrite
		}
	}
	if err == nil && !a.noSync {
		what = "syncing"
		if err = a.injected("sync"); err == nil {
			err = a.f.Sync()
		}
		if err != nil {
			n = len(line) // the bytes are in the file, whether the disk has them is not known
		}
	}
	if err == nil {
		return nil
	}
	// a half line would break the chain, an unsynced one claims more than the disk has: take it back
	if n > 0 {
		terr := a.injected("truncate")
		if terr == nil {
			terr = a.f.Truncate(a.size)
		}
		if terr != nil {
			log.Errorf("admin audit: cannot remove a partly written line from %s: %v", a.path, terr)
			_ = a.f.Close()
			a.f = nil
		}
	}
	return fmt.Errorf("%s the admin audit file: %w", what, err)
}

// rotateLocked moves the generations up and the file to .1. It either does all of it or none: the oldest
// generation is only set aside until the active file is certainly renamed, and every rename that was done
// is undone when a later one fails. The new file is opened by finishRotateLocked.
func (a *adminAuditLog) rotateLocked() error {
	if a.f == nil {
		return errors.New("no open file")
	}
	// the checkpoint first: it names the last line of the file that is about to be closed, so that a
	// rotation cut off by a crash is told from a trail that lost its newest file
	if err := a.writeCheckpointLocked(); err != nil {
		log.Errorf("admin audit: the checkpoint before the rotation was not written: %v", err)
	}
	drop := a.generation(adminAuditGenerations) + ".drop"
	var done [][2]string
	move := func(from, to string, optional bool) error {
		if err := a.renameFile(from, to); err != nil {
			if optional && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		done = append(done, [2]string{from, to})
		return nil
	}
	undo := func() {
		for i := len(done) - 1; i >= 0; i-- {
			if err := os.Rename(done[i][1], done[i][0]); err != nil {
				log.Errorf("admin audit: rotation rollback: %s could not be moved back to %s: %v", done[i][1], done[i][0], err)
			}
		}
	}
	err := move(a.generation(adminAuditGenerations), drop, true)
	for n := adminAuditGenerations - 1; err == nil && n >= 1; n-- {
		err = move(a.generation(n), a.generation(n+1), true)
	}
	if err == nil {
		err = move(a.path, a.generation(1), false)
	}
	if err != nil {
		undo()
		return err
	}
	if err := os.Remove(drop); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Errorf("admin audit: the oldest generation %s could not be removed: %v", drop, err)
	}
	if err := a.syncDirectory(); err != nil {
		log.Errorf("admin audit: the directory was not synced after the rotation: %v", err)
	}
	_ = a.f.Close()
	a.f, a.size, a.lines = nil, 0, 0
	a.pendingRotate = true
	return nil
}

// finishRotateLocked opens the new file and writes its first line, audit.rotate, chained to the closed one.
// pendingRotate stays set until that line is on disk, so a failed write is retried by the next record
// instead of leaving a file that does not start with it.
func (a *adminAuditLog) finishRotateLocked() error {
	if a.f == nil {
		f, err := openAuditNew(a.path)
		if errors.Is(err, os.ErrExist) {
			// left by an earlier try of this very step: it must be an empty regular file
			f, err = openAuditAppend(a.path)
			if err == nil {
				if fi, serr := f.Stat(); serr != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
					f.Close()
					err = fmt.Errorf("admin audit file %s exists after a rotation and is not empty", a.path)
				}
			}
		}
		if err != nil {
			return err
		}
		a.f, a.size, a.lines = f, 0, 0
		if err := a.syncDirectory(); err != nil {
			log.Errorf("admin audit: the directory was not synced after creating %s: %v", a.path, err)
		}
	}
	detail := fmt.Sprintf("rotated %s to %s", filepath.Base(a.path), filepath.Base(a.generation(1)))
	a.appendLocked(adminAuditSystemActor, adminAuditRotateAction, filepath.Base(a.path), adminAuditLocalSource, adminAuditResultOK, detail, nil)
	if a.lastWriteErr != nil {
		return a.lastWriteErr
	}
	a.pendingRotate = false
	if err := a.writeCheckpointLocked(); err != nil {
		log.Errorf("admin audit: the checkpoint after the rotation was not written: %v", err)
	}
	return nil
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

// adminAuditVerifyOK and adminAuditVerifyBroken are the shapes of GET /api/audit/verify: the first is the
// only one with ok:true. State says which of the three answers it is: "verified", "broken" (a concrete
// break, brokenAt says where) or "unverified" (continuity cannot be established, nothing is claimed).
type adminAuditVerifyOK struct {
	OK       bool   `json:"ok"`
	State    string `json:"state"`
	Lines    int64  `json:"lines"`
	LastSeq  int64  `json:"lastSeq"`
	LastHash string `json:"lastHash"`
	// CheckpointSeq is the newest line the checkpoint vouches for; Unanchored lines come after it and are
	// covered by the memory of the running panel only.
	CheckpointSeq int64 `json:"checkpointSeq"`
	Unanchored    int64 `json:"unanchored"`
	// Gaps counts the audit.gap lines of the retained files: records the panel knows it could not write.
	Gaps        int64 `json:"gaps"`
	FirstGapSeq int64 `json:"firstGapSeq,omitempty"`
	// Unrecorded counts the records the panel failed to write and has not yet been able to account for with an
	// audit.gap line (the disk is still failing): present only while it is not zero.
	Unrecorded int64 `json:"unrecorded,omitempty"`
}

type adminAuditVerifyBroken struct {
	OK       bool   `json:"ok"`
	State    string `json:"state"`
	BrokenAt int64  `json:"brokenAt,omitempty"`
	Reason   string `json:"reason"`
	// what was found, for an "unverified" answer
	Lines   int64 `json:"lines,omitempty"`
	LastSeq int64 `json:"lastSeq,omitempty"`
}

const (
	adminAuditStateVerified   = "verified"
	adminAuditStateBroken     = "broken"
	adminAuditStateUnverified = "unverified"
)

// Verify walks every generation, oldest first, and checks each line: parseable and in canonical form, its
// hash, its prev (the hash of the line before, across files too), and an unbroken seq. A first line of a
// file after the oldest must be audit.rotate. Then it holds the end of what it found against what must be
// there: the active file (it exists and is the file the panel writes to), the newest line this process
// wrote, the checkpoint, and the findings of earlier starts. The first problem is reported with the seq the
// line should have; nothing is repaired.
//
// SHA-256 here shows consistency, not who wrote a line, and the checkpoint shares the fate of the volume
// unless it is protected separately: a green answer means "nothing in this volume contradicts itself", not
// "nobody with write access changed it".
func (a *adminAuditLog) Verify() (okRes *adminAuditVerifyOK, bad *adminAuditVerifyBroken) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var (
		total, expect, firstSeq, gaps, firstGap int64
		prevHash                                string
		haveAny                                 bool
		cpHashSeen                              string
		cpSeen                                  bool
	)
	cp, cpState, cpErr := readAdminAuditCheckpoint(a.checkpointPath())
	fail := func(seq int64, reason string) {
		if seq < 1 {
			seq = 1
		}
		bad = &adminAuditVerifyBroken{OK: false, State: adminAuditStateBroken, BrokenAt: seq, Reason: reason}
	}

	// the active file holds the newest records: it must exist, and be the file the panel is writing to
	activeInfo, aerr := os.Lstat(a.path)
	switch {
	case errors.Is(aerr, os.ErrNotExist):
		present := 0
		for n := 1; n <= adminAuditGenerations; n++ {
			if _, err := os.Lstat(a.generation(n)); err == nil {
				present++
			}
		}
		why := "the active file %s is missing and %d older generation(s) exist: the newest records are gone, this is not an empty trail"
		if present == 0 {
			why = "the active file %s is missing and no generation exists (%d present): the trail is gone, this is not an empty trail"
		}
		if a.pendingRotate {
			why += "; a rotation is unfinished (the new file could not be created)"
		}
		fail(a.seq, fmt.Sprintf(why, filepath.Base(a.path), present))
		return nil, bad
	case aerr == nil && a.f != nil:
		if of, err := a.f.Stat(); err == nil && !os.SameFile(of, activeInfo) {
			fail(a.seq, fmt.Sprintf("the active file %s is not the file the panel writes to (it was replaced, or deleted and created again): records written since are not in it", filepath.Base(a.path)))
			return nil, bad
		}
	}

	for fi, path := range a.files() {
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
				firstSeq = rec.Seq
			case rec.Prev != prevHash:
				fail(want, fmt.Sprintf("%s: prev does not match the hash of the line before", filepath.Base(path)))
				return false
			case first && fi > 0 && rec.Action != adminAuditRotateAction:
				fail(want, fmt.Sprintf("%s: the first line of a rotated file is not %s", filepath.Base(path), adminAuditRotateAction))
				return false
			}
			if rec.Action == auditActAuditGap {
				if gaps == 0 {
					firstGap = rec.Seq
				}
				gaps++
			}
			if cpState == adminAuditCheckpointOK && rec.Seq == cp.Seq {
				cpSeen, cpHashSeen = true, rec.Hash
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

	lastSeq, lastHash := int64(0), adminAuditZeroHash
	if haveAny {
		lastSeq, lastHash = expect-1, prevHash
	}

	// 1. the newest line this process wrote must be the last line of the files
	if lastSeq != a.seq || lastHash != a.lastHash {
		fail(min(lastSeq, a.seq)+1, fmt.Sprintf("the newest record the panel committed is seq %d, the trail ends at seq %d: the trail was cut, or lines were added that this panel did not write", a.seq, lastSeq))
		return nil, bad
	}
	// 2. the checkpoint, written independently of the lines
	var unverified []string
	switch cpState {
	case adminAuditCheckpointOK:
		switch {
		case cp.Seq > lastSeq:
			fail(lastSeq+1, fmt.Sprintf("the checkpoint names seq %d as committed, the trail ends at seq %d: the newest %d records are missing", cp.Seq, lastSeq, cp.Seq-lastSeq))
			return nil, bad
		case cp.Seq == lastSeq && cp.Hash != lastHash:
			fail(cp.Seq, fmt.Sprintf("the checkpoint names a different hash for seq %d than the trail holds", cp.Seq))
			return nil, bad
		case cp.Seq > 0 && cp.Seq < lastSeq && cpSeen && cp.Hash != cpHashSeen:
			fail(cp.Seq, fmt.Sprintf("the checkpoint names a different hash for seq %d than the trail holds", cp.Seq))
			return nil, bad
		case cp.Seq > 0 && cp.Seq < lastSeq && !cpSeen:
			unverified = append(unverified, fmt.Sprintf("the checkpoint (seq %d) is older than the oldest retained record (seq %d): it does not anchor what is retained", cp.Seq, firstSeq))
		}
	case adminAuditCheckpointMissing:
		unverified = append(unverified, "there is no checkpoint file: nothing shows that the newest records still exist")
	default:
		unverified = append(unverified, fmt.Sprintf("the checkpoint cannot be used (%v): nothing shows that the newest records still exist", cpErr))
	}
	// 3. what an earlier start found
	for _, n := range a.readNotices() {
		if n.Kind == adminAuditNoticeBroken {
			fail(lastSeq, fmt.Sprintf("%s: %s (written %s; move %s away once it has been looked at)", filepath.Base(a.noticePath()), n.Reason, n.Ts, filepath.Base(a.noticePath())))
			return nil, bad
		}
		unverified = append(unverified, fmt.Sprintf("%s: %s (written %s; move %s away once it has been looked at)", filepath.Base(a.noticePath()), n.Reason, n.Ts, filepath.Base(a.noticePath())))
	}
	if len(unverified) > 0 {
		return nil, &adminAuditVerifyBroken{OK: false, State: adminAuditStateUnverified, Reason: strings.Join(unverified, "; "), Lines: total, LastSeq: lastSeq}
	}
	return &adminAuditVerifyOK{OK: true, State: adminAuditStateVerified, Lines: total, LastSeq: lastSeq, LastHash: lastHash,
		CheckpointSeq: cp.Seq, Unanchored: lastSeq - cp.Seq, Gaps: gaps, FirstGapSeq: firstGap, Unrecorded: a.lost.n}, nil
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

// auditAdminConfigured: the panel has Basic credentials, so the middleware authenticates every request.
func auditAdminConfigured() bool { return *basicUsername != "" && *basicPassword != "" }

// auditAdminProven: the request carries exactly the configured credentials. It is the same comparison as
// the middleware makes (hashed first, constant time), repeated here so that a handler does not rest on
// the middleware alone.
func auditAdminProven(r *http.Request) bool {
	if !auditAdminConfigured() {
		return false
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	wantUser, wantPass := sha256.Sum256([]byte(*basicUsername)), sha256.Sum256([]byte(*basicPassword))
	gotUser, gotPass := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(pass))
	return subtle.ConstantTimeCompare(gotUser[:], wantUser[:])&subtle.ConstantTimeCompare(gotPass[:], wantPass[:]) == 1
}

// auditActor names the actor of a request. "basic-auth:<user>" only when the request proved the configured
// credentials; a Basic user name that nothing checked (the panel runs without credentials) is
// "unverified:<user>", never a claim; no Basic header at all is "system". The source says where it came from.
func auditActor(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		if auditAdminProven(r) {
			return "basic-auth:" + user
		}
		return adminAuditUnauthActorMark + user
	}
	return adminAuditSystemActor
}

// auditReqState travels in the context of a request when OVPN_ADMIN_AUDIT_REQUIRED is on: fromRequest
// flags a record that could not be written, auditRequiredMiddleware turns the answer into a 500.
type auditReqState struct{ failed atomic.Bool }

type auditReqKey struct{}

// fromRequest records an action of a request at the point where its result is known. A failed write is
// logged and returned; it is not turned into the answer unless OVPN_ADMIN_AUDIT_REQUIRED is on (see
// auditRequiredMiddleware): the panel action has happened (or failed) already.
func (a *adminAuditLog) fromRequest(r *http.Request, action, target string, ok bool, detail string, secrets ...string) error {
	if a == nil {
		return nil
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
	_, err := a.Record(auditActor(r), action, target, auditSource(r), result, detail, secrets...)
	if err != nil {
		log.Errorf("admin audit: %s %s was NOT recorded: %v", action, result, err)
		if st, _ := r.Context().Value(auditReqKey{}).(*auditReqState); st != nil {
			st.failed.Store(true)
		}
	}
	return err
}

// auditRequired is the switch OVPN_ADMIN_AUDIT_REQUIRED (default false).
func auditRequired() bool { return adminAuditRequiredFlag != nil && *adminAuditRequiredFlag }

// auditRequiredMiddleware, with OVPN_ADMIN_AUDIT_REQUIRED on, answers 500 to a request whose audit record
// could not be written, instead of the answer the handler chose. It cannot undo the action: the 500 says
// so. The answer is held back only until the handler's first write, so a record that is written after
// the answer went out (the sync archives) cannot change it; it is logged like with the switch off.
func auditRequiredMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auditRequired() || adminAudit == nil {
			next.ServeHTTP(w, r)
			return
		}
		st := &auditReqState{}
		gw := &auditRequiredWriter{ResponseWriter: w, st: st}
		next.ServeHTTP(gw, r.WithContext(context.WithValue(r.Context(), auditReqKey{}, st)))
	})
}

type auditRequiredWriter struct {
	http.ResponseWriter
	st      *auditReqState
	started bool
	swapped bool
}

func (w *auditRequiredWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *auditRequiredWriter) WriteHeader(code int) {
	if w.started {
		return
	}
	w.started = true
	if w.st.failed.Load() {
		w.swapped = true
		h := w.Header()
		for k := range h {
			if k != "Cache-Control" && !strings.HasPrefix(k, "X-") && k != "Content-Security-Policy" && k != "Referrer-Policy" {
				h.Del(k)
			}
		}
		h.Set("Content-Type", "application/json")
		w.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		_, _ = w.ResponseWriter.Write([]byte(`{"status":"error","message":"the action was carried out but its audit record could not be written (OVPN_ADMIN_AUDIT_REQUIRED is on)"}`))
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditRequiredWriter) Write(p []byte) (int, error) {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	if w.swapped {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

// system records an action nobody asked for in a request (the scheduled CRL rebuild).
func (a *adminAuditLog) system(action, target string, ok bool, detail string) error {
	if a == nil {
		return nil
	}
	result := adminAuditResultFail
	if ok {
		result = adminAuditResultOK
	}
	_, err := a.Record(adminAuditSystemActor, action, target, adminAuditLocalSource, result, detail)
	if err != nil {
		log.Errorf("admin audit: %s %s was NOT recorded: %v", action, result, err)
	}
	return err
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

func (t *adminLoginThrottle) forgetOK(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.okSeen, key)
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
func (a *adminAuditLog) loginOK(r *http.Request, user string) error {
	if a == nil {
		return nil
	}
	src := auditSource(r)
	key := user + "\x00" + src
	if !a.throttle.shouldRecordOK(key, a.now()) {
		return nil
	}
	err := a.loginEvent(auditActLoginOK, user, src, adminAuditResultOK, "login accepted")
	if err != nil {
		a.throttle.forgetOK(key) // the next request tries again: a login that left no line is not "seen"
	}
	return err
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

func (a *adminAuditLog) loginEvent(action, user, src, result, detail string) error {
	user = auditText(user, 64, nil)
	// a failed login is the actor's claim, not a proof; a successful one passed the middleware's comparison
	actor := adminAuditUnauthActorMark + user
	if result == adminAuditResultOK {
		actor = "basic-auth:" + user
	}
	_, err := a.Record(actor, action, user, src, result, detail)
	if err != nil {
		log.Errorf("admin audit: %s was NOT recorded: %v", action, err)
	}
	return err
}

// ---- HTTP ----

// auditEndpointGate lets an authenticated admin through and nobody else. The trail names actors, sources and
// targets, and verify scans every file under the writer's lock, so neither is served without proof of the admin
// credentials: with none configured (the binary default, where the middleware lets everything pass) the
// answer is 403, and so it is for a request that reaches the handler without the configured credentials. The
// refusal goes to the ordinary log and not into the trail: an unauthenticated caller must not be able to
// write lines at will.
func auditEndpointGate(w http.ResponseWriter, r *http.Request) bool {
	if auditAdminProven(r) {
		return true
	}
	why := "the request did not carry the admin credentials"
	if !auditAdminConfigured() {
		why = "no admin credentials are configured (--basic.username and --basic.password), the trail is not served without authentication"
	}
	log.Warnf("admin audit: %s %s from %s refused with 403: %s", r.Method, r.URL.Path, auditSource(r), why)
	http.Error(w, `{"status":"error","message":"the audit trail is served to an authenticated admin only: set --basic.username and --basic.password"}`, http.StatusForbidden)
	return false
}

// adminAuditListHandler serves GET /api/audit/admin?limit=100&before=<seq>: newest first. limit is 1..500
// (default 100, a larger value is cut to 500); before returns only lines with a smaller seq, so the seq of
// the last line of a page is the before of the next. It is for an authenticated admin only (see
// auditEndpointGate) and every read is recorded as audit.read.
func (oAdmin *OvpnAdmin) adminAuditListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !auditEndpointGate(w, r) {
		return
	}
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
	// the read is recorded after it, so the page does not contain its own line
	_ = adminAudit.fromRequest(r, auditActAuditRead, filepath.Base(adminAudit.path), true,
		fmt.Sprintf("limit=%d before=%d returned=%d", limit, before, len(recs)))
	body, _ := json.Marshal(recs)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// adminAuditVerifyHandler serves GET /api/audit/verify and records the check itself as audit.verify. It is
// for an authenticated admin only (see auditEndpointGate). The answer has three states (ok:true "verified";
// ok:false "broken" or "unverified", see the top of this file). SHA-256 shows consistency, not who wrote a
// line, and the checkpoint shares the fate of the volume unless it is separately protected.
func (oAdmin *OvpnAdmin) adminAuditVerifyHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !auditEndpointGate(w, r) {
		return
	}
	if !auditGetOnly(w, r) {
		return
	}
	if adminAudit == nil {
		http.Error(w, `{"status":"error","message":"the admin audit trail is not enabled"}`, http.StatusServiceUnavailable)
		return
	}
	okRes, bad := adminAudit.Verify()
	var body []byte
	target := filepath.Base(adminAudit.path)
	switch {
	case bad != nil && bad.State == adminAuditStateUnverified:
		body, _ = json.Marshal(bad)
		_ = adminAudit.fromRequest(r, auditActAuditVerify, target, false, "continuity cannot be established: "+bad.Reason)
	case bad != nil:
		body, _ = json.Marshal(bad)
		_ = adminAudit.fromRequest(r, auditActAuditVerify, target, false, fmt.Sprintf("chain broken at seq %d: %s", bad.BrokenAt, bad.Reason))
	default:
		body, _ = json.Marshal(okRes)
		_ = adminAudit.fromRequest(r, auditActAuditVerify, target, true,
			fmt.Sprintf("chain intact: %d lines, continuous with the checkpoint (seq %d)", okRes.Lines, okRes.CheckpointSeq))
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
