package src

// LOCAL PATCH (ovpn-admin), fourth modification: the re-hash spool.
//
// The login hook runs as the user OpenVPN drops to (nobody) and users.db belongs to root, so the UPDATE of
// rehashAfterLogin fails with "attempt to write a readonly database". Making users.db writable for that user would
// let the network-facing OpenVPN process rewrite every stored secret, so instead the hook leaves the new hash in a
// spool directory next to the database (users.db.rehash/, created and handed to the hook user by the panel) and a
// root-side applier (the "rehash-apply" command, run by the panel) stores it.
//
//   - One file per user, named after sha256(user name), written to a temporary name and renamed into place: a reader
//     never sees half a file, and a second login of the same user finds the entry and writes nothing.
//   - An entry holds the user name, the old hash, the new hash and the time. Never a password.
//   - The applier stores a hash only where the row still holds the old hash:
//     UPDATE users SET password = <new> WHERE username = <user> AND CAST(password AS TEXT) = <old>.
//     A row that no longer matches drops the entry, the stored hash is never touched. Every entry is deleted after
//     it was applied or dropped; an entry that could not be applied (database busy) stays for the next round.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	spoolEntryVersion = 1
	spoolMaxEntry     = 4096 // bytes; a real entry is about 250
	spoolMaxPerRun    = 1000 // entries handled by one rehash-apply run
	spoolTempPrefix   = ".tmp-"
	spoolTempMaxAge   = 10 * time.Minute
)

// SpoolDirFor is the spool directory that belongs to a users.db path.
func SpoolDirFor(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return dbPath + ".rehash"
}

type spoolEntry struct {
	Version int    `json:"version"`
	User    string `json:"user"`
	Old     string `json:"old"`
	New     string `json:"new"`
	Time    int64  `json:"time"`
}

var (
	spoolNameRe   = regexp.MustCompile(`^[0-9a-f]{64}\.json$`)
	bcryptHashRe  = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
	spoolWarnOnce sync.Once
)

func spoolFileName(user string) string {
	sum := sha256.Sum256([]byte(user))
	return hex.EncodeToString(sum[:]) + ".json"
}

// validSpoolEntry checks what the applier will trust of a file the hook user wrote. The hook user is the
// network-facing OpenVPN process, so nothing in the file is believed more than it has to be.
func validSpoolEntry(e *spoolEntry, name string) error {
	switch {
	case e.Version != spoolEntryVersion:
		return fmt.Errorf("unknown entry version %d", e.Version)
	case e.User == "" || len(e.User) > 256 || strings.ContainsAny(e.User, "\x00\r\n"):
		return errors.New("bad user name")
	case spoolFileName(e.User) != name:
		return errors.New("the file name does not belong to the user name")
	case !bcryptHashRe.MatchString(e.Old) || !bcryptHashRe.MatchString(e.New):
		return errors.New("not a bcrypt hash")
	}
	oldCost, err := bcrypt.Cost([]byte(e.Old))
	if err != nil || oldCost >= bcryptCost {
		return errors.New("the old hash is not below the target cost")
	}
	if newCost, err := bcrypt.Cost([]byte(e.New)); err != nil || newCost != bcryptCost {
		return errors.New("the new hash is not at the target cost")
	}
	return nil
}

// readSpoolEntry reads one entry without following a symlink and refuses anything that is not a small regular file.
func readSpoolEntry(dir, name string) (*spoolEntry, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > spoolMaxEntry {
		return nil, errors.New("not a regular file of reasonable size")
	}
	data, err := io.ReadAll(io.LimitReader(f, spoolMaxEntry+1))
	if err != nil {
		return nil, err
	}
	var e spoolEntry
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return nil, err
	}
	if err := validSpoolEntry(&e, name); err != nil {
		return nil, err
	}
	return &e, nil
}

// spoolHas says whether an entry for user that replaces storedHash is already waiting.
func (oUser *OpenvpnUser) spoolHas(user, storedHash string) bool {
	if oUser.SpoolDir == "" {
		return false
	}
	e, err := readSpoolEntry(oUser.SpoolDir, spoolFileName(user))
	return err == nil && e.Old == storedHash
}

// spoolRehash leaves the entry for the root-side applier. The directory is created by the panel and handed to the
// user of the hook; it is not created here (a directory made by the wrong user would shut the hook out).
func (oUser *OpenvpnUser) spoolRehash(user, oldHash, newHash string) error {
	if oUser.SpoolDir == "" {
		return errors.New("no spool directory")
	}
	data, err := json.Marshal(spoolEntry{Version: spoolEntryVersion, User: user, Old: oldHash, New: newHash, Time: time.Now().Unix()})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(oUser.SpoolDir, spoolTempPrefix+"*") // created 0600
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(oUser.SpoolDir, spoolFileName(user))); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// warnSpoolOnce prints the warning for a re-hash that could not be spooled, once per process.
func warnSpoolOnce(user string, direct, spool error) {
	spoolWarnOnce.Do(func() {
		fmt.Fprintf(rehashLog, "openvpn-user: warning: the password hash of %q was not re-made at cost %d: %v; it could not be spooled either: %v\n", user, bcryptCost, direct, spool)
	})
}

// SpoolResult is what the applier did with one entry.
type SpoolResult struct {
	User    string
	OldCost int
	Applied bool   // the row was updated
	Dropped string // non-empty: the entry was removed without applying it, and why
	Err     error  // the entry stays; the next run tries again
}

// ApplySpool stores the hashes of the entries in the spool directory (see the top of this file). It reads the
// directory only if it exists, and handles at most spoolMaxPerRun entries.
func (oUser *OpenvpnUser) ApplySpool() ([]SpoolResult, error) {
	dir := oUser.SpoolDir
	if dir == "" {
		return nil, nil
	}
	d, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	_ = d.Close()
	if err != nil {
		return nil, err
	}
	var results []SpoolResult
	handled := 0
	for _, name := range names {
		path := filepath.Join(dir, name)
		if strings.HasPrefix(name, spoolTempPrefix) {
			if fi, err := os.Lstat(path); err == nil && time.Since(fi.ModTime()) > spoolTempMaxAge {
				_ = os.Remove(path) // left by a hook that died between create and rename
			}
			continue
		}
		if handled >= spoolMaxPerRun {
			break
		}
		handled++
		if !spoolNameRe.MatchString(name) {
			results = append(results, SpoolResult{User: "?", Dropped: "unexpected file name in the spool directory"})
			_ = os.Remove(path)
			continue
		}
		e, err := readSpoolEntry(dir, name)
		if err != nil {
			results = append(results, SpoolResult{User: "?", Dropped: "unusable entry: " + err.Error()})
			_ = os.Remove(path)
			continue
		}
		oldCost, _ := bcrypt.Cost([]byte(e.Old))
		res, err := oUser.Database.Exec("UPDATE users SET password = ? WHERE username = ? AND CAST(password AS TEXT) = ?", e.New, e.User, e.Old)
		if err != nil {
			results = append(results, SpoolResult{User: e.User, OldCost: oldCost, Err: err})
			continue
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			results = append(results, SpoolResult{User: e.User, OldCost: oldCost, Dropped: "the stored hash is not the one the entry replaces (password changed, or user gone)"})
			_ = os.Remove(path)
			continue
		}
		_ = os.Remove(path)
		results = append(results, SpoolResult{User: e.User, OldCost: oldCost, Applied: true})
	}
	return results, nil
}

// PrintSpoolResults writes one line per result for the panel to read. Never a hash, never a password.
func PrintSpoolResults(w io.Writer, results []SpoolResult) {
	for _, r := range results {
		switch {
		case r.Applied:
			fmt.Fprintf(w, "openvpn-user: rehash applied user=%q cost %d -> %d\n", r.User, r.OldCost, bcryptCost)
		case r.Dropped != "":
			fmt.Fprintf(w, "openvpn-user: rehash dropped user=%q: %s\n", r.User, r.Dropped)
		case r.Err != nil:
			fmt.Fprintf(w, "openvpn-user: warning: rehash not applied user=%q: %v\n", r.User, r.Err)
		}
	}
}
