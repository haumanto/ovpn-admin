package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Root-side applier of the password re-hash spool.
//
// The OpenVPN login hook runs as nobody and cannot write users.db (root's), so a login with a hash below bcrypt cost
// 12 leaves the new hash as a small file in users.db.rehash/ (see third_party/openvpn-user/src/rehash_spool.go).
// The panel creates that directory (owned by the hook user, mode 0700) and drains it: once at start and then every
// rehashSpoolInterval. An idle panel reads nothing but one directory entry per round; the openvpn-user command
// "rehash-apply" runs only when the directory is not empty. The command stores a hash only where the row still holds the
// hash the entry replaces; a stale entry is dropped. Nothing is ever written about a password or a hash: one info line
// per applied entry carries the user name and the costs.

const (
	rehashSpoolInterval = 5 * time.Second
	rehashApplyTimeout  = 90 * time.Second
	rehashWarnEvery     = time.Minute
)

// rehashAppliedRe and rehashDroppedRe read the lines "openvpn-user rehash-apply" prints. The user name arrives
// quoted (%q) from a file the hook user wrote: it is unquoted and checked before it is used for anything.
var (
	rehashAppliedRe = regexp.MustCompile(`^openvpn-user: rehash applied user=("(?:[^"\\]|\\.)*") cost ([0-9]{1,2}) -> 12$`)
	rehashDroppedRe = regexp.MustCompile(`^openvpn-user: rehash dropped user=("(?:[^"\\]|\\.)*"): (.{0,200})$`)
)

func rehashSpoolDir() string { return *authDatabase + ".rehash" }

// rehashHookOwner is the user the OpenVPN hooks run as ("user nobody" in setup/openvpn.conf).
func rehashHookOwner() (uid, gid int) {
	uid, gid = 65534, 65534
	if u, err := user.Lookup("nobody"); err == nil {
		if n, err := strconv.Atoi(u.Uid); err == nil {
			uid = n
		}
		if n, err := strconv.Atoi(u.Gid); err == nil {
			gid = n
		}
	}
	return uid, gid
}

// ensureRehashSpoolDir creates the spool directory (0700, owned by the hook user) or checks the one that is there.
// A symlink or a plain file in its place is an error. When the panel may not chown, the directory stays the panel's own
// and the hook warns once per login that it cannot spool: the login itself is never affected.
func ensureRehashSpoolDir(dir string, uid, gid int) error {
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s exists and is not a directory (a symlink or a file)", dir)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("%s was made but could not be handed to the hook user %d:%d, the login hook cannot spool a re-hash: %w", dir, uid, gid, err)
	}
	return nil
}

// rehashSpoolNonEmpty reads one entry of the directory.
func rehashSpoolNonEmpty(dir string) bool {
	d, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer d.Close()
	names, err := d.Readdirnames(1)
	return err == nil && len(names) > 0
}

type rehashLine struct {
	user    string
	oldCost int
	dropped string // non-empty: the entry was dropped, and why
}

// parseRehashApplyOutput reads the lines of "openvpn-user rehash-apply". Lines it does not know, and lines whose user
// name is not a valid user name, are ignored: the output comes from a command that read files the hook user wrote.
func parseRehashApplyOutput(out string) (applied, dropped []rehashLine, other []string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := rehashAppliedRe.FindStringSubmatch(line); m != nil {
			u, err := strconv.Unquote(m[1])
			c, cerr := strconv.Atoi(m[2])
			if err == nil && cerr == nil && validateLegacyUsername(u) == nil {
				applied = append(applied, rehashLine{user: u, oldCost: c})
				continue
			}
		}
		if m := rehashDroppedRe.FindStringSubmatch(line); m != nil {
			u, err := strconv.Unquote(m[1])
			if err == nil && (u == "?" || validateLegacyUsername(u) == nil) {
				dropped = append(dropped, rehashLine{user: u, dropped: m[2]})
				continue
			}
		}
		other = append(other, truncateRunes(line, 200))
	}
	return applied, dropped, other
}

// rehashSpoolApplier drains the spool.
type rehashSpoolApplier struct {
	dir      string
	run      func(ctx context.Context) (string, error) // runs "openvpn-user rehash-apply"
	lastWarn time.Time
	now      func() time.Time
}

func newRehashSpoolApplier() *rehashSpoolApplier {
	return &rehashSpoolApplier{
		dir: rehashSpoolDir(),
		run: func(ctx context.Context) (string, error) {
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, "openvpn-user", "rehash-apply", "--db.path="+*authDatabase)
			cmd.Stdout = io.Writer(&stdout)
			cmd.Stderr = io.Writer(&stderr)
			err := cmd.Run()
			if err != nil {
				return stdout.String() + stderr.String(), err
			}
			return stdout.String(), nil
		},
		now: time.Now,
	}
}

func (a *rehashSpoolApplier) warn(format string, args ...any) {
	if now := a.now(); now.Sub(a.lastWarn) >= rehashWarnEvery {
		a.lastWarn = now
		log.Warnf(format, args...)
	}
}

// drainOnce applies what is in the spool. It does nothing when the directory is empty or missing.
func (a *rehashSpoolApplier) drainOnce() {
	if !rehashSpoolNonEmpty(a.dir) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rehashApplyTimeout)
	defer cancel()
	out, err := a.run(ctx)
	applied, dropped, other := parseRehashApplyOutput(out)
	for _, l := range applied {
		log.Infof("rehash applied: user=%s cost %d -> 12", l.user, l.oldCost)
		auditRehashNotice(l.user, fmt.Sprintf("%scost %d -> 12", rehashNoticePrefix, l.oldCost))
	}
	for _, l := range dropped {
		log.Warnf("rehash dropped: user=%s: %s", l.user, l.dropped)
	}
	for _, line := range other {
		a.warn("rehash spool: %s", line)
	}
	if err != nil {
		a.warn("rehash spool: openvpn-user rehash-apply failed (the entries stay and are tried again): %v", err)
	}
}

// loop drains once at start, then on a ticker. It stops when ctx ends.
func (a *rehashSpoolApplier) loop(ctx context.Context, interval time.Duration, uid, gid int) {
	if err := ensureRehashSpoolDir(a.dir, uid, gid); err != nil {
		log.Warnf("rehash spool: %v", err)
	}
	a.drainOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := os.Lstat(a.dir); errors.Is(err, os.ErrNotExist) { // the database directory may have appeared since the start
				if err := ensureRehashSpoolDir(a.dir, uid, gid); err != nil {
					a.warn("rehash spool: %v", err)
				}
			}
			a.drainOnce()
		}
	}
}

// startRehashSpoolApplier is called once at start when password authentication is on.
func startRehashSpoolApplier() {
	uid, gid := rehashHookOwner()
	go newRehashSpoolApplier().loop(context.Background(), rehashSpoolInterval, uid, gid)
}
