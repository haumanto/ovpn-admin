package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestParseRehashApplyOutput(t *testing.T) {
	out := strings.Join([]string{
		`openvpn-user: rehash applied user="alice" cost 4 -> 12`,
		`openvpn-user: rehash applied user="bob.smith" cost 9 -> 12`,
		`openvpn-user: rehash dropped user="carol": the stored hash is not the one the entry replaces (password changed, or user gone)`,
		`openvpn-user: rehash dropped user="?": unusable entry: bad user name`,
		`openvpn-user: rehash applied user="a b; rm" cost 4 -> 12`, // not a valid user name
		`openvpn-user: rehash applied user="../etc" cost 4 -> 12`,  // not a valid user name
		`openvpn-user: rehash applied user="dave" cost 4 -> 13`,    // not the target cost
		`openvpn-user: rehash applied user="x\ny" cost 4 -> 12`,    // newline escaped by %q: not a valid user name
		`openvpn-user: warning: rehash not applied user="erin": database is locked`,
		`noise`,
		``,
	}, "\n")
	applied, dropped, other := parseRehashApplyOutput(out)
	if len(applied) != 2 || applied[0].user != "alice" || applied[0].oldCost != 4 || applied[1].user != "bob.smith" || applied[1].oldCost != 9 {
		t.Errorf("applied = %+v", applied)
	}
	if len(dropped) != 2 || dropped[0].user != "carol" || dropped[1].user != "?" || dropped[0].dropped == "" {
		t.Errorf("dropped = %+v", dropped)
	}
	if len(other) != 6 { // the warning, the noise, and the four lines that did not pass the checks
		t.Errorf("other = %q", other)
	}
}

func TestEnsureRehashSpoolDir(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	base := t.TempDir()
	dir := filepath.Join(base, "users.db.rehash")
	if err := ensureRehashSpoolDir(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0700 {
		t.Fatalf("spool dir: %v %v", fi, err)
	}
	// loose mode is put right, an existing directory is kept
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureRehashSpoolDir(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0700 {
		t.Errorf("mode %v after the check, want 0700", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "keep")); err != nil {
		t.Errorf("an existing entry was lost: %v", err)
	}
	// a symlink or a file in its place is refused
	link := filepath.Join(base, "link.rehash")
	if err := os.Symlink(base, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureRehashSpoolDir(link, uid, gid); err == nil {
		t.Errorf("a symlink was accepted as the spool directory")
	}
	file := filepath.Join(base, "file.rehash")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureRehashSpoolDir(file, uid, gid); err == nil {
		t.Errorf("a file was accepted as the spool directory")
	}
	// a parent that does not exist is an error, not a created tree
	if err := ensureRehashSpoolDir(filepath.Join(base, "nope", "x.rehash"), uid, gid); err == nil {
		t.Errorf("a missing parent directory was created")
	}
}

type applierRig struct {
	a     *rehashSpoolApplier
	runs  int32
	out   string
	err   error
	clock time.Time
}

func newApplierRig(t *testing.T) *applierRig {
	t.Helper()
	r := &applierRig{clock: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	r.a = &rehashSpoolApplier{
		dir: filepath.Join(t.TempDir(), "users.db.rehash"),
		run: func(ctx context.Context) (string, error) {
			atomic.AddInt32(&r.runs, 1)
			return r.out, r.err
		},
		now: func() time.Time { return r.clock },
	}
	if err := os.Mkdir(r.a.dir, 0700); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *applierRig) addEntry(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.a.dir, name), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestIdleApplierRunsNothing(t *testing.T) {
	r := newApplierRig(t)
	for i := 0; i < 5; i++ {
		r.a.drainOnce()
	}
	if n := atomic.LoadInt32(&r.runs); n != 0 {
		t.Errorf("the command ran %d times against an empty spool", n)
	}
	r.a.dir = filepath.Join(t.TempDir(), "missing")
	r.a.drainOnce()
	if n := atomic.LoadInt32(&r.runs); n != 0 {
		t.Errorf("the command ran against a missing directory")
	}
}

func TestApplierLogsOneInfoLinePerAppliedEntryAndAuditsIt(t *testing.T) {
	trail := useAdminAudit(t, "")
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	r := newApplierRig(t)
	r.addEntry(t, "e1.json")
	r.out = `openvpn-user: rehash applied user="alice" cost 4 -> 12` + "\n" +
		`openvpn-user: rehash applied user="bob" cost 4 -> 12` + "\n" +
		`openvpn-user: rehash dropped user="carol": the stored hash is not the one the entry replaces (password changed, or user gone)` + "\n"
	r.a.drainOnce()
	if n := atomic.LoadInt32(&r.runs); n != 1 {
		t.Fatalf("%d runs, want 1", n)
	}
	var infos, warns []string
	for _, e := range hook.AllEntries() {
		switch e.Level {
		case log.InfoLevel:
			infos = append(infos, e.Message)
		case log.WarnLevel:
			warns = append(warns, e.Message)
		}
		if strings.Contains(e.Message, "$2a$") {
			t.Errorf("a hash in the log: %s", e.Message)
		}
	}
	if len(infos) != 2 || infos[0] != "rehash applied: user=alice cost 4 -> 12" || infos[1] != "rehash applied: user=bob cost 4 -> 12" {
		t.Errorf("info lines = %q", infos)
	}
	if len(warns) != 1 || !strings.HasPrefix(warns[0], "rehash dropped: user=carol: ") {
		t.Errorf("warn lines = %q", warns)
	}
	trail.Close()
	n := 0
	for _, l := range readAuditFile(t, trail.path) {
		rec, err := parseAdminAuditLine([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Action == auditActRehash {
			n++
			if rec.Target != "alice" && rec.Target != "bob" {
				t.Errorf("audit target %q", rec.Target)
			}
			if !strings.Contains(rec.Detail, "was cost 4") || strings.Contains(l, "$2a$") {
				t.Errorf("audit line %s", l)
			}
		}
	}
	if n != 2 {
		t.Errorf("%d auth.rehash audit lines, want 2", n)
	}
}

func TestApplierFailureWarnsAtMostOncePerMinute(t *testing.T) {
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	r := newApplierRig(t)
	r.addEntry(t, "e1.json")
	r.err = errors.New("exit status 1")
	r.out = "openvpn-user: warning: rehash not applied user=\"alice\": database is locked\n"
	for i := 0; i < 6; i++ {
		r.a.drainOnce()
		r.clock = r.clock.Add(5 * time.Second)
	}
	warns := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.WarnLevel {
			warns++
		}
	}
	if warns != 1 { // the first failure warns, the next five rounds of the same minute stay silent
		t.Errorf("%d warnings in 30 s of failing rounds, want 1", warns)
	}
	r.clock = r.clock.Add(time.Minute)
	r.a.drainOnce()
	warns2 := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.WarnLevel {
			warns2++
		}
	}
	if warns2 <= warns {
		t.Errorf("no warning after the minute passed")
	}
}

// With a real child process: the command line is exactly "openvpn-user rehash-apply --db.path=<db>" and it runs only
// when the spool holds something.
func TestApplierRunsTheRealCommandOnlyForANonEmptySpool(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args.txt")
	script := "#!/bin/sh\necho \"$@\" >> " + argsFile + "\necho 'openvpn-user: rehash applied user=\"alice\" cost 4 -> 12'\n"
	if err := os.WriteFile(filepath.Join(bin, "openvpn-user"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	db := filepath.Join(t.TempDir(), "users.db")
	setFlag(t, authDatabase, db)
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })

	a := newRehashSpoolApplier()
	if a.dir != db+".rehash" {
		t.Fatalf("spool dir %q", a.dir)
	}
	if err := ensureRehashSpoolDir(a.dir, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	a.drainOnce() // empty
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatalf("the command ran for an empty spool")
	}
	if err := os.WriteFile(filepath.Join(a.dir, "e.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	a.drainOnce()
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("the command did not run: %v", err)
	}
	if got := strings.TrimSpace(string(raw)); got != "rehash-apply --db.path="+db {
		t.Errorf("command line %q", got)
	}
	found := false
	for _, e := range hook.AllEntries() {
		if e.Level == log.InfoLevel && e.Message == "rehash applied: user=alice cost 4 -> 12" {
			found = true
		}
	}
	if !found {
		t.Errorf("no info line for the applied entry")
	}
}

func TestApplierLoopCreatesTheDirectoryDrainsAtStartAndGoesQuietWhenEmpty(t *testing.T) {
	r := newApplierRig(t)
	if err := os.Remove(r.a.dir); err != nil {
		t.Fatal(err)
	}
	// an entry that is there at start is drained at start (before the first tick)
	if err := os.Mkdir(r.a.dir, 0700); err != nil {
		t.Fatal(err)
	}
	r.addEntry(t, "e1.json")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.a.loop(ctx, time.Hour, os.Getuid(), os.Getgid())
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&r.runs) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&r.runs); n != 1 {
		t.Fatalf("%d runs at start, want 1", n)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop")
	}
	// no directory yet: the loop creates it at start and does not run the command
	r2 := newApplierRig(t)
	if err := os.Remove(r2.a.dir); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		r2.a.loop(ctx2, 10*time.Millisecond, os.Getuid(), os.Getgid())
		close(done2)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2
	if fi, err := os.Stat(r2.a.dir); err != nil || fi.Mode().Perm() != 0700 {
		t.Errorf("the loop did not create the spool directory: %v %v", fi, err)
	}
	if n := atomic.LoadInt32(&r2.runs); n != 0 {
		t.Errorf("an idle spool ran the command %d times in 10 rounds", n)
	}
}
