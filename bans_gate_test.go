package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The release gate of the ban engine (t_e8b21764): an upgrade never loses the permanent bans of the operator, the reply of a ban says
// what was enforced, an unban never forgets history whose rule still stands, the state directory is trusted or the engine refuses to
// run, and a rule left by an interrupted ban is adopted or removed. Same fake firewall and clock as bans_test.go.

func (r *banRig) write(rel, content string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *banRig) appendFile(rel, content string) {
	r.t.Helper()
	f, err := os.OpenFile(filepath.Join(r.dir, rel), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		r.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		r.t.Fatal(err)
	}
}

func (r *banRig) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(r.dir, rel))
	return err == nil
}

// restart is a container start: init, then the jail start (setup), then the readiness check. It returns the first failing step.
func (r *banRig) restart() (string, int) {
	r.t.Helper()
	var all []string
	for _, step := range []string{"init", "setup", "check"} {
		out, code := r.run(nil, step)
		all = append(all, out)
		if code != 0 {
			return fmt.Sprintf("step %s failed: %s", step, strings.Join(all, "\n")), code
		}
	}
	return strings.Join(all, "\n"), 0
}

// legacyRows: the ban-history.tsv of the earlier releases (ip, count, first, last, permanent, reason, failures): two permanent bans and
// one temporary one whose last offence was 100 s ago (its ban of an hour would still be running)
func legacyRows() string {
	return "1.2.3.4\t3\t10\t20\t1\tauth-failed\t3\n" +
		"2001:db8::9\t5\t10\t30\t1\tfail2ban\t3\n" +
		fmt.Sprintf("5.6.7.8\t1\t10\t%d\t0\tfail2ban\t3\n", rigStart-100)
}

// ---- case (a), (b), (c): the upgrade fixture ----------------------------------------------------------------------------------------

func TestBanGateUpgradeFixture(t *testing.T) {
	t.Parallel()
	t.Run("fresh install, nothing anywhere: healthy", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		if out, code := r.restart(); code != 0 {
			t.Fatalf("fresh install: exit %d: %s", code, out)
		}
		if len(r.rules("4"))+len(r.rules("6")) != 0 || r.exists("audit/bans-history.tsv") {
			t.Errorf("a fresh install has rules %v %v or a history %q", r.rules("4"), r.rules("6"), r.read("audit/bans-history.tsv"))
		}
	})
	t.Run("readable legacy history: exactly the two permanent bans and the temporary one in force are restored, healthy", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		legacy := r.write("audit/ban-history.tsv", legacyRows())
		if out, code := r.restart(); code != 0 {
			t.Fatalf("upgrade: exit %d: %s", code, out)
		}
		if got := strings.Join(r.rules("4"), "|"); got != "-A OVPN_BAN -s 1.2.3.4/32 -j DROP|-A OVPN_BAN -s 5.6.7.8/32 -j DROP" {
			t.Errorf("IPv4 rules after the upgrade: %q", got)
		}
		if got := strings.Join(r.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8::9/128 -j DROP" {
			t.Errorf("IPv6 rules after the upgrade: %q", got)
		}
		for _, e := range []string{"1.2.3.4", "2001:db8::9"} {
			if row := r.stateRow(e); row == nil || row[2] != "0" {
				t.Errorf("no permanent row for %s: %q", e, r.read("audit/bans.tsv"))
			}
		}
		// the temporary ban was made 100 s before the start and lasts the legacy bantime (3600 s): it keeps that end
		if row := r.stateRow("5.6.7.8"); row == nil || row[1] != fmt.Sprint(rigStart-100) || row[2] != fmt.Sprint(rigStart-100+3600) {
			t.Errorf("the temporary legacy ban in force: %v", row)
		}
		if n := strings.Count(r.read("audit/bans.tsv"), "\n"); n != 3 {
			t.Errorf("exactly three rows expected: %q", r.read("audit/bans.tsv"))
		}
		if h := r.read("audit/bans-history.tsv"); strings.Count(h, "\n") != 3 || !strings.Contains(h, "5.6.7.8\t32\t") {
			t.Errorf("the history must hold all three entries: %q", h)
		}
		if _, err := os.Stat(legacy + ".migrated"); err != nil {
			t.Errorf("the legacy file is not kept: %v", err)
		}
	})
	t.Run("legacy history in the directory of the earlier layout", func(t *testing.T) {
		t.Parallel()
		old := t.TempDir()
		r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+old)
		if err := os.WriteFile(filepath.Join(old, "ban-history.tsv"), []byte(legacyRows()), 0o600); err != nil {
			t.Fatal(err)
		}
		// the layout copy of the same file next to the ban list: one history, not two
		r.write("audit/ban-history.tsv", legacyRows())
		if out, code := r.restart(); code != 0 {
			t.Fatalf("upgrade from the old directory: exit %d: %s", code, out)
		}
		if len(r.rules("4")) != 2 || len(r.rules("6")) != 1 {
			t.Errorf("rules %v %v", r.rules("4"), r.rules("6"))
		}
		if h := r.read("audit/bans-history.tsv"); strings.Count(h, "\n") != 3 {
			t.Errorf("the same history in two places was read twice: %q", h)
		}
		for _, f := range []string{filepath.Join(old, "ban-history.tsv.migrated"), filepath.Join(r.dir, "audit", "ban-history.tsv.migrated")} {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("the old file is not kept: %v", err)
			}
		}
	})
	t.Run("unreadable legacy history: the start fails and names the file, never healthy-empty", func(t *testing.T) {
		t.Parallel()
		for name, setup := range map[string]func(r *banRig) string{
			"a directory in its place": func(r *banRig) string {
				p := filepath.Join(r.dir, "audit", "ban-history.tsv")
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
				return p
			},
			"not a ban history": func(r *banRig) string {
				return r.write("audit/ban-history.tsv", "this is not\ta ban history\n1.2.3.4\n")
			},
			"one row that fits and one that does not": func(r *banRig) string {
				return r.write("audit/ban-history.tsv", "1.2.3.4\t3\t10\t20\t1\tauth-failed\t3\nbroken row\n")
			},
			"a link": func(r *banRig) string {
				target := r.write("elsewhere/ban-history.tsv", legacyRows())
				p := filepath.Join(r.dir, "audit", "ban-history.tsv")
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
				return p
			},
		} {
			name, setup := name, setup
			t.Run(name, func(t *testing.T) {
				r := newBanRig(t)
				file := setup(r)
				out, code := r.run(nil, "init")
				if code == 0 || !strings.Contains(out, file) {
					t.Errorf("init: exit %d, the file %s must be named: %s", code, file, out)
				}
				for _, step := range []string{"setup", "check"} {
					if out, code := r.run(nil, step); code == 0 {
						t.Errorf("%s reported success with an unknown history: %s", step, out)
					}
				}
				if out, code := r.run(nil, "ban", "1.2.3.4", "3"); code == 0 {
					t.Errorf("a ban was decided from an unknown history: %s", out)
				}
				if len(r.rules("4"))+len(r.rules("6")) != 0 {
					t.Errorf("rules %v %v", r.rules("4"), r.rules("6"))
				}
				if r.exists("audit/bans-history.tsv") {
					t.Errorf("an empty history was published for a legacy file that was not understood: %q", r.read("audit/bans-history.tsv"))
				}
			})
		}
	})
	t.Run("old format at a custom OVPN_BAN_HISTORY: converted, never silently empty", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_BAN_HISTORY=")
		path := filepath.Join(r.dir, "audit", "ban-history.tsv")
		r.env = append(r.env, "OVPN_BAN_HISTORY="+path)
		r.write("audit/ban-history.tsv", legacyRows())
		if out, code := r.restart(); code != 0 {
			t.Fatalf("custom old-format path: exit %d: %s", code, out)
		}
		if len(r.rules("4")) != 2 || len(r.rules("6")) != 1 {
			t.Errorf("the bans of the old-format file were not restored: %v %v", r.rules("4"), r.rules("6"))
		}
		if got := r.read("audit/ban-history.tsv"); strings.Count(got, "\n") != 3 || !strings.Contains(got, "1.2.3.4\t32\tauth-failed\t3\t0") {
			t.Errorf("the file was not converted in place: %q", got)
		}
		if got := r.read("audit/ban-history.tsv.legacy-format"); got != legacyRows() {
			t.Errorf("the original must be kept: %q", got)
		}
	})
	t.Run("custom path with something that is neither format: refused, file untouched", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_BAN_HISTORY=")
		path := filepath.Join(r.dir, "audit", "custom-history.tsv")
		r.env = append(r.env, "OVPN_BAN_HISTORY="+path)
		bad := "1.2.3.4\t3\t10\t20\t1\tauth-failed\t3\nnot a row at all\n"
		r.write("audit/custom-history.tsv", bad)
		out, code := r.run(nil, "init")
		if code == 0 || !strings.Contains(out, path) {
			t.Errorf("init: exit %d: %s", code, out)
		}
		if got := r.read("audit/custom-history.tsv"); got != bad {
			t.Errorf("the file was rewritten: %q", got)
		}
		if _, code := r.run(nil, "check"); code == 0 {
			t.Errorf("check passed on an unrecognised history")
		}
	})
	t.Run("an explicitly empty, readable file is an empty history, not a failure", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		r.write("audit/bans-history.tsv", "")
		if out, code := r.restart(); code != 0 {
			t.Fatalf("empty history: exit %d: %s", code, out)
		}
		r2 := newBanRig(t)
		r2.write("audit/ban-history.tsv", "")
		if out, code := r2.restart(); code != 0 {
			t.Fatalf("empty legacy history: exit %d: %s", code, out)
		}
		if got := r2.read("audit/bans-history.tsv"); got != "" {
			t.Errorf("history %q", got)
		}
	})
}

// ---- row 1: one incident counts once; the cap -----------------------------------------------------------------------------------------

func TestBanGateOneIncidentCountsOnce(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.must("ban", "1.2.3.4", "3")
	first := r.stateRow("1.2.3.4")
	r.setNow(rigStart + 5)
	r.must("ban", "1.2.3.4", "3") // a retry or a duplicate action for the entry that is already banned
	r.must("ban", "1.2.3.4", "4")
	second := r.stateRow("1.2.3.4")
	if first == nil || second == nil || strings.Join(first, "\t") != strings.Join(second, "\t") {
		t.Errorf("the row of a running ban changed: %v -> %v", first, second)
	}
	if h := r.read("audit/bans-history.tsv"); strings.Count(h, "1.2.3.4") != 1 {
		t.Errorf("one incident, one history row: %q", h)
	}
	bans := 0
	for _, ev := range r.events() {
		if ev["action"] == "ban" {
			bans++
		}
	}
	if bans != 1 {
		t.Errorf("%d ban events for one incident", bans)
	}
	// once it ran out, the next incident is the next step
	r.setNow(rigStart + 601)
	r.must("ban", "1.2.3.4", "3")
	if ev := r.lastEvent("ban"); ev["offence"] != float64(2) || ev["ban_seconds"] != float64(3600) {
		t.Errorf("the next incident: %v", ev)
	}
	// a ban whose rule exists but whose row is missing (the kill window) is repaired, not counted again
	r2 := newBanRig(t)
	r2.must("ban", "9.9.9.9", "3")
	r2.write("audit/bans.tsv", "")
	r2.must("ban", "9.9.9.9", "3")
	if row := r2.stateRow("9.9.9.9"); row == nil || row[2] != fmt.Sprint(rigStart+600) {
		t.Errorf("the repaired row: %v", row)
	}
	if h := r2.read("audit/bans-history.tsv"); strings.Count(h, "9.9.9.9") != 1 {
		t.Errorf("the repair counted a second offence: %q", h)
	}
}

func TestBanGateCapNeverDeletesHistory(t *testing.T) {
	t.Parallel()
	r := newBanRig(t, "OVPN_BAN_MAX_ENTRIES=2")
	hist := ""
	for _, a := range []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"} {
		hist += fmt.Sprintf("%d\t%s\t32\tmanual\t0\t0\n", rigStart-1000, a)
	}
	r.write("audit/bans-history.tsv", hist)
	out, code := r.restart()
	if code != 0 {
		t.Fatalf("restart: exit %d: %s", code, out)
	}
	if len(r.rules("4")) != 3 || r.read("audit/bans-history.tsv") != hist {
		t.Errorf("a cap below the permanent history must not drop anything: rules %v history %q", r.rules("4"), r.read("audit/bans-history.tsv"))
	}
	if !strings.Contains(out, "no NEW address can be banned") || !strings.Contains(out, "OVPN_BAN_MAX_ENTRIES=2") {
		t.Errorf("the start says nothing about the full table: %s", out)
	}
	if o, code := r.run(nil, "ban", "8.8.8.8", "3"); code == 0 || r.stateRow("8.8.8.8") != nil || !strings.Contains(o, "full of permanent bans") {
		t.Errorf("a new key with a full permanent table: exit %d: %s", code, o)
	}
	if r.read("audit/bans-history.tsv") != hist {
		t.Errorf("the refusal changed the history")
	}
}

// ---- row 3: an unban is not "forget every overlapping entry" ----------------------------------------------------------------------------

func TestBanGateUnbanKeepsCoveringHistory(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.run([]string{"OVPN_BAN_IPV6_PREFIX=128"}, "ban-manual", "2001:db8:1:2::9") // a host entry (as an earlier release wrote them)
	r.must("ban-manual", "2001:db8:1:2::77")                                     // and the /64 around it
	if got := strings.Join(r.rules("6"), "|"); !strings.Contains(got, "2001:db8:1:2::9/128") || !strings.Contains(got, "2001:db8:1:2::/64") {
		t.Fatalf("setup: %q", got)
	}
	out := r.must("unban", "2001:db8:1:2::9", "--force")
	if !strings.Contains(out, "ovpn-ban-result unban entry=2001:db8:1:2::9 ") || !strings.Contains(out, "still=2001:db8:1:2::/64") {
		t.Errorf("the reply must name the entry that was lifted and the one that still blocks: %s", out)
	}
	if got := strings.Join(r.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8:1:2::/64 -j DROP" {
		t.Errorf("rules after the unban: %q", got)
	}
	h := r.read("audit/bans-history.tsv")
	if !strings.Contains(h, "2001:db8:1:2::77\t64\t") || strings.Contains(h, "2001:db8:1:2::9\t128\t") {
		t.Errorf("the covering entry keeps its history, the lifted one loses its own: %q", h)
	}
	// the covering rule still works after a restart
	if out, code := r.restart(); code != 0 {
		t.Fatalf("restart: %d %s", code, out)
	}
	if got := strings.Join(r.rules("6"), "|"); got != "-A OVPN_BAN6 -s 2001:db8:1:2::/64 -j DROP" {
		t.Errorf("the covering rule vanished at the restart: %q", got)
	}
	// an unban of a network that no row has does not touch the history of the narrower entries
	r.must("ban-manual", "--force", "198.51.100.7")
	before := r.read("audit/bans-history.tsv")
	r.must("unban", "198.51.0.0/16", "--force")
	if r.read("audit/bans-history.tsv") != before || len(r.rules("4")) != 1 {
		t.Errorf("an unban of a broader network changed history or rules: %q %v", r.read("audit/bans-history.tsv"), r.rules("4"))
	}
}

// ---- row 4: the reply is what was enforced --------------------------------------------------------------------------------------------

func TestBanGateResultLine(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	out := r.must("ban-manual", "--minutes", "5", "2001:db8:1:2::5")
	want := fmt.Sprintf("ovpn-ban-result ban entry=2001:db8:1:2::/64 requested=2001:db8:1:2::5 seconds=300 expires=%d ", rigStart+300)
	if !strings.Contains(out, want) {
		t.Errorf("a whole prefix was banned, the result must say so:\nwant %q\ngot  %s", want, out)
	}
	r.must("ban-manual", "5.5.5.5")
	out = r.must("ban-manual", "--minutes", "5", "5.5.5.5")
	if !strings.Contains(out, "seconds=0 expires=0 ") || !strings.Contains(out, "status=unchanged") {
		t.Errorf("a permanent ban on record decides the length: %s", out)
	}
	out = r.must("ban", "1.2.3.4", "3")
	if !strings.Contains(out, "ovpn-ban-result ban entry=1.2.3.4 requested=1.2.3.4 seconds=600 ") || !strings.Contains(out, "status=new") {
		t.Errorf("result of a fail2ban ban: %s", out)
	}
	out = r.must("ban", "1.2.3.4", "3")
	if !strings.Contains(out, "status=unchanged") {
		t.Errorf("the same incident again: %s", out)
	}
}

func startBanWatcher(t *testing.T, r *banRig, extraEnv ...string) func(banControlRequest) banControlResult {
	t.Helper()
	watcher, err := filepath.Abs(filepath.Join("setup", "ovpn-ban-control.py"))
	if err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(r.dir, "control")
	if err := os.Mkdir(ctl, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", watcher, ctl)
	cmd.Env = append(append(append([]string{}, r.env...), "OVPN_BAN_TOOL="+r.script, "OVPN_BAN_CONTROL_POLL=0.05", "OVPN_BAN_SWEEP_SECONDS=1"), extraEnv...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return func(req banControlRequest) banControlResult {
		t.Helper()
		res, err := submitBanControlRequest(context.Background(), ctl, req, 20*time.Second)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		return res
	}
}

func TestBanGateWatcherReplyIsEnforcedState(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	submit := startBanWatcher(t, r)
	res := submit(banControlRequest{Action: "ban", IP: "2001:db8:1:2::5", Minutes: 5})
	if !res.OK || !strings.Contains(res.Message, "banned 2001:db8:1:2::/64 for 5 minutes until ") || !strings.Contains(res.Message, "(requested 2001:db8:1:2::5)") {
		t.Errorf("IPv6 reply: %+v", res)
	}
	submit(banControlRequest{Action: "ban", IP: "5.5.5.5"})
	res = submit(banControlRequest{Action: "ban", IP: "5.5.5.5", Minutes: 5})
	if !res.OK || !strings.Contains(res.Message, "banned 5.5.5.5 permanently") || !strings.Contains(res.Message, "NOT the 5 minutes asked for") {
		t.Errorf("a permanent ban on record: %+v", res)
	}
	res = submit(banControlRequest{Action: "unban", IP: "2001:db8:1:2::5"})
	if !res.OK || !strings.Contains(res.Message, "unbanned 2001:db8:1:2::/64 (requested 2001:db8:1:2::5)") {
		t.Errorf("unban of an address inside a banned prefix: %+v", res)
	}
	res = submit(banControlRequest{Action: "unban", IP: "9.9.9.9"})
	if !res.OK || !strings.Contains(res.Message, "nothing was banned for 9.9.9.9") {
		t.Errorf("unban of something that is not banned: %+v", res)
	}
}

func TestBanGateForcedIPv6LoopbackCanBeUnbanned(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.must("ban-manual", "--force", "::1")
	if row := r.stateRow("::1"); row == nil {
		t.Fatalf("the forced ban of ::1 is listed as %q", r.read("audit/bans.tsv"))
	}
	if got := strings.Join(r.rules("6"), "|"); got != "-A OVPN_BAN6 -s ::1/128 -j DROP" {
		t.Errorf("rules %q", got)
	}
	r.must("unban", "::1", "--force")
	if len(r.rules("6")) != 0 || r.stateRow("::1") != nil {
		t.Errorf("unban left %v %q", r.rules("6"), r.read("audit/bans.tsv"))
	}
	// the row an earlier release wrote for it ("::/64") stays removable
	r.appendFile("fw/rules6", "-A OVPN_BAN6 -s ::/64 -j DROP\n")
	r.appendFile("audit/bans.tsv", fmt.Sprintf("::/64\t%d\t0\t0\tmanual\n", rigStart))
	if out, code := r.run(nil, "unban", "::/64", "--force"); code != 0 {
		t.Fatalf("unban of the old row: exit %d: %s", code, out)
	}
	if len(r.rules("6")) != 0 || r.stateRow("::/64") != nil {
		t.Errorf("the old row stays: %v %q", r.rules("6"), r.read("audit/bans.tsv"))
	}
	// the other unspecified networks are still refused
	if _, code := r.run(nil, "unban", "::/0", "--force"); code == 0 {
		t.Errorf("::/0 accepted")
	}
}

// ---- row 6: the state directory is trusted or the engine does not run ----------------------------------------------------------------------

func TestBanGateStateDirectoryTrust(t *testing.T) {
	t.Parallel()
	t.Run("a directory that group or other can write", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		dir := filepath.Join(r.dir, "audit")
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"init"}, {"setup"}, {"ban", "1.2.3.4", "3"}, {"expire"}} {
			out, code := r.run(nil, args...)
			if code == 0 || !strings.Contains(out, "writable by group or other") || !strings.Contains(out, dir) {
				t.Errorf("%v: exit %d: %s", args, code, out)
			}
		}
		if len(r.rules("4")) != 0 {
			t.Errorf("a ban was applied from an untrusted directory: %v", r.rules("4"))
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		r.must("ban", "1.2.3.4", "3")
	})
	t.Run("a directory owned by the VPN hook user", func(t *testing.T) {
		t.Parallel()
		if os.Geteuid() != 0 {
			t.Skip("needs root to chown")
		}
		r := newBanRig(t)
		dir := filepath.Join(r.dir, "audit")
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Skipf("chown: %v", err)
		}
		out, code := r.run(nil, "init")
		if code == 0 || !strings.Contains(out, "owned by uid 65534") {
			t.Errorf("init: exit %d: %s", code, out)
		}
		_ = os.Chown(dir, 0, 0)
		r.must("init")
		// a state file replaced by the hook user
		r.must("ban-manual", "9.9.9.9")
		if err := os.Chown(filepath.Join(dir, "bans-history.tsv"), 65534, 65534); err != nil {
			t.Fatal(err)
		}
		out, code = r.run(nil, "setup")
		if code == 0 || !strings.Contains(out, "bans-history.tsv is owned by uid 65534") {
			t.Errorf("setup: exit %d: %s", code, out)
		}
	})
	t.Run("a link in place of the history is never followed", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		target := r.write("elsewhere/hist.tsv", fmt.Sprintf("%d\t9.9.9.9\t32\tmanual\t0\t0\n", rigStart))
		if err := os.Symlink(target, filepath.Join(r.dir, "audit", "bans-history.tsv")); err != nil {
			t.Fatal(err)
		}
		for _, step := range []string{"init", "setup", "check"} {
			out, code := r.run(nil, step)
			if code == 0 || !strings.Contains(out, "symbolic link") {
				t.Errorf("%s: exit %d: %s", step, code, out)
			}
		}
		if len(r.rules("4")) != 0 {
			t.Errorf("the ban of the linked file was enforced: %v", r.rules("4"))
		}
	})
	t.Run("a link in place of the lock is never followed", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		victim := filepath.Join(r.dir, "elsewhere", "victim")
		if err := os.MkdirAll(filepath.Dir(victim), 0o700); err != nil {
			t.Fatal(err)
		}
		lock := filepath.Join(r.dir, "audit", "bans.tsv.lock")
		_ = os.Remove(lock)
		if err := os.Symlink(victim, lock); err != nil {
			t.Fatal(err)
		}
		out, code := r.run(nil, "ban", "1.2.3.4", "3")
		if code == 0 || !strings.Contains(out, "symbolic link") {
			t.Errorf("exit %d: %s", code, out)
		}
		if r.exists("elsewhere/victim") {
			t.Errorf("the lock path was followed and created its target")
		}
	})
	t.Run("a link in place of the ban list is never followed", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		target := r.write("elsewhere/bans.tsv", fmt.Sprintf("9.9.9.9\t%d\t0\t0\tmanual\n", rigStart))
		list := filepath.Join(r.dir, "audit", "bans.tsv")
		_ = os.Remove(list)
		if err := os.Symlink(target, list); err != nil {
			t.Fatal(err)
		}
		if out, code := r.run(nil, "expire"); code == 0 || !strings.Contains(out, "symbolic link") {
			t.Errorf("expire: exit %d: %s", code, out)
		}
	})
}

// ---- row 6: the kill window ------------------------------------------------------------------------------------------------------------------

func TestBanGateReconcileAfterInterruptedBan(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	// killed after the DROP rule, before anything else: no row, no history: an orphan that nothing could ever lift
	r.appendFile("fw/rules4", "-A OVPN_BAN -s 7.7.7.7/32 -j DROP\n")
	// killed after the history, before the row: the ban is in force in the history, the row is missing
	r.write("audit/bans-history.tsv", fmt.Sprintf("%d\t8.8.4.4\t32\tauth-failed\t1\t3600\n", rigStart-10))
	r.appendFile("fw/rules4", "-A OVPN_BAN -s 8.8.4.4/32 -j DROP\n")
	// a rule whose ban in the history has run out and that has no row
	r.appendFile("fw/rules4", "-A OVPN_BAN -s 8.8.8.8/32 -j DROP\n")
	r.appendFile("audit/bans-history.tsv", fmt.Sprintf("%d\t8.8.8.8\t32\tauth-failed\t1\t600\n", rigStart-5000))
	// a row of a ban in force whose rule is missing; and a row with a rule (adopted as it is)
	r.write("audit/bans.tsv", fmt.Sprintf("6.6.6.6\t%d\t%d\t3\tauth-failed\n5.5.5.5\t%d\t%d\t3\tauth-failed\n", rigStart-10, rigStart+3000, rigStart-10, rigStart+3000))
	r.appendFile("fw/rules4", "-A OVPN_BAN -s 5.5.5.5/32 -j DROP\n")
	// an IPv6 orphan
	r.appendFile("fw/rules6", "-A OVPN_BAN6 -s 2001:db8:77::/64 -j DROP\n")
	if out, code := r.run(nil, "expire"); code != 0 {
		t.Fatalf("expire: exit %d: %s", code, out)
	}
	got := strings.Join(r.rules("4"), "|")
	for _, want := range []string{"-s 8.8.4.4/32", "-s 6.6.6.6/32", "-s 5.5.5.5/32"} {
		if !strings.Contains(got, want) {
			t.Errorf("rules %q lack %s", got, want)
		}
	}
	for _, gone := range []string{"7.7.7.7", "8.8.8.8/32"} {
		if strings.Contains(got, gone) {
			t.Errorf("rules %q still hold the orphan %s", got, gone)
		}
	}
	if row := r.stateRow("8.8.4.4"); row == nil || row[1] != fmt.Sprint(rigStart-10) || row[2] != fmt.Sprint(rigStart+3590) {
		t.Errorf("the adopted row must carry the time and the end of the history: %v", row)
	}
	if len(r.rules("6")) != 0 {
		t.Errorf("IPv6 orphan stays: %v", r.rules("6"))
	}
	if ev := r.lastEvent("orphan-removed"); ev == nil {
		t.Errorf("no event for the removal of an orphan rule")
	}
	// a second sweep changes nothing
	before := r.read("audit/bans.tsv") + strings.Join(r.rules("4"), "\n")
	r.must("expire")
	if after := r.read("audit/bans.tsv") + strings.Join(r.rules("4"), "\n"); after != before {
		t.Errorf("a healthy sweep changed something:\n%s\n%s", before, after)
	}
	// the jail start (setup) reconciles too
	r.appendFile("fw/rules4", "-A OVPN_BAN -s 7.7.7.8/32 -j DROP\n")
	r.must("setup")
	if strings.Contains(strings.Join(r.rules("4"), "|"), "7.7.7.8") {
		t.Errorf("setup left an orphan: %v", r.rules("4"))
	}
}

func TestBanGateWatcherSweepsAtStart(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.appendFile("fw/rules4", "-A OVPN_BAN -s 7.7.7.7/32 -j DROP\n")
	startBanWatcher(t, r, "OVPN_BAN_SWEEP_SECONDS=3600")
	deadline := time.Now().Add(15 * time.Second)
	for len(r.rules("4")) != 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if len(r.rules("4")) != 0 {
		t.Errorf("the first sweep of the watcher did not run: %v", r.rules("4"))
	}
}

// ---- row 2: a ban in force survives a container restart, with its original end ----------------------------------------------------------------

func TestBanGateTemporaryBansSurviveRestart(t *testing.T) {
	t.Parallel()
	r := newBanRig(t)
	r.must("ban", "1.2.3.4", "3")                      // 600 s
	r.must("ban-manual", "--minutes", "60", "9.9.9.9") // timed manual ban
	r.must("ban-manual", "8.8.8.8")                    // permanent
	r.must("ban-manual", "--minutes", "30", "7.7.7.7") // lifted by the operator below
	r.must("unban", "7.7.7.7", "--force")
	r.setNow(rigStart + 100)
	if out, code := r.restart(); code != 0 {
		t.Fatalf("restart: %d %s", code, out)
	}
	got := strings.Join(r.rules("4"), "|")
	for _, a := range []string{"8.8.8.8", "1.2.3.4", "9.9.9.9"} {
		if !strings.Contains(got, "-s "+a+"/32 -j DROP") {
			t.Errorf("rules after the restart %q lack %s", got, a)
		}
	}
	if strings.Contains(got, "7.7.7.7") {
		t.Errorf("a ban the operator lifted came back: %q", got)
	}
	// the rows (what /api/bans lists) are the rules, with the original time and end
	if row := r.stateRow("1.2.3.4"); row == nil || row[1] != fmt.Sprint(rigStart) || row[2] != fmt.Sprint(rigStart+600) {
		t.Errorf("row of 1.2.3.4: %v", row)
	}
	if row := r.stateRow("9.9.9.9"); row == nil || row[2] != fmt.Sprint(rigStart+3600) {
		t.Errorf("row of 9.9.9.9: %v", row)
	}
	if n := strings.Count(r.read("audit/bans.tsv"), "\n"); n != len(r.rules("4")) {
		t.Errorf("rows (%d) and rules (%d) disagree: %q %v", n, len(r.rules("4")), r.read("audit/bans.tsv"), r.rules("4"))
	}
	// a ban that ran out while the container was down is not restored, one that has not is
	r.setNow(rigStart + 700)
	if out, code := r.restart(); code != 0 {
		t.Fatalf("second restart: %d %s", code, out)
	}
	got = strings.Join(r.rules("4"), "|")
	if strings.Contains(got, "1.2.3.4") || !strings.Contains(got, "9.9.9.9") || !strings.Contains(got, "8.8.8.8") {
		t.Errorf("after the second restart: %q", got)
	}
	// the restored ban is lifted when it runs out, by the sweep
	r.setNow(rigStart + 3601)
	r.must("expire")
	if strings.Contains(strings.Join(r.rules("4"), "|"), "9.9.9.9") || r.stateRow("9.9.9.9") != nil {
		t.Errorf("the restored temporary ban was not lifted: %v %q", r.rules("4"), r.read("audit/bans.tsv"))
	}
	// the cap bounds the rows: permanent first, then the newest; the rest stays in the history
	c := newBanRig(t, "OVPN_BAN_MAX_ENTRIES=2")
	hist := fmt.Sprintf("%d\t8.8.8.8\t32\tmanual\t0\t0\n%d\t1.1.1.1\t32\tauth-failed\t1\t3600\n%d\t1.1.1.2\t32\tauth-failed\t1\t3600\n", rigStart-50, rigStart-30, rigStart-20)
	c.write("audit/bans-history.tsv", hist)
	out, code := c.restart()
	if code != 0 || !strings.Contains(out, "1 NOT restored: OVPN_BAN_MAX_ENTRIES=2 is reached") {
		t.Fatalf("capped restore: %d %s", code, out)
	}
	if got := strings.Join(c.rules("4"), "|"); !strings.Contains(got, "8.8.8.8") || !strings.Contains(got, "1.1.1.2") || strings.Contains(got, "1.1.1.1") {
		t.Errorf("capped restore keeps the permanent and the newest: %q", got)
	}
	if c.read("audit/bans-history.tsv") != hist {
		t.Errorf("the cap changed the history")
	}
}
