package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A truncated ban history must never start healthy (t_98d06364). QA found, on ec13b2b, that a legacy ban-history.tsv cut short still
// parsed, started healthy under OVPN_BAN_REQUIRED=true and left permanent bans out: real clients that v0.1.11 had banned permanently
// logged in after the upgrade. The two files below are the data the real v0.1.11 release wrote (three permanent bans and one temporary
// one, made by real failed logins and manual bans through its panel): the history (234 bytes) and the ban list next to it (191 bytes).
// The sweep takes every truncation length of the history, runs the real "ovpn-ban.sh init" on it and demands: no length is accepted with
// fewer permanent bans than the old ban list holds.

const (
	v0111History = "172.31.150.70\t2\t1795454461\t1795454472\t1\tauth-failed\t3\n" +
		"172.31.150.71\t1\t1795454474\t1795454474\t1\tmanual: qa legacy\t0\n" +
		"fd00:172:150::70\t1\t1795454475\t1795454475\t1\tmanual: qa legacy v6\t0\n" +
		"172.31.150.72\t1\t1795454481\t1795454481\t0\tauth-failed\t3\n"
	v0111BanList = "172.31.150.70\t1795454472\t0\t3\tauth-failed\n" +
		"172.31.150.71\t1795454474\t0\t0\tmanual: qa legacy\n" +
		"fd00:172:150::70\t1795454475\t0\t0\tmanual: qa legacy v6\n" +
		"172.31.150.72\t1795454481\t1795458081\t3\tauth-failed\n"
	v0111HistorySHA = "3d8192d74b606497aeb2e60bb9ec6fb433f1254825fbbdbe708b6c6e41abea2a"
	v0111BanListSHA = "31a101ad56900df87d6c28acad7da980364e26df793a08fda81492076cfcc2c8"
)

// permRows counts the permanent rows (last field 0) of a history in the current format.
func permRows(history string) int {
	n := 0
	for _, l := range strings.Split(history, "\n") {
		if f := strings.Split(l, "\t"); len(f) == 6 && f[5] == "0" {
			n++
		}
	}
	return n
}

// resetGate puts the rig back to "no history anywhere": every history file next to the ban list and in the directory of the earlier layout.
func (r *banRig) resetGate(legacyDir string) {
	r.t.Helper()
	for _, pat := range []string{filepath.Join(r.dir, "audit", "*history*"), filepath.Join(legacyDir, "*")} {
		m, err := filepath.Glob(pat)
		if err != nil {
			r.t.Fatal(err)
		}
		for _, f := range m {
			if err := os.RemoveAll(f); err != nil {
				r.t.Fatal(err)
			}
		}
	}
}

func TestBanGateTruncationFixtureIsTheRealFile(t *testing.T) {
	t.Parallel()
	for name, c := range map[string][2]string{
		"ban-history.tsv": {v0111History, v0111HistorySHA},
		"bans.tsv":        {v0111BanList, v0111BanListSHA},
	} {
		sum := sha256.Sum256([]byte(c[0]))
		if got := hex.EncodeToString(sum[:]); got != c[1] {
			t.Errorf("%s of v0.1.11 changed: sha256 %s, want %s", name, got, c[1])
		}
	}
	if len(v0111History) != 234 || strings.Count(v0111History, "\n") != 4 {
		t.Errorf("history: %d bytes, %d rows", len(v0111History), strings.Count(v0111History, "\n"))
	}
}

// The sweep. Three ways the same file reaches the engine: migrated from next to the ban list (the layout copy of the old list is there, and
// init empties that list), migrated while both old files are only in the directory of the earlier layout, and converted in place because
// OVPN_BAN_HISTORY names it. The permanent entries of the old list are three; a cut is accepted only when all three are in the result.
func TestBanGateTruncationSweep(t *testing.T) {
	t.Parallel()
	hist := v0111History
	third := 0
	for i := 0; i < 3; i++ {
		third += strings.Index(hist[third:], "\n") + 1
	}
	// accepted: the whole file, and a cut after the third row (the temporary row of the old list is not required); nothing else
	okLen := func(n int) bool { return n >= third && (n == len(hist) || hist[n-1] == '\n') }
	type variant struct {
		name    string
		inPlace bool
		legacy  bool // both old files live in the directory of the earlier layout, the state directory has none
		full    bool // every length; the others try the lengths where the decision changes (see sampled below)
		// the live sweep scripts of the card try every length of each layout
	}
	variants := []variant{
		{"migration, old files next to the ban list", false, false, true},
		{"migration, old files in the directory of the earlier layout", false, true, false},
		{"in-place conversion of OVPN_BAN_HISTORY", true, false, false},
	}
	rowEnd := func(n int) bool { return n == 0 || hist[n-1] == '\n' }
	// the sampled variants try the lengths where the decision changes (the ends, the cut of QA at 40 bytes, every row end and the byte on
	// either side of it): about 17 of 235 lengths, because a full sweep of each variant adds minutes to a suite that has a 10 minute
	// default limit; the live sweep scripts of the card try every length of each layout
	sampled := func(n int) bool {
		return n <= 1 || n >= len(hist)-1 || n == 40 || rowEnd(n) || (n+1 <= len(hist) && rowEnd(n+1)) || rowEnd(n-1)
	}
	const workers = 5
	for _, v := range variants {
		for w := 0; w < workers; w++ {
			v, w := v, w
			t.Run(fmt.Sprintf("%s/worker %d", v.name, w), func(t *testing.T) {
				t.Parallel()
				legacyDir := t.TempDir()
				r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+legacyDir)
				stateList := filepath.Join(r.dir, "audit", "bans.tsv")
				histPath := filepath.Join(r.dir, "audit", "ban-history.tsv") // where the history of the earlier release is found
				listPath := stateList
				if v.legacy {
					histPath, listPath = filepath.Join(legacyDir, "ban-history.tsv"), filepath.Join(legacyDir, "bans.tsv")
				}
				if v.inPlace {
					histPath = filepath.Join(r.dir, "audit", "custom-history.tsv")
					r.env = append(r.env, "OVPN_BAN_HISTORY="+histPath)
				}
				var accepted, refused int
				for n := w; n <= len(hist); n += workers {
					if !v.full && !sampled(n) {
						continue
					}
					r.resetGate(legacyDir)
					r.write("audit/bans.tsv", "")
					if err := os.WriteFile(listPath, []byte(v0111BanList), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(histPath, []byte(hist[:n]), 0o600); err != nil {
						t.Fatal(err)
					}
					out, code := r.run(nil, "init")
					where := filepath.Join(r.dir, "audit", "bans-history.tsv") // the migrated history
					if v.inPlace {
						where = histPath
					}
					got, _ := os.ReadFile(where)
					if code == 0 {
						accepted++
						if p := permRows(string(got)); p != 3 {
							t.Errorf("length %d (last byte %q): init ACCEPTED the file with %d of 3 permanent bans: %q\n%s", n, lastByte(hist, n), p, got, out)
						}
						if !okLen(n) {
							t.Errorf("length %d (last byte %q): init accepted a file that is cut short", n, lastByte(hist, n))
						}
						continue
					}
					refused++
					if okLen(n) {
						t.Errorf("length %d: init refused an intact history (exit %d): %s", n, code, out)
					}
					if !strings.Contains(out, histPath) {
						t.Errorf("length %d: the refusal does not name the history %s: %s", n, histPath, out)
					}
					if n == 0 || hist[n-1] == '\n' {
						// a cut at a row end, or an empty file, still parses: only the old ban list can tell, and the message names both files
						if !strings.Contains(out, listPath) {
							t.Errorf("length %d: a cut at a row end must name the ban list %s: %s", n, listPath, out)
						}
					}
					if v.inPlace {
						if string(got) != hist[:n] {
							t.Errorf("length %d: the refused file was rewritten: %q", n, got)
						}
						if m, _ := filepath.Glob(histPath + ".legacy-format*"); len(m) != 0 {
							t.Errorf("length %d: a refused conversion left copies behind: %v", n, m)
						}
					} else if r.exists("audit/bans-history.tsv") {
						t.Errorf("length %d: a history was published for a refused file: %q", n, r.read("audit/bans-history.tsv"))
					}
					if !v.legacy && r.read("audit/bans.tsv") != v0111BanList {
						t.Errorf("length %d: a refused start emptied the old ban list: %q", n, r.read("audit/bans.tsv"))
					}
				}
				t.Logf("%s, worker %d: %d lengths accepted (each with 3 permanent bans), %d refused", v.name, w, accepted, refused)
			})
		}
	}
}

func lastByte(s string, n int) string {
	if n == 0 {
		return ""
	}
	return string(s[n-1])
}

// Repair 1 for the history of this engine: a file that is not empty and does not end in a newline is cut short, in either format.
func TestBanGateCutCurrentHistoryIsRefused(t *testing.T) {
	t.Parallel()
	cur := fmt.Sprintf("%d\t8.8.8.8\t32\tmanual\t0\t0\n%d\t1.1.1.1\t32\tauth-failed\t1\t3600\n%d\t2001:db8::\t64\tauth-failed\t2\t0\n", rigStart-50, rigStart-30, rigStart-20)
	const workers = 6
	for w := 0; w < workers; w++ {
		w := w
		t.Run(fmt.Sprintf("worker %d", w), func(t *testing.T) {
			t.Parallel()
			r := newBanRig(t)
			legacyDir := t.TempDir()
			for n := w; n <= len(cur); n += workers {
				if n%2 == 1 && cur[n-1] != '\n' && (n == len(cur) || cur[n] != '\n') {
					continue // every second cut inside a row; every cut at or next to a row end is tried
				}
				r.resetGate(legacyDir)
				r.write("audit/bans-history.tsv", cur[:n])
				out, code := r.run(nil, "init")
				rowEnd := n == 0 || cur[n-1] == '\n'
				if rowEnd && code != 0 {
					t.Errorf("length %d (a whole number of rows): refused: %s", n, out)
				}
				if !rowEnd {
					if code == 0 {
						t.Errorf("length %d (last byte %q): a cut current history was accepted", n, lastByte(cur, n))
					} else if !strings.Contains(out, "bans-history.tsv") || !strings.Contains(out, "newline") {
						t.Errorf("length %d: the refusal must name the file and the missing newline: %s", n, out)
					}
					if r.read("audit/bans-history.tsv") != cur[:n] {
						t.Errorf("length %d: the cut file was rewritten", n)
					}
				}
			}
		})
	}
}

func TestBanGateOldBanListChecks(t *testing.T) {
	t.Parallel()
	t.Run("zero-byte legacy history, permanent bans in the old list: refused, both files named", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		r.write("audit/bans.tsv", v0111BanList)
		hist := r.write("audit/ban-history.tsv", "")
		out, code := r.run(nil, "init")
		if code == 0 || !strings.Contains(out, hist) || !strings.Contains(out, filepath.Join(r.dir, "audit", "bans.tsv")) || !strings.Contains(out, "172.31.150.70") {
			t.Errorf("init: exit %d: %s", code, out)
		}
		if _, code := r.run(nil, "setup"); code == 0 {
			t.Errorf("setup went on from a refused migration")
		}
	})
	t.Run("a refused start that is tried again is refused again: the old list is not emptied", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		r.write("audit/bans.tsv", v0111BanList)
		r.write("audit/ban-history.tsv", v0111History[:v0111HistoryRow2End])
		for i := 0; i < 3; i++ {
			if out, code := r.run(nil, "init"); code == 0 {
				t.Fatalf("try %d accepted a cut history: %s", i, out)
			}
			if got := r.read("audit/bans.tsv"); got != v0111BanList {
				t.Fatalf("try %d: the old ban list changed: %q", i, got)
			}
		}
		// the operator restores the file: the next start is healthy and restores all three permanent bans
		r.write("audit/ban-history.tsv", v0111History)
		if out, code := r.restart(); code != 0 {
			t.Fatalf("restart with the whole history: exit %d: %s", code, out)
		}
		if len(r.rules("4")) != 2 || len(r.rules("6")) != 1 {
			t.Errorf("rules %v %v", r.rules("4"), r.rules("6"))
		}
	})
	t.Run("the whole real v0.1.11 data: all three permanent bans, healthy, and healthy again on the next start", func(t *testing.T) {
		t.Parallel()
		legacyDir := t.TempDir()
		r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+legacyDir)
		r.write("audit/bans.tsv", v0111BanList)
		r.write("audit/ban-history.tsv", v0111History)
		if err := os.WriteFile(filepath.Join(legacyDir, "bans.tsv"), []byte(v0111BanList), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, code := r.restart(); code != 0 {
			t.Fatalf("upgrade: exit %d: %s", code, out)
		}
		if got := permRows(r.read("audit/bans-history.tsv")); got != 3 {
			t.Errorf("permanent rows %d", got)
		}
		// the old list in the directory of the earlier layout stays; it is only compared during a migration
		if out, code := r.restart(); code != 0 {
			t.Fatalf("second start: exit %d: %s", code, out)
		}
	})
	t.Run("temporary rows of the old list are not required, a permanent row the history calls temporary is", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		r.write("audit/bans.tsv", "9.9.9.9\t10\t99999999999\t3\tauth-failed\n")
		r.write("audit/ban-history.tsv", legacyRows())
		if out, code := r.run(nil, "init"); code != 0 {
			t.Errorf("a temporary old row blocked the migration: %s", out)
		}
		r2 := newBanRig(t)
		r2.write("audit/bans.tsv", "5.6.7.8\t10\t0\t3\tmanual\n")
		r2.write("audit/ban-history.tsv", legacyRows()) // 5.6.7.8 is a temporary row there
		out, code := r2.run(nil, "init")
		if code == 0 || !strings.Contains(out, "5.6.7.8") {
			t.Errorf("init: exit %d: %s", code, out)
		}
	})
	t.Run("an old list that cannot be read is not taken for none", func(t *testing.T) {
		t.Parallel()
		for name, content := range map[string]string{
			"a row cut short":             v0111BanList[:60],
			"no newline at the end":       strings.TrimSuffix(v0111BanList, "\n"),
			"a row that is not a ban row": "this is not a row\n",
			"not text":                    "\xff\xfe\x00\x01\n",
		} {
			name, content := name, content
			t.Run(name, func(t *testing.T) {
				r := newBanRig(t)
				r.write("audit/bans.tsv", content)
				r.write("audit/ban-history.tsv", v0111History)
				out, code := r.run(nil, "init")
				if code == 0 || !strings.Contains(out, filepath.Join(r.dir, "audit", "bans.tsv")) {
					t.Errorf("init: exit %d: %s", code, out)
				}
			})
		}
		t.Run("a directory in its place, in the directory of the earlier layout", func(t *testing.T) {
			legacyDir := t.TempDir()
			r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+legacyDir)
			if err := os.Mkdir(filepath.Join(legacyDir, "bans.tsv"), 0o700); err != nil {
				t.Fatal(err)
			}
			r.write("audit/ban-history.tsv", v0111History)
			out, code := r.run(nil, "init")
			if code == 0 || !strings.Contains(out, filepath.Join(legacyDir, "bans.tsv")) {
				t.Errorf("init: exit %d: %s", code, out)
			}
		})
		t.Run("a link in its place, in the directory of the earlier layout", func(t *testing.T) {
			legacyDir := t.TempDir()
			r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+legacyDir)
			target := r.write("elsewhere/bans.tsv", v0111BanList)
			if err := os.Symlink(target, filepath.Join(legacyDir, "bans.tsv")); err != nil {
				t.Fatal(err)
			}
			r.write("audit/ban-history.tsv", v0111History)
			out, code := r.run(nil, "init")
			if code == 0 || !strings.Contains(out, filepath.Join(legacyDir, "bans.tsv")) {
				t.Errorf("init: exit %d: %s", code, out)
			}
		})
	})
	t.Run("in-place conversion: a cut at a row end is refused, the file and its name stay as they were", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_BAN_HISTORY=")
		path := filepath.Join(r.dir, "audit", "custom-history.tsv")
		r.env = append(r.env, "OVPN_BAN_HISTORY="+path)
		r.write("audit/bans.tsv", v0111BanList)
		cut := v0111History[:v0111HistoryRow2End]
		r.write("audit/custom-history.tsv", cut)
		out, code := r.run(nil, "init")
		if code == 0 || !strings.Contains(out, path) || !strings.Contains(out, filepath.Join(r.dir, "audit", "bans.tsv")) {
			t.Errorf("init: exit %d: %s", code, out)
		}
		if r.read("audit/custom-history.tsv") != cut {
			t.Errorf("the refused file was rewritten")
		}
		if m, _ := filepath.Glob(path + ".legacy-format*"); len(m) != 0 {
			t.Errorf("copies left behind: %v", m)
		}
	})
}

// The second record (t_3834d189, QA findings N1 and N3). A history that is empty, cut at a row end or replaced is a valid file of fewer
// bans: only a ban list can say it lost some. Every start compares the permanent rows of the engine's own ban list with the history, and
// the zero-byte history is compared with the old ban list too unless a conversion left its proof. The tests run the real script on the
// rig; the live proofs on real containers and clients are in the card's evidence directory.

// listRig is a rig that has banned three permanent addresses (two IPv4, one IPv6) through the script, so the history and the ban list are
// what the engine writes. It returns the rig and the two files' contents.
func listRig(t *testing.T, extra ...string) (*banRig, string, string) {
	t.Helper()
	r := newBanRig(t, extra...)
	r.must("ban-manual", "8.8.8.8", "first")
	r.must("ban-manual", "1.1.1.1", "second")
	r.must("ban-manual", "2001:db8:1:2::9", "third")
	hist, list := r.read("audit/bans-history.tsv"), r.read("audit/bans.tsv")
	if permRows(hist) != 3 || strings.Count(list, "\t0\t") != 3 {
		t.Fatalf("the rig did not make three permanent bans: history %q list %q", hist, list)
	}
	return r, hist, list
}

func TestBanGateListCrossCheckRefusesLostRows(t *testing.T) {
	t.Parallel()
	t.Run("current format: every cut at a row end and the emptied file is refused, every whole file starts", func(t *testing.T) {
		t.Parallel()
		r, hist, list := listRig(t)
		histPath, listPath := filepath.Join(r.dir, "audit", "bans-history.tsv"), filepath.Join(r.dir, "audit", "bans.tsv")
		var ends []int
		for i, c := range hist {
			if c == '\n' {
				ends = append(ends, i+1)
			}
		}
		for _, n := range append([]int{0}, ends...) {
			r.write("audit/bans-history.tsv", hist[:n])
			r.write("audit/bans.tsv", list)
			out, code := r.run(nil, "init")
			if n == len(hist) {
				if code != 0 {
					t.Errorf("the whole history refused: %s", out)
				}
				continue
			}
			lost := 3 - permRows(hist[:n])
			if code == 0 {
				t.Errorf("length %d of %d: a history with %d of 3 permanent bans was accepted: %s", n, len(hist), 3-lost, out)
				continue
			}
			for _, want := range []string{histPath, listPath, fmt.Sprintf("holds %d permanent ban(s)", lost)} {
				if !strings.Contains(out, want) {
					t.Errorf("length %d: the refusal lacks %q: %s", n, want, out)
				}
			}
			if r.read("audit/bans.tsv") != list || r.read("audit/bans-history.tsv") != hist[:n] {
				t.Errorf("length %d: a refused start changed a file", n)
			}
			if _, c2 := r.run(nil, "init"); c2 == 0 {
				t.Errorf("length %d: the second try was accepted (the first one emptied the list?)", n)
			}
		}
	})
	t.Run("a history that lost one row among the others is refused, the address named", func(t *testing.T) {
		t.Parallel()
		r, hist, list := listRig(t)
		rows := strings.SplitAfter(hist, "\n")
		r.write("audit/bans-history.tsv", rows[0]+rows[2]) // the second row is gone
		out, code := r.run(nil, "init")
		if code == 0 || !strings.Contains(out, "1.1.1.1") || strings.Contains(out, "8.8.8.8, ") {
			t.Errorf("init: exit %d: %s", code, out)
		}
		_ = list
	})
	t.Run("a ban list that is damaged is not taken for none", func(t *testing.T) {
		t.Parallel()
		for name, content := range map[string]string{"cut inside a row": "8.8.8.8\t1800000000\t0\t0\tmanu", "not a ban row": "no ban row\n", "not text": "\xff\xfe\x00\n"} {
			name, content := name, content
			t.Run(name, func(t *testing.T) {
				r, _, _ := listRig(t)
				r.write("audit/bans.tsv", content)
				out, code := r.run(nil, "init")
				if code == 0 || !strings.Contains(out, filepath.Join(r.dir, "audit", "bans.tsv")) {
					t.Errorf("init: exit %d: %s", code, out)
				}
			})
		}
	})
	t.Run("N1: the zero-byte file OVPN_BAN_HISTORY names, the old list next to it holds permanent bans", func(t *testing.T) {
		t.Parallel()
		legacyDir := t.TempDir()
		r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+legacyDir)
		named := filepath.Join(r.dir, "audit", "custom-history.tsv")
		r.env = append(r.env, "OVPN_BAN_HISTORY="+named)
		listPath := filepath.Join(r.dir, "audit", "bans.tsv")
		oldList := filepath.Join(legacyDir, "bans.tsv")
		check := func(t *testing.T, name string, wantRefused bool, wantFiles ...string) {
			t.Helper()
			out, code := r.run(nil, "init")
			if (code != 0) != wantRefused {
				t.Errorf("%s: exit %d, want refused=%v: %s", name, code, wantRefused, out)
			}
			for _, f := range wantFiles {
				if wantRefused && !strings.Contains(out, f) {
					t.Errorf("%s: the refusal does not name %s: %s", name, f, out)
				}
			}
			if wantRefused && !strings.Contains(out, "holds 3 permanent ban(s)") {
				t.Errorf("%s: the refusal lacks the count: %s", name, out)
			}
		}
		// case C of QA: the layout step copied the old list next to the history; nothing proves a conversion
		r.write("audit/custom-history.tsv", "")
		r.write("audit/bans.tsv", v0111BanList)
		check(t, "state list with 3 permanent rows (the layout copy)", true, listPath, named)
		// the old list only in the directory of the earlier layout (init without the layout step)
		r.write("audit/bans.tsv", "")
		if err := os.WriteFile(oldList, []byte(v0111BanList), 0o600); err != nil {
			t.Fatal(err)
		}
		check(t, "old list only in the earlier layout", true, oldList, named)
		// a marker that is a link proves nothing
		if err := os.Symlink(r.write("elsewhere/marker", ""), named+".legacy-format"); err != nil {
			t.Fatal(err)
		}
		check(t, "a link named like the marker", true, oldList, named)
		if err := os.Remove(named + ".legacy-format"); err != nil {
			t.Fatal(err)
		}
		// case F of QA: the conversion happened (its proof is on disk), the operator lifted every ban, the old copy stays in the old directory
		r.write("audit/custom-history.tsv.legacy-format", v0111History)
		check(t, "in-place marker, old list is only a copy", false)
		if err := os.Remove(named + ".legacy-format"); err != nil {
			t.Fatal(err)
		}
		r.write("audit/ban-history.tsv.migrated", v0111History)
		check(t, "migration marker next to the history of the state directory", false)
		// the marker does not excuse the engine's own list: the history that lost rows after the conversion is refused all the same
		r.write("audit/bans.tsv", v0111BanList)
		check(t, "marker, but the engine's own list holds permanent bans", true, listPath, named)
	})
}

// A start must never be refused for a state an operator or the engine legitimately leaves behind (every one of these is a real start of the
// script after the real operations; the live proofs are on containers). A false refusal stops a working site.
func TestBanGateListCrossCheckLegitimateStatesStart(t *testing.T) {
	t.Parallel()
	restartOK := func(t *testing.T, r *banRig, what string) {
		t.Helper()
		for i := 0; i < 1; i++ {
			if out, code := r.restart(); code != 0 {
				t.Fatalf("%s, start %d: exit %d: %s", what, i+1, code, out)
			}
		}
	}
	has := func(r *banRig, a string) bool {
		return strings.Contains(strings.Join(append(r.rules("4"), r.rules("6")...), "|"), a)
	}
	t.Run("a permanent ban lifted (forced unban, what the panel does), the others stay", func(t *testing.T) {
		t.Parallel()
		r, _, _ := listRig(t)
		r.must("unban", "8.8.8.8", "--force")
		restartOK(t, r, "lifted")
		if has(r, "8.8.8.8") || !has(r, "1.1.1.1") || permRows(r.read("audit/bans-history.tsv")) != 2 {
			t.Errorf("lifted: rules %v %v history %q", r.rules("4"), r.rules("6"), r.read("audit/bans-history.tsv"))
		}
	})
	t.Run("an unban without force leaves a permanent ban as it is", func(t *testing.T) {
		t.Parallel()
		r, _, _ := listRig(t)
		r.run(nil, "unban", "8.8.8.8")
		restartOK(t, r, "unban without force")
		if !has(r, "8.8.8.8") {
			t.Errorf("a permanent ban was lost: %v", r.rules("4"))
		}
	})
	t.Run("the same address banned again after its lift", func(t *testing.T) {
		t.Parallel()
		r, _, _ := listRig(t)
		r.must("unban", "8.8.8.8", "--force")
		r.must("ban-manual", "8.8.8.8", "again")
		restartOK(t, r, "banned again")
		if !has(r, "8.8.8.8") {
			t.Errorf("the re-ban was lost: %v", r.rules("4"))
		}
		r.must("unban", "8.8.8.8", "--force")
		r.must("ban-manual", "--minutes", "30", "8.8.8.8", "again temporary this time")
		restartOK(t, r, "banned again, temporarily")
	})
	t.Run("a temporary ban that expired, in the running container and while it was down", func(t *testing.T) {
		t.Parallel()
		r, _, _ := listRig(t)
		r.must("ban-manual", "--minutes", "1", "9.9.9.9")
		r.must("ban-manual", "--minutes", "1", "7.7.7.7")
		r.setNow(rigStart + 100)
		r.must("expire")
		r.must("ban-manual", "--minutes", "1", "6.6.6.6") // runs out while the container is down
		r.setNow(rigStart + 300)
		restartOK(t, r, "expired")
		if has(r, "9.9.9.9") || has(r, "6.6.6.6") || !has(r, "1.1.1.1") {
			t.Errorf("expired: rules %v", r.rules("4"))
		}
	})
	t.Run("a temporary ban that was made permanent by the escalation", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_BAN_ESCALATION=60,0")
		r.must("ban", "1.2.3.4", "3")
		r.setNow(rigStart + 120)
		r.must("expire")
		r.must("ban", "1.2.3.4", "3") // second offence: permanent
		if permRows(r.read("audit/bans-history.tsv")) != 1 {
			t.Fatalf("no permanent offence: %q", r.read("audit/bans-history.tsv"))
		}
		restartOK(t, r, "escalated")
		if !has(r, "1.2.3.4") {
			t.Errorf("the permanent ban was lost: %v", r.rules("4"))
		}
	})
	t.Run("the operator emptied the ban list and the history together", func(t *testing.T) {
		t.Parallel()
		r, _, _ := listRig(t)
		r.write("audit/bans.tsv", "")
		r.write("audit/bans-history.tsv", "")
		restartOK(t, r, "emptied together")
		if len(r.rules("4"))+len(r.rules("6")) != 0 {
			t.Errorf("rules: %v %v", r.rules("4"), r.rules("6"))
		}
	})
	t.Run("both files removed", func(t *testing.T) {
		t.Parallel()
		r, _, _ := listRig(t)
		for _, f := range []string{"audit/bans.tsv", "audit/bans-history.tsv"} {
			if err := os.Remove(filepath.Join(r.dir, f)); err != nil {
				t.Fatal(err)
			}
		}
		restartOK(t, r, "both removed")
	})
	t.Run("a fresh installation, and a named history that does not exist yet", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t)
		restartOK(t, r, "fresh")
		n := newBanRig(t, "OVPN_BAN_HISTORY=")
		n.env = append(n.env, "OVPN_BAN_HISTORY="+filepath.Join(n.dir, "audit", "named.tsv"))
		restartOK(t, n, "fresh with a named history")
		z := newBanRig(t)
		z.write("audit/bans-history.tsv", "")
		restartOK(t, z, "a zero-byte history and no list")
	})
	t.Run("a good upgrade, then restarts and a lift", func(t *testing.T) {
		t.Parallel()
		legacyDir := t.TempDir()
		r := newBanRig(t, "OVPN_BAN_LEGACY_DIR="+legacyDir)
		r.write("audit/bans.tsv", v0111BanList)
		r.write("audit/ban-history.tsv", v0111History)
		if err := os.WriteFile(filepath.Join(legacyDir, "bans.tsv"), []byte(v0111BanList), 0o600); err != nil {
			t.Fatal(err)
		}
		restartOK(t, r, "upgrade")
		for _, a := range []string{"172.31.150.70", "172.31.150.71", "172.31.150.72"} {
			r.must("unban", a, "--force")
		}
		r.must("unban", "fd00:172:150::70", "--force")
		restartOK(t, r, "every ban lifted after the upgrade (the old list stays in the old directory)")
		r.write("audit/bans-history.tsv", "")
		restartOK(t, r, "history emptied after every ban was lifted")
	})
	t.Run("the cap: more permanent bans than OVPN_BAN_MAX_ENTRIES", func(t *testing.T) {
		t.Parallel()
		r := newBanRig(t, "OVPN_BAN_MAX_ENTRIES=2")
		r.write("audit/bans-history.tsv", fmt.Sprintf("%d\t8.8.8.8\t32\tmanual\t0\t0\n%d\t1.1.1.1\t32\tmanual\t0\t0\n%d\t9.9.9.9\t32\tmanual\t0\t0\n", rigStart-50, rigStart-30, rigStart-20))
		restartOK(t, r, "cap")
	})
}

// the end of the second row of the real history: a cut there parses and lacks the third permanent ban
var v0111HistoryRow2End = func() int {
	n := 0
	for i := 0; i < 2; i++ {
		n += strings.Index(v0111History[n:], "\n") + 1
	}
	return n
}()
