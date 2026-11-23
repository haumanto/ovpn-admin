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
	// One documented exception: a zero-byte file that OVPN_BAN_HISTORY itself names is an empty history of the current format as far as
	// anybody can tell (an operator who lifted every ban has exactly that file); the engine does not convert it, so nothing compares it with
	// the old list. A zero-byte file in the place of the history of the earlier release IS compared (all variants but the in-place one).
	emptyInPlace := func(v bool, n int) bool { return v && n == 0 }
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
						if emptyInPlace(v.inPlace, n) {
							if len(got) != 0 {
								t.Errorf("length 0 in place: the empty file was changed: %q", got)
							}
							continue
						}
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

// the end of the second row of the real history: a cut there parses and lacks the third permanent ban
var v0111HistoryRow2End = func() int {
	n := 0
	for i := 0; i < 2; i++ {
		n += strings.Index(v0111History[n:], "\n") + 1
	}
	return n
}()
