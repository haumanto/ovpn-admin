package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

// Ban list written by the OpenVPN ban engine (setup/ovpn-ban.sh). One tab-separated row per active ban, no header:
//
//	ip  banned_at_unix  expires_at_unix  failures  reason
//
// ip is an address, or for an IPv6 ban of a prefix the network with the prefix length it was banned with ("2001:db8:1:2::/64"; the
// engine bans a whole /64 by default). expires_at_unix 0 marks a permanent ban: it never expires on its own and is removed only by a
// manual unban.
//
// The file sits next to the audit log (--audit.path) and is replaced atomically by the writer.
const (
	banFieldCount   = 5
	banFileName     = "bans.tsv"
	banMaxReadBytes = 4 << 20
)

// banEntry is one parsed row of the ban list.
type banEntry struct {
	IP        string
	BannedAt  int64
	ExpiresAt int64
	Failures  int
	Reason    string
}

// permanent reports a ban without an expiry (expires_at 0 in the ban list).
func (b banEntry) permanent() bool { return b.ExpiresAt == 0 }

// banJSON is the wire form of a ban in GET /api/bans. A permanent ban has "permanent": true and an empty expires_at.
type banJSON struct {
	IP        string `json:"ip"`
	BannedAt  string `json:"banned_at"`
	ExpiresAt string `json:"expires_at"`
	Permanent bool   `json:"permanent"`
	Failures  int    `json:"failures"`
	Reason    string `json:"reason"`
}

type bansResponse struct {
	Bans []banJSON `json:"bans"`
}

// stateDir is the root-only state tree of the VPN container (compose: /var/lib/ovpn-admin), which holds the ban list (bans.tsv) and the
// manual ban queue (control/). Empty, the default, keeps the earlier layout: both sit next to the audit log (--audit.path).
var stateDir = kingpin.Flag("state.dir", "directory of the ban list (bans.tsv) and the manual ban queue (control/), written by the ban engine of the openvpn container; empty = the directory of --audit.path (earlier layout)").Default("").Envar("OVPN_STATE_DIR").String()

// banStateBase is the directory of the ban list and the ban queue: --state.dir, else the directory of the audit log, empty with neither.
func banStateBase() string {
	if *stateDir != "" {
		return filepath.Clean(*stateDir)
	}
	if *auditPath == "" {
		return ""
	}
	return filepath.Dir(*auditPath)
}

// banListPath is the ban list file: bans.tsv in the state directory, or in the directory of the audit log without one.
func banListPath() string {
	base := banStateBase()
	if base == "" {
		return ""
	}
	return filepath.Join(base, banFileName)
}

// parseBanSource parses the first column of a row: an address, or for an IPv6 ban of a prefix the network with the prefix length it was
// banned with ("2001:db8:1:2::/64"). It returns the canonical text of it; the unban of a row names exactly that text.
func parseBanSource(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("bad network %q", raw)
		}
		return network.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("bad ip %q", raw)
	}
	return ip.String(), nil
}

// parseBanLine parses one row of the ban list. The reason is the last column and may be empty.
func parseBanLine(line string) (banEntry, error) {
	f := strings.SplitN(strings.TrimRight(line, "\r"), "\t", banFieldCount)
	if len(f) != banFieldCount {
		return banEntry{}, fmt.Errorf("want %d fields, got %d", banFieldCount, len(f))
	}
	ipText, err := parseBanSource(f[0])
	if err != nil {
		return banEntry{}, err
	}
	bannedAt, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
	if err != nil || bannedAt <= 0 {
		return banEntry{}, fmt.Errorf("bad banned_at %q", f[1])
	}
	expiresAt, err := strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64)
	if err != nil || expiresAt < 0 {
		return banEntry{}, fmt.Errorf("bad expires_at %q", f[2])
	}
	failures, err := strconv.Atoi(strings.TrimSpace(f[3]))
	if err != nil || failures < 0 {
		return banEntry{}, fmt.Errorf("bad failures %q", f[3])
	}
	return banEntry{
		IP:        ipText,
		BannedAt:  bannedAt,
		ExpiresAt: expiresAt,
		Failures:  failures,
		Reason:    strings.TrimSpace(f[4]),
	}, nil
}

// parseBans parses the file content, skips malformed rows and rows that expired at or before now (a permanent row,
// expires_at 0, never expires), and returns the rest newest ban first (ties by IP). The second result counts the malformed rows.
func parseBans(data []byte, now time.Time) ([]banEntry, int) {
	bans := []banEntry{}
	skipped := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		b, err := parseBanLine(line)
		if err != nil {
			skipped++
			continue
		}
		if !b.permanent() && b.ExpiresAt <= now.Unix() {
			continue
		}
		bans = append(bans, b)
	}
	sort.SliceStable(bans, func(i, j int) bool {
		if bans[i].BannedAt != bans[j].BannedAt {
			return bans[i].BannedAt > bans[j].BannedAt
		}
		return bans[i].IP < bans[j].IP
	})
	return bans, skipped
}

// readBans loads the active bans. A missing or unreadable file is an empty list.
func readBans(path string, now time.Time) []banEntry {
	if path == "" {
		return []banEntry{}
	}
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warnf("bans: open %s: %v", path, err)
		}
		return []banEntry{}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, banMaxReadBytes))
	if err != nil {
		log.Warnf("bans: read %s: %v", path, err)
		return []banEntry{}
	}
	bans, skipped := parseBans(data, now)
	if skipped > 0 {
		log.Debugf("bans: %s: skipped %d malformed row(s)", path, skipped)
	}
	return bans
}

// bansHandler serves GET /api/bans.
func (oAdmin *OvpnAdmin) bansHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, `{"status":"error"}`, http.StatusMethodNotAllowed)
		return
	}
	resp := bansResponse{Bans: []banJSON{}}
	for _, b := range readBans(banListPath(), time.Now()) {
		j := banJSON{
			IP:        b.IP,
			BannedAt:  auditTimeString(b.BannedAt),
			Permanent: b.permanent(),
			Failures:  b.Failures,
			Reason:    b.Reason,
		}
		if !j.Permanent {
			j.ExpiresAt = auditTimeString(b.ExpiresAt)
		}
		resp.Bans = append(resp.Bans, j)
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
