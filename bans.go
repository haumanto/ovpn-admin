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

	log "github.com/sirupsen/logrus"
)

// Ban list written by the OpenVPN ban engine (setup/ovpn-ban.sh). One tab-separated row per active ban, no header:
//
//	ip  banned_at_unix  expires_at_unix  failures  reason
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

// banJSON is the wire form of a ban in GET /api/bans.
type banJSON struct {
	IP        string `json:"ip"`
	BannedAt  string `json:"banned_at"`
	ExpiresAt string `json:"expires_at"`
	Failures  int    `json:"failures"`
	Reason    string `json:"reason"`
}

type bansResponse struct {
	Bans []banJSON `json:"bans"`
}

// banListPath is the ban list file: bans.tsv in the directory of the audit log.
func banListPath() string {
	if *auditPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(*auditPath), banFileName)
}

// parseBanLine parses one row of the ban list. The reason is the last column and may be empty.
func parseBanLine(line string) (banEntry, error) {
	f := strings.SplitN(strings.TrimRight(line, "\r"), "\t", banFieldCount)
	if len(f) != banFieldCount {
		return banEntry{}, fmt.Errorf("want %d fields, got %d", banFieldCount, len(f))
	}
	ip := net.ParseIP(strings.TrimSpace(f[0]))
	if ip == nil {
		return banEntry{}, fmt.Errorf("bad ip %q", f[0])
	}
	bannedAt, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
	if err != nil || bannedAt <= 0 {
		return banEntry{}, fmt.Errorf("bad banned_at %q", f[1])
	}
	expiresAt, err := strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64)
	if err != nil || expiresAt <= 0 {
		return banEntry{}, fmt.Errorf("bad expires_at %q", f[2])
	}
	failures, err := strconv.Atoi(strings.TrimSpace(f[3]))
	if err != nil || failures < 0 {
		return banEntry{}, fmt.Errorf("bad failures %q", f[3])
	}
	return banEntry{
		IP:        ip.String(),
		BannedAt:  bannedAt,
		ExpiresAt: expiresAt,
		Failures:  failures,
		Reason:    strings.TrimSpace(f[4]),
	}, nil
}

// parseBans parses the file content, skips malformed rows and rows that expired at or before now, and returns the
// rest newest ban first (ties by IP). The second result counts the malformed rows.
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
		if b.ExpiresAt <= now.Unix() {
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
		resp.Bans = append(resp.Bans, banJSON{
			IP:        b.IP,
			BannedAt:  auditTimeString(b.BannedAt),
			ExpiresAt: auditTimeString(b.ExpiresAt),
			Failures:  b.Failures,
			Reason:    b.Reason,
		})
	}
	body, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
