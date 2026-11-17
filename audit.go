package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Audit log written by the OpenVPN connection hooks. One tab-separated event per line, append-only:
//
//	event  time_unix  username  real_ip  real_port  virtual_ip4  virtual_ip6  bytes_received  bytes_sent
//
// event is connect, disconnect, auth_ok or auth_fail; a missing value is "-".
const (
	auditFieldCount       = 9
	auditMaxReadBytes     = 2 << 20 // only the tail of the file is read
	auditCacheTTL         = 5 * time.Second
	auditDefaultLimit     = 50
	auditMaxLimit         = 500
	auditEventConnect     = "connect"
	auditEventDisconnect  = "disconnect"
	auditEventAuthOK      = "auth_ok"
	auditEventAuthFail    = "auth_fail"
	auditMissingFieldMark = "-"
)

// auditEvent is one parsed line of the audit log.
type auditEvent struct {
	Time          int64
	Event         string
	Username      string
	IP            string
	VirtualIP     string
	BytesReceived int64
	BytesSent     int64
}

// auditEventJSON is the wire form of an event in GET /api/user/audit.
type auditEventJSON struct {
	Time          string `json:"Time"`
	Event         string `json:"Event"`
	IP            string `json:"IP"`
	VirtualIP     string `json:"VirtualIP"`
	BytesReceived int64  `json:"BytesReceived"`
	BytesSent     int64  `json:"BytesSent"`
}

type auditResponse struct {
	Username string           `json:"username"`
	Events   []auditEventJSON `json:"events"`
}

// auditIndex holds the events of the read window grouped by username, oldest first.
type auditIndex struct {
	byUser map[string][]auditEvent
}

func auditTimeString(unix int64) string {
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

// lastLogin returns the newest connect event of the user, or, if there is none, the newest auth_ok.
func (idx *auditIndex) lastLogin(username string) (auditEvent, bool) {
	if idx == nil {
		return auditEvent{}, false
	}
	events := idx.byUser[username]
	var authOK *auditEvent
	for i := len(events) - 1; i >= 0; i-- {
		switch events[i].Event {
		case auditEventConnect:
			return events[i], true
		case auditEventAuthOK:
			if authOK == nil {
				authOK = &events[i]
			}
		}
	}
	if authOK != nil {
		return *authOK, true
	}
	return auditEvent{}, false
}

// newest returns up to limit events of the user, newest first.
func (idx *auditIndex) newest(username string, limit int) []auditEvent {
	if idx == nil {
		return nil
	}
	events := idx.byUser[username]
	if len(events) < limit {
		limit = len(events)
	}
	out := make([]auditEvent, 0, limit)
	for i := len(events) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, events[i])
	}
	return out
}

func auditField(s string) string {
	if s == auditMissingFieldMark {
		return ""
	}
	return s
}

func auditBytesField(s string) (int64, error) {
	if s == auditMissingFieldMark || s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad byte count %q", s)
	}
	return n, nil
}

// parseAuditLine parses one line without its newline.
func parseAuditLine(line string) (auditEvent, error) {
	fields := strings.Split(strings.TrimSuffix(line, "\r"), "\t")
	if len(fields) != auditFieldCount {
		return auditEvent{}, fmt.Errorf("want %d fields, got %d", auditFieldCount, len(fields))
	}
	var ev auditEvent
	switch fields[0] {
	case auditEventConnect, auditEventDisconnect, auditEventAuthOK, auditEventAuthFail:
		ev.Event = fields[0]
	default:
		return auditEvent{}, fmt.Errorf("unknown event %q", fields[0])
	}
	t, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || t < 0 {
		return auditEvent{}, fmt.Errorf("bad time %q", fields[1])
	}
	ev.Time = t
	ev.Username = auditField(fields[2])
	if ev.Username == "" {
		return auditEvent{}, errors.New("no username")
	}
	ev.IP = auditField(fields[3])
	// fields[4] is the real port, not exposed
	ev.VirtualIP = auditField(fields[5])
	if ev.VirtualIP == "" {
		ev.VirtualIP = auditField(fields[6])
	}
	if ev.BytesReceived, err = auditBytesField(fields[7]); err != nil {
		return auditEvent{}, err
	}
	if ev.BytesSent, err = auditBytesField(fields[8]); err != nil {
		return auditEvent{}, err
	}
	return ev, nil
}

// buildAuditIndex parses the data; malformed lines are skipped and counted.
func buildAuditIndex(data []byte) (*auditIndex, int) {
	idx := &auditIndex{byUser: map[string][]auditEvent{}}
	skipped := 0
	for _, raw := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		ev, err := parseAuditLine(string(raw))
		if err != nil {
			skipped++
			log.Debugf("audit: skipping malformed line: %v", err)
			continue
		}
		idx.byUser[ev.Username] = append(idx.byUser[ev.Username], ev)
	}
	// hooks of concurrent connections may append slightly out of order; stable sort keeps
	// file order for equal timestamps, so the later line counts as newer
	for _, events := range idx.byUser {
		sort.SliceStable(events, func(i, j int) bool { return events[i].Time < events[j].Time })
	}
	return idx, skipped
}

// readAuditTail returns at most auditMaxReadBytes from the end of the file; when the file is
// larger, the partial first line is dropped. The returned FileInfo is that of the open file.
func readAuditTail(path string) ([]byte, fs.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	size := info.Size()
	start := int64(0)
	if size > auditMaxReadBytes {
		start = size - auditMaxReadBytes
	}
	// when truncating, read one byte earlier to tell whether the window starts on a line boundary
	readFrom := start
	if start > 0 {
		readFrom = start - 1
	}
	buf := make([]byte, size-readFrom)
	n, err := f.ReadAt(buf, readFrom)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, err
	}
	buf = buf[:n]
	if start > 0 {
		if len(buf) > 0 && buf[0] != '\n' {
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				buf = buf[i:]
			} else {
				buf = nil
			}
		}
	}
	return buf, info, nil
}

// auditLog reads the audit file and caches the parsed index for auditCacheTTL, keyed by the
// file's (path, mtime, size). The mutex guards the cache.
type auditLog struct {
	pathFn func() string
	now    func() time.Time

	mu       sync.Mutex
	path     string
	mtime    time.Time
	size     int64
	loadedAt time.Time
	idx      *auditIndex
	reads    int // number of times the file was read; observable by tests
}

func newAuditLog(pathFn func() string) *auditLog {
	return &auditLog{pathFn: pathFn, now: time.Now}
}

// defaultAuditLog serves the handlers; it follows the --audit.path flag.
var defaultAuditLog = newAuditLog(func() string { return *auditPath })

// index returns the current parsed index. A missing or unreadable file is an empty history.
func (a *auditLog) index() *auditIndex {
	empty := &auditIndex{byUser: map[string][]auditEvent{}}
	path := a.pathFn()
	if path == "" {
		return empty
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	st, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warnf("audit: stat %s: %v", path, err)
		}
		a.idx = nil
		return empty
	}
	if a.idx != nil && a.path == path && a.mtime.Equal(st.ModTime()) && a.size == st.Size() &&
		a.now().Sub(a.loadedAt) < auditCacheTTL {
		return a.idx
	}

	data, info, err := readAuditTail(path)
	a.reads++
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warnf("audit: read %s: %v", path, err)
		}
		a.idx = nil
		return empty
	}
	idx, skipped := buildAuditIndex(data)
	if skipped > 0 {
		log.Debugf("audit: %s: skipped %d malformed line(s)", path, skipped)
	}
	a.idx, a.path, a.mtime, a.size, a.loadedAt = idx, path, info.ModTime(), info.Size(), a.now()
	return idx
}

// userAuditHandler serves GET /api/user/audit?username=<name>&limit=<n>.
func (oAdmin *OvpnAdmin) userAuditHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, `{"status":"error"}`, http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	limit := auditDefaultLimit
	if raw := strings.TrimSpace(r.FormValue("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = n
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}

	resp := auditResponse{Username: username, Events: []auditEventJSON{}}
	for _, ev := range defaultAuditLog.index().newest(username, limit) {
		resp.Events = append(resp.Events, auditEventJSON{
			Time:          auditTimeString(ev.Time),
			Event:         ev.Event,
			IP:            ev.IP,
			VirtualIP:     ev.VirtualIP,
			BytesReceived: ev.BytesReceived,
			BytesSent:     ev.BytesSent,
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

// withLastLogin returns a copy of clients with LastLogin and LastLoginIP filled from the audit log.
func withLastLogin(clients []OpenvpnClient, idx *auditIndex) []OpenvpnClient {
	if clients == nil {
		return nil
	}
	out := make([]OpenvpnClient, len(clients))
	copy(out, clients)
	for i := range out {
		out[i].LastLogin, out[i].LastLoginIP = "", ""
		if ev, ok := idx.lastLogin(out[i].Identity); ok {
			out[i].LastLogin = auditTimeString(ev.Time)
			out[i].LastLoginIP = ev.IP
		}
	}
	return out
}
