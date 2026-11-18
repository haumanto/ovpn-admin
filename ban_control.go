package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

// Manual ban control. The ban engine runs in the OpenVPN container (setup/ovpn-ban-control.py); the admin talks to it
// through a queue directory shared with this container, a subdirectory "control" of the audit directory:
//
//	<id>.req     {"id":"<id>","action":"ban"|"unban","ip":"<address>","reason":"<note>"}   written here
//	<id>.result  {"ok":true|false,"message":"..."}                                          written by the watcher
//
// <id> is 1 to 64 characters of [A-Za-z0-9_-] and is also the file name stem, so it can never leave the directory.
const (
	banControlDirName  = "control"
	banControlPoll     = 50 * time.Millisecond
	banControlMaxBytes = 4096
	banReasonMaxLen    = 120
	banControlIDLen    = 16 // random bytes, 32 hex characters
)

// banControlWait is how long a request waits for the watcher; a variable so that tests can shorten it.
var banControlWait = 6 * time.Second

var (
	errBanControlTimeout = errors.New("the ban watcher did not answer in time")
	errBanControlResult  = errors.New("the ban watcher result is unreadable")
)

// banControlRequest is the JSON of a queue request.
type banControlRequest struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// banControlResult is the JSON of a queue result.
type banControlResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// banControlDir is <audit dir>/control, "" without an audit path.
func banControlDir() string {
	if *auditPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(*auditPath), banControlDirName)
}

// validBanControlID: 1 to 64 characters of [A-Za-z0-9_-]. Anything else could name another path.
func validBanControlID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// newBanControlID returns 32 hex characters from crypto/rand.
func newBanControlID() (string, error) {
	b := make([]byte, banControlIDLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateBanIP accepts one literal address and returns its canonical text. Loopback, unspecified, multicast and
// link-local addresses are refused: they are never a remote client worth banning, or would lock the host out.
func validateBanIP(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("ip is required")
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", errors.New("ip is not a valid IPv4 or IPv6 address")
	}
	switch {
	case ip.IsUnspecified():
		return "", errors.New("the unspecified address cannot be banned")
	case ip.IsLoopback():
		return "", errors.New("a loopback address cannot be banned")
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast():
		return "", errors.New("a multicast address cannot be banned")
	case ip.IsLinkLocalUnicast():
		return "", errors.New("a link-local address cannot be banned")
	}
	return ip.String(), nil
}

// validateBanReason: at most 120 characters, printable ASCII and spaces only (no tab, newline or control character).
func validateBanReason(reason string) error {
	if len(reason) > banReasonMaxLen {
		return fmt.Errorf("note is longer than %d characters", banReasonMaxLen)
	}
	for i := 0; i < len(reason); i++ {
		if reason[i] < 0x20 || reason[i] > 0x7e {
			return errors.New("note may contain only printable ASCII characters and spaces")
		}
	}
	return nil
}

// writeBanControlRequest writes <dir>/<id>.req through a temporary file and a rename, so that the watcher never
// reads a half written request. The directory must exist: the watcher owns and creates it.
func writeBanControlRequest(dir string, req banControlRequest) error {
	if !validBanControlID(req.ID) {
		return errors.New("invalid request id")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+req.ID)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(dir, req.ID+".req"))
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}

// readBanControlResult reads and parses <dir>/<id>.result. found is false while the file does not exist yet.
func readBanControlResult(dir, id string) (res banControlResult, found bool, err error) {
	path := filepath.Join(dir, id+".result")
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, false, nil
		}
		return res, false, err
	}
	if !st.Mode().IsRegular() {
		return res, true, errBanControlResult
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, false, nil
		}
		return res, true, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, banControlMaxBytes+1))
	if err != nil || len(data) > banControlMaxBytes {
		return res, true, errBanControlResult
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return banControlResult{}, true, errBanControlResult
	}
	return res, true, nil
}

// submitBanControl queues one request and waits up to timeout for its result. The result file is always removed
// after it was seen. On a timeout the request is withdrawn if the watcher has not claimed it yet, so that a request
// answered with 504 is not run later.
func submitBanControl(ctx context.Context, dir, action, ip, reason string, timeout time.Duration) (banControlResult, error) {
	id, err := newBanControlID()
	if err != nil {
		return banControlResult{}, err
	}
	if err := writeBanControlRequest(dir, banControlRequest{ID: id, Action: action, IP: ip, Reason: reason}); err != nil {
		return banControlResult{}, err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(banControlPoll)
	defer tick.Stop()
	for {
		res, found, err := readBanControlResult(dir, id)
		if found {
			_ = os.Remove(filepath.Join(dir, id+".result"))
			return res, err
		}
		if err != nil {
			return banControlResult{}, err
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			// one last look: the answer may have landed between the last poll and the deadline
			if res, found, err := readBanControlResult(dir, id); found {
				_ = os.Remove(filepath.Join(dir, id+".result"))
				return res, err
			}
			_ = os.Remove(filepath.Join(dir, id+".req"))
			return banControlResult{}, errBanControlTimeout
		case <-ctx.Done():
			_ = os.Remove(filepath.Join(dir, id+".req"))
			return banControlResult{}, ctx.Err()
		}
	}
}

func writeBanControlJSON(w http.ResponseWriter, code int, status, message string) {
	body, _ := json.Marshal(struct {
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
	}{status, message})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// banControlHandler serves POST /api/ban/manual (action "ban") and POST /api/unban (action "unban"). Master only.
func (oAdmin *OvpnAdmin) banControlHandler(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info(r.RemoteAddr, " ", r.URL.Path)
		if !requireSameOriginPost(w, r) {
			return
		}
		if oAdmin.role == "slave" {
			http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
			return
		}
		_ = r.ParseForm()
		ip, err := validateBanIP(r.PostFormValue("ip"))
		if err != nil {
			writeBanControlJSON(w, http.StatusBadRequest, "error", err.Error())
			return
		}
		reason := ""
		if action == "ban" {
			reason = r.PostFormValue("reason")
			if err := validateBanReason(reason); err != nil {
				writeBanControlJSON(w, http.StatusBadRequest, "error", err.Error())
				return
			}
		}
		dir := banControlDir()
		if dir == "" {
			writeBanControlJSON(w, http.StatusInternalServerError, "error", "ban control is not available: no audit path is configured")
			return
		}
		res, err := submitBanControl(r.Context(), dir, action, ip, reason, banControlWait)
		switch {
		case errors.Is(err, errBanControlTimeout):
			log.Warnf("ban control: %s %s: no answer from the ban watcher", action, ip)
			writeBanControlJSON(w, http.StatusGatewayTimeout, "error", "The ban watcher did not answer in time. Check that the OpenVPN container is running.")
		case err != nil:
			log.Warnf("ban control: %s %s: %v", action, ip, err)
			writeBanControlJSON(w, http.StatusInternalServerError, "error", "Could not reach the ban watcher: "+banControlErrorKind(err))
		case !res.OK:
			msg := res.Message
			if msg == "" {
				msg = "The ban watcher rejected the request."
			}
			writeBanControlJSON(w, http.StatusBadRequest, "error", msg)
		default:
			log.Infof("ban control: %s %s ok", action, ip)
			writeBanControlJSON(w, http.StatusOK, "ok", res.Message)
		}
	}
}

// banControlErrorKind keeps host paths out of the response.
func banControlErrorKind(err error) string {
	switch {
	case errors.Is(err, errBanControlResult):
		return "unreadable answer"
	case errors.Is(err, os.ErrNotExist):
		return "control directory not found"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	case errors.Is(err, context.Canceled):
		return "request canceled"
	}
	return "write failed"
}

func (oAdmin *OvpnAdmin) banManualHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.banControlHandler("ban")(w, r)
}

func (oAdmin *OvpnAdmin) unbanHandler(w http.ResponseWriter, r *http.Request) {
	oAdmin.banControlHandler("unban")(w, r)
}
