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
	"strconv"
	"strings"
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
	banMinMinutes      = 1
	banMaxMinutes      = 525600 // one year
)

// banControlWait is how long a request waits for the watcher; a variable so that tests can shorten it.
var banControlWait = 6 * time.Second

var (
	errBanControlTimeout = errors.New("the ban watcher did not answer in time")
	errBanControlResult  = errors.New("the ban watcher result is unreadable")
)

// banControlRequest is the JSON of a queue request.
type banControlRequest struct {
	ID      string `json:"id"`
	Action  string `json:"action"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Force   bool   `json:"force,omitempty"`   // ban only: apply although the address is loopback, ignored, in the VPN network or private
	Minutes int    `json:"minutes,omitempty"` // ban only: 1..banMaxMinutes, 0 = permanent
}

// banControlResult is the JSON of a queue result.
type banControlResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// banControlDir is <state dir>/control (--state.dir), or <audit dir>/control without one, "" with neither.
func banControlDir() string {
	base := banStateBase()
	if base == "" {
		return ""
	}
	return filepath.Join(base, banControlDirName)
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
func validateBanIP(raw string) (string, error) { return validateBanTarget(raw, false) }

// validateBanTarget is validateBanIP with the override of the manual ban: with force a loopback address is accepted here (the ban
// tool refuses a private, ignore-listed or VPN network address itself and applies it with force too). An unspecified,
// multicast or link-local address is never accepted.
func validateBanTarget(raw string, force bool) (string, error) {
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
	case ip.IsLoopback() && !force:
		return "", errors.New("refused: the address is a loopback address (force=true overrides)")
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast():
		return "", errors.New("a multicast address cannot be banned")
	case ip.IsLinkLocalUnicast():
		return "", errors.New("a link-local address cannot be banned")
	}
	return ip.String(), nil
}

// validateUnbanTarget accepts an address or the network a ban list row shows ("2001:db8:1:2::/64") and returns its canonical text.
// An unban may name a loopback address: a forced ban can have put it on the list.
func validateUnbanTarget(raw string) (string, error) {
	if strings.Contains(raw, "/") {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return "", errors.New("ip is not a valid IPv4 or IPv6 address or network")
		}
		if ones, _ := network.Mask.Size(); ones == 0 {
			return "", errors.New("the whole address space cannot be unbanned by network")
		}
		return network.String(), nil
	}
	return validateBanTarget(raw, true)
}

// validateBanMinutes parses the optional duration of a manual ban: empty = permanent (0), else a whole number of minutes
// from 1 to banMaxMinutes (one year).
func validateBanMinutes(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < banMinMinutes || n > banMaxMinutes {
		return 0, fmt.Errorf("minutes must be a whole number from %d to %d", banMinMinutes, banMaxMinutes)
	}
	return n, nil
}

// parseBanForce reads the optional force flag of a manual ban: empty, "false" or "0" = off; "true" or "1" = on; anything else is refused.
func parseBanForce(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	}
	return false, errors.New("force must be true or false")
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
	return submitBanControlRequest(ctx, dir, banControlRequest{Action: action, IP: ip, Reason: reason}, timeout)
}

// submitBanControlRequest is submitBanControl for a request that carries options (force, minutes); the id is set here.
func submitBanControlRequest(ctx context.Context, dir string, req banControlRequest, timeout time.Duration) (banControlResult, error) {
	id, err := newBanControlID()
	if err != nil {
		return banControlResult{}, err
	}
	req.ID = id
	if err := writeBanControlRequest(dir, req); err != nil {
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
		auditAction := auditActBanManual
		if action == "unban" {
			auditAction = auditActUnban
		}
		// the answer of the ban watcher is its own text; the trail keeps a fixed sentence per outcome
		record := func(ip string, ok bool, detail string) {
			adminAudit.fromRequest(r, auditAction, ip, ok, detail)
		}
		force := false
		minutes := 0
		if action == "ban" {
			var ferr, merr error
			force, ferr = parseBanForce(r.PostFormValue("force"))
			minutes, merr = validateBanMinutes(r.PostFormValue("minutes"))
			if err := errors.Join(ferr, merr); err != nil {
				record(r.PostFormValue("ip"), false, "the request was refused: "+err.Error())
				writeBanControlJSON(w, http.StatusBadRequest, "error", err.Error())
				return
			}
		}
		var ip string
		var err error
		if action == "unban" {
			ip, err = validateUnbanTarget(r.PostFormValue("ip"))
		} else {
			ip, err = validateBanTarget(r.PostFormValue("ip"), force)
		}
		if err != nil {
			record(r.PostFormValue("ip"), false, "the address was refused: "+err.Error())
			writeBanControlJSON(w, http.StatusBadRequest, "error", err.Error())
			return
		}
		reason := ""
		if action == "ban" {
			reason = r.PostFormValue("reason")
			if err := validateBanReason(reason); err != nil {
				record(ip, false, "the reason was refused: "+err.Error())
				writeBanControlJSON(w, http.StatusBadRequest, "error", err.Error())
				return
			}
		}
		dir := banControlDir()
		if dir == "" {
			record(ip, false, "ban control is not available")
			writeBanControlJSON(w, http.StatusInternalServerError, "error", "ban control is not available: no audit path is configured")
			return
		}
		res, err := submitBanControlRequest(r.Context(), dir, banControlRequest{Action: action, IP: ip, Reason: reason, Force: force, Minutes: minutes}, banControlWait)
		switch {
		case errors.Is(err, errBanControlTimeout):
			log.Warnf("ban control: %s %s: no answer from the ban watcher", action, ip)
			record(ip, false, "the ban watcher did not answer in time")
			writeBanControlJSON(w, http.StatusGatewayTimeout, "error", "The ban watcher did not answer in time. Check that the OpenVPN container is running.")
		case err != nil:
			log.Warnf("ban control: %s %s: %v", action, ip, err)
			record(ip, false, "the ban watcher could not be reached: "+banControlErrorKind(err))
			writeBanControlJSON(w, http.StatusInternalServerError, "error", "Could not reach the ban watcher: "+banControlErrorKind(err))
		case !res.OK:
			msg := res.Message
			if msg == "" {
				msg = "The ban watcher rejected the request."
			}
			record(ip, false, "the ban watcher rejected the request")
			writeBanControlJSON(w, http.StatusBadRequest, "error", msg)
		default:
			log.Infof("ban control: %s %s ok", action, ip)
			record(ip, true, "request carried out by the ban watcher")
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
