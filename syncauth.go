package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

// The sync token travels in a header, not in the URL: a URL ends up in proxy and access logs, in the browser history
// and in "ps" of a slave that runs curl. Two header forms are accepted on the two download endpoints of the sync
// (/api/data/certs/download and /api/data/ccd/download):
//
//	Authorization: Bearer <token>   (cannot be used while the panel itself is behind HTTP Basic Auth, which owns Authorization)
//	X-OVPN-Token: <token>           (what a slave sends: it also sends Basic credentials when the master asks for them)
//
// The query form ?token=<token> still works for one release and logs a deprecation warning, at most once an hour.
// When a header and the query are both present the header wins: a wrong header is refused even if the query is right.
var masterAllowInsecureHTTP = kingpin.Flag("master.allow-insecure-http", "serve the sync archives (PKI with every client key, CCD) also over plain HTTP from a non-loopback address; by default the master answers 426 there. Set it only when a TLS proxy on another host terminates TLS in front of the master").Default("false").Envar("OVPN_MASTER_ALLOW_INSECURE_HTTP").Bool()

const (
	syncTokenHeader = "X-OVPN-Token"

	syncTokenSourceNone   = ""
	syncTokenSourceBearer = "Authorization: Bearer header"
	syncTokenSourceHeader = syncTokenHeader + " header"
	syncTokenSourceQuery  = "token query parameter"

	// syncQueryWarnEvery is the least time between two deprecation warnings about ?token=.
	syncQueryWarnEvery = time.Hour

	syncPlainHTTPRefusal = "plain HTTP is refused for the sync: use HTTPS (the token and the archives must not cross the network in clear), or set --master.allow-insecure-http / OVPN_MASTER_ALLOW_INSECURE_HTTP on the master"
)

// syncTokenFromRequest returns the token the caller sent and where it came from: Authorization: Bearer first,
// then X-OVPN-Token, then the query parameter "token". An Authorization header of another scheme (Basic) is not a
// token. The value is never logged.
func syncTokenFromRequest(r *http.Request) (token, source string) {
	if auth := r.Header.Get("Authorization"); len(auth) > len("Bearer ") && strings.EqualFold(auth[:len("Bearer ")], "Bearer ") {
		return strings.TrimSpace(auth[len("Bearer "):]), syncTokenSourceBearer
	}
	if vals := r.Header.Values(syncTokenHeader); len(vals) > 0 {
		return strings.TrimSpace(vals[0]), syncTokenSourceHeader
	}
	if vals, ok := r.URL.Query()["token"]; ok && len(vals) > 0 {
		return vals[0], syncTokenSourceQuery
	}
	return "", syncTokenSourceNone
}

// syncQueryWarner limits the deprecation warning about ?token= to one per interval for the whole process.
type syncQueryWarner struct {
	mu   sync.Mutex
	last time.Time
	now  func() time.Time
}

var syncQueryWarning = &syncQueryWarner{now: time.Now}

// warn logs the deprecation once per syncQueryWarnEvery and reports whether it did. peer is the address of the
// caller (never the URL: it carries the token).
func (w *syncQueryWarner) warn(peer string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	if !w.last.IsZero() && now.Sub(w.last) < syncQueryWarnEvery {
		return false
	}
	w.last = now
	log.Warnf("sync: the token was sent in the URL (?token=) by %s: this form is deprecated and will be removed in the next release; send it in an %s or Authorization: Bearer header (this warning is logged at most once an hour)", peer, syncTokenHeader)
	return true
}

// syncRequestToken reads the token of a sync download and, when it came in the URL, logs the deprecation (once an
// hour). It returns the token and its source.
func syncRequestToken(r *http.Request) (string, string) {
	token, source := syncTokenFromRequest(r)
	if source == syncTokenSourceQuery {
		syncQueryWarning.warn(peerHost(r))
	}
	return token, source
}

// peerHost is the host part of the address the connection came from. It is the TCP peer, never a header.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requestFromLoopback is true when the TCP peer is a loopback address (127.0.0.0/8, ::1, ::ffff:127.0.0.1). A peer
// that cannot be parsed is not loopback: the check fails closed. X-Forwarded-For is not looked at.
func requestFromLoopback(r *http.Request) bool {
	ip := net.ParseIP(peerHost(r))
	return ip != nil && ip.IsLoopback()
}

// syncPlainHTTPRefused is true when the sync must be refused because the request did not come over TLS (r.TLS is
// nil: a TLS proxy on another host looks like plain HTTP here) from a non-loopback peer and the operator did not
// allow it. A caller on the loopback address is always served: nothing crosses a network.
func syncPlainHTTPRefused(r *http.Request) bool {
	return r.TLS == nil && !requestFromLoopback(r) && !*masterAllowInsecureHTTP
}

// syncTokenMatches fails closed: without a configured token the sync is disabled and no request
// token is accepted, the empty one included. Both values are hashed first so the comparison takes the same time
// whatever the length of the given one.
func syncTokenMatches(configured, given string) bool {
	if strings.TrimSpace(configured) == "" {
		return false
	}
	c := sha256.Sum256([]byte(configured))
	g := sha256.Sum256([]byte(given))
	return subtle.ConstantTimeCompare(c[:], g[:]) == 1
}

// syncGate is the common start of both download handlers once the role and the storage backend are checked. It
// answers 426 for plain HTTP from a non-loopback peer and 403 for a wrong token, writes the audit line of a refusal and
// reports whether the request may go on. fileName is the archive the caller asked for.
func (oAdmin *OvpnAdmin) syncGate(w http.ResponseWriter, r *http.Request, fileName string) bool {
	if strings.TrimSpace(oAdmin.masterSyncToken) != "" && syncPlainHTTPRefused(r) {
		adminAudit.fromRequest(r, auditActSyncExport, fileName, false, "refused: plain HTTP from a non-loopback address")
		w.Header().Set("Upgrade", "TLS/1.2, HTTP/1.1")
		w.Header().Set("Connection", "Upgrade")
		http.Error(w, syncPlainHTTPRefusal, http.StatusUpgradeRequired)
		return false
	}
	token, source := syncRequestToken(r)
	if !syncTokenMatches(oAdmin.masterSyncToken, token) {
		detail := "sync token rejected"
		if source != syncTokenSourceNone {
			detail += " (" + source + ")"
		}
		adminAudit.fromRequest(r, auditActSyncExport, fileName, false, detail)
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return false
	}
	return true
}

// syncRequestHeader is what a slave sends to its master: the token in X-OVPN-Token (Authorization is taken by HTTP
// Basic Auth when the master asks for it). The token is never part of the URL.
func syncRequestHeader(token string) http.Header {
	h := http.Header{}
	h.Set(syncTokenHeader, token)
	return h
}

// warnSyncTransport writes the start-up warnings about the transport of the sync: a master that allows plain HTTP, and a
// slave whose master URL is plain HTTP to a host that is not this machine (the master answers 426 there unless it
// was told to allow it).
func warnSyncTransport(role, token, masterURL string, allowInsecure bool) {
	if role != "slave" && strings.TrimSpace(token) != "" && allowInsecure {
		log.Warn("--master.allow-insecure-http is set: the sync archives (the PKI with every client key) are served over plain HTTP to non-loopback callers")
	}
	if role == "slave" {
		u, err := url.Parse(masterURL)
		if err != nil || u.Scheme != "http" {
			return
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() || strings.EqualFold(u.Hostname(), "localhost") {
			return
		}
		log.Warnf("--master.host is a plain HTTP URL to a non-loopback host: the master answers 426 to the sync unless it runs with --master.allow-insecure-http (OVPN_MASTER_ALLOW_INSECURE_HTTP); use an https:// URL")
	}
}
