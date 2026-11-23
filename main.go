package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/alecthomas/kingpin/v2"
)

//go:embed frontend/static
var staticFiles embed.FS

//go:embed templates
var templateFiles embed.FS

const (
	usernameRegexp         = `^([a-zA-Z0-9_.\-@])+$`
	passwordMinLength      = 12
	passwordMaxBytes       = 72 // bcrypt hashes at most 72 bytes; golang.org/x/crypto >= 0.5 returns an error above that
	certsArchiveFileName   = "certs.tar.gz"
	ccdArchiveFileName     = "ccd.tar.gz"
	indexTxtDateLayout     = "060102150405Z"
	stringDateFormat       = "2006-01-02 15:04:05"
	downloadCertsApiUrl    = "api/data/certs/download"
	downloadCcdApiUrl      = "api/data/ccd/download"
	labelKeyIndexTxt       = "index.txt"
	labelKeyType           = "type"
	labelKeyName           = "name"
	labelKeyManagedBy      = "app.kubernetes.io/managed-by"
	labelValueClientAuth   = "clientAuth"
	labelValueManagedByApp = "ovpn-admin"

	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin; empty means all interfaces (IPv4 and IPv6), e.g. 0.0.0.0, ::, ::1").Default("").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	listenBaseUrl            = kingpin.Flag("listen.base-url", "base url for ovpn-admin").Default("/").Envar("OVPN_LISTEN_BASE_URL").String()
	serverRole               = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server, IPv6 hosts in brackets: http://[fd00::1]:8080").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	basicUsername            = kingpin.Flag("basic.username", "username for HTTP Basic Auth on the web UI, API and metrics (except /ping); requires --basic.password, both empty disables it").Default("").Envar("BASIC_USERNAME").String()
	basicPassword            = kingpin.Flag("basic.password", "password for HTTP Basic Auth on the web UI, API and metrics (except /ping); requires --basic.username, both empty disables it").Default("").Envar("BASIC_PASSWORD").String()
	masterBasicAuthUser      = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token; empty disables the sync (a slave requires it); the example and built-in default values are refused").Default("").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "IPv4 NETWORK/MASK_PREFIX (or NETWORK/NETMASK) for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnNetworkIPv6       = kingpin.Flag("ovpn.network.ipv6", "IPv6 NETWORK/PREFIX for OpenVPN server (server-ipv6), e.g. fd00:16:100::/64; empty disables IPv6").Default("").Envar("OVPN_NETWORK_IPV6").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server, IPv6 hosts in brackets: [2001:db8::1]:1194:udp; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB    = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName       = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface, IPv6 hosts in brackets: main=[::1]:8989; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file; empty means <easyrsa.path>/pki/index.txt").Default("").Envar("OVPN_INDEX_PATH").String()
	easyrsaBinPath           = kingpin.Flag("easyrsa.bin-path", "path to easyrsa script").Default("easyrsa").Envar("EASYRSA_BIN_PATH").String()
	ccdEnabled               = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	authDataBaseInit         = kingpin.Flag("auth.db-init", "enable database initialization if db user not exists or size is 0").Default("false").Envar("OVPN_AUTH_DB_INIT").Bool()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	auditPath                = kingpin.Flag("audit.path", "path to the OpenVPN connection audit log (tab-separated, written by the connection hooks); a missing file is an empty login history").Default("/var/log/openvpn-audit/audit.tsv").Envar("OVPN_AUDIT_PATH").String()
	clientCertExpirationDays = kingpin.Flag("client-cert.expiration-days", "Expiration period of OpenVPN client certificates in days, the period will shrink automatically to the CA expiration period").Default("3650").Envar("CLIENT_CERT_EXPIRATION_DAYS").String()

	// the CRL is valid for 180 days (easyrsa, kubernetes.go); OpenVPN refuses every client once its nextUpdate has passed
	crlRenewBefore = 30 * 24 * time.Hour
	// the check runs once a day; the first one waits crlFirstCheckDelay so that it does not race the start of the
	// openvpn container (a fresh PKI is still being built then, easyrsa allows one run at a time), and a failed
	// one is repeated after crlRetryInterval instead of a day later
	crlCheckInterval   = 24 * time.Hour
	crlFirstCheckDelay = 5 * time.Minute
	crlRetryInterval   = time.Hour

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	version = "0.1.11"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnCrlExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_crl_expire_days",
		Help: "days until the nextUpdate of the certificate revocation list (pki/crl.pem), negative when it has expired",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "total connected openvpn clients",
	},
	)

	ovpnUniqClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_uniq_clients_connected",
		Help: "uniq connected openvpn clients",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	clients                []OpenvpnClient
	activeClients          []clientStatus
	promRegistry           *prometheus.Registry
	mgmtInterfaces         map[string]string
	modules                []string
	createUserMutex        *sync.Mutex
}

type openvpnClientConfig struct {
	Hosts      []OpenvpnServer
	CA         string
	Cert       string
	Key        string
	TLS        string
	PasswdAuth bool
}

type OpenvpnClient struct {
	Identity         string `json:"Identity"`
	AccountStatus    string `json:"AccountStatus"`
	ExpirationDate   string `json:"ExpirationDate"`
	RevocationDate   string `json:"RevocationDate"`
	ConnectionStatus string `json:"ConnectionStatus"`
	Connections      int    `json:"Connections"`
	LastLogin        string `json:"LastLogin"`
	LastLoginIP      string `json:"LastLoginIP"`
}

type indexTxtLine struct {
	Flag              string
	ExpirationDate    string
	RevocationDate    string
	SerialNumber      string
	Filename          string
	DistinguishedName string
	Identity          string
}

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)

	if *storageBackend == "kubernetes.secrets" {
		err := app.updateIndexTxtOnDisk()
		if err != nil {
			log.Errorln(err)
		}
		oAdmin.clients = oAdmin.usersList()
	}

	usersList, _ := json.Marshal(withLastLogin(oAdmin.clients, defaultAuditLog.index()))
	fmt.Fprintf(w, "%s", usersList)
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	userCreated, userCreateStatus, status := oAdmin.userCreateStatus(r.FormValue("username"), r.FormValue("password"))
	adminAudit.fromRequest(r, auditActUserCreate, r.FormValue("username"), userCreated,
		auditDetail(userCreated, "client certificate issued", userCreateStatus), r.FormValue("password"))

	if userCreated {
		oAdmin.clients = oAdmin.usersList()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, userCreateStatus)
		return
	} else {
		http.Error(w, userCreateStatus, status)
	}
}
func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRotate(r.FormValue("username"), r.FormValue("password"))
	adminAudit.fromRequest(r, auditActUserRotate, r.FormValue("username"), err == nil,
		auditErrDetail(err, "certificate rotated"), r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), userOpErrorStatus(err))
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userDelete(r.FormValue("username"))
	adminAudit.fromRequest(r, auditActUserDelete, r.FormValue("username"), err == nil,
		auditErrDetail(err, "user deleted"))
	if err != nil {
		http.Error(w, err.Error(), userOpErrorStatus(err))
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRevoke(r.FormValue("username"))
	adminAudit.fromRequest(r, auditActUserRevoke, r.FormValue("username"), err == nil,
		auditErrDetail(err, "certificate revoked"))
	if err != nil {
		http.Error(w, err.Error(), userOpErrorStatus(err))
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userUnrevoke(r.FormValue("username"))
	adminAudit.fromRequest(r, auditActUserUnrevoke, r.FormValue("username"), err == nil,
		auditErrDetail(err, "certificate restored"))
	if err != nil {
		http.Error(w, err.Error(), userOpErrorStatus(err))
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	if *authByPassword {
		err, msg := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		adminAudit.fromRequest(r, auditActUserChangePassword, r.FormValue("username"), err == nil,
			auditErrDetail(err, "password changed"), r.FormValue("password"))
		status, code := "ok", http.StatusOK
		if err != nil {
			status, code = "error", http.StatusInternalServerError
			if isInputError(err) {
				code = http.StatusBadRequest
			}
		}
		body, _ := json.Marshal(map[string]string{"status": status, "message": msg})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	} else {
		adminAudit.fromRequest(r, auditActUserChangePassword, r.FormValue("username"), false,
			"password authentication is not enabled")
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	_ = r.ParseForm()
	found := usernameIsPathSafe(r.FormValue("username")) && checkUserExist(r.FormValue("username"))
	fmt.Fprint(w, oAdmin.renderClientConfig(r.FormValue("username")))
	adminAudit.fromRequest(r, auditActUserConfigDownload, r.FormValue("username"), found,
		auditDetail(found, "client configuration shown", "user not found"))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	_ = r.ParseForm()
	// the handler answers 200 but disconnects nobody (the call is commented out below): the trail says so
	adminAudit.fromRequest(r, auditActUserDisconnect, r.FormValue("username"), false,
		"not implemented: no session was disconnected")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	_ = r.ParseForm()
	userCcd, err := oAdmin.getCcd(r.FormValue("username"))
	if err != nil {
		status := http.StatusBadRequest
		var notFound userNotFoundError
		if errors.As(err, &notFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	ccd, _ := json.Marshal(userCcd)
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if !requireSameOriginPost(w, r) {
		return
	}
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var ccd Ccd
	if r.Body == nil {
		http.Error(w, "Please send a request body", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
		adminAudit.fromRequest(r, auditActUserCcdApply, "", false, "the request body was refused")
		http.Error(w, "invalid request body: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)
	adminAudit.fromRequest(r, auditActUserCcdApply, ccd.User, ccdApplied,
		auditDetail(ccdApplied, "client-config-dir entry written", applyStatus))

	if ccdApplied {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
	if enabledModulesErr != nil {
		log.Errorln(enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.URL.Path)
	fmt.Fprint(w, oAdmin.lastSyncTime)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.URL.Path)
	fmt.Fprint(w, oAdmin.lastSuccessfulSyncTime)
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if !syncTokenMatches(oAdmin.masterSyncToken, token) {
		adminAudit.fromRequest(r, auditActSyncExport, certsArchiveFileName, false, "sync token rejected")
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	// a private temp file per request, removed when the answer is written: it holds every client key
	// and users.db, so it must not sit in /tmp afterwards
	archive, err := archiveCerts()
	if err != nil {
		adminAudit.fromRequest(r, auditActSyncExport, certsArchiveFileName, false, "the archive could not be built")
		log.Errorf("downloadCertsHandler: no archive is served: %s", err)
		http.Error(w, `{"status":"error","msg":"the sync archive cannot be built: the identity of the CA signing key is not usable, see the admin log"}`, http.StatusInternalServerError)
		return
	}
	defer removeArchive(archive)
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, archive)
	adminAudit.fromRequest(r, auditActSyncExport, certsArchiveFileName, true, "PKI archive served to the caller")
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.URL.Path)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if !syncTokenMatches(oAdmin.masterSyncToken, token) {
		adminAudit.fromRequest(r, auditActSyncExport, ccdArchiveFileName, false, "sync token rejected")
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archive, err := archiveCcd()
	if err != nil {
		adminAudit.fromRequest(r, auditActSyncExport, ccdArchiveFileName, false, "the archive could not be built")
		log.Errorf("downloadCcdHandler: %s", err)
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}
	defer removeArchive(archive)
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, archive)
	adminAudit.fromRequest(r, auditActSyncExport, ccdArchiveFileName, true, "client-config-dir archive served to the caller")
}

var app OpenVPNPKI

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

	if err := validateBasicAuthConfig(*basicUsername, *basicPassword); err != nil {
		log.Fatal(err)
	}

	if err := validateSyncTokenConfig(*serverRole, *masterSyncToken); err != nil {
		log.Fatal(err)
	}

	if err := initNetworkConfig(); err != nil {
		log.Fatal(err)
	}

	// no trail, no panel: a record that cannot be written must not be dropped silently
	if err := initAdminAudit(); err != nil {
		log.Fatalf("admin audit trail: %v", err)
	}

	if *storageBackend == "kubernetes.secrets" {
		err := app.run()
		if err != nil {
			log.Error(err)
		}
		if app.KubeClient == nil {
			log.Fatal("--storage.backend=kubernetes.secrets: kubernetes client is not initialized")
		}
	}

	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}

	if *authByPassword || *authDataBaseInit {
		ovpnUserPrepareDb()
	}

	ovpnAdmin := new(OvpnAdmin)

	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}
	ovpnAdmin.createUserMutex = &sync.Mutex{}
	ovpnAdmin.mgmtInterfaces = make(map[string]string)

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	// a slave needs the PKI and CCD from the master before anything reads them
	// (management check, state, metrics); sync needs the master's basic-auth flag
	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	ovpnAdmin.mgmtCheckVersions()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()
	go ovpnAdmin.crlRefreshLoop(crlFirstCheckDelay, crlCheckInterval, crlRetryInterval, nil)

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		if *storageBackend != "kubernetes.secrets" {
			ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
		} else {
			log.Fatal("Right now the keys `--storage.backend=kubernetes.secret` and `--auth.password` are not working together. Please use only one of them ")
		}
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if ovpnNetworkV6.IsValid() {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ipv6")
	}

	staticFS, _ := fs.Sub(staticFiles, "frontend/static")
	static := CacheControlWrapper(http.FileServer(http.FS(staticFS)), staticFS)

	http.Handle(*listenBaseUrl, http.StripPrefix(strings.TrimRight(*listenBaseUrl, "/"), static))
	http.HandleFunc(*listenBaseUrl+"api/server/settings", ovpnAdmin.serverSettingsHandler)
	http.HandleFunc(*listenBaseUrl+"api/users/list", ovpnAdmin.userListHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/create", ovpnAdmin.userCreateHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/change-password", ovpnAdmin.userChangePasswordHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/rotate", ovpnAdmin.userRotateHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/delete", ovpnAdmin.userDeleteHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/revoke", ovpnAdmin.userRevokeHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/unrevoke", ovpnAdmin.userUnrevokeHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/config/show", ovpnAdmin.userShowConfigHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/disconnect", ovpnAdmin.userDisconnectHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/statistic", ovpnAdmin.userStatisticHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/audit", ovpnAdmin.userAuditHandler)
	http.HandleFunc(*listenBaseUrl+"api/bans", ovpnAdmin.bansHandler)
	http.HandleFunc(*listenBaseUrl+"api/ban/manual", ovpnAdmin.banManualHandler)
	http.HandleFunc(*listenBaseUrl+"api/unban", ovpnAdmin.unbanHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/ccd", ovpnAdmin.userShowCcdHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/ccd/apply", ovpnAdmin.userApplyCcdHandler)
	http.HandleFunc(*listenBaseUrl+"api/audit/admin", ovpnAdmin.adminAuditListHandler)
	http.HandleFunc(*listenBaseUrl+"api/audit/verify", ovpnAdmin.adminAuditVerifyHandler)

	http.HandleFunc(*listenBaseUrl+"api/sync/last/try", ovpnAdmin.lastSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl+"api/sync/last/successful", ovpnAdmin.lastSuccessfulSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl+downloadCertsApiUrl, ovpnAdmin.downloadCertsHandler)
	http.HandleFunc(*listenBaseUrl+downloadCcdApiUrl, ovpnAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc(*listenBaseUrl+"ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	})

	log.Printf("Bind: %s", bindURL(*listenHost, *listenPort, *listenBaseUrl))
	// /ping stays open for health checks; everything else, /metrics included, needs credentials
	handler := securityHeadersMiddleware(
		basicAuthMiddleware(http.DefaultServeMux, *basicUsername, *basicPassword, *listenBaseUrl+"ping"),
		*listenBaseUrl+"api/")
	if *basicUsername != "" {
		log.Info("HTTP Basic Auth is enabled")
	}
	log.Fatal(http.ListenAndServe(listenAddress(*listenHost, *listenPort), handler))
}

// Public values that must never protect the sync: the token of the example compose files and the
// former built-in default of --master.sync-token.
const (
	syncTokenExample         = "TOKEN"
	syncTokenBuiltinFallback = "VerySecureToken"
)

// validateSyncTokenConfig refuses a sync token everybody knows. The sync is enabled when the
// token is set (the master then serves the PKI and CCD archives) and always on a slave (it
// downloads them). The error names the rejected value, never the token. A master without a token
// has the sync disabled: no token, no sync, no error.
func validateSyncTokenConfig(role, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		if role == "slave" {
			return errors.New("--master.sync-token is empty: a slave needs the sync token of its master")
		}
		return nil
	}
	switch {
	case strings.EqualFold(token, syncTokenExample):
		return errors.New("--master.sync-token rejected: it is the example value from the documentation, set a strong secret")
	case strings.EqualFold(token, syncTokenBuiltinFallback):
		return errors.New("--master.sync-token rejected: it is the built-in default value, set a strong secret")
	}
	return nil
}

// syncTokenMatches fails closed: without a configured token the sync is disabled and no request
// token is accepted, the empty one included.
func syncTokenMatches(configured, given string) bool {
	if strings.TrimSpace(configured) == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(configured), []byte(given)) == 1
}

// requireSameOriginPost is the first check of every handler that changes state. Other methods
// than POST get 405. When the browser names where the request comes from (Origin, Referer) its
// host must be the Host of the request, otherwise 403 and nothing is done. Requests with neither
// header (curl, CLI clients) pass; a present but empty or unparsable header does not.
func requireSameOriginPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed, use POST", http.StatusMethodNotAllowed)
		return false
	}
	for _, name := range []string{"Origin", "Referer"} {
		for _, v := range r.Header.Values(name) {
			u, err := url.Parse(strings.TrimSpace(v))
			if err != nil || u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
				http.Error(w, "cross-site request refused", http.StatusForbidden)
				return false
			}
		}
	}
	return true
}

// validateBasicAuthConfig fails closed: setting only one of the two credentials
// would otherwise leave the server silently unprotected or unusable.
func validateBasicAuthConfig(username, password string) error {
	if (username == "") != (password == "") {
		return errors.New("--basic.username and --basic.password must be set together (or both left empty to disable HTTP Basic Auth)")
	}
	return nil
}

// basicAuthMiddleware requires HTTP Basic credentials on every request except
// those whose URL path is exactly one of openPaths. Username and password are
// both always compared, in constant time. With both credentials empty the
// authentication is disabled and next is returned unchanged.
func basicAuthMiddleware(next http.Handler, username, password string, openPaths ...string) http.Handler {
	if username == "" && password == "" {
		return next
	}

	// hashing first gives ConstantTimeCompare equal-length inputs, so the
	// length of the configured secrets does not leak through timing
	wantUser := sha256.Sum256([]byte(username))
	wantPass := sha256.Sum256([]byte(password))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(openPaths, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		gotUser, gotPass, ok := r.BasicAuth()
		userHash := sha256.Sum256([]byte(gotUser))
		passHash := sha256.Sum256([]byte(gotPass))
		userOK := subtle.ConstantTimeCompare(userHash[:], wantUser[:])
		passOK := subtle.ConstantTimeCompare(passHash[:], wantPass[:])

		if !ok || userOK&passOK != 1 {
			// Only attempts with credentials are logged: the plain browser challenge is not an
			// attack. Neither the credentials nor X-Forwarded-For are written. Behind a reverse
			// proxy remote is the proxy address, so the line serves detection, not banning.
			if r.Header.Get("Authorization") != "" {
				log.Warnf("auth failed remote=%s path=%s", r.RemoteAddr, r.URL.Path)
				adminAudit.loginFail(r, gotUser)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="ovpn-admin", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		adminAudit.loginOK(r, gotUser)
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds the hardening headers to every answer, the 401 of the auth
// middleware included, so it has to be the outermost handler. Answers under apiPrefix also
// get Cache-Control: no-store (the static UI keeps its own no-cache + ETag, set by
// CacheControlWrapper). HSTS is left to the TLS-terminating proxy.
func securityHeadersMiddleware(next http.Handler, apiPrefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// CacheControlWrapper makes browsers revalidate the embedded web UI on every load:
// index.html holds the Vue template and must match dist/*.min.js, whose names are fixed,
// so a long max-age could combine a new index.html with an old bundle after an upgrade
// (or vice versa). The ETag (content hash) keeps revalidation cheap (304 Not Modified).
func CacheControlWrapper(h http.Handler, files fs.FS) http.Handler {
	etags := staticETags(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		if etag, ok := etags[staticFilePath(r.URL.Path)]; ok {
			w.Header().Set("ETag", etag)
		}
		h.ServeHTTP(w, r)
	})
}

// staticETags returns strong ETags (content hashes) of all files in files.
func staticETags(files fs.FS) map[string]string {
	etags := map[string]string{}
	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(files, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		etags[p] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	if err != nil {
		log.Warnf("computing ETags of static files: %v", err)
	}
	return etags
}

// staticFilePath maps a request path to the file http.FileServer serves for it ("/" -> "index.html").
func staticFilePath(urlPath string) string {
	p := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	if p == "" || strings.HasSuffix(urlPath, "/") {
		p = path.Join(p, "index.html")
	}
	return p
}

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnCrlExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnUniqClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
	setCrlExpireGauge(time.Now())
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		ovpnClientCertificateExpire.Reset()
		go oAdmin.setState()
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	var indexTxt []indexTxtLine

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case (strings.HasPrefix(str[0], "E") || strings.HasPrefix(str[0], "V")) && len(str) >= 5:
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], SerialNumber: str[2], Filename: str[3], DistinguishedName: str[4], Identity: str[4][strings.Index(str[4], "=")+1:]})
			case strings.HasPrefix(str[0], "R") && len(str) >= 6:
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], RevocationDate: str[2], SerialNumber: str[3], Filename: str[4], DistinguishedName: str[5], Identity: str[5][strings.Index(str[5], "=")+1:]})
			}
		}
	}

	return indexTxt
}

func renderIndexTxt(data []indexTxtLine) string {
	indexTxt := ""
	for _, line := range data {
		switch {
		case line.Flag == "V", line.Flag == "E":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		case line.Flag == "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		}
	}
	return indexTxt
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTplBytes, clientConfigTplErr := templateFiles.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Errorf("clientConfigTpl not found in embedded templates: %v", clientConfigTplErr)
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTplBytes)))
	}
}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	if usernameIsPathSafe(username) && checkUserExist(username) {
		hosts := slices.Clone(ovpnServers)

		if len(hosts) == 0 && *openvpnServerBehindLB {
			var err error
			hosts, err = getOvpnServerHostsFromKubeApi()
			if err != nil {
				log.Error(err)
			}
		}

		log.Tracef("hosts for %s\n %v", username, hosts)

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

		if *storageBackend == "kubernetes.secrets" {
			conf.Cert, conf.Key = app.easyrsaGetClientCert(username)
		} else {
			conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
			conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
		}

		conf.PasswdAuth = *authByPassword

		t := oAdmin.getClientConfigTemplate()

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Errorf("something goes wrong during rendering config for %s", username)
			log.Debugf("rendering config for %s failed with error %v", username, err)
		}

		log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

		return fmt.Sprintf("%+v", tmp.String())
	}
	log.Warnf("user \"%s\" not found", username)
	return fmt.Sprintf("user \"%s\" not found", username)
}

func validateUsername(username string) error {
	var validUsername = regexp.MustCompile(usernameRegexp)
	if validUsername.MatchString(username) && usernameIsPathSafe(username) {
		return nil
	} else {
		return inputError{fmt.Sprintf("Username can only contains %s and must not be \".\" or \"..\"", usernameRegexp)}
	}
}

// inputError is a value of the request that is refused (user name, password): the handlers answer
// it with HTTP 400 and its message.
type inputError struct{ msg string }

func (e inputError) Error() string { return e.msg }

func isInputError(err error) bool {
	var ie inputError
	return errors.As(err, &ie)
}

// userOpErrorStatus is the HTTP status of a failed revoke, rotate or delete: 400 for a refused
// request (unknown user, bad password), 500 for a failure on the server side (easyrsa, the CRL, the
// management interface, the password database). The body stays the plain text of the error.
func userOpErrorStatus(err error) int {
	if isInputError(err) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// usernameIsPathSafe reports whether username can be used as a file name
// (no path separators, not "." or "..").
func usernameIsPathSafe(username string) bool {
	return username != "" && username != "." && username != ".." &&
		!strings.ContainsAny(username, "/\\\x00")
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < passwordMinLength {
		return inputError{fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength)}
	}
	// openvpn-user ignores the error of bcrypt.GenerateFromPassword, so a longer password would be
	// reported as saved while no hash is stored. The limit is in bytes, not characters.
	if len(password) > passwordMaxBytes {
		return inputError{fmt.Sprintf("Password too long, the hash accepts at most %d bytes", passwordMaxBytes)}
	}
	return nil
}

// checkUserExist reports whether username is a user: a certificate with CN=username in index.txt
// that is not an OpenVPN server certificate (those are neither listed nor managed).
func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN="+username) && !isServerCertificate(u) {
			return true
		}
	}
	return false
}

// checkCommonNameExist reports whether index.txt has any certificate with CN=commonName,
// users and server certificates alike: a new user must not reuse it.
func checkCommonNameExist(commonName string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + commonName) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if isServerCertificate(line) {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
			continue
		}
		if !strings.Contains(line.Identity, "REVOKED") {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch {
			case line.Flag == "V":
				ovpnClient.AccountStatus = "Active"
				validCerts += 1
			case line.Flag == "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				revokedCerts += 1
			case line.Flag == "E":
				ovpnClient.AccountStatus = "Expired"
				expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))

			if (parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) < 0 {
				if ovpnClient.AccountStatus != "Revoked" {
					ovpnClient.AccountStatus = "Expired"
				}
			}
			ovpnClient.Connections = 0

			userConnected, userConnectedTo := isUserConnected(line.Identity, oAdmin.activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				for range userConnectedTo {
					ovpnClient.Connections += 1
					totalActiveConnections += 1
				}
				connectedUniqUsers += 1
			}

			users = append(users, ovpnClient)
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (bool, string) {
	created, msg, _ := oAdmin.userCreateStatus(username, password)
	return created, msg
}

// userCreateStatus is userCreate with the HTTP status of the answer: 400 for a refused value (user
// name, password, a name that is taken), 422 when the user could not be created for another reason.
func (oAdmin *OvpnAdmin) userCreateStatus(username, password string) (bool, string, int) {
	ucErr := fmt.Sprintf("User \"%s\" created", username)

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if checkCommonNameExist(username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists\n", username)
		log.Debugf("userCreate: checkCommonNameExist():  %s", ucErr)
		return false, ucErr, http.StatusBadRequest
	}

	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return false, err.Error(), http.StatusBadRequest
	}

	if *authByPassword {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return false, err.Error(), http.StatusBadRequest
		}
	}

	// the password is stored before the certificate is issued: if it cannot be stored,
	// no certificate is left behind; if the certificate cannot be issued, the password is removed again
	if *authByPassword {
		// openvpn-user exits with 0 even when the INSERT fails (e.g. a database that was not migrated),
		// so the row is checked afterwards
		if _, err := runOpenvpnUser("create", "--user="+username, "--password="+password); err != nil || !ovpnUserExistsInDb(username) {
			log.Errorf("userCreate: saving the password of user %s failed: %v", username, err)
			return false, fmt.Sprintf("Failed to save the password of user \"%s\"", username), http.StatusUnprocessableEntity
		}
	}
	rollbackPassword := func() {
		if *authByPassword {
			if _, err := runOpenvpnUser("delete", "--force", "--user="+username); err != nil {
				log.Errorf("userCreate: removing the password of user %s: %v", username, err)
			}
		}
	}

	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaBuildClient(username)
		if err != nil {
			log.Error(err)
			rollbackPassword()
			return false, err.Error(), http.StatusUnprocessableEntity
		}
	} else {
		if _, err := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "--batch", "build-client-full", username, "nopass"); err != nil {
			log.Errorf("userCreate: %v", err)
			rollbackPassword()
			return false, fmt.Sprintf("Failed to issue certificate for user \"%s\"", username), http.StatusUnprocessableEntity
		}
	}

	log.Infof("Certificate for user %s issued", username)

	//oAdmin.clients = oAdmin.usersList()

	return true, ucErr, http.StatusOK
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (error, string) {

	if checkUserExist(username) {
		// a revoked user cannot connect: a new password would only look like a repair. Refused before the
		// password is looked at and before anything is written.
		if userCertRevoked(username) {
			msg := fmt.Sprintf("user %q is revoked, unrevoke or rotate it first", username)
			log.Warnf("userChangePassword: %s", msg)
			return inputError{msg}, msg
		}
		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err, err.Error()
		}

		// "change-password" of openvpn-user reports success also for a user without a row in the database
		if !ovpnUserExistsInDb(username) {
			if _, err := runOpenvpnUser("create", "--user="+username, "--password="+password); err != nil || !ovpnUserExistsInDb(username) {
				log.Errorf("userChangePassword: saving the password of user %s failed: %v", username, err)
				return fmt.Errorf("saving the password of user %q failed", username), "Failed to change password"
			}
		}

		if _, err := runOpenvpnUser("change-password", "--user="+username, "--password="+password); err != nil {
			log.Errorf("userChangePassword: %v", err)
			return err, "Failed to change password"
		}

		log.Infof("Password for user %s was changed", username)

		return nil, "Password changed"
	}

	// a user that does not exist is a refused request (HTTP 400), like a bad password
	return inputError{fmt.Sprintf("user %q not found", username)}, fmt.Sprintf("User \"%s\" not found", username)
}

// runOpenvpnUser runs an openvpn-user command against --auth.db. Values are passed as
// --flag=value: kingpin (used by openvpn-user) does not accept a separate value that
// starts with "-", e.g. the password "-Secret1".
func runOpenvpnUser(command string, args ...string) (string, error) {
	return runCommand("", "", "openvpn-user", append([]string{command, "--db.path=" + *authDatabase}, args...)...)
}

// ovpnUserExistsInDb reports whether the openvpn-user database has a row for username, including
// revoked and deleted ones ("create" refuses those as well). "openvpn-user check" prints nothing
// since 1.0.5, so the table printed by "list --all" is parsed instead.
func ovpnUserExistsInDb(username string) bool {
	out, err := runOpenvpnUser("list", "--all")
	if err != nil {
		log.Errorf("ovpnUserExistsInDb: %v", err)
	}
	return ovpnUserListHasUser(out, username)
}

// ovpnUserListHasUser looks for username in the output of "openvpn-user list --all":
//
//	id | username | revoked | deleted | app_configured
//	1  | alice    | false   | false   | false
func ovpnUserListHasUser(out, username string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64); err != nil {
			continue // header or an error message
		}
		if strings.TrimSpace(fields[1]) == username {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.activeClients {
		if u.CommonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
}

// userRevoke revokes the certificate (and the password row) of username, rebuilds the CRL, confirms that
// the CRL lists the certificate and ends every session of the user on every management interface.
// It reports success only when all of that is done: a step that fails does not stop the others (the
// sessions are killed even when the certificate could not be revoked or the CRL failed), and the error
// names every step that failed and says whether the sessions were ended. A user that is revoked already
// goes through the steps after the revoke again, so a revoke that ended in an error can be repeated.
// It holds createUserMutex, the lock of every write to the PKI.
func (oAdmin *OvpnAdmin) userRevoke(username string) (error, string) {
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()
	return oAdmin.userRevokeLocked(username)
}

// userRevokeLocked is userRevoke for a caller that holds createUserMutex already (rotate, delete).
func (oAdmin *OvpnAdmin) userRevokeLocked(username string) (error, string) {
	log.Infof("Revoke certificate for user %s", username)
	if !(usernameIsPathSafe(username) && checkUserExist(username)) {
		log.Infof("user \"%s\" not found", username)
		msg := fmt.Sprintf("User \"%s\" not found", username)
		return inputError{msg}, msg
	}

	var problems []string
	problem := func(what string, err error) {
		log.Errorf("userRevoke: %s: %v", what, err)
		problems = append(problems, what)
	}

	if *storageBackend == "kubernetes.secrets" {
		// easyrsaRevoke rebuilds and publishes the CRL itself (also for a certificate that is revoked
		// already: the annotation of an earlier call says nothing about the CRL) and returns the error of
		// every step
		if err := app.easyrsaRevoke(username); err != nil {
			problem("the certificate could not be revoked in kubernetes", err)
		} else if err := confirmRevokedInKubernetes(username); err != nil {
			problem("the new CRL does not list the revoked certificate", err)
		}
	} else if alreadyRevoked, err := userCertRevokedErr(username); err != nil {
		problem("index.txt could not be read", err)
	} else {
		revokeFailed := false
		if !alreadyRevoked {
			if _, err := runCommand(*easyrsaDirPath, "yes\n", *easyrsaBinPath, "revoke", username); err != nil {
				problem("the certificate could not be revoked", err)
				// easyrsa can fail after it has written index.txt: then the CRL still has to be built
				revokeFailed = !userCertRevoked(username)
			}
		}
		if !revokeFailed {
			// the revoke is only worth something once the CRL that OpenVPN reads lists the certificate
			if err := easyrsaGenCrl(); err != nil {
				problem("the CRL could not be rebuilt", err)
			} else if err := confirmRevokedInCrl(username); err != nil {
				problem("the new CRL does not list the revoked certificate", err)
			}
		}
	}

	if *authByPassword {
		out, err := runOpenvpnUser("list", "--all")
		if err != nil {
			problem("the password database could not be read", err)
		} else if row := ovpnUserListRow(out, username); row.exists && !row.revoked {
			if _, err := runOpenvpnUser("revoke", "--user="+username); err != nil {
				problem("the password of the user could not be revoked", err)
			}
		}
	}

	// OpenVPN reads the CRL as an unprivileged user: a CRL it cannot read is a failed revoke
	if err := crlFix(); err != nil {
		problem("the CRL could not be made readable for OpenVPN", err)
	}

	// whatever the panel knows about the active clients: the list is up to 28 s old and a session
	// it has not seen yet must not survive the revoke. It is tried in every case, also when a step above
	// failed
	killed := true
	if err := oAdmin.mgmtKillUser(username); err != nil {
		problem("the session of the user could not be killed", err)
		killed = false
	}

	oAdmin.setState()

	if len(problems) > 0 {
		msg := fmt.Sprintf("Revoke of user \"%s\" is incomplete, do not rely on it: %s.", username, strings.Join(problems, "; "))
		if killed {
			msg += " The sessions of the user were ended."
		}
		msg += " Check the admin log, the revoke can be repeated"
		return errors.New(msg), msg
	}
	return nil, fmt.Sprintf("user \"%s\" revoked", username)
}

// userUnrevoke makes a revoked certificate valid again. It answers success only for what it can back:
// the certificate files are back, index.txt says valid, the CRL that OpenVPN reads no longer lists the
// serial (read from the file, on this call and on every retry: a flag that was written by an earlier call
// proves nothing about the CRL) and the password row is restored. Every step that fails is returned.
func (oAdmin *OvpnAdmin) userUnrevoke(username string) (error, string) {
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if !(usernameIsPathSafe(username) && checkUserExist(username)) {
		return inputError{fmt.Sprintf("user \"%s\" not found", username)}, fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}

	var problems []string
	problem := func(what string, err error) {
		log.Errorf("userUnrevoke: %s: %v", what, err)
		problems = append(problems, what)
	}

	if *storageBackend == "kubernetes.secrets" {
		if err := app.easyrsaUnrevoke(username); err != nil {
			problem("the certificate could not be unrevoked in kubernetes", err)
		}
	} else if usersFromIndexTxt, err := readIndexTxt(); err != nil {
		problem("index.txt could not be read", err)
	} else {
		filesBack, wasRevoked := true, false
		for i := range usersFromIndexTxt {
			if usersFromIndexTxt[i].DistinguishedName == "/CN="+username && usersFromIndexTxt[i].Flag == "R" {
				wasRevoked = true
				// every file is tried, every failure is named: index.txt only says valid once all of them are back
				restoreRevokedFiles(username, usersFromIndexTxt[i].SerialNumber, func(what string, err error) {
					filesBack = false
					problem(what, err)
				})
				if filesBack {
					usersFromIndexTxt[i].Flag = "V"
					usersFromIndexTxt[i].RevocationDate = ""
					if err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
						problem("index.txt could not be written", err)
						filesBack = false
					}
				}
				break
			}
		}
		if filesBack {
			// the CRL is rebuilt when index.txt changed now, and when the CRL on disk still lists the
			// certificate (or cannot be read) although index.txt does not say revoked: an earlier call may have
			// stopped after it wrote the flag
			rebuild := wasRevoked
			if !rebuild {
				if err := confirmNotRevokedInCrl(username); err != nil {
					log.Warnf("userUnrevoke: %v: the CRL is rebuilt", err)
					rebuild = true
				}
			}
			if rebuild {
				if err := easyrsaGenCrl(); err != nil {
					problem("the CRL could not be rebuilt", err)
				}
			}
			// success is the state of the CRL on disk, not the exit code of the rebuild
			if err := confirmNotRevokedInCrl(username); err != nil {
				problem("the CRL on disk still lists the certificate", err)
			}

			if *authByPassword {
				out, err := runOpenvpnUser("list", "--all")
				if err != nil {
					problem("the password database could not be read", err)
				} else if row := ovpnUserListRow(out, username); row.exists && row.revoked {
					if _, err := runOpenvpnUser("restore", "--user="+username); err != nil {
						problem("the password of the user could not be restored", err)
					}
				}
			}
		}
	}

	if err := crlFix(); err != nil {
		problem("the CRL could not be made readable for OpenVPN", err)
	}
	oAdmin.clients = oAdmin.usersList()
	if len(problems) > 0 {
		msg := fmt.Sprintf("Unrevoke of user \"%s\" is incomplete: %s. Check the admin log", username, strings.Join(problems, "; "))
		return errors.New(msg), msg
	}
	return nil, fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
}

// restoreRevokedFiles puts back what easy-rsa moved to pki/revoked/ when it revoked the certificate. A
// file that is not in revoked/ but in its place is fine (easy-rsa 3.2 leaves the key and the request where
// they are, and an earlier try may have moved it); a file that is in neither place is a failure. Every
// failure goes to fail, the steps do not stop at the first.
func restoreRevokedFiles(username, serial string, fail func(what string, err error)) {
	move := func(what, from, to string) {
		switch {
		case fExist(from):
			if err := fMove(from, to); err != nil {
				fail(what, err)
			}
		case fRegularFile(to):
		case fExist(to):
			// a directory (or another special file) in the place of the file is not a restored file
			fail(what, fmt.Errorf("%s exists but is not a regular file", to))
		default:
			fail(what, fmt.Errorf("neither %s nor %s exists", from, to))
		}
	}
	revokedCert := pkiFile("revoked", "certs_by_serial", serial+".crt")
	issued := pkiFile("issued", username+".crt")
	copySource := revokedCert
	if !fExist(copySource) {
		copySource = issued
	}
	if fExist(copySource) {
		if err := fCopy(copySource, pkiFile("certs_by_serial", serial+".pem")); err != nil {
			fail("the copy of the certificate in certs_by_serial could not be restored", err)
		}
	}
	move("the certificate could not be restored", revokedCert, issued)
	move("the private key could not be restored", pkiFile("revoked", "private_by_serial", serial+".key"), pkiFile("private", username+".key"))
	move("the request could not be restored", pkiFile("revoked", "reqs_by_serial", serial+".req"), pkiFile("reqs", username+".req"))
}

// fRegularFile reports whether path is an existing regular file (a symlink counts as what it points to).
func fRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// readIndexTxt reads and parses index.txt. An index that cannot be read is an error, never an empty
// index: whoever rewrites index.txt from an "empty" read would erase every certificate.
func readIndexTxt() ([]indexTxtLine, error) {
	raw, err := os.ReadFile(*indexTxtPath)
	if err != nil {
		return nil, fmt.Errorf("reading index.txt: %w", err)
	}
	return indexTxtParser(string(raw)), nil
}

// userCertRevokedErr reports whether the certificate of username is revoked (index.txt flag R); an
// index that cannot be read is an error.
func userCertRevokedErr(username string) (bool, error) {
	lines, err := readIndexTxt()
	if err != nil {
		return false, err
	}
	for _, line := range lines {
		if line.DistinguishedName == "/CN="+username {
			return line.Flag == "R", nil
		}
	}
	return false, nil
}

// userCertRevoked is userCertRevokedErr for callers that treat an unreadable index as "not revoked".
func userCertRevoked(username string) bool {
	revoked, _ := userCertRevokedErr(username)
	return revoked
}

// revokeBeforeReplace revokes the certificate of username and ends its sessions. Rotate and delete
// replace or hide a certificate: an active one must not stay valid (it could still connect), and
// easyrsa revoke moves its files out of issued/, private/ and reqs/ (an expired one kept them, so no
// new certificate with the same name could be issued). A certificate that is revoked already goes
// through userRevoke as well, which then only rebuilds and checks the CRL and kills the sessions: they
// are cut on every rotate and delete, also on the repeat of one that failed before.
// The caller holds createUserMutex.
func (oAdmin *OvpnAdmin) revokeBeforeReplace(username string) error {
	err, _ := oAdmin.userRevokeLocked(username)
	return err
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (error, string) {
	if !(usernameIsPathSafe(username) && checkUserExist(username)) {
		return inputError{fmt.Sprintf("user %q not found", username)}, fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
	}
	// checked before anything is changed: a refused password must not cost the user its certificate
	if *authByPassword {
		if err := validatePassword(newPassword); err != nil {
			log.Warningf("userRotate: %s", err.Error())
			return err, err.Error()
		}
	}

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if *storageBackend == "kubernetes.secrets" {
		if err := oAdmin.revokeBeforeReplace(username); err != nil {
			return err, err.Error()
		}
		if err := app.easyrsaRotate(username, newPassword); err != nil {
			log.Errorf("userRotate: %v", err)
			msg := fmt.Sprintf("Failed to rotate user \"%s\", check the admin log", username)
			oAdmin.clients = oAdmin.usersList()
			return errors.New(msg), msg
		}
	} else if err, msg := oAdmin.rotateFilesystem(username, newPassword); err != nil {
		return err, msg
	}

	oAdmin.clients = oAdmin.usersList()
	if err := crlFix(); err != nil {
		msg := fmt.Sprintf("User \"%s\" was rotated but the CRL could not be made readable for OpenVPN: %v. Check the admin log", username, err)
		return errors.New(msg), msg
	}
	return nil, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
}

// rotation holds what userRotate needs to put a user back as it was. The filesystem backend replaces a
// certificate in several steps (revoke, move the old request and key away, issue, replace the password)
// and a failing step must never leave the user revoked, without a password or without files.
type rotation struct {
	username   string
	serial     string // serial of the certificate that is replaced
	index      []byte // index.txt before the first change
	wasRevoked bool   // the certificate was revoked before the rotation
	row        ovpnUserRow
	files      []rotationFile
	inline     map[string][]byte // inline files, easyrsa revoke deletes them
}

// rotationFile is a file of the user that easy-rsa refuses to overwrite (live) and the place where
// easy-rsa keeps it once its certificate is revoked (archive).
type rotationFile struct {
	live, archive             string
	liveBefore, archiveBefore bool
}

// ovpnUserRow is the state of a user in the openvpn-user database.
type ovpnUserRow struct{ exists, revoked bool }

func pkiFile(parts ...string) string {
	return path.Join(append([]string{*easyrsaDirPath, "pki"}, parts...)...)
}

func newRotation(username string) (*rotation, error) {
	raw, err := os.ReadFile(*indexTxtPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read index.txt: %w", err)
	}
	r := &rotation{username: username, index: raw, inline: map[string][]byte{}}
	found := false
	for _, line := range indexTxtParser(string(raw)) {
		if line.DistinguishedName == "/CN="+username {
			r.serial, r.wasRevoked, found = line.SerialNumber, line.Flag == "R", true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("user %q not found", username)
	}
	r.files = []rotationFile{
		{live: pkiFile("issued", username+".crt"), archive: pkiFile("revoked", "certs_by_serial", r.serial+".crt")},
		{live: pkiFile("private", username+".key"), archive: pkiFile("revoked", "private_by_serial", r.serial+".key")},
		{live: pkiFile("reqs", username+".req"), archive: pkiFile("revoked", "reqs_by_serial", r.serial+".req")},
	}
	for i := range r.files {
		r.files[i].liveBefore = fExist(r.files[i].live)
		r.files[i].archiveBefore = fExist(r.files[i].archive)
	}
	for _, p := range []string{pkiFile("inline", username+".inline"), pkiFile("inline", "private", username+".inline")} {
		if data, err := os.ReadFile(p); err == nil {
			r.inline[p] = data
		}
	}
	if *authByPassword {
		out, err := runOpenvpnUser("list", "--all")
		if err != nil {
			return nil, fmt.Errorf("cannot read the password database: %w", err)
		}
		r.row = ovpnUserListRow(out, username)
	}
	return r, nil
}

// ovpnUserListRow finds username in the output of "openvpn-user list --all" (see ovpnUserListHasUser).
func ovpnUserListRow(out, username string) ovpnUserRow {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 3 {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64); err != nil {
			continue
		}
		if strings.TrimSpace(fields[1]) == username {
			return ovpnUserRow{exists: true, revoked: strings.TrimSpace(fields[2]) == "true"}
		}
	}
	return ovpnUserRow{}
}

func pemBlocks(data []byte) []*pem.Block {
	var blocks []*pem.Block
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return blocks
		}
		blocks = append(blocks, b)
	}
}

func serialMatches(serial *big.Int, hexSerial string) bool {
	want, ok := new(big.Int).SetString(hexSerial, 16)
	return ok && serial.Cmp(want) == 0
}

// oldCertificate reads the certificate that is replaced, wherever easy-rsa has it by now.
func (r *rotation) oldCertificate() *x509.Certificate {
	for _, p := range []string{
		pkiFile("issued", r.username+".crt"),
		pkiFile("revoked", "certs_by_serial", r.serial+".crt"),
		pkiFile("certs_by_serial", r.serial+".pem"),
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, b := range pemBlocks(data) {
			if b.Type != "CERTIFICATE" {
				continue
			}
			if c, err := x509.ParseCertificate(b.Bytes); err == nil && serialMatches(c.SerialNumber, r.serial) {
				return c
			}
		}
	}
	return nil
}

// belongsTo reports whether the certificate, the request or the private key in file is the one of cert.
func belongsTo(file string, cert *x509.Certificate) bool {
	data, err := os.ReadFile(file)
	if err != nil {
		return false
	}
	samePublicKey := func(pub crypto.PublicKey) bool {
		k, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
		return ok && k.Equal(cert.PublicKey)
	}
	for _, b := range pemBlocks(data) {
		switch {
		case b.Type == "CERTIFICATE":
			if c, err := x509.ParseCertificate(b.Bytes); err == nil && c.Equal(cert) {
				return true
			}
		case strings.HasSuffix(b.Type, "CERTIFICATE REQUEST"):
			if csr, err := x509.ParseCertificateRequest(b.Bytes); err == nil && samePublicKey(csr.PublicKey) {
				return true
			}
		case strings.HasSuffix(b.Type, "PRIVATE KEY"):
			var key any
			if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
				key = k
			} else if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
				key = k
			} else if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
				key = k
			}
			if s, ok := key.(interface{ Public() crypto.PublicKey }); ok && samePublicKey(s.Public()) {
				return true
			}
		}
	}
	return false
}

// archiveStaleFiles moves the files easy-rsa leaves behind when it revokes a certificate (easy-rsa 3.2 keeps
// private/<user>.key and reqs/<user>.req) to the place where it keeps the files of a revoked certificate,
// so build-client-full does not abort with "Request file already exists". A file is moved only when it
// belongs to the certificate with the serial of the revoked entry, and never over another file.
func (r *rotation) archiveStaleFiles() error {
	var cert *x509.Certificate
	for _, f := range r.files {
		if !fExist(f.live) {
			continue
		}
		if cert == nil {
			cert = r.oldCertificate()
		}
		if cert == nil || !belongsTo(f.live, cert) {
			return fmt.Errorf("%s is still there and does not belong to the certificate %s that is replaced, it is not touched", f.live, r.serial)
		}
		if fExist(f.archive) {
			return fmt.Errorf("%s exists already, %s is not moved over it", f.archive, f.live)
		}
		if err := os.MkdirAll(path.Dir(f.archive), 0755); err != nil {
			return err
		}
		if err := os.Rename(f.live, f.archive); err != nil {
			return fmt.Errorf("moving %s: %w", f.live, err)
		}
	}
	return nil
}

// retireIndexEntry renames the replaced certificate in index.txt, so the name is free for the new one.
func (r *rotation) retireIndexEntry() error {
	lines, err := readIndexTxt()
	if err != nil {
		return err
	}
	for i := range lines {
		if lines[i].SerialNumber == r.serial && lines[i].DistinguishedName == "/CN="+r.username {
			lines[i].DistinguishedName = "/CN=REVOKED-" + r.username + "-" + strings.Replace(uuid.New().String(), "-", "", -1)
			return fWrite(*indexTxtPath, renderIndexTxt(lines))
		}
	}
	return fmt.Errorf("certificate %s of %q is not in index.txt", r.serial, r.username)
}

// putNewCertificateFirst gives the new certificate the place of the old one in index.txt.
func (r *rotation) putNewCertificateFirst() error {
	lines, err := readIndexTxt()
	if err != nil {
		return err
	}
	oldIndex, newIndex := -1, -1
	for i := range lines {
		if lines[i].SerialNumber == r.serial {
			oldIndex = i
		} else if lines[i].DistinguishedName == "/CN="+r.username {
			newIndex = i
		}
	}
	if oldIndex < 0 || newIndex < 0 {
		return fmt.Errorf("index.txt has no new certificate for %q", r.username)
	}
	lines[oldIndex], lines[newIndex] = lines[newIndex], lines[oldIndex]
	return fWrite(*indexTxtPath, renderIndexTxt(lines))
}

// replacePassword stores the new password in the row the user has already, or in a new one. The old
// password stays in the database until the very last step: a failing step leaves it untouched.
func (r *rotation) replacePassword(password string) error {
	// the state now, not the one before: revoking the certificate has revoked the row as well
	out, err := runOpenvpnUser("list", "--all")
	if err != nil {
		return err
	}
	if current := ovpnUserListRow(out, r.username); !current.exists {
		if _, err := runOpenvpnUser("create", "--user="+r.username, "--password="+password); err != nil {
			return err
		}
	} else {
		if current.revoked {
			if _, err := runOpenvpnUser("restore", "--user="+r.username); err != nil {
				return err
			}
		}
		if _, err := runOpenvpnUser("change-password", "--user="+r.username, "--password="+password); err != nil {
			return err
		}
	}
	// openvpn-user exits with 0 also when the statement fails, the row is checked
	out, err = runOpenvpnUser("list", "--all")
	if err != nil {
		return err
	}
	if row := ovpnUserListRow(out, r.username); !row.exists || row.revoked {
		return fmt.Errorf("the password row of %q is %+v after the change", r.username, row)
	}
	return nil
}

// rollback puts index.txt, the files, the CRL and the password row back as they were before the rotation.
func (r *rotation) rollback() error {
	var failed []string
	fail := func(what string, err error) {
		log.Errorf("userRotate rollback: %s: %v", what, err)
		failed = append(failed, fmt.Sprintf("%s: %v", what, err))
	}

	// the new serials go away with the index entry, drop their copies
	known := map[string]bool{}
	for _, line := range indexTxtParser(string(r.index)) {
		known[line.SerialNumber] = true
	}
	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if !known[line.SerialNumber] {
			if err := os.Remove(pkiFile("certs_by_serial", line.SerialNumber+".pem")); err != nil && !os.IsNotExist(err) {
				fail("removing the copy of the new certificate", err)
			}
		}
	}

	for _, f := range r.files {
		archived := fExist(f.archive) && !f.archiveBefore
		if (archived || !f.liveBefore) && fExist(f.live) {
			// created by the failed issue (the old file is in the archive, or there was none)
			if err := os.Remove(f.live); err != nil {
				fail("removing "+f.live, err)
			}
		}
		if archived && !fExist(f.live) {
			if err := os.Rename(f.archive, f.live); err != nil {
				fail("restoring "+f.live, err)
			}
		}
	}
	for p, data := range r.inline {
		if !fExist(p) {
			err := os.MkdirAll(path.Dir(p), 0755)
			if err == nil {
				err = os.WriteFile(p, data, 0600)
			}
			if err != nil {
				fail("restoring "+p, err)
			}
		}
	}
	if err := os.WriteFile(*indexTxtPath, r.index, 0644); err != nil {
		fail("restoring index.txt", err)
	}
	if fExist(r.files[0].live) && !fExist(pkiFile("certs_by_serial", r.serial+".pem")) {
		if err := fCopy(r.files[0].live, pkiFile("certs_by_serial", r.serial+".pem")); err != nil {
			fail("restoring certs_by_serial", err)
		}
	}
	if !r.wasRevoked {
		if err := easyrsaGenCrl(); err != nil {
			fail("rebuilding the CRL", err)
		}
		if err := crlFix(); err != nil {
			fail("making the CRL readable for OpenVPN", err)
		}
	}

	if *authByPassword {
		out, err := runOpenvpnUser("list", "--all")
		if err != nil {
			fail("reading the password database", err)
		} else if now := ovpnUserListRow(out, r.username); now.exists != r.row.exists {
			if now.exists {
				if _, err := runOpenvpnUser("delete", "--force", "--user="+r.username); err != nil {
					fail("removing the new password row", err)
				}
			}
		} else if now.exists && now.revoked != r.row.revoked {
			command := "restore"
			if r.row.revoked {
				command = "revoke"
			}
			if _, err := runOpenvpnUser(command, "--user="+r.username); err != nil {
				fail("openvpn-user "+command, err)
			}
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// passwordNow tells what the password database says now about the password that a rotation stores: "new"
// when openvpn-user accepts it, "absent" when the user has no row, "revoked" when the row is revoked (it
// authenticates nobody), "other" when the row is active and refuses it, and "unknown" when users.db cannot
// be read or the row needs a second factor, which a password check cannot see through.
func (r *rotation) passwordNow(password string) string {
	if _, err := runOpenvpnUser("auth", "--user="+r.username, "--password="+password); err == nil {
		return "new"
	}
	out, err := runOpenvpnUser("list", "--all")
	if err != nil {
		return "unknown"
	}
	row := ovpnUserListRow(out, r.username)
	switch {
	case !row.exists:
		return "absent"
	case ovpnUserListAppConfigured(out, r.username):
		return "unknown"
	case row.revoked:
		return "revoked"
	}
	return "other"
}

// newPasswordState tells whether the password that a rotation is about to store is live now, before the
// rollback. "changed": it is accepted, so the password row has the new password. "unchanged": it is refused
// and users.db can be read (a row that is revoked or has no password is refused too, but then the command
// that stores the password never ran). "unknown": users.db cannot be read, or the row needs a second
// factor. It is not the answer after the rollback: see passwordNow, which the reply is composed from.
func (r *rotation) newPasswordState(password string) string {
	switch r.passwordNow(password) {
	case "new":
		return "changed"
	case "unknown":
		return "unknown"
	}
	return "unchanged"
}

// ovpnUserListAppConfigured reports whether the row of username has a registered 2FA application (the
// fifth column of "openvpn-user list --all").
func ovpnUserListAppConfigured(out, username string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 5 {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64); err != nil {
			continue
		}
		if strings.TrimSpace(fields[1]) == username {
			return strings.TrimSpace(fields[4]) == "true"
		}
	}
	return false
}

// rotateFilesystem replaces the certificate of username (easy-rsa on the filesystem) and its password.
// It is all or nothing for the certificate: when a step fails the old certificate, index entry and files
// are back. The password is the very last step, so a failure of any earlier step never touches it. The
// answer says what is true of the password: it is "as before" only when that was checked.
// The caller holds createUserMutex.
func (oAdmin *OvpnAdmin) rotateFilesystem(username, newPassword string) (error, string) {
	r, err := newRotation(username)
	if err != nil {
		log.Errorf("userRotate: %v", err)
		return err, fmt.Sprintf("Failed to rotate user \"%s\": %v", username, err)
	}

	passwordStep := false
	failed := func(err error) (error, string) {
		log.Errorf("userRotate: %v", err)
		// asked before the rollback: what the failed step left in the password row
		state := "unchanged"
		if passwordStep {
			state = r.newPasswordState(newPassword)
		}
		rbErr := r.rollback()
		// asked again after the rollback: it re-revokes a row the failed step had restored and deletes a row
		// it had created, so what was true before says nothing about the row that is there now
		now := ""
		if passwordStep {
			now = r.passwordNow(newPassword)
		}
		var msg string
		switch {
		case rbErr != nil:
			msg = fmt.Sprintf("Failed to rotate user \"%s\" and the previous state could not be restored completely, check the admin log", username)
		case state == "unchanged" && now != "new":
			msg = fmt.Sprintf("Failed to rotate user \"%s\", the certificate and the password are as before", username)
		default:
			msg = fmt.Sprintf("Failed to rotate user \"%s\", the certificate is as before", username)
		}
		switch {
		case now == "new":
			msg += ". The new password was already stored and is live: the password of the user is the one you entered, not the old one"
		case state == "unchanged":
			// nothing was stored, the sentence above says what is true
		case now == "absent":
			msg += ". The new password is not live: after the rollback the user has no password row, so no password is accepted"
		case now == "revoked":
			msg += ". The new password is not live: after the rollback the password row of the user is revoked, so no password is accepted"
			if state == "changed" {
				msg += " (the stored password is the new one, it is accepted again when the user is unrevoked)"
			}
		default:
			msg += ". The password of the user may be the new one or the old one, it could not be checked: set it again with change password"
		}
		oAdmin.clients = oAdmin.usersList()
		return errors.New(msg), msg
	}

	if err := oAdmin.revokeBeforeReplace(username); err != nil {
		return failed(err)
	}
	if err := r.archiveStaleFiles(); err != nil {
		return failed(err)
	}
	if err := r.retireIndexEntry(); err != nil {
		return failed(err)
	}
	if _, err := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "--batch", "build-client-full", username, "nopass"); err != nil {
		return failed(err)
	}
	if err := r.putNewCertificateFirst(); err != nil {
		return failed(err)
	}
	if err := easyrsaGenCrl(); err != nil {
		return failed(err)
	}
	if *authByPassword {
		passwordStep = true
		if err := r.replacePassword(newPassword); err != nil {
			return failed(err)
		}
	}
	log.Infof("Certificate for user %s rotated", username)
	return nil, ""
}

func (oAdmin *OvpnAdmin) userDelete(username string) (error, string) {
	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if usernameIsPathSafe(username) && checkUserExist(username) {
		if err := oAdmin.revokeBeforeReplace(username); err != nil {
			return err, err.Error()
		}
		// the certificate is revoked: drop the ccd so a user created later with the same name
		// does not inherit the static address and the routes (kubernetes.secrets keeps the ccd in
		// the secret of the certificate, which easyrsaDelete retires)
		if *storageBackend != "kubernetes.secrets" {
			if err := removeCcdFile(username); err != nil {
				log.Errorf("userDelete: %v", err)
				return err, err.Error()
			}
		}
		var problems []string
		problem := func(what string, err error) {
			log.Errorf("userDelete: %s: %v", what, err)
			problems = append(problems, what)
		}
		if *storageBackend == "kubernetes.secrets" {
			if err := app.easyrsaDelete(username); err != nil {
				problem("the certificate could not be retired in kubernetes", err)
			}
		} else {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			// an index that cannot be read is an error: it is never rewritten from an "empty" read
			usersFromIndexTxt, indexErr := readIndexTxt()
			if indexErr != nil {
				problem("index.txt could not be read", indexErr)
			}
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					break
				}
			}
			if *authByPassword {
				if _, err := runOpenvpnUser("delete", "--force", "--user="+username); err != nil {
					problem("the password row of the user could not be deleted", err)
				}
			}
			if indexErr == nil {
				if err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt)); err != nil {
					problem("index.txt could not be written", err)
				}
			}
			if err := easyrsaGenCrl(); err != nil {
				problem("the CRL could not be rebuilt", err)
			}
		}
		if err := crlFix(); err != nil {
			problem("the CRL could not be made readable for OpenVPN", err)
		}
		oAdmin.clients = oAdmin.usersList()
		if len(problems) > 0 {
			// the certificate is revoked and its sessions are killed (revokeBeforeReplace): what failed is the clean-up
			msg := fmt.Sprintf("Delete of user \"%s\" is incomplete: %s. The certificate is revoked. Check the admin log", username, strings.Join(problems, "; "))
			return errors.New(msg), msg
		}
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
	}
	return inputError{fmt.Sprintf("User \"%s\" not found", username)}, fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+*listenBaseUrl+downloadCertsApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+*listenBaseUrl+downloadCcdApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

// certsArchiveSkips is true for the files of pki/ that must never be in the sync archive: the CA
// private key (private/ca.key, wherever it is). It stays on the master: a slave only serves the PKI and cannot issue
// or revoke certificates, and a slave that held the key would turn every slave host into a way to
// sign certificates for the whole VPN. Everything else a slave needs stays: ca.crt, the server
// certificate and its key (private/server.key, OpenVPN on the slave reads it), ta.key, dh, the CRL,
// index.txt, the issued certificates and client keys (the slave panel builds client configs from
// them) and users.db (the slave's openvpn-user auth hook checks passwords against it).
//
// easy-rsa 3.2 also writes inline/private/<name>.inline files (certificate plus key in one file); the one of the CA
// (ca.inline) would carry the CA key again, so it is left out too.
func certsArchiveSkips(rel string) bool {
	switch path.Base(rel) {
	case "ca.key", "ca.inline":
		return true
	}
	return false
}

// archiveCerts builds the sync archive of pki/ in a new private temp file and returns its path; the
// caller removes it (removeArchive) once it has been served. The CA signing key is left out by what it
// is, not only by name: see caKeyIdentity.
func archiveCerts() (string, error) {
	pki := *easyrsaDirPath + "/pki"
	identity, err := loadCaKeyIdentity(pki)
	if err != nil {
		// the CA key cannot be told from other files: no archive rather than one that may carry it
		return "", fmt.Errorf("reading the CA key identity: %w", err)
	}
	return archiveToTemp(pki, "certs-*.tar.gz", certsArchiveSkips, identity.skipsContent)
}

// caKeyIdentity is what the CA signing key is made of, independent of any file name: the public keys of the
// CA certificate(s) (pki/ca.crt) and of pki/private/ca.key, and the exact DER bytes of every PEM body of
// pki/private/ca.key (this also recognises an encrypted copy, which cannot be parsed).
type caKeyIdentity struct {
	public []crypto.PublicKey
	bodies [][]byte
}

// loadCaKeyIdentity reads the identity of the CA signing key from pki/ca.crt and pki/private/ca.key. It
// fails closed: without a readable ca.crt that holds certificates that parse, a readable ca.key, at least
// one public key and at least one reference body, the archive filter could not recognise a renamed copy of
// the key, so there is no identity and no archive.
func loadCaKeyIdentity(pki string) (caKeyIdentity, error) {
	var id caKeyIdentity
	data, err := os.ReadFile(pki + "/ca.crt")
	if err != nil {
		return id, err
	}
	certificates := 0
	for _, b := range pemBlocks(data) {
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return id, fmt.Errorf("parsing %s/ca.crt: %w", pki, err)
		}
		id.public = append(id.public, c.PublicKey)
		certificates++
	}
	if certificates == 0 {
		return id, fmt.Errorf("%s/ca.crt holds no certificate", pki)
	}
	data, err = os.ReadFile(pki + "/private/ca.key")
	if err != nil {
		return id, err
	}
	id.addKeyMaterial(data)
	id.bodies = append(id.bodies, pemBodies(data)...)
	if len(id.public) == 0 || len(id.bodies) == 0 {
		return id, fmt.Errorf("the CA identity is not usable: %d public key(s) and %d reference body(ies) from %s/ca.crt and %s/private/ca.key, at least one of each is needed", len(id.public), len(id.bodies), pki, pki)
	}
	return id, nil
}

// pemBodies returns the decoded body of every PEM block that holds usable private key material: a key that
// parses to a public key (the same parsePrivateKeyDER that addKeyMaterial uses, so the two cannot disagree),
// or an encrypted key, which cannot be parsed and is kept as reference material on purpose. A block of a
// private key type with a body that is neither is not reference material.
func pemBodies(data []byte) [][]byte {
	var out [][]byte
	for _, b := range pemBlocks(data) {
		if !strings.HasSuffix(b.Type, "PRIVATE KEY") {
			continue
		}
		if _, ok := parsePrivateKeyDER(b.Bytes); ok || encryptedKeyBlock(b) {
			out = append(out, b.Bytes)
		}
	}
	return out
}

// encryptedKeyBlock reports whether b is an encrypted private key that cannot be parsed without its
// passphrase: an "ENCRYPTED PRIVATE KEY" block whose body is a well formed PKCS #8 EncryptedPrivateKeyInfo
// (an algorithm and the encrypted data), or a legacy PEM block that declares its encryption: Proc-Type
// "4,ENCRYPTED" and a DEK-Info of a cipher legacy OpenSSL uses for PEM keys with an IV of that cipher's block
// size. Nothing is decrypted, so the body of a legacy block is not inspected.
func encryptedKeyBlock(b *pem.Block) bool {
	if len(b.Bytes) == 0 {
		return false
	}
	if legacyEncryptionDeclared(b.Headers) {
		return true
	}
	if b.Type != "ENCRYPTED PRIVATE KEY" {
		return false
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, err := asn1.Unmarshal(b.Bytes, &info)
	return err == nil && len(rest) == 0 && len(info.Data) > 0
}

// legacyPEMCipherIVSize is the set of ciphers legacy OpenSSL writes into the DEK-Info header of an encrypted
// PEM key, with the IV size in bytes, which is the block size of the cipher.
var legacyPEMCipherIVSize = map[string]int{
	"DES-EDE3-CBC": 8,
	"AES-128-CBC":  16,
	"AES-192-CBC":  16,
	"AES-256-CBC":  16,
}

// legacyEncryptionDeclared reports whether the PEM headers declare an encrypted legacy key: Proc-Type exactly
// "4,ENCRYPTED" and DEK-Info "<CIPHER>,<HEX IV>" with a cipher of legacyPEMCipherIVSize and an IV of its size.
func legacyEncryptionDeclared(headers map[string]string) bool {
	if strings.TrimSpace(headers["Proc-Type"]) != "4,ENCRYPTED" {
		return false
	}
	cipher, iv, ok := strings.Cut(strings.TrimSpace(headers["DEK-Info"]), ",")
	size, known := legacyPEMCipherIVSize[strings.TrimSpace(cipher)]
	if !ok || !known {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimSpace(iv))
	return err == nil && len(raw) == size
}

// parsePrivateKeyDER returns the public key of a DER encoded private key (PKCS #8, PKCS #1 or SEC 1).
func parsePrivateKeyDER(der []byte) (crypto.PublicKey, bool) {
	var key any
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		key = k
	} else if k, err := x509.ParseECPrivateKey(der); err == nil {
		key = k
	}
	s, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, false
	}
	return s.Public(), true
}

// addKeyMaterial adds the public keys of the private keys in data (PEM or a bare DER key).
func (id *caKeyIdentity) addKeyMaterial(data []byte) {
	for _, pub := range privateKeysIn(data) {
		id.public = append(id.public, pub)
	}
}

// privateKeysIn returns the public keys of every private key in data: PEM blocks, or the whole of data
// as one DER encoded key when it holds no PEM.
func privateKeysIn(data []byte) []crypto.PublicKey {
	var out []crypto.PublicKey
	blocks := pemBlocks(data)
	for _, b := range blocks {
		if !strings.HasSuffix(b.Type, "PRIVATE KEY") {
			continue
		}
		if pub, ok := parsePrivateKeyDER(b.Bytes); ok {
			out = append(out, pub)
		}
	}
	if len(blocks) == 0 {
		if pub, ok := parsePrivateKeyDER(data); ok {
			out = append(out, pub)
		}
	}
	return out
}

// holdsCaKey reports whether data contains the CA signing key in any encoding the PKI uses: a private
// key whose public key is the one of the CA, or a PEM block with the exact body of ca.key.
func (id caKeyIdentity) holdsCaKey(data []byte) bool {
	same := func(pub crypto.PublicKey) bool {
		for _, ca := range id.public {
			if k, ok := pub.(interface{ Equal(crypto.PublicKey) bool }); ok && k.Equal(ca) {
				return true
			}
		}
		return false
	}
	for _, pub := range privateKeysIn(data) {
		if same(pub) {
			return true
		}
	}
	for _, body := range pemBodies(data) {
		for _, caBody := range id.bodies {
			if bytes.Equal(body, caBody) {
				return true
			}
		}
	}
	return false
}

// skipsContent is the content filter of the sync archive: it leaves out every file that holds the CA key.
func (id caKeyIdentity) skipsContent(rel string, data []byte) bool {
	if id.holdsCaKey(data) {
		log.Warnf("the sync archive leaves out %s: it holds the CA signing key", rel)
		return true
	}
	return false
}

func archiveCcd() (string, error) {
	return archiveToTemp(*ccdDir, "ccd-*.tar.gz", nil, nil)
}

func archiveToTemp(dir, pattern string, skip func(rel string) bool, skipData func(rel string, data []byte) bool) (string, error) {
	f, err := os.CreateTemp("", pattern) // mode 0600
	if err != nil {
		return "", fmt.Errorf("creating the archive file: %w", err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		removeArchive(name)
		return "", err
	}
	if err := createArchiveFromDirFiltered(dir, name, skip, skipData); err != nil {
		removeArchive(name)
		return "", fmt.Errorf("archiving %s: %w", dir, err)
	}
	return name, nil
}

// removeArchive deletes a temp archive; a file that is already gone is not an error.
func removeArchive(name string) {
	if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Errorf("removing %s: %s", name, err)
	}
}

func unArchiveCerts() {
	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
	}

	err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki")
	if err != nil {
		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
	}
}

func unArchiveCcd() {
	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
	}

	err := extractFromArchive(ccdArchivePath, *ccdDir)
	if err != nil {
		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
	}
}

// ovpnUserPrepareDb creates the openvpn-user database when it is missing or empty and --auth.db-init
// is set, and brings an existing one to the schema of openvpn-user 1.0.9:
//   - db-init runs also for an existing database: it only adds missing tables, and the "migrations"
//     table it creates is required by db-migrate (without it db-migrate silently does nothing);
//   - db-migrate adds the column "secret" without a default, so users created by openvpn-user <= 1.0.4
//     get NULL there and "openvpn-user auth" fails for them; NULL is replaced by an empty string,
//     the value openvpn-user 1.0.9 stores for new users.
func ovpnUserPrepareDb() {
	fi, err := os.Stat(*authDatabase)
	if (errors.Is(err, os.ErrNotExist) || (err == nil && fi.Size() == 0)) && !*authDataBaseInit {
		log.Warnf("password database %s does not exist, use --auth.db-init to create it", *authDatabase)
		return
	}

	for _, command := range []string{"db-init", "db-migrate"} {
		if _, err := runOpenvpnUser(command); err != nil {
			log.Errorf("ovpnUserPrepareDb: %v", err)
			return
		}
	}

	fixNullSecrets := "UPDATE users SET secret = '' WHERE secret IS NULL;"
	if _, err := exec.LookPath("sqlite3"); err != nil {
		log.Warnf("sqlite3 not found: users created by openvpn-user <= 1.0.4 cannot log in until you run: sqlite3 %s \"%s\"", *authDatabase, fixNullSecrets)
		return
	}
	if _, err := runCommand("", "", "sqlite3", *authDatabase, fixNullSecrets); err != nil {
		log.Errorf("ovpnUserPrepareDb: %v", err)
	}
}

// easyrsaGenCrl regenerates the CRL with easyrsa (filesystem backend). The error is the caller's to
// report: a CRL that was not rebuilt means a revoked certificate can still connect.
func easyrsaGenCrl() error {
	if _, err := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "gen-crl"); err != nil {
		return err
	}
	return nil
}

// crlNextUpdate reads the CRL that OpenVPN uses (pki/crl.pem) and returns its nextUpdate.
func crlNextUpdate() (time.Time, error) {
	data, err := os.ReadFile(*easyrsaDirPath + "/pki/crl.pem")
	if err != nil {
		return time.Time{}, fmt.Errorf("reading the CRL: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, errors.New("crl.pem holds no PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing the CRL: %w", err)
	}
	return crl.NextUpdate, nil
}

// crlExpireDays is the time until nextUpdate in days, negative when it has passed.
func crlExpireDays(nextUpdate, now time.Time) float64 {
	return nextUpdate.Sub(now).Hours() / 24
}

// setCrlExpireGauge sets ovpn_crl_expire_days from the CRL on disk. A CRL that cannot be read leaves
// the gauge as it was: the daily check logs the reason.
func setCrlExpireGauge(now time.Time) {
	next, err := crlNextUpdate()
	if err != nil {
		log.Debugf("ovpn_crl_expire_days: %v", err)
		return
	}
	ovpnCrlExpire.Set(crlExpireDays(next, now))
}

// rebuildCrl writes a new CRL: easyrsa gen-crl on the filesystem backend, the CRL secret on kubernetes.
func rebuildCrl() error {
	if *storageBackend == "kubernetes.secrets" {
		if err := app.easyrsaGenCRL(); err != nil {
			return err
		}
		if err := app.updateCRLOnDisk(); err != nil {
			return err
		}
		return crlFix()
	}
	if err := easyrsaGenCrl(); err != nil {
		return err
	}
	return crlFix()
}

// crlRefresh is one run of the daily CRL check. A CRL with less than crlRenewBefore left (or one that
// exists but cannot be read) is rebuilt on a master; a slave never holds the CA key, its CRL comes with the
// sync from the master, so it only reports. A CRL file that does not exist is a PKI that is not built yet
// (first start of a new stack): one warning, nothing to rebuild. It logs one line when it rebuilds and one
// when that fails, and never panics or exits. The result is checked on disk: a rebuild whose nextUpdate
// did not move counts as failed. It returns false only for a failed rebuild (the caller retries sooner).
func (oAdmin *OvpnAdmin) crlRefresh(now time.Time) bool {
	if oAdmin.role != "slave" {
		// every write to the PKI holds this lock (revoke, unrevoke, delete, rotate, create). The expiry is read
		// after it is taken: a revoke that ran while this waited has rebuilt the CRL already, and a CRL is
		// never built from an index that was read before the lock
		oAdmin.createUserMutex.Lock()
		defer oAdmin.createUserMutex.Unlock()
	}
	next, readErr := crlNextUpdate()
	if readErr == nil {
		ovpnCrlExpire.Set(crlExpireDays(next, now))
		if next.Sub(now) >= crlRenewBefore {
			log.Debugf("CRL check: nextUpdate %s, %.1f days left, no rebuild needed", next.UTC().Format(time.RFC3339), crlExpireDays(next, now))
			return true
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		log.Warnf("CRL check: %v: there is no CRL yet, nothing to rebuild (the PKI is built by the openvpn container at its first start)", readErr)
		return true
	}
	if oAdmin.role == "slave" {
		if readErr != nil {
			log.Errorf("CRL check on a slave: %v", readErr)
		} else {
			log.Errorf("CRL check on a slave: nextUpdate %s is %.1f days away and the CRL comes from the master, which rebuilds it daily: check the sync", next.UTC().Format(time.RFC3339), crlExpireDays(next, now))
		}
		return true
	}

	why := fmt.Sprintf("nextUpdate %s is %.1f days away (limit %d days)", next.UTC().Format(time.RFC3339), crlExpireDays(next, now), int(crlRenewBefore.Hours()/24))
	if readErr != nil {
		why = readErr.Error()
	}

	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return rebuildCrl()
	}()
	defer func() {
		adminAudit.system(auditActCrlRebuild, "crl.pem", err == nil, auditErrDetail(err, "scheduled rebuild: "+why))
	}()
	if err == nil {
		var after time.Time
		after, err = crlNextUpdate()
		if err == nil && readErr == nil && !after.After(next) {
			err = fmt.Errorf("the CRL was rebuilt but its nextUpdate did not move (still %s)", after.UTC().Format(time.RFC3339))
		}
		if err == nil {
			ovpnCrlExpire.Set(crlExpireDays(after, now))
			log.Infof("CRL rebuilt (%s): nextUpdate is now %s, %.1f days away", why, after.UTC().Format(time.RFC3339), crlExpireDays(after, now))
			return true
		}
	}
	log.Errorf("CRL rebuild failed (%s): %v", why, err)
	return false
}

// crlRefreshLoop runs crlRefresh after firstDelay, then every interval (a day), or after retry when the
// last run failed, in the manner of updateState. It ends when stop is closed (a nil stop never ends; only
// the tests close it).
func (oAdmin *OvpnAdmin) crlRefreshLoop(firstDelay, interval, retry time.Duration, stop <-chan struct{}) {
	wait := firstDelay
	for {
		select {
		case <-time.After(wait):
		case <-stop:
			return
		}
		if oAdmin.crlRefresh(time.Now()) {
			wait = interval
		} else {
			log.Warnf("CRL check: the next try is in %s", retry)
			wait = retry
		}
	}
}

// confirmRevokedInCrl reads the CRL that OpenVPN uses (pki/crl.pem) and checks that it lists the
// serial of the revoked certificate of username (index.txt flag R). It fails closed: a missing or
// unreadable CRL, or a serial that is not in it, is an error.
func confirmRevokedInCrl(username string) error {
	lines, err := readIndexTxt()
	if err != nil {
		return err
	}
	serial := ""
	for _, line := range lines {
		if line.DistinguishedName == "/CN="+username && line.Flag == "R" {
			serial = line.SerialNumber
			break
		}
	}
	if serial == "" {
		return fmt.Errorf("index.txt has no revoked certificate for %q", username)
	}
	want, ok := new(big.Int).SetString(serial, 16)
	if !ok {
		return fmt.Errorf("the serial %q of %q in index.txt is not hexadecimal", serial, username)
	}
	return checkSerialInCrl(want, username)
}

// confirmRevokedInKubernetes is confirmRevokedInCrl for the kubernetes.secrets backend, where the serial
// of the revoked certificate is read from its secret (index.txt there holds decimal serials).
func confirmRevokedInKubernetes(username string) error {
	serial, err := app.easyrsaRevokedSerial(username)
	if err != nil {
		return err
	}
	return checkSerialInCrl(serial, username)
}

// crlHasSerial reads the CRL file OpenVPN reads (pki/crl.pem) and tells whether it lists serial, and how
// many entries it has. It is the one place that parses that file for a serial: the revoke check and the
// unrevoke check both use it.
func crlHasSerial(serial *big.Int) (bool, int, error) {
	data, err := os.ReadFile(*easyrsaDirPath + "/pki/crl.pem")
	if err != nil {
		return false, 0, fmt.Errorf("reading the CRL: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false, 0, errors.New("crl.pem holds no PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return false, 0, fmt.Errorf("parsing the CRL: %w", err)
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true, len(crl.RevokedCertificateEntries), nil
		}
	}
	return false, len(crl.RevokedCertificateEntries), nil
}

// checkSerialInCrl checks that the CRL file OpenVPN reads (pki/crl.pem) lists serial.
func checkSerialInCrl(serial *big.Int, username string) error {
	listed, entries, err := crlHasSerial(serial)
	if err != nil {
		return err
	}
	if !listed {
		return fmt.Errorf("serial %X of %q is not in the CRL (%d entries)", serial, username, entries)
	}
	return nil
}

// confirmNotRevokedInCrl is the check behind an unrevoke: the CRL file OpenVPN reads must not list the
// serial of the certificate of username that index.txt does not say revoked. It fails closed: an index or
// a CRL that cannot be read, or a certificate that is not in the index, is an error.
func confirmNotRevokedInCrl(username string) error {
	lines, err := readIndexTxt()
	if err != nil {
		return err
	}
	for _, line := range lines {
		if line.DistinguishedName != "/CN="+username || line.Flag == "R" {
			continue
		}
		serial, ok := new(big.Int).SetString(line.SerialNumber, 16)
		if !ok {
			return fmt.Errorf("the serial %q of %q in index.txt is not hexadecimal", line.SerialNumber, username)
		}
		listed, entries, err := crlHasSerial(serial)
		if err != nil {
			return err
		}
		if listed {
			return fmt.Errorf("serial %X of %q is still in the CRL (%d entries)", serial, username, entries)
		}
		return nil
	}
	return fmt.Errorf("index.txt has no certificate of %q that is not revoked", username)
}

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Info("Decompressing archive with certificates from master")
			unArchiveCerts()
			removeArchive(certsArchivePath)
			log.Info("Decompression archive with certificates from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		}
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Info("Decompressing archive with ccd from master")
			unArchiveCcd()
			removeArchive(ccdArchivePath)
			log.Info("Decompression archive with ccd from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		}
	}

	oAdmin.lastSyncTime = time.Now().Format(stringDateFormat)
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.lastSuccessfulSyncTime = time.Now().Format(stringDateFormat)
	}
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	notFound := []OpenvpnServer{{Host: "kubernetes services not found"}}

	config, err := rest.InClusterConfig()
	if err != nil {
		return notFound, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return notFound, err
	}

	serviceNamespace := strings.TrimSpace(fRead(kubeNamespaceFilePath))

	var hosts []OpenvpnServer
	seen := map[OpenvpnServer]bool{}
	var lastErr error

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(serviceNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("get kubernetes service %s: %v", serviceName, err)
			lastErr = err
			continue
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		if len(service.Spec.Ports) == 0 {
			log.Warnf("kubernetes service %s has no ports", serviceName)
			continue
		}
		port := strconv.Itoa(int(service.Spec.Ports[0].Port))
		protocol := strings.ToLower(string(service.Spec.Ports[0].Protocol))

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			lbHost := ingress.IP
			if lbHost == "" {
				lbHost = ingress.Hostname
			}
			if lbHost == "" {
				continue
			}

			host := OpenvpnServer{Host: lbHost, Port: port, Protocol: protocol}
			if seen[host] {
				continue
			}
			seen[host] = true
			hosts = append(hosts, host)
		}
	}

	if len(hosts) == 0 {
		return notFound, lastErr
	}

	return hosts, nil
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
	}

	certPem, _ := pem.Decode(caCert)
	if certPem == nil {
		log.Errorf("error decode certificate %s", caCertPath)
		return time.Now()
	}
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
// crlFix makes pki/ and pki/crl.pem readable for OpenVPN, which reads the CRL as an unprivileged user
// (nobody). A chmod that fails is an error: a CRL the daemon cannot read is a failed revoke.
func crlFix() error {
	var errs []error
	if err := os.Chmod(*easyrsaDirPath+"/pki", 0755); err != nil {
		log.Error(err)
		errs = append(errs, err)
	}
	if err := os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644); err != nil {
		log.Error(err)
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
