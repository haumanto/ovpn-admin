#!/usr/bin/env bash
set -ex

EASY_RSA_LOC="/etc/openvpn/easyrsa"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"

# IPv4 pool for VPN clients (OpenVPN --server)
OVPN_SRV_NET="${OVPN_SERVER_NET:-172.16.100.0}"
OVPN_SRV_MASK="${OVPN_SERVER_MASK:-255.255.255.0}"
# IPv6 pool for VPN clients in CIDR format (OpenVPN --server-ipv6), e.g. fd00:16:100::/64; empty = IPv6 disabled
OVPN_SRV_NET6="${OVPN_SERVER_NET6:-}"
# Listener transport (OpenVPN --proto): tcp = IPv4 only, tcp6 = dual-stack (IPv4 and IPv6 clients)
OVPN_SRV_PROTO="${OVPN_PROTO:-tcp}"

# Ban engine (fail2ban, see start_fail2ban below). Every value is validated here, before anything is changed:
# a bad value stops the container at startup instead of producing a broken fail2ban config.
BAN_ENABLED="${OVPN_BAN_ENABLED:-true}"
BAN_REQUIRED="${OVPN_BAN_REQUIRED:-false}"
BAN_MAXRETRY="${OVPN_BAN_MAXRETRY:-3}"
BAN_FINDTIME="${OVPN_BAN_FINDTIME:-600}"
BAN_BANTIME="${OVPN_BAN_BANTIME:-3600}"
# OpenVPN listener port inside the container (--port below): the ban chains are only reachable through jumps for this port
BAN_PORT="${OVPN_BAN_PORT:-1194}"
# size limit of openvpn.log and fail2ban.log, checked once at container start (see rotate_log)
LOG_MAX_BYTES="${OVPN_LOG_MAX_BYTES:-10485760}"
# hosts and networks that are never banned (Docker bridge and private source addresses by default)
BAN_IGNOREIP="${OVPN_BAN_IGNOREIP:-127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10}"
for ban_bool in OVPN_BAN_ENABLED:"${BAN_ENABLED}" OVPN_BAN_REQUIRED:"${BAN_REQUIRED}"; do
  if [ "${ban_bool#*:}" != "true" ] && [ "${ban_bool#*:}" != "false" ]; then
    echo "ERROR: ${ban_bool%%:*} must be true or false, got \"${ban_bool#*:}\"" >&2
    exit 1
  fi
done
for ban_num in OVPN_BAN_MAXRETRY:"${BAN_MAXRETRY}" OVPN_BAN_FINDTIME:"${BAN_FINDTIME}" OVPN_BAN_BANTIME:"${BAN_BANTIME}" OVPN_LOG_MAX_BYTES:"${LOG_MAX_BYTES}"; do
  if ! [[ "${ban_num#*:}" =~ ^[1-9][0-9]{0,9}$ ]]; then
    echo "ERROR: ${ban_num%%:*} must be a positive integer, got \"${ban_num#*:}\"" >&2
    exit 1
  fi
done
if ! [[ "${BAN_PORT}" =~ ^[1-9][0-9]{0,4}$ ]] || [ "${BAN_PORT}" -gt 65535 ]; then
  echo "ERROR: OVPN_BAN_PORT must be a port number from 1 to 65535, got \"${BAN_PORT}\"" >&2
  exit 1
fi
# one line of IPv4/IPv6 addresses or CIDR networks separated by single spaces; no host names, no other characters
if ! [[ "${BAN_IGNOREIP}" =~ ^[0-9A-Fa-f:./]+( [0-9A-Fa-f:./]+)*$ ]]; then
  echo "ERROR: OVPN_BAN_IGNOREIP must be IP addresses or CIDR networks separated by single spaces" >&2
  exit 1
fi


cd "${EASY_RSA_LOC}"

if [ -e "${SERVER_CERT}" ]; then
  echo "Found existing certs - reusing"
else
  if [ "${OVPN_ROLE:-master}" = "slave" ]; then
    echo "Waiting for initial sync data from master"
    # ovpn-admin shares the network namespace of this container and listens on port ${OVPN_LISTEN_PORT:-8080};
    # wait until it has completed the first successful sync with the master
    # with BASIC_USERNAME/BASIC_PASSWORD set on ovpn-admin the endpoint needs the same credentials;
    # tracing is off while they are handled so that they do not end up in the container log
    set +x
    WGET_AUTH_ARGS=()
    if [ -n "${BASIC_USERNAME:-}" ] && [ -n "${BASIC_PASSWORD:-}" ]; then
      WGET_AUTH_ARGS=(--header "Authorization: Basic $(printf '%s:%s' "${BASIC_USERNAME}" "${BASIC_PASSWORD}" | base64 | tr -d '\n')")
    fi
    while :; do
      last_sync="$(wget -q "${WGET_AUTH_ARGS[@]}" http://127.0.0.1:${OVPN_LISTEN_PORT:-8080}/api/sync/last/successful -O - || true)"
      if [ -n "${last_sync}" ] && [ "${last_sync}" != "unknown" ]; then
        break
      fi
      sleep 5
    done
    set -x
  else
    echo "Generating new certs"
    easyrsa --batch init-pki
    cp -R /usr/share/easy-rsa/* "${EASY_RSA_LOC}/pki"
    echo "ca" | easyrsa build-ca nopass
    easyrsa --batch build-server-full server nopass
    easyrsa gen-dh
    openvpn --genkey secret ./pki/ta.key
  fi
fi
easyrsa gen-crl

# Select iptables backend.
# Default: system iptables
# Older Docker hosts: iptables-legacy
IPTABLES_BIN="${OVPN_IPTABLES_BIN:-iptables}"

command -v "$IPTABLES_BIN" >/dev/null 2>&1 || {
    echo "ERROR: iptables binary not found: $IPTABLES_BIN" >&2
    exit 1
}

"$IPTABLES_BIN" -t nat -D POSTROUTING \
    -s "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" \
    ! -d "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" \
    -j MASQUERADE || true

"$IPTABLES_BIN" -t nat -A POSTROUTING \
    -s "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" \
    ! -d "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" \
    -j MASQUERADE

# IPv6 counterpart of the selector above (default ip6tables; ip6tables-legacy together with iptables-legacy)
IP6TABLES_BIN="${OVPN_IP6TABLES_BIN:-ip6tables}"

OVPN_IPV6_ARGS=()
if [ -n "${OVPN_SRV_NET6}" ]; then
  command -v "$IP6TABLES_BIN" >/dev/null 2>&1 || {
    echo "ERROR: ip6tables binary not found: $IP6TABLES_BIN" >&2
    exit 1
  }
  "$IP6TABLES_BIN" -t nat -D POSTROUTING -s "${OVPN_SRV_NET6}" ! -d "${OVPN_SRV_NET6}" -j MASQUERADE || true
  "$IP6TABLES_BIN" -t nat -A POSTROUTING -s "${OVPN_SRV_NET6}" ! -d "${OVPN_SRV_NET6}" -j MASQUERADE

  if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]; then
    if ! sysctl -w net.ipv6.conf.all.forwarding=1; then
      echo "WARNING: cannot enable IPv6 forwarding (/proc/sys is read-only?)." \
        "Set net.ipv6.conf.all.forwarding=1 for this container (e.g. docker compose 'sysctls'), otherwise IPv6 traffic of VPN clients is not routed." >&2
    fi
  fi

  OVPN_IPV6_ARGS=(--server-ipv6 "${OVPN_SRV_NET6}")
fi

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf

# connection audit log: the hooks append one line per connect, disconnect and password-auth result
# (format and path: audit.sh, env OVPN_AUDIT_LOG; ovpn-admin reads the same file)
mkdir -p /etc/openvpn/scripts/
for script in audit.sh client-connect.sh client-disconnect.sh; do
  cp -f "/etc/openvpn/setup/${script}" "/etc/openvpn/scripts/${script}"
  chmod 0755 "/etc/openvpn/scripts/${script}"
done
echo "script-security 2" | tee -a /etc/openvpn/openvpn.conf
echo "client-connect /etc/openvpn/scripts/client-connect.sh" | tee -a /etc/openvpn/openvpn.conf
echo "client-disconnect /etc/openvpn/scripts/client-disconnect.sh" | tee -a /etc/openvpn/openvpn.conf
# the hooks run as the unprivileged "user nobody" of openvpn.conf, so it owns the directory (and an existing log);
# the directory is 700 and the log is created 600 (umask 077 in audit.sh)
AUDIT_LOG_FILE="${OVPN_AUDIT_LOG:-/etc/openvpn/audit/audit.tsv}"
AUDIT_LOG_DIR="$(dirname "${AUDIT_LOG_FILE}")"
mkdir -p "${AUDIT_LOG_DIR}"
chown nobody:nogroup "${AUDIT_LOG_DIR}"
chmod 700 "${AUDIT_LOG_DIR}"
if [ -f "${AUDIT_LOG_FILE}" ]; then
  chown nobody:nogroup "${AUDIT_LOG_FILE}"
  chmod 600 "${AUDIT_LOG_FILE}"
fi

if [ "${OVPN_PASSWD_AUTH:-false}" = "true" ]; then
  cp -f /etc/openvpn/setup/auth.sh /etc/openvpn/scripts/auth.sh
  chmod 0755 /etc/openvpn/scripts/auth.sh
  echo "auth-user-pass-verify /etc/openvpn/scripts/auth.sh via-file" | tee -a /etc/openvpn/openvpn.conf
  echo "verify-client-cert require" | tee -a /etc/openvpn/openvpn.conf
  # db-init also creates the "migrations" table that openvpn-user >= 1.0.5 needs for db-migrate on a database created by <= 1.0.4
  openvpn-user db-init --db.path="${EASY_RSA_LOC}/pki/users.db" && openvpn-user db-migrate --db.path="${EASY_RSA_LOC}/pki/users.db"
  # the migration adds the column "secret" without a default: users created by openvpn-user <= 1.0.4 get NULL there,
  # and "openvpn-user auth" of 1.0.9 fails for them, so NULL is replaced by an empty string (what 1.0.9 writes for new users)
  sqlite3 "${EASY_RSA_LOC}/pki/users.db" "UPDATE users SET secret = '' WHERE secret IS NULL;"
fi

[ -d "${EASY_RSA_LOC}/pki" ] && chmod 755 "${EASY_RSA_LOC}/pki"
[ -f "${EASY_RSA_LOC}/pki/crl.pem" ] && chmod 644 "${EASY_RSA_LOC}/pki/crl.pem"

mkdir -p /etc/openvpn/ccd

# --- OpenVPN log, ban engine -------------------------------------------------------------------------------
# OpenVPN writes its log to a file (--log-append below) that fail2ban watches; tail -F mirrors the file to stdout
# so "docker compose logs" still shows it. The file is created before OpenVPN so that the jail can open it.
OPENVPN_LOG="${AUDIT_LOG_DIR}/openvpn.log"
FAIL2BAN_LOG="/var/log/fail2ban.log"

# rotate_log FILE: at container start, a log larger than OVPN_LOG_MAX_BYTES becomes FILE.1 (one previous file is kept,
# an older FILE.1 is replaced) and the caller creates a fresh FILE. Logs that grow during a run are bounded at the next start.
rotate_log() {
  local size
  [ -f "$1" ] || return 0
  size="$(stat -c %s "$1" 2>/dev/null || echo 0)"
  if [ "${size}" -gt "${LOG_MAX_BYTES}" ]; then
    echo "log rotation: $1 is ${size} bytes (limit ${LOG_MAX_BYTES}), moved to $1.1"
    mv -f "$1" "$1.1"
  fi
}
rotate_log "${OPENVPN_LOG}"
rotate_log "${FAIL2BAN_LOG}"
touch "${OPENVPN_LOG}"
chown nobody:nogroup "${OPENVPN_LOG}"
chmod 600 "${OPENVPN_LOG}"
tail -n 0 -F "${OPENVPN_LOG}" &

# ban list and enforcement, see ovpn-ban.sh (installed fresh at every start)
BAN_STATE_FILE="${AUDIT_LOG_DIR}/bans.tsv"
export OVPN_BAN_STATE="${BAN_STATE_FILE}" OVPN_BAN_LOG="${OPENVPN_LOG}" OVPN_BAN_BANTIME="${BAN_BANTIME}" OVPN_IPTABLES_BIN="${IPTABLES_BIN}" OVPN_IP6TABLES_BIN="${IP6TABLES_BIN}" OVPN_BAN_PORT="${BAN_PORT}"
BAN_TOOL="/usr/local/sbin/ovpn-ban.sh"
install -D -m 0755 /etc/openvpn/setup/ovpn-ban.sh "${BAN_TOOL}"
# clear the ban list once, before fail2ban starts: a fresh network namespace has no bans, so no stale rows
"${BAN_TOOL}" init

# start_fail2ban: writes the fail2ban config from the validated values above (always rebuilt, so nothing stale
# survives a restart), starts the server and checks that the jail is running. Returns non-zero on any failure;
# no "set -e" inside, because the caller tests the result.
start_fail2ban() {
  local i
  # a container restart keeps the filesystem: remove the previous server's socket, pid file and ban database
  rm -f /run/fail2ban/fail2ban.sock /run/fail2ban/fail2ban.pid /var/lib/fail2ban/fail2ban.sqlite3 || return 1
  mkdir -p /etc/fail2ban/fail2ban.d /etc/fail2ban/filter.d /etc/fail2ban/action.d /etc/fail2ban/jail.d /run/fail2ban || return 1

  # server log to a file (a daemonized server has no usable stderr), mirrored to stdout below; no ban database
  cat > /etc/fail2ban/fail2ban.d/ovpn-admin.local <<EOF || return 1
[Definition]
loglevel = INFO
logtarget = ${FAIL2BAN_LOG}
dbfile = None
EOF

  # only these two OpenVPN log lines count; the line starts with "IP:port" (OpenVPN's per-connection prefix):
  #   IP:port VERIFY ERROR: ... certificate revoked
  #   IP:port AUTH_FAILED   (also as "IP:port SENT CONTROL [user]: 'AUTH_FAILED' (status=1)", how OpenVPN 2.x logs it)
  # TLS handshake failures, expired certificates and network errors do not match. <HOST> matches IPv4 and IPv6 sources;
  # OpenVPN prefixes the address with [AF_INET] or [AF_INET6] when the listener is dual-stack (tcp6/udp6).
  cat > /etc/fail2ban/filter.d/ovpn-admin.conf <<'EOF' || return 1
[Definition]
failregex = ^\s*(?:\[AF_INET6?\])?<HOST>:\d+ VERIFY ERROR: .*certificate revoked
            ^\s*(?:\[AF_INET6?\])?<HOST>:\d+ (?:SENT CONTROL \[[^]]*\]: ')?AUTH_FAILED
ignoreregex =
EOF

  # actionban/actionunban go through ovpn-ban.sh: DROP rule in the OVPN_BAN (IPv4) or OVPN_BAN6 (IPv6) chain plus the
  # ban list for the UI. Chains and the INPUT jumps (tcp and udp, port ${BAN_PORT} only) are created at jail start and
  # removed at jail stop. The iptables binary is the backend selector.
  cat > /etc/fail2ban/action.d/ovpn-admin.conf <<EOF || return 1
[Definition]
actionstart = ${BAN_TOOL} teardown || true
              ${BAN_TOOL} setup
actionstop = ${BAN_TOOL} teardown
actioncheck = ${IPTABLES_BIN} -w 5 -n -L OVPN_BAN
actionban = ${BAN_TOOL} ban <ip> <failures>
actionunban = ${BAN_TOOL} unban <ip>
EOF

  cat > /etc/fail2ban/jail.d/ovpn-admin.local <<EOF || return 1
[ovpn-admin]
enabled = true
filter = ovpn-admin
action = ovpn-admin
backend = polling
logpath = ${OPENVPN_LOG}
maxretry = ${BAN_MAXRETRY}
findtime = ${BAN_FINDTIME}
bantime = ${BAN_BANTIME}
ignoreip = ${BAN_IGNOREIP}
usedns = no

# the Alpine package enables sshd jails (jail.d/alpine-ssh.conf) that read /var/log/messages: not used in this container
[sshd]
enabled = false

[sshd-ddos]
enabled = false
EOF

  : >> "${FAIL2BAN_LOG}" || return 1
  tail -n 0 -F "${FAIL2BAN_LOG}" &

  # started in the background and polled: with a broken runtime directory the forking parent never returns on its own
  fail2ban-server -b -x >/dev/null 2>&1 &
  for i in $(seq 1 30); do
    fail2ban-client ping >/dev/null 2>&1 && break
    sleep 1
  done
  if ! fail2ban-client ping >/dev/null 2>&1; then
    pkill -9 -f '[f]ail2ban-server' >/dev/null 2>&1 || true
    return 1
  fi
  # the server answers ping even when a jail failed to load
  fail2ban-client status ovpn-admin >/dev/null 2>&1 || return 1
}

if [ "${BAN_ENABLED}" = "true" ]; then
  if start_fail2ban; then
    echo "fail2ban: jail ovpn-admin running (maxretry=${BAN_MAXRETRY} findtime=${BAN_FINDTIME}s bantime=${BAN_BANTIME}s)"
  else
    echo "################################################################################" >&2
    echo "ERROR: fail2ban did not start: failed OpenVPN logins and revoked certificates are NOT banned." >&2
    echo "################################################################################" >&2
    tail -n 20 "${FAIL2BAN_LOG}" >&2 2>/dev/null || true
    if [ "${BAN_REQUIRED}" = "true" ]; then
      echo "ERROR: OVPN_BAN_REQUIRED=true, stopping the container" >&2
      exit 1
    fi
    echo "WARNING: OVPN_BAN_REQUIRED=false, continuing without the ban engine" >&2
    # no half-started ban engine: stop a server that came up without a working jail, drop chain and jump
    fail2ban-client stop >/dev/null 2>&1 || true
    "${BAN_TOOL}" teardown || true
  fi
else
  echo "fail2ban: disabled (OVPN_BAN_ENABLED=false)"
  # a restarted container may still carry the chain of a previous run
  "${BAN_TOOL}" teardown || true
fi

exec openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --port 1194 --proto "${OVPN_SRV_PROTO}" --management 127.0.0.1 8989 --dev tun0 --server "${OVPN_SRV_NET}" "${OVPN_SRV_MASK}" "${OVPN_IPV6_ARGS[@]}" --log-append "${OPENVPN_LOG}"
