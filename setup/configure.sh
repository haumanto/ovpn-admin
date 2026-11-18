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
# OpenVPN listener port inside the container (--port at the end of this script). One value feeds the openvpn command line
# and the ban jumps; the published host port (right side of the compose "ports" mapping) must point at it
OVPN_SRV_PORT="${OVPN_SERVER_PORT:-1194}"

# Ban engine (fail2ban, see start_fail2ban below). Every value is validated here, before anything is changed:
# a bad value stops the container at startup instead of producing a broken fail2ban config.
BAN_ENABLED="${OVPN_BAN_ENABLED:-true}"
BAN_REQUIRED="${OVPN_BAN_REQUIRED:-false}"
BAN_MAXRETRY="${OVPN_BAN_MAXRETRY:-3}"
BAN_FINDTIME="${OVPN_BAN_FINDTIME:-600}"
BAN_BANTIME="${OVPN_BAN_BANTIME:-3600}"
# the Nth ban of the same address is permanent (never expires; kept across restarts in ban-history.tsv); 1 = every ban is permanent
BAN_REPEAT_COUNT="${OVPN_BAN_REPEAT_COUNT:-2}"
# The enforced port and transport are derived below from OVPN_SERVER_PORT and OVPN_PROTO, the values of the openvpn command
# line. OVPN_BAN_PORT is only an optional assertion: when set it must equal the derived listener port or the container stops.
BAN_PORT_ASSERT="${OVPN_BAN_PORT:-}"
# true (default): with IPv6 on (OVPN_PROTO tcp6/udp6 or OVPN_SERVER_NET6) the container stops when the IPv6 ban chain cannot be
# created. false is the single opt-out: loud warning, IPv6 sources are then not banned
BAN_IPV6_REQUIRED="${OVPN_BAN_IPV6_REQUIRED:-true}"
# openvpn.log and fail2ban.log are rotated (copy, then empty the original in place, so OpenVPN, fail2ban and tail keep following
# the same file) when they exceed LOG_MAX_BYTES; checked every LOG_ROTATE_INTERVAL seconds and at start; LOG_KEEP rotated copies
LOG_MAX_BYTES="${OVPN_LOG_MAX_BYTES:-10485760}"
LOG_KEEP="${OVPN_LOG_KEEP:-3}"
LOG_ROTATE_INTERVAL="${OVPN_LOG_ROTATE_INTERVAL:-60}"
# hosts and networks that are never banned (Docker bridge and private source addresses by default)
BAN_IGNOREIP="${OVPN_BAN_IGNOREIP:-127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10}"
for ban_bool in OVPN_BAN_ENABLED:"${BAN_ENABLED}" OVPN_BAN_REQUIRED:"${BAN_REQUIRED}" OVPN_BAN_IPV6_REQUIRED:"${BAN_IPV6_REQUIRED}"; do
  if [ "${ban_bool#*:}" != "true" ] && [ "${ban_bool#*:}" != "false" ]; then
    echo "ERROR: ${ban_bool%%:*} must be true or false, got \"${ban_bool#*:}\"" >&2
    exit 1
  fi
done
for ban_num in OVPN_BAN_MAXRETRY:"${BAN_MAXRETRY}" OVPN_BAN_FINDTIME:"${BAN_FINDTIME}" OVPN_BAN_BANTIME:"${BAN_BANTIME}" OVPN_BAN_REPEAT_COUNT:"${BAN_REPEAT_COUNT}" OVPN_LOG_MAX_BYTES:"${LOG_MAX_BYTES}" OVPN_LOG_KEEP:"${LOG_KEEP}" OVPN_LOG_ROTATE_INTERVAL:"${LOG_ROTATE_INTERVAL}"; do
  if ! [[ "${ban_num#*:}" =~ ^[1-9][0-9]{0,9}$ ]]; then
    echo "ERROR: ${ban_num%%:*} must be a positive integer, got \"${ban_num#*:}\"" >&2
    exit 1
  fi
done
if [ "${LOG_KEEP}" -gt 99 ]; then
  echo "ERROR: OVPN_LOG_KEEP must be 1 to 99, got \"${LOG_KEEP}\"" >&2
  exit 1
fi
# listener port: a valid port that is not the ovpn-admin port (shared network namespace) or the management port
ADMIN_PORT="${OVPN_LISTEN_PORT:-8080}"
if ! [[ "${OVPN_SRV_PORT}" =~ ^[1-9][0-9]{0,4}$ ]] || [ "${OVPN_SRV_PORT}" -gt 65535 ]; then
  echo "ERROR: OVPN_SERVER_PORT must be a port number from 1 to 65535, got \"${OVPN_SRV_PORT}\"" >&2
  exit 1
fi
if [ "${OVPN_SRV_PORT}" = "${ADMIN_PORT}" ] || [ "${OVPN_SRV_PORT}" = "8989" ]; then
  echo "ERROR: OVPN_SERVER_PORT ${OVPN_SRV_PORT} is the ovpn-admin or OpenVPN management port; the OpenVPN listener needs its own port" >&2
  exit 1
fi
# transport and family of the listener, from OVPN_PROTO (the openvpn --proto value): the ban jumps cover exactly these
case "${OVPN_SRV_PROTO}" in
  tcp | tcp4 | tcp6 | tcp-server | tcp4-server | tcp6-server) BAN_PROTOS="tcp" ;;
  udp | udp4 | udp6) BAN_PROTOS="udp" ;;
  *)
    echo "ERROR: OVPN_PROTO must be one of tcp, tcp4, tcp6, tcp-server, tcp4-server, tcp6-server, udp, udp4, udp6, got \"${OVPN_SRV_PROTO}\"" >&2
    exit 1
    ;;
esac
# IPv6 is on when the listener is IPv6 capable (tcp6/udp6) or the tunnel has an IPv6 pool
BAN_IPV6="false"
if [ -n "${OVPN_SRV_NET6}" ] || [[ "${OVPN_SRV_PROTO}" == *6* ]]; then
  BAN_IPV6="true"
fi
# the optional OVPN_BAN_PORT assertion must agree with the listener; it can never choose the port
if [ -n "${BAN_PORT_ASSERT}" ] && [ "${BAN_PORT_ASSERT}" != "${OVPN_SRV_PORT}" ]; then
  echo "ERROR: OVPN_BAN_PORT=\"${BAN_PORT_ASSERT}\" does not match the OpenVPN listener port ${OVPN_SRV_PORT} (OVPN_SERVER_PORT): refusing to start with bans scoped to another port. Unset OVPN_BAN_PORT or make both agree." >&2
  exit 1
fi
BAN_PORT="${OVPN_SRV_PORT}"
# one line of IPv4/IPv6 addresses or CIDR networks separated by single spaces; no host names, no other characters
if ! [[ "${BAN_IGNOREIP}" =~ ^[0-9A-Fa-f:./]+( [0-9A-Fa-f:./]+)*$ ]]; then
  echo "ERROR: OVPN_BAN_IGNOREIP must be IP addresses or CIDR networks separated by single spaces" >&2
  exit 1
fi


# --- Telegram ban notifications ---------------------------------------------------------------------------------
# A new ban sends one Telegram message (ovpn-ban.sh calls the notifier after the DROP rule and the ban list row are written).
# OVPN_TELEGRAM_ENABLED=true needs the bot token (OVPN_TELEGRAM_BOT_TOKEN, or OVPN_TELEGRAM_BOT_TOKEN_FILE: the path of a regular
# readable file whose first line is the token; the file wins over the variable) and OVPN_TELEGRAM_CHAT_ID; optional
# OVPN_TELEGRAM_THREAD_ID (forum topic) and OVPN_TELEGRAM_API_BASE (default https://api.telegram.org). The API base must be
# https://; http:// is accepted only with OVPN_TELEGRAM_ALLOW_HTTP=true (default false, local mock tests only). The base is
# validated by the notifier itself ("--check-api-base"), the same validator as the send path. Availability comes first: a
# missing or malformed value logs one ERROR, notifications stay off and the VPN starts anyway.
# The token is a secret: this block runs without "set -x" (the trace would print it), the value is kept in a shell variable that
# is not exported, and it is removed from the environment so that openvpn and its hooks do not inherit it. Only the fail2ban
# server gets it (and with it the notifier, started by the ban action), through a one-command environment in start_fail2ban,
# never through an argument, a file or the log. Nothing here prints the token or the chat id.
# It runs before the first child process of this script, so that no later process (openvpn, its hooks, the log tails) inherits the token.
TELEGRAM_TOOL="/usr/local/sbin/ovpn-telegram-notify"
install -D -m 0755 /etc/openvpn/setup/ovpn-telegram-notify.py "${TELEGRAM_TOOL}"
{ set +x; } 2>/dev/null
TG_TOKEN="${OVPN_TELEGRAM_BOT_TOKEN:-}"
TG_CHAT_ID="${OVPN_TELEGRAM_CHAT_ID:-}"
TG_THREAD_ID="${OVPN_TELEGRAM_THREAD_ID:-}"
TG_API_BASE="${OVPN_TELEGRAM_API_BASE:-https://api.telegram.org}"
TG_ALLOW_HTTP="${OVPN_TELEGRAM_ALLOW_HTTP:-false}"
TG_TOKEN_FILE="${OVPN_TELEGRAM_BOT_TOKEN_FILE:-}"
unset OVPN_TELEGRAM_BOT_TOKEN OVPN_TELEGRAM_BOT_TOKEN_FILE
TG_ENABLED="false"
case "${OVPN_TELEGRAM_ENABLED:-false}" in
  true)
    tg_problems=()
    tg_token_src="OVPN_TELEGRAM_BOT_TOKEN"
    tg_token_ok="true"
    if [ -n "${TG_TOKEN_FILE}" ]; then
      # the file wins over OVPN_TELEGRAM_BOT_TOKEN; an unusable file is an error, never a silent fallback to the variable.
      # First line only (at most 300 characters, the trailing newline and carriage return are dropped); the content is never printed.
      tg_token_src="OVPN_TELEGRAM_BOT_TOKEN_FILE"
      TG_TOKEN=""
      if [ -f "${TG_TOKEN_FILE}" ] && [ -r "${TG_TOKEN_FILE}" ]; then
        IFS= read -r -n 300 TG_TOKEN < "${TG_TOKEN_FILE}" || true
        TG_TOKEN="${TG_TOKEN%$'\r'}"
      else
        tg_token_ok="false"
        tg_problems+=("OVPN_TELEGRAM_BOT_TOKEN_FILE is not a readable regular file")
      fi
    fi
    if [ "${tg_token_ok}" = "true" ]; then
      if [ -z "${TG_TOKEN}" ]; then
        tg_problems+=("${tg_token_src} is not set or the file is empty")
      elif ! [[ "${TG_TOKEN}" =~ ^[0-9]{1,20}:[A-Za-z0-9_-]{1,128}$ ]]; then
        tg_problems+=("${tg_token_src} does not hold a bot token (<digits>:<characters>)")
      fi
    fi
    if [ -z "${TG_CHAT_ID}" ]; then
      tg_problems+=("OVPN_TELEGRAM_CHAT_ID is not set")
    elif ! [[ "${TG_CHAT_ID}" =~ ^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,63})$ ]]; then
      tg_problems+=("OVPN_TELEGRAM_CHAT_ID must be an integer or @channelname")
    fi
    if [ -n "${TG_THREAD_ID}" ] && ! [[ "${TG_THREAD_ID}" =~ ^[1-9][0-9]{0,15}$ ]]; then
      tg_problems+=("OVPN_TELEGRAM_THREAD_ID must be a positive integer")
    fi
    case "${TG_ALLOW_HTTP}" in
      true|false) ;;
      *) tg_problems+=("OVPN_TELEGRAM_ALLOW_HTTP must be true or false"); TG_ALLOW_HTTP="false" ;;
    esac
    # the same validator as the send path (api_base in the notifier): https:// (http:// only with ALLOW_HTTP=true), host,
    # a numeric port 1-65535, no user info, query or fragment. The reason it prints never contains the value.
    if ! tg_base_err="$(OVPN_TELEGRAM_ALLOW_HTTP="${TG_ALLOW_HTTP}" "${TELEGRAM_TOOL}" --check-api-base "${TG_API_BASE}" 2>&1)"; then
      tg_problems+=("${tg_base_err%%$'\n'*}")
    fi
    if [ "${#tg_problems[@]}" -eq 0 ]; then
      TG_ENABLED="true"
    else
      tg_joined="$(printf '%s; ' "${tg_problems[@]}")"
      echo "ERROR: OVPN_TELEGRAM_ENABLED=true but ${tg_joined%; }: Telegram notifications are disabled, the VPN starts anyway" >&2
    fi
    ;;
  false) ;;
  *) echo "ERROR: OVPN_TELEGRAM_ENABLED must be true or false: Telegram notifications are disabled, the VPN starts anyway" >&2 ;;
esac
if [ "${TG_ENABLED}" = "true" ]; then
  echo "telegram notifications: enabled"
  if [ "${BAN_ENABLED}" != "true" ]; then
    echo "WARNING: OVPN_BAN_ENABLED=false: no address is banned, so no Telegram notification is ever sent" >&2
  fi
else
  TG_TOKEN=""
  echo "telegram notifications: disabled"
fi
set -x


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
      last_sync="$(wget -q "${WGET_AUTH_ARGS[@]}" http://127.0.0.1:"${OVPN_LISTEN_PORT:-8080}"/api/sync/last/successful -O - || true)"
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

# rotate_log FILE: when FILE is larger than OVPN_LOG_MAX_BYTES, FILE.(N-1) becomes FILE.N (N = OVPN_LOG_KEEP, the oldest is
# dropped), FILE is copied to FILE.1 and FILE itself is emptied in place (same inode). OpenVPN (--log-append) and fail2ban
# write in append mode, so they keep writing at the new end; "tail -F" and the fail2ban polling backend notice the file shrank
# and read from the start. Lines written between the copy and the emptying are lost (milliseconds); that is the price of not
# having to signal the writers. Runs at start and every OVPN_LOG_ROTATE_INTERVAL seconds (rotate_loop below).
rotate_log() {
  local f="$1" size i
  [ -f "$f" ] || return 0
  size="$(stat -c %s "$f")" || { echo "log rotation: cannot read the size of $f" >&2; return 1; }
  [ "${size}" -gt "${LOG_MAX_BYTES}" ] || return 0
  echo "log rotation: $f is ${size} bytes (limit ${LOG_MAX_BYTES}), rotated to $f.1 (keeping ${LOG_KEEP})"
  rm -f "$f.${LOG_KEEP}" || return 1
  for ((i = LOG_KEEP - 1; i >= 1; i--)); do
    if [ -e "$f.$i" ]; then mv -f "$f.$i" "$f.$((i + 1))" || return 1; fi
  done
  cp -p "$f" "$f.1" || return 1
  : > "$f" || return 1
}
rotate_log "${OPENVPN_LOG}" || true
rotate_log "${FAIL2BAN_LOG}" || true
touch "${OPENVPN_LOG}"
chown nobody:nogroup "${OPENVPN_LOG}"
chmod 600 "${OPENVPN_LOG}"
tail -n 0 -F "${OPENVPN_LOG}" &

# ban list and enforcement, see ovpn-ban.sh (installed fresh at every start). The ban history (ban-history.tsv, same directory) keeps
# the ban counts and the permanent bans across restarts; "init" below leaves it alone and "setup" restores the permanent bans.
BAN_STATE_FILE="${AUDIT_LOG_DIR}/bans.tsv"
export OVPN_BAN_STATE="${BAN_STATE_FILE}" OVPN_BAN_LOG="${OPENVPN_LOG}" OVPN_BAN_BANTIME="${BAN_BANTIME}" OVPN_BAN_REPEAT_COUNT="${BAN_REPEAT_COUNT}" OVPN_IPTABLES_BIN="${IPTABLES_BIN}" OVPN_IP6TABLES_BIN="${IP6TABLES_BIN}"
# the enforced scope, derived above from the same variables as the openvpn command line (never taken from OVPN_BAN_PORT)
export OVPN_BAN_NOTIFY_LOG="${FAIL2BAN_LOG}"
export OVPN_BAN_PORT="${BAN_PORT}" OVPN_BAN_PROTOS="${BAN_PROTOS}" OVPN_BAN_IPV6="${BAN_IPV6}" OVPN_BAN_IPV6_REQUIRED="${BAN_IPV6_REQUIRED}" OVPN_LISTEN_PORT="${ADMIN_PORT}"
BAN_TOOL="/usr/local/sbin/ovpn-ban.sh"
install -D -m 0755 /etc/openvpn/setup/ovpn-ban.sh "${BAN_TOOL}"
# manual ban/unban queue shared with the ovpn-admin container: a directory next to bans.tsv, owned by root, mode 0700 (the admin
# container runs as root too); the watcher (started below, only with the ban engine) executes the requests through ovpn-ban.sh
BAN_CONTROL_TOOL="/usr/local/sbin/ovpn-ban-control"
BAN_CONTROL_DIR="${AUDIT_LOG_DIR}/control"
install -D -m 0755 /etc/openvpn/setup/ovpn-ban-control.py "${BAN_CONTROL_TOOL}"
export OVPN_BAN_TOOL="${BAN_TOOL}" OVPN_BAN_CONTROL_DIR="${BAN_CONTROL_DIR}"
# clear the ban list once, before fail2ban starts: a fresh network namespace has no bans, so no stale rows
"${BAN_TOOL}" init

# start_ban_control: the queue watcher of the manual ban control (see ovpn-ban-control.py), in the background for the life of the
# container. Started with the Telegram settings in its environment (the notification of a manual ban comes from ovpn-ban.sh, like
# the one of fail2ban), set the same way as for the fail2ban server: one-command environment, no trace while the token is expanded.
# A watcher that does not come up is an error line, not a reason to stop the VPN.
start_ban_control() {
  mkdir -p "${BAN_CONTROL_DIR}" && chown root:root "${BAN_CONTROL_DIR}" && chmod 0700 "${BAN_CONTROL_DIR}" || {
    echo "ERROR: cannot create the ban control directory ${BAN_CONTROL_DIR}: manual ban control is NOT available" >&2
    return 1
  }
  { set +x; } 2>/dev/null
  OVPN_TELEGRAM_ENABLED="${TG_ENABLED}" OVPN_TELEGRAM_BOT_TOKEN="${TG_TOKEN}" OVPN_TELEGRAM_CHAT_ID="${TG_CHAT_ID}" \
    OVPN_TELEGRAM_THREAD_ID="${TG_THREAD_ID}" OVPN_TELEGRAM_API_BASE="${TG_API_BASE}" OVPN_TELEGRAM_ALLOW_HTTP="${TG_ALLOW_HTTP}" \
    "${BAN_CONTROL_TOOL}" "${BAN_CONTROL_DIR}" &
  BAN_CONTROL_PID=$!
  set -x
  sleep 1
  if ! kill -0 "${BAN_CONTROL_PID}" 2>/dev/null; then
    echo "ERROR: the ban control watcher did not start: manual ban control is NOT available" >&2
    return 1
  fi
  echo "ban control: watching ${BAN_CONTROL_DIR}"
}

# start_fail2ban: writes the fail2ban config from the validated values above (always rebuilt, so nothing stale
# survives a restart), starts the server and checks that the jail is running. Returns non-zero on any failure;
# no "set -e" inside, because the caller tests the result.
start_fail2ban() {
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

  # only these two OpenVPN log lines count. After the timestamp (which fail2ban strips) OpenVPN 2.7 starts the line with the
  # listener's --proto name and the source, "<proto>:IP:port": tcp-server, tcp4-server, tcp6-server for TCP and udp, udp4,
  # udp6 for UDP (not udp-server; the AUTH_FAILED pattern accepts it anyway). An IPv6 source is written in brackets,
  # "<proto>:[IPv6]:port". Old-style lines have no proto name and may carry [AF_INET] or [AF_INET6] in front of the address.
  # Real lines of OpenVPN 2.7.7, default image:
  #   2026-11-17 19:11:47 tcp6-server:172.20.0.50:54768 VERIFY ERROR: depth=0, error=certificate revoked: CN=x, serial=N
  #   2026-11-17 20:07:41 tcp6-server:172.30.14.50:54826 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)
  #   2026-11-17 20:07:41 tcp6-server:172.30.14.50:54826 SENT CONTROL [user]: 'AUTH_FAILED' (status=1)
  #   2026-11-17 19:48:29 udp6:[fd00:172:20::61]:49031 SENT CONTROL [UNDEF]: 'AUTH_FAILED' (status=1)
  # The proto name is optional and "IP:port" must follow it directly (an unknown prefix makes the line a miss).
  # One wrong password writes TWO AUTH_FAILED lines with the same source and port, one right after the other: "[UNDEF]"
  # (sent before the common name is known) and "[<common name>]". They have the same shape, so a pattern for the shape
  # counts every attempt twice and the ban (OVPN_BAN_MAXRETRY=3) lands on the second attempt. Only the "[UNDEF]" line is
  # counted: it is written first, for every failed login, whatever the common name. TLS handshake failures, expired
  # certificates and network errors do not match. <HOST> matches IPv4 and IPv6 sources.
  cat > /etc/fail2ban/filter.d/ovpn-admin.conf <<'EOF' || return 1
[Definition]
failregex = ^\s*(?:(?:tcp[46]?-server|udp[46]?):)?(?:\[AF_INET6?\])?\[?<HOST>\]?:\d+ VERIFY ERROR: .*certificate revoked
            ^\s*(?:(?:tcp[46]?-server|udp[46]?(?:-server)?):)?(?:\[AF_INET6?\])?\[?<HOST>\]?:\d+ SENT CONTROL \[UNDEF\]: 'AUTH_FAILED'
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
actioncheck = ${BAN_TOOL} check
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
  # the Telegram settings go to this one command only (see the Telegram block above); no trace while the token is expanded
  { set +x; } 2>/dev/null
  OVPN_TELEGRAM_ENABLED="${TG_ENABLED}" OVPN_TELEGRAM_BOT_TOKEN="${TG_TOKEN}" OVPN_TELEGRAM_CHAT_ID="${TG_CHAT_ID}" \
    OVPN_TELEGRAM_THREAD_ID="${TG_THREAD_ID}" OVPN_TELEGRAM_API_BASE="${TG_API_BASE}" OVPN_TELEGRAM_ALLOW_HTTP="${TG_ALLOW_HTTP}" \
    fail2ban-server -b -x >/dev/null 2>&1 &
  set -x
  for _ in $(seq 1 30); do
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
  # fail closed on IPv6 (before fail2ban): with IPv6 on and OVPN_BAN_IPV6_REQUIRED not false, an IPv6 ban chain that cannot be
  # created stops the container (ovpn-ban.sh exit 3), whatever OVPN_BAN_REQUIRED says. Other setup failures (IPv4) go through
  # start_fail2ban and OVPN_BAN_REQUIRED below. setup is idempotent; the jail start repeats it.
  if "${BAN_TOOL}" setup; then
    :
  else
    ban_rc=$?
    if [ "${ban_rc}" -eq 3 ]; then
      echo "ERROR: IPv6 is enabled (OVPN_PROTO=${OVPN_SRV_PROTO} OVPN_SERVER_NET6=${OVPN_SRV_NET6:-<empty>}) but IPv6 bans cannot be enforced; stopping the container. Fix ip6tables or set OVPN_BAN_IPV6_REQUIRED=false to accept running without IPv6 bans." >&2
      "${BAN_TOOL}" teardown || true
      exit 1
    fi
  fi
  if start_fail2ban && "${BAN_TOOL}" check; then
    echo "fail2ban: jail ovpn-admin running (maxretry=${BAN_MAXRETRY} findtime=${BAN_FINDTIME}s bantime=${BAN_BANTIME}s repeat-count=${BAN_REPEAT_COUNT})"
    # after the jail start (its start action rebuilt the chains and restored the permanent bans), before OpenVPN
    start_ban_control || true
  else
    ban_rc=$?
    if [ "${ban_rc}" -eq 3 ]; then
      echo "ERROR: required IPv6 ban enforcement is missing after the jail start; stopping the container" >&2
      exit 1
    fi
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

# ongoing log bound: check the size of both logs every OVPN_LOG_ROTATE_INTERVAL seconds for the life of the container
# (a background loop like the tail processes above; no cron). Tracing is off in the loop so that it does not write a line per check.
(
  set +ex
  while :; do
    sleep "${LOG_ROTATE_INTERVAL}"
    rotate_log "${OPENVPN_LOG}" || echo "log rotation of ${OPENVPN_LOG} failed" >&2
    rotate_log "${FAIL2BAN_LOG}" || echo "log rotation of ${FAIL2BAN_LOG} failed" >&2
  done
) &

exec openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --port "${OVPN_SRV_PORT}" --proto "${OVPN_SRV_PROTO}" --management 127.0.0.1 8989 --dev tun0 --server "${OVPN_SRV_NET}" "${OVPN_SRV_MASK}" "${OVPN_IPV6_ARGS[@]}" --log-append "${OPENVPN_LOG}"
