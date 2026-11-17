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

OVPN_IPV6_ARGS=()
if [ -n "${OVPN_SRV_NET6}" ]; then
  ip6tables -t nat -D POSTROUTING -s "${OVPN_SRV_NET6}" ! -d "${OVPN_SRV_NET6}" -j MASQUERADE || true
  ip6tables -t nat -A POSTROUTING -s "${OVPN_SRV_NET6}" ! -d "${OVPN_SRV_NET6}" -j MASQUERADE

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

exec openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --port 1194 --proto "${OVPN_SRV_PROTO}" --management 127.0.0.1 8989 --dev tun0 --server "${OVPN_SRV_NET}" "${OVPN_SRV_MASK}" "${OVPN_IPV6_ARGS[@]}"
