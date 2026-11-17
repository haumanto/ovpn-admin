#!/usr/bin/env sh

PATH=$PATH:/usr/local/bin

# shellcheck disable=SC1091
. "$(dirname "$0")/audit.sh" || true

auth_usr=$(head -1 "$1")
auth_passwd=$(tail -1 "$1")

# the client address is "untrusted" until the connection is accepted: trusted_ip is not always set yet
auth_ip="${trusted_ip:-${trusted_ip6:-${untrusted_ip:-${untrusted_ip6:-}}}}"
auth_port="${trusted_port:-${untrusted_port:-}}"

auth_ok=false
if [ "$common_name" = "$auth_usr" ]; then
  # --flag=value: a separate value starting with "-" (e.g. the password "-secret") is not accepted by openvpn-user
  if openvpn-user auth --db.path=/etc/openvpn/easyrsa/pki/users.db --user="${auth_usr}" --password="${auth_passwd}"; then
    auth_ok=true
  fi
fi

# only the username, address and port are logged, never the password
if [ "$auth_ok" = "true" ]; then
  audit_log auth_ok "$auth_usr" "$auth_ip" "$auth_port" "" "" "" ""
  exit 0
fi

echo "Authorization failed"
audit_log auth_fail "$auth_usr" "$auth_ip" "$auth_port" "" "" "" ""
exit 1
