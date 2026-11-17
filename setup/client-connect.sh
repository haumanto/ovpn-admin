#!/usr/bin/env sh
# OpenVPN client-connect hook: logs a "connect" event, never rejects the client.
# trusted_ip6 is the real address of clients that connect over IPv6.

# shellcheck disable=SC1091
. "$(dirname "$0")/audit.sh" || exit 0

audit_log connect "${common_name:-}" "${trusted_ip:-${trusted_ip6:-}}" "${trusted_port:-}" \
  "${ifconfig_pool_remote_ip:-}" "${ifconfig_pool_remote_ip6:-}" "" ""

exit 0
