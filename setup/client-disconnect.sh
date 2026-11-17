#!/usr/bin/env sh
# OpenVPN client-disconnect hook: logs a "disconnect" event with the byte counters of the session, never fails.
# trusted_ip6 is the real address of clients that connect over IPv6.

# shellcheck disable=SC1091
. "$(dirname "$0")/audit.sh" || exit 0

audit_log disconnect "${common_name:-}" "${trusted_ip:-${trusted_ip6:-}}" "${trusted_port:-}" \
  "${ifconfig_pool_remote_ip:-}" "${ifconfig_pool_remote_ip6:-}" "${bytes_received:-}" "${bytes_sent:-}"

exit 0
