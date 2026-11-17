#!/usr/bin/env sh
# Helper sourced by auth.sh, client-connect.sh and client-disconnect.sh: appends one event to the audit log.
#
# Line format (tab-separated, append-only; ovpn-admin reads the same file):
#   event time_unix username real_ip real_port virtual_ip4 virtual_ip6 bytes_received bytes_sent
# event is connect, disconnect, auth_ok or auth_fail; a missing value is "-".
#
# Usage: audit_log event user ip port v4 v6 rx tx
# Passwords are never passed to this helper and must not be.

AUDIT_LOG="${OVPN_AUDIT_LOG:-/etc/openvpn/audit/audit.tsv}"
AUDIT_FIELD_MAX=128

# audit_field VALUE: one line without tab/CR/LF, at most AUDIT_FIELD_MAX characters, "-" if empty
audit_field() {
  _af=$(printf '%s' "$1" | tr '\t\r\n' '   ' | cut -c "1-${AUDIT_FIELD_MAX}")
  printf '%s' "${_af:--}"
}

# audit_log never fails the caller: a failed write only prints a warning to stderr
audit_log() {
  _a_event=$(audit_field "$1")
  _a_user=$(audit_field "$2")
  _a_ip=$(audit_field "$3")
  _a_port=$(audit_field "$4")
  _a_v4=$(audit_field "$5")
  _a_v6=$(audit_field "$6")
  _a_rx=$(audit_field "$7")
  _a_tx=$(audit_field "$8")
  # Always wall-clock time. Do not use OpenVPN's time_unix: it is the session START timestamp and
  # OpenVPN reuses the same value in the client-disconnect environment (time_duration is the session length),
  # so it would stamp disconnect with the connect time and order auth_ok after connect.
  _a_time=$(audit_field "$(date +%s)")

  if ! (
    umask 077
    mkdir -p "$(dirname "$AUDIT_LOG")" &&
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$_a_event" "$_a_time" "$_a_user" "$_a_ip" "$_a_port" "$_a_v4" "$_a_v6" "$_a_rx" "$_a_tx" >> "$AUDIT_LOG"
  ) 2>/dev/null; then
    echo "audit: cannot write to ${AUDIT_LOG}" >&2
  fi
  return 0
}
