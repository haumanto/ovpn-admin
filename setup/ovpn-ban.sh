#!/usr/bin/env bash
# Ban enforcement and ban list for the fail2ban jail "ovpn-admin" (called from the fail2ban action, see configure.sh).
#
#   ovpn-ban.sh init             clear the ban list (container start, before fail2ban starts)
#   ovpn-ban.sh ban IP FAILURES  DROP IP in the OVPN_BAN chain and add (or replace) its row in the ban list
#   ovpn-ban.sh unban IP         remove the DROP rule and the row
#   ovpn-ban.sh flush            remove every DROP rule and clear the ban list
#   ovpn-ban.sh teardown         remove the INPUT jump, flush, delete the OVPN_BAN chain (actionstop, ban engine disabled)
#
# Ban list (read by ovpn-admin): OVPN_BAN_STATE, default /etc/openvpn/audit/bans.tsv, root:root 0600, no header, one
# tab-separated row per active ban: ip, banned_at_unix, expires_at_unix, failures, reason.
# The file is replaced atomically (temp file in the same directory + rename) while holding an flock.
#
# Environment:
#   OVPN_IPTABLES_BIN  iptables binary (default iptables; iptables-legacy on older Docker hosts), same selector as configure.sh
#   OVPN_BAN_STATE     ban list path
#   OVPN_BAN_BANTIME   seconds a ban lasts, used for expires_at_unix (default 3600)
#   OVPN_BAN_LOG       OpenVPN log, only read to name the reason of a ban (default /etc/openvpn/audit/openvpn.log)
#
# IPv4 only. Nothing from the caller reaches a shell: IP and FAILURES are validated against strict patterns
# and every command is called with a fixed argument vector.

set -u
umask 077

CHAIN="OVPN_BAN"
IPT="${OVPN_IPTABLES_BIN:-iptables}"
STATE="${OVPN_BAN_STATE:-/etc/openvpn/audit/bans.tsv}"
LOCK="${STATE}.lock"
BANTIME="${OVPN_BAN_BANTIME:-3600}"
OVPN_LOG="${OVPN_BAN_LOG:-/etc/openvpn/audit/openvpn.log}"

die() { echo "ovpn-ban: $*" >&2; exit 1; }

case "$IPT" in
  *[!A-Za-z0-9._-]* | "") die "invalid OVPN_IPTABLES_BIN" ;;
esac
case "$BANTIME" in
  *[!0-9]* | "" | 0*) die "invalid OVPN_BAN_BANTIME" ;;
esac

ipt() { "$IPT" -w 5 "$@"; }

# valid_ip4 IP: dotted quad without leading zeros; refuses 0.x.x.x, loopback, multicast/reserved (>= 224)
valid_ip4() {
  local re='^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'
  [[ "$1" =~ $re ]] || return 1
  local first="${1%%.*}"
  [ "$first" -ne 0 ] && [ "$first" -ne 127 ] && [ "$first" -lt 224 ]
}

valid_posint() { [[ "$1" =~ ^[1-9][0-9]{0,9}$ ]]; }

ensure_chain() {
  # a concurrent ban may create the chain or the jump between the check and the create: re-check before failing
  ipt -n -L "$CHAIN" >/dev/null 2>&1 || ipt -N "$CHAIN" 2>/dev/null || ipt -n -L "$CHAIN" >/dev/null 2>&1 || return 1
  ipt -C INPUT -j "$CHAIN" >/dev/null 2>&1 || ipt -I INPUT 1 -j "$CHAIN" 2>/dev/null || ipt -C INPUT -j "$CHAIN" >/dev/null 2>&1 || return 1
}

# with_state_lock CMD [ARGS]: runs CMD while holding the exclusive lock of the ban list
with_state_lock() {
  (
    flock -x 9 || exit 1
    "$@"
  ) 9>>"$LOCK"
}

# write_rows: stdin becomes the new ban list (atomic rename, 0600)
write_rows() {
  local tmp
  tmp="$(mktemp "${STATE}.XXXXXX")" || return 1
  if cat > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$STATE"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# rows_without IP: current rows except the one of IP
rows_without() {
  [ -f "$STATE" ] || return 0
  awk -F '\t' -v ip="$1" '$1 != ip' "$STATE"
}

# reason_for IP: which failure kinds the log shows for IP (only fixed words are returned)
reason_for() {
  local lines="" kinds=()
  [ -r "$OVPN_LOG" ] && lines="$(tail -n 5000 "$OVPN_LOG" 2>/dev/null | grep -F " $1:" 2>/dev/null || true)"
  case "$lines" in *"certificate revoked"*) kinds+=("revoked-certificate") ;; esac
  case "$lines" in *"AUTH_FAILED"*) kinds+=("auth-failed") ;; esac
  case "${#kinds[@]}" in
    0) echo "fail2ban" ;;
    1) echo "${kinds[0]}" ;;
    *) echo "${kinds[0]}+${kinds[1]}" ;;
  esac
}

do_ban_row() { # ip failures reason
  local now
  now="$(date +%s)"
  {
    rows_without "$1"
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$now" "$((now + BANTIME))" "$2" "$3"
  } | write_rows
}

do_unban_row() { rows_without "$1" | write_rows; }

do_clear_rows() { : | write_rows; }

cmd_init() {
  mkdir -p "$(dirname "$STATE")" || die "cannot create $(dirname "$STATE")"
  with_state_lock do_clear_rows || die "cannot reset $STATE"
}

cmd_ban() {
  [ "$#" -eq 2 ] || die "usage: ban IP FAILURES"
  valid_ip4 "$1" || die "refusing to ban: not a public-routable IPv4 address: $1"
  valid_posint "$2" || die "FAILURES must be a positive integer: $2"
  ensure_chain || die "cannot create chain $CHAIN with $IPT"
  ipt -C "$CHAIN" -s "$1" -j DROP >/dev/null 2>&1 || ipt -A "$CHAIN" -s "$1" -j DROP || die "cannot add DROP rule for $1"
  with_state_lock do_ban_row "$1" "$2" "$(reason_for "$1")" || die "rule added but cannot update $STATE"
}

cmd_unban() {
  [ "$#" -eq 1 ] || die "usage: unban IP"
  valid_ip4 "$1" || die "not a valid IPv4 address: $1"
  local rc=0
  # a rule can exist more than once if added by hand: remove all copies
  while ipt -C "$CHAIN" -s "$1" -j DROP >/dev/null 2>&1; do
    ipt -D "$CHAIN" -s "$1" -j DROP || { rc=1; break; }
  done
  with_state_lock do_unban_row "$1" || rc=1
  return "$rc"
}

cmd_flush() {
  local rc=0
  if ipt -n -L "$CHAIN" >/dev/null 2>&1; then ipt -F "$CHAIN" || rc=1; fi
  with_state_lock do_clear_rows || rc=1
  return "$rc"
}

cmd_teardown() {
  local rc=0
  while ipt -C INPUT -j "$CHAIN" >/dev/null 2>&1; do
    ipt -D INPUT -j "$CHAIN" || { rc=1; break; }
  done
  cmd_flush || rc=1
  if ipt -n -L "$CHAIN" >/dev/null 2>&1; then ipt -X "$CHAIN" || rc=1; fi
  return "$rc"
}

action="${1:-}"
[ "$#" -gt 0 ] && shift
case "$action" in
  init) [ "$#" -eq 0 ] || die "usage: init"; cmd_init ;;
  ban) cmd_ban "$@" ;;
  unban) cmd_unban "$@" ;;
  flush) [ "$#" -eq 0 ] || die "usage: flush"; cmd_flush ;;
  teardown) [ "$#" -eq 0 ] || die "usage: teardown"; cmd_teardown ;;
  *) die "usage: $0 init | ban IP FAILURES | unban IP | flush | teardown" ;;
esac
