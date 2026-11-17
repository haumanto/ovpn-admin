#!/usr/bin/env bash
# Ban enforcement and ban list for the fail2ban jail "ovpn-admin" (called from the fail2ban action, see configure.sh).
#
#   ovpn-ban.sh init             clear the ban list and every DROP rule of both families (container start, before fail2ban starts)
#   ovpn-ban.sh setup            create the OVPN_BAN (IPv4) and OVPN_BAN6 (IPv6) chains and their INPUT jumps (jail start)
#   ovpn-ban.sh ban IP FAILURES  DROP IP in OVPN_BAN (IPv4) or OVPN_BAN6 (IPv6) and add (or replace) its row in the ban list
#   ovpn-ban.sh unban IP         remove the DROP rule and the row; succeeds when neither exists
#   ovpn-ban.sh flush            remove every DROP rule of both chains and clear the ban list
#   ovpn-ban.sh teardown         remove the INPUT jumps, flush, delete both chains (actionstop, ban engine disabled)
#
# Ban list (read by ovpn-admin): OVPN_BAN_STATE, default /etc/openvpn/audit/bans.tsv, root:root 0600, no header, one
# tab-separated row per active ban: ip, banned_at_unix, expires_at_unix, failures, reason. IPv4 and IPv6 share the file;
# the ip column holds the canonical text form of the address.
# The file is replaced atomically (temp file in the same directory + rename) while holding an flock.
#
# Scope: the INPUT chain jumps to the ban chains only for the OpenVPN listener (tcp and udp, destination port
# OVPN_BAN_PORT). Other listeners in the same network namespace, such as the ovpn-admin port 8080, are never behind a ban.
#
# Environment:
#   OVPN_IPTABLES_BIN   iptables binary for IPv4 (default iptables; iptables-legacy on older Docker hosts), same selector as configure.sh
#   OVPN_IP6TABLES_BIN  ip6tables binary for IPv6 (default ip6tables; set ip6tables-legacy together with iptables-legacy)
#   OVPN_BAN_PORT       OpenVPN listener port inside the container that the bans apply to (default 1194)
#   OVPN_BAN_STATE      ban list path
#   OVPN_BAN_BANTIME    seconds a ban lasts, used for expires_at_unix (default 3600)
#   OVPN_BAN_LOG        OpenVPN log, only read to name the reason of a ban (default /etc/openvpn/audit/openvpn.log)
#
# IPv4 and IPv6 sources are banned in their own chain (iptables and ip6tables). Nothing from the caller reaches a shell:
# IP and FAILURES are validated (python3 ipaddress, strict patterns) and every command is called with a fixed argument vector.

set -u
umask 077

CHAIN4="OVPN_BAN"
CHAIN6="OVPN_BAN6"
IPT4="${OVPN_IPTABLES_BIN:-iptables}"
IPT6="${OVPN_IP6TABLES_BIN:-ip6tables}"
PORT="${OVPN_BAN_PORT:-1194}"
STATE="${OVPN_BAN_STATE:-/etc/openvpn/audit/bans.tsv}"
LOCK="${STATE}.lock"
BANTIME="${OVPN_BAN_BANTIME:-3600}"
OVPN_LOG="${OVPN_BAN_LOG:-/etc/openvpn/audit/openvpn.log}"

die() { echo "ovpn-ban: $*" >&2; exit 1; }

for bin in "$IPT4" "$IPT6"; do
  case "$bin" in
    *[!A-Za-z0-9._-]* | "") die "invalid OVPN_IPTABLES_BIN or OVPN_IP6TABLES_BIN" ;;
  esac
done
case "$BANTIME" in
  *[!0-9]* | "" | 0*) die "invalid OVPN_BAN_BANTIME" ;;
esac
[[ "$PORT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$PORT" -le 65535 ] || die "invalid OVPN_BAN_PORT"

# ipt FAMILY ARGS: iptables (4) or ip6tables (6) with a lock wait
ipt() {
  local fam="$1"; shift
  if [ "$fam" = "6" ]; then "$IPT6" -w 5 "$@"; else "$IPT4" -w 5 "$@"; fi
}

chain_of() { if [ "$1" = "6" ]; then echo "$CHAIN6"; else echo "$CHAIN4"; fi; }

# classify_ip IP: sets FAM (4 or 6) and IP (canonical text form). Accepts only an address that is allowed to be banned:
# refuses 0.x.x.x, unspecified, loopback, link-local, multicast and reserved ranges; an IPv4-mapped IPv6 address is
# treated as the IPv4 address. The address reaches python3 as an argument, never through a shell.
classify_ip() {
  local out
  [[ "$1" =~ ^[0-9A-Fa-f:.]{2,45}$ ]] || return 1
  out="$(python3 -c '
import ipaddress, sys
a = ipaddress.ip_address(sys.argv[1])
if a.version == 6 and a.ipv4_mapped is not None:
    a = a.ipv4_mapped
if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved:
    sys.exit(1)
if a.version == 4 and int(a) >> 24 == 0:
    sys.exit(1)
print(a.version, a)
' "$1" 2>/dev/null)" || return 1
  [[ "$out" =~ ^[46]\ [0-9a-f:.]+$ ]] || return 1
  FAM="${out%% *}"
  IP="${out#* }"
}

valid_posint() { [[ "$1" =~ ^[1-9][0-9]{0,9}$ ]]; }

# ensure_chain FAMILY: chain plus one jump per transport (tcp, udp), both limited to the OpenVPN listener port.
# A concurrent ban may create the chain or a jump between the check and the create: re-check before failing.
ensure_chain() {
  local fam="$1" chain proto
  chain="$(chain_of "$fam")"
  ipt "$fam" -n -L "$chain" >/dev/null 2>&1 || ipt "$fam" -N "$chain" 2>/dev/null || ipt "$fam" -n -L "$chain" >/dev/null 2>&1 || return 1
  for proto in tcp udp; do
    ipt "$fam" -C INPUT -p "$proto" --dport "$PORT" -j "$chain" >/dev/null 2>&1 \
      || ipt "$fam" -I INPUT 1 -p "$proto" --dport "$PORT" -j "$chain" 2>/dev/null \
      || ipt "$fam" -C INPUT -p "$proto" --dport "$PORT" -j "$chain" >/dev/null 2>&1 || return 1
  done
}

# drop_jumps FAMILY: remove the INPUT jumps, scoped ones and the unscoped one that earlier versions created
drop_jumps() {
  local fam="$1" chain proto
  chain="$(chain_of "$fam")"
  for proto in tcp udp; do
    while ipt "$fam" -C INPUT -p "$proto" --dport "$PORT" -j "$chain" >/dev/null 2>&1; do
      ipt "$fam" -D INPUT -p "$proto" --dport "$PORT" -j "$chain" || return 1
    done
  done
  while ipt "$fam" -C INPUT -j "$chain" >/dev/null 2>&1; do
    ipt "$fam" -D INPUT -j "$chain" || return 1
  done
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
  local lines="" kinds=() re
  # the log line starts with "IP:port" or "[AF_INET]IP:port" / "[AF_INET6]IP:port"; the address is only [0-9a-f:.]
  re="(^|[] ])${1//./[.]}:[0-9]+ "
  [ -r "$OVPN_LOG" ] && lines="$(tail -n 5000 "$OVPN_LOG" 2>/dev/null | grep -E "$re" 2>/dev/null || true)"
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

# flush_chains: empty both chains when they exist; fails only when an existing chain cannot be emptied
flush_chains() {
  local fam rc=0
  for fam in 4 6; do
    if ipt "$fam" -n -L "$(chain_of "$fam")" >/dev/null 2>&1; then ipt "$fam" -F "$(chain_of "$fam")" || rc=1; fi
  done
  return "$rc"
}

cmd_init() {
  mkdir -p "$(dirname "$STATE")" || die "cannot create $(dirname "$STATE")"
  flush_chains || die "cannot empty the ban chains"
  with_state_lock do_clear_rows || die "cannot reset $STATE"
}

# setup: IPv4 is required; IPv6 is created when ip6tables works and otherwise reported (an IPv6 ban then fails loudly)
cmd_setup() {
  ensure_chain 4 || die "cannot create chain $CHAIN4 with $IPT4"
  ensure_chain 6 || echo "ovpn-ban: WARNING: cannot create chain $CHAIN6 with $IPT6, IPv6 sources will not be banned" >&2
  return 0
}

cmd_ban() {
  [ "$#" -eq 2 ] || die "usage: ban IP FAILURES"
  classify_ip "$1" || die "refusing to ban: not a public-routable IPv4 or IPv6 address: $1"
  valid_posint "$2" || die "FAILURES must be a positive integer: $2"
  local chain
  chain="$(chain_of "$FAM")"
  ensure_chain "$FAM" || die "cannot create chain $chain"
  ipt "$FAM" -C "$chain" -s "$IP" -j DROP >/dev/null 2>&1 || ipt "$FAM" -A "$chain" -s "$IP" -j DROP || die "cannot add DROP rule for $IP"
  with_state_lock do_ban_row "$IP" "$2" "$(reason_for "$IP")" || die "rule added but cannot update $STATE"
}

cmd_unban() {
  [ "$#" -eq 1 ] || die "usage: unban IP"
  classify_ip "$1" || die "not a valid IPv4 or IPv6 address: $1"
  local rc=0 chain
  chain="$(chain_of "$FAM")"
  # a rule can exist more than once if added by hand: remove all copies; a missing rule or chain is not an error
  while ipt "$FAM" -C "$chain" -s "$IP" -j DROP >/dev/null 2>&1; do
    ipt "$FAM" -D "$chain" -s "$IP" -j DROP || { rc=1; break; }
  done
  with_state_lock do_unban_row "$IP" || rc=1
  return "$rc"
}

cmd_flush() {
  local rc=0
  flush_chains || rc=1
  with_state_lock do_clear_rows || rc=1
  return "$rc"
}

cmd_teardown() {
  local fam rc=0
  for fam in 4 6; do
    drop_jumps "$fam" || rc=1
  done
  cmd_flush || rc=1
  for fam in 4 6; do
    if ipt "$fam" -n -L "$(chain_of "$fam")" >/dev/null 2>&1; then ipt "$fam" -X "$(chain_of "$fam")" || rc=1; fi
  done
  return "$rc"
}

action="${1:-}"
[ "$#" -gt 0 ] && shift
case "$action" in
  init) [ "$#" -eq 0 ] || die "usage: init"; cmd_init ;;
  setup) [ "$#" -eq 0 ] || die "usage: setup"; cmd_setup ;;
  ban) cmd_ban "$@" ;;
  unban) cmd_unban "$@" ;;
  flush) [ "$#" -eq 0 ] || die "usage: flush"; cmd_flush ;;
  teardown) [ "$#" -eq 0 ] || die "usage: teardown"; cmd_teardown ;;
  *) die "usage: $0 init | setup | ban IP FAILURES | unban IP | flush | teardown" ;;
esac
