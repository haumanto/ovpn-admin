#!/usr/bin/env bash
# Ban enforcement and ban list for the fail2ban jail "ovpn-admin" (called from the fail2ban action, see configure.sh).
#
#   ovpn-ban.sh init             clear the ban list and every DROP rule of both families (container start, before fail2ban starts)
#   ovpn-ban.sh setup            create the OVPN_BAN (IPv4) and OVPN_BAN6 (IPv6) chains and their INPUT jumps (jail start);
#                                exit 3 when IPv6 is enabled, the IPv6 chain cannot be created and OVPN_BAN_IPV6_REQUIRED is not false
#   ovpn-ban.sh check            verify the chains and jumps of every enforced family; exit 3 = required IPv6 enforcement missing
#   ovpn-ban.sh ban IP FAILURES  DROP IP in OVPN_BAN (IPv4) or OVPN_BAN6 (IPv6) and add (or replace) its row in the ban list;
#                                a new ban then sends the Telegram notification when OVPN_TELEGRAM_ENABLED=true (see below)
#   ovpn-ban.sh unban IP         remove the DROP rule and the row; succeeds when neither exists
#   ovpn-ban.sh flush            remove every DROP rule of both chains and clear the ban list
#   ovpn-ban.sh teardown         remove the INPUT jumps, flush, delete both chains (actionstop, ban engine disabled)
#
# Ban list (read by ovpn-admin): OVPN_BAN_STATE, default /etc/openvpn/audit/bans.tsv, root:root 0600, no header, one
# tab-separated row per active ban: ip, banned_at_unix, expires_at_unix, failures, reason. IPv4 and IPv6 share the file;
# the ip column holds the canonical text form of the address.
# The file is replaced atomically (temp file in the same directory + rename) while holding an flock.
#
# Scope: the INPUT chain jumps to the ban chains only for the OpenVPN listener: the port and transport that configure.sh
# derives from the same variables as the openvpn command line. Other listeners in the same network namespace, such as the
# ovpn-admin port (OVPN_LISTEN_PORT, 8080), are never behind a ban; a listener port equal to the admin port is refused.
#
# Environment (OVPN_BAN_PORT, OVPN_BAN_PROTOS, OVPN_BAN_IPV6 are set by configure.sh, never by hand; there is no default):
#   OVPN_IPTABLES_BIN   iptables binary for IPv4 (default iptables; iptables-legacy on older Docker hosts), same selector as configure.sh
#   OVPN_IP6TABLES_BIN  ip6tables binary for IPv6 (default ip6tables; set ip6tables-legacy together with iptables-legacy)
#   OVPN_BAN_PORT       OpenVPN listener port inside the container that the bans apply to (derived from OVPN_SERVER_PORT)
#   OVPN_BAN_PROTOS     transports of the listener, "tcp" or "udp" (derived from OVPN_PROTO)
#   OVPN_BAN_IPV6       true when the listener or the tunnel has IPv6 (OVPN_PROTO tcp6/udp6 or OVPN_SERVER_NET6), default false
#   OVPN_BAN_IPV6_REQUIRED  default true: with IPv6 on, a missing IPv6 ban chain stops setup (exit 3); false = loud warning, continue
#   OVPN_LISTEN_PORT   ovpn-admin port of the shared network namespace (default 8080), never allowed as the ban port
#   OVPN_BAN_STATE      ban list path
#   OVPN_BAN_BANTIME    seconds a ban lasts, used for expires_at_unix (default 3600)
#   OVPN_BAN_LOG        OpenVPN log, only read to name the reason of a ban (default /etc/openvpn/audit/openvpn.log)
#   OVPN_BAN_NOTIFY_LOG  file that receives the warning when a Telegram notification fails (set by configure.sh to the fail2ban log)
#   OVPN_TELEGRAM_ENABLED  set by configure.sh (true only when the Telegram settings are valid); with true, a successful new ban
#                       runs /usr/local/sbin/ovpn-telegram-notify IP FAILURES REASON EXPIRES_AT after the DROP rule and the row are
#                       written. The bot token and chat id reach the notifier through its environment only (inherited from the
#                       fail2ban server, set by configure.sh), never through an argument. A notifier failure is one warning in the
#                       fail2ban log, which the container log mirrors; the ban stays successful and the exit status is not affected. No notification on unban.
#
# IPv4 and IPv6 sources are banned in their own chain (iptables and ip6tables). Nothing from the caller reaches a shell:
# IP and FAILURES are validated (python3 ipaddress, strict patterns) and every command is called with a fixed argument vector.

set -u
umask 077

CHAIN4="OVPN_BAN"
CHAIN6="OVPN_BAN6"
IPT4="${OVPN_IPTABLES_BIN:-iptables}"
IPT6="${OVPN_IP6TABLES_BIN:-ip6tables}"
PORT="${OVPN_BAN_PORT:-}"
PROTOS="${OVPN_BAN_PROTOS:-}"
V6="${OVPN_BAN_IPV6:-false}"
V6_REQUIRED="${OVPN_BAN_IPV6_REQUIRED:-true}"
ADMIN_PORT="${OVPN_LISTEN_PORT:-8080}"
MGMT_PORT="8989"
STATE="${OVPN_BAN_STATE:-/etc/openvpn/audit/bans.tsv}"
LOCK="${STATE}.lock"
BANTIME="${OVPN_BAN_BANTIME:-3600}"
OVPN_LOG="${OVPN_BAN_LOG:-/etc/openvpn/audit/openvpn.log}"
NOTIFY_BIN="/usr/local/sbin/ovpn-telegram-notify"
NOTIFY_LOG="${OVPN_BAN_NOTIFY_LOG:-}"

die() { echo "ovpn-ban: $*" >&2; exit 1; }

for bin in "$IPT4" "$IPT6"; do
  case "$bin" in
    *[!A-Za-z0-9._-]* | "") die "invalid OVPN_IPTABLES_BIN or OVPN_IP6TABLES_BIN" ;;
  esac
done
case "$BANTIME" in
  *[!0-9]* | "" | 0*) die "invalid OVPN_BAN_BANTIME" ;;
esac
for flag in "$V6" "$V6_REQUIRED"; do
  case "$flag" in true | false) ;; *) die "OVPN_BAN_IPV6 and OVPN_BAN_IPV6_REQUIRED must be true or false" ;; esac
done

# need_listener: the ports of the jumps come from configure.sh only; refuse anything that is not a valid listener scope.
# Commands that create or check jumps call this first, so a missing or wrong value fails instead of scoping a jump somewhere else.
need_listener() {
  local p
  [[ "$PORT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$PORT" -le 65535 ] || die "OVPN_BAN_PORT is not a valid listener port (set by configure.sh from OVPN_SERVER_PORT): \"$PORT\""
  if [ "$PORT" = "$ADMIN_PORT" ] || [ "$PORT" = "$MGMT_PORT" ]; then
    die "refusing to scope the ban jump to port $PORT: it is the ovpn-admin or OpenVPN management port"
  fi
  [ -n "$PROTOS" ] || die "OVPN_BAN_PROTOS is empty (set by configure.sh from OVPN_PROTO)"
  for p in $PROTOS; do
    case "$p" in tcp | udp) ;; *) die "invalid transport in OVPN_BAN_PROTOS: $p" ;; esac
  done
}

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

# ensure_chain FAMILY: chain plus one jump per listener transport, limited to the OpenVPN listener port.
# A concurrent ban may create the chain or a jump between the check and the create: re-check before failing.
ensure_chain() {
  local fam="$1" chain proto
  chain="$(chain_of "$fam")"
  ipt "$fam" -n -L "$chain" >/dev/null 2>&1 || ipt "$fam" -N "$chain" 2>/dev/null || ipt "$fam" -n -L "$chain" >/dev/null 2>&1 || return 1
  for proto in $PROTOS; do
    ipt "$fam" -C INPUT -p "$proto" --dport "$PORT" -j "$chain" >/dev/null 2>&1 \
      || ipt "$fam" -I INPUT 1 -p "$proto" --dport "$PORT" -j "$chain" 2>/dev/null \
      || ipt "$fam" -C INPUT -p "$proto" --dport "$PORT" -j "$chain" >/dev/null 2>&1 || return 1
  done
}

# jumps_ok FAMILY: the chain exists and has its INPUT jump for every listener transport
jumps_ok() {
  local fam="$1" chain proto
  chain="$(chain_of "$fam")"
  ipt "$fam" -n -L "$chain" >/dev/null 2>&1 || return 1
  for proto in $PROTOS; do
    ipt "$fam" -C INPUT -p "$proto" --dport "$PORT" -j "$chain" >/dev/null 2>&1 || return 1
  done
}

# drop_jumps FAMILY: remove every INPUT jump to the ban chain, whatever its port or transport (also those of an earlier
# configuration in a reused network namespace). The rule text comes from the firewall itself ("-S"), so the match is on the target only.
drop_jumps() {
  local fam="$1" chain rule
  local -a args
  chain="$(chain_of "$fam")"
  while rule="$(ipt "$fam" -S INPUT 2>/dev/null | grep -m1 -E -- " -j ${chain}\$")" && [ -n "$rule" ]; do
    read -r -a args <<< "${rule/#-A /-D }"
    ipt "$fam" "${args[@]}" || return 1
  done
  return 0
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
  # after the timestamp the log line starts with "IP:port", "[AF_INET]IP:port" / "[AF_INET6]IP:port" or, as OpenVPN 2.7 writes it,
  # "<proto>:IP:port" / "<proto>:[IPv6]:port" (tcp6-server:172.20.0.41:33392, udp6:[fd00::61]:49031); the address is only [0-9a-f:.]
  re="(^|[] ]|(tcp|udp)[46]?(-server)?:)\\[?${1//./[.]}\\]?:[0-9]+ "
  [ -r "$OVPN_LOG" ] && lines="$(tail -n 5000 "$OVPN_LOG" 2>/dev/null | grep -E "$re" 2>/dev/null || true)"
  case "$lines" in *"certificate revoked"*) kinds+=("revoked-certificate") ;; esac
  case "$lines" in *"AUTH_FAILED"*) kinds+=("auth-failed") ;; esac
  case "${#kinds[@]}" in
    0) echo "fail2ban" ;;
    1) echo "${kinds[0]}" ;;
    *) echo "${kinds[0]}+${kinds[1]}" ;;
  esac
}

do_ban_row() { # ip failures reason now
  {
    rows_without "$1"
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$4" "$(($4 + BANTIME))" "$2" "$3"
  } | write_rows
}

# notify_ban IP FAILURES REASON EXPIRES_AT: Telegram message for a new ban (see the header). Never fails the caller. fail2ban does
# not log the stderr of a successful action, so a warning of the notifier is appended to OVPN_BAN_NOTIFY_LOG (the fail2ban log,
# which the container mirrors to its log; set by configure.sh) and also written to our own stderr (visible to a manual caller).
# The notifier prints at most one line, never the token or a response body; the line is cut to its first 300 characters.
notify_ban() {
  local rc=0 msg=""
  [ "${OVPN_TELEGRAM_ENABLED:-false}" = "true" ] || return 0
  if [ ! -x "$NOTIFY_BIN" ]; then
    msg="ovpn-ban: WARNING: Telegram notification for $1 not sent: $NOTIFY_BIN is not installed"
  else
    msg="$(timeout 20 "$NOTIFY_BIN" "$@" 2>&1 </dev/null)" || rc=$?
    if [ "$rc" -gt 2 ]; then msg="ovpn-ban: WARNING: Telegram notification for $1 failed (notifier exit $rc)"; fi
  fi
  msg="${msg%%$'\n'*}"
  [ -n "$msg" ] || return 0
  msg="${msg:0:300}"
  echo "$msg" >&2
  if [ -n "$NOTIFY_LOG" ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') $msg" >>"$NOTIFY_LOG" 2>/dev/null || true; fi
  return 0
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

# setup: IPv4 is always required. IPv6 is required whenever it is enabled (OVPN_BAN_IPV6=true): a missing IPv6 chain exits 3
# unless OVPN_BAN_IPV6_REQUIRED=false, which is the single opt-out and warns loudly.
cmd_setup() {
  need_listener
  ensure_chain 4 || die "cannot create chain $CHAIN4 with $IPT4"
  if [ "$V6" = "true" ]; then
    if ! ensure_chain 6; then
      if [ "$V6_REQUIRED" = "true" ]; then
        echo "ovpn-ban: ERROR: IPv6 is enabled but the IPv6 ban chain $CHAIN6 cannot be created with $IPT6: IPv6 sources could not be banned. Fix ip6tables (or OVPN_IP6TABLES_BIN), or set OVPN_BAN_IPV6_REQUIRED=false to run without IPv6 bans." >&2
        exit 3
      fi
      echo "ovpn-ban: WARNING: ################ OVPN_BAN_IPV6_REQUIRED=false: IPv6 is enabled but chain $CHAIN6 cannot be created with $IPT6; IPv6 sources are NOT banned ################" >&2
    fi
  fi
  return 0
}

# check: running state of the enforcement (chains and jumps present). Exit 3: required IPv6 enforcement missing; 1: IPv4 missing.
cmd_check() {
  need_listener
  jumps_ok 4 || die "IPv4 ban chain $CHAIN4 or its jump for $PROTOS port $PORT is missing"
  if [ "$V6" = "true" ] && [ "$V6_REQUIRED" = "true" ]; then
    jumps_ok 6 || { echo "ovpn-ban: ERROR: IPv6 is enabled but chain $CHAIN6 or its jump for $PROTOS port $PORT is missing" >&2; exit 3; }
    echo "ovpn-ban: check ok: IPv4 and IPv6 enforce $PROTOS port $PORT"
  elif [ "$V6" = "true" ]; then
    jumps_ok 6 && echo "ovpn-ban: check ok: IPv4 and IPv6 enforce $PROTOS port $PORT" \
      || echo "ovpn-ban: check ok: IPv4 enforces $PROTOS port $PORT; IPv6 is NOT enforced (OVPN_BAN_IPV6_REQUIRED=false)"
  else
    echo "ovpn-ban: check ok: IPv4 enforces $PROTOS port $PORT (IPv6 off)"
  fi
}

cmd_ban() {
  [ "$#" -eq 2 ] || die "usage: ban IP FAILURES"
  classify_ip "$1" || die "refusing to ban: not a public-routable IPv4 or IPv6 address: $1"
  valid_posint "$2" || die "FAILURES must be a positive integer: $2"
  local chain now reason added=0
  need_listener
  chain="$(chain_of "$FAM")"
  ensure_chain "$FAM" || die "cannot create chain $chain"
  if ! ipt "$FAM" -C "$chain" -s "$IP" -j DROP >/dev/null 2>&1; then
    ipt "$FAM" -A "$chain" -s "$IP" -j DROP || die "cannot add DROP rule for $IP"
    added=1
  fi
  now="$(date +%s)"
  reason="$(reason_for "$IP")"
  with_state_lock do_ban_row "$IP" "$2" "$reason" "$now" || die "rule added but cannot update $STATE"
  # a new ban only (an address that already had its DROP rule is not announced again); the ban is complete at this point
  if [ "$added" -eq 1 ]; then
    notify_ban "$IP" "$2" "$reason" "$((now + BANTIME))"
  fi
  return 0
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
  check) [ "$#" -eq 0 ] || die "usage: check"; cmd_check ;;
  ban) cmd_ban "$@" ;;
  unban) cmd_unban "$@" ;;
  flush) [ "$#" -eq 0 ] || die "usage: flush"; cmd_flush ;;
  teardown) [ "$#" -eq 0 ] || die "usage: teardown"; cmd_teardown ;;
  *) die "usage: $0 init | setup | check | ban IP FAILURES | unban IP | flush | teardown" ;;
esac
