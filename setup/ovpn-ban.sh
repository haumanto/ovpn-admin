#!/usr/bin/env bash
# Ban enforcement and ban list for the fail2ban jail "ovpn-admin" (called from the fail2ban action, see configure.sh).
#
#   ovpn-ban.sh init             clear the ban list and every DROP rule of both families (container start, before fail2ban starts);
#                                the ban history (ban-history.tsv, see below) is kept
#   ovpn-ban.sh setup            create the OVPN_BAN (IPv4) and OVPN_BAN6 (IPv6) chains and their INPUT jumps (jail start), then restore the
#                                DROP rule and the row (expires_at=0) of every permanent entry of the ban history;
#                                exit 3 when IPv6 is enabled, the IPv6 chain cannot be created and OVPN_BAN_IPV6_REQUIRED is not false
#   ovpn-ban.sh check            verify the chains and jumps of every enforced family; exit 3 = required IPv6 enforcement missing
#   ovpn-ban.sh ban IP FAILURES  DROP IP in OVPN_BAN (IPv4) or OVPN_BAN6 (IPv6) and add (or replace) its row in the ban list;
#                                a new ban then sends the Telegram notification when OVPN_TELEGRAM_ENABLED=true (see below).
#                                Every call counts in the ban history; the OVPN_BAN_REPEAT_COUNT-th ban of the same address is permanent
#                                (row with expires_at=0, no expiry)
#   ovpn-ban.sh ban-manual IP [REASON]  permanent ban at once (DROP rule, row with expires_at=0, history reason "manual" or
#                                "manual: REASON"); REASON is limited to [A-Za-z0-9 ._:-]{0,120}, anything else is refused
#   ovpn-ban.sh unban IP         remove the DROP rule and the row; succeeds when neither exists. A permanent address is left as it is
#                                (success, no change): fail2ban calls this at the end of the jail bantime
#   ovpn-ban.sh unban IP --force remove the DROP rule, the row and the history entry, permanent or not; the address starts clean
#   ovpn-ban.sh flush            remove every DROP rule of both chains and clear the ban list
#   ovpn-ban.sh teardown         remove the INPUT jumps, flush, delete both chains (actionstop, ban engine disabled)
#
# Ban list (read by ovpn-admin): OVPN_BAN_STATE, default /etc/openvpn/audit/bans.tsv, root:root 0600, no header, one
# tab-separated row per active ban: ip, banned_at_unix, expires_at_unix, failures, reason. IPv4 and IPv6 share the file;
# the ip column holds the canonical text form of the address.
# The file is replaced atomically (temp file in the same directory + rename) while holding an flock.
# A permanent ban has expires_at_unix 0 (ovpn-admin versions before the manual-control release skip such a row as malformed).
#
# Ban history: ban-history.tsv next to the ban list, root:root 0600, no header, one row per address that was ever banned (and not
# force-unbanned): ip, ban_count, first_banned_unix, last_banned_unix, permanent (0/1), last_reason, last_failures. It survives
# container restarts (init keeps it); setup restores every permanent=1 entry. Rewritten atomically under the same flock as the ban list.
# A ban that fail2ban re-derives from the log lines right after a container start (within OVPN_BAN_RESTART_GRACE seconds of init) for an
# address whose ban was still running at the restart (or that is permanent) is the same ban, not a new one: it is not counted again.
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
#   OVPN_BAN_REPEAT_COUNT  the Nth ban of the same address is permanent (positive integer, default 2)
#   OVPN_BAN_HISTORY    ban history path (default ban-history.tsv in the directory of OVPN_BAN_STATE)
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
HISTORY="${OVPN_BAN_HISTORY:-$(dirname "$STATE")/ban-history.tsv}"
BOOT_FILE="${STATE}.boot"
BANTIME="${OVPN_BAN_BANTIME:-3600}"
REPEAT="${OVPN_BAN_REPEAT_COUNT:-2}"
RESTART_GRACE=120
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
[[ "$REPEAT" =~ ^[1-9][0-9]{0,9}$ ]] || die "OVPN_BAN_REPEAT_COUNT must be a positive integer: \"$REPEAT\""
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

# write_file FILE: stdin becomes the new content of FILE (atomic rename, 0600)
write_file() {
  local tmp
  tmp="$(mktemp "${1}.XXXXXX")" || return 1
  if cat > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$1"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# write_rows: stdin becomes the new ban list; write_hist: stdin becomes the new ban history
write_rows() { write_file "$STATE"; }
write_hist() { write_file "$HISTORY"; }

# hist_line IP: the history row of IP (empty when there is none); hist_without IP: every other row
hist_line() {
  [ -f "$HISTORY" ] || return 0
  awk -F '\t' -v ip="$1" '$1 == ip { print; exit }' "$HISTORY"
}
hist_without() {
  [ -f "$HISTORY" ] || return 0
  awk -F '\t' -v ip="$1" '$1 != ip' "$HISTORY"
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

# ban_row IP FAILURES REASON BANNED_AT EXPIRES_AT: the ban list with the row of IP added or replaced (the caller holds the lock)
ban_row() {
  {
    rows_without "$1"
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$4" "$5" "$2" "$3"
  } | write_rows
}

# txn_ban IP FAILURES REASON NOW MODE: the history and ban list part of a ban, under the lock. MODE is auto (fail2ban) or manual.
# Prints "PERMANENT NEWLY_PERMANENT EXPIRES_AT" (1/0 flags, expires 0 = never) on stdout.
txn_ban() {
  local ip="$1" fails="$2" reason="$3" now="$4" mode="$5"
  local line prev_n=0 first="$4" last="$4" prev_perm=0 n perm newperm=0 expires boot=0
  line="$(hist_line "$ip")"
  if [ -n "$line" ]; then
    IFS=$'\t' read -r _ prev_n first last prev_perm _ <<< "$line"
    [[ "$prev_n" =~ ^[0-9]{1,10}$ ]] || prev_n=0
    [[ "$first" =~ ^[0-9]{1,12}$ ]] || first="$now"
    [[ "$last" =~ ^[0-9]{1,12}$ ]] || last="$now"
    [ "$prev_perm" = "1" ] || prev_perm=0
  fi
  if [ "$mode" = "manual" ]; then
    n="$prev_n"
    [ "$prev_perm" = "1" ] || n=$((prev_n + 1))
    last="$now"
    perm=1
  else
    n=$((prev_n + 1))
    if [ -n "$line" ]; then
      [ -r "$BOOT_FILE" ] && read -r boot < "$BOOT_FILE" 2>/dev/null
      [[ "$boot" =~ ^[0-9]{1,12}$ ]] || boot=0
      # fail2ban re-derives the ban from the log right after a container start: the same ban, not a new one
      if [ "$boot" -gt 0 ] && [ "$((now - boot))" -le "$RESTART_GRACE" ] && [ "$last" -lt "$boot" ] \
        && { [ "$prev_perm" = "1" ] || [ "$((last + BANTIME))" -gt "$boot" ]; }; then
        n="$prev_n"
      else
        last="$now"
      fi
    fi
    perm="$prev_perm"
    [ "$n" -ge "$REPEAT" ] && perm=1
  fi
  [ "$perm" = "1" ] && [ "$prev_perm" = "0" ] && newperm=1
  expires=$((now + BANTIME))
  [ "$perm" = "1" ] && expires=0
  {
    hist_without "$ip"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$n" "$first" "$last" "$perm" "$reason" "$fails"
  } | write_hist || return 1
  ban_row "$ip" "$fails" "$reason" "$now" "$expires" || return 1
  echo "$perm $newperm $expires"
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

# fw_remove FAMILY IP: remove every DROP rule of IP (a rule can exist more than once if added by hand); a missing rule or chain is not an error
fw_remove() {
  local fam="$1" ip="$2" chain
  chain="$(chain_of "$fam")"
  while ipt "$fam" -C "$chain" -s "$ip" -j DROP >/dev/null 2>&1; do
    ipt "$fam" -D "$chain" -s "$ip" -j DROP || return 1
  done
  return 0
}

# txn_unban IP FAMILY FORCE: under the lock. A permanent address (history flag, or a row without expiry) is kept unless FORCE=1.
txn_unban() {
  local ip="$1" fam="$2" force="$3" line perm=0 rowexp
  line="$(hist_line "$ip")"
  if [ -n "$line" ]; then
    IFS=$'\t' read -r _ _ _ _ perm _ <<< "$line"
  fi
  if [ "$perm" != "1" ] && [ -f "$STATE" ]; then
    rowexp="$(awk -F '\t' -v ip="$ip" '$1 == ip { print $3; exit }' "$STATE")"
    [ "$rowexp" = "0" ] && perm=1
  fi
  if [ "$perm" = "1" ] && [ "$force" != "1" ]; then
    echo "ovpn-ban: $ip is permanently banned, unban ignored (use unban $ip --force)" >&2
    return 0
  fi
  fw_remove "$fam" "$ip" || return 1
  rows_without "$ip" | write_rows || return 1
  if [ "$force" = "1" ] && [ -n "$line" ]; then
    hist_without "$ip" | write_hist || return 1
  fi
  return 0
}

do_clear_rows() { : | write_rows; }

# flush_chains: empty both chains when they exist; fails only when an existing chain cannot be emptied
flush_chains() {
  local fam rc=0
  for fam in 4 6; do
    if ipt "$fam" -n -L "$(chain_of "$fam")" >/dev/null 2>&1; then ipt "$fam" -F "$(chain_of "$fam")" || rc=1; fi
  done
  return "$rc"
}

# init: DROP rules and ban list are cleared, the ban history stays; the start time is recorded for the restart rule of txn_ban
cmd_init() {
  mkdir -p "$(dirname "$STATE")" || die "cannot create $(dirname "$STATE")"
  flush_chains || die "cannot empty the ban chains"
  with_state_lock do_clear_rows || die "cannot reset $STATE"
  date +%s | write_file "$BOOT_FILE" || die "cannot write $BOOT_FILE"
}

# restore_permanent: DROP rule and row (expires_at=0) for every permanent entry of the history, under the lock.
# An address whose family has no chain (IPv6 not enforced) is skipped with a warning; a failing entry never stops the others.
restore_permanent() {
  local line ip n first last perm reason fails fam chain count=0 skipped=0
  [ -f "$HISTORY" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    IFS=$'\t' read -r ip n first last perm reason fails <<< "$line"
    [ "$perm" = "1" ] || continue
    if ! classify_ip "$ip"; then
      echo "ovpn-ban: WARNING: permanent entry skipped, not a bannable address: $ip" >&2
      skipped=$((skipped + 1))
      continue
    fi
    fam="$FAM"
    chain="$(chain_of "$fam")"
    if [ "$fam" = "6" ] && [ "$V6" != "true" ]; then
      echo "ovpn-ban: WARNING: permanent ban of $IP NOT restored: IPv6 is not enabled" >&2
      skipped=$((skipped + 1))
      continue
    fi
    if ! ensure_chain "$fam"; then
      echo "ovpn-ban: WARNING: permanent ban of $IP NOT restored: chain $chain is not available" >&2
      skipped=$((skipped + 1))
      continue
    fi
    if ! ipt "$fam" -C "$chain" -s "$IP" -j DROP >/dev/null 2>&1; then
      ipt "$fam" -A "$chain" -s "$IP" -j DROP || { echo "ovpn-ban: WARNING: cannot restore the DROP rule of $IP" >&2; skipped=$((skipped + 1)); continue; }
    fi
    [[ "$last" =~ ^[1-9][0-9]{0,11}$ ]] || last="$(date +%s)"
    [[ "$fails" =~ ^[0-9]{1,10}$ ]] || fails=0
    [ -n "$reason" ] || reason="restored"
    ban_row "$IP" "$fails" "$reason" "$last" 0 || { echo "ovpn-ban: WARNING: cannot restore the row of $IP" >&2; skipped=$((skipped + 1)); continue; }
    count=$((count + 1))
  done < "$HISTORY"
  echo "ovpn-ban: restored $count permanent ban(s)$([ "$skipped" -gt 0 ] && echo ", $skipped skipped")" >&2
  return 0
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
  with_state_lock restore_permanent || echo "ovpn-ban: WARNING: restoring the permanent bans failed" >&2
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

# do_ban IP FAILURES REASON MODE: the common part of ban and ban-manual (IP already classified: FAM and IP are set)
do_ban() {
  local ip="$1" fails="$2" reason="$3" mode="$4" chain now added=0 out perm newperm expires
  need_listener
  chain="$(chain_of "$FAM")"
  ensure_chain "$FAM" || die "cannot create chain $chain"
  if ! ipt "$FAM" -C "$chain" -s "$ip" -j DROP >/dev/null 2>&1; then
    ipt "$FAM" -A "$chain" -s "$ip" -j DROP || die "cannot add DROP rule for $ip"
    added=1
  fi
  now="$(date +%s)"
  out="$(with_state_lock txn_ban "$ip" "$fails" "$reason" "$now" "$mode")" || die "rule added but cannot update $STATE or $HISTORY"
  read -r perm newperm expires <<< "$out"
  [[ "$expires" =~ ^[0-9]{1,12}$ ]] || die "internal error: unexpected result of the ban transaction"
  # a new ban (the address had no DROP rule) or a ban that just became permanent is announced once; an address that already had its
  # DROP rule and stays what it was is not announced again. The ban is complete at this point.
  if [ "$added" -eq 1 ] || [ "$newperm" = "1" ]; then
    notify_ban "$ip" "$fails" "$reason" "$expires"
  fi
  if [ "$perm" = "1" ]; then echo "ovpn-ban: $ip banned permanently" >&2; fi
  return 0
}

cmd_ban() {
  [ "$#" -eq 2 ] || die "usage: ban IP FAILURES"
  classify_ip "$1" || die "refusing to ban: not a public-routable IPv4 or IPv6 address: $1"
  valid_posint "$2" || die "FAILURES must be a positive integer: $2"
  do_ban "$IP" "$2" "$(reason_for "$IP")" auto
}

# ban-manual IP [REASON]: permanent at once. REASON: [A-Za-z0-9 ._:-]{0,120}; the history and the notification carry "manual" or "manual: REASON"
cmd_ban_manual() {
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "usage: ban-manual IP [REASON]"
  local note="${2:-}"
  classify_ip "$1" || die "refusing to ban: not a public-routable IPv4 or IPv6 address: $1"
  [[ "$note" =~ ^[A-Za-z0-9\ ._:-]{0,120}$ ]] || die "REASON must match [A-Za-z0-9 ._:-]{0,120}"
  note="${note#"${note%%[! ]*}"}"
  note="${note%"${note##*[! ]}"}"
  if [ -n "$note" ]; then do_ban "$IP" 0 "manual: $note" manual; else do_ban "$IP" 0 "manual" manual; fi
}

# unban IP [--force]: see the header. A permanent address needs --force.
cmd_unban() {
  local force=0
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "usage: unban IP [--force]"
  if [ "$#" -eq 2 ]; then
    [ "$2" = "--force" ] || die "usage: unban IP [--force]"
    force=1
  fi
  classify_ip "$1" || die "not a valid IPv4 or IPv6 address: $1"
  with_state_lock txn_unban "$IP" "$FAM" "$force"
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
  ban-manual) cmd_ban_manual "$@" ;;
  unban) cmd_unban "$@" ;;
  flush) [ "$#" -eq 0 ] || die "usage: flush"; cmd_flush ;;
  teardown) [ "$#" -eq 0 ] || die "usage: teardown"; cmd_teardown ;;
  *) die "usage: $0 init | setup | check | ban IP FAILURES | ban-manual IP [REASON] | unban IP [--force] | flush | teardown" ;;
esac
