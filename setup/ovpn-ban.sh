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
# Locking: every command that changes the firewall chains or the ban list/history (init, setup, check, ban, ban-manual, unban, flush,
# teardown) does so inside ONE exclusive flock (OVPN_BAN_STATE.lock, wait at most 30 s): the firewall check/add and the state decision of a
# ban are one critical section, so an expiry unban can never run between "DROP rule exists" and "row/history say permanent". The Telegram
# notification runs after the lock is released.
#
# Removal journal (force-unban recovery): OVPN_BAN_STATE.removals, root:root 0600, one canonical address per line. unban IP --force first
# records the address there (atomic write; this is the commit point of the removal), then removes the DROP rule (absence verified, a firewall
# read error is a failure, never "absent"), the row and the history entry, verifies all three, and only then clears the journal line. A
# crash, a failed write or an unreadable ban list or history at any step leaves the journal line behind; the next ban-engine operation (setup,
# check, ban, ban-manual, unban) completes the removal first (it converges to a clean removal once the files are readable), and restore never
# re-adds a journaled address (an unreadable journal fails restore instead). Outcomes: before the journal write, nothing changed and the
# caller got an error; from the journal write on, the address ends up unbanned and absent from history, whatever the caller was told.
# A new ban of a journaled address supersedes the pending removal.
#
# Restore and readiness: setup returns non-zero when a permanent entry of an enforced family cannot be restored (exit 3 when the failing
# family is IPv6 with OVPN_BAN_IPV6_REQUIRED=true, 1 otherwise). The intentional opt-outs (OVPN_BAN_IPV6=false, or
# OVPN_BAN_IPV6_REQUIRED=false with no usable IPv6 chain) are warnings, not failures. check also verifies, for every permanent history entry,
# that its DROP rule and a PERMANENT row (expires_at=0; a temporary row of the address does not count) exist; a missing one is reconciled once
# (the same restore, which replaces the row) and fails check (same exit codes) if it stays missing. A healthy check changes nothing.
# Both setup and check need a successful enumeration of the permanent history: a history file that does not exist (first start) has no
# entries and is fine, one that exists but cannot be read (permissions, a directory in its place, an I/O error) fails setup and check with
# exit 1, so readiness is degraded, and nothing is restored from it.
#
# State file reads: the ban list, the history and the removal journal are read with an explicit result (present / absent / error). A file
# that exists but cannot be read is "state unknown", never "empty" or "absent". A replacement of one of these files (publish) is written to a
# temporary file and renamed only after the old content was read completely and the new content produced without error, so an unreadable
# input can never wipe a file or acknowledge a removal. Without --force an unban whose permanence decision needs an unreadable file fails
# without changing anything; a forced unban keeps its journal line (see above) and the next operation repeats the removal.
#
# Firewall reads (fw_has): "iptables -C" status 0 = rule present; status 1 is not taken for "absent" on its own: the chain listing ("-S chain")
# is read and searched for the rule "-A chain -s IP[/32|/128] -j DROP" (listed = present, readable and not listed = absent, listing
# unreadable: absent only when the whole ruleset is readable and has no such chain); any other status = state unknown (error).
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
REMOVALS="${STATE}.removals"
LOCK_WAIT=30
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

# with_state_lock CMD [ARGS]: runs CMD while holding the exclusive lock of the ban list (the one lock for the firewall chains, the
# ban list, the history and the removal journal). Fails without running CMD when the lock is not free within LOCK_WAIT seconds.
# The wait is a poll (flock -n every 0.2 s, at most LOCK_WAIT seconds) because the BusyBox flock of the Alpine image has no -w, and
# "timeout N flock" there leaves a helper process holding the descriptor for a moment after the critical section. The lock belongs to the
# open file description of fd 9, so it is held by this subshell after the short-lived flock process has exited.
with_state_lock() {
  (
    local tries=0
    until flock -n -x 9; do
      tries=$((tries + 1))
      if [ "$tries" -gt $((LOCK_WAIT * 5)) ]; then echo "ovpn-ban: cannot take the state lock $LOCK" >&2; exit 1; fi
      sleep 0.2
    done
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

# publish FILE CMD [ARGS]: the new content of FILE is the output of CMD. FILE is replaced (atomic rename, 0600) only when CMD succeeded, so
# a producer that fails half way (a read error of the old content) can never publish partial content. Returns 1 and leaves FILE as it was
# otherwise. Pipelines are not used for replacements: their status would be the one of the writer and hide the one of the producer.
publish() {
  local f="$1" tmp
  shift
  tmp="$(mktemp "${f}.XXXXXX")" || return 1
  if "$@" > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$f"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# file_state FILE: what a read of FILE would see. 0 = a regular file that opens for reading; 1 = FILE does not exist (and every directory on
# the way can be searched); 2 = anything else (a directory or other non-regular file, no read permission, a directory that cannot be
# searched, a dangling link): the content is unknown. 2 is never to be treated as "empty" or "absent".
file_state() {
  local f="$1" d
  if [ -e "$f" ] || [ -L "$f" ]; then
    [ -f "$f" ] && [ -r "$f" ] && { : < "$f"; } 2>/dev/null && return 0
    return 2
  fi
  d="$(dirname -- "$f")"
  while :; do
    if [ -e "$d" ] || [ -L "$d" ]; then
      [ -d "$d" ] && [ -x "$d" ] && return 1
      return 2
    fi
    d="$(dirname -- "$d")"
  done
}

# Readers of the ban list, the history and the removal journal. Every one returns 0 when the file was read completely or does not exist
# (a first start: no entries), and 2 when it exists but cannot be read (state unknown, never "empty"). Output is only trusted with status 0.
#   hist_line IP     the history row of IP (no output when there is none)
#   hist_without IP  every other history row;  rows_without IP  every other ban list row
#   read_all FILE    the whole file (callers take it into a variable and check the status before looping over it)
read_rows() { # FILE MODE IP: MODE line = the first row of IP, MODE others = every row except those of IP
  local f="$1" mode="$2" ip="$3" st=0
  file_state "$f" || st=$?
  [ "$st" -eq 1 ] && return 0
  [ "$st" -eq 0 ] || return 2
  if [ "$mode" = "line" ]; then
    awk -F '\t' -v ip="$ip" '$1 == ip { print; exit }' "$f" || return 2
  else
    awk -F '\t' -v ip="$ip" '$1 != ip' "$f" || return 2
  fi
}
read_all() {
  local st=0
  file_state "$1" || st=$?
  [ "$st" -eq 1 ] && return 0
  [ "$st" -eq 0 ] || return 2
  cat -- "$1" || return 2
}
hist_line() { read_rows "$HISTORY" line "$1"; }
hist_without() { read_rows "$HISTORY" others "$1"; }
rows_without() { read_rows "$STATE" others "$1"; }

# row_kind IP: what the ban list says about IP: "none" (no row), "perm" (every row of IP has expires_at 0), "temp" (a row with an expiry).
# Status 2 when the ban list cannot be read. Only a "perm" row satisfies a permanent entry.
row_kind() {
  local st=0
  file_state "$STATE" || st=$?
  [ "$st" -eq 1 ] && { echo none; return 0; }
  [ "$st" -eq 0 ] || return 2
  awk -F '\t' -v ip="$1" '$1 == ip { f = 1; if ($3 != "0") bad = 1 } END { print (!f ? "none" : (bad ? "temp" : "perm")) }' "$STATE" || return 2
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

# rows_with IP FAILURES REASON BANNED_AT EXPIRES_AT: the ban list content with the row of IP added or replaced (a producer for publish)
rows_with() {
  rows_without "$1" || return 1
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$4" "$5" "$2" "$3"
}

# ban_row IP FAILURES REASON BANNED_AT EXPIRES_AT: replace (or add) the row of IP (the caller holds the lock); fails, leaving the ban list
# as it was, when the current ban list cannot be read completely
ban_row() { publish "$STATE" rows_with "$@"; }

# hist_with IP N FIRST LAST PERM REASON FAILURES: the history content with the row of IP added or replaced (a producer for publish)
hist_with() {
  hist_without "$1" || return 1
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$@"
}

# txn_ban IP FAILURES REASON NOW MODE: the history and ban list part of a ban, under the lock. MODE is auto (fail2ban) or manual.
# Prints "PERMANENT NEWLY_PERMANENT EXPIRES_AT" (1/0 flags, expires 0 = never) on stdout.
txn_ban() {
  local ip="$1" fails="$2" reason="$3" now="$4" mode="$5"
  local line prev_n=0 first="$4" last="$4" prev_perm=0 n perm newperm=0 expires boot=0
  line="$(hist_line "$ip")" || { echo "ovpn-ban: cannot read the ban history $HISTORY: $ip not recorded" >&2; return 1; }
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
  publish "$HISTORY" hist_with "$ip" "$n" "$first" "$last" "$perm" "$reason" "$fails" || return 1
  # 2 = the history (authoritative for permanence) is written, the row is not: setup/check restore the row of a permanent entry
  ban_row "$ip" "$fails" "$reason" "$now" "$expires" || return 2
  echo "$perm $newperm $expires"
}

# txn_ban_fw IP FAILURES REASON MODE FAMILY: the whole ban in ONE critical section (the caller holds the lock): complete a pending
# removal, check/add the DROP rule, decide and record permanence (txn_ban). The firewall check and the state decision can therefore not
# be separated by an unban of the same address. Prints "PERMANENT NEWLY_PERMANENT EXPIRES_AT ADDED" on stdout. When the history cannot
# be written, a rule added here is taken out again; a firewall read error refuses the ban.
txn_ban_fw() {
  local ip="$1" fails="$2" reason="$3" mode="$4" fam="$5" chain now out rc added=0
  chain="$(chain_of "$fam")"
  reconcile_removals || echo "ovpn-ban: WARNING: a pending removal could not be completed yet" >&2
  removal_has "$ip"; rc=$?
  case "$rc" in
    0) removal_drop "$ip" || { echo "ovpn-ban: cannot clear the pending removal of $ip: not banned" >&2; return 1; } ;;
    1) ;;
    *) echo "ovpn-ban: cannot read the removal journal $REMOVALS: $ip not banned" >&2; return 1 ;;
  esac
  ensure_chain "$fam" || { echo "ovpn-ban: cannot create chain $chain" >&2; return 1; }
  fw_has "$fam" "$ip"; rc=$?
  case "$rc" in
    0) ;;
    1) ipt "$fam" -A "$chain" -s "$ip" -j DROP || { echo "ovpn-ban: cannot add DROP rule for $ip" >&2; return 1; }
       added=1 ;;
    *) echo "ovpn-ban: cannot read chain $chain of the firewall: $ip not banned" >&2; return 1 ;;
  esac
  now="$(date +%s)"
  out="$(txn_ban "$ip" "$fails" "$reason" "$now" "$mode")"; rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ "$rc" -eq 1 ] && [ "$added" -eq 1 ]; then
      fw_remove "$fam" "$ip" || echo "ovpn-ban: WARNING: the DROP rule of $ip stays although the history could not be written" >&2
    fi
    echo "ovpn-ban: cannot update $STATE or $HISTORY for $ip" >&2
    return 1
  fi
  echo "$out $added"
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

# fw_listed CHAIN IP: reads "iptables -S CHAIN" on stdin; 0 when it lists the rule "-A CHAIN -s IP -j DROP" (the source printed as IP, IP/32 or
# IP/128, no other match: the shape ovpn-ban.sh adds and "-C -s IP -j DROP" asks for)
fw_listed() {
  awk -v chain="$1" -v ip="$2" '
    $1 == "-A" && $2 == chain && NF == 6 && $3 == "-s" && $5 == "-j" && $6 == "DROP" && ($4 == ip || $4 == ip "/32" || $4 == ip "/128") { found = 1 }
    END { exit !found }'
}

# fw_has FAMILY IP: is there a DROP rule for IP? 0 = present, 1 = verified absent (the chain listing was read and has no such rule, or the whole
# ruleset can be read and has no such chain), 2 = the firewall cannot be read (state unknown, never to be treated as absent).
# "iptables -C" exits 1 for a missing rule and also for a missing chain, and a backend is not trusted to use 1 for nothing else: after status 1
# the chain listing ("-S chain") is read and searched for the rule. A rule that "-C" did not find but the listing shows counts as present.
fw_has() {
  local fam="$1" ip="$2" chain rc all listing
  chain="$(chain_of "$fam")"
  ipt "$fam" -C "$chain" -s "$ip" -j DROP >/dev/null 2>&1 && return 0
  rc=$?
  [ "$rc" -eq 1 ] || return 2
  if listing="$(ipt "$fam" -S "$chain" 2>/dev/null)"; then
    fw_listed "$chain" "$ip" <<< "$listing"
    case "$?" in 0) return 0 ;; 1) return 1 ;; *) return 2 ;; esac
  fi
  all="$(ipt "$fam" -S 2>/dev/null)" || return 2
  if grep -qxF -- "-N $chain" <<< "$all"; then return 2; fi
  return 1
}

# fw_remove FAMILY IP: remove every DROP rule of IP (a rule can exist more than once if added by hand). A missing rule or chain is not an
# error; a firewall read error or a rule that cannot be deleted is (return 1). Success means absence was read back from the firewall.
fw_remove() {
  local fam="$1" ip="$2" chain rc n=0
  chain="$(chain_of "$fam")"
  while [ "$n" -lt 64 ]; do
    n=$((n + 1))
    fw_has "$fam" "$ip"; rc=$?
    case "$rc" in
      0) ipt "$fam" -D "$chain" -s "$ip" -j DROP || return 1 ;;
      1) return 0 ;;
      *) echo "ovpn-ban: cannot read chain $chain of the firewall: removal of $ip not verified" >&2; return 1 ;;
    esac
  done
  return 1
}

# Removal journal (see the header): one canonical address per line, rewritten atomically, only under the state lock. Like the other state
# files it is read with an explicit result: removal_has returns 0 = journaled, 1 = not journaled (or no journal yet), 2 = journal unreadable.
removal_has() {
  local st=0
  file_state "$REMOVALS" || st=$?
  [ "$st" -eq 1 ] && return 1
  [ "$st" -eq 0 ] || return 2
  grep -qxF -- "$1" "$REMOVALS"
  case "$?" in 0) return 0 ;; 1) return 1 ;; *) return 2 ;; esac
}
removal_without() {
  local st=0
  file_state "$REMOVALS" || st=$?
  [ "$st" -eq 1 ] && return 0
  [ "$st" -eq 0 ] || return 2
  awk -v ip="$1" '$0 != ip && $0 != ""' "$REMOVALS" || return 2
}
removal_with() { removal_without "$1" || return 1; echo "$1"; }
removal_add() { publish "$REMOVALS" removal_with "$1"; }
removal_drop() {
  local rc=0
  removal_has "$1" || rc=$?
  [ "$rc" -eq 1 ] && return 0
  [ "$rc" -eq 0 ] || return 1
  publish "$REMOVALS" removal_without "$1"
}

# removal_apply IP FAMILY: carry out a recorded removal (idempotent, every step can be repeated): DROP rule (absence read back), row, history
# entry, then verify all three and clear the journal line. Returns 1 at the first step that fails, including every read error of the ban
# list or the history (an unreadable file is not an absent entry); the journal line then stays and the next ban engine operation repeats the
# removal. Replacements of the ban list and the history are published only after their old content was read completely (publish).
removal_apply() {
  local ip="$1" fam="$2" rc line rk
  fw_remove "$fam" "$ip" || return 1
  publish "$STATE" rows_without "$ip" || { echo "ovpn-ban: cannot rewrite the ban list $STATE: removal of $ip not complete" >&2; return 1; }
  line="$(hist_line "$ip")" || { echo "ovpn-ban: cannot read the ban history $HISTORY: removal of $ip not complete" >&2; return 1; }
  if [ -n "$line" ]; then
    publish "$HISTORY" hist_without "$ip" || { echo "ovpn-ban: cannot rewrite the ban history $HISTORY: removal of $ip not complete" >&2; return 1; }
  fi
  fw_has "$fam" "$ip"; rc=$?
  [ "$rc" -eq 1 ] || { echo "ovpn-ban: $ip is still in the firewall after its removal" >&2; return 1; }
  rk="$(row_kind "$ip")" || { echo "ovpn-ban: cannot read the ban list $STATE: removal of $ip not verified" >&2; return 1; }
  line="$(hist_line "$ip")" || { echo "ovpn-ban: cannot read the ban history $HISTORY: removal of $ip not verified" >&2; return 1; }
  if [ "$rk" != "none" ] || [ -n "$line" ]; then echo "ovpn-ban: $ip is still in the ban list or history after its removal" >&2; return 1; fi
  removal_drop "$ip" || return 1
}

# reconcile_removals: complete every removal left in the journal (the caller holds the lock). Fails when one cannot be completed or when the
# journal itself cannot be read (the pending removals are then unknown).
reconcile_removals() {
  local ip rc=0 data
  data="$(read_all "$REMOVALS")" || { echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS: pending removals unknown" >&2; return 1; }
  [ -n "$data" ] || return 0
  while IFS= read -r ip <&3; do
    [ -n "$ip" ] || continue
    if ! classify_ip "$ip"; then
      removal_drop "$ip" || rc=1
      continue
    fi
    if removal_apply "$IP" "$FAM"; then
      echo "ovpn-ban: completed the pending removal of $IP" >&2
    else
      echo "ovpn-ban: WARNING: the pending removal of $IP is not complete yet" >&2
      rc=1
    fi
  done 3<<< "$data"
  return "$rc"
}

# txn_unban IP FAMILY FORCE: under the lock. A permanent address (history flag, or a row without expiry) is kept unless FORCE=1.
# FORCE=1 records the removal in the journal first (the commit point), then applies it (removal_apply): from there on it always ends in
# "unbanned", even when a step fails (an unreadable history or ban list included) and the caller is told so: the journal line stays and the
# removal is repeated by the next operation, never reversed. Success is only reported after absence is verified. Without FORCE the
# permanence decision needs the history and the ban list: when one cannot be read the state is unknown and the unban fails (nothing changed).
txn_unban() {
  local ip="$1" fam="$2" force="$3" line perm=0 rk
  reconcile_removals || echo "ovpn-ban: WARNING: a pending removal could not be completed yet" >&2
  if [ "$force" = "1" ]; then
    removal_add "$ip" || { echo "ovpn-ban: cannot record the removal of $ip: nothing was changed" >&2; return 1; }
    removal_apply "$ip" "$fam" || { echo "ovpn-ban: removal of $ip is recorded but not complete: the next ban engine operation finishes it, it is not restored" >&2; return 1; }
    return 0
  fi
  line="$(hist_line "$ip")" || { echo "ovpn-ban: cannot read the ban history $HISTORY: unban of $ip not done" >&2; return 1; }
  if [ -n "$line" ]; then
    IFS=$'\t' read -r _ _ _ _ perm _ <<< "$line"
  fi
  if [ "$perm" != "1" ]; then
    rk="$(row_kind "$ip")" || { echo "ovpn-ban: cannot read the ban list $STATE: unban of $ip not done" >&2; return 1; }
    [ "$rk" = "perm" ] && perm=1
  fi
  if [ "$perm" = "1" ]; then
    echo "ovpn-ban: $ip is permanently banned, unban ignored (use unban $ip --force)" >&2
    return 0
  fi
  fw_remove "$fam" "$ip" || return 1
  publish "$STATE" rows_without "$ip" || return 1
  return 0
}

do_clear_rows() { : | write_file "$STATE"; }

# flush_chains: empty both chains when they exist; fails only when an existing chain cannot be emptied
flush_chains() {
  local fam rc=0
  for fam in 4 6; do
    if ipt "$fam" -n -L "$(chain_of "$fam")" >/dev/null 2>&1; then ipt "$fam" -F "$(chain_of "$fam")" || rc=1; fi
  done
  return "$rc"
}

# txn_flush: chains and ban list emptied in one critical section (the caller holds the lock). The history and the journal stay.
txn_flush() {
  local rc=0
  flush_chains || rc=1
  do_clear_rows || rc=1
  return "$rc"
}

# init: DROP rules and ban list are cleared, the ban history stays; the start time is recorded for the restart rule of txn_ban
cmd_init() {
  mkdir -p "$(dirname "$STATE")" || die "cannot create $(dirname "$STATE")"
  with_state_lock txn_flush || die "cannot empty the ban chains and reset $STATE"
  date +%s | write_file "$BOOT_FILE" || die "cannot write $BOOT_FILE"
}

# perm_entries: one line "IP FAM" per permanent entry of the history that is to be enforced now. Not listed: addresses with a pending
# removal, entries that are not a bannable address (warning), IPv6 entries with IPv6 off (the intentional opt-out, warning).
# Returns 2, listing nothing trustworthy, when the history or the removal journal exists but cannot be read: a failed enumeration is an error,
# never "no permanent entries". A history file that does not exist (first start) has no entries and is a success.
perm_entries() {
  local line ip n first last perm reason fails data jr
  data="$(read_all "$HISTORY")" || { echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY" >&2; return 2; }
  [ -n "$data" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    IFS=$'\t' read -r ip n first last perm reason fails <<< "$line"
    [ "$perm" = "1" ] || continue
    if ! classify_ip "$ip"; then
      echo "ovpn-ban: WARNING: permanent entry skipped, not a bannable address: $ip" >&2
      continue
    fi
    jr=0
    removal_has "$IP" || jr=$?
    case "$jr" in
      0) continue ;;
      1) ;;
      *) echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS" >&2; return 2 ;;
    esac
    if [ "$FAM" = "6" ] && [ "$V6" != "true" ]; then
      echo "ovpn-ban: WARNING: permanent ban of $IP NOT restored: IPv6 is not enabled" >&2
      continue
    fi
    echo "$IP $FAM"
  done <<< "$data"
}

# fail_status REQUIRED6_FAILURES OTHER_FAILURES: 3 when a required IPv6 enforcement is missing, 1 for any other failure, else 0
fail_status() {
  if [ "$1" -gt 0 ]; then return 3; fi
  if [ "$2" -gt 0 ]; then return 1; fi
  return 0
}

# restore_permanent: DROP rule and row (expires_at=0) for every permanent entry of the history, under the lock. A failing entry never
# stops the others, but any failure of an enforced family is returned (see fail_status). Skipped, not failed: IPv6 entries when IPv6 is off
# or, with OVPN_BAN_IPV6_REQUIRED=false, when the IPv6 chain cannot be created (the intentional opt-outs), entries that are not an address.
restore_permanent() {
  local line ip n first last perm reason fails fam chain count=0 skipped=0 failed=0 req6=0 other=0 rc data jr jst=0
  # the whole history is read, and the journal checked, BEFORE anything is restored: an unreadable file is an error (status 1), not an empty history
  data="$(read_all "$HISTORY")" || { echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY: the permanent bans are unknown, nothing restored" >&2; return 1; }
  file_state "$REMOVALS" || jst=$?
  [ "$jst" -ne 2 ] || { echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS: nothing restored" >&2; return 1; }
  [ -n "$data" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    IFS=$'\t' read -r ip n first last perm reason fails <<< "$line"
    [ "$perm" = "1" ] || continue
    if ! classify_ip "$ip"; then
      echo "ovpn-ban: WARNING: permanent entry skipped, not a bannable address: $ip" >&2
      skipped=$((skipped + 1))
      continue
    fi
    jr=0
    removal_has "$IP" || jr=$?
    if [ "$jr" -eq 0 ]; then
      echo "ovpn-ban: WARNING: permanent entry of $IP skipped, its removal is pending" >&2
      skipped=$((skipped + 1))
      continue
    elif [ "$jr" -ne 1 ]; then
      echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS: $IP not restored" >&2
      failed=$((failed + 1)); other=$((other + 1))
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
      if [ "$fam" = "6" ] && [ "$V6_REQUIRED" != "true" ]; then
        echo "ovpn-ban: WARNING: permanent ban of $IP NOT restored: chain $chain is not available (OVPN_BAN_IPV6_REQUIRED=false)" >&2
        skipped=$((skipped + 1))
      else
        echo "ovpn-ban: ERROR: permanent ban of $IP NOT restored: chain $chain is not available" >&2
        failed=$((failed + 1)); if [ "$fam" = "6" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      fi
      continue
    fi
    fw_has "$fam" "$IP"; rc=$?
    if [ "$rc" -eq 1 ]; then
      ipt "$fam" -A "$chain" -s "$IP" -j DROP || rc=2
    elif [ "$rc" -ne 0 ]; then
      rc=2
    fi
    if [ "$rc" -eq 2 ]; then
      echo "ovpn-ban: ERROR: cannot restore the DROP rule of $IP" >&2
      failed=$((failed + 1)); if [ "$fam" = "6" ] && [ "$V6_REQUIRED" = "true" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      continue
    fi
    [[ "$last" =~ ^[1-9][0-9]{0,11}$ ]] || last="$(date +%s)"
    [[ "$fails" =~ ^[0-9]{1,10}$ ]] || fails=0
    [ -n "$reason" ] || reason="restored"
    if ! ban_row "$IP" "$fails" "$reason" "$last" 0; then
      echo "ovpn-ban: ERROR: cannot restore the row of $IP" >&2
      failed=$((failed + 1)); if [ "$fam" = "6" ] && [ "$V6_REQUIRED" = "true" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      continue
    fi
    count=$((count + 1))
  done <<< "$data"
  echo "ovpn-ban: restored $count permanent ban(s)$([ "$skipped" -gt 0 ] && echo ", $skipped skipped")$([ "$failed" -gt 0 ] && echo ", $failed FAILED")" >&2
  fail_status "$req6" "$other"
}

# txn_restore: complete pending removals, then restore; the status of restore_permanent, or 1 when a removal cannot be completed
txn_restore() {
  local rc=0 r=0
  reconcile_removals || r=1
  restore_permanent || rc=$?
  if [ "$rc" -eq 0 ] && [ "$r" -ne 0 ]; then rc=1; fi
  return "$rc"
}

# verify_permanent: every permanent entry that is to be enforced (perm_entries) has its DROP rule and a PERMANENT row (expires_at=0: a
# temporary row of the address does not count, the UI could expire it); 0, or the fail_status. A rule or a row that cannot be read counts as
# missing; a history that cannot be enumerated fails the verification (status 1).
verify_permanent() {
  local ip fam rc rk rrc why req6=0 other=0 entries
  entries="$(perm_entries 2>/dev/null)" || { echo "ovpn-ban: ERROR: cannot enumerate the permanent bans of the history $HISTORY: enforcement not verified" >&2; return 1; }
  while read -r ip fam <&3; do
    [ -n "$ip" ] || continue
    if [ "$fam" = "6" ] && [ "$V6_REQUIRED" != "true" ] && ! jumps_ok 6; then continue; fi
    fw_has "$fam" "$ip"; rc=$?
    rrc=0
    rk="$(row_kind "$ip")" || rrc=$?
    why=""
    [ "$rc" -eq 1 ] && why=" (no DROP rule)"
    [ "$rc" -eq 2 ] && why=" (firewall unreadable)"
    if [ "$rc" -eq 0 ]; then
      if [ "$rrc" -ne 0 ]; then why=" (ban list unreadable)"
      elif [ "$rk" = "none" ]; then why=" (no row)"
      elif [ "$rk" != "perm" ]; then why=" (row is temporary, expires_at is not 0)"; fi
    fi
    if [ "$rc" -ne 0 ] || [ "$rrc" -ne 0 ] || [ "$rk" != "perm" ]; then
      echo "ovpn-ban: ERROR: expected permanent ban of $ip is not enforced$why" >&2
      if [ "$fam" = "6" ] && [ "$V6_REQUIRED" = "true" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
    fi
  done 3<<< "$entries"
  fail_status "$req6" "$other"
}

# txn_check_permanent: complete pending removals, verify the permanent bans; when one is missing, reconcile once (restore) and verify again
txn_check_permanent() {
  local rc=0
  reconcile_removals || return 1
  verify_permanent 2>/dev/null && return 0
  echo "ovpn-ban: WARNING: a permanent ban is not enforced, restoring" >&2
  restore_permanent || true
  verify_permanent || rc=$?
  return "$rc"
}

# setup: IPv4 is always required. IPv6 is required whenever it is enabled (OVPN_BAN_IPV6=true): a missing IPv6 chain exits 3
# unless OVPN_BAN_IPV6_REQUIRED=false, which is the single opt-out and warns loudly. A permanent ban of an enforced family that cannot be
# restored fails setup (exit 3 for a required IPv6 family, 1 otherwise): the jail start and the readiness check then fail.
cmd_setup() {
  local rc=0
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
  with_state_lock txn_restore || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "ovpn-ban: ERROR: the permanent bans of the history are not all enforced (setup failed, exit $rc)" >&2
    exit "$rc"
  fi
  return 0
}

# check: running state of the enforcement (chains and jumps present, every expected permanent ban enforced).
# Exit 3: required IPv6 enforcement missing; 1: IPv4 missing or a permanent ban not enforced.
cmd_check() {
  local msg prc=0
  need_listener
  jumps_ok 4 || die "IPv4 ban chain $CHAIN4 or its jump for $PROTOS port $PORT is missing"
  if [ "$V6" = "true" ] && [ "$V6_REQUIRED" = "true" ]; then
    jumps_ok 6 || { echo "ovpn-ban: ERROR: IPv6 is enabled but chain $CHAIN6 or its jump for $PROTOS port $PORT is missing" >&2; exit 3; }
    msg="ovpn-ban: check ok: IPv4 and IPv6 enforce $PROTOS port $PORT"
  elif [ "$V6" = "true" ]; then
    if jumps_ok 6; then msg="ovpn-ban: check ok: IPv4 and IPv6 enforce $PROTOS port $PORT"
    else msg="ovpn-ban: check ok: IPv4 enforces $PROTOS port $PORT; IPv6 is NOT enforced (OVPN_BAN_IPV6_REQUIRED=false)"; fi
  else
    msg="ovpn-ban: check ok: IPv4 enforces $PROTOS port $PORT (IPv6 off)"
  fi
  with_state_lock txn_check_permanent || prc=$?
  if [ "$prc" -ne 0 ]; then
    echo "ovpn-ban: ERROR: check failed: an expected permanent ban is not enforced (exit $prc)" >&2
    exit "$prc"
  fi
  echo "$msg"
}

# do_ban IP FAILURES REASON MODE: the common part of ban and ban-manual (IP already classified: FAM and IP are set).
# Firewall check/add and the history/ban list decision are one critical section (txn_ban_fw); the notification follows the unlock.
do_ban() {
  local ip="$1" fails="$2" reason="$3" mode="$4" out perm newperm expires added
  need_listener
  out="$(with_state_lock txn_ban_fw "$ip" "$fails" "$reason" "$mode" "$FAM")" || die "ban of $ip not completed"
  read -r perm newperm expires added <<< "$out"
  [[ "$expires" =~ ^[0-9]{1,12}$ ]] && [[ "$added" =~ ^[01]$ ]] || die "internal error: unexpected result of the ban transaction"
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
  with_state_lock txn_flush
}

# txn_teardown: jumps, rules, rows and chains removed in one critical section (the caller holds the lock)
txn_teardown() {
  local fam rc=0
  for fam in 4 6; do
    drop_jumps "$fam" || rc=1
  done
  txn_flush || rc=1
  for fam in 4 6; do
    if ipt "$fam" -n -L "$(chain_of "$fam")" >/dev/null 2>&1; then ipt "$fam" -X "$(chain_of "$fam")" || rc=1; fi
  done
  return "$rc"
}

cmd_teardown() {
  with_state_lock txn_teardown
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
