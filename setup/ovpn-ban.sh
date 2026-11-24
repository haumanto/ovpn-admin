#!/usr/bin/env bash
# Ban enforcement and ban list for the fail2ban jail "ovpn-admin" (called from the fail2ban action, see configure.sh).
#
#   ovpn-ban.sh init             clear the ban list and every DROP rule of both families (container start, before fail2ban starts);
#                                the ban history (bans-history.tsv, see below) is kept, decayed offences are pruned, an old history is migrated
#   ovpn-ban.sh setup            create the OVPN_BAN (IPv4) and OVPN_BAN6 (IPv6) chains and their INPUT jumps (jail start), then restore the
#                                DROP rule and the row (expires_at=0) of every permanent entry of the ban history, and of every temporary ban
#                                that has not run out (original end), and reconcile rules and ban list;
#                                exit 3 when IPv6 is enabled, the IPv6 chain cannot be created and OVPN_BAN_IPV6_REQUIRED is not false
#   ovpn-ban.sh check            verify the chains and jumps of every enforced family; exit 3 = required IPv6 enforcement missing
#   ovpn-ban.sh ban IP FAILURES  DROP the address (IPv6: its prefix, default /64) in OVPN_BAN (IPv4) or OVPN_BAN6 (IPv6) and add (or replace)
#                                its row in the ban list. The offence is counted per address (IPv6: per prefix) and the ban lasts the step
#                                of OVPN_BAN_ESCALATION that belongs to that offence number (default 10m, 1h, 24h, then permanent). A new
#                                ban or offence is recorded in the ban event log and sends the Telegram message when OVPN_TELEGRAM_ENABLED=true
#   ovpn-ban.sh ban-manual [--force] [--minutes N] IP [REASON]
#                                operator ban: permanent, or N minutes (1..525600). Refused (exit 4, reason on stderr, a "refuse" event, no
#                                change) when the address is loopback, on the ignore list, inside the VPN client network or in a private
#                                range, unless --force. History reason "manual" or "manual: REASON"; REASON is limited to
#                                [A-Za-z0-9 ._:-]{0,120}, anything else is refused
#   ovpn-ban.sh unban IP         remove the DROP rule and the row of an address whose ban has run out; succeeds when neither exists. A
#                                permanent address, and a temporary one that has not run out, is left as it is (success, no change):
#                                fail2ban calls this at the end of the jail bantime, which is the first step of the escalation
#   ovpn-ban.sh unban IP --force remove the DROP rule, the row and every history row of the address, permanent or not; it starts clean.
#                                IP can also be the network as the ban list writes it (2001:db8:1:2::/64)
#   ovpn-ban.sh expire           lift every temporary ban that has run out and reconcile the DROP rules with the ban list: a rule with no row and
#                                no ban in force in the history is removed, a rule whose ban the history has in force gets its row, a row of a
#                                ban in force without its rule gets the rule (also done by every ban and by the jail start, and every 30 s by
#                                the watcher ovpn-ban-control, or by the supervisor of configure.sh while the watcher is down)
#   ovpn-ban.sh jail-bantime     print the bantime for the fail2ban jail (the first escalation step in seconds, -1 = permanent)
#   ovpn-ban.sh flush            remove every DROP rule of both chains and clear the ban list
#   ovpn-ban.sh teardown         remove the INPUT jumps, flush, delete both chains (actionstop, ban engine disabled); the ban list is
#                                emptied too, except while the history cannot vouch for it (a refused init): then the rows stay
#
# Ban list (read by ovpn-admin): OVPN_BAN_STATE, default /var/lib/ovpn-admin/bans.tsv, root:root 0600, no header, one
# tab-separated row per active ban: ip, banned_at_unix, expires_at_unix, failures, reason. IPv4 and IPv6 share the file;
# the ip column holds the canonical text form of the address, or for an IPv6 ban of a prefix the network with the prefix length it was
# banned with ("2001:db8:1:2::/64"): the unban removes exactly that rule. OVPN_BAN_MAX_ENTRIES (default 500) bounds the rows of the list
# that a NEW ban may add, nothing else: when the list is full the oldest temporary ban is dropped (logged, counted in
# OVPN_BAN_STATE.caphits, event "cap-evict") and a list full of permanent bans refuses every new key (event "cap-refuse"). It does not bound
# the history and never limits the restore: the permanent bans of the history are all restored whatever the setting says (a warning at the
# start names the case), and no setting deletes a history row.
# The file is replaced atomically (temp file in the same directory + rename) while holding an flock.
# A permanent ban has expires_at_unix 0 (ovpn-admin versions before the manual-control release skip such a row as malformed).
#
# Ban history: bans-history.tsv next to the ban list, root:root 0600, no header, one tab-separated row per OFFENCE:
#   time_unix  address  prefix  reason  offence  ban_seconds        (ban_seconds 0 = permanent)
# The offence number of an address (IPv6: of its prefix) is the offence number of its last offence inside OVPN_BAN_DECAY_DAYS (default 30)
# plus one; an address without an offence in that window starts again at 1. Rows older than the window are pruned (at init, setup and at
# every offence), a permanent row never decays: the fourth offence stays permanent. A manual ban is recorded with the offence number the
# address has and does not raise it. It survives container restarts (init keeps it); setup restores every permanent entry. Rewritten
# atomically under the same flock as the ban list. The file of the earlier releases (ban-history.tsv, one row per address) is migrated to
# this one at the first setup and kept as ban-history.tsv.migrated.
# A ban that fail2ban re-derives from the log lines right after a container start (within 120 seconds of init) for an address whose ban was
# still running at the restart (or that is permanent) is the same ban, not a new offence: it is not counted again.
#
# Ban event log: OVPN_BAN_EVENTS_LOG, default /var/lib/ovpn-admin/audit/ban-events.log, root:root 0600 (umask 077), JSON lines:
#   {"time","time_unix","address","prefix","reason","offence","ban_seconds","action"[,"forced":true],"user"}   action: ban, unban, refuse, expire,
#   cap-evict, cap-refuse, orphan-removed (the sweep removed a rule that nothing could lift). "user" is the last field of every line: the user
#   name of a "ban" line when the audit log names one (see "User name" below), "-" otherwise and on every other action.
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
#   OVPN_BAN_ESCALATION ban length by offence number, comma separated steps (whole number, optional unit s, m, h, d; no unit = seconds;
#                       0 = permanent, ends the list); default "10m,1h,24h,0". An offence beyond the last step gets the last step again
#   OVPN_BAN_BANTIME, OVPN_BAN_REPEAT_COUNT  the earlier single-duration policy, still accepted: only when OVPN_BAN_ESCALATION is empty and
#                       either is set, they mean "BANTIME seconds (default 3600) for REPEAT_COUNT-1 bans (default 2), then permanent"
#   OVPN_BAN_DECAY_DAYS days without an offence after which the offence count of an address starts again (default 30)
#   OVPN_BAN_IPV6_PREFIX  prefix length of an IPv6 ban, 48 to 128 (default 64; 128 = the single address). A prefix that would also cover an
#                       address of the ignore list is narrowed to the single address
#   OVPN_BAN_MAX_ENTRIES  most active bans in the ban list (default 500), see above
#   OVPN_BAN_IGNOREIP   the ignore list of fail2ban (set by configure.sh): an address on it is not banned; the manual ban guard reads it too
#   OVPN_BAN_OWN_NETS   VPN client networks (set by configure.sh, space separated; OVPN_NETWORK and OVPN_NETWORK_IPV6 are read as well):
#                       the manual ban guard refuses an address inside them
#   OVPN_BAN_HISTORY    ban history path (default bans-history.tsv in the directory of OVPN_BAN_STATE)
#   OVPN_BAN_LEGACY_DIR directory of the earlier layout that is searched for ban-history.tsv besides the directory of the ban list
#                       (default /etc/openvpn/audit)
#   OVPN_BAN_SWEEP_SECONDS  seconds between two sweeps of the watcher (default 30, read by ovpn-ban-control and configure.sh)
#   OVPN_BAN_EVENTS_LOG ban event log (default /var/lib/ovpn-admin/audit/ban-events.log)
#   OVPN_BAN_LOG        OpenVPN log, only read to name the reason of a ban (default /var/lib/ovpn-admin/openvpn.log)
#   OVPN_AUDIT_LOG      OpenVPN audit log (default /etc/openvpn/audit/audit.tsv, written by audit.sh), only read to name the user of a ban
#   OVPN_BAN_NOTIFY_LOG  file that receives the warning when a Telegram notification fails (set by configure.sh to the fail2ban log)
#   OVPN_TELEGRAM_ENABLED  set by configure.sh (true only when the Telegram settings are valid); with true, a new ban (or offence) and the
#                       lifting of a ban run /usr/local/sbin/ovpn-telegram-notify ban|unban ... after the DROP rule and the row are
#                       written, outside the lock. The message carries the address (the network of an IPv6 ban), the reason, the user name
#                       when the audit log knows it, the offence number, the duration, the end of the ban and the host. Since v0.1.12
#                       OVPN_TELEGRAM_INCLUDE_ADDRESS defaults to true (v0.1.11 sent neither address nor name: the owner reversed that);
#                       false is the escape hatch: the notifier then gets "-" instead of the address and no user name, and the message
#                       names neither. The bot token and chat id reach the notifier through its
#                       environment only (inherited from the fail2ban server, set by configure.sh), never through an argument. A notifier
#                       failure is one warning in the fail2ban log, which the container log mirrors; the ban stays successful and the
#                       exit status is not affected.
#
# User name (ban messages and the "user" field of the event log): before a ban is queued for the notifier, the audit log is searched for
# the newest "auth_fail" row (event time username real_ip real_port virtual_ip4 virtual_ip6 rx tx, tab separated) whose real_ip is the banned
# address (for an IPv6 /64 ban: lies inside the banned prefix) and whose time is within 600 seconds of the ban. Its user name is used when it
# matches [A-Za-z0-9][A-Za-z0-9._-]{0,63}. A missing, unreadable, non-regular or link file, no such row, a row of another kind, a "-" user, an
# unreadable row or an invalid name mean NO name: the line is left out and the event log says "-". A name is never guessed from an older row
# and the lookup never fails or delays a ban (the file is read through a bounded tail, 5 s limit). The name is what the client typed at the
# failed login: it is not verified. The audit directory is writable only by the VPN hook user; the name is validated again before the queue
# file, the event log and the notifier argument, so the audit file cannot inject a line.
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
# check, ban, ban-manual, unban) completes the removal first (it converges to a clean removal once the files are readable), and restore
# never re-adds a journaled address (an unreadable journal fails restore instead). Outcomes: before the journal write, nothing changed and the
# caller got an error; from the journal write on, the address ends up unbanned and absent from history, whatever the caller was told.
# The journal line is committed intent: it is cleared only by a COMPLETED removal (all three verified) and by nothing else. A new ban of a
# journaled address first replays the removal; when the replay of that address is not complete (an unreadable history, a failing step) the
# new ban FAILS and the line stays, and a retry can only go on after the replay succeeded. A line is discarded only when it is not a
# bannable address (the classifier said "invalid"); when the classifier itself fails (python3 missing or crashing) the line is kept.
#
# History at a start (init, then setup and check): three cases, never "no bans" by accident (hist_gate).
#   (a) no history file and no file of the earlier releases anywhere (OVPN_BAN_LEGACY_DIR, default /etc/openvpn/audit, and the directory of
#       the ban list): a fresh installation, a normal start. A history file that is readable and zero bytes is a history with no bans: the same,
#       unless a ban list holds permanent bans that it lacks (the refusals below).
#   (b) a file of the earlier releases (ban-history.tsv, 7 fields) that is readable and entirely in that format: converted into the history,
#       the old file kept as ban-history.tsv.migrated, and every permanent ban in it restored by setup. When OVPN_BAN_HISTORY itself names a
#       file in the earlier format it is converted in place and the original is kept as FILE.legacy-format.
#   (c) a history or earlier-release file that exists but cannot be read (permissions, a directory or a link in its place, an I/O error), is
#       not entirely in a known format (one bad row refuses the whole file: a row that is skipped is a ban that is lost), is not a plain file
#       of the user of this process, or cannot be converted: init fails, naming the file, and so do setup, check, ban and unban; nothing is
#       published from it. configure.sh stops the container with OVPN_BAN_REQUIRED=true (without it the container runs without the ban
#       engine, loudly). The history is never reported as empty because it could not be read.
#   Three more refusals, each for a history that is cut short and would otherwise lose permanent bans without a sound:
#     - a history file (current or earlier format) that is not empty and does not end in a newline: every writer ends each row with one;
#     - a migration or in-place conversion whose result lacks a permanent entry of the ban list of the earlier release (old_lists: the ban list
#       of this engine, and bans.tsv in OVPN_BAN_LEGACY_DIR): a cut at a row end, or an emptied file, still parses. init fails and the message
#       names the ban list and the history. To start without those bans on purpose, move both files away;
#     - a history that is missing, empty or in the current format and lacks a permanent entry (expires_at 0) of the ban list of this engine
#       (list_gate): a history cut at a row end, emptied or replaced is a valid file of fewer bans, and so is the zero-byte file that
#       OVPN_BAN_HISTORY names. The list is the second record: a ban is written to the history before the list, a lifting removes the list row
#       before the history rows, and a container stop, a crash and a refused start leave the list as it is (only an accepted init, the jail
#       stop, teardown, and the flush command empty it; a teardown that follows a refusal does not, see txn_teardown: a start with
#       OVPN_BAN_REQUIRED=false or OVPN_BAN_ENABLED=false after a refusal keeps the list, so the next start with true is refused again),
#       so at a start every permanent row of the list has its
#       permanent row in the history. When the history is empty or missing, bans.tsv in OVPN_BAN_LEGACY_DIR is compared too, unless
#       ban-history.tsv.migrated or FILE.legacy-format (the proof of a conversion) exists: that file is then an old copy that the operator may
#       have emptied since. A state that was emptied on purpose is an empty list AND an empty history (the panel's unban removes both).
#   Not covered: an emptied history whose list is empty too (the operator emptied both, or the list was never written), and a history cut at a
#   row end after its list was emptied: there is no second record left to compare. Refused although the operator may mean it: an old bans.tsv
#   of the earlier layout with permanent rows next to an emptied history, after the operator deleted the conversion marker (move that
#   bans.tsv away, as the layout message says once its bans have been checked).
# A container restart keeps the bans in force: init empties the chains and the list, setup puts back every permanent ban and every
# TEMPORARY ban that has not run out (restore_temporary) with its original end, from the history (rule and row together, so /api/bans and the
# firewall agree; a ban that ran out while the container was down is not restored; one the operator lifted is not in the history any more).
# Newest first, within OVPN_BAN_MAX_ENTRIES; what does not fit stays in the history and is warned about. A ban that fail2ban re-derives from
# the log right after the start finds its rule and row and is the same incident (txn_ban_fw), or, for an entry that was not restored, within
# RESTART_GRACE of the start.
#
# Order of a ban and the kill window: DROP rule, history row, list row (txn_ban_fw). A kill between them leaves a rule with no row. With a
# history row of a ban in force the next sweep (expire, the jail start) writes the row from it (the ban was complete but not listed: up to
# OVPN_BAN_SWEEP_SECONDS, 30 s, the firewall blocks and /api/bans does not yet show it); without one it is an orphan rule and the sweep removes it
# (the ban was never recorded; fail2ban counts the next failures again). An unban or expiry removes the rule first, then the row: a kill
# between leaves a row of a ban that ran out or was lifted, which txn_expire or the journal removes.
#
# State trust (trust_state, every locked command): the directory of the ban list, of the history and of the lock, and each state file in
# it, must belong to the user of this process, be closed to group and other and (files) be plain single-link files; no directory above it
# may belong to another user. Otherwise the command fails (exit 1, the path named) and the container does not start. This stands on its own: the
# VPN hook user ("nobody") that owned the state directory in the earlier layout could replace the ban list, the history and the lock name.
# State, history and lock are read without following links. Group-writable ancestors are not checked.
#
# Reply of a ban and an unban (stdout, the line the watcher builds its answer from, never from the request):
#   ovpn-ban-result ban entry=ENTRY requested=ADDRESS seconds=N expires=UNIX offence=N status=new|renewed|unchanged   (0 = permanent)
#   ovpn-ban-result unban entry=ENTRY requested=TARGET had=0|1 still=OVERLAPPING_ENTRY|-
# ENTRY is what is enforced (the whole /64 of an IPv6 address), seconds and expires the real length and end (a permanent ban on record
# overrides the minutes asked for), still an entry that overlaps the lifted one, whose rule and history stay: an unban forgets the history
# of exactly the entry it lifts, never of a rule that still stands.
#
# Restore and readiness: setup returns non-zero when a permanent entry of an enforced family cannot be restored (exit 3 when the failing
# family is IPv6 with OVPN_BAN_IPV6_REQUIRED=true, 1 otherwise). The intentional opt-outs (OVPN_BAN_IPV6=false, or
# OVPN_BAN_IPV6_REQUIRED=false with no usable IPv6 chain) are warnings, not failures. check also verifies, for every permanent history entry,
# that its DROP rule and a PERMANENT row (expires_at=0; a temporary row of the address does not count) exist; a missing one is reconciled once
# (the same restore, which replaces the row) and fails check (same exit codes) if it stays missing. A healthy check changes nothing.
# Both setup and check need a successful enumeration of the permanent history (hist_gate above): the history of a fresh installation has no
# entries and is fine, one that cannot be read or understood fails setup and check with exit 1, so readiness is degraded, and nothing is
# restored from it.
#
# State file reads: the ban list, the history and the removal journal are read with an explicit result (present / absent / error). A file
# that exists but cannot be read is "state unknown", never "empty" or "absent"; "absent" is only what lstat answered with ENOENT (path_probe,
# a python3 lstat: the shell tests -e and -L cannot tell a missing file from a failed lookup, so a metadata I/O error looked like absence).
# A loop over a snapshot (here-string) of such a file counts the rows it consumed and compares them with the rows of the snapshot: a loop
# that could not be set up runs no iteration, and "no failure counted" is never read as success without that.
# A replacement of one of these files (publish) is written to a
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
STATE="${OVPN_BAN_STATE:-/var/lib/ovpn-admin/bans.tsv}"
LOCK="${STATE}.lock"
REMOVALS="${STATE}.removals"
CAP_HITS="${STATE}.caphits"
LOCK_WAIT=30
HISTORY="${OVPN_BAN_HISTORY:-$(dirname "$STATE")/bans-history.tsv}"
LEGACY_HISTORY="$(dirname "$STATE")/ban-history.tsv"
# Every place a history of the earlier releases (ban-history.tsv, 7 fields) can be: next to the ban list and, when the state directory is not
# the audit directory of the earlier layout (/etc/openvpn/audit), there as well. See migrate_legacy.
LEGACY_DIR="${OVPN_BAN_LEGACY_DIR:-/etc/openvpn/audit}"
LEGACY_FILES=("$LEGACY_HISTORY")
[ "$LEGACY_DIR/ban-history.tsv" = "$LEGACY_HISTORY" ] || LEGACY_FILES+=("$LEGACY_DIR/ban-history.tsv")
BOOT_FILE="${STATE}.boot"
EVENTS_LOG="${OVPN_BAN_EVENTS_LOG:-/var/lib/ovpn-admin/audit/ban-events.log}"
RESTART_GRACE=120
OVPN_LOG="${OVPN_BAN_LOG:-/var/lib/ovpn-admin/openvpn.log}"
NOTIFY_BIN="${OVPN_BAN_NOTIFY_BIN:-/usr/local/sbin/ovpn-telegram-notify}"
NOTIFY_LOG="${OVPN_BAN_NOTIFY_LOG:-}"
TG_INCLUDE_ADDRESS="${OVPN_TELEGRAM_INCLUDE_ADDRESS:-true}"
AUDIT_LOG="${OVPN_AUDIT_LOG:-/etc/openvpn/audit/audit.tsv}"
AUDIT_WINDOW=600
IPV6_PREFIX="${OVPN_BAN_IPV6_PREFIX:-64}"
MAX_ENTRIES="${OVPN_BAN_MAX_ENTRIES:-500}"
DECAY_DAYS="${OVPN_BAN_DECAY_DAYS:-30}"
MIN_MANUAL_MINUTES=1
MAX_MANUAL_MINUTES=525600

die() { echo "ovpn-ban: $*" >&2; exit 1; }

for bin in "$IPT4" "$IPT6"; do
  case "$bin" in
    *[!A-Za-z0-9._-]* | "") die "invalid OVPN_IPTABLES_BIN or OVPN_IP6TABLES_BIN" ;;
  esac
done
for flag in "$V6" "$V6_REQUIRED" "$TG_INCLUDE_ADDRESS"; do
  case "$flag" in true | false) ;; *) die "OVPN_BAN_IPV6, OVPN_BAN_IPV6_REQUIRED and OVPN_TELEGRAM_INCLUDE_ADDRESS must be true or false" ;; esac
done
[[ "$IPV6_PREFIX" =~ ^[0-9]{2,3}$ ]] && [ "$IPV6_PREFIX" -ge 48 ] && [ "$IPV6_PREFIX" -le 128 ] || die "OVPN_BAN_IPV6_PREFIX must be a whole number from 48 to 128: \"$IPV6_PREFIX\""
[[ "$MAX_ENTRIES" =~ ^[1-9][0-9]{0,5}$ ]] || die "OVPN_BAN_MAX_ENTRIES must be a positive integer: \"$MAX_ENTRIES\""
[[ "$DECAY_DAYS" =~ ^[1-9][0-9]{0,3}$ ]] && [ "$DECAY_DAYS" -le 3650 ] || die "OVPN_BAN_DECAY_DAYS must be a whole number of days from 1 to 3650: \"$DECAY_DAYS\""
DECAY_SECONDS=$((DECAY_DAYS * 86400))

# Escalation: the Nth offence of one address (IPv6: one prefix) gets the Nth step; a step is a whole number with an optional unit
# s, m, h or d (no unit = seconds); 0 is permanent and ends the list. An offence beyond the last step gets the last step again.
# OVPN_BAN_BANTIME and OVPN_BAN_REPEAT_COUNT (the earlier single-duration policy) are still accepted: when OVPN_BAN_ESCALATION is empty
# and either of them is set, the list is "BANTIME x (REPEAT_COUNT-1), then permanent", which is what they always meant (defaults 3600 and 2).
# parse_escalation sets STEPS (the list in seconds, 0 = permanent) and STEPS_CSV.
parse_escalation() {
  local raw="$1" tok secs n unit ended=0
  local -a toks
  STEPS=()
  IFS=',' read -r -a toks <<< "$raw"
  for tok in "${toks[@]}"; do
    tok="${tok//[[:space:]]/}"
    [[ "$tok" =~ ^([0-9]{1,9})([smhd]?)$ ]] || return 1
    n="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[2]}"
    n=$((10#$n))
    case "$unit" in m) secs=$((n * 60)) ;; h) secs=$((n * 3600)) ;; d) secs=$((n * 86400)) ;; *) secs="$n" ;; esac
    [ "$secs" -le 315360000 ] || return 1   # ten years: longer is a typo, use 0 for permanent
    [ "$ended" -eq 1 ] && continue          # steps after a permanent one are checked, never reached
    STEPS+=("$secs")
    [ "$secs" -eq 0 ] && ended=1
  done
  [ "${#STEPS[@]}" -ge 1 ] || return 1
  local IFS=,
  STEPS_CSV="${STEPS[*]}"
}

ESCALATION="${OVPN_BAN_ESCALATION:-}"
LEGACY_BANTIME="${OVPN_BAN_BANTIME:-}"
LEGACY_REPEAT="${OVPN_BAN_REPEAT_COUNT:-}"
# the earlier settings are checked whenever they are set, also when OVPN_BAN_ESCALATION wins: a typo is not silently ignored
if [ -n "$LEGACY_BANTIME" ]; then
  case "$LEGACY_BANTIME" in *[!0-9]* | 0*) die "invalid OVPN_BAN_BANTIME" ;; esac
  [ "${#LEGACY_BANTIME}" -le 9 ] || die "invalid OVPN_BAN_BANTIME"
fi
if [ -n "$LEGACY_REPEAT" ]; then
  [[ "$LEGACY_REPEAT" =~ ^[1-9][0-9]{0,9}$ ]] || die "OVPN_BAN_REPEAT_COUNT must be a positive integer: \"$LEGACY_REPEAT\""
fi
if [ -z "$ESCALATION" ]; then
  if [ -n "$LEGACY_BANTIME" ] || [ -n "$LEGACY_REPEAT" ]; then
    LEGACY_BANTIME="${LEGACY_BANTIME:-3600}"
    LEGACY_REPEAT="${LEGACY_REPEAT:-2}"
    ESCALATION=""
    for ((i = 1; i < LEGACY_REPEAT && i <= 1000; i++)); do ESCALATION="${ESCALATION}${LEGACY_BANTIME},"; done
    ESCALATION="${ESCALATION}0"
  else
    ESCALATION="10m,1h,24h,0"
  fi
fi
parse_escalation "$ESCALATION" || die "OVPN_BAN_ESCALATION must be a comma separated list of durations (whole number, optional unit s, m, h or d; 0 = permanent), got \"${OVPN_BAN_ESCALATION:-}\""

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

# PYLIB: the address, history and event logic of the engine, one python3 program called as "python3 -c "$PYLIB" SUBCOMMAND ARGS".
# Nothing from a caller reaches a shell: every value is an argument vector element. Exit status: 0 ok, 2 a file exists but cannot be read
# (state unknown, never "empty"), 3 invalid or refused address, 5 manual guard refusal (reason on stdout), 6 address is on the ignore list,
# 64 usage error, anything else (an uncaught exception gives 1) = failure.
read -r -d '' PYLIB <<'PYEOF'
import datetime, ipaddress, json, os, re, stat, sys

PRIV = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
LOOP = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128")]
REASON_RE = re.compile(r"^[A-Za-z0-9 ._:+-]{1,120}$")


class Exit(Exception):
    def __init__(self, code):
        self.code = code


def nets(text):
    out = []
    for tok in text.split():
        try:
            out.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            pass
    return out


def ov(a, b):
    return a.version == b.version and a.overlaps(b)


def unwrap(a):
    if a.version == 6 and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


def hard_refused(a, allow_loopback=False):
    """Never bannable: unspecified, multicast, link-local, reserved (::1 is inside the reserved ::/8: a loopback address is let through
    when allow_loopback, which only the manual ban with force and the unban of such a ban use)."""
    if allow_loopback and a.is_loopback:
        return False
    return a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved or (a.version == 4 and int(a) >> 24 == 0)


def entry_text(net):
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def host_net(a, pfx6):
    if a.version == 4:
        return ipaddress.ip_network((a, 32))
    if a.is_loopback:
        # ::1 with a /64 would be ::/64, the unspecified network: a forced ban of the IPv6 loopback address is the single address, so that
        # the entry the ban list shows is an entry the unban accepts
        return ipaddress.ip_network((a, 128))
    return ipaddress.ip_network((a, pfx6), strict=False)


def own_nets():
    t = os.environ.get("OVPN_BAN_OWN_NETS", "") + " " + os.environ.get("OVPN_NETWORK", "") + " " + os.environ.get("OVPN_NETWORK_IPV6", "")
    return nets(t)


def show(net, addr):
    print(net.version, addr, entry_text(net), net.prefixlen)


def cmd_classify(mode, arg, pfx6):
    pfx6 = int(pfx6)
    if mode == "target":
        try:
            if "/" in arg:
                net = ipaddress.ip_network(arg, strict=False)
                if net.version == 6 and net.network_address.ipv4_mapped is not None:
                    raise Exit(3)
            else:
                a = unwrap(ipaddress.ip_address(arg))
                net = ipaddress.ip_network((a, a.max_prefixlen))
        except ValueError:
            raise Exit(3)
        if hard_refused(net.network_address, True) and not (net.version == 6 and net.network_address.is_unspecified and 48 <= net.prefixlen < 128):
            # (the exception: "::/64" is what an earlier release wrote for a forced ban of ::1; it must stay removable)
            raise Exit(3)
        return show(net, net.network_address)
    if "/" in arg:
        raise Exit(3)
    try:
        a = unwrap(ipaddress.ip_address(arg))
    except ValueError:
        raise Exit(3)
    if hard_refused(a, mode == "manual"):
        raise Exit(3)
    if mode == "auto":
        if a.is_loopback:
            raise Exit(3)
        ign = nets(os.environ.get("OVPN_BAN_IGNOREIP", ""))
        if any(a in n for n in ign if n.version == a.version):
            raise Exit(6)
    net = host_net(a, pfx6)
    if mode == "auto" and net.prefixlen < net.max_prefixlen and any(ov(net, n) for n in ign):
        # the whole prefix would take an address of the ignore list with it: ban the one address instead
        net = ipaddress.ip_network((a, a.max_prefixlen))
    show(net, a)


def cmd_guard(entry):
    """Manual ban guard: print the reason and exit 5 when the target must not be banned without force."""
    net = ipaddress.ip_network(entry, strict=False)
    if any(ov(net, n) for n in LOOP):
        why = "the address is a loopback address"
    elif any(ov(net, n) for n in nets(os.environ.get("OVPN_BAN_IGNOREIP", ""))):
        why = "the address is on the ignore list (OVPN_BAN_IGNOREIP)"
    elif any(ov(net, n) for n in own_nets()):
        why = "the address is inside the VPN client network (OVPN_NETWORK, OVPN_NETWORK_IPV6, OVPN_SERVER_NET)"
    elif any(ov(net, n) for n in PRIV):
        why = "the address is in a private range"
    else:
        return
    print(why)
    raise Exit(5)


class Row:
    def __init__(self, t, addr, prefix, reason, off, sec):
        self.t, self.addr, self.prefix, self.reason, self.off, self.sec = t, addr, prefix, reason, off, sec
        self.net = ipaddress.ip_network((addr, prefix), strict=False)

    def line(self):
        return "%d\t%s\t%d\t%s\t%d\t%d\n" % (self.t, self.addr, self.prefix, self.reason, self.off, self.sec)

    def manual(self):
        return self.reason.startswith("manual")


def fail(code, msg):
    sys.stderr.write("ovpn-ban: ERROR: " + msg + "\n")
    raise Exit(code)


def parse_row(line):
    """One row of the current history format (6 fields); ValueError when it is not one."""
    p = line.split("\t")
    if len(p) != 6:
        raise ValueError("fields")
    t, off, sec, prefix = int(p[0]), int(p[4]), int(p[5]), int(p[2])
    if t < 0 or off < 0 or sec < 0:
        raise ValueError("negative")
    return Row(t, ipaddress.ip_address(p[1]), prefix, p[3], off, sec)


def parse_legacy(line, bantime):
    """One row of the file of the earlier releases (ip, count, first, last, permanent 0|1, [reason, [failures]]) as a history row."""
    p = line.split("\t")
    if not 5 <= len(p) <= 7 or p[4] not in ("0", "1"):
        raise ValueError("fields")
    a = ipaddress.ip_address(p[0])
    n, last = int(p[1]), int(p[3])
    if n < 0 or last < 0 or int(p[2]) < 0:
        raise ValueError("negative")
    reason = p[5] if len(p) > 5 and REASON_RE.match(p[5]) else "legacy"
    return Row(last, a, a.max_prefixlen, reason, max(n, 1), 0 if p[4] == "1" else int(bantime))


def classify_file(path, bantime=3600):
    """Opens PATH without following a link and says what it holds: (\"missing\"|\"empty\"|\"new\"|\"legacy\", rows). A file whose content is
    not entirely one of the two formats is refused (exit 7, naming the file and the first line that does not fit): a row that is silently
    skipped is a ban that is silently lost. A file that exists but cannot be read exits 2 (state unknown, never \"empty\")."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return "missing", []
    with os.fdopen(fd, encoding="utf-8", newline="") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            fail(2, "%s is not a regular file" % path)
        try:
            data = f.read()
        except UnicodeDecodeError:
            fail(7, "%s is not text: format not recognised" % path)
    if data and not data.endswith("\n"):
        # every writer ends each row with a newline: a last row without one is a file that was cut short, and a cut can leave a row that still
        # parses (the rows after it are simply gone)
        fail(7, "%s does not end in a newline: the file is cut short (every row of the ban history ends with one): format not recognised" % path)
    new, old = [], []
    for n, line in enumerate(data.split("\n"), 1):
        if line == "":
            continue
        try:
            new.append(parse_row(line))
            continue
        except ValueError:
            pass
        try:
            old.append(parse_legacy(line, bantime))
        except ValueError:
            fail(7, "%s: line %d is not a ban history row of the current (6 fields) or the earlier (7 fields) format: format not recognised" % (path, n))
    if new and old:
        fail(7, "%s mixes the current and the earlier ban history format: format not recognised" % path)
    if old:
        return "legacy", old
    return ("new" if new else "empty"), new


def read_hist(path):
    """Rows of the offence history; a missing file is empty, any other read error propagates (exit 2), a file that is not in the current
    format exits 7 (not recognised) or 8 (the format of the earlier releases, to be converted first): never zero rows from a file that has some."""
    kind, rows = classify_file(path)
    if kind == "legacy":
        fail(8, "%s is in the format of the earlier releases (7 fields) and has not been converted" % path)
    return rows


def emit(rows):
    sys.stdout.write("".join(r.line() for r in rows))


def keep(rows, now, decay):
    """Rows that still count: younger than the decay window, and every permanent row (it never decays)."""
    return [r for r in rows if r.sec == 0 or now - r.t <= decay]


def cmd_decide(path, entry, mode, now, decay, steps, manual_sec, boot, grace, active):
    """Prints "OFFENCE BAN_SECONDS APPEND BASE": the offence number and ban length for a ban of ENTRY now, whether a history row is to be
    written (APPEND 1) and the time its length counts from (NOW, or the time of the ban that is being re-applied). ACTIVE 1 = the entry
    already has its DROP rule and a ban that has not run out: an automatic ban of it is the SAME incident again (a retry, a duplicate action
    of the jail) and counts once: nothing is appended, the offence and the end of the running ban are unchanged."""
    now, decay, manual_sec, boot, grace = int(now), int(decay), int(manual_sec), int(boot), int(grace)
    steps = [int(s) for s in steps.split(",")]
    net = ipaddress.ip_network(entry, strict=False)
    rel = [r for r in read_hist(path) if ov(r.net, net)]
    perm = [r for r in rel if r.sec == 0]
    if perm:
        # a permanent decision that no row of this very network backs (an overlapping permanent host, a narrower prefix) is recorded: a
        # restart restores the entry from the history, so the history must say what is enforced
        print(max(r.off for r in perm), 0, 0 if any(r.net == net for r in perm) else 1, max(r.t for r in perm))
        return
    if active == "1" and mode != "manual":
        mine = [r for r in rel if r.net == net]
        if mine:
            last = max(mine, key=lambda r: r.t)
            print(last.off, last.sec, 0, last.t)
            return
    win = [r for r in rel if not r.manual() and now - r.t <= decay]
    prev = max((r.off for r in win), default=0)
    if mode == "manual":
        print(prev, manual_sec, 1, now)
        return
    if win and boot > 0 and 0 <= now - boot <= grace:
        last = max(win, key=lambda r: r.t)
        if last.t < boot and (last.sec == 0 or last.t + last.sec > now):
            # fail2ban re-derives the ban from the log right after a container start: the same ban, not a new offence
            print(last.off, last.sec, 0, last.t)
            return
    off = prev + 1
    print(off, steps[min(off, len(steps)) - 1], 1, now)


def cmd_append(path, now, decay, addr, prefix, reason, off, sec):
    now = int(now)
    rows = keep(read_hist(path), now, int(decay))
    rows.append(Row(now, ipaddress.ip_address(addr), int(prefix), reason, int(off), int(sec)))
    emit(rows)


def cmd_prune(path, now, decay):
    emit(keep(read_hist(path), int(now), int(decay)))


def cmd_forget(path, entry):
    """The history without the rows of exactly this network. Rows of an overlapping (narrower or broader) network are not this entry's:
    their rules may still stand, and a rule whose history is gone disappears at the next restart."""
    net = ipaddress.ip_network(entry, strict=False)
    emit([r for r in read_hist(path) if r.net != net])


def cmd_has(path, entry):
    net = ipaddress.ip_network(entry, strict=False)
    if not any(ov(r.net, net) for r in read_hist(path)):
        raise Exit(1)


def cmd_has_exact(path, entry):
    net = ipaddress.ip_network(entry, strict=False)
    if not any(r.net == net for r in read_hist(path)):
        raise Exit(1)


def cmd_live(path, entry, now):
    """Prints "TIME SECONDS REASON" of the ban of exactly this network that is still to be in force at NOW (a permanent row, or the latest
    row whose end has not passed); exit 1 when there is none."""
    net = ipaddress.ip_network(entry, strict=False)
    mine = [r for r in read_hist(path) if r.net == net]
    perm = [r for r in mine if r.sec == 0]
    if perm:
        r = max(perm, key=lambda r: r.t)
    else:
        live = [r for r in mine if r.t + r.sec > int(now)]
        if not live:
            raise Exit(1)
        r = max(live, key=lambda r: r.t)
    print("%d\t%d\t%s" % (r.t, r.sec, r.reason))


def cmd_cover(path, entry):
    """The entries of the ban list whose network overlaps ENTRY but is not ENTRY: what still blocks the address after ENTRY was lifted."""
    net = ipaddress.ip_network(entry, strict=False)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    with os.fdopen(fd, encoding="utf-8") as f:
        data = f.read()
    for line in data.split("\n"):
        col = line.split("\t")[0]
        if not col:
            continue
        try:
            n = ipaddress.ip_network(col, strict=False)
        except ValueError:
            continue
        if n != net and ov(n, net):
            print(entry_text(n))


def cmd_is_perm(path, entry):
    net = ipaddress.ip_network(entry, strict=False)
    if not any(r.sec == 0 and ov(r.net, net) for r in read_hist(path)):
        raise Exit(1)


def cmd_perm(path):
    """One line per permanent entry: ENTRY FAMILY TIME REASON (tab separated), the latest row of each network."""
    seen = {}
    for r in read_hist(path):
        if r.sec == 0 and (r.net not in seen or r.t >= seen[r.net].t):
            seen[r.net] = r
    for net, r in seen.items():
        print("%s\t%d\t%d\t%s" % (entry_text(net), net.version, r.t, r.reason))


def cmd_temp(path, now):
    """One line per TEMPORARY ban that is still in force at NOW, newest first: ENTRY FAMILY TIME REASON SECONDS (tab separated). The latest row
    of a network decides, and a network with a permanent row is not listed (cmd_perm has it)."""
    now = int(now)
    last = {}
    for r in read_hist(path):
        if r.net not in last or r.t >= last[r.net].t:
            last[r.net] = r
    perm = {r.net for r in read_hist(path) if r.sec == 0}
    live = [r for net, r in last.items() if net not in perm and r.sec > 0 and r.t + r.sec > now]
    for r in sorted(live, key=lambda r: -r.t):
        print("%s\t%d\t%d\t%s\t%d" % (entry_text(r.net), r.net.version, r.t, r.reason, r.sec))


def old_perm_entries(path):
    """The permanent entries (expires_at 0) of the ban list of the earlier release at PATH, as (network, line number). A file that does not
    exist has none. One that cannot be read exits 2; one that is cut short or has a row that is not a ban list row exits 7: its permanent
    bans are then unknown and are never taken for "none". The ban list is written whole and atomically with a newline after every row."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return []
    with os.fdopen(fd, encoding="utf-8", newline="") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            fail(2, "%s is not a regular file" % path)
        try:
            data = f.read()
        except UnicodeDecodeError:
            fail(7, "%s is not text: its permanent bans cannot be compared with the ban history" % path)
    if data and not data.endswith("\n"):
        fail(7, "the ban list %s does not end in a newline: the file is cut short, its permanent bans cannot be compared with the ban history" % path)
    out = []
    for n, line in enumerate(data.split("\n"), 1):
        if line == "":
            continue
        p = line.split("\t")
        try:
            if len(p) < 3:
                raise ValueError("fields")
            net, exp = ipaddress.ip_network(p[0], strict=False), int(p[2])
            if exp < 0:
                raise ValueError("negative")
        except ValueError:
            fail(7, "the ban list %s: line %d is not a ban list row (address, banned_at, expires_at, ...): its permanent bans cannot be compared with the ban history" % (path, n))
        if exp == 0:
            out.append((net, n))
    return out


def cmd_migrate(bantime, nold, *rest):
    """The per-address history of the earlier releases (ban-history.tsv: ip, count, first, last, permanent, reason, failures) as offence
    rows; a legacy IPv6 address keeps its single-address scope (prefix 128). A path that does not exist is skipped; one that cannot be
    read exits 2, one that is not entirely in the earlier format exits 7: nothing is produced from a file that is only partly understood.
    REST is NOLD ban lists of the earlier release followed by the history files. A ban list says what was banned: every permanent entry
    in it must be a permanent row (or lie inside a permanent network) of the migrated history, else exit 7 and nothing is produced: a
    history that was cut at a row end, or emptied, still parses, and the permanent bans after the cut would be lost without a sound."""
    nold = int(nold)
    olds, paths = rest[:nold], rest[nold:]
    rows, seen = [], set()
    for p in paths:
        kind, rs = classify_file(p, bantime)
        if kind == "new":
            fail(7, "%s is not in the format of the earlier releases (7 fields)" % p)
        for r in rs:
            # the same file in two places (the layout copy and the original) is one history, not two
            if r.line() not in seen:
                seen.add(r.line())
                rows.append(r)
    perm = [r.net for r in rows if r.sec == 0]
    for o in olds:
        lost = [n for n, _ in old_perm_entries(o) if not any(n.version == q.version and n.subnet_of(q) for q in perm)]
        if lost:
            fail(7, "the ban list %s holds %d permanent ban(s) (%s%s) that the ban history %s does not: that history is cut short or incomplete. "
                    "Nothing was migrated and the start is refused. Restore both files from a backup, or move both away to start without these bans"
                 % (o, len(lost), ", ".join(entry_text(n) for n in lost[:5]), ", ..." if len(lost) > 5 else "", " and ".join(paths)))
    emit(rows)


def cmd_listcheck(hist, *lists):
    """The history HIST (missing, empty or in the current format) against the ban lists LISTS: every permanent entry (expires_at 0) of a ban
    list must be a permanent row (or lie inside a permanent network) of the history, else exit 7 naming the list, the history and the
    count. A ban list is written whole, after the history row of its ban (txn_ban_fw), and a lifting removes the row first and the history
    after it (removal_apply), so a list can only hold a permanent entry the history lacks when the history lost rows: cut at a row end,
    emptied, replaced. A list that is cut, not text or not a ban list is refused the same way (old_perm_entries): its permanent bans are
    unknown."""
    perm = [r.net for r in read_hist(hist) if r.sec == 0]
    for o in lists:
        lost = [n for n, _ in old_perm_entries(o) if not any(n.version == q.version and n.subnet_of(q) for q in perm)]
        if lost:
            fail(7, "the ban list %s holds %d permanent ban(s) (%s%s) that the ban history %s does not: the history lost rows (cut short, emptied or "
                    "replaced). The start is refused and both files are left as they are. Restore the history from a backup; to start without these "
                    "bans on purpose, lift them in the panel, or move both files away"
                 % (o, len(lost), ", ".join(entry_text(n) for n in lost[:5]), ", ..." if len(lost) > 5 else "", hist))


def cmd_hist_kind(path):
    """missing | empty | new | legacy (exit 2 unreadable, 7 not recognised)."""
    print(classify_file(path)[0])


def cmd_trust(ndirs, *paths):
    """Fails closed (exit 9) when a directory that holds engine state (the first NDIRS paths) is not a real directory owned by the user
    of this process and closed to group and other, or when a state file in it (the other paths) is not a regular file of that user closed
    to group and other (a link, another owner, a second hard link, group or other write): whoever else can write there can rewrite the
    ban list, the history or the lock. A path that does not exist is fine."""
    me = os.geteuid()
    for i, p in enumerate(paths):
        want_dir = i < int(ndirs)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            if want_dir:
                fail(9, "state directory %s does not exist" % p)
            continue
        if stat.S_ISLNK(st.st_mode):
            fail(9, "%s is a symbolic link: the ban engine state must be real files in a real directory" % p)
        if want_dir and not stat.S_ISDIR(st.st_mode):
            fail(9, "%s is not a directory" % p)
        if not want_dir and not stat.S_ISREG(st.st_mode):
            fail(9, "%s is not a regular file" % p)
        if st.st_uid != me:
            fail(9, "%s is owned by uid %d, not by the user of the ban engine (uid %d): that user could rewrite the ban state; refusing to run" % (p, st.st_uid, me))
        if st.st_mode & 0o022:
            fail(9, "%s is writable by group or other (mode %o): refusing to run" % (p, stat.S_IMODE(st.st_mode)))
        if not want_dir and st.st_nlink != 1:
            fail(9, "%s has more than one hard link: refusing to run" % p)
        if want_dir:
            # whoever owns a directory above the state directory can rename it away and put another one in its place
            a = os.path.dirname(os.path.realpath(p))
            while True:
                ast = os.stat(a)
                if ast.st_uid not in (0, me):
                    fail(9, "%s, above the state directory %s, is owned by uid %d: that user could replace the state directory; refusing to run" % (a, p, ast.st_uid))
                if ast.st_mode & 0o002 and not ast.st_mode & stat.S_ISVTX:
                    fail(9, "%s, above the state directory %s, is writable by everyone (mode %o): refusing to run" % (a, p, stat.S_IMODE(ast.st_mode)))
                if a == os.path.dirname(a):
                    break
                a = os.path.dirname(a)


def cmd_sweep(state, hist, now, fam, *rules):
    """Reconciliation plan of one family: RULES are the sources of the DROP rules in the ban chain (as the firewall lists them). Prints
    ORPHAN ENTRY      a rule with no row and no ban of the history that is still in force: nothing could ever lift it
    ADOPT ENTRY T SEC REASON   a rule with no row whose ban the history says is in force (kill between the history and the row): the row is rewritten
    READD ENTRY       a row of a ban that has not run out and has no rule: the rule is put back (the list never says banned for a source that is not)
    (tab separated). A row whose time has passed is not planned: the expiry lifts it."""
    now, fam = int(now), int(fam)
    rows = {}
    try:
        fd = os.open(state, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, encoding="utf-8") as f:
            data = f.read()
        for line in data.split("\n"):
            p = line.split("\t")
            if len(p) < 3 or p[0] == "":
                continue
            try:
                n = ipaddress.ip_network(p[0], strict=False)
                exp = int(p[2])
            except ValueError:
                continue
            if n.version == fam:
                rows[entry_text(n)] = exp
    present = set()
    for r in rules:
        try:
            n = ipaddress.ip_network(r, strict=False)
        except ValueError:
            continue
        if n.version == fam:
            present.add(entry_text(n))
    rs = read_hist(hist)
    for e in sorted(present):
        if e in rows:
            continue
        net = ipaddress.ip_network(e, strict=False)
        mine = [r for r in rs if r.net == net]
        perm = [r for r in mine if r.sec == 0]
        live = perm or [r for r in mine if r.t + r.sec > now]
        if live:
            r = max(live, key=lambda r: r.t)
            print("ADOPT\t%s\t%d\t%d\t%s" % (e, r.t, r.sec, r.reason))
        else:
            print("ORPHAN\t%s" % e)
    for e, exp in sorted(rows.items()):
        if e not in present and (exp == 0 or exp > now):
            print("READD\t%s" % e)


def cmd_state_find(path, target):
    """The entry of the ban list row that holds TARGET (an address or a network): the most specific row that contains it."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    with os.fdopen(fd, encoding="utf-8") as f:
        data = f.read()
    t = ipaddress.ip_network(target, strict=False)
    best = None
    for line in data.split("\n"):
        col = line.split("\t")[0]
        if not col:
            continue
        try:
            n = ipaddress.ip_network(col, strict=False)
        except ValueError:
            continue
        if n.version == t.version and t.subnet_of(n) and (best is None or n.prefixlen > best.prefixlen):
            best = n
    if best is not None:
        print(entry_text(best))


NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")   # fullmatch only: "$" would also match before a trailing newline
AUDIT_TAIL = 4 * 1024 * 1024


def cmd_auditname(path, entry, now, window):
    """The user name of the newest auth_fail row of the audit log (event time username real_ip ...) whose real_ip is ENTRY (an address, or a
    network: an address inside it) and whose time is within WINDOW seconds of NOW. Prints the name, or nothing: no file, no row, a "-" user, an
    unreadable row, an invalid name. Only the last AUDIT_TAIL bytes are read and only a regular file is opened (a FIFO or a link in its place
    must not block or redirect the ban). Always status 0: no name is not an error."""
    net = ipaddress.ip_network(entry, strict=False)
    now, window = int(now), int(window)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        with os.fdopen(fd, "rb") as f:
            fd = -1
            size = os.fstat(f.fileno()).st_size
            start = max(0, size - AUDIT_TAIL)
            f.seek(start)
            data = f.read(AUDIT_TAIL)
    except OSError:
        return
    finally:
        if fd >= 0:
            os.close(fd)
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]    # the first line of a tail starts in the middle of a row
    best_t, best_user = None, None
    for raw in lines:
        try:
            f = raw.decode("utf-8").split("\t")
        except UnicodeError:
            continue
        if len(f) < 4 or f[0] != "auth_fail" or not re.fullmatch(r"[0-9]{1,12}", f[1]):
            continue
        t = int(f[1])
        if abs(now - t) > window:
            continue
        try:
            a = unwrap(ipaddress.ip_address(f[3]))
        except ValueError:
            continue
        if a.version != net.version or a not in net:
            continue
        if best_t is None or t >= best_t:    # the newest row; on a tie the later line
            best_t, best_user = t, f[2]
    if best_user is not None and NAME_RE.fullmatch(best_user):
        print(best_user)


def cmd_event(path, when, action, address, prefix, reason, off, sec, forced, user="-"):
    rec = {
        "time": datetime.datetime.fromtimestamp(int(when), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "time_unix": int(when),
        "address": address,
        "prefix": int(prefix),
        "reason": reason,
        "offence": int(off),
        "ban_seconds": int(sec),
        "action": action,
    }
    if forced == "1":
        rec["forced"] = True
    rec["user"] = user if NAME_RE.fullmatch(user) else "-"
    d = os.path.dirname(path) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(rec, separators=(",", ":")) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


CMDS = {
    "classify": (cmd_classify, 3), "guard": (cmd_guard, 1), "decide": (cmd_decide, 10), "append": (cmd_append, 8), "prune": (cmd_prune, 3),
    "forget": (cmd_forget, 2), "has": (cmd_has, 2), "has_exact": (cmd_has_exact, 2), "is_perm": (cmd_is_perm, 2), "perm": (cmd_perm, 1),
    "migrate": (cmd_migrate, None), "listcheck": (cmd_listcheck, None), "hist_kind": (cmd_hist_kind, 1), "trust": (cmd_trust, None), "live": (cmd_live, 3), "cover": (cmd_cover, 2),
    "state_find": (cmd_state_find, 2), "sweep": (cmd_sweep, None), "temp": (cmd_temp, 2),
    "event": (cmd_event, 10), "auditname": (cmd_auditname, 4),
}
try:
    fn, n = CMDS[sys.argv[1]]
    if n is not None and len(sys.argv) - 2 != n:
        raise Exit(64)
    fn(*sys.argv[2:])
except Exit as e:
    sys.exit(e.code)
except (KeyError, IndexError):
    sys.exit(64)
except (OSError, UnicodeError):
    sys.exit(2)
PYEOF

# pylib SUBCOMMAND ARGS: run the program above
pylib() { python3 -c "$PYLIB" "$@"; }

# classify_ip ARG [MODE]: sets FAM (4 or 6), IP (the address; for a network the network address), ENTRY (what the DROP rule and the ban
# list say: the address, or "network/prefix" when the prefix is shorter than the whole address) and PFX (its prefix length).
# MODE auto (default, a ban by the engine): only an address that is allowed to be banned: refuses 0.x.x.x, unspecified, loopback,
# link-local, multicast and reserved ranges; an IPv4-mapped IPv6 address is the IPv4 address; an IPv6 address gets the prefix
# OVPN_BAN_IPV6_PREFIX (default 64), narrowed to the single address when the prefix would also cover an address of the ignore list.
# MODE manual: the same but loopback and private ranges pass (ban_guard decides); MODE target (unban, journal): an address or a network
# "address/prefix" as the ban list writes it. The address reaches python3 as an argument, never through a shell.
#   Status: 0 = accepted; 1 = INVALID address (not an address, or one that must never be banned); 2 = the classifier itself failed (python3
#   missing, crashed, unexpected output): the address is unknown, not invalid, and a caller must never discard anything because of it;
#   4 = the address is on the ignore list (auto mode only).
classify_ip() {
  local mode="${2:-auto}" out rc=0 re='^[0-9A-Fa-f:.]{2,45}$'
  [ "$mode" = "target" ] && re='^[0-9A-Fa-f:.]{2,45}(/[0-9]{1,3})?$'
  [[ "$1" =~ $re ]] || return 1
  out="$(pylib classify "$mode" "$1" "$IPV6_PREFIX" 2>/dev/null)" || rc=$?
  case "$rc" in 0) ;; 3) return 1 ;; 6) return 4 ;; *) return 2 ;; esac
  [[ "$out" =~ ^[46]\ [0-9a-f:.]+\ [0-9a-f:./]+\ [0-9]{1,3}$ ]] || return 2
  read -r FAM IP ENTRY PFX <<< "$out"
}

# classify_or_die MESSAGE ADDRESS [MODE]: classify_ip for a command line argument; exits with MESSAGE for an invalid address and with a
# different message when the classifier itself failed
classify_or_die() {
  local rc=0
  classify_ip "$2" "${3:-auto}" || rc=$?
  case "$rc" in
    0) ;;
    2) die "cannot check the address $2: the address classifier (python3) failed" ;;
    4) echo "ovpn-ban: $2 is on the ignore list (OVPN_BAN_IGNOREIP): not banned" >&2; exit 0 ;;
    *) die "$1: $2" ;;
  esac
}

# nlines DATA: sets NLINES to the number of lines of DATA (the output of a command substitution: no trailing newline, "" = 0 lines).
# A loop over a here-string snapshot counts its rows and compares them with this number: a loop whose redirection could not be set up
# runs no iteration, and "no failure counted" must never be read as "everything was checked".
nlines() {
  local t
  NLINES=0
  [ -n "$1" ] || return 0
  t="${1//[!$'\n']/}"
  NLINES=$((${#t} + 1))
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

# trust_state: fails closed (status 1, the path and the reason on stderr) when the directory of the ban list, of the history or of the lock, or
# one of the state files in them, can be written by anyone but the user of this process: not owned by that user, writable by group or
# other, a link, a second hard link, or below a directory of another user (pylib trust). The shipped state directory used to belong to the
# unprivileged "nobody" of the OpenVPN hooks, which could then replace the ban list, the history or the lock name; the check does not rely
# on the layout that moved the tree. It runs at every locked operation, so it is also the check of the start (init).
trust_state() {
  pylib trust 3 "$(dirname "$STATE")" "$(dirname "$HISTORY")" "$(dirname "$LOCK")" \
    "$STATE" "$HISTORY" "$LOCK" "$REMOVALS" "$BOOT_FILE" "$CAP_HITS" "$NOTIFY_QUEUE" >&2 \
    || { echo "ovpn-ban: ERROR: the ban engine state is not trusted (see above): refusing to run" >&2; return 1; }
}

# with_state_lock CMD [ARGS]: runs CMD while holding the exclusive lock of the ban list (the one lock for the firewall chains, the
# ban list, the history and the removal journal). Fails without running CMD when the lock is not free within LOCK_WAIT seconds.
# The wait is a poll (flock -n every 0.2 s, at most LOCK_WAIT seconds) because the BusyBox flock of the Alpine image has no -w, and
# "timeout N flock" there leaves a helper process holding the descriptor for a moment after the critical section. The lock belongs to the
# open file description of fd 9, so it is held by this subshell after the short-lived flock process has exited.
with_state_lock() {
  # the directory and the files of the engine state belong to the user of this process and to nobody else (see trust_state), and the
  # lock file is a regular file of ours: a link in its place is refused BEFORE it is opened (the >> below would follow it)
  trust_state || return 1
  if [ -L "$LOCK" ]; then echo "ovpn-ban: ERROR: the state lock $LOCK is a symbolic link: refusing to run" >&2; return 1; fi
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

# path_probe PATH: does PATH exist? 0 = it exists (lstat succeeded: any type, a link is not followed); 1 = it is MISSING (lstat failed with
# ENOENT, and the nearest existing ancestor is a directory that can be searched, so the name really is absent); 2 = any other error (EACCES,
# EIO, ELOOP, ENOTDIR, ENAMETOOLONG, a dangling link on the way, python3 failing to run: the existence is unknown). The shell tests
# [ -e ] / [ -L ] cannot tell "missing" from "lstat failed": both answer false, so a metadata I/O error looked like absence. The decision is
# taken on the errno of the filesystem call itself, in a small python program (exit 0 present, 3 missing, anything else, also the 1 of an
# uncaught exception, = unknown). Status 2 is never to be treated as "empty", "absent" or "no entries".
path_probe() {
  local rc=0
  python3 -c '
import errno, os, stat, sys
p = sys.argv[1]
try:
    os.lstat(p)
except OSError as e:
    if e.errno != errno.ENOENT:
        sys.exit(2)
else:
    sys.exit(0)
d = os.path.dirname(p) or "."
while True:
    try:
        st = os.stat(d)
    except FileNotFoundError:
        try:
            os.lstat(d)
        except FileNotFoundError:
            nd = os.path.dirname(d)
            if nd == d:
                sys.exit(2)
            d = nd
            continue
        except OSError:
            sys.exit(2)
        sys.exit(2)
    except OSError:
        sys.exit(2)
    if stat.S_ISDIR(st.st_mode) and os.access(d, os.X_OK):
        sys.exit(3)
    sys.exit(2)
' "$1" 2>/dev/null || rc=$?
  case "$rc" in 0) return 0 ;; 3) return 1 ;; *) return 2 ;; esac
}

# file_state FILE: what a read of FILE would see. 0 = a regular file that opens for reading; 1 = FILE is missing (path_probe: lstat said
# ENOENT and the directory it belongs in is searchable); 2 = anything else (a directory or other non-regular file, no read permission, a
# failed lookup of any kind, a dangling link): the content is unknown. 2 is never to be treated as "empty" or "absent".
file_state() {
  local f="$1" pr=0
  path_probe "$f" || pr=$?
  [ "$pr" -eq 1 ] && return 1
  [ "$pr" -eq 0 ] || return 2
  [ -L "$f" ] && return 2   # a link is never followed: what it points at is not the state file
  [ -f "$f" ] && [ -r "$f" ] && { : < "$f"; } 2>/dev/null && return 0
  return 2
}

# Readers of the ban list and the removal journal. Every one returns 0 when the file was read completely or does not exist
# (a first start: no entries), and 2 when it exists but cannot be read (state unknown, never "empty"). Output is only trusted with status 0.
# The history is read by the python program (pylib: a missing file is empty, an unreadable one exits 2).
#   rows_without ENTRY  every ban list row except those of ENTRY
#   read_all FILE       the whole file (callers take it into a variable and check the status before looping over it)
read_rows() { # FILE MODE ENTRY: MODE line = the first row of ENTRY, MODE others = every row except those of ENTRY
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

# entry_parts ENTRY: sets E_ADDR (the address, for a network its network address) and E_PFX (its prefix length)
entry_parts() {
  case "$1" in
    */*) E_ADDR="${1%%/*}"; E_PFX="${1##*/}" ;;
    *:*) E_ADDR="$1"; E_PFX=128 ;;
    *) E_ADDR="$1"; E_PFX=32 ;;
  esac
}

# fam_of ENTRY: 6 for an IPv6 entry, 4 otherwise
fam_of() { case "$1" in *:*) echo 6 ;; *) echo 4 ;; esac; }

# warn_log MESSAGE: a warning on our stderr (visible to a manual caller) and, when OVPN_BAN_NOTIFY_LOG is set, one line in the fail2ban
# log (fail2ban does not log the stderr of a successful action; the container mirrors that log to its own)
warn_log() {
  echo "$1" >&2
  if [ -n "$NOTIFY_LOG" ]; then echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >>"$NOTIFY_LOG" 2>/dev/null || true; fi
  return 0
}

# valid_name NAME: 0 when NAME is a user name the alert may carry: [A-Za-z0-9][A-Za-z0-9._-]{0,63}, nothing else (no space, no newline, no
# "-"). The one shell validator, used before the name reaches the queue file, the event log and the argument of the notifier.
valid_name() {
  local LC_ALL=C
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

# audit_user ENTRY NOW: sets AUDIT_USER to the user name the audit log has for the ban of ENTRY (see "User name" in the header), "-" when it
# has none. Never fails and never prints.
audit_user() {
  local out=""
  AUDIT_USER="-"
  out="$(timeout 5 python3 -c "$PYLIB" auditname "$AUDIT_LOG" "$1" "$2" "$AUDIT_WINDOW" 2>/dev/null </dev/null)" || return 0
  if valid_name "$out"; then AUDIT_USER="$out"; fi
  return 0
}

# ban_event ACTION ADDRESS PREFIX REASON OFFENCE SECONDS [FORCED [USER]]: one JSON line in the ban event log (OVPN_BAN_EVENTS_LOG, default
# /var/lib/ovpn-admin/audit/ban-events.log, created 0600 with umask 077): time, address, prefix, reason, offence, ban_seconds, action, user
# ("-" when none). One line per ban, unban and refusal, plus "expire" (a ban ran out) and "cap-evict" (a temporary ban was dropped for room).
# The panel audit trail is separate (it carries a hash chain that is only written by ovpn-admin). A log that cannot be written is a warning,
# never a failed ban.
ban_event() {
  local user="${8:--}"
  [ "$user" = "-" ] || valid_name "$user" || user="-"
  pylib event "$EVENTS_LOG" "$(date +%s)" "$1" "$2" "$3" "$4" "$5" "$6" "${7:-0}" "$user" 2>/dev/null \
    || warn_log "ovpn-ban: WARNING: cannot write the ban event log $EVENTS_LOG"
  return 0
}

# Telegram. The message carries the address (the network of an IPv6 ban), the reason, the user name when the audit log knows it, the offence
# number, the duration, the end of the ban and the host. OVPN_TELEGRAM_INCLUDE_ADDRESS=false leaves the address and the user name out (the
# notifier then gets "-" and no user). A ban reason of a manual ban is cut to the word "manual" here: its note is free text of the operator.
# Messages are queued under the lock (queue_notify) and sent after it is released (flush_notify): a slow or failing Telegram API never holds
# up the firewall.
NOTIFY_QUEUE="${STATE}.notify"
# queue_notify ban ENTRY REASON OFFENCE SECONDS [USER] | queue_notify unban ENTRY
# queue line (tab separated; no field is ever empty, so the tabs are not collapsed on reading): ban ENTRY REASON OFFENCE SECONDS USER ("-" = none)
queue_notify() {
  [ "${OVPN_TELEGRAM_ENABLED:-false}" = "true" ] || return 0
  local kind="$1" entry="$2" reason="${3:-}" user="${6:--}"
  case "$reason" in manual*) reason="manual" ;; esac
  [ "$user" = "-" ] || valid_name "$user" || user="-"
  if [ "$kind" = "ban" ]; then
    printf 'ban\t%s\t%s\t%s\t%s\t%s\n' "$entry" "$reason" "$4" "$5" "$user" >> "$NOTIFY_QUEUE" 2>/dev/null || true
  else
    printf 'unban\t%s\t\t\t\t\n' "$entry" >> "$NOTIFY_QUEUE" 2>/dev/null || true
  fi
  return 0
}

# send_notify KIND ENTRY REASON OFFENCE SECONDS [USER]: one notifier call. Never fails the caller. The notifier prints at most one line, never
# the token or a response body; the line is cut to its first 300 characters. The user name is an argument only with an address-including
# message and a valid name.
send_notify() {
  local kind="$1" entry="$2" rc=0 msg="" shown="-" user="${6:--}"
  local -a extra=()
  [ "$TG_INCLUDE_ADDRESS" = "true" ] && shown="$entry"
  if [ "$TG_INCLUDE_ADDRESS" = "true" ] && [ "$user" != "-" ] && valid_name "$user"; then extra=("$user"); fi
  if [ ! -x "$NOTIFY_BIN" ]; then
    msg="ovpn-ban: WARNING: Telegram notification ($kind) not sent: $NOTIFY_BIN is not installed"
  else
    if [ "$kind" = "ban" ]; then
      msg="$(timeout 20 "$NOTIFY_BIN" ban "$shown" "$3" "$4" "$5" ${extra[@]+"${extra[@]}"} 2>&1 </dev/null)" || rc=$?
    else
      msg="$(timeout 20 "$NOTIFY_BIN" unban "$shown" 2>&1 </dev/null)" || rc=$?
    fi
    if [ "$rc" -gt 2 ]; then msg="ovpn-ban: WARNING: Telegram notification ($kind) failed (notifier exit $rc)"; fi
  fi
  msg="${msg%%$'\n'*}"
  [ -n "$msg" ] || return 0
  warn_log "${msg:0:300}"
}

# flush_notify: send what the transactions queued. The queue file is claimed by a rename first, so two callers never send a line twice.
flush_notify() {
  local claimed="${NOTIFY_QUEUE}.$$" kind entry reason off sec user
  [ "${OVPN_TELEGRAM_ENABLED:-false}" = "true" ] || return 0
  mv -f "$NOTIFY_QUEUE" "$claimed" 2>/dev/null || return 0
  while IFS=$'\t' read -r kind entry reason off sec user; do
    case "$kind" in
      ban)
        # a name that is not valid (or a queue line of the earlier format, no sixth field) is dropped: the message goes out without it
        [ "${user:--}" = "-" ] || valid_name "$user" || user="-"
        [[ "$off" =~ ^[0-9]{1,10}$ && "$sec" =~ ^[0-9]{1,10}$ ]] && send_notify ban "$entry" "$reason" "$off" "$sec" "${user:--}" ;;
      unban) send_notify unban "$entry" ;;
    esac
  done < "$claimed"
  rm -f "$claimed"
  return 0
}

# cap_count: one more cap hit, kept in CAP_HITS (sets CAP_N)
cap_count() {
  local n=0
  [ -r "$CAP_HITS" ] && { read -r n < "$CAP_HITS" 2>/dev/null || true; }
  [[ "$n" =~ ^[0-9]{1,12}$ ]] || n=0
  CAP_N=$((n + 1))
  echo "$CAP_N" | write_file "$CAP_HITS" || true
}

# cap_hit VICTIM: the ban list is full and the oldest temporary ban VICTIM is dropped: count, log and record the event
cap_hit() {
  cap_count
  warn_log "ovpn-ban: WARNING: the ban list is full (OVPN_BAN_MAX_ENTRIES=$MAX_ENTRIES, cap hit number $CAP_N): dropped the oldest temporary ban $1"
  entry_parts "$1"
  ban_event cap-evict "$E_ADDR" "$E_PFX" "cap" 0 0
}

# cap_make_room ENTRY: the ban list holds at most OVPN_BAN_MAX_ENTRIES rows (the caller holds the lock). A ban of an entry that already has
# a row replaces it and needs no room. When the list is full, the oldest TEMPORARY ban is lifted (rule, row, event, counted); a permanent ban
# is never dropped: a list that holds only permanent bans refuses the new ban (status 4, counted and logged).
cap_make_room() {
  local entry="$1" data n victim guard=0
  while [ "$guard" -lt 1000 ]; do
    guard=$((guard + 1))
    data="$(read_all "$STATE")" || { echo "ovpn-ban: cannot read the ban list $STATE: $entry not banned" >&2; return 1; }
    n="$(awk -F '\t' -v e="$entry" 'NF >= 3 && $1 != "" { if ($1 == e) f = 1; c++ } END { print (f ? -1 : c + 0) }' <<< "$data")"
    [[ "$n" =~ ^-?[0-9]+$ ]] || return 1
    [ "$n" -lt "$MAX_ENTRIES" ] && return 0
    victim="$(awk -F '\t' 'NF >= 3 && $1 != "" && $3 != "0" { if (v == "" || $2 + 0 < m + 0) { m = $2; v = $1 } } END { print v }' <<< "$data")"
    if [ -z "$victim" ]; then
      cap_count
      warn_log "ovpn-ban: ERROR: the ban list is full of permanent bans (OVPN_BAN_MAX_ENTRIES=$MAX_ENTRIES, cap hit number $CAP_N): $entry not banned"
      entry_parts "$entry"
      ban_event cap-refuse "$E_ADDR" "$E_PFX" "cap" 0 0
      return 4
    fi
    fw_remove "$(fam_of "$victim")" "$victim" || return 1
    publish "$STATE" rows_without "$victim" || return 1
    cap_hit "$victim"
  done
  return 1
}

# txn_expire NOW: lift every ban whose expires_at has passed (the caller holds the lock): DROP rule, row, event, queued unban message.
# A permanent row (expires_at 0) is never touched. Fails (status 1) when the ban list cannot be read or one lifting did not complete;
# the rest is still done and the next call repeats the rest.
txn_expire() {
  local now="$1" data list entry rc=0 seen=0 want
  data="$(read_all "$STATE")" || { echo "ovpn-ban: cannot read the ban list $STATE: expiry not checked" >&2; return 1; }
  [ -n "$data" ] || return 0
  list="$(awk -F '\t' -v now="$now" 'NF >= 3 && $1 != "" && $3 ~ /^[0-9]+$/ && $3 != "0" && $3 + 0 <= now + 0 { print $1 }' <<< "$data")" || return 1
  [ -n "$list" ] || return 0
  nlines "$list"; want="$NLINES"
  while IFS= read -r entry <&3; do
    seen=$((seen + 1))
    fw_remove "$(fam_of "$entry")" "$entry" || { rc=1; continue; }
    publish "$STATE" rows_without "$entry" || { rc=1; continue; }
    entry_parts "$entry"
    ban_event expire "$E_ADDR" "$E_PFX" "expired" 0 0
    queue_notify unban "$entry"
  done 3<<< "$list"
  [ "$seen" -eq "$want" ] || rc=1
  return "$rc"
}

# reconcile_family FAM NOW: the DROP rules of one chain and the rows of the ban list of that family agree (the caller holds the lock). The
# order of a ban is DROP rule, history row, list row (txn_ban_fw), so a kill or a failed write leaves exactly one of these two states, and
# both are put right here: a rule with a history row of a ban in force but no list row is ADOPTED (the row is written from the history), a rule
# with neither is an ORPHAN and is removed (nothing could ever lift it). A row of a ban that has not run out and has no rule gets its rule
# back. Only rules of the exact shape "-A CHAIN -s SOURCE -j DROP" are looked at; a chain that does not exist is skipped.
reconcile_family() {
  local fam="$1" now="$2" chain listing plan kind entry t sec reason exp rc=0
  local -a srcs=()
  chain="$(chain_of "$fam")"
  [ "$fam" = "6" ] && [ "$V6" != "true" ] && return 0
  ipt "$fam" -n -L "$chain" >/dev/null 2>&1 || return 0
  listing="$(ipt "$fam" -S "$chain" 2>/dev/null)" || { echo "ovpn-ban: WARNING: cannot list chain $chain: rules and ban list not reconciled" >&2; return 1; }
  while IFS= read -r entry; do
    [ -n "$entry" ] && srcs+=("$entry")
  done < <(awk -v chain="$chain" '$1 == "-A" && $2 == chain && NF == 6 && $3 == "-s" && $5 == "-j" && $6 == "DROP" { print $4 }' <<< "$listing")
  plan="$(pylib sweep "$STATE" "$HISTORY" "$now" "$fam" "${srcs[@]}")" || { echo "ovpn-ban: WARNING: cannot read the ban list or the history: rules and ban list not reconciled" >&2; return 1; }
  [ -n "$plan" ] || return 0
  while IFS=$'\t' read -r kind entry t sec reason <&3; do
    case "$kind" in
      ORPHAN)
        if fw_remove "$fam" "$entry"; then
          warn_log "ovpn-ban: WARNING: removed the DROP rule of $entry: it had no row in the ban list and no ban in force in the history (a ban that was interrupted)"
          entry_parts "$entry"
          ban_event orphan-removed "$E_ADDR" "$E_PFX" "orphan-rule" 0 0
        else
          rc=1
        fi ;;
      ADOPT)
        [[ "$t" =~ ^[0-9]{1,12}$ && "$sec" =~ ^[0-9]{1,10}$ ]] || { rc=1; continue; }
        exp=0
        [ "$sec" -gt 0 ] && exp=$((t + sec))
        [ -n "$reason" ] || reason="restored"
        if ban_row "$entry" 0 "$reason" "$t" "$exp"; then
          warn_log "ovpn-ban: WARNING: wrote the missing ban list row of $entry from the history (a ban that was interrupted after its DROP rule)"
        else
          rc=1
        fi ;;
      READD)
        if ipt "$fam" -A "$chain" -s "$entry" -j DROP; then
          warn_log "ovpn-ban: WARNING: put the DROP rule of $entry back: the ban list has a ban in force for it"
        else
          rc=1
        fi ;;
    esac
  done 3<<< "$plan"
  return "$rc"
}

# txn_sweep NOW: the expiry and the reconciliation of both chains (the caller holds the lock). Run by "expire" (the watcher, every
# OVPN_BAN_SWEEP_SECONDS) and by the restore of every jail start. Fails (status 1) when a part of it could not be done.
txn_sweep() {
  local now="$1" rc=0
  txn_expire "$now" || rc=1
  reconcile_family 4 "$now" || rc=1
  reconcile_family 6 "$now" || rc=1
  return "$rc"
}

# txn_ban_fw ADDRESS ENTRY FAMILY PREFIX FAILURES REASON MODE MANUAL_SECONDS: the whole ban in ONE critical section (the caller holds the
# lock): complete a pending removal, lift expired bans, make room (OVPN_BAN_MAX_ENTRIES), decide the offence number and the length from the
# history (pylib decide), check/add the DROP rule for ENTRY, record the offence and the row. The firewall check and the state decision can
# therefore not be separated by an unban of the same entry. MODE is auto (fail2ban: escalation) or manual (MANUAL_SECONDS, 0 = permanent).
# Prints "OFFENCE SECONDS EXPIRES_AT ADDED APPENDED ACTIVE USER" on stdout (USER: the name of the audit log, "-" = none) (SECONDS and EXPIRES_AT 0 = permanent). When the history cannot be
# written, a rule added here is taken out again; a firewall read error refuses the ban.
txn_ban_fw() {
  local addr="$1" entry="$2" fam="$3" pfx="$4" fails="$5" reason="$6" mode="$7" msec="$8"
  local chain now out rc added=0 boot=0 off sec append base expires active=0 rk=none have=0 banned_at
  chain="$(chain_of "$fam")"
  reconcile_removals || echo "ovpn-ban: WARNING: a pending removal could not be completed yet" >&2
  # The journal line of THIS entry is committed intent (a force-unban the caller was told about or crashed in). It is cleared only by a
  # completed removal (removal_apply). While it is still there the replay of this entry failed (or its journal cannot be read): the new
  # ban fails and the line stays, so the removal is repeated by the next operation. A retry can only go on after the replay succeeded.
  removal_has "$entry"; rc=$?
  case "$rc" in
    0) echo "ovpn-ban: the pending removal of $entry could not be completed (the journal line is kept, the removal is repeated by the next operation): $entry not banned" >&2; return 1 ;;
    1) ;;
    *) echo "ovpn-ban: cannot read the removal journal $REMOVALS: $entry not banned" >&2; return 1 ;;
  esac
  # no ban is decided from a history that is unreadable, not recognised or not migrated yet: it could be missing permanent bans
  hist_gate || { echo "ovpn-ban: $entry not banned" >&2; return 1; }
  now="$(date +%s)"
  txn_expire "$now" || echo "ovpn-ban: WARNING: an expired ban could not be lifted yet" >&2
  ensure_chain "$fam" || { echo "ovpn-ban: cannot create chain $chain" >&2; return 1; }
  [ -r "$BOOT_FILE" ] && { read -r boot < "$BOOT_FILE" 2>/dev/null || true; }
  [[ "$boot" =~ ^[0-9]{1,12}$ ]] || boot=0
  # One incident is counted once. Whether this entry is ALREADY banned (its DROP rule, and a row or a history row of a ban that has not run
  # out) is read BEFORE the decision: a repeated action for an active entry (a retry, a duplicate action of the jail) is the same incident
  # and must not advance the ladder. Manual bans are an explicit new decision of the operator and are not affected.
  fw_has "$fam" "$entry"; rc=$?
  case "$rc" in
    0) have=1 ;;
    1) ;;
    *) echo "ovpn-ban: cannot read chain $chain of the firewall: $entry not banned" >&2; return 1 ;;
  esac
  if [ "$have" -eq 1 ] && [ "$mode" = "auto" ]; then
    rk="$(row_kind "$entry")" || { echo "ovpn-ban: cannot read the ban list $STATE: $entry not banned" >&2; return 1; }
    if [ "$rk" != "none" ]; then
      active=1
    else
      rc=0
      pylib live "$HISTORY" "$entry" "$now" >/dev/null 2>&1 || rc=$?
      case "$rc" in
        0) active=1 ;;   # rule and history of a ban in force, row missing (a kill between the history and the row): the row is repaired below
        1) ;;
        *) echo "ovpn-ban: cannot read the ban history $HISTORY: $entry not banned" >&2; return 1 ;;
      esac
    fi
  fi
  out="$(pylib decide "$HISTORY" "$entry" "$mode" "$now" "$DECAY_SECONDS" "$STEPS_CSV" "$msec" "$boot" "$RESTART_GRACE" "$active")" \
    || { echo "ovpn-ban: cannot read the ban history $HISTORY: $entry not banned" >&2; return 1; }
  read -r off sec append base <<< "$out"
  [[ "$off" =~ ^[0-9]{1,10}$ && "$sec" =~ ^[0-9]{1,10}$ && "$append" =~ ^[01]$ && "$base" =~ ^[0-9]{1,12}$ ]] \
    || { echo "ovpn-ban: internal error: unexpected result of the ban decision" >&2; return 1; }
  cap_make_room "$entry" || return 1
  if [ "$have" -eq 0 ]; then
    ipt "$fam" -A "$chain" -s "$entry" -j DROP || { echo "ovpn-ban: cannot add DROP rule for $entry" >&2; return 1; }
    added=1
  fi
  # Order of the writes: DROP rule, history, row. A kill (or a failed write) between them is recoverable: the rule is the enforcement and
  # is never taken out for a failed record; the history row is the evidence that reconcile_rules (every sweep, see txn_sweep) adopts a
  # rule from (it writes the missing row), and a rule with no row and no history of a ban in force is an orphan that the sweep removes.
  if [ "$append" = "1" ]; then
    if ! publish "$HISTORY" pylib append "$HISTORY" "$now" "$DECAY_SECONDS" "$addr" "$pfx" "$reason" "$off" "$sec"; then
      if [ "$added" -eq 1 ]; then
        fw_remove "$fam" "$entry" || echo "ovpn-ban: WARNING: the DROP rule of $entry stays although the history could not be written" >&2
      fi
      echo "ovpn-ban: cannot update $HISTORY for $entry" >&2
      return 1
    fi
  fi
  expires=0
  [ "$sec" -gt 0 ] && expires=$((base + sec))
  banned_at="$now"
  [ "$active" -eq 1 ] && banned_at="$base"
  if [ "$active" -eq 1 ] && [ "$rk" != "none" ]; then
    :   # the same ban, still running: its row (banned_at, expires_at, failures, reason) stays as it is
  elif ! ban_row "$entry" "$fails" "$reason" "$banned_at" "$expires"; then
    # the rule stays (fail closed) when the history has the ban: the sweep writes the row from it. Without a history row the rule would
    # be an orphan that nothing could lift, so it is taken out again
    if [ "$append" != "1" ] && [ "$added" -eq 1 ]; then fw_remove "$fam" "$entry" || true; fi
    echo "ovpn-ban: cannot update $STATE for $entry" >&2
    return 1
  fi
  # a new ban (no DROP rule before) or a new offence is announced once; the same ban that is only re-applied is not announced again
  # The user name is looked up here, before the message is queued (the audit log is read through a bounded tail: no waiting inside the lock).
  AUDIT_USER="-"
  if [ "$added" -eq 1 ] || [ "$append" = "1" ]; then
    audit_user "$entry" "$now"
    queue_notify ban "$entry" "$reason" "$off" "$sec" "$AUDIT_USER"
  fi
  echo "$off $sec $expires $added $append $active $AUDIT_USER"
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

# removal_apply ENTRY FAMILY: carry out a recorded removal (idempotent, every step can be repeated): DROP rule (absence read back), row, history
# rows of the network (every offence of it: the address starts clean), then verify all three and clear the journal line. Returns 1 at the
# first step that fails, including every read error of the ban list or the history (an unreadable file is not an absent entry); the journal
# line then stays and the next ban engine operation repeats the removal. Replacements of the ban list and the history are published only
# after their old content was read completely (publish).
removal_apply() {
  local ip="$1" fam="$2" rc rk hrc=0
  fw_remove "$fam" "$ip" || return 1
  publish "$STATE" rows_without "$ip" || { echo "ovpn-ban: cannot rewrite the ban list $STATE: removal of $ip not complete" >&2; return 1; }
  # only the offence rows of exactly this entry are forgotten: an overlapping entry (a narrower host in a prefix, a broader prefix around a
  # host) has its own rule, and a rule whose history is gone is not restored at the next start
  pylib has_exact "$HISTORY" "$ip" || hrc=$?
  case "$hrc" in
    0) publish "$HISTORY" pylib forget "$HISTORY" "$ip" || { echo "ovpn-ban: cannot rewrite the ban history $HISTORY: removal of $ip not complete" >&2; return 1; } ;;
    1) ;;
    *) echo "ovpn-ban: cannot read the ban history $HISTORY: removal of $ip not complete" >&2; return 1 ;;
  esac
  fw_has "$fam" "$ip"; rc=$?
  [ "$rc" -eq 1 ] || { echo "ovpn-ban: $ip is still in the firewall after its removal" >&2; return 1; }
  rk="$(row_kind "$ip")" || { echo "ovpn-ban: cannot read the ban list $STATE: removal of $ip not verified" >&2; return 1; }
  hrc=0
  pylib has_exact "$HISTORY" "$ip" || hrc=$?
  [ "$hrc" -eq 1 ] || { echo "ovpn-ban: cannot verify the ban history $HISTORY: removal of $ip not verified" >&2; return 1; }
  if [ "$rk" != "none" ]; then echo "ovpn-ban: $ip is still in the ban list after its removal" >&2; return 1; fi
  removal_drop "$ip" || return 1
}

# reconcile_removals: complete every removal left in the journal (the caller holds the lock). Fails when one cannot be completed or when the
# journal itself cannot be read (the pending removals are then unknown).
reconcile_removals() {
  local ip rc=0 data seen=0 want crc
  data="$(read_all "$REMOVALS")" || { echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS: pending removals unknown" >&2; return 1; }
  [ -n "$data" ] || return 0
  nlines "$data"; want="$NLINES"
  while IFS= read -r ip <&3; do
    seen=$((seen + 1))
    [ -n "$ip" ] || continue
    crc=0
    classify_ip "$ip" target || crc=$?
    if [ "$crc" -eq 1 ]; then
      # only a line that is not a bannable address or network is discarded; a failing classifier says nothing about the line, which stays
      removal_drop "$ip" || rc=1
      continue
    elif [ "$crc" -ne 0 ]; then
      echo "ovpn-ban: WARNING: the pending removal of $ip is kept: the address classifier failed" >&2
      rc=1
      continue
    fi
    if removal_apply "$ENTRY" "$FAM"; then
      echo "ovpn-ban: completed the pending removal of $ENTRY" >&2
    else
      echo "ovpn-ban: WARNING: the pending removal of $ENTRY is not complete yet" >&2
      rc=1
    fi
  done 3<<< "$data"
  if [ "$seen" -ne "$want" ]; then
    echo "ovpn-ban: ERROR: the removal journal snapshot was not consumed completely ($seen of $want lines): pending removals not done" >&2
    return 1
  fi
  return "$rc"
}

# txn_unban TARGET DEFAULT_ENTRY FORCE: under the lock. TARGET is what the caller named (an address, or a network as the ban list writes it).
# The entry that is removed is the one the ban list holds for it (pylib state_find: the row whose network contains TARGET), so an unban
# removes exactly the rule that was added, with the prefix it was added with; without a row it is DEFAULT_ENTRY (what a ban would add now).
# A permanent entry (history row without end, or a row without expiry) is kept unless FORCE=1. A temporary one is lifted only when its
# expires_at has passed: fail2ban unbans at its own bantime, which is the first escalation step and ends before a longer ban does (the
# periodic "expire" lifts those when they run out). FORCE=1 records the removal in the journal first (the commit point), then applies it
# (removal_apply): from there on it always ends in "unbanned", even when a step fails (an unreadable history or ban list included) and the
# caller is told so: the journal line stays and the removal is repeated by the next operation, never reversed. Success is only reported
# after absence is verified. Without FORCE the permanence decision needs the history and the ban list: when one cannot be read the state is
# unknown and the unban fails (nothing changed).
txn_unban() {
  local target="$1" def="$2" force="$3" entry found fam rc perm=0 rk row now had=0 exp
  reconcile_removals || echo "ovpn-ban: WARNING: a pending removal could not be completed yet" >&2
  hist_gate || { echo "ovpn-ban: unban of $target not done" >&2; return 1; }
  found="$(pylib state_find "$STATE" "$target")" || { echo "ovpn-ban: cannot read the ban list $STATE: unban of $target not done" >&2; return 1; }
  entry="${found:-$def}"
  fam="$(fam_of "$entry")"
  fw_has "$fam" "$entry"; rc=$?
  [ "$rc" -eq 1 ] || had=1
  rk="$(row_kind "$entry")" || {
    [ "$force" = "1" ] || { echo "ovpn-ban: cannot read the ban list $STATE: unban of $entry not done" >&2; return 1; }
    rk="unknown"   # a forced removal goes on: the journal repeats it until the ban list can be read
  }
  [ "$rk" != "none" ] && had=1
  if [ "$force" = "1" ]; then
    pylib has "$HISTORY" "$entry" && had=1
    removal_add "$entry" || { echo "ovpn-ban: cannot record the removal of $entry: nothing was changed" >&2; return 1; }
    removal_apply "$entry" "$fam" || { echo "ovpn-ban: removal of $entry is recorded but not complete: the next ban engine operation finishes it, it is not restored" >&2; return 1; }
    entry_parts "$entry"
    ban_event unban "$E_ADDR" "$E_PFX" "manual-unban" 0 0
    [ "$had" -eq 1 ] && queue_notify unban "$entry"
    unban_result "$entry" "$target" "$had"
    return 0
  fi
  rc=0
  pylib is_perm "$HISTORY" "$entry" || rc=$?
  case "$rc" in
    0) perm=1 ;;
    1) ;;
    *) echo "ovpn-ban: cannot read the ban history $HISTORY: unban of $entry not done" >&2; return 1 ;;
  esac
  [ "$rk" = "perm" ] && perm=1
  if [ "$perm" = "1" ]; then
    echo "ovpn-ban: $entry is permanently banned, unban ignored (use unban $entry --force)" >&2
    return 0
  fi
  now="$(date +%s)"
  row="$(read_rows "$STATE" line "$entry")" || { echo "ovpn-ban: cannot read the ban list $STATE: unban of $entry not done" >&2; return 1; }
  if [ -n "$row" ]; then
    IFS=$'\t' read -r _ _ exp _ <<< "$row"
    if [[ "$exp" =~ ^[0-9]{1,12}$ ]] && [ "$exp" -gt "$now" ]; then
      echo "ovpn-ban: $entry is banned for $((exp - now)) more seconds, unban ignored (the ban ends on its own; use unban $entry --force)" >&2
      return 0
    fi
  fi
  fw_remove "$fam" "$entry" || return 1
  publish "$STATE" rows_without "$entry" || return 1
  if [ "$had" -eq 1 ]; then
    entry_parts "$entry"
    ban_event unban "$E_ADDR" "$E_PFX" "expired" 0 0
    queue_notify unban "$entry"
  fi
  unban_result "$entry" "$target" "$had"
  return 0
}

# unban_result ENTRY REQUESTED HAD: the line the caller answers an operator from: the entry that was really lifted (an unban of an
# address inside a banned prefix lifts the prefix), whether there was anything to lift, and an overlapping entry that STILL blocks (its
# rule and its history are untouched)
unban_result() {
  local cov
  cov="$(pylib cover "$STATE" "$1" 2>/dev/null)" || cov=""
  cov="${cov%%$'\n'*}"
  echo "ovpn-ban-result unban entry=$1 requested=$2 had=$3 still=${cov:--}"
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

# hist_gate: is the history of the permanent bans KNOWN? The one question that must never be answered "no entries" by accident. Sets
# HIST_WHY and returns 2 unless the source of truth is one of
#   - the history file, readable, a regular file, empty or entirely in the current format (an explicitly empty file the operator really
#     has is a history with no bans: nothing is lost), or
#   - no history file AND no file of the earlier releases anywhere (a fresh installation: no history is the correct answer).
# Everything else is "unknown": the history exists but cannot be read (permissions, a directory or a link in its place, an I/O error), is not
# in a recognised format (including the 7-field format of the earlier releases at the path OVPN_BAN_HISTORY names, until it is converted), or
# does not exist while a file of the earlier releases does (the migration did not happen or failed). Restore, check, a ban and an unban
# refuse to go on from an unknown history; the init of a container start fails, which stops it with OVPN_BAN_REQUIRED=true (configure.sh).
hist_gate() {
  local st=0 f kind rc=0 lst
  HIST_WHY=""
  file_state "$HISTORY" || st=$?
  case "$st" in
    0)
      kind="$(pylib hist_kind "$HISTORY" 2>&1)" || rc=$?
      if [ "$rc" -ne 0 ]; then
        case "$rc" in
          2) HIST_WHY="the ban history $HISTORY cannot be read" ;;
          *) HIST_WHY="the ban history $HISTORY is not in a recognised format: ${kind#ovpn-ban: ERROR: }" ;;
        esac
      elif [ "$kind" = "legacy" ]; then
        HIST_WHY="the ban history $HISTORY is in the format of the earlier releases (7 fields) and has not been converted"
      else
        return 0
      fi ;;
    1)
      for f in "${LEGACY_FILES[@]}"; do
        lst=0
        path_probe "$f" || lst=$?
        case "$lst" in
          1) ;;
          0) HIST_WHY="the ban history of the earlier releases $f exists but was not migrated to $HISTORY"; break ;;
          *) HIST_WHY="cannot tell whether the ban history of the earlier releases $f exists"; break ;;
        esac
      done
      [ -z "$HIST_WHY" ] && return 0 ;;
    *) HIST_WHY="the ban history $HISTORY cannot be read (no read permission, not a regular file, a symbolic link or an I/O error)" ;;
  esac
  echo "ovpn-ban: ERROR: $HIST_WHY: the permanent bans are UNKNOWN, refusing to treat the history as empty" >&2
  return 2
}

# old_lists: sets OLDL to the ban list(s) of the earlier release that exist (the ban list of this engine, which in the earlier layout is the one
# the old release wrote, and bans.tsv in the directory of the earlier layout, OVPN_BAN_LEGACY_DIR). A migration is checked against them: every
# permanent entry in them must be in the migrated history (cmd_migrate), because a history file that was cut short, or emptied, still parses and
# its missing rows are not seen by any format check. Returns 1, the file named, when one exists and cannot be read, or lies in the directory of the
# earlier layout and is not a plain file of ours: its permanent bans are unknown, so nothing is migrated.
old_lists() {
  local f st
  local -a cand=("$STATE")
  OLDL=()
  [ "$LEGACY_DIR/bans.tsv" = "$STATE" ] || cand+=("$LEGACY_DIR/bans.tsv")
  for f in "${cand[@]}"; do
    st=0
    file_state "$f" || st=$?
    case "$st" in
      1) ;;
      0) OLDL+=("$f") ;;
      *) echo "ovpn-ban: ERROR: the ban list $f exists but cannot be read (permissions, a link or an I/O error): its permanent bans cannot be compared with the history, not migrated" >&2; return 1 ;;
    esac
    if [ "$st" -eq 0 ] && [ "$f" != "$STATE" ]; then
      pylib trust 0 "$f" >&2 || { echo "ovpn-ban: ERROR: the ban list $f is not trusted (see above): not migrated" >&2; return 1; }
    fi
  done
}

# conv_marker: has a conversion of the history of the earlier releases happened here? 0 when it left its proof: FILE.legacy-format next to the
# history (the in-place conversion, also with the time stamp migrate_legacy adds when one exists) or ban-history.tsv.migrated beside a file
# of the earlier releases (the migration). Only a plain file counts, never a link.
conv_marker() {
  local f m
  for m in "${HISTORY}.legacy-format" "${HISTORY}".legacy-format.*; do
    [ -f "$m" ] && [ ! -L "$m" ] && return 0
  done
  for f in "${LEGACY_FILES[@]}"; do
    [ -f "${f}.migrated" ] && [ ! -L "${f}.migrated" ] && return 0
  done
  return 1
}

# list_gate: the second record. The history is known (hist_gate said so) but it can still be shorter than it was: cut at a row end, emptied,
# replaced, and every row that is left is a valid row. The ban lists say what was banned, so the permanent entries of
#   - the ban list of this engine ($STATE: written after the history row of each ban, emptied of a ban only after the history lost it; it is
#     left as it was by a container stop or a crash (not by the jail stop, teardown, unless the history is unknown or lacks rows of the
#     list: then teardown keeps it as well) and by a refused start), always, and
#   - bans.tsv of the earlier layout (OVPN_BAN_LEGACY_DIR), when the history is empty or missing and nothing proves that a conversion
#     happened (conv_marker). After a conversion that file is an old copy: the operator may have lifted the bans since, and it is not
#     compared again.
# must all be in the history (cmd_listcheck). Otherwise the start is refused, both files named, and nothing is changed. The caller holds the
# lock and has seen hist_gate succeed. A ban list that exists but cannot be read, or is not a ban list, refuses the start as well.
list_gate() {
  local st=0 hk="" f lst=0
  local -a lists=()
  file_state "$STATE" || st=$?
  case "$st" in
    0) lists+=("$STATE") ;;
    1) ;;
    *) echo "ovpn-ban: ERROR: the ban list $STATE exists but cannot be read (permissions, a link or an I/O error): its permanent bans cannot be compared with the ban history $HISTORY" >&2; return 1 ;;
  esac
  st=0
  file_state "$HISTORY" || st=$?
  case "$st" in
    1) hk=missing ;;
    0) hk="$(pylib hist_kind "$HISTORY" 2>/dev/null)" || { echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY" >&2; return 1; } ;;
    *) echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY" >&2; return 1 ;;
  esac
  f="$LEGACY_DIR/bans.tsv"
  if { [ "$hk" = "missing" ] || [ "$hk" = "empty" ]; } && [ "$f" != "$STATE" ] && ! conv_marker; then
    file_state "$f" || lst=$?
    case "$lst" in
      0)
        pylib trust 0 "$f" >&2 || { echo "ovpn-ban: ERROR: the ban list $f is not trusted (see above): its permanent bans cannot be compared with the ban history $HISTORY" >&2; return 1; }
        lists+=("$f") ;;
      1) ;;
      *) echo "ovpn-ban: ERROR: the ban list $f exists but cannot be read (permissions, a link or an I/O error): its permanent bans cannot be compared with the ban history $HISTORY" >&2; return 1 ;;
    esac
  fi
  [ "${#lists[@]}" -gt 0 ] || return 0
  pylib listcheck "$HISTORY" "${lists[@]}" >&2 || {
    HIST_WHY="the ban history $HISTORY lacks permanent bans of ${lists[*]}"
    echo "ovpn-ban: ERROR: $HIST_WHY: the permanent bans are UNKNOWN, refusing to start without them" >&2
    return 1
  }
}

# migrate_legacy: the per-address history of the earlier releases (ban-history.tsv: 7 fields, one row per address with a counter and a
# permanent flag) becomes offence rows (6 fields) in the history, once. A permanent address stays permanent. The old file is renamed to
# ban-history.tsv.migrated, never deleted. The caller holds the lock. Returns 1 (and says which file) when it cannot do it, and then
# changes nothing: hist_gate keeps the engine from starting on a history that is not there.
#   - the history file is missing: every file of the earlier releases that exists (LEGACY_FILES: next to the ban list, and the audit
#     directory of the earlier layout) must be readable and entirely in the earlier format, else nothing is migrated; the rows of all of
#     them go into the new file;
#   - the history file exists and is itself in the earlier format (OVPN_BAN_HISTORY still names the old file): it is converted in place; the
#     original is kept as FILE.legacy-format (or FILE.legacy-format.UNIXTIME);
#   - a file that is readable but zero bytes is an empty history (nothing to lose) and migrates to an empty history.
migrate_legacy() {
  local nst=0 lst f mig="${OVPN_BAN_BANTIME:-3600}" kind rc=0 backup
  local -a present=()
  [[ "$mig" =~ ^[1-9][0-9]{0,8}$ ]] || mig=3600
  file_state "$HISTORY" || nst=$?
  case "$nst" in
    0)
      kind="$(pylib hist_kind "$HISTORY" 2>/dev/null)" || return 1   # unreadable or not recognised: hist_gate names it
      for f in "${LEGACY_FILES[@]}"; do
        lst=0
        [ "$f" = "$HISTORY" ] || path_probe "$f" || lst=$?
        [ "$f" != "$HISTORY" ] && [ "$lst" -ne 1 ] && echo "ovpn-ban: WARNING: the ban history of the earlier releases $f exists next to the current history $HISTORY and is NOT used; check it for permanent bans and remove it" >&2
      done
      [ "$kind" = "legacy" ] || return 0
      old_lists || return 1
      backup="${HISTORY}.legacy-format"
      [ -e "$backup" ] || [ -L "$backup" ] && backup="${backup}.$(date +%s)"
      cp -p -- "$HISTORY" "$backup" || { echo "ovpn-ban: ERROR: cannot keep a copy of $HISTORY as $backup: not converted" >&2; return 1; }
      publish "$HISTORY" pylib migrate "$mig" "${#OLDL[@]}" ${OLDL[@]+"${OLDL[@]}"} "$HISTORY" || {
        rm -f -- "$backup"   # the copy of a file that stays as it is
        echo "ovpn-ban: ERROR: cannot convert the ban history $HISTORY to the current format (see above): the file is left as it is" >&2
        return 1
      }
      echo "ovpn-ban: converted the ban history $HISTORY from the format of the earlier releases (the original is kept as $backup)" >&2
      return 0 ;;
    1) ;;
    *) return 1 ;;
  esac
  for f in "${LEGACY_FILES[@]}"; do
    [ "$f" != "$HISTORY" ] || continue
    lst=0
    file_state "$f" || lst=$?
    case "$lst" in
      1) ;;
      0) present+=("$f") ;;
      *) echo "ovpn-ban: ERROR: cannot read the ban history of the earlier releases $f (permissions, a link or an I/O error): not migrated" >&2; return 1 ;;
    esac
  done
  [ "${#present[@]}" -gt 0 ] || return 0
  # a file in the directory of the earlier layout (the VPN hook user owned that directory) is read only when it is a plain file of ours
  pylib trust 0 "${present[@]}" >&2 || { echo "ovpn-ban: ERROR: the ban history of the earlier releases ${present[*]} is not trusted (see above): not migrated" >&2; return 1; }
  old_lists || return 1
  publish "$HISTORY" pylib migrate "$mig" "${#OLDL[@]}" ${OLDL[@]+"${OLDL[@]}"} "${present[@]}" || { echo "ovpn-ban: ERROR: cannot migrate the ban history ${present[*]} to $HISTORY (see above): nothing migrated" >&2; return 1; }
  for f in "${present[@]}"; do
    mv -f "$f" "${f}.migrated" 2>/dev/null || echo "ovpn-ban: WARNING: cannot rename $f to ${f}.migrated; the new history $HISTORY is used from now on" >&2
    echo "ovpn-ban: migrated the ban history $f to $HISTORY (the old file is kept as ${f}.migrated)" >&2
  done
}

# prune_history: drop the offences older than OVPN_BAN_DECAY_DAYS (a permanent entry never decays). Only an existing file is rewritten.
# The caller holds the lock.
prune_history() {
  local st=0
  file_state "$HISTORY" || st=$?
  [ "$st" -eq 0 ] || return 0
  publish "$HISTORY" pylib prune "$HISTORY" "$(date +%s)" "$DECAY_SECONDS"
}

# txn_housekeeping: migration of an old history, pruning of the decayed offences (the caller holds the lock). A failure is reported and
# returned; hist_gate (not this function) is what keeps the engine from starting on a history it could not read.
txn_housekeeping() {
  local rc=0
  migrate_legacy || rc=1
  if [ "$rc" -eq 0 ]; then
    prune_history || { echo "ovpn-ban: WARNING: cannot prune the ban history $HISTORY" >&2; rc=1; }
  fi
  return "$rc"
}

# init: DROP rules and ban list are cleared, the ban history stays (decayed offences are pruned, an old history is migrated); the start
# time is recorded for the restart rule of the ban decision. Fails (status 1, the file named on stderr) when the history of the permanent
# bans is unknown (hist_gate): the caller (configure.sh) stops the container with OVPN_BAN_REQUIRED=true. The chains and the list are
# emptied here; the bans in force (permanent, and temporary ones that have not run out) are put back from the history by setup. The
# migration runs before the list is emptied (it is checked against the old list, see old_lists), and a start that fails empties the chains
# only: the list stays as the record of what was banned.
cmd_init() {
  local rc=0
  mkdir -p "$(dirname "$STATE")" || die "cannot create $(dirname "$STATE")"
  trust_state || exit 1
  # Migration and gate first: the ban list of an earlier release is what a migration is checked against (old_lists), and the flush empties it.
  with_state_lock txn_housekeeping || true
  with_state_lock hist_gate || rc=1
  # the history is known; is it the whole history? (a cut at a row end, an emptied file: compared with the ban lists)
  [ "$rc" -eq 0 ] && { with_state_lock list_gate || rc=1; }
  if [ "$rc" -eq 0 ]; then
    with_state_lock txn_flush || die "cannot empty the ban chains and reset $STATE"
  else
    # an unknown history: the chains are emptied, the ban list is NOT. It is the only record of the permanent bans left, and the next start
    # compares the migration against it again (a start that is refused and tried again must not pass because the first one emptied it)
    with_state_lock flush_chains || die "cannot empty the ban chains"
  fi
  date +%s | write_file "$BOOT_FILE" || die "cannot write $BOOT_FILE"
  if [ "$rc" -ne 0 ]; then
    echo "ovpn-ban: ERROR: init: the history of the permanent bans is unknown (see above): the ban engine cannot restore them" >&2
    exit 1
  fi
}

# perm_entries: one line "ENTRY FAM" per permanent entry of the history that is to be enforced now (ENTRY: the address, or the network
# with the prefix it was banned with). Not listed: entries with a pending removal, IPv6 entries with IPv6 off (the intentional opt-out, warning).
# Returns 2, listing nothing trustworthy, when the history or the removal journal exists but cannot be read: a failed enumeration is an error,
# never "no permanent entries". A history file that does not exist (first start) has no entries and is a success.
perm_entries() {
  local line entry fam t reason data jr seen=0 want
  hist_gate || return 2
  data="$(pylib perm "$HISTORY")" || { echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY" >&2; return 2; }
  [ -n "$data" ] || return 0
  nlines "$data"; want="$NLINES"
  while IFS= read -r line || [ -n "$line" ]; do
    seen=$((seen + 1))
    [ -n "$line" ] || continue
    IFS=$'\t' read -r entry fam t reason <<< "$line" || { echo "ovpn-ban: ERROR: cannot parse a row of the ban history $HISTORY" >&2; return 2; }
    jr=0
    removal_has "$entry" || jr=$?
    case "$jr" in
      0) continue ;;
      1) ;;
      *) echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS" >&2; return 2 ;;
    esac
    if [ "$fam" = "6" ] && [ "$V6" != "true" ]; then
      echo "ovpn-ban: WARNING: permanent ban of $entry NOT restored: IPv6 is not enabled" >&2
      continue
    fi
    echo "$entry $fam"
  done <<< "$data"
  if [ "$seen" -ne "$want" ]; then
    echo "ovpn-ban: ERROR: the history snapshot was not consumed completely ($seen of $want rows): the permanent bans are unknown" >&2
    return 2
  fi
}

# fail_status REQUIRED6_FAILURES OTHER_FAILURES: 3 when a required IPv6 enforcement is missing, 1 for any other failure, else 0
fail_status() {
  if [ "$1" -gt 0 ]; then return 3; fi
  if [ "$2" -gt 0 ]; then return 1; fi
  return 0
}

# restore_permanent: DROP rule and row (expires_at=0) for every permanent entry of the history, under the lock. A failing entry never
# stops the others, but any failure of an enforced family is returned (see fail_status). Skipped, not failed: IPv6 entries when IPv6 is off
# or, with OVPN_BAN_IPV6_REQUIRED=false, when the IPv6 chain cannot be created (the intentional opt-outs).
restore_permanent() {
  local line entry fam t reason chain count=0 skipped=0 failed=0 req6=0 other=0 rc data jr jst=0 seen=0 want
  # the whole history is read, and the journal checked, BEFORE anything is restored: an unreadable file is an error (status 1), not an empty history
  hist_gate || return 1
  data="$(pylib perm "$HISTORY")" || { echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY: the permanent bans are unknown, nothing restored" >&2; return 1; }
  file_state "$REMOVALS" || jst=$?
  [ "$jst" -ne 2 ] || { echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS: nothing restored" >&2; return 1; }
  [ -n "$data" ] || return 0
  nlines "$data"; want="$NLINES"
  while IFS= read -r line || [ -n "$line" ]; do
    seen=$((seen + 1))
    [ -n "$line" ] || continue
    if ! IFS=$'\t' read -r entry fam t reason <<< "$line"; then
      echo "ovpn-ban: ERROR: cannot parse a row of the ban history $HISTORY" >&2
      failed=$((failed + 1)); other=$((other + 1))
      continue
    fi
    jr=0
    removal_has "$entry" || jr=$?
    if [ "$jr" -eq 0 ]; then
      echo "ovpn-ban: WARNING: permanent entry of $entry skipped, its removal is pending" >&2
      skipped=$((skipped + 1))
      continue
    elif [ "$jr" -ne 1 ]; then
      echo "ovpn-ban: ERROR: cannot read the removal journal $REMOVALS: $entry not restored" >&2
      failed=$((failed + 1)); other=$((other + 1))
      continue
    fi
    chain="$(chain_of "$fam")"
    if [ "$fam" = "6" ] && [ "$V6" != "true" ]; then
      echo "ovpn-ban: WARNING: permanent ban of $entry NOT restored: IPv6 is not enabled" >&2
      skipped=$((skipped + 1))
      continue
    fi
    if ! ensure_chain "$fam"; then
      if [ "$fam" = "6" ] && [ "$V6_REQUIRED" != "true" ]; then
        echo "ovpn-ban: WARNING: permanent ban of $entry NOT restored: chain $chain is not available (OVPN_BAN_IPV6_REQUIRED=false)" >&2
        skipped=$((skipped + 1))
      else
        echo "ovpn-ban: ERROR: permanent ban of $entry NOT restored: chain $chain is not available" >&2
        failed=$((failed + 1)); if [ "$fam" = "6" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      fi
      continue
    fi
    fw_has "$fam" "$entry"; rc=$?
    if [ "$rc" -eq 1 ]; then
      ipt "$fam" -A "$chain" -s "$entry" -j DROP || rc=2
    elif [ "$rc" -ne 0 ]; then
      rc=2
    fi
    if [ "$rc" -eq 2 ]; then
      echo "ovpn-ban: ERROR: cannot restore the DROP rule of $entry" >&2
      failed=$((failed + 1)); if [ "$fam" = "6" ] && [ "$V6_REQUIRED" = "true" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      continue
    fi
    [[ "$t" =~ ^[1-9][0-9]{0,11}$ ]] || t="$(date +%s)"
    [ -n "$reason" ] || reason="restored"
    if ! ban_row "$entry" 0 "$reason" "$t" 0; then
      echo "ovpn-ban: ERROR: cannot restore the row of $entry" >&2
      failed=$((failed + 1)); if [ "$fam" = "6" ] && [ "$V6_REQUIRED" = "true" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      continue
    fi
    count=$((count + 1))
  done <<< "$data"
  if [ "$seen" -ne "$want" ]; then
    # the snapshot could not be set up or was not consumed to its end: rows were never looked at, so "no failure counted" proves nothing
    echo "ovpn-ban: ERROR: the history snapshot was not consumed completely ($seen of $want rows): the permanent bans are not all restored" >&2
    failed=$((failed + 1)); other=$((other + 1))
  fi
  echo "ovpn-ban: restored $count permanent ban(s)$([ "$skipped" -gt 0 ] && echo ", $skipped skipped")$([ "$failed" -gt 0 ] && echo ", $failed FAILED")" >&2
  # OVPN_BAN_MAX_ENTRIES bounds the bans that are ADMITTED (a new ban when the list is full), not the permanent bans of the history: an
  # operator's permanent bans are restored whatever the setting says, and a setting never deletes a history row. A list that is full of
  # permanent bans refuses every new key (cap-refuse): say so at the start, not at the first attack.
  [ "$count" -ge "$MAX_ENTRIES" ] && echo "ovpn-ban: WARNING: $count permanent ban(s) restored with OVPN_BAN_MAX_ENTRIES=$MAX_ENTRIES: the list is full of permanent bans, no NEW address can be banned until some are lifted or the setting is raised (nothing was dropped)" >&2
  fail_status "$req6" "$other"
}

# restore_temporary: the TEMPORARY bans of the history that are still in force (their end, time + length, has not passed) are put back
# with their original end: DROP rule and row (banned_at = the time of the offence, expires_at = its end). A container restart (init empties
# the chains and the list) therefore does not shorten a one hour or 24 hour ban, and /api/bans (the rows) and the firewall are made
# together. Newest first, at most OVPN_BAN_MAX_ENTRIES rows in all (the permanent bans come first and are never dropped); what does
# not fit is warned about and stays in the history. A ban whose removal is pending is not restored. Failures count like those of the
# permanent bans (see fail_status): a recorded ban that is not enforced is not a healthy start. The caller holds the lock.
restore_temporary() {
  local line entry fam t reason sec chain exp rc rows cnt=0 skipped=0 capped=0 failed=0 req6=0 other=0 seen=0 want jr data now
  hist_gate >/dev/null 2>&1 || return 1   # an unknown history is reported by restore_permanent
  now="$(date +%s)"
  data="$(pylib temp "$HISTORY" "$now")" || { echo "ovpn-ban: ERROR: cannot read the ban history $HISTORY: the temporary bans are unknown, not restored" >&2; return 1; }
  [ -n "$data" ] || return 0
  rows="$(awk -F '\t' 'NF >= 3 && $1 != "" { c++ } END { print c + 0 }' "$STATE")" || { echo "ovpn-ban: ERROR: cannot read the ban list $STATE: temporary bans not restored" >&2; return 1; }
  nlines "$data"; want="$NLINES"
  while IFS=$'\t' read -r entry fam t reason sec; do
    seen=$((seen + 1))
    [ -n "$entry" ] || continue
    jr=0
    removal_has "$entry" || jr=$?
    if [ "$jr" -eq 0 ]; then skipped=$((skipped + 1)); continue
    elif [ "$jr" -ne 1 ]; then failed=$((failed + 1)); other=$((other + 1)); continue; fi
    if [ "$fam" = "6" ] && [ "$V6" != "true" ]; then skipped=$((skipped + 1)); continue; fi
    rc=0
    row_kind "$entry" >/dev/null || rc=$?
    [ "$rc" -eq 0 ] || { failed=$((failed + 1)); other=$((other + 1)); continue; }
    if [ "$(row_kind "$entry")" != "none" ]; then continue; fi
    if [ "$rows" -ge "$MAX_ENTRIES" ]; then capped=$((capped + 1)); continue; fi
    chain="$(chain_of "$fam")"
    if ! ensure_chain "$fam"; then
      if [ "$fam" = "6" ] && [ "$V6_REQUIRED" != "true" ]; then skipped=$((skipped + 1))
      else failed=$((failed + 1)); if [ "$fam" = "6" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi; fi
      continue
    fi
    rc=0
    fw_has "$fam" "$entry" || rc=$?
    if [ "$rc" -eq 1 ]; then rc=0; ipt "$fam" -A "$chain" -s "$entry" -j DROP || rc=2; elif [ "$rc" -ne 0 ]; then rc=2; fi
    exp=$((t + sec))
    if [ "$rc" -ne 0 ] || ! ban_row "$entry" 0 "$reason" "$t" "$exp"; then
      echo "ovpn-ban: ERROR: cannot restore the temporary ban of $entry" >&2
      failed=$((failed + 1)); if [ "$fam" = "6" ] && [ "$V6_REQUIRED" = "true" ]; then req6=$((req6 + 1)); else other=$((other + 1)); fi
      continue
    fi
    cnt=$((cnt + 1)); rows=$((rows + 1))
  done <<< "$data"
  [ "$seen" -eq "$want" ] || { echo "ovpn-ban: ERROR: the temporary ban snapshot was not consumed completely ($seen of $want rows)" >&2; failed=$((failed + 1)); other=$((other + 1)); }
  echo "ovpn-ban: restored $cnt temporary ban(s) with their original end$([ "$skipped" -gt 0 ] && echo ", $skipped skipped")$([ "$capped" -gt 0 ] && echo ", $capped NOT restored: OVPN_BAN_MAX_ENTRIES=$MAX_ENTRIES is reached (they stay in the history until they run out)")$([ "$failed" -gt 0 ] && echo ", $failed FAILED")" >&2
  fail_status "$req6" "$other"
}

# txn_restore: migrate an old history, complete pending removals, then restore; the status of restore_permanent, or 1 when a removal cannot
# be completed
txn_restore() {
  local rc=0 r=0 trc
  txn_housekeeping
  reconcile_removals || r=1
  restore_permanent || rc=$?
  # the temporary bans in force are restored whatever became of the permanent ones (the first failure status wins)
  trc=0
  restore_temporary || trc=$?
  [ "$rc" -ne 0 ] || rc="$trc"
  if [ "$rc" -eq 0 ] && [ "$r" -ne 0 ]; then rc=1; fi
  # a rule left by an interrupted ban (a jail restart without a container restart keeps the chains): adopted or removed, see reconcile_family
  [ "$rc" -eq 0 ] && { reconcile_family 4 "$(date +%s)" || true; reconcile_family 6 "$(date +%s)" || true; }
  return "$rc"
}

# verify_permanent: every permanent entry that is to be enforced (perm_entries) has its DROP rule and a PERMANENT row (expires_at=0: a
# temporary row of the address does not count, the UI could expire it); 0, or the fail_status. A rule or a row that cannot be read counts as
# missing; a history that cannot be enumerated fails the verification (status 1).
verify_permanent() {
  local ip fam rc rk rrc why req6=0 other=0 entries seen=0 want
  entries="$(perm_entries 2>/dev/null)" || { echo "ovpn-ban: ERROR: cannot enumerate the permanent bans of the history $HISTORY: enforcement not verified" >&2; return 1; }
  nlines "$entries"; want="$NLINES"
  [ "$want" -gt 0 ] || return 0
  while read -r ip fam <&3; do
    seen=$((seen + 1))
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
  if [ "$seen" -ne "$want" ]; then
    # the entry list could not be set up as input or was not consumed to its end: entries were never verified
    echo "ovpn-ban: ERROR: the permanent entry list was not consumed completely ($seen of $want entries): enforcement not verified" >&2
    other=$((other + 1))
  fi
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

# do_ban ADDRESS ENTRY FAMILY PREFIX FAILURES REASON MODE MANUAL_SECONDS FORCED: the common part of ban and ban-manual (the address is already
# classified). Firewall check/add and the history/ban list decision are one critical section (txn_ban_fw); the event line is written after
# it and the Telegram message follows the unlock.
do_ban() {
  local addr="$1" entry="$2" fam="$3" pfx="$4" fails="$5" reason="$6" mode="$7" msec="$8" forced="$9"
  local out off sec expires added append active status user
  need_listener
  out="$(with_state_lock txn_ban_fw "$addr" "$entry" "$fam" "$pfx" "$fails" "$reason" "$mode" "$msec")" || { flush_notify; die "ban of $entry not completed"; }
  read -r off sec expires added append active user <<< "$out"
  [ "${user:--}" = "-" ] || valid_name "$user" || user="-"
  if ! [[ "$off" =~ ^[0-9]{1,10}$ && "$sec" =~ ^[0-9]{1,10}$ && "$expires" =~ ^[0-9]{1,12}$ && "$added" =~ ^[01]$ && "$append" =~ ^[01]$ && "$active" =~ ^[01]$ ]]; then
    flush_notify
    die "internal error: unexpected result of the ban transaction"
  fi
  # a new ban (the entry had no DROP rule) or a new offence is recorded once; the same ban that is only re-applied is not recorded again.
  # The ban is complete at this point.
  if [ "$added" -eq 1 ] || [ "$append" -eq 1 ]; then ban_event ban "$addr" "$pfx" "$reason" "$off" "$sec" "$forced" "${user:--}"; fi
  flush_notify
  if [ "$sec" -eq 0 ]; then
    echo "ovpn-ban: $entry banned permanently (offence $off)" >&2
  else
    echo "ovpn-ban: $entry banned for $sec seconds (offence $off)" >&2
  fi
  # what is ENFORCED, for the caller that answers an operator (ovpn-ban-control builds its reply from this line, never from the request):
  # the entry (the whole prefix of an IPv6 address), the length and end really in force, the offence, and whether anything changed
  status=new
  if [ "$added" -eq 0 ] && [ "$append" -eq 0 ]; then status=unchanged; elif [ "$added" -eq 0 ]; then status=renewed; fi
  echo "ovpn-ban-result ban entry=$entry requested=$addr seconds=$sec expires=$expires offence=$off status=$status"
  return 0
}

cmd_ban() {
  [ "$#" -eq 2 ] || die "usage: ban IP FAILURES"
  classify_or_die "refusing to ban: not a public-routable IPv4 or IPv6 address" "$1" auto
  valid_posint "$2" || die "FAILURES must be a positive integer: $2"
  do_ban "$IP" "$ENTRY" "$FAM" "$PFX" "$2" "$(reason_for "$IP")" auto 0 0
}

# ban-manual [--force] [--minutes N] IP [REASON]: an operator ban. Permanent unless --minutes (1..525600). The address is refused (status 4,
# a refusal event, no change) when it is a loopback address, on the ignore list, inside the VPN client network or a private range, unless
# --force. REASON: [A-Za-z0-9 ._:-]{0,120}; the history and the ban list carry "manual" or "manual: REASON" (the Telegram message only "manual")
cmd_ban_manual() {
  local force=0 minutes="" minutes_set=0 note="" why rc=0 msec=0 forced=0 reason
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --force) force=1; shift ;;
      --minutes) [ "$#" -ge 2 ] || die "usage: ban-manual [--force] [--minutes N] IP [REASON]"; minutes="$2"; minutes_set=1; shift 2 ;;
      --) shift; break ;;
      --*) die "usage: ban-manual [--force] [--minutes N] IP [REASON]" ;;
      *) break ;;
    esac
  done
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "usage: ban-manual [--force] [--minutes N] IP [REASON]"
  note="${2:-}"
  classify_or_die "refusing to ban: not a public-routable IPv4 or IPv6 address" "$1" manual
  [[ "$note" =~ ^[A-Za-z0-9\ ._:-]{0,120}$ ]] || die "REASON must match [A-Za-z0-9 ._:-]{0,120}"
  note="${note#"${note%%[! ]*}"}"
  note="${note%"${note##*[! ]}"}"
  if [ "$minutes_set" -eq 1 ]; then
    [[ "$minutes" =~ ^[0-9]{1,7}$ ]] && [ "$((10#$minutes))" -ge "$MIN_MANUAL_MINUTES" ] && [ "$((10#$minutes))" -le "$MAX_MANUAL_MINUTES" ] \
      || die "minutes must be a whole number from $MIN_MANUAL_MINUTES to $MAX_MANUAL_MINUTES: $minutes"
    msec=$((10#$minutes * 60))
  fi
  why="$(pylib guard "$ENTRY" 2>/dev/null)" || rc=$?
  case "$rc" in
    0) ;;
    5)
      if [ "$force" -eq 1 ]; then
        forced=1
      else
        echo "ovpn-ban: refused: $why (force=true overrides)" >&2
        ban_event refuse "$IP" "$PFX" "$why" 0 0
        exit 4
      fi ;;
    *) die "cannot check the address $1: the address classifier (python3) failed" ;;
  esac
  reason="manual"
  [ -n "$note" ] && reason="manual: $note"
  do_ban "$IP" "$ENTRY" "$FAM" "$PFX" 0 "$reason" manual "$msec" "$forced"
}

# unban IP|NETWORK [--force]: see the header. A permanent address needs --force.
cmd_unban() {
  local force=0 target def
  [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "usage: unban IP [--force]"
  if [ "$#" -eq 2 ]; then
    [ "$2" = "--force" ] || die "usage: unban IP [--force]"
    force=1
  fi
  classify_or_die "not a valid IPv4 or IPv6 address" "$1" target
  target="$ENTRY"
  def="$ENTRY"
  # a bare address without a row is looked up under the entry a ban would add now (its prefix)
  case "$1" in */*) ;; *) classify_ip "$1" manual && def="$ENTRY" ;; esac
  with_state_lock txn_unban "$target" "$def" "$force" || { flush_notify; return 1; }
  flush_notify
}

# expire: lift every temporary ban whose time has passed (also done at every ban, unban and by the watcher of ovpn-ban-control)
cmd_expire() {
  local rc=0
  with_state_lock txn_sweep "$(date +%s)" || rc=$?
  flush_notify
  return "$rc"
}

# jail-bantime: the ban time of the fail2ban jail, the first step of the escalation in seconds (-1 = permanent). fail2ban only schedules
# its own unban with it; the length of a ban is decided here and enforced by "expire"
cmd_jail_bantime() {
  if [ "${STEPS[0]}" -eq 0 ]; then echo -1; else echo "${STEPS[0]}"; fi
}

cmd_flush() {
  with_state_lock txn_flush
}

# txn_teardown: jumps, rules and chains removed in one critical section (the caller holds the lock). The rows of the ban list go with them
# only while the history can vouch for them: when hist_gate or list_gate says the history of the permanent bans is unknown or lacks a
# permanent row of the list (the state a refused init leaves), the list is the only record of those bans left and it stays as it is. The
# caller of a refusal is configure.sh: with OVPN_BAN_REQUIRED=false (or OVPN_BAN_ENABLED=false) it runs this teardown right after the
# refused init, and a list emptied there would let the next start with OVPN_BAN_REQUIRED=true pass on the damaged history (QA W1). An
# accepted init and the explicit flush command still empty the list. The gates are only read here and speak on stderr.
txn_teardown() {
  local fam rc=0 keep=0
  # The two gates read the files of the permanent bans (a python call each) and run FIRST, with the jumps still in place: the jail start action
  # is teardown, then setup, and the readiness check of configure.sh looks at the jumps while that action runs. Run after drop_jumps, the gates
  # kept the jumps away for seconds (median 1.2 s against 0.4 s, QA W1 item 5). The caller holds the lock, so nothing changes the files between
  # the gates and the rows being cleared below.
  hist_gate || keep=1
  [ "$keep" -ne 0 ] || list_gate || keep=1
  for fam in 4 6; do
    drop_jumps "$fam" || rc=1
  done
  flush_chains || rc=1
  if [ "$keep" -eq 0 ]; then
    do_clear_rows || rc=1
  else
    echo "ovpn-ban: WARNING: the ban list $STATE is left as it is by teardown: the history of the permanent bans is unknown or lacks bans of the list (see above), so the list is the only record of them. Chains and jumps are removed; the next start with OVPN_BAN_REQUIRED=true is refused until the history is restored or both files are moved away" >&2
  fi
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
  expire) [ "$#" -eq 0 ] || die "usage: expire"; cmd_expire ;;
  jail-bantime) [ "$#" -eq 0 ] || die "usage: jail-bantime"; cmd_jail_bantime ;;
  flush) [ "$#" -eq 0 ] || die "usage: flush"; cmd_flush ;;
  teardown) [ "$#" -eq 0 ] || die "usage: teardown"; cmd_teardown ;;
  *) die "usage: $0 init | setup | check | ban IP FAILURES | ban-manual [--force] [--minutes N] IP [REASON] | unban IP [--force] | expire | jail-bantime | flush | teardown" ;;
esac
