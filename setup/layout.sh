#!/usr/bin/env bash
# Directory layout of the openvpn container, sourced by configure.sh (and by nothing else). Two trees, split by who may write them:
#
#   audit tree      (dirname of OVPN_AUDIT_LOG, default /etc/openvpn/audit)   nobody:nogroup 0700
#       audit.tsv                       the connect, disconnect and auth events written by the OpenVPN hooks, which run as "nobody".
#                                       Nothing else lives here: a compromised VPN process can only write its own event file.
#   state tree      (OVPN_STATE_DIR, default /var/lib/ovpn-admin)             root:root 0700
#       openvpn.log                     OpenVPN log (opened by root before OpenVPN drops privileges), read by fail2ban
#       bans.tsv, bans-history.tsv      ban list and offence history (+ .lock, .removals, .caphits, .boot made by ovpn-ban.sh)
#       control/                        manual ban queue shared with the ovpn-admin container
#       state/                          engine state: ban-state-migrated (marker written when the ban state of an older deployment was copied)
#       audit/                          admin-audit.log (ovpn-admin) and ban-events.log (ovpn-ban.sh)
#
# Every path is refused when it is a symlink ([ -L ]); ownership is changed with chown -h and only when it differs, so a second run
# changes nothing (no ctime churn). Failures return non-zero and the caller (set -e) stops the container.

LAYOUT_AUDIT_OWNER="${OVPN_AUDIT_OWNER:-nobody:nogroup}"
LAYOUT_ROOT_OWNER="root:root"

layout_fail() {
  echo "ERROR: layout: $*" >&2
  return 1
}

# layout_refuse_link PATH: a symlink anywhere in the trees is an error, never followed
layout_refuse_link() {
  if [ -L "$1" ]; then
    layout_fail "$1 is a symbolic link; refusing to continue (the audit and state trees must be real directories and files)"
    return 1
  fi
}

# layout_own PATH OWNER MODE: set owner (chown -h) and mode only when they differ; PATH must exist and not be a link
layout_own() {
  local p="$1" owner="$2" mode="$3" cur
  layout_refuse_link "$p" || return 1
  cur="$(stat -c '%U:%G' "$p")" || return 1
  if [ "${cur}" != "${owner}" ]; then
    chown -h "${owner}" "$p" || return 1
  fi
  cur="$(stat -c '%a' "$p")" || return 1
  if [ "${cur}" != "${mode#0}" ] && [ "${cur}" != "${mode}" ]; then
    chmod "${mode}" "$p" || return 1
  fi
}

# layout_dir PATH OWNER: an existing or new real directory, mode 0700
layout_dir() {
  local d="$1" owner="$2"
  layout_refuse_link "$d" || return 1
  if [ -e "$d" ] && [ ! -d "$d" ]; then
    layout_fail "$d exists and is not a directory"
    return 1
  fi
  if [ ! -d "$d" ]; then
    mkdir -p "$d" || return 1
    layout_refuse_link "$d" || return 1
  fi
  layout_own "$d" "${owner}" 0700
}

# layout_file PATH OWNER: an existing file gets owner and mode 0600 (a missing file is left to its writer)
layout_file() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  if [ -L "$1" ]; then layout_refuse_link "$1"; return 1; fi
  layout_own "$1" "$2" 0600
}

# layout_copy_root SRC DST: root:root 0600 copy, atomic (temporary name, then rename), never through a link
layout_copy_root() {
  local src="$1" dst="$2" tmp
  layout_refuse_link "${src}" || return 1
  layout_refuse_link "${dst}" || return 1
  tmp="${dst}.migrating.$$"
  rm -f "${tmp}"
  install -m 0600 -o root -g root "${src}" "${tmp}" || { rm -f "${tmp}"; return 1; }
  mv -f "${tmp}" "${dst}" || { rm -f "${tmp}"; return 1; }
}

# layout_migrate OLD_DIR NEW_DIR: an existing deployment kept bans.tsv, bans-history.tsv and the earlier ban-history.tsv in the audit
# directory. When the new tree has no bans.tsv yet and the old tree has ban state, the files are copied (never moved: the old ones stay as
# the rollback copy and the operator removes them), before the ban engine starts; ovpn-ban.sh init/setup then restores the permanent bans
# from the copied history. Once bans.tsv or the state/ban-state-migrated marker exists in the new tree this does nothing, so the copy happens once. audit.tsv is never touched.
layout_migrate() {
  local old="$1" new="$2" f moved=() skipped=() marker
  marker="${new}/state/ban-state-migrated"
  [ "${old}" != "${new}" ] || return 0
  # done once: bans.tsv in the new tree, or the marker (the ban engine can be disabled, then bans.tsv is never created)
  if [ -e "${new}/bans.tsv" ] || [ -L "${new}/bans.tsv" ] || [ -e "${marker}" ] || [ -L "${marker}" ]; then
    return 0
  fi
  [ -f "${old}/bans.tsv" ] || [ -f "${old}/bans-history.tsv" ] || [ -f "${old}/ban-history.tsv" ] || return 0
  for f in bans.tsv bans-history.tsv ban-history.tsv; do
    [ -e "${old}/${f}" ] || continue
    if [ -e "${new}/${f}" ] || [ -L "${new}/${f}" ]; then
      skipped+=("${f}")
      continue
    fi
    layout_copy_root "${old}/${f}" "${new}/${f}" || return 1
    moved+=("${f}")
  done
  printf 'copied from %s: %s\n' "${old}" "${moved[*]:-nothing}" > "${marker}" || return 1
  chmod 0600 "${marker}" || return 1
  echo "ovpn-layout: migrated ban state from ${old} to ${new}: copied ${moved[*]:-nothing}${skipped:+ (already present: ${skipped[*]})}; the old files stay in ${old} and can be removed once the ban list has been checked (audit.tsv is not touched)"
}

# ovpn_layout_prepare: create both trees, set ownership and modes, migrate the ban state. Idempotent.
# Sets: AUDIT_LOG_FILE AUDIT_LOG_DIR STATE_DIR STATE_CONTROL_DIR STATE_AUDIT_DIR STATE_STATE_DIR
ovpn_layout_prepare() {
  AUDIT_LOG_FILE="${OVPN_AUDIT_LOG:-/etc/openvpn/audit/audit.tsv}"
  AUDIT_LOG_DIR="$(dirname "${AUDIT_LOG_FILE}")"
  STATE_DIR="${OVPN_STATE_DIR:-/var/lib/ovpn-admin}"
  if [ "${AUDIT_LOG_DIR}" = "${STATE_DIR}" ]; then
    layout_fail "OVPN_AUDIT_LOG (${AUDIT_LOG_FILE}) and OVPN_STATE_DIR (${STATE_DIR}) name the same directory; the event file and the root-only state must be separate trees"
    return 1
  fi
  STATE_CONTROL_DIR="${STATE_DIR}/control"
  STATE_STATE_DIR="${STATE_DIR}/state"
  STATE_AUDIT_DIR="${STATE_DIR}/audit"

  # refuse links first, before anything is created or changed
  layout_refuse_link "${AUDIT_LOG_DIR}" || return 1
  layout_refuse_link "${STATE_DIR}" || return 1

  layout_dir "${AUDIT_LOG_DIR}" "${LAYOUT_AUDIT_OWNER}" || return 1
  layout_file "${AUDIT_LOG_FILE}" "${LAYOUT_AUDIT_OWNER}" || return 1

  layout_dir "${STATE_DIR}" "${LAYOUT_ROOT_OWNER}" || return 1
  layout_dir "${STATE_CONTROL_DIR}" "${LAYOUT_ROOT_OWNER}" || return 1
  layout_dir "${STATE_STATE_DIR}" "${LAYOUT_ROOT_OWNER}" || return 1
  layout_dir "${STATE_AUDIT_DIR}" "${LAYOUT_ROOT_OWNER}" || return 1

  layout_migrate "${AUDIT_LOG_DIR}" "${STATE_DIR}" || return 1

  local f
  for f in openvpn.log bans.tsv bans-history.tsv audit/admin-audit.log audit/ban-events.log; do
    layout_file "${STATE_DIR}/${f}" "${LAYOUT_ROOT_OWNER}" || return 1
  done
}
