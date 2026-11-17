#!/usr/bin/env bash
# Upgrade a docker compose deployment of ovpn-admin (upstream ./start.sh or registry images)
# to v0.1.0 of this fork. See UPGRADING-v0.1.0.md.
#
# What it does: preflight, backup of the bind-mounted data (easyrsa_master, ccd_master),
# build --pull or pull, up -d, wait for /ping. It never runs "down", never touches volumes,
# never deletes anything and never rolls back by itself: on a failure it prints the rollback steps.
set -euo pipefail

PROG=$(basename "$0")
TARGET_VERSION="v0.1.0"

PROJECT_DIR=""
COMPOSE_FILE="docker-compose.yaml"
PROJECT_NAME="openvpn-master"
BACKUP_DIR=""
HEALTH_URL="http://127.0.0.1:8080/ping"
HEALTH_TIMEOUT=180
PREVIOUS_REF=""
DRY_RUN=0
ASSUME_YES=0
BACKUP_ONLY=0

# bind-mount sources (relative to the project dir) that are backed up; detected from the compose file
SOURCES=()
HAS_BUILD=0
BACKUP_FILE=""
BACKUP_DONE=0
TS=$(date -u +%Y%m%dT%H%M%SZ)
STAGE="preflight"

usage() {
  cat <<EOF
Usage: $PROG --project-dir DIR [options]

Upgrade a docker compose deployment of ovpn-admin to ${TARGET_VERSION}.

Options:
  --project-dir DIR       directory with the compose file and the easyrsa_master/ and ccd_master/
                          bind mounts (required)
  --compose-file NAME     compose file inside the project dir (default: docker-compose.yaml)
  --project-name NAME     compose project name (default: openvpn-master, as in start.sh)
  --backup-dir DIR        where the backup archive is written (default: <project-dir>/backups)
  --health-url URL        URL that must answer 2xx after the upgrade (default: $HEALTH_URL)
  --health-timeout SECS   how long to wait for it (default: $HEALTH_TIMEOUT)
  --previous-ref REF      git tag or commit of the version you are leaving, only used to fill in
                          the rollback steps
  --backup-only           run the preflight and the backup, then stop (nothing is built or started)
  --dry-run               print the plan and every command, change nothing (no archive is written)
  --yes                   do not ask for confirmation
  -h, --help              this text
EOF
}

log() { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# print a command; run it unless this is a dry run
run() {
  printf '+ %s\n' "$*"
  if [[ $DRY_RUN -eq 0 ]]; then
    "$@"
  fi
}

compose() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

print_rollback() {
  local prev="${PREVIOUS_REF:-<previous tag or commit>}"
  cat >&2 <<EOF

================ ROLLBACK (nothing was rolled back automatically) ================
The backup is: ${BACKUP_FILE}
Run these steps by hand, in the project dir:

  cd ${PROJECT_DIR}
  # 1. stop the stack (no "down -v", volumes stay)
  docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE} stop
  # 2. restore the data: move the current directories aside, then unpack the backup
EOF
  local s
  for s in "${SOURCES[@]}"; do
    printf '  mv %s %s.failed-upgrade\n' "$s" "$s" >&2
  done
  cat >&2 <<EOF
  tar -xzf ${BACKUP_FILE} -C ${PROJECT_DIR}
  # 3. go back to the previous version (if the project dir is a git checkout; also restore the previous compose file if you edited it in place)
  git checkout ${prev}
  # 4. start the previous version
EOF
  if [[ $HAS_BUILD -eq 1 ]]; then
    printf '  docker compose -p %s -f %s up -d --build\n' "$PROJECT_NAME" "$COMPOSE_FILE" >&2
  else
    printf '  docker compose -p %s -f %s pull\n  docker compose -p %s -f %s up -d\n' \
      "$PROJECT_NAME" "$COMPOSE_FILE" "$PROJECT_NAME" "$COMPOSE_FILE" >&2
  fi
  cat >&2 <<EOF
  # 5. check that it answers
  curl -fsS ${HEALTH_URL}
===================================================================================
EOF
}

on_exit() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    printf '\nFAILED during stage: %s (exit code %s)\n' "$STAGE" "$rc" >&2
    if [[ $BACKUP_DONE -eq 1 ]]; then
      print_rollback
    else
      log "No backup was taken and nothing was changed, so there is nothing to roll back." >&2
    fi
  fi
}
trap on_exit EXIT

# ---------------------------------------------------------------- arguments
need_value() { [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir)    need_value "$@"; PROJECT_DIR=$2; shift 2 ;;
    --compose-file)   need_value "$@"; COMPOSE_FILE=$2; shift 2 ;;
    --project-name)   need_value "$@"; PROJECT_NAME=$2; shift 2 ;;
    --backup-dir)     need_value "$@"; BACKUP_DIR=$2; shift 2 ;;
    --health-url)     need_value "$@"; HEALTH_URL=$2; shift 2 ;;
    --health-timeout) need_value "$@"; HEALTH_TIMEOUT=$2; shift 2 ;;
    --previous-ref)   need_value "$@"; PREVIOUS_REF=$2; shift 2 ;;
    --backup-only)    BACKUP_ONLY=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    --yes)            ASSUME_YES=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ -n "$PROJECT_DIR" ]] || { usage >&2; die "--project-dir is required"; }
[[ "$HEALTH_TIMEOUT" =~ ^[0-9]+$ ]] || die "--health-timeout must be a number of seconds"
[[ "$PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "--project-name must be lowercase letters, digits, - or _"
[[ "$COMPOSE_FILE" != */* ]] || die "--compose-file is a file name inside the project dir, not a path"

[[ -d "$PROJECT_DIR" ]] || die "project dir does not exist: $PROJECT_DIR"
PROJECT_DIR=$(realpath "$PROJECT_DIR")
[[ -n "$BACKUP_DIR" ]] || BACKUP_DIR="$PROJECT_DIR/backups"
BACKUP_DIR=$(realpath -m "$BACKUP_DIR")

# ---------------------------------------------------------------- preflight
preflight() {
  log "== Preflight"
  command -v docker >/dev/null 2>&1 || die "docker is not installed or not in PATH"
  docker compose version || die "'docker compose' (the compose plugin) is not available"
  command -v tar >/dev/null 2>&1 || die "tar is not installed"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is not installed"
  command -v curl >/dev/null 2>&1 || die "curl is not installed (needed for the health check)"

  [[ -f "$PROJECT_DIR/$COMPOSE_FILE" ]] || die "compose file does not exist: $PROJECT_DIR/$COMPOSE_FILE"
  cd "$PROJECT_DIR"

  # the upstream registry images would be pulled again and nothing would be upgraded
  if grep -Eq 'ghcr\.io/palark/' "$COMPOSE_FILE"; then
    die "$COMPOSE_FILE still references the upstream images ghcr.io/palark/...; replace it with the docker-compose.yaml of ${TARGET_VERSION} first (see UPGRADING-${TARGET_VERSION}.md)"
  fi

  if grep -Eq '^[[:space:]]+build:' "$COMPOSE_FILE"; then
    HAS_BUILD=1
    log "compose file builds locally (build: section found): the images will be built with --pull"
  else
    log "compose file uses registry images (no build: section): the images will be pulled"
  fi

  detect_sources
  check_required_variables

  # compose validates the file; -q prints nothing, so no interpolated secret reaches the terminal
  compose config -q || die "docker compose config failed for $COMPOSE_FILE, see the message above"

  if docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" -q 2>/dev/null | grep -q .; then
    log "project '${PROJECT_NAME}': existing containers found"
  else
    warn "no containers belong to the compose project '${PROJECT_NAME}' (or docker is not reachable). This would be a fresh start, not an upgrade. Check --project-name."
  fi
}

# bind-mount sources of the easyrsa and ccd directories, from "- ./src:/target" lines of the compose file
detect_sources() {
  local line src tgt have_easyrsa=0 have_ccd=0 s seen
  local re='^[[:space:]]*-[[:space:]]*["'"'"']?([^:"'"'"'[:space:]]+):(/[^:"'"'"'[:space:]]+)'
  while IFS= read -r line; do
    [[ "$line" =~ $re ]] || continue
    src=${BASH_REMATCH[1]}
    tgt=${BASH_REMATCH[2]}
    [[ "$src" == .* || "$src" == /* ]] || continue # named volume
    case "$tgt" in
      /etc/openvpn/easyrsa|/mnt/easyrsa) have_easyrsa=1 ;;
      /etc/openvpn/ccd|/mnt/ccd)         have_ccd=1 ;;
      *) continue ;;
    esac
    [[ "$src" != *'$'* ]] || die "bind-mount source '$src' contains a variable; cannot decide what to back up"
    seen=0
    for s in "${SOURCES[@]}"; do [[ "$s" == "$src" ]] && seen=1; done
    [[ $seen -eq 1 ]] || SOURCES+=("$src")
  done < "$COMPOSE_FILE"
  [[ $have_easyrsa -eq 1 ]] || { warn "no easyrsa bind mount found in $COMPOSE_FILE, assuming ./easyrsa_master"; SOURCES+=("./easyrsa_master"); }
  [[ $have_ccd -eq 1 ]] || { warn "no ccd bind mount found in $COMPOSE_FILE, assuming ./ccd_master"; SOURCES+=("./ccd_master"); }

  # normalise to paths relative to the project dir; refuse anything that leaves it
  local abs rel normalised=()
  for s in "${SOURCES[@]}"; do
    abs=$(realpath -m "$PROJECT_DIR/$s")
    [[ "$abs" == "$PROJECT_DIR"/* ]] || die "bind-mount source '$s' is outside the project dir; this script only touches the project dir and the backup dir"
    rel=${abs#"$PROJECT_DIR"/}
    [[ -d "$abs" ]] || die "bind-mount source directory does not exist: $abs (wrong --project-dir?)"
    normalised+=("$rel")
  done
  SOURCES=("${normalised[@]}")
  log "data directories to back up: ${SOURCES[*]}"
}

# ${VAR:?...} variables of the compose file must be set in the environment or in .env; only names are printed
check_required_variables() {
  local missing=() name
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if [[ -n "${!name:-}" ]]; then continue; fi
    if [[ -f .env ]] && grep -Eq "^[[:space:]]*(export[[:space:]]+)?${name}=.+" .env; then continue; fi
    missing+=("$name")
  done < <(grep -Eo '\$\{[A-Za-z_][A-Za-z0-9_]*:\?' "$COMPOSE_FILE" | sed -E 's/^\$\{//; s/:\?$//' | sort -u)
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "the compose file requires these variables and they are not set in the environment or in $PROJECT_DIR/.env: ${missing[*]} (see UPGRADING-${TARGET_VERSION}.md)"
  fi
}

# ---------------------------------------------------------------- plan
print_plan() {
  log ""
  log "== Plan"
  [[ $DRY_RUN -eq 0 ]] || log "(dry run: nothing below is executed)"
  log "project dir:   $PROJECT_DIR"
  log "compose file:  $COMPOSE_FILE"
  log "project name:  $PROJECT_NAME"
  log "backup:        $BACKUP_DIR/pre-${TARGET_VERSION}-${TS}.tar.gz  (${SOURCES[*]})"
  if [[ $BACKUP_ONLY -eq 1 ]]; then
    log "stop after the backup (--backup-only)"
  else
    if [[ $HAS_BUILD -eq 1 ]]; then
      log "upgrade:       docker compose -p $PROJECT_NAME -f $COMPOSE_FILE build --pull"
    else
      log "upgrade:       docker compose -p $PROJECT_NAME -f $COMPOSE_FILE pull"
    fi
    log "               docker compose -p $PROJECT_NAME -f $COMPOSE_FILE up -d"
    log "health:        GET $HEALTH_URL for up to ${HEALTH_TIMEOUT}s"
  fi
  log "never run:     down, down -v, volume removal, rm"
}

confirm() {
  [[ $DRY_RUN -eq 0 && $ASSUME_YES -eq 0 ]] || return 0
  [[ -t 0 ]] || die "stdin is not a terminal; pass --yes to run without the confirmation prompt"
  local answer
  read -r -p "Back up and upgrade now? [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" ]] || { log "Aborted, nothing was changed."; exit 0; }
}

# ---------------------------------------------------------------- backup
backup() {
  STAGE="backup"
  log ""
  log "== Backup"
  BACKUP_FILE="$BACKUP_DIR/pre-${TARGET_VERSION}-${TS}.tar.gz"

  if [[ $DRY_RUN -eq 1 ]]; then
    printf '+ mkdir -p %s\n' "$BACKUP_DIR"
    printf '+ tar -czf %s -C %s %s\n' "$BACKUP_FILE" "$PROJECT_DIR" "${SOURCES[*]}"
    log "(dry run) no archive written; a real run prints its path, size and sha256 here"
    return 0
  fi

  [[ ! -e "$BACKUP_FILE" ]] || die "backup file already exists: $BACKUP_FILE"
  # the archive holds the CA private key: owner-only
  (umask 077 && mkdir -p "$BACKUP_DIR")
  printf '+ tar -czf %s -C %s %s\n' "$BACKUP_FILE" "$PROJECT_DIR" "${SOURCES[*]}"
  if ! (umask 077 && tar -czf "$BACKUP_FILE" -C "$PROJECT_DIR" "${SOURCES[@]}"); then
    die "tar failed (unreadable files? the data of a running stack is often owned by root: re-run with sudo). Nothing was changed."
  fi

  local size entries sum
  size=$(stat -c %s "$BACKUP_FILE")
  [[ "$size" -gt 0 ]] || die "backup archive is empty: $BACKUP_FILE"
  entries=$(tar -tzf "$BACKUP_FILE" | wc -l)
  [[ "$entries" -gt 0 ]] || die "backup archive has no entries: $BACKUP_FILE"
  sum=$(sha256sum "$BACKUP_FILE" | cut -d' ' -f1)
  BACKUP_DONE=1
  log "backup archive: $BACKUP_FILE"
  log "size (bytes):   $size"
  log "entries:        $entries"
  log "sha256:         $sum"
}

# ---------------------------------------------------------------- upgrade and health
upgrade() {
  STAGE="upgrade"
  log ""
  log "== Upgrade"
  if [[ $HAS_BUILD -eq 1 ]]; then
    run docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" build --pull
  else
    run docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" pull
  fi
  run docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d
}

redact() { sed -E 's/((password|passwd|token|secret)[=:] *)[^ &"]+/\1[redacted]/Ig'; }

health() {
  STAGE="health"
  log ""
  log "== Health"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '+ curl -fsS --max-time 5 %s   (every 3s, up to %ss)\n' "$HEALTH_URL" "$HEALTH_TIMEOUT"
    return 0
  fi
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  while :; do
    if curl -fsS --max-time 5 -o /dev/null "$HEALTH_URL" 2>/dev/null; then
      log "healthy: $HEALTH_URL answered 2xx after about $((SECONDS - (deadline - HEALTH_TIMEOUT)))s"
      compose ps
      return 0
    fi
    [[ $SECONDS -lt $deadline ]] || break
    sleep 3
  done
  {
    log "NOT healthy: $HEALTH_URL did not answer 2xx within ${HEALTH_TIMEOUT}s"
    log "-- container status"
    compose ps -a || true
    log "-- last 20 log lines (passwords and tokens redacted)"
    compose logs --no-color --tail 20 2>&1 | redact || true
  } >&2
  return 1
}

main() {
  preflight
  print_plan
  STAGE="confirm"
  confirm
  backup
  if [[ $BACKUP_ONLY -eq 1 ]]; then
    log ""
    log "Backup only: nothing was built or started."
    return 0
  fi
  upgrade
  health
  STAGE="done"
  log ""
  if [[ $DRY_RUN -eq 1 ]]; then
    log "Dry run finished: nothing was changed or started."
  else
    log "Upgrade to ${TARGET_VERSION} finished. Backup kept at: $BACKUP_FILE"
  fi
}

main
