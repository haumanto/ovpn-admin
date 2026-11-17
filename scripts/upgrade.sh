#!/usr/bin/env bash
# Upgrade a docker compose deployment of ovpn-admin (upstream ./start.sh, v0.1.0 or registry images)
# to a release of this fork (default: v0.1.3). One script for every version, see UPGRADING.md.
#
# What it does: preflight, backup of the bind-mounted data (easyrsa_master, ccd_master and, when the
# compose file mounts it, audit_master), build --pull or pull, then an ordered start: openvpn first,
# wait until its management interface answers, only then ovpn-admin, then wait for /ping. It never
# runs "down", never touches volumes, never deletes anything and never rolls back by itself: on a
# failure it prints the rollback steps.
set -euo pipefail

PROG=$(basename "$0")
# only used in messages, the backup file name and the rollback text; it does not select any code
TARGET_VERSION="v0.1.3"

PROJECT_DIR=""
COMPOSE_FILE="docker-compose.yaml"
PROJECT_NAME="openvpn-master"
BACKUP_DIR=""
HEALTH_URL="http://127.0.0.1:8080/ping"
HEALTH_TIMEOUT=180
MGMT_TIMEOUT=180
PREVIOUS_REF=""
DRY_RUN=0
ASSUME_YES=0
BACKUP_ONLY=0

# bind-mount sources (relative to the project dir) that are backed up; detected from the compose file
SOURCES=()
# audit mount: AUDIT_SRC is the (relative) source of the shared audit directory, created 0755 when missing
AUDIT_SRC=""
AUDIT_MISSING_DIR=0
HAS_BUILD=0
# compose command, set by detect_compose(): (docker compose) for V2, (docker-compose) for V1 >= 1.25
COMPOSE_CMD=(docker compose)
COMPOSE_STR="docker compose"
COMPOSE_V1=0
BACKUP_FILE=""
BACKUP_DONE=0
TS=$(date -u +%Y%m%dT%H%M%SZ)
STAGE="preflight"

usage() {
  cat <<EOF
Usage: $PROG --project-dir DIR [options]

Upgrade a docker compose deployment of ovpn-admin to ${TARGET_VERSION}.

Options:
  --project-dir DIR       directory with the compose file and the easyrsa_master/, ccd_master/ and
                          audit_master/ bind mounts (required)
  --target-version VER    version you are upgrading to, used only in messages, the backup file name
                          and the rollback text (default: $TARGET_VERSION)
  --compose-file NAME     compose file inside the project dir (default: docker-compose.yaml)
  --project-name NAME     compose project name (default: openvpn-master, as in start.sh)
  --backup-dir DIR        where the backup archive is written (default: <project-dir>/backups)
  --health-url URL        URL that must answer 2xx after the upgrade (default: $HEALTH_URL)
  --health-timeout SECS   how long to wait for it (default: $HEALTH_TIMEOUT)
  --mgmt-timeout SECS     how long to wait for the OpenVPN management interface (127.0.0.1:8989 inside
                          the openvpn container) before ovpn-admin is started (default: $MGMT_TIMEOUT)
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
  "${COMPOSE_CMD[@]}" -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

# V1 (docker-compose) lists stopped containers in "ps" by default and only got "ps -a" later; V2 needs -a
compose_ps_all() {
  if [[ $COMPOSE_V1 -eq 1 ]]; then compose ps; else compose ps -a; fi
}

# V2 plugin ("docker compose") first, else the standalone V1 "docker-compose" (>= 1.25), else a clear error
detect_compose() {
  local out first major minor
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
    COMPOSE_STR="docker compose"
    COMPOSE_V1=0
    docker compose version
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1 && out=$(docker-compose version 2>&1); then
    first=$(head -n 1 <<<"$out")
    [[ "$first" =~ ([0-9]+)\.([0-9]+) ]] || die "could not read the version of docker-compose from: $first"
    major=$((10#${BASH_REMATCH[1]}))
    minor=$((10#${BASH_REMATCH[2]}))
    if [[ $major -lt 1 || ( $major -eq 1 && $minor -lt 25 ) ]]; then
      die "docker-compose ${major}.${minor} is too old: this script needs docker-compose >= 1.25 (V1) or the 'docker compose' plugin (V2). Upgrade Compose and re-run."
    fi
    COMPOSE_CMD=(docker-compose)
    COMPOSE_STR="docker-compose"
    COMPOSE_V1=0
    [[ $major -ge 2 ]] || COMPOSE_V1=1
    log "using standalone docker-compose: $first"
    return 0
  fi
  die "neither 'docker compose' (the Compose V2 plugin) nor 'docker-compose' (V1 >= 1.25) is available; install one of them"
}

print_rollback() {
  local prev="${PREVIOUS_REF:-<previous tag or commit>}"
  cat >&2 <<EOF

================ ROLLBACK (nothing was rolled back automatically) ================
The backup is: ${BACKUP_FILE}
Run these steps by hand, in the project dir:

  cd ${PROJECT_DIR}
  # 1. stop the stack (no "down -v", volumes stay)
  ${COMPOSE_STR} -p ${PROJECT_NAME} -f ${COMPOSE_FILE} stop
  # 2. restore the data: move the current directories aside, then unpack the backup
EOF
  local s
  # the +"${arr[@]}" form keeps empty arrays safe under set -u on Bash < 4.4
  for s in "${SOURCES[@]+"${SOURCES[@]}"}"; do
    printf '  mv %s %s.failed-upgrade\n' "$s" "$s" >&2
  done
  cat >&2 <<EOF
  tar -xzf ${BACKUP_FILE} -C ${PROJECT_DIR}
  # 3. go back to the previous version (if the project dir is a git checkout; also restore the previous compose file if you edited it in place)
  git checkout ${prev}
  # 4. start the previous version
EOF
  if [[ $HAS_BUILD -eq 1 ]]; then
    printf '  %s -p %s -f %s up -d --build\n' "$COMPOSE_STR" "$PROJECT_NAME" "$COMPOSE_FILE" >&2
  else
    printf '  %s -p %s -f %s pull\n  %s -p %s -f %s up -d\n' \
      "$COMPOSE_STR" "$PROJECT_NAME" "$COMPOSE_FILE" "$COMPOSE_STR" "$PROJECT_NAME" "$COMPOSE_FILE" >&2
  fi
  cat >&2 <<EOF
  # 5. check that it answers
  curl -fsS ${HEALTH_URL}
Rolling back from ${TARGET_VERSION}. The *.failed-upgrade directories (login history in audit_master included)
are kept: delete them by hand, only once the previous version runs.
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
    --target-version) need_value "$@"; TARGET_VERSION=$2; shift 2 ;;
    --backup-dir)     need_value "$@"; BACKUP_DIR=$2; shift 2 ;;
    --health-url)     need_value "$@"; HEALTH_URL=$2; shift 2 ;;
    --health-timeout) need_value "$@"; HEALTH_TIMEOUT=$2; shift 2 ;;
    --mgmt-timeout)   need_value "$@"; MGMT_TIMEOUT=$2; shift 2 ;;
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
[[ "$MGMT_TIMEOUT" =~ ^[0-9]+$ ]] || die "--mgmt-timeout must be a number of seconds"
[[ "$TARGET_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "--target-version may only contain letters, digits, . _ and -"
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
  detect_compose
  command -v tar >/dev/null 2>&1 || die "tar is not installed"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is not installed"
  command -v curl >/dev/null 2>&1 || die "curl is not installed (needed for the health check)"

  [[ -f "$PROJECT_DIR/$COMPOSE_FILE" ]] || die "compose file does not exist: $PROJECT_DIR/$COMPOSE_FILE"
  cd "$PROJECT_DIR"

  # the upstream registry images would be pulled again and nothing would be upgraded
  if grep -Eq 'ghcr\.io/palark/' "$COMPOSE_FILE"; then
    die "$COMPOSE_FILE still references the upstream images ghcr.io/palark/...; replace it with the docker-compose.yaml of ${TARGET_VERSION} first (see UPGRADING.md)"
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
  compose config -q || die "$COMPOSE_STR config failed for $COMPOSE_FILE, see the message above"

  # the ordered start names both services; a compose file without them (the slave file, for one) is not for this script
  local svc
  svc=$(compose config --services) || die "$COMPOSE_STR config --services failed for $COMPOSE_FILE"
  if ! { grep -qx 'openvpn' <<<"$svc" && grep -qx 'ovpn-admin' <<<"$svc"; }; then
    die "$COMPOSE_FILE has no 'openvpn' and 'ovpn-admin' services (found: $(tr '\n' ' ' <<<"$svc")). This script upgrades the master stack; a slave is upgraded by hand, see UPGRADING.md"
  fi

  if docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" -q 2>/dev/null | grep -q .; then
    log "project '${PROJECT_NAME}': existing containers found"
  else
    warn "no containers belong to the compose project '${PROJECT_NAME}' (or docker is not reachable). This would be a fresh start, not an upgrade. Check --project-name."
  fi
}

# bind-mount sources of the easyrsa and ccd directories, from "- ./src:/target" lines of the compose file
detect_sources() {
  local line src tgt have_easyrsa=0 have_ccd=0 s seen audit_raw=""
  local re='^[[:space:]]*-[[:space:]]*["'"'"']?([^:"'"'"'[:space:]]+):(/[^:"'"'"'[:space:]]+)'
  while IFS= read -r line; do
    [[ "$line" =~ $re ]] || continue
    src=${BASH_REMATCH[1]}
    tgt=${BASH_REMATCH[2]}
    [[ "$src" == .* || "$src" == /* ]] || continue # named volume
    case "$tgt" in
      /etc/openvpn/easyrsa|/mnt/easyrsa) have_easyrsa=1 ;;
      /etc/openvpn/ccd|/mnt/ccd)         have_ccd=1 ;;
      /etc/openvpn/audit|/mnt/audit)     audit_raw=$src ;;
      *) continue ;;
    esac
    [[ "$src" != *'$'* ]] || die "bind-mount source '$src' contains a variable; cannot decide what to back up"
    seen=0
    # the +"${arr[@]}" form keeps empty arrays safe under set -u on Bash < 4.4
    for s in "${SOURCES[@]+"${SOURCES[@]}"}"; do [[ "$s" == "$src" ]] && seen=1; done
    [[ $seen -eq 1 ]] || SOURCES+=("$src")
  done < "$COMPOSE_FILE"
  [[ $have_easyrsa -eq 1 ]] || { warn "no easyrsa bind mount found in $COMPOSE_FILE, assuming ./easyrsa_master"; SOURCES+=("./easyrsa_master"); }
  [[ $have_ccd -eq 1 ]] || { warn "no ccd bind mount found in $COMPOSE_FILE, assuming ./ccd_master"; SOURCES+=("./ccd_master"); }

  # the audit directory (v0.1.1+) is optional: a v0.1.0 or upstream compose file has no such mount
  if [[ -n "$audit_raw" ]]; then
    seen=0
    # the +"${arr[@]}" form keeps empty arrays safe under set -u on Bash < 4.4
    for s in "${SOURCES[@]+"${SOURCES[@]}"}"; do [[ "$s" == "$audit_raw" ]] && seen=1; done
    [[ $seen -eq 1 ]] || SOURCES+=("$audit_raw")
  elif grep -Eq '^[[:space:]]*[^#[:space:]].*OVPN_AUDIT_PATH' "$COMPOSE_FILE"; then
    warn "$COMPOSE_FILE sets OVPN_AUDIT_PATH but the audit directory is not a bind mount of /etc/openvpn/audit or /mnt/audit; it is NOT part of the backup, back it up yourself"
  else
    warn "$COMPOSE_FILE has no audit mount (/etc/openvpn/audit or OVPN_AUDIT_PATH): login history will not persist until the ${TARGET_VERSION} docker-compose.yaml is used (see UPGRADING.md). The compose file is not edited."
    # an audit directory left by an earlier v0.1.1 compose file is still worth keeping in the backup
    if [[ -d "$PROJECT_DIR/audit_master" ]]; then
      SOURCES+=("./audit_master")
      log "found ./audit_master on disk: it is included in the backup"
    fi
  fi

  # normalise to paths relative to the project dir; refuse anything that leaves it
  local abs rel normalised=()
  # the +"${arr[@]}" form keeps empty arrays safe under set -u on Bash < 4.4
  for s in "${SOURCES[@]+"${SOURCES[@]}"}"; do
    abs=$(realpath -m "$PROJECT_DIR/$s")
    [[ "$abs" == "$PROJECT_DIR"/* ]] || die "bind-mount source '$s' is outside the project dir; this script only touches the project dir and the backup dir"
    rel=${abs#"$PROJECT_DIR"/}
    if [[ -n "$audit_raw" && "$(realpath -m "$PROJECT_DIR/$audit_raw")" == "$abs" ]]; then
      # created by backup() with mode 0755 so the first start does not leave a root-owned surprise
      AUDIT_SRC=$rel
      [[ -d "$abs" ]] || AUDIT_MISSING_DIR=1
    else
      [[ -d "$abs" ]] || die "bind-mount source directory does not exist: $abs (wrong --project-dir?)"
    fi
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
  if [[ -n "${missing[*]-}" ]]; then
    die "the compose file requires these variables and they are not set in the environment or in $PROJECT_DIR/.env: ${missing[*]} (see UPGRADING.md)"
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
  log "target:        ${TARGET_VERSION}"
  if [[ $AUDIT_MISSING_DIR -eq 1 ]]; then
    log "audit dir:     $AUDIT_SRC does not exist and will be created with mode 0755 before the backup"
  fi
  log "backup:        $BACKUP_DIR/pre-${TARGET_VERSION}-${TS}.tar.gz  (${SOURCES[*]})"
  if [[ $BACKUP_ONLY -eq 1 ]]; then
    log "stop after the backup (--backup-only)"
  else
    if [[ $HAS_BUILD -eq 1 ]]; then
      log "upgrade:       $COMPOSE_STR -p $PROJECT_NAME -f $COMPOSE_FILE build --pull"
    else
      log "upgrade:       $COMPOSE_STR -p $PROJECT_NAME -f $COMPOSE_FILE pull"
    fi
    log "start:         $COMPOSE_STR -p $PROJECT_NAME -f $COMPOSE_FILE up -d --no-deps openvpn"
    log "               wait for the management interface for up to ${MGMT_TIMEOUT}s (probe below)"
    log "               $COMPOSE_STR -p $PROJECT_NAME -f $COMPOSE_FILE up -d --no-deps ovpn-admin"
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
    [[ $AUDIT_MISSING_DIR -eq 0 ]] || printf '+ mkdir -p %s && chmod 0755 %s\n' "$PROJECT_DIR/$AUDIT_SRC" "$PROJECT_DIR/$AUDIT_SRC"
    printf '+ mkdir -p %s\n' "$BACKUP_DIR"
    printf '+ tar -czf %s -C %s %s\n' "$BACKUP_FILE" "$PROJECT_DIR" "${SOURCES[*]}"
    log "(dry run) no archive written; a real run prints its path, size and sha256 here"
    return 0
  fi

  [[ ! -e "$BACKUP_FILE" ]] || die "backup file already exists: $BACKUP_FILE"
  if [[ $AUDIT_MISSING_DIR -eq 1 ]]; then
    printf '+ mkdir -p %s && chmod 0755 %s\n' "$PROJECT_DIR/$AUDIT_SRC" "$PROJECT_DIR/$AUDIT_SRC"
    { mkdir -p "$PROJECT_DIR/$AUDIT_SRC" && chmod 0755 "$PROJECT_DIR/$AUDIT_SRC"; } || die "could not create $PROJECT_DIR/$AUDIT_SRC. Nothing was changed."
  fi
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
    run "${COMPOSE_CMD[@]}" -p "$PROJECT_NAME" -f "$COMPOSE_FILE" build --pull
  else
    run "${COMPOSE_CMD[@]}" -p "$PROJECT_NAME" -f "$COMPOSE_FILE" pull
  fi
  # ordered start: ovpn-admin connects to the management interface of openvpn, which is not listening
  # until openvpn has finished its first-start work (DH parameters take ~20s), so openvpn goes first
  STAGE="start openvpn"
  run "${COMPOSE_CMD[@]}" -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d --no-deps openvpn
  wait_management
  STAGE="start ovpn-admin"
  run "${COMPOSE_CMD[@]}" -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d --no-deps ovpn-admin
}

# the management interface listens on 127.0.0.1:8989 inside the openvpn container (setup/configure.sh).
# The sleep matters: BusyBox nc exits as soon as its stdin hits EOF, so "printf 'version\nquit\n' | nc"
# only ever shows the banner (">INFO:OpenVPN Management Interface Version 6") and loses the reply.
MGMT_PROBE="(printf 'version\\n'; sleep 1; printf 'quit\\n') | nc -w 2 127.0.0.1 8989"

wait_management() {
  STAGE="wait for management interface"
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '+ %s -p %s -f %s exec -T openvpn sh -c "%s" | grep -q %s   (every 2s, up to %ss; ovpn-admin is started only after it passes)\n' \
      "$COMPOSE_STR" "$PROJECT_NAME" "$COMPOSE_FILE" "$MGMT_PROBE" "'OpenVPN Version'" "$MGMT_TIMEOUT"
    return 0
  fi
  log "waiting up to ${MGMT_TIMEOUT}s for the OpenVPN management interface (127.0.0.1:8989 in the openvpn container)"
  local start=$SECONDS deadline=$((SECONDS + MGMT_TIMEOUT)) attempt=0 out="" nc_ok=0 rc
  while :; do
    attempt=$((attempt + 1))
    # a missing nc must be a clear error, not a silent timeout: "command -v" prints nothing and exits 1
    # when nc is absent, while a container that is not running yet makes compose print an error
    if [[ $nc_ok -eq 0 ]]; then
      rc=0
      out=$(compose exec -T openvpn sh -c 'command -v nc' 2>&1) || rc=$?
      if [[ $rc -eq 0 ]]; then
        nc_ok=1
      elif [[ -z "$out" ]]; then
        die "the 'nc' tool is missing in the openvpn container, so the management interface cannot be probed. The v0.1.1 openvpn image provides BusyBox nc: rebuild it (build --pull) and re-run. ovpn-admin was NOT started."
      fi
    fi
    if [[ $nc_ok -eq 1 ]]; then
      out=$(compose exec -T openvpn sh -c "$MGMT_PROBE" 2>&1) || true
      if grep -q 'OpenVPN Version' <<<"$out"; then
        log "management interface answered on attempt ${attempt} after about $((SECONDS - start))s"
        return 0
      fi
    fi
    if [[ $attempt -eq 1 || $((attempt % 5)) -eq 0 ]]; then
      log "  attempt ${attempt} ($((SECONDS - start))s): management interface not answering yet"
    fi
    [[ $SECONDS -lt $deadline ]] || break
    sleep 2
  done
  {
    log "NOT ready: the management interface did not answer within ${MGMT_TIMEOUT}s (${attempt} attempts)"
    log "last probe output (passwords and tokens redacted): ${out:-<none>}" | redact
    log "ovpn-admin was NOT started or recreated."
    log "-- container status"
    compose_ps_all || true
    log "-- last 40 openvpn log lines (passwords and tokens redacted)"
    compose logs --no-color --tail=40 openvpn 2>&1 | redact || true
  } >&2
  return 1
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
    compose_ps_all || true
    log "-- last 20 log lines (passwords and tokens redacted)"
    compose logs --no-color --tail=20 2>&1 | redact || true
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
