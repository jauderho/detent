#!/usr/bin/env bash
#
# mounts-activation-check.sh - Prove on a real systemd host (testhost) that a
# `mounts` apply through a running `detent serve` starts the mount units of
# the fstab entries it adds, that a commit-confirm rollback stops exactly
# those units and nothing else, and that a confirm keeps them (BUGFIX Track
# D 1; owner decision 2026-10-06: [mounts] activate_new_entries).
#
# Usage:
#   scripts/mounts-activation-check.sh [OPTIONS]
#
# Options:
#   --detent <path>       The detent binary (default: /usr/local/bin/detent).
#   --url <url>           Base URL of the running server
#                          (default: https://127.0.0.1:3333).
#   --state-root <path>   detent's state root; its owner is the worker
#                          account that mints the API token
#                          (default: /var/lib/detent).
#   --base <dir>          Directory the test mount points are made under.
#                          Created, and removed at the end
#                          (default: /mnt/detent-check).
#   --nfs                 Also add an NFS entry to an unreachable server
#                          (192.0.2.1, TEST-NET-1). Its unit must end
#                          `pending` or `failed` within the wait, never
#                          hang the apply. Needs mount.nfs (nfs-common).
#   --expect-off          The server runs with [mounts] activate_new_entries
#                          = false: check that the apply reports
#                          `activated: false` and mounts nothing.
#   --escape-only         Only compare detent's unit-name table with
#                          `systemd-escape --path --suffix=mount`; change
#                          nothing. Needs no root and no server.
#   --dryrun              Print the entries and the requests this script
#                          would make, and change nothing.
#   --verbose, -v         Print step-level progress and every API answer.
#   -h, --help            Show this help message.
#
# Before the run (check mode, as root on testhost):
#   1. Install the build under test and the packaged unit, with
#      `[mounts] activate_new_entries = true` (or false, with --expect-off)
#      in /etc/detent/detent.toml, and start it: `systemctl start detent`.
#   2. The `detent` account must exist (it owns --state-root).
#
# What it does (check mode):
#   1. Compares the unit-name table of crates/modules/mounts with
#      systemd-escape.
#   2. Mints a write-scope API token (one hour) as the worker account; it
#      stays in a 0600 file in the work directory, never in argv, and is
#      revoked at the end.
#   3. Round 1: adds a tmpfs entry, an x-systemd.automount tmpfs entry, a
#      noauto entry (and, with --nfs, an NFS entry) through
#      POST /api/v1/modules/mounts/apply. Checks the reported units and
#      their names against systemd-escape, that the tmpfs is mounted, that
#      the automount unit is active, and that the noauto entry is not
#      listed. Then rolls the commit back and checks that /etc/fstab is
#      back, that the test units are inactive, and that every mount point
#      mounted before the run is still mounted.
#   4. Round 2: the same apply, then a confirm. The tmpfs stays mounted.
#   5. Cleanup (also on any failure): puts the original /etc/fstab back
#      when it differs, reloads systemd, stops the test units, revokes the
#      token, and removes the empty test directories (rmdir only). Nothing
#      mounted before the run is touched.
#
# Exit codes: 0 every check passed; 1 a check failed; 2 a precondition is
# missing (not root, no systemd, a tool or the server is absent).
#
# Requires: bash, curl, jq, systemd (systemctl, systemd-escape), findmnt,
# runuser.

set -euo pipefail

DETENT_BIN="/usr/local/bin/detent"
BASE_URL="https://127.0.0.1:3333"
STATE_ROOT="/var/lib/detent"
BASE="/mnt/detent-check"
NFS=false
EXPECT_OFF=false
ESCAPE_ONLY=false
DRYRUN=false
VERBOSE=false

FSTAB="/etc/fstab"
WORKDIR=""
FSTAB_ORIGINAL=""
TOKEN_ID=""
WORKER_USER=""
FAILED=0

if [[ -n "${NO_COLOR:-}" ]]; then
  RED=""
  GREEN=""
  BLUE=""
  NC=""
else
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  BLUE=$'\033[0;34m'
  NC=$'\033[0m'
fi

log() {
  echo "${BLUE}[mounts-check]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[mounts-check][verbose]${NC} $*"
  fi
}

pass() {
  echo "${GREEN}PASS${NC} $*"
}

fail() {
  echo "${RED}FAIL${NC} $*" >&2
  FAILED=1
}

die() {
  echo "${RED}FAIL${NC} $*" >&2
  exit 1
}

missing() {
  echo "${RED}MISSING${NC} $*" >&2
  exit 2
}

show_usage() {
  sed -n '2,67p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detent)
      DETENT_BIN="$2"
      shift 2
      ;;
    --url)
      BASE_URL="$2"
      shift 2
      ;;
    --state-root)
      STATE_ROOT="$2"
      shift 2
      ;;
    --base)
      BASE="$2"
      shift 2
      ;;
    --nfs)
      NFS=true
      shift
      ;;
    --expect-off)
      EXPECT_OFF=true
      shift
      ;;
    --escape-only)
      ESCAPE_ONLY=true
      shift
      ;;
    --dryrun)
      DRYRUN=true
      shift
      ;;
    --verbose | -v)
      VERBOSE=true
      shift
      ;;
    -h | --help)
      show_usage
      exit 0
      ;;
    *)
      echo "${RED}Unknown argument: $1${NC}" >&2
      show_usage
      exit 2
      ;;
  esac
done

# --- The test entries -------------------------------------------------------

# One "spec|mountpoint|fstype|options" line per entry, in file order.
test_entries() {
  echo "tmpfs|${BASE}/tmp-data|tmpfs|nosuid,nodev,noexec,nofail,size=1m"
  echo "tmpfs|${BASE}/auto|tmpfs|x-systemd.automount,nosuid,nodev,noexec,nofail,size=1m"
  echo "tmpfs|${BASE}/manual|tmpfs|noauto,user,nosuid,nodev,noexec,size=1m"
  if [[ "${NFS}" == true ]]; then
    echo "192.0.2.1:/export|${BASE}/nfs|nfs4|nofail,_netdev,soft,timeo=10,retrans=1"
  fi
}

# --- 1. Unit names ----------------------------------------------------------

# The table of mount_unit_names_follow_systemd_path_escaping
# (crates/modules/mounts/src/lib.rs): decoded path, then detent's unit name.
ESCAPE_TABLE=(
  "/|-.mount"
  "/srv/data|srv-data.mount"
  "/srv/my-data|srv-my\\x2ddata.mount"
  "/mnt/with space|mnt-with\\x20space.mount"
  "/mnt/back\\\\slash|mnt-back\\x5c\\x5cslash.mount"
  "/.hidden/x|\\x2ehidden-x.mount"
  "/mnt/a.b:c_d|mnt-a.b:c_d.mount"
  "/mnt/ü|mnt-\\xc3\\xbc.mount"
)

check_escape_table() {
  command -v systemd-escape >/dev/null 2>&1 || missing "systemd-escape"
  local row path expected got
  for row in "${ESCAPE_TABLE[@]}"; do
    path="${row%%|*}"
    expected="${row#*|}"
    got="$(systemd-escape --path --suffix=mount -- "${path}")"
    log_verbose "${path} -> ${got}"
    if [[ "${got}" == "${expected}" ]]; then
      pass "unit name of ${path}: ${got}"
    else
      fail "unit name of ${path}: systemd-escape says ${got}, detent says ${expected}"
    fi
  done
}

if [[ "${ESCAPE_ONLY}" == true ]]; then
  if [[ "${DRYRUN}" == true ]]; then
    log "would compare ${#ESCAPE_TABLE[@]} unit names with systemd-escape"
    exit 0
  fi
  check_escape_table
  exit "${FAILED}"
fi

if [[ "${DRYRUN}" == true ]]; then
  log "would compare ${#ESCAPE_TABLE[@]} unit names with systemd-escape"
  log "would mint a write-scope token as the owner of ${STATE_ROOT} with ${DETENT_BIN}"
  log "would add these entries to ${FSTAB} through POST ${BASE_URL}/api/v1/modules/mounts/apply:"
  while IFS='|' read -r spec mountpoint fstype options; do
    log "  ${spec} ${mountpoint} ${fstype} ${options} 0 0"
  done < <(test_entries)
  if [[ "${EXPECT_OFF}" == true ]]; then
    log "would expect mounts.activated = false and nothing mounted, then roll back"
  else
    log "round 1: would check the units, then POST /api/v1/commits/{id}/rollback"
    log "round 2: would apply again, then POST /api/v1/commits/{id}/confirm"
  fi
  log "would restore ${FSTAB} if it differs, stop the test units and remove ${BASE}"
  exit 0
fi

# --- Preconditions ------------------------------------------------------------

[[ "$(id -u)" -eq 0 ]] || missing "root (run with sudo)"
[[ -d /run/systemd/system ]] || missing "systemd as the init system"
for tool in curl jq systemctl systemd-escape findmnt runuser cmp comm; do
  command -v "${tool}" >/dev/null 2>&1 || missing "${tool}"
done
[[ -x "${DETENT_BIN}" ]] || missing "${DETENT_BIN}"
curl -sS -k --noproxy '*' -o /dev/null "${BASE_URL}/healthz" ||
  missing "a running detent serve at ${BASE_URL}"
WORKER_USER="$(stat -c '%U' "${STATE_ROOT}")" || missing "${STATE_ROOT}"

WORKDIR="$(mktemp -d /tmp/detent-mounts-check.XXXXXX)"
chmod 0700 "${WORKDIR}"
FSTAB_ORIGINAL="${WORKDIR}/fstab.original"
cp -p "${FSTAB}" "${FSTAB_ORIGINAL}"
findmnt -rn -o TARGET | sort >"${WORKDIR}/mounted.before"
log_verbose "work directory ${WORKDIR}"

unit_of() {
  local path="$1" options="$2" suffix="mount"
  if [[ ",${options}," == *",x-systemd.automount,"* ]]; then
    suffix="automount"
  fi
  systemd-escape --path --suffix="${suffix}" -- "${path}"
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "${FSTAB_ORIGINAL}" && -f "${FSTAB_ORIGINAL}" ]] &&
    ! cmp -s "${FSTAB_ORIGINAL}" "${FSTAB}"; then
    log "putting the original ${FSTAB} back"
    cp -p "${FSTAB_ORIGINAL}" "${FSTAB}"
    systemctl daemon-reload
  fi
  while IFS='|' read -r _ mountpoint _ options; do
    systemctl stop "$(unit_of "${mountpoint}" "${options}")" >/dev/null 2>&1
    if [[ ",${options}," == *",x-systemd.automount,"* ]]; then
      systemctl stop "$(unit_of "${mountpoint}" "")" >/dev/null 2>&1
    fi
  done < <(test_entries)
  systemctl daemon-reload
  if [[ -n "${TOKEN_ID}" ]]; then
    runuser -u "${WORKER_USER}" -- "${DETENT_BIN}" --state-root "${STATE_ROOT}" \
      token revoke "${TOKEN_ID}" >/dev/null
  fi
  # rmdir, not rm -r: a mount point that is still mounted keeps its
  # contents, and an unreachable share is never walked.
  while IFS='|' read -r _ mountpoint _ _; do
    rmdir -- "${mountpoint}" 2>/dev/null
  done < <(test_entries)
  rmdir -- "${BASE}" 2>/dev/null
  rm -rf -- "${WORKDIR}"
  exit "${status}"
}
trap cleanup EXIT

# --- 2. The API token ---------------------------------------------------------

AUTH_HEADER="${WORKDIR}/auth.header"
(
  umask 077
  runuser -u "${WORKER_USER}" -- "${DETENT_BIN}" --json --state-root "${STATE_ROOT}" \
    token create "mounts-check-$$" --write --expires-secs 3600 >"${WORKDIR}/token.json"
  printf 'Authorization: Bearer %s\n' "$(jq -r '.token' "${WORKDIR}/token.json")" \
    >"${AUTH_HEADER}"
)
TOKEN_ID="$(jq -r '.id' "${WORKDIR}/token.json")"
rm -f -- "${WORKDIR}/token.json"
grep -q 'Bearer [^n]' "${AUTH_HEADER}" || die "token create gave no token"

# api METHOD PATH [BODY_FILE] -> prints the body; fails on a non-2xx status.
api() {
  local method="$1" path="$2" body="${3:-}" out="${WORKDIR}/answer.json" status
  local -a args=(-sS -k --noproxy '*' -o "${out}" -w '%{http_code}' -X "${method}"
    -H "@${AUTH_HEADER}")
  if [[ -n "${body}" ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary "@${body}")
  fi
  status="$(curl "${args[@]}" "${BASE_URL}${path}")"
  log_verbose "${method} ${path} -> ${status}: $(cat "${out}")"
  [[ "${status}" == 2* ]] || die "${method} ${path} answered ${status}: $(cat "${out}")"
  cat "${out}"
}

# --- 3. Apply, check, roll back or confirm ------------------------------------

# Writes the apply request (the current model plus the test entries) to $1.
apply_request() {
  local view="${WORKDIR}/view.json" added="${WORKDIR}/added.json"
  api GET /api/v1/modules/mounts >"${view}"
  test_entries | jq -R -s '
    split("\n") | map(select(length > 0) | split("|")
      | {spec: .[0], mountpoint: .[1], fstype: .[2],
         options: (.[3] | split(",")), dump: 0, pass: 0})' >"${added}"
  jq --slurpfile added "${added}" \
    '{model: (.model | .entries += $added[0]), expected_hash: .current_hash}' \
    "${view}" >"$1"
}

mounted() {
  findmnt -rn -o TARGET --mountpoint "$1" >/dev/null 2>&1
}

check_report() {
  local report="$1" mountpoint options unit state
  if [[ "${EXPECT_OFF}" == true ]]; then
    [[ "$(jq -r '.mounts.activated' "${report}")" == "false" ]] ||
      fail "activation is off, but the report says otherwise: $(jq -c '.mounts' "${report}")"
    [[ "$(jq '.mounts.units | length' "${report}")" == "0" ]] ||
      fail "activation is off, but units were reported"
    if mounted "${BASE}/tmp-data"; then
      fail "${BASE}/tmp-data is mounted with activation off"
    fi
    pass "activation off: nothing reported, nothing mounted"
    return
  fi
  [[ "$(jq -r '.mounts.activated' "${report}")" == "true" ]] ||
    die "the report says activation is off: $(jq -c '.mounts' "${report}")"
  [[ "$(jq -r '.mounts.error // ""' "${report}")" == "" ]] ||
    die "no unit started: $(jq -r '.mounts.error' "${report}")"
  while IFS='|' read -r _ mountpoint _ options; do
    unit="$(unit_of "${mountpoint}" "${options}")"
    state="$(jq -r --arg m "${mountpoint}" \
      '.mounts.units[] | select(.mountpoint == $m) | .state + "|" + .unit' "${report}")"
    if [[ ",${options}," == *",noauto,"* ]]; then
      if [[ -z "${state}" ]]; then
        pass "noauto entry ${mountpoint} is not listed"
      else
        fail "noauto entry ${mountpoint} is listed: ${state}"
      fi
      continue
    fi
    [[ "${state#*|}" == "${unit}" ]] ||
      fail "${mountpoint}: detent's unit ${state#*|} is not systemd-escape's ${unit}"
    case "${mountpoint}" in
      */nfs)
        if [[ "${state%%|*}" == "pending" || "${state%%|*}" == "failed" ]]; then
          pass "NFS entry to an unreachable server: ${state%%|*}"
        else
          fail "NFS entry: ${state%%|*}"
        fi
        ;;
      */auto)
        [[ "${state%%|*}" == "mounted" ]] || fail "${mountpoint}: ${state%%|*}"
        if systemctl is-active --quiet "${unit}"; then
          pass "${unit} is active"
        else
          fail "${unit} is not active"
        fi
        ;;
      *)
        [[ "${state%%|*}" == "mounted" ]] || fail "${mountpoint}: ${state%%|*}"
        if mounted "${mountpoint}"; then
          pass "${mountpoint} is mounted"
        else
          fail "${mountpoint} is not mounted"
        fi
        ;;
    esac
  done < <(test_entries)
}

check_rolled_back() {
  local mountpoint options unit
  if cmp -s "${FSTAB_ORIGINAL}" "${FSTAB}"; then
    pass "${FSTAB} is back"
  else
    fail "${FSTAB} differs from the original after the rollback"
  fi
  while IFS='|' read -r _ mountpoint _ options; do
    unit="$(unit_of "${mountpoint}" "${options}")"
    if systemctl is-active --quiet "${unit}"; then
      fail "${unit} is still active after the rollback"
    else
      pass "${unit} is not active"
    fi
    if mounted "${mountpoint}"; then
      fail "${mountpoint} is still mounted after the rollback"
    fi
  done < <(test_entries)
  findmnt -rn -o TARGET | sort >"${WORKDIR}/mounted.after"
  if comm -23 "${WORKDIR}/mounted.before" "${WORKDIR}/mounted.after" | grep -q .; then
    fail "mounts present before the run are gone: $(comm -23 "${WORKDIR}/mounted.before" \
      "${WORKDIR}/mounted.after" | tr '\n' ' ')"
  else
    pass "every mount present before the run is still mounted"
  fi
}

run_round() {
  local finish="$1" request="${WORKDIR}/apply.json" report="${WORKDIR}/report.json" commit
  apply_request "${request}"
  while IFS='|' read -r _ mountpoint _ _; do
    mkdir -p -- "${mountpoint}"
  done < <(test_entries)
  log "applying ${FSTAB} with the test entries (then ${finish})"
  SECONDS=0
  api POST /api/v1/modules/mounts/apply "${request}" >"${report}"
  log "the apply answered in ${SECONDS}s"
  commit="$(jq -r '.commit.commit_id' "${report}")"
  [[ "${commit}" =~ ^[0-9]+$ ]] || die "the apply armed no commit-confirm window"
  check_report "${report}"
  api POST "/api/v1/commits/${commit}/${finish}" >/dev/null
  pass "commit ${commit}: ${finish}"
}

check_escape_table

run_round rollback
check_rolled_back

if [[ "${EXPECT_OFF}" == false ]]; then
  run_round confirm
  if mounted "${BASE}/tmp-data"; then
    pass "${BASE}/tmp-data stays mounted after the confirm"
  else
    fail "${BASE}/tmp-data is not mounted after the confirm"
  fi
fi

if [[ "${FAILED}" -ne 0 ]]; then
  die "at least one check failed"
fi
pass "every check passed"
