#!/usr/bin/env bash
#
# capability-user-check.sh - Prove on a real systemd host (the test host) that
# detent works in the capability-user privilege mode (PLAN §2.4, Phase 12;
# BUGFIX Track F): the service runs as `detent` with only the ambient
# capabilities it needs, each child keeps only its own, a module apply writes
# a root-owned file in /etc, a service restart goes through polkit, the
# polkit rule refuses what it must refuse, and `detent doctor` is green.
#
# Usage:
#   scripts/capability-user-check.sh [OPTIONS]
#
# Options:
#   --detent <path>          The detent binary (default: /usr/local/bin/detent).
#   --url <url>              Base URL of the running server
#                             (default: https://127.0.0.1:3333).
#   --state-root <path>      detent's state root (default: /var/lib/detent).
#   --service-module <id>    The module whose service is restarted through
#                             the API (default: chrony).
#   --mounts                 Also run scripts/mounts-activation-check.sh
#                             against the same server (the server must run
#                             with [mounts] activate_new_entries = true).
#   --dryrun                 Print the checks and requests this script would
#                             make, and change nothing.
#   --verbose, -v            Print step-level progress and every API answer.
#   -h, --help               Show this help message.
#
# Before the run (as root on the test host):
#   1. Install the build under test with
#      `packaging/install.sh --mode capability-user --binary <detent>`.
#   2. Put `[privilege] mode = "capability-user"` in /etc/detent/detent.toml
#      (with --mounts also `[mounts] activate_new_entries = true`), run
#      `sudo -u detent detent setup` once, and `systemctl start detent`.
#   3. The service of --service-module must be installed (chrony: chronyd).
#
# What it does:
#   1. Unit: `systemctl show` says User=detent, the three ambient
#      capabilities and NoNewPrivileges=yes, and the unit is active.
#   2. Processes: the monitor (MainPID) runs as detent with CapEff exactly
#      CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER; of its children the runner
#      holds only CAP_DAC_OVERRIDE (effective, permitted, ambient) and every
#      other child (worker, acme) holds nothing.
#   3. `detent doctor --json` as detent: `ok` is true and every privilege row
#      is ok.
#   4. Mints a write-scope API token (one hour) as detent; it stays in a 0600
#      file in the work directory, never in argv, and is revoked at the end.
#   5. /etc write: adds a test entry (192.0.2.77, TEST-NET-1) to /etc/hosts
#      through POST /api/v1/modules/hosts/apply, checks the file has it and
#      is still root:root with its old mode, then applies the original model
#      back and checks the entry is gone.
#   6. Service restart: POST /api/v1/services/<module> {"action":"restart"};
#      the unit's ActiveEnterTimestamp must change.
#   7. polkit: `systemctl daemon-reload` as detent succeeds; pkcheck (as root,
#      for a process of detent) refuses a restart of an unlisted unit, a stop
#      of -.mount and var-lib.mount, and a start of detent-update.service;
#      `systemd-run` as detent cannot start detent-update.service or any other
#      transient unit (the shipped rule grants no transient unit).
#   8. With --mounts: runs scripts/mounts-activation-check.sh.
#   Cleanup (also on any failure): puts /etc/hosts back when it differs,
#   revokes the token, removes the work directory.
#
# Exit codes: 0 every check passed; 1 a check failed; 2 a precondition is
# missing (not root, no systemd, a tool or the server is absent).
#
# Requires: bash, curl, jq, systemd (systemctl, systemd-run), pkcheck,
# runuser, setpriv, cmp.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETENT_BIN="/usr/local/bin/detent"
BASE_URL="https://127.0.0.1:3333"
STATE_ROOT="/var/lib/detent"
SERVICE_MODULE="chrony"
MOUNTS=false
DRYRUN=false
VERBOSE=false

ACCOUNT="detent"
UNIT="detent.service"
HOSTS="/etc/hosts"
TEST_IP="192.0.2.77"
TEST_NAME="detent-capability-check.invalid"
WORKDIR=""
HOSTS_ORIGINAL=""
TOKEN_ID=""
AUTH_HEADER=""
SUBJECT_PID=""
FAILED=0

# Capability masks as /proc/<pid>/status prints them.
MASK_MONITOR="000000000000000b" # CAP_CHOWN (0), CAP_DAC_OVERRIDE (1), CAP_FOWNER (3)
MASK_RUNNER="0000000000000002"  # CAP_DAC_OVERRIDE (1)
MASK_NONE="0000000000000000"

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
  echo "${BLUE}[capability-user-check]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[capability-user-check][verbose]${NC} $*" >&2
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
  sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

need_value() {
  [[ $# -ge 2 && -n "$2" ]] || {
    echo "$1 requires a value" >&2
    exit 2
  }
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detent)
      need_value "$@"
      DETENT_BIN="$2"
      shift 2
      ;;
    --url)
      need_value "$@"
      BASE_URL="$2"
      shift 2
      ;;
    --state-root)
      need_value "$@"
      STATE_ROOT="$2"
      shift 2
      ;;
    --service-module)
      need_value "$@"
      SERVICE_MODULE="$2"
      shift 2
      ;;
    --mounts)
      MOUNTS=true
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
      echo "unknown option: $1" >&2
      show_usage >&2
      exit 2
      ;;
  esac
done

log_verbose "detent: ${DETENT_BIN}; url: ${BASE_URL}; state root: ${STATE_ROOT}"
log_verbose "service module: ${SERVICE_MODULE}; mounts: ${MOUNTS}"

if [[ "${DRYRUN}" == true ]]; then
  log "would read ${UNIT} with systemctl show (User, AmbientCapabilities, NoNewPrivileges)"
  log "would compare CapEff/CapPrm/CapAmb of MainPID (${MASK_MONITOR}) and its children"
  log "  (runner ${MASK_RUNNER}, every other child ${MASK_NONE})"
  log "would run '${DETENT_BIN} doctor --json' as ${ACCOUNT}"
  log "would mint a write-scope token as ${ACCOUNT}, revoked at the end"
  log "would add '${TEST_IP} ${TEST_NAME}' to ${HOSTS} through POST ${BASE_URL}/api/v1/modules/hosts/apply, then apply the original model back"
  log "would POST ${BASE_URL}/api/v1/services/${SERVICE_MODULE} {\"action\":\"restart\"}"
  log "would run 'systemctl daemon-reload' and 'systemd-run --unit=detent-update' as ${ACCOUNT}, and pkcheck refusals"
  if [[ "${MOUNTS}" == true ]]; then
    log "would run ${SCRIPT_DIR}/mounts-activation-check.sh --detent ${DETENT_BIN} --url ${BASE_URL} --state-root ${STATE_ROOT}"
  fi
  exit 0
fi

# --- 0. Preconditions ---------------------------------------------------------

[[ "${EUID}" -eq 0 ]] || missing "run as root"
[[ -d /run/systemd/system ]] || missing "systemd is not running"
for tool in curl jq systemctl systemd-run pkcheck runuser setpriv cmp; do
  command -v "${tool}" >/dev/null 2>&1 || missing "${tool}"
done
[[ -x "${DETENT_BIN}" ]] || missing "${DETENT_BIN}"
id -u "${ACCOUNT}" >/dev/null 2>&1 || missing "user ${ACCOUNT}"
curl -sS -k --noproxy '*' -o /dev/null "${BASE_URL}/healthz" ||
  missing "no server answers at ${BASE_URL}"

WORKDIR="$(mktemp -d)"
chmod 0700 "${WORKDIR}"
HOSTS_ORIGINAL="${WORKDIR}/hosts.orig"
cp -p -- "${HOSTS}" "${HOSTS_ORIGINAL}"

cleanup() {
  local status=$?
  if [[ -n "${SUBJECT_PID}" ]]; then
    kill "${SUBJECT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${HOSTS_ORIGINAL}" && -f "${HOSTS_ORIGINAL}" ]] &&
    ! cmp -s "${HOSTS_ORIGINAL}" "${HOSTS}"; then
    log "restoring ${HOSTS}"
    cp -p -- "${HOSTS_ORIGINAL}" "${HOSTS}"
  fi
  if [[ -n "${TOKEN_ID}" ]]; then
    runuser -u "${ACCOUNT}" -- "${DETENT_BIN}" --state-root "${STATE_ROOT}" \
      token revoke "${TOKEN_ID}" >/dev/null || echo "token ${TOKEN_ID} not revoked" >&2
  fi
  if [[ -n "${WORKDIR}" ]]; then
    rm -rf -- "${WORKDIR}"
  fi
  exit "${status}"
}
trap cleanup EXIT

# --- 1. The unit ---------------------------------------------------------------

unit_value() {
  systemctl show --property="$1" --value -- "${UNIT}"
}

[[ "$(unit_value ActiveState)" == "active" ]] || die "${UNIT} is not active"
[[ "$(unit_value User)" == "${ACCOUNT}" ]] || fail "${UNIT} User= is '$(unit_value User)'"
ambient="$(unit_value AmbientCapabilities)"
for cap in cap_chown cap_dac_override cap_fowner; do
  [[ " ${ambient} " == *" ${cap} "* ]] || fail "${UNIT} AmbientCapabilities lacks ${cap}: ${ambient}"
done
[[ "$(unit_value NoNewPrivileges)" == "yes" ]] || fail "${UNIT} has NoNewPrivileges=no"
pass "unit: User=${ACCOUNT}, AmbientCapabilities=${ambient}, NoNewPrivileges=yes"

# --- 2. The processes ----------------------------------------------------------

# status_field PID FIELD -> the value of FIELD in /proc/PID/status.
status_field() {
  awk -v field="$2:" '$1 == field { print $2; exit }' "/proc/$1/status"
}

main_pid="$(unit_value MainPID)"
[[ "${main_pid}" =~ ^[1-9][0-9]*$ ]] || die "no MainPID for ${UNIT}"
monitor_uid="$(status_field "${main_pid}" Uid)"
[[ "${monitor_uid}" == "$(id -u "${ACCOUNT}")" ]] ||
  fail "the monitor runs as uid ${monitor_uid}"
[[ "$(status_field "${main_pid}" CapEff)" == "${MASK_MONITOR}" ]] ||
  fail "monitor CapEff $(status_field "${main_pid}" CapEff), want ${MASK_MONITOR}"
pass "monitor ${main_pid}: uid ${monitor_uid}, CapEff ${MASK_MONITOR}"

runners=0
read -r -a children <"/proc/${main_pid}/task/${main_pid}/children" || true
for child in "${children[@]}"; do
  eff="$(status_field "${child}" CapEff)"
  prm="$(status_field "${child}" CapPrm)"
  amb="$(status_field "${child}" CapAmb)"
  log_verbose "child ${child}: CapEff ${eff} CapPrm ${prm} CapAmb ${amb}"
  if [[ "${eff}" == "${MASK_RUNNER}" ]]; then
    runners=$((runners + 1))
    [[ "${prm}" == "${MASK_RUNNER}" && "${amb}" == "${MASK_RUNNER}" ]] ||
      fail "runner ${child}: CapPrm ${prm} CapAmb ${amb}, want ${MASK_RUNNER}"
  elif [[ "${eff}" != "${MASK_NONE}" || "${prm}" != "${MASK_NONE}" || "${amb}" != "${MASK_NONE}" ]]; then
    fail "child ${child} holds capabilities: CapEff ${eff} CapPrm ${prm} CapAmb ${amb}"
  fi
done
[[ "${runners}" -eq 1 ]] || fail "${runners} children hold ${MASK_RUNNER}; want exactly one (the runner)"
pass "children: the runner holds only CAP_DAC_OVERRIDE, every other child nothing"

# --- 3. doctor -----------------------------------------------------------------

doctor="${WORKDIR}/doctor.json"
runuser -u "${ACCOUNT}" -- "${DETENT_BIN}" --json --state-root "${STATE_ROOT}" doctor \
  >"${doctor}" || true
log_verbose "doctor: $(jq -c '.checks' "${doctor}")"
doctor_ok=true
if [[ "$(jq -r '.ok' "${doctor}")" != "true" ]]; then
  fail "doctor is not green: $(jq -c '[.checks[] | select(.status == "fail")]' "${doctor}")"
  doctor_ok=false
fi
for row in privilege-mode service-account state-owner backups-dir polkit-rule polkit-daemon unit-capabilities; do
  status="$(jq -r --arg n "${row}" '[.checks[] | select(.name == $n) | .status][0] // "absent"' "${doctor}")"
  if [[ "${status}" != "ok" ]]; then
    fail "doctor row ${row}: ${status}"
    doctor_ok=false
  fi
done
[[ "${doctor_ok}" == true ]] && pass "doctor: ok, every privilege row ok"

# --- 4. The API token ----------------------------------------------------------

AUTH_HEADER="${WORKDIR}/auth.header"
(
  umask 077
  runuser -u "${ACCOUNT}" -- "${DETENT_BIN}" --json --state-root "${STATE_ROOT}" \
    token create "capability-user-check-$$" --write --expires-secs 3600 >"${WORKDIR}/token.json"
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

# --- 5. A module apply writes /etc ---------------------------------------------

owner_mode() {
  stat -c '%U:%G %a' -- "$1"
}

before="$(owner_mode "${HOSTS}")"
view="${WORKDIR}/hosts-view.json"
request="${WORKDIR}/hosts-request.json"
api GET /api/v1/modules/hosts >"${view}"
jq --arg ip "${TEST_IP}" --arg name "${TEST_NAME}" \
  '{model: (.model | .entries += [{ip: $ip, hostnames: [$name]}]), expected_hash: .current_hash}' \
  "${view}" >"${request}"
api POST /api/v1/modules/hosts/apply "${request}" >/dev/null
grep -q "${TEST_NAME}" "${HOSTS}" || fail "${HOSTS} has no ${TEST_NAME} after the apply"
after="$(owner_mode "${HOSTS}")"
[[ "${after}" == "${before}" ]] || fail "${HOSTS} was ${before}, is ${after} after the apply"
pass "apply wrote ${HOSTS} (${after})"

api GET /api/v1/modules/hosts >"${WORKDIR}/hosts-view2.json"
jq --slurpfile original "${view}" \
  '{model: $original[0].model, expected_hash: .current_hash}' \
  "${WORKDIR}/hosts-view2.json" >"${request}"
api POST /api/v1/modules/hosts/apply "${request}" >/dev/null
if grep -q "${TEST_NAME}" "${HOSTS}"; then
  fail "${TEST_NAME} is still in ${HOSTS} after the second apply"
else
  pass "the second apply removed the test entry"
fi

# --- 6. A service restart through polkit ----------------------------------------

service_view="${WORKDIR}/service.json"
api GET "/api/v1/services/${SERVICE_MODULE}" >"${service_view}"
service_unit="$(jq -r '.unit' "${service_view}")"
[[ -n "${service_unit}" && "${service_unit}" != "null" ]] ||
  die "no unit for module ${SERVICE_MODULE}: $(cat "${service_view}")"
started_before="$(systemctl show --property=ActiveEnterTimestampMonotonic --value -- "${service_unit}")"
printf '{"action":"restart"}' >"${WORKDIR}/restart.json"
api POST "/api/v1/services/${SERVICE_MODULE}" "${WORKDIR}/restart.json" >/dev/null
started_after="$(systemctl show --property=ActiveEnterTimestampMonotonic --value -- "${service_unit}")"
if [[ "${started_after}" != "${started_before}" ]]; then
  pass "restart of ${service_unit} through the API and polkit"
else
  fail "${service_unit} did not restart (ActiveEnterTimestampMonotonic ${started_after})"
fi

# --- 7. What polkit allows and refuses -------------------------------------------

if runuser -u "${ACCOUNT}" -- systemctl --no-ask-password daemon-reload; then
  pass "daemon-reload as ${ACCOUNT}"
else
  fail "daemon-reload as ${ACCOUNT} was refused"
fi

# A process of the account for pkcheck to ask about, as systemd does. Not
# runuser: `$!` would be the runuser parent, which stays root, and polkit
# allows root everything.
setpriv --reuid="${ACCOUNT}" --regid="${ACCOUNT}" --init-groups sleep 120 &
SUBJECT_PID=$!
sleep 0.5

refused() {
  local what="$1"
  shift
  if pkcheck --process "${SUBJECT_PID}" "$@" >/dev/null 2>&1; then
    fail "polkit allows ${ACCOUNT} to ${what}"
  else
    pass "polkit refuses ${ACCOUNT} to ${what}"
  fi
}

manage=(--action-id org.freedesktop.systemd1.manage-units)
refused "restart sshd.service" "${manage[@]}" --detail unit sshd.service --detail verb restart
refused "stop ${service_unit}" "${manage[@]}" --detail unit "${service_unit}" --detail verb stop
refused "stop -.mount" "${manage[@]}" --detail unit -.mount --detail verb stop
refused "stop var-lib.mount" "${manage[@]}" --detail unit var-lib.mount --detail verb stop
refused "start detent-update.service" "${manage[@]}" --detail unit detent-update.service --detail verb start
refused "edit unit files" --action-id org.freedesktop.systemd1.manage-unit-files

for name in detent-update capability-user-check-other; do
  if runuser -u "${ACCOUNT}" -- systemd-run --no-ask-password --quiet \
    --unit="${name}" --collect /bin/true 2>"${WORKDIR}/run.err"; then
    fail "systemd-run as ${ACCOUNT} started ${name}.service"
  else
    log_verbose "systemd-run ${name}: $(cat "${WORKDIR}/run.err")"
    pass "systemd-run as ${ACCOUNT} cannot start ${name}.service"
  fi
done

# --- 8. Mount activation ----------------------------------------------------------

if [[ "${MOUNTS}" == true ]]; then
  mount_args=(--detent "${DETENT_BIN}" --url "${BASE_URL}" --state-root "${STATE_ROOT}")
  if [[ "${VERBOSE}" == true ]]; then
    mount_args+=(--verbose)
  fi
  if "${SCRIPT_DIR}/mounts-activation-check.sh" "${mount_args[@]}"; then
    pass "mount activation (mounts-activation-check.sh)"
  else
    fail "mounts-activation-check.sh failed"
  fi
fi

if [[ "${FAILED}" -ne 0 ]]; then
  echo "${RED}capability-user check: FAILED${NC}" >&2
  exit 1
fi
echo "${GREEN}capability-user check: every check passed${NC}"
