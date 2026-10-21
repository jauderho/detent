#!/usr/bin/env bash
#
# d3-inside.sh - Phase 7 and Phase 8 acceptance checks of one distro, run
# INSIDE a container whose PID 1 is systemd (BUGFIX Track D 3, done in
# containers; owner decision 2026-10-14). spikes/d3-containers.sh builds the
# container and calls this script; read that script for the whole flow.
#
# Usage:
#   d3-inside.sh [OPTIONS]
#
# Options:
#   --distro <name>     Result label (default: ID from /etc/os-release).
#   --detent <path>     The detent binary (default: /stage/detent).
#   --stage <dir>       Directory with packaging/ and scripts/ copied from the
#                        repository (default: /stage).
#   --out <file>        Result file, one tab-separated row per check:
#                        distro, module, step, result, detail
#                        (default: /stage/results/<distro>.tsv). The raw
#                        output of every step goes to <out minus .tsv>.d/.
#   --only <list>       Comma list of sections to run, from: prep chrony
#                        samba nfs resolver mounts dhcp network (default: all).
#   --net <list>        Comma list of network flavours to try, from: ifupdown
#                        nm networkd netplan netplan-nm (netplan with the
#                        NetworkManager renderer) (default: by distro).
#   --dryrun            Print the sections and checks that would run; change
#                        nothing.
#   --verbose, -v       Print step-level progress and every command output.
#   -h, --help          Show this help message.
#
# Results: PASS, FAIL (a check failed; the detail has the first error line),
# NT (not testable in a container; the detail has the exact error), INFO.
#
# What the container gives (see d3-containers.sh): systemd as PID 1, a
# private network namespace with loopback only, all capabilities except
# CAP_SYS_TIME, no kernel module loading outside what the host already did.
# The network checks use a veth pair (mgmt0 here, peer0 in the namespace
# d3peer) so a bad address change cuts a real path.
#
# Order matters. A root CLI write before `detent serve` ever ran leaves the
# audit log root-owned (a finding, recorded by the `order` step), so the CLI
# sections run first and the audit directory is repaired before the API
# sections.
#
# Requires: bash, jq, curl, iproute2, util-linux, systemd, timeout.

set -euo pipefail

DISTRO=""
DET="/stage/detent"
STAGE="/stage"
OUT=""
ONLY="prep,chrony,samba,nfs,resolver,mounts,dhcp,network"
NETS=""
DRYRUN=false
VERBOSE=false

BASE_URL="https://127.0.0.1:3333"
WORK=""
LOGD=""
TOK=""
HIDDEN=()
STUBBED=()
CONFIRM_WAIT=75

if [[ -n "${NO_COLOR:-}" ]]; then
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  NC=""
else
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[0;33m'
  BLUE=$'\033[0;34m'
  NC=$'\033[0m'
fi

log() {
  echo "${BLUE}[d3]${NC} $*"
}

vlog() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[d3][verbose]${NC} $*" >&2
  fi
}

die() {
  echo "${RED}ERROR${NC} $*" >&2
  exit 2
}

show_usage() {
  sed -n '2,43p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --distro)
      DISTRO="$2"
      shift 2
      ;;
    --detent)
      DET="$2"
      shift 2
      ;;
    --stage)
      STAGE="$2"
      shift 2
      ;;
    --out)
      OUT="$2"
      shift 2
      ;;
    --only)
      ONLY="$2"
      shift 2
      ;;
    --net)
      NETS="$2"
      shift 2
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

if [[ -z "${DISTRO}" ]]; then
  # shellcheck source=/dev/null
  DISTRO="$(. /etc/os-release && echo "${ID}")"
fi
if [[ -z "${OUT}" ]]; then
  OUT="${STAGE}/results/${DISTRO}.tsv"
fi
if [[ -z "${NETS}" ]]; then
  case "${DISTRO}" in
    debian) NETS="ifupdown,nm" ;;
    ubuntu) NETS="netplan,netplan-nm" ;;
    fedora) NETS="nm" ;;
    arch) NETS="networkd" ;;
    *) NETS="networkd" ;;
  esac
fi

wanted() {
  [[ ",${ONLY}," == *",$1,"* ]]
}

if [[ "${DRYRUN}" == true ]]; then
  log "distro ${DISTRO}; sections ${ONLY}; network flavours ${NETS}"
  log "would write ${OUT} and ${OUT%.tsv}.d/"
  log "would install ${DET} with ${STAGE}/packaging/install.sh and start detent"
  log "per module: get, validate, plan, apply (CLI for chrony samba nfs; API for"
  log "resolver mounts dhcp network, which need commit-confirm), file and service checks"
  log "network: baseline apply, then a bad address with a 60 s window and a rollback check"
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "run as root"
for tool in jq curl ip timeout systemctl; do
  command -v "${tool}" >/dev/null 2>&1 || die "missing ${tool}"
done
[[ -x "${DET}" ]] || die "missing ${DET}"

mkdir -p "$(dirname "${OUT}")"
LOGD="${OUT%.tsv}.d"
rm -rf "${LOGD}"
mkdir -p "${LOGD}"
: >"${OUT}"
WORK="$(mktemp -d /tmp/d3-work.XXXXXX)"

# --- recording -----------------------------------------------------------------

# rec MODULE STEP RESULT DETAIL...
rec() {
  local module="$1" step="$2" result="$3" detail
  shift 3
  detail="$(printf '%s' "$*" | tr '\t\r\n' '   ' | cut -c1-400)"
  printf '%s\t%s\t%s\t%s\t%s\n' "${DISTRO}" "${module}" "${step}" "${result}" "${detail}" >>"${OUT}"
  local colour="${YELLOW}"
  case "${result}" in
    PASS) colour="${GREEN}" ;;
    FAIL) colour="${RED}" ;;
  esac
  echo "${colour}${result}${NC} ${module} ${step}: ${detail}"
}

# cap NAME CMD... : run CMD with stdin from $STDIN_FILE when set; keep the
# output in the log directory; set RC and CAPFILE. Never fails.
RC=0
CAPFILE=""
STDIN_FILE=""
cap() {
  local name="$1"
  shift
  if [[ "$1" == "${DET}" ]]; then
    serve_down
  fi
  CAPFILE="${LOGD}/${name}.txt"
  RC=0
  {
    echo "\$ $*"
    if [[ -n "${STDIN_FILE}" ]]; then
      timeout 180 "$@" <"${STDIN_FILE}" 2>&1 || RC=$?
    else
      timeout 180 "$@" 2>&1 </dev/null || RC=$?
    fi
    echo "[rc=${RC}]"
  } >"${CAPFILE}" 2>&1
  vlog "$(cat "${CAPFILE}")"
}

# first_line FILE REGEX : first matching line of the capture, trimmed.
first_line() {
  grep -E -m1 -- "$2" "$1" | cut -c1-300 || true
}

# --- helpers ---------------------------------------------------------------------

unit_exists() {
  systemctl cat "$1" >/dev/null 2>&1
}

first_unit() {
  local unit
  for unit in "$@"; do
    if unit_exists "${unit}"; then
      echo "${unit}"
      return 0
    fi
  done
  return 1
}

# hide PATH : move a program aside so detent does not see the service.
hide() {
  local path="$1"
  if [[ -e "${path}" && ! -e "${path}.d3off" ]]; then
    serve_down
    mv "${path}" "${path}.d3off"
    HIDDEN+=("${path}")
    vlog "hid ${path}"
  fi
}

# stub PATH : make PATH a program that exits 0. This stands in for a validator
# that cannot judge the candidate (wrong format, or not installed). It is a
# workaround to reach the code after the checks, never a pass of the check.
stub() {
  local path="$1"
  serve_down
  if [[ -e "${path}" && ! -e "${path}.d3off" ]]; then
    mv "${path}" "${path}.d3off"
  fi
  printf '#!/bin/sh\nexit 0\n' >"${path}"
  chmod 755 "${path}"
  STUBBED+=("${path}")
}

unhide_all() {
  local path
  if [[ ${#HIDDEN[@]} -gt 0 || ${#STUBBED[@]} -gt 0 ]]; then
    serve_down
  fi
  for path in ${STUBBED[@]+"${STUBBED[@]}"}; do
    rm -f "${path}"
    if [[ -e "${path}.d3off" ]]; then
      mv "${path}.d3off" "${path}"
    fi
  done
  STUBBED=()
  for path in ${HIDDEN[@]+"${HIDDEN[@]}"}; do
    if [[ -e "${path}.d3off" ]]; then
      mv "${path}.d3off" "${path}"
    fi
  done
  HIDDEN=()
}

cleanup() {
  local status=$?
  set +e
  unhide_all
  if [[ -n "${WORK}" ]]; then
    rm -rf "${WORK}"
  fi
  exit "${status}"
}
trap cleanup EXIT

wait_boot() {
  local state=""
  state="$(timeout 120 systemctl is-system-running --wait 2>/dev/null || true)"
  echo "${state}"
}

# detent_cli ARGS... with the model in $STDIN_FILE.
cli() {
  "${DET}" "$@"
}

# seed_target MODULE : the module reads one fixed path and the distro keeps the
# file elsewhere or ships none. Put a copy (or a minimal file) at that path so
# the rest of the module can be exercised. Prints what it did; returns 1 when
# there is nothing to do.
seed_target() {
  case "$1" in
    chrony)
      [[ -f /etc/chrony.conf && ! -e /etc/chrony/chrony.conf ]] || return 1
      mkdir -p /etc/chrony
      cp -p /etc/chrony.conf /etc/chrony/chrony.conf
      echo "copied /etc/chrony.conf to /etc/chrony/chrony.conf"
      ;;
    resolver)
      local vendor f
      vendor=""
      for f in /usr/lib/systemd/resolved.conf /lib/systemd/resolved.conf; do
        if [[ -f "${f}" ]]; then
          vendor="${f}"
          break
        fi
      done
      [[ -n "${vendor}" && ! -e /etc/systemd/resolved.conf ]] || return 1
      cp -p "${vendor}" /etc/systemd/resolved.conf
      echo "copied ${vendor} to /etc/systemd/resolved.conf"
      ;;
    network)
      [[ ! -e /etc/network/interfaces ]] || return 1
      mkdir -p /etc/network/interfaces.d
      printf 'source /etc/network/interfaces.d/*\n' >/etc/network/interfaces
      echo "created a one-line /etc/network/interfaces"
      ;;
    *) return 1 ;;
  esac
}

cli_get() {
  local module="$1" raw seeded
  raw="${LOGD}/${module}-get.txt"
  serve_down
  RC=0
  "${DET}" --json config "${module}" get >"${raw}" 2>&1 || RC=$?
  if [[ "${RC}" -eq 0 ]] && ! jq -e '.module.model != null' "${raw}" >/dev/null 2>&1; then
    rec "${module}" get FAIL "rc=0 but the model is null: no readable target file among $(jq -r '[.module.descriptor.targets[].path] | join(" ")' "${raw}" 2>/dev/null)"
    if seeded="$(seed_target "${module}")"; then
      rec "${module}" get-seed INFO "workaround: ${seeded}"
      RC=0
      "${DET}" --json config "${module}" get >"${raw}" 2>&1 || RC=$?
    fi
  fi
  if [[ "${RC}" -ne 0 ]] || ! jq -e '.module.model != null' "${raw}" >/dev/null 2>&1; then
    rec "${module}" get FAIL "rc=${RC} $(grep -v -E '^(installed|network backend|detection)' "${raw}" | head -n 1 | cut -c1-250)"
    return 1
  fi
  jq -c '.module' "${raw}" >"${WORK}/${module}.get.json"
  jq -c '.model' "${WORK}/${module}.get.json" >"${WORK}/${module}.model.json"
}

# cli_validate MODULE MODEL_FILE STEP_LABEL
cli_validate() {
  local module="$1" model="$2" label="${3:-validate}"
  STDIN_FILE="${model}"
  cap "${module}-${label}" "${DET}" config "${module}" validate
  STDIN_FILE=""
  if [[ "${RC}" -eq 0 ]] && ! grep -q '^error:' "${CAPFILE}"; then
    rec "${module}" "${label}" PASS "$(first_line "${CAPFILE}" '^(warning|note):')"
  else
    rec "${module}" "${label}" FAIL "rc=${RC} $(first_line "${CAPFILE}" '^error:')"
  fi
}

# cli_plan MODULE MODEL_FILE STEP_LABEL
cli_plan() {
  local module="$1" model="$2" label="${3:-plan}"
  STDIN_FILE="${model}"
  cap "${module}-${label}" "${DET}" config "${module}" plan
  STDIN_FILE=""
  if [[ "${RC}" -eq 0 ]] && grep -q '^+++ ' "${CAPFILE}"; then
    rec "${module}" "${label}" PASS "diff for $(sed -n 's/^+++ //p' "${CAPFILE}" | head -n 1)"
  else
    rec "${module}" "${label}" FAIL "rc=${RC} $(first_line "${CAPFILE}" '(not valid|cannot|error|failed)')"
  fi
}

# validator_failures CAPFILE : programs that "ran; passed: no" or "did not
# run" in a plan. An apply fails closed on either (detent-ops engine).
validator_failures() {
  sed -n -e 's/^the upstream validator \([^ ]*\) ran; passed: no.*/\1/p' \
    -e 's/^the upstream validator \([^ ]*\) did not run.*/\1/p' "$1"
}

# --- the API ---------------------------------------------------------------------

API_CODE=""
API_FILE=""

start_detent() {
  systemctl start detent
  for _ in $(seq 1 30); do
    if curl -sS -k --noproxy '*' -o /dev/null "${BASE_URL}/healthz" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

mint_token() {
  TOK="$(runuser -u detent -- "${DET}" --json token create "d3-${DISTRO}" --write \
    --expires-secs 14400 2>/dev/null | jq -r '.token // empty')"
  [[ -n "${TOK}" ]]
}

# The CLI cannot run while `detent serve` holds the state lock, and the API
# needs it: switch between the two. No commit window may be open.
serve_down() {
  if systemctl is-active --quiet detent.service; then
    systemctl stop detent.service
  fi
}

serve_up() {
  if ! systemctl is-active --quiet detent.service; then
    start_detent
  fi
  if [[ -z "${TOK}" ]]; then
    mint_token
  fi
}

# api METHOD PATH [BODY_FILE] : answer in $API_FILE, status in $API_CODE.
api() {
  local method="$1" path="$2" body="${3:-}"
  serve_up || true
  API_FILE="${WORK}/api.out"
  local -a args=(-sS -k --noproxy '*' -o "${API_FILE}" -w '%{http_code}' -X "${method}"
    -H "Authorization: Bearer ${TOK}")
  if [[ -n "${body}" ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary "@${body}")
  fi
  API_CODE="$(timeout 120 curl "${args[@]}" "${BASE_URL}${path}" 2>/dev/null || echo 000)"
  vlog "${method} ${path} -> ${API_CODE}: $(head -c 600 "${API_FILE}")"
}

# api_apply MODULE JQ_FILTER SECS [SERVICE] LABEL : build the request from the
# current model with FILTER applied; the answer lands in $API_FILE. Sets
# COMMIT_ID ("" when none) and APPLY_OK (true/false).
COMMIT_ID=""
APPLY_OK=false
# NO_HASH=true : send no expected_hash. `current_hash` is the hash of the
# detected file; a model with only another file's section writes that file.
NO_HASH=false
api_apply() {
  local module="$1" filter="$2" secs="$3" service="$4" label="$5"
  api GET "/api/v1/modules/${module}"
  cp "${API_FILE}" "${WORK}/${module}.api-get.json"
  jq -c --argjson secs "${secs}" --arg svc "${service}" --argjson nohash "${NO_HASH}" \
    "{model: (.model | ${filter}), confirm_secs: \$secs}
     + (if \$nohash then {} else {expected_hash: .current_hash} end)
     + (if \$svc == \"\" then {} else {service_action: \$svc} end)" \
    "${WORK}/${module}.api-get.json" >"${WORK}/${module}.req.json"
  api POST "/api/v1/modules/${module}/apply" "${WORK}/${module}.req.json"
  cp "${API_FILE}" "${LOGD}/${module}-${label}.json"
  COMMIT_ID="$(jq -r '.commit.commit_id // empty' "${API_FILE}" 2>/dev/null || true)"
  APPLY_OK=false
  if [[ "${API_CODE}" == 2* ]]; then
    APPLY_OK=true
  fi
}

# first_action MODULE FILTER : plan the filtered model through the API; sets
# FIRST_UNIT and FIRST_ACTION from the first affected service.
first_action() {
  local module="$1" filter="$2"
  FIRST_UNIT=""
  FIRST_ACTION=""
  api GET "/api/v1/modules/${module}"
  jq -c "{model: (.model | ${filter})}" "${API_FILE}" >"${WORK}/${module}.plan-req.json"
  api POST "/api/v1/modules/${module}/plan" "${WORK}/${module}.plan-req.json"
  cp "${API_FILE}" "${LOGD}/${module}-api-plan.json"
  FIRST_UNIT="$(jq -r '.affected_services[0].unit // empty' "${API_FILE}" 2>/dev/null || true)"
  FIRST_ACTION="$(jq -r '.affected_services[0].actions[0] // empty' "${API_FILE}" 2>/dev/null || true)"
}

api_detail() {
  jq -r '(.message_id // "") + " " + (.code // "")' "${API_FILE}" 2>/dev/null | head -c 200 || true
}

commit_act() {
  local act="$1"
  api POST "/api/v1/commits/${COMMIT_ID}/${act}"
  [[ "${API_CODE}" == 2* ]]
}

# apply_with_retry MODULE FILTER SECS SERVICE LABEL
# Tries the apply as is. When an external check blocks it, records that as a
# FAIL, hides the validators that failed in `plan`, and tries again.
# Sets APPLY_OK and COMMIT_ID.
apply_with_retry() {
  local module="$1" filter="$2" secs="$3" service="$4" label="$5"
  api_apply "${module}" "${filter}" "${secs}" "${service}" "${label}"
  if [[ "${APPLY_OK}" == true ]]; then
    rec "${module}" "${label}" PASS "http ${API_CODE}; commit ${COMMIT_ID:-none}"
    return 0
  fi
  local detail
  detail="$(api_detail)"
  rec "${module}" "${label}" FAIL "http ${API_CODE} ${detail}"
  if [[ "${detail}" != *ops-check-failed* ]]; then
    return 0
  fi
  # Which validator blocked it? Ask the CLI plan for the same model.
  jq -c '.model' "${WORK}/${module}.req.json" >"${WORK}/${module}.req-model.json"
  STDIN_FILE="${WORK}/${module}.req-model.json"
  cap "${module}-${label}-plan" "${DET}" config "${module}" plan
  STDIN_FILE=""
  local prog failed=""
  while read -r prog; do
    [[ -n "${prog}" ]] || continue
    failed="${failed} ${prog}"
    stub "${prog}"
  done < <(validator_failures "${CAPFILE}")
  if [[ -z "${failed}" ]]; then
    rec "${module}" "${label}-validators" FAIL "no failing validator found in the plan"
    return 0
  fi
  rec "${module}" "${label}-validators" INFO "failing validators replaced by stubs that exit 0:${failed}"
  api_apply "${module}" "${filter}" "${secs}" "${service}" "${label}-retry"
  if [[ "${APPLY_OK}" == true ]]; then
    rec "${module}" "${label}-retry" PASS "http ${API_CODE}; commit ${COMMIT_ID:-none}"
    return 0
  fi
  detail="$(api_detail)"
  rec "${module}" "${label}-retry" FAIL "http ${API_CODE} ${detail}; monitor: $(monitor_error)"
  if [[ "${detail}" != *ops-check-failed* ]]; then
    return 0
  fi
  # The CLI plan runs validators outside the unit's sandbox. Under `serve`
  # another one can fail: stub every declared validator and try once more.
  while read -r prog; do
    [[ -n "${prog}" ]] || continue
    stub "${prog}"
  done < <(jq -r '.module.descriptor.checks[].program' "${LOGD}/${module}-get.txt")
  rec "${module}" "${label}-validators2" INFO "every declared validator replaced by a stub (some fail only under serve)"
  api_apply "${module}" "${filter}" "${secs}" "${service}" "${label}-retry2"
  if [[ "${APPLY_OK}" == true ]]; then
    rec "${module}" "${label}-retry2" PASS "http ${API_CODE}; commit ${COMMIT_ID:-none}"
  else
    rec "${module}" "${label}-retry2" FAIL "http ${API_CODE} $(api_detail); monitor: $(monitor_error)"
  fi
}

# settle_commit confirm|rollback LABEL MODULE
settle_commit() {
  local act="$1" module="$2"
  if [[ -z "${COMMIT_ID}" ]]; then
    rec "${module}" "commit-${act}" FAIL "no commit id: the apply armed no window"
    return 0
  fi
  if commit_act "${act}"; then
    rec "${module}" "commit-${act}" PASS "commit ${COMMIT_ID}"
  else
    rec "${module}" "commit-${act}" FAIL "http ${API_CODE} $(head -c 200 "${API_FILE}")"
  fi
}

# --- prep ------------------------------------------------------------------------

# ensure_file PATH CONTENT : create PATH when the distro does not ship it.
ensure_file() {
  local path="$1" content="$2"
  if [[ ! -e "${path}" ]]; then
    mkdir -p "$(dirname "${path}")"
    printf '%s' "${content}" >"${path}"
    rec host ensure-file INFO "${path} is not shipped by the package; created a minimal one"
  fi
}

section_prep() {
  log "prep"
  local state
  state="$(wait_boot)"
  rec host boot INFO "systemd is-system-running: ${state}"
  # shellcheck source=/dev/null
  rec host os INFO "$(. /etc/os-release && echo "${PRETTY_NAME}"); systemd $(systemctl --version | head -n 1 | cut -d' ' -f2); detent $("${DET}" --version 2>/dev/null | head -n 1 || true)"
  cap host-detent "${DET}" host
  rec host detent-host INFO "$(grep -E 'network backend' "${CAPFILE}" || echo "${RC}")"
  # Some distros ship no file for a service (Arch: smb.conf, exports, fstab).
  # Create a minimal one so the module has something to edit, and say so.
  ensure_file /etc/samba/smb.conf $'[global]\n   workgroup = WORKGROUP\n'
  ensure_file /etc/exports ''
  ensure_file /etc/fstab $'# /etc/fstab\n'
  cap install bash "${STAGE}/packaging/install.sh" --binary "${DET}"
  if [[ "${RC}" -eq 0 ]]; then
    rec host install PASS "packaging/install.sh (root-confined)"
  else
    rec host install FAIL "rc=${RC} $(tail -n 3 "${CAPFILE}" | head -n 1)"
  fi
  cap host-doctor "${DET}" doctor
  rec host doctor INFO "$(grep -c '^ok' "${CAPFILE}") ok, $(grep -c '^warn' "${CAPFILE}") warn, $(grep -c '^fail' "${CAPFILE}") fail"
  local line
  while read -r line; do
    rec host doctor-line INFO "${line}"
  done < <(grep -E '^(warn|fail)' "${CAPFILE}" || true)
  if ip link show mgmt0 >/dev/null 2>&1; then
    return 0
  fi
  ip netns add d3peer
  ip link add mgmt0 type veth peer name peer0
  ip link set peer0 netns d3peer
  ip netns exec d3peer ip addr add 192.0.2.2/24 dev peer0
  ip netns exec d3peer ip link set peer0 up
  ip netns exec d3peer ip link set lo up
  ip link set mgmt0 up
  ip addr add 192.0.2.1/24 dev mgmt0
  if ip netns exec d3peer ping -c1 -W2 192.0.2.1 >/dev/null 2>&1; then
    rec host veth PASS "mgmt0 (192.0.2.1/24) reaches peer0 (192.0.2.2/24) in namespace d3peer"
  else
    rec host veth FAIL "the veth pair does not carry traffic"
  fi
}

# --- chrony ----------------------------------------------------------------------

chrony_conf() {
  local f
  for f in /etc/chrony/chrony.conf /etc/chrony.conf; do
    if [[ -f "${f}" ]]; then
      echo "${f}"
      return 0
    fi
  done
  return 1
}

section_chrony() {
  log "chrony"
  local conf
  cli_get chrony || return 0
  conf="$(chrony_conf)" || {
    rec chrony get FAIL "no chrony.conf"
    return 0
  }
  local nerr
  nerr="$(jq '[.diagnostics[] | select(.severity == "error")] | length' "${WORK}/chrony.get.json")"
  rec chrony get PASS "$(jq '.model.settings | length' "${WORK}/chrony.get.json") settings; ${nerr} error diagnostic(s) on the stock file"
  jq -c '.settings |= (map(select(.key != "cmdport")) + [{"key":"cmdport","value":"0"}])' \
    "${WORK}/chrony.model.json" >"${WORK}/chrony.edit.json"
  cli_validate chrony "${WORK}/chrony.edit.json" validate-stock
  cli_plan chrony "${WORK}/chrony.edit.json" plan-stock
  STDIN_FILE="${WORK}/chrony.edit.json"
  cap chrony-apply-stock "${DET}" config chrony apply --service none
  STDIN_FILE=""
  if [[ "${RC}" -eq 0 ]]; then
    rec chrony apply-stock PASS "stock file edited"
  else
    rec chrony apply-stock FAIL "rc=${RC} $(first_line "${CAPFILE}" 'not valid|error')"
    # The stock file has directives the module refuses; drop them and retry.
    local keys
    keys="$(jq -c '[.diagnostics[] | select(.id == "chrony-external-directive") | .args.key] | unique' "${WORK}/chrony.get.json")"
    jq -c --argjson keys "${keys}" \
      '.settings |= map(select(.key as $k | ($keys | index($k)) | not))' \
      "${WORK}/chrony.edit.json" >"${WORK}/chrony.edit2.json"
    cli_validate chrony "${WORK}/chrony.edit2.json" validate-stripped
    STDIN_FILE="${WORK}/chrony.edit2.json"
    cap chrony-apply-stripped "${DET}" config chrony apply --service restart
    STDIN_FILE=""
    if [[ "${RC}" -eq 0 ]]; then
      rec chrony apply-stripped PASS "after removing ${keys}: $(first_line "${CAPFILE}" 'was asked to')"
    else
      rec chrony apply-stripped FAIL "rc=${RC} $(first_line "${CAPFILE}" 'not valid|error')"
    fi
  fi
  if grep -Eq '^cmdport[[:space:]]+0$' "${conf}"; then
    rec chrony file PASS "${conf} has cmdport 0"
  else
    rec chrony file FAIL "${conf} has no cmdport 0"
  fi
  local unit
  unit="$(first_unit chrony.service chronyd.service || true)"
  if [[ -n "${unit}" ]] && systemctl is-active --quiet "${unit}"; then
    rec chrony service PASS "${unit} is active"
  else
    rec chrony service NT "${unit:-chrony}: $(systemctl status "${unit:-chrony}" --no-pager 2>&1 | grep -E 'Active:|Condition' | head -n 2 | tr '\n' ' ') (CAP_SYS_TIME is dropped on purpose: a container must not touch the host clock)"
  fi
  if chronyd -p -f "${conf}" >/dev/null 2>&1; then
    rec chrony upstream-check PASS "chronyd -p -f accepts the written file"
  else
    rec chrony upstream-check FAIL "chronyd -p -f rejects the written file"
  fi
}

# --- samba -----------------------------------------------------------------------

section_samba() {
  log "samba"
  cli_get samba || return 0
  rec samba get PASS "$(jq '.model.entries | length' "${WORK}/samba.get.json") entries"
  jq -c '.entries |= map(select(.key != "server min protocol" and .key != "restrict anonymous"))
    | (.entries | map(.section == "global" and .key == "") | index(true)) as $i
    | .entries |= (.[0:$i+1]
        + [{"key":"server min protocol","section":null,"value":"SMB3_00"},
           {"key":"restrict anonymous","section":null,"value":"2"}]
        + .[$i+1:])' "${WORK}/samba.model.json" >"${WORK}/samba.edit.json" ||
    {
      rec samba edit FAIL "no [global] header in the model"
      return 0
    }
  cli_validate samba "${WORK}/samba.edit.json" validate
  cli_plan samba "${WORK}/samba.edit.json" plan
  STDIN_FILE="${WORK}/samba.edit.json"
  cap samba-apply "${DET}" config samba apply --service restart
  STDIN_FILE=""
  if [[ "${RC}" -eq 0 ]]; then
    rec samba apply PASS "$(first_line "${CAPFILE}" 'was asked to restart')"
  else
    rec samba apply FAIL "rc=${RC} $(first_line "${CAPFILE}" 'not valid|error')"
  fi
  if grep -Eq '^[[:space:]]*server min protocol[[:space:]]*=[[:space:]]*SMB3_00' /etc/samba/smb.conf; then
    rec samba file PASS "/etc/samba/smb.conf has server min protocol = SMB3_00"
  else
    rec samba file FAIL "setting not in /etc/samba/smb.conf"
  fi
  if testparm -s /etc/samba/smb.conf >/dev/null 2>&1; then
    rec samba upstream-check PASS "testparm -s accepts the written file"
  else
    rec samba upstream-check FAIL "testparm -s rejects the written file"
  fi
  local unit
  unit="$(first_unit smbd.service smb.service samba.service || true)"
  sleep 2
  if [[ -n "${unit}" ]] && systemctl is-active --quiet "${unit}"; then
    rec samba service PASS "${unit} is active after the restart"
  else
    rec samba service FAIL "${unit:-smbd} is not active: $(systemctl status "${unit:-smbd}" --no-pager 2>&1 | grep -E 'Active:' | head -n 1)"
  fi
}

# --- nfs -------------------------------------------------------------------------

section_nfs() {
  log "nfs"
  mkdir -p /srv/d3
  cli_get nfs || return 0
  rec nfs get PASS "$(jq '.model.entries | length' "${WORK}/nfs.get.json") exports"
  jq -c '.entries += [{"path":"/srv/d3","clients":[{"host":"192.0.2.0/24","options":["ro","sync","root_squash","no_subtree_check"]}]}]' \
    "${WORK}/nfs.model.json" >"${WORK}/nfs.edit.json"
  cli_validate nfs "${WORK}/nfs.edit.json" validate
  cli_plan nfs "${WORK}/nfs.edit.json" plan
  STDIN_FILE="${WORK}/nfs.edit.json"
  cap nfs-apply "${DET}" config nfs apply --service reload
  STDIN_FILE=""
  if [[ "${RC}" -eq 0 ]]; then
    rec nfs apply PASS "$(first_line "${CAPFILE}" 'was asked to')"
  else
    rec nfs apply FAIL "rc=${RC} $(first_line "${CAPFILE}" 'not valid|error')"
  fi
  if grep -Eq '^/srv/d3[[:space:]]+192\.0\.2\.0/24\(ro,sync,root_squash,no_subtree_check\)' /etc/exports; then
    rec nfs file PASS "/etc/exports has the /srv/d3 export"
  else
    rec nfs file FAIL "$(grep -c d3 /etc/exports) /srv/d3 lines; $(grep d3 /etc/exports | head -n 1)"
  fi
  local unit
  unit="$(first_unit nfs-server.service nfs-kernel-server.service || true)"
  if [[ -n "${unit}" ]] && systemctl is-active --quiet "${unit}"; then
    if exportfs -v 2>/dev/null | grep -q '/srv/d3'; then
      rec nfs service PASS "${unit} is active and exportfs -v lists /srv/d3"
    else
      rec nfs service FAIL "${unit} is active but exportfs -v does not list /srv/d3"
    fi
  else
    rec nfs service NT "${unit:-nfs-server} is not active; start says: $(systemctl start "${unit:-nfs-server}" 2>&1 | head -n 1) / $(journalctl -u "${unit:-nfs-server}" --no-pager 2>/dev/null | tail -n 2 | cut -c1-200 | tr '\n' ' ')"
  fi
}

# --- order (a root CLI write before serve) ---------------------------------------

section_order() {
  log "order: serve after a root CLI write"
  start_detent || {
    rec host serve FAIL "detent.service did not answer /healthz within 30 s"
    return 0
  }
  rec host serve PASS "detent.service answers $(curl -sS -k --noproxy '*' "${BASE_URL}/healthz" 2>/dev/null | head -c 60)"
  mint_token || {
    rec host token FAIL "token create gave no token"
    return 0
  }
  mkdir -p /mnt/d3o
  api_apply mounts '.entries += [{"spec":"tmpfs","mountpoint":"/mnt/d3o","fstype":"tmpfs","options":["nosuid","nodev","noexec","nofail","size=1m"],"dump":0,"pass":0}]' 20 "" order
  if [[ "${APPLY_OK}" == true ]]; then
    rec host order PASS "an API apply works after a root CLI apply (audit dir owner: $(stat -c '%U' /var/lib/detent/audit 2>/dev/null))"
    commit_act rollback || true
  else
    rec host order FAIL "http ${API_CODE} $(api_detail); audit dir owner $(stat -c '%U' /var/lib/detent/audit 2>/dev/null); journal: $(journalctl -u detent --no-pager 2>/dev/null | grep -E 'audit record could not' | tail -n 1 | sed 's/.*ERROR //')"
    # Repair so the API sections can run: the worker account owns the audit log.
    serve_down
    rm -rf /var/lib/detent/audit
    install -d -o detent -g detent -m 700 /var/lib/detent/audit
    serve_up || rec host serve FAIL "serve did not come back"
  fi
}

# --- resolver --------------------------------------------------------------------

# monitor_error : the last error the monitor logged for a refused request.
monitor_error() {
  journalctl -u detent --no-pager 2>/dev/null | grep -E 'outcome="error"' | tail -n 1 |
    sed 's/.*error="\(.*\)"$/\1/' | cut -c1-200
}

# add_rw_path PATH : let the packaged unit write PATH (workaround for a unit
# whose ReadWritePaths lacks a path the module writes).
add_rw_path() {
  serve_down
  mkdir -p /etc/systemd/system/detent.service.d
  printf '[Service]\nReadWritePaths=%s\n' "$1" >/etc/systemd/system/detent.service.d/d3-rw.conf
  systemctl daemon-reload
}

# resolver_apply LABEL FILTER : apply as is; when the monitor then fails the
# write, say why and retry once with the path made writable.
resolver_apply() {
  local label="$1" filter="$2"
  apply_with_retry resolver "${filter}" 30 "" "${label}"
  if [[ "${APPLY_OK}" == true ]]; then
    return 0
  fi
  local err
  err="$(monitor_error)"
  rec resolver "${label}-monitor" INFO "monitor error: ${err}"
  if [[ "${err}" != *"read-only"* ]]; then
    return 0
  fi
  add_rw_path /etc/systemd/resolved.conf
  rec resolver "${label}-rw" INFO "workaround: ReadWritePaths=/etc/systemd/resolved.conf added in a unit drop-in"
  api_apply resolver "${filter}" 30 "" "${label}-rw"
  if [[ "${APPLY_OK}" == true ]]; then
    rec resolver "${label}-rw" PASS "http ${API_CODE}; commit ${COMMIT_ID:-none}"
  else
    rec resolver "${label}-rw" FAIL "http ${API_CODE} $(api_detail)"
  fi
}

section_resolver() {
  log "resolver"
  cli_get resolver || return 0
  rec resolver get PASS "model keys: $(jq -c '.model | keys' "${WORK}/resolver.get.json")"
  jq -c '.resolved |= (. + [{"dns_over_tls":{"mode":"opportunistic"}},{"dns_sec":{"mode":"allow_downgrade"}}])' \
    "${WORK}/resolver.model.json" >"${WORK}/resolver.edit.json"
  cli_validate resolver "${WORK}/resolver.edit.json" validate
  cli_plan resolver "${WORK}/resolver.edit.json" plan
  STDIN_FILE="${WORK}/resolver.edit.json"
  cap resolver-cli-apply "${DET}" config resolver apply --confirm 60s
  STDIN_FILE=""
  if [[ "${RC}" -ne 0 ]] && grep -q 'requires commit-confirm' "${CAPFILE}"; then
    rec resolver cli-apply-refused PASS "the CLI refuses a commit-confirm module and points to serve"
  else
    rec resolver cli-apply-refused FAIL "rc=${RC} $(first_line "${CAPFILE}" '.')"
  fi
  # API apply of the resolved settings, rolled back to prove the window.
  local before
  before="$(sha256sum /etc/systemd/resolved.conf | cut -d' ' -f1)"
  resolver_apply apply-resolved \
    '.resolved |= (. + [{"dns_over_tls":{"mode":"opportunistic"}},{"dns_sec":{"mode":"allow_downgrade"}}])'
  local where
  where="$(grep -rl 'DNSOverTLS=opportunistic' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d 2>/dev/null | head -n 1 || true)"
  if [[ -n "${where}" ]]; then
    rec resolver file PASS "DNSOverTLS=opportunistic is in ${where}"
  else
    rec resolver file FAIL "DNSOverTLS=opportunistic is in no resolved file"
  fi
  if [[ "${APPLY_OK}" == true ]]; then
    settle_commit rollback resolver
    if [[ "$(sha256sum /etc/systemd/resolved.conf | cut -d' ' -f1)" == "${before}" ]]; then
      rec resolver rollback PASS "resolved.conf is byte-identical after the rollback"
    else
      rec resolver rollback FAIL "resolved.conf differs after the rollback"
    fi
  fi
  unhide_all
  # Unbound: where does the entry go? One apply edits one file, so the
  # model holds only the unbound section; `get` shows only the detected
  # file, so the section starts empty here.
  NO_HASH=true
  resolver_apply apply-unbound \
    '.resolv = [] | .resolved = [] | .unbound |= (. + ["server",{"hardening":{"key":"qname-minimisation","enabled":true}}])'
  NO_HASH=false
  local u
  u="$(grep -rl 'qname-minimisation' /etc/unbound /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d 2>/dev/null | head -n 1 || true)"
  if [[ "${u}" == /etc/unbound/* ]]; then
    rec resolver file-unbound PASS "qname-minimisation is in ${u}"
  else
    rec resolver file-unbound FAIL "qname-minimisation landed in ${u:-no file}, not in an unbound file"
  fi
  if [[ "${APPLY_OK}" == true ]]; then
    settle_commit confirm resolver
  fi
  unhide_all
}

# --- mounts ----------------------------------------------------------------------

section_mounts() {
  log "mounts"
  mkdir -p /mnt/d3a
  cli_get mounts || return 0
  rec mounts get PASS "$(jq '.model.entries | length' "${WORK}/mounts.get.json") entries"
  local filter='.entries += [{"spec":"tmpfs","mountpoint":"/mnt/d3a","fstype":"tmpfs","options":["nosuid","nodev","noexec","nofail","size=1m"],"dump":0,"pass":0}]'
  jq -c "${filter}" "${WORK}/mounts.model.json" >"${WORK}/mounts.edit.json"
  cli_validate mounts "${WORK}/mounts.edit.json" validate
  cli_plan mounts "${WORK}/mounts.edit.json" plan
  local before
  before="$(sha256sum /etc/fstab | cut -d' ' -f1)"
  apply_with_retry mounts "${filter}" 30 "" apply
  if grep -q '^tmpfs /mnt/d3a ' /etc/fstab; then
    rec mounts file PASS "/etc/fstab has the tmpfs entry"
  else
    rec mounts file FAIL "/etc/fstab has no tmpfs entry"
  fi
  rec mounts upstream-check INFO "$(jq -c '[.checks[]? | {program, passed}]' "${LOGD}/mounts-apply.json" 2>/dev/null)"
  settle_commit rollback mounts
  if [[ "$(sha256sum /etc/fstab | cut -d' ' -f1)" == "${before}" ]]; then
    rec mounts rollback PASS "/etc/fstab is byte-identical after the rollback"
  else
    rec mounts rollback FAIL "/etc/fstab differs after the rollback"
  fi
  apply_with_retry mounts "${filter}" 30 "" apply-confirm
  settle_commit confirm mounts
  # The repository's own testhost acceptance script, in a container.
  if [[ -x "${STAGE}/scripts/mounts-activation-check.sh" ]]; then
    printf '[mounts]\nactivate_new_entries = true\n' >/etc/detent/detent.toml
    systemctl restart detent
    start_detent || true
    cap mounts-activation "${STAGE}/scripts/mounts-activation-check.sh" --detent "${DET}"
    local other
    other="$(grep -E 'FAIL|MISSING' "${CAPFILE}" | grep -v -E 'auto|at least one check failed' || true)"
    if [[ "${RC}" -eq 0 ]]; then
      rec mounts activation-script PASS "$(grep -c 'PASS' "${CAPFILE}") checks passed"
    elif [[ -z "${other}" ]]; then
      rec mounts activation-script PASS "$(grep -c 'PASS' "${CAPFILE}") checks passed; the only failures are the x-systemd.automount ones (next row)"
    else
      rec mounts activation-script FAIL "rc=${RC} $(printf '%s' "${other}" | head -n 1)"
    fi
    if grep -q 'automount unsupported' <(journalctl --no-pager 2>/dev/null); then
      rec mounts automount NT "not testable in a container: systemd logs: $(journalctl --no-pager 2>/dev/null | grep -m1 -o 'Starting of .*automount unsupported' | sed 's/\\/\\\\/g')"
    fi
    rm -f /etc/detent/detent.toml
    systemctl restart detent
    start_detent || true
    mint_token || true
  fi
}

# --- dhcp ------------------------------------------------------------------------

section_dhcp() {
  log "dhcp"
  systemctl stop unbound.service systemd-resolved.service 2>/dev/null || true
  cli_get dhcp || return 0
  rec dhcp get PASS "model keys: $(jq -c '.model | keys' "${WORK}/dhcp.get.json")"
  local dns_filter='.dnsmasq |= (map(select(.key != "dhcp-range" and .key != "interface")) + [{"key":"interface","value":"mgmt0"},{"key":"dhcp-range","value":"192.0.2.50,192.0.2.150,12h"}])'
  jq -c "${dns_filter}" "${WORK}/dhcp.model.json" >"${WORK}/dhcp.edit.json"
  cli_validate dhcp "${WORK}/dhcp.edit.json" validate-dnsmasq
  cli_plan dhcp "${WORK}/dhcp.edit.json" plan-dnsmasq
  apply_with_retry dhcp "${dns_filter}" 30 restart apply-dnsmasq
  if grep -Eq '^dhcp-range=192\.0\.2\.50,192\.0\.2\.150,12h' /etc/dnsmasq.conf; then
    rec dhcp file-dnsmasq PASS "/etc/dnsmasq.conf has the dhcp-range"
  else
    rec dhcp file-dnsmasq FAIL "no dhcp-range in /etc/dnsmasq.conf"
  fi
  if dnsmasq --test -C /etc/dnsmasq.conf >/dev/null 2>&1; then
    rec dhcp upstream-check-dnsmasq PASS "dnsmasq --test accepts the written file"
  else
    rec dhcp upstream-check-dnsmasq FAIL "dnsmasq --test rejects the written file"
  fi
  sleep 2
  if systemctl is-active --quiet dnsmasq.service; then
    rec dhcp service-dnsmasq PASS "dnsmasq.service is active"
  else
    rec dhcp service-dnsmasq FAIL "dnsmasq.service: $(systemctl status dnsmasq --no-pager 2>&1 | grep -E 'Active:' | head -n 1)"
  fi
  settle_commit confirm dhcp
  unhide_all
  # Kea: a model with only the kea_v4 section edits the Kea file, with
  # dnsmasq still installed (BUGFIX Track D 7).
  local kea_filter='.dnsmasq = [] | .kea_v4 = {"interfaces":["mgmt0"],"subnets":[{"id":1,"subnet":"192.0.2.0/24","pools":[{"pool":"192.0.2.50 - 192.0.2.150"}],"routers":["192.0.2.1"],"domain-name-servers":["192.0.2.1"]}],"valid-lifetime":3600}'
  jq -c "${kea_filter}" "${WORK}/dhcp.model.json" >"${WORK}/dhcp.kea.json"
  cli_validate dhcp "${WORK}/dhcp.kea.json" validate-kea
  cli_plan dhcp "${WORK}/dhcp.kea.json" plan-kea
  NO_HASH=true
  apply_with_retry dhcp "${kea_filter}" 30 restart apply-kea
  NO_HASH=false
  local kconf=/etc/kea/kea-dhcp4.conf kunit
  kunit="$(first_unit kea-dhcp4-server.service kea-dhcp4.service || true)"
  if [[ "${APPLY_OK}" == true ]]; then
    if grep -Eq '^[[:space:]]*"subnet"[[:space:]]*:[[:space:]]*"192\.0\.2\.0/24"' "${kconf}"; then
      rec dhcp file-kea PASS "${kconf} has the subnet"
    else
      rec dhcp file-kea FAIL "${kconf} has no subnet"
    fi
    sleep 2
    if [[ -n "${kunit}" ]] && systemctl is-active --quiet "${kunit}"; then
      rec dhcp service-kea PASS "${kunit} is active"
    else
      rec dhcp service-kea FAIL "${kunit:-kea}: $(systemctl status "${kunit:-kea-dhcp4-server}" --no-pager 2>&1 | grep -E 'Active:' | head -n 1)"
    fi
    settle_commit confirm dhcp
  else
    rec dhcp file-kea FAIL "not written: the apply failed above"
  fi
  # The upstream tool itself, on the stock file, as root and as the Kea account.
  local kbin kuser
  kbin="$(command -v kea-dhcp4 || true)"
  kuser="$(getent passwd _kea kea | head -n 1 | cut -d: -f1 || true)"
  if [[ -n "${kbin}" ]]; then
    if "${kbin}" -t "${kconf}" >/dev/null 2>&1; then
      rec dhcp kea-t-root PASS "kea-dhcp4 -t opens ${kconf} as root"
    else
      rec dhcp kea-t-root FAIL "kea-dhcp4 -t as root: $("${kbin}" -t "${kconf}" 2>&1 | head -n 1)"
    fi
    if [[ -n "${kuser}" ]] && runuser -u "${kuser}" -- "${kbin}" -t "${kconf}" >/dev/null 2>&1; then
      rec dhcp kea-t-keauser PASS "kea-dhcp4 -t opens ${kconf} as ${kuser}"
    else
      rec dhcp kea-t-keauser FAIL "kea-dhcp4 -t as ${kuser:-the Kea account} failed"
    fi
  fi
  unhide_all
  systemctl stop dnsmasq.service "${kunit:-kea-dhcp4-server.service}" 2>/dev/null || true
}

# --- network ---------------------------------------------------------------------

NET_DIRS=(/etc/network /etc/netplan /etc/NetworkManager/system-connections /etc/systemd/network)

peer_ping() {
  ip netns exec d3peer ping -c1 -W1 192.0.2.1 >/dev/null 2>&1
}

mgmt_addr() {
  ip -4 -br addr show dev mgmt0 | tr -s ' '
}

net_files() {
  find "${NET_DIRS[@]}" -type f -newer "${WORK}/net.stamp" 2>/dev/null | sort | tr '\n' ' ' || true
}

# net_snapshot / net_reset : put the network configuration directories back
# to what the image shipped, so one flow does not leak into the next.
NET_PRESENT=()
net_snapshot() {
  local dir
  NET_PRESENT=()
  for dir in "${NET_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
      NET_PRESENT+=("${dir#/}")
    fi
  done
  tar -cf "${WORK}/net.orig.tar" -C / ${NET_PRESENT[@]+"${NET_PRESENT[@]}"}
}

net_reset() {
  local dir
  serve_down
  for dir in "${NET_DIRS[@]}"; do
    rm -rf "${dir}"
  done
  tar -xf "${WORK}/net.orig.tar" -C /
  rm -f /etc/NetworkManager/conf.d/10-d3.conf
}

# net_prepare FLAVOUR : the distro's own network stack, with mgmt0 flushed.
net_prepare() {
  local flavour="$1"
  # Only one stack may own mgmt0: NetworkManager strips foreign addresses.
  if [[ "${flavour}" != nm && "${flavour}" != netplan-nm ]]; then
    systemctl stop NetworkManager.service 2>/dev/null || true
  fi
  ip addr flush dev mgmt0
  rm -f /run/network/ifstate.mgmt0
  ip link set mgmt0 up
  case "${flavour}" in
    ifupdown)
      mkdir -p /etc/network/interfaces.d
      if [[ ! -f /etc/network/interfaces ]]; then
        printf 'source /etc/network/interfaces.d/*\n' >/etc/network/interfaces
      fi
      ;;
    nm)
      mkdir -p /etc/NetworkManager/conf.d /etc/NetworkManager/system-connections
      printf '[device-d3]\nmatch-device=interface-name:mgmt0\nmanaged=1\n' >/etc/NetworkManager/conf.d/10-d3.conf
      # The file detent edits: the administrator creates it (apply never
      # creates a target), here as a profile with no address.
      printf '[connection]\nid=mgmt0\ntype=ethernet\ninterface-name=mgmt0\n\n[ipv4]\nmethod=disabled\n\n[ipv6]\nmethod=disabled\n' \
        >/etc/NetworkManager/system-connections/detent.nmconnection
      chmod 600 /etc/NetworkManager/system-connections/detent.nmconnection
      systemctl restart NetworkManager 2>&1 || true
      sleep 3
      ;;
    networkd)
      mkdir -p /etc/systemd/network
      printf '[Match]\nName=mgmt0\n' >/etc/systemd/network/10-detent.network
      systemctl start systemd-networkd 2>&1 || true
      ;;
    netplan)
      mkdir -p /etc/netplan
      # No `ethernets: {}`: with that empty map in another file the netplan
      # generator (daemon-reload) writes nothing (netplan 1.x, Ubuntu 26.04).
      printf 'network:\n  version: 2\n  renderer: networkd\n' >/etc/netplan/10-d3.yaml
      printf 'network:\n  version: 2\n' >/etc/netplan/90-detent.yaml
      chmod 600 /etc/netplan/10-d3.yaml /etc/netplan/90-detent.yaml
      systemctl start systemd-networkd 2>&1 || true
      ;;
    netplan-nm)
      mkdir -p /etc/netplan /etc/NetworkManager/conf.d
      printf '[device-d3]\nmatch-device=interface-name:mgmt0\nmanaged=1\n' >/etc/NetworkManager/conf.d/10-d3.conf
      printf 'network:\n  version: 2\n  renderer: NetworkManager\n' >/etc/netplan/10-d3.yaml
      printf 'network:\n  version: 2\n  renderer: NetworkManager\n' >/etc/netplan/90-detent.yaml
      chmod 600 /etc/netplan/10-d3.yaml /etc/netplan/90-detent.yaml
      systemctl stop systemd-networkd 2>/dev/null || true
      systemctl restart NetworkManager 2>&1 || true
      sleep 3
      ;;
  esac
  rec "network-${flavour}" seed INFO "the detent file of the backend, created by hand: $(find "${NET_DIRS[@]}" -name '*detent*' -type f 2>/dev/null | tr '\n' ' ')"
}

# backend_apply DIR : what an administrator runs to make the backend read the
# file detent wrote into DIR. Used to put a change live when detent's own
# service action does not.
backend_apply() {
  local out="${LOGD}/backend-apply.txt"
  : >"${out}"
  case "$1" in
    /etc/network/*)
      {
        ifdown --force mgmt0
        ifup mgmt0
      } >>"${out}" 2>&1 || true
      ;;
    /etc/netplan/*)
      netplan apply >>"${out}" 2>&1 || true
      ;;
    /etc/NetworkManager/*)
      {
        nmcli connection reload
        nmcli connection up ifname mgmt0
      } >>"${out}" 2>&1 || true
      ;;
    /etc/systemd/network*)
      {
        systemctl start systemd-networkd
        networkctl reload
        networkctl reconfigure mgmt0
      } >>"${out}" 2>&1 || true
      ;;
  esac
  sleep 3
}

backend_say() {
  tr '\n' ' ' <"${LOGD}/backend-apply.txt" | cut -c1-160
}

# network_flow TAG : get, validate, plan, a good apply, a confirm, then a
# deliberate misconfiguration with a 60 s window that nobody confirms.
network_flow() {
  local tag="$1"
  ip addr flush dev mgmt0
  touch "${WORK}/net.stamp"
  sleep 1
  cap "${tag}-host" "${DET}" host
  rec "${tag}" host INFO "$(grep -E 'network backend|NetworkManager|networkd|netplan|ifupdown' "${CAPFILE}" | tr -s ' ' | tr '\n' ';' | cut -c1-200)"
  cli_get network || return 0
  rec "${tag}" get PASS "$(jq '.model.interfaces | length' "${WORK}/network.get.json") interfaces"
  # Replace mgmt0 only; keep the other interfaces (lo) the file has.
  local good='.interfaces = ([.interfaces[] | select(.name != "mgmt0")] + [{"name":"mgmt0","addresses":["192.0.2.1/24"],"dhcp_v4":false,"dhcp_v6":false,"dns":[],"gateway_v4":null,"gateway_v6":null,"routes":[],"vlan":null,"bridge":null}] | sort_by(.name))'
  local bad='.interfaces = ([.interfaces[] | select(.name != "mgmt0")] + [{"name":"mgmt0","addresses":["198.51.100.1/24"],"dhcp_v4":false,"dhcp_v6":false,"dns":[],"gateway_v4":null,"gateway_v6":null,"routes":[],"vlan":null,"bridge":null}] | sort_by(.name))'
  jq -c "${good}" "${WORK}/network.model.json" >"${WORK}/network.good.json"
  STDIN_FILE="${WORK}/network.good.json"
  cap "${tag}-validate" "${DET}" config network validate
  if [[ "${RC}" -eq 0 ]] && ! grep -q '^error:' "${CAPFILE}"; then
    rec "${tag}" validate PASS "$(first_line "${CAPFILE}" '^(warning|note):')"
  else
    rec "${tag}" validate FAIL "rc=${RC} $(first_line "${CAPFILE}" '^error:')"
  fi
  cap "${tag}-plan" "${DET}" config network plan
  STDIN_FILE=""
  if [[ "${RC}" -eq 0 ]] && grep -q '^+++ ' "${CAPFILE}"; then
    rec "${tag}" plan PASS "target $(sed -n 's/^+++ //p' "${CAPFILE}" | head -n 1); $(first_line "${CAPFILE}" 'would affect')"
  else
    rec "${tag}" plan FAIL "rc=${RC} $(first_line "${CAPFILE}" 'cannot|not exist|error|failed')"
    return 0
  fi
  rec "${tag}" plan-validators INFO "not passing: $(validator_failures "${CAPFILE}" | tr '\n' ' ')"
  # The service of the written file, and its first declared action.
  local action
  first_action network "${good}"
  action="${FIRST_ACTION:-reload}"
  rec "${tag}" service INFO "plan names ${FIRST_UNIT:-no unit}; the apply asks for its first action: ${action}"
  # Baseline.
  apply_with_retry network "${good}" 40 "${action}" apply-baseline
  if [[ "${APPLY_OK}" != true ]]; then
    return 0
  fi
  local files loc base_live=false
  files="$(net_files)"
  rec "${tag}" files-written INFO "${files}"
  if [[ "${tag}" == *netplan* ]]; then
    rec "${tag}" generated INFO "$(find /run/systemd/network /run/NetworkManager/system-connections -name '*netplan*' 2>/dev/null | tr '\n' ' ')"
    rec "${tag}" link-state INFO "$(networkctl list --no-legend 2>&1 | grep mgmt0 | tr -s ' ')"
    rec "${tag}" detent-log INFO "$(journalctl -u detent --no-pager 2>/dev/null | grep -i -E 'reload|service' | tail -n 3 | tr '\n' ' ' | cut -c1-300)"
  fi
  loc="$(dirname "${files%% *}")/"
  sleep 3
  if peer_ping; then
    base_live=true
    rec "${tag}" live-after-detent PASS "detent's service action put 192.0.2.1/24 on mgmt0: $(mgmt_addr)"
  else
    base_live=false
    rec "${tag}" live-after-detent FAIL "mgmt0 is not configured after the apply and its service action: $(mgmt_addr)"
    backend_apply "${loc}"
    if peer_ping; then
      base_live=true
      rec "${tag}" live-after-manual INFO "after the administrator's own reload for ${loc} mgmt0 is up: $(mgmt_addr)"
    else
      rec "${tag}" live-after-manual FAIL "even after the reload for ${loc} mgmt0 is not up: $(mgmt_addr) [$(backend_say)]"
    fi
  fi
  settle_commit confirm network
  api GET /api/v1/modules/network
  local good_hash
  good_hash="$(jq -r '.current_hash' "${API_FILE}")"
  # The deliberate misconfiguration: a wrong subnet cuts the veth path.
  local t0 t_back="" t_ok="" now
  api_apply network "${bad}" 60 "${action}" apply-misconfig
  if [[ "${APPLY_OK}" == true ]]; then
    rec "${tag}" apply-misconfig PASS "bad address 198.51.100.1/24; commit ${COMMIT_ID}, 60 s window"
  else
    rec "${tag}" apply-misconfig FAIL "http ${API_CODE} $(api_detail)"
    return 0
  fi
  t0="$(date +%s)"
  sleep 3
  if peer_ping; then
    rec "${tag}" misconfig-live INFO "detent's service action left the old address live: $(mgmt_addr)"
    backend_apply "${loc}"
  else
    rec "${tag}" misconfig-live INFO "detent's service action put the bad config live: $(mgmt_addr)"
  fi
  if peer_ping; then
    rec "${tag}" misconfig-effect FAIL "peer0 still reaches 192.0.2.1 under the bad config: $(mgmt_addr)"
  elif [[ "${base_live}" == true ]]; then
    rec "${tag}" misconfig-effect PASS "peer0 cannot reach 192.0.2.1 under the bad config: $(mgmt_addr)"
  else
    rec "${tag}" misconfig-effect INFO "no effect to see: the baseline never went live, so the path was down before"
  fi
  # Wait for the monitor's deadline rollback: nobody confirms.
  for _ in $(seq 1 "${CONFIRM_WAIT}"); do
    api GET /api/v1/modules/network
    if [[ "$(jq -r '.current_hash' "${API_FILE}")" == "${good_hash}" ]]; then
      now="$(date +%s)"
      t_back=$((now - t0))
      break
    fi
    sleep 2
  done
  if [[ -n "${t_back}" ]]; then
    rec "${tag}" rollback-file PASS "the file hash returned to the baseline ${t_back} s after the apply (window 60 s)"
  else
    rec "${tag}" rollback-file FAIL "the file hash did not return to the baseline within $((CONFIRM_WAIT * 2)) s"
  fi
  for _ in $(seq 1 8); do
    if peer_ping; then
      t_ok=yes
      break
    fi
    sleep 2
  done
  if [[ -n "${t_ok}" ]]; then
    rec "${tag}" rollback-live PASS "peer0 pings 192.0.2.1 again after the rollback, no manual step: $(mgmt_addr)"
  else
    rec "${tag}" rollback-live FAIL "the file is back but the live config is not: $(mgmt_addr)"
    backend_apply "${loc}"
    if peer_ping; then
      rec "${tag}" rollback-live-manual INFO "the restored file is right: after a reload for ${loc} peer0 pings 192.0.2.1 again"
    else
      rec "${tag}" rollback-live-manual FAIL "even after a reload for ${loc} the path is down: $(mgmt_addr) [$(backend_say)]"
    fi
  fi
  api POST "/api/v1/commits/${COMMIT_ID}/confirm"
  rec "${tag}" confirm-after-rollback INFO "a late confirm answers http ${API_CODE}"
}

section_network() {
  local flavour
  IFS=',' read -r -a flavours <<<"${NETS}"
  net_snapshot
  for flavour in "${flavours[@]}"; do
    log "network (${flavour}, all services installed)"
    net_reset
    net_prepare "${flavour}"
    network_flow "network-${flavour}"
    unhide_all
  done
  # The module chooses its target from the probed services; hide the probed
  # ones that are not network services and see which target it then picks.
  log "network (probes hidden)"
  if unit_exists systemd-networkd.service; then
    net_reset
    net_prepare networkd
    local probe
    for probe in chronyd smbd unbound dnsmasq kea-dhcp4 resolvectl; do
      hide "/usr/sbin/${probe}"
      hide "/usr/bin/${probe}"
    done
    network_flow "network-probes-hidden"
    unhide_all
  else
    rec network-probes-hidden flow NT "this image has no systemd-networkd"
  fi
  # The CLI refuses a commit-confirm module (Phase 8: --confirm 60s).
  STDIN_FILE="${WORK}/network.good.json"
  cap network-cli-apply "${DET}" config network apply --confirm 60s
  STDIN_FILE=""
  if [[ "${RC}" -ne 0 ]] && grep -q 'requires commit-confirm' "${CAPFILE}"; then
    rec network cli-apply-refused PASS "the CLI refuses a commit-confirm module and points to serve"
  else
    rec network cli-apply-refused FAIL "rc=${RC} $(first_line "${CAPFILE}" '.')"
  fi
}

# --- main ------------------------------------------------------------------------

log "distro ${DISTRO}; result file ${OUT}"
if wanted prep; then section_prep; fi
# run_section NAME : a section that dies on an unexpected error is recorded
# and does not stop the next one.
run_section() {
  local name="$1"
  if ! "section_${name}"; then
    rec "${name}" section FAIL "the section stopped on an unexpected error"
  fi
}

# CLI sections first (see the header), then the API sections.
if wanted chrony; then run_section chrony; fi
if wanted samba; then run_section samba; fi
if wanted nfs; then run_section nfs; fi
if wanted resolver || wanted mounts || wanted dhcp || wanted network; then
  run_section order
fi
if wanted resolver; then run_section resolver; fi
if wanted mounts; then run_section mounts; fi
if wanted dhcp; then run_section dhcp; fi
if wanted network; then run_section network; fi
log "done: $(grep -c PASS "${OUT}") PASS, $(grep -c $'\tFAIL\t' "${OUT}") FAIL, $(grep -c $'\tNT\t' "${OUT}") NT"
