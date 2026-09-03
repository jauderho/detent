#!/usr/bin/env bash
#
# size-check.sh - Compare a built binary's size against size-baseline.json.
#
# Usage:
#   scripts/size-check.sh [OPTIONS] <path-to-binary>
#
# Options:
#   --baseline <path>   Path to the baseline JSON file (default: size-baseline.json
#                        in the repository root).
#   --key <name>        Key in the baseline JSON to compare against
#                        (default: detent-default).
#   --dryrun             Accepted for interface consistency with other repo
#                        scripts. This script performs no writes, so the flag
#                        is a no-op.
#   --verbose, -v        Print step-level progress and key variable state.
#   -h, --help            Show this help message.
#
# Baseline format (size-baseline.json):
#   {"detent-default": {"bytes": 12345678, "tolerance_pct": 3}}
#
# Behavior:
#   - Reads the measured size (in bytes) of the given binary.
#   - Compares it against baseline.<key>.bytes, allowing up to
#     baseline.<key>.tolerance_pct percent growth.
#   - If baseline.<key>.bytes is 0, the script is in bootstrap mode: it
#     prints the measured size and exits 0 without comparison.
#   - Exits non-zero if the measured size exceeds the tolerance.
#
# Requires: jq.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BASELINE_PATH="${REPO_ROOT}/size-baseline.json"
BASELINE_KEY="detent-default"
DRYRUN=false
VERBOSE=false
BINARY_PATH=""

if [[ -n "${NO_COLOR:-}" ]]; then
  RED=""
  GREEN=""
  YELLOW=""
  BLUE=""
  NC=""
else
  RED=$'\033[0;31m'
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[1;33m'
  BLUE=$'\033[0;34m'
  NC=$'\033[0m'
fi

log() {
  echo "${BLUE}[size-check]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[size-check][verbose]${NC} $*"
  fi
}

show_usage() {
  sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# Portable file size in bytes (Linux stat -c, macOS/BSD stat -f).
file_size_bytes() {
  local path="$1"
  if stat -c '%s' "${path}" >/dev/null 2>&1; then
    stat -c '%s' "${path}"
  else
    stat -f '%z' "${path}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)
      BASELINE_PATH="$2"
      shift 2
      ;;
    --key)
      BASELINE_KEY="$2"
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
    -*)
      echo "${RED}Unknown option: $1${NC}" >&2
      show_usage
      exit 1
      ;;
    *)
      BINARY_PATH="$1"
      shift
      ;;
  esac
done

if [[ -z "${BINARY_PATH}" ]]; then
  echo "${RED}Error: missing <path-to-binary> argument${NC}" >&2
  show_usage
  exit 1
fi

if [[ "${DRYRUN}" == true ]]; then
  log_verbose "dryrun requested; this script has no side effects, continuing normally"
fi

if [[ ! -f "${BINARY_PATH}" ]]; then
  echo "${RED}Error: binary not found: ${BINARY_PATH}${NC}" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "${RED}Error: jq is required${NC}" >&2
  exit 1
fi

if [[ ! -f "${BASELINE_PATH}" ]]; then
  echo "${RED}Error: baseline file not found: ${BASELINE_PATH}${NC}" >&2
  exit 1
fi

log_verbose "binary: ${BINARY_PATH}"
log_verbose "baseline file: ${BASELINE_PATH}"
log_verbose "baseline key: ${BASELINE_KEY}"

measured_bytes="$(file_size_bytes "${BINARY_PATH}")"
log_verbose "measured size: ${measured_bytes} bytes"

baseline_bytes="$(jq -r --arg key "${BASELINE_KEY}" '.[$key].bytes // empty' "${BASELINE_PATH}")"
tolerance_pct="$(jq -r --arg key "${BASELINE_KEY}" '.[$key].tolerance_pct // empty' "${BASELINE_PATH}")"

if [[ -z "${baseline_bytes}" || -z "${tolerance_pct}" ]]; then
  echo "${RED}Error: baseline key '${BASELINE_KEY}' missing 'bytes' or 'tolerance_pct' in ${BASELINE_PATH}${NC}" >&2
  exit 1
fi

if [[ "${baseline_bytes}" -eq 0 ]]; then
  log "${YELLOW}bootstrap mode (baseline bytes = 0): measured ${measured_bytes} bytes for '${BASELINE_KEY}'; pass${NC}"
  exit 0
fi

# max_allowed = baseline_bytes * (1 + tolerance_pct / 100), integer arithmetic.
max_allowed=$(((baseline_bytes * (100 + tolerance_pct)) / 100))
log_verbose "baseline: ${baseline_bytes} bytes, tolerance: ${tolerance_pct}%, max allowed: ${max_allowed} bytes"

if ((measured_bytes > max_allowed)); then
  echo "${RED}FAIL${NC}: '${BASELINE_KEY}' size ${measured_bytes} bytes exceeds max allowed ${max_allowed} bytes (baseline ${baseline_bytes} + ${tolerance_pct}%)" >&2
  exit 1
fi

log "${GREEN}PASS${NC}: '${BASELINE_KEY}' size ${measured_bytes} bytes within ${tolerance_pct}% of baseline ${baseline_bytes} bytes"
