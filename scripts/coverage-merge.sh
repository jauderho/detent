#!/usr/bin/env bash
#
# coverage-merge.sh - Merge one or more lcov files and enforce the
# coverage thresholds recorded in coverage-baseline.json.
#
# Usage:
#   scripts/coverage-merge.sh [OPTIONS] <lcov-file> [<lcov-file> ...]
#
# Options:
#   --baseline <path>   Path to the baseline JSON file (default:
#                        coverage-baseline.json in the repository root).
#   --output <path>     Path to write the merged lcov file (default:
#                        merged.info in the current directory).
#   --dryrun             Merge and report, but skip the threshold check
#                        (still writes the merged file; no other side effects).
#   --verbose, -v        Print step-level progress and key variable state.
#   -h, --help            Show this help message.
#
# Baseline format (coverage-baseline.json):
#   {"lines_min_pct": 0, "ratchet_note": "..."}
#
# Behavior:
#   - Merges all given lcov files with `lcov -a <file> ... -o <output>`.
#   - Computes line coverage percent from `lcov --summary <output>`.
#   - Fails if line coverage is below baseline.lines_min_pct.
#   - Prints a one-line summary.
#
# Requires: lcov, jq.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BASELINE_PATH="${REPO_ROOT}/coverage-baseline.json"
OUTPUT_PATH="merged.info"
DRYRUN=false
VERBOSE=false
LCOV_FILES=()

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
  echo "${BLUE}[coverage-merge]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[coverage-merge][verbose]${NC} $*"
  fi
}

show_usage() {
  sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)
      BASELINE_PATH="$2"
      shift 2
      ;;
    --output)
      OUTPUT_PATH="$2"
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
      LCOV_FILES+=("$1")
      shift
      ;;
  esac
done

if [[ "${#LCOV_FILES[@]}" -eq 0 ]]; then
  echo "${RED}Error: at least one <lcov-file> is required${NC}" >&2
  show_usage
  exit 1
fi

for f in "${LCOV_FILES[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "${RED}Error: lcov file not found: ${f}${NC}" >&2
    exit 1
  fi
done

if ! command -v lcov >/dev/null 2>&1; then
  echo "${RED}Error: lcov is required${NC}" >&2
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

log_verbose "lcov files: ${LCOV_FILES[*]}"
log_verbose "baseline file: ${BASELINE_PATH}"
log_verbose "output file: ${OUTPUT_PATH}"

lcov_add_args=()
for f in "${LCOV_FILES[@]}"; do
  lcov_add_args+=(-a "${f}")
done

log_verbose "running: lcov ${lcov_add_args[*]} -o ${OUTPUT_PATH}"
lcov "${lcov_add_args[@]}" -o "${OUTPUT_PATH}" >/dev/null

summary="$(lcov --summary "${OUTPUT_PATH}" 2>&1)"
log_verbose "lcov summary output:"
log_verbose "${summary}"

# Extract the "lines......: NN.N%" figure from the summary.
lines_pct="$(echo "${summary}" | grep -Eo 'lines\.+:[[:space:]]+[0-9]+\.[0-9]+%' | grep -Eo '[0-9]+\.[0-9]+' || true)"

if [[ -z "${lines_pct}" ]]; then
  echo "${RED}Error: could not parse line coverage percentage from lcov summary${NC}" >&2
  echo "${summary}" >&2
  exit 1
fi

lines_min_pct="$(jq -r '.lines_min_pct // empty' "${BASELINE_PATH}")"
if [[ -z "${lines_min_pct}" ]]; then
  echo "${RED}Error: baseline missing 'lines_min_pct' in ${BASELINE_PATH}${NC}" >&2
  exit 1
fi

log "merged $(printf '%d' "${#LCOV_FILES[@]}") lcov file(s) -> ${OUTPUT_PATH}: lines ${lines_pct}% (min ${lines_min_pct}%)"

if [[ "${DRYRUN}" == true ]]; then
  log "${YELLOW}dryrun requested; skipping threshold enforcement${NC}"
  exit 0
fi

# Integer comparison via awk to support fractional percentages.
below_threshold="$(awk -v have="${lines_pct}" -v want="${lines_min_pct}" 'BEGIN { print (have < want) ? "1" : "0" }')"

if [[ "${below_threshold}" == "1" ]]; then
  echo "${RED}FAIL${NC}: line coverage ${lines_pct}% is below minimum ${lines_min_pct}%" >&2
  exit 1
fi

log "${GREEN}PASS${NC}: line coverage ${lines_pct}% meets minimum ${lines_min_pct}%"
