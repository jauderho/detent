#!/usr/bin/env bash
#
# coverage-merge.sh - Merge one or more lcov files and enforce the
# coverage thresholds recorded in coverage-baseline.json.
#
# Usage:
#   scripts/coverage-merge.sh [OPTIONS] <lcov-file> [<lcov-file> ...]
#   scripts/coverage-merge.sh --selftest
#
# Options:
#   --baseline <path>   Path to the baseline JSON file (default:
#                        coverage-baseline.json in the repository root).
#   --output <path>     Path to write the merged lcov file (default:
#                        merged.info in the current directory).
#   --dryrun             Merge and report, but skip the threshold check
#                        (still writes the merged file; no other side effects).
#   --verbose, -v        Print step-level progress and key variable state.
#   --selftest            Run the built-in pass/fail self-test against two
#                          synthetic lcov files in a temp dir and exit. Does
#                          not require lcov (only jq and awk). Ignores all
#                          other options.
#   -h, --help            Show this help message.
#
# Baseline format (coverage-baseline.json):
#   {
#     "lines_min_pct": 0,
#     "per_path": {"crates/detent-core/": 100, "crates/modules/": 100},
#     "ratchet_note": "..."
#   }
#   `per_path` is optional; each key is matched as a substring against the
#   `SF:` path of every lcov record (lcov paths from cargo-llvm-cov may be
#   absolute or repo-relative, so substring match handles both).
#
# Behavior:
#   - With 2+ lcov files: merges them with `lcov -a <file> ... -o <output>`
#     (requires lcov). With exactly 1 file: uses it directly as the merged
#     file (no lcov dependency, so --selftest does not need lcov installed).
#   - Computes line coverage (global, and per `per_path` entry) directly from
#     the merged file's DA (per-line hit count) records with awk.
#   - Fails if global coverage is below baseline.lines_min_pct, or if any
#     per_path coverage is below its configured minimum.
#   - Prints one summary line per per_path entry, plus the global summary line.
#
# Requires: jq, awk. lcov only when merging 2+ input files.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BASELINE_PATH="${REPO_ROOT}/coverage-baseline.json"
OUTPUT_PATH="merged.info"
DRYRUN=false
VERBOSE=false
SELFTEST=false
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
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# Emit "<lf>\t<lh>" for one lcov file, restricted to records whose SF: path
# contains the given substring (empty substring matches every record).
# Uses awk only, so it never depends on lcov being installed.
lcov_totals() {
  local file="$1"
  local needle="${2:-}"
  awk -v needle="${needle}" '
    /^SF:/ { path = path_of($0) }
    # Derive found/hit from DA records, as lcov itself does. cargo-llvm-cov
    # emits LF/LH per function instantiation, so a crate compiled once for its
    # unit tests and once for an integration test double-counts lines in LF/LH
    # while the per-line DA records are already merged.
    /^DA:/ {
      rec = $0; sub(/^DA:/, "", rec); split(rec, parts, ",")
      lf += 1
      if (parts[2] + 0 > 0) { lh += 1 }
    }
    /^end_of_record/ {
      if (needle == "" || index(path, needle) > 0) {
        total_lf += lf
        total_lh += lh
      }
      path = ""; lf = 0; lh = 0
    }
    function path_of(line) {
      s = line
      sub(/^SF:/, "", s)
      return s
    }
    END { printf "%d\t%d\n", total_lf, total_lh }
  ' "${file}"
}

pct_of() {
  local lf="$1"
  local lh="$2"
  awk -v lf="${lf}" -v lh="${lh}" 'BEGIN { if (lf > 0) { printf "%.2f", (lh / lf) * 100 } else { printf "0.00" } }'
}

below() {
  local have="$1"
  local want="$2"
  awk -v have="${have}" -v want="${want}" 'BEGIN { print (have + 0 < want + 0) ? "1" : "0" }'
}

# Evaluate the merged lcov file at $1 against the baseline JSON at $2.
# Prints one summary line per per_path entry, then the global summary line.
# Returns 1 (via `fail=1`) if any threshold is missed; does not exit itself
# so callers can honor --dryrun.
evaluate_coverage() {
  local merged="$1"
  local baseline="$2"
  local dryrun="$3"
  local fail=0

  local per_path_keys
  per_path_keys="$(jq -r '.per_path // {} | keys[]' "${baseline}")"

  if [[ -n "${per_path_keys}" ]]; then
    while IFS= read -r key; do
      [[ -z "${key}" ]] && continue
      local min_pct
      min_pct="$(jq -r --arg k "${key}" '.per_path[$k]' "${baseline}")"
      local totals lf lh pct
      totals="$(lcov_totals "${merged}" "${key}")"
      lf="$(cut -f1 <<<"${totals}")"
      lh="$(cut -f2 <<<"${totals}")"
      pct="$(pct_of "${lf}" "${lh}")"
      log "per-path ${key}: lines ${pct}% (min ${min_pct}%, ${lh}/${lf} lines)"
      if [[ "${dryrun}" != true ]]; then
        if [[ "$(below "${pct}" "${min_pct}")" == "1" ]]; then
          echo "${RED}FAIL${NC}: ${key} line coverage ${pct}% is below minimum ${min_pct}%" >&2
          fail=1
        fi
      fi
    done <<<"${per_path_keys}"
  fi

  local global_totals lf lh pct lines_min_pct
  global_totals="$(lcov_totals "${merged}" "")"
  lf="$(cut -f1 <<<"${global_totals}")"
  lh="$(cut -f2 <<<"${global_totals}")"
  pct="$(pct_of "${lf}" "${lh}")"
  lines_min_pct="$(jq -r '.lines_min_pct // empty' "${baseline}")"
  if [[ -z "${lines_min_pct}" ]]; then
    echo "${RED}Error: baseline missing 'lines_min_pct' in ${baseline}${NC}" >&2
    return 1
  fi
  log "global: lines ${pct}% (min ${lines_min_pct}%, ${lh}/${lf} lines)"
  if [[ "${dryrun}" != true ]]; then
    if [[ "$(below "${pct}" "${lines_min_pct}")" == "1" ]]; then
      echo "${RED}FAIL${NC}: global line coverage ${pct}% is below minimum ${lines_min_pct}%" >&2
      fail=1
    fi
  fi

  return "${fail}"
}

run_selftest() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN

  # Case 1: everything at 100% -> expect PASS (exit 0).
  cat >"${tmp}/pass.info" <<'EOF'
TN:
SF:/repo/crates/detent-core/src/lib.rs
DA:1,1
DA:2,1
LF:2
LH:2
end_of_record
SF:/repo/crates/modules/hosts/src/lib.rs
DA:1,1
LF:1
LH:1
end_of_record
EOF

  local baseline="${tmp}/baseline.json"
  cat >"${baseline}" <<'EOF'
{"lines_min_pct": 100, "per_path": {"crates/detent-core/": 100, "crates/modules/": 100}, "ratchet_note": "selftest"}
EOF

  log "selftest: case 1 (expect PASS)"
  if ! "${BASH_SOURCE[0]}" --baseline "${baseline}" --output "${tmp}/merged-pass.info" "${tmp}/pass.info"; then
    echo "${RED}selftest FAILED${NC}: case 1 (all lines covered) should have passed" >&2
    return 1
  fi

  # Case 2: detent-core has an uncovered line -> expect FAIL (nonzero exit).
  cat >"${tmp}/fail.info" <<'EOF'
TN:
SF:/repo/crates/detent-core/src/lib.rs
DA:1,1
DA:2,0
LF:2
LH:1
end_of_record
SF:/repo/crates/modules/hosts/src/lib.rs
DA:1,1
LF:1
LH:1
end_of_record
EOF

  log "selftest: case 2 (expect FAIL)"
  if "${BASH_SOURCE[0]}" --baseline "${baseline}" --output "${tmp}/merged-fail.info" "${tmp}/fail.info"; then
    echo "${RED}selftest FAILED${NC}: case 2 (uncovered line in detent-core) should have failed" >&2
    return 1
  fi

  log "${GREEN}selftest PASS${NC}: both cases behaved as expected"
  return 0
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
    --selftest)
      SELFTEST=true
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

if [[ "${SELFTEST}" == true ]]; then
  run_selftest
  exit $?
fi

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

if [[ "${#LCOV_FILES[@]}" -eq 1 ]]; then
  log_verbose "single input file; skipping lcov merge, using it directly"
  cp "${LCOV_FILES[0]}" "${OUTPUT_PATH}"
else
  if ! command -v lcov >/dev/null 2>&1; then
    echo "${RED}Error: lcov is required to merge multiple lcov files${NC}" >&2
    exit 1
  fi
  lcov_add_args=()
  for f in "${LCOV_FILES[@]}"; do
    lcov_add_args+=(-a "${f}")
  done
  log_verbose "running: lcov ${lcov_add_args[*]} -o ${OUTPUT_PATH}"
  lcov "${lcov_add_args[@]}" -o "${OUTPUT_PATH}" >/dev/null
fi

if [[ "${DRYRUN}" == true ]]; then
  evaluate_coverage "${OUTPUT_PATH}" "${BASELINE_PATH}" true
  log "${YELLOW}dryrun requested; skipping threshold enforcement${NC}"
  exit 0
fi

if ! evaluate_coverage "${OUTPUT_PATH}" "${BASELINE_PATH}" false; then
  exit 1
fi

log "${GREEN}PASS${NC}: all coverage thresholds met"
