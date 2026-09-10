#!/usr/bin/env bash
#
# cooldown-check.sh - Verify the Bun/npm supply-chain cooldown (ADR-011) is
#                     actually in force wherever `bun install` can run.
#
# Usage:
#   scripts/cooldown-check.sh [OPTIONS]
#
# Options:
#   --min-seconds <n>   Required minimum release age, in seconds
#                        (default: 604800, i.e. 7 days per ADR-011).
#   --root <path>       Repository root to scan (default: the directory
#                        containing this script's parent).
#   --dryrun            Accepted for interface consistency with the other repo
#                        scripts. This script performs no writes, so the flag
#                        is a no-op.
#   --verbose, -v       Print step-level progress and key variable state.
#   -h, --help          Show this help message.
#
# Why this check exists:
#   Bun reads `bunfig.toml` from the *current working directory* only - it does
#   not walk up to parent directories. A `bunfig.toml` at the repository root
#   therefore has no effect on `bun install` run inside `web/`, which is where
#   this project's only package.json lives and where CI installs from. The
#   cooldown would silently not apply, which is the failure mode this script
#   makes loud.
#
# Behavior:
#   For every package.json in the tree (node_modules and dist excluded), the
#   sibling bunfig.toml must exist and must set:
#     - [install] minimumReleaseAge >= --min-seconds
#     - [install] minimumReleaseAgeExcludes to an empty list (a non-empty
#       exclude list waives the cooldown for the named packages)
#   Exits non-zero, listing every violation, if any of that does not hold.
#
# Requires: bash 3.2+, POSIX grep/sed. No jq, no network.

set -euo pipefail

MIN_SECONDS=604800
ROOT=""
VERBOSE=0

if [[ -n "${NO_COLOR:-}" || ! -t 1 ]]; then
  C_RED='' C_GREEN='' C_DIM='' C_OFF=''
else
  C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_DIM=$'\033[2m' C_OFF=$'\033[0m'
fi

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'
}

log() {
  if [[ "$VERBOSE" -eq 1 ]]; then
    printf '%s%s%s\n' "$C_DIM" "$*" "$C_OFF" >&2
  fi
}

die() {
  printf '%scooldown-check: %s%s\n' "$C_RED" "$*" "$C_OFF" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --min-seconds)
      [[ $# -ge 2 ]] || die "--min-seconds needs a value"
      MIN_SECONDS="$2"
      shift 2
      ;;
    --root)
      [[ $# -ge 2 ]] || die "--root needs a value"
      ROOT="$2"
      shift 2
      ;;
    --dryrun)
      shift
      ;;
    --verbose | -v)
      VERBOSE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ "$MIN_SECONDS" =~ ^[0-9]+$ ]] || die "--min-seconds must be a whole number, got: $MIN_SECONDS"

if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
[[ -d "$ROOT" ]] || die "no such directory: $ROOT"

log "root=$ROOT min_seconds=$MIN_SECONDS"

# Read `key = value` out of a bunfig.toml, ignoring comments and whitespace.
# TOML here is a four-line file the repo owns; a full parser is not warranted.
#
# An absent key is a normal answer, not an error: `grep` exits 1 and, under
# `set -o pipefail`, that status would propagate out of the command
# substitution and abort the whole scan. The trailing `|| true` keeps a missing
# key as an empty string so the caller can decide what it means.
toml_value() {
  local file="$1" key="$2"
  {
    sed -e 's/#.*$//' "$file" |
      grep -E "^[[:space:]]*${key}[[:space:]]*=" |
      head -n 1 |
      sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//"
  } || true
}

violations=0
checked=0

report() {
  printf '%s  ✗ %s%s\n' "$C_RED" "$*" "$C_OFF" >&2
  violations=$((violations + 1))
}

# `find -print0` + `read -d ''` keeps paths with spaces intact.
while IFS= read -r -d '' manifest; do
  dir="$(dirname "$manifest")"
  rel="${dir#"$ROOT"/}"
  [[ "$rel" == "$dir" ]] && rel="."
  checked=$((checked + 1))
  log "checking $rel/package.json"

  bunfig="$dir/bunfig.toml"
  if [[ ! -f "$bunfig" ]]; then
    report "$rel/package.json has no sibling bunfig.toml — bun does not read one from a parent directory, so the ADR-011 cooldown would not apply to installs run here"
    continue
  fi

  age="$(toml_value "$bunfig" minimumReleaseAge)"
  if [[ -z "$age" ]]; then
    report "$rel/bunfig.toml does not set minimumReleaseAge"
  elif [[ ! "$age" =~ ^[0-9]+$ ]]; then
    report "$rel/bunfig.toml has a non-numeric minimumReleaseAge: $age"
  elif [[ "$age" -lt "$MIN_SECONDS" ]]; then
    report "$rel/bunfig.toml sets minimumReleaseAge=$age, below the required $MIN_SECONDS"
  else
    log "  minimumReleaseAge=$age"
  fi

  excludes="$(toml_value "$bunfig" minimumReleaseAgeExcludes)"
  if [[ -n "$excludes" && "$excludes" != "[]" ]]; then
    report "$rel/bunfig.toml waives the cooldown for: $excludes"
  fi
done < <(find "$ROOT" \
  \( -name node_modules -o -name dist -o -name target -o -name .git \) -prune -o \
  -name package.json -type f -print0)

if [[ "$checked" -eq 0 ]]; then
  die "found no package.json under $ROOT — the scan path is probably wrong"
fi

if [[ "$violations" -gt 0 ]]; then
  printf '%scooldown-check: FAIL — %d violation(s) across %d manifest(s)%s\n' \
    "$C_RED" "$violations" "$checked" "$C_OFF" >&2
  exit 1
fi

printf '%scooldown-check: OK — %d manifest(s), cooldown ≥ %ss enforced at each%s\n' \
  "$C_GREEN" "$checked" "$MIN_SECONDS" "$C_OFF"
