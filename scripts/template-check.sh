#!/usr/bin/env bash
#
# template-check.sh - Instantiate crates/modules/_template with the README
# recipe in a throwaway copy of the tree, then build, lint and test the copy.
#
# Usage:
#   scripts/template-check.sh [OPTIONS]
#
# Options:
#   --id <id>            Module id for the copy (default: tmplcheck).
#   --keep               Keep the throwaway tree and print its path.
#   --dryrun             Print the steps and do nothing.
#   --verbose, -v        Print step-level progress and key variable state.
#   -h, --help           Show this help message.
#
# Behavior:
#   - Exports HEAD's tracked files (`git archive`) into a temporary directory,
#     so the working tree and its workspace are never changed.
#   - Runs the instantiation recipe from crates/modules/_template/README.md.
#   - Runs `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test`
#     on `detent-module-<id>`, reusing this repository's target directory
#     (CARGO_TARGET_DIR, default <repo>/target) so dependencies are not rebuilt.
#   - Exits non-zero if any step fails. STAGE3 L-MODA12.
#
# Requires: git, cargo, sed, find.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ID="tmplcheck"
KEEP=false
DRYRUN=false
VERBOSE=false

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
  echo "${BLUE}[template-check]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[template-check][verbose]${NC} $*"
  fi
}

show_usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --id)
      ID="${2:?--id needs a value}"
      shift 2
      ;;
    --keep)
      KEEP=true
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
      echo "${RED}error:${NC} unknown option: $1" >&2
      show_usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "${ID}" =~ ^[a-z][a-z0-9]*$ ]]; then
  echo "${RED}error:${NC} --id must be lowercase letters and digits: ${ID}" >&2
  exit 2
fi
TYPE="$(printf '%s' "${ID:0:1}" | tr '[:lower:]' '[:upper:]')${ID:1}Module"
PACKAGE="detent-module-${ID}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
log_verbose "id=${ID} type=${TYPE} package=${PACKAGE} target=${CARGO_TARGET_DIR}"

if [[ "${DRYRUN}" == true ]]; then
  log "dryrun: export HEAD to a temporary tree"
  log "dryrun: instantiate _template as crates/modules/${ID} (${TYPE})"
  log "dryrun: cargo fmt --check, clippy -D warnings, test on ${PACKAGE}"
  exit 0
fi

WORK="$(mktemp -d)"
cleanup() {
  if [[ "${KEEP}" == true ]]; then
    log "kept ${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

log "exporting HEAD to ${WORK}"
git -C "${REPO_ROOT}" archive HEAD | tar -x -C "${WORK}"
cd "${WORK}"

# The recipe, as in crates/modules/_template/README.md.
log "instantiating crates/modules/${ID}"
cp -R crates/modules/_template "crates/modules/${ID}"
for kind in parse roundtrip edit; do
  mv "crates/modules/${ID}/fuzz/fuzz_TEMPLATE_${kind}.rs" \
    "crates/modules/${ID}/fuzz/fuzz_${ID}_${kind}.rs"
done
find "crates/modules/${ID}" -type f \
  \( -name '*.rs' -o -name '*.toml' -o -name '*.ftl' -o -name '*.md' \) -print0 |
  while IFS= read -r -d '' f; do
    sed -e "s/detent-module-template/detent-module-${ID}/g" \
      -e "s/detent_module_template/detent_module_${ID}/g" \
      -e "s/TemplateModule/${TYPE}/g" -e "s/TEMPLATE/${ID}/g" "$f" >"${f}.new"
    mv "${f}.new" "$f"
  done
cat "crates/modules/${ID}/locale-snippet.ftl" >>locales/en-US/core.ftl
rm "crates/modules/${ID}/locale-snippet.ftl" "crates/modules/${ID}/README.md"
mkdir -p "fixtures/${ID}/edge"
cargo fmt -p "${PACKAGE}"

log "checking ${PACKAGE}"
cargo fmt -p "${PACKAGE}" -- --check
cargo clippy -p "${PACKAGE}" --all-targets --all-features -- -D warnings
cargo test -p "${PACKAGE}" --all-features

echo "${GREEN}PASS${NC}: the template instantiates as ${PACKAGE} and its checks pass"
