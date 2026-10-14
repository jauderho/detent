#!/usr/bin/env bash
# ci-changes.sh - Decide which CI areas a change touches.
#
# Usage:
#   git diff --name-only BASE HEAD | scripts/ci-changes.sh [--verbose]
#   scripts/ci-changes.sh --all
#
# Reads changed paths (one per line) on stdin and prints one `area=true|false`
# line per area on stdout, ready to append to $GITHUB_OUTPUT. The `changes`
# job in .github/workflows/ci.yml calls it.
#
# Areas:
#   rust       crates, Cargo files, fuzz, toolchain and tool config, baselines,
#              locales (web.ftl is embedded in the binary), docs/openapi.json
#              (embedded and drift-tested), scripts and packaging (CI scripts
#              and packaged units are read by Rust jobs and tests)
#   web        web, locales, docs/openapi.json
#   shell      packaging, scripts
#   workflows  .github (a change here sets every area)
#   docs       any path that matches no other area (informational)
#
# Switches:
#   --all      Print every area as true (push, schedule, manual run).
#   --verbose  Print each path and the areas it matched to stderr.
#   -h, --help Print this text.
set -euo pipefail

verbose=0
all=0
for arg in "$@"; do
  case "$arg" in
    --all) all=1 ;;
    --verbose | -v) verbose=1 ;;
    -h | --help)
      sed -n '2,/^set -/p' "$0" | sed '$d'
      exit 0
      ;;
    *)
      echo "unknown switch: $arg" >&2
      exit 2
      ;;
  esac
done

rust_re='^(crates/|fuzz/|locales/|packaging/|scripts/|\.cargo/|include/|examples/|fixtures/|Cargo\.(toml|lock)$|deny\.toml$|rust-toolchain|rustfmt\.toml$|size-baseline\.json$|coverage-baseline\.json$|Makefile$|docs/openapi\.json$)'
web_re='^(web/|locales/|docs/openapi\.json$)'
shell_re='^(packaging/|scripts/)'
workflows_re='^\.github/'

rust=false
web=false
shell=false
workflows=false
docs=false

if [[ "$all" -eq 1 ]]; then
  rust=true web=true shell=true workflows=true docs=true
else
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    hit=0
    if [[ "$path" =~ $rust_re ]]; then
      rust=true hit=1
    fi
    if [[ "$path" =~ $web_re ]]; then
      web=true hit=1
    fi
    if [[ "$path" =~ $shell_re ]]; then
      shell=true hit=1
    fi
    if [[ "$path" =~ $workflows_re ]]; then
      workflows=true hit=1
    fi
    if [[ "$hit" -eq 0 ]]; then
      docs=true
    fi
    if [[ "$verbose" -eq 1 ]]; then
      echo "ci-changes: ${path} matched=${hit}" >&2
    fi
  done
  # A workflow change can break any job, so it runs everything.
  if [[ "$workflows" == true ]]; then
    rust=true web=true shell=true docs=true
  fi
fi

echo "rust=${rust}"
echo "web=${web}"
echo "shell=${shell}"
echo "workflows=${workflows}"
echo "docs=${docs}"
