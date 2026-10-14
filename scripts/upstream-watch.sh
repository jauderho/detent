#!/usr/bin/env bash
#
# upstream-watch.sh - Compare each module's tracked upstream version with the
#                     newest upstream release tag.
#
# Usage:
#   scripts/upstream-watch.sh select <upstream.toml> [tags-file]
#   scripts/upstream-watch.sh check [--dryrun] [--verbose] [--root <path>]
#   scripts/upstream-watch.sh selftest [--root <path>]
#
# Commands:
#   select    Read tag names (one per line) from tags-file or stdin, keep the
#             tags that match the toml's `tag_regex`, extract the version with
#             `version_regex`, and print the newest one (`sort -V`). Prints
#             nothing when no tag matches.
#   check     For every crates/modules/*/upstream.toml (not _template), list the
#             tags of `tags_repo` (default: `repo_url`) with `git ls-remote`,
#             select the newest release and open an issue only when it is newer
#             than `tracked_version`.
#   selftest  Run `select` over the recorded tag lists in
#             scripts/fixtures/upstream-watch/<module>.tags and compare with the
#             expected versions below. Needs no network.
#
# Switches:
#   --dryrun       Print the issue that would be opened; run no `gh` command.
#   --verbose, -v  Print step-level progress to stderr.
#   --root <path>  Repository root (default: parent of this script's directory).
#   -h, --help     Print this text.
#
# upstream.toml keys read here (TOML literal strings, single quotes):
#   tracked_version  Version the module tracks.
#   repo_url         Git remote used to list tags unless `tags_repo` is set.
#   tags_repo        Optional. Git remote for tags when `repo_url` is not one.
#   tag_regex        ERE; a tag is a release only when the whole tag matches it.
#                    Prereleases (rc, alpha, pre, test, devel, .9000) must not.
#   version_regex    ERE with one capture group that yields the version from a
#                    release tag. `-` in the result becomes `.` (nfs-utils).
#
# Environment:
#   FAKE_VERSION   If set, replaces every tracked_version (tests the issue
#                  path). GH_TOKEN is read by `gh`.
#
# Requires: bash, git, sed, sort -V (GNU or macOS), gh (check without --dryrun).

set -euo pipefail

verbose=0
dryrun=0
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
  if [[ "${verbose}" -eq 1 ]]; then
    echo "$*" >&2
  fi
}

# toml_get <file> <key>: value of `key = '...'` or `key = "..."`, else empty.
toml_get() {
  sed -n -e "s/^$2 = '\\(.*\\)'\$/\\1/p" -e "s/^$2 = \"\\(.*\\)\"\$/\\1/p" "$1" | head -1
}

# select_version <toml> [tags-file]
select_version() {
  local toml="$1" tags="${2:-/dev/stdin}" tag_re ver_re
  tag_re="$(toml_get "${toml}" tag_regex)"
  ver_re="$(toml_get "${toml}" version_regex)"
  if [[ -z "${tag_re}" || -z "${ver_re}" ]]; then
    echo "${toml}: tag_regex and version_regex are required" >&2
    return 2
  fi
  { grep -E "${tag_re}" "${tags}" || true; } |
    sed -n -E "s/${ver_re}/\\1/p" |
    tr '-' '.' |
    sort -V |
    tail -1
}

# newer_than <latest> <tracked>: success when latest sorts after tracked.
newer_than() {
  [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]
}

cmd_check() {
  local failed=0 toml id tracked repo latest existing title
  for toml in "${root}"/crates/modules/*/upstream.toml; do
    id="$(basename "$(dirname "${toml}")")"
    [[ "${id}" == _template ]] && continue
    tracked="$(toml_get "${toml}" tracked_version)"
    repo="$(toml_get "${toml}" tags_repo)"
    [[ -n "${repo}" ]] || repo="$(toml_get "${toml}" repo_url)"
    if [[ -n "${FAKE_VERSION:-}" ]]; then
      tracked="${FAKE_VERSION}"
    fi
    log "--- ${id}: tracked=${tracked} repo=${repo}"
    latest=""
    if [[ -n "${repo}" ]]; then
      latest="$(git ls-remote --tags --refs "${repo}" 2>/dev/null |
        sed -n 's|.*refs/tags/||p' | select_version "${toml}" || true)"
    fi
    if [[ -z "${latest}" ]]; then
      echo "could not determine latest for ${id}; skipping"
      continue
    fi
    if ! newer_than "${latest}" "${tracked}"; then
      echo "${id} current: tracked=${tracked} latest=${latest}"
      continue
    fi
    title="upstream ${id} moved: tracked ${tracked}, latest ${latest}"
    echo "${id} drifted: tracked=${tracked} latest=${latest}"
    if [[ "${dryrun}" -eq 1 ]]; then
      echo "dryrun: would open issue: ${title}"
      continue
    fi
    existing="$(gh issue list --search "upstream ${id} moved in:title" \
      --state open --limit 1 --json title --jq length 2>/dev/null || echo 0)"
    if [[ "${existing}" != "0" ]]; then
      echo "issue already open for ${id}; skipping"
      continue
    fi
    gh issue create --title "${title}" \
      --body "Diff docs, add/deprecate options in the schema, add fixtures, bump \`tracked_version\`, add \`since\`. (PLAN §2.3)" ||
      failed=1
  done
  return "${failed}"
}

# Expected newest release in each recorded tag list (recorded 2026-10-14).
declare -a EXPECTED=(
  "chrony 4.9"
  "dhcp 2.93"
  "hosts 2.44"
  "mounts 2.42.4"
  "network 262"
  "nfs 3.1.1"
  "resolver 262"
  "samba 4.25.0"
)

cmd_selftest() {
  local failed=0 entry id want got toml fx
  for entry in "${EXPECTED[@]}"; do
    id="${entry%% *}"
    want="${entry##* }"
    toml="${root}/crates/modules/${id}/upstream.toml"
    fx="${root}/scripts/fixtures/upstream-watch/${id}.tags"
    got="$(select_version "${toml}" "${fx}")"
    if [[ "${got}" == "${want}" ]]; then
      echo "ok   ${id}: ${got}"
    else
      echo "FAIL ${id}: want ${want}, got ${got:-<none>}"
      failed=1
    fi
  done
  # Every module with an upstream.toml must have an entry above.
  for toml in "${root}"/crates/modules/*/upstream.toml; do
    id="$(basename "$(dirname "${toml}")")"
    [[ "${id}" == _template ]] && continue
    if [[ " ${EXPECTED[*]} " != *" ${id} "* ]]; then
      echo "FAIL ${id}: no selftest entry"
      failed=1
    fi
  done
  # Ordering: 2.9.2 < 2.10 and 4.9 < 4.10 must hold; prereleases never win.
  newer_than 2.10 2.9 || {
    echo "FAIL ordering 2.10 vs 2.9"
    failed=1
  }
  newer_than 4.9 4.9 && {
    echo "FAIL equal versions count as newer"
    failed=1
  }
  return "${failed}"
}

cmd="${1:-}"
[[ $# -gt 0 ]] && shift
args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dryrun) dryrun=1 ;;
    --verbose | -v) verbose=1 ;;
    --root)
      root="$2"
      shift
      ;;
    -h | --help)
      sed -n '2,/^set -/p' "$0" | sed '$d'
      exit 0
      ;;
    *) args+=("$1") ;;
  esac
  shift
done

case "${cmd}" in
  select) select_version "${args[@]}" ;;
  check) cmd_check ;;
  selftest) cmd_selftest ;;
  -h | --help)
    sed -n '2,/^set -/p' "$0" | sed '$d'
    ;;
  *)
    echo "usage: $0 select|check|selftest [switches]" >&2
    exit 2
    ;;
esac
