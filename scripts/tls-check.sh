#!/usr/bin/env bash
#
# tls-check.sh - External (non-rustls) verification of detent-web's TLS 1.3
# only posture (PLAN Phase 4, task 1), using the system `openssl` as an
# independent implementation of the TLS client.
#
# Usage:
#   scripts/tls-check.sh [OPTIONS] <host> <port>
#
# Options:
#   --openssl <path>     Path to the `openssl` binary to use (default:
#                         `openssl` on PATH).
#   --timeout <seconds>  Per-connection timeout, when a `timeout`/`gtimeout`
#                         binary is available (default: 10). Ignored with a
#                         warning if neither is on PATH.
#   --dryrun              Print the openssl commands this script would run,
#                          without connecting to anything, and exit 0.
#   --verbose, -v          Print step-level progress, the exact openssl
#                           command lines, and their raw output.
#   -h, --help              Show this help message.
#
# Behavior:
#   Against a running `detent serve` instance (or any TLS 1.3-only, ALPN h2
#   server), asserts all three of:
#     1. `openssl s_client -tls1_2` FAILS to negotiate a session.
#     2. `openssl s_client -tls1_3` SUCCEEDS.
#     3. ALPN negotiates `h2` under TLS 1.3.
#   Exits 0 only if all three checks pass; exits 1 and prints which check(s)
#   failed otherwise. Certificate chain trust is not checked (detent's
#   bootstrap cert is self-signed); only the protocol/ALPN negotiation is.
#
# `detent serve` needs root and a `detent` system account, so there is no
# CI job wired up for this script yet (running it means running the real
# server in a container). Manual procedure:
#
#   1. On a Linux host or container, install detent and run it as root:
#        sudo detent serve --config /etc/detent/detent.toml
#   2. From another shell (same host, or one that can reach the listen
#      address), run:
#        scripts/tls-check.sh 127.0.0.1 3333
#
# Requires: openssl (s_client, ALPN and TLS 1.3 support). `timeout` or
# `gtimeout` is used for a per-connection timeout when available; the
# checks still run without it, just without a hard time bound.

set -euo pipefail

OPENSSL_BIN="openssl"
CONNECT_TIMEOUT=10
DRYRUN=false
VERBOSE=false
HOST=""
PORT=""

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
  echo "${BLUE}[tls-check]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[tls-check][verbose]${NC} $*"
  fi
}

show_usage() {
  sed -n '2,42p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --openssl)
      OPENSSL_BIN="$2"
      shift 2
      ;;
    --timeout)
      CONNECT_TIMEOUT="$2"
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
      if [[ -z "${HOST}" ]]; then
        HOST="$1"
      elif [[ -z "${PORT}" ]]; then
        PORT="$1"
      else
        echo "${RED}Unexpected argument: $1${NC}" >&2
        show_usage
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "${HOST}" || -z "${PORT}" ]]; then
  echo "${RED}Error: missing <host> and/or <port> argument${NC}" >&2
  show_usage
  exit 1
fi

TARGET="${HOST}:${PORT}"

# Portable per-connection timeout: prefer GNU `timeout`, then `gtimeout`
# (macOS + `brew install coreutils`), else run unbounded with a warning.
TIMEOUT_CMD=()
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD=(timeout "${CONNECT_TIMEOUT}")
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_CMD=(gtimeout "${CONNECT_TIMEOUT}")
else
  log_verbose "no 'timeout' or 'gtimeout' on PATH; checks run without a hard time bound"
fi

if [[ "${DRYRUN}" != true ]]; then
  if ! command -v "${OPENSSL_BIN}" >/dev/null 2>&1; then
    echo "${RED}Error: '${OPENSSL_BIN}' not found${NC}" >&2
    exit 1
  fi

  # `openssl s_client -help` exits non-zero on its own (that is how the
  # subcommand reports "-help was given"), independent of whether the flags
  # we look for are present. Capture it separately so `pipefail` does not
  # turn that expected non-zero exit into a false "flag unsupported" error.
  help_output="$("${OPENSSL_BIN}" s_client -help 2>&1 || true)"
  for flag in -tls1_2 -tls1_3 -alpn; do
    if ! grep -q -- "${flag}" <<<"${help_output}"; then
      echo "${RED}Error: ${OPENSSL_BIN} s_client does not support ${flag}${NC}" >&2
      echo "${RED}       install a newer openssl and pass it with --openssl <path>${NC}" >&2
      exit 1
    fi
  done
fi

log_verbose "target: ${TARGET}"
log_verbose "openssl: ${OPENSSL_BIN} ($(${OPENSSL_BIN} version 2>/dev/null || echo unknown))"

# Runs `openssl s_client -connect $TARGET -servername $HOST "$@" </dev/null`,
# printing (under --verbose) the command and its output. Sets $LAST_OUTPUT.
#
# `s_client`'s own exit code is deliberately not used to decide pass/fail: it
# reflects things unrelated to protocol negotiation (a non-zero certificate
# verify result — always true against detent's self-signed bootstrap cert —
# and platform-specific quirks reading from a closed stdin both surface as a
# non-zero exit even after a fully successful handshake). Pass/fail is
# decided from the transcript text instead (see the checks below), which is
# what `s_client` actually prints once a session is established regardless
# of how it later exits.
run_s_client() {
  local -a cmd=(
    "${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"}" "${OPENSSL_BIN}" s_client
    -connect "${TARGET}" -servername "${HOST}" "$@"
  )

  if [[ "${DRYRUN}" == true ]]; then
    log "would run: ${cmd[*]} </dev/null"
    LAST_OUTPUT=""
    return 0
  fi

  log_verbose "running: ${cmd[*]} </dev/null"
  set +e
  LAST_OUTPUT="$("${cmd[@]}" </dev/null 2>&1)"
  local rc=$?
  set -e
  log_verbose "openssl exited ${rc} (not used to decide pass/fail; see comment above)"
  if [[ "${VERBOSE}" == true ]]; then
    while IFS= read -r line; do
      echo "${BLUE}[tls-check][verbose]${NC} ${line}"
    done <<<"${LAST_OUTPUT}"
  fi
  return 0
}

# True if $1 (an s_client transcript) shows a session actually negotiated
# at protocol $2 (e.g. "TLSv1\.2"). Both OpenSSL and LibreSSL print an
# `SSL-Session:`/`Protocol :` block echoing the *requested* version even on
# a hard handshake failure (a TLS 1.3-only server refusing a TLS 1.2
# ClientHello still gets a "Protocol : TLSv1.2" line back) — the real
# success signal is that a cipher was actually agreed: `Cipher is (NONE)`
# and `Cipher    : 0000` are how both implementations spell "no cipher".
negotiated() {
  local text="$1" version_re="$2"
  grep -q "Protocol *: ${version_re}" <<<"${text}" || return 1
  grep -q "Cipher is (NONE)" <<<"${text}" && return 1
  grep -q "Cipher *: 0000" <<<"${text}" && return 1
  return 0
}

overall_pass=true

# --- Check 1: TLS 1.2 must fail to negotiate. ---------------------------
log "checking that -tls1_2 fails against ${TARGET}"
run_s_client -tls1_2
if [[ "${DRYRUN}" == true ]]; then
  log "${YELLOW}dryrun: skipped${NC}"
elif negotiated "${LAST_OUTPUT}" 'TLSv1\.2'; then
  echo "${RED}FAIL${NC}: TLS 1.2 negotiated a session; the server must refuse it" >&2
  overall_pass=false
else
  log "${GREEN}PASS${NC}: TLS 1.2 was refused"
fi

# --- Check 2: TLS 1.3 must succeed. --------------------------------------
log "checking that -tls1_3 succeeds against ${TARGET}"
run_s_client -tls1_3
if [[ "${DRYRUN}" == true ]]; then
  log "${YELLOW}dryrun: skipped${NC}"
elif negotiated "${LAST_OUTPUT}" 'TLSv1\.3'; then
  log "${GREEN}PASS${NC}: TLS 1.3 negotiated"
else
  echo "${RED}FAIL${NC}: TLS 1.3 did not negotiate" >&2
  overall_pass=false
fi

# --- Check 3: ALPN negotiates h2 under TLS 1.3. --------------------------
log "checking that ALPN negotiates h2 against ${TARGET}"
run_s_client -tls1_3 -alpn h2
if [[ "${DRYRUN}" == true ]]; then
  log "${YELLOW}dryrun: skipped${NC}"
elif negotiated "${LAST_OUTPUT}" 'TLSv1\.3' && grep -qi "ALPN protocol: *h2" <<<"${LAST_OUTPUT}"; then
  log "${GREEN}PASS${NC}: ALPN negotiated h2"
else
  echo "${RED}FAIL${NC}: ALPN did not negotiate h2" >&2
  overall_pass=false
fi

if [[ "${DRYRUN}" == true ]]; then
  log "${YELLOW}dryrun requested; no checks were actually run${NC}"
  exit 0
fi

if [[ "${overall_pass}" != true ]]; then
  echo "${RED}FAIL${NC}: one or more TLS checks failed against ${TARGET}" >&2
  exit 1
fi

log "${GREEN}PASS${NC}: all TLS checks passed against ${TARGET}"
