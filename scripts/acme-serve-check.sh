#!/usr/bin/env bash
#
# acme-serve-check.sh - Prove that `detent serve` with `tls.bootstrap =
# "acme"` gets a certificate from Pebble by dns-01 through the RFC 2136
# provider (TSIG), serves it, keeps the acme process confined, and stops
# cleanly on SIGTERM (ADR-015, STAGE4 §4.3 item 2, slice C4).
#
# Usage:
#   scripts/acme-serve-check.sh [OPTIONS] --tsig-key-file <path> \
#       <detent-binary> <pebble-ca-file> <directory-url>
#   scripts/acme-serve-check.sh [OPTIONS] --tsig-key-file <path> \
#       --write-dns-config <dir>
#
# Options:
#   --tsig-key-file <path>   File that holds the base64 TSIG secret
#                             (hmac-sha256). Required. Generate it at run
#                             time (`openssl rand -base64 32`); never commit one.
#   --write-dns-config <dir> Write a BIND 9 configuration for the test zone
#                             into <dir> and exit: <dir>/etc/named.conf (mount
#                             it at /etc/bind) and <dir>/cache/db.<zone> (mount
#                             it at /var/cache/bind). The zone accepts TXT
#                             updates below it signed with the TSIG key.
#   --dns-server <host:port> The RFC 2136 primary the acme process updates
#                             (default: 127.0.0.1:5300).
#   --zone <name>            The test zone (default: detent.test).
#   --domain <name>          The name to order a certificate for
#                             (default: serve.<zone>).
#   --key-name <name>        The TSIG key name (default: detent-acme).
#   --port <port>            The port `serve` listens on, on 127.0.0.1
#                             (default: 3443).
#   --state-root <path>      detent's state root. It must exist and belong to
#                             the `detent` account (default: /var/lib/detent).
#   --issue-timeout <secs>   How long to wait until the listener serves a
#                             certificate issued by Pebble (default: 180).
#   --stop-timeout <secs>    How long `serve` may take to stop after SIGTERM
#                             (default: 30).
#   --trace <prefix>         `strace -ff -o` prefix: one file per thread,
#                             <prefix>.<pid> (default: <workdir>/trace).
#   --workdir <dir>          Where the configuration, the logs and the trace
#                             go. Created if missing (default: a new
#                             `mktemp -d` directory under /tmp).
#   --dryrun                 Print the configuration and the commands this
#                             script would run, without running anything.
#   --verbose, -v            Print step-level progress and the serve log.
#   -h, --help               Show this help message.
#
# Behavior (check mode, as root):
#   1. Writes detent.toml (tls.bootstrap = "acme", [acme.provider] kind =
#      "rfc2136") and a 0600 secrets.toml with the TSIG key into the workdir,
#      and copies the Pebble CA there (the acme process reads it as `detent`).
#   2. Starts `detent serve` under `strace -ff` and waits until the leaf that
#      `openssl s_client` sees is issued by Pebble and names the domain.
#   3. Finds the four processes in the trace (monitor, runner, acme, worker),
#      and checks the acme process: uid `detent`, NoNewPrivs 1, Seccomp 2,
#      Landlock applied, and the TSIG update sent from it.
#   4. Sends SIGTERM to `serve` (the monitor, the process strace started)
#      and requires all four to end within the stop timeout and `serve` to
#      exit 0.
#   5. Fails when a syscall of the acme process returned EPERM, except the
#      calls the `ACME` seccomp table documents as refused and tolerated.
#      Prints the acme process's distinct syscall names.
#   Exits 0 only when every check passes.
#
# Requires: root, a `detent` system account, strace, openssl, timeout.

set -euo pipefail

TSIG_KEY_FILE=""
WRITE_DNS_DIR=""
DNS_SERVER="127.0.0.1:5300"
ZONE="detent.test"
DOMAIN=""
KEY_NAME="detent-acme"
PORT=3443
STATE_ROOT="/var/lib/detent"
ISSUE_TIMEOUT=180
STOP_TIMEOUT=30
TRACE=""
WORKDIR=""
DRYRUN=false
VERBOSE=false
DETENT_BIN=""
PEBBLE_CA=""
DIRECTORY_URL=""

# The worker account `serve` drops to (`SpawnConfig::default`).
WORKER_USER="detent"

# Syscalls the `ACME` table leaves out on purpose: the traces showed them
# refused and the callers go on (see the table's doc comment in
# crates/detent-platform/src/sandbox/seccomp.rs).
TOLERATED_EPERM=(uname ioctl prctl)

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
  echo "${BLUE}[acme-serve-check]${NC} $*"
}

log_verbose() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[acme-serve-check][verbose]${NC} $*"
  fi
}

pass() {
  log "${GREEN}PASS${NC}: $*"
}

die() {
  echo "${RED}FAIL${NC}: $*" >&2
  exit 1
}

show_usage() {
  sed -n '2,64p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

need_value() {
  if [[ $# -lt 2 || -z "$2" ]]; then
    echo "${RED}Option $1 needs a value${NC}" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tsig-key-file | --write-dns-config | --dns-server | --zone | --domain | \
      --key-name | --port | --state-root | --issue-timeout | --stop-timeout | \
      --trace | --workdir)
      need_value "$@"
      case "$1" in
        --tsig-key-file) TSIG_KEY_FILE="$2" ;;
        --write-dns-config) WRITE_DNS_DIR="$2" ;;
        --dns-server) DNS_SERVER="$2" ;;
        --zone) ZONE="$2" ;;
        --domain) DOMAIN="$2" ;;
        --key-name) KEY_NAME="$2" ;;
        --port) PORT="$2" ;;
        --state-root) STATE_ROOT="$2" ;;
        --issue-timeout) ISSUE_TIMEOUT="$2" ;;
        --stop-timeout) STOP_TIMEOUT="$2" ;;
        --trace) TRACE="$2" ;;
        --workdir) WORKDIR="$2" ;;
      esac
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
      if [[ -z "${DETENT_BIN}" ]]; then
        DETENT_BIN="$1"
      elif [[ -z "${PEBBLE_CA}" ]]; then
        PEBBLE_CA="$1"
      elif [[ -z "${DIRECTORY_URL}" ]]; then
        DIRECTORY_URL="$1"
      else
        echo "${RED}Unexpected argument: $1${NC}" >&2
        show_usage
        exit 1
      fi
      shift
      ;;
  esac
done

DOMAIN="${DOMAIN:-serve.${ZONE}}"
DNS_PORT="${DNS_SERVER##*:}"

if [[ -z "${TSIG_KEY_FILE}" ]]; then
  echo "${RED}Error: --tsig-key-file is required${NC}" >&2
  exit 1
fi
if [[ "${DRYRUN}" == true && ! -r "${TSIG_KEY_FILE}" ]]; then
  TSIG_KEY="<the key in ${TSIG_KEY_FILE}>"
else
  [[ -r "${TSIG_KEY_FILE}" ]] || die "cannot read ${TSIG_KEY_FILE}"
  TSIG_KEY="$(tr -d '[:space:]' <"${TSIG_KEY_FILE}")"
  [[ -n "${TSIG_KEY}" ]] || die "${TSIG_KEY_FILE} is empty"
fi

# --- DNS configuration mode ---------------------------------------------

# Prints named.conf. `-g` logs to stderr, so no logging block is needed.
named_conf() {
  cat <<EOF
options {
  directory "/var/cache/bind";
  listen-on port 53 { any; };
  listen-on-v6 { none; };
  recursion no;
  allow-query { any; };
  dnssec-validation no;
  pid-file none;
};
key "${KEY_NAME}" {
  algorithm hmac-sha256;
  secret "${TSIG_KEY}";
};
zone "${ZONE}" {
  type primary;
  file "/var/cache/bind/db.${ZONE}";
  update-policy { grant ${KEY_NAME} zonesub TXT; };
};
EOF
}

# Prints the zone file: an SOA, an NS and an address for the domain.
zone_file() {
  cat <<EOF
\$TTL 60
@ IN SOA ns1.${ZONE}. hostmaster.${ZONE}. 1 60 60 3600 60
@ IN NS ns1.${ZONE}.
ns1 IN A 127.0.0.1
${DOMAIN%."${ZONE}"} IN A 127.0.0.1
EOF
}

if [[ -n "${WRITE_DNS_DIR}" ]]; then
  if [[ "${DRYRUN}" == true ]]; then
    log "would write ${WRITE_DNS_DIR}/etc/named.conf:"
    named_conf | sed "s|${TSIG_KEY}|<redacted>|"
    log "would write ${WRITE_DNS_DIR}/cache/db.${ZONE}:"
    zone_file
    exit 0
  fi
  mkdir -p "${WRITE_DNS_DIR}/etc" "${WRITE_DNS_DIR}/cache"
  # The server runs as its own account (uid 53 in the ISC image): it must
  # read the configuration and write the zone journal. The key is a
  # throwaway made for this run.
  chmod 0755 "${WRITE_DNS_DIR}/etc"
  chmod 0777 "${WRITE_DNS_DIR}/cache"
  named_conf >"${WRITE_DNS_DIR}/etc/named.conf"
  zone_file >"${WRITE_DNS_DIR}/cache/db.${ZONE}"
  chmod 0644 "${WRITE_DNS_DIR}/etc/named.conf" "${WRITE_DNS_DIR}/cache/db.${ZONE}"
  log "wrote the BIND configuration for ${ZONE} into ${WRITE_DNS_DIR}"
  exit 0
fi

# --- Check mode -----------------------------------------------------------

if [[ -z "${DETENT_BIN}" || -z "${PEBBLE_CA}" || -z "${DIRECTORY_URL}" ]]; then
  echo "${RED}Error: need <detent-binary> <pebble-ca-file> <directory-url>${NC}" >&2
  show_usage
  exit 1
fi

if [[ -z "${WORKDIR}" ]]; then
  if [[ "${DRYRUN}" == true ]]; then
    WORKDIR="/tmp/detent-acme-serve.XXXXXX"
  else
    WORKDIR="$(mktemp -d /tmp/detent-acme-serve.XXXXXX)"
  fi
fi
TRACE="${TRACE:-${WORKDIR}/trace}"
CONFIG="${WORKDIR}/detent.toml"
SECRETS="${WORKDIR}/secrets.toml"
CA_COPY="${WORKDIR}/pebble-ca.pem"
SERVE_LOG="${WORKDIR}/serve.log"
CLONES="${WORKDIR}/clones.txt"

# Prints detent.toml.
detent_toml() {
  cat <<EOF
[listen]
addr = "127.0.0.1:${PORT}"

[tls]
bootstrap = "acme"
cert_dir = "${STATE_ROOT}/certs"

[acme]
directory_url = "${DIRECTORY_URL}"
domains = ["${DOMAIN}"]
credentials_path = "${STATE_ROOT}/acme/account.json"
ca_root = "${CA_COPY}"

[acme.provider]
kind = "rfc2136"
server = "${DNS_SERVER}"
zone = "${ZONE}"
key_name = "${KEY_NAME}"
algorithm = "hmac-sha256"
EOF
}

SERVE_CMD=(strace -ff -o "${TRACE}" "${DETENT_BIN}" --config "${CONFIG}"
  --state-root "${STATE_ROOT}" serve)

if [[ "${DRYRUN}" == true ]]; then
  log "would write ${CONFIG}:"
  detent_toml
  log "would write ${SECRETS} (0600) with the TSIG key as [acme] dns_provider"
  log "would copy ${PEBBLE_CA} to ${CA_COPY}"
  log "would run: ${SERVE_CMD[*]}"
  log "would poll: openssl s_client -connect 127.0.0.1:${PORT} -servername ${DOMAIN}"
  log "would send SIGTERM to serve and wait ${STOP_TIMEOUT}s for all four processes"
  log "would fail on EPERM in the acme process, except: ${TOLERATED_EPERM[*]}"
  log "${YELLOW}dryrun requested; nothing was run${NC}"
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "run as root: serve forks and drops to ${WORKER_USER}"
for tool in strace openssl timeout; do
  command -v "${tool}" >/dev/null 2>&1 || die "${tool} not found"
done
[[ -x "${DETENT_BIN}" ]] || die "${DETENT_BIN} is not an executable"
[[ -r "${PEBBLE_CA}" ]] || die "cannot read ${PEBBLE_CA}"
[[ -d "${STATE_ROOT}" ]] || die "state root ${STATE_ROOT} does not exist"
WORKER_UID="$(id -u "${WORKER_USER}")" || die "no ${WORKER_USER} account"

# The acme process runs as `detent` and reads the CA copy: the workdir must
# be searchable by it. secrets.toml stays 0600, owned by root.
mkdir -p "${WORKDIR}"
chmod 0755 "${WORKDIR}"
detent_toml >"${CONFIG}"
chmod 0644 "${CONFIG}"
install -m 0644 "${PEBBLE_CA}" "${CA_COPY}"
(
  umask 077
  printf '[acme]\ndns_provider = "%s"\n' "${TSIG_KEY}" >"${SECRETS}"
)
chmod 0600 "${SECRETS}"
log_verbose "workdir ${WORKDIR}; domain ${DOMAIN}; dns server ${DNS_SERVER}"
if [[ "${VERBOSE}" == true ]]; then
  detent_toml
fi

SERVE_PID=""
# On any exit, stop what is still running, so a failed check does not leave
# a server behind.
cleanup() {
  if [[ -n "${SERVE_PID}" ]] && kill -0 "${SERVE_PID}" 2>/dev/null; then
    pkill -KILL -P "${SERVE_PID}" 2>/dev/null || true
    kill -KILL "${SERVE_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

show_serve_log() {
  echo "--- serve log (${SERVE_LOG}) ---" >&2
  sed "s|${TSIG_KEY}|<redacted>|g" "${SERVE_LOG}" >&2 || true
  echo "--- end of serve log ---" >&2
  # A seccomp kill (SIGSYS) shows in the trace only: print the refused call.
  local file
  for file in "${TRACE}".*; do
    if [[ -f "${file}" ]] && grep -q '^+++ killed by' "${file}"; then
      echo "pid ${file##*.}:" >&2
      tail -n 2 "${file}" >&2
    fi
  done
}

log "starting: ${SERVE_CMD[*]}"
"${SERVE_CMD[@]}" >"${SERVE_LOG}" 2>&1 &
SERVE_PID=$!

# --- 1. The listener serves a certificate issued by Pebble ---------------

leaf_pem() {
  timeout 10 openssl s_client -connect "127.0.0.1:${PORT}" -servername "${DOMAIN}" \
    </dev/null 2>/dev/null | openssl x509 2>/dev/null || true
}

deadline=$((SECONDS + ISSUE_TIMEOUT))
issuer=""
leaf=""
while ((SECONDS < deadline)); do
  if ! kill -0 "${SERVE_PID}" 2>/dev/null; then
    show_serve_log
    die "serve ended before it served an ACME certificate"
  fi
  leaf="$(leaf_pem)"
  if [[ -n "${leaf}" ]]; then
    issuer="$(openssl x509 -noout -issuer <<<"${leaf}")"
    log_verbose "served leaf: ${issuer}"
    if grep -q "Pebble" <<<"${issuer}"; then
      break
    fi
  fi
  sleep 2
done
if ! grep -q "Pebble" <<<"${issuer}"; then
  show_serve_log
  die "no certificate issued by Pebble within ${ISSUE_TIMEOUT}s (last: ${issuer:-none})"
fi
pass "the listener serves a leaf with ${issuer}"

san="$(openssl x509 -noout -ext subjectAltName <<<"${leaf}")"
log_verbose "SAN: ${san//$'\n'/ }"
grep -q "DNS:${DOMAIN}\b" <<<"${san}" || die "the leaf does not name ${DOMAIN}: ${san}"
pass "the leaf names DNS:${DOMAIN}"

# --- 2. The four processes, and the acme process's confinement -----------

# One line per clone in the trace: "<parent> <child> <thread|process>".
list_clones() {
  local file parent
  for file in "${TRACE}".*; do
    parent="${file##*.}"
    sed -nE 's/^(clone|clone3|fork|vfork)\((.*)\) += ([0-9]+)$/\3 \2/p' "${file}" |
      while read -r child args; do
        if [[ "${args}" == *CLONE_THREAD* ]]; then
          echo "${parent} ${child} thread"
        else
          echo "${parent} ${child} process"
        fi
      done
  done
}

# The pid that `strace` started: the one no clone created.
main_pid() {
  local file pid
  for file in "${TRACE}".*; do
    pid="${file##*.}"
    if ! awk -v p="${pid}" '$2 == p { found = 1 } END { exit !found }' "${CLONES}"; then
      echo "${pid}"
    fi
  done
}

# The process (thread group leader) that thread or process $1 belongs to.
group_leader() {
  local pid="$1" parent
  while parent="$(awk -v p="${pid}" '$2 == p && $3 == "thread" { print $1 }' "${CLONES}")" &&
    [[ -n "${parent}" ]]; do
    pid="${parent}"
  done
  echo "${pid}"
}

# $1 and every thread or process it created, recursively.
descendants() {
  local pid
  echo "$1"
  awk -v p="$1" '$1 == p { print $2 }' "${CLONES}" | while read -r pid; do
    descendants "${pid}"
  done
}

# Trace files of $1 and its descendants that match the regex $2.
tree_matches() {
  local pid
  for pid in $(descendants "$1"); do
    if [[ -f "${TRACE}.${pid}" ]] && grep -qE "$2" "${TRACE}.${pid}"; then
      echo "${pid}"
    fi
  done
}

list_clones >"${CLONES}"
mapfile -t mains < <(main_pid)
[[ "${#mains[@]}" -eq 1 ]] || die "expected one traced root process, found: ${mains[*]:-none}"
MAIN="${mains[0]}"
mapfile -t children < <(awk -v p="${MAIN}" '$1 == p && $3 == "process" { print $2 }' "${CLONES}")
log_verbose "serve (monitor) pid ${MAIN}; forked: ${children[*]:-none}"

# The acme process is the one that sent the TSIG update to the DNS server.
mapfile -t senders < <(grep -lE "^connect\(.*htons\(${DNS_PORT}\).*\) = 0$" "${TRACE}".* 2>/dev/null |
  while read -r file; do group_leader "${file##*.}"; done | sort -u)
[[ "${#senders[@]}" -eq 1 ]] || die "expected one process to reach ${DNS_SERVER}, found: ${senders[*]:-none}"
ACME="${senders[0]}"
WORKER=""
RUNNER=""
# Host detection also starts programs (`chronyd --version` and the like):
# those children `execve`, the three forks of serve do not.
for child in "${children[@]}"; do
  if [[ "${child}" == "${ACME}" ]] || grep -q '^execve(' "${TRACE}.${child}"; then
    continue
  elif [[ -n "$(tree_matches "${child}" '^listen\(.*\) = 0$')" ]]; then
    WORKER="${child}"
  elif [[ -z "${RUNNER}" ]]; then
    RUNNER="${child}"
  fi
done
[[ " ${children[*]} " == *" ${ACME} "* ]] || die "the acme process ${ACME} is not a child of serve (${MAIN})"
[[ -n "${WORKER}" ]] || die "no child of serve listens"
[[ -n "${RUNNER}" ]] || die "no runner among the children of serve: ${children[*]}"
for pid in "${MAIN}" "${RUNNER}" "${ACME}" "${WORKER}"; do
  [[ -d "/proc/${pid}" ]] || die "process ${pid} is not running"
done
pass "four processes run: monitor ${MAIN}, runner ${RUNNER}, acme ${ACME}, worker ${WORKER}"

status_field() {
  awk -v f="$1:" '$1 == f { print $2 }' "/proc/${ACME}/status"
}
[[ "$(status_field Uid)" == "${WORKER_UID}" ]] ||
  die "the acme process runs as uid $(status_field Uid), not ${WORKER_USER} (${WORKER_UID})"
[[ "$(status_field NoNewPrivs)" == "1" ]] || die "the acme process has no no_new_privs"
[[ "$(status_field Seccomp)" == "2" ]] || die "the acme process has no seccomp filter"
grep -qE '^seccomp\(SECCOMP_SET_MODE_FILTER, .*\) = 0$' "${TRACE}.${ACME}" ||
  die "the trace shows no seccomp filter installed by the acme process"
grep -qE '^landlock_restrict_self\(.*\) = 0$' "${TRACE}.${ACME}" ||
  die "the trace shows no Landlock ruleset applied by the acme process"
pass "the acme process runs as ${WORKER_USER} with no_new_privs, seccomp (filter) and Landlock"

# --- 3. SIGTERM ends all four; serve exits 0 ------------------------------

log "sending SIGTERM to serve (${MAIN})"
kill -TERM "${MAIN}"
deadline=$((SECONDS + STOP_TIMEOUT))
while kill -0 "${SERVE_PID}" 2>/dev/null && ((SECONDS < deadline)); do
  sleep 1
done
if kill -0 "${SERVE_PID}" 2>/dev/null; then
  show_serve_log
  die "serve still runs ${STOP_TIMEOUT}s after SIGTERM"
fi
set +e
wait "${SERVE_PID}"
serve_status=$?
set -e
SERVE_PID=""
for pid in "${MAIN}" "${RUNNER}" "${ACME}" "${WORKER}"; do
  [[ ! -d "/proc/${pid}" ]] || die "process ${pid} still runs after serve ended"
done
if [[ "${serve_status}" -ne 0 ]]; then
  show_serve_log
  die "serve exited ${serve_status} after SIGTERM, not 0"
fi
pass "all four processes ended after SIGTERM; serve exited 0"

# --- 4. No EPERM in the acme process -------------------------------------

mapfile -t acme_pids < <(descendants "${ACME}")
acme_files=()
for pid in "${acme_pids[@]}"; do
  [[ -f "${TRACE}.${pid}" ]] && acme_files+=("${TRACE}.${pid}")
done
tolerated_re="^($(
  IFS='|'
  echo "${TOLERATED_EPERM[*]}"
))\("
refused="$(grep -hE '= -1 EPERM ' "${acme_files[@]}" || true)"
tolerated="$(grep -E "${tolerated_re}" <<<"${refused}" || true)"
refused="$(grep -vE "${tolerated_re}" <<<"${refused}" || true)"
if [[ -n "${tolerated}" ]]; then
  log "${YELLOW}tolerated EPERM in the acme process:${NC}"
  sed -E 's/\(.*//' <<<"${tolerated}" | sort | uniq -c
fi
log "syscalls of the acme process (${#acme_files[@]} threads):"
grep -hoE '^[a-z_0-9]+\(' "${acme_files[@]}" | tr -d '(' | sort -u | tr '\n' ' '
echo
if [[ -n "${refused}" ]]; then
  echo "${refused}" >&2
  die "the acme process was refused the syscalls above (EPERM)"
fi
pass "no syscall of the acme process returned EPERM outside: ${TOLERATED_EPERM[*]}"

if [[ "${VERBOSE}" == true ]]; then
  show_serve_log
fi
log "${GREEN}PASS${NC}: detent serve obtained and served a Pebble certificate, confined"
