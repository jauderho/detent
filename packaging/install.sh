#!/usr/bin/env bash
#
# packaging/install.sh — install or uninstall the detent binary, systemd
# unit, sysusers/tmpfiles snippets, and polkit rule (PLAN §2.4, §2.10,
# Phase 2 "Packaging" deliverable).
#
# Usage:
#   install.sh [OPTIONS]
#
# Options:
#   --binary <path>   Path to the detent binary to install.
#                      Default: ./target/release/detent
#   --mode <mode>      root-confined | capability-user (default: root-confined).
#                      Selects whether the capability-user systemd drop-in
#                      (packaging/systemd/detent.service.d/capability-user.conf)
#                      is installed alongside detent.service.
#   --uninstall         Remove previously installed files instead of installing.
#   --prefix <dir>      Install under <dir> instead of /. DESTDIR semantics:
#                        files are placed only — no systemctl, systemd-sysusers,
#                        or systemd-tmpfiles calls are made, and no ownership
#                        changes are attempted (so this works unprivileged,
#                        including on macOS, for testing packaging layout).
#   --dryrun            Print the actions that would be taken; make no changes.
#   --verbose, -v       Print step-level progress and key variable state.
#   -h, --help          Show this help and exit.
#
# Examples:
#   sudo packaging/install.sh
#   sudo packaging/install.sh --mode capability-user
#   sudo packaging/install.sh --uninstall
#   packaging/install.sh --binary ./target/release/detent --prefix /tmp/detent-root
#   packaging/install.sh --dryrun --verbose
#
# Notes:
#   - Must be run as root (EUID 0) for a real install/uninstall. Under
#     --dryrun or --prefix it never requires root and never invokes sudo —
#     if privilege is genuinely required and neither flag is given, this
#     script exits with an error rather than escalating itself.
#   - Linux-first. Runs on macOS only in --dryrun or --prefix mode (no
#     systemd on macOS, so a real install there is refused).

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants and defaults
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BINARY="./target/release/detent"
MODE="root-confined"
PREFIX=""
UNINSTALL=0
DRYRUN=0
VERBOSE=0

BIN_DEST="usr/local/bin/detent"
SERVICE_DEST="etc/systemd/system/detent.service"
DROPIN_DEST="etc/systemd/system/detent.service.d/capability-user.conf"
SYSUSERS_DEST="etc/sysusers.d/detent.conf"
TMPFILES_DEST="etc/tmpfiles.d/detent.conf"
POLKIT_DEST="etc/polkit-1/rules.d/50-detent.rules"

# ---------------------------------------------------------------------------
# Colors (NO_COLOR-aware; disabled when not a tty)
# ---------------------------------------------------------------------------

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RED=$'\033[31m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_GREEN=$'\033[32m'
  C_RESET=$'\033[0m'
else
  C_RED=""
  C_YELLOW=""
  C_BLUE=""
  C_GREEN=""
  C_RESET=""
fi

log_info() { printf '%s\n' "${C_BLUE}==>${C_RESET} $*"; }
log_verbose() { ((VERBOSE)) && printf '%s\n' "${C_BLUE}  ->${C_RESET} $*" || true; }
log_warn() { printf '%s\n' "${C_YELLOW}warning:${C_RESET} $*" >&2; }
log_err() { printf '%s\n' "${C_RED}error:${C_RESET} $*" >&2; }
log_ok() { printf '%s\n' "${C_GREEN}==>${C_RESET} $*"; }

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      [[ $# -ge 2 ]] || {
        log_err "--binary requires an argument"
        exit 1
      }
      BINARY="$2"
      shift 2
      ;;
    --mode)
      [[ $# -ge 2 ]] || {
        log_err "--mode requires an argument"
        exit 1
      }
      MODE="$2"
      shift 2
      ;;
    --prefix)
      [[ $# -ge 2 ]] || {
        log_err "--prefix requires an argument"
        exit 1
      }
      PREFIX="$2"
      shift 2
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    --dryrun)
      DRYRUN=1
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
      log_err "unknown option: $1"
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$MODE" != "root-confined" && "$MODE" != "capability-user" ]]; then
  log_err "--mode must be root-confined or capability-user (got: $MODE)"
  exit 1
fi

# ---------------------------------------------------------------------------
# Privilege check — no sudo is ever invoked by this script.
# ---------------------------------------------------------------------------

if ((DRYRUN == 0)) && [[ -z "$PREFIX" ]]; then
  if [[ "$EUID" -ne 0 ]]; then
    log_err "must be run as root for a real install/uninstall (EUID=$EUID)."
    log_err "re-run with sudo, or use --dryrun / --prefix <dir> to run unprivileged."
    exit 1
  fi
  if [[ "$(uname -s)" != "Linux" ]]; then
    log_err "a real install is Linux-only (systemd unit + sysusers.d + tmpfiles.d)."
    log_err "use --dryrun or --prefix <dir> on $(uname -s)."
    exit 1
  fi
fi

DEST_ROOT="${PREFIX:-/}"
# Normalize so DEST_ROOT/rel-path never produces a double slash.
DEST_ROOT="${DEST_ROOT%/}"

log_verbose "script dir:   $SCRIPT_DIR"
log_verbose "binary:       $BINARY"
log_verbose "mode:         $MODE"
log_verbose "prefix:       ${PREFIX:-<none, installing to />}"
log_verbose "uninstall:    $UNINSTALL"
log_verbose "dryrun:       $DRYRUN"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# run <description> -- <command...>
# Prints the action; executes it unless --dryrun.
run() {
  local desc="$1"
  shift
  log_verbose "$desc"
  if ((DRYRUN)); then
    printf '%s\n' "${C_YELLOW}[dryrun]${C_RESET} $*"
    return 0
  fi
  "$@"
}

# install_file <src> <dest-relative-path> <mode>
install_file() {
  local src="$1" rel="$2" mode="$3"
  local dest="$DEST_ROOT/$rel"
  local destdir
  destdir="$(dirname "$dest")"

  log_info "installing $rel"
  run "mkdir -p $destdir" mkdir -p "$destdir"
  run "copy $src -> $dest" cp "$src" "$dest"
  run "chmod $mode $dest" chmod "$mode" "$dest"

  # Only chown when doing a real, non-prefixed install (root, on the real
  # filesystem) — chown requires root and is meaningless under --prefix.
  if ((DRYRUN == 0)) && [[ -z "$PREFIX" ]]; then
    run "chown root:root $dest" chown root:root "$dest"
  fi
}

remove_file() {
  local rel="$1"
  local dest="$DEST_ROOT/$rel"
  if [[ -e "$dest" || -L "$dest" ]]; then
    log_info "removing $rel"
    run "rm -f $dest" rm -f "$dest"
  else
    log_verbose "already absent: $rel"
  fi
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

do_uninstall() {
  remove_file "$BIN_DEST"
  remove_file "$SERVICE_DEST"
  remove_file "$DROPIN_DEST"
  remove_file "$SYSUSERS_DEST"
  remove_file "$TMPFILES_DEST"
  remove_file "$POLKIT_DEST"

  if ((DRYRUN == 0)) && [[ -z "$PREFIX" ]]; then
    run "systemctl daemon-reload" systemctl daemon-reload
  else
    log_verbose "skipping systemctl daemon-reload (--dryrun or --prefix)"
  fi

  log_ok "uninstall complete"
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

do_install() {
  if [[ ! -f "$BINARY" ]]; then
    log_err "binary not found: $BINARY (pass --binary <path>)"
    exit 1
  fi

  install_file "$BINARY" "$BIN_DEST" 0755
  install_file "$SCRIPT_DIR/systemd/detent.service" "$SERVICE_DEST" 0644
  install_file "$SCRIPT_DIR/sysusers.d/detent.conf" "$SYSUSERS_DEST" 0644
  install_file "$SCRIPT_DIR/tmpfiles.d/detent.conf" "$TMPFILES_DEST" 0644
  install_file "$SCRIPT_DIR/polkit/50-detent.rules" "$POLKIT_DEST" 0644

  if [[ "$MODE" == "capability-user" ]]; then
    install_file "$SCRIPT_DIR/systemd/detent.service.d/capability-user.conf" \
      "$DROPIN_DEST" 0644
  else
    log_verbose "root-confined mode: not installing capability-user.conf drop-in"
  fi

  if ((DRYRUN == 0)) && [[ -z "$PREFIX" ]]; then
    run "systemd-sysusers detent.conf" systemd-sysusers "$SCRIPT_DIR/sysusers.d/detent.conf"
    run "systemd-tmpfiles --create" systemd-tmpfiles --create "$SCRIPT_DIR/tmpfiles.d/detent.conf"
    run "systemctl daemon-reload" systemctl daemon-reload
  else
    log_verbose "skipping systemd-sysusers/systemd-tmpfiles/systemctl (--dryrun or --prefix)"
  fi

  log_ok "install complete (mode: $MODE)"
  if ((DRYRUN == 0)) && [[ -z "$PREFIX" ]]; then
    log_info "next: run 'detent setup' to create the admin user and configure listen/ACME"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ((UNINSTALL)); then
  do_uninstall
else
  do_install
fi
