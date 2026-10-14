#!/usr/bin/env bash
#
# d3-containers.sh - Run the Phase 7 per-module acceptance and the Phase 8
# network matrix of detent in podman containers on the test host, one
# container per distro with systemd as PID 1 (BUGFIX Track D 3, done in
# containers; owner decision 2026-10-14: containers only, no VMs).
#
# Usage:
#   d3-containers.sh [OPTIONS]
#
# Options:
#   --stage <dir>       Directory that holds the cross-built `detent` binary,
#                        `packaging/` and `scripts/` (copied from the
#                        repository) and `d3-inside.sh`. Mounted in every
#                        container as /stage; results land in <dir>/results/
#                        (default: the current directory).
#   --distro <list>     Comma list from: debian ubuntu fedora arch
#                        (default: all four).
#   --only <list>       Pass-through of d3-inside.sh --only (default: all
#                        sections).
#   --keep              Keep the containers and images at the end (default:
#                        remove them, and the base images they came from).
#   --cleanup           Only remove the d3-* containers and images and the
#                        base images this script pulled; run nothing.
#   --dryrun            Print what would run; change nothing.
#   --verbose, -v       Print step-level progress and key variable state.
#   -h, --help          Show this help message.
#
# What it does, per distro:
#   1. Writes a Containerfile (systemd + the distro's backend packages) and
#      builds the image. The build uses the host network namespace for the
#      package download only; nothing on the host network is configured.
#   2. Runs the container with systemd as PID 1, all capabilities except
#      CAP_SYS_TIME (a container must never touch the host clock), no
#      seccomp or AppArmor profile (systemd and the network tools need it),
#      and NO network: `--network=none` gives it a private namespace with
#      loopback only. The checks add a veth pair inside that namespace.
#   3. Runs d3-inside.sh in it and keeps the rows in results/<distro>.tsv.
#   4. Removes the container (and, without --keep, the image).
#
# Run it as root on the test host (sudo). It never compiles anything: build
# the binary elsewhere (cargo zigbuild --locked --release -p detent --target
# x86_64-unknown-linux-musl) and copy it to <stage>/detent.
#
# Exit codes: 0 every distro ran (results may hold FAIL rows: read them);
# 2 a precondition is missing or a build failed.
#
# Requires: bash, podman, root.

set -euo pipefail

STAGE="."
DISTROS="debian,ubuntu,fedora,arch"
ONLY=""
KEEP=false
CLEANUP=false
DRYRUN=false
VERBOSE=false

PODMAN_BASE_IMAGES=(
  docker.io/library/debian:stable
  docker.io/library/ubuntu:latest
  docker.io/library/fedora:latest
  docker.io/library/archlinux:latest
)

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
  echo "${BLUE}[d3-containers]${NC} $*"
}

vlog() {
  if [[ "${VERBOSE}" == true ]]; then
    echo "${BLUE}[d3-containers][verbose]${NC} $*" >&2
  fi
}

die() {
  echo "${RED}ERROR${NC} $*" >&2
  exit 2
}

show_usage() {
  sed -n '2,46p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage)
      STAGE="$2"
      shift 2
      ;;
    --distro)
      DISTROS="$2"
      shift 2
      ;;
    --only)
      ONLY="$2"
      shift 2
      ;;
    --keep)
      KEEP=true
      shift
      ;;
    --cleanup)
      CLEANUP=true
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
      echo "${RED}Unknown argument: $1${NC}" >&2
      show_usage
      exit 2
      ;;
  esac
done

STAGE="$(cd "${STAGE}" && pwd)"

# run CMD... : print the command in verbose mode, skip it under --dryrun.
run() {
  vlog "$*"
  if [[ "${DRYRUN}" == true ]]; then
    log "would run: $*"
    return 0
  fi
  "$@"
}

# --- Containerfiles -------------------------------------------------------------

containerfile() {
  case "$1" in
    debian)
      cat <<'EOF'
FROM docker.io/library/debian:stable
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv systemd-resolved dbus polkitd ifupdown network-manager \
    iproute2 iputils-ping curl jq ca-certificates chrony nfs-kernel-server samba \
    unbound dnsmasq kea-dhcp4-server kea-dhcp6-server util-linux mount procps \
    diffutils && apt-get clean
CMD ["/usr/lib/systemd/systemd"]
EOF
      ;;
    ubuntu)
      cat <<'EOF'
FROM docker.io/library/ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv systemd-resolved dbus polkitd netplan.io \
    iproute2 iputils-ping curl jq ca-certificates chrony nfs-kernel-server samba \
    unbound dnsmasq kea-dhcp4-server kea-dhcp6-server util-linux mount procps \
    diffutils && apt-get clean
CMD ["/usr/lib/systemd/systemd"]
EOF
      ;;
    fedora)
      cat <<'EOF'
FROM docker.io/library/fedora:latest
RUN dnf -y --setopt=install_weak_deps=False install \
    systemd systemd-resolved NetworkManager polkit iproute iputils curl jq \
    chrony nfs-utils samba samba-common-tools unbound dnsmasq kea util-linux \
    procps-ng findutils diffutils hostname passwd && dnf clean all
CMD ["/usr/lib/systemd/systemd"]
EOF
      ;;
    arch)
      cat <<'EOF'
FROM docker.io/library/archlinux:latest
RUN pacman -Syu --noconfirm --disable-sandbox \
    systemd polkit iproute2 iputils curl jq chrony nfs-utils samba unbound \
    dnsmasq kea util-linux procps-ng diffutils && pacman -Scc --noconfirm
CMD ["/usr/lib/systemd/systemd"]
EOF
      ;;
    *) die "unknown distro $1" ;;
  esac
}

# --- cleanup --------------------------------------------------------------------

remove_all() {
  local distro name
  for distro in debian ubuntu fedora arch; do
    name="d3-${distro}"
    if podman container exists "${name}" 2>/dev/null; then
      run podman rm -f "${name}" >/dev/null
    fi
  done
  for distro in debian ubuntu fedora arch; do
    name="localhost/d3-${distro}"
    if podman image exists "${name}" 2>/dev/null; then
      run podman rmi -f "${name}" >/dev/null
    fi
  done
}

remove_base_images() {
  local image
  for image in "${PODMAN_BASE_IMAGES[@]}"; do
    if podman image exists "${image}" 2>/dev/null; then
      run podman rmi -f "${image}" >/dev/null
    fi
  done
}

if [[ "${DRYRUN}" == false ]]; then
  [[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"
  command -v podman >/dev/null 2>&1 || die "podman is not installed"
fi

if [[ "${CLEANUP}" == true ]]; then
  log "removing d3-* containers, images and the base images"
  remove_all
  remove_base_images
  exit 0
fi

if [[ "${DRYRUN}" == false ]]; then
  [[ -x "${STAGE}/detent" ]] || die "missing ${STAGE}/detent (cross-build it; never compile here)"
  [[ -x "${STAGE}/d3-inside.sh" ]] || die "missing ${STAGE}/d3-inside.sh"
  [[ -f "${STAGE}/packaging/install.sh" ]] || die "missing ${STAGE}/packaging/install.sh"
fi

# --- one distro -----------------------------------------------------------------

run_distro() {
  local distro="$1" name="d3-$1" ctx inside_args=()
  log "${distro}: image"
  ctx="$(mktemp -d /tmp/d3-build.XXXXXX)"
  containerfile "${distro}" >"${ctx}/Containerfile"
  if [[ "${DRYRUN}" == true ]]; then
    log "would build ${name} from:"
    cat "${ctx}/Containerfile"
  elif ! podman build --network=host -t "${name}" "${ctx}" >"${STAGE}/results/build-${distro}.log" 2>&1; then
    tail -n 15 "${STAGE}/results/build-${distro}.log" >&2
    rm -rf "${ctx}"
    echo "${RED}FAIL${NC} the ${distro} image did not build (log: results/build-${distro}.log)" >&2
    return 1
  fi
  rm -rf "${ctx}"
  log "${distro}: container"
  run podman run -d --name "${name}" --cap-add=ALL --cap-drop=SYS_TIME \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --security-opt label=disable --network=none --systemd=always \
    -v "${STAGE}:/stage" "localhost/${name}" >/dev/null
  if [[ -n "${ONLY}" ]]; then
    inside_args+=(--only "${ONLY}")
  fi
  if [[ "${VERBOSE}" == true ]]; then
    inside_args+=(--verbose)
  fi
  if [[ "${DRYRUN}" == true ]]; then
    inside_args+=(--dryrun)
  else
    sleep 6
  fi
  log "${distro}: checks"
  run podman exec "${name}" /stage/d3-inside.sh --distro "${distro}" \
    ${inside_args[@]+"${inside_args[@]}"} || true
  if [[ "${KEEP}" == false ]]; then
    run podman rm -f "${name}" >/dev/null
    run podman rmi -f "localhost/${name}" >/dev/null
  fi
}

if [[ "${DRYRUN}" == false ]]; then
  mkdir -p "${STAGE}/results"
fi
IFS=',' read -r -a LIST <<<"${DISTROS}"
FAILED_BUILDS=()
for distro in "${LIST[@]}"; do
  if ! run_distro "${distro}"; then
    FAILED_BUILDS+=("${distro}")
  fi
done

if [[ "${KEEP}" == false ]]; then
  remove_all
  remove_base_images
fi

if [[ "${DRYRUN}" == false ]]; then
  for distro in "${LIST[@]}"; do
    if [[ -f "${STAGE}/results/${distro}.tsv" ]]; then
      log "${distro}: $(grep -c $'\tPASS\t' "${STAGE}/results/${distro}.tsv") PASS," \
        "$(grep -c $'\tFAIL\t' "${STAGE}/results/${distro}.tsv") FAIL," \
        "$(grep -c $'\tNT\t' "${STAGE}/results/${distro}.tsv") NT"
    fi
  done
fi
if [[ ${#FAILED_BUILDS[@]} -gt 0 ]]; then
  echo "${RED}builds failed:${NC} ${FAILED_BUILDS[*]}" >&2
  exit 2
fi
echo "${GREEN}done${NC}"
