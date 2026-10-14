# D3: Phase 7 and Phase 8 acceptance in containers

Date: 2026-10-14. BUGFIX Track D item 3. Owner decision 2026-10-14: run the
per-module acceptance (PLAN Phase 7) and the network matrix (PLAN Phase 8) in
containers on the test host, no VMs. Build under test: `0.1.1` from `59fb2eb`
(`cargo zigbuild --locked --release -p detent --target
x86_64-unknown-linux-musl`, default features, built off the test host).

Nothing in `crates/` changed. Every fault below is recorded as a BUGFIX item
(Track D 4 to 12) with the exact output. No fault was fixed here.

## Method

- Tool: rootful `podman` 5.8, installed for this run and removed after it
  (see "Test host changes").
- One container per distro, systemd as PID 1: `debian:stable` (13, systemd
  257), `ubuntu:latest` (26.04, systemd 259), `fedora:latest` (44, systemd
  259), `archlinux:latest` (systemd 262). The image adds the backend packages
  of each module (chrony, samba, nfs-utils, unbound, dnsmasq, kea,
  systemd-resolved, the distro network stack) and nothing else.
- Isolation: `--network=none` (private network namespace, loopback only; the
  image build uses the host network for the package download only), all
  capabilities except `CAP_SYS_TIME` (a container must not touch the host
  clock), no seccomp or AppArmor profile (systemd and the network tools need
  that). The host network was not configured. The checks add a veth pair
  inside the container namespace (`mgmt0`, with `peer0` in the namespace
  `d3peer`) so a bad address change cuts a real path.
- detent is installed with `packaging/install.sh` (root-confined mode) and
  runs as the packaged `detent.service`. The CLI runs for `get`, `validate`,
  `plan` and for `apply` of the modules without commit-confirm (chrony, samba,
  nfs). The commit-confirm modules (resolver, mounts, dhcp, network) apply
  through `POST /api/v1/modules/<id>/apply` with `confirm_secs`, as the CLI
  refuses them.
- Scripts: `spikes/d3-containers.sh` (image, container, cleanup) and
  `spikes/d3-inside.sh` (the checks). Results: one tab-separated row per
  check (`PASS`, `FAIL`, `NT` not testable in a container, `INFO`).
- Workarounds are never a pass. When an apply is blocked by a fault, the
  script records the `FAIL`, then applies a labelled workaround (a validator
  replaced by a stub that exits 0, a missing target file copied in, a unit
  drop-in) so the code after the fault can still be exercised. Rows after a
  workaround say what was done.

## Matrix

Counts are `PASS / FAIL / NT` of the checks of that module in that container
(INFO rows left out). A module with a `FAIL` row is not accepted; the notes
name the fault.

| Module | Debian 13 | Ubuntu 26.04 | Fedora 44 | Arch |
|---|---|---|---|---|
| host (install, `doctor`, veth) | 3 / 1 / 0 | 3 / 1 / 0 | 3 / 1 / 0 | 3 / 1 / 0 |
| chrony | 5 / 3 / 1 | 5 / 3 / 1 | 5 / 4 / 1 | 6 / 1 / 1 |
| samba | 7 / 0 / 0 | 7 / 0 / 0 | 7 / 0 / 0 | 6 / 1 / 0 |
| nfs | 6 / 0 / 0 | 6 / 0 / 0 | 5 / 0 / 1 | 5 / 0 / 1 |
| resolver | 10 / 4 / 0 | 10 / 4 / 0 | 11 / 4 / 0 | 0 / 2 / 0 |
| mounts | 10 / 0 / 1 | 10 / 0 / 1 | 10 / 0 / 1 | 10 / 0 / 1 |
| dhcp | 10 / 5 / 0 | 10 / 5 / 0 | 4 / 10 / 0 | 11 / 4 / 0 |
| network | 16 / 10 / 0 | 8 / 9 / 0 | 4 / 5 / 0 | 8 / 9 / 0 |

Notes by module (the `FAIL` rows, with the BUGFIX item):

- host: `order`. A root CLI write before `serve` ever ran leaves the audit
  log root-owned; the first API apply then answers `500 ops-audit-unavailable`
  (D4). The script repairs the directory and goes on. `doctor` also warns
  `landlock: /sys/kernel/security/lsm: No such file or directory`: securityfs
  is not mounted in a container (not testable here).
- chrony: the stock file is refused. Debian, Ubuntu and Fedora ship
  `sourcedir`/`confdir`; `validate` prints the errors and exits 0, `plan` and
  `apply` exit 1 (D9). With those lines removed the apply works. Fedora and
  Arch keep the file at `/etc/chrony.conf`, a path the module does not read:
  `get` answers `"model":null` and exits 0 (D8); the checks copied the file
  to `/etc/chrony/chrony.conf` to go on. Service: `NT`, the unit's
  `ConditionCapability=CAP_SYS_TIME` is unmet by design.
- samba: all green on Debian, Ubuntu, Fedora. Arch ships no `smb.conf`; a
  minimal one was created. After the apply `smb.service` is not active on Arch
  (not explained; `testparm -s` accepts the file).
- nfs: all green on Debian and Ubuntu (the export is listed by
  `exportfs -v`). Fedora: `exportfs: /srv/d3 does not support NFS export`
  (probably the overlay root file system of the container, not a detent fault; not isolated); Arch:
  `nfsdctl: Error: Invalid argument`. Both are `NT`.
- resolver: the apply is blocked three times over (D5, D6, D7): the
  `unbound-checkconf` validator runs on `resolved.conf` and fails; with it
  stubbed the monitor cannot write `resolved.conf` (read-only under the
  packaged unit); with that fixed by a drop-in the apply, the file check and
  the rollback pass, but a model edit for unbound lands in `resolved.conf`.
  Fedora and Arch have no `/etc/systemd/resolved.conf` (D8); Fedora got the
  vendor file copied in. On Arch the vendor file is absent too, so nothing
  could be tested.
- mounts: all green, including `scripts/mounts-activation-check.sh` (20 checks)
  and the rollback with a byte-identical `/etc/fstab`. `x-systemd.automount`
  is `NT`: `Starting of mnt-detent\x2dcheck-auto.automount unsupported`.
- dhcp: dnsmasq works once the Kea validators are stubbed (D5). Kea cannot be
  edited at all (D7). Fedora's stock `dnsmasq.conf` has `conf-dir` and is
  refused (D9). `kea-dhcp4 -t` cannot open any file as root in the container
  (D12).
- network: see the next section.

## Network and the rollback test

Per container the script runs the distro's own flavour (Debian: ifupdown and
NetworkManager; Ubuntu: netplan; Fedora: NetworkManager; Arch: networkd), then
once more with the probed non-network services hidden (see D7).

Baseline: `mgmt0` is set to `192.0.2.1/24`; `peer0` pings it. Then the
deliberate misconfiguration: apply `198.51.100.1/24` with a 60 s window
(`confirm_secs: 60`, the API form of `--confirm 60s`; the CLI refuses a
commit-confirm module and says so: PASS on every distro). Nobody confirms.

| Container | Baseline apply | Bad address effective | File rolled back | Live state restored |
|---|---|---|---|---|
| Debian, ifupdown | needs validator stubs (D5); file written | yes, after a manual `ifup` (peer0 cannot ping) | yes, 61 s after the apply | no (D11) |
| Debian, NetworkManager | same as above: the file is `/etc/network/interfaces` (D7) | not testable: the baseline never went live | yes, 61 s | no |
| Ubuntu, netplan | needs all validators stubbed (D5); file `/etc/network/interfaces` | not testable (no `ifup` in the image) | yes, 62 s | no |
| Fedora, NetworkManager | not applied: `ops-privsep-failed`, `no known unit name resolved on this host (tried ["systemd-networkd.service"])` (D11) | no | not applicable | not applicable |
| Arch, networkd | needs all validators stubbed (D5); file `/etc/network/interfaces` | not testable (no `ifup` in the image) | yes, 61 s | no |

Result of the rollback test (the Phase 8 acceptance line): **commit-confirm
works as a file mechanism.** On four of five flavours the monitor restored
the target file byte for byte (hash equal to the baseline) 61 to 62 s after
the apply, with no confirm, for a 60 s window. A late confirm answers
`409`. On Debian ifupdown the bad config really cut the path (`mgmt0` held
`198.51.100.1/24`, `peer0` could not ping `192.0.2.1`). **The live state was
not restored**: the rollback replays the service action of the apply, which
is `systemd-networkd.service` for every flavour, so ifupdown never re-read the
restored file (`mgmt0@if2 UP 198.51.100.1/24` after the rollback). A manual
`ifdown/ifup` then restored the path, so the restored file is right.

The Phase 8 acceptance (rollback demonstrated on each of the four tier-1
stacks) is therefore not met: only the Debian ifupdown flavour could be taken
all the way, and its live-state result is `FAIL`.

## Not testable in a container

- `x-systemd.automount` units: `Starting of ...automount unsupported`.
- Service state of `chrony`: `CAP_SYS_TIME` is dropped on purpose.
- `nfs-server` on Fedora and Arch: `exportfs: /srv/d3 does not support NFS
  export` (overlay root), `nfsdctl: Error: Invalid argument`.
- Landlock status in `doctor`: `/sys/kernel/security/lsm` is absent.
- A real NetworkManager, netplan and networkd link: the veth pair stood in; on
  Ubuntu, Arch and Fedora the module wrote to `/etc/network/interfaces` (D7),
  so those backends were never driven by detent.
- DHCP serving on a real LAN, upstream-watch, any reboot behaviour, and
  `sysctl` or firewall effects.

VM-only work that remains: the same runs on a VM with real links and a kernel
the tests may load modules into; the live-state rollback for netplan,
NetworkManager and networkd (blocked by D7 and D11 until the module writes
the right files); the Landlock status line; automount; `chrony` serving time.

## Reproduce

Cross-build, copy `detent`, `packaging/`, `scripts/mounts-activation-check.sh`
and the two scripts into one directory on the test host, then:

    sudo spikes/d3-containers.sh --stage <dir>            # all four distros
    sudo spikes/d3-containers.sh --stage <dir> --distro debian --only network
    sudo spikes/d3-containers.sh --cleanup                # containers, images

Results land in `<dir>/results/<distro>.tsv`, raw command output in
`<dir>/results/<distro>.d/`. A full run takes about 25 minutes.

## Test host changes

Installed (apt, `--no-install-recommends`): `podman crun passt uidmap`, with
the dependencies apt added: `netavark libyajl2 golang-github-containers-image
libsubid5 conmon golang-github-containers-common`. Removed again with
`apt-get purge` of the same ten packages, `podman system reset`, and removal of
`/var/lib/containers`, `/etc/containers` and `/run/containers`. All containers,
images and the staging directories were removed; `apt-get autoremove -s`
lists nothing; no detent binary, unit, `/etc/detent` or `/run/detent` is left;
`/var/lib/detent` holds only `monitor.lock`; the `detent` account is kept.
