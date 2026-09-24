# packaging/

Linux packaging for detent (PLAN §2.4, §2.10, Phase 2 "Packaging" deliverable).
**macOS gets no service files in v1** — per PLAN §1.6, macOS is a tier-1
host/dev platform (the binary builds and runs there), but service control and
Linux sandboxing (`systemd`, Landlock, seccomp, sysusers.d, tmpfiles.d,
polkit) are Linux-only. `install.sh` only performs a real install on Linux;
elsewhere it works in `--dryrun` or `--prefix` mode only (see below), which is
how it is exercised in CI/dev on macOS.

FreeBSD rc scripts and OpenRC init scripts are deferred (Phase 11, parked per
PLAN §1.6) and are intentionally not present here yet.

## Files

| Path | Purpose |
|---|---|
| `systemd/detent.service` | The monitor unit, **root-confined** privilege mode (ADR-001 default). `User=root`, confined via capability bounding set, Landlock, seccomp, and the systemd sandboxing directives in PLAN §2.4/Appendix C. |
| `systemd/detent.service.d/capability-user.conf` | Drop-in for the **capability-user** hardened mode (Phase 12): switches to `User=detent` with ambient capabilities instead of root, adds `RemoveIPC=yes`. Only installed with `--mode capability-user`. |
| `sysusers.d/detent.conf` | Creates the unprivileged `detent` system user (`systemd-sysusers`). |
| `tmpfiles.d/detent.conf` | Creates `/var/lib/detent` (0700 detent:detent), `/var/lib/detent/backups` and `/run/detent/staging` (0700 root:root monitor-only), plus `/etc/detent` (0750 root:detent) (`systemd-tmpfiles --create`). The capability-user drop-in hands the runtime tree to `detent` before startup. |
| `polkit/50-detent.rules` | polkit JS rule granting the `detent` user `org.freedesktop.systemd1.manage-units` (start/stop/restart/reload only) for an explicit unit allow-list. Only takes effect in capability-user mode (root already bypasses polkit); harmless to install unconditionally. |
| `install.sh` | Installs/uninstalls the above plus the `detent` binary. |

## Install / uninstall

```bash
# Root-confined mode (default, ADR-001)
sudo packaging/install.sh --binary ./target/release/detent

# Capability-user mode (Phase 12 hardened; also installs the polkit rule's
# prerequisite drop-in)
sudo packaging/install.sh --binary ./target/release/detent --mode capability-user

# Remove everything install.sh placed
sudo packaging/install.sh --uninstall
```

`install.sh --dryrun` prints the plan without making changes.
`install.sh --prefix <dir>` places files under `<dir>` (DESTDIR-style) and
skips every `systemctl`/`systemd-sysusers`/`systemd-tmpfiles` call — this is
what makes packaging testable unprivileged, including on macOS. See
`install.sh --help` for the full flag reference.

After a real install: `systemd-sysusers`, `systemd-tmpfiles --create`, and
`systemctl daemon-reload` are run automatically, then the script prints the
next step (`detent setup`). Enabling/starting the service
(`systemctl enable --now detent`) is left to the operator, matching
`install.sh` not assuming the config (`/etc/detent/detent.toml`) exists yet.

## Verifying the systemd hardening score

PLAN §2.4 (revised by `docs/spikes/02-sandbox.md`) targets
`systemd-analyze security` exposure **≤ 2.5** in root-confined mode and
**≤ 1.8** in capability-user mode. Measure offline, no running systemd needed:

```bash
docker run --rm -v "$PWD/packaging:/p" fedora:latest bash -c '
  dnf install -y -q systemd >/dev/null 2>&1
  mkdir -p /r/etc/systemd/system/detent.service.d
  cp /p/systemd/detent.service /r/etc/systemd/system/
  echo "=== root-confined ==="
  systemd-analyze security --offline=true --root=/r detent.service | tail -5
  echo "=== capability-user ==="
  cp /p/systemd/detent.service.d/capability-user.conf /r/etc/systemd/system/detent.service.d/
  systemd-analyze security --offline=true --root=/r detent.service | tail -5
'
```

Measured at the time this packaging was written: **2.5** (root-confined),
**1.8** (capability-user). Both meet the target exactly. The residual findings
in both modes are structural and are *not* fixable without breaking the
daemon (a network daemon that forks an unprivileged worker and writes
root-owned files) — see the comments in `systemd/detent.service` for exactly
which directives were deliberately not added and why:
`PrivateNetwork=`, `PrivateUsers=`, `IPAddressDeny=`, and `User=root` in
root-confined mode all carry fixed weight that cannot be removed while
detent still reaches the LAN, changes UID to spawn the worker, and manages
files it does not own.

`SystemCallFilter=` appears twice in `detent.service` (`@system-service` then
`~@resources`) — this is the one intentional repeated key in the file. It is
systemd's documented idiom for "allow-list, then subtract a named set from
it": a `~`-prefixed token mixed into an otherwise-positive `SystemCallFilter=`
line is silently ignored, so the subtraction must be its own assignment.
`~@privileged` was deliberately **not** subtracted even though
`systemd-analyze` scores it, because `@privileged` includes the `chown()`
family (needed to preserve file ownership in the atomic write protocol) and
`setuid`/`setreuid`/`setresuid`/`setgroups` (needed by the monitor to drop
the forked worker to uid `detent`) — removing it breaks the daemon.
