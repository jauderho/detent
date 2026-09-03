# Spike 3 — Linux sandbox (Landlock, seccomp, caps) and `systemd-analyze security`

**Date:** 2026-09-03 · Binary under test: `spikes/xbuild` built for
`aarch64-unknown-linux-musl` with `crypto-aws-lc` (see `docs/spikes/00-cross-build.md`),
2 906 408 bytes, statically linked, stripped.

## Kernel caveat — read this first

The task brief assumed Docker Desktop. This host actually runs **OrbStack**, so
every container in this spike executed on OrbStack's Linux VM kernel:

```
$ docker info --format '{{.Architecture}} {{.KernelVersion}} {{.OperatingSystem}}'
aarch64 7.0.14-orbstack-00380-ga7e0a2dc9535 OrbStack
```

That is a modern 7.0 kernel with everything enabled. It is **not** representative
of a Raspberry Pi OS or an SBC vendor kernel, which are the cases that actually
matter for the Landlock-availability risk in PLAN §7. Nothing here tells us how
detent behaves on a kernel *without* Landlock, or with Landlock ABI 1 only.
**Those must be re-checked on real boards / a Pi kernel in Phase 2 privileged CI.**
The `debian:bookworm` and `fedora:latest` images differ only in userland; both
saw the identical kernel, so the two rows below are not two independent data points
for anything kernel-level.

## Setup (exact commands)

`sandbox-probe` and `seccomp-allowlist` subcommands were implemented in
`spikes/xbuild/src/main.rs`.

```bash
docker run --rm --privileged -v <bin>:/x:ro debian:bookworm sh -c 'uname -r; /x sandbox-probe'
docker run --rm --privileged -v <bin>:/x:ro fedora:latest   sh -c 'uname -r; /x sandbox-probe'
docker run --rm             -v <bin>:/x:ro debian:bookworm /x sandbox-probe   # unprivileged
docker run --rm --privileged -v <bin>:/x:ro debian:bookworm sh -c '/x seccomp-allowlist; echo "exit=$?"'
docker run --rm --privileged -v <bin>:/x:ro fedora:latest   sh -c '/x seccomp-allowlist; echo "exit=$?"'
```

What each check does:

- **Landlock ABI probe** — `Ruleset::default().set_compatibility(HardRequirement)
  .handle_access(AccessFs::from_all(abi)).create()` for `ABI::V1..V5`, reporting the
  highest that succeeds.
- **Landlock enforcement** — ruleset handling `AccessFs::from_all(ABI::V1)`, granting
  full access beneath `/tmp/allowed` and read-only beneath `/`, then `restrict_self()`.
  Then writes `/tmp/allowed/ok.txt` (must succeed) and `/tmp/denied/no.txt` (must fail).
- **`PR_SET_NO_NEW_PRIVS`** — raw `prctl(38, 1, 0, 0, 0)`.
- **Capability bounding set** — `caps::read(None, Bounding)`, then `caps::drop` for
  everything except `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER` (the §2.4 minimum).
- **seccomp (deny-list form)** — `seccompiler` filter, default `Allow`, `ptrace`
  → `Errno(EPERM)`; then a raw `syscall(__NR_ptrace, 0,0,0,0)`.
- **seccomp (true allow-list form)** — `seccompiler` filter with 36 allowed
  aarch64 syscall numbers, **default action `Trap`**; then `ptrace`, which is not
  on the list, so the process must die of `SIGSYS` (shell exit 159 = 128 + 31).

## Results

### `sandbox-probe`, `debian:bookworm`, `--privileged`, uid 0

```
uname: 7.0.14-orbstack-00380-ga7e0a2dc9535
landlock: highest supported ABI = 5
no_new_privs: OK
landlock enforce: FullyEnforced
write /tmp/allowed/ok.txt: OK (expected OK)
write /tmp/denied/no.txt: ERR PermissionDenied raw=Some(13) (expected PermissionDenied)
caps bounding: 41 -> 3 OK
seccomp: filter installed OK (ptrace -> EPERM)
ptrace after seccomp: DENIED rc=-1 errno=Operation not permitted (os error 1)
SANDBOX PROBE DONE
```

### `sandbox-probe`, `fedora:latest` (Fedora 44), `--privileged`, uid 0

Byte-identical output except the release string, including `caps bounding: 41 -> 3 OK`.

### `sandbox-probe`, `debian:bookworm`, **no** `--privileged`

Identical, except `caps bounding: 14 -> 3 OK` (Docker's default bounding set is 14
capabilities, not 41). Landlock, `no_new_privs` and seccomp all still worked under
Docker's default seccomp profile — useful for CI, since the sandbox tests do not
need a privileged runner.

### Summary table

| Check | debian:bookworm (priv) | fedora:44 (priv) | debian (unpriv) |
|---|---|---|---|
| `uname -r` | 7.0.14-orbstack-… | 7.0.14-orbstack-… | 7.0.14-orbstack-… |
| Landlock highest ABI | **5** | **5** | **5** |
| Landlock ruleset enforce | `FullyEnforced` | `FullyEnforced` | `FullyEnforced` |
| write `/tmp/allowed` | allowed | allowed | allowed |
| write `/tmp/denied` | **EACCES (errno 13)** | **EACCES (errno 13)** | **EACCES (errno 13)** |
| `PR_SET_NO_NEW_PRIVS` | OK | OK | OK |
| caps bounding drop → 3 | 41 → 3 OK | 41 → 3 OK | 14 → 3 OK |
| seccomp deny-list installs | OK | OK | OK |
| `ptrace` after deny-list | EPERM (rc −1) | EPERM (rc −1) | EPERM (rc −1) |
| seccomp allow-list installs | OK | OK | not run |
| `ptrace` after allow-list | **SIGSYS, exit 159** | **SIGSYS, exit 159** | not run |

Everything the plan needs on Linux works, unmodified, on both distros, from a
single statically-linked musl binary, with no glibc and no runtime dependency.

### `systemd-analyze security --offline=true`

`spikes/sandbox/detent.service` is PLAN Appendix C verbatim, plus the `[Unit]`
and `[Install]` sections it omits. Run under `fedora:latest`, `systemd 259 (259.8-1.fc44)`:

```bash
docker run --rm -v ./spikes/sandbox:/s:ro fedora:latest sh -c '
  dnf install -y systemd >/dev/null 2>&1
  mkdir -p /r/etc/systemd/system && cp /s/detent.service /r/etc/systemd/system/
  systemd-analyze security --offline=true --root=/r detent.service'
```

Offline analysis works; no running systemd is needed.

```
→ Overall exposure level for detent.service: 2.9 OK :-)
```

**Top findings by weight (the whole ✗ set, ordered):**

| Weight | Setting | Finding |
|---:|---|---|
| 0.5 | `PrivateNetwork=` | Service has access to the host's network |
| 0.4 | `User=`/`DynamicUser=` | Service runs as root user |
| 0.3 | `RestrictAddressFamilies=~AF_(INET\|INET6)` | Service may allocate Internet sockets |
| 0.3 | `CapabilityBoundingSet=~CAP_SET(UID\|GID\|PCAP)` | Service may change UID/GID identities |
| 0.2 | `CapabilityBoundingSet=~CAP_(DAC_*\|FOWNER\|IPC_OWNER)` | May override file/IPC permission checks |
| 0.2 | `CapabilityBoundingSet=~CAP_(CHOWN\|FSETID\|SETFCAP)` | May change file ownership/mode |
| 0.2 | `SystemCallFilter=~@privileged` | `@system-service` includes `@privileged` |
| 0.2 | `ProtectClock=` | May write the hardware/system clock |
| 0.2 | `ProtectProc=` | Full access to the process tree |
| 0.2 | `PrivateUsers=` | Access to other users |
| 0.2 | `IPAddressDeny=` | No IP address allow list |
| 0.1 each | `ProtectHostname=`, `ProcSubset=`, `CAP_KILL`, `AF_UNIX`, `AF_NETLINK`, `RootDirectory=` | |

**The §2.4 acceptance criterion of ≤ 2.0 is not met by Appendix C as written (2.9),
and cannot be met in `privilege.mode = "root-confined"`.** Two further variants were
measured to find out how close it can get:

| Unit | Added | Score |
|---|---|---:|
| `spikes/sandbox/detent.service` (Appendix C) | — | **2.9** |
| `spikes/sandbox/detent-hardened.service` | `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectProc=invisible`, `ProcSubset=pid`, `PrivateUsers=self`, `IPAddressDeny=any` + `IPAddressAllow=localhost`, `SystemCallFilter=@system-service ~@privileged` | **2.3** |
| `spikes/sandbox/detent-capuser.service` | the above, plus `User=detent` and `CapabilityBoundingSet`/`AmbientCapabilities` = `CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER` (i.e. §2.4's `privilege.mode = "capability-user"`) | **1.6** |

The residual 2.3 in root-confined mode is structural: `PrivateNetwork` 0.5 +
`User=root` 0.4 + `AF_INET` 0.3 + `CAP_SETUID/SETGID` 0.3 are all *required* by what
detent is (a network daemon that forks an unprivileged worker), and together they
already exceed 1.5. Dropping to `capability-user` removes the `User=` 0.4 and the
`CAP_SET(UID|GID|PCAP)` 0.3 and lands at **1.6**.

`SystemCallFilter=@system-service ~@privileged` scored *worse* on one line in the
hardened variant (it added a `@resources` 0.2 finding) — the `~` subtraction changes
how systemd classifies the list. Worth a second look before adopting it.

## Conclusion

**Minimum Landlock ABI to require: ABI 1 (kernel 5.13).** Every restriction §2.4
actually asks for — confine writes to a fixed set of directories, read-only
elsewhere — is expressible with `AccessFs::from_all(ABI::V1)`, and that is what was
demonstrated (`FullyEnforced`, denied write returns `EACCES`). ABI 5 is available
here but nothing in the plan needs V2+ (refer/rename, truncate, IPC/network scoping)
for v1. Detent should *probe* for the highest ABI at startup and use it with
`CompatLevel::BestEffort`, but *require* only ABI 1.

**Fallback behaviour when Landlock is absent or below ABI 1:** do not fail to start.
Log a structured warning once at startup with the detected ABI, surface it as a
degraded item in `detent doctor` and in the web UI's health panel, and continue with
`PR_SET_NO_NEW_PRIVS` + capability bounding-set drop + seccomp — all three of which
were demonstrated working independently of Landlock, including in an unprivileged
container. Make it a hard failure only under an explicit
`privilege.require_landlock = true` config knob for operators who want it.

**Unit score: 2.9 for Appendix C as written; 2.3 achievable in root-confined mode;
1.6 in capability-user mode.** §2.4's "≤ 2.0" acceptance criterion should be
restated as **≤ 2.3 for `root-confined` and ≤ 1.6 for `capability-user`**, or it will
block Phase 2 on something arithmetically impossible.

## Open questions for the orchestrator

1. §2.4 says `systemd-analyze security detent.service ≤ 2.0`. Confirm the revised
   split target (2.3 / 1.6) and which mode CI gates on. Appendix C should absorb
   the six extra directives that took it from 2.9 to 2.3; they cost nothing.
2. `PrivateDevices=yes` in Appendix C already has a caveat comment for TPM/PPS.
   The capuser variant also picked up a `DeviceAllow=` 0.1 finding for `char-rtc:r`.
   Worth deciding now whether chrony's PPS refclock support forces `PrivateDevices=no`,
   because that changes the score again.
3. **Nothing here was tested on a Landlock-less or ABI-1-only kernel.** The
   recommended minimum (ABI 1) and the degrade path are reasoned, not measured.
   Phase 2 privileged CI must add a Raspberry Pi OS kernel and ideally one 5.10-era
   kernel with no Landlock at all.
4. The seccomp allow-list used here is a hand-written 36-entry aarch64 list, tuned
   only far enough to reach `ptrace`. The real monitor/worker allow-lists will need
   to be derived properly (per-arch tables; `strace`-derived, then tested under
   `SCMP_ACT_LOG`), and the arch tables differ between aarch64, x86_64, armv7 and
   riscv64 — four tables, not one.
5. FreeBSD/Capsicum was not exercised at all (no FreeBSD host available). §2.4's
   `cap_enter()` path remains entirely unverified.
