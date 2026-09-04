# Milestone M1 — a headless operator edits a real box

**Date:** 2026-09-04 · **Phase 3 task 4** (`docs/PLAN.md` §5, Phase 3) ·
**Acceptance:** `detent config hosts apply` edits a real `/etc/hosts` safely, with
validation, a backup, a restore, and an audit trail.

**Host:** macOS 15 (Darwin 25.6.0), Apple Silicon, Docker 29.4.0 (OrbStack).
**Guest:** `rust:1-bookworm`, Debian 12, aarch64, rustc 1.98.0 (88d9e12ae 2026-08-18)
as pinned by `rust-toolchain.toml`. Running as **root** inside the container.

## How to reproduce

```bash
mkdir -p /tmp/m1-target
docker run --rm -i --cap-add SYS_ADMIN \
  -v "$PWD:/src" -v /tmp/m1-target:/tmp/target -w /src \
  rust:1-bookworm bash -s < m1.sh
```

Two deviations from the plain `docker run --rm -v "$PWD:/src" -w /src rust:1-bookworm`
of the task, both forced by the container and both visible in the transcript:

1. **`--cap-add SYS_ADMIN`, and `umount /etc/hosts` as the first step.** Docker
   bind-mounts `/etc/hosts` from the host. `detent`'s atomic write protocol
   (`detent_platform::fs::atomic`, PLAN §2.4) writes a temporary file next to the
   target and `rename(2)`s it into place, and renaming **over a bind mount** fails
   with `EBUSY` — the first run of this demo ended in
   `i/o error: renameat: resource busy`, with `/etc/hosts` correctly left untouched.
   Unmounting it turns `/etc/hosts` back into an ordinary file, which is what it is
   on a real box. The failure is a property of Docker, not of `detent`: the write
   was refused, nothing was half-applied, and the audit log recorded the failure.
2. **`CARGO_TARGET_DIR=/tmp/target`** (mounted from the host so a re-run does not
   rebuild), so the container never writes into the repository's own `target/`.

## What this demonstrates

| M1 requirement | Where in the transcript |
|---|---|
| the CLI runs on a real box | `=== environment`, `=== build` |
| host and build introspection | `detent doctor`, `detent host --json` |
| read the current configuration | `detent config hosts get` |
| validation before anything is written | `detent config hosts validate` (twice) |
| a preview that writes nothing | `detent config hosts plan`, `apply --dryrun` |
| a real edit of `/etc/hosts` | `detent config hosts apply` |
| a backup was kept | `find /var/lib/detent`, `detent backup list hosts` |
| the change can be reverted | `detent backup restore hosts 0` |
| every mutation is audited | `detent audit`, `detent audit --json` |
| optimistic concurrency | `apply --expect-hash 0000…` |
| the documented exit codes | `=== exit codes` (0, 1, 2) and `serve` (3) |
| the privsep process model really forks | `detent --verbose serve` |

### Findings worth keeping

* **The stock `/etc/hosts` is invalid by the module's rules.** Debian ships
  `localhost` as the canonical name of both the `127.0.0.1` and the `::1` entry,
  and `hosts-duplicate-canonical` is an *error* — see
  `detent config hosts validate < /tmp/model.json` in the transcript. An earlier
  run of this demo, which changed nothing else, therefore had its `apply` refused
  with `ops-invalid-model` and exit 1 **before the file was opened**. The demo
  model consequently also fixes that entry, which is exactly the workflow the
  module exists for. Validation gating writes is not theoretical.
* **Landlock is unavailable on this kernel/container** (`/sys/kernel/security/lsm`
  does not exist), and `doctor` reports it as a warning rather than a failure, per
  PLAN §2.4's "warn once, mark degraded, continue". seccomp is available.
* **`serve` needs the `detent` account.** Without it the pair cannot be created
  and the CLI exits **3** (a privilege problem), with a localized message. With
  `useradd --system detent` the fork works: the worker drops privileges
  (`privileges dropped: 1`), completes the handshake, and both halves exit 0.
* `commit rollback` reaches the monitor and reports `unknown commit id 1`, because
  no commit was armed — the `hosts` module does not set `commit_confirm`.

## The script

```bash
#!/usr/bin/env bash
# M1 acceptance demo: a headless operator edits a real /etc/hosts safely.
set -u
export CARGO_TARGET_DIR=/tmp/target
export CARGO_TERM_COLOR=never
cd /src

D=/tmp/target/debug/detent

run() {
  echo
  echo "\$ $*"
  "$@"
  echo "[exit $?]"
}

run_in() {
  local input="$1"; shift
  echo
  echo "\$ $* < $input"
  "$@" <"$input"
  echo "[exit $?]"
}

echo "=== environment"
run cat /etc/os-release
run id
run uname -srm

echo
echo "=== docker bind-mounts /etc/hosts, and rename(2) over a bind mount is EBUSY;"
echo "=== atomic replacement needs an ordinary file, so unmount it and seed one"
run sh -c 'mount | grep /etc/hosts'
run umount /etc/hosts
cat >/etc/hosts <<'HOSTS'
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::	ip6-localnet
ff00::	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
HOSTS
run chmod 0644 /etc/hosts
run ls -l /etc/hosts

echo
echo "=== build"
cargo build -q -p detent 2>&1 | tail -5
run "$D" --version

echo
echo "=== doctor"
run "$D" doctor

echo
echo "=== the file before anything happens"
run cat /etc/hosts
run sha256sum /etc/hosts

echo
echo "=== read the model"
"$D" config hosts get >/tmp/model.json
run cat /tmp/model.json

echo
echo "=== validate what is already there"
run_in /tmp/model.json "$D" config hosts validate

echo
echo "=== a changed model: add one entry, and fix the duplicate canonical name"
sed -e '0,/"entries": \[/s//"entries": [\n    {\n      "ip": "192.0.2.10",\n      "hostnames": [\n        "detent-demo"\n      ],\n      "comment": "added by the m1 demo"\n    },/' \
    -e '/^        "localhost",$/d' /tmp/model.json >/tmp/next.json
run head -20 /tmp/next.json
run_in /tmp/next.json "$D" config hosts validate

echo
echo "=== plan (writes nothing)"
run_in /tmp/next.json "$D" config hosts plan
run_in /tmp/next.json "$D" --verbose config hosts plan

echo
echo "=== dry-run apply (writes nothing)"
run_in /tmp/next.json "$D" config hosts apply --dryrun
run sha256sum /etc/hosts

echo
echo "=== apply for real"
run_in /tmp/next.json "$D" config hosts apply
run cat /etc/hosts
run sha256sum /etc/hosts

echo
echo "=== the backup the monitor kept"
run find /var/lib/detent -type f
run "$D" backup list hosts

echo
echo "=== restore it"
run "$D" backup restore hosts 0
run cat /etc/hosts
run sha256sum /etc/hosts

echo
echo "=== optimistic concurrency: a stale --expect-hash is refused"
run_in /tmp/next.json "$D" config hosts apply --expect-hash 0000000000000000000000000000000000000000000000000000000000000000

echo
echo "=== the audit log"
run "$D" audit
run "$D" audit --json --limit 1

echo
echo "=== other fronts of the same operations layer"
run "$D" service hosts status
run "$D" commit rollback 1
run sh -c '/tmp/target/debug/detent completions bash | head -4'

echo
echo "=== exit codes"
run "$D" config no-such-module get
run "$D" config hosts
run "$D" host --json

echo
echo "=== serve, and its process model"
run timeout 10 "$D" serve --dryrun
run timeout 10 "$D" serve
run useradd --system --no-create-home --shell /usr/sbin/nologin detent
run timeout 30 "$D" --verbose serve
```

## Transcript (verbatim)

```console
=== environment

$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
[exit 0]

$ id
uid=0(root) gid=0(root) groups=0(root)
[exit 0]

$ uname -srm
Linux 7.0.14-orbstack-00380-ga7e0a2dc9535 aarch64
[exit 0]

=== docker bind-mounts /etc/hosts, and rename(2) over a bind mount is EBUSY;
=== atomic replacement needs an ordinary file, so unmount it and seed one

$ sh -c mount | grep /etc/hosts
/dev/vdb1 on /etc/hosts type btrfs (rw,noatime,nodatasum,nodatacow,ssd,discard,space_cache=v2,subvolid=5,subvol=/)
[exit 0]

$ umount /etc/hosts
[exit 0]

$ chmod 0644 /etc/hosts
[exit 0]

$ ls -l /etc/hosts
-rw-r--r-- 1 root root 148 Sep  4 19:25 /etc/hosts
[exit 0]

=== build
info: syncing channel updates for 1.98.0-aarch64-unknown-linux-gnu
info: latest update on 2026-08-20 for version 1.98.0 (88d9e12ae 2026-08-18)
info: downloading 3 components

$ /tmp/target/debug/detent --version
detent 0.0.1
[exit 0]

=== doctor

$ /tmp/target/debug/detent doctor
e25936b8ae1f: linux, init none, 12016 mib of ram
ok modules compiled into this build: hosts
warn state directory /var/lib/detent (absent)
warn configuration file /etc/detent/detent.toml (absent)
ok privilege separation can fork a working pair: pid 72
warn landlock: /sys/kernel/security/lsm: No such file or directory (os error 2)
ok seccomp: kill_process kill_thread trap errno user_notif trace log allow
[exit 0]

=== the file before anything happens

$ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::	ip6-localnet
ff00::	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
[exit 0]

$ sha256sum /etc/hosts
ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580  /etc/hosts
[exit 0]

=== read the model
error: `localhost` is the canonical name of more than one entry.

$ cat /tmp/model.json
{
  "entries": [
    {
      "hostnames": [
        "localhost"
      ],
      "ip": "127.0.0.1"
    },
    {
      "hostnames": [
        "localhost",
        "ip6-localhost",
        "ip6-loopback"
      ],
      "ip": "::1"
    },
    {
      "hostnames": [
        "ip6-localnet"
      ],
      "ip": "fe00::"
    },
    {
      "hostnames": [
        "ip6-mcastprefix"
      ],
      "ip": "ff00::"
    },
    {
      "hostnames": [
        "ip6-allnodes"
      ],
      "ip": "ff02::1"
    },
    {
      "hostnames": [
        "ip6-allrouters"
      ],
      "ip": "ff02::2"
    }
  ]
}
[exit 0]

=== validate what is already there

$ /tmp/target/debug/detent config hosts validate < /tmp/model.json
error: `localhost` is the canonical name of more than one entry.
[exit 0]

=== a changed model: add one entry, and fix the duplicate canonical name

$ head -20 /tmp/next.json
{
  "entries": [
    {
      "ip": "192.0.2.10",
      "hostnames": [
        "detent-demo"
      ],
      "comment": "added by the m1 demo"
    },
    {
      "hostnames": [
        "localhost"
      ],
      "ip": "127.0.0.1"
    },
    {
      "hostnames": [
        "ip6-localhost",
        "ip6-loopback"
      ],
[exit 0]

$ /tmp/target/debug/detent config hosts validate < /tmp/next.json
note: there is no ipv6 `localhost` entry.
[exit 0]

=== plan (writes nothing)

$ /tmp/target/debug/detent config hosts plan < /tmp/next.json
--- /etc/hosts
+++ /etc/hosts
@@ -1,5 +1,6 @@
+192.0.2.10	detent-demo	# added by the m1 demo
 127.0.0.1	localhost
-::1	localhost ip6-localhost ip6-loopback
+::1	ip6-localhost ip6-loopback
 fe00::	ip6-localnet
 ff00::	ip6-mcastprefix
 ff02::1	ip6-allnodes
note: there is no ipv6 `localhost` entry.
[exit 0]

$ /tmp/target/debug/detent --verbose config hosts plan < /tmp/next.json
locale en-US, state root /var/lib/detent, config /etc/detent/detent.toml
running Plan for hosts
--- /etc/hosts
+++ /etc/hosts
@@ -1,5 +1,6 @@
+192.0.2.10	detent-demo	# added by the m1 demo
 127.0.0.1	localhost
-::1	localhost ip6-localhost ip6-loopback
+::1	ip6-localhost ip6-loopback
 fe00::	ip6-localnet
 ff00::	ip6-mcastprefix
 ff02::1	ip6-allnodes
the file now hashes to ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580; pass it as --expect-hash to refuse a racing edit.
note: there is no ipv6 `localhost` entry.
[exit 0]

=== dry-run apply (writes nothing)

$ /tmp/target/debug/detent config hosts apply --dryrun < /tmp/next.json
dry run: this is what would be written to /etc/hosts for hosts.
note: there is no ipv6 `localhost` entry.
dry run: nothing was changed.
--- /etc/hosts
+++ /etc/hosts
@@ -1,5 +1,6 @@
+192.0.2.10	detent-demo	# added by the m1 demo
 127.0.0.1	localhost
-::1	localhost ip6-localhost ip6-loopback
+::1	ip6-localhost ip6-loopback
 fe00::	ip6-localnet
 ff00::	ip6-mcastprefix
 ff02::1	ip6-allnodes
[exit 0]

$ sha256sum /etc/hosts
ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580  /etc/hosts
[exit 0]

=== apply for real

$ /tmp/target/debug/detent config hosts apply < /tmp/next.json
hosts was written to /etc/hosts.
it hashed to ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580 and now hashes to fd14a3d71db7f6b18e853cd12b7822755283a578925cf16ce3cd0706b849730b; backup kept: yes
[exit 0]

$ cat /etc/hosts
192.0.2.10	detent-demo	# added by the m1 demo
127.0.0.1	localhost
::1	ip6-localhost ip6-loopback
fe00::	ip6-localnet
ff00::	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
[exit 0]

$ sha256sum /etc/hosts
fd14a3d71db7f6b18e853cd12b7822755283a578925cf16ce3cd0706b849730b  /etc/hosts
[exit 0]

=== the backup the monitor kept

$ find /var/lib/detent -type f
/var/lib/detent/backups/hosts/0/2026-09-04T19:25:40.058569948Z-ba0a2015
/var/lib/detent/audit/detent-audit.jsonl
[exit 0]

$ /tmp/target/debug/detent backup list hosts
0  2026-09-04T19:25:40.058569948Z-ba0a2015  148 bytes  ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580
[exit 0]

=== restore it

$ /tmp/target/debug/detent backup restore hosts 0
target 0 was put back and now hashes to ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580.
[exit 0]

$ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::	ip6-localnet
ff00::	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
[exit 0]

$ sha256sum /etc/hosts
ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580  /etc/hosts
[exit 0]

=== optimistic concurrency: a stale --expect-hash is refused

$ /tmp/target/debug/detent config hosts apply --expect-hash 0000000000000000000000000000000000000000000000000000000000000000 < /tmp/next.json
`/etc/hosts` changed on disk since it was read; re-read it and try again.
[exit 1]

=== the audit log

$ /tmp/target/debug/detent audit
2026-09-04T19:25:40.085523459Z  uid:0  apply  hosts  error  ops-hash-conflict
2026-09-04T19:25:40.080732984Z  uid:0  restore  hosts  ok  
2026-09-04T19:25:40.065984224Z  uid:0  apply  hosts  ok  
[exit 0]

$ /tmp/target/debug/detent audit --json --limit 1
{
  "audit": [
    {
      "ts": "2026-09-04T19:25:40.085523459Z",
      "who": "uid:0",
      "kind": "local_user",
      "op": "apply",
      "module": "hosts",
      "prev_hash": "ba0a20158b52d3a04aecb4882f66ea5f6b1074a292c5102baae85f8d74ec0580",
      "new_hash": null,
      "result": "error",
      "error_id": "ops-hash-conflict"
    }
  ]
}
[exit 0]

=== other fronts of the same operations layer

$ /tmp/target/debug/detent service hosts status
`hosts` controls no service on this host, so it cannot be restarted.
[exit 1]

$ /tmp/target/debug/detent commit rollback 1
the privileged helper refused or could not complete the request: monitor refused the request: unknown commit id 1
[exit 1]

$ sh -c /tmp/target/debug/detent completions bash | head -4
_detent() {
  local cur path i candidate __detent_words
  cur="${COMP_WORDS[COMP_CWORD]}"
  path="detent"
[exit 0]

=== exit codes

$ /tmp/target/debug/detent config no-such-module get
there is no module named `no-such-module` in this build.
[exit 1]

$ /tmp/target/debug/detent config hosts
error: 'detent config' requires a subcommand but one was not provided
  [subcommands: get, validate, plan, apply, defaults]

Usage: detent config [OPTIONS] <MODULE> <COMMAND>

For more information, try '--help'.
[exit 2]

$ /tmp/target/debug/detent host --json
{
  "host": {
    "profile": {
      "os": "linux",
      "init": "none",
      "hostname": "e25936b8ae1f",
      "service_versions": {},
      "ram_mib": 12016
    },
    "distro_id": "debian",
    "distro_version_id": "12",
    "network_backend": "unknown",
    "resolver_backend": "static",
    "notes": []
  }
}
[exit 0]

=== serve, and its process model

$ timeout 10 /tmp/target/debug/detent serve --dryrun
dry run: the monitor and worker would start with 1 modules and 1 targets, rooted at /var/lib/detent.
[exit 0]

$ timeout 10 /tmp/target/debug/detent serve
the monitor and worker could not be started: cannot resolve the worker account
[exit 3]

$ useradd --system --no-create-home --shell /usr/sbin/nologin detent
[exit 0]

$ timeout 30 /tmp/target/debug/detent --verbose serve
locale en-US, state root /var/lib/detent, config /etc/detent/detent.toml
the worker started as pid 133; privileges dropped: 1
the worker is running; its http server arrives in phase 4. handshake: 1
[exit 0]
```
