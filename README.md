# detent

One static binary that reads, validates, previews and writes the system
configuration files on a Linux host — `/etc/hosts`, resolver, chrony, fstab,
NFS exports, Samba, DHCP, network interfaces — from a CLI, an HTTP API, or a
web console. Think busybox, for config files.

Built for SBCs and embedded systems: no runtime, no interpreter, no sidecar.
The web console is compiled into the binary.

> **Status: pre-release.** The `hosts` module is implemented; the other module
> flags exist but have no backend yet. There are no published release
> artifacts — build from source. Interfaces may change.

## Install

Requires Rust 1.98+. [`bun`](https://bun.com) is needed only to build the web
console.

```bash
git clone https://github.com/jauderho/detent && cd detent
cargo build --release -p detent
```

That gives every module plus the HTTP API, but not the web console — see
below. CLI only, no server, is the smallest build:

```bash
cargo build --release -p detent --no-default-features \
  --features module-hosts,init-systemd
```

With the web console, which must be built first:

```bash
(cd web && bun install --frozen-lockfile && bun run build)
cargo build --release -p detent --features ui
```

Targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and the
two Apple Silicon/Intel macOS equivalents. Cross-compile with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild).

Stripped sizes, `aarch64-unknown-linux-musl`:

| Build | Bytes |
|---|---|
| CLI only (`module-hosts,init-systemd`) | 1,712,952 |
| Default — all modules, API, TLS | 4,971,696 |
| Default + `ui` (console embedded) | 5,659,696 |

## Usage

Every module is driven the same way. Models are JSON on stdin and stdout.

```bash
detent config hosts get                  # current state as JSON
detent config hosts defaults             # secure defaults for this host
detent config hosts validate < model.json
detent config hosts plan     < model.json   # diff; writes nothing
detent config hosts apply    < model.json
```

`apply` can restart the service and arm a rollback window. If nothing confirms
before the deadline, the privileged monitor reverts the change — so a bad
network edit cannot lock you out:

```bash
detent config network apply --service reload --confirm 90s < model.json
detent commit confirm <id>     # keep it
detent commit rollback <id>    # undo it now
```

Other commands:

```bash
detent host                    # detected distro, init system, backends
detent doctor                  # check for common misconfigurations
detent service chrony status
detent backup list hosts
detent audit
detent completions bash
```

### Web console

Create the first account, then start the server. It listens on **:3333**, TLS
1.3 only, with a self-signed certificate until ACME is configured.

`setup`, `user` and `token` write files the server's `detent` service account
must read, so on a packaged install run them as that account; they refuse to
run as root. In an unprivileged dev run, drop the `sudo -u detent` prefix.

```bash
sudo -u detent detent setup    # prompts for a password; never takes one on argv
detent serve
```

API tokens for scripting, read-only unless `--write`:

```bash
sudo -u detent detent token create ci-readonly
sudo -u detent detent token list
```

Ask the running server to renew its ACME certificate now, with a write token
from a file (`0600`, not a symlink) or `DETENT_TOKEN`, never argv. The server
starts at most one forced order per hour:

```bash
(umask 077; sudo -u detent detent --json token create renew-bot --write | jq -r .token > ~/.detent-token)
detent cert renew --token-file ~/.detent-token
```

The API is documented in [`docs/API.md`](docs/API.md); the machine-readable
spec is [`docs/openapi.json`](docs/openapi.json), also served at
`/api/v1/openapi.json`. Every `/api/v1` route needs a credential — only
`/healthz` and the login endpoint are open.

### Updates

`detent update` installs the newest signed release, restarts the service and
rolls back if `/healthz` fails. The web console only reads the result of the
last `detent update --check`; detent ships no timer for it, so schedule it as
root yourself, for example in root's crontab:

```bash
17 4 * * * /usr/local/bin/detent update --check >/dev/null
```

Until it runs once, the console says no update check has run. An install
from the console runs `detent update --tag <tag>` in a transient
`detent-update` unit.

## Security

- **No setuid.** A privileged monitor and an unprivileged worker exchange a
  closed message protocol over a socketpair; the worker parses untrusted file
  content and can request writes but cannot perform them.
- Landlock and seccomp confine both processes, and startup **fails closed** if
  a seccomp filter does not install. Landlock is best-effort: Raspberry Pi OS
  does not compile it in, so detent runs there without filesystem confinement
  and says so — check `detent doctor`.
- TLS 1.3 only — the binary is built without TLS 1.2 support, so it cannot
  negotiate it.
- Argon2id password hashing, CSRF checked three ways on cookie-authenticated
  writes, scoped API tokens.
- Dependencies are subject to a 7-day cooldown before adoption (ADR-011).

See [`docs/SECURITY_HARDENING.md`](docs/SECURITY_HARDENING.md) for the control
list and the known gaps.

## Build flags

Each module is a cargo feature (`module-hosts`, `module-resolver`, …), as are
the init system (`init-systemd`, `init-openrc`, `init-bsdrc`), the crypto
backend (`crypto-aws-lc`, `crypto-ring`), and the optional `web`, `ui`,
`acme-dns01` and `update` features. Build only what the host needs. The
`web` feature also compiles in the web console's message catalogue
(`web.ftl`, every shipped locale); a build without it carries only the CLI and
diagnostic messages.

## Development

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cd web && bun run test && bun run lint && bun run e2e
```

The web console's unit tests run on `bun test`; `bun run e2e` drives the built
bundle in Chromium with Playwright and axe-core, so it needs
`bunx playwright install chromium` once.

[`AGENTS.md`](AGENTS.md) covers coding standards,
[`AESTHETIC_CONTRACT.md`](AESTHETIC_CONTRACT.md) the UI design contract,
[`docs/PLAN.md`](docs/PLAN.md) the roadmap,
[`docs/PROGRESS.md`](docs/PROGRESS.md) the current state and
[`docs/TOOLS.md`](docs/TOOLS.md) the toolchain and how to reclaim disk.

## License

BSD-3-Clause. See [`LICENSE`](LICENSE).
