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

Stripped sizes in bytes, release builds, measured 2026-10-13 at commit
`9f07124`:

| Build | `aarch64-unknown-linux-musl` | `x86_64-unknown-linux-musl` |
|---|---|---|
| CLI only (`module-hosts,init-systemd`) | 2,089,464 | 2,343,080 |
| Default — all modules, API, TLS | 5,921,712 | 7,159,776 |
| Default + `ui` (console embedded) | 7,176,240 | 8,414,944 |

Memory, `x86_64-unknown-linux-musl`, default + `ui`, root-confined, under the
packaged unit, measured 2026-10-14 at commit `7f2c7f5` (`VmRSS` in kB; `serve`
runs three processes). The unit sets `MIMALLOC_PURGE_DELAY=0` and
`MIMALLOC_ALLOW_THP=0`; a `serve` started without them uses more (worker
34,456 idle, 84,180 after a login).

| Process | Idle (60 s after start) | After 200 API reads and 20 plans |
|---|---|---|
| monitor | 8,524 | 8,620 |
| runner | 5,744 | 5,744 |
| worker | 9,040 | 11,672 |
| Total | 23,308 | 26,036 |

About 6.4 MiB of each process is the shared, clean pages of the binary. A
login briefly uses the 64 MiB Argon2 block; the worker is back to 11,904 kB
5 s later.

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
detent audit verify            # check the audit hash chain; prints the head digest
detent completions bash
```

`detent audit verify` reads the whole operations audit log and checks its
sequence and hash chain. It exits 0 and prints the sequence number and digest
of the last record, or exits 1 and names the first bad record (`--json` prints
the same as an object). The chain shows that a record was edited, removed,
inserted or moved. It cannot show that the end of the log was cut off, so keep
the digest it prints somewhere the log's account cannot write (a ticket, a
mail, another host) and compare it with a later run: a log that was cut back
prints a different digest. It does not read the web sign-in log
(`audit/detent-auth.jsonl`), which has no chain. The service also writes each
change to the journal; forward the journal to a remote host if you need a
copy the host cannot rewrite. detent has no built-in remote sink. To forward
the journal:

- `systemd-journal-upload` on this host sends to `systemd-journal-remote` on a
  log host: set `URL=` in `/etc/systemd/journal-upload.conf` (use HTTPS with
  certificates), then `systemctl enable --now systemd-journal-upload`.
- Or use rsyslog with `imjournal` and an `omfwd` action over TCP with TLS.
- Filter on the `detent` unit. Each record is the event `detent audit` (the
  operation, who, module, result and error id; no hashes). It is logged only
  at `RUST_LOG=info`, which the packaged unit sets.

#### Alerting

detent does not send alerts. Raise them from the journal, with your own
monitoring. Every web sign-in event is one `detent audit` line in the journal
of the `detent` unit. The line is text, and `event=` holds the event name in
CamelCase (the sign-in log file has the same event in `snake_case`). Match
these events:

- `event=LockedOut`: the rate limiter locked a user or a client address out.
- `event=LoginFailed`: a refused sign-in. Alert on a high rate.
- `event=ScopeDenied`: a valid caller tried an operation without its scope.
- `event=CredentialRejected`: a token or session cookie that did not resolve
  (at most one line per client address per minute; `suppressed=` counts the
  rest).
- `event=TokenRateLimited`: an API token went over its request budget (one
  line when it starts; none again until the budget has refilled).
- `event=StepUpFailed`: a session gave a wrong password or code before an
  apply, restore, update or certificate renewal.

```bash
journalctl -u detent --since -1h --grep 'detent audit.*event=(LockedOut|ScopeDenied)'
```

For a log host, give your log tool the same match: for rsyslog, an `if
$msg contains 'event=LockedOut'` rule on the `imjournal` input; for
`systemd-journal-remote`, run the `journalctl` query above from a timer.

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

Turn on a second factor (TOTP: SHA-1, 6 digits, 30 s) for an account. A
signed-in user can do it in the console (settings: password, then a QR code
and a code; turning it off takes the password and a code). On the command
line, the command prints an `otpauth://` URI and the base32 key once, then asks for a
current code from your authenticator and stores the key only if the code is
valid. The code is read from the terminal, never from argv. Set
`auth.totp_required = true` in `detent.toml` only after every account has a
key, because an account without one cannot sign in then. The code that
confirmed the enrolment is used up, so wait for the next one at the first
sign-in. Turn it off again with `disable` (`--yes` skips the question):

```bash
sudo -u detent detent user totp enable admin
sudo -u detent detent user totp disable admin
```

API tokens for scripting, read-only unless `--write`:

```bash
sudo -u detent detent token create ci-readonly
sudo -u detent detent token list
```

The settings page of the console lists, creates and revokes tokens too. It
asks for the password again first, and shows a new token once. With
`auth.totp_required`, only a session that signed in with a code may create
one (docs/API.md "API tokens").

Each token may make 60 requests at once, then 120 a minute; over that it gets
`429` with `Retry-After`. Change this in `detent.toml` (neither may be zero):

```toml
[auth]
token_burst = 60
token_rate_per_minute = 120
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
from the console runs `detent update --tag <tag>` in the systemd unit
`detent-update@<tag>.service` (both privilege modes).

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
diagnostic messages. Locale text is stored compressed in the binary; the
program expands only the locale it uses (and `en-US`, the fallback). A new
locale is a new directory under `locales/` (see
[`docs/TRANSLATING.md`](docs/TRANSLATING.md)); no build flag changes.

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
