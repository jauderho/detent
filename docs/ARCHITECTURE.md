# detent architecture

This document describes how the parts of `detent` fit together, for a
security audit. Each claim names the file that implements it and, where one
exists, the test that proves it, so that a reviewer can verify the claim
instead of trusting it. [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md) is
the control-by-control table (threat, implementation, proof) and its
[Gaps](SECURITY_HARDENING.md#gaps) section lists what is not yet proven. The
ADRs in [`adr/`](adr/) record why each design was chosen.

State as of 2026-09-25 (branch `claude/determined-noether-wo0uh8`).

## 1. What detent does

`detent` edits root-owned configuration files of Linux network services
(hosts, resolver, chrony, mounts, NFS, Samba, DHCP, network interfaces) and
restarts those services, from a CLI, a web UI/API, an MCP server, or a C ABI.
It reads each file into a lossless model, applies the requested change,
validates the result, and writes it back atomically with a backup. Only the
changed lines differ.

The central security property: **the network-facing code never holds root.**
All root actions happen in a small monitor process that accepts a closed set
of requests which name allow-list entries by index, never by path.

## 2. Component map

One Cargo workspace. `detent` is one binary; the other crates are libraries.

| Crate | Role | I/O | `unsafe` |
|---|---|---|---|
| `detent-core` | Lossless document model, module SDK (`ConfigModule`, `DynModule`), diagnostics, conformance harness | none | forbidden |
| `crates/modules/*` | One crate per config format (ADR-004): parse, render, validate, apply a JSON model | none | forbidden |
| `detent-modules` | Registry of the modules a build enables (`cfg(feature)`, no link-time registration) | none | forbidden |
| `detent-i18n` | Fluent message catalogue (embedded) | none | forbidden |
| `detent-ops` | `Operation` enum and `OpsEngine`: the only path from any front end to a mutation; authz hook, hash-chained audit log, commit-confirm | via privsep client | forbidden |
| `detent-platform` | Privsep monitor/worker/runner, protocol, allow-list, atomic file writes, Landlock/seccomp/capabilities, service managers, host detection | files, processes, syscalls | allowed with `// SAFETY:` (fork, `_exit`, seccomp syscalls) |
| `detent-web` | Axum server: TLS 1.3, auth, sessions, CSRF, `/api/v1`, embedded SPA | network | forbidden |
| `detent-update` | Release fetch and in-tree Sigstore verifier (ADR-005, ADR-014) | network (worker), none (verify) | forbidden |
| `detent-acme` | ACME order flow, dns-01 and device-attest-01 seams | network | forbidden |
| `detent-mcp` | MCP tools over `Operation` (optional feature) | stdio / loopback HTTP | forbidden |
| `detent-ffi` | `libdetent` C ABI over the pure core only (`docs/FFI.md`) | none | allowed at the ABI edge |
| `detent` | CLI (`clap`), `serve`, `mcp`, `doctor`, output rendering | all of the above | forbidden |

Verify the `unsafe` column: `rg -n 'unsafe_code' crates/*/src/lib.rs
crates/detent/src/main.rs`. Lint policy is in the root `Cargo.toml`
(`unwrap_used`, `expect_used`, `panic`, `indexing_slicing` denied; ADR-010).

## 3. Process model

There are three ways the engine runs. Only `detent serve` separates
privilege.

### 3.1 `detent serve` (the network-facing deployment)

```text
                       detent serve (root)
                               │
       1. spawn_runner ────────┼──────────────▶ runner (root, NOT confined)
                               │                  runs declared validators and
                               │                  service actions, by id only
       2. spawn_pair ──────────┤
                               ├──▶ monitor (root, confined: caps, Landlock,
                               │      seccomp, no_new_privs, not dumpable)
                               │      the only process that writes targets
                               │
                               └──▶ worker (uid `detent`, no caps, confined)
                                      TLS listener, auth, API, ops engine
```

- Order and forks: `crates/detent/src/serve.rs` (`run`, `start_runner`,
  `run_monitor`, `prepare_worker`); `crates/detent-platform/src/privsep/spawn.rs`
  (`spawn_runner`, `spawn_pair`, one shared `fork` site). Both forks happen
  before any thread or runtime starts.
- The worker drops the runner descriptor it inherits, first thing
  (`serve.rs`, `Role::Worker` arm). It then drops to uid `detent`
  (`become_worker`) and confines itself.
- The monitor confines itself in `spawn_pair` before it releases the worker
  (`sandbox.confine_monitor()`, then the start byte).
- The worker binds the listener, so the port must be ≥ 1024
  (`PRIVILEGED_PORT_CEILING`, `serve.rs`).
- The dns-01 provider secret lives in `secrets.toml`, next to `detent.toml`
  (`/etc/detent/secrets.toml`, `Settings::secrets_path` in `run.rs`), `0600`
  and owned by root. The privileged parent reads it before the fork
  (`preflight_dns_provider`, `serve.rs`), through
  `crates/detent-web/src/secrets.rs` (`load`: `O_NOFOLLOW`, regular file,
  ≤ 64 KiB, no group/other bits, owner = euid). A secret that reaches the
  worker gets there only as memory inherited across the fork: the worker
  runs as uid `detent` and cannot reread the `0600` file. Today `serve`
  only proves that `[acme.provider]` and the secret build a provider, then
  drops both; the renewal loop that keeps them is not built yet.

### 3.2 One-shot CLI commands and `detent mcp`

`detent get|plan|apply|…` and `detent mcp` run the monitor **as a thread in
the same process** (`crates/detent/src/run.rs`, `Session::start`) over an
in-process socket pair. There is no uid split and no confinement: the
operator who runs the command already holds the privilege it uses. The
protocol, the allow-list, the content checks and the audit log are the same
code as under `serve`.

Audit note: `detent mcp --transport http` binds loopback
(`127.0.0.1:3334` by default) and authenticates each request with a bearer
token that must also be live in `tokens.json` (`crates/detent/src/mcp.rs`),
but the process that parses those requests is the same process that holds
the monitor's privilege. Treat it as a local-only surface.

### 3.3 `libdetent` (C ABI)

`crates/detent-ffi` exposes parse/render/validate/apply over strings. It
links only the pure core and the modules: no file, network or process
access (`docs/FFI.md`).

## 4. Trust boundaries

| # | Boundary | Untrusted side | Enforced by |
|---|---|---|---|
| TB1 | Network → worker | any TCP peer | TLS 1.3 only, connection cap, first-request deadline, body/time limits, auth, CSRF (§7) |
| TB2 | Worker → monitor socket | the worker (assume compromised) | closed request enum, 1 MiB frames, ids into the allow-list, content re-validation (§5, §6) |
| TB3 | Monitor → runner socket | the monitor (assume compromised) | ids into the runner's own allow-list copy, staged file name only (§5.3) |
| TB4 | Candidate content → root daemons | bytes the worker sends | module parser + validator + per-daemon execution deny-list in the monitor (§6) |
| TB5 | Release feed → running binary | GitHub and the network | Sigstore bundle verification in the monitor before the swap (§8) |
| TB6 | Local operator → CLI / MCP | the local user | Unix permissions: the CLI needs the privilege it uses (§3.2) |

## 5. The privsep protocol

### 5.1 Worker → monitor

Defined in `crates/detent-platform/src/privsep/proto.rs`; served by
`crates/detent-platform/src/privsep/monitor.rs` (`Monitor::dispatch`).
Encoding is postcard with a length prefix; a frame over `MAX_FRAME` (1 MiB)
is refused before allocation, and an undecodable frame closes the
connection (`transport.rs`). `Hello` must come first and carries
`PROTO_VERSION`.

| Request | Monitor checks before acting |
|---|---|
| `Hello` | version match; once only |
| `ReadTarget { target }` | id in the target table; a missing file is `NotFound` |
| `WriteTarget { target, expected_prev, bytes, journal }` | id; `expected_prev` digest (optimistic concurrency); content re-validation (§6); atomic write with backup |
| `RunCheck { check, bytes }` | id; bytes staged in the monitor's staging dir; run through the runner |
| `Service { binding, action }` | id; action declared by the binding; run through the runner |
| `ListBackups`, `Restore` | module id; backup index into the monitor's own listing |
| `StartConfirmTimer`, `ConfirmCommit`, `RollbackCommit`, `PendingCommit` | one pending commit at a time; journal of this commit's writes only |
| `ReplaceBinary { tag, len, sha256 }` | digest and length; Sigstore verification (§8) |
| `Mount` | reserved; answers `Unsupported` |
| `Shutdown` | — |

No request carries a path, a program name, an argument or a unit name.
Errors (`ProtoError`) carry no path or OS message
(`atomic_to_proto`, `monitor.rs`).

### 5.2 The allow-list

`crates/detent-platform/src/privsep/allowlist.rs` builds four tables
(targets, checks, service bindings, modules) at startup from the compiled-in
`ModuleDescriptor`s of the enabled modules. `HelloAck` tells the worker
what each entry is (module names, target paths, checks, bindings) so that it
can display them, but every request names an entry only by its index.
Everything a request can reach is therefore fixed by the build's feature set
and visible in each module's `descriptor()`.

### 5.3 Monitor → runner (STAGE3 H6)

A seccomp filter binds every child of the process that installs it, so the
confined monitor does not start programs itself.
`crates/detent-platform/src/privsep/runner.rs`:

- Requests: `Check { check id, candidate file name }` and
  `Service { binding id, action }`. The runner looks the id up in its own
  copy of the allow-list (forked before confinement) and builds the program
  and arguments from the static declaration.
- A candidate must be one plain path component naming a regular file (not
  a symlink) directly in the staging directory (`staged_candidate`).
- A `Service` action must be declared by the binding; `Status` is refused.
- Any channel error disables the client for good, so every later check or
  service call is `Unavailable` and apply fails closed.

Proof: `enforce_mode_monitor_runs_real_validators_through_the_runner`
(`sandbox/linux.rs`) and the `runner::tests` module.

## 6. The write path

```text
client ─▶ worker: /api/v1 handler ─▶ Operation::Apply ─▶ OpsEngine (detent-ops)
  0. web layer: session or token, CSRF, token scope (authz.rs); under serve the
     engine's own authz hook is AllowAll
  1. audit "started" record; if it cannot be written, the operation is refused
  2. ReadTarget ─────────────────────────────▶ monitor
  3. module.apply_json(current, model)  (lossless: only changed lines differ)
  4. RunCheck per declared validator ────────▶ monitor ─▶ runner
  5. WriteTarget(expected_prev = digest from 2) ─▶ monitor:
       a. id → allow-listed path          (allowlist.rs)
       b. execution deny-list             (exec_deny.rs)   new or changed
          exec directive → refused
       c. module parser + validator       (validate_candidate)
       d. declared validators again       (revalidate → runner)
       e. atomic write: backup, O_EXCL temp, fsync, rename, fsync(dir)
          (fs/atomic.rs); digest mismatch → Conflict, nothing written
  6. Service action (optional) ──────────────▶ monitor ─▶ runner
  7. commit-confirm (optional): timer armed; no confirm → rollback + service replay
  8. audit "ok" / "error" record (hash-chained)
```

- Apply never creates a missing target: `ReadTarget` answers `NotFound` and
  the engine reports `ops-target-missing` (`engine.rs` `map_client`).
- The deny-list (step 5b) compares normalised name/value instances as a
  multiset: a directive already in the file may stay unchanged; a new one, or
  a changed value, is refused. It is best effort; see §10.
- Proof: `crates/detent-ops/tests/engine.rs` (apply, plan, conflict, audit
  order), `exec_deny::tests`, `write_target_refuses_new_root_exec_directives`,
  `crates/detent-platform/tests/privsep_e2e.rs`.

## 7. The web layer (worker)

`crates/detent-web`. Details and proofs: SECURITY_HARDENING §Transport and
§Web.

- TLS 1.3 only, ALPN `h2`/`http/1.1`, rustls (ADR-002). Bootstrap
  self-signed certificate, fingerprint logged every start for trust on first
  use; ACME-renewed pair preferred when stored (`tls.rs`, `serve.rs`).
- Connection handling (`server.rs`): semaphore cap, TLS handshake timeout,
  first request within the header timeout (H9), HTTP/2 keep-alive and
  stream limits, 10 min connection lifetime, request timeout, 256 KiB body
  cap, security headers on every response.
- Authentication: Argon2id passwords (`auth/password.rs`), per-IP and
  per-user rate limit with lockout (`auth/ratelimit.rs`), TOTP
  (`auth/totp.rs`), sessions in memory with a `__Host-` cookie, 15 min idle
  and 8 h absolute limits, id rotation on login (`auth/session.rs`),
  a background sweep started on the serve runtime (L-WEB16). API tokens are
  stored as SHA-256 digests with scopes and expiry (`auth/token.rs`).
- CSRF (`csrf.rs`): non-GET requests need `Sec-Fetch-Site`, `Origin` and
  `X-Detent-CSRF`; GET never mutates.
- Only `/healthz` answers without a credential
  (`no_api_route_is_reachable_without_a_credential`).
- Handlers call the synchronous engine through a bridge thread
  (`spawn_engine`, `detent-web/src/lib.rs` and `engine.rs`); they never touch
  files or services.

## 8. The update path

`crates/detent-update`, ADR-005, ADR-014.

1. The worker fetches release metadata and assets (one hyper-rustls client,
   `fetch.rs`), applies the selection policy (no downgrade, `policy.rs`), and
   writes the binary and its `<tag>.sigstore.json` bundle under
   `<state_root>/update/staged`.
2. `ReplaceBinary { tag, len, sha256 }`: the monitor copies the bytes into
   its private staging base `/run/detent/staging` (digest-named, checked
   owner and mode), verifies the Sigstore bundle against the embedded trust
   root with the in-tree verifier, and only then renames the file over the
   running binary.
3. A verification failure answers `VerificationFailed`; nothing is swapped.

Known open item: the Rekor signed-entry-timestamp verification gap (STAGE3
H17, `docs/stage4-wip/h17-set-partial.patch`).

## 9. Confinement per process

| | runner | monitor | worker |
|---|---|---|---|
| uid | root | root | `detent` |
| Capabilities | all | bounding set cut to `DAC_OVERRIDE`, `CHOWN`, `FOWNER`; start fails if the cut fails (`require_caps`) | none |
| `no_new_privs` / not dumpable | no / no | yes / yes | yes / yes |
| Landlock (writes) | none | target parent dirs, backup dirs, state root, `/run/detent/staging`, the binary's dir; degrades with a warning if absent (`require_landlock` off by default) | state root only |
| seccomp | none | `MONITOR` table, kill on violation; start fails if it does not install (`require_seccomp`) | `WORKER` table, same rule |
| Reachable by | monitor only (socket pair) | worker only (socket pair) | network |

Sources: `crates/detent-platform/src/sandbox/mod.rs` (`Policy::monitor`,
`Policy::worker`), `sandbox/linux.rs` (`confine`), `sandbox/seccomp.rs`
(tables and their derivation). `detent doctor` and the startup notes report
any degraded step (`report_confinement`, `serve.rs`).

## 10. State on disk

| Path | Written by | Contents |
|---|---|---|
| allow-listed targets (e.g. `/etc/hosts`) | monitor | managed configuration |
| per-target backup dirs | monitor | timestamped backups, retained count from config |
| `/var/lib/detent` (state root) | monitor and worker | the items below |
| `…/audit/detent-audit.jsonl` | engine | operation audit, sequence and hash chain |
| `…/audit/detent-auth.jsonl` | worker | login, token and session events |
| `…/users.json`, `…/tokens.json` | `detent setup`, `detent user`, `detent token` (local operator) | Argon2id hashes; token SHA-256 digests |
| `…/pending-commit.json` | monitor | commit-confirm marker, replayed at start |
| `…/update/staged/` | worker | downloaded release and bundle (untrusted until verified) |
| `/var/lib/detent/certs` | worker | TLS pair, `0600` in a `0700` dir |
| `/run/detent/staging` | monitor | candidate files for validators; verified update bytes |

## 11. Residual risks an auditor should weigh

1. **Content can still reach root.** The execution deny-list (`exec_deny.rs`)
   covers the directives it names for each daemon. A directive it does not
   name, or a non-exec root write (a log or drift-file path), is not caught.
2. **The runner is root and unconfined by design.** Its only input is the
   monitor's socket, and it accepts only allow-list ids and staged file
   names. The monitor seccomp table still lists `clone`/`execve`; removing
   them needs a traced run.
3. **One-shot CLI and `detent mcp` are not privilege-separated** (§3.2).
4. **Landlock is absent on Raspberry Pi OS kernels** (SECURITY_HARDENING
   Gaps). Seccomp and the capability cut still apply.
5. **aarch64 confinement is compiled and unit-tested but not run on
   hardware.**
6. Open STAGE3 items are tracked in [`STAGE3.md`](STAGE3.md) §11–§12 and
   [`STAGE4.md`](STAGE4.md).

## 12. How to verify

Run from the repository root (Linux, as root for the sandbox tests):

```sh
cargo test --workspace --all-features            # everything
cargo test -p detent-platform --all-features sandbox::linux -- --test-threads=1
cargo test -p detent-platform --all-features privsep::    # protocol, monitor, runner, deny-list
cargo test -p detent-ops --all-features --test engine     # write path and audit order
cargo test -p detent-web --all-features --test tls        # TLS and connection limits
git grep -c -E '#!?\[(allow|expect)\(' -- crates          # lint suppressions (may only go down)
```

Points to read first, in order: `privsep/proto.rs` (the whole attack
surface of TB2), `privsep/monitor.rs` `dispatch` and `revalidate`,
`privsep/exec_deny.rs`, `privsep/runner.rs`, `sandbox/mod.rs` `Policy`,
`fs/atomic.rs`, `detent-web/src/server.rs`, `detent-web/src/csrf.rs`,
`detent-update/src/verify.rs`.
