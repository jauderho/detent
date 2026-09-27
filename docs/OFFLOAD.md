# OFFLOAD — work for a second model (oh-my-pi)

This file gives self-contained tasks to a less capable model that the owner
runs with oh-my-pi. The main orchestrator (Claude) keeps all work on
security boundaries. Each task below is small, has one clear result, and has
checks that prove it.

Read this whole file before you start a task. Then read `AGENTS.md`. The
rules in `AGENTS.md` apply, and the guardrails below add to them. If this
file and `AGENTS.md` do not agree, stop and ask the owner.

## 1. Guardrails (all tasks)

### 1.1 Scope

- Do **one task per branch**. Do only what the task says. Do not "improve"
  code near your change.
- **Never edit these paths.** If the task seems to need a change there, stop
  and report to the owner:
  - `crates/detent-platform/src/sandbox/**` (seccomp, Landlock, capabilities)
  - `crates/detent-platform/src/privsep/**` (monitor, worker, runner, acme
    process, transport)
  - `crates/detent-acme/**` (ACME client, DNS providers, TSIG)
  - `crates/detent/src/acme.rs`, `crates/detent/src/serve.rs`
  - `crates/detent-web/src/tls.rs`, `crates/detent-web/src/secrets.rs`,
    `crates/detent-web/src/auth/**`, `crates/detent-web/src/authz.rs`
  - `.github/**`, `scripts/**`
  - `Cargo.toml`, `Cargo.lock`, `web/package.json`, `web/bun.lock`
  - `coverage-baseline.json`, `size-baseline.json`, `deny.toml`
  - `docs/adr/**`, `docs/SECURITY_HARDENING.md`
- **No new dependencies** (Rust or JS). The supply-chain cooldown
  (ADR-011) forbids them.
- Change only the files the task names, plus its tests, plus locale files
  where the task says so, plus one entry in `docs/PROGRESS.md`.

### 1.2 Code quality

- Rust: no `.unwrap()`, `.expect()` or `panic!` in non-test code. Use `?`.
- **No new lint suppressions**: no `#[allow]`, `#[expect]`,
  `// biome-ignore`, `// @ts-ignore`, `// @ts-expect-error`, `eslint-disable`.
- **Never weaken a test**: do not delete a test, remove an assertion, add
  `#[ignore]`, skip a test, loosen a comparison, or mock away the behavior
  under test. Never lower a coverage floor.
- TypeScript: strict types, no `any`. Every user-facing string goes through
  the locale files (Fluent `.ftl`), never as literal text.
- Match the style of the file you change: names, comments, error handling.

### 1.3 Git

- Start from the latest `main`:
  `git fetch origin main && git switch -c offload/<task-id>-<slug> origin/main`.
- Commit with a signature and sign-off: `git commit -S -s -F <message-file>`.
  One logical change per commit.
- Commit messages: ASD-STE100 Simplified Technical English, imperative
  subject of at most 72 characters, a short body, then this trailer:
  ```
  Item: OFFLOAD <task-id>
  Test: <test names>; failed before the fix with: <exact line>
  Gates: <commands you ran and their results>
  Linux: container only
  Allows added: 0
  ```
- **Never** force-push, rebase a pushed branch, amend a pushed commit, or
  push to `main`. Push only your `offload/...` branch. The owner merges.
- Do not create tags or releases, and do not change GitHub settings.

### 1.4 Checks before you say "done"

Run every gate the task lists, and report the real output. "Done" means the
gates ran and passed. If a gate fails and you cannot fix it inside the
task's scope, stop and report the failure with the exact output.

Common Rust gates (run from the repository root):

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy -p detent --all-targets -- -D warnings
cargo test -p <crate you changed> --all-features --no-fail-fast
```

Known state: when the tests run as **root**,
`webadmin::tests::setup_with_force_reports_a_write_failure_as_a_credential_failure`
fails (task T2 fixes this). As a normal user it passes. Any other failure
is yours.

Common web gates (run in `web/`):

```
bun run lint
bun run typecheck
bun run test
bun run coverage:check
bun run i18n:check
bun run contrast:check
bun run api:check
bun run build
```

### 1.5 Stop conditions

Stop and report to the owner, with no workaround, when:
- the task needs a change in a path from §1.1;
- a gate fails for a reason outside the task;
- a hook or a permission refuses a command;
- the task text and the code do not agree;
- you are not sure the change is correct.

### 1.6 Report

At the end, write a short report: branch name, commit hashes, what changed,
the gates and their results (quote failures), and anything uncertain.

## 2. Tasks

The orchestrator does not change the files of an open task until the owner
merges or closes it.

### T1 — Fix the clippy errors in the CLI-only build

**Why:** a build without the `web` feature does not compile its tests.
CI does not build this feature set, so nobody sees it.

**Reproduce:**
```
cargo clippy -p detent --all-targets --no-default-features \
  --features module-hosts,init-systemd -- -D warnings
```
Today it fails with three errors:
- `crates/detent/src/run.rs:2654`: `cannot find function 'failed' in module 'super'`
  (the function at `run.rs:1068` is compiled only with a feature that is
  off here);
- `crates/detent/src/completions.rs:196` and `:227`: `variable does not need
  to be mutable`.

**Do:** fix the cause with the smallest change. Put the test that calls
`super::failed` under the same `#[cfg(...)]` as the function, or make the
function available to that test; choose what matches how the file already
gates code. For the two `mut` warnings, make the binding mutable only in
the feature combination that needs it (for example with a `#[cfg]` on the
statement, or by restructuring), not with `#[allow]`.

**Files:** `crates/detent/src/run.rs`, `crates/detent/src/completions.rs`.

**Gates:** the reproduce command above passes; the common Rust gates pass;
`cargo test -p detent --no-default-features --features
module-hosts,init-systemd` passes.

### T2 — Make the root-only webadmin test pass as root

**Why:** `webadmin::tests::setup_with_force_reports_a_write_failure_as_a_credential_failure`
(`crates/detent/src/webadmin.rs`, about line 1972) makes a write fail by
removing write permission from a directory. Root ignores directory
permissions, so as root the write succeeds and the test fails. The test
itself is correct; its way of causing the failure is not.

**Do:** cause the write failure in a way that also works for root, and keep
every assertion (`Exit::Failed`, a note is written, and it is reported as a
credential failure). Good ways: put a regular file where the code expects
the directory, or point the store at a path under a regular file (the
kernel then answers `ENOTDIR` for every user). Keep the test's name and its
meaning. Do not skip it for root.

**Files:** `crates/detent/src/webadmin.rs` (test module only).

**Gates:** the common Rust gates; `cargo test -p detent --all-features
webadmin::` passes **as root and as a normal user** (for example
`sudo -u nobody` with a copy of the test binary, or ask the owner to run it
on a host). Remove the "known state" sentence from §1.4 of this file in the
same commit.

### T3 — Renew button on the Certificates page

**Why:** the server now has `POST /api/v1/system/cert/renew`
(`crates/detent-web/src/api/system.rs`). The UI has no control for it.

**API contract (read the handler and `docs/openapi.json` to confirm):**
- write scope and the CSRF token, like the other POSTs in `web/src/api/`;
- `202` with `{ "requested": true }`: a renewal was requested;
- `409` with message id `web-cert-renew-not-acme`: no ACME process runs
  (`tls.bootstrap` is not `acme`);
- `503` with message id `web-cert-renew-unavailable`: the ACME process is
  gone;
- `403` for a caller without write scope.

**Do:**
1. Add a mutation hook in `web/src/api/system.ts` next to `useCert`, built
   like the existing `useMutation` hooks in `web/src/api/backups.ts` and
   `web/src/api/commits.ts`. After `202`, invalidate the cert query so the
   page refreshes.
2. On `web/src/routes/CertificatesPage.tsx`, add a "Renew now" button. Show
   it enabled only for a user with write scope (use the same scope check
   `BackupsPage.tsx` or `ServicesPage.tsx` uses). While the request runs, disable it. After `202`, show
   a short success message ("Renewal requested. The new certificate is
   installed when the CA issues it."). On an error, show the localized
   server message with the existing error helper (`useApiErrorMessage`).
3. On `web/src/routes/AuditPage.tsx`, add a label for the auth-log event
   `cert_renew_requested` (see how other auth events are labeled there).
4. Put every new string in `locales/en-US/web.ftl` and
   `locales/qps-ploc/web.ftl` (the pseudo-locale; see how `bun run test`
   generates or checks it, and `bun run i18n:check`). Follow
   `AESTHETIC_CONTRACT.md`: no new colors or fonts, use the existing
   components (`Panel`, `Banner`, and so on).
5. Tests in `web/src/routes/__tests__/CertificatesPage.test.tsx` (and the
   audit page test if one exists): button hidden or disabled for a read-only
   user; `202` shows the success text and refetches; `409` and `503` show
   the server's message; the button is disabled while the request runs.

**Files:** `web/src/api/system.ts`, `web/src/routes/CertificatesPage.tsx`,
`web/src/routes/AuditPage.tsx`, their tests, `locales/*/web.ftl`.

**Gates:** all common web gates, including `bun run e2e` if Playwright
works on your machine (report it if it does not).

### T4 — `detent cert status` (read-only)

**Why:** an operator needs to see the served certificate from the shell,
without the web UI. This command only reads files; it never contacts the
server or the CA.

**Do:**
1. Add a subcommand `detent cert status` with an optional `--json` in
   `crates/detent/src/cli.rs`, built like the other subcommands with
   `clap`. Compile it only with the `web` feature (the certificate code
   lives in `detent-web`).
2. In `crates/detent/src/run.rs` (or a new small module `cert.rs`, if the
   file layout makes that cleaner), load `detent.toml` with the same
   settings helper other commands use, and read the served pair with
   `detent_web::serving_pair(&config.tls.cert_dir)`. Report:
   - the source: `acme` when an ACME pair is stored
     (`detent_web::load_acme`), else `bootstrap`;
   - the SHA-256 fingerprint (`CertifiedKeyPair::fingerprint`);
   - `not_after` (`CertifiedKeyPair::not_after_unix`), as an RFC 3339 time;
   - the used part of the lifetime in percent, and the warning level
     (none, half, quarter). Reuse the logic behind
     `GET /api/v1/system/cert` (`cert_report` in
     `crates/detent-web/src/api/system.rs`) through a public function; do
     not copy it. If that needs a new `pub` function in `detent-web`, add
     only that, outside the forbidden files.
3. Exit codes: `0` when the certificate is valid, the existing "failed"
   exit when no certificate is stored or the directory cannot be read (say
   why, localized). Never print key material.
4. Localize every message in `locales/en-US/cli.ftl` (the only CLI
   locale; follow the existing `cli-...` ids and the id lists the i18n
   tests check).
5. Tests: text and `--json` output for an ACME pair and for a bootstrap
   pair (build them with the test helpers that already exist, for example
   `detent_web::bootstrap_self_signed`), a missing directory, and a pair at
   55 % and 80 % of its lifetime (the warnings). The output never contains
   `PRIVATE KEY`.
6. Add the command to the shell completions if the file lists commands by
   hand (`crates/detent/src/completions.rs`), and to the CLI section of
   `docs/ARCHITECTURE.md` if it lists commands.

**Files:** `crates/detent/src/cli.rs`, `crates/detent/src/run.rs` (or a new
`crates/detent/src/cert.rs`), `crates/detent/src/main.rs` (module line
only), `crates/detent/src/completions.rs` if needed, a small `pub` function
in `crates/detent-web/src/api/system.rs` or a module it uses (not the
forbidden files), `locales/en-US/cli.ftl`, `docs/ARCHITECTURE.md`.

**Gates:** the common Rust gates; `cargo test -p detent --all-features`;
`cargo test -p detent-web --all-features` if you changed it;
`cargo test -p detent-i18n`. Coverage floors: `crates/detent/` 95 %,
`crates/detent-web/` 97 % lines. CI measures them; cover every new line.

## 3. Work the orchestrator keeps

These need security review or a design decision, so they stay with the
orchestrator: a rate limit on renew requests (CA duplicate limits),
`detent cert renew` (it must authenticate to the running server), the CI job
where Pebble issues short-lived certificates and the server renews one, the
ACME order-flow seam and the M18 test, the aarch64 syscall trace, and every
change to the seccomp tables, the process model, TLS, secrets and CI.
