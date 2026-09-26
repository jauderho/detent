# STAGE4 — Handoff to oh-my-pi (2026-09-25)

Written by the orchestrator (Claude) at the end of a cloud session, for
oh-my-pi. Read this file, then `docs/STAGE3.md` (the remaining items and
the binding rules in its §00). The full STAGE3 history, including §11 and the
old §12, is `git show 08e08fa:docs/STAGE3.md`. `docs/PROGRESS.md` has one
entry per landed item.

## 1. State now (2026-09-26)

- `main` = the tip of branch `claude/determined-noether-wo0uh8` (fast-forward).
- STAGE3: everything that can be done without a010, a release tag or an owner
  decision is done. What is left is the whole of `docs/STAGE3.md` (rewritten
  2026-09-26), worked by the owner with a010.
- Allow count: **111**. It may only go down.
- CI: the runs at `5dcea73` and `08e08fa` were red. Causes, all fixed in
  `0fce86a`…`a9e1dc7`: the M2 confined-record test under an unprivileged user
  and under coverage; the C1-b FIFO test did not compile on macOS; detent-core
  and detent-ops were below their 100 % coverage floors. A CI-shaped coverage
  run in the container passes every floor. One macOS failure
  (`bind_web_server_reuses_the_stored_certificate_on_restart`,
  `Channel(Closed)`) is not explained yet; the fixture now prints the
  monitor's error so a repeat names the cause.
- Local builds: `docs/TOOLS.md` "Faster local builds" (sccache, mold,
  Cranelift `server-dev`), per machine only.

## 2. Disk and build hygiene (new — use it)

- `make clean` removes incremental caches, coverage, release and cross builds, fuzz builds and artifacts, the generated fuzz corpus, test reports, and debug files older than 2 days. It keeps the warm debug build and `web/node_modules`. `make realclean` returns the tree to the as-cloned state; it keeps `.sops/`, `.mcp.json*` and your untracked files. Both take `DRYRUN=1 VERBOSE=1`. `make du` shows usage.
- `Cargo.toml` `[profile.dev.package."*"] debug = false`: dependencies build without debug info. A clean full test build is 5.0 GB (it was 19 GB+). Run `make realclean` once after you pull, so the old target/ goes.
- Run `make clean` after a coverage run, a fuzz run or a cross build.
- `cargo llvm-cov` needs `cargo llvm-cov clean --workspace` first, or stale binaries give wrong line numbers. Only the full CI-shaped run is valid for the per-path floors (commands in `.github/workflows/ci.yml`, Coverage job). Per-crate `--lcov` output also counts comment and blank lines as uncovered; do not trust it.

## 3. Traps found this session (do not repeat)

- **`git commit` takes the whole index.** In a shared tree, another agent's staged change can land in your commit (this happened in `216d326`). Before every commit, run `git diff --cached --stat`. Sub-agents must never stage.
- **Root-only test:** `webadmin::tests::setup_with_force_reports_a_write_failure_as_a_credential_failure` fails only as uid 0. It passes unprivileged and in CI. It is not a regression.
- **A test must not skip itself** when it is not root (D2). One such test was removed from a delivery this session.
- **CI job logs and artifacts** (blob storage) are blocked from the cloud container. To find a fuzz crash, run it locally: `cargo +nightly fuzz run --target=x86_64-unknown-linux-gnu <target> -- -max_total_time=60` (cargo-fuzz 0.13.2).
- **Branch CI:** `ci.yml`, `codespell.yml`, `linter.yml` and `fuzz.yml` run on a branch only through `workflow_dispatch`.
- **Shared `CARGO_TARGET_DIR` across worktrees is unsafe.** Cargo decides freshness by mtime, and its hash ignores the worktree path. So a run in the main tree can reuse a test binary built from another worktree's mutated source (seen this session: false failures at HEAD). For negative checks, give the worktree its own target dir, or `touch` the crate's sources and rebuild before trusting a main-tree result. **After you pull, run `make realclean` once.**
- **Codespell:** smb.conf words (e.g. `browseable`) go in `.codespellignore`.

## 4. Work queue, in order

### 4.1–4.2 STAGE3 verification, REOPEN items, §12 follow-ups — DONE

The verification pass, the REOPEN items, the PARTIAL items, the vacuous
tests and the §12 follow-ups (H17 leaf + SET, aligned edits, network gaps,
dead code) are done: commits and tests are in
`git show 08e08fa:docs/STAGE3.md` §11.9–§11.10 and in `docs/PROGRESS.md`.
M17 and M18 move into Phase 6 below (they live in `detent-acme`).

### 4.3 PLAN Phase 6 (ACME) — in-repo items (next)

Also in this phase: **M17** (propagate the directory fsync error in the ACME
credential write, `detent-acme` `lib.rs` and `order.rs`; **DONE**, `sync_dir`) and **M18** (a
real test of `present_challenges`, which item 4's seam makes possible).

The gap analysis was done at `c50200e`. In short: the pieces exist, but nothing wires them into `serve`.
1. **Provider HTTPS transport** for Cloudflare, acme-dns and deSEC. Use the hyper-rustls client that `detent-acme` `order.rs` already builds. **The docs are wrong that a new dependency is needed**; fix `providers.rs:51-60` and `Cargo.toml:12-15`. Add TSIG for RFC 2136 with `hmac`/aws-lc (already in the workspace). Add provider selection in `[acme]`. Tests: recorded fixtures, and a **log-capture** test that no secret is logged.
   - **Transport: DONE** (`src/https.rs`; the docs and `Cargo.toml` comments are fixed). **TSIG: DONE** (`src/tsig.rs`, HMAC-SHA2 only; fixtures checked by dnspython). **Provider selection: DONE** (slice A: `[acme.provider]`, `secrets.toml` next to `detent.toml`, checked before the fork). **Open:** the log-capture test (it needs the serve path that logs).
   - **Renewal loop (item 2): owner chose option (b), 2026-09-26: ADR-015.** The ACME client runs in its own confined process and hands each certificate to the worker over a socketpair. Slices: **C1** (`detent-platform`): seccomp role `Acme`, `Policy::acme`, `spawn_acme` (fork, harden, drop, confine), the acme⇄worker message set and channel. **C2** (`detent-acme`): one `issue()` for the whole order flow (the Pebble test calls it), DER validity and ARI helpers. **C3** (`detent`): the acme main loop (`renew_once` behind an `Issuer` seam, backoff, warnings, log-capture test), the worker side that checks and installs a pair, serve wiring, preflight (replaces `cli-serve-acme-unsupported`), docs. **C4** (CI): the Pebble job runs the acme process under its real confinement, and the `Acme` table is proven with `strace -f`. Earlier notes: `present_challenges` needs `publish: &(dyn Fn(&DnsRecord) + Sync)`; ARI needs a DER form of `ari_identifier`; `[acme]` has no EAB field yet.
2. **Renewal loop in `serve`**:
   - Read `[acme]`, order, `CertStore::install_acme` (hot reload), ARI window (`should_renew_ari`).
   - Remove the `cli-serve-acme-unsupported` refusal (`serve.rs:~309`).
   - Implement `Operation::CertRenew` (now `Unsupported`, `engine.rs:~329`).
   - Apply the `shortlived` profile by default on LE.
3. **`detent cert status|renew` CLI**, journal/CLI warnings at 50 %/25 % lifetime, and a renew button on `CertificatesPage.tsx`.
4. **Order-flow seam**, so fixtures can drive `order.rs` and raise the detent-acme floor from 87 toward 100.
5. **Pebble test with a short-lifetime profile that really renews** (`ci.yml` job `acme-pebble`).

Phase 6 items **blocked on the owner or external infrastructure**:
- `hickory-client` propagation checks (new dependency, ADR-011 7-day cooldown);
- the TPM attestor with the step-ca + swtpm CI job (`tss-esapi`, cooldown);
- Let's Encrypt staging run (`docs/spikes/acme-le.md`).

### 4.4 After Phase 6

Phases 7, 8, 9 and 12 are in the gap analysis. Summary:
- **P7:** mounts `daemon-reload` apply; detection of the installed version for `since`-gated options (chrony/samba).
- **P9:**
  - `release.yml`: macOS targets, a double-build SHA gate, the `actions/attest` DSSE bundle (H17 1–7), and egress `block`.
  - Embedded trust root from TUF (`trust.rs:27` placeholder).
  - The UI update apply control.
- **P12:** THREAT_MODEL.md, PENTEST_CHECKLIST.md, `[privilege] mode` plus the doctor check, mTLS, de/ja translations, the mutants and geiger jobs, and semver-checks for detent-core.
- **Needs the owner:** VM runs, release tags, and repo settings.

## 5. Rules that still bind

STAGE3 §00:
- One item per commit, in the §00.3 body format.
- Test first, and show it failing.
- All gates `--all-features`.
- No new suppressions.
- No weakened checks.
- a010 is the only Linux host, test-only, and no packages are removed there for now.
- Commits are signed (`git commit -S -s -F <file>`) and use ASD-STE100 messages.
- Jev only for classification and routing, never for readiness.
