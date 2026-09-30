# BUGFIX — open work, in order

Written 2026-09-30 at `02fd9d5`. This file replaces `STAGE2.md`, `STAGE3.md`
and `STAGE4.md`. Their full text is in git:

- `git show 02fd9d5:docs/STAGE2.md` — the Jev / TypeSafe experiment (post-v1).
- `git show 02fd9d5:docs/STAGE3.md` — the open review items (rewritten 2026-09-26).
- `git show 08e08fa:docs/STAGE3.md` — the full review, every item text, §1–§11.10.
- `git show 02fd9d5:docs/STAGE4.md` — the Phase 6 handoff, traps and gap analysis.

How the documents fit together:

| File | Job |
|---|---|
| [`PLAN.md`](PLAN.md) | The design and the phases, with their acceptance criteria. |
| [`PROGRESS.md`](PROGRESS.md) | The log: one dated entry per landed piece of work. |
| **`BUGFIX.md`** (this file) | The **only** list of open work, the order to do it in, and the rules that bind it. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | How the parts fit together. |

**Item ids.** Ids such as H6, M2, L-PLAT7 or C1-b come from the STAGE3 review;
code comments and ADRs cite them. The full item text is in
`git show 08e08fa:docs/STAGE3.md`.

When an item lands: remove it here (or mark the part that is done) in the same
commit, and add one entry to `PROGRESS.md`. When a phase meets its acceptance
criteria, flip its status line in `PLAN.md` §5.

---

## 1. State (2026-09-30)

- `main` = `02fd9d5`. CI is green on `e5dceef` (the last code change).
- Lint suppressions (`#[allow]`/`#[expect]` in `crates/`): **110**. The count may
  only go down. Check:
  `git grep -c -E '#!?\[(allow|expect)\(' HEAD -- crates | awk -F: '{s+=$NF}END{print s}'`.
- Milestones: **M1** (Phase 3) and **M2** (Phase 5) reached. **M3** (Phase 9)
  needs a release tag. **M4** (Phase 12) not started.

| Phase | PLAN status | Real state |
|---|---|---|
| 0–5 | `[x]` | Done. |
| 6 ACME | `[~]` | In-repo core done: confined acme process (ADR-015), dns-01 providers + TSIG, scheduled and forced renewal, hot reload, `cert status`, renew button, Pebble CI with a 180 s profile. Open: §3 Track B. Blocked: §3 Track G. |
| 7 Modules wave 1 | `[~]` | resolver, chrony, mounts, nfs, samba landed. Open: §3 Track D. |
| 8 Modules wave 2 | `[~]` | network, dhcp landed. Open: VM acceptance runs (§3 Track D). |
| 9 Release + update | `[~]` | Workflows, verifier (ADR-014), swap, rollback, healthz, install POST landed. Open: §3 Track E. |
| 10 FFI + MCP | `[x]` | Done. |
| 11 BSD | `[deferred]` | Parked (PLAN §1.6). Do not schedule. |
| 12 Hardening, v1.0 | `[ ]` | §3 Track F. |

---

## 2. Rules that bind every item

### 2.1 The loop
1. Read the item. **Find every cited line again at HEAD**; line numbers move.
2. **Test first.** Write the test, run it, see it **fail**, and paste the
   failing line in the commit body.
3. Make the smallest fix. Touch only the files the item needs, plus tests,
   Fluent ids and the docs it names. If a control in `SECURITY_HARDENING.md`
   changes, update its row in the same commit.
4. Gates, whole workspace, `--all-features`: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
   `cargo test --workspace --all-features`. For `web/`: `bun run lint`,
   `typecheck`, `test`, `api:check`, `i18n:check`. For a change in `detent`
   that uses an optional crate, also build the three CI feature sets
   (`ci.yml` "cargo build (feature set A/B/default)").
5. Commit signed (`git commit -S -s -F <file>`), one item per commit,
   ASD-STE100 subject ≤ 72 characters, then:
   ```
   Item: <ITEM-ID>
   Test: <test names>; failed before the fix with: <exact line>
   Gates: <commands and results>
   Linux: <testhost binary + command -> result> | container only | n/a
   Allows added: 0
   ```
6. Run CI on the branch (`workflow_dispatch`) before `main` moves.

### 2.2 Never
- More than one item id per commit.
- New lint suppressions: `#[allow]`, `#[expect]`, `#[ignore]`, `biome-ignore`,
  `eslint-disable`, `@ts-*`, `shellcheck disable`.
- Weakened checks: lower coverage floors, relaxed or deleted assertions, tests
  that skip themselves, `|| true` or `continue-on-error` in CI.
- Invented versions, tags or digests. New dependencies follow ADR-011 (7-day
  cooldown, `deny.toml`).
- History rewriting on pushed commits.
- "Done", "green" or "clean" without the command and its result.
- Jev deciding readiness. Jev may classify and route work only; push, merge,
  "done" and release are decided by the gates above.

### 2.3 testhost — test there, never compile there
testhost: Ubuntu (development release), x86_64, kernel 7.3, Landlock present,
passwordless sudo, 2 CPUs, 3 GB RAM. It is the only Linux host for real
daemons and root sandbox runs.
- Build locally (`cargo zigbuild --target x86_64-unknown-linux-musl ...`),
  copy binaries to `testhost:~/detent-test/<short-sha>/`, run there, delete the
  directory when done. Never run `cargo` or `bun`, or edit files, on testhost.
- Runtime packages allowed (record each install in `PROGRESS.md`): `strace
  samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server`. No compilers.
  Do not change network config, users, firewall, sysctls or kernel
  parameters. Start a daemon only for the test that needs it.
- aarch64: no host. For a seccomp change, run `cargo check --target
  aarch64-unknown-linux-gnu -p detent-platform`, pin the aarch64 numbers in a
  unit test, and write "aarch64 runtime unverified".

### 2.4 Traps (do not repeat)
- **`git commit` takes the whole index.** Run `git diff --cached --stat`
  before every commit. Sub-agents never stage another agent's files.
- **Shared `CARGO_TARGET_DIR` across worktrees is unsafe** (freshness is by
  mtime; a stale test binary gives false results). Give each worktree its own
  target dir.
- **Disk:** `make clean` after coverage, fuzz or cross builds; `make
  realclean` once after a pull that changed profiles. `cargo llvm-cov clean
  --workspace` before a coverage run; only the full CI-shaped run is valid for
  the per-path floors.
- **Branch CI:** `ci.yml`, `codespell.yml`, `linter.yml` and `fuzz.yml` run on
  a branch only through `workflow_dispatch`.
- **CI logs and artifacts** are blocked from the cloud container; reproduce
  locally (fuzz: `cargo +nightly fuzz run --target=x86_64-unknown-linux-gnu
  <target> -- -max_total_time=60`).
- **Optional crates in `detent`:** `time` is on only with `update`. Code (and
  tests) built for feature set B cannot use it.
- **Local ACME runs:** pass Pebble's static `test/certs/pebble.minica.pem` as
  the CA (not the per-run root), keep files the `detent` account reads on a
  path it can traverse, and use `curl --noproxy '*'` for loopback requests.
- **Codespell:** smb.conf words (e.g. `browseable`) go in `.codespellignore`.

---

## 3. Work queue

### Order of work (the plan)

| Step | What | Where | Why this order |
|---|---|---|---|
| 1 | **Track A** — security fixes in code | any dev machine | Small, independent, and each closes a real gap in a boundary. |
| 2 | **Track B** — close Phase 6 | any dev machine | The ACME path is live in `serve` now; finish its tests and its operator commands. |
| 3 | **Track C** — testhost runs | owner's setup, **in parallel** with 1–2 | Proves the confined `serve` on a real host; A1 shrinks the monitor filter. |
| 4 | **Track E** — M3 release path | dev machine, then the owner tags | Turns the updater from tested code into a real, verifiable release. |
| 5 | **Track D** — Phase 7/8 gaps | dev machine + VMs | Behavior gaps and acceptance runs; lower risk than 1–4. |
| 6 | **Track F** — Phase 12, v1.0 | orchestrator + owner | Needs the rest to be stable. |
| — | **Track G** — blocked | owner / external | Starts when its blocker clears. |
| after v1 | **§5** — Jev experiment | — | Gated; see §5. |

Owner decisions that block or change items are in §4.

### Track A — security fixes (any dev machine)

In this order (highest risk first):

2. **B6 (H1) — the state lock fallback.** `privsep/monitor.rs` `lock_state`
   falls back to a `/dev/null` lock on `EACCES`, so two monitors share no
   mutual exclusion. Refuse to start with a clear error. Test: a lock file
   that cannot be created refuses the lock.
3. **B4 (C1-b) — the bundle open and the leftover copy.** In the
   `ReplaceBinary` path, open `<tag>.sigstore.json` the way
   `open_staged_input` opens the binary (per-component `O_NOFOLLOW`, owner
   check, regular file, `O_NONBLOCK`), and remove the `O_EXCL` copy on every
   failure path. Tests: symlinked bundle refused; FIFO bundle does not block;
   no copy left after a failed verify.
5. **B9 (L-PLAT7) — trust the staging directory.** Create it `0700`, then
   require owner = monitor euid and no group/other write. Test: mode `0777` or
   another owner is refused.
6. **B2 (H17 step 6) — refuse unknown Rekor entry kinds.** Only
   `hashedrekord` and `dsse`. Test: a `rekord`/`intoto` fixture is refused
   with its own error.
7. **B1 (H17 step 5) — parse the Rekor checkpoint as a signed note.** Size
   **equal** to the proof's `tree_size`, root equal to the computed root,
   signature verified (key hint per the note spec). Tests: the real staging
   checkpoint verifies; wrong size, root or signature each refuse.
8. **B11 — small follow-ups.** (a) `docs/openapi.json`: add `503` to `POST
   /api/v1/auth/login` and regenerate. (b) An existing `<state>/audit`
   directory is not tightened to `0700`; tighten it when the process owns it,
   and test.
9. **B10 (L-BIN18) — the last plain `String` of the typed password**
   (`detent/src/webadmin.rs`): keep it in `Zeroizing<String>`. Evidence: the
   type change and an `rg` in the commit body.
10. **B5 (C1-f) — document capability-user mode** in ADR-001 and
    `SECURITY_HARDENING.md` Gaps: monitor and worker share uid `detent`, so
    staging ownership checks separate nothing. No code change.

B3 (real Fulcio/Rekor trust roots) moved to Track E, item 2.

### Track B — close Phase 6 (any dev machine)

1. **Log-capture test** (Phase 6 task 2): run the acme loop with each
   provider against fixtures and assert that no secret (API token, TSIG key)
   reaches the log output.
2. **Order-flow seam** (`detent-acme` `order.rs`) so fixtures can drive the
   order flow; raise the `detent-acme` coverage floor from 87 toward 100.
   Then **M18**: a real test of `present_challenges`.
3. **`detent cert renew`**: it must authenticate to the running server (a
   token, not a local bypass). Also wire `Operation::CertRenew` and
   `CertStatus` in the engine so the MCP tools stop answering `Unsupported`.
4. **Journal warnings** at 50 % and 25 % of lifetime from the acme process
   (the CLI and UI already warn).
5. **`shortlived` by default on Let's Encrypt:** `order.rs` supports the
   profile, but only a test requests it. Make the `serve` path request it
   when the CA advertises it, and test that.
6. **aarch64 syscall trace** of the acme process (C4 was x86_64 only). Needs
   an aarch64 host or runner; until then keep "aarch64 runtime unverified".

Phase 6 is done (`[x]` in PLAN) when 1–5 land and Track G is either done or
deferred by the owner.

### Track C — testhost (owner's local setup; parallel)

1. **A1 (H6) — trace a confined `serve`, then shrink the monitor filter.**
   Run `detent serve` under `strace -f` with one module that has a validator
   (chrony); drive one `plan` and one `systemctl restart` through the API.
   Confirm the validator and `systemctl` ran in the runner's tree with no
   `SIGSYS`, then remove from `MONITOR` every process-creation call the
   monitor no longer uses (keep `KillProcess`). Replace
   `enforce_mode_monitor_can_spawn_a_validator` with a test that a confined
   monitor dies by `SIGSYS` on `execve`. Record the trace in
   `SECURITY_HARDENING.md` (runner row).
2. **A2 (H6) — full confined `serve` end to end** with the packaged units:
   HTTPS login, `plan` and `apply` with a real validator, a service restart,
   commit-confirm expiry and rollback, shutdown on `SIGTERM`. Each failure
   becomes its own item here.
3. **A3 — negative checks never run.** In a throwaway worktree with its own
   target dir, remove each fix, run its pinning test, and quote the failure.
   A test that does not fail is vacuous: write a real one first.

   | Item | Pinning test(s) | Needs testhost |
   |---|---|---|
   | C1-a | `read_staged_verified_refuses_a_hard_linked_image` (add a dispatch-level test) | no |
   | C1-c | wrong-identity / missing-bundle / embedded-roots / valid-release tests in `monitor.rs` | no |
   | H1 | `serve_locked`, `rollback_pending_on_exit`, CLI recovery tests | no |
   | H2 | the 4 commit-confirm arming tests in `detent-ops/src/engine.rs` | no |
   | H12 | `http_transport_refused_for_root` | no |
   | M1 | `caps_that_do_not_drop_are_fatal_only_when_required` | yes (root) |
   | M11 | `bind_table_keeps_bearer_on_loopback`, `http_config_enforces_origin_validation` | no |
   | L-PLAT6 | `stdout_pattern_requires_literal_match_and_exit_zero` | no |
   | L-PLAT7 | `run_check_places_the_candidate_in_monitor_staging` | no |
   | L-BIN16 | the two `spawn.rs` child-abort tests | no |

   The rows marked "no" can run on any dev machine and may go with Track A.
4. **A4 (M1) — the worker's capability report after `setuid`.**
   `drop_capabilities` reports `Applied` while the bounding set is still full.
   Report the real state (or drop the bounding set before the uid change).
   Test on testhost as root: compare `/proc/self/status` `CapBnd` with the
   reported outcome.

### Track D — Phase 7/8 gaps

1. **mounts:** apply runs `daemon-reload` (and the optional mount) through
   the monitor, as PLAN Phase 7 says.
2. **Version-gated options** (chrony, samba): detect the installed version so
   `since`-gated options are offered only when supported.
3. **VM acceptance runs** (owner): Phase 7 per-module spikes
   (`docs/spikes/m-<module>.md`) and the Phase 8 matrix (Debian ifupdown +
   NM, Ubuntu netplan, Fedora NM, Arch networkd), including one deliberate
   misconfiguration rolled back by commit-confirm.

### Track E — Milestone M3 (release path)

1. **R1 (H17 steps 1 and 8):** `release.yml` publishes the `actions/attest`
   DSSE bundle as `detent-<triple>.sigstore.json` (not the cosign
   message-signature bundle). After the first real release, commit one
   captured bundle as a fixture and add `real_attest_bundle_verifies`.
2. **B3 (H17 step 7) — real trust roots:** embed the real Fulcio root and
   intermediate and the real Rekor key (paste source and digests in the commit
   body); later from TUF (PLAN §2.9, `trust.rs`). Test: a real Fulcio leaf
   chains to the embedded root.
3. `release.yml`: macOS targets, the two-build SHA-256 gate, harden-runner
   egress `block`.
4. **UI update apply control** (the install POST exists; the web UI has no
   control for it).
5. **Owner:** tag `v0.0.1-rc`, then `v0.1.0`; run the M3 acceptance (a device
   updates and rolls back from a broken `v0.1.1-test`); set immutable
   releases and the rulesets in `docs/RELEASING.md`.

### Track F — Phase 12 / M4 (v1.0)

`THREAT_MODEL.md` (STRIDE per component, mapped to tests; it must also cover
any egress §5 would add), `PENTEST_CHECKLIST.md` (ASVS L2), `[privilege]
mode = "capability-user"` with polkit and the doctor check, optional mTLS,
`de`/`ja` translations (marked `# needs-review`), `cargo-mutants` and
`cargo geiger` jobs, `cargo semver-checks` for `detent-core`, final size/RSS
numbers in the README, then v1.0.0. Acceptance is in PLAN Phase 12.

### Track G — blocked on the owner or external infrastructure

- `hickory-client` propagation checks (new dependency; ADR-011 cooldown).
- TPM attestor (`device-attest-01`) with the step-ca + swtpm CI job
  (`tss-esapi`; cooldown).
- Let's Encrypt staging run (`docs/spikes/acme-le.md`).

---

## 4. Owner decisions

Format: `- <ITEM>: <question> — proposed: <default> — owner answer:`

- H5: apply refuses when a declared validator cannot run (binary missing), not
  only when it fails. — proposed: keep fail-closed — owner answer:
- M5: `plan` runs root validators but needs only read scope. — proposed: keep
  read scope (plan writes nothing; validators get a staged copy) — owner answer:
- C1-b: chunked `StageUpdate`, so the worker never writes update bytes to a
  path the monitor reads. The interim (`4b098d0`, `95f6b01`) copies into
  monitor staging with no-follow opens and owner checks. — proposed: confirm
  the interim, defer chunking — owner answer:
- D4: remove build toolchains from testhost. — proposed: after Track C A1–A3 —
  owner answer:
- libbz2 on testhost: `libbz2-1.0` was downgraded to `1.0.8-6build2` by an earlier
  agent. — proposed: restore the distro version — owner answer:
- Track G: defer `hickory-client`, the TPM attestor and the LE staging run past
  v1, so Phase 6 can close? — proposed: defer the TPM attestor; keep the other
  two for v1 — owner answer:

---

## 5. After v1: the Jev / TypeSafe experiment (was STAGE2)

**Status: investigation only. No product code.** Full text, including the
request shapes and the 2026-09-22/23 results: `git show 02fd9d5:docs/STAGE2.md`.

**Gate — all must hold before any work:** Tracks A–F done (v1.0 shipped, CI
green), `THREAT_MODEL.md` covers the added egress, and the owner answers
**yes** to the egress question. If no, this section closes. (The offline
corpus harness may run earlier: it touches no product code, but it needs
A1/A2 so the apply path produces real check results.)

**Candidates:**
- **Doctor urgency ranking — first trial.** Read-only and display-only; send
  only the check name, its status and a fixed detail id.
- **Apply blast-radius advisory — conditional.** It may only **add** friction
  (require a confirm, lengthen the window, show a banner). Build it only if
  the evaluation below passes.
- **MCP natural-language routing — rejected** (duplicates the client's job;
  prompt-injection surface).
- Never Jev: authz, privsep, validation, update verification.

**Hard constraints:**
- Off by default; an explicit `[typesafe]` section (`enabled`, `endpoint`,
  pinned `model`, `timeout_ms`, key **file** path `0600`). The key is
  redacted in `Debug`, logs, audit and every endpoint. Calls run in the
  worker only, over the existing hyper-rustls stack; set an explicit
  User-Agent.
- **Structural state only:** a typed `ApplyFeatures` struct (module id,
  service action, unit names, hunk and line counts, check results, Fluent
  ids, commit-confirm flag) with no free-text field. A test proves a secret in
  `PlanReport.rendered` never reaches the request.
- **Fail safe:** any error, timeout (≤ 1 s), 403, 429, 5xx or parse failure
  means "feature off". The answer can never skip a confirm, override a
  failing check or shorten a window; confidence < 0.5 maps to `confirm`.
  Record the friction level and its source in the audit record, never model
  text.

**Evaluation (must pass before product code):** a corpus of 30 real-engine
plans (12 benign, 12 risky, 6 ambiguous) over structural state; go only if
≥ 90 % of risky plans get `confirm`/`hold`, zero benign plans get `hold`, p95
≤ 1 s from testhost, no WAF 403, and low confidence on ≤ 30 %. Re-run when the
pinned model changes.
