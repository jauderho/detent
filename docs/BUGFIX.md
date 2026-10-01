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
   Linux: <a010 binary + command -> result> | container only | n/a
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

### 2.3 a010 — test there, never compile there
a010: Ubuntu (development release), x86_64, kernel 7.3, Landlock present,
passwordless sudo, 2 CPUs, 3 GB RAM. It is the only Linux host for real
daemons and root sandbox runs.
- Build locally (`cargo zigbuild --target x86_64-unknown-linux-musl ...`),
  copy binaries to `a010:~/detent-test/<short-sha>/`, run there, delete the
  directory when done. Never run `cargo` or `bun`, or edit files, on a010.
- Runtime packages allowed (record each install in `PROGRESS.md`): `strace
  samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server`. No compilers.
  Do not change network config, users, firewall, sysctls or kernel
  parameters. Start a daemon only for the test that needs it.
- Exception (owner, 2026-09-30): system user `detent` (uid 999, gid 979,
  no home, `nologin`) was added on a010 for Track C `serve` runs, which
  drop the worker to it. **Remove it later** (`sudo userdel detent`) with
  the D4 cleanup. Restarting `chrony` for Track C is allowed.
- aarch64: the owner's Apple silicon Mac with OrbStack runs a native
  aarch64 Linux kernel (Landlock, seccomp, ptrace). Use a `--privileged`
  container (Docker's own seccomp profile is then off) and cross-built
  binaries. x86_64 containers there run under Rosetta: not valid for a
  seccomp trace; use a010.

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
- **Stale cherry-pick sequence.** An old `.git/sequencer` (from an unfinished
  multi-commit cherry-pick) makes `git cherry-pick --continue` resume it and
  apply old commits. Check `ls .git/sequencer` first. Clear it with
  `git cherry-pick --quit` after restoring the touched files; **never**
  `--abort`, which resets HEAD to the sequence's old start.
- **Codespell:** smb.conf words (e.g. `browseable`) go in `.codespellignore`.

---

## 3. Work queue

### Order of work (the plan)

| Step | What | Where | Why this order |
|---|---|---|---|
| 1 | **Track A** — security fixes in code | any dev machine | Small, independent, and each closes a real gap in a boundary. |
| 2 | **Track B** — close Phase 6 | any dev machine | The ACME path is live in `serve` now; finish its tests and its operator commands. |
| 3 | **Track C** — a010 runs | owner's setup, **in parallel** with 1–2 | Proves the confined `serve` on a real host; A1 shrinks the monitor filter. |
| 4 | **Track E** — M3 release path | dev machine, then the owner tags | Turns the updater from tested code into a real, verifiable release. |
| 5 | **Track D** — Phase 7/8 gaps | dev machine + VMs | Behavior gaps and acceptance runs; lower risk than 1–4. |
| 6 | **Track F** — Phase 12, v1.0 | orchestrator + owner | Needs the rest to be stable. |
| — | **Track G** — blocked | owner / external | Starts when its blocker clears. |
| after v1 | **§5** — Jev experiment | — | Gated; see §5. |

Owner decisions that block or change items are in §4.

### Track A — security fixes (any dev machine)

All ten items landed on 2026-09-30 (`PROGRESS.md`).

Follow-ups found while reviewing Track A (not yet scheduled):
- **Real `hashedrekord` body.** `verify_hashedrekord_body`
  (`detent-update/src/verify.rs`) expects a bare public key, but a real
  `hashedrekord` entry embeds the Fulcio certificate. Production bundles use
  `dsse`, so updates are not blocked; a real `hashedrekord` bundle would
  fail body agreement. Fix with a captured real fixture (Track E, R1).
- **Owner of the staged file itself.** `open_staged_input` (used for the
  update binary and, since B4, its bundle) checks the owner of each
  directory, not of the file. Consider requiring the file's owner to be the
  worker uid (root-confined mode) as a second barrier.
- **Legacy syscalls in `MONITOR`, not yet traced.** The confined monitor
  now uses only the `*at` forms on the request paths (`unlinkat`, `fchmod`,
  `renameat`; a read and write copy in place of `copy_file_range`; owner
  decision 2026-09-30, no table change). Traced 2026-09-30 (`PROGRESS.md`):
  aarch64 musl has no call outside `MONITOR`. **x86_64 musl (the release
  target) kills the monitor with `SIGSYS`** in 10 of 13
  `enforce_mode_monitor_*` tests: musl issues `stat` and `lstat`, and
  `MONITOR` has only `newfstatat`/`statx`. `WORKER` has the same gap
  (`stat`, `EPERM`; `enforce_mode_worker_can_tighten_an_audit_directory`
  fails). Fixed 2026-09-30 (owner decision): `MONITOR` gets `stat` and
  `lstat`, `WORKER` gets `stat`; a010 then passes 18 of 18 `enforce_mode_*`.

B3 (real Fulcio/Rekor trust roots) moved to Track E, item 2.

### Track B — close Phase 6 (any dev machine)

1. ~~**Log-capture test**~~ Done 2026-09-30 (`PROGRESS.md`).
2. ~~**Order-flow seam** and **M18**~~ — done 2026-09-30 (`PROGRESS.md`):
   a scripted `instant_acme::HttpClient` drives `present_challenges`,
   `wait_ready` and `finalize`; `detent-acme` floor 87 → 93.
   The wildcard name and the two-values-at-one-name follow-up are fixed
   (2026-09-30, `PROGRESS.md`).
3. ~~**`detent cert renew`**~~ — done 2026-09-30 (`PROGRESS.md`): it asks
   the running server over HTTPS with an API token (owner decision
   2026-09-30). The MCP tools `cert_status` and `cert_renew` are wired too
   (engine hook `CertFrontEnd`, installed by `detent mcp`).
4. ~~**Journal warnings**~~ — done: `renew_once` calls `warn_expiry`, which
   logs a `tracing::warn!` at half and at a quarter of the lifetime to
   stderr, and systemd sends stderr to the journal (test
   `expiry_warnings_go_to_the_log_at_half_and_a_quarter`, `acme.rs`).
6. **aarch64 syscall trace** of the acme process — traced 2026-09-30
   (`PROGRESS.md`): `scripts/acme-serve-check.sh`, unchanged, on the
   aarch64 musl binary. All serve checks pass; the one call outside `ACME`
   is `faccessat` (mimalloc's NUMA probe, the aarch64 form of the tolerated
   `access`), refused with `EPERM`. The script now tolerates it (owner
   decision 2026-09-30) and passes on aarch64. Done.

Follow-ups found in item 3 (not yet scheduled):
- ~~**`mcp` without `web` has no certificate hook.**~~ Done 2026-09-30:
  `mcp` implies `web` (owner decision). An `mcp`-only build also had no
  `detent token` command to mint its own token.
- ~~**Stale lines in `docs/API.md`.**~~ Done 2026-09-30: `mcp` now implies
  `web`; `cert_renew` is a normal parity pair with `renew_cert`.

Phase 6 is done (`[x]` in PLAN) when 1–5 land and Track G is either done or
deferred by the owner.

### Track C — a010 (owner's local setup; parallel)

1. ~~**A1 (H6) — trace a confined `serve`, then shrink the monitor filter.**~~
   Done 2026-09-30 (`PROGRESS.md`): 23 process-creation rows removed; found
   A5 (AppArmor).
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
   Run 2026-09-30 on a010 (`PROGRESS.md`): passes end to end with a
   test-only drop-in `NoNewPrivileges=no`. Fixed on the way: optional
   `ReadWritePaths`, staging in `RuntimeDirectory=`, `CAP_SETPCAP`, no
   `StateDirectory=`, `ConfigurationDirectoryMode=0750`, and error causes in
   the journal. A2-a fixed 2026-10-01 (ambient capabilities); A2 then
   passes with the shipped unit. Open (§4): A2-b `detent setup` as root.
3. **A3 — negative checks never run.** In a throwaway worktree with its own
   target dir, remove each fix, run its pinning test, and quote the failure.
   A test that does not fail is vacuous: write a real one first.

   | Item | Pinning test(s) | Needs a010 |
   |---|---|---|
   | C1-a | `read_staged_verified_refuses_a_hard_linked_image` (add a dispatch-level test) | no |
   | C1-c | wrong-identity / missing-bundle / embedded-roots / valid-release tests in `monitor.rs` | no |
   | H1 | `serve_locked`, `rollback_pending_on_exit`, CLI recovery tests | no |
   | H2 | the 4 commit-confirm arming tests in `detent-ops/src/engine.rs` | no |
   | H12 | `http_transport_refused_for_root` | no |
   | M1 | `caps_that_do_not_drop_are_fatal_only_when_required` | yes (root) |
   | M11 | `bind_table_keeps_bearer_on_loopback`, `http_config_enforces_origin_validation` | no |
   | L-PLAT6 | `stdout_pattern_requires_literal_match_and_exit_zero` | no |
   | L-PLAT7 | `run_check_places_the_candidate_beside_the_primary_target`, `run_check_uses_monitor_staging_for_a_module_without_a_file_target` | no |
   | L-BIN16 | the two `spawn.rs` child-abort tests | no |

   The rows marked "no" can run on any dev machine and may go with Track A.
4. **A4 (M1) — the worker's capability report after `setuid`.**
   `drop_capabilities` reports `Applied` while the bounding set is still full.
   Report the real state (or drop the bounding set before the uid change).
   Test on a010 as root: compare `/proc/self/status` `CapBnd` with the
   reported outcome.

5. ~~**A5 (new, found in A1, 2026-09-30) — AppArmor blocks validators that
   read the candidate.** On a010 (Ubuntu) the `chrony` check ran in the
   runner and failed: `chronyd: Could not open
   /run/detent/staging/detent-candidate-V2VU39 : Permission denied`; the
   kernel log shows `apparmor="DENIED" operation="open"
   profile="/usr/sbin/chronyd" name="/run/detent/staging/detent-candidate-…"`.
   `kea-dhcp4` also has an enforcing profile on a010 (not yet run); so a
   `plan`/`apply` of these modules always reports the check as failed on
   Ubuntu. Owner choice (§4, "AppArmor validators"). Not a seccomp or
   Landlock refusal.
   Done 2026-09-30 (owner: move the candidate to paths the profiles
   already allow): the candidate is written beside the module's primary
   target as `.detent-candidate-*`; a010 `serve` chrony check ran and
   passed with AppArmor enforcing.

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
- D4: remove build toolchains from a010. — proposed: after Track C A1–A3 —
  owner answer:
- libbz2 on a010: `libbz2-1.0` was downgraded to `1.0.8-6build2` by an earlier
  agent. — proposed: restore the distro version — owner answer:
- Legacy stat forms: add `stat` and `lstat` (x86_64 only; aarch64 has
  neither) to `MONITOR`, and `stat` to `WORKER`, so the x86_64 musl release
  binary works; add `faccessat` to the acme `TOLERATED_EPERM` list in
  `scripts/acme-serve-check.sh` (the aarch64 form of `access`). —
  proposed: yes (same operation as the allowed `newfstatat`) — owner answer:
  yes, all (2026-09-30).
- AppArmor validators (Track C A5): ship AppArmor local includes, or
  stage the candidate in a path the distro profiles already allow. — owner
  answer (2026-09-30): the latter; real config locations stay as they are
  (detent supplements the host's binaries, it does not replace them).
- A2-a: `CAP_SETUID` missing under the unit. — owner answer (2026-10-01):
  stay with capabilities. Cause: systemd 261 drops `CAP_SETUID` from a root
  service with `NoNewPrivileges=yes` plus any seccomp-based directive. Fix:
  `AmbientCapabilities=CAP_SETUID CAP_SETGID`; `NoNewPrivileges=yes` stays.
- A2-b: `sudo detent setup` (what the installer and README suggest)
  writes `/var/lib/detent/state/users.json` as root, and the worker
  (`detent`) cannot read it, so `serve` fails. — proposed: when run as
  root, `setup`/`user`/`token` refuse and say `sudo -u detent detent
  setup`; the installer prints that — owner answer:
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
≤ 1 s from a010, no WAF 403, and low confidence on ≤ 30 %. Re-run when the
pinned model changes.
