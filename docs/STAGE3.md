# STAGE3 — Adversarial review of all code to date

Status: REVIEW ONLY. No production code was changed for this stage.
Baseline: `3f502ff` (2026-09-22). Re-checked against `69b1de7`
(2026-09-23), which adds oh-my-pi's ReplaceBinary hardening
(`65ad621`, `e396d26`, `98f5ec3`) and cert-status work. Line numbers are
as of `3f502ff` unless the item says otherwise. **Re-locate every line
before you edit it** — the tree is moving.

This file is written for an implementor that did not see the review. Each
item is self-contained: problem, evidence, fix, test, acceptance. Read
**§00 and §0** before starting any item. **§11 tracks what is done.**

---

## 00. Orchestrator steering — binding on every implementing agent

The orchestrator (Claude) owns this file and the work order. Implementing
agents (oh-my-pi and any sub-agent it spawns) execute it. The orchestrator
audits every commit against this section. Work that breaks it is reopened,
whether or not the code is correct.

### 00.1 Authority and scope
- **This file is the work order.** Do only STAGE3 items. No PLAN.md feature work, no refactors, no "while I'm here" edits, and no STAGE2 work until the orchestrator marks STAGE3 complete in §11.
- **You may edit only §11 (status) and §12 (questions)** of this file. §00–§10 belong to the orchestrator. If an item is wrong or cannot be done as written, stop that item, write the reason in §12, and move to the next item.
- **Never** delete, rename, revert, stash, `git checkout --`, `git restore`, `git clean` or regenerate `docs/STAGE2.md` or `docs/STAGE3.md`. Both are committed. If either is missing or changed without your edit, run `git restore --source=HEAD docs/STAGE2.md docs/STAGE3.md` and log it in §12.
- `DECISION` items: build the non-decision parts. For the decision itself, stop and list it in §12 with the documented default. Do not pick a default yourself unless §12 records the owner's answer.

### 00.2 Where to start
Start at **§11.3 step 1** and go in order. Items reopened by the orchestrator jump the queue. Within a batch you may choose the order, including with Jev, but Jev must never decide whether something is ready, done, or pushable.

### 00.3 The loop — one item at a time
1. Read the item in full. Re-locate every cited line at HEAD; the line numbers are old.
2. **Test first.** Write the named test (or an equivalent with the same assertion) and run it. It must **fail**.
   - For items already changed by `dc3a279` or other earlier commits, prove the test is not vacuous: revert only the relevant hunk locally, show the test fails, then restore the hunk.
   - Paste the failing output into the commit body.
3. Make the smallest fix that makes the test pass. Touch only files the item names, plus tests, Fluent ids, and the docs the item says to correct.
4. Run **all** gates from §0.4 on the whole workspace with `--all-features`. For `web/` changes, also run the web gates. If you touch `sandbox/`, `privsep/`, seccomp, Landlock or caps, run the Linux check on **a010** (§00.5).
5. Commit **one item per commit** (`git commit -S -s`), with this body format:
   ```
   <imperative ASD-STE100 subject, ≤72 chars> (<ITEM-ID>)

   Item: <ITEM-ID>
   Test: <test name(s)> — failed before fix: yes (<one-line failure>)
   Gates: fmt=0 clippy=0 test=0 (<N> passed) [web=0]
   Linux: a010 <binary + exact command> -> <result> (built locally: <zigbuild cmd>)   |   n/a
   Allows added: none   |   <lint> at <file:line> because <reason>
   ```
6. Update this file's §11: move the item to "Done — verified by implementor" with the commit hash. Add one PROGRESS.md entry per item.
7. **Push after every 1–3 items**, then run `gh run watch` on the resulting CI run. If CI goes red, fixing it becomes the next item, before anything else.

### 00.4 Hard prohibitions (any one of these gets the commit reopened)
- **Batch commits.** More than one item ID per commit is forbidden (`dc3a279` is the example not to follow). A commit touching more than ~400 changed lines outside tests or fixtures needs a §12 note first.
- **New lint suppressions.** No new `#[allow]`, `#![allow]`, `#[expect]`, `#[ignore]`, `// biome-ignore`, `eslint-disable` or `@ts-*`. The count is 116 at `6c1d723` and may only go down. If a suppression is truly unavoidable, write the §12 note first and name it in the commit body.
- **Weakening checks.** No lowering coverage floors, relaxing assertions, deleting tests, special-casing `cfg(test)`, adding `|| true` in CI, or `continue-on-error`.
- **Unverified pins.** Never invent versions, tags or digests. Resolve them first (`docker manifest inspect`, `gh api`, `cargo search`, `npm view`) and paste the proof in the commit body. New dependencies follow ADR-011: a 7-day cooldown and a `deny.toml` check.
- **History rewriting.** No force-push, `rebase -i`, `reset --hard` on pushed commits, or amending pushed commits.
- **Other hosts.** No Linux host other than **a010**: not a009, not k001, not CI runners over ssh.
- **Claims without evidence.** "Done", "clean" or "green" must be backed by the command and its exit code in the commit body. A macOS-only run never counts as Linux verification.
- **Scratch files in the repo.** Throwaway files go in `/tmp`. Remove stray worktrees when done (`git worktree list`; `/private/tmp/wt-f3309b6` exists now).

### 00.5 Linux host: a010 only — test there, never compile there
a010 is Ubuntu (development release) on x86_64, kernel 7.3, with Landlock present (`/sys/kernel/security/lsm` lists `landlock`), `fs.protected_hardlinks=1`, passwordless sudo, 2 CPUs, 3 GB RAM, and 66 GB free. It is a **test target only**. The owner directed (2026-09-24) that nothing is compiled on a010.

**Build locally, copy binaries up.** On the macOS dev host:
```bash
rustup target add x86_64-unknown-linux-musl          # once
export PATH="$PWD/spikes/bin:$PATH"                  # zig shim (docs/TOOLS.md)
# product binary
cargo zigbuild --release --target x86_64-unknown-linux-musl -p detent --all-features
# test binaries for the crate under change (no run)
cargo zigbuild --target x86_64-unknown-linux-musl -p detent-platform --all-features --tests --no-run --message-format=json \
  | jq -r 'select(.profile.test == true) | .executable'
```
- Copy the binaries to `a010:~/detent-test/<short-sha>/` with `scp` or `rsync`, then run them there. Run root-required sandbox and privsep tests with `sudo`, for example `sudo ./detent_platform-<hash> sandbox:: --test-threads=1`.
- Never `cargo build`, `cargo test` or `bun` on a010. Never edit files there.
- Delete `~/detent-test/<old-sha>/` directories when done with them.
- If a test reads fixtures through `CARGO_MANIFEST_DIR`, rsync only the needed crate directory (no `target/`) to the same absolute path on a010 under a throwaway tree. Record the path in the commit body.
- If `cargo zigbuild` for musl fails on a crate, stop and write it in §12. Do not fall back to building on a010.

**Allowed provisioning on a010 (runtime only; record each command in PROGRESS.md):** apt `strace samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server` (chrony, netplan and strace-capable sudo are already present). No compilers, no rustup, no bun, no build-essential.

Do not change a010's network config, users, firewall, sysctls or kernel params. Do not enable or start any installed daemon beyond what a single test needs, and stop it afterwards.

**What still runs where:**
- macOS local: fmt, clippy, the full `cargo test --workspace --all-features`, web gates, and fuzz.
- a010: Linux-only runtime behaviour (sandbox, privsep, seccomp, Landlock, caps, confined `detent serve`, and the real validators `chronyd -p`, `testparm`, `unbound-checkconf`, `exportfs`, `dnsmasq --test`, `kea-dhcp4 -t`).
- GitHub CI: the Linux full-workspace test run and Linux coverage. CI green on a pushed commit is the final gate.

**aarch64:** no aarch64 host is available. For seccomp or arch-specific changes, run `cargo check --target aarch64-unknown-linux-gnu -p detent-platform` locally and add a unit test that pins the aarch64 syscall numbers. Record "aarch64 runtime unverified" in §11. Do not claim it.

### 00.6 Reporting
- At the end of each session, append a dated block to §11 with:
  - items done (id + hash);
  - items opened in §12;
  - the gate state at HEAD;
  - the latest CI run URL and conclusion;
  - the current allow count (`git grep -c -E '#!?\[(allow|expect)\(' HEAD -- crates | awk -F: '{s+=$NF}END{print s}'`).
- If PROGRESS.md or any doc claims something you find is false, correct it in the same item's commit.

---

## 0. Rules for the implementor

1. **One item = one commit** (`git commit -S -s`, ASD-STE100 message).
   Do not batch items. Do not fix adjacent things you notice; add them to
   §12 instead.
2. **Test first.** Write the test named in the item, run it, confirm it
   **fails** on the current tree, then fix, then confirm it passes. If the
   test passes before the fix, stop: the finding or the test is wrong —
   report it, do not force it.
3. **Never game the check.** No `#[allow]`, no `#[ignore]`, no weakened
   assertions, no `cfg(test)` special-casing, no deleting tests. The
   workspace denies `unwrap_used`/`expect_used` even under test — tests
   return `Result`.
4. **Gates before every commit** (all must pass; quote failures verbatim):
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```
   For `web/` items: `cd web && bun run typecheck && bun run lint && bun run test && bun run i18n:check`.
   `--all-features` is mandatory: per-crate or default-feature runs are
   how the current red CI (H20) was missed.
5. **Linux items** (anything under `sandbox/`, `privsep/`, seccomp,
   Landlock, caps) must be verified on **a010**, the only Linux host
   allowed (§00.5). macOS cannot run them. There is no aarch64 host: use
   `cargo check --target aarch64-unknown-linux-gnu` plus syscall-number
   unit tests, and mark aarch64 runtime as unverified.
6. **Items marked `DECISION` need an owner answer first.** The default
   named in the item is what to do if the owner says "use the default".
7. New user-facing strings need a Fluent id in `locales/en-US/*.ftl`.
8. Append a PROGRESS.md entry per landed item. State what was verified
   and how; never "should work".
9. **Order matters.** Follow §2. In particular **H5 must not land before
   H6**: running validators on apply while the monitor's seccomp filter
   forbids `execve` kills the monitor on every apply on a confined host.
10. **Never delete or revert `docs/STAGE3.md` or `docs/STAGE2.md`.** Update
    §11 when an item lands. Keep uncommitted docs out of any `git stash`,
    `git checkout -- .`, or `git clean`.

Model routing (per AGENTS.md; Jev-routed, reviewed by the orchestrator):
**Opus** = security boundary, privsep, crypto, concurrency, or
cross-component state machines. **Sonnet** = local, well-specified change.
The tier is given per item.

---

## 1. How this review was done

- Baseline gates, run by the orchestrator on macOS at `3f502ff`:
  - `cargo test --workspace --all-features`: exit 0, 61 suites.
  - `cargo clippy --workspace --all-targets --all-features -D warnings`: **FAILS**, 2 errors in `crates/detent/src/mcp.rs`.
  - Coverage (`cargo llvm-cov` + `scripts/coverage-merge.sh`): **FAILS**. detent-ops 99.64/100, detent-web 96.81/97, detent 91.64/95.
  - Web typecheck, lint, test (436 pass) and i18n: all green.
  - `fuzz/Cargo.lock`: consistent.
  - GitHub CI on `main`: the last 5 `ci.yml` runs failed. `fuzz.yml` has failed every day since 2026-09-18.
- Eight parallel read-only reviewers, one per crate group: Opus for all Rust, Sonnet for the SPA, scripts and CI. The orchestrator then re-read the code behind every critical and high item and most mediums. Each item carries a **Verified** line:
  - `orchestrator`: re-read and confirmed by the orchestrator.
  - `reviewer`: fully traced by a reviewer and spot-checked.
  - `plausible`: the code path is confirmed, but the external behaviour (upstream daemon semantics, GitHub behaviour) was not executed.
- Complex reasoning (review, verification, fix design, the STAGE2 assessment) was done by the default model.
- **Jev (`jev-1.13.0`, live `POST /v1/systemone`)** was used only for classification and routing:
  1. **Reviewer-tier routing:** one Choice per review unit, 13 units, 2,382 input tokens. Result: 12/13 were routed to the strong tier; `web-spa` got conf 0.36, so it went to Sonnet.
  2. **Severity cross-check:** one Score per deduplicated finding (49 items). Jev rated most mediums a band higher than the orchestrator. The orchestrator raised **M26 → H23** (a Score of 2.9 is right: the worker can write `root preexec` into smb.conf) and kept the rest.
  3. **Implementor-tier routing:** one Choice per finding. The orchestrator overrode it where Jev's confidence was below 0.3.

  Steps 2 and 3 went in one request: 98 questions, 13,946 input tokens.
- Payloads containing literal paths such as `/etc/...` or words like "root" were blocked by the TypeSafe Cloudflare WAF (HTTP 403). Neutral wording worked. Keep this in mind for Stage 2 (see §8).

---

## 2. Fix order (batches)

| Batch | Items | Why first |
|---|---|---|
| 0 CI green | H20 | Nothing else can be trusted while CI is red. |
| 1 Root boundary | C1 residuals, H23, H6, H12, M1, M2, M11 | Worker-compromise → root, and a monitor that dies on first use. |
| 2 Commit-confirm | H1, H2, H3, H4, H21, H22, M7, L-OPS14 | The lock-out safety net is broken in five independent ways. |
| 3 Apply safety | H5 (after H6), M5, M20, M21, L-OPS12 | Validators never gate apply; edits misplace lines. |
| 4 Config injection | H13, H14, H15, H16, M22–M25, M8, L-MODA11, L-MODB7 | Typed-model boundary can be escaped per module. |
| 5 Web auth | H8, H9, H10, M9, M10, M6 | Pre-auth DoS and revocation that does nothing. |
| 6 Audit | H7, M3, M4 | Audit fails open and is forgeable. |
| 7 Self-update | H17, H18, H19, M14, M16, L-SUP12..15 | Update cannot work on any real host today. |
| 8 ACME | M15, M17, M18, M19, L-SUP10/11/16..18 | Latent (no production caller yet) — fix before wiring the loop. |
| 9 MCP / FFI / CLI | H11, M12, M13, L-BIN* | |
| 10 Docs / claims | §7 | Make the docs stop lying. |

**Process finding:** the recent log shows new feature slices (ACME status fields, the renewal predicate) landing while CI on `main` is red. Jev "push_ready" Nouls were also used as a gate (PROGRESS 2026-09-22). Readiness must be the deterministic gate (§0.4, CI green), never a model judgement. **Freeze feature work until batches 0–2 land.**

---

## 3. Critical

### C1 Root monitor installs a binary chosen by the worker (privsep escape) — PARTIALLY FIXED
- Tier: Opus. Verified: orchestrator. Reviewers: PLAT-1, PLAT-4, OPS-1.
- Location: `crates/detent-platform/src/privsep/monitor.rs` `replace_binary`, `read_staged_verified`, `swap_running_binary`; `crates/detent-ops/src/engine.rs` `update_apply`; `packaging/tmpfiles.d/detent.conf` (`/var/lib/detent 0700 detent:detent`); `sandbox/mod.rs` `Policy::worker` (`writable_paths = [state_root]`).
- **Original defect (at `3f502ff`):** the monitor checked the staged file only against a length and SHA-256 that the worker itself sent. The file lived in a directory the worker owns. A compromised worker could stage any ELF, send `ReplaceBinary`, and root would swap it over `current_exe`: root code execution on the next restart. The monitor also re-opened the path by name after hashing (TOCTOU) and hard-linked the worker-owned inode into place.
- **What `65ad621`/`e396d26`/`98f5ec3` fixed (reviewed, sound as an interim):**
  - The staged file is opened `O_RDONLY|O_NOFOLLOW|O_CLOEXEC` and must be a regular file.
  - It must be owned by the monitor's euid.
  - Its bytes are read from that fd, hashed, and those same bytes are written to the target, with no re-open and no hard link.
  - Because the engine materialises the digest file worker-side, the web `UpdateApply` path now **fails closed** on a privileged monitor.
- **Residual work (do all of these):**
  - **C1-a — hard-link / downgrade.** Ownership alone is not authenticity. On a host without Landlock (e.g. Raspberry Pi OS) and with `fs.protected_hardlinks=0`, the worker can hard-link any root-owned file on the same filesystem into `staged/<digest>`: an older signed detent (downgrade to a known-vulnerable build), `.prev`, or `/bin/true` (DoS). The owner check passes.
    - Fix: in `read_staged_verified`, refuse unless `meta.nlink() == 1`. Also require the parent directory to be owned by the monitor euid, with mode `& 0o022 == 0` (`fstatat` on the parent before opening the child).
    - Test: `replace_binary_refuses_a_hard_linked_staged_file`. Create the file, `hard_link` it to a second name, dispatch, and assert `Response::Error` with the target unchanged.
  - **C1-b — move staging out of the worker's tree.** `DECISION` (default: yes). Stage into a monitor-owned `root:root 0700` directory that is not under `state_root` (e.g. `/var/lib/detent-monitor/staged`, added to `packaging/tmpfiles.d/detent.conf`). Also add it to the monitor Landlock policy and not the worker's. The worker streams the bytes over the channel in a new chunked `Request::StageUpdate { offset, chunk }`, because frames cap at 1 MiB. The monitor writes them with `O_EXCL|O_NOFOLLOW`.
  - **C1-c — authenticity in the monitor.** `DECISION` (default: yes). The monitor must verify the Sigstore bundle itself before swapping. Split `crates/detent-update/src/{bundle,verify,trust}.rs` into a new dependency-light crate `detent-update-verify` that both `detent-platform` and `detent-update` depend on (no cycle). `StageUpdate` carries the bundle, and `replace_binary` calls `verify::verify(bytes, bundle, tag, trust::embedded())` and refuses on any error. **This is blocked on H17** — the verifier cannot parse real bundles yet. Until C1-c lands, `UpdateApply` stays fail-closed as it is now. Do not re-open it.
  - **C1-d — durability.** In `swap_running_binary`, create the temp file with `OpenOptions::new().write(true).create_new(true).mode(0o700)` rather than `fs::write`. Call `sync_all` before the rename, then fsync the target directory after it.
- Acceptance: the C1-a test passes. With C1-b and C1-c, add `replace_binary_refuses_bytes_that_do_not_verify`: stage self-hashed bytes with no valid bundle and expect `Error` with the target unchanged. Also add a positive case using the ADR-014 signed fixture.

---

## 4. High

### H1 A pending commit-confirm is dropped when the monitor stops; CLI and MCP never roll back
- Tier: Opus. Verified: orchestrator. Reviewers: OPS-2, BIN-2.
- Location: `monitor.rs` `serve` (`return Ok(ExitReason::Shutdown)` ~:354, `PeerClosed` ~:361, both with `self.pending` still set); `Monitor::recover_pending` ~:788 (called only from tests); `crates/detent/src/run.rs` `Session::start`/`finish` (the CLI runs an in-process monitor and shuts it down after one op); `crates/detent/src/mcp.rs`; `crates/detent/src/serve.rs` `run_monitor`.
- Problem:
  1. `detent config network apply` arms a 90 s window, prints "commit 1 armed", then `finish()` stops the monitor. Nothing ever rolls back, and `detent commit rollback 1` from a new process gets `UnknownId`.
  2. Under `serve`, a worker crash or `systemctl restart detent` inside the window leaves the change unguarded. `pending-commit.json` is written but never read at the next start.
  3. SECURITY_HARDENING.md:105 claims the window "survives a monitor restart". It does not.
- Fix:
  1. In `Monitor::serve`, before **every** return (Shutdown, PeerClosed, protocol violation, channel error), if `self.pending.take()` is `Some`, call `self.roll_back(entries)` and `clear_marker`. Invariant: a monitor never exits with a pending commit.
  2. Call `Monitor::recover_pending(state_root)` at every monitor start, before `Monitor::new(..)`: in `serve::run_monitor` and in `run.rs` `Session::start`. Report the `Recovered` result through the renderer (new id `cli-commit-recovered`).
  3. Hold an exclusive `flock` on `<state_root>/monitor.lock` for the monitor's lifetime. A one-shot CLI that cannot take the lock must refuse mutating ops (new id `cli-monitor-busy`) and must not run recovery, so it never rolls back a commit that a live `serve` owns.
  4. `DECISION` for one-shot CLI applies to `commit_confirm` modules. Default: refuse with `cli-commit-confirm-needs-serve`, pointing at the web UI or `serve`. The alternative is a `netplan try`-style tty prompt that keeps the session open until the deadline.
- Tests:
  - `monitor.rs::shutdown_with_a_pending_commit_rolls_back`: write, arm 60 s, dispatch `Shutdown`. Assert the target is restored and the marker is gone.
  - `serve.rs::run_monitor_recovers_a_leftover_marker`.
  - `run.rs::a_cli_apply_on_a_commit_confirm_module_never_leaves_an_unenforced_commit`: after `run()`, the target is unchanged or restored, and no `pending-commit.json` exists.
- Acceptance: all three tests pass. Correct SECURITY_HARDENING.md:105 in the same commit.

### H2 Apply arms commit-confirm only after the write and the service restart
- Tier: Opus. Verified: orchestrator. Reviewer: OPS-3.
- Location: `crates/detent-ops/src/engine.rs` `apply`. Step 4 `write_target` (~:496), step 5 `self.act(..)?` (~:507), step 6 `arm_commit` (~:516). `monitor.rs` `start_confirm_timer` returns `CommitPending` if one is already armed.
- Problem:
  - (a) File written, restart fails: `?` returns before arming, so there is no rollback. For `network` this is exactly the lock-out ADR-012 exists for.
  - (b) With commit A pending, a second commit-confirm apply writes and restarts, then gets `CommitPending`. It has no rollback, and its journal entry lingers (H3).
  - (c) With no backup made (`keep_backups = 0`), the engine reports an armed commit with `rollback_targets = 0`, which restores nothing.
- Fix, in `apply`, for `descriptor.commit_confirm || confirm.is_some()`:
  1. Before writing, ask the monitor whether a commit is pending: add `Request::PendingCommit` → `Response::Pending(Option<CommitId>)`. If one is, return a new `OpsError::CommitPending` (Fluent `ops-commit-pending`) and write nothing.
  2. Arm immediately **after** `write_target` and **before** `act`.
  3. If `act` fails, call `client.rollback_commit(id)`, then return the original error.
  4. If `receipt.backed_up` is false, roll back immediately and return `OpsError::NoBackup` (new id). A commit-confirm apply without a backup is not a safe apply.
- Tests (`crates/detent-ops/tests/engine.rs`):
  - `a_failed_service_action_on_a_commit_confirm_module_restores_the_file` (Err, contents back to v1).
  - `a_second_commit_confirm_apply_while_one_is_pending_writes_nothing`.
  - `a_commit_confirm_apply_without_a_backup_is_refused`.

### H3 The rollback journal collects writes from every module
- Tier: Opus. Verified: orchestrator. Reviewer: OPS-4.
- Location: `monitor.rs` `write_target` (~:479 pushes a `RollbackEntry` for every successful write); `start_confirm_timer` (~:656 `mem::take(&mut self.journal)`).
- Problem: the journal is only cleared when a timer arms. So a plain `hosts` apply at 09:00 is rolled back by an unrelated `network` commit that expires at 15:00. Stale entries can also point at backups that rotation has already deleted.
- Fix: add `journal: bool` to `Request::WriteTarget`. The engine sets it only for commit-confirm applies. The monitor pushes only when `journal` is true. When pending is `None` and `journal` is true, clear the journal before pushing, because one commit equals one write today. Bump `PROTO_VERSION`.
- Test: `engine.rs::an_unrelated_earlier_write_is_not_rolled_back_by_a_later_commit`. Apply plain A v1→v2, then apply commit-confirm B with a 1 s window and let it expire. Assert A is still v2 and `rollback_targets == 1`.

### H4 Rollback restores files but never replays the service action
- Tier: Opus. Verified: reviewer (OPS-5). Claim source: ADR-012 and PLAN §2.5 ("re-applies the prior service action").
- Location: `monitor.rs` `roll_back` (~:845), `enforce_deadline` (~:739). `RollbackEntry` has no binding or action.
- Problem: a bad network config plus a restart locks the admin out. At the deadline the file is restored, but networkd keeps running the bad config.
- Fix:
  1. Add `service: Option<(BindingId, ServiceAction)>` to `StartConfirmTimer`, to `PendingCommit`, and to the persisted `PendingCommitMarker`. Keep serde defaults so old markers still parse.
  2. After restoring files, `roll_back` calls `hooks.services.service(binding, action)` (it becomes `&self`) and logs the failure. `recover_pending` does the same.
  3. The engine passes the action it just performed.
- Test: `monitor.rs::an_expired_commit_replays_the_service_action`, using a recording `ServiceControl`.

### H5 External validators never run on apply — land H6 first
- Tier: Sonnet. Verified: orchestrator. Reviewers: MODA-1, MODB-3.
- Location: `engine.rs` `apply` (~:455-525); `run_checks` is only called from `plan` (~:395). Claim: SECURITY_HARDENING.md:102 "External validators run before apply".
- Problem: `chronyd -p`, `testparm -s`, `unbound-checkconf`, `findmnt --verify` and `netplan generate` only inform `plan`. Any apply from the CLI, MCP, FFI or an API client that skips `plan` writes a config the daemon rejects. `chrony` and `dhcp` have no commit-confirm at all.
- Fix:
  1. In `apply`, after `apply_json` and before `write_target`, call `self.run_checks(&wiring, rendered.as_bytes())`.
  2. If any report has `ran && !passed`, return a new `OpsError::CheckFailed { reports }` (Fluent `ops-check-failed`) and write nothing.
  3. `DECISION` for a validator that is not installed (`!ran`). Default: allow, and include the reports in `ApplyReport.checks` (new field) so the UI shows "not validated".
- Test: `engine.rs::apply_refuses_when_an_external_check_fails`. Add `FailChecks` beside the existing `OkChecks` runner. Assert `Err(CheckFailed)`, target bytes unchanged, and no backup created.
- **Dependency:** H6 first, then verify on a010 under `detent serve` that a real `chrony` apply runs `chronyd -p` and the monitor survives.

### H6 Monitor seccomp filter forbids process creation; the first validator or restart kills it
- Tier: Opus. Verified: orchestrator (the `MONITOR` table at `sandbox/seccomp.rs:155-218` has no `clone`, `clone3`, `fork`, `vfork`, `execve`, `execveat`, `pipe2`, `dup3` or `kill`; `Role::Monitor => KillProcess`). Reviewer: PLAT-2.
- Location: `sandbox/seccomp.rs` `MONITOR`, `SYSCALL_NUMBERS`; `serve.rs:170-174`, where the monitor's hooks are the real `ExternalCheckRunner` and `service::for_host`; `service/exec.rs` (`Command::spawn`, reader threads, `child.kill()`).
- Problem: on a confined `detent serve`, any `RunCheck` (every plan on chrony, samba, dhcp, network or resolver) or `Service` request makes the monitor spawn a process. The filter kills it with SIGSYS and the pair dies. The derivation comment (seccomp.rs:20-25) wrongly calls `execve`/`clone` test-harness noise. Real-hardware testing (PROGRESS 2026-09-16) only ran `host` and `doctor`, so this was never exercised.
- Fix:
  1. On a010, run a confined `detent serve` under `strace -f -o /tmp/mon.trace`. Drive one real `plan` on chrony (runs `chronyd -p`) and one `systemctl restart` through the API. Collect every syscall the monitor and its children use.
  2. Add the missing ones to `MONITOR` with both arch numbers: at least `clone`, `clone3`, `execve`, `execveat`, `pipe2`, `dup3`, `kill`, `tgkill`, `rseq`, `set_robust_list`, `sched_getaffinity`, plus whatever strace shows.
  3. Keep `KillProcess`. Rewrite the derivation comment.
  4. aarch64: no host. Run `cargo check --target aarch64-unknown-linux-gnu -p detent-platform` and pin the aarch64 numbers in the unit test below. Mark the aarch64 runtime unverified in §11.
- Tests:
  - `sandbox/linux.rs::enforce_mode_monitor_can_spawn_a_validator`: in the existing `in_forked_child` helper, call `confine(Role::Monitor, &Policy::monitor(&allow))`, then `RealProcessRunner.run("/bin/true", &[], 5s)`. The parent asserts exit 0. It must fail on the current tree.
  - `seccomp.rs::monitor_table_allows_process_creation_on_both_arches`.

### H7 Audit fails open; nothing is recorded before the side effect
- Tier: Opus. Verified: orchestrator. Reviewer: OPS-6.
- Location: `engine.rs` ~:205 (`if let Err(err) = self.audit.record(record) { tracing::error!(..) }`); records are emitted only after dispatch. The test `crates/detent-ops/tests/engine.rs:1749 an_unwritable_audit_sink_does_not_fail_the_operation` **enforces** fail-open. Claim: `detent-ops/src/lib.rs:8-9` ("complete record rather than a best-effort one").
- Problem: with a full disk, a read-only filesystem, or `audit/` replaced by a file (the worker owns it), every Apply, Restore, ServiceAction and UpdateApply succeeds unaudited. A crash mid-dispatch leaves a write with no record.
- Fix:
  1. Add `AuditResult::Started`.
  2. For mutating ops, `execute` writes an intent record **before** dispatch. On `Err`, return `OpsError::Audit` (new id `ops-audit-unavailable`) without dispatching.
  3. Keep the outcome record after dispatch. If that fails, return the op's result but log at error level; the intent record already exists.
  4. `emit` returns `Result`.
- Test: **replace** the fail-open test with `an_unwritable_audit_sink_refuses_the_mutation`, asserting `Err(OpsError::Audit)` with the target still v1. This intentionally reverses documented behaviour; say so in the commit message.

### H8 The login rate limiter is one global bucket
- Tier: Sonnet. Verified: orchestrator (no `ConnectInfo` insertion anywhere outside a test). Reviewer: WEB-1.
- Location: `crates/detent-web/src/server.rs` ~:294 (`TowerToHyperService::new(router)`; `peer` is only logged); `auth/extract.rs` ~:281-286 (missing `ConnectInfo` becomes `0.0.0.0`); `auth/routes.rs` ~:198-221. False claim: `crates/detent-web/Cargo.toml:44-47`.
- Problem: every client is keyed `ip:0.0.0.0`. Five bad logins from anyone return 429 to everyone, including the admin. With the 15-minute backoff, one bad login per 15 minutes locks the UI permanently. Auth audit records also lose the source IP.
- Fix:
  1. In `Server::serve`, per accepted connection, wrap the router: `let svc = tower::ServiceExt::map_request(router.clone(), move |mut req: axum::extract::Request| { req.extensions_mut().insert(axum::extract::ConnectInfo(peer)); req });`, then call `TowerToHyperService::new(svc)`.
  2. In `ratelimit.rs`, key IPv6 by /64 (mask the low 64 bits).
  3. Fix the Cargo.toml comment.
- Tests:
  - `tests/tls.rs::the_peer_address_reaches_the_handlers`: a `GET /ip` route returns `ClientIp`; a TLS client from 127.0.0.1 must see "127.0.0.1".
  - `ratelimit.rs::ipv6_addresses_in_one_slash64_share_a_bucket`.

### H9 No header-read or idle timeout after the TLS handshake (slowloris)
- Tier: Sonnet. Verified: orchestrator (`rg 'header_read_timeout|\.timer\(|keep_alive' crates/detent-web/src` finds nothing). Reviewer: WEB-2. False claim: SECURITY_HARDENING.md:72.
- Location: `server.rs` ~:295 (`auto::Builder::new(TokioExecutor::new())`), ~:340-345 (`watcher.watch(connection).await` with no deadline).
- Problem: hyper's default header timeout is inert without a timer. Sixty-four idle post-handshake connections hold every semaphore permit, so the UI is down pre-auth.
- Fix:
  1. `builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT)` (10 s).
  2. `builder.http2().timer(TokioTimer::new()).keep_alive_interval(Some(30s)).keep_alive_timeout(30s).max_concurrent_streams(32)`.
  3. Wrap `watcher.watch(connection)` in `tokio::time::timeout(MAX_CONNECTION_LIFETIME, ..)` (e.g. 10 min).
  4. Make the durations `Server` fields so tests can shorten them.
- Test: `tests/tls.rs::an_idle_connection_does_not_hold_a_permit`.
  1. Set `max_connections = 1` and the header timeout to 200 ms.
  2. Handshake, then send nothing; sleep 500 ms.
  3. A second client gets `/healthz` 200.

### H10 User and token stores are loaded once; revocation does nothing and removed users come back
- Tier: Opus. Verified: orchestrator (`TokenStore::authenticate` scans an in-memory `Vec` loaded in `load`). Reviewers: WEB-3, BIN-5.
- Location: `crates/detent-web/src/auth/token.rs` (claim at :22-24 "no cache in front of it" is false; `authenticate` ~:296; `records` ~:343); `auth/users.rs` `mutate` (clones the stale set and writes it back), `note_totp_counter`; `crates/detent/src/serve.rs:346`; `crates/detent/src/webadmin.rs:353-374`; `crates/detent/src/mcp.rs` (token authenticated once at startup; `detent-mcp` `check_auth` compares the server's own env var with itself).
- Problem:
  - `detent token revoke` and `detent user rm/passwd` run in another process and never reach a running `serve` or `mcp`.
  - Worse, the next server-side write (for example any TOTP login) rewrites `users.json` from the stale in-memory set and resurrects a removed user or an old password.
  - Revoked or expired tokens keep working in MCP until restart.
- Fix:
  1. Add `refresh()` to `TokenStore` and `UserStore`. It stats the file, compares `(dev, ino, len, mtime_ns)` with a cached fingerprint held in the same mutex, and re-decodes on change. `NotFound` means empty.
  2. Call it at the start of `authenticate` and `verify_password`, and inside `mutate()` under the lock before cloning, so every write is a read-modify-write of the current file.
  3. When a refresh drops a user or changes their PHC, call a new `SessionStore::revoke_subject(name)`.
  4. MCP: replace the startup-only check with a `StoreVerifier { state_root }` that calls `TokenStore::load(..)?.authenticate(token, now)` per request. Pass the presented token into `check_auth` explicitly instead of reading `DETENT_MCP_TOKEN` again. Label the identity `token:<id>`; never use `&token[..8]`, which exposes part of the secret and panics on a non-ASCII boundary.
- Tests:
  - `token.rs::a_token_revoked_through_another_store_stops_working`.
  - `users.rs::a_removed_user_is_neither_accepted_nor_resurrected`.
  - `detent/src/mcp.rs::a_revoked_token_is_refused_on_the_next_call` (also cover an expired token).

### H11 MCP stdio (the default transport) deadlocks
- Tier: Sonnet. Verified: orchestrator (`main.rs:94-99` holds `stdin.lock()`/`stdout.lock()` for the whole `run::run`). Reviewer: BIN-1, traced through tokio 1.53.1 and rmcp 3.4.0.
- Problem: rmcp uses `tokio::io::stdin()`, whose blocking thread calls `Stdin::read`, which needs the lock `main` holds. The server never answers `initialize`. PROGRESS 2026-09-22 saw this ("pipe stayed silent… likely framing") and shipped anyway.
- Fix: in `main.rs`, pass the unlocked handles instead (`let mut input = std::io::stdin(); let mut out = std::io::stdout(); let mut notes = std::io::stderr();`). `Streams` takes `&mut dyn Read/Write`, so nothing else changes. Keep the final flushes.
- Test: `crates/detent/tests/binary.rs::mcp_stdio_answers_initialize` (`#[cfg(feature = "mcp")]`).
  1. Create a token with `detent token create t --json --state-root <tmp>`.
  2. Spawn `detent mcp` with `DETENT_MCP_TOKEN` set.
  3. Write one `initialize` JSON-RPC line.
  4. Read one stdout line on a thread with a 10 s timeout; it must contain `"id":1` and `"result"`.

### H12 `detent mcp --transport http` serves the network from the root process
- Tier: Opus. `DECISION`. Verified: reviewer (BIN-3).
- Location: `crates/detent/src/mcp.rs` (`start_session` = in-process monitor thread, then `serve_http` in the same process); `run.rs:3-19` (the module doc justifies the in-process monitor because "a one-shot CLI has no network-facing side", which is false for `mcp`).
- Problem: hyper, axum and rmcp parse network input in the same process as the root monitor, with no fork, uid drop, Landlock or seccomp. `serve` forks for exactly this reason.
- Fix (default = option B now, option A later):
  - **B (interim):** refuse `--transport http` when `geteuid() == 0` (`Exit::Privilege`, id `cli-mcp-http-needs-privsep`). Fix the `run.rs` doc.
  - **A:** mirror `serve.rs`. Read the token store before forking. Call `spawn_pair` with `SandboxHooks::new(Policy::monitor(..), Policy::worker(..))`. Run `serve::run_monitor` on the monitor side. On the worker side, build the engine behind the privsep client and run `serve_http` on a runtime built inside the worker.
- Test (B): a pure helper `http_transport_allowed(euid_is_root: bool) -> bool` plus a unit test.

### H13 smb.conf syntax injection through keys and values
- Tier: Sonnet. Verified: orchestrator (`render_line` guards only `\n\r\0` plus a round-trip through the module's own parser). Reviewer: MODA-2. Upstream semantics come from smb.conf(5) and were not executed.
- Location: `crates/modules/samba/src/lib.rs` `parse_entry` (~:189-211), `render_line` (~:247-264), `validate_entry` (~:438-452). The header doc at :18-21 describes continuation wrongly.
- Problem:
  - (a) A value ending in `\` makes Samba fold the **next** line into it, e.g. swallowing `valid users = @admins`. The model still shows the swallowed line as present.
  - (b) A key like `[evil] x` renders as `[evil] x = y`, which Samba reads as a new section. Every later `[global]` hardening directive moves into a share, where it is ignored.
  - (c) A key starting with `;` or `#` becomes a comment, and the directive silently vanishes.
  - (d) A section name containing `]` is truncated.
- Fix:
  1. `render_line` returns `EditError::Unsupported` when a key starts with `[`, `#` or `;`; when a key or value ends with `\`; or when a section name contains `[` or `]` or ends with `\`.
  2. Add matching `Severity::Error` diagnostics in `validate_entry` (new Fluent ids).
  3. `parse_entry` returns `None` for a trimmed line ending in `\`, so continued lines stay `Unknown` and are never rewritten.
  4. Fix the header doc.
- Tests: `render_line_rejects_smb_conf_syntax` covers each case above. Assert `parse_entry("a = b \\") == None`. Add the same probes to `crates/modules/samba/tests/conformance.rs`.

### H14 NFS exports: a `-opts` host sets default options and bypasses the warnings
- Tier: Sonnet. Verified: orchestrator (`parse_client` rejects only `#` and `"`). Reviewer: MODA-3. Upstream semantics come from exports(5) and were not executed.
- Location: `crates/modules/nfs/src/lib.rs` `parse_client` (~:199-225), `parse_export` (~:233-244), `render_line` (~:275-295), `validate_client` (~:506-536); the header at :14-19.
- Problem: clients `[{host:"-rw,no_root_squash"}, {host:"*"}]` render as `/srv -rw,no_root_squash *`. exportfs applies those as defaults, which gives world read-write with root. Validation sees two plain hosts and raises nothing. A trailing `\` joins the next line, `#` inside a path or option truncates the line, and `"` toggles quoting.
- Fix:
  1. `parse_client` returns `None` if the host starts with `-` or contains `\`.
  2. `parse_export` returns `None` if the path or any option contains `#`, `"` or `\`, or if the trimmed line ends with `\`.
  3. Add matching `Severity::Error` diagnostics.
  4. Fix the header.
- Tests: `parse_export("/srv -rw,no_root_squash *") == None`. `render_line` returns `Err(Unsupported)` for a `-rw` host, `h\`, a path `/a#b` and an option `rw#`. The `-rw` model `validate(..).has_errors()`. Add conformance probes.

### H15 unbound `name:`/`forward-addr:` outside a forward zone is not validated
- Tier: Sonnet. Verified: reviewer (MODB-2). Plausible: unbound's multi-statement-per-line parsing was not executed.
- Location: `crates/modules/resolver/src/lib.rs` `validate_unbound` (~:1237-1267: misplaced entries get a Warning and the value is never checked), `render_unbound` (~:697), `parse_unbound` (~:563-572). The test `forward_items_outside_a_zone_are_misplaced` asserts `!has_errors()`.
- Problem: any `stub-zone:`, `auth-zone:` or `view:` section makes its `name:` lines "misplaced", which skips value validation. A Write caller can set a value such as `. server: access-control: 0.0.0.0/0 allow remote-control: control-enable: yes …` and escape the typed model (open resolver, unauthenticated remote control).
- Fix:
  1. Always run `is_valid_forward_zone_name(name)` / `is_valid_forward_addr(addr)` and emit `Severity::Error` on failure, whatever the section. Keep the misplaced Warning.
  2. In `render_unbound`, return `EditError::Unsupported` if `name` or `addr` contains whitespace, `:` or `#`.
- Test: `misplaced_forward_name_is_still_validated`. Also update the existing test so it asserts errors for an invalid value and no error for a valid misplaced one.

### H16 network `apply` moves preserved keys out of their INI section
- Tier: Sonnet. Verified: reviewer (MODB-1; traced against `fixtures/network/edge/unknown-sections.network`, not executed).
- Location: `crates/modules/network/src/lib.rs` `NetworkModule::apply` (~:1899-1959). It removes every `Directive` line and re-appends the rendering at EOF. `.map_or(at, |_| at)` is dead code.
- Problem: unmodelled keys (e.g. `IPv6AcceptRA=no`) stay where they were while their `[Network]` header moves to the end. They end up outside any section, and networkd ignores them. This breaks ADR-008's "preserved-but-opaque" promise, and the plan diff misleads the operator.
- Fix: rewrite `apply` as the two-pass minimal edit already used by `ChronyModule::apply` / `apply_dnsmasq`:
  1. Pair rendered directive lines with existing ones.
  2. `replace_raw` changed lines and `remove_line` surplus ones.
  3. `insert_line` new ones after the last directive of the same section.
  4. Never move a section header past its keys.
  - Interim alternative: return `EditError::Unsupported` when a non-blank `Unknown` line sits between directive lines.
  - Delete the dead insert-position code (L-MODB8).
- Test: `crates/modules/network/tests/conformance.rs::edit_keeps_unknown_keys_under_their_section`.

### H17 The update verifier cannot accept any real Sigstore bundle
- Tier: Opus. `DECISION` (bundle format). Verified: orchestrator (`release.yml:134` is `cosign sign-blob --bundle`, a messageSignature bundle; `bundle.rs:53` requires `dsse_envelope`). Reviewer: SUP-1.
- Location: `crates/detent-update/src/{bundle.rs,verify.rs}`; `src/bin/gen-fixtures.rs` (mints bundles in the verifier's own invented format); `.github/workflows/release.yml:134, :290-293`; ADR-014; PLAN §2.9 ("Tested against real bundles" is false).
- Problem: every real release fails `bundle::parse` (missing `dsseEnvelope`). Even an `actions/attest` DSSE bundle fails independently on each of these:
  - `verificationMaterial.certificate` (v0.3), which is not `x509CertificateChain`;
  - the payload type is `application/vnd.in-toto+json`;
  - the Rekor leaf hash is `SHA256(0x00||body)`;
  - the checkpoint is a signed note carrying base64(root), not sha256(root);
  - the hashedrekord `publicKey` is an object;
  - the Fulcio intermediate is missing from `trust/`.

  The result refuses closed, so there is no bypass, but self-update works 0% of the time and every test passes on self-minted fixtures.
- Fix:
  1. Pick one artifact (default: the `actions/attest` DSSE bundle) and publish it as `detent-<triple>.sigstore.json`.
  2. Accept `verificationMaterial.certificate`.
  3. Set `DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"`.
  4. Hash the leaf as `0x00||body`. Authenticate `integratedTime` via `inclusionPromise.signedEntryTimestamp` with the Rekor key.
  5. Parse the checkpoint as a signed note: size must equal `tree_size`, compare the root directly, and the signature is a 4-byte keyhint plus the signature over body+"\n".
  6. Branch body agreement on entry kind (hashedrekord vs dsse) and refuse other kinds.
  7. Embed the Fulcio intermediate.
  8. **Replace the fixtures with captured real bundles**: capture one from a real release run and commit it.
- Tests: `tests/verify_fixtures.rs::a_real_cosign_bundle_parses` / `real_attest_bundle_verifies` against a committed real bundle. Also add the negative tests from M16.

### H18 The update HTTP client does not follow redirects
- Tier: Sonnet. Verified: orchestrator (`fetch.rs:298` fails on any non-2xx; there is no `Location` handling). Plausible: GitHub's 302 on `browser_download_url` is well known but was not re-checked live.
- Location: `crates/detent-update/src/fetch.rs` `RealTransport::get` (~:288-303); `.https_or_http()` at :264. The module doc claims the real client is tested; no test constructs `RealTransport`.
- Fix:
  1. Loop at most 5 times. On 301/302/303/307/308, resolve `Location` against the current URL, refuse any non-https target, and re-GET with the same caps and timeouts.
  2. Use `.https_only()`.
  3. Add a test-only `RealTransport::with_roots` constructor.
- Tests: `tests/real_transport.rs::follows_a_302_to_the_asset` (a loopback TLS server where `/a` → 302 → `/b` returns "hello"), and `refuses_redirect_to_http`.

### H19 The post-update health probe pins the bootstrap cert, so every update rolls back on ACME hosts
- Tier: Sonnet. Verified: reviewer (SUP-3, BIN-8). Latent until an ACME cert is stored in production.
- Location: `crates/detent/src/run.rs` `restart_and_check` (~:667-681, pins `BOOTSTRAP_CERT_FILE`); `crates/detent/src/serve.rs` (~:419-438 prefers `load_acme`); `crates/detent-update/src/health.rs` (`SERVER_NAME = "localhost"`, webpki name check).
- Problem: after `store_acme`, serve presents the ACME chain, but the probe trusts only the bootstrap cert and asks for SNI `localhost`. It fails for 30 s, then `mark_bad(tag)` and rollback. Every release gets blacklisted.
- Fix:
  1. Share one `serving_pair(cert_dir)` selector between `serve.rs` and `run.rs`: ACME if present, else bootstrap.
  2. In `health.rs`, replace webpki anchor and name validation with a custom `rustls::client::danger::ServerCertVerifier` that accepts only if `end_entity == pinned DER`, delegating signature checks to `rustls::crypto::verify_tls13_signature`.
  3. Build the `ClientConfig` with an explicit provider (`ClientConfig::builder_with_provider`) and delete `ensure_provider()`, which installs a process-global default from library code (L-ORC2).
- Test: `health.rs::a_ca_issued_leaf_without_localhost_is_healthy_when_pinned`.

### H20 CI on `main` is red in four independent ways
- Tier: Sonnet. Verified: orchestrator (gh runs 35797819270 and later; local reproduction).
- **H20-a clippy:** `crates/detent/src/mcp.rs` has items after the test module (`shutdown_signal` at ~:361, `transport_name`, `scope_name`) and `.expect("fixture header")` at ~:345. Fix: move the three fns above `mod tests`. Make the `headers()` fixture return `Result<HeaderMap, InvalidHeaderValue>` and use `?`. No `#[allow]`. PROGRESS "clippy clean" was a `-p detent-mcp`-only run.
- **H20-b Linux-only test failure:** `doctor::confinement_tests::a_duplicate_module_id_warns_instead_of_panicking` fails on Linux: it expects one warning and gets the landlock and seccomp checks. Fix: gate that test module `#[cfg(all(test, not(target_os = "linux")))]`, and add a Linux test `linux_confinement_reports_landlock_and_seccomp`. The PROGRESS "workspace tests exit 0" results were macOS-only.
- **H20-c coverage floors:** detent-ops 99.64 (uncovered: `engine.rs:350-354, :374`, the `update_apply` error arms); detent-web 96.81; detent 91.64. Fix by adding tests for those arms. **Never lower a floor** in `coverage-baseline.json`. Many items in this file add tests that recover detent and detent-web.
- **H20-d fuzz workflow:** `.github/workflows/fuzz.yml` installs nightly, but `rust-toolchain.toml` (`channel = "1.98.1"`) overrides it, so `cargo fuzz` runs `-Z` on stable and fails. It has failed daily since 2026-09-18. Fix: invoke `cargo +nightly fuzz list` / `cargo +nightly fuzz run ...` in the workflow. Verify with `gh workflow run fuzz.yml` followed by a green run.
- Acceptance: a green `ci.yml` and `fuzz.yml` on `main`.

### H21 Web UI cannot confirm a commit; reload loses the countdown
- Tier: Sonnet. Verified: orchestrator (`useConfirmCommit` / `useRollbackCommit` in `web/src/api/commits.ts` have no callers outside tests). Reviewer: FE-1.
- Location: `web/src/app/PendingCommit.tsx`, `web/src/api/commits.ts`.
- Problem: every commit-confirm apply from the browser (network, resolver, dhcp, mounts) auto-rolls back at the deadline, whatever the operator wants. Pending state is plain `useState`, so a reload drops the banner while the timer still runs.
- Fix:
  1. Add **Confirm** and **Roll back** buttons to the `PendingCommit` banner, wired to the hooks. Show errors with the existing error pattern and Fluent ids for the labels. Follow AESTHETIC_CONTRACT.md.
  2. Add `GET /api/v1/commits/pending` (read scope), returning the monitor's pending commit via the new `Request::PendingCommit` from H2. Rehydrate the banner from it on load.
  3. Regenerate `docs/openapi.json` and `schema.d.ts` (see the PROGRESS "Traps" for the procedure).
- Tests:
  - Component test: clicking Confirm calls `POST /commits/{id}/confirm` and clears the banner.
  - e2e: apply, reload, the banner is still shown, confirm succeeds.

### H22 On the default config every browser mutation is refused by CSRF
- Tier: Sonnet. Verified: reviewer (WEB-7).
- Location: `crates/detent-web/src/csrf.rs` `Origin::for_config` (~:133-139, `hostnames.first()` or else `listen.addr.ip()`, which is `0.0.0.0` by default); a test at ~:702 enshrines `https://0.0.0.0:3333`.
- Problem: a browser at `https://192.168.1.5:3333` sends `Origin: https://192.168.1.5:3333`, which never matches. Login, logout, apply, confirm and rollback all return 403 on a default install. It fails closed, so there is no hole, but combined with H21 the UI cannot complete a safe apply.
- Fix: in `verdict`, derive the expected origin from the request authority (`Host`, or the `:authority` for h2; exactly one value) and require `Origin == https://<authority>`. Keep `Sec-Fetch-Site: same-origin` and the `__Host-` cookie. Delete the `0.0.0.0` assertion.
- Test: `csrf.rs::a_wildcard_listener_accepts_its_own_authority`. `Host 192.0.2.10:3333` + matching Origin → allowed; `Origin https://evil.example:3333` → 403.

### H23 A compromised worker can still reach root through config content
- Tier: Opus. `DECISION`. Verified: orchestrator. Reviewer: PLAT design note. Jev severity 2.9.
- Location: `monitor.rs` `write_target` (writes any worker-supplied bytes to an allow-listed target); ADR-001 ("a worker compromise does not directly grant root").
- Problem: allow-listed targets include root-execution vectors: smb.conf `root preexec`, dnsmasq `dhcp-script`, `/etc/fstab`, `/etc/exports` `no_root_squash`, ifupdown `up` lines. The monitor does no content validation, and its Landlock grant covers each target's parent directory (`/etc`). So ADR-001's central claim is false for any build with those modules enabled.
- Fix (default):
  1. **Now:** rewrite ADR-001 and SECURITY_HARDENING "Local privilege" to state the real guarantee: the worker is confined to the allow-listed files, but content written there can execute as root.
  2. **Then:** make the monitor re-validate before writing. It parses the candidate with the module's parser (link `detent-modules` into the monitor side), refuses if `validate` has errors, and refuses any rendered content containing a per-module deny-list of exec directives. The deny-list must cover at least smb.conf `root preexec`/`root postexec`/`preexec`/`postexec`/`add user script`/`include`, dnsmasq `dhcp-script`/`dhcp-luascript`/`conf-file`/`conf-dir`, chrony `include`/`confdir`/`sourcedir`/`pidfile`, unbound `include:`/`python-script:`, ifupdown `up`/`down`/`pre-up`/`post-down` with anything but the module's own route form, and fstab `x-systemd.*` exec-like options. Directives already present in the current file are allowed to stay; only new ones are refused. That needs a diff of before and after in the monitor.
- Test: `monitor.rs::write_target_refuses_new_root_exec_directives`, with an allow-listed samba target and a candidate adding `root preexec = /bin/sh` → `Response::Error`.

---

## 5. Medium

Each item: location → fix → test. Tier in brackets.

- **M1 Capability drop fails open** [Opus] (PLAT-3; known gap in PROGRESS).
  - Location: `sandbox/linux.rs:33` (`drop_capabilities` never gated), `sandbox/mod.rs` `Policy`.
  - Fix:
    - Add `require_caps: bool` to `Policy`, true for the monitor.
    - Add `SandboxError::CapsRequired`.
    - Add `caps_verdict(required, &Outcome)`, mirroring `seccomp_verdict`, and call it after `drop_capabilities`.
    - For the worker: drop the bounding set **before** `setuid` in `become_worker`, or treat "effective and permitted already empty" as `Applied`.
  - Test: `caps_that_do_not_drop_are_fatal_only_when_required`. Verify on a010, both as root under `detent serve` and in the forked-pair test that CI runs.
- **M2 `serve` never reports degraded confinement** [Sonnet] (PLAT-5).
  - Location: `serve.rs`. `hooks.confinement()` is never read, and `confine` never logs.
  - Fix:
    - After `spawn_pair`, in both the monitor and worker branches, read `hooks.confinement()`.
    - For each field that is not `Applied`/`FullyEnforced`, emit a renderer note `cli-serve-confinement-degraded` plus `tracing::warn!`.
    - Persist the result to `<state_root>/state/confinement.json` so doctor and the UI show the real outcome.
  - Test: a pure `degradation_notes(&Confinement)` helper; `a_missing_landlock_is_reported_at_startup`. This matters on hosts without Landlock, such as Raspberry Pi OS.
- **M3 Audit log is not tamper-evident** [Opus] (OPS-7).
  - Location: `detent-ops/src/audit.rs:220-236`. The worker owns the file, and there is no chain.
  - Fix:
    - Add `seq` and `prev` (SHA-256 of the previous line) fields, written under a mutex; `query` verifies them.
    - Create the directory 0700 and fsync the parent.
    - Correct SECURITY_HARDENING:107 ("append-only"). Document journald (after M12) as the copy the worker cannot rewrite.
  - Test: `a_deleted_middle_record_breaks_the_chain`.
- **M4 The engine runs `AllowAll`; scope denials are not audited** [Opus] (OPS-8, WEB-8).
  - Location: `serve.rs:340`, `run.rs:1118`, `detent-web/src/engine.rs:266`, `api/mod.rs:219`, `detent-mcp` `mcp.rs:465`. docs/API.md:122 is false.
  - Fix:
    - Change the signature to `execute(op, who, authz: &dyn Authz)`: `ScopedAuthz` for web and MCP, `AllowAll` for the CLI. Drop the stored field. The engine's existing Denied audit path then fires.
    - Also add `AuthEvent::Denied` in `WriteCaller` rejection.
  - Test: `integration_tests.rs::a_scope_denial_is_audited`.
- **M5 A read-scope `plan` runs root validators on invalid input** [Sonnet] (OPS-9).
  - Location: `engine.rs:382-395`. `run_checks` runs even when `diagnostics.has_errors()`, and its `detail` returns validator output.
  - Fix: skip `run_checks` when `has_errors()`. Truncate `detail` to the first 512 bytes, as the monitor does today. `DECISION`: whether plan-with-checks needs Write scope. Default: no, but audit it as a new `OpKind::Plan` when checks ran.
  - Test: `plan_does_not_run_checks_for_a_model_with_errors`.
- **M6 Read scope exposes secret-bearing config** [Opus] `DECISION` (WEB-4).
  - Location: `authz.rs:150-153` (`allows(Read)` is always true); `api/modules.rs:199-212, :277-296`; `report.rs` `PlanReport.rendered` / `unified_diff`; mounts `options` (CIFS `password=`); Kea `password`; NM `psk=` if keyfiles are a wired target.
  - Fix (default): for callers without Write scope, blank `rendered`, `unified_diff` and `diff` in `plan`. Add `fn secret_pointers(&self) -> &'static [&'static str]` to the module trait (empty by default), and redact matching values in `GetModule` views for non-write callers. Document the rule in API.md.
  - Test: `a_read_token_never_sees_a_rendered_file` ("hunter2" must be absent for the read token and present for the write token).
- **M7 Optimistic concurrency is optional; restore and rollback overwrite concurrent edits** [Opus] (OPS-10).
  - Fix:
    - Make `expected_hash` required on `Apply`. The CLI passes the digest it read; the web client already has `current_hash`.
    - Add `expected_hash` to `Restore`.
    - Record `new_digest` in `RollbackEntry`, and have `roll_back` pass it as `expected_prev`. On `Conflict`, log, skip, and report it.
  - Test: `rollback_does_not_overwrite_an_edit_made_during_the_window`.
- **M8 Conformance property tests never generate multi-line input** [Sonnet] (OPS-13).
  - Location: `crates/detent-core/src/conformance.rs:356-376`. `src in ".*"` never yields `\n`, and invariants 3 and 4 accept `Exercised::No`.
  - Fix:
    - Use a strategy `vec("[^\n]*(\n|\r\n)?", 0..20)` joined into one string, exposed as `conformance_src_strategy()`.
    - Require that at least some cases produce `Exercised::Yes`, using a counter.
  - Test: `property_inputs_include_newlines`. Expect new failures in the modules; those are real bugs, so fix them rather than narrowing the strategy.
- **M9 TOTP replay race; the counter can go backwards** [Sonnet] (WEB-5).
  - Location: `auth/routes.rs:305-310, :358-366`; `users.rs:397-401`.
  - Fix: `note_totp_counter` becomes a compare-and-set under the store mutex. It returns `Err(InvalidCredentials)` if `last >= counter`.
  - Test: `a_totp_counter_cannot_be_reused_or_go_backwards`.
- **M10 Refused logins fill the disk** [Sonnet] (WEB-6).
  - Location: `auth/routes.rs:221, :371`; `auth/audit.rs:192-206`.
  - Fix: do not append for `RateLimited` (debug log only; the lockout itself is already audited). Rotate `detent-auth.jsonl` to `.1` above 16 MiB.
  - Test: `rate_limited_attempts_do_not_grow_the_audit_log`.
- **M11 `mcp --bind` accepts non-loopback addresses (plaintext bearer)** [Sonnet] (BIN-4).
  - Location: `cli.rs:167-171`, `mcp.rs:65, :278`.
  - Fix: refuse `!bind.ip().is_loopback()` with `cli-mcp-bind-not-loopback` and `Exit::Usage`. Call `enforce_origin_validation()`.
  - Test: a `check_bind` table test (`0.0.0.0`, `192.168.1.10`, `[::]` refused; `127.0.0.1`, `[::1]` allowed).
- **M12 No tracing subscriber is installed** [Sonnet] `DECISION` (new dependency, ADR-011 cooldown) (BIN-9).
  - Problem: monitor protocol-violation warnings, rollbacks and the "journald audit stream" (`auth/audit.rs:3-7`) go nowhere, and `RUST_LOG` in the unit file does nothing.
  - Fix: add `tracing-subscriber` (`fmt`, `env-filter`, cooled per ADR-011). Initialise it for `serve` and `mcp` only, writing to **stderr** (stdout is the MCP stdio channel).
  - Test: a binary test running `detent mcp` with a bad token and `RUST_LOG=info`; stdout must be empty.
- **M13 FFI has no panic guard** [Opus] `DECISION` (BIN-10).
  - Location: every `extern "C"` in `crates/detent-ffi/src/lib.rs`; `[profile.release] panic = "abort"`; docs/FFI.md promises it "never panics across the boundary".
  - Fix (default): wrap every entry point in `catch_unwind(AssertUnwindSafe(..))`, returning NULL and setting the last error to `internal: panic`. Build the cdylib and staticlib with a profile where `panic = "unwind"`. If that is rejected, correct FFI.md to say that a panic aborts the host process.
  - Test: an internal `guard(|| panic!())` returns NULL and sets the error.
- **M14 The update age gate is bypassed by release-note text** [Sonnet] (SUP-4; verified by the orchestrator).
  - Location: `update.rs:204` `chosen.body.contains(SECURITY_MARKER)`; `release.yml:310` `--generate-notes`, which includes PR titles.
  - Fix, minimum: `body.lines().any(|l| l.trim() == SECURITY_MARKER)`. Preferred: carry the flag inside signed material, checked after verify. Also have `release.yml` fail if the generated notes contain the marker without a workflow input.
  - Test: `marker_embedded_in_a_sentence_does_not_bypass`.
- **M15 ACME ARI renewal logic is inverted** [Sonnet] (SUP-5; verified by the orchestrator at `schedule.rs:57-74`).
  - Problem: RFC 9773 says to renew inside the window, and immediately if the window is already past. The code renews in the window only at 66% used, and otherwise waits until 90%.
  - Fix: `Some((start, _)) => now >= start || used >= 66`. Update `renewal_decision_covers_all_three_arms`, which enshrines the bug.
  - Tests: `a_past_ari_window_renews_immediately`, `an_open_ari_window_renews_before_two_thirds`.
- **M16 Verifier tests cannot catch a removed body-agreement check; SCT/SET are claimed but absent** [Opus] (SUP-6).
  - Fix: add `gen-fixtures` variants `bad-body-sig` and `bad-body-key` (proof and checkpoint valid over the altered body), and `wrong-digest.json`. Rename `bad-sct` to `bad-checkpoint-sig`. Either implement SET verification (it is part of H17) or remove the SCT/SET claims from PLAN §2.9 and ADR-014.
  - Tests: `a_body_with_another_signature_is_refused_at_step_6`, `a_forged_integrated_time_is_refused`. Check each is non-vacuous by deleting `verify.rs:312` and watching it fail.
- **M17 ACME credential write is not crash-safe** [Sonnet] (SUP-7).
  - Location: `detent-acme/src/order.rs:438-471` (`write_json_atomically`) and `lib.rs:252-270` (`HookProvider::present`).
  - Fix: call `f.sync_all()` after `write_all`. After the rename, `File::open(parent)?.sync_all()`.
  - Test: none is unit-observable. Say so in the commit; do not fake one.
- **M18 dns-01 TXT records are never deleted** [Sonnet] (SUP-8).
  - Location: `order.rs:31-56`. `DnsProvider::delete` has no non-test caller.
  - Fix: `present_challenges` tracks the records it presented and deletes them on error. It returns `Vec<DnsRecord>` on success. Add `cleanup_challenges(provider, &records)`, which callers run after `finalize` whatever the outcome.
  - Test: `present_failure_withdraws_already_presented_records`.
- **M19 device-attest-01 is advertised but cannot work** [Sonnet] (SUP-9).
  - Problem: the `acme-attest` feature adds no attestor, but `--self-test` still reports it, and `covers()` then requires every future binary to report it too. `finalize` mints a fresh key, so a TPM attestation could never bind to the certified key.
  - Fix: remove the feature id from self-test and from `crates/detent/Cargo.toml` until a real attestor exists.
  - Test: `run.rs::acme_attest_is_not_advertised_without_an_attestor`.
- **M20 Positional pairing in `apply` rewrites later lines and moves directives** [Opus] (MODA-4, MODB-6).
  - Location: `apply` in samba, nfs, hosts, mounts, `_template`, and resolver (`plan_slot`).
  - Fix: generalise the Myers diff in `crates/detent-ops/src/diff.rs` into `align<T: PartialEq>` in `detent-core`. Add one shared `Document` helper that keeps unchanged lines, removes deleted ones, and inserts new ones after the previous kept line in the **same section**. Every module's apply uses it.
  - Tests:
    - samba `deleting_a_directive_does_not_move_later_directives`.
    - hosts: drop the first of three entries; assert `changed_lines == 0` for the rest.
    - resolver: an appended `Hardening` entry lands in `server:`, not in the trailing `forward-zone:`. For unbound, make "misplaced" a `Severity::Error`.
- **M21 Quadratic `Document` edits allow a read-scope DoS** [Opus] (MODA-5; plausible, not timed).
  - Location: `detent-core/src/doc.rs:244-348`. Each edit calls `normalize`, which is O(n).
  - Fix: add a one-pass `Document::rebuild(|lines| ..)` that normalises once. M20's helper uses it.
  - Test: a 200,000-line hosts file with an empty model applies in under 5 s (release profile, `#[ignore]`d **only** if the owner agrees it is a benchmark; otherwise use a lower bound on a debug build).
- **M22 fstab lock-out cases are not caught** [Sonnet] (MODA-6).
  - Location: `crates/modules/mounts/src/lib.rs`. `SERVICES` is empty, and `Request::Mount` is `Unsupported`, so commit-confirm cannot observe a bad fstab.
  - Fix:
    - Error on a non-absolute mountpoint (other than `none`/`swap`).
    - Warn on a missing `nofail`/`x-systemd.automount` for every non-root, non-swap entry.
    - Warn when entries exist but none is `/`.
    - Correct the SERVICES comment. Document that commit-confirm cannot protect fstab until reboot.
  - Tests: `validate_flags_relative_mountpoint`, `validate_warns_missing_nofail_on_any_data_mount`, `validate_warns_when_root_entry_absent`.
- **M23 Samba security validation ignores sections and synonyms** [Sonnet] (MODA-7).
  - Location: `samba/src/lib.rs:458-561` (`value_of` returns the last value anywhere in the file).
  - Fix:
    - Track the current section.
    - Read global-only parameters from `[global]` only.
    - For per-share parameters, compute the share's effective value (its own, else `[global]`'s).
    - Normalise names (lowercase, strip whitespace) and map synonyms (`public` → `guestok`, `minprotocol` → `serverminprotocol`).
  - Tests: `validate_is_section_aware`; `public = yes` and `GuestOK = yes` both warn.
- **M24 Block-form netplan nameservers are parsed as interface addresses** [Sonnet] (MODB-4).
  - Location: `network/src/lib.rs:584-593`.
  - Fix: if the stack ends `[.., "nameservers", "addresses"]`, push to `entry.dns`.
  - Test: `netplan_block_nameservers_are_dns`.
- **M25 chrony and dnsmasq accept include/script directives silently** [Sonnet] (MODB-5).
  - Fix: add Warnings, with new ids, for chrony `include`, `confdir`, `sourcedir`, `pidfile`, `user` and dnsmasq `dhcp-script`, `dhcp-luascript`, `dhcp-scriptuser`. Add `dhcp-script` to dnsmasq `INCLUDE_KEYS`. H23 is the real control; this is the plan-time signal.
  - Tests: `validate_warns_on_include_directive`, `validate_warns_on_dhcp_script`.
- **M26** → raised to **H23**.

---

## 6. Low

One line each: location → fix → test. Sonnet unless marked.

**Platform**
- **L-PLAT6** `service/checks.rs:96-101`: `StdoutPattern` is a plain substring match and ignores the exit code. It is used only by a test fixture; every shipped module uses `ExitZero`.
  - Fix: rename it `StdoutContains` and also require `status == Some(0)`.
  - Test: `stdout_pattern_requires_literal_match_and_exit_zero`.
- **L-PLAT7** `monitor.rs` `run_check` writes candidates under the worker-owned `<state_root>/tmp`, and `create_dir_all` follows symlinks.
  - Fix: use a monitor-owned `/run/detent/check` (0700 root), created with no symlink following.
  - Test: `check_candidates_live_outside_worker_writable_paths`. [Opus]
- **L-PLAT8** `proto.rs:52-55`: the doc says `ReplaceBinary` "still answers Unsupported", which is stale. Fix the doc.

**Ops / core / i18n**
- **L-OPS11** Audit records for UpdateApply, Restore, Confirm and Rollback omit hashes and the commit id.
  - Fix: set `hashes.new`, read the previous digest before a restore, and add `commit_id` to `AuditRecord`.
  - Test: extend `update_apply_is_swapped_through_the_monitor_and_audited_once`.
- **L-OPS12** A no-op Apply still writes the file, evicts a backup, restarts the service and arms a commit.
  - Fix: return early when `rendered == current`.
  - Test: `an_identical_apply_writes_nothing_and_keeps_backups`.
- **L-OPS14** A `ConfirmCommit` processed after the deadline is still accepted (`monitor.rs:700-711`).
  - Fix: guard with `Instant::now() < pending.deadline`; otherwise enforce the deadline and answer `UnknownId`.
  - Test: `a_confirm_after_the_deadline_is_refused`. [Opus]
- **L-OPS15** `AuditQuery` reads the whole log.
  - Fix: set a default and a maximum `limit`, read backwards from EOF, and rotate by size.
  - Test: `query_without_a_limit_returns_at_most_the_default_cap`.
- **L-OPS16** Unknown module ids from callers are copied raw into audit records.
  - Fix: record the registry id, or `<unknown>`.
  - Test: `an_unknown_module_id_is_not_copied_into_the_audit_record`.
- **L-OPS17** Apply cannot create a missing target, although `ApplyReport.created` suggests it can.
  - Fix: add a distinct `ProtoError::NotFound` meaning an empty current file, and refuse commit-confirm for created files.
  - Test: `apply_creates_a_missing_target`.
- **L-OPS18** `detent-modules/Cargo.toml:27-30` has a stale comment. The "empty registry" test is gated on `not(module-hosts)` only.
  - Fix: gate it on `not(any(all eight))`.
- **L-OPS19** `detent-i18n` passes C0, C1 and bidi control characters in args through to terminals.
  - Fix: sanitise argument values.
  - Test: `render_neutralises_control_and_bidi_chars_in_args`.

**Web**
- **L-WEB9** `tls.rs` `store_acme` does two renames, so a torn cert/key pair blocks `serve` from starting.
  - Fix: write one framed `acme.bundle.der`. In `bind_web_server`, fall back to the bootstrap pair on a load error.
  - Test: `a_mismatched_stored_acme_pair_falls_back_to_bootstrap`.
- **L-WEB10** The 90-day bootstrap cert is reused forever.
  - Fix: regenerate when `not_after` is less than now + 7 days.
  - Test: `an_expiring_bootstrap_pair_is_regenerated`.
- **L-WEB11** The Argon2 timing parity only holds while stored params match the current ones.
  - Fix: rehash on login when the PHC params differ.
  - Test: `a_login_rehashes_a_hash_made_at_old_params`.
- **L-WEB12** Argon2 runs on async runtime workers.
  - Fix: run it in `spawn_blocking` behind a 2-permit semaphore, answering 503 `web-auth-busy` when full.
  - Test: `logins_beyond_the_hashing_cap_are_refused_not_queued`.
- **L-WEB13** `GET /system/update` checks live on every call until a stamp exists.
  - Fix: write the stamp after a live check, and add a 10-minute in-process guard.
  - Test: `a_second_uncached_check_does_not_reach_the_network`.
- **L-WEB14** The route table and the router are hand-kept parallel lists, and `the_table_and_the_router_describe_the_same_three_routes` never touches the router.
  - Fix: add `the_router_answers_exactly_the_table`, which sends every method to every path.
- **L-WEB15** "The binary does not compile rustls `tls12`" is false: instant-acme's default features pull in hyper-rustls `tls12`.
  - Fix: set `default-features = false`, or reword the claim. Add a CI `cargo tree -e features -i rustls` check.
- **L-WEB16** `spawn_sweeper`, `SessionStore::rotate` and the limiter sweep are dead in production.
  - Fix: delete them or wire them in. Fix the SECURITY_HARDENING:57 citation.
- **L-WEB17** The session cookie is read only from the first `Cookie` header, so HTTP/2 split cookies are missed.
  - Fix: use `get_all(COOKIE)` in both places.
  - Test: `a_session_cookie_in_a_second_cookie_field_is_found`.

**Update / ACME**
- **L-SUP10** SECURITY_HARDENING still calls detent-acme "a stub". The issuance code has no production caller, and `bootstrap = "acme"` expects an issuer that does not exist.
  - Fix: update the docs and refuse `bootstrap = "acme"` until it is wired.
- **L-SUP11** `Issued` derives `Debug`, which includes `key_pem`, and a test asserts on it.
  - Fix: write a manual redacting `Debug`.
  - Test: assert the output does not contain "PRIVATE KEY".
- **L-SUP12** `policy::select` trusts API order, so a later-published backport hides a newer release.
  - Fix: sort parsable tags by version.
  - Test: `a_later_published_backport_does_not_hide_a_newer_release`.
- **L-SUP13** `root_from_path` does not refuse `index >= size`, and recurses without bound at size 1.
  - Fix: refuse both, and cap `path_hashes` at 64.
  - Test: `root_from_path(0,1,leaf,&[[0;32]])` is `Err`.
- **L-SUP14** `install.rs` swap and rollback do not fsync the directory.
  - Fix: call `File::open(dir)?.sync_all()` after each rename. No unit test is possible; say so.
- **L-SUP15** acme-dns accepts `http://`, and the fetch connector uses `https_or_http`.
  - Fix: accept https only (or loopback-only http for acme-dns).
  - Test: `acme_dns_refuses_plain_http`.
- **L-SUP16** The deSEC fixtures are invented: TXT values are unquoted and the TTL is 60.
  - Fix: send quoted values with ttl 3600, and use captured responses.
  - Test: `desec_sends_quoted_txt_rdata`. Plausible only.
- **L-SUP17** `HttpRequest` derives `Debug`, which includes the bearer header.
  - Fix: write a manual `Debug` that prints header names only.
  - Test: `http_request_debug_redacts_headers`.
- **L-SUP18** `pebble_live` returns `Ok` when `PEBBLE_URL` is unset, and the CI images use `:latest`.
  - Fix: panic when the variable is unset, and pin the images `@sha256`.

**Binary / MCP / FFI**
- **L-BIN11** FFI entry points are safe `extern "C" fn` but dereference raw pointers. `from_raw_parts` has no `len <= isize::MAX` check, and `split_doc` reads the header after releasing the `LIVE` lock.
  - Fix: declare them `pub unsafe extern "C" fn` with `# Safety` docs, check the length, and hold the lock across the header read. Update FFI.md to say double-free detection is best-effort.
  - Test: `oversized_length_is_refused`. [Opus]
- **L-BIN12** FFI error codes cannot be retrieved. `detent_parse` does not parse, `detent_defaults_json` swallows bad JSON, and `alloc_cstring` returns NULL with no error set.
  - Fix: add `detent_last_error_code()`, make parse real, return an error for a bad profile, set the error on every NULL path, and regenerate the header.
  - Tests: one per case.
- **L-BIN13** On 32-bit targets the FFI alloc alignment uses `align_of::<usize>()` but writes a `u64`.
  - Fix: use `align_of::<AllocHeader>()`, plus a const assert.
- **L-BIN14** `doctor` follows symlinks and ignores ownership.
  - Fix: use `symlink_metadata` and fail on a symlink. When running as root, fail if `uid != euid`.
  - Test: `a_symlinked_state_root_fails`.
- **L-BIN15** `token create --expires-secs <overflow>` gives a token that never expires.
  - Fix: return a usage error, `cli-bad-expiry`.
  - Test: `an_overflowing_expiry_is_a_usage_error`.
- **L-BIN16** A forked child whose `spawn_pair` fails returns into `main`.
  - Fix: call `abort_child(1)` in the child arm on a `become_worker` error.
  - Test: failing `confine_worker` hooks make the child exit 1. [Opus]
- **L-BIN17** Weak tests:
  - `doctor.rs:464` `assert_eq!(Status::Ok, Status::Ok)`.
  - The English scanner (`main.rs:159`) stops at the first `#[cfg(test)]`.
  - The `webadmin.rs:711` test assumes there is no `/dev/tty`.
  - The rollback test at `run.rs:3128` only asserts "not a usage error".
  - `ffi.rs` has no negative tests.
  - Fix each one; do not delete coverage.
- **L-BIN18** Passwords typed at the prompt stay in an un-zeroised `BufReader` and are cloned.
  - Fix: read byte by byte into `Zeroizing<Vec<u8>>`.
- **L-BIN19** Dead code: public test fixtures in detent-mcp (`RecordingExecutor`, `AllowAllAuthz`, `LockedEngine`, `from_digests`), and the always-false `SessionExecutor.dryrun`.
  - Fix: put the fixtures behind `#[cfg(test)]` and delete the rest.

**Modules**
- **L-MODA8** NFS: no `sec=` counts as sys but is not flagged, `sec=sys:krb5p` is not flagged, and `0.0.0.0/0`, `::/0` and `*.*` are not treated as world.
  - Fix: flag these, and flip the existing test.
  - Tests: `validate_warns_default_sec_sys`, `validate_flags_cidr_world_export`.
- **L-MODA9** hosts: pointing `localhost` at a non-loopback address is only a Warning.
  - Fix: make it an Error, and include `ip6-localhost` and `ip6-loopback`.
- **L-MODA10** Samba root-exec and exposure parameters raise no warning.
  - Fix: add warnings.
  - Test: `validate_warns_root_exec_parameters`.
- **L-MODA11** The samba and nfs conformance probes only try `\n`, `\r` and `\0`.
  - Fix: add probes for `\ # ; [ ] " -` and widen the fuzz alphabets. These probes must fail before H13/H14 and pass after.
- **L-MODA12** `_template` is excluded from the workspace and never compiled.
  - Fix: add a CI step that instantiates it and runs its tests. Extend its `render_line` TODO: "reject every character the upstream parser treats as syntax".
- **L-MODB7** The network conformance `prop_filter` always passes, routes are never generated, and the probes cover only `\n\r\0`.
  - Fix: delete the filter, generate routes, add `route_to_probe("0.0.0.0/0; reboot")`, and make `render_ifupdown` reject a non-CIDR/IP `route.to`/`via` itself.
- **L-MODB8** Dead insert-position code and `let _ = gw/bridge` placeholders in the network module. networkd drops `bridge` silently, and NM drops routes silently.
  - Fix: return `EditError::Unsupported` instead of dropping them.
  - Tests: an NM apply with routes, and a networkd apply with a bridge, each return `Err`.

**Frontend / docs / misc**
- **L-FE3** `web/src/api/schema.d.ts` has stale JSDoc.
  - Fix: `bun run api:generate`; `bun run api:check` must pass.
- **L-ORC1** The `// (Jev-routed)` doc comment on production code (`crates/detent/src/mcp.rs:128` `resolve_identity`) is dev-process metadata.
  - Fix: delete it. Routing provenance belongs in PROGRESS.md.
- **L-ORC2** `detent-update/src/health.rs` `ensure_provider()` installs a process-global rustls provider from library code.
  - Fix: fold into H19 (use an explicit-provider `ClientConfig`).

---

## 7. Claims that are false today (fix the doc in the item's commit, or in batch 10)

| Doc | Claim | Reality | Item |
|---|---|---|---|
| SECURITY_HARDENING:102 | External validators run before apply | Plan only; the monitor would be killed anyway | H5, H6 |
| SECURITY_HARDENING:105 | Commit-confirm survives a monitor restart | `recover_pending` has no caller | H1 |
| SECURITY_HARDENING:107 | Audit log append-only | Worker-owned, rewritable, fail-open | H7, M3 |
| SECURITY_HARDENING:72 | Request timeouts stop slow-loris | No header timer | H9 |
| ADR-001 | Worker compromise does not directly grant root | ReplaceBinary (C1) and config content (H23) | C1, H23 |
| ADR-012 / PLAN §2.5 | Rollback re-applies the prior service action | Files only | H4 |
| PLAN §2.9, ADR-014 | Tested against real bundles; SCT/SET verified | Self-minted fixtures; no SCT/SET | H17, M16 |
| detent-ops lib.rs:8-9 | Complete audit record, not best-effort | Fail-open, and a test enforces it | H7 |
| detent-web token.rs:22 | No cache in front of the store | Loaded once | H10 |
| detent-web Cargo.toml:44 | Peer address handed to handlers | Never inserted | H8 |
| docs/API.md:122, :170 | Refusals audited; MCP honours revocation | Neither | M4, H10 |
| docs/FFI.md | Never panics across the boundary; typed error codes | No guard; codes not retrievable | M13, L-BIN12 |
| detent-web tls.rs:12 | No rustls `tls12` in the binary | Pulled in by instant-acme | L-WEB15 |
| PROGRESS (many entries) | clippy clean / workspace tests green | `--all-features` clippy red; Linux test red; coverage red; fuzz CI red | H20 |
| PROGRESS "What exists" | "the 14 operations" | 17 | batch 10 |
| samba lib.rs:18-21, nfs lib.rs:14-19 | Continuation and `-`/`#` handling | Wrong | H13, H14 |

---

## 8. STAGE2 (Jev opportunities): what this review accepts, corrects, and rejects

STAGE2 was re-read in full against the code. **Accepted:**
- Stage 2 waits until initial development is complete. The order is now **STAGE3 → the rest of PLAN.md → STAGE2**; STAGE2.md §0 holds the gate. STAGE2's main proposal depends on subsystems that do not work yet (below). STAGE2.md was revised on 2026-09-23 to include everything in this section.
- Jev must never sit on the security boundary. Authz, privsep and validation stay deterministic, and `validate`/`has_errors()` stay authoritative.
- Pin `jev-1.13.0` (not `jev-latest`) once tuned. Re-check pricing, limits and thresholds at build time.
- The falsifying-evaluation discipline (a 20-plan corpus, go/no-go criteria, kill conditions) is right. Keep it.
- Doctor ranking (§4.2) is the lowest-risk trial because it is read-only. Low value, but acceptable as a first experiment.
- Deprioritising audit triage is correct. Audit records carry hashes and ids only.

**Corrected:**
1. **§4.1's premise about checks is wrong.** STAGE2 says `CheckReport` collapses stdout via a substring match (`checks.rs:96-101`). That code exists, but only a test fixture uses `StdoutPattern`; every shipped module uses `ExitZero` (L-PLAT6). The real problems are larger:
   - validators never run on apply (H5);
   - under a confined `serve`, running one kills the monitor (H6).

   The `checks` field the proposed apply gate would read is empty on the apply path today.
2. **"Safety is time-only" is not the defect.** A deterministic commit-confirm window is the right mechanism (ADR-012). The defect is that it is broken: H1–H4, H21 and H22. Fix it before adding model-tuned "friction". A model must never compensate for a broken safety net.
3. **The privacy guard in §6 does not protect anything.** STAGE2 says "never send config bodies beyond what PlanReport already exposes". But `PlanReport.rendered` is the whole file, and `unified_diff` carries full lines, which can include CIFS passwords, Kea DB passwords and NM PSKs (M6). If §4.1 is ever built, the request state must be **structural features only**: module id, `service_action`, affected unit names, hunk and line counts, check pass/fail/exit codes, and diagnostic ids. No file text and no diff lines. Make this a typed struct with no `String` fields that could carry file content.
4. **Failure mode must be specified.** The call runs in the worker. On any API error, timeout (>1 s) or WAF 403, apply behaves exactly as today. Jev may only **add** friction (require an explicit confirm, a longer window, a second click). It may **never remove** a deterministic requirement: `route = auto_apply` must not skip a descriptor's `commit_confirm` or a failing check. The feature is off by default and needs explicit egress config, because a root-adjacent tool calling a third-party API is an egress-policy decision for the owner.
5. **WAF caveat.** TypeSafe's Cloudflare WAF returned 403 for payloads containing literal system paths and privilege words. Real plan metadata contains exactly those. This is one more reason for structural-only state, and it makes the fail-open-to-today's-behaviour rule mandatory.
6. **Dependency note.** A Rust client needs an HTTPS client in the worker. `detent-update` already has hyper-rustls; reuse that stack (ADR-009), so no new TLS dependency or ADR-011 cooldown is needed.

**Rejected:**
- **§4.3 MCP natural-language → Operation routing.** MCP clients are already LLMs that emit typed tool calls against 17 `deny_unknown_fields` schemas. A server-side NL router duplicates the client's job and adds a prompt-injection surface: text in a config file or ticket can steer an operation choice. No benefit over the typed tools.
- **Using Jev Nouls as process gates.** PROGRESS shows `push_ready` Nouls deciding pushes while CI was red. Slice ordering by Jev is harmless; readiness gates must be deterministic (§0.4, CI green).

---

## 9. Checked and clean (coverage record — do not re-review without cause)

- **privsep wire:**
  - `transport.rs` frame cap checked before allocation; `proto.rs` closed enums with trailing-byte rejection; handshake required, and a second Hello is fatal.
  - Allowlist ids are dense and no paths cross the wire.
  - `atomic_to_proto` strips paths.
  - `sys.rs` unsafe is sound: the setgroups → setgid → setuid order is checked.
  - `spawn.rs` forks before any runtime, and sets no_new_privs and dumpable=0 before dropping privileges.
- **`fs/atomic.rs`:**
  - `O_NOFOLLOW`/`O_EXCL` temp in the same directory, fchmod/fchown, xattr copy (SELinux), fsync of the file, renameat, fsync of the directory.
  - Backups 0700/0600 with rotation fsync'd.
- **`service/exec.rs`:** absolute compile-time paths, no shell, `env_clear` + `LC_ALL=C`, capped output, timeout then kill and reap. Unit names are never taken from the worker.
- **Engine:**
  - `authz.permit` runs before any I/O for all 17 variants, and mutating variants emit exactly one outcome record.
  - `has_errors()` gates apply.
  - `expected_hash`, when present, closes the read→write TOCTOU via `expected_prev`.
  - The engine is single and `&mut self`.
  - Double rollback is impossible (`take_if`), and the confirm window is clamped to 1..=3600.
- **Lossless doc model:** `parse`/`render` are total and exact (CRLF, lone CR, NUL, no final newline), and every edit path rejects `\n\r\0`.
  - Kea JSONC escapes correctly with depth ≤128.
  - chrony, dhcp and resolver use two-pass edits.
  - There are no `unwrap`/`expect`/panicking indexes in non-test module code.
  - Every model uses `deny_unknown_fields`.
- **Web:**
  - Every mutating route sits under the CSRF layer with `WriteCaller` + `authorize`.
  - `__Host-` cookie with Secure/HttpOnly/SameSite=Strict; login invalidates the presented id.
  - `subtle` comparisons throughout; a 256 KiB body cap plus a JSON depth check.
  - SPA serving has no filesystem join.
  - TLS 1.3 only with no 0-RTT; hot replace is safe; `load_acme` framing uses checked splits.
  - Secrets are redacted in `Debug`; `Config`/`AcmeConfig` are not `Serialize`.
- **Update:**
  - The verified buffer is exactly what gets installed.
  - The SAN check is exact equality bound to the tag; downgrade is refused by default.
  - The placeholder trust root refuses closed.
  - Streaming caps and timeouts are in place.
  - Self-test runs before the swap; `.prev` plus rollback and `mark_bad`.
- **ACME:**
  - EAB and provider secrets redacted; credential files 0600 via `create_new`; an unreadable credential never re-registers.
  - `percent_used` is overflow-safe.
  - HookProvider fqdn validation prevents traversal.
  - Pebble issuance runs in CI.
- **MCP:**
  - The HTTP bearer check uses SHA-256 + `ct_eq` and returns 401 before rmcp runs; rmcp's default allowed hosts are loopback only.
  - Every tool input uses `deny_unknown_fields`; scope is checked before execute.
- **FFI:** alloc and free pair correctly; every pointer is null-checked and every string UTF-8-checked; handles live behind mutexes.
- **SPA:** no `dangerouslySetInnerHTML`, CSRF token held in a closure (not in storage), no `any` at API boundaries, CSP hash matches the inline theme script, errors surfaced rather than swallowed.
- **CI and packaging:**
  - All actions are SHA-pinned with least-privilege permissions, and there is no `pull_request_target`.
  - `install.sh` has no `curl|sh`.
  - systemd and polkit hardening match ADR-001; release publishes Sigstore signatures, SBOM and attestations.

---

## 10. Out of scope, noted for later

- Upstream daemon parsing (smb.conf continuation, exportfs `-opts`, unbound multi-statement lines, deSEC rdata) was taken from man pages and memory, not executed. H13, H14, H15 and L-SUP16 should each start with a quick live confirmation on a010 before the fix: run `testparm`, `exportfs -v` and `unbound-checkconf` against the crafted file.
- The coverage floors were measured on macOS. CI measures on Linux (detent-platform is known to differ by about 5 points).

---

## 11. Status

### 11.1 Snapshot 2026-09-24 at `c216842` (orchestrator audit)

Method:
- Code evidence per item from `git log -G` / `git grep` at HEAD, with no trust in commit messages.
- Gates re-run on a clean HEAD worktree (without oh-my-pi's uncommitted WIP).
- GitHub CI read for the last pushed commit (`7e59ab7`).
- Items marked **done** have code evidence. They were **not** re-reviewed in depth; a verification pass is still owed (§11.3).

**Gates at HEAD — still red (H20 not done):**

| Gate | State |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy --all-features -D warnings` | **fail**, 2 new errors from the H1 commits: `run.rs:1192` redundant closure; `serve.rs:243` needless `&mut` |
| `cargo test --workspace --all-features` (macOS) | 1728 pass, 0 fail, 6 ignored |
| CI Rust (Linux) and Coverage | **fail**: `hooks_confine_both_roles_across_a_forked_pair` → `PR_CAPBSET_DROP ... EPERM`. M1 made caps required and did not fix the drop-after-`setuid` ordering the item warned about. |
| CI macOS | **fail**: `detent-update --test real_transport` `caps_redirect_loop` |
| CI ACME Pebble | **fail**: `ghcr.io/letsencrypt/pebble:v2.10.1: not found`. The L-SUP18 pin names a tag that does not exist. |
| CI Web | fail (not triaged) |
| Codespell | **fail**, 5 hits: `detent-mcp/src/lib.rs:16`, `detent-update/src/verify.rs:355`, `detent-web/src/auth/users.rs:979`, `modules/dhcp/src/lib.rs:2581`, `docs/API.md:174` |
| Lint (Checkov) | **fail** on the `Upstream watch` workflow |
| fuzz.yml | **fail** (last run 2026-09-23) |
| Pushed? | No. 12 local commits after `7e59ab7` are unpushed. |

**Process violations to stop now:**
1. `dc3a279` is one ~4,000-line commit (70+ files) spanning dozens of items, with a vague message. Its "clippy clean" claim was false by the next push. This breaks §0.1 (one item per commit) and §0.8.
2. Lint suppressions rose from **97 to 116** since the baseline (e.g. `a77c3ae` adds `#![allow(clippy::expect_used, clippy::unwrap_used)]` to `real_transport.rs`). This breaks §0.3. Each new `allow` must be justified in its commit or removed.
3. None of the Linux sandbox items (H6, M1, M2) were verified on a Linux host (§0.5), and M1 broke Linux CI.
4. `docs/STAGE2.md` was reverted and `docs/STAGE3.md` deleted in the working tree. §0.10 now forbids that.
5. A stray worktree, `/private/tmp/wt-f3309b6`, exists. Remove it when done.

### 11.2 Per-item state

**Done — code evidence present (awaiting verification pass):**
C1-a, C1-d, H1, H2, H4, H5, H7, H8, H9, H11, H12 (option B), H13, H14, H15,
H16, H21, H22, H23, M2, M5, M6, M9, M10, M11, M12, M13 (doc path: panic
aborts), M14, M15, M17, M18, M19, M21, M24, M25, L-PLAT6, L-PLAT8, L-OPS18,
L-OPS19, L-WEB14, L-WEB17, L-BIN11, L-BIN12, L-BIN13, L-MODB8, L-ORC1.

**Landed but broken or partial — fix before anything new:**
- **H20:** see the gate table above. This is the top priority.
- **M1:** breaks Linux CI. Drop the bounding set **before** `setuid` in `become_worker`, or treat "effective and permitted already empty" as `Applied` for the worker. Verify on a010.
- **H6:** exec syscalls were added to `MONITOR` but never run confined on Linux. Do the strace step and add the `enforce_mode_monitor_can_spawn_a_validator` test.
- **H10:** web stores refresh and revoke sessions (done). MCP is now closed too (2026-09-24, item H10-MCP): `check_auth` takes the presented token explicitly instead of reading `DETENT_MCP_TOKEN` per call, `StoreVerifier { state_root }` re-reads `tokens.json` on every authentication (tool calls and the HTTP bearer gate), and identities are labelled `token:<id>` — `&token[..8]` is gone from `ConstantTimeTokenVerifier`. Tests: `crates/detent/src/mcp.rs::a_revoked_token_is_refused_on_the_next_call`, `::an_expired_token_is_refused_on_the_next_call`, `::the_identity_label_is_the_token_id` (all failed before the fix). Pending the orchestrator's verification pass like every other Done item.
- **H17:** the payload type and `verificationMaterial.certificate` are accepted. There is no evidence of a **captured real bundle** fixture test, and M16 (negative tests) is open. Treat as unproven until a real release bundle verifies.
- **H18:** redirects are implemented, but `caps_redirect_loop` fails on macOS CI. Fix the test or the code; do not `#[ignore]` it.
- **C1-c:** the monitor now calls `detent_update::verify::verify`, so detent-platform depends on detent-update rather than the split crate `detent-update-verify` STAGE3 asked for. That is acceptable only if it does not pull network or TLS code into the monitor's reachable set; check `cargo tree -p detent-platform -e normal`. It is only as good as H17.
- **L-SUP18:** the Pebble image pin must be a real digest (`@sha256:`), not an invented tag.

**Inside the `dc3a279` batch only — unverified, review item by item:**
M3, M7, M8, M22, M23, L-OPS11, L-OPS14, L-OPS17, L-PLAT7, L-WEB9, L-WEB10,
L-WEB11, L-WEB12, L-WEB13, L-WEB15, L-WEB16, L-SUP10, L-SUP11, L-SUP12,
L-SUP14, L-SUP15, L-SUP16, L-SUP17, L-BIN14, L-BIN15, L-BIN16, L-BIN17,
L-BIN18, L-BIN19, L-MODA8, L-MODA9, L-MODA10, L-MODA11, L-FE3.

**Open — no evidence of work:**
C1-b (staging out of the worker tree), H3 (the journal still accumulates
across modules: `monitor.rs` pushes on every write), H19 (WIP in
`health.rs`, uncommitted), M4 (engine still `AllowAll`; denials not
audited), M16, M20 (positional pairing), L-OPS12, L-OPS15, L-OPS16, L-SUP13,
L-MODA12, L-MODB7.

**Uncommitted WIP in the tree at snapshot time** (27 files): `health.rs`
(H19), `tls.rs` (L-WEB9/10), `monitor.rs`/`spawn.rs`/`sandbox/mod.rs`
(likely the M1 fix), mounts/samba/network modules, `conformance.rs`, and
packaging.

**Tally (≈94 items):** ~45 done pending verification, 8 broken or partial,
~34 batch-only and unverified, 12 open.

### 11.3 Next steps, in order
0. Install the runtime packages on a010 allowed by §00.5 (no build tools), set up the local musl cross-build, record both in PROGRESS.md, and remove the stray `/private/tmp/wt-f3309b6` worktree. Commit or discard your own uncommitted WIP **one item at a time**. Do not commit it as a batch; if a WIP hunk cannot be tied to a single item, discard it and redo it under the loop in §00.3.
1. Make CI green on a **pushed** commit (H20, M1, L-SUP18, H18, clippy, Codespell, Checkov, fuzz). No new items until it is green.
2. Remove the new lint suppressions or justify each one.
3. Close H3, M4, H19, and H10's MCP half. These are safety items still open.
4. Verification pass: a fresh reviewer re-checks the 45 "done" items and the 34 batch-only items against each item's Test/Acceptance line in this file. Mark each one ✅ here, or reopen it.
5. Then the remaining open items. Then PLAN.md.

### 11.4 Orchestrator audit 2026-09-24 at `a5d06a1` — STAGE3 is NOT finished

oh-my-pi reported "finished". The audit disagrees. Findings, then directives.

**Gates (CI run 35967845615 on `a5d06a1`) — red, 4 jobs:**
- Rust (Linux): `cargo fmt --check` fails. Unformatted code was pushed, so the §0.4 gates were not run before the push.
- Coverage (Linux): 6 `sandbox::linux::tests` fail with `PR_CAPBSET_DROP ... EPERM`. The runner is unprivileged and the monitor policy now requires caps.
- macOS: the `clippy` component is missing from the toolchain.
- Web: `coverage:check` fails.
- `fuzz.yml` has not run since 2026-09-23 (last run: failure). Its fix in `6e50880` is unproven.
- The allow count stays at 116. Good: it did not grow.

**Process violations:**
1. **0 of 24 commits** (`d0cffe1..a5d06a1`) follow the §00.3 body format. None carries an `Item:` id, failing-test evidence, gate exit codes, or an a010 line, so none can be attributed or verified from history.
2. **§11 was never updated** and no §00.6 session report was written. The status lives only in PROGRESS.md, which also contradicts CI ("1736 passed" on macOS against a red Linux run).
3. **a010 provisioning broke §00.5:**
   - It installed build-essential, clang, lld, rustup, nightly, cargo-llvm-cov, cargo-fuzz and bun, all through `curl | sh`.
   - It ran `apt-get install --allow-downgrades libbz2-1.0=1.0.8-6build2`, which downgraded a base system library.
   - The owner's rule is that a010 is test-only and that nothing is compiled there.
4. **C1-b (a `DECISION`) was implemented without an owner answer.** Staging moved to `/run/detent/staging` (`4b098d0`). The design matches the proposed default, so it may stand if the owner confirms it in §12.
5. **Uncommitted WIP weakens a check.** It makes sandbox tests disable the caps requirement and "skip with a diagnostic" when `CAP_SETPCAP` is absent. A test that silently passes in CI is exactly what §00.4 forbids. **Rejected** — see directive D2.

**Item state after this audit (changes to §11.2 only):**
- **Now done (code evidence):** C1-b (pending owner confirmation), C1-c (the monitor verifies the Sigstore bundle before every swap; there is no fallback), L-OPS12, L-OPS15, L-OPS16, L-OPS11 (commit id), M4 partially (the web layer now audits `ScopeDenied`; the engine is still `AllowAll`, which is acceptable for now).
- **Still open:**
  - **H3**: `monitor.rs` `write_target` still pushes every write into `journal`, and nothing clears it outside `start_confirm_timer`.
  - **H19**: `run.rs` still pins `load_bootstrap` with a webpki root store and the `localhost` name, so every update on an ACME host still rolls back.
  - **H10 (MCP half)**: `detent-mcp` `check_auth` still reads `DETENT_MCP_TOKEN` from the env.
  - Also open: M16, M20, L-SUP13, L-MODA12, L-MODB7.
- **New finding C1-e (high) — monitor-side downgrade.**
  - Problem: `replace_binary` verifies the bundle for the **worker-supplied** `tag` but never checks that tag against the running version. A compromised worker can stage an **older, genuinely signed** release plus its bundle and have root install it, i.e. downgrade to a build with known holes. Update policy refuses downgrades only in the worker (`policy.rs`), and the worker is the party we are defending against.
  - Fix: in `replace_binary`, parse `tag` as semver and refuse unless it is greater than `env!("CARGO_PKG_VERSION")`. Downgrade stays a CLI-only, operator-typed path, never over the privsep channel.
  - Test: `replace_binary_refuses_an_older_signed_release` (sign the fixture with an older tag).
- **Note C1-f (doc)** — capability-user mode. There the monitor and worker share uid `detent` (`capability-user.conf` `User=detent`; spawn drops uid only when euid is 0), so the staging ownership check separates nothing. The only barriers are Landlock (absent on some hosts) and C1-c's signature check. Record this in ADR-001 and SECURITY_HARDENING. No code change needed while C1-c holds.

**Directives, binding, in this order:**
- **D1. Stop claiming "finished".** STAGE3 is done only when §11.3 steps 1–5 are satisfied **and** the orchestrator marks it complete here.
- **D2. Sandbox tests in CI run for real, as root.** Discard the "skip when `CAP_SETPCAP` is absent" WIP.
  - In `ci.yml`, run the unprivileged test step with `--skip sandbox::linux::tests` (explicit and visible).
  - Add a step that runs **only** those tests as root: `sudo -E env PATH="$PATH" cargo test -p detent-platform --lib --all-features sandbox::linux::tests -- --test-threads=1`. Do the same in the coverage job, or merge its profile.
  - A test must never pass by skipping itself.
- **D3. Get CI green on a pushed commit.** Run `cargo fmt --all --check`, workspace `clippy --all-features`, and workspace `test --all-features` **before every push**. Paste the exit codes in the commit body. Fix the macOS clippy component and web `coverage:check`. Then `gh workflow run fuzz.yml` and confirm it is green.
- **D4. Clean a010 back to test-only.**
  - Remove the build toolchains: `rustup self uninstall -y`, `rm -rf ~/.bun ~/.cargo/bin/cargo-llvm-cov ~/.cargo/bin/cargo-fuzz`, and `sudo apt-get remove -y build-essential clang lld` (plus now-unused autoremovals, **listed first** in §12).
  - Keep only the runtime packages from §00.5.
  - **Do not touch `libbz2`.** The downgrade is logged for the owner to decide.
  - Record every command in PROGRESS.md.
- **D5. Retroactive attribution.** Add a table to §11 (below this block) mapping each of the 24 commits `d0cffe1..a5d06a1`, plus earlier post-review commits that lack an `Item:` line, to the STAGE3 item ids they address. Give each item's test name, and say whether the test was shown to fail first (yes / no / not recorded). "Not recorded" items go on the orchestrator's verification list.
- **D6. Close the open safety items next, one commit each, in §00.3 format:** C1-e, H3, H19, the H10 MCP half. Then M16, M20, L-SUP13, L-MODA12, L-MODB7.
- **D7. From now on**, every commit uses the §00.3 body. The orchestrator will reopen any commit that does not.

### 11.5 Orchestrator audit 2026-09-24 at `28cf87a` — STAGE3 is still NOT finished

Three commits since §11.4 (`5ab7702`, `3d01a09`, `28cf87a`), plus uncommitted WIP in `seccomp.rs`, `PendingCommit.tsx`, `web/e2e/*` and PROGRESS.md.

**Directive status:**

| Directive | State | Evidence |
|---|---|---|
| D1 no "finished" claim | **violated** | "finished" reported again |
| D2 sandbox tests as root | **done, correctly** | `5ab7702`. Running as root exposed a real bug (below). |
| D3 CI green on a pushed commit | **not met** | CI run 35975076938: Rust (Linux), Coverage and Web fail. fuzz run 35975002743 still in progress. |
| D4 a010 back to test-only | **not done** | `~/.cargo/bin/cargo`, `~/.bun`, `build-essential`, `clang`, `lld` and `gcc` still installed |
| D5 retroactive attribution table | **not done** | §11 unchanged |
| D6 C1-e, H3, H19, H10-MCP | **not started** | no commits |
| D7 §00.3 commit body | **attempted, broken** | bodies contain literal `\n` instead of line breaks (see below). `3d01a09` is tagged H18 but is a web-coverage test (H20). `28cf87a` (L-SUP18, docs) also edits `providers.test.tsx`, which is outside its item. |

**Real bug exposed by D2 (good outcome): H6 is not fixed.** As root on Linux CI, `sandbox::linux::tests::enforce_mode_monitor_can_spawn_a_validator` **fails**. The monitor is still killed when it spawns a process. So every validator run and every service restart under a confined `serve` still crashes the monitor, and H5 (validators on apply) is unsafe on real hosts until this passes. Reopen H6:
1. Find the missing syscall(s). Run the cross-built test binary on a010 under `sudo strace -f -o /tmp/h6.trace`, or use `SeccompAction::Log` temporarily in a local-only experiment, never committed.
2. Add them to `MONITOR` with both arch numbers.
3. The test must pass as root in CI.

**Commit-body mechanics.** Write the message to a file and use `git commit -S -s -F /tmp/msg.txt`, or pass one `-m` per line. Never embed `\n` in a single `-m`. Check with `git log -1 --format=%B` before pushing.

**Next, in this order — nothing else:**
1. Commit the H6 seccomp fix (Item: H6) once `enforce_mode_monitor_can_spawn_a_validator` passes as root on a010. Build the test binary locally with zigbuild, run it on a010 with sudo, and paste the output.
2. Fix Web `e2e` (Item: H21 if it is the PendingCommit change, otherwise H20), then push and watch CI until **all** jobs are green, including fuzz. D3.
3. D4 a010 cleanup, logged in PROGRESS.md.
4. D5 attribution table.
5. D6: C1-e, H3, H19, H10-MCP.
6. Write the §00.6 session report here. Then stop and wait for orchestrator review. Do not report "finished".

### 11.6 Orchestrator audit 2026-09-24 at `f2e0106` — improving, still NOT finished

Two commits since §11.5: `1cadb77` (H6) and `f2e0106` (H21). **Discipline improved:** both follow §00.3 exactly (separate lines, correct item, a010 evidence for H6, no new allows). Keep doing this.

**H6 (`1cadb77`): accepted as partial.**
- The `numbers_for` change is sound: x86_64-only syscalls are skipped on aarch64, and unknown names still error.
- The test now spawns `/bin/true` as root on a010.
- **Still owed:** the item's step 1. Run a confined `detent serve` on a010 under `strace -f`, driving one real `chronyd -p` validator (a chrony plan through the API) and one real `systemctl restart`. Add any further syscalls. A trivial `true` does not prove that real validators survive. Until this is done, H5 is not safe on real hosts.

**CI run 36054734922: red, and D2 as implemented caused two of the three failures.**
1. **Rust (Linux), `Permission denied (os error 13)` writing `target/debug/.fingerprint/...`.** The root `cargo test` step leaves root-owned files in `target/`, and later unprivileged `cargo build` steps cannot write there.
2. **Coverage: every per-path floor fails** (core 98.21, i18n 99.78, ops 98.83, platform 91.88, web 95.75, detent 91.50, modules 99.89). The root sandbox run is outside the llvm-cov profile, so its lines and the shared ones are lost.
3. **macOS: `detent-update --test real_transport` `caps_redirect_loop` times out** (`GET https://localhost:49200/next ... timed out` after 30 s). H18's test is still not stable. Do not `#[ignore]` it: make the loop cap trip before any timeout, e.g. with a per-request timeout the test controls.

**Directive D2', which replaces how D2 is done. Never run `cargo` as root:**
- **Rust job:**
  1. Build the tests unprivileged: `cargo test -p detent-platform --lib --all-features --no-run --message-format=json`, extracting the executable with `jq`.
  2. Run **that binary** as root: `sudo "$BIN" sandbox::linux::tests --test-threads=1`.
  3. The unprivileged workspace step keeps `--skip sandbox::linux::tests`.
- **Coverage job:**
  1. Run `cargo llvm-cov --workspace --all-features --no-report -- --skip sandbox::linux::tests` unprivileged.
  2. Build the instrumented platform test binary (`cargo llvm-cov --no-report --no-run -p detent-platform --lib --all-features`, or take it from the JSON output).
  3. Run it as root with `LLVM_PROFILE_FILE` pointing into the llvm-cov target's profraw directory: `sudo env LLVM_PROFILE_FILE=... "$BIN" sandbox::linux::tests --test-threads=1`.
  4. `sudo chown -R "$USER" target`.
  5. `cargo llvm-cov report --lcov --output-path ...`, then `coverage-merge.sh`.
- **Never lower a floor.** If a floor still fails after D2', the missing lines are real gaps: add tests.

**Still not done:**
- **D4 (a010 test-only).** The toolchains are still installed. The untracked `docs/INSTALLED.md` documents them instead of removing them. Remove them as D4 says, then turn INSTALLED.md into a short record of runtime packages only (plus the libbz2 note) and commit it.
- **D5** (attribution table).
- **D6** (C1-e, H3, H19, H10-MCP).
- **D1:** "finished" was reported again.

**Next, in order:**
1. D2' in `ci.yml` (Item: H20).
2. Stabilise `caps_redirect_loop` (Item: H18).
3. Push and watch until **every** CI job and `fuzz.yml` (run 36054742009) are green.
4. Finish H6: real validator + restart under strace on a010.
5. D4.
6. D5.
7. D6.
8. The §00.6 report, then stop.

---

## 12. Questions and blocked items (implementor writes here; orchestrator answers)

Format: `- <date> <ITEM-ID>: <what is blocked or wrong> — proposed: <default or fix> — owner/orchestrator answer: <blank until answered>`

Open decisions carried from the review (owner answers pending):
- C1-b: move staging to a monitor-owned root directory outside `state_root`. Proposed: yes (default).
- C1-c / H17: bundle format for releases. Proposed: the `actions/attest` DSSE bundle (default).
- M5: plan-with-checks scope. Proposed: stays Read scope, audited when checks ran (default).
- 2026-09-24 STEP0-GATES: §00.3 requires `clippy=0` before every commit, while §11.3 step 0 requires WIP resolution before step 1 H20; H20 is required to make the workspace gate green. Proposed: apply the two mechanical H20 clippy fixes before committing any WIP item; push only after §11.3 step 1 is green. — owner/orchestrator answer: **Approved (orchestrator, 2026-09-24).** Land the two H20 clippy fixes (`run.rs:1192`, `serve.rs:243`) first as their own commit (Item: H20-a). Then resolve the WIP one item per commit. Push only once §11.3 step 1 is green locally, then watch CI.
- H1.4: one-shot CLI apply on a commit-confirm module. Check what 13e4f10/462e9bf chose and record it here.
- 2026-09-24 C1-b (orchestrator): implemented in `4b098d0` before an owner answer. Owner to confirm or reject: monitor staging at `/run/detent/staging` (root 0700). — owner answer:
- 2026-09-24 a010 libbz2 (orchestrator): oh-my-pi downgraded `libbz2-1.0` to `1.0.8-6build2` with `--allow-downgrades`. Owner to decide whether to restore it. Agents must not touch it. — owner answer:
- 2026-09-24 H6: root proof done on a010 with operator sudo. Trap oracle named `__NR_open` (`open("/dev/null")`, musl `File::open_c`); fix adds `open` (2,-1) plus `dup2 arch_prctl access readlink readlinkat ppoll poll`. `enforce_mode_monitor_can_spawn_a_validator` passes as root, zero SIGSYS. - owner/orchestrator answer:

- 2026-09-25 CLI-SIZE (owner answer): the CLI-only binary linked the Sigstore verifier and aws-lc-rs through C1-c. Owner chose to gate it: `detent-platform` feature `update`; without it `ReplaceBinary` refuses every staged release (`a6f9447`). — owner answer: **gate** (2026-09-25)
- 2026-09-25 SIZE-BASELINE (owner answer): full, ui and CLI rows re-cut; the oldest commit here already exceeded the 2026-09-10 baselines (`281b91a`). — owner answer: **re-cut** (2026-09-25)
- 2026-09-25 NET-ORDER (owner answer): network `to_model` sorts interfaces, so an unsorted model broke invariant 3 (fuzz). Owner chose: `validate` flags order as an Error (`4ee303f`). UI/API clients must send interfaces in name order. — owner answer: **validate** (2026-09-25)
- 2026-09-25 L-MODA12: premise out of date — `_template` is a workspace member and compiles. What was broken was the copy recipe (duplicate package name); fixed and tested in CI (`272076d`). — orchestrator: closed.
- 2026-09-25 L-MODB8: marked done, but NM `render_nm` silently dropped routes. Fixed under L-MODB7 (`65e9e41`): NM now refuses routes and bridges. Verification pass should re-check L-MODB8. — orchestrator answer:
- 2026-09-25 H17/M16 SET gap: a forged `integratedTime` is refused only because the verifier hashes the whole tlog entry as the Merkle leaf. Real Rekor hashes the body only; then only the (unverified) SET binds `integratedTime`. H17 must add SET verification when it moves to real bundles. Also: `bad-set.json` corrupts a path hash, not a SET; ADR-014 step 6 says "certificate hash" where the code compares public keys. — orchestrator answer:
- 2026-09-25 M20 scope: chrony, dhcp and network `apply` still pair entries by position (not in M20's listed modules). Each is a small follow-up with `Document::edit_entries`. — orchestrator answer:
- 2026-09-25 network follow-ups (from L-MODB7 and the fuzz fixes): `validate` does not flag the renderer's interface-name charset; a leading `-` in a name is allowed; `is_valid_cidr` accepts `+24`; `render_netplan` never writes routes/gateways for bridges or routes for VLANs (now refused by the round-trip check rather than lost); the networkd sectioned path leaves the document partly edited on refusal (the caller discards it). — orchestrator answer:
- 2026-09-25 dead code: `UserStore::refresh_locked` (detent-web `auth/users.rs`) carries `#[allow(dead_code)]` and has no caller. — orchestrator answer:
- 2026-09-25 H6 real-validator strace and D4: not done this session. There is no a010 access from the cloud container, and the owner said "do not remove packages on a010 for now". — owner answer:

### 11.7 Session report 2026-09-25 at `0f69392` — D6 landed (C1-e, H3, H10-MCP), H19 committed earlier
- Items done: H19-health `8bd105b`; H19 `7332e50`; C1-e `35fdd42`; H3 `5d651be`; H10-MCP `0f69392`. (H16 `2febdc8`, H18 `7f1df06`, H20-fuzz `b21461e`, H20 `3a9d1cc` also on this stack, outside D6.)
- Items opened in §12: none this session.
- Gates at HEAD: `cargo fmt --all --check` 0; `cargo clippy --workspace --all-targets --all-features -- -D warnings` 0 errors; `cargo test --workspace --all-features` 0 failures (full run, no FAILED lines).
- Latest CI: run 36074875296 (push of H19-health `8bd105b`): Rust/Web/macOS/FFI/ACME green; Coverage and Size check fail. Fuzz run 36074883068: cargo-fuzz failure. D6 commits unpushed, CI not yet watched.
- Allow count: 117 (`git grep -c -E '#!?\[(allow|expect)\(' HEAD -- crates`).
- Still owed per §11.5/§11.6: D3 (push + all-green CI incl. fuzz), H6 real-validator strace on a010, D4 a010 cleanup, D5 attribution table. Stopping for orchestrator review; STAGE3 not finished.

### 11.8 Session report 2026-09-25 at `c94a860` — D3 CI green, D5 table, D6 tail landed

Worked by the orchestrator in a cloud container (Linux x86_64, root), with Opus/Sonnet implementors whose diffs were reviewed before each commit. The branch is `claude/determined-noether-wo0uh8`; CI was run by `workflow_dispatch` there.

**Items done (id + hash):**
- H20 (CI red): `2ff9f87` macOS rollback-deadline race (poll, not one sleep); `281b91a` size baselines re-cut (owner-approved); `1248f1e` platform, `7e781d8` web, `a149e56` detent, `430935a` core/i18n/ops coverage tests; `bb2f054` dead nfs checks; `675aca2` last module line; `de0b8bd` codespell word; `4ae64c8` + `4ee303f` network fuzz findings (lossy bridge, own-model loss, inet6 dhcp, positional loss, interface order).
- C1-c follow-up: `a6f9447` verifier behind `detent-platform/update` (owner-approved; CLI binary 3.06 → 2.10 MB); `4fd56b4` fuzz lock.
- D6 tail: L-SUP13 `9923f36`; M20 `5b184f9`; M16 `947cfa8`; L-MODB7 `65e9e41`; L-MODA12 `272076d`.
- §11.3 step 2 (new suppressions): `098a213`, `216d326`, `1a5eb24` removed the three added since the root commit. **Allow count 114** (was 117).
- Tooling: `39d7951` `make clean` / `make realclean` (`scripts/clean.sh`).
- Process error, fixed forward: `216d326` also committed another implementor's staged fixture rename, so the detent-update fixture test was red for `216d326..1248f1e`; `947cfa8` fixed it. Since then the index is checked before every commit, and implementors do not stage.

**Items opened in §12:** CLI-SIZE, SIZE-BASELINE, NET-ORDER (all answered by the owner), L-MODA12 note, L-MODB8 re-check, H17/M16 SET gap, M20 scope (chrony/dhcp/network still positional), network follow-ups, dead `refresh_locked`, H6/D4 not done.

**Gates at HEAD (local, root container):** `cargo fmt --all --check` 0; `cargo clippy --workspace --all-targets --all-features -D warnings` 0; `cargo test --workspace --all-features --no-fail-fast` 1911 passed, 1 failed. The failure, `webadmin::tests::setup_with_force_reports_a_write_failure_as_a_credential_failure`, fails only as uid 0 and passes as uid 65534. Full coverage run: all per-path floors PASS (core/i18n/ops/modules 100, platform 92.56, web 97.75, detent 95.23 as root). All 29 fuzz targets 60 s clean except the two network targets, since fixed; network edit/roundtrip/parse 120 s clean after the fixes.

**Latest CI:** CI run 36124975918 on `4ee303f`: **success, all 11 jobs** (Rust, macOS, Coverage, Size check, Web, FFI Miri/semver, ACME, supply chain, shell, pins). Fuzz run 36124973393 on `4ee303f`: **success** (all 29 targets). Codespell run 36124977836 on `4ee303f`: success. Lint Code Base run 36120650130 on `675aca2`: success.

**Jev (`jev-1.13.0`, live POST) used only for classification and routing:** item order (L-SUP13 first, conf 0.59); implementor tier for M20 (strong, 0.96), L-MODB7 (strong, 0.76), M16 (strong, 0.86); D5 commit-to-item classification (26 Choices, 77,685 input tokens; 8 overridden, marked in the table). Everything else, including every readiness judgement, came from deterministic gates and the default model.

**D5 — retroactive attribution** (commits after the review with no `Item:` line). Jev (`jev-1.13.0`, one Choice per commit over the 98 STAGE3 ids plus `none`, 77,685 input tokens) proposed the item; the orchestrator checked each diff and overrode where marked. No commit body records a failing test, so every "Failed first" is **not recorded**, and all 26 commits go on the verification list (§11.3 step 4).

| Commit | Subject | Item(s) | Jev (conf) | Test(s) added | Failed first |
|---|---|---|---|---|---|
| `462e9bf` | Recover pending commits on monitor startup | H1 | H1 (0.97) | `shutdown_with_a_pending_commit_rolls_back`, `a_cli_apply_on_a_commit_confirm_module_never_leaves_an_unenforced_commit` | not recorded |
| `13e4f10` | Add pending commit rehydration and safe arming | H1, H2, H21 | H1 (0.45; H2 0.38) | `commit_confirm_does_not_arm_without_a_backup`, `a_commit_confirm_apply_without_a_backup_is_refused`; web "reads the monitor pending commit without a mutation body" | not recorded |
| `d0cffe1` | Fix CLI clippy warnings | H20-a | none (0.98) — **override**: §12 STEP0-GATES answer | none (lint fix) | n/a |
| `c80ab63` | Pin ACME test images by digest | L-SUP18 | none (0.76) — **override** | none (CI pin) | n/a |
| `776f717` | Fix codespell findings | H20 | none (0.99) — **override**: Codespell gate | none | n/a |
| `711ac58` | Harden upstream watch dispatch | H20 | none (0.85) — **override**: Checkov gate | none | n/a |
| `6e50880` | Fix fuzz harness edit targets | H20 | none (0.87) — **override**: fuzz gate | none (fuzz targets) | n/a |
| `9063b90` | Stabilize redirect transport tests | H18 | H18 (0.65) | changes `caps_redirect_loop` | not recorded |
| `a8bffcf` | Handle worker capability drop after setuid | M1 | M1 (0.94) | none new | not recorded |
| `4b098d0` | Move update staging to monitor runtime | C1-b | L-PLAT7 (0.90) — **override**: §11.4 names it C1-b | `monitor_rejects_group_writable_staging_permissions`, `only_the_monitor_policy_grants_the_runtime_staging_base` | not recorded |
| `de63e2e` | Reap workers on monitor startup failure | L-BIN16 | L-BIN16 (0.57) | `a_failed_monitor_setup_returns_an_error_and_reaps_its_worker` | not recorded |
| `fb82560` | Reject disabled critical mounts | M22 | M22 (0.71) | `validate_flags_boot_blockers_and_rejects_critical_noauto` | not recorded |
| `7613890` | Fix network backend round trips | L-MODB7 (partial: routes round-trip; filter and probe still open) | L-MODB7 (0.61) | `route_models_validate_and_round_trip_through_real_backends` | not recorded |
| `61e3f88` | Harden Samba security validation | M23, L-MODA10 | M23 (0.54; L-MODA10 0.45) | `root_command_warning_only_matches_root_hooks` | not recorded |
| `5800807` | Validate conformance renders | M8 | M8 (0.68) | none new | not recorded |
| `bdd33e0` | Harden Sigstore bundle verification | H17, M16 (partial: SCT parse only) | M16 (0.78; H17 0.18) | `accepts_sigstore_certificate_objects_and_in_toto_payload_type`, `an_sct_octet_string_must_parse_as_a_nonempty_list` | not recorded |
| `4de4b09` | Use explicit TLS provider for health checks | L-ORC2 | L-ORC2 (0.72) | none new | not recorded |
| `de97cad` | Harden TLS pair lifecycle | L-WEB9, L-WEB10 | L-WEB10 (0.58; L-WEB9 0.27) | `self_signed_rotation_obeys_the_acme_configuration_and_expiry`, `an_expiring_bootstrap_pair_is_regenerated` | not recorded |
| `7aa07dd` | Update operations staging fixtures | C1-b (follow-up) | none (0.84) — **override** | fixture update | n/a |
| `87cdbf3` | Sanitize unknown module audit records | L-OPS16 | L-OPS16 (0.99) | `an_unknown_module_is_sanitized_in_audit_records` | not recorded |
| `74d19c7` | Test no-op apply preserves backups | L-OPS12 | L-OPS12 (0.96) | test-only commit | not recorded |
| `a19e637` | Audit commit id on apply | L-OPS11 | L-OPS11 (0.52) | none new | not recorded |
| `e3ceee0` | Record STAGE3 hardening progress | none (docs) | none (0.99) | — | n/a |
| `75c680e` | Align missing staging error test | C1-b (follow-up) | none (0.69) — **override** | test assertion change | n/a |
| `93f3eb2` | Make staging error assertion portable | C1-b (follow-up) | none (0.76) — **override** | test assertion change | n/a |
| `a5d06a1` | Fix concurrent web test request stubs | H20 (Web CI) | none (0.85) — **override** | test stub change | n/a |

`35fdd42` (C1-e), `5d651be` (H3), `0f69392` (H10-MCP), `1cadb77` (H6), `f2e0106` (H21), `3a9d1cc` (H20) and `7f1df06` (H18) carry an `Item:` line in the body but not as a git trailer; they need no row.

**Still owed:**
- D4 (a010 cleanup): the owner said "do not remove packages on a010 for now".
- H6 real-validator strace on a010: no a010 access from the cloud container.
- §11.3 step 4 verification pass over the "done" and batch-only items, including the 26 D5 commits.
- The §12 follow-ups.

STAGE3 is not marked complete; that is for the orchestrator audit.

### 11.9 Verification pass (§11.3 step 4), started 2026-09-25 at `733d6e0`

Method: reviewer per group; each item is checked against its Fix/Test/Acceptance lines; non-vacuity is shown by removing the fix in a throwaway worktree. Verdicts: VERIFIED, VERIFIED-NO-NEG, PARTIAL, REOPEN. Groups without a table here are **not yet done**; see `docs/STAGE4.md` §4.1.

**Group C (web) — 7 VERIFIED, 8 PARTIAL, 3 REOPEN.** `cargo test -p detent-web --all-features` 340 + 9 pass; the web tests named below pass; `bun run api:check` OK.

| Item | Verdict | Evidence / what is missing |
|---|---|---|
| H8 | VERIFIED | `server.rs:384-390` ConnectInfo, `ratelimit.rs:44-57` /64; `the_peer_address_reaches_the_handlers`, `ipv6_addresses_in_one_slash64_share_a_bucket` fail without the fix |
| H9 | **REOPEN** | The header timeout does not free an idle post-handshake connection: it holds a permit until the 600 s lifetime (the auto builder sniffs the protocol with no deadline). `an_idle_connection_does_not_hold_a_permit` passes only because it sets lifetime 450 ms. Fix: a deadline on the first read (timeout, or ALPN → `http1_only`/`http2_only`); the test must use the default lifetime |
| H10 (web) | PARTIAL | The refresh in `authenticate`/`verify_password` is pinned. The refresh inside `mutate()` (`users.rs:567`, `token.rs:443`) is **unpinned** (removing it keeps all tests green). Add: store A, not yet refreshed, writes after store B removed a user / revoked a token; assert no resurrection |
| H21 | PARTIAL | Confirm/rollback UI pinned (`PendingCommit.test.tsx` fails without onClick). The e2e test (apply → reload → banner → confirm) is missing |
| H22 | VERIFIED | `csrf.rs:260-271`; `a_wildcard_listener_accepts_its_own_authority` fails with the old origin. Note: `Sec-Fetch-Site: same-site` is also accepted |
| M6 | VERIFIED | `modules.rs:216-245`, `module.rs` `secret_pointers`; `a_read_token_never_sees_a_rendered_file` fails without `blank_plan`. No module overrides `secret_pointers` (heuristic only) |
| M9 | VERIFIED | `users.rs:506`; `totp_counter_cannot_be_reused_or_go_backwards` fails without the check |
| M10 | PARTIAL | No audit for RateLimited is pinned. The 16 MiB rotation (`audit.rs:203-208`) has no test |
| L-WEB9 | VERIFIED | `tls.rs:786`, `:874-904`; `a_mismatched_stored_acme_pair_falls_back_to_bootstrap` |
| L-WEB10 | VERIFIED | `tls.rs:81-86`; `an_expiring_bootstrap_pair_is_regenerated` |
| L-WEB11 | VERIFIED | `users.rs:445-448`; `successful_verification_rehashes_at_the_current_cost_without_clearing_the_flag` |
| L-WEB12 | PARTIAL | The cap is 4, not 2; logins queue instead of 503 `web-auth-busy` (id missing); test `logins_beyond_the_hashing_cap_are_refused_not_queued` absent |
| L-WEB13 | PARTIAL | No 10-minute in-process guard for a failed live check; test `a_second_uncached_check_does_not_reach_the_network` absent |
| L-WEB14 | PARTIAL | `the_router_answers_exactly_the_table` checks one direction only; auth routes are not compared with the router |
| L-WEB15 | PARTIAL | No `tls12` in the tree today, but the CI step (`cargo tree -e features -i rustls` fails on `tls12`) is missing |
| L-WEB16 | **REOPEN** | `spawn_sweeper` starts only if a Tokio runtime exists (`state.rs:81`). `serve` calls `AuthState::open` (`serve.rs:433`) before it builds the runtime (`:447`), so the sweeper never runs in production. Fix: start it after the runtime exists; add a serve-level test |
| L-WEB17 | VERIFIED | `csrf.rs:236-239`, `extract.rs:100-107`; both tests fail with `.get(COOKIE)` |
| L-FE3 | VERIFIED | `api:check` exits 1 when `schema.d.ts` JSDoc is edited |

**Group A (platform) — checked at `9bdcc65`. No negative checks ran:** the reviewer's permission classifier refused the worktree mutations, so "VERIFIED" items are VERIFIED-NO-NEG. Tests at HEAD pass: platform lib 131 (filtered), `sandbox::linux::tests` 9 as root, `privsep_e2e` 22.

| Item | Verdict | Evidence / what is missing |
|---|---|---|
| C1-a | VERIFIED-NO-NEG | `monitor.rs:1566` nlink, `:1590-1594` parent uid / mode; `read_staged_verified_refuses_a_hard_linked_image` (unit-level; no dispatch-level test) |
| C1-b | PARTIAL | Copy-from-worker-tree, not chunked `StageUpdate` (owner still to confirm, §12). Read-only findings: the source open has no `O_NONBLOCK` / regular-file check (a planted FIFO blocks the monitor and its deadline enforcement); `O_NOFOLLOW` guards the last component only (`update/staged` → `/etc` symlink lets the worker learn sizes and SHA-256 of root-readable files via the length check and `Conflict`); the bundle is opened with a symlink-following `File::open`; a failed verify leaves the `O_EXCL` file behind, so a retry fails until reboot |
| C1-c | VERIFIED-NO-NEG | `monitor.rs:593-647`; wrong-identity / missing-bundle / embedded-roots / valid-release tests; no HTTP/TLS stack in `detent-platform` (only as good as H17) |
| C1-d | VERIFIED-NO-NEG (weak) | `O_EXCL` 0o700, file + dir fsync. The test puts a directory at the temp name, which fails without EXCL too, so it is likely vacuous for EXCL. A failed dir `open` skips fsync silently |
| H1 | VERIFIED-NO-NEG | `serve_locked`, `rollback_pending_on_exit`, CLI recovery; 3 tests. `lock_state` falls back to a `/dev/null` lock on EACCES (no mutual exclusion then) |
| H2 | VERIFIED-NO-NEG | `engine.rs:571-630`; 4 tests. If `arm_commit` fails after the write, no rollback |
| H4 | PARTIAL | Replay on request is pinned (`rollback_replays_the_service_after_restoring_files`). Replay on deadline expiry, on monitor exit and in `recover_pending` has no test that records the call; `an_expired_commit_replays_the_service_action` is absent |
| H6 | **REOPEN** | The monitor survives a spawn, but **the seccomp filter is inherited across execve**: a probe running `uname`, `id`, `sh -c`, `findmnt --verify`, `systemctl show`/`--version` under the confined monitor saw each killed (SIGSYS; syscalls 63, 107, 102, 157). `MONITOR` also lacks `socket`/`connect`, which systemctl needs. So **every real validator and service action under a confined `serve` fails**, and apply fails closed for every module with checks. Fix: allow-list what the children need, or install a separate child filter before exec; extend the test beyond `/bin/true` to `findmnt` and `systemctl --version`. The a010 strace step stays blocked |
| H12 | VERIFIED-NO-NEG | `mcp.rs:69-78`; `http_transport_refused_for_root`. Gated on euid only, not on capabilities |
| H23 | **REOPEN** | The deny-list is bypassed (probe): samba `rootpreexec`, `root  preexec`, `root_preexec` (a full `WriteTarget` wrote `rootpreexec = /bin/sh` to disk); changing an existing directive's value (counts, not values, are compared); ifupdown indented `    up …` (no trim before split), `up … x=1` (`=` in the key), `post-up`/`pre-down` missing, `$(…)` inside `up ip route add`; unbound `include:/x` (no space); Kea `hooks-libraries` and unbound `dynlib-file:` not covered. Fix: normalise names as each daemon does, trim before split, compare values, add the missing hooks, one regression test per bypass |
| M1 | VERIFIED-NO-NEG | `caps_that_do_not_drop_are_fatal_only_when_required`. The worker's after-`setuid` branch reports `Applied` with its bounding set still full (untested) |
| M2 | PARTIAL | Startup notes and warning work. `state/confinement.json` is read by nothing; both roles write the same file; the root monitor writes it with a symlink-following `std::fs::write` inside the worker-owned state root. Fix: one file per role, no-follow writes, doctor reads it |
| M11 | VERIFIED-NO-NEG | `mcp.rs:87-94`; `bind_table_keeps_bearer_on_loopback`, `http_config_enforces_origin_validation` |
| L-PLAT6 | VERIFIED-NO-NEG | `checks.rs:96-101`; `stdout_pattern_requires_literal_match_and_exit_zero` |
| L-PLAT7 | VERIFIED-NO-NEG | `monitor.rs:901` staging dir; `run_check_places_the_candidate_in_monitor_staging`. Plain `create_dir_all` with no trust check (unsafe in capability-user mode, C1-f) |
| L-PLAT8 | VERIFIED | Doc-only; `proto.rs:296-302` |
| L-BIN16 | VERIFIED-NO-NEG | `spawn.rs` child arm aborts; two tests |

**Group D (update, ACME).** Tests at HEAD pass: detent-update 64 + 3 + 1 + 18; detent-acme 66.

| Item | Verdict | Evidence / what is missing |
|---|---|---|
| H17 | PARTIAL | Steps: 1 **missing** (`release.yml:140` still ships a cosign messageSignature bundle; `dsse_envelope` is required, so the shipped file fails `bundle::parse`); 2 present, **untested** (disabling the `verificationMaterial.certificate` fallback keeps tests green); 3 present; 4 **missing** (the leaf hashes the whole entry, not `0x00‖body`; no SET); 5 **missing** (checkpoint size `>=` not `==`, compares base64(sha256(root)), no 4-byte keyhint); 6 partial (unknown kinds fall into hashedrekord; the real `publicKey` is an object); 7 **missing** (trust files are placeholders, no Fulcio intermediate); 8 **missing** (no captured real bundle) |
| H18 | VERIFIED | `fetch.rs:291-336`; `follows_302`, `refuses_redirect_to_http`, `caps_redirect_loop` fail without the 3xx branch |
| M14 | VERIFIED | `policy.rs:136-141`; `marker_embedded_in_sentence_does_not_bypass` fails with `.contains`. Residual: `update.rs:204` still sets `CheckReport.security` with `.contains` |
| M15 | VERIFIED | `schedule.rs:67-70`; three tests fail with the old 66/90 logic |
| M17 | VERIFIED-NO-NEG | fsync present; no unit test possible. The dir fsync is best-effort (`let _ =`), not the propagating `?` the Fix asked for |
| M18 | PARTIAL | Code correct (`order.rs:93-160`), but **`present_failure_withdraws_presented` is vacuous** (removing every cleanup call keeps it green; it never calls `present_challenges`). Needs a test that fails on the 2nd record and asserts the 1st was deleted |
| M19 | VERIFIED | `acme_attest_is_not_advertised_without_an_attestor` fails when the id is put back |
| L-SUP10 | PARTIAL | Refusal pinned (`serve.rs:309-316`). `SECURITY_HARDENING.md` contradicts itself (l.45 "implemented…exercised by Pebble" vs l.233 "empty crate"); neither says issuance has no production caller |
| L-SUP11 | VERIFIED | `issued_debug_redacts_private_key` |
| L-SUP12 | PARTIAL | Sort present (`policy.rs:88-96`) but **the test is vacuous** (input already newest-first). Use `[v0.0.3 (later), v0.1.0]`, expect `v0.1.0` |
| L-SUP14 | VERIFIED-NO-NEG | `install.rs:48,78` `sync_directory` propagates; no unit test possible |
| L-SUP15 | VERIFIED-NO-NEG | https-only everywhere; `acme_dns_rejects_plain_http`. The negative run was blocked by the reviewer's permission classifier |
| L-SUP16 | VERIFIED | `desec_derives_subnames_and_replaces_wholesale` fails with unquoted rdata / ttl 60. Fixtures still hand-written |
| L-SUP17 | VERIFIED | `http_request_debug_redacts_header_values` |
| L-SUP18 | VERIFIED-NO-NEG | Pebble and challtestsrv pinned `@sha256:` (both manifests return 200); the live test returns `Err` without `PEBBLE_URL` |
| L-ORC2 | VERIFIED-NO-NEG | Explicit aws_lc_rs provider in `health.rs:67-96`; no global install left |

**Group E (CLI, MCP, FFI).** All 17 FFI tests pass.

| Item | Verdict | Evidence / what is missing |
|---|---|---|
| H11 | VERIFIED | `main.rs:93-95`; `mcp_stdio_answers_initialize` deadlocks with `.lock()` restored |
| M12 | VERIFIED | `run.rs:169` `init_tracing`; `mcp_refused_startup_writes_nothing_to_stdout` fails without it |
| M13 | VERIFIED-NO-NEG | Doc path: `FFI.md:112-116` + deny lints; `hostile_inputs_never_panic_and_report_errors` |
| L-BIN11 | VERIFIED | `check_utf8` `isize::MAX` guard; `oversized_length_is_refused` aborts (UB) without it |
| L-BIN12 | VERIFIED-NO-NEG | error code on every NULL path; 4 tests |
| L-BIN13 | VERIFIED-NO-NEG | `align_of::<AllocHeader>()` + const asserts (no 32-bit run) |
| L-BIN14 | VERIFIED | `doctor.rs:172-211`; `doctor_refuses_symlink_targets` fails with plain `metadata` |
| L-BIN15 | VERIFIED | `webadmin.rs:322-333`; `token_create_rejects_expiry_overflow_without_writing` fails with `wrapping_add` |
| L-BIN17 | PARTIAL | Still open: `main.rs:155` English scanner stops at the first `#[cfg(test)]`; `run.rs` `commit_rollback_surfaces_whatever_the_operations_layer_says` keeps its weak assertion |
| L-BIN18 | VERIFIED-NO-NEG | Zeroizing chunk read; one un-zeroized `String` copy remains (`webadmin.rs:667-671`) |
| L-BIN19 | PARTIAL | `ConstantTimeTokenVerifier::from_digests` (`detent-mcp/src/mcp.rs:100`) is public dead code; gate with `#[cfg(test)]` or delete |
| L-ORC1 | VERIFIED | Comment removed |
