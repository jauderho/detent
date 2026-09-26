# STAGE3 — Remaining items

Rewritten 2026-09-26 at `08e08fa`. The full review text, every closed item and
the audit history (§1–§11.10) are in git: `git show 08e08fa:docs/STAGE3.md`.
Closed items with their commits and tests are in that file's §11.10 and in
`docs/PROGRESS.md`.

This file keeps only what is **still open**. It is the work order for the
owner's local setup, which has access to **a010**. Items are grouped by where
the work must be done (grouping by Jev, checked by the orchestrator).
`docs/ARCHITECTURE.md` explains how the parts fit together.

---

## 00. Rules — binding on everyone who works an item here

### 00.1 Scope
- Do only the items in this file, one item per commit.
- `DECISION` items: build the non-decision parts; the decision itself waits for
  the owner's answer in §5.

### 00.2 The loop
1. Read the item. **Re-locate every cited line at HEAD**; line numbers move.
2. **Test first.** Write the named test (or one with the same assertion), run
   it, and see it **fail**. Paste the failing line into the commit body.
3. Make the smallest fix. Touch only the files the item needs, plus tests,
   Fluent ids and the docs the item says to correct. If a control in
   `docs/SECURITY_HARDENING.md` changes, update its row in the same commit.
4. Gates on the whole workspace, `--all-features`: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
   `cargo test --workspace --all-features`. For `web/`: `bun test`, `tsc -b`,
   `bun run api:check`, biome. If you touch `sandbox/`, `privsep/`, seccomp,
   Landlock or caps, also run the Linux check on a010 (§00.4).
5. Commit with `git commit -S -s`, this body:
   ```
   <imperative ASD-STE100 subject, ≤72 chars> (<ITEM-ID>)

   Item: <ITEM-ID>
   Test: <test name(s)> — failed before fix: yes (<one-line failure>)
   Gates: fmt=0 clippy=0 test=0 (<N> passed) [web=0]
   Linux: a010 <binary + exact command> -> <result>   |   n/a
   Allows added: none
   ```
6. Remove the item from this file in the same commit (or mark the part that
   is done), and add one line to `docs/PROGRESS.md`.

### 00.3 Hard prohibitions
- More than one item id per commit.
- New lint suppressions (`#[allow]`, `#[expect]`, `#[ignore]`, `biome-ignore`,
  `eslint-disable`, `@ts-*`). The count is **111** at `08e08fa`
  (`git grep -c -E '#!?\[(allow|expect)\(' HEAD -- crates | awk -F: '{s+=$NF}END{print s}'`)
  and may only go down.
- Weakened checks: lower coverage floors, relaxed or deleted assertions, tests
  that skip themselves, `|| true` or `continue-on-error` in CI.
- Invented versions, tags or digests. Resolve them first and paste the proof.
  New dependencies follow ADR-011 (7-day cooldown, `deny.toml`).
- History rewriting on pushed commits.
- Claims without evidence: "done", "green" and "clean" need the command and
  its exit code in the commit body. A macOS run is not Linux evidence.

### 00.4 a010 — test there, never compile there
a010: Ubuntu (development release), x86_64, kernel 7.3, Landlock present,
`fs.protected_hardlinks=1`, passwordless sudo, 2 CPUs, 3 GB RAM.

- **Build locally, copy binaries up.** Product binary:
  `cargo zigbuild --release --target x86_64-unknown-linux-musl -p detent --all-features`.
  Test binaries for a crate:
  `cargo zigbuild --target x86_64-unknown-linux-musl -p detent-platform --all-features --tests --no-run --message-format=json | jq -r 'select(.profile.test == true) | .executable'`.
- Copy to `a010:~/detent-test/<short-sha>/` and run there. Root sandbox and
  privsep tests: `sudo ./detent_platform-<hash> sandbox:: --test-threads=1`.
- Never `cargo`, `bun` or edit files on a010. Delete old
  `~/detent-test/<sha>/` directories when done.
- Runtime packages allowed on a010 (record each command in PROGRESS.md):
  `strace samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server` (chrony and
  netplan are present). No compilers. Do not change network config, users,
  firewall, sysctls or kernel parameters. Start a daemon only for the one
  test that needs it, then stop it.
- **aarch64:** no host. For seccomp changes, run
  `cargo check --target aarch64-unknown-linux-gnu -p detent-platform` and pin
  the aarch64 syscall numbers in a unit test. Say "aarch64 runtime unverified".

---

## 1. On a010 (real sandbox, real daemons)

### A1. H6 — trace a confined `serve`, then shrink the monitor filter
Since `73e7c88` the monitor does not start programs itself: validators and
service actions run in the unconfined **runner** (`privsep/runner.rs`,
forked before confinement; `docs/ARCHITECTURE.md` §3.1, §5.3). The monitor
seccomp table (`sandbox/seccomp.rs` `MONITOR`) still lists `clone`, `clone3`,
`execve`, `execveat`, `pipe2`, `dup3`, `kill` and friends from the old design.
1. On a010, run a confined `detent serve` under `strace -f -o /tmp/mon.trace`
   (install and configure one module whose validator exists, e.g. chrony).
   Drive one real `plan` (runs `chronyd -p` through the runner) and one
   `systemctl restart` through the API.
2. Confirm the validator and `systemctl` ran in the runner's process tree,
   with no `SIGSYS` anywhere, and list the syscalls the **monitor** pid used.
3. Remove from `MONITOR` every process-creation syscall the monitor no longer
   uses. Keep `KillProcess`. Update the derivation comment in `seccomp.rs`.
- Tests: `enforce_mode_monitor_runs_real_validators_through_the_runner`
  (exists) stays green; replace `enforce_mode_monitor_can_spawn_a_validator`
  with a test that a confined monitor is killed by `SIGSYS` when it calls
  `execve` itself (the new, narrower contract).
- Also record in SECURITY_HARDENING (runner row, "Residual") that the trace
  was done, with the date and kernel.

### A2. H6 — full confined `serve` end to end
A complete `detent serve` run as root on a010 with the packaged units
(`packaging/`): login over HTTPS, `plan` and `apply` on one module with a real
validator, a service restart, commit-confirm expiry and rollback, and
shutdown on `SIGTERM`. Record the commands and results in PROGRESS.md. Any
failure becomes its own item here.

### A3. Group A negative checks (never run)
The §11.9 verification of these platform items could not prove that each test
fails without its fix (VERIFIED-NO-NEG). For each: in a throwaway worktree
with its **own** target dir, remove the fix, run the pinning test (on a010 as
root for the sandbox ones), quote the failing line, and record it in
PROGRESS.md. If a test does not fail, that item's test is vacuous: write a
real one (test first) in its own commit.

| Item | Pinning test(s) | Needs a010 |
|---|---|---|
| C1-a | `read_staged_verified_refuses_a_hard_linked_image` (also add a dispatch-level test) | no |
| C1-c | the wrong-identity / missing-bundle / embedded-roots / valid-release tests in `monitor.rs` | no |
| H1 | `serve_locked`, `rollback_pending_on_exit`, CLI recovery tests | no |
| H2 | the 4 commit-confirm arming tests in `crates/detent-ops/src/engine.rs` | no |
| H12 | `http_transport_refused_for_root` (`crates/detent/src/mcp.rs`) | no |
| M1 | `caps_that_do_not_drop_are_fatal_only_when_required` | yes (as root, `--test-threads=1`) |
| M11 | `bind_table_keeps_bearer_on_loopback`, `http_config_enforces_origin_validation` | no |
| L-PLAT6 | `stdout_pattern_requires_literal_match_and_exit_zero` | no |
| L-PLAT7 | `run_check_places_the_candidate_in_monitor_staging` | no |
| L-BIN16 | the two `spawn.rs` child-abort tests | no |

### A4. M1 — the worker's capability report after `setuid`
`sandbox/linux.rs` `drop_capabilities`: for the worker (`require_caps: false`)
with empty effective and permitted sets it returns `Outcome::Applied` while
the **bounding** set is still full. After `setuid` to a non-root uid the full
bounding set cannot be regained without an exec of a setuid binary, which
`no_new_privs` blocks, so the risk is low — but the report is not true.
- Fix: report the real state (a distinct outcome, or drop the bounding set
  before the uid change in `spawn.rs` `become_worker` if the kernel allows it).
- Test on a010 as root: spawn a worker with an unprivileged account and assert
  what `/proc/self/status` `CapBnd` shows against the reported outcome.

---

## 2. Code items (any dev machine)

### B1. H17 step 5 — parse the Rekor checkpoint as a signed note
`crates/detent-update/src/verify.rs` step 6 checks the checkpoint loosely
(tree size `>=`, no note parsing). A Rekor checkpoint is a signed note:
`origin\nsize\nbase64(root)\n\n— <name> <base64(keyhint(4) || sig)>`.
- Fix: parse the body lines; require size **equal** to the proof's
  `tree_size`; compare the decoded root with the computed root; verify the
  signature (4-byte key hint = first 4 bytes of SHA-256 of the key's
  `name\n0x01 || SPKI` per the note spec; check the one Rekor uses) over the
  body plus `"\n"` with the embedded Rekor key.
- Tests: the real staging checkpoint in the source of
  `tests/fixtures/rekor-staging-proof.json` verifies; a wrong size, a wrong
  root and a wrong signature each refuse.

### B2. H17 step 6 — refuse unknown entry kinds
Entries whose kind is neither `hashedrekord` nor `dsse` fall through to the
hashedrekord body check. Branch on the kind and refuse any other.
- Test: a fixture with `"kind":"rekord"` (or `intoto`) is refused with a
  distinct error.

### B3. H17 step 7 — real trust roots
`crates/detent-update/src/trust.rs` embeds placeholder trust files and no
Fulcio intermediate. Embed the real Fulcio root **and** intermediate and the
real Rekor key (from the Sigstore TUF root; paste the source and digests in
the commit body). PLAN §9 wants these from TUF later; keep a comment.
- Test: a chain from a real Fulcio leaf (from the captured bundle in R1,
  or the sigstore-go example bundle already used for the SET test) builds to
  the embedded root.

### B4. C1-b — the bundle open and the leftover copy
In `privsep/monitor.rs` (`ReplaceBinary` path):
- The bundle `<tag>.sigstore.json` is read with a symlink-following open
  (`read_bounded_file`). Open it the way `open_staged_input` opens the binary:
  `openat` down from `state_root` with `O_NOFOLLOW|O_DIRECTORY` per component,
  owner check, `O_NONBLOCK|O_NOFOLLOW`, regular-file check.
- A failed verification leaves the materialized `O_EXCL` copy in the staging
  directory. Remove it on every failure path.
- Tests: a symlinked bundle is refused; a FIFO bundle does not block; after a
  failed verify the staging directory holds no copy.

### B5. C1-f — document capability-user mode
In capability-user mode (`packaging/…/capability-user.conf`, `User=detent`)
the monitor and worker share uid `detent`, so staging ownership checks
separate nothing. The barriers are Landlock (absent on some hosts) and the
Sigstore check. Write this in ADR-001 and in SECURITY_HARDENING (Gaps). No
code change.

### B6. H1 — the state lock fallback
`Monitor::lock` / `lock_state` falls back to a `/dev/null` lock on `EACCES`,
so two monitors then share no mutual exclusion. Refuse to start instead (or
use a lock path that is always writable by the monitor), with a clear error.
- Test: a state root whose lock file cannot be created refuses the lock.

### B7. H2 — arming failure after the write
`crates/detent-ops/src/engine.rs`: if arming the commit-confirm timer fails
after `WriteTarget` succeeded, nothing rolls the write back. Roll back (or
arm before the write, as H2's original fix asked) so a commit-confirm module
never keeps an unguarded change.
- Test: a fake monitor that fails `StartConfirmTimer` after a successful write;
  assert the target is restored and the error is reported.

### B8. H12 — gate the MCP HTTP transport on capabilities
`crates/detent/src/mcp.rs` refuses `--transport http` only when euid is 0.
A non-root process that still holds capabilities (e.g. `CAP_DAC_OVERRIDE`)
passes. Also refuse when the effective or permitted capability set is not
empty.
- Test: the refusal check with a non-empty capability set (inject the reader).

### B9. L-PLAT7 — trust the staging directory
The monitor creates its staging directory with plain `create_dir_all` and no
trust check. Create it `0700`, then verify owner = monitor euid and no
group/other write, refusing otherwise (as `materialize_staged` does).
- Test: a staging directory with mode `0777` or another owner is refused.

### B10. L-BIN18 — the last un-zeroised password copy
`crates/detent/src/webadmin.rs` (~667–671) keeps one `String` copy of the
typed password. Keep it in `Zeroizing<String>` (or avoid the copy).
- Test: none possible at runtime; show the type change and that no plain
  `String` of the password remains (`rg` in the commit body).

### B11. Small follow-ups
- `docs/openapi.json` lists no `503` for `POST /api/v1/auth/login`
  (`web-auth-busy`, `web-auth-session-limit`). Add it in the utoipa
  annotation and regenerate (`cargo test -p detent-web api::openapi -- --ignored write_openapi_json`,
  then `cd web && bun run api:generate`).
- An existing `<state>/audit` directory is not changed to `0700`: both
  `detent-ops` `FileAudit` and the web auth sink only create it `0700`. Tighten
  the mode of an existing directory the process owns, and test it.

---

## 3. Release infrastructure

### R1. H17 step 1 and step 8 — real release bundles
- `.github/workflows/release.yml` still ships a cosign messageSignature
  bundle (`cosign sign-blob --bundle`). The verifier accepts the
  `actions/attest` DSSE bundle. Publish that bundle as
  `detent-<triple>.sigstore.json` (DECISION C1-c/H17 default).
- After a real release run, commit one captured bundle as a fixture and add
  `real_attest_bundle_verifies` (`tests/verify_fixtures.rs`). Needs a release
  tag (owner).

---

## 4. Moved elsewhere
- **M18** — a real test of `present_challenges` needs the ACME order-flow
  seam: done with STAGE4 §4.3 item 4.
- **M17** — the ACME credential write ignores the directory fsync error
  (`let _ = dir.sync_all()` in `crates/detent-acme/src/lib.rs` and
  `order.rs`): done with STAGE4 §4.3 (Phase 6 works in that crate).

---

## 5. Owner decisions (answer here)

Format: `- <ITEM>: <question> — proposed: <default> — owner answer:`

- H5: apply refuses when a declared validator cannot run (binary missing), not
  only when it runs and fails. — proposed: keep fail-closed — owner answer:
- M5: `plan` runs root validators but needs only read scope. — proposed: keep
  read scope (plan writes nothing; validators get a staged copy) — owner answer:
- C1-b: chunked `StageUpdate` so the worker never writes the update bytes to a
  path the monitor reads. The interim (`4b098d0`, `95f6b01`) copies from the
  worker tree into monitor staging `/run/detent/staging` (root, 0700) with
  no-follow opens and owner checks. — proposed: confirm the interim, defer
  chunking — owner answer:
- D4: remove build toolchains from a010 (`rustup`, `~/.bun`, `cargo-llvm-cov`,
  `cargo-fuzz`, `build-essential clang lld`). You said "do not remove packages
  on a010 for now". — proposed: do it once A1–A3 are done — owner answer:
- libbz2 on a010: `libbz2-1.0` was downgraded to `1.0.8-6build2` with
  `--allow-downgrades` by an earlier agent. — proposed: restore the distro
  version — owner answer:
