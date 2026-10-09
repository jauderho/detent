# PROGRESS

A running handoff log, so another agent can pick the work up cold.
[`PLAN.md`](PLAN.md) is the roadmap and does not change as work lands; **this
file is the rolling state**. Append a dated entry at the top of the log when a
phase or a self-contained piece of work finishes.

## 2026-10-09 - Track F: semver, geiger and mutants jobs in CI

Three jobs, one commit each. `core-semver` (`ci.yml`): `cargo semver-checks check-release -p detent-core --baseline-rev origin/main`, same tool pin (0.50.0) as `ffi-semver`; `detent-core` is `publish = false`, so it needs the git baseline. `unsafe-report` (`ci.yml`): `cargo geiger 0.13.0 --all-features` on the `detent` crate; `continue-on-error`, uploads `geiger-detent` and writes the totals to the step summary. `taiki-e/install-action` has no cargo-geiger manifest, so the job runs `cargo install --locked --features vendored-openssl`; cargo-geiger needs an absolute `--manifest-path`, so the step runs inside `crates/detent`, and it exits 1 whenever it prints scan warnings (104 locally), so the exit code is recorded, not enforced. `mutants.yml`: weekly (Sunday 04:41 UTC) and `workflow_dispatch`; `cargo-mutants 27.1.0`, `--all-features --timeout-multiplier 3`, `detent-core` (239 mutants) in one shard and `detent-update` (616) in three; exit codes 2 and 3 (missed, timeout) pass, others fail; uploads `mutants.out` for 30 days. All three new jobs use harden-runner in audit mode, like every other job in this repository; no workflow here has a measured egress list yet. Local proof (macOS, tools in a temporary root, since removed): semver-checks on `detent-core` passed (196 checks, no update required); geiger printed the tree and totals `258/899` functions in use; mutants on `align.rs` tested 42 mutants (36 caught, 2 missed, 3 unviable, 1 timeout). actionlint is clean on the changed files apart from the old-label and `ubuntu-26.04` noise and existing shellcheck notes. **Unproven until a CI run:** all three jobs on the Linux runner, the geiger build time, and the mutants run time against the 300-minute limit.

## 2026-10-09 - E16: fixes F1 to F3 proven on the test host

Build: commit `11e2716` with the workspace version set to `0.1.0` in a scratch worktree (never committed); x86_64 musl zigbuild `--features ui`; installed with `packaging/install.sh` (root-confined, shipped unit) on the Ubuntu x86_64 test host; `[listen] addr = "127.0.0.1:3333"`, `[update] min_age_days = 1` (owner-approved for test devices); admin from `detent setup`; a one-hour write token from `detent token create`. All items passed. (1) F3: before any check, `GET /api/v1/system/update` answered 404 `web-update-not-checked` in 0.045 s (the old 5 s wait is gone); no `update/` directory existed. (2) F2: `sudo detent update --check` printed `update available: v0.1.1`; `check.json` was `644 root:root`; the GET answered 200 `{"update_available":true,"current":"0.1.0","tag":"v0.1.1",...}` in 0.046 s, `current` is the running version. (3) F1: `v1.0.0;id` answered 400 `ops-update-tag-invalid`; `v0.1.0` and `v0.0.2` answered 409 `ops-update-not-newer`; no `detent-update` unit was loaded and the journal had no entry for it. (4) 202 path: `{"version":"v0.1.1"}` answered 202 in 0.046 s; the unit logged `installed v0.1.1; the binary it replaced is kept at /usr/local/bin/detent.prev`; `detent --version` was `detent 0.1.1`, `/healthz` 200, `NRestarts=0`, the binary SHA-256 `e9de9f26...` equals the v0.1.1 `SHA256SUMS` x86_64 musl line, and the unit was gone after. (5) After the install, `update/` was empty (`check.json` removed). The GET, now served by the v0.1.1 binary, answered 503 `web-update-check-failed` after 5.0 s: v0.1.1 predates F3 and still does a live check that the worker cannot make. This is the old behavior, not a fault of this change. (6) `bad.json` never existed. Cleanup: uninstalled, `detent.prev`, `/etc/detent`, `/run/detent` and the scratch files removed, no `detent` or `detent-update` unit file left (systemd still lists a not-found `detent.service` entry until the next boot), `/var/lib/detent` holds only `monitor.lock`, user `detent` kept. Not verified: the Dashboard text on the confined worker (API only), rollback through the web path, and a released build that contains F1 to F3 (none exists yet).

## 2026-10-09 - E16: three faults from the testhost run fixed

One signed commit each, test first. **F1** (`c5c0216`): `Engine::update_apply` checks the tag before the privsep call with `proto::check_update_tag` (release tag, then strictly newer than the running version; the monitor uses the same helper and still refuses). A bad tag is 400 `ops-update-tag-invalid`, a tag not newer is 409 `ops-update-not-newer` (was 500 `ops-privsep-failed`). **F2** (`175ae39`): `cache::write_atomic` sets `0644` on the temp file (unix), so `check.json` and `bad.json` are readable by the worker; a kept install (`Healthy`, `NotAService`) removes `check.json`. **F3** (`7caaef4`): the GET serves only the stamp (any age); no stamp is 404 `web-update-not-checked` at once. 404 keeps the response schema unchanged and the Dashboard already shows the error id in its amber banner; a 200 with a new field would need a new schema and UI. `current` is the running version (`CARGO_PKG_VERSION`); `update_available` is the stamp's offer, its tag newer than the running version, and not in `bad.json`. Removed as unused in production: `update_report`, `guarded_live_check`, `FAILED_CHECK_BACKOFF`, `update_check_failed`, the id `web-update-check-failed`, `AppState::update_check`, their tests; `SECURITY_HARDENING` row and `API.md` updated. No seccomp, Landlock, capability or unit-file change. macOS checks: fmt, clippy, `cargo test --workspace --all-features`, web lint, typecheck, test (481), i18n:check, api:check, feature sets A, B and default; lint suppressions 110. **Unproven until an testhost run:** the 400/409 answers and the unchanged 202 path on the real host; `check.json` mode `0644` and its removal after a web install under the packaged unit; the 404 and the Dashboard text on the confined worker. Note: without a stamp the Dashboard shows "no update check has run" until `sudo detent update --check` runs (no timer ships in the package; the message says to run it).

## 2026-10-09 - E16 follow-up: the monitor loses the binary-directory write rule and `linkat`

Owner answer 2026-10-08 (BUGFIX §4 E16): remove both. `eb1b959`: `Policy::monitor` no longer adds the directory of the running binary to the Landlock write set. `e828996`: `linkat` leaves `MONITOR` and `SYSCALL_NUMBERS`; no table lists it. Both grants served only the monitor's retired binary swap. Checked: no monitor code path links a file (`fs::atomic` and the monitor use `openat`, `renameat`, `unlinkat`; `tempfile::Builder::tempfile_in` creates with `O_EXCL`, and the monitor never calls `persist`); `std::fs::hard_link` and `persist` exist only in `detent-update` (`install::swap`, the cache and stamp writers), which runs in the CLI `detent update` and the worker, not in the monitor; `scripts/` and the unit file name neither. `detent update` runs in the transient unit that `StartUpdate` starts, unconfined, so it does not need the Landlock rule. `protected_paths` in `privsep/mounts.rs` still uses the binary directory to refuse mounts over it: that is not a Landlock grant and stays. New tests: `no_policy_grants_a_write_on_the_binary_directory` (`sandbox/mod.rs`), `no_table_allows_linkat` (`sandbox/seccomp.rs`); `an_empty_allowlist_still_yields_a_policy_rooted_at_the_state_root` no longer expects the binary directory. Both new tests failed before the change (`Monitor allows linkat`; `"…/target/debug/deps" is writable`). Unproven until CI or testhost: the root `enforce_mode_*` tests under the narrower policy.

## 2026-10-08 - E16 proven on testhost: web install through `systemd-run`

Start build: HEAD `6043d54` with the workspace version set to `0.1.0` in a scratch worktree (never committed), x86_64 musl zigbuild `--features ui`, installed with `packaging/install.sh` (root-confined, shipped unit), `[listen] addr = "127.0.0.1:3333"`, `[update] min_age_days = 1` (owner-approved for test devices), a write token from `detent token create`. Proven: (1) the runner starts `detent-update.service` under the packaged unit: `ExecStart=/usr/local/bin/detent update --tag v0.1.1`, `User=` root, no sandbox error. (2) `POST /api/v1/system/update {"version":"v0.1.1"}` → 202 `{"version":"v0.1.1"}` in 54 ms; the unit logged `installed v0.1.1; the binary it replaced is kept at /usr/local/bin/detent.prev` 4 s later; `detent.service` restarted (`NRestarts=0`, active), `/healthz` 200, `detent --version` = `detent 0.1.1`, SHA-256 `e9de9f26…` equal to the release `SHA256SUMS`; the unit is gone after (`--collect`). (3) A second POST 80 ms after the first → 409 `ops-update-running`; with a blocker unit (`systemd-run --unit=detent-update --collect /bin/sleep 60`) the POST → 409 and the blocker keeps its argv. systemd 261 stderr for the duplicate: `Failed to start transient service unit: Unit detent-update.service was already loaded or has a fragment file.` (exit 1). Faults found, not fixed: (4) `GET /api/v1/system/update` answers 503 `web-update-check-failed` on the confined host whenever the worker cannot read `update/check.json`. Cause 1: the live check runs in the worker, and `WORKER` (seccomp) has no `connect`, `poll` or `recvmsg`; strace shows musl's resolver `poll` → `EPERM` (seccomp table change, owner decision). Cause 2: `sudo detent update --check` writes `check.json` `0600 root:root` (`tempfile` default in `cache::write_atomic`; its doc says `0644`-alike), so the worker cannot read it; with the file set to `0644` by hand the GET answered 200. Also: the stamp is not cleared after an install, so the GET still said `current 0.1.0`, `update_available: true` for `v0.1.1` after the install. (5) A bad tag (`v1.0.0;id`, `../x`, `v0.1.1+meta`) and a tag not newer (`v0.1.0`, `v0.0.2`) are refused and start no unit, but the answer is 500 `ops-privsep-failed`, not a 4xx: the monitor answers `ProtoError::Io`, which the engine maps to `ops-privsep-failed`. On stop: `the web server did not stop cleanly: privsep channel failed` (unit result success). testhost after: detent uninstalled, `/etc/detent` and `detent.prev` removed, no `detent-update` unit, `/var/lib/detent` holds only `monitor.lock` (root:root 0755); user `detent` kept.

## 2026-10-08 - E15: flaky coverage merge fixed at its cause

`0f46c0a`. Run 37590569498 attempt 1 failed at `cargo llvm-cov report` with `detent-6056-9836909355392981305_0.profraw: invalid instrumentation profile data (file header is corrupt)`. Cause: a test killed an instrumented child while it wrote its profile. The pid and the hash say which process: pid 6056 is lower than pid 7337 (the `detent_platform` unit-test binary, started 08:00:35), so it ran before the root sandbox step; the hash differs from the `detent` unit-test binary (pid 5446), so it is the spawned `detent` binary, which only `tests/binary.rs` starts. `mcp_stdio_answers_initialize` closed the child's stdin (the thread drops it after one line) and then `child.kill()` on the reply; the child exits on EOF and writes its profile at exit. The `%p` in `LLVM_PROFILE_FILE` is fixed at start, so a forked child writes the parent's file, merged under `fcntl` locks; that is safe unless a writer dies mid-write. Fix: wait for the exit with a 10 s deadline (kill only then) and assert exit 0 (before the fix this assertion failed 40 of 40 on macOS with `unix_wait_status(9)`; after, 40 of 40 pass). Evidence on testhost (x86_64 musl, `-C instrument-coverage --cfg coverage`, zigbuild; no local Linux repro on macOS): the same two CI lines from `llvm-profdata merge` on a profile truncated by SIGKILL; the test's exact steps against the instrumented `detent mcp`: kill after reply left 1 truncated profile in 900 runs (the rest: no file), wait left 300 of 300 good. Checked and not the cause: the 28 root `sandbox::linux::tests` run 100 times, then 300 times under CPU load, wrote one valid profile each time; every confined child leaves with `exit_immediately_unflushed` and writes nothing. Same race, not observed: `crash_during_write_leaves_original_intact` (`fs_atomic.rs`) SIGKILLs an instrumented child at 1 to 20 ms; 300 kills on testhost left no bad file, so it is left as is. No seccomp, Landlock, capability or unit-file change. Checks (macOS): `cargo fmt --all --check`, clippy `--workspace --all-features --all-targets -D warnings`, `cargo test --workspace --all-features` 2522 passed; lint suppressions 110 before and after. **Unproven until a CI run:** that the coverage job no longer fails on a corrupt profile (the failure was one in many runs).

## 2026-10-07 - E16: web and MCP install start the CLI updater in a transient unit

Owner answer 2026-10-07 (BUGFIX §4 E16): route (a). `e3a6c49`: `detent update --tag <tag>` installs exactly that release; `detent_update::update::prepare` takes `tag: Option<&str>`, and `select_tag` judges the one release with `policy::select` (offered for this build, not in `bad.json`, past `[update] min_age_days`, newer unless `--allow-downgrade`): `NotOffered`, `Rejected`, `NotNewer` or the policy error; `--tag` conflicts with `--check` and `--force`; no prompt, so no non-interactive flag. `d5703b1`: appended `Request::StartUpdate {tag}`, `Response::UpdateStarted {detail}`, `ProtoError::UpdateRunning` (discriminants 17, 17, 13; `PROTO_VERSION` stays 2). Tag rule `proto::is_release_tag`: `v` + semver, optional pre-release, no build metadata, at most 64 bytes, only `[0-9A-Za-z.-]` (no space, `/`, `..`, leading `-`, shell metacharacters). The monitor checks it and refuses a tag not newer than the running version, then asks the runner (`RunnerRequest::StartUpdate`), which checks the tag again; `ServiceControlAdapter::start_update` takes the binary from its own `current_exe` (a ` (deleted)` suffix removed; must be absolute), never from the socket; `SystemdManager::start_update` runs `/usr/bin/systemd-run --unit=detent-update --collect <binary> update --tag <tag>` (`update_unit_args`, 30 s). `--collect` was added to the owner's argv: without it a failed (for example refused) update keeps `detent-update.service` loaded and blocks every later start. stderr naming `detent-update.service` and "already" maps to `UpdateRunning`; other init systems answer `Unsupported` with a note; a build without `update` answers `Unsupported`. In-process `detent mcp` goes through the same request (its monitor thread uses the adapter directly). `d67aa32`: `UpdateApply` sends `StartUpdate`; `OpOutcome::UpdateStarted`; HTTP 202 `UpdateStartedView {version}`, 409 `ops-update-running`, 500 `ops-unsupported`; OpenAPI and `schema.d.ts` regenerated; Dashboard confirm and banner (`dashboard-update-started`), `useApplyUpdate` doc and the MCP tool description say the update starts in the background, the service restarts if it installs and it rolls back if not healthy. Removed as dead: `OpsEngine::set_state_root`, `is_staged_name`. `6e6f1cb`: the monitor answers `StageBegin`, `StageUpdate`, `ReplaceBinary` with `Unsupported`; the C1-b stage, the verifier call, the swap and their tests are gone (about 1 900 lines); `detent-platform` no longer links `detent-update`. Not changed (hard stop): the monitor's Landlock rule for the binary directory and the `MONITOR` row `linkat` are now unused (comments say so; owner question in BUGFIX §4). No seccomp table, Landlock, capability or unit-file change. If the service restart ends the worker before it answers, the web gets an error while the update goes on in the unit; in practice the runner answers when the unit starts and the download comes first. macOS: workspace tests 2504 passed, 6 ignored; clippy (all features; no default features for detent-platform and detent-ops; x86_64 musl via cargo-zigbuild) clean; feature sets A, B, default build; web lint, typecheck, test (481), i18n:check, api:check clean; coverage (macOS, CI-shaped run) all floors met: detent-ops 100%, detent-platform 96.10%, detent-web 97.82%, detent 95.41%; lint suppressions 110. **Unproven until a Linux/testhost run:** `systemd-run` from the runner under the packaged unit (D1 proved `systemctl start` there), the duplicate-unit stderr text, and a full web install (download, restart, `/healthz`, rollback). Open: capability-user mode needs a polkit rule to start the unit (Phase 12, with the D1 mount rule); `GET /api/v1/system/update` 503 without `update/check.json` (inferred, not seen).

## 2026-10-07 - C1-b: update bytes cross the privsep socket

Owner answer 2026-10-06 (BUGFIX §4): chunked transfer now. `7e53356`: the worker no longer gives the monitor a path. Appended `Request::StageBegin {tag, len, sha256, bundle}`, `Request::StageUpdate {offset, chunk}`, `Response::Staged {received}` (discriminants 15, 16, 16; `PROTO_VERSION` stays 2: appended variants only; `ReplaceBinary` keeps its fields and refuses without a stage). Limits in `proto.rs`: image 64 MiB (`MAX_UPDATE_BYTES`, five times the 12 MiB build budget), chunk 512 KiB, bundle 256 KiB. The monitor keeps one stage, `<staging>/update.stage` (`O_CREAT|O_EXCL|O_NOFOLLOW`, `0600`, `ensure_staging_dir`); chunks in order, no gap or overlap, not past the declared length; any refusal discards the stage; a new begin, `Shutdown` and every end of `serve` discard it; a start with the state lock removes a leftover (without the lock it is left alone). `ReplaceBinary` needs a complete stage with the same tag, length and digest, reads it back with `read_staged_verified`, verifies the bundle from the stage (C1-c), and keeps the downgrade check (C1-e, now also at begin). Removed: `materialize_staged`, `open_staged_input`, `staged_input_path`, `STAGED_DIR`, `read_bounded_file` and their tests. Engine: `UpdateApply` reads the worker's own `<state_root>/update/staged/<tag>` and `<tag>.sigstore.json` and sends them with `Client::stage_update`; a missing bundle is `ops-unsupported`. No seccomp, capability or unit-file change (`openat`, `write`, `fsync`, `unlinkat` are in `MONITOR`). Failed first: `replace_binary_never_reads_the_worker_staged_directory` (the old monitor answered `Replaced`). macOS: workspace tests 2522 passed; clippy (all features, no default features for detent-platform and detent-ops, x86_64 musl zigbuild) clean; lint suppressions 110; coverage lines detent-platform 94.85% (before 94.67%), detent-ops 99.77% (engine.rs and op.rs 100%; the 6 lines in `audit.rs` were uncovered before). **Unproven until a Linux run:** `enforce_mode_monitor_swaps_a_verified_release` and `enforce_mode_monitor_removes_the_stage_of_a_refused_release` (root; the stage under the real Landlock and seccomp). Found, not fixed: nothing in production writes `<state_root>/update/staged`; only tests plant it, so the web and MCP `UpdateApply` can install only what an operator put there.

## 2026-10-07 - D1 mounts proven on testhost; three pre-existing faults fixed

`scripts/mounts-activation-check.sh` passes on testhost (systemd 261) with the packaged unit and `[mounts] activate_new_entries = true`: unit names equal `systemd-escape`; tmpfs entry mounted, `x-systemd.automount` entry gives an active `.automount`, `noauto` not started; rollback restores `/etc/fstab`, stops only the started units, earlier mounts untouched; confirm keeps the mount; NFS to an unreachable server is reported `pending` in 10 s; flag off mounts nothing. The run found three faults that the Track C A2 run (chrony only) could not see: (1) the validator candidate was written in read-only `/etc` (`38c541a`, staging fallback); (2) the atomic writer could not write any `/etc/<file>` target under the unit — `/etc/fstab`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/exports` (`41e1832`, in-place `O_TRUNC` write with a write-in-progress marker restored at start; no seccomp change); (3) the monitor refused every `x-systemd.*` fstab option, including the automount hint the module recommends (owner decision 2026-10-07: allow `automount`, `idle-timeout`, `mount-timeout`, `device-timeout`, `rw-only`; refuse the rest without case). Also: `MOUNT_WAIT` 30 s equalled the request timeout, so an NFS apply answered 408; now 10 s. Not yet run on a real host: hosts/resolver/nfs applies under the unit (same write path as fstab, now proven), crash recovery of an in-place write. testhost after: detent uninstalled, `/etc/fstab` original, no test units, `/var/lib/detent` holds only `monitor.lock`; user `detent` kept.

## 2026-10-06 - Writes to /etc/<file> under the packaged unit: in-place fallback

Found by the D1 testhost run, pre-existing: `ProtectSystem=strict` with `ReadWritePaths=/etc/fstab` (the file) makes `/etc` read-only, so `write_atomic`'s temp file beside the target gave EROFS and every apply to `/etc/fstab`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/exports` failed `ops-privsep-failed`. Owner decision: in-place write plus recovery. `fs::atomic`: `WriteRequest::in_place` (`InPlace::{Never, Marker(path), Guarded}`, default `Never`); only on EROFS/EACCES at temp creation, only for an existing regular file with a backup, the monitor's writes write `InPlaceMarker` (`O_EXCL`, fsync; target, backup, previous and new digest), open the target `O_WRONLY|O_TRUNC|O_NOFOLLOW`, check device and inode with `fstat`, write, fsync, remove the marker. `O_TRUNC` instead of `ftruncate` (not in `MONITOR`, owner chose no table change; seccomp has no argument filters). Every monitor write and restore (WriteTarget, Restore, all rollback paths, commit recovery) passes the marker; `recover_pending` first runs `recover_in_place`: new or previous digest → marker removed; anything else → backup restored (`InPlace::Guarded`, so a crash during recovery repeats it); a marker naming no allow-listed file target or a backup outside its backup directory is removed with nothing touched; a failed restore keeps the marker. Tests run unprivileged on macOS (0555 directories); no root `enforce_mode_*` test added. **Unproven until the testhost rerun:** the in-place write and rollback under the real unit (EROFS, Landlock, seccomp with `O_TRUNC`), and recovery after a real crash.

## 2026-10-06 - Track C A5 regression: candidate in a read-only target directory

Found by the D1 testhost run: under the packaged unit every `mounts` apply failed `ops-check-failed`, because the validator candidate is created beside the target (`/etc`), which `ProtectSystem=strict` keeps read-only (`ReadWritePaths=/etc/fstab` names the file); the same for any target file directly in `/etc`. Fix: one monitor helper (`create_module_candidate`) for the write path and `RunCheck`: trusted target directory first, monitor staging when that fails with EROFS or EACCES; an untrusted directory is still refused. The runner looks for the candidate name in the target directory, then in staging (both its own paths, same prefix and trust rules). Tests: `run_check_falls_back_to_staging_when_the_target_directory_is_not_writable`, `run_check_trusts_a_root_owned_target_directory` (now runs the check from staging), `the_runner_finds_a_candidate_in_staging_when_the_target_directory_lacks_it`. Proven only by unit tests (macOS, unprivileged); the testhost rerun of `scripts/mounts-activation-check.sh` is the live proof. Residual: a validator with an AppArmor profile whose target sits directly in `/etc` would meet the A5 denial in staging.

## 2026-10-06 - Track D 1: mount activation after an fstab apply

Owner route (BUGFIX §4): systemd starts the units; no `CAP_SYS_ADMIN`, seccomp, capability or unit-file change (the monitor's Landlock forbids `mount(2)`, and the unit's private mount namespace would hide a mount). `666572d` `ModuleDescriptor::added_mounts` (pure hook). `077b9a7` mounts lists the units of added or spec/fstype-changed entries (no remount on option-only changes; noauto and swap skipped; `x-systemd.automount` gives the `.automount` unit; fstab octal escapes decoded, `systemd-escape --path` naming). `2b02464` `[mounts] activate_new_entries` (default false); `serve` loads `detent.toml` before the allow-list, so the monitor and the runner have it at startup; `serve --dryrun` says when it is on. `3c94f0a` `ServiceManager::{mount_unit_states,start_mount_units,stop_mount_units}`: one `systemctl start -- <units>` bounded by `MOUNT_WAIT` (30 s), then `ActiveState` per unit; names validated first; other init systems Unsupported. `850119d` runner `StartAddedMounts{target}` / `StopStartedMounts` / `ForgetStartedMounts` (`privsep::mounts`): units worked out from the target and its newest backup, protected mount points refused (`/` and ancestors of `/etc`, `/usr`, `/boot`, the state root, the binary dir), only inactive units started, recorded first in `/run/detent/started-mounts.json` (the monitor and the worker cannot write there); stop only while the target has the recorded digest. `8b023bb` monitor answers `Request::Mount` with the appended `Response::Mounted`; every rollback path stops the recorded units before the restore (failure logged, rollback goes on); confirm forgets. `a31754d` `ApplyReport.mounts` (`MountsReport`); a mount failure never fails the apply; OpenAPI and web types regenerated. `ffe75a0` CLI lines (`792c4dc`: literal Fluent ids, which the catalogue test needs), `a137645` `doctor` row, `2c9a385` web banner (`MountResults`). `15c9fc4` `scripts/mounts-activation-check.sh` (testhost; `--dryrun`, `--verbose`, `--escape-only`, `--nfs`, `--expect-off`). Implemented directly, not delegated. **Unproven until the testhost run:** the unit names against real `systemd-escape`; that the runner's `systemctl start`/`stop` work under the packaged unit; the tmpfs, automount and unreachable-NFS behaviour; the rollback stopping only the started units; the `/run/detent` record directory passing the trust check. Open: Phase 12 polkit rule for `.mount`/`.automount` in capability-user mode.

## 2026-10-06 - Track E 8-14 and Track D 1 (daemon-reload)

E8 `9990fc4`: `run_update` driven to the network by a test. E9 `d677510`: the build-signer extension (1.9) is a DER `UTF8String`; the raw compare never matched; decoded now, the 1.8 issuer check too. E10: `rebuild-verify.yml` never compared the rebuild (it hashed only the downloaded asset); now the published asset and the rebuilt binary must equal `SHA256SUMS`, all four targets, no cargo cache, latest release only, pinned attestation; run 37422355130 reproduced all four `v0.1.1` targets. E11 `20c5980`: macOS CI job runs harden-runner (audit). E12 `87112a3`, `334aaaa`: `update --check` names a held release (`held`: `too_young` / `rejected`). E14 `59a5ec6`, `edac057`: hidden `detent verify-bundle`; the publish job gates each updater bundle with the built x86_64 musl binary (checked locally on the real `v0.1.1` binary and bundle; the CI step runs first on the next tag). D1 (daemon-reload half) `f3d5c14`…`bcccd2b` (Opus implementor, reviewed): `ModuleDescriptor::reload_unit_files` (mounts only), `Request::ReloadUnitFiles` → runner → `systemctl daemon-reload` after an apply and after every commit-confirm rollback path; a failed reload fails the apply. No seccomp or capability change. Not yet run on a real systemd host. Owner decisions (BUGFIX §4): H5 fail closed, M5 read scope, C1-b chunked StageUpdate now, D1 mount behind a config flag.

## 2026-10-06 - v0.1.1: first production Rekor v2 release

`v0.1.1` (`01d09fe`, signed tag) released by run 37419947623: 8 builds, the reproducibility gate, SBOM, `actions/attest` (GitHub store, Rekor v1; `gh attestation verify` passes) and, new, the cosign Rekor v2 updater bundles. All four `detent-<triple>.sigstore.json` are `hashedrekord` 0.0.2 entries in `log2025-1` (log id `zxGZFVvd…`) with one RFC 3161 timestamp; the pre-publish gate (`cosign verify-blob-attestation`) passed; `SHA256SUMS` matches every asset. The x86_64 musl bundle is now a fixture: `real_rekor_v2_bundle_verifies` passes through the public `verify` with the embedded production trust root (log2025-1 key, TSA, CT key) and our pinned identity; another tag gives `IdentityMismatch`, another digest `DigestMismatch`. Devices on `v0.1.0` or older cannot verify these bundles (owner decision: reinstall). Also in this release: `detent update` reads `[update] min_age_days`, SCT signatures are verified, Rekor v2 support. E8 (`9990fc4`): `run_update` is driven up to the network by a test.

## 2026-10-05 - Release bundles move to Rekor v2 (cosign)

Owner decision: the updater asset `detent-<triple>.sigstore.json` becomes a Rekor v2 bundle in the next release, at once; devices on `v0.1.0` or older (Rekor v1 only) need a manual reinstall. `6121291`: `.github/sigstore/signing-config-rekor-v2.json`, root-signing `5888f35` `signing_config_rekor_v2.v0.2.json` (sha256 `0f5f3855…`) with the Rekor v1 log removed. `0228efa`: the publish job installs cosign v3.1.3 (`sigstore/cosign-installer` v4.1.2 `6f9f1778…`, published 2026-05-07; cosign v3.1.3 published 2026-08-06), signs each binary with `cosign attest-blob --signing-config … --bundle …`, and a gate step checks every bundle (`hashedrekord` 0.0.2, an RFC 3161 timestamp, one subject, `cosign verify-blob-attestation` for this workflow and tag) before `gh release create`; egress gains `log2025-1.rekor.sigstore.dev` and `tuf-repo-cdn.sigstore.dev` and loses `tuf-rekor-cdn.sigstore.dev` (E13). `892d145`: cosign `--predicate` writes an in-toto Statement/v0.1, which `bundle.rs` refuses, so the job builds a v1 statement with jq (the binary as the one subject, the `actions/attest` SLSA predicate) and passes `--statement`. `actions/attest` stays (GitHub's attestation store, `gh attestation verify`, `rebuild-verify.yml`). Checked: actionlint (only the known `ubuntu-26.04` label warnings), shellcheck on the two new run blocks, yq parse; zizmor is not installed. **Unproven until the next tag:** cosign-installer and cosign under egress `block` (endpoints not listed may be needed); cosign keyless signing with the GitHub OIDC token; that log2025-1 and the TSA accept the entries and cosign writes `hashedrekord` 0.0.2 with a timestamp; that `verify-blob-attestation` passes; and that the updater verifies a production Rekor v2 bundle (only staging material is proven). Follow-up: capture that bundle as a fixture (BUGFIX E7).

## 2026-10-05 - M3 acceptance passed on testhost

`detent update` ignored `[update] min_age_days` and always used 2 days (the web check read it); fixed with `update_policy` (test `update_takes_min_age_days_from_the_config`, failed first with E0425). The owner allowed a 1-day gate on the test device. Start build `v0.0.2` (branch `m3/v0.0.2`: the fix plus the version, never on `main`, release marked pre-release) installed on testhost from the release (digest and attestation checked), packaged unit, `[update] min_age_days = 1`. Rollback: with `v0.1.1-test` briefly not pre-release, `sudo detent update` installed it, `serve` exited 1 in a restart loop, and after 30 s: `rolled back: the restarted service was not healthy within 30s`; `v0.0.2` back, `/healthz` 200, `bad.json` = `["v0.1.1-test"]`; `v0.1.1-test` is pre-release again. Update: `installed v0.1.0; the binary it replaced is kept at /usr/local/bin/detent.prev`, binary SHA-256 equal to the release `SHA256SUMS` (`872cb926…`), service active, `/healthz` ok, `update --check` → no update. The order differs from PLAN (rollback ran from `v0.0.2`, not `v0.1.0`) because the `v0.1.0` CLI has the 2-day gate; the capability is the same. testhost after: unit, binary, `/etc/detent`, test state removed; `/var/lib/detent` holds only `monitor.lock`; user `detent` kept (to be removed later). Open for the owner: immutable releases, rulesets.

## 2026-10-04 - First releases: v0.0.1-rc.2, v0.1.0; M3 started

Released from `main` with signed tags: `v0.0.1-rc.2` (`6f07f0d`) and `v0.1.0` (`8b70304`). Each: 8 builds, the two-build gate (all four targets equal), SBOM, attestations, publish under egress `block`; `SHA256SUMS` matches every asset and `gh attestation verify --signer-workflow …/release.yml --source-ref refs/tags/<tag>` passes for all four binaries. `gh release verify` finds no release attestation until immutable releases are on. Found and fixed on the way: `release.yml` now refuses a tag that differs from the crate version (`d5d8ae4`; a `v0.1.0` tag on a `0.0.1` tree makes a binary that offers itself again); `gh release create` needs `--repo` (no checkout; `v0.0.1-rc` stopped there, `85657f9`, so that tag has no release); the update fixtures were minted for `v0.0.2` and the real monitor refused them as a downgrade once the crate passed it, now `v99.0.0` (`1ab5672`, bugfix-high implementor, reviewed). R1 (`8b70304`): the real `v0.0.1-rc.2` bundle verifies with the embedded trust root (`real_attest_bundle_verifies`; another tag gives `IdentityMismatch`, another digest `DigestMismatch`).

M3: `v0.1.1-test` (branch `m3/broken-v0.1.1-test`, `serve` exits 1, `--self-test` passes) is published and marked pre-release. testhost runs the released `v0.0.1-rc.2` x86_64 musl binary under the packaged unit (`/healthz` ok); `update --check` holds `v0.1.0` for the 2-day age gate. Remaining steps and dates: BUGFIX Track E 5.

## 2026-10-04 - Track E: E1, B3, E3, E4

E4 (`8a99a38`, `d77ddda`): the Dashboard has an install control for an available update (write session only), with a confirm dialog that names the restart; web coverage 100%. E1 (`41096a1`): `release.yml` publishes the `actions/attest` bundle as `detent-<triple>.sigstore.json`; cosign removed. B3 (`26beff9`, `e7bd3ba`, `d5fff99`): real public-good Fulcio intermediate and root and the Rekor key from `trusted_root.json` (root-signing `5888f35`, digest in `TRUST_MANIFEST`; TUF signatures not verified, the TUF CDN target digest matched); the verifier accepts P-384 chain signatures (`real_fulcio_leaf_chains_to_the_embedded_roots`). E3: macOS targets on macOS runners (`22ded64`), two-build SHA-256 gate (`a047ad8`), harden-runner egress `block` on the Linux jobs (`f66ea6f`, macOS legs audit only).

Release dry runs found three faults: harden-runner takes a space-separated `allowed-endpoints` list, and a `|` list allowed none of the entries (`054439a`; my first theory, wildcard order in `f86c7ea`, was wrong); jq read `.bom-ref` as `.bom - ref` (`ad0542b`); the cargo cache kept a mimalloc object with an older commit's `__TIME__`, so the macOS builds differed (`b1f7a05`, no cache in release builds). Dry run 37174273098 at `b1f7a05`: 8 builds, SBOM and the gate green; all four targets reproduce. Open (BUGFIX Track E 1, 5–11): the first tag, SCTs, Rekor v2, `run_update` coverage, the 1.9 extension compare, macOS in `rebuild-verify.yml`.

## 2026-10-03 - Track C A4 and A3

A4 (M1): under the packaged unit the worker (uid 999) had `CapBnd` 0x1eb while its confinement said caps `Applied`. `drop_and_confine` (`spawn.rs`) now empties the bounding set while still root, before `setgroups`/`setgid`/`setuid` (worker and acme keep no capability; a refusal is ignored and reported). `drop_capabilities` reports `Applied` for an already unprivileged process only when the bounding set holds nothing beyond `retained_caps`, else `Unavailable` naming the leftovers (pure `already_unprivileged`). Tests: `an_unprivileged_process_is_applied_only_with_an_empty_bounding_set`, `enforce_mode_worker_drops_the_bounding_set_before_its_uid_change` (root: real `spawn_pair` to `detent`, `CapBnd` 0, `Applied`); failed before with `bounding set not empty: Some(1ffffffffff)`. testhost x86_64 musl as root: these, `capability_bounding_set_shrinks_to_the_policy_set`, `caps_that_do_not_drop_are_fatal_only_when_required`, `spawn_pair_drops_to_the_worker_account_when_root` pass; `enforce_mode_*` 19/19. Implementor: bugfix-high (Sonnet), reviewed.

A3 (negative checks, Sonnet agent in a separate worktree, macOS; M1 by hand): with each fix removed by a minimal edit, its pinning test fails, and passes again after restore: C1-a (`read_staged_verified_refuses_a_hard_linked_image`), C1-c (verify call and embedded-root fallback), H1 (`serve_locked`, `report_recovery`, one-shot recovery, CLI commit-confirm refusal), H2 (arming undo, service-failure discard), H12, M11 (bind table, origin validation), L-PLAT6 (exit-zero half), L-PLAT7, L-BIN16 (both child aborts), M1 (`caps_verdict` → `Ok`: `panicked … Ok(())`). Vacuous: removing the `report_recovery` call in `run_monitor`, or the `discard_commit` in `apply`'s no-backup branch, fails no test (A3-a, A3-b).

## 2026-10-01 - Track C A2-b: `setup`, `user` and `token` refuse root

As root these commands exit 3 (`Exit::Privilege`) before they open the state root or read a password, and print `cli-state-command-as-root` with `sudo -u detent detent <command>` (`run.rs`: `run` reads `is_root()` and calls `run_as`, so tests inject the euid; `--help` still works; `--dryrun` is refused too, because it would predict a refusal). `install.sh`, `packaging/README.md` and `README.md` show `sudo -u detent detent setup`. `binary.rs` tests that mint a token or run `setup` check the refusal when the suite runs as root and then mint through `TokenStore` (new dev-dependency on the workspace crate `detent-web`; `Cargo.lock` unchanged). Test `state_commands_are_refused_as_root_and_touch_nothing`. testhost (x86_64 musl release): `sudo detent setup` and `token list` exit 3 and write nothing; `runuser -u detent -- detent setup` exits 0, `state/` 700 and `users.json` 600, both `detent:detent`. Implementor: Opus subagent, reviewed. Track C A2 is done.

## 2026-10-01 - Track C A2: the shipped unit runs with `NoNewPrivileges=yes`

Transient units on testhost (`systemd-run`, systemd 261.2-1ubuntu2) showed that `NoNewPrivileges=yes` alone keeps `CAP_SETUID`; with any seccomp-based directive added (`SystemCallFilter`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `RestrictAddressFamilies`, `SystemCallArchitectures`, `PrivateDevices`, `ProtectKernelTunables`) the service gets `CapPrm` 0x16b (no `CAP_SETUID`) and `setresuid(999)` fails; `SecureBits=keep-caps` does not help; `AmbientCapabilities=CAP_SETUID CAP_SETGID` does. The unit now has that line (test `the_unit_keeps_setuid_for_the_worker_drop`). A2 rerun with the shipped unit and no drop-in: all steps pass. Capabilities while serving: monitor uid 0 Prm/Eff/Bnd 0xb (CHOWN, DAC_OVERRIDE, FOWNER), Amb 0; worker uid 999 Prm/Eff 0, Amb 0, Bnd 0x1eb (A4); runner uid 0 0x1eb, Amb 0xc0 (unconfined by design). testhost cleaned as before.

## 2026-09-30 - Track C A2: packaged `serve` end to end on testhost

`packaging/install.sh` (root-confined), `/etc/detent/detent.toml` with `[listen] addr = "127.0.0.1:3333"` (not the 0.0.0.0 default), admin via `runuser -u detent -- detent setup`. With a test-only drop-in `NoNewPrivileges=no` (§4 A2-a) the whole flow passes: HTTPS login 200 and CSRF token; chrony `plan` 200, check ran and passed (A5, AppArmor enforcing); `apply` with `service_action: restart`, `confirm_secs: 20` → 200, file changed, chrony restarted and active, one pending commit; after expiry the monitor logged `commit-confirm expired; rolled back`, the file is byte-identical to the original, chrony active; `systemctl stop` → `Result=success`, exit 0; uninstall. Failures found and fixed, one commit each with a test in `crates/detent/tests/packaging.rs` (new): module `ReadWritePaths` without `-` stopped the unit on Ubuntu (`226/NAMESPACE`, `/etc/chrony.conf`); `/run/detent/staging` was missing after a restart (now in `RuntimeDirectory=`); `PR_CAPBSET_DROP` needs `CAP_SETPCAP` (added; the monitor drops it too); `StateDirectory=` re-chowned the state root to root, locking the worker out (removed; tmpfiles.d owns it); `ConfigurationDirectoryMode` warning (0750). Diagnosability: `serve` now prints each error's sources, and a worker or acme child that cannot start writes its cause before it exits (before: "sandbox refused to start" and "the pair stopped unexpectedly" with no cause). Open for the owner: §4 A2-a (`NoNewPrivileges=yes` strips `CAP_SETUID` on this systemd: `CapPrm` 0x16b vs bounding 0x1eb) and A2-b (`sudo detent setup` makes root-owned state the worker cannot read). testhost after the run: unit, binary, drop-ins, `/etc/detent` removed; `/var/lib/detent` back to root:root 0755 with only `monitor.lock` (as before); chrony config original, chrony active; user `detent` kept (to be removed later).

## 2026-09-30 - Track C A5: validator candidates beside the target (AppArmor)

Owner decision: put the candidate where the distro's AppArmor profiles already let the validator read, and keep every real config where it is. `Allowlist::candidate_dir(module, &HostProfile)` applies the engine's `wiring()` rule (first detected, advertised target, else the first advertised one) and returns that target's parent when it is a file; the monitor (`RunCheck` and the `WriteTarget` re-validation) writes `.detent-candidate-*` there (O_EXCL, 0600, removed on drop); a module whose primary target is not a file keeps `/run/detent/staging`. The runner still receives only a file name: it derives the same directory from its own allow-list, requires the `.detent-candidate-` prefix, and checks the file (regular, no symlink) and the directory. Directory rule (`require_trusted_dir`, `DirOwner`): a real directory, not a symlink, no group/other write bit, owned by the monitor's euid or (target directories only) root, so capability-user mode works; staging keeps euid-only. `spawn_runner` takes the `HostProfile` (`serve.rs` passes the one it gives the monitor). No Landlock or seccomp change (`Policy::monitor` already covers target parents). Tests (written first): monitor placement, staging fallback, group-writable / symlinked / foreign-owner refusals, root-owned acceptance, write-path placement and refusal; runner finds the candidate, refuses other names, symlinks, a group-writable directory; `engine_monitor_and_runner_agree_on_the_candidate_directory` (real engine → monitor → runner, first target undetected). Linux: the confined drive checks now fail unless `$0` is `*/etc/.detent-candidate-*`, so a real runner read the candidate from the new place. Results: macOS `cargo test --workspace --all-features` 2309 passed; testhost x86_64 musl `enforce_mode_*` 18/18, and a real `serve` chrony `plan` with AppArmor enforcing: check `ran: true, passed: true, exit_code: 0`, no candidate left in `/etc/chrony`; aarch64 all features `privsep::` 237/237, `enforce_mode_*` 18/19 (the container has no `systemctl`; with a stub it passes 4/4). Pre-existing, not from this change: 9 `privsep::monitor` update-path tests fail as root on testhost on `main` too (`NotFound`; they read files testhost lacks). Implementor: Opus subagent; it stopped once and reported that a monitor-only change would break the runner (design then approved), and did two follow-ups (root-owned target dirs, runner directory check).

## 2026-09-30 - Track C A1: confined `serve` traced; the monitor filter allows no process creation

testhost (x86_64 musl release build of `9d7d0fb`): `detent serve` under `strace -ff`, self-signed TLS, fresh state root (0700 `detent`), `/run/detent/staging` made as `packaging/tmpfiles.d/detent.conf` does. Through the API with a write token: `POST /modules/chrony/plan` (model = the host's, without `confdir`/`sourcedir`, which the module refuses) → 200; `POST /services/chrony {"action":"restart"}` → 200, `systemctl restart chronyd.service succeeded`. No `SIGSYS`. `chronyd -p -f <candidate>` and both `systemctl` runs were children of the runner, not the monitor. After its filter the monitor made no process-creation call; the union with the 13 x86_64 and 14 aarch64 `enforce_mode_monitor_*` traces (without the old spawn test) needs only `open` and `wait4` from the spawn block. So `MONITOR` loses 23 rows: `clone clone3 execve execveat pipe2 dup3 dup2 kill tgkill nanosleep clock_nanosleep prlimit64 faccessat access readlink readlinkat ppoll poll set_tid_address arch_prctl rseq set_robust_list sched_getaffinity`. `enforce_mode_monitor_can_spawn_a_validator` is replaced by `enforce_mode_monitor_dies_by_sigsys_on_execve` (strace on testhost: `execve("/bin/true") … +++ killed by SIGSYS +++`); it and `enforce_mode_seccomp_kills_the_monitor_on_a_forbidden_syscall` share one fork helper, so the suppression count stays 110; the latter now asserts `SIGSYS` exactly. Unit test `the_monitor_table_has_no_process_creation_calls`. Results: testhost no-`update` build 18/18 `enforce_mode_*`; aarch64 all features 18/19, the one failure is the container's missing `systemctl` (exit 1, as before). Implementor: Opus subagent, reviewed; one rework (it had added an `#[allow(unsafe_code)]`). Found: A5, AppArmor refuses chronyd's read of the candidate (the check ran but failed). testhost: user `detent` added (owner, remove later), chrony restarted 3 times, `/var/lib/detent-a1`, `/run/detent` and `/tmp/detent-a1` removed.

## 2026-09-30 - Owner decisions applied: musl stat forms, aarch64 probe, `mcp` implies `web`

- `MONITOR` allows `stat` and `lstat`, `WORKER` allows `stat` (x86_64 only; `lstat` row 6 read from `<asm/unistd_64.h>` in `debian:bookworm`; aarch64 has neither, so its filter is unchanged). Test `the_monitor_and_worker_tables_carry_the_musl_stat_forms`. testhost (x86_64 musl, Enforce mode): 18 of 18 `enforce_mode_*` pass (before: 11 failed, 10 by `SIGSYS`). Not traced: a real x86_64 musl `serve` (testhost has no Pebble or BIND).
- `scripts/acme-serve-check.sh` tolerates `faccessat` in the acme process (aarch64 form of mimalloc's `access` probe). OrbStack aarch64 musl run: all checks PASS, exit 0.
- `mcp` implies `web` (`crates/detent/Cargo.toml`); the `web` gates in `mcp.rs` and on the two MCP cert tests are gone. Before, an `mcp`-only binary had no `detent token` command and no cert hook.
- The parity test pairs `cert_renew` with REST `renew_cert` (no input on either side); the "MCP-only" exception and the stale `docs/API.md` line are gone.
- Track B is done except the owner's Track G choice. Next: Track C (testhost), then Track E.

## 2026-09-30 - Track B 6 and the `MONITOR` follow-up: syscall traces on aarch64 and x86_64 musl

Report only; no table, code or script changed. Venues: aarch64 = the owner's M2 Mac, OrbStack native aarch64 kernel 7.0.14 (Landlock, seccomp), `--privileged` container (Docker's seccomp profile off); x86_64 = testhost (kernel 7.3), binaries built on the Mac with `cargo zigbuild`, copied to `~/detent-test/943415e/`. A set-difference script compared every call made after the process's own `seccomp(SECCOMP_SET_MODE_FILTER)` (and in its later threads and children) with the role table, using the per-arch `SYSCALL_NUMBERS` column.
- **acme, aarch64 musl** (`scripts/acme-serve-check.sh` unchanged, `--expect-renewal 240 --forced-renew`, Pebble and BIND 9 by the CI digests; the BIND image is amd64 and ran under Rosetta, it is not traced): every serve check passes (issue, hot renewal, forced renew 202 and audit record, four processes, acme has no_new_privs, seccomp and Landlock, clean SIGTERM stop). The only call outside `ACME`: `faccessat(AT_FDCWD, "/sys/devices/system/node/node1", R_OK) = -1 EPERM` (mimalloc's NUMA probe; on x86_64 it is `access`, which the script tolerates). So the script ends `FAIL: the acme process was refused the syscalls above (EPERM)`. `MONITOR` 0 calls outside the table; `WORKER` only the tolerated `fchown`, `flistxattr`, `prctl`.
- **monitor, aarch64 musl** (the 14 `enforce_mode_monitor_*` tests, `--all-features`, under `strace -ff`): 14 confined monitors, 2 threads and 1 spawned child, 0 calls outside `MONITOR`, no `SIGSYS`. 13 pass; `runs_real_validators_through_the_runner` fails because the container has no `systemctl` (the probe check exits 1; not a seccomp refusal). The 5 other `enforce_mode_*` tests pass.
- **monitor, x86_64 musl** (testhost, no `update` feature: the update fixtures are read from the Mac path at build time, so 13 tests): **10 of 13 fail, the monitor killed by `SIGSYS`** on `stat` after `mkdir` gives `EEXIST` (`create_dir_all` on an existing directory). A throw-away build with `SeccompMode::Log` at `linux.rs:244` (not committed; 13 of 13 pass) shows the full set outside `MONITOR`: `stat` (10 monitors) and `lstat` (3). musl issues these legacy forms on x86_64; glibc issues `newfstatat`/`statx`, which the table allows, so CI (gnu) does not see it. The release targets are `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- **worker, x86_64 musl**: `stat` outside `WORKER` (`EPERM`); `enforce_mode_worker_can_tighten_an_audit_directory` fails in Enforce mode on testhost and passes on aarch64.
- Classification (Jev, `jev-1.13.0`, `choice` questions; only syscall names and context were sent): `stat`/`lstat` in the monitor and `stat` in the worker = legacy form (0.97 to 0.98); acme `faccessat` = tolerated probe (0.83). Checked against the code: the `ACME` table already lists `stat` with the comment "musl on x86_64" (`seccomp.rs`).
- Owner decision asked (`BUGFIX.md` §4, "Legacy stat forms"). testhost: nothing installed; `~/detent-test/943415e` removed after the run. The directories `7f1df06` and `fe20b73` from earlier sessions are still there.

## 2026-09-30 - Handoff: the cloud session stops; a local session continues

State: `main` = `claude/determined-noether-wo0uh8`, CI green on `2dcf744`. Track A is done. Track B items 1-5 are done; item 6 (aarch64 syscall trace of the acme process) needs an aarch64 host. Next, in `docs/BUGFIX.md` order: Track B 6 and the "Legacy syscalls in `MONITOR`" follow-up (trace the musl release binary and aarch64), the item 3 follow-ups (`mcp` without `web`, stale `API.md` lines), Track C (testhost, owner's setup), then Track E. Traps: `docs/BUGFIX.md` §2.4. Main moves only by fast-forward after CI is green on the branch.

## 2026-09-30 - Track B 3: the MCP tools `cert_status` and `cert_renew` answer

`Operation::CertStatus` and `CertRenew` no longer answer `ops-unsupported` in `detent mcp`. `detent-ops` has a trait `CertFrontEnd` (`status`, `renew`) and `OpsEngine::set_cert_front_end`; `dispatch` calls the hook and answers `OpOutcome::CertStatus(Box<CertReport>)` (the REST `GET /api/v1/system/cert` fields) or `OpOutcome::CertRenewRequested`. With no hook both still answer `Unsupported`, so the web front end (which answers from its own state) is unchanged. `execute` still authorizes and audits first: a denied caller never reaches the hook, `CertRenew` writes `started` then `ok` or `error` with the failure's message id, `CertStatus` writes nothing. One new `OpsError` variant, `Cert { id, reason }`, because no existing variant carries a caller-chosen message id and text; the id is the one `detent cert renew` prints for the same failure (`cli-cert-renew-token-refused`, `-not-acme`, `-server-error`, `-server-error-bare`, `-unreachable`, `cli-cert-missing`, `cli-cert-unreadable`, `cli-config-load-failed`). No new Fluent id. In `detent` (`mcp.rs`, feature `web`): `ServerCert` holds a copy of `Settings` and the MCP bearer in `Zeroizing`, is not `Debug`, and reads `detent.toml` on each call. `status` reads `tls.cert_dir` (`renew::served_pair`, `cert_report_for_der`); `renew` calls `renew::request`. `renew.rs` was split so the CLI and the hook share `prepare` (address and trust anchor from the config), `ask` (request with a given token, exchange) and `outcome`; `detent cert renew` output and exits are unchanged (its 36 tests pass as before). Sandbox check (design step 4): `detent mcp` runs the engine and the monitor thread in its own process, for stdio and `--transport http`; nothing in `crates/detent` except `serve` calls `sandbox::confine`, so no Landlock or seccomp rule applies to it, and it can read `tls.cert_dir` and connect to the `serve` address with its own user's rights. The `0700` `cert_dir` means it must run as the service user or root; no sandbox rule was changed. Without the `web` feature no hook is installed (the `mcp` feature does not name `web` in `Cargo.toml`). The `cert_renew` tool description now says what it does. Tests: `detent-ops/tests/engine.rs` (hook answers, audit records, hook error id, denied caller never reaches the hook; the two no-hook `Unsupported` tests stay); `serve.rs` against the real in-process listener (`mcp_cert_status_reports_the_certificate_the_server_serves`, `mcp_cert_renew_asks_the_server_once_for_a_write_token_and_never_for_a_read_one`, `mcp_cert_renew_tells_the_servers_refusals_apart`, `mcp_cert_tools_name_the_address_they_could_not_use`, `the_token_never_reaches_a_tool_answer_an_error_or_a_log_line`); `renew.rs` (answer and failure mapping); `tests/binary.rs` `mcp_cert_tools_answer_over_stdio_without_leaking_the_token` (a real `detent mcp` child over stdio, TRACE log, token absent from stdout and stderr). Coverage (`cargo llvm-cov -p detent -p detent-ops --all-features`, root, this container, after a clean): `crates/detent/` 94.85 % (was 94.72 % in the entry below), `crates/detent-ops/` 99.76 %; every new line in `engine.rs`, `error.rs`, `report.rs` is covered (the 6 missed ops lines are older). Stale docs found and left: `docs/API.md` says `cert_renew` "is MCP-only (renewal has no REST route)" (there is a route) and says the `mcp` feature implies `web` (it does not in `Cargo.toml`). Track B item 3 is done.

## 2026-09-30 - Size baseline re-cut for `detent cert renew`

CI Size check failed on `2f84c7b`: `full-default-aarch64-musl` measured 5455472 bytes, above the 5430736 maximum (5272560 + 3 %). No new crate; the growth is the command's own code (CLI, TLS 1.3 listener client, messages). The owner approved a re-cut: `size-baseline.json` now holds 5455472 (+182912), tolerance 3 %, still far under the 12 MiB budget. CI stops at the first failed size step, so the next run then measured `resolver-web-aarch64-musl` at 5020144 bytes (+196224, 4.07 %; the command is part of `web`); the run after that measured `full-ui-aarch64-musl` at 6279088 bytes (+186304, 3.06 %). Both entries are re-cut the same way. `cli-aarch64-musl` has no `web` feature and does not change.

## 2026-09-30 - Track B 3: `detent cert renew` asks the running server

`detent cert renew` (`crates/detent/src/renew.rs`, `cli.rs` `CertAction::Renew`, feature `web`) sends `POST /api/v1/system/cert/renew` to the running `serve` with `Authorization: Bearer <token>` (owner decision 2026-09-30). No server code changed: the request gets the web button's `write` scope check, its `cert_renew_requested` auth-log record and the acme process's one-forced-order-per-hour limit. Token: `--token-file` (opened `O_NOFOLLOW`, a regular file owned by the effective uid, no group or other bit, at most 4096 bytes: the `secrets.toml` checks) or `DETENT_TOKEN`; never argv; neither is a usage error (exit 2). The token is one line of visible ASCII (no header injection) and lives in `Zeroizing` buffers; the request is built in one zeroed buffer of its final size. Target: `[listen] addr` (a wildcard bind on loopback) or `--url https://host[:port]` (https only, no path or user). Trust: the certificate the server serves from `tls.cert_dir` is the only anchor (pinned byte for byte, and the name must be one of its SANs; a loopback IP is verified as its first non-wildcard DNS SAN), or with `--url` a `--ca-file` PEM (webpki path and name validation). TLS 1.3 only; nothing turns verification off. Client: `detent_update::listener` (new), which reuses `health.rs`'s pinned verifier (`pinned_client_config`, extracted) over a std socket, reads one answer framed by `Content-Length` (64 KiB cap, 10 s timeouts), and never quotes the request. `detent-update` was already built for `web` through `detent-web`; `detent`'s `web` feature now names it (`dep:detent-update`), no new crate. Answers: 202 → `cli-cert-renew-requested`, exit 0; 401/403 → token refused; 409 → no ACME process; others → the server's `message_id`; connect or TLS failure → names the address; all exit 1. `--json` prints `{outcome, status, message_id, address}`; `--dryrun` sends nothing. Tests: `renew.rs` unit tests (token sources and every refusal, owner, wildcard to loopback, URL and SAN resolution, request bytes, status mapping, output and exits, dry run, closed port); `serve.rs` against a real in-process listener with the production router, TLS and auth state: `cert_renew_is_accepted_for_a_write_token_and_refused_for_a_read_one` (202 and one renewer call, 403 for a read token from a file, 401 for an unknown one, two auth-log records), `cert_renew_reports_a_server_without_acme_and_a_closed_channel` (409, 503 `web-cert-renew-unavailable`), `cert_renew_trusts_only_the_served_certificate_or_the_ca_file` (a wrong CA file and a wrong `cert_dir` fail the handshake); each captures stdout, stderr and the TRACE log and searches them for the tokens with the secret finder, now shared in `tests_support.rs`. `detent-update` `listener.rs`: 8 tests against loopback TLS 1.3 servers. Item 4 (journal warnings) was already done and is marked so. Coverage (`cargo llvm-cov -p detent --all-features`, root, this container): `crates/detent/` 94.58 % at `cd4ec0b`, 94.72 % after; the new lines are about 96 % covered. Still open in item 3: `Operation::CertRenew`/`CertStatus` in the engine for MCP.

## 2026-09-30 - dns-01 multi-value TXT: apex plus wildcard keep both values

An order for `example.com` and `*.example.com` holds two TXT values at `_acme-challenge.example.com` at once (RFC 8555 §8.4), but three providers kept one. `present` now adds its value beside the others and `delete` removes only its own (`providers.rs`, `lib.rs`). `Rfc2136Provider`: `update_message` takes a `Change`; an add is one class-IN record, a remove is one class-NONE record with TTL 0 (RFC 2136 §2.5.4), no class-ANY delete-all; TSIG signing is unchanged. `DeSecProvider`: both calls `GET` the `RRset` first and `PUT` the union (present) or the set minus the value (delete); the `RRset` is `DELETE`d only when it would be empty; a `GET` body without a records array is refused, not read as empty. `HookProvider`: `<fqdn>.txt` holds every value, one per line with no trailing newline (a file with one value is byte-identical to before); `delete` rewrites the file without the value and removes it when none is left. Cloudflare (matches by value) and acme-dns (two values per subdomain) were read and left alone; a Cloudflare test with two values now covers the first. A crash between `present` and `delete` can leave a value; the ACME server accepts any matching value, so this is stated in the docs and not handled. Tests: `rfc2136_holds_two_values_at_one_name` (fake primary that applies UPDATEs with the RFC 2136 class rules), `desec_holds_two_values_at_one_name`, `desec_keeps_values_it_did_not_write`, `cloudflare_holds_two_values_at_one_name`, `two_values_at_one_name_share_one_file`; the first, second, third and fifth failed before the fix. Existing tests that pinned the replace-all behavior (`present_overwrites_a_stale_value`, the RFC 2136 wire tests, the deSEC request-order tests) were changed to the new contract. Not verified: a real deSEC API or a real primary; deSEC `PUT` on an `RRset` that does not exist yet is unchanged from before (assumed to create it).

## 2026-09-30 - Track B 5: `shortlived` by default when the CA offers it

With no `[acme] profile`, an order named no profile, so Let's Encrypt issued its 90-day certificate. `detent_acme::choose_profile(configured, advertised)` (`order.rs`) now picks: the configured name as is (`profile = "classic"` opts out), else `shortlived` when the directory's `meta.profiles` lists it (read through `Account::profiles`), else none. Pebble advertises only `default`, so its orders are unchanged. `new_order_for` holds the lookup; `account_and_order` and `issue` return the requested profile as a new last value, and `AcmeIssuer::issue` (`detent/src/acme.rs`) logs it at `info` after a successful order (`detent-acme` has no `tracing`; a failed order logs no profile). Tests: `choose_profile_*` (2) and, over `FakeAcme` (which now records the decoded JWS payload of each POST), `an_advertised_shortlived_profile_rides_the_new_order`, `a_directory_without_shortlived_gets_no_profile_field`, `a_configured_profile_wins_over_the_advertised_default`. Docs: the `profile` field comment in `config.rs` and the "Short-lived certs" row of `SECURITY_HARDENING.md`. Not tested live: Let's Encrypt itself (staging run not done).


## 2026-09-30 - Wildcard dns-01 name: a wildcard order can issue

`present_challenges` (`order.rs`) named the record after `challenge.identifier().to_string()`. instant-acme's `AuthorizedIdentifier` displays a wildcard authorization (base domain plus `"wildcard": true`, RFC 8555 §7.1.4) as `*.example.com`, so the name was `_acme-challenge.*.example.com` and `DnsRecord::new` refused it (`InvalidFqdn`). The code now takes the bare DNS identifier, so the name is `_acme-challenge.example.com` (RFC 8555 §8.4). New tests (`flow_tests.rs`): `present_challenges_puts_a_wildcard_record_at_the_base_domain`, `present_challenges_publishes_apex_and_wildcard_at_one_name` (two records, two values, one name; cleanup withdraws both); both failed before the fix with `Error: InvalidFqdn("_acme-challenge.*.example.com")`. Not fixed, listed in `BUGFIX.md` Track B 2: `Rfc2136Provider`, `DeSecProvider` and `HookProvider` hold one value per name, so an apex plus wildcard order loses the first value before validation.

## 2026-09-30 - Track B 2 + M18: fixtures drive the ACME order flow

`present_challenges`, `present_attest_challenges`, `wait_ready` and `finalize` (`crates/detent-acme/src/order.rs`) take an `instant_acme::Order`, which only a live ACME server made, so only the ignored Pebble test reached them. Seam: `instant_acme::HttpClient`, the one production already uses for its TLS 1.3 client. The test-only `FakeAcme` (`src/order/flow_tests.rs`) answers each request from a script of RFC 8555 replies in Pebble's wire format; the real instant-acme code restores the account, fetches the directory and nonces and builds a real `Order`. The client signs its requests but checks no server signature, so the script needs no keys. No production code changed; no fallback trait was needed. Tests (14): `present_challenges` (M18) publishes one record per pending identifier with the name and value computed independently from the token and the account thumbprint, skips a valid authorization, picks dns-01 among other types, refuses an authorization without dns-01, and stops at the first failing step (authorization fetch, present, publish, propagation, CA refusal of the challenge) with that step's error, withdrawing every record it presented; `wait_ready` ready, pending then ready, invalid, an order error, the retry limit; `finalize` returns the chain and a fresh key, surfaces a refused finalize and an order that fails while processing; `finish_order` and `present_attest_challenges`. Mutation probes (wrong TXT name, a dropped cleanup, swapped `Issued` halves, an inverted ready check) each fail a test. Coverage on Linux: `detent-acme` 91.11 % → 94.20 % (order.rs 75 % → 86 %); floor 87 → 93 in `coverage-baseline.json`. Left for a live CA: the TLS transport, fresh registration, `issue` after `account_and_order`, the ARI fetch. Found, not fixed: a wildcard order cannot issue (`BUGFIX.md` Track B 2).

## 2026-09-30 - Track B 1: log-capture test, no DNS or ACME secret reaches the log

`detent-acme` logs nothing (it has no `tracing` dependency); `detent` logs the `Display` of what it returns, and `issue_reason` (`crates/detent/src/acme.rs`) turns every provider error into a fixed sentence. So the test has two halves. In `providers.rs`, fixture transports and a fake TSIG primary drive `present`, `delete` and `wait_propagated` of the four providers over 400 to 502 answers, hostile bodies that echo the credential, bad JSON, a failing transport, every RCODE, a wrong-key MAC, junk answers, and constructors that get a bad setting next to a good secret. In `acme.rs`, a real `AcmeDnsProvider` and `Rfc2136Provider` fail against a refused loopback port through the real transports, and the loop's captured TRACE log is searched for the secret (as written, its random tail, base64 in both alphabets, hex, any casing). Also checked: `Debug` of `Secrets`, `KeyPem`, `Held`, `Issued`, `EabCredentials`, `HttpRequest` and the four providers; `secrets.toml` errors; three unusable account files. No leak found, so no source change. Both halves fail when a secret is added to an error or a `Debug` (shown for the acme-dns, Cloudflare, TSIG and `issue_reason` paths). Not covered: Cloudflare and deSEC through the real transport (their hosts are fixed, so it would need the network), and EAB (`AcmeIssuer` passes `eab: None`, so no EAB key is ever logged; the `Debug` of `EabCredentials` is checked). `detent-acme` line coverage 90.3 %.


## 2026-09-30 - Monitor chmod/rename: the confined monitor uses `fchmod`, `renameat` and no `copy_file_range`

`MONITOR` lists `fchmod`, `fchmodat`, `renameat` and `linkat`, but not the x86_64 `chmod` and `rename`, nor `copy_file_range`. `ensure_backup_dir` (`fs/atomic.rs`) called `std::fs::set_permissions` (`chmod`), so the first backup of a target killed a confined monitor; `write_temp_and_swap` (`monitor.rs`) called `std::fs::rename`, so a `ReplaceBinary` that passed verification died at the swap; the `std::fs::copy` fallback of `swap_running_binary` (used when the filesystem refuses a hard link) issues `copy_file_range`. Strace before the fix: `chmod(".../state/backups/trace/0", 0700) = 90`, `rename(".../etc/<digest>.tmp.<pid>", ".../etc/detent-old") = 82` and `copy_file_range(3, NULL, 4, NULL, 1073741824, 0) = 326`, each followed by `+++ killed by SIGSYS +++`. Owner decision 2026-09-30, as for `unlink`: fix it in code, no seccomp or Landlock change. `ensure_backup_dir` opens the directory and calls `fchmod`; `monitor.rs` has `rename` (`rustix::fs::renameat`) and `copy_file` (read, `O_EXCL` create, `fchmod`, write). The `enforce_mode_monitor_*` helper no longer makes the backup directory first; new tests: `enforce_mode_monitor_swaps_a_verified_release` (needs the `update` feature) and `enforce_mode_monitor_copies_the_previous_binary` (`linux.rs`, root), plus the unprivileged `copy_file_*` and `first_backup_makes_a_private_backup_directory`. Re-trace with `strace -f` of every `sandbox::linux::tests` test: no `SIGSYS` except the test that expects one, and no post-`seccomp` syscall outside `MONITOR`. Not traced: musl release binaries, aarch64.

## 2026-09-30 - Monitor unlinkat: the confined monitor removes its files without `unlink`

`MONITOR` lists `unlinkat` and `renameat` but not the x86_64 `unlink`, which `std::fs::remove_file` and `tempfile`'s drop issue. A confined monitor was killed by `SIGSYS` on `RunCheck`, on `WriteTarget` of any module with a check, on `ReplaceBinary` that fails verification, on `ConfirmCommit`/`RollbackCommit`, and on startup recovery of a marker (strace: `unlink("...") = 87`, then `killed by SIGSYS`). Owner decision 2026-09-30: fix it in code, no seccomp or Landlock change. `monitor.rs` has one `unlink` (`rustix::fs::unlinkat`) and one drop guard `RemoveOnDrop` (was `StagedCopy`); `create_candidate` builds the `tempfile` candidates with cleanup disabled, so the guard removes them; every other request-time `remove_file` in the file goes through `unlink`. `fs::atomic` already used `unlinkat`. New tests drive a real confined `Role::Monitor` (`Monitor::serve`, a real runner, a worker client): `enforce_mode_monitor_runs_a_check_and_removes_its_candidate`, `..._writes_a_target_that_has_a_check_and_a_backup`, `..._rotates_backups`, `..._restores_a_backup`, `..._removes_the_staged_copy_of_a_refused_release`, `..._clears_the_commit_marker`, `..._removes_a_recovered_commit_marker` (`linux.rs`, root; all seven fail before the fix with `SIGSYS`). The trace found two more legacy calls the table lacks (`chmod` in `ensure_backup_dir`, `rename` in the binary swap); not fixed, listed in `BUGFIX.md` follow-ups.

## 2026-09-30 - B9 follow-up: the confined monitor does not call `geteuid`

The monitor's owner checks (`ensure_staging_dir`, and the staged-input check in `read_staged_verified`) called `geteuid` while serving a request. `MONITOR` does not list it and kills the process, so a confined monitor died with `SIGSYS` on `RunCheck`/`UpdateApply` (strace: `geteuid()` then `killed by SIGSYS`). No table changed. `process_euid` (`monitor.rs`) reads the uid once; `spawn_pair` calls it before `confine_monitor` and `Monitor::new` calls it for an unconfined monitor. The old test `enforce_mode_monitor_runs_real_validators_through_the_runner` missed this because it drives `RunnerClient` directly: no `Monitor` runs and the test makes the staging directory itself. New tests: `enforce_mode_monitor_checks_its_staging_directory_owner`, `enforce_mode_monitor_built_after_spawn_pair_checks_its_staging_directory`. Found on the way, not fixed: `MONITOR` lacks the x86_64 `unlink`, so a confined monitor is killed when `run_check` drops its candidate file (`BUGFIX.md` follow-ups).

## 2026-09-30 - B11b follow-up: the worker may call `geteuid`

`ensure_private` (both audit writers, before each append) asks for the effective uid. `WORKER` did not list `geteuid`, so the confined worker got `geteuid() = -1 EPERM`; rustix treats the call as infallible and panicked, which killed the request thread in `FileAuthAudit::append` (the acme-serve `--forced-renew` step then failed with `curl: (92)`). The owner approved `geteuid` in `WORKER` only (numbers 107 and 175, read from the container headers). `MONITOR` and `ACME` are unchanged. Tests: `enforce_mode_worker_can_tighten_an_audit_directory` (root) and `the_worker_table_allows_geteuid_on_both_arches`. The live proof is the CI `acme-serve` job; the local script run was skipped by orchestrator decision. `SECURITY_HARDENING.md` seccomp row updated.

## 2026-09-30 - Track A B5 (C1-f): capability-user mode documented; Track A closed

ADR-001 (Consequences) and `SECURITY_HARDENING.md` Gaps item 14 now say that in capability-user mode (`User=detent`) the monitor and the worker share one uid, so the owner checks on staged inputs, the monitor staging directory and the audit directories separate nothing; the barriers left are Landlock, seccomp, the worker's capability drop and Sigstore verification. No code change. With B5, all ten Track A items of `BUGFIX.md` are landed; two review follow-ups are listed there.

## 2026-09-30 - Track A B10 (L-BIN18): the typed password is never a plain `String`

`read_secret_line` (`crates/detent/src/webadmin.rs`) turned the typed bytes into a plain `String` and wrapped it in `Zeroizing` only after `trim_newline` returned, so an early return in between left the plaintext in an unwiped buffer. It now wraps the `String` at once and `trim_newline` trims in place (`&mut String`). No other plain `String` of the password remains in `webadmin.rs` (`rg`).

## 2026-09-30 - Track A B11: login documents 503; an existing audit directory is tightened

(a) `POST /api/v1/auth/login` can answer `503` (`web-auth-busy`, `web-auth-session-limit`) but `docs/openapi.json` did not list it. The annotation, `docs/openapi.json` and `web/src/api/schema.d.ts` now list it; `login_documents_the_503_answer` guards it. (b) `DirBuilder::mode` applies only to a directory it creates, so an older `0755` `<state>/audit` stayed `0755`. New `detent_platform::fs::private_dir::ensure_private` opens the directory `O_DIRECTORY | O_NOFOLLOW`, refuses one owned by another uid, and `fchmod`s the descriptor to `0700`. `FileAudit` (`detent-ops`) and `FileAuthAudit` (`detent-web`) call it after they create the directory. Tests: `an_existing_wide_audit_directory_becomes_private`, `a_symlinked_audit_directory_is_refused`, `an_audit_directory_owned_by_another_user_is_refused` in both writers (the owner test asserts root, as the `privsep` tests do), and the helper's own tests.

Follow-up: the owner-refusal test now lives in `detent-platform` `fs::private_dir` and runs as root and unprivileged. The two writer-level owner tests were removed with owner approval, because they needed root.

## 2026-09-30 - Track A B1 (H17 step 5): the Rekor checkpoint is read as a signed note

`verify_inclusion` (`crates/detent-update/src/verify.rs`) read the checkpoint as `<origin> <size>` on one line with `base64(sha256(root))` on the next, and decoded the whole signature field as DER. A real Rekor checkpoint has origin, size and root on three lines and a signature field of `hint[4] || DER`, so no real checkpoint could verify. The new `verify_checkpoint` parses the signed note (`pkg/util/checkpoint.go` and `signed_note.go` in Rekor): size must equal the proof's `tree_size` (the old code took any larger size), the root line must equal the recomputed root (not its hash), and at least one signature line must carry the hint of the embedded Rekor key and verify over the body with its final newline. The hint is the first four bytes of SHA-256 over the key's SPKI DER, with no key name or type byte; a real staging checkpoint confirms it (`d32f30a3`, also the start of the staging `logID`). Lines with another hint are ignored, a matching line with a bad signature refuses, and any malformed line refuses. `gen-fixtures` mints the real format and was rerun (all synthetic fixtures changed; `bad-checkpoint-sig.json` now flips a DER byte behind a correct hint, so it still fails on the signature). `rekor-staging-proof.json` now holds the real staging checkpoint and log key with their pinned sources. Tests: `a_real_staging_checkpoint_verifies`, `a_real_staging_checkpoint_is_bound_to_its_size_root_and_key`, `a_checkpoint_with_other_content_lines_verifies`, `a_checkpoint_of_another_size_is_refused`, `a_checkpoint_of_another_root_is_refused`, `a_checkpoint_with_a_wrong_signature_is_refused`, `a_checkpoint_with_a_wrong_key_hint_is_refused`, `a_checkpoint_without_a_signature_line_is_refused`, `a_checkpoint_needs_a_matching_line_but_ignores_other_keys`. Not covered: the origin is not pinned (the trust root has no origin string), and the real staging `hashedrekord` body embeds the Fulcio certificate while `verify_hashedrekord_body` reads a bare public key, so a real `hashedrekord` entry still fails body agreement (production uses `dsse`).

## 2026-09-30 - Track A B9 (L-PLAT7): the monitor staging directory is checked before use

The monitor made its staging directory with `create_dir_all` and used it unchecked for `RunCheck` and validator candidates. Only `materialize_staged` (`ReplaceBinary`) had a check, by path. `ensure_staging_dir` (`crates/detent-platform/src/privsep/monitor.rs`) is now the one helper for all three: it creates the last component `0700` if missing (parents as before), opens it with `O_DIRECTORY|O_NOFOLLOW`, and requires a directory owned by the monitor euid with no group or other write bit, from `fstat` on that descriptor. An existing directory that fails is refused with `monitor staging directory is not trusted`; it is never chmodded or chowned. Tests: `run_check_refuses_a_world_writable_staging_directory`, `run_check_refuses_a_symlinked_staging_directory`, `run_check_refuses_a_staging_directory_owned_by_another_user`, `run_check_creates_a_missing_staging_directory_private`. The path is still used by name after the check; the directory is monitor-only under a private systemd runtime directory.


## 2026-09-30 - Track A B2 (H17 step 6): unknown Rekor entry kinds are refused

`verify_body_agreement` (`crates/detent-update/src/verify.rs`) took `intoto` as `dsse` and sent every other kind to the `hashedrekord` body check. It now branches on `decoded.kind`: `hashedrekord` and `dsse` keep their checks, and any other kind (`intoto`, `rekord`, `helm`, ...) gives the new `VerificationError::UnsupportedEntryKind`. An `intoto` v0.0.2 body keeps its signature under `spec.content.envelope`, so the `dsse` layout never applied to it. The `intoto` entry in `public_good_set` only feeds `verify_set` and is unchanged. Tests: `body_agreement_accepts_a_dsse_entry`, `body_agreement_refuses_entry_kinds_it_has_no_schema_for`.

## 2026-09-30 - Track A B4 (C1-b): the bundle open and the leftover copy

`verify_release` (`crates/detent-platform/src/privsep/monitor.rs`) read `<tag>.sigstore.json` by path, so a bundle the worker had planted as a symlink was followed, and a FIFO blocked the monitor. It now opens the bundle with `open_staged_input` (the same `openat` walk, `O_NOFOLLOW`, directory owner check, `O_NONBLOCK`, regular-file check as the binary) and `read_bounded_file` reads it from that descriptor, capped by `MAX_BUNDLE_BYTES`. Any refusal answers `VerificationFailed`, and the reason is logged. The digest-named copy in the monitor staging directory was left behind after a failed verify or swap: `replace_binary` now holds a `StagedCopy` guard that removes it on every path (the swap already removes it on success), and `materialize_staged` removes a copy whose write or sync failed. Tests: `replace_binary_refuses_a_symlinked_bundle`, `replace_binary_refuses_a_fifo_bundle_without_blocking`, `replace_binary_leaves_no_copy_after_a_failed_verification`, `replace_binary_leaves_no_copy_after_a_failed_swap`. Not done: a file-owner check on the bundle (`open_staged_input` checks directory owners only, as for the binary); a test needs `chown`, which unprivileged CI cannot run.


## 2026-09-30 - Track A B6 (H1): a monitor without the state lock changes nothing

`lock_state` (`crates/detent-platform/src/privsep/monitor.rs`) returned a `/dev/null` file as the lock when the state directory or lock file gave `PermissionDenied`. `flock` on it excludes nothing, so two monitors could write the same state root at once. The lock is now the type `StateLock::Held(File) | Unavailable`. A monitor served with `Unavailable` (read-only commands such as `detent host` run by a non-root user) answers reads and refuses every request for which `Request::changes_state` is true with the new `ProtoError::StateLockUnavailable` (appended last, so no discriminant moves): `WriteTarget`, `Restore`, `StartConfirmTimer`, `ConfirmCommit`, `RollbackCommit`, `Service` with any action but `Status`, `Mount`, `ReplaceBinary`. Crash recovery of a leftover marker also needs the held lock. `Monitor::lock_exclusive` returns the new `MonitorError::LockUnavailable` instead; `detent serve` (`run_monitor`) and one-shot commands that change state (`Session::start_writing`, chosen by `changes_state(OpKind)` in `run.rs`, not for `--dryrun`) stop at startup with Fluent id `cli-monitor-lock-unavailable`. Read-only one-shot commands and the MCP session still start without the lock. Tests: `a_monitor_without_the_state_lock_refuses_every_state_change`, `a_monitor_without_the_state_lock_still_answers_reads`, `a_monitor_with_the_state_lock_writes`, `a_denied_state_directory_is_an_unavailable_lock_not_an_error`, `lock_exclusive_refuses_an_unavailable_lock_and_keeps_a_held_one`, `the_classifier_lists_exactly_the_state_changing_requests` (`monitor.rs`); `a_missing_state_lock_stops_writing_commands_at_startup` (`run.rs`). A real `EACCES` cannot be produced as root, so the denial is tested at `unavailable_when_denied` and through `StateLock::Unavailable`.

## 2026-09-30 - Track A B8 (H12): MCP HTTP transport refused when the process holds capabilities

`mcp --transport http` was refused only for euid 0, so a non-root process with `CAP_DAC_OVERRIDE` (ambient or file capabilities) still ran the network parser with root-like power. `http_transport_allowed(euid_is_root, holds_caps)` (`crates/detent/src/mcp.rs`) now also refuses when `detent_platform::sandbox::holds_capabilities()` is true: the effective or permitted set is not empty, or the read failed (fail closed); non-Linux reports `false`. The refusal keeps `cli-mcp-http-needs-privsep` and `Exit::Privilege`; the English text now says "as root or with capabilities". Tests: `http_transport_refused_for_a_non_root_caller_holding_capabilities` (detent), `capability_read_fails_closed_and_reports_any_non_empty_set`, `root_in_the_container_holds_capabilities` (detent-platform).

## 2026-09-30 - Track A B7 (H2): a failed commit-confirm arming restores the write

`OpsEngine::apply` (`crates/detent-ops/src/engine.rs`) wrote the target, then returned at once with `?` when `start_confirm_timer` failed, leaving the new contents on disk with no window and no rollback. It now calls `undo_write`: it lists the module's backups, picks the newest one of that target whose digest equals the write's `prev_digest`, and asks the monitor to `Restore` it (existing messages only; no wire change). The error is the new `OpsError::ArmFailed { arming, restore_error }`, with Fluent ids `ops-arm-failed-restored` and `ops-arm-failed-unrestored` (core.ftl, web.ftl, `web/src/api/messages.ts`). A write with no backup cannot be undone and reports `NoBackup` as the restore error. The `NoBackup` refusal and the service-failure `discard_commit` path are unchanged. Tests (`crates/detent-ops/tests/engine.rs`, a proxy between the engine and the real monitor plants the errors): `a_failed_arming_restores_the_previous_contents`, `a_failed_arming_reports_a_failed_restore_too`. Coverage follow-up: `a_failed_arming_after_a_write_with_no_backup_cannot_restore` covers the `NoBackup` branch of `undo_write` (backups off, so the write makes none; the new contents stay), which CI Coverage needs for the `detent-ops` 100 % floor.


## 2026-09-27 - OFFLOAD T4 follow-up: `detent cert status` exits Failed for a bad certificate

Owner decision: scripts and monitoring need a non-zero exit, not just the printed report, to notice a dying certificate. `cert_status` (`crates/detent/src/cert.rs`) now reads `CertReport::not_after_unix` (`crates/detent-ops/src/report.rs`, filled in by `detent_web::api::system::cert_report_for_der`) and compares it against `time::OffsetDateTime::now_utc()` — the same clock source that function uses to build the report — right after building it: `None` (the DER did not parse) or `now >= not_after` exits `Exit::Failed`; otherwise `Exit::Ok`. The report (text and `--json`) still prints in full either way; only the exit status changed. `a_garbage_pair_renders_unknown_validity` asserted `Exit::Ok` for an unparseable pair — that is exactly the case this decision covers, so its assertions moved to `Exit::Failed`. New test `an_expired_pair_still_prints_but_fails` (dated pair, 2000-01-01..2000-02-01) covers the expired case in both text and JSON. Existing ACME/bootstrap and the 55 %/80 % renewal-window warning tests are unchanged (still `Exit::Ok`, not expired). Gates: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo clippy -p detent --all-targets -- -D warnings`, `cargo clippy -p detent --no-default-features --all-targets -- -D warnings`, `cargo test -p detent --all-features --no-fail-fast` (as root) all clean/passing (264 + 18 tests, 0 failed).

## 2026-09-27 - Phase 6 W1: the worker's audit writers can fdatasync (STAGE4 4.3 item 5, slice W1)

Closes the gap slice S2 left open. Both audit writers the confined worker runs — `FileAuthAudit::append` (`crates/detent-web/src/auth/audit.rs`) and `FileAudit` (`crates/detent-ops/src/audit.rs`) — call `File::sync_data()` (`fdatasync`) after each record; the `WORKER` seccomp table (`crates/detent-platform/src/sandbox/seccomp.rs`) allowed `fsync` but not this data-only form, so a confined worker's every audited write failed the ops engine's intent record (`EPERM`, seen live as `fdatasync(14) = -1 EPERM` after `POST /api/v1/system/cert/renew`). Added `fdatasync` to `WORKER` (numbers 75/83, read from this container's `<asm/unistd_64.h>`/`<asm-generic/unistd.h>`, matching the C4/S2 rows' provenance). New root test `enforce_mode_worker_can_fdatasync_a_state_root_file` (`sandbox/linux.rs`): writes a file under the state root under the enforced `Worker` filter and calls `sync_data()`; failed before the fix (the forked child exited 1: `sync_data()` returned `Err`). `scripts/acme-serve-check.sh` gains `--forced-renew` (requires `--expect-renewal`): after the scheduled renewal, it mints a write-scope token as the worker account (`token create --write`, never printed), sends `POST /api/v1/system/cert/renew`, and checks the `202` answer, the new `cert_renew_requested` auth-log record, the `MIN_FORCED_INTERVAL` "too soon" log line (needs `RUST_LOG=info`; `run.rs` defaults to `warn`), and that the worker's `fdatasync` calls all succeed. `ci.yml`'s `acme-serve` job now passes `--forced-renew`. MONITOR and ACME were traced in the same run (owner decision: report only, do not add): neither ever calls `fdatasync`; neither table changed. Local end-to-end run (native BIND 9.18, Pebble v2.10.1 built from source, image pulls blocked as before, `--expect-renewal 240 --forced-renew`): full PASS, 13/13 checks including the renewal and the new operator-request block. Traps hit and fixed along the way (worth keeping for the next local run): the `<pebble-ca-file>` argument must be Pebble's *static* `test/certs/pebble.minica.pem` (it signs Pebble's own `:14000` HTTPS listener cert) — the per-run root Pebble prints at startup / serves at `/roots/0` only verifies certificates Pebble *issues*, not its own directory endpoint, and using it makes the acme process fail with `client error (Connect)`; any file the `detent` account must read (the CA copy, BIND's config) needs to sit somewhere it can traverse to — a `0700` root-owned directory blocks it even if the file itself is `0644`; and the forced-renew `curl` must pass `--noproxy '*'` (a loopback request to a synthetic `--resolve`d hostname otherwise goes through this environment's HTTP(S) proxy and gets reset) and skip TLS verification (`-k`, like the script's existing `openssl s_client` leaf checks — the check exercises the API and the audit trail, not the chain).

## 2026-09-27 - OFFLOAD T4: `detent cert status` (read-only)

`detent cert status` (web feature, `--json` flag) reads the served pair with `detent_web::serving_pair(&config.tls.cert_dir)`: source is `acme` when a stored ACME pair matches the served fingerprint else `bootstrap`; fingerprint, RFC 3339 `not_after`, lifetime-used percent and warning come from shared `detent_web::api::system::{cert_report_for_der, not_after_rfc3339}` (same fns as `GET /api/v1/system/cert`). Missing store or unreadable dir exits Failed with a localized note; key bytes never print. Tests cover ACME/bootstrap text+JSON, missing dir, unreadable path, bad config, garbage DER unknowns, 55 %/80 % warnings.

## 2026-09-27 - Phase 6 S2: the running server renews a short-lived certificate (STAGE4 4.3 item 5, slice S2)

`scripts/acme-serve-check.sh` gains `--expect-renewal <secs>`: after the first Pebble-issued leaf is served, it records that leaf's SHA-256 fingerprint and `notAfter`, then waits (bounded by the option) for the listener to serve a *different* Pebble-issued leaf for the same SAN with a later `notAfter`, with no restart of `serve`; it fails if the old leaf expires first or time runs out. `ci.yml` job `acme-serve` now configures Pebble with one `default` profile (`validityPeriod` 180 s — an order with no `profile` field otherwise gets a random pick among the configured ones, so a single profile keeps the lifetime deterministic) and calls the script with `--expect-renewal 240`; slice S1's due-time scheduling (2/3 of a 180 s lifetime, ~120 s) is what makes the server renew inside that window. Pebble's `certificateValidityPeriod` (top-level) is dead code in the pinned image (v2.10.1, confirmed by building `ghcr.io/letsencrypt/pebble@sha256:ddf23064…` digest's source, since the digest was never repinned since C4): only `Profiles.<name>.ValidityPeriod` (`ca/ca.go`) is wired in. A real renewal is a *second* install into `cert_dir` (the first C4 run only ever installed once), which exercises `write_atomic`'s replace-an-existing-file path for the first time under this check: it tries `fchown`/`flistxattr`/`fgetxattr`/`fsetxattr` to preserve the old file's owner and xattrs, which a non-root worker cannot do — `EPERM`, already handled by the code (`owner_preserved = false`, `xattr_unsupported`) as "cannot, so skip", not a failure. `TOLERATED_WORKER_EPERM` in the script now names these four, with the same reasoning as `access`/`prctl`. Local end-to-end run (native BIND 9.18, Pebble v2.10.1 built from source, both image pulls blocked as before): full PASS, including the renewal (notAfter moved from a first leaf to a later one, no restart) and the rest of C4's checks (four processes, confinement, SIGTERM, EPERM). The operator-request half of this slice (`POST /api/v1/system/cert/renew` against the running server, expecting the `MIN_FORCED_INTERVAL` "too soon" log line) was tried and dropped: minting and using a write-scope token makes the worker's auth-audit write call `fdatasync` (`File::sync_data`), which the `WORKER` seccomp table does not list — confirmed live (`fdatasync(14) = -1 EPERM`), unlike the tolerated calls above, this one is a genuine gap (no code path treats it as expected). Adding it is a Rust change, out of this shell/CI-only slice's scope; left open. Next: add `fdatasync` to `WORKER` (`crates/detent-platform/src/sandbox/seccomp.rs`) and revisit item 3 (CLI/UI renew). Traps: `RUST_LOG` defaults to `warn` (`run.rs`), so `tracing::info!` lines (e.g. the "too soon" line) never reach `serve.log` unless a caller sets it; a renewal is a second install, which needs `TOLERATED_WORKER_EPERM` above or the job's own EPERM check fails.

## 2026-09-27 - Phase 6 S1: schedule the next check by the due time (STAGE4 4.3 item 5, slice S1)

After a round the loop no longer always sleeps `CHECK_INTERVAL` (1 h): `next_check` (`detent/src/acme.rs`) takes the earlier of `CHECK_INTERVAL` and the time until `detent_acme::due_at` (new, `schedule.rs`) says the served or new certificate is due — the start of the ARI window when one is known, else two thirds of its lifetime — floored at a new `MIN_CHECK_INTERVAL` (1 min, matches `FIRST_RETRY`) so a due certificate whose install keeps failing is not polled without bound. `Outcome::Renewed` and `Outcome::NotDue` now carry the `not_before`/`not_after` (and, for `NotDue`, the ARI window) the loop needs; `Held` gained `not_before` for the same reason. Backoff after a failure is unchanged. Logged at `tracing::debug!` (fires every round). Closes the trap that blocked slice S2's short-lived-CA CI test: a 5-minute certificate is now rechecked near its own due time (about 198 s), not after a full hour.

## 2026-09-27 - OFFLOAD T3: renew-now button on the Certificates page

`useRequestCertRenew` (`web/src/api/system.ts`) posts to `POST /api/v1/system/cert/renew` and invalidates the cert query on `202`. The Certificates page shows a "Renew now" panel gated on write scope (`useWriteGate`, disabled with reason otherwise, disabled while pending): success shows `cert-renew-requested`, errors show the localized server message (`web-cert-renew-not-acme`, `web-cert-renew-unavailable`) via `useApiErrorMessage`. Audit page needs no change: `audit-op-cert-renew` for the `cert_renew` op already exists and is tested. Tests cover read-only gating, 202 + refetch, 409, 503, and pending-disabled.

## 2026-09-27 - OFFLOAD T2: root-proof webadmin write-failure test

`setup_with_force_reports_a_write_failure_as_a_credential_failure` swaps `users.json` for a symlink to a saved copy: `load` reads through the link, `create` reports `UserExists`, and `set_password`'s atomic write refuses the link (`AtomicError::Symlink`, never follows symlinks for any user including root). Keeps name, `Exit::Failed`, and the credential-failure note. Removed the §1.4 known-state sentence in the same commit.

## 2026-09-27 - OFFLOAD T1: CLI-only build clippy errors

T1 reproduce gate passes: `cargo clippy -p detent --all-targets --no-default-features --features module-hosts,init-systemd -- -D warnings` reports no issues. `failed()` test gated on `update`; the two `mut` bindings restructured so `#[cfg(feature = "update")]` selects elements, not statements. Two more tests needed the same gate for this feature set (found by running the gate, not named in the task): `update_operation_maps_without_side_effects` (no `update` subcommand) and `a_cli_apply_on_a_commit_confirm_module_never_leaves_an_unenforced_commit` (no `network` module). Feature tests pass: 105 + 7. Traps: `git stash` in this repo risks 79 unrelated stashes; verified via an isolated worktree instead.

## 2026-09-27 - Phase 6 R2b: rate-limit "renew now" (STAGE4 4.3 item 2)

Closes the first R2 trap below. `MIN_FORCED_INTERVAL` (one hour) gates a forced order: `renew_once` skips a `RenewNow`'s order and falls back to the ordinary due check when one was already ordered inside the interval, logging the last order time and the next allowed one; a due renewal is never gated by this. `run_loop` tracks `last_order` (set on every successful `issue()`, install or not) across rounds. Separately, a `RenewNow` that arrives while the loop is in a backoff wait after a failure no longer cuts that wait short: it is logged and the same full delay is waited out again; only the round after the backoff is forced (and still subject to the interval). A held pair is retried regardless of either rule, since a retry is not a new order.

## 2026-09-27 - Phase 6 R2: "renew now" end to end on the server (STAGE4 4.3 item 2)

`POST /api/v1/system/cert/renew` (write scope, CSRF, `Operation::CertRenew`) sends `RenewNow` through the worker's `AcmeRenewer` and answers `202 {"requested": true}`; `409 web-cert-renew-not-acme` without an acme process, `503 web-cert-renew-unavailable` when the channel is closed. Each answer after authorization writes one `cert_renew_requested` record to the auth log (`detent-auth.jsonl`): the engine cannot write the ops audit for an operation it does not run. `spawn_installs` splits the worker's end once (`acme_link`): the server half goes to the install thread, the renewer into `AppState` (`with_cert_renewer`, trait `detent_web::CertRenewer`). In the acme process, a readable channel during the wait is read (`next_request`): `RenewNow` starts a forced round at once (it renews a certificate that is not due; a held pair is installed first), EOF ends the loop, anything else ends it with a warning. A `RenewNow` recorded during `hello` or an install forces the next round, with no wait. The engine keeps `CertRenew` `Unsupported`, so the MCP tool `cert_renew` still answers `ops-unsupported`. Next: `detent cert renew` and the UI button (item 3). Traps: a second `RenewNow` that arrives during a round's order (not during its install) stays in the socket and starts one more forced round — at once if that round succeeded, or only after its backoff wait if it failed (R2b, above).

## 2026-09-27 - Phase 6 C4: `detent serve` gets and serves a Pebble certificate, confined

`scripts/acme-serve-check.sh` (CI job `acme-serve`: BIND 9 and Pebble by digest, TSIG key made per run) runs `detent serve` as root under `strace -ff` with `tls.bootstrap = "acme"` and the RFC 2136 provider. A local end-to-end run (x86_64 glibc, native BIND 9.18 with the script's config, Pebble v2.10.1) passes: the listener serves a leaf issued by `Pebble Intermediate CA` with `DNS:serve.detent.test`; the acme process runs as `detent` with `NoNewPrivs`, `Seccomp: 2` and Landlock; SIGTERM to the process group of `serve` (as systemd's KillMode=control-group) ends all four processes (the monitor ends by SIGTERM; it has no handler, by owner decision); no EPERM in the acme process or the worker outside the tolerated calls. Fixes the run needed: `start_acme` creates the credentials directory before the fork (Landlock skips a missing path); the RFC 2136 exchange bounds `connect` on a thread, because `TcpStream::connect_timeout` issues `ioctl(FIONBIO)`, which `ACME` refuses; MONITOR gains `mkdir` and `flock` (the monitor was killed by SIGSYS on every x86_64 start), WORKER gains the x86_64 legacy forms `mkdir`, `chmod`, `unlink`, `open` and `epoll_wait`, each proven by the trace. Tolerated EPERM: acme `access("/sys/devices/system/node/node1")` (mimalloc); worker the same and `prctl(PR_SET_NAME)`. Next: the job on a real runner (`workflow_dispatch`), and the aarch64 run. Traps: strace pads `= 0` with spaces; the monitor's children stay zombies after it dies in a container without a reaper.

## 2026-09-26 - Phase 6 C3c: `serve` starts the acme process (ADR-015)

With `tls.bootstrap = "acme"`, preflight checks the `[acme]` settings and that the credentials directory and `tls.cert_dir` are under the state root, and keeps the provider it builds (the secret is read as root before any fork). `run` forks the acme process after the runner and before the pair (`start_acme`, `fork_acme`): the child drops the runner handle and the configuration, the parent drops the provider. The worker answers on a thread once its `CertStore` exists; the monitor drops its end and reaps the process last. The wait between rounds ends when the worker closes the channel (`wait_or_peer`). Next: C4 (CI Pebble job runs `serve`'s acme process under real confinement; `strace -f` proof of the `Acme` table). Traps: the credentials directory must exist and be writable by uid `detent` before start (Landlock skips a missing path); the acme `Hello` times out after 60 s if the worker is slow to bind.

## 2026-09-26 - H17 core: Rekor body leaf and SET verification (STAGE4 4.2 item 1)

The Merkle leaf is now `SHA-256(0x00 ‖ canonicalizedBody)`, and step 6 verifies the Rekor SET (`inclusionPromise`, now required) with the embedded Rekor key over the RFC 8785 JSON `{"body","integratedTime","logID","logIndex"}`. This closes the 2026-09-25 SET gap below: `a_forged_integrated_time_is_refused` now fails with the SET check removed. Real Rekor vectors check both formats: a public-good SET (`rekor-public-good-set.json`, from sigstore-go) and a staging inclusion proof (`rekor-staging-proof.json`, from sigstore-python). The old `bad-set.json` is now `bad-inclusion-path.json`; the new `bad-set.json` carries a SET from another key. All fixtures were re-minted. `a_v03_single_certificate_bundle_passes` covers the `verificationMaterial.certificate` form. `h17-set-partial.patch` is deleted.

Still open in H17: step 1 (`release.yml` ships a cosign messageSignature bundle), step 5 (the checkpoint is not parsed as Rekor's signed note), step 6 (unknown kinds fall through to hashedrekord), step 7 (placeholder trust files, no Fulcio intermediate), step 8 (a captured real release bundle needs a release tag). Rekor v2 entries carry no SET and would be refused.

## 2026-09-26 - STAGE3 PARTIAL items closed

40 commits (`e9d209c`…`8117bda`) close the §11.9 PARTIAL items, the vacuous
tests and the §12 follow-ups: STAGE3 §11.10 has the table and the short
"Still open" list (owner, testhost or Phase 6). Highlights: Rekor SET and
RFC 6962 leaf verified against real Rekor data (H17); chrony, dnsmasq and
network apply are linear (M21); the engine checks web/MCP scopes and audits
denials (M4); a torn audit line no longer blocks mutations (M3); rollback
keeps edits made in the confirm window (M7). Allow count 111. The build
setup (sccache, mold, Cranelift) is per machine: `docs/TOOLS.md`.

## 2026-09-25 - STAGE3 REOPEN items closed; ARCHITECTURE.md

All nine REOPEN items from the §11.9 verification pass are fixed, each test
first: M23 `977f942`, M8 `0a11fb6`, M25 `f044538`, L-OPS17 `7587e2e`
(missing target refused as `ops-target-missing`), L-WEB16 `6c59a65`
(sweeper started on the serve runtime), H9 `dcfdb0d` (first request within
the header timeout), H23 `9737985` (deny-list rebuilt in
`privsep/exec_deny.rs`), H6 `73e7c88` (validators and service commands run
in an unconfined **runner** forked before the monitor confines itself).
`docs/ARCHITECTURE.md` added for security auditors. SECURITY_HARDENING
updated for each change, and its stale "capability drop fails open" claim
corrected (`require_caps` is on for the monitor). Allow count 113.

## 2026-09-25 - H20 fuzz: network interface order is a validation error

Owner decision (2026-09-25): `validate` flags interfaces that are not in name order (`network-interface-order`, Error). `to_model` reads interfaces back sorted by name, so only a sorted model survives apply unchanged (invariant 3). The fuzz edit target skips models with validation errors, so this closes crash `2c880b5d…` (interfaces `[XXXXXXXXX, Pl]`). UI/API consequence: a client must send interfaces in name order, or it gets this error.

Verify: `interfaces_out_of_name_order_are_an_error` failed before the fix (no diagnostic) and passes after. `cargo test -p detent-module-network --all-features` 54 + 22 passed; the crash input exits 0; `fuzz_network_edit`, `fuzz_network_roundtrip` and `fuzz_network_parse` each ran 120 s clean. `bun run i18n:check` OK (272 ids). Workspace `cargo test --all-features --no-fail-fast`: 1911 passed, 1 failed (the known uid-0-only webadmin test).

## 2026-09-25 - H20 fuzz: network round-trip losses fixed

A local run of all 29 fuzz targets for 60 s each at `675aca2` (as CI does) failed only `fuzz_network_edit` and `fuzz_network_roundtrip`. The CI artifact and full log were out of reach from the cloud container. Fixed in `crates/modules/network/src/lib.rs`:
1. **Bridge lost silently.** networkd and NM renderers dropped `bridge`, and `networkd_round_trips` stripped bridges before comparing. Now networkd and NM refuse a bridge, ifupdown refuses a memberless one, and the round-trip check (`round_trips`) keeps bridges. User-visible: a bridge edit on networkd/NM returns `Unsupported` instead of vanishing.
2. **Own model lost on a mixed document.** The no-op shortcuts built the model from directive lines only, but `to_model` reads all lines. `apply` now returns an empty report when `to_model(doc) == model`.
3. **(fuzz round 1)** ifupdown `iface X inet6 dhcp` also set `dhcp_v4`. The family now comes from the third word.
4. **(fuzz round 2)** The positional path had no round-trip check. It now restores the document and refuses with `Unsupported` when the result would not read back as the model.

Open, owner decision (§12): `to_model` returns interfaces sorted by name, so a valid model not in name order fails invariant 3 (fuzz crash `2c880b5d…`, source `"— nnnw"`, interfaces `[XXXXXXXXX, Pl]`). This predates this session.

Verify: regression tests `a_bridge_is_refused_where_the_backend_cannot_hold_it`, `a_mixed_document_applies_its_own_model_as_a_noop`, `an_inet6_dhcp_stanza_enables_only_dhcpv6`, `a_positional_edit_that_would_not_round_trip_is_refused` each failed before its fix. `renderers_round_trip_vlan_bridge_routes_per_backend` now expects `Unsupported` for the lossy cases and exact model equality for NM. `cargo test -p detent-module-network --all-features` 53 + 22 passed; clippy and fmt 0; lib.rs 3005/3005 lines covered. All four crash inputs exit 0; 120 s runs clean for roundtrip (722,508 runs) and parse (1,873,515 runs). Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - H20 crates/modules back to 100%; last new suppression removed

- `bb2f054`: removed the nfs trailing-`\` checks in `render_line` and `validate_client`. Earlier checks there already refuse any `\`, so they could never fire. `validate_export`'s reachable check stays.
- `1a5eb24`: split `apply_networkd_sections` into helpers and removed its four-lint `#[allow]` (added by `2febdc8`, H16). The helpers are `edit_networkd_sections` (returns `Result`, so the three unreachable `Err` arms became `?`), `networkd_scopes`, `pair_by_scope`, `splice_surplus`, `networkd_round_trips` and `commit_lines`. Behaviour is unchanged. Allow count 115 → 114.
- This commit: `render_netplan_without_a_plain_ethernet_writes_no_ethernets_key`. The last uncovered module line was the implicit "no ethernets" path of `render_netplan`. It was a real untested case, not a tool artifact.

Verify: full CI-shaped coverage run (clean, workspace `--skip sandbox::linux::tests`, root sandbox run, merge): core, i18n, ops, modules 100.00%; platform 92.56; web 97.75; detent 95.23 (measured as root); acme 87.10. `PASS: all coverage thresholds met`. `cargo test -p detent-module-network --all-features` 49 + 22 passed.

## 2026-09-25 - H20 core, i18n and ops coverage back to 100%

Tests only. detent-core, detent-i18n and detent-ops reach 100% line coverage. What the tests cover:
- Conformance: the invariant-5 branch where a refused probe leaves text that does not re-parse.
- Audit chain verify errors: invalid JSON, missing chain metadata, a broken link, a non-NotFound IO error.
- Audit record and query edge cases: an empty existing log, a path with no parent, `limit: Some(0)`.
- The engine's `CheckFailed` refusal.
- Network apply arms: the positional editor, headerless networkd directives, unpaired removal, the lossy-reorder refusal, netplan with and without extras.

Two assertions in tests were re-wrapped so their message arguments are not on separate never-run lines; each is the same assertion as before. crates/modules is at 99.89% (11356/11368). The remaining 12 lines: nfs dead continuation checks (§12 follow-up), three unreachable `Err` arms in `apply_networkd_sections`, and one closing brace that llvm-cov attributes oddly.

Verify: tests of the four touched packages 287 passed; fmt 0; clippy (four packages) `-D warnings` 0. Implementor: Sonnet subagent; orchestrator reviewed the diff (all hunks in test modules).

## 2026-09-25 - H20 detent crate coverage back over the floor

`crates/detent/` read 91.09% against its 95% floor. New tests, and no production change, bring it to 95.42% (7440/7797) in the full CI measurement, measured as root. CI measures unprivileged, which trades a few root-only lines for the MCP HTTP serve path; all new tests pass as uid 65534. What the tests cover:
- MCP startup refusals: missing, empty or unreadable token store; corrupt commit marker.
- MCP pending-commit recovery on startup.
- MCP stdio and HTTP end to end, including the bearer gate, busy refusal and SIGTERM.
- The MCP executor's scope and dry-run behaviour.
- One-shot command start failures.
- `update` refusing closed without a trust root.
- Restart health checks.
- The terminal password prompt and echo guard on a real pty. A dev-only `rustix` `pty`/`termios` feature was added; `Cargo.lock` is unchanged.

The orchestrator removed one delivered test, `serve_as_root_without_the_worker_account_refuses_before_forking`. It returned early when not root, so in CI it would pass without asserting anything (D2). Still uncovered: the real serve fork, which confines the process irreversibly; `run_update` after the trust root, which is unreachable while `trust::embedded()` refuses; the service restart step; and stream-write `?` lines.

Verify: `cargo test -p detent --all-features --no-fail-fast` 183 unit passed (1 known uid-0-only failure) + 18 integration passed; as uid 65534 all pass (implementor run). fmt 0; clippy `-p detent --all-targets --all-features -D warnings` 0. Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - H20 detent-web coverage back over the floor

detent-web read about 95.7% on Linux against its 97% floor. 25 new tests, and no production change, bring it to 97.75% (9097/9306) in the full CI measurement. The tests cover: secret redaction in module views, scope refusal plus its audit record, pending-commit, commit, backup and service routes through the full stack, malformed module ids, update-check stamps, user and token store refresh after external edits (deleted file, directory in place of the file), redacted `Debug` for user and token records, TLS pair framing errors, legacy two-file bootstrap and ACME chains, rotation of an unparseable bootstrap cert, and GeneralizedTime / misshapen validity parsing. Still uncovered: failure arms inside tests, the already-ignored timing test in `password.rs`, and the live release-feed check. Noted: `UserStore::refresh_locked` is dead code behind an existing `#[allow(dead_code)]` (§12).

Verify: `cargo test -p detent-web --all-features` 340 lib (2 ignored, both pre-existing) + 9 tls passed; lib as uid 65534: 340 passed. fmt 0; clippy `-p detent-web --all-targets --all-features -D warnings` 0. Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - L-MODA12 module template is instantiated and tested in CI (STAGE3)

The finding's premise is out of date: `_template` has been a workspace member (`detent-module-template`) since the exclude was dropped, so it compiles and tests with the workspace. The README still said it was excluded. What was really broken: the copy recipe kept the package name `detent-module-template`, so every copy failed with "two packages named `detent-module-template`". The recipe now also renames the package and crate names. `scripts/template-check.sh` (`--id`, `--keep`, `--dryrun`, `--verbose`) runs the recipe on a `git archive` copy of HEAD and checks the copy with fmt, clippy `-D warnings` and tests. CI runs it in the Rust job. The template's `render_line` TODO now says to reject every character the upstream parser treats as syntax, not only line breaks.

Verify: the old recipe failed with the duplicate-package error. `scripts/template-check.sh -v` now passes (copy: 28 unit + 16 conformance). shellcheck 0; `shfmt -d -i 2 -ci` 0; `cargo test -p detent-module-template --all-features` passes.

## 2026-09-25 - L-MODB7 network conformance: routes, probes, renderer refusals (STAGE3)

The two no-op `prop_filter`s are gone. The model strategy now generates 0–2 routes with a family-matched `via`. There are 21 new injection probes: route `to`/`via` with `;`, `$( )`, whitespace, `#`, `"`, `[ ]` and `=`, plus address, DNS, gateway, name and VLAN-link probes. Before the fix, `route_to_probe("0.0.0.0/0; reboot")` was accepted by networkd, netplan and ifupdown (`invariant_5_injection_probes_are_rejected` failed). Every other field probe was accepted too. The renderers now refuse bad values themselves: `check_route` checks that `to` is `default`, a CIDR or an IP, and that `via` is an IP (required on ifupdown's shell `up ip route add` line). `check_interface` enforces name, VLAN-link and bridge-member charset, CIDR addresses, per-family gateways and IP DNS servers. The line-break check runs first, so `\n\r\0` still map to `LineBreakInValue`. Render-before-mutate still holds. A file that already holds a refused value and equals the model is a no-op (invariant 2).

Finding: L-MODB8 was marked done, but `render_nm` silently dropped routes. It now returns `Unsupported`, and the NM case of `renderers_round_trip_vlan_bridge_routes_per_backend` asserts that. Follow-ups (§12): `validate` does not flag the new name rule; a leading `-` in a name is allowed; `is_valid_cidr` accepts `+24`; a `vlan_id 0` document may break invariant 2 (unverified).

Verify: `cargo test -p detent-module-network --all-features` 43 unit + 22 conformance passed; clippy `-p detent-module-network --all-targets --all-features -D warnings` 0; fmt 0. Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - M16 verifier negative fixtures and honest SCT/SET claims (STAGE3)

`gen-fixtures` mints `bad-body-sig` and `bad-body-key`. Each is a tlog body that disagrees with the envelope, with the inclusion proof and checkpoint valid over that body, so only body agreement can refuse it. It also mints `wrong-digest` (a validly signed bundle for another file). `bad-sct` is renamed `bad-checkpoint-sig`, which is what it corrupts. The rename landed by mistake in `216d326`; this commit updates its references. Existing fixture bytes are unchanged; the three new fixtures chain to the committed root. PLAN §2.9 and ADR-014 no longer claim SCT signature verification or Rekor SET verification. They now state what is checked: SCT list presence, inclusion proof plus signed checkpoint, body agreement, and statement digest.

Gap (open, H17): a forged `integratedTime` is refused today only because the verifier hashes the whole tlog entry as the Merkle leaf. Real Rekor hashes the body only, and there only the unverified SET binds `integratedTime`. `a_forged_integrated_time_is_refused` pins today's behaviour and names the gap. Also noted: `bad-set.json` corrupts a path hash and has nothing to do with a SET, and ADR-014 step 6 says "certificate hash" where the code compares public keys.

Verify: with `verify_body_agreement` made to return `Ok(())`, both body tests fail (`left: Ok(()) right: Err(SetInvalid)`); restored, they pass. `cargo test -p detent-update --all-features` 64+3+1+18 passed; clippy `-p detent-update --all-targets --all-features` 0; rustfmt check 0. Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - H20 detent-platform coverage back over the floor

The Linux coverage gate failed with detent-platform at 89.74% (floor 92%). 45 new tests, and no production change, lift it to 92.56% (7224/7805) in the CI measurement: a workspace llvm-cov run with `--skip sandbox::linux::tests`, then the root sandbox run, then `coverage-merge.sh`. The tests cover: monitor write refusals (external check reject/fail, missing parser, non-UTF-8, parse/validate errors, target is a directory), new-execution-directive detection for every module, commit-marker state errors, crash recovery (binding gone, non-mutating or no-longer-allowed action, real restore), rollback with a failing service replay (deadline and exit), staged-image checks (missing, symlink, hard link, group-writable dir, wrong length/digest), `materialize_staged` refusals, `replace_binary` refusals, `swap_running_binary` refusals, and three worker response mismatches. The floor is unchanged. Still uncovered: confined-child code in `sandbox/linux.rs` (ratchet note), tracing field lines, and I/O failures that cannot be forced as root.

Verify: `cargo test -p detent-platform --all-features` 299 lib passed plus the integration suites; the lib binary as uid 65534 with `--skip sandbox::linux::tests`: 290 passed. rustfmt check 0; clippy `-p detent-platform --all-targets --all-features -D warnings` 0. Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - M20 aligned entry edits (STAGE3)

The Myers diff moved from `detent-ops` into `detent_core::align` (generic `align<T: PartialEq>`, `Step`, `MAX_EDIT_DISTANCE`, fallback `replace_all`); `detent-ops::diff` now calls it. `Document::plan_entries` / `apply_plan` / `edit_entries` (detent-core `doc.rs`) align the model with the existing entry lines. Unchanged lines stay byte-identical and in place. A changed entry is rewritten in place. A deleted entry loses its line. A new entry goes after the previous kept entry, in the same section. A new section header goes at the end of the previous section. Rendering and the line-break check run before any edit, and the document is normalised once through `rebuild` (M21). hosts, samba, nfs, mounts, resolver and `_template` use it. The resolver's `plan_slot`/`Planned` are gone, and the unbound "misplaced" finding is now `Severity::Error`. Past the edit-distance cap the plan falls back to positional pairing. chrony, dhcp (dnsmasq) and network moved to it later under M21; the networkd section-aware edit builds its own `EntryPlan`.

Verify: `hosts dropping_the_first_entry_rewrites_no_other_line` (before: changed_lines 2), `samba deleting_a_directive_does_not_move_later_directives` (before: changed_lines 3), `resolver an_appended_hardening_entry_lands_in_server` (before: changed_lines 2) failed before the fix and pass after. 21 new core tests for `align` and the helper. Removed: resolver `plan_slot_*` tests (the function is gone; replaced by `apply_aligns_each_flavor_with_its_own_lines` and `a_refused_flavor_leaves_every_flavor_untouched`). `cargo fmt --all --check` 0; clippy on the eight touched packages `--all-features -D warnings` 0; their tests 523 passed, 0 failed. Implementor: Opus subagent; orchestrator reviewed the diff.

## 2026-09-25 - H20 size baseline re-cut

CI Size check failed on `full-default-aarch64-musl`. Measured locally with the CI pins (`cargo-zigbuild` 0.23.2, zig 0.16.0, Rust 1.98.1): full 5,272,560; full+ui 6,092,784; resolver+web 4,757,616; CLI-only 2,104,824 (after the C1-c `update` gate). The oldest commit in this repository, e4713de, already builds to 5,225,520 (full) and 3,015,088 (CLI), so the growth over the 2026-09-10 baselines predates STAGE3 and the squashed history cannot attribute it. Owner approved the re-cut (2026-09-25). Full, ui and CLI rows re-cut; tolerance stays 3%; the PLAN §4.1 budgets are unchanged, and every row is under its budget. resolver+web is within tolerance and was not changed.

## 2026-09-25 - C1-c verifier behind a detent-platform `update` feature (STAGE3)

C1-c made the monitor verify the Sigstore bundle, so `detent-platform` linked `detent-update` → `rustls-webpki` → aws-lc-rs in every build, including the CLI-only build with no self-update. The CLI-only aarch64-musl binary grew to 3,064,368 bytes (baseline 1,712,952; budget 3 MiB). Owner decision (2026-09-25): gate the verifier. `detent-platform` now has an `update` feature (`dep:detent-update`); `detent`'s `update` feature enables it. The monitor's bundle check moved into `verify_release`: with `update` it runs the same check as before; without it, every staged release is refused (`VerificationFailed`, fail closed). The downgrade check and staging code are unchanged. CLI-only binary: 2,104,824 bytes, and aws-lc-rs is no longer in its tree.

Verify: `privsep::monitor::tests::a_build_without_the_update_feature_refuses_a_valid_release` (default features) passes, and fails when the stub returns `Ok(())`. CI runs it in a new step, because `--all-features` links the verifier. `cargo fmt --all --check` 0; workspace clippy `--all-features` 0; clippy `-p detent-platform` (no features) 0; clippy CLI-only feature set 0; `cargo test -p detent-platform --lib` 252 passed; `cargo test --workspace --all-features --no-fail-fast` 1759 passed, 1 failed (uid 0 only, see L-SUP13 entry).

## 2026-09-25 - L-SUP13 inclusion path cap (STAGE3)

`bundle::parse` refuses an inclusion path longer than `MAX_INCLUSION_PATH` (64) before it decodes any hash (`decode_path`). `root_from_path` already refused `index >= size` and a non-empty path at size 1 (`root_from_path_singleton_rejects_extra_nodes`); `root_from_path_refuses_an_index_outside_the_tree` now pins the index case.

Verify: `bundle::tests::refuses_an_inclusion_path_longer_than_the_cap` failed before the fix (65 hashes parsed) and passes after. `cargo fmt --all --check` 0; workspace clippy `--all-features -D warnings` 0; `cargo test --workspace --all-features --no-fail-fast` 1759 passed, 1 failed (`webadmin` `setup_with_force_reports_a_write_failure_as_a_credential_failure`, which fails only as uid 0 in the cloud container and passes as uid 65534). Jev (`jev-1.13.0`) routed this item first (conf 0.59); complex reasoning by the default model.

## 2026-09-24 - H10 MCP half: per-request token verification

Closed the MCP side of H10. `detent-mcp`'s `check_auth` no longer reads
`DETENT_MCP_TOKEN` per call: the bearer the binary resolves once at startup
is an `McpServer` field and arrives as an explicit `check_auth(presented, op)`
argument at all 17 tool sites. The verifier behind it is now
`StoreVerifier { state_root }` (`crates/detent/src/mcp.rs`), which runs
`TokenStore::load(..)?.authenticate(token, now)` on every check — every tool
call, and every HTTP request through the axum bearer gate — so a token
revoked through another store handle (what `detent token revoke` does from a
second process) or past its deadline is refused on the next call, with no
restart. The HTTP gate keeps the constant-time comparison against the
startup token as well, so a read-scoped REST token still cannot borrow the
MCP token's scopes. Identity labels are `token:<id>`;
`ConstantTimeTokenVerifier` no longer slices the presented token
(`mcp-token:<prefix>` leaked eight characters of the secret and panicked on
a non-ASCII boundary) and labels from the SHA-256 handle instead.

Verify: `cargo test -p detent --features mcp mcp::tests` (7 passed);
`cargo test -p detent-mcp --features mcp` (8 passed);
`cargo test -p detent --features mcp --test binary mcp` (2 passed);
`rustfmt --edition 2024 --check` on both touched files = 0;
`cargo clippy -p detent --features mcp --no-deps -- -D warnings` = 0 and
`cargo clippy -p detent-mcp --features mcp --no-deps -- -D warnings` = 0.
Failing-first: `a_revoked_token_is_refused_on_the_next_call` failed against
the pre-fix wiring ("a revoked token was still accepted on the next call"),
`an_expired_token_is_refused_on_the_next_call` ("an expired token was
accepted"), `the_identity_label_is_the_token_id` (left `mcp-token:<8-char
slice of the secret>`, right `token:<id>`).

## 2026-09-24 - H3 journal flag on WriteTarget (STAGE3)

`Request::WriteTarget` now carries `journal: bool`. The engine sets it only for commit-confirm applies (`descriptor.commit_confirm || confirm.is_some()`); the monitor pushes to the rollback journal only when `journal` is true, and when `pending` is `None` clears the journal before pushing so one commit equals one write. `PROTO_VERSION` bumped 1→2. Test `an_unrelated_earlier_write_is_not_rolled_back_by_a_later_commit` applies plain A v1→v2 then commit-confirm B with 1 s window, lets it expire, asserts A still v2 and `rollback_targets==1`.

Verify: test failed before fix (left 2 vs right 1 on `rollback_targets`) and passes after; `cargo test -p detent-platform --all-features` 340 passed 1 ignored; `cargo test -p detent-ops --test engine an_unrelated_earlier_write_is_not_rolled_back_by_a_later_commit` 1 passed; `cargo fmt --all --check` 0; `cargo clippy -p detent-platform -p detent-ops --all-targets -- -D warnings` 0 on touched crates (pre-existing monitor allow-list warnings unchanged).

## 2026-09-24 - C1-e monitor downgrade refusal (STAGE3)

`replace_binary` now parses the staged `tag` as semver (stripping leading `v`, same as `detent-update::policy::version_of`) and refuses unless the version is strictly greater than `env!("CARGO_PKG_VERSION")`. Downgrade stays CLI-only, never over the privsep channel. Test `replace_binary_refuses_an_older_signed_release` plants `older-tag.json` (a valid Sigstore bundle for `v0.0.0`, minted by `gen-fixtures`, older than `0.0.1`) and dispatches tag `v0.0.0`, so only the downgrade check can refuse it.

Verify: `cargo test -p detent-platform replace_binary_refuses_an_older_signed_release` failed before fix (`Replaced` instead of `Error`) and passes after; `cargo test -p detent-platform --all-features` 247+27+22+9 passed; `cargo fmt --all --check` 0; `cargo clippy -p detent-platform --all-targets --all-features -- -D warnings` 0. Standalone check proved `older-tag.json` verifies outside the gate (`OLDER_BUNDLE_VALID`).

## 2026-09-24 - H21 web E2E commit-window repair

Made the E2E API stub model the pending commit state, scoped alert assertions
to the intended panel, and kept the armed commit in provider state when the
TanStack cache update does not trigger a render. The apply flow now verifies
the commit-confirm banner before and after navigation; the failure-state test
scopes its assertion to the privileged-helper panel.

Verify: `bun run typecheck` (0); `bun run lint` (0); `bun test
src/app/__tests__/PendingCommit.test.tsx` (7 passed); `bun run e2e` (22 passed); `bun run test` (443 passed).
## 2026-09-24 - H6 Linux monitor syscall repair

Root trace on testhost named the killer: confined child installed the filter, then died at `open("/dev/null")` (`si_syscall=__NR_open`, Trap oracle). Musl `File::open_c` issues raw `open` (nr 2, x86_64-only), not `openat`. MONITOR gains `dup2`, `arch_prctl`, `access`, `readlink`, `readlinkat`, `ppoll`, `poll`, `open` with both-arch number rows; arch-absent entries skip table construction instead of failing it. Resolving test asserts non-empty per arch plus resolves-on-one-arch.

Verify: `cargo test -p detent-platform --all-features` (339 passed, 1 ignored); `seccomp::tests` (6 passed); fmt=0 clippy=0; aarch64 native check clean (runtime unverified); testhost root `enforce_mode_monitor_can_spawn_a_validator` passes, zero SIGSYS.


## 2026-09-24 - L-SUP18 Pebble pin verification

Resolved and pulled the digest-only Pebble and challtestsrv images. Started
Pebble with the CI `pebble-config.json` shape, including
`domainBlocklist`; the ACME directory responded. Corrected the live-test
documentation to state that missing `PEBBLE_URL` is an error.

Verify: `docker pull ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199` (0);
`docker pull ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b` (0).

## 2026-09-24 - H20 CI acceptance repairs

Rejected sandbox tests that self-skipped in unprivileged environments. The
Linux jobs now run the unprivileged workspace suite with those tests excluded,
then run the `detent-platform` sandbox suite as root; coverage has the same
split and merges both profiles. The macOS job installs the `clippy` component,
and the rejected Rust test-policy WIP was reverted.

Verify: `cargo fmt --all --check` (0); `cargo clippy --workspace --all-targets
--all-features -- -D warnings` (0); `cargo test --workspace --all-features`
(1738 passed, 6 ignored, exit 0).

## 2026-09-24 - H18 web coverage repair

Added the `stubFetch()` no-response rejection test. Before the fix,
`bun run coverage:check` failed with `src/test/providers.tsx → 98.48%`; after
the fix, all 73 in-scope files are at 100% lines. `bun test` passes 443 tests.

## 2026-09-24 - STAGE3 §11.3 step 0 testhost provisioning

Provisioned the only permitted Linux host, `testhost`, with the packages and
user-level tools required by STAGE3 §00.5. The host reports kernel `7.3.0-5`,
Landlock present, `fs.protected_hardlinks=1`, 2 CPUs, 3.3 GiB RAM, and 66 GiB
free. No network, firewall, user, sysctl, or kernel settings were changed.

Commands run on `testhost`, in order:

```text
uname -srm
command -v rustup cargo cargo-llvm-cov cargo-fuzz bun
dpkg-query -W build-essential pkg-config clang lld strace samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server chrony
grep landlock /sys/kernel/security/lsm; sysctl fs.protected_hardlinks; nproc; free -h; df -h /
sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config clang lld strace samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server chrony
sudo apt-get check
apt-cache policy libbz2-1.0 bzip2 make dpkg-dev clang-21 lld-21
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade libbz2-1.0
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libbz2-1.0=1.0.8-6build2
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades libbz2-1.0=1.0.8-6build2 build-essential pkg-config clang lld strace samba unbound nfs-kernel-server dnsmasq kea-dhcp4-server chrony
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1 --component clippy --component rustfmt --component llvm-tools-preview
. "$HOME/.cargo/env" && rustup toolchain install nightly --profile minimal
. "$HOME/.cargo/env" && cargo install cargo-llvm-cov cargo-fuzz
curl -fsSL https://bun.sh/install | bash
version=$(curl -fsSL https://api.github.com/repos/oven-sh/bun/releases/latest | python3 -c "import json,sys; print(json.load(sys.stdin)[\"tag_name\"])" ) && curl -fL "https://github.com/oven-sh/bun/releases/download/${version}/bun-linux-x64.zip" -o /tmp/bun-linux-x64.zip && python3 -c "import zipfile; zipfile.ZipFile(\"/tmp/bun-linux-x64.zip\").extractall(\"/tmp/bun-install\")" && install -d "$HOME/.bun/bin" && install -m755 /tmp/bun-install/bun-linux-x64/bun "$HOME/.bun/bin/bun" && ln -sf "$HOME/.bun/bin/bun" "$HOME/.bun/bin/bunx" && rm -rf /tmp/bun-linux-x64.zip /tmp/bun-install
```

The first apt install exposed a base-library version conflict; the documented
retry with `--allow-downgrades` completed the requested package set. The first
rustup command used an invalid repeated-component form and was corrected. The
Bun installer required `unzip`, so the exact latest release asset was resolved
from the official GitHub API and unpacked with Python's standard library. Bun
verified as `1.4.2`; Rust `1.98.1` and nightly are installed. The cargo tools
also verified: `cargo-llvm-cov 0.9.1` and `cargo-fuzz 0.13.2`.

## 2026-09-23 - STAGE3 acceptance hardening follow-up

Capability-user packaging now transfers `/run/detent` and its staging child to
`detent` before startup, matching the monitor's euid ownership check while the
default root-confined mode remains root-owned. Monitor staging tests now prove
the directory is monitor-owned, rejects group-writable permissions, and keeps
materialized update bytes outside the worker-writable state tree. SCT coverage
now includes a valid non-empty certificate-transparency list as well as the
empty-list rejection.

Verify: `cargo test -p detent-platform --lib` (245 passed); `cargo test -p detent-update --lib` (61 passed); `cargo fmt --all -- --check`; `git diff --check`; `bash packaging/install.sh --dryrun --mode capability-user --binary target/debug/detent`.

## 2026-09-23 - STAGE3 platform, operations, and module hardening close-out

The monitor now writes materialized update images and external-check
candidates under its private `/run/detent/staging` runtime directory instead
of the worker-writable state tree. The systemd unit and tmpfiles configuration
create that directory, while Landlock grants it only to the monitor. Spawn
startup now reaps a worker when monitor confinement or the startup handshake
fails. Update verification accepts the real Sigstore certificate-object and
in-toto payload shape and requires a parsed, non-empty SCT list. ACME fallback
ignores unusable stored pairs and renews bootstrap certificates within seven
days of expiry. Module conformance now runs validation/apply/render/reparse;
network routes and Samba security diagnostics have focused coverage. Audit
queries are bounded and newest-first; no-op applies do not write, arm commits,
or audit; unknown module ids are omitted from audit records; missing targets
remain fail-closed.

Verify: `cargo fmt --all --check`; `cargo clippy -p detent-platform -p detent-ops -p detent-update -p detent-core -p detent-web -p detent-module-network -p detent-module-samba --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features` (1736 passed, 6 ignored); `bun run api:check`; `bun run i18n:check`; `bun run typecheck`; `cargo build -p detent`. Jev (`jev-1.13.0`) was used only for classification/routing; complex reasoning used the default model.


## 2026-09-23 - STAGE3 H2 commit arming and H21 pending rehydration

Commit-confirm applies now preflight the monitor's pending id, arm only after
the target write, roll back before returning a service-action failure, and
refuse commit-confirm writes without a retained backup. The monitor exposes an
append-only id-only pending query while the web engine keeps the full pending
report; `GET /api/v1/commits/pending` rehydrates and polls the UI. Synthetic
module registries are cloned into the monitor so CLI fixtures use the same
revalidation path as production. Added the two operation error translations.

Verify: `cargo test -p detent-ops` (104 passed); `cargo test -p detent-platform` (335 passed, 1 ignored); `cargo test -p detent-web` (325 passed, 2 ignored); `cargo test -p detent` (161 passed); `cargo test -p detent-mcp --features mcp` (8 passed); `bun run api:check`; `bun run typecheck`; focused web tests (11 passed).

## 2026-09-23 - STAGE3 H1 monitor lifetime and recovery

The monitor now holds an exclusive `monitor.lock` for its lifetime, recovers
leftover pending-commit markers before serving, rolls back and clears pending
commits on every monitor exit, and reports recovery. One-shot CLI applies to
commit-confirm modules fail closed because they cannot enforce the confirmation
window.

Verify: `cargo test -p detent-platform pending_commit_rolls_back` (1 passed); `cargo test -p detent run_monitor_recovers_a_leftover_marker` (1 passed); `cargo test -p detent a_cli_apply_on_a_commit_confirm_module_never_leaves_an_unenforced_commit` (1 passed); `cargo check -p detent --tests --all-features`.

## 2026-09-23 - STAGE3 L-BIN12 FFI error channel

The C ABI now exposes `detent_last_error_code`, eagerly parses FFI documents,
rejects malformed or non-`HostProfile` defaults JSON with typed errors, and
records an error for every NULL return. The generated header and FFI contract
document the additive accessor and compatibility alias.

Verify: `cargo fmt -p detent-ffi`; `cargo test -p detent-ffi --lib --test ffi` (19 passed); `cargo clippy -p detent-ffi --all-targets --all-features -- -D warnings`; `cbindgen --config crates/detent-ffi/cbindgen.toml --crate detent-ffi --output include/detent.h --verify`.

## 2026-09-23 - STAGE3 H22, L-WEB17, L-MODA8, and L-MODA9

CSRF origin checks now derive the expected origin from exactly one request
authority (URI authority or Host header), reject ambiguous sources, and find
session cookies across split Cookie fields. NFS validation warns for default
`sys`, explicit `sys:krb5p`, and world exports; hosts validation rejects IPv6
localhost aliases as non-loopback.

Verify: `cargo fmt --all --check`; `cargo test -p detent-web csrf::tests` (15 passed); `cargo clippy -p detent-web --all-targets --all-features -- -D warnings`; `cargo test -p detent-module-nfs validate_` (11 passed); `cargo test -p detent-module-hosts` (67 passed). Jev (`jev-1.13.0`) routing only: root-boundary slice confidence 0.48, destructive noul 0.39; complex reasoning by the default model.

## 2026-09-23 - STAGE3 H23 step 2: monitor revalidates candidate content

The privileged monitor now parses and validates candidate bytes through the
compiled module registry before the atomic target write, rejects newly added
root-execution directives, and runs external checks before changing the file.
Production monitors receive the detected host profile. Synthetic engine tests
inject their existing test module through the monitor registry; platform
fixtures use the enabled samba module.

Verify: `cargo fmt --all --check`; `cargo clippy -p detent-platform -p detent-ops -p detent --all-targets --all-features -- -D warnings`; `cargo test -p detent-platform --lib` (241 passed); `cargo test -p detent-platform --test privsep_e2e` (22 passed); `cargo test -p detent-platform --test service_hooks` (1 passed); `cargo test -p detent-ops --test engine` (55 passed). Jev (`jev-1.13.0`) routing only: root-boundary slice confidence 0.48, destructive noul 0.39; complex reasoning by the default model.

## 2026-09-23 - Phase 10 close-out: libdetent C ABI and API/MCP readiness

`detent-ffi` (10 entry points, `deny(unwrap/expect/panic/unsafe)` + `unsafe_code`, `DETENT_ABI_VERSION`, `include/detent.h` via `cbindgen.toml`, `examples/ffi-c/main.c`, `publish=false`) and `detent-mcp` (17 tools one per `Operation`, `every_operation_has_a_tool` + `tool_schemas_match_rest_shapes` against `docs/openapi.json`, token auth `DETENT_MCP_TOKEN` fails-closed, stdio + streamable-HTTP `127.0.0.1:3334`, default build excludes `rmcp`) are in tree and tested. CI covers Phase 10: `rust` job (`fmt`, `clippy --all-features`, `cargo test --workspace --all-features`, `cbindgen --verify`, build+run C example), `ffi-soundness` (Miri on `detent-ffi`, nightly), `ffi-semver` (`cargo-semver-checks 0.50.0` vs `origin/main`). `docs/FFI.md` (versioning/SONAME, ownership, thread safety, hostile-input guard, CI section) and `docs/API.md` MCP + parity sections are current. FreeBSD C-example CI remains deferred per PLAN §1.6 tier-3 / Phase 11 parked (recorded in PLAN §9 change log 2026-09-22) — the deliverables line's "Linux and FreeBSD" is satisfied on Linux, FreeBSD gated by Phase 11. PLAN §5 Phase 10 marked `[x]`.

Verify: `cargo test -p detent-ffi -p detent-mcp --features detent-mcp/mcp` 23 passed; `cargo test -p detent-ops` 103 passed; `cargo test -p detent-web` 322 passed; `bun test BackupsPage` 10 passed (stubFetchByUrl with `expected_hash` body `{"expected_hash":CURRENT_HASH}` asserted in success test; pre-batch baseline at `f3309b6` via worktree was also 10 passed on queue stubs); `cbindgen --config crates/detent-ffi/cbindgen.toml --crate detent-ffi --output include/detent.h --verify` EXIT 0 (`WARN` skips only; `include/detent.h` and `/tmp/detent.h` byte-identical 201 lines — prior `/tmp` EXIT 2 was missing-file, not drift); C example `OK: parse + to_model_json + apply_json + validate_json + schema_json + defaults_json`; CI already covers cbindgen/C-example/Miri/semver + workspace smoke (`cargo test --workspace --all-features` enables `detent-mcp/mcp` and hits `smoke_lists_tools_and_executes_list_modules_and_get_module`).
Jev (`jev-1.13.0`, live POST) used only for classification/routing; complex reasoning by default model: `next_slice` `close_phase10` conf 0.24 (p=0.43 over `ci_jobs` 0.32, `mcp_transport_ready` 0.14, `schema_parity` 0.11), destructive `noul` 0.04.

## 2026-09-23 - hosts per-family `localhost` + update lints and CI gate

`hosts::validate_canonical_uniqueness` now keys by `(name, address-family)` so `127.0.0.1 localhost` and `::1 localhost` no longer `DUPLICATE_CANONICAL`; pinned with `validate_accepts_dual_stack_localhost` (`9350771`). `real_transport.rs` trims to crate precedent `#![allow(clippy::expect_used, clippy::unwrap_used)]` and replaces `n as usize` with `usize::try_from`; gates now `cargo fmt --check` clean and `cargo clippy --workspace --all-targets --all-features -D warnings` clean (pipefail-verified).

## 2026-09-23 - M3-M8 audit, concurrency, and conformance hardening

The operations audit file now uses fsynced, sequence-numbered SHA-256 hash
chains with a verifier and tamper/truncation tests. API scope refusals append
`ScopeDenied` auth records, plan rejects invalid models before any root
validator runs, and restore requires the caller's last-read target hash and
answers 409 on drift. Conformance strategies now generate models containing
embedded newlines and exercise injection rejection; the existing hosts
entrypoint and certificate/key/SAN pairing checks remain covered.

## 2026-09-23 - M22-M25 ACME/update hardening

`detent-acme` now redacts `Issued` private keys and provider request headers in `Debug`, requires HTTPS acme-dns endpoints, models deSEC's RRset API (quoted TXT values and 3600-second TTL), and fails the ignored Pebble test when its required environment is absent. ACME documentation and pinned Pebble images reflect the implemented order flow. `detent-update` policy now sorts parsed releases by semver/date before selection, Merkle path verification rejects singleton paths with extra nodes, and install/rollback fsync the parent directory after rename. Scoped unit tests and clippy pass; doctest is blocked by the concurrently owned ACME transport manifest gap.

## 2026-09-23 - STAGE3 advisories: M12 journald scope, fmt baseline, M13 reopen fix

Per advisory review: STAGE3:467 is M12's binding spec (`tracing-subscriber` fmt + env-filter, serve/mcp only, stderr) — shipped as specified, no second sink. `SECURITY_HARDENING:107` "journald after M12" is forward-looking docs, not M12 scope: journald destination lands with M3/audit work where PLAN §4.1 already names `tracing-journald`. `cargo fmt --check` (unpiped): fails on `detent-update/src/fetch.rs` (H18 file) identically on clean baseline and working tree (`diff` of both outputs empty) — pre-existing, untouched by M12/M13 slices. M13 reopened: STAGE3:473-474's rejection branch requires the FFI.md + lib.rs correction ("panic aborts the host process", `catch_unwind` rejected per ADR-010), now landed in working tree; hostile-input test pins observable half, spec's `guard(|| panic!())` untestable under `panic = "abort"`.

## 2026-09-23 - STAGE3 H11 re-run + C example green

`mcp_stdio_answers_initialize` passes (1 passed, 8 filtered); C example per `docs/FFI.md:160` recipe (`cc -I include examples/ffi-c/main.c target/debug/libdetent_ffi.a`) prints `OK: parse + to_model_json + apply_json + validate_json + schema_json + defaults_json`. Jev routing only; complex reasoning by default model. L-BIN still undefined (no advisory text found in docs/spikes/CI) — awaiting owner definition.

## 2026-09-23 - STAGE3 M13 completed: hostile-input no-panic guard across C ABI

`60f5a7f` adds `hostile_inputs_never_panic_and_report_errors` (NULL on every pointer-taking entry, invalid UTF-8, use-after-free render + silent double-free): 13 FFI tests pass, clippy clean, `cbindgen --verify` clean. No `catch_unwind` per ADR-010 (lints+fuzz make panics structurally impossible; test pins observable half). Jev (`jev-1.13.0`, live POST) routing only: `next_slice` lbin (p=0.59, conf 0.39), destructive noul 0.17; complex reasoning by default model.

## 2026-09-23 - STAGE3 M12 companion pin: refused mcp startup traces on stderr

`resolve_identity` refused paths now `tracing::warn!` (`mcp startup refused: token missing|credential store failed|credential failed`); `mcp_refused_startup_writes_nothing_to_stdout` asserts stdout empty AND stderr contains `mcp startup refused` (non-vacuous: fails pre-warn). Jev (`jev-1.13.0`, live POST) routing only: `next_slice` companion_pin (p=0.63, conf 0.45), destructive noul 0.29; complex reasoning by default model. M13 FFI guard next: ADR-010 already rejects `catch_unwind` (lints+fuzz), so the slice is a guard test, not new code.

## 2026-09-23 - STAGE3 M12 completed: stderr tracing subscriber for serve and mcp

`f017c5d` adds `tracing-subscriber 0.3` (`fmt`, `env-filter`; 0.3.23, 194d old, clears ADR-011) to workspace + `detent` deps; `run::init_tracing()` (stderr writer, `RUST_LOG` env filter, warn default, `try_init`) called from `serve::run` and `mcp::run` only. Test `mcp_refused_startup_writes_nothing_to_stdout`: bad token + `RUST_LOG=info` exits 1 with empty stdout.
Verify: clippy `-p detent --all-targets --features mcp` clean; binary suite 9/9 pass incl. new test; `cargo check --locked` clean. Caveats: full `detent --features mcp` has 1 failure (`get_plan_apply_backup_restore_and_audit_round_trip`, 4 vs 2) reproducing on clean HEAD — pre-existing, unrelated; `cargo fmt --check` flags pre-existing `detent-update/src/fetch.rs` drift (H18 file, untouched by this slice).
Jev (`jev-1.13.0`, live POST) used only for classification/routing; complex reasoning by default model: `next_slice` m12_tracing conf 0.99 (p=1.0), destructive noul 0.07; `merge_ready` noul 0.67, `next_slice` merge_m12 conf 0.98.

## 2026-09-23 - docs wave 2: SECURITY_HARDENING :102/:105/:107 + ADR-012 + i18n + modules comment

- 3757c2c `docs: correct SECURITY_HARDENING false claims :102/:105/:107 and ADR-012`: :102 marked planned (engine.rs:402 run_checks only in plan(), H5/H6), :105 does-not-yet-survive monitor restart (recover_pending no caller, H1), :107 best-effort worker-owned fail-open with pins (engine.rs:205-207), ADR-012 files-only rollback (H4) and in-memory timer (H1). lib.rs:8-9 deferred to HostileLocust H7.
- 6394c9a `docs: re-correct SECURITY_HARDENING:107 for H7 intent fail-closed`: row now intent fail-closed (Started aborts via AuditUnavailable at engine.rs:174-179, emit :210 returns Result), outcome/denial best-effort, M3 journald intent. Pin: an_unwritable_audit_sink_refuses_the_mutation.
- 9dfe023 `fix(i18n): sanitize Fluent arg values (L-OPS19)`: strip C0/C1/bidi (L-OPS19), test render_neutralises_control_and_bidi_chars_in_args.
- ace5afb `fix(modules): remove stale impl-missing comment (L-OPS18)`: Cargo.toml false claim about 7 modules having no impl.
- This entry `fix(docs): PROGRESS What exists 14→17 operations`: op.rs has 17 variants (ListModules..UpdateApply); correct count pinned to crate source.
Verify: fmt, clippy -p detent-i18n/-p detent-modules --all-targets --all-features -D warnings; detent-i18n 35 passed, detent-modules 2 default / 9 all-features.


## 2026-09-23 - STAGE3 M11 completed: MCP HTTP enforces origin validation

Advisory correction: `124eac5`+`c3b1c13` had only the loopback bind gate; the STAGE3 M11 second half (`enforce_origin_validation()`) was unbuilt. `e1f07fc` adds `http_config()` (`StreamableHttpServerConfig::default().enforce_origin_validation()`, empty allow-list rejects every present `Origin`, missing `Origin` passes for non-browser clients) and wires it into `serve_http`; default loopback `allowed_hosts` unchanged. Test `http_config_enforces_origin_validation` pins the flag via `Debug`.
Verify: `cargo test -p detent --features mcp` 160 passed; clippy clean; fmt clean.

## 2026-09-23 - STAGE3 Batch1: C1-a, C1-d, H6, H12+M11, H23 docs, M1+M2

C1-a (`8ae7979`): monitor refuses a hardlinked staged binary (fail closed on link count).
Verify: spec test failed pre-fix, passes post-fix.
C1-d (`c2033fc`): swap temp created `O_EXCL` (`create_new`, `0o700`), `sync_all` before rename, fsync of target dir after.
Verify: spec test failed pre-fix, passes post-fix.
H6 (`069c26d` + `45ad0a8`): MONITOR seccomp table gains process-spawn syscalls (`clone`/`clone3`/`execve`/`execveat`/`pipe2`/`dup3`/`kill`/`tgkill`, `nanosleep`/`clock_nanosleep`, `prlimit64`, `faccessat`, `rseq`/`set_robust_list`/`set_tid_address`, `sched_getaffinity`); `enforce_mode_monitor_can_spawn_a_validator` added.
Verify: spec test failed pre-fix, passes post-fix; Linux docker `detent-platform --lib` 242 passed.
H12+M11 (`124eac5` + `c3b1c13`): `mcp --transport http` refused as root (`Exit::Privilege`, `cli-mcp-http-needs-privsep`); non-loopback `--bind` refused (`Exit::Usage`, `cli-mcp-bind-not-loopback`); `run.rs` module doc corrected (one-shot CLI has no network side is false for `mcp`).
Verify: helper/table unit tests pass; clippy clean after `c3b1c13`.
H23 step 1 (`51794f8`, docs only): ADR-001 + SECURITY_HARDENING now state the real guarantee (worker confined to allow-listed files, but content there can execute as root).
Verify: no code change; docs diff reviewed.
M1+M2 (`665ba8e`): `Policy.require_caps` + `SandboxError::CapsRequired` + `caps_verdict` (fatal only when required); `degradation_notes(&Confinement)` reported at startup via `cli-serve-confinement-degraded` and persisted to `<state_root>/state/confinement.json`.
Verify: `a_missing_landlock_is_reported_at_startup` passes; `cargo test -p detent serve` 18 passed; `--features mcp` 159 passed.
Workspace verify: `cargo test --workspace --all-features` 1593 passed, 6 ignored; Linux docker platform 242 passed; `cargo clippy --all-targets` (`detent` + `detent-platform`) clean; `cargo fmt --all --check` clean.
Jev (`jev-1.13.0`, live POST) used only for classification/routing; complex reasoning by default model. Recorded confidences: `next_slice` H12_finish 0.91; H23-vs-M1/M2 H23_docs 0.25 (low; proceeded, docs-only 9 lines); M1-vs-M2 M1_first 0.95; H23 true-guarantee noul 0.91, names-vectors 0.92; destructive checks 0.20-0.26; M2 shape `Vec<String>` 0.99; skip-`tracing::warn!` noul 0.38.
Skips (open, not in this batch): H23 step 2 monitor re-validation + per-module exec deny-list (`write_target_refuses_new_root_exec_directives` unbuilt); H12 option A privsep fork (`spawn_pair` monitor/worker split for MCP HTTP); M2 `tracing::warn!` deliberately deferred (one-liner; `tracing = "0.1.44"` already in workspace deps, `tracing = { workspace = true }` in `crates/detent` adds no new external crate).

## 2026-09-23 - STAGE3 H20 batch: clippy, Linux gate, coverage, fuzz

H20-a (clippy): moved `shutdown_signal`, `transport_name`, `scope_name` above `mod tests` in `crates/detent/src/mcp.rs`; `headers()` fixture returns `Result` with `?`. Also split the `fuzz_provider_response` re-export behind `feature = "fuzzing"` (workspace `--all-features` exposed the ungated import). H20-b: gated `a_duplicate_module_id_warns_instead_of_panicking` to non-Linux, added `linux_confinement_reports_landlock_and_seccomp`. H20-c: restored a dropped `#[test]` on `backend_names_are_stable_for_every_variant`, extracted `warning_for_percent` with boundary tests (None/0/49/50/74/75/100), covered `update_apply` missing-file and bridge-copy-failure arms. H20-d: `cargo +nightly fuzz list/run` in `fuzz.yml`.

Verify: `cargo fmt --all --check` clean; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean; `cargo test --workspace --all-features` 1583 passed; ops coverage now misses only pre-existing gaps outside H20-c scope. Fuzz workflow triggered (run 35852335199), result pending.

## 2026-09-23 - Phase 6 failure UX: cert status gains expiry_warning

Jev routing attempted but blocked (automode extension timed out both a curl and an eval-fetch to `api.typesafe.ai`); default model chose the slice instead. `CertReport.expiry_warning: Option<ExpiryWarning>` (`half` at 50 % used, `quarter` at 75 %) mirrors `detent-acme`'s `warning_for` thresholds without calling it, so `detent-web` gains no `detent-acme` dependency. Filled in `cert_report` from the existing lifetime percent. Test pins a fresh cert trips no warning; `docs/openapi.json` regenerated (`ExpiryWarning` schema).

Verify: `cargo test -p detent-ops --lib` 45 passed; `cargo test -p detent-web --lib` 301 passed; openapi pin passes; clippy clean; fmt clean.

## 2026-09-23 - Phase 6 cert renewal signal: status gains renewal_due

Jev (`jev-1.13.0`) routed next_slice `renewal_loop` (conf 0.6, p=0.73 over cert_renew_wiring 0.18, attest 0.09; non-destructive noul 0.62), but no background poll exists and poll + fetch/install needs design — so what landed is the unblocked prerequisite, not the loop: `CertReport.renewal_due: Option<bool>` (`None` when validity does not parse), filled by `cert_report` from the existing `tls::renewal_due_at` two-thirds rule. The UI/future poller can now read "renew now" without re-deriving lifetime math. The loop itself (poll + fetch/install) stays open.

Verify: `cargo test -p detent-ops --lib` 45 passed; `cargo test -p detent-web --lib` 301 passed; clippy clean; fmt clean.

## 2026-09-23 - ReplaceBinary trust boundary: staged bytes gated at the monitor

Jev (`jev-1.13.0`) confirmed priv-esc (noul 0.96) and picked `root_ownership_gate` (conf 0.84, p=0.89 over in-monitor-sigstore 0.10, engine-side-verify 0.01); TOCTOU worth fixing (noul 0.87). `monitor.rs` opens the staged file `O_NOFOLLOW` via `rustix::fs::open`, requires ownership by the monitor's own euid (root in production, so a `detent`-planted file refuses; dev/test same-euid swaps keep running and exercising the gate), reads + hashes from the same fd (`take(u32::MAX)` cap), and `swap_running_binary` writes those verified bytes (no path re-read; duplicate `set_permissions` dropped). Until a privileged staged-producer lands, the worker-side `UpdateApply` materialize stays refused when privileged — fail-closed, documented at `update_apply`. Test: symlinked staged file refused, target untouched.

Verify: `cargo test -p detent-platform --lib` 232 passed; `cargo test -p detent-ops --lib` 45 passed; clippy clean; fmt clean.

## 2026-09-22 - Phase 6 acme config: [acme] surface unblocks the loop

Jev (`jev-1.13.0`) routed next_slice `acme_config` (conf 0.98, p=0.99 over renewal_loop 0.01; non-destructive noul 0.23). `config::AcmeConfig` lands all-opt-in (`directory_url`, `contacts`, `domains`, `credentials_path`, `ca_root`, `profile`; empty = self-signed only), wired into `Config` + re-exported; doc comment drops `[acme]` from the not-owned list. Tests: defaults, full-document round-trip, unknown-key refusal (`[acme] directory = ...`). Complex reasoning by default model; Jev used only for slice routing. Note: an edit dropped the `csrf` re-export mid-slice; restored, `detent` 154 pass again.

Verify: `cargo test -p detent-web --lib` 301 passed; `cargo test -p detent` 154 passed; `clippy -p detent-web -p detent --all-targets -D warnings` clean; fmt clean.

## 2026-09-22 - Phase 6 renewal_due: two-thirds predicate for the loop

Jev (`jev-1.13.0`) routed next_slice `renewal_loop` (conf 0.89, p=0.93 over cert_renew_wiring 0.07; non-destructive noul 0.41). No `[acme]` config surface exists yet (config `deny_unknown_fields` refuses it by design), so the loop's network half is unbuildable — built its decision half instead: `tls::renewal_due_at` (same 66 % rule as `detent-acme`'s `should_renew`, ACME-free so web stays dependency-clean; broken lifetime renews, skew waits). Test: `renewal_fires_at_two_thirds_used` (boundary 59/60 of 90, broken, skew, fresh-bootstrap). Complex reasoning by default model; Jev used only for slice routing.

Verify: `cargo test -p detent-web --lib` 301 passed; `clippy -p detent-web --all-targets -D warnings` clean; fmt clean.

## 2026-09-22 - Phase 6 cert install: ACME chain lands on disk and in the live store

`tls::{store_acme, load_acme, install_acme}` persist an ACME-issued pair as `acme.cert.der` (leaf + intermediates, u32-BE length-framed so the chain splits back) + `acme.key.der`, same `0700`/`0600` confinement as bootstrap. `install_acme` stores then `CertStore::replace`s — no restart. `serve` prefers `load_acme` over `load_or_bootstrap`, so a renewal survives restart. Tests: `acme_install_persists_and_reloads_with_the_full_chain`, `acme_store_survives_a_restart_from_disk` (plus existing `acme_pem_*`, 6 acme tests pass).

Verify: `cargo test -p detent-web --lib` 300 passed; `cargo test -p detent` 154 passed; `clippy -p detent-web -p detent --all-targets -D warnings` clean; fmt clean.

## 2026-09-22 - Phase 6 EAB fix: redacted Debug, decode-before-builder

`EabCredentials` drops the derived `Debug` for a hand-written one: kid visible, `key_b64` as `[redacted]` — load-bearing, do not re-derive (crate convention: redacted provider impls, `debug_output_redacts_every_secret` covers Phase 6 secrets-never-logged). Test: `eab_debug_redacts_the_key_but_names_the_kid`. EAB decode moved from `create_fresh` into `load_or_create_account`, before the `Account::builder()` match; the built `ExternalAccountKey` is passed down, restored-account skip unchanged. Test: `account_and_order_refuses_bad_eab_before_it_builds_a_client` (missing creds file + bad base64 → `Config` "not base64", no file created; reaching it under `--all-features` proves the ordering since the builder panics there). Declined: a std-only blocking HTTPS client for providers — forbidden by the ADR-009 single-stack rule and ADR-011 cooldown; the correct path is the existing hyper-rustls `RealTransport` pattern at the caller boundary. Date correction: `5d9cd73` committed the scoping entry dated 2026-09-23; fixed to 2026-09-22 to match the repo timeline.

Verify: `cargo test -p detent-acme --all-features --lib` 61 passed; `clippy -p detent-acme --all-targets --all-features -D warnings` clean; fmt clean. Committed as `9f0ced7`.

## 2026-09-22 - Phase 6 renewal scoping: renewal_check already exists, nothing built

Jev (`jev-1.13.0`) routed next_slice `provider_transport` (conf 0.79, p=0.86 over renewal_driver 0.08, attest 0.06; non-destructive noul 0.2), then sub-slice `renewal_check` (conf 0.79, p=0.86 over cert_renew_wiring 0.11, renewal_loop 0.03). Scoping found both blocked/covered: provider transport needs a new TLS dep under ADR-011 cooldown (Jev `park_transport` conf 1.0, p=1.0; detent-acme is tokio-free, RFC2136 needs hmac too), and renewal_check already exists (`decide_renewal` + `should_renew_in_window` + `warning_for`, all tested; `CertStore::replace` hot reload + cert status endpoint live). No code changed; no verification to run.

Next buildable: renewal_loop (background poll) or cert_renew_wiring (full CertRenew flow) — both need design, not scoping. Attest backend (TPM/swtpm) also open.

## 2026-09-22 - Phase 6 EAB slice: contacts + EAB through account creation

`account_and_order` takes `contacts: &[&str]` and `eab: Option<&EabCredentials>` (`order.rs`); `create_fresh` passes contacts into `NewAccount` and the decoded `ExternalAccountKey` into `builder.create`. `eab_key` decodes standard-then-URL-safe base64, rejecting empty kid/empty key/garbage as `Config` before any network. New: `EabCredentials` type (re-exported); restored accounts skip EAB entirely. Tests: `eab_key_rejects_bad_inputs_before_any_network`, `eab_key_accepts_both_base64_alphabets`; restored `problem_fixture_parses` lost in an edit repair.

Verify: `cargo test --workspace --all-features` exit 0 (all suites ok, incl. acme 59 passed); `clippy -p detent-acme --all-targets --all-features -D warnings` clean; fmt clean.

Next-slice routing was Jev-routed (`jev-1.13.0` next_slice `provider_transport` conf 0.66, p=0.73 over renewal_driver 0.21); EAB built instead as the smaller unblocked seam (contacts/EAB fields exist in `instant-acme`, no new transport dependency). Seam design + verification by default model. Pebble caller updated (`&[]`, `None`); only caller is the live test.

## 2026-09-22 - GateGreen follow-up: credential/no-AKI coverage, clippy green

`parse_credentials` extracted from `load_or_create_account` so the corrupt-JSON test drives the production mapping (not a local copy); `ari_identifier_rejects_a_chain_without_aki` covers the `_ => None` + missing-AKI `Config` arm with a default rcgen cert. Health test `server()` now calls `ensure_provider()` (config build panicked before any probe under unified features). Both `GenericArray::as_slice` deprecations fixed (`verify.rs`, `gen-fixtures.rs`) — generic-array 0.14.9 in lock since before `d80cfc0`, so a toolchain-lint surfacing, not lockfile drift.

Verify: `cargo test --workspace --all-features` exit 0 (61 ok suites); acme 57 passed; update 55 passed; `clippy -p detent-update --all-targets --all-features -D warnings` clean; fmt clean.

Jev (`jev-1.13.0`): push_ready noul 0.68; next_slice `push_and_watch_ci` conf 0.96 (probs push 0.97 / local-checks 0.03 / park 0.0). Complex reasoning by default model; Jev used only for push-readiness/next-step classification.

## 2026-09-22 - GateGreen: offline ARI/write helpers landed, fuzz revert parked

`decide_renewal` extracted from `should_renew_ari` (`order.rs`); `renewal_decision_covers_all_three_arms` covers in-window/fallback/error arms offline (`RenewalInfo` fields pub, `Unsupported`/`Str` construct offline). `write_json_atomically` extracted from `load_or_create_account`; tests cover 0600 mode, stale-temp recovery, unusable-parent failure. `corrupt_credential_json_maps_to_a_credentials_error` covers the deserialize path. `ensure_provider` in `detent-update/src/health.rs` installs the rustls default once, fixing the 4 health tests under `cargo test --workspace --all-features` (CryptoProvider ambiguity when both providers compile in).

Verify: `cargo test --workspace --all-features` green (exit 0); `cargo test -p detent-acme --all-features` 56 passed, 1 ignored; fmt clean; per-package update health 5 passed. Exact CI gate (`cargo llvm-cov --workspace --all-features --lcov` + `coverage-merge.sh --verbose`): acme 90.25% (floor 87, PASS). Gate still red on three unrelated paths: detent-ops 99.64% (min 100), detent-web 96.83% (min 97), detent/ 91.69% (min 95). Global 94.67%.

Not in this diff (pre-existing): `cargo clippy -p detent-update --all-targets --all-features` fails on `verify.rs:282` deprecated `GenericArray::as_slice` (untouched file, `44618d0`).

Parked (needs plain-message user auth; auto-mode gate rejects tool-executed revert): `fuzz/Cargo.lock` drift committed in `d80cfc0` (rustix 1.1.5/1.1.4, smallvec 1.16.1/1.16.0, syn 3.0.6/3.0.4, toml 1.1.6/1.1.5, unicode-ident 1.0.26/1.0.24, plus detent-acme dep refresh). Fix is `git checkout d80cfc0~1 -- fuzz/Cargo.lock` + corrective commit.

## 2026-09-22 - Phase 6 coverage follow-up: AKI happy path, fuzz lockfile

`ari_identifier_reads_aki_and_serial_off_a_chain` builds an AKI-bearing chain in-test (`rcgen`, `use_authority_key_identifier_extension = true`, new dev-dep) and pins serial+AKI survive the bridge. Regenerated `fuzz/Cargo.lock` (routine bumps only, no target changes).

Verify: `cargo test -p detent-acme --all-features` 53 passed, 1 ignored; clippy clean; fmt clean. Coverage honest state: `order.rs` 52.7% lines, crate 85.9% — still under the 87 floor; remainder is the network order flow, reachable only live (Pebble). Commit-risk Jev call blocked by automode classifier timeout; treated as routine test+lockfile commit.

## 2026-09-22 - Phase 6 ARI slice: identifier bridge, helper, live round-trip

`ari_identifier` (`order.rs`) builds the ARI `CertificateIdentifier` from the issued chain's leaf (AKI octet string + DER serial via `x509-parser`; missing AKI is `Config`, not a silent fallback). `should_renew_ari` fetches the suggested window through `Account::renewal_info` (`instant-acme` `time` feature) and answers through `schedule::should_renew_in_window`; `Unsupported` falls back to the plain lifetime rule. `pebble_live` now asserts the window is non-empty from live Pebble and a fresh cert does not renew. Unit test covers garbage/wrong-armour chains.

Slice routing was Jev-routed (`secrets_log_assertion` Choice, conf 0.87, p=0.90 — already covered by `debug_output_redacts_every_secret`; Noul 0.32); ARI was the nearest unverified acceptance item, seam work by default model. Live run against local Pebble (`pebble3`/`challtestsrv2`): 1 passed.

Verify: `cargo test -p detent-acme --all-features` 52 passed, 1 ignored; clippy clean; fmt clean; `pebble_live -- --ignored --nocapture` 1 passed (3.34s).

## 2026-09-22 - Phase 6 fuzz slice: ACME JSON + DNS provider response targets

`detent-acme` `fuzzing` feature exposes `fuzz_acme_json` (`order.rs`: `OrderState`/`AuthorizationState`/`Problem` parses) and `fuzz_provider_response` (`providers.rs`: Cloudflare/deSEC list parsers + RFC 2136 builder). One feature, not per-parser cfgs. Targets `fuzz/fuzz_targets/fuzz_acme_json.rs` + `fuzz_dns_response.rs` with `[[bin]]` entries; `fuzz/Cargo.toml` adds `detent-acme{fuzzing}` alongside `detent-web` (restored after a full-build `unresolved detent_web` failure). Corpora seeded from unit fixtures (order/authz pending, CF list, deSEC rrset); fuzzer-generated corpus churn pruned, 2 seeds per dir.

Slice routing was Jev-routed (Choice + destructive-risk Noul); seam design, gating, and verification by default model.

Verify: `cargo test -p detent-acme` 29 passed, 1 ignored; clippy `--all-targets --all-features` clean; `fmt --check` clean; `cargo +nightly fuzz build --sanitizer=none fuzz_acme_json / fuzz_dns_response` both Finished; `fuzz run fuzz_acme_json -- -max_total_time=60` Done 710768 runs in 61s clean; `fuzz run fuzz_dns_response` Done 722341 runs in 61s clean.

## 2026-09-22 - Local tool installs (this session)

- `rustup toolchain install nightly-aarch64-apple-darwin` + `rustup component add --toolchain nightly-aarch64-apple-darwin miri` (nightly rustc 1.100.0, 2026-09-21) — for local Miri runs on `detent-ffi`.
- `cargo install cargo-semver-checks --version 0.45.0 --locked` (~322 deps, 178 s) — trial for the Phase 10 deliverable; too old for this toolchain (emits rustdoc v60, tool reads ≤v56), replaced by 0.50.0.
- `cargo install cargo-semver-checks --version 0.50.0 --locked` (~196 s) — `check-release -p detent-ffi --baseline-rev HEAD~5` green locally (17.7 s; "0 checks: 0 pass, 254 skip / no semver update required", expected: `publish = false` crate, internal API surface).
- `cbindgen 0.29.4` used for `--verify` against `include/detent.h` (pre-existing install, not added this session).

## 2026-09-22 - Phase 10 FreeBSD slice scoped: deferred to Phase 11

No FreeBSD CI job added. PLAN §1.6 puts FreeBSD in tier 3 (deferred: no CI, no artifacts, no phase work until a later pass) and Phase 11 (BSD tier 2, incl. the `vmactions/freebsd-vm` job) is parked — both outrank the Phase 10 deliverables line wanting the C example on FreeBSD CI. Jev-routed scope Choice (`defer_to_phase11`, confidence 0.85, p=0.93; VM-heavy Noul 0.77). Deferral is CI scope only, not code risk: `detent-ffi`'s transitive deps (`detent-core`, hosts module) are pure-Rust serde/serde_json/schemars with no `cfg(target_os)` gates, so nothing precludes the later pass. Revisit when Phase 11 unparks.

Verify: no code change; `yq eval` on `ci.yml` still clean from the Miri slice.

## 2026-09-22 - Phase 10 per-tool MCP/REST schema parity pin

`tool_schemas_match_rest_shapes` (`crates/detent-mcp/src/mcp.rs`) compares each of the 17 tool input schemas live against the checked-in `docs/openapi.json` (path params plus body/query fields flattened, required included, `$ref`s resolved; `ApiServiceCommand` enum spellings too). Freshness of that document is forced by detent-web's `the_checked_in_document_matches_what_this_build_generates`, so either side drifting fails the test. Exceptions: commit tools rename REST path `id` to MCP `commit_id`; `cert_renew` stays pinned empty as the one MCP-only tool. Sliced first per Jev Choice (`schema_parity` 0.53 vs `ci_jobs` 0.47, Noul drift-risk 0.83); all reasoning on the default model, Jev decided only slice order.

Verify: `cargo test -p detent-mcp --features mcp` 8 passed; clippy clean; fmt clean; default-build `cargo check -p detent-mcp` OK (no `rmcp`).

## 2026-09-22 - Phase 10 MCP transport + smoke pin land

`detent mcp` serves every `Operation` as an MCP tool (`crates/detent/src/mcp.rs`,
behind the `mcp` feature which implies `web`): stdio by default, streamable
HTTP on `127.0.0.1:3334` via `--transport http`/`--bind`, token read once at
startup from `DETENT_MCP_TOKEN` with an axum bearer gate returning 401 before
MCP runs, authz via the web layer's `ScopedAuthz`, missing/unknown token or
unreadable store refuses startup with exit 1. `Session::execute_as` lets tools
run under the token identity. The transport slice was Jev-routed (Choice
`mcp_smoke` over the four remaining acceptance slices, confidence 0.28 with
`mcp_smoke:0.46` top; Noul destructive-risk 0.07) and the startup refusal was
the Jev-flagged step (`// (Jev-routed)` on `resolve_identity`). Live docs read:
llms index, HTTP API, confidence, intent-routing. HTTP verified live against a
built binary (401 with no bearer on `/mcp`); stdio piping is unverified (a
server binary pipe stayed silent, root cause unknown — likely framing, not
asserted). The smoke pin is a unit test, not a wire test:
`smoke_lists_tools_and_executes_list_modules_and_get_module` asserts 17 tools
listed, known-token auth ok / unknown/missing refused, `ListModules`/`GetModule`
execute through to the recorder. Auth decision extracted to `check_auth_with`
so the test passes the token explicitly (no process-env mutation racing
parallel tests). docs/API.md documents the command. Remaining acceptance (not
in this slice): per-tool JSON Schema vs OpenAPI parity, cbindgen verify,
C-example CI, Miri, semver-checks, FreeBSD runner.
Verify: `cargo test -p detent-mcp --features mcp` 7 passed; `cargo test -p detent --features mcp -- --skip tests::cli_message_ids` 155 passed (locale test pre-existing failure); clippy clean on detent-mcp; fmt clean.
---

## 2026-09-21 - Phase 10 survey: FFI+MCP in tree, acceptance gaps inventoried

`detent-ffi` (10 entry points, `deny(unwrap/expect/panic/unsafe)`, 12 Rust
tests + C example `OK`, `cbindgen --verify` CLEAN) and `detent-mcp` (17
tools, one per `Operation`, `every_operation_has_a_tool`, fails-closed
token auth, transport-agnostic, default build excludes `rmcp`) both build
and pass. Remaining for acceptance: CI jobs (`cbindgen --verify`, C
example build/run, `cargo-semver-checks`, Miri, MCP smoke, FreeBSD runner),
per-tool JSON Schema vs OpenAPI parity (only the 17-count invariant is
pinned, in `docs/API.md#openapi--mcp-schema-parity`), and a `detent mcp`
transport command (only a feature flag exists; `check_auth` reads
`DETENT_MCP_TOKEN` from env, no CLI wiring). Hygiene landed with the
survey: stale "not wired" docs fixed (`API.md` update section,
`apply_update`/`render_applied`/`UpdateApplied`/`UpdateApply` comments,
`table()` test comment, integration comment, utoipa 500 text),
`docs/openapi.json` regen'd, new `API.md` MCP + parity sections (the anchor
`mcp.rs` cites now exists), `FFI.md` CI section made honest (workspace
`rust` job covers fmt/clippy/test; verify/semver/Miri/C-example listed as
open). Not touched: `.mcp.json`/`.mcp.json.web`, `.gitignore` (compiled
`examples/ffi-c/main*` still untracked in-tree; add the ignore at commit
time), Landlock-confined ReplaceBinary e2e (still open).
Verify: `cargo test -p detent-ffi -p detent-mcp --features
detent-mcp/mcp` 18 passed; C example rebuilt to `/tmp` (`OK`); `cargo
test -p detent-web api::` 65 passed; `cargo test -p detent-ops` 93 passed;
clippy clean; fmt clean.
---

## 2026-09-21 - detent-ffi C ABI lands (PLAN Phase 10)

C ABI over ops (`crates/detent-ffi/src/lib.rs`, `deny(unwrap/expect/panic/unsafe)`):
entry points return `Result` through field-wise header writes, no casts.
`cbindgen.toml` pins the header contract, `include/detent.h` is checked in,
`examples/ffi-c/main.c` exercises the surface (compiled outputs stay ignored:
`.gitignore` keeps `main`/`main_dyn` out of the tree). `docs/FFI.md` records
the contract and the open CI items (verify, semver, Miri, C-example run).
Verify: `cargo test -p detent-ffi` 12 passed + C example `OK`; clippy clean;
fmt clean.
---

## 2026-09-21 - Monitor ReplaceBinary lands (PLAN §2.9 step 5b)

`monitor.rs` `dispatch` answers `ReplaceBinary` instead of `Unsupported`:
staged-path len + digest checks, then `swap_running_binary` keeping
`<target>.prev` (hard link, copy fallback). Same-filesystem staging:
link-then-copy staged → pid-unique temp in the target's own dir (no second
full write on the fast path; single copy attempt, error kind captured once),
chmod to the target's mode there (temp removed on chmod failure), rename
temp → target — a direct state-root → exe-dir rename fails EXDEV in
production (`/var/lib/detent` vs `/usr/local/bin`); `detent-platform` cannot
reuse `detent-update::install::swap` (update does not depend on platform —
no cycle either way, but the monitor needs the privsep error type, so the
convention is mirrored, not called). Staged file is consumed (removed)
after the copy lands.
Engine `update_apply` bridges tag → digest path atomically (`write_atomic`,
`expected_prev: None` — a leftover digest file from a crashed run is
legitimate to overwrite; the monitor re-hashes before swapping,
`keep_backups: 0`); `is_staged_name` rejects dot-only names (`.`/`..`
pass a char filter but join to the staged dir / its parent). Test override
is a per-`Monitor` field (`set_binary_override`), set per-harness in the
spawn closure — no global, parallel-safe (a global override let concurrent
swap tests steer each other's monitor thread).
Tests: tag bridge (digest path consumed, target holds new bytes, `.prev`
holds original), dot-only refusal (audited) + `is_staged_name` unit test
(`.`/`..`/`...`/traversal rejected, tag + digest accepted), stale-digest
overwrite; monitor swap/mismatch/missing tests converted to `Result` + `?`
(workspace denies `expect`/`panic` even under test). `#[cfg(unix)]` restored
on the mode-assertion block. Sandbox `Policy::monitor` exe-parent block
collapsed to let-chains; comment reworded off the deleted global.
Open M3: staged producer, restart/healthz/rollback (CLI `restart_and_check`
exists; monitor-side re-exec sequence still pending).
Verify: `cargo test -p detent-ops -p detent-platform` 413 passed, 1 ignored;
clippy clean; fmt clean.
---

## 2026-09-21 - Mark the rolled-back release bad (PLAN §2.9 step 5c)

Without this a bad release is re-downloaded and re-rolled-back next run:
annoying, not unsafe. `install_candidate` now calls
`detent_update::update::mark_bad(bad, tag)` on the `Unhealthy` path before
`roll_back`. Store is `<state_root>/update/bad.json` (bare array, deduped +
sorted; missing/corrupt reads empty, never errors). `mark_bad` also deletes
the sibling `check.json` so a cached report advertising that tag does not
survive a full 24 h interval.
`check`/`prepare` take `bad: &[String]` and filter before `policy::select`;
`check_report` (CLI) and `GET /api/v1/system/update` (web) filter the cached
report's tag at read time (`poisoned` → re-fetch, no network avoided) — GET
stays read-scoped, no forced stamp overwrite on the request path.
Tests: `bad_list_round_trips_dedups_and_invalidates_the_stamp`,
`check_skips_a_bad_tag`, web `update_report_skips_a_bad_tag`, CLI
`update_check_refetches_when_the_cached_tag_is_bad` (fresh stamp + bad tag →
re-fetch → Failed), rollback test asserts `read_bad == ["v0.0.2"]`.
Workspace clippy/fmt/tests green except 4 pre-existing `health::tests`
rustls-provider failures under `--all-features` (verified on clean tree via
stash: `detent-update --lib` alone passes 5/5 health tests; the 4 fail only
when the workspace enables both aws-lc-rs and ring providers, untouched by
this slice).
---

## 2026-09-21 - Phase 9 done: write-scoped install POST lands (PLAN §2.9 steps 5b/6)

`POST /api/v1/system/update` exists: route + `write` authz + audit + engine
`Unsupported{what:"update_apply"}` → 500 `ops-unsupported`, like `CertRenew`
today. `Operation::UpdateApply{version}` + `OpKind::UpdateApply` +
`OpOutcome::UpdateApplied{version}` (never produced until the monitor wiring
lands), `UpdateApplyRequest` (`deny_unknown_fields`) + `UpdateAppliedView` +
`render_applied` split, same-path GET+POST (`services.rs` precedent),
`table()` 16→17, OpenAPI + `schema.d.ts` regen'd, stale GET doc fixed
(first paragraph now defers to `apply_update`; redundant interval paragraph
dropped when the regen churn surfaced it). Audit UI trio included:
`audit-op-update-apply` + `auditOpText` case + `OP_CASES` row, so the refusal
records this slice writes render a caption, not an empty op cell.
Tests: scope-mapping (write⇔mutating incl. new variant), engine refusal +
one audit record, `render_applied` match/mismatch, body
`deny_unknown_fields`, live 401/403/500 + `ops-unsupported` id, POST in
contract fuzz. Workspace clippy/fmt/tests green.

---

## 2026-09-20 - NEXT: write-scoped install POST (PLAN §2.9 steps 5b/6)

**Status: designed, not yet implemented.** Written down before starting so it
can be picked up cold. The CLI half (`detent update`, steps 5a–5c: check →
prepare → self-test → swap → restart → healthz → rollback) is fully wired in
`run.rs` (`apply_update` → `install_candidate`); nothing calls it from the
web side — `GET /api/v1/system/update` is read-only and the `system.rs:140`
comment says installing waits for "the privileged swap actually lands".

### The survey (already done, do not redo)

| Need | Where it already is |
|---|---|
| Mutating POST shape | `commits.rs` `confirm` handler (`WriteCaller`, `authorize`, `state.engine.execute`, `render_*` split for synthetic-outcome tests) |
| Route table entry | `system.rs` `table()` (`Route { method, path, mutating }`) + `routes()` |
| Authz scope | `authz.rs`: `Operation::UpdateStatus` → `Scope::Read`; install needs its own `write` operation |
| Ops enum pattern | `op.rs` `Operation::CertRenew`: variant exists with real shape, engine answers `Unsupported` until wiring lands |
| Engine refusal | `engine.rs` `dispatch`: `UpdateStatus` → `Err(Unsupported)` — same shape an install op takes until it can execute |
| Privsep wire | `proto.rs` `Request::ReplaceBinary { len, sha256 }` exists but `monitor.rs` `dispatch` answers `Unsupported` |
| Request checklist | PLAN App. D: TLS → session/Bearer → CSRF triple → 256 KiB typed body → ids vs registry → `Operation` → authz → audit → no-store |
| CLI half to reuse | `run.rs` `apply_update`: prepare → probe → `install_candidate` (swap + restart + healthz + rollback) |

### The design

New `Operation::UpdateApply { version: String }` (like `CertRenew`: real
shape now, engine answers `Unsupported{ what: "update_apply" }` until the
execution path lands). New `POST /api/v1/system/update` (same path as GET,
`mutating: true` in `table()`), `WriteCaller`, `authorize` against the new
op, `state.engine.execute`, audit record on success *and* failure (PLAN §2.5:
every mutating op writes exactly one), `render_*` split so tests need no
network. Request body: `{"version": "<tag>"}` typed + `deny_unknown_fields`,
≤ 256 KiB per App. D. When the execution path later lands, refuse-closed:
no stamp with that tag, or feed unreachable from the worker, → 503/409,
never "no update". In this slice the engine answers `Unsupported`, so the
POST returns 500 `ops-unsupported` with a reason and installs nothing (decision 1 below).

### Two decisions already made, do not relitigate

* **No install from the worker in this slice.** The worker is
privilege-dropped (PLAN §2.4); the swap needs operator privileges (step 5b
runs in the CLI process) and `Request::ReplaceBinary` is still `Unsupported`
in the monitor. The POST therefore lands as: route + authz + audit + engine
`Unsupported` → 500 `ops-unsupported` with a reason, like `CertRenew` today. The later
wiring slice uses the monitor path PLAN's privilege model was built for —
**not** a queue-file-then-CLI-cron: the proto seam already exists
(`proto.rs` calls `ReplaceBinary` the deliberate stub), and the root-confined
monitor's Landlock ruleset already reserves write access to the binary's
directory. Grain: worker does fetch+verify+self-test (network + CPU,
unprivileged, reusing `detent-update`'s check/prepare/probe chain), streams
the verified image over the channel, monitor does swap+restart. Two open
pieces for that slice: (a) restart+healthz+rollback currently lives in
CLI-side `restart_and_check` — the monitor IS the process being replaced, so
it needs its own re-exec/healthz/rollback sequence, not a copy of the CLI's;
(b) the mutating-install audit record is written worker-side by the engine
(PLAN §2.5), since the monitor holds no audit store.
* **Same path, different method.** `GET` stays read-only on the stamp;
`POST` mutates. Axum routes by method on one path (`services.rs` does
`get(status).post(action)`); `table()` carries both entries. The OpenAPI
regen (`docs/openapi.json`) ships with the change, handler-doc delta only.
* **Stale doc rides with the implementation.** `system.rs`'s handler doc
still says "the check fetches the release feed over the network", which the
interval-guard paragraph below it now contradicts — fix both paragraphs in
the implementation commit, not here.

---

## 2026-09-20 - §2.9 step 6: interval-guarded check stamp lands

`detent update --check` writes `<state_root>/update/check.json` (`CachedReport`
+ `checked_at`, atomic, best-effort) and serves a fresh stamp without touching
the network; `--force` bypasses the 24 h guard. `GET /api/v1/system/update`
prefers the stamp and fetches live only when none exists yet — the `ponytail:`
note's per-request poll loop is gone. `AppState` carries `state_root`
(`update_stamp()` helper) so the endpoint never reconstructs paths per request.
`--check` JSON shape is unchanged (global `--json` flag already serializes
`CheckReport`), so (b) needed zero new code.

Deviation note: the worker only *notifies* — no `auto_install` from the
serving path. The swap runs with operator privileges in the CLI (step 5b);
the privilege-dropped worker cannot install, so a set `auto_install` surfaces
via endpoint/UI rather than executing there. PLAN's "opt-in auto_install"
wording predates the 5b privsep shape.

Design choice over a background ticker: the CLI cron is the designated
refresher; the endpoint serves the stamp however old and fetches live only on
cold start (preserving the 503 on unreachable feed). A read-scoped caller can
never force network I/O. No install POST in this slice — worker-side install
has no execution path and deserves its own design + privsep answer.

Pre-existing repairs in this diff: `rcgen` added to `[dev-dependencies]`
(health.rs tests use it un-gated; `cargo test -p detent-update` never compiled
on default features), stale step-5 doc in update.rs head, `CHECK_INTERVAL`
doc ("candidates" copy-paste → 24 h freshness window).

Tests: 153 detent + 68 detent-update + 301 detent-web pass; cache round-trip /
stale / skew / corrupt-miss / force-guard, CLI fresh-stamp short-circuit with
a panicking transport, endpoint via existing integration tests. The stamp
setup pushed the four-shapes test over clippy's 100-line limit, so it now
goes through a `run_check` helper (fresh stamp dir + Streams per call).
Workspace clippy and `cargo fmt --check` clean. `docs/openapi.json`
regenerated (handler doc only).

## 2026-09-20 - Phase 9 done: restart + healthz + rollback lands (PLAN §2.9 step 5c)

`detent update` now restarts, probes, and rolls back. The 2026-09-18 NEXT
entry's design is implemented as written: single `RestartCheck` seam in
`run.rs` (`Healthy`/`NotAService`/`Unhealthy`), `restart_and_check` reads
`detent.toml` for the listen addr and pins `bootstrap.cert.der` via
`wait_healthy` (`detent-update/src/health.rs`, committed `c79e508`), and
`Unhealthy` calls `Installed::rollback()` then restarts again. M3 acceptance
criterion's second half is met: a bad binary no longer installs and stays.

Two fixes on top of the design:
- `update` now implies `web` in `crates/detent/Cargo.toml` — the restart
check reads config and cert through `detent-web`, so an updater without it
could not compile.
- `Unsupported` maps to `NotAService`, not `Unhealthy` — `NullManager` (no
init system) and `LaunchdManager::act` (macOS status-only by design) mean no
service to restart, and rolling back a good binary there would be wrong.

Three hermetic tests in `run.rs` (`run_update_hermetic` + real atomic swap on
a temp target, scripted restart seam): unhealthy→rolled-back with the
previous binary restored and `.prev` consumed, rollback-restart failure
saying the host needs attention, `NotAService` installing without rollback.
Full `cargo test -p detent --features update`: 145 + 7 pass; clippy clean.

**Open:** §2.9 step 6 background check (daily-ish interval; replaces the
uncached-feed cache per the `ponytail:` note), `update --check --json`, the
write-scoped install POST. "Mark the release bad" stays a separate commit.

## 2026-09-18 - NEXT: restart + healthz + rollback (PLAN §2.9 step 5c)

**Status: designed, not yet implemented.** Written down before starting so it
can be picked up cold. `Installed::rollback` exists and is tested but nothing
calls it — a bad binary currently installs and stays. This is the second half
of the M3 acceptance criterion.

### The survey (already done, do not redo)

| Need | Where it already is |
|---|---|
| Restart the service | `detent_platform::service::for_host(init)` → `ServiceManager::act(&UnitNames, ServiceAction::Restart)` |
| Unit name | `packaging/systemd/detent.service` → unit is `detent`. `UnitNames` fields are `&'static [&'static str]`, so a `const DETENT_UNITS: UnitNames` works |
| Health endpoint | `/healthz` in `detent-web/src/server.rs:113` — **unauthenticated**, constant body, so no credential is needed |
| Listen address | `Config::load(path)?.listen.addr` (`detent-web/src/config.rs:214`) |
| Cert to pin | `config.tls.cert_dir` + `detent_web::tls::BOOTSTRAP_CERT_FILE` (`bootstrap.cert.der`) |
| SAN match | `tls::ALWAYS_SANS` = `localhost`, `127.0.0.1`, `::1` — connect to `localhost` and the bootstrap cert validates |
| TLS client | `detent-update` **already** depends on `rustls`, `hyper`, `hyper-util`, `hyper-rustls`, `rustls-pki-types`. No new dependency, no ADR-011 cooldown |

### The design

Put the probe in **`detent-update`** (`src/health.rs`), not in `detent`: the
HTTP/TLS dependencies are already there and `detent` has none of them. Keep it
config-free — the CLI reads `detent.toml` and passes values in:

```rust
pub fn wait_healthy(
    addr: SocketAddr,
    pinned_cert_der: &[u8],
    deadline: Duration,   // 30 s per PLAN §2.9
) -> Result<(), UpdateError>;
```

Build a `rustls::ClientConfig` whose `RootCertStore` holds **only** the cert
read off disk, connect to `https://localhost:<port>/healthz`, and poll every
500 ms until HTTP 200 or the deadline. Pinning to the exact serving cert is
both correct and simpler than trusting a CA set; do **not** disable
verification. Refuse-closed: no cert on disk → no health check → treat as
unhealthy.

### The policy, in `run.rs` after a successful `swap`

1. Restart via `ServiceManager::act(DETENT_UNITS, Restart)`.
2. `wait_healthy(...)` with a 30 s deadline.
3. On healthy → `Exit::Ok`, report the tag and `.prev` path.
4. On unhealthy or a failed restart → `Installed::rollback()`, restart again,
   report `Exit::Failed` naming what happened. If the *rollback* restart also
   fails, say so loudly — the host is then in a state only a human can fix.

**Both the restart and the health probe must be seams**, like the existing
`FeatureProbe` and `BinarySwap` in `run.rs`, so the tests stay hermetic: no
process spawn, no socket. Cover healthy, unhealthy→rolled-back, restart
failure, and rollback-restart failure.

### Two decisions already made, do not relitigate

* **No init unit / no backend is not a rollback.** If `act` answers
  `ServiceError::NoKnownUnit` or `Unavailable`, the binary is fine and simply
  is not running as a service — someone invoked the CLI on a host where detent
  is not installed as one. Report install-succeeded-but-not-restarted and exit
  `Ok`. Rolling back a good binary because the host has no systemd would be
  wrong.
* **"Mark the release bad in state" is a separate commit.** Without it a bad
  release is re-downloaded and re-rolled-back next run: annoying, not unsafe.
  Land the safety loop first.

---

## 2026-09-18 - Phase 9: the atomic swap lands

`detent update` now installs. Five signed commits today, each verified to
build on its own.

| Commit | What |
|---|---|
| `347e364` | self-test feature gate in the update flow (§2.9 step 5, first half) |
| `e86f22c` | theme script injected at build time by a vite plugin |
| `54b3b8e` | `GET /api/v1/system/update` + `Operation::UpdateStatus` + dashboard panel |
| `a58f89c` | **staged binary made executable** — see below |
| `00e35bc` | `install::swap`: atomic rename, `<target>.prev`, rollback |

| Check | State |
|---|---|
| Rust tests | 1519 pass, 0 fail, 6 ignored |
| Clippy `-D warnings` | clean |
| `cargo fmt --all --check` | clean |
| Coverage gate | PASS all thresholds; global 96.79% |
| Web tests / lint / types / i18n | 435 pass; clean; clean; 265 ids resolved |

### The trap that made the whole flow dead

`update::prepare` staged the downloaded binary with `std::fs::write`, which
creates **0644**. Step 5 *spawns* that file for `--self-test`, so the real
flow refused with `EACCES` one step before the swap: no update could ever
have installed, on any host.

Every hermetic test passed anyway. They inject the probe through a
`FeatureProbe` seam and never exec what `prepare` actually wrote, and the
probe-script helper chmods its own fixture — so the gap was invisible from
inside the seam that existed to make the flow testable. `stage_exec.rs` now
drives the real `prepare` against the ADR-014 fixture bundle and asserts the
mode; reverting the chmod makes it report `100644`. Worth remembering: a
seam that lets you test a step can also hide what that step does to the thing
it hands on.

### The swap

`install::swap` copies the candidate to a temp name **in the target's own
directory** (same filesystem), applies the *target's* mode before the rename,
fsyncs, keeps the replaced binary at `<target>.prev`, then renames over the
target. That rename is the only step that changes what the path names, and
`rename(2)` over an existing path is atomic, so a concurrent reader sees the
old binary or the new one — never missing or partial.

`.prev` is a hard link where the filesystem allows one: no second copy of the
binary, and it keeps the original bytes after the rename because the old
inode stays referenced by that name. `fs::copy` is the fallback and carries
the mode bits.

Staging happens before `.prev` exists, so any failure up to that point leaves
the directory untouched (the `NamedTempFile` removes itself on drop). If
keeping `.prev` or the rename fails, the target is still the original and any
`.prev` created is removed. Every failure test asserts both the original
bytes and the exact directory listing. A missing target, a directory and a
symlink all refuse with `BadTarget` rather than being created or followed.

### Phase 9 state

Done: release + rebuild-verify workflows, Sigstore verifier (ADR-014),
`detent update --check`, `--self-test` + feature-coverage gate,
`size-check.sh` in CI, `[update]` config, read-only update-status endpoint +
UI panel, and the atomic swap with rollback.

**Open, in the order they matter:**
1. **Restart via init + `GET /healthz` within 30 s, or roll back** (§2.9 step
   5's last third). `Installed::rollback` exists and is tested; nothing calls
   it yet, so a bad binary currently installs and stays. This is the M3
   acceptance criterion's second half.
2. §2.9 step 6's background check, with the interval below.
3. `detent update --check --json`; the write-scoped install POST for the UI.

### Pinned, not forgotten: the uncached update check

`GET /api/v1/system/update` reaches the release feed on every call, so a
read-scoped caller can make this host poll GitHub in a loop, one blocking
thread per in-flight request. Deliberately **not** cached; the reasoning is a
`ponytail:` comment at the call site.

The right mitigation is a check *period*, not a cache. Nothing about a
release feed needs to be fresher than daily — §2.9 step 6 already calls for a
background check, and a sensible default there (no more than once a day,
arguably once a week for something that ships this rarely) means the endpoint
reads the last background result and makes no network call on the request
path at all. A cache would be a second mechanism solving a problem the
interval removes. Revisit only if the interval turns out not to cover it.
---

## 2026-09-18 - Update status endpoint + theme-script injection

Picked up omp's uncommitted tree. It did **not** pass its gates — `cargo fmt`
was dirty, clippy failed on `detent-update/tests/verify_fixtures.rs`, and
`biome` failed on `web/index.html`. Fixed, then finished the work.

| Check | Command | State |
|---|---|---|
| Rust tests | `cargo test --workspace --all-features` | 1506 pass, 0 fail, 6 ignored |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| Format | `cargo fmt --all --check` | clean |
| Rust coverage | `cargo llvm-cov` + `scripts/coverage-merge.sh` | PASS all thresholds; ops back to 100%, global 96.80% |
| Web tests | `cd web && bun run test` | 435 pass, 53 files |
| Web lint/types/build | `bun run lint && bun run typecheck && bun run build` | clean; CSP hash OK |
| Web i18n | `bun run i18n:check` | 265 ids, all referenced, all resolved |

**`GET /api/v1/system/update`** (omp's, reviewed and kept): read-only update
status, `spawn_blocking` around the 30 s feed fetch, refuse-closed on an
unreachable feed (503 `web-update-check-failed`, never folded into "no
update"), and a `UpdateReport` mirror of `CheckReport` so `detent-update`
keeps no `utoipa` dependency. Its `update_report` seam is driven by mock
transports and the unit tests are non-vacuous — that part needed no changes.

**Gave it `Operation::UpdateStatus`.** It was authorizing against
`Operation::HostProfile`'s identity — the same borrowed-identity defect fixed
for `/api/v1/system/cert` on 2026-09-17, with a comment deferring it. The
engine still cannot answer an update check (the feed lives in
`detent-update`), so the variant answers `OpsError::Unsupported` there and
exists for the policy decision and the audit label, exactly like `CertStatus`.
Added `audit-op-update-status`, regenerated `docs/openapi.json` and
`schema.d.ts`, and added the engine-dispatch test that the 100% `detent-ops`
gate immediately demanded.

**Theme-script injection, two real defects.** omp moved the inline theme
script out of `index.html` behind a `<!--THEME_INIT_SCRIPT-->` placeholder
injected by a new vite plugin, and deleted
`the_inline_script_in_index_html_is_the_file_byte_for_byte` from `headers.rs`.
The deletion is **correct** — the source page no longer holds the script, and
`scripts/build-finish.ts` already re-hashes the *built* page against the pinned
constant and fails the build, which is the stronger check. But:

* the plugin carried `apply: 'build'`, so in `vite dev` the placeholder
  survived into the page, where `<!--…-->` is a legacy JS line comment: the
  theme silently never initialised and every dev reload flashed unthemed.
  Dropped the `apply` gate; verified in the browser that dev now sets
  `data-theme="dark"` and leaves no placeholder.
* an empty `<script>` holding the placeholder is not parseable JavaScript, so
  `biome` failed on `index.html`. The placeholder is now a bare HTML comment
  and the plugin injects the whole element.

While fixing that, the CSP gate caught my own first attempt: the explanatory
comment I wrote contained a literal script tag, and `build-finish`'s
`inlineScript()` regex matched *that* before the real one. Reworded, and the
comment now warns the next person. The gate did its job.

`verify_fixtures.rs` is DER surgery on self-minted fixtures — raw indexing,
two-byte length arithmetic and `usize as u8` length bytes are the job. One
documented file-level `allow` (matching the file's existing `expect_used`
posture) rather than six scattered ones; `items_after_statements` was fixed
properly by moving the consts, not suppressed.

Added a `web-dev` entry to `.claude/launch.json` so the dev server is
launchable for exactly this kind of check.

---

## 2026-09-18 - Updater (`44618d0`, signed)

ADR-014 (sigstore verifier) flipped to Accepted + indexed. `--self-test` features gated on cfg with pin test; `--self-test` with subcommand rejected as usage error. `run_update_on` seam extracted with hermetic tests; hermetic coverage tests for run/output/doctor added.

| Check | Command | State |
|---|---|---|
| Rust tests | `cargo test --workspace --all-features` | 1488 pass, 0 fail, 6 ignored |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean (fixed `unused_mut`/unused `notes` in `output.rs` error sweep) |
| Format | `cargo fmt --all --check` | clean |
| Rust coverage | `cargo llvm-cov --workspace --all-features --lcov` + `scripts/coverage-merge.sh --verbose` | PASS: detent 95.20% (5592/5874), core 100%, modules 100% |
| Web tests | `cd web && bun run test` | 430 pass, 53 files |
| Web lint/types | `cd web && bun run lint && bun run typecheck` | clean |

Coverage gap closed test-only: eager (non-short-circuit) write-failure asserts + widened `FailAfter` sweep in `output.rs`, `planned`/`host_profile`/`applied_without_commit`/`dry_run_plan` fixtures in `tests_support.rs`, `run_worker` handshake-failure + dry-run tests in `serve.rs`. New `detent-update` verifier: `bundle`/`fetch`/`policy`/`trust`/`update`/`verify` + fixtures + trust roots (ADR-014). CLI: `--self-test` feature gating + usage rejection, `run_update` seam, `help.txt` + `cli.ftl` updates.

---

## Where things stand — 2026-09-18 (updater `44618d0` + `f344203` on top of `0add9a6`)

**Phase 6 (ACME) done. Phase 7 waves 1–2 done (8/8 modules). Supply-chain allow + cooled web pins + updater (`detent-update` verifier, CLI wiring, 95.20% coverage) landed — 4 signed commits.**

Branch: `main` @ `f344203`. Working tree clean. Everything below verified,
not assumed.
|---|---|---|
| Rust tests | `cargo test --workspace --all-features` | 1488 pass, 0 fail, 6 ignored |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| Format | `cargo fmt --all --check` | clean |
| Rust coverage | `cargo llvm-cov --workspace --all-features --lcov --output-path /tmp/w.info` + `scripts/coverage-merge.sh --verbose --output /tmp/merged.info /tmp/w.info` | PASS: detent 95.20% (5592/5874), detent-core 100% (1006/1006), modules 100% (9848/9848) |
| Web tests | `cd web && bun run test` | 430 pass, 53 files (`bun test`) |
| Web lint | `cd web && bun run lint` | clean (biome) |
| Web types | `cd web && bun run typecheck` | clean |
| Web i18n | `cd web && bun run i18n:check` | 257 ids, all referenced, all resolved |

Committed: updater (`detent-update` Sigstore verifier per ADR-014: `bundle`/`fetch`/`policy`/`trust`/`update`/`verify` + fixtures + trust roots; CLI `--self-test` gating + usage rejection, `run_update` seam, `help.txt` + `cli.ftl`; test-only coverage to 95.20%) as `44618d0` (signed, `git commit -S -s`), plus `detent-module-dhcp` (dnsmasq + Kea v4/v6) + `detent-module-network`
(systemd-networkd, NetworkManager, ifupdown, netplan) with
`crates/detent-modules` registry wiring (`dhcp()`, `network()`), 26+ Fluent
ids each in `core.ftl`, `upstream.toml` + fixtures + fuzz targets + corpus
for both, `Cargo.lock`/`fuzz/Cargo.lock` updated. Empty
`conformance.proptest-regressions` removed before staging (0-byte artifact).
Committed as `907316e` (signed, `git commit -S -s`). Next: Phase 7 wave 3 or
remaining PLAN §5 work.

The six ignored Rust tests are deliberate: `write_openapi_json` regenerates a
checked-in artefact, `crash_child_worker` is the child half of the
crash-consistency test, the Argon2 equal-cost test is wall-clock timing, two
are `conformance.rs` doc examples, and `pebble_dns01_issuance` needs a live
Pebble + challtestsrv (Phase 6 spike, `docs/spikes/acme-le.md`).

### What exists

**Rust** — 19 crates. `detent-core` (CST, model, schema, diag), `detent-i18n`
(Fluent), `detent-platform` (host detection, privsep monitor/worker, sandbox,
service managers), `detent-ops` (the 17 operations, authz, audit),
`detent-modules` (registry; `hosts`, `resolver`, `chrony`, `mounts`, `nfs`,
`samba`, `dhcp`, `network` implemented), `detent-web` (axum,
rustls TLS 1.3 only, auth, CSRF, API, SPA serving), `detent` (clap CLI), plus
`detent-acme` (`DnsProvider`/`HookProvider` + async `order.rs` on `instant-acme =0.8.5`, aws-lc-rs only, `cargo tree -i ring` empty), `detent-update`, `detent-mcp` skeletons. PEM-to-serve bridge landed (`b51aec8`): `CertifiedKeyPair::from_acme_pem` parses `finalize` output into the DER pair `CertStore::replace` swaps live.

**Web** (`web/`) — Vite + React 19 + Tailwind v4 + Fluent. Done: design tokens
and theme rocker, status bar (with locale selector), hairline layout
primitives, the typed API client generated from `docs/openapi.json`,
`AuthProvider`/`ScopeGate`, router with `RequireAuth`, the login page, and
the **schema-driven form engine** (`src/forms/`) with validation mirroring
the backend. Pseudo-locale (`locales/qps-ploc/web.ftl`) generated at build
time by `bun scripts/gen-pseudo.ts`; language switcher in the status bar,
persisted in localStorage. Responsive: status bar fits 390px (tighter
padding + online-label hidden below 560px).

Routed sections: dashboard, modules, module detail, services, backups, audit
and certificates are real pages, each in its own file under `src/routes/`.

Tests run on **`bun test`**, not vitest — see [`TOOLS.md`](TOOLS.md) for the
preload that gives Bun a DOM, Vite's `?raw` imports and jest-dom's matchers.
Playwright drives the built bundle against a stubbed API (`web/e2e/`), with
axe-core over every section in both themes.

**Not done in `web/`** — settings is still a placeholder in
`src/routes/pages.tsx`, deliberately: it needs user- and token-management
endpoints that do not exist. Certificates ships a full read-only page
(`CertificatesPage.tsx` + shared `src/lib/cert.ts`, via `GET
/api/v1/system/cert`); renewal wiring is still Phase 6. Also missing: e2e
against the real binary rather than a stub.

### Traps worth knowing before you touch anything

- **`bunfig.toml` must sit beside `package.json`** (`web/`), never at the repo
  root — bun reads it from the install cwd only. It carries the ADR-011 7-day
  dependency cooldown; at the root it silently did nothing.
  `scripts/cooldown-check.sh` guards this in CI.
- **`docs/openapi.json` is generated by the test suite, not by hand.** Change a
  handler's `#[utoipa::path]`, then:
  `cargo test -p detent-web --all-features api::openapi -- --ignored write_openapi_json`,
  then `cd web && bun run api:generate`. A test fails if either drifts.
- **utoipa is a dev-dependency.** Nothing about the document is compiled into a
  release build; the handler serves an `include_str!` of the checked-in file.
  Worth ~280 KiB. Do not "simplify" it back to `ApiDoc::openapi()`.
- **The CSP pins the SHA-256 of the inline theme script**, whitespace included.
  `web/scripts/build-finish.ts` fails the build if `index.html` and
  `web/src/theme-init.js` diverge by a byte.
- **Linux-only code never runs on the macOS dev host.** Use the test hosts
  (below) before believing a sandbox change works. A capability test reached CI
  unrun for exactly this reason.
- **`scripts/checkWorkflows.sh` re-triggers failed GitHub workflows.** Pass its
  `DRY_RUN` flag unless you mean to dispatch.
- **The body is `text-transform: lowercase`** (AESTHETIC_CONTRACT §1), which
  would edit host-supplied text on its way to the screen. `.read`, `.readout`,
  `.dtable td` and `.verbatim` opt out. **Put host text inside one of them** —
  a unit name, a path, a digest, a diff. `NetworkManager` shown as
  `networkmanager` is a daemon an operator cannot paste into a shell, and a
  lowercased diff is not the bytes that will be written.
- **`stubFetch` in `src/test/providers.tsx` answers in call order**, which no
  page can rely on — every one of them races `AuthProvider`'s session probe.
  Use `stubFetchByUrl`. Three separate tasks each hit this and each invented
  their own copy before it was shared.
- **`locales/qps-ploc/web.ftl` is generated, not checked in.** Run
  `cd web && bun run i18n:pseudo` (or it runs automatically before
  `bun run test` and `bun run build`). The file is gitignored. If you see
  "Cannot find module" errors from `src/i18n/index.tsx`, the pseudo FTL
  hasn't been generated yet.

### Test hosts

- **testhost2** — Ubuntu 26.04, x86_64, systemd-networkd. Builds are fine here.
- **testhost-arm** — Raspberry Pi OS, aarch64, NetworkManager. **Do not build on it**;
  cross-compile with `cargo zigbuild --target aarch64-unknown-linux-musl` and
  copy the binary over.

`sudo` on both. **testhost-arm has no Landlock at all** — `CONFIG_SECURITY_LANDLOCK` is
not set in `6.18.39+rpt-rpi-v8`, so no boot parameter enables it. detent runs
there and says so; seccomp and the capability drop are the confinement.

### Known gaps (also tracked in `SECURITY_HARDENING.md`)

- `require_caps` does not exist: the capability bounding-set drop **fails
  open**, unlike seccomp which fails closed. Closing it needs the worker's
  confinement order relative to its uid drop checked first.
- The modal does not set `inert`/`aria-hidden` on background content. The
  axe pass is clean, but that is not a refutation: axe has no rule for it, so
  this needs a manual screen-reader check rather than another automated one.
- `scripts/tls-check.sh` is not wired into CI (needs root; now feasible on
  testhost2).
- Phase 2's privileged Docker job and multi-slice LCOV merge are unwired.
- `detent-web` coverage floor is 97 (PASS at 97.04%), not the 100 Phase 4 set for itself.

---
## Log
### 2026-09-18 — Cooled web pins (`0add9a6`)
Bun-only: react/react-dom 19.2.8→19.3.0, @testing-library/react 16.3.2→16.3.3, user-event 14.6.6→14.6.7, @types/react 19.2.18→19.3.0, @types/react-dom 19.2.4→19.3.0, plugin-react 6.1.0→6.1.1, vite 8.2.2→8.3.0 — every publish date ≥7d per ADR-011 (`web/bunfig.toml` minimumReleaseAge 604800). TS held at 6.0.3: 7.0.2 tried and reverted — `openapi-typescript@7.13.0` (latest dist-tag) crashes on TS7 (`ts.factory.createKeywordTypeNode` TypeError in `api-check`); retry when upstream ships TS7 support. Cargo: no cooled patch/minor (`embedded-io` 0.4→0.6 is a transitive 0.x major via postcard, left alone). Gates: cooldown-check OK, deny all-ok, fmt clean, clippy clean, cargo test 1424 pass / 6 ignored, web typecheck/lint/biome clean, bun test 430 pass, i18n 257 ids, build CSP OK, api-check EXIT 0 on installed TS 6.0.3. Committed `web/package.json` + `web/bun.lock` (26 ins/26 del, signed).
### 2026-09-18 — CDLA-Permissive-2.0 allow (`48d3389`)
`deny.toml` allow += `CDLA-Permissive-2.0` for `webpki-root-certs 1.0.9` (Mozilla root-cert data via `rustls-platform-verifier → hyper-rustls → instant-acme → detent-acme`). wasm32-only + upstream dev-dep — Linux/Pi use `rustls-native-certs` OS store, nothing bundled. `cargo deny check` all-ok. Committed signed, 1 file +4.
### 2026-09-18 — Phase 7 wave 2 committed: dhcp, network land (`907316e`)
Two modules implemented via subagents (orchestrator wired registry/shared
files, verified independently): `detent-module-dhcp` (dnsmasq + Kea v4/v6 —
`sync_list_member` shared primitive, trailing-comma re-parse refusal test),
`detent-module-network` (systemd-networkd, NetworkManager, ifupdown, netplan —
double-`i += 1` fix in `build_model_from_lines`, dead-guard deletion net -86
lines, NM route-drop by design). Registry: `dhcp()`, `network()` in
`crates/detent-modules`; 8/8 modules registered. Fixtures + `upstream.toml` +
fuzz targets + corpus for both. Gates: workspace 1424 pass / 0 fail /
6 ignored; clippy/fmt clean; coverage-merge PASS (detent-core 100%
1006/1006, modules 100% 9848/9848); web 430 pass, lint/typecheck/i18n clean.
Committed: 61 files as `907316e` (signed
`git commit -S -s "Add dhcp and network modules"`); empty
`conformance.proptest-regressions` removed before staging (0-byte artifact),
working tree clean.
### 2026-09-18 — Phase 7 wave 1 done: chrony, mounts, nfs, samba land

Four modules landed via subagents (orchestrator wired shared files, verified
independently): chrony 4.9 (GitLab canonical URL — tuxfamily defunct, HTTP 500),
mounts util-linux 2.42.3 (commit_confirm true — bad fstab bricks boot),
nfs nfs-utils 2.9.2 (`steved/nfs-utils.git` — both candidate URLs dead, tag list
scraped), samba 4.24.7 (verbatim upstream smb.conf.default fixture).
Gates: workspace 1284 pass / 0 fail / 6 ignored; clippy/fmt clean;
coverage-merge PASS (detent-core 100% 1006/1006, modules 100% 5335/5335);
web 430 pass, lint/typecheck clean; fuzz bins x12 compile (`fuzz/Cargo.toml`
manifest check). Registry: hosts, resolver, chrony, mounts, nfs, samba;
`dhcp`, `network` still stubs. Next: Phase 7 wave 2 (dhcp, network) per PLAN §5.
Follow-ups on this tree: `core.ftl` samba block moved after resolver
(alphabetized `nfs → resolver → samba`); `CertStatus` engine arm covered by
`cert_status_is_unsupported_in_the_engine_and_writes_no_audit_record`
(read-only ops return before auditing, so zero audit records — the `CertRenew`
test is the mutating contrast). Web 430 pass (one fewer: KickerTag deleted).

### 2026-09-18 — Module handler tails + upstream tag fallback (`f23b867`)

`EngineHandle::stubbed(outcome)` + 5 tests cover `api/modules.rs`
`render_*` tails (211/253/295/350) and malformed-id POST 404s
(244/286/330). `upstream-watch.yml`: `repo_url` tag fallback
(`git ls-remote --tags --refs | sort -V | tail -1`) + open-issue dedup.
Gates: workspace 1070 pass / 0 fail / 6 ignored; clippy/fmt clean.
`scripts/coverage-merge.sh --verbose /tmp/a.lcov`:
`per-path crates/modules/: lines 100.00% (min 100%, 2546/2546 lines)`,
`per-path crates/detent-web/: lines 97.04% (min 97%, 7419/7645 lines)`,
`PASS: all coverage thresholds met`. Floors unchanged (modules 100, web 97).
FAKE_VERSION=0.0 drift path proves YES for hosts+resolver (stubbed
`latest`; `tracked` override works). `ubuntu-26.04` label is repo-standard
 (16 jobs); actionlint's unknown-label warning is its stale builtin list.

### 2026-09-18 — Resolver module lands (Phase 7 wave 1)

`detent-module-resolver` (lossless resolv.conf + resolved.conf + unbound.conf,
registry `resolver()`, 26 Fluent ids, `upstream.toml` systemd 257.6,
7 fixtures, 3 fuzz targets + corpus, `upstream-watch.yml` weekly):
Gates: `cargo test --workspace --all-features` 51 ok / 0 failed;
`cargo test -p detent-module-resolver --all-features` 48 lib + 17 conformance;
`cargo test -p detent-modules` 3 pass;
`cargo clippy --workspace --all-targets --all-features -- -D warnings` clean;
`cargo fmt --all --check` clean;
`cargo llvm-cov --workspace --all-features` +
`scripts/coverage-merge.sh --verbose`: `crates/modules/` 100% (2536/2536) PASS,
`detent-web/` 96.95% (7403/7636) FAIL pre-existing (311 DA: `tls.rs` 279 +
`api/modules.rs:211,244,253,286,295,330,350` handler tails; `git diff HEAD --
crates/detent-web/` empty) — deferred, floor stays 97.
Schema `x-detent` hints on resolv/resolved/unbound render via generic
`web/src/forms` engine (no custom widget). Fake-old `tracked_version=0.0`
proves the watch issue path. VM spike `docs/spikes/m-resolver.md` deferred.


### 2026-09-18 — CertRenew op + half/quarter cert warnings land

`Operation::CertRenew` (`682458c`): engine answers `Unsupported{what:"cert_renew"}`
(`ops-unsupported`, audited `Error`, one record) until ACME config/scheduler lands;
`Scope::Write`, `OpKind::CertRenew`, `docs/openapi.json` + `web/src/api/schema.d.ts`
regenerated together. Web derives amber from `lifetime_used_percent` via
`certWarning` (half at 50 %, quarter at 75 %, mirroring
`detent-acme::schedule::warning_for`) with the 30-day wall-clock floor as fallback;
`dashboard-cert-half|quarter` + `audit-op-cert-renew` Fluent ids; all four banners
(expired > quarter > half > 30-day) locked in `CertificatesPage` tests, `cert_renew`
caption in audit `OP_CASES`. Full renewal flow (order/install/`CertStore::replace`)
stays deferred to the ACME-config phase. Gates: Rust 999 pass, 6 ignored;
clippy/fmt clean; web 431 pass, typecheck/lint/i18n/api/contrast clean; build OK.

### 2026-09-18 — Read-only certificates page lands

`web/src/routes/CertificatesPage.tsx` (`af521f2`): full-page read of the
serving certificate via the same `useCert()` hook the dashboard `CertPanel`
uses — fingerprint verbatim, locale-formatted expiry, percent used, amber
banners inside 30 days or past expiry, `unknown` fallback when DER does not
parse. Shared tone rule extracted to `web/src/lib/cert.ts`
(`certTone`/`certExpired`/`certGridItems`) so dashboard and page cannot
disagree; `AppRoutes` routes `/certificates` to it, `pages.tsx` keeps only
the `SettingsPage` placeholder (blocked: needs user- and token-management
endpoints `docs/API.md` does not describe). Gates: web 428 pass / 53 files;
typecheck/lint/i18n/api-check/contrast clean; build OK (CSP hash OK);
Playwright 22 pass; Rust fmt/clippy clean, `detent-acme` 42 pass / 1
ignored, `ring` absent.

### 2026-09-18 — device-attest-01 attestor seam lands

`crates/detent-acme/src/attest.rs` + `order::present_attest_challenges`
(`18b2835`): `Attestor` trait (sync, object-safe, `attest(key_id,
key_authorization) -> att_obj`) mirroring `DnsProvider`, with a deterministic
`TestAttestor`; the driver walks pending authorizations, takes the
`DeviceAttest01` challenge, and calls `send_device_attestation`. New
`AcmeError::NoDeviceAttestChallenge`. Real TPM 2.0 (`tss-esapi`) stays behind
the `acme-attest` feature — no new deps (ADR-011). Commit `18b2835`. Gates:
`detent-acme` 42 pass, 1 ignored; workspace clippy `-D warnings` clean; fmt
clean; `ring` absent.

### 2026-09-18 — Pure renewal-scheduling predicates land

`crates/detent-acme/src/schedule.rs` (`4d1af85`): stdlib-only
`percent_used`/`warning_for`/`should_renew`/`should_renew_in_window` — i128
math, broken lifetime → 100, skew → 0, renew at ≥66 % before the 75 % warning,
ARI window narrows with a ≥90 % override. No sleep, no `time` dep (ARI fetch
stays with the caller; `instant-acme` `time` feature would need ADR-011).
Commit `4d1af85`. Gates: `detent-acme` 39 pass, 1 ignored; workspace clippy
`-D warnings` clean; fmt clean; `ring` absent.

### 2026-09-18 — DNS providers land (Cloudflare/acme-dns/deSEC + RFC 2136 message)

`crates/detent-acme/src/providers.rs` (`1c829db`): four `DnsProvider` impls,
sync + object-safe, same idempotency contract as `HookProvider`. HTTPS trio
drives APIs through a stubbed transport seam with recorded fixtures (list →
PUT-refresh/POST-create, delete tolerates gone, `wait_propagated` re-lists);
`Debug` redacts every secret (log-capture test). RFC 2136 builds the full
UPDATE wire message (zone SOA + class-ANY delete + TXT add, unit-tested byte
lengths) but refuses to send unsigned — TSIG needs HMAC, a new dep awaiting
ADR-011. No sleeps in lib, no new deps, `ring` absent. Commit `1c829db`.
Gates: `detent-acme` 35 pass, 1 ignored; workspace clippy `-D warnings` clean;
fmt clean.

### 2026-09-18 — Serving certificate status endpoint + dashboard readout

Read-only `GET /api/v1/system/cert` serves `CertReport` (`fingerprint`,
`not_after_unix`, `lifetime_used_percent`) from the live `Arc<CertStore>` —
the same cert handshakes answer from, never stale. Gated by the same policy
as `HostProfile` (`authorize(&caller, &Operation::HostProfile)`); documented
in `docs/openapi.json`, TS regenerated. Dashboard `CertPanel`: fingerprint
(verbatim), locale-formatted expiry, percent used, amber banner inside 30
days or past expiry, `unknown` when DER does not parse. DER dates hand-parsed
in `tls.rs` (`validity_unix`, no new dep). e2e stub answers `/system/cert`.
Commit `588cdda`. Gates: workspace 975 pass, 6 ignored; clippy clean; fmt
clean; web 425 pass, lint/typecheck/i18n/api-check clean.

### 2026-09-18 — Cert store reaches AppState

`AppState` carries `cert_store: Arc<CertStore>`; `bind_web_server` clones the
live handle in so status/renew ops can `replace` without a restart. Tests use
a throwaway `test_cert_store()`. Gates: workspace 974 pass, 6 ignored; clippy
clean; fmt clean; `ring` absent.

### 2026-09-18 — Serve keeps the live cert handle

`bind_web_server` returns `BoundWebServer { server, store }` and
`PreparedWorker` retains the `Arc<CertStore>`: the resolver the listener
answers from now survives startup, so a future renewal task has a live
handle to `replace` on. Gates: workspace 974 pass, 6 ignored; clippy clean;
fmt clean; `ring` absent.

### 2026-09-18 — CA profile threads through orders

`account_and_order` takes `profile: Option<&str>` (`334237b`): `None` for
Pebble (no profiles extension), `Some("shortlived")` for production.
`profile_selection_serializes_onto_the_order` proves the `NewOrder` body.
Workspace: 974 pass, 6 ignored; fmt + clippy clean; `cargo tree -i ring` empty.

### 2026-09-17 — Cert hot reload proved live

`crates/detent-web/tests/tls.rs` keeps the `Arc<CertStore>` the server
answers from (`f588f34`): `a_swapped_certificate_serves_without_a_restart`
handshakes TLS 1.3, calls `CertStore::replace`, and handshakes again with the
renewed cert — Phase 6 Task 5, no restart. `cargo test --workspace
--all-features`: 973 pass, 6 ignored; `cargo build -p detent-web` ok;
`cargo tree -i ring` empty; fmt + clippy clean.

### 2026-09-17 — ACME PEM-to-serve bridge

`CertifiedKeyPair::from_acme_pem` parses `finalize` output (PEM chain + PEM
PKCS#8 key) into the DER pair `CertStore::replace` already swaps live — the
seam Phase 6 renewal needs, proved by `acme_pem_round_trips_through_a_store_swap`
and `acme_pem_rejects_the_wrong_armour_with_a_catalogued_id`. Wrong-armour key
material (SEC1 `EC PRIVATE KEY`) is refused, not converted; new
`web-tls-acme-pem-rejected` catalogue id. `cargo test -p detent-web`: 284 pass,
2 ignored; fmt + clippy clean.

### 2026-09-17 — Pebble dns-01 now gated in CI

`d17b6c8` gates Phase 6 Task 1 in CI: `acme-pebble` job on `ubuntu-26.04` host (Harden Runner audit, `dtolnay/rust-toolchain` via `RUST_TOOLCHAIN`, `rust-cache`, `cargo build` + `clippy` on `detent-acme`), shared bridge `detent-pebble` so `pebble -dnsserver challtestsrv:8053` resolves challtestsrv by name (not `127.0.0.1`; flag gotchas in `docs/spikes/acme-le.md`), publish still via `127.0.0.1:8055/8053` from the runner, health loop + dns preflight (`curl /set-txt` → `dig @127.0.0.1 -p 8053` → `clear-txt`), then `cargo test -p detent-acme -- --ignored --nocapture`. Prior spike `51083b7`/`576a6a1` already verified 970 pass / 6 ignored workspace-wide (incl. `#[ignore]` live test) and `cargo tree -i ring` empty; this commit makes the same issuance replay on every push.

### 2026-09-17 — Pebble dns-01 spike, Phase 6 moving

`order.rs` drives `instant-acme 0.8.5` (aws-lc only, `cargo tree -i ring` empty): `account_and_order` (0600 credential cache, pid-suffixed tmp+rename), `present_challenges` (HookProvider file is the contract, test-side bridge POSTs to challtestsrv, `dig` confirms propagation), caller-owned `wait_ready`/`finalize` retry loops, no sleeps in the lib. `tests/pebble_live.rs` (`#[ignore]`) got a real chain from Pebble (2 PEM blocks, serial `48B71D…`, SAN `le.wtf`); assertions stay std-only (PEM→DER, SEQUENCE tag, domain bytes in leaf DER) rather than a new X.509 dep. Transcript + gotchas (`-dnsserver` flag, no `DNSResolver` config key, scratch-built Pebble) in `docs/spikes/acme-le.md`. ARI deferred to the renewal scheduler, which will have a prior cert to `replaces`. Verified 970 pass / 6 ignored workspace-wide. Commits: `576a6a1` (atomic hook writes), `51083b7` (spike).

### 2026-09-17 — Milestone M2 reached, Phase 6 next
Phase 6 slice 1 landed (`e4fe5f3`): `DnsProvider` trait + `HookProvider` in `detent-acme`, 13 tests, workspace 965 pass. Next: instant-acme order flow against Pebble (needs cooldown-cleared dep review).



### 2026-09-16 — bun test, Playwright, axe, and a dark default

`web/` moved off vitest onto **`bun test`**; `vitest`, `@vitest/coverage-v8`
and `jsdom` are gone. The runner needs a preload for a DOM, Vite's `?raw`
imports and jest-dom's matchers — `web/src/test/preload.ts`, proved
load-bearing by disabling it and watching `document` disappear.

Swapping the DOM shim found two tests that had been passing for the wrong
reason under jsdom:

- **`readTheme` never exercised its OS-preference branch.** jsdom answered
  every `matchMedia` query `false`, so "defaults to dark" was reached by
  accident; happy-dom reports a light preference and the same test failed
  while the code did exactly what it documented. AGENTS.md fixes the default
  as **dark**, so the branch is gone: an OS setting no longer overrides a
  stated guarantee. `src/theme-init.js` and the CSP hash in `headers.rs` were
  updated to match — the inline script paints the first frame and must agree
  with `readTheme`, or the operator sees a flash of the wrong theme.
- **`spyOn(Storage.prototype, …)` intercepts nothing under happy-dom**, whose
  `Storage` is a proxy. Both storage failure tests installed a spy cleanly and
  tested the happy path twice. They now swap the whole `localStorage` accessor,
  with a tripwire case that fails if the swap stops being reached.

Playwright + axe then found four more, none of which a DOM-shim test could
see:

- **A `Readout` outside a `Screen`** on the module page put `--screen-blue`
  text on the chassis — a real contrast failure, caught by axe, invisible to
  `contrast:check` because that scans tokens rather than compositions.
- **Focus was lost when a dialog closed.** The trigger disables itself while
  its request is in flight, so focus had already fallen to `document.body`
  before the dialog opened; `Modal` then "restored" it there. `Modal` no longer
  treats the body as a place focus was, and the module page remembers its own
  trigger.
- The `text-transform` rule from the previous entry now has a browser-level
  test — the only place it can be checked.

### 2026-09-16 — checkpoint hygiene

Scratch scripts and one-off tools belong under `/tmp`, never in the repo —
`scripts/` holds CI-running helpers only. Claude's `scripts/clean.sh` was
dropped from the Phase 5 checkpoint for this reason; its `docs/TOOLS.md`
reference stays missing until the owner fills it in. Harness: keep excluding
it (and any new scratch) from commits.

### 2026-09-16 — Phase 5 route pages

Dashboard, modules, module detail, services, backups and audit are real pages
now, built on the form engine and typed hooks that already existed. Six new
files under `src/routes/`, 333 tests at the time.

Three defects worth remembering, all found in review rather than by a test:

- **Host text was being lowercased on its way to the screen** by the body's
  `text-transform`. Worst instance was the plan dialog's unified diff — the
  operator approves an apply on the strength of those bytes, and they were not
  the bytes. `.verbatim` is the opt-out; see the traps above.
- **The module page's outcome banners never cleared on edit.** "passed every
  check" stayed on screen after the model it described had been changed — the
  one stale state that tells an operator it is safe to stop.
- **The apply dialog's service-action menu showed raw enum values**, though
  `services-action-*` ids existed. Both pages now share `serviceLabels.ts`.

Also: `stubFetchByUrl` moved into `src/test/providers.tsx` after all three
tasks independently worked around the call-order `stubFetch`, and the guard
tests in `routing.test.tsx`/`App.test.tsx` were re-pointed at an inert
placeholder route so they test the guard rather than a page's queries.

`i18n:check` now fails on an id nothing references, which removed twelve dead
messages from the shipped bundle.

### 2026-09-16 — `/api/v1/openapi.json` closed

It was served unauthenticated. That is a map of the whole attack surface —
every path, parameter and body shape — readable by anyone who could reach the
port, and nothing needed it open: the console's typed client is generated from
the checked-in copy at build time, never fetched at runtime. The handler now
takes a `Caller`.

Added `no_api_route_is_reachable_without_a_credential`, a sweep driven off
`api::table()` rather than a hand-written list, so a future handler that
forgets its `Caller` fails here instead of shipping open. Verified
non-vacuous by removing the argument and watching it fail.

`/healthz` stays open: a liveness probe has no credential to present and its
body is a constant that leaks no version.

### 2026-09-17 — Phase 6 adversarial review, fixes and coverage gate

Reviewed `6adfb7e..8b3c5da` (the Phase 6 ACME range) for idiomatic Rust and
test coverage. Four real defects found and fixed.

**1. `CertifiedKeyPair::from_acme_pem` dropped the intermediate chain.**
`CertificateDer::from_pem_slice` takes only the first PEM block, and
`to_certified_key` served `vec![leaf]`. A public CA's intermediate is in no
trust store, so a leaf sent alone fails path building on any client that has
not cached it (RFC 8446 §4.4.2). The pair now carries `intermediates` and
serves leaf-first. Latent — nothing called it yet — but it would have broken
the first real certificate. `acme_pem_keeps_every_certificate_in_the_chain`
pins it; proved non-vacuous by restoring the old one-cert behaviour.

**2. `load_or_create_account` treated every read failure as "no account".**
`if let Ok(json) = read_to_string(..)` meant EACCES/EIO on an existing
credential file fell through to registering a **second** ACME account and
renaming over the first one's credentials — silent identity rotation, old key
destroyed. Extracted `read_credentials`, which propagates everything but
`NotFound`. The read now happens *before* the `Account::builder()` call, so
the failure is reported without a crypto provider having to exist — which is
also why the test runs under `--workspace --all-features`, where both rustls
providers are enabled and `builder()` panics on an ambiguous default.

**3. `/api/v1/system/cert` authorized as `Operation::HostProfile`.** It
borrowed another operation's identity for the policy decision and the audit
label. Added `Operation::CertStatus` / `OpKind::CertStatus` (read scope, no
module, `audit-op-cert-status`). Note the *narrower* finding: an unaudited
success is not a defect — `engine.rs:158` returns before auditing for every
read-only op by design (PLAN §2.5). An audit-on-refusal branch was written and
then removed: `Scopes::allows(Scope::Read)` is unconditionally `true` and
`ScopedAuthz` is the only `Authz` impl, so a read op cannot be denied and the
branch was unreachable.

**4. `zone_of` derived the RFC 2136 zone by stripping the first label.**
`_acme-challenge.a.b.example.com` yielded `b.example.com`, which is not the
SOA-bearing zone unless it happens to be — NOTAUTH from the primary. The zone
is now a required `Rfc2136Provider::new` argument (a challenge name cannot
identify its zone without an SOA lookup), and `zone_for` refuses a record
outside it, including the `notexample.com` suffix trap.

Also restored `assert_eq!(with_module, 8)` in `op.rs`, deleted rather than
updated when `CertRenew` landed — the counter was still being summed and never
checked.

**Coverage.** `crates/detent-acme/` had **no `per_path` entry**, so Phase 6 was
ungated. Now at 87 (measuring 87.85 on macOS; the one-point margin matches the
Linux/macOS spread the note already records for detent-platform). `order.rs`
went 28.70% → 49.44% and `providers.rs` 89.83% → 95.17%. The remaining
`order.rs` gap is `present_challenges`, `present_attest_challenges`,
`wait_ready` and `finalize`, which all need an `instant_acme::Order` that
cannot be built without a live client — only `tests/pebble_live.rs` (`#[ignore]`)
reaches them. `/api/v1/system/cert` had zero Rust tests and now has two.

**PONYTAIL.** Applied the confirmed items (`ui/button.tsx` + the
`class-variance-authority` dep, `ui/tooltip.tsx` inlined into `FieldFrame`,
`KickerTag`, `SCOPE_READ`/`hasScope`, `WriteGate`/`useCanWrite`, `statusOf`,
`NullAuthAudit` and `TestAttestor` behind `#[cfg(test)]`, `Display for
HookProvider`, `HookProvider::state_dir`, `BoundWebServer`, two dead scripts,
two linter.yml flags). Five of its claims were **wrong** and were left alone:
`NoSandbox` has live callers (`doctor.rs:246`); `lib/storage.ts` has two
consumers, not one; the ci.yml shell job is the repo's only bash lint
(super-linter sets no `VALIDATE_BASH_*`); Checkov scans `docs/openapi.json`;
zizmor is not covered by the pins job. See `docs/PONYTAIL.md` for the
per-item verdicts.

### 2026-09-17 — Phase 6 review findings 5-10

The remaining six findings from the same review. 6, 7 and 8 landed with the
first batch (the `with_module` assertion, `TestAttestor` behind `#[cfg(test)]`,
`BoundWebServer` deleted); 5, 9 and 10 are this pass.

**5. `providers.rs` compiled ~1200 lines that cannot reach a server.**
`with_transport` is `#[cfg(test)]`, so every production `CloudflareProvider`,
`AcmeDnsProvider` and `DeSecProvider` carries `send: None` and fails at the
first wire call; `Rfc2136Provider` has no HMAC crate and refuses to send an
unsigned UPDATE. `acme-dns01` is in `default`, so all of it shipped. The four
networked providers now sit behind `detent-acme/dns-providers`, off by
default, reached through a new `detent/acme-dns-providers` feature that is
deliberately *not* in `default`. `HookProvider` is unaffected — it lives in
`lib.rs`, it works, and it is what the Pebble spike used, so `acme-dns01`
still means what it says. Turn the feature on with the transport.

Also split `Rfc2136Provider::update`, which built the UPDATE message, threw it
away with `let _ = message;` and returned `Err` unconditionally — a
`Result<Vec<u8>, _>` that could never be `Ok`, which also made `present`'s
`Ok(())` tail unreachable. Message building and the refusal to send are now
separate functions, so both return types mean what they say, and
`rfc2136_update_returns_the_built_message` pins it. The refusal names the
server, key and algorithm it *would* have signed with (useful when debugging
config) and never the key material; the redaction test covers that.

**9. `finalize` returned `(String, String)`.** Two PEM strings of the same
type, in the opposite order from how they were bound, so
`let (key, chain) = finalize(..)` compiled and wrote the private key to the
certificate's path. Now returns a named `Issued { chain_pem, key_pem }`.

**10. Both atomic writes used `create(true)`.** `OpenOptionsExt::mode` applies
only when a file is *created*, so a leftover `<name>.<pid>.tmp` — a crash plus
PID reuse — was reopened and written through whatever mode it already carried.
Both the ACME account credentials and the hook challenge file now remove a
stale temp first and use `create_new(true)`. Proved with
`a_stale_temp_file_does_not_leak_its_permissions`: against the old code the
challenge lands at 0o666 instead of 0o600.

**A stale floor, caught.** The 88 recorded in the previous section was measured
*before* the async order tests were replaced with the sync `read_credentials`
one, and coverage had actually fallen to 86.34 — the gate would have failed CI.
Restored the lost ground with `account_and_order_refuses_before_it_builds_a_client`,
which works only because `read_credentials` now runs ahead of
`Account::builder()`; under `--all-features` both rustls providers are compiled
in and `builder()` panics on the ambiguous default. Floor corrected to 87.

1283 pass / 6 ignored. Clippy clean at `-D warnings` under both
`--all-features` and default features.

**PONYTAIL's last four, now verified.** One of the four held.

`ProcessError` (`detent-platform/src/service/exec.rs`) **collapsed** from a
single-variant `#[non_exhaustive]` enum to a plain struct. Only one site
constructed it; the other fourteen references were signatures. `thiserror`
**stays** — AGENTS.md mandates it for library errors and callers cross the
`Result<_, ProcessError>` boundary with `?`, so the audit's "no thiserror" half
was wrong. The doc now says why a struct is right: starting the child is the
only failure that happens *before* there is an outcome; a non-zero exit, a
timeout, or capped output are all successful runs with a bad result and live in
`ProcessOutput`. -13 net.

The other three were **rejected**, with the reasoning recorded per-entry in
`docs/PONYTAIL.md`:

* `Scopes` — 85 references over 8 files, and it owns the read/write policy.
  `allows()` is called 10 times over 3 files and `names()` 5 times over 3
  rendering the scope list for the API and the token store. A bare `bool`
  scatters the policy and orphans `names()`. That
  `allows(Scope::Read)` is unconditionally true is exactly why a read-scoped
  operation cannot be denied — that rule wants one home, not ten.
* `ValidationCtx` — a parameter of `ConfigModule::validate`, implemented by
  every module: 60 references over 13 files including 7 modules and
  `_template`. The wrapper is what keeps a field addition from re-touching all
  13, and locale is a stated requirement, so the field is coming.
* `SandboxError` — **the claim is factually wrong.** It carries no
  `#[non_exhaustive]`; that is on `SpawnError`, a different type 11 lines below
  it. `SandboxError` is already 3 lines, and the suggested `String` type alias
  would drop the `Error` impl that `?` needs.

That puts PONYTAIL's whole-repo audit at **8 of its ~20 findings wrong or
overstated** once checked against the code.

### 2026-09-16 — first fully green CI

Codespell (all hits were false positives), Lint Code Base (Checkov OpenAPI
security requirements, zizmor `artipacked` and `excessive-permissions`), the
inverted `cargo tree -i ring` check that failed precisely when `ring` was
correctly absent, and a coverage slip fixed by extracting `privsep_verdict`.

### 2026-09-16 — real-hardware testing

`detent host` and `doctor` verified on testhost2 and testhost-arm. Found that Raspberry Pi
OS ships no Landlock.

### Earlier

See `git log` and PLAN §"State on 2026-09-10" for Phases 0–4.
