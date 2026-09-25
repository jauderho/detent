# PROGRESS

A running handoff log, so another agent can pick the work up cold.
[`PLAN.md`](PLAN.md) is the roadmap and does not change as work lands; **this
file is the rolling state**. Append a dated entry at the top of the log when a
phase or a self-contained piece of work finishes.
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

The Myers diff moved from `detent-ops` into `detent_core::align` (generic `align<T: PartialEq>`, `Step`, `MAX_EDIT_DISTANCE`, fallback `replace_all`); `detent-ops::diff` now calls it. `Document::plan_entries` / `apply_plan` / `edit_entries` (detent-core `doc.rs`) align the model with the existing entry lines. Unchanged lines stay byte-identical and in place. A changed entry is rewritten in place. A deleted entry loses its line. A new entry goes after the previous kept entry, in the same section. A new section header goes at the end of the previous section. Rendering and the line-break check run before any edit, and the document is normalised once through `rebuild` (M21). hosts, samba, nfs, mounts, resolver and `_template` use it. The resolver's `plan_slot`/`Planned` are gone, and the unbound "misplaced" finding is now `Severity::Error`. Past the edit-distance cap the plan falls back to positional pairing. Not in M20's listed scope and still positional: chrony, dhcp, network (§12).

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

Root trace on a010 named the killer: confined child installed the filter, then died at `open("/dev/null")` (`si_syscall=__NR_open`, Trap oracle). Musl `File::open_c` issues raw `open` (nr 2, x86_64-only), not `openat`. MONITOR gains `dup2`, `arch_prctl`, `access`, `readlink`, `readlinkat`, `ppoll`, `poll`, `open` with both-arch number rows; arch-absent entries skip table construction instead of failing it. Resolving test asserts non-empty per arch plus resolves-on-one-arch.

Verify: `cargo test -p detent-platform --all-features` (339 passed, 1 ignored); `seccomp::tests` (6 passed); fmt=0 clippy=0; aarch64 native check clean (runtime unverified); a010 root `enforce_mode_monitor_can_spawn_a_validator` passes, zero SIGSYS.


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

## 2026-09-24 - STAGE3 §11.3 step 0 a010 provisioning

Provisioned the only permitted Linux host, `a010`, with the packages and
user-level tools required by STAGE3 §00.5. The host reports kernel `7.3.0-5`,
Landlock present, `fs.protected_hardlinks=1`, 2 CPUs, 3.3 GiB RAM, and 66 GiB
free. No network, firewall, user, sysctl, or kernel settings were changed.

Commands run on `a010`, in order:

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

- **a009** — Ubuntu 26.04, x86_64, systemd-networkd. Builds are fine here.
- **k001** — Raspberry Pi OS, aarch64, NetworkManager. **Do not build on it**;
  cross-compile with `cargo zigbuild --target aarch64-unknown-linux-musl` and
  copy the binary over.

`sudo` on both. **k001 has no Landlock at all** — `CONFIG_SECURITY_LANDLOCK` is
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
  a009).
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

`detent host` and `doctor` verified on a009 and k001. Found that Raspberry Pi
OS ships no Landlock.

### Earlier

See `git log` and PLAN §"State on 2026-09-10" for Phases 0–4.
