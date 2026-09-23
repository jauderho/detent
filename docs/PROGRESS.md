# PROGRESS

A running handoff log, so another agent can pick the work up cold.
[`PLAN.md`](PLAN.md) is the roadmap and does not change as work lands; **this
file is the rolling state**. Append a dated entry at the top of the log when a
phase or a self-contained piece of work finishes.

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
service managers), `detent-ops` (the 14 operations, authz, audit),
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
