# Security hardening checklist

Threat-model checklist pass for PLAN §3 (PLAN Phase 4, task 5). This is not a
replacement for `docs/THREAT_MODEL.md` (full text, Phase 12) — it is a working
checklist that turns PLAN §3's controls map into one row per control, each
pointing at the code that implements it and the test that proves it.

**Rule for this document:** the last column has to be true. "Covered" only
appears where a real test function was found and named below. Where no test
exists, the row says so plainly under [Gaps](#gaps) — that list is the most
useful part of this document and is not padded to look better than it is.

## Assets and adversaries (PLAN §3)

Assets: the device's config files, service control, TLS keys, admin
credentials, the binary itself.

Adversaries: a remote unauthenticated network attacker; a compromised browser
tab on the admin's machine (CSRF/XSS); a compromised upstream crate/action
(supply chain); a local unprivileged user on the device; a malicious GitHub
release (compromised token).

## How to read the table

- **Control** — the mechanism, as named in PLAN §3's controls map.
- **Defends against** — which adversary/asset pair it addresses.
- **Implemented in** — `crate/src/file.rs`.
- **Proven by** — a test function name (run with `cargo test -p <crate> <name>`
  unless noted), or the kind of non-test evidence (a spike transcript, a CI
  job) when that is what actually proves the control.

---

## Transport (TLS 1.3 + short-lived certs)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| TLS 1.3 only, no downgrade to 1.2 | remote attacker; protocol downgrade | `crates/detent-web/src/tls.rs` (`ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])`) | `a_tls13_client_negotiates_tls13_and_h2`, `a_tls12_only_client_is_refused` (`crates/detent-web/tests/tls.rs`) — an out-of-process rustls **client** with `tls12` explicitly enabled is refused by the server, so the refusal is proven for a client capable of 1.2, not just one that never offered it. External, non-rustls confirmation (`openssl s_client`) is `scripts/tls-check.sh`, added by this change — see [External TLS verification](#external-tls-verification) below; not yet wired into CI (documented manual procedure only). |
| ALPN h2 negotiated | protocol confusion; forces the security-header/CSRF assumptions that depend on HTTP semantics | `crates/detent-web/src/tls.rs` | `a_server_config_advertises_the_requested_alpn` (`tls.rs`); end-to-end via `a_tls13_client_negotiates_tls13_and_h2` (`tests/tls.rs`); externally via `scripts/tls-check.sh` (checks ALPN as part of its TLS 1.3 check; not yet CI-wired). |
| Client that speaks no TLS at all / an untrusted client | remote attacker; malformed-connection DoS | `crates/detent-web/src/tls.rs`, `server.rs` | `a_client_that_speaks_no_tls_at_all_is_dropped_quietly`, `an_untrusting_client_is_refused_by_its_own_verifier` (`tests/tls.rs`) |
| Concurrent-connection cap | remote attacker; connection-exhaustion DoS | `crates/detent-web/src/server.rs` | `a_connection_over_the_cap_is_dropped_without_a_handshake`; a peer that sends no request within the header timeout loses its permit, over HTTP/1.1 and HTTP/2: `an_idle_connection_does_not_hold_a_permit`, `an_idle_h2_connection_does_not_hold_a_permit`, `a_served_connection_outlives_the_first_request_deadline` (`tests/tls.rs`) |
| Bootstrap self-signed cert, fingerprint logged for TOFU | MITM during first boot before ACME succeeds | `crates/detent-web/src/tls.rs` | `a_bootstrap_certificate_loads_into_the_provider`, `the_fingerprint_is_uppercase_colon_separated_sha256` (`tls.rs`) |
| Cert store hot reload, `0600` under `0700` dir | local unprivileged user reading key material; stale-cert outage | `crates/detent-web/src/tls.rs` | `the_store_is_written_0600_under_a_0700_directory`, `a_pre_existing_store_directory_is_narrowed_to_0700`, `the_store_swaps_what_it_resolves`, `a_poisoned_store_still_serves_and_still_reloads` (`tls.rs`) |
| Private key never in debug output / logs | key exfiltration via logs | `crates/detent-web/src/tls.rs` | `the_debug_output_never_carries_the_private_key` (`tls.rs`) |
| Short-lived certs (ACME `shortlived` profile, dns-01, device-attest-01) | stolen-cert reuse window | `detent-acme` (Phase 6) | **implemented.** `instant-acme` order/account flow, dns-01 providers, renewal scheduling, ARI helpers, and device-attest-01 seam are present; live issuance is exercised by the Pebble test. |
| HSTS `max-age=63072000; includeSubDomains` | protocol downgrade via a stripped first request | `crates/detent-web/src/headers.rs` | `every_header_is_present_with_its_exact_value` (asserts the exact `Strict-Transport-Security` value; `headers.rs`) |

## Web (Argon2id + rate limits + sessions/CSRF/CSP)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| Argon2id password hashing, configurable cost | offline password cracking after a leak | `crates/detent-web/src/auth/password.rs` | `a_hash_verifies_against_its_own_password_and_no_other`, `two_hashes_of_one_password_differ_because_the_salt_does`, `the_cost_comes_from_the_configuration_and_the_host` (`password.rs`) |
| Constant-time verify, dummy-hash on unknown user | username enumeration via timing | `crates/detent-web/src/auth/password.rs`, `auth/users.rs`, `auth/routes.rs` | `the_dummy_hash_always_refuses_and_costs_what_a_real_one_costs` (functional); `unknown_user_and_wrong_password_cost_the_same` (`password.rs`) is the actual **statistical timing** test PLAN task 2 asks for, but it is `#[ignore]`d by default (wall-clock assertions are flaky on shared CI runners) — run explicitly with `cargo test -p detent-web -- --ignored unknown_user_and_wrong_password`. `an_unknown_user_and_a_wrong_password_are_indistinguishable` (`routes.rs`) and `an_unknown_user_and_a_wrong_password_answer_the_same` (`users.rs`) cover the response-shape side without timing. |
| Passwords/hashes never logged or rendered in debug | credential exfiltration via logs/panics | `password.rs`, `users.rs` | `the_debug_output_carries_no_password_and_no_hash` (`password.rs`); `the_request_body_never_renders_its_password` (`routes.rs`) |
| Login rate limiting, per-IP and per-user, exponential backoff, lockout | credential stuffing / brute force | `crates/detent-web/src/auth/ratelimit.rs` | `the_first_failures_are_free_and_the_next_one_locks_out`, `the_backoff_doubles_and_is_capped`, `a_lockout_expires_on_its_own`, `the_two_buckets_are_independent` (`ratelimit.rs`); end-to-end via `repeated_failures_lock_the_account_out_and_the_lockout_is_audited` (`routes.rs`, also proves the lockout is audited) |
| Rate-limiter table bounded (no unbounded memory growth from spoofed names) | remote attacker; memory-exhaustion DoS | `ratelimit.rs` | `the_maps_are_bounded_by_eviction`, `eviction_drops_the_least_recently_seen_entry`, `a_name_that_does_not_exist_is_still_throttled` (`ratelimit.rs`) |
| Sessions: 32-byte CSPRNG id, `__Host-` cookie, `Secure`/`HttpOnly`/`SameSite=Strict`, idle 15 min, absolute 8 h, rotate on login | session fixation/hijack; cookie theft via XSS; stale sessions | `crates/detent-web/src/auth/session.rs` | `a_new_session_is_found_by_its_id_and_by_nothing_else`, `the_idle_timeout_removes_the_session_rather_than_refusing_it`, `the_absolute_timeout_ends_a_session_that_is_still_being_used`, `rotation_replaces_the_id_and_the_csrf_token_at_once`, `the_cookie_carries_the_three_attributes_the_host_prefix_requires` (`session.rs`); login rotation: `signing_in_again_invalidates_the_session_the_request_arrived_with` (`routes.rs`); the expiry sweep runs under `serve`: `prepare_worker_reaches_a_bound_listener` (`crates/detent/src/serve.rs`) |
| Explicit logout invalidates immediately | stolen-cookie reuse after logout | `session.rs`, `auth/routes.rs` | `logout_invalidates_immediately_and_only_once` (`session.rs`); `logging_out_ends_the_session_and_clears_the_cookie` (`routes.rs`) |
| Session id/view never leaks the raw id | session-fixation via a leaked identifier | `session.rs` | `the_view_says_when_it_expires_and_never_carries_the_id`, `nothing_here_prints_a_secret` (`session.rs`) |
| CSRF: `Sec-Fetch-Site`, `Origin`, `X-Detent-CSRF` all required on non-GET; Bearer bypass only with no cookie ambient authority | CSRF from a compromised browser tab | `crates/detent-web/src/csrf.rs` | `each_missing_or_wrong_condition_is_a_refusal` (table-driven, one case per PLAN task 3 condition), `a_bearer_token_skips_the_checks_entirely`, `a_repeated_authorization_header_does_not_bypass`, `an_expired_session_is_not_treated_as_a_csrf_failure` (`csrf.rs`) |
| GET never mutates | CSRF via a simple cross-site GET/image tag | `csrf.rs` | `no_get_route_is_registered_for_a_mutating_operation`, `a_mutating_route_refuses_a_get` (`csrf.rs`) |
| API tokens: 32-byte random, stored as SHA-256 digest only, scoped, revocable, expirable | token database leak; stolen-token misuse | `crates/detent-web/src/auth/token.rs` | `a_token_is_shown_once_and_stored_only_as_a_digest`, `an_expired_token_is_refused_exactly_like_an_unknown_one`, `a_revoked_token_stops_working_at_once`, `nothing_here_prints_a_token_or_a_digest` (`token.rs`) |
| Token scopes: `read`/`write`, write implies read | over-privileged token misuse | `crates/detent-web/src/authz.rs` | `the_required_scope_is_write_exactly_for_mutating_operations`, `write_implies_read_and_read_does_not_imply_write`, `a_read_only_caller_may_read_everything_and_write_nothing` (`authz.rs`) |
| TOTP: RFC 6238 vectors, ±1 step window, anti-replay | credential-stuffing after a password leak (2FA); code replay | `crates/detent-web/src/auth/totp.rs` | `the_rfc_6238_test_vectors_produce_the_published_codes`, `the_window_accepts_one_step_either_side_and_no_more`, `a_code_cannot_be_used_twice` (`totp.rs`); end-to-end login with TOTP via `an_enrolled_account_must_present_a_fresh_code`, `a_host_that_requires_totp_refuses_an_account_without_one` (`routes.rs`) |
| Security headers: CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/COEP, `Cache-Control: no-store` on API | XSS, MIME sniffing, cross-origin leaks, referrer leakage, API response caching | `crates/detent-web/src/headers.rs` | `every_header_is_present_with_its_exact_value`, `the_csp_is_the_policy_from_the_plan`, `only_api_paths_are_marked_no_store`, `error_responses_carry_the_headers_too` (`headers.rs`) |
| CSP script hash matches the actual inline theme script | script injection via a hash that no longer matches the shipped script | `headers.rs`, `spa.rs` | `theme_script_sha256_matches_the_file_it_hashes`, `the_inline_script_in_index_html_is_the_file_byte_for_byte` (`headers.rs`) |
| Body size limit (256 KiB) | remote attacker; memory-exhaustion DoS via oversized bodies | `crates/detent-web/src/server.rs` | `a_body_over_the_limit_is_refused` (`server.rs`) |
| Request timeouts | slow-loris / hung-handler DoS | `server.rs` | `a_slow_handler_is_timed_out_with_the_security_headers_intact` (`server.rs`) |
| `deny_unknown_fields` bodies, JSON depth limit | request smuggling via unexpected fields; stack-exhaustion via deeply nested JSON | `crates/detent-web/src/api/*.rs` | `no_bodied_endpoint_ever_answers_5xx` (proptest/arbitrary-driven, one strategy per bodied endpoint), `a_pathologically_nested_body_is_refused_without_crashing` (`api/integration_tests.rs`) — this is the PLAN task 4 contract-fuzz test. Also `fuzz_api_json` (`fuzz/fuzz_targets/fuzz_api_json.rs`, cargo-fuzz, run by `.github/workflows/fuzz.yml` on PRs touching `crates/**`/`fuzz/**` and nightly on schedule). |
| Session cookie parsing is fuzzed | malformed/adversarial `Cookie` header crashing the parser | `crates/detent-web/src/auth/session.rs` (parser), `fuzz/fuzz_targets/fuzz_session_cookie.rs` | `fuzz_session_cookie` target, same `fuzz.yml` job as above. Functional case: `a_cookie_header_is_parsed_only_for_this_name` (`session.rs`). |
| `healthz` unauthenticated, constant body, no version leak | information disclosure via a pre-auth endpoint; version fingerprinting | `crates/detent-web/src/server.rs` | `healthz_answers_a_constant_body_and_nothing_else` (`server.rs`); `healthz_is_reachable_through_the_assembled_router` (`api/integration_tests.rs`) |
| `/healthz` is the **only** route reachable without a credential | a new endpoint shipping open because its handler forgot to take a `Caller` — `/api/v1/openapi.json` did exactly this, serving a map of every path, parameter and body shape to anyone | `crates/detent-web/src/api/*.rs` (every handler takes `Caller`/`WriteCaller`) | `no_api_route_is_reachable_without_a_credential` (`api/integration_tests.rs`), a sweep driven off `api::table()` rather than a hand-written list |
| API errors are codes + Fluent ids, never raw internal errors | information disclosure via stack traces/internal error text | `crates/detent-web/src/error.rs` | `the_body_is_a_code_and_a_fluent_id_and_nothing_else`, `every_auth_failure_maps_to_a_status_and_a_code`, `every_ops_error_variant_maps_to_its_documented_status` (`error.rs`) |
| Precompressed, hashed-asset SPA serving; app-shell fallback does not leak API paths | cache poisoning; API route confusion with static serving | `crates/detent-web/src/spa.rs` | `hashed_assets_are_immutable_and_everything_else_revalidates`, `a_missing_asset_with_an_extension_is_404_not_the_app_shell`, `an_api_shaped_path_is_refused_not_handed_the_app_shell` (`spa.rs`) |
| `Server` header removed / no directory listing / `/metrics` absent | fingerprinting; information disclosure | `crates/detent-web/src/server.rs`, `api/mod.rs` route table | **not directly tested.** These are architectural absences (axum does not set a `Server` header by default; no `/metrics` route or static directory listing is registered anywhere in `api/mod.rs`/`spa.rs`), not asserted by a dedicated negative test. See [Gaps](#gaps). |
| Output escaping (React) / per-format quoting in rendered config | XSS in the admin UI; injection into rendered config files | `web/` (Phase 5, not built); `crates/detent-core/src/conformance.rs` for the render side | UI escaping: **not yet — Phase 5** (`web/src` today is Phase 4's own bootstrap only: `index.html`, the inline theme script whose SHA-256 the CSP pins, and base CSS — no application/form code, no module pages). Config-rendering quoting: `invariant_5_injection_probes_are_rejected` (module-conformance macro, instantiated per module, e.g. `crates/modules/hosts/tests/conformance.rs`) — proves injection probes are rejected on the render path that Phase 4 already ships. |

## Local privilege (privsep + Landlock + seccomp + caps + allow-lists)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| Privilege separation: monitor (tiny, blocking, no TLS/HTTP) / worker (uid `detent`, no caps, network-facing) over a socketpair | a compromised network-facing worker requesting paths outside the allow-list | `crates/detent-platform/src/privsep/monitor.rs`, `worker.rs` | `hooks_confine_both_roles_across_a_forked_pair` (`sandbox/linux.rs`); `dispatch_requires_the_handshake_before_anything_else`, `a_second_hello_is_a_ha… |
| Content written to allow-listed targets is re-validated by the monitor: the module's parser and validator run on the candidate, and a candidate that adds an execution directive or changes the value of one is refused (smb.conf `*exec*`/`*script`/`*command`/`include`/`vfs objects`, dnsmasq `dhcp-script`/`conf-*`, Kea `hooks-libraries`/`<?include?>`, chrony `include`/`confdir`/`sourcedir`/`pidfile`/`user`, unbound `include:`/`python-script:`/`dynlib-file:`, ifupdown hooks other than the module's route form, fstab `x-systemd.*`/`helper=`/FUSE, exports `no_root_squash`/`anonuid=0`), with names normalised as each daemon reads them (STAGE3 H23) | a compromised worker gaining root through config content | `crates/detent-platform/src/privsep/exec_deny.rs`, `monitor.rs` `revalidate` | `every_known_bypass_is_refused`, `ordinary_edits_are_allowed` (`exec_deny.rs`); `write_target_refuses_new_root_exec_directives` (`monitor.rs`). **Residual:** a deny-list is best effort — a directive it does not list, or a non-exec root file write (for example a log or drift file path), is not caught |
| ≤ 1 MiB message cap, postcard-encoded, `deny_unknown_fields`-equivalent (unknown discriminant closes the connection) | a compromised worker flooding/crashing the monitor with oversized or malformed frames | `crates/detent-platform/src/privsep/proto.rs` | `oversize_frames_are_rejected_before_allocating`, `truncated_and_unknown_frames_are_rejected` (`proto.rs`) |
| `PR_SET_NO_NEW_PRIVS` at startup | privilege escalation via setuid binaries after confinement | `crates/detent-platform/src/sandbox/linux.rs` | `no_new_privs_is_set_afterwards` (kernel-observable: reads `/proc/self/status`, `linux.rs`) |
| `PR_SET_DUMPABLE=0` | a local user attaching a debugger / reading `/proc/<pid>/mem` to extract key material | `crates/detent-platform/src/sandbox/linux.rs` (`harden_dumpable`) | **not directly tested.** The outcome is folded into `confine()`'s returned struct (asserted only indirectly, e.g. by `debug_format_of_the_monitor_does_not_panic`-style tests elsewhere), but no test reads `/proc/self/status`'s `Dumpable:` field the way `no_new_privs_is_set_afterwards` does for `NoNewPrivs:`. See [Gaps](#gaps). |
| Capability bounding set shrunk to the computed minimum | a compromised process using an unneeded capability (e.g. `CAP_SYS_ADMIN`) | `crates/detent-platform/src/sandbox/linux.rs` | `capability_bounding_set_shrinks_to_the_policy_set` (`linux.rs`), which asserts the shrunk mask where `CAP_SETPCAP` is held and, where it is not, asserts only that the refusal is reported rather than mistaken for success. **Fails open, unlike seccomp:** shrinking the bounding set needs `CAP_SETPCAP`, and when the drop is refused `confine` records `Outcome::Unavailable` and start-up continues with the full bounding set. `require_seccomp` defaults on and `require_landlock` exists; there is no `require_caps`. The monitor starts as root and so normally has `CAP_SETPCAP`, but a deployment that does not (a restrictive container, a `CapBnd`-trimmed unit) loses this control silently. See [Gaps](#gaps). |
| Landlock ruleset restricting writes to target dirs + backup dir (+ binary dir for `update`), with the monitor-only `/run/detent/staging` base for materialized update bytes | a compromised worker/monitor writing outside its declared file set | `crates/detent-platform/src/sandbox/linux.rs`, `crates/detent-platform/src/privsep/monitor.rs` | `only_the_monitor_policy_grants_the_runtime_staging_base` (`sandbox/mod.rs`); `materialized_digest_is_monitor_owned_private_and_durable` and `monitor_rejects_group_writable_staging_permissions` (`monitor.rs`) |
| Landlock absence degrades loudly (warn, `doctor`/UI-visible, hard-fail only if `require_landlock=true`) rather than silently | silent loss of confinement on old kernels | `crates/detent-platform/src/sandbox/mod.rs` | `confine_is_all_unavailable_and_never_errs_off_linux`, `landlock_status_serializes_to_snake_case` (`mod.rs`) — the "warn once / mark degraded in doctor" UI-visible half of this is not yet exercised by a test (doctor output tested elsewhere, not cross-checked against sandbox degradation here); noted in [Gaps](#gaps). |
| seccomp allow-list, per-architecture tables, `SCMP_ACT_LOG` before enforcing | a compromised process making an unexpected syscall (container/sandbox escape primitives) | `crates/detent-platform/src/sandbox/seccomp.rs`, `linux.rs` | `every_table_entry_resolves_on_both_tier_one_architectures`, `the_two_tables_share_every_ipc_and_runtime_housekeeping_syscall` (`seccomp.rs`); `log_mode_seccomp_lets_a_forbidden_syscall_through`, `enforce_mode_seccomp_refuses_ptrace`, `enforce_mode_seccomp_kills_the_monitor_on_a_forbidden_syscall` (`linux.rs`) |
| Validators and service commands run in the **runner**, a root helper forked before the monitor confines itself, because a seccomp filter binds every child of the process that installs it (STAGE3 H6). The runner takes only an allow-list check id plus the file name of a regular file directly in the staging directory, or a binding id plus a declared action — never a path, program or argument. Any channel failure disables the runner client, so apply fails closed | a validator or `systemctl` killed by `SIGSYS` under the monitor filter (every apply with checks failing); a compromised monitor using the unconfined helper to run arbitrary programs | `crates/detent-platform/src/privsep/runner.rs`, `spawn.rs` (`spawn_runner`), `crates/detent/src/serve.rs` | `enforce_mode_monitor_runs_real_validators_through_the_runner` (`sandbox/linux.rs`: confined monitor, real `uname`/`id`/`findmnt`/`systemctl`; fails when the monitor runs the probe itself); `the_runner_refuses_anything_outside_the_allow_list`, `the_client_sends_only_allow_listed_declarations`, `a_runner_that_is_gone_makes_every_later_call_unavailable` (`runner.rs`). **Residual:** the runner is root and unconfined by design; the worker drops its inherited runner descriptor at start (`serve.rs`), which no test observes. The monitor table still lists `clone`/`execve`; removing them is a follow-up |
| Atomic write protocol: backup before write, `O_EXCL` temp, `fsync` + `rename` + `fsync(dir)` | torn writes / lost updates on power loss or crash mid-write | `crates/detent-platform/src/fs/atomic.rs` | `temp_guard_unlinks_on_drop`, `create_exclusive_gives_up_on_a_permanently_taken_name`, `backup_names_disambiguate_identical_timestamps` (`atomic.rs`) |
| Optimistic concurrency: `expected_hash` mismatch refuses the write | two admin sessions racing to edit the same file (lost update) | `crates/detent-ops/src/engine.rs` | `apply_refuses_a_stale_expected_hash` (`crates/detent-ops/tests/engine.rs`) |
| systemd unit hardening (`ProtectSystem=strict`, capability bounding set, etc.), `systemd-analyze security` ≤ 2.5 (root-confined) / ≤ 1.8 (capability-user) | a compromised `detent` process pivoting through systemd-granted access | `packaging/systemd/detent.service`, `packaging/systemd/detent.service.d/capability-user.conf` | **spike evidence, not a unit test:** `docs/spikes/02-sandbox.md` (systemd hardening spike measured 2.9 → 2.3 → 1.6 across iterations; the unit file's own header cites the spike and the `<= 2.5` target — see PLAN §2.4). No CI job re-runs `systemd-analyze security` against the checked-in unit to catch a future regression — see [Gaps](#gaps). |

## Integrity/availability (lossless model + injection-safe rendering + external validators + backups + commit-confirm)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| Lossless render/parse round-trip | silent data loss/corruption of unmanaged config content | `crates/detent-core/src/conformance.rs` (macro), instantiated per module | `invariant_1_render_parse_roundtrip` (module-conformance macro test, e.g. `crates/modules/hosts/tests/conformance.rs`) |
| Apply of a module's own rendered model is a no-op | apply-time drift/thrash on a config that was not actually changed | `conformance.rs` | `invariant_2_apply_of_own_model_is_a_noop` (module-conformance macro test) |
| Injection-safe rendering | config injection via a field value that breaks out of its syntactic context | `conformance.rs` | `invariant_5_injection_probes_are_rejected` (module-conformance macro test) |
| External validators gate `plan` and `apply`: the engine runs them before a write and fails closed, and the monitor runs them again on the exact bytes in `revalidate` | applying a config that would fail to load at the service level | `crates/detent-ops/src/engine.rs` (`run_checks` in `plan` and `apply`), `crates/detent-platform/src/privsep/monitor.rs` (`RunCheck`, `revalidate`), `service/checks.rs` | `run_check_reports_success_through_a_working_check_runner`, `run_check_maps_a_failed_hook_to_an_io_error`, `run_check_rejects_an_unknown_check_id` (`monitor.rs`); under confined `serve` they run through the runner (row below) |
| Backups on every write, rotation (keep 20), listed newest-first | losing the ability to recover from a bad apply | `crates/detent-platform/src/fs/atomic.rs`, `privsep/monitor.rs` | `backup_names_disambiguate_identical_timestamps`, `list_backups_propagates_non_not_found_errors` (`atomic.rs`); `list_backups_orders_multiple_entries_newest_first`, `list_backups_rejects_an_unknown_module` (`monitor.rs`) |
| Restore from backup | recovering after a bad apply | `monitor.rs` | `restore_rejects_an_unknown_module`, `restore_reports_io_error_when_the_target_directory_is_not_writable` (`monitor.rs`); `restore_backup` (`api/integration_tests.rs`) |
| Commit-confirm: apply arms a timer, every monitor exit rolls back an unconfirmed apply and clears its marker, and the next monitor start recovers a leftover marker before serving; one-shot CLI applies to commit-confirm modules are refused | an apply that breaks network/service reachability locking the admin out of the host | `crates/detent-platform/src/privsep/monitor.rs` (`PENDING_COMMIT_MARKER`, `recover_pending`, `serve_locked`), `crates/detent/src/{serve,run}.rs` | `shutdown_with_a_pending_commit_rolls_back`, `run_monitor_recovers_a_leftover_marker`, `a_cli_apply_on_a_commit_confirm_module_never_leaves_an_unenforced_commit` |
| Only one pending commit at a time | overlapping applies corrupting the rollback state | `monitor.rs` | covered by the `pending: Option<Pending>` single-slot design exercised through `confirm_commit_and_start_confirm_timer_log_through_tracing`; no test explicitly asserts a second `Apply` is refused while one is pending — see [Gaps](#gaps). |
| Audit log: intent fail-closed (`Started` persistence failure aborts via `AuditUnavailable`); every line is fsynced, sequenced, and SHA-256 hash-chained; terminal anchors must be retained externally to detect tail truncation; outcome/denial persistence is best-effort; journald is the independent copy; no secrets/full bodies | undetected mutation, reordering, insertion, or tail truncation; accidental secret leakage into the audit trail | `crates/detent-ops/src/audit.rs` (`FileAudit`, `verify_records`, fsynced append), `crates/detent-ops/src/engine.rs` (intent `Started` → `AuditUnavailable`) | `the_file_sink_appends_one_line_per_record_and_reads_them_newest_first`, `verification_detects_tampering_and_truncation_against_an_anchor` (`audit.rs`); `an_unwritable_audit_sink_refuses_the_mutation` (`engine.rs`) |

## Supply chain (reproducible builds + SBOM + provenance + immutable releases + Sigstore verification + cooldowns)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| Dependency source/license/advisory policy (`cargo-deny`) | a malicious or unmaintained transitive dependency; license contamination | `deny.toml` | CI job, not a unit test: `.github/workflows/ci.yml` "Supply chain (deny, audit, cooldown)" job. |
| 7-day cooldown on new **Cargo** dependency versions (ADR-011) | a just-published, not-yet-scrutinized malicious release landing immediately | `docs/adr/ADR-011-supply-chain-cooldown.md`; CI | CI job: `.github/workflows/ci.yml` step "cargo cooldown check (7-day supply-chain cooldown, ADR-011)" (`cargo cooldown check --locked`). |
| 7-day cooldown on new **Bun/npm** dependency versions (ADR-011) | the same, for the web dependency tree | `web/bunfig.toml` (`minimumReleaseAge = 604800`) | CI job: `.github/workflows/ci.yml` step "Supply-chain cooldown is in force (ADR-011)" (`scripts/cooldown-check.sh`), which runs before `bun install`. **Defect found and fixed during Phase 5:** `bunfig.toml` sat at the repository root while every `bun install` runs in `web/`, and bun reads `bunfig.toml` from its working directory only — never from a parent. The Bun cooldown had therefore never been in force, and nothing failed, because an ignored config is indistinguishable from a satisfied one. Confirmed empirically before and after the move (a temp project with the file in a parent resolved `^22.20.1`; with it alongside `package.json`, `22.20.1` — and a deliberately long `minimumReleaseAge` pushed `typescript` from 7.0.2 back to 5.8.2). `scripts/cooldown-check.sh` now asserts a conforming `bunfig.toml` next to every `package.json`. |
| `rcgen` cannot silently pull `ring` into an aws-lc-rs build | a build that believes it's aws-lc-rs-only but ships a second crypto stack (larger attack surface, audit blind spot) | `Cargo.toml` (`rcgen` pinned `default-features = false`) | CI job: `.github/workflows/ci.yml` step "cargo tree -i ring (rustls builds must not pull in ring)"; originally verified by hand in `docs/spikes/00-cross-build.md`. |
| Reproducible builds | verifying a released binary matches its source | — | **not yet — Phase 9.** No build-reproducibility tooling/verification exists yet. |
| SBOM generation | knowing what's actually in a shipped binary, post-incident | — | **not yet — Phase 9.** No SBOM tooling (`cyclonedx`/`syft`/etc.) is wired in yet. |
| Provenance / immutable releases | tampering with a published release after the fact | — | **not yet — Phase 9.** `detent-update/Cargo.toml` has no dependencies yet; the self-update verifier described in PLAN §2.9 (in-tree Sigstore-bundle verifier, not the `sigstore` crate — see `docs/adr/ADR-005-update-verification-sigstore.md`) does not exist yet. |
| Sigstore verification of release artifacts | a malicious or coerced release build | — | **not yet — Phase 9,** same as above. |
| Every CI `uses:` action SHA-pinned with a version comment (ADR-011) | a compromised/re-tagged third-party GitHub Action | `.github/workflows/*.yml` | CI job: `.github/workflows/ci.yml` "pins" job (regex-checks every `uses:` line). **Caveat found during this pass:** the check only verifies *format* (40-hex SHA + comment), not that the SHA is actually reachable in the upstream repo — `fuzz.yml`'s `dtolnay/rust-toolchain@82fc405565b9cf90abfe700ba43b4751ce2fe422 # nightly` pin does not resolve to any commit in `dtolnay/rust-toolchain` (verified against the GitHub API while working on this task). See [Gaps](#gaps). |

## Memory safety/correctness (`deny(unsafe_code)` outside two crates, fuzzing, 100% coverage gate)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| `unsafe_code = "forbid"` workspace-wide, `"deny"` (allow-listed per item) only in `detent-platform`/`detent-ffi` | memory-safety bugs from unaudited `unsafe` | `Cargo.toml` (`[workspace.lints.rust]`), `crates/detent-platform/Cargo.toml`, `crates/detent-ffi/Cargo.toml` | Enforced at compile time (a lint, not a test): any `unsafe` block outside those two crates fails `cargo build`/`cargo clippy`. `cargo clippy --workspace --all-targets --all-features -- -D warnings` in `.github/workflows/ci.yml` ("rust" job). |
| Fuzzing: `fuzz_hosts_parse`, `fuzz_hosts_roundtrip`, `fuzz_hosts_edit`, `fuzz_privsep_decode`, `fuzz_api_json`, `fuzz_session_cookie` | parser/decoder crashes and panics on adversarial input | `fuzz/fuzz_targets/*.rs` | `.github/workflows/fuzz.yml`: runs every registered target for 60 s on PRs touching `crates/**`/`fuzz/**`, 1200 s nightly. PLAN Phase 4's acceptance specifically names `fuzz_api_json`/`fuzz_session_cookie` clean — both exist and run in this job. |
| 100% line coverage gate on `detent-core`, `detent-i18n`, `detent-ops`, `crates/modules/*`; ratcheting floor elsewhere | correctness regressions in security-relevant code shipping untested | `coverage-baseline.json`, `scripts/coverage-merge.sh` | CI-enforced threshold, not a single test. **Current state (from `coverage-baseline.json`):** `detent-core`/`detent-i18n`/`detent-ops`/`crates/modules/*` are at the 100% gate; `detent-platform` floor is 92% (documented, kernel-effect-only paths under an active seccomp filter can't self-report — see the file's `ratchet_note`); **`detent-web` floor is 97%, not the 100% PLAN Phase 4 states as its acceptance criterion** — this is a real, currently-open gap, not yet closed. See [Gaps](#gaps). |

---

## External TLS verification

PLAN Phase 4 task 1 asks for an external (non-rustls) check: `openssl
s_client -tls1_2` fails, `-tls1_3` succeeds, ALPN negotiates `h2`, plus a
`testssl.sh` CI job. `scripts/tls-check.sh` (added by this change) implements
the `openssl s_client`/ALPN half of that against a running `detent serve`
instance; see its `--help` for usage. It is **not wired into CI** — `detent
serve` needs root and a `detent` system account, which means running it in a
container, and no such container test job exists yet. `scripts/tls-check.sh
--help` documents the manual procedure. `testssl.sh` itself is not invoked by
anything in this repository yet.

---

## Gaps

Controls named in PLAN §3 with **no** test and no other evidence found during
this pass, or found only partially covered. Listed here rather than folded
quietly into the tables above.

1. **The capability bounding-set drop fails open.** Seccomp refuses to start
   when its filter does not install (`require_seccomp`, default on) and
   Landlock has `require_landlock`; the capability drop has no equivalent. If
   `CAP_SETPCAP` is absent, `caps::drop` answers `EPERM`, `confine` records
   `Outcome::Unavailable`, and the process continues with the **full** bounding
   set. The monitor starts as root and normally holds `CAP_SETPCAP`, so this is
   latent rather than active — but it is the same shape as the seccomp
   fail-open fixed in Phase 4, and it is invisible at run time because
   everything else works. Found when CI first ran the Linux-only test as an
   unprivileged user. A `require_caps` knob, defaulted on for the monitor,
   would close it; deferred because the worker's confinement order relative to
   its uid drop needs checking first.
2. **Landlock is unavailable on Raspberry Pi OS, detent's flagship target.**
   Measured on a Pi running Debian 13, kernel `6.18.39+rpt-rpi-v8`:
   `/sys/kernel/security/lsm` reports `capability` alone, and the kernel config
   says `# CONFIG_SECURITY_LANDLOCK is not set`. It is not a matter of adding
   `lsm=` to `cmdline.txt` — the LSM is not compiled in, so no boot parameter
   can turn it on, and an operator would need a custom kernel. `detent doctor`
   reports this correctly (`warn landlock: capability`) and `require_landlock`
   defaults to `false`, so detent runs — but on the most common SBC it runs
   with filesystem confinement absent, leaving seccomp and the capability drop.
   Ubuntu 26.04 on x86_64 has it (`lockdown,capability,landlock,yama,apparmor,
   ima,evm`). Worth stating in the operator documentation rather than leaving
   to be discovered, given how much of PLAN §2.4 rests on Landlock.
3. **`detent-web` coverage is 97%, not the 100% PLAN Phase 4 sets as its own
   acceptance criterion** (`coverage-baseline.json`). The file's own note says
   what's missing: error paths that need a failing syscall to reach
   (`getrandom` failing, `accept(2)` erroring, a handshake timing out, a
   graceful-shutdown grace window expiring), plus the access-log tracing call.
4. ~~**`fuzz.yml`'s `dtolnay/rust-toolchain` pin for the nightly toolchain does
   not resolve.**~~ **Fixed.** `82fc405565b9cf90abfe700ba43b4751ce2fe422` is not
   a commit that exists in `dtolnay/rust-toolchain` (the GitHub API answers 422
   for it). The `nightly` branch there is force-pushed daily, so a SHA pinned
   against it goes unreachable once GC runs. `fuzz.yml` now uses the same
   pinned `v1` commit `ci.yml` does and asks for nightly by input, which is
   both reachable and stable.
5. ~~**Every `dtolnay/rust-toolchain@…# v1` step in `ci.yml` omits the required
   `toolchain` input.**~~ **Fixed, then reworked 2026-09-22.** The action declares `toolchain` as
   `required: true` and hard-fails when it is empty, so *every* job in `ci.yml`
   would have failed at its first step — which is consistent with the workflow
   never having run. The first fix passed `${{ env.RUST_TOOLCHAIN }}` plus a
   `Toolchain pin matches rust-toolchain.toml` step; that is now superseded.
   Current controls: `ci.yml` sets workflow-wide `RUSTUP_TOOLCHAIN: stable`
   (the ubuntu-26.04 image provisions only `stable-*` via `--default-toolchain=stable`,
   so a versioned channel would download a second copy), the `rust`/`size` jobs
   fail closed with a drift check that reads preinstalled stable from `$RUNNER_TEMP`
   (outside the checkout, where neither the env override nor the pin file masks it),
   `rust-macos` installs pinned `1.98.1` with a job-level override, and
   `release.yml`/`rebuild-verify.yml` keep exact `RUST_TOOLCHAIN: "1.98.1"` via
   `dtolnay` for hash-for-hash reproducibility (ADR-011).

   Neither of these had anything to do with the security controls this document
   covers, and both were found only because someone went looking for the
   evidence behind a checklist item. That is the argument for the document.

6. **`PR_SET_DUMPABLE=0` has no dedicated test.** `harden_dumpable()`
   (`crates/detent-platform/src/sandbox/linux.rs`) is called and its outcome
   folded into `confine()`'s result struct, but no test reads
   `/proc/self/status`'s `Dumpable:` field the way
   `no_new_privs_is_set_afterwards` does for `NoNewPrivs:`.
7. **Landlock-absent degradation is only partly tested.** `confine()`'s
   behavior when Landlock is unavailable is tested
   (`confine_is_all_unavailable_and_never_errs_off_linux`), but the "warn
   once, mark degraded in `doctor`/UI" half of PLAN §2.4 is not cross-checked
   by a test that ties sandbox degradation to `doctor` output.
8. **systemd unit hardening (`packaging/systemd/detent.service`,
   `systemd-analyze security` ≤ 2.5 / ≤ 1.8) is spike evidence, not a
   regression test.** The unit file exists and cites `docs/spikes/02-sandbox.md`
   in its own header, but nothing in CI re-measures `systemd-analyze security`
   against it to catch a future regression.
9. **"Only one pending commit at a time" has no explicit negative test.** The
   single-slot `Option<Pending>` design makes a second concurrent `Apply`
   structurally hard to reach in the current tests, but no test asserts that
   a second `Apply` while one commit is pending is refused (as opposed to
   silently replacing the first).
10. **`Server` header removal, no directory listing, `/metrics` absent** are
   true by construction (nothing registers them) but have no dedicated
   negative test asserting their absence.
11. **Reproducible builds, SBOM, provenance, immutable releases, Sigstore
   verification** — all Phase 9 (`detent-update`) work; none of it exists
   yet. `detent-acme` (short-lived certs, dns-01, device-attest-01) is
   likewise Phase 6 and does not exist yet beyond an empty crate.
12. **`testssl.sh` is not invoked anywhere in this repository.** PLAN Phase 4
    task 1 names it explicitly ("CI job, allow network"); no such job exists.
    `scripts/tls-check.sh` (added by this change) covers the
    `openssl s_client`/ALPN portion of task 1 but not the weak-cipher-suite
    sweep `testssl.sh` performs.
13. **Output escaping in the admin UI (React) is not yet applicable** — `web/src`
    has Phase 4's bootstrap only (`index.html`, the theme script, base CSS);
    no application/form code exists yet (Phase 5).
