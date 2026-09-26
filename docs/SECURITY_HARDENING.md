# Security hardening checklist

Threat-model checklist pass for PLAN §3 (PLAN Phase 4, task 5). This is not a
replacement for `docs/THREAT_MODEL.md` (full text, Phase 12) — it is a working
checklist that turns PLAN §3's controls map into one row per control, each
pointing at the code that implements it and the test that proves it.
[`ARCHITECTURE.md`](ARCHITECTURE.md) shows how the processes, trust
boundaries and data paths these controls protect fit together.

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
| TLS 1.3 only, no downgrade to 1.2 | remote attacker; protocol downgrade | `crates/detent-web/src/tls.rs` (`ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])`) | `a_tls13_client_negotiates_tls13_and_h2`, `a_tls12_only_client_is_refused` (`crates/detent-web/tests/tls.rs`) — an out-of-process rustls **client** with `tls12` explicitly enabled is refused by the server, so the refusal is proven for a client capable of 1.2, not just one that never offered it. External, non-rustls confirmation (`openssl s_client`) is `scripts/tls-check.sh`, added by this change — see [External TLS verification](#external-tls-verification) below; not yet wired into CI (documented manual procedure only). The shipped binary compiles no rustls `tls12` code at all: CI step "cargo tree -e features -i rustls (the binary must not enable tls12)" in the `rust` job of `.github/workflows/ci.yml` fails if `rustls feature "tls12"` appears in `cargo tree -e normal,features -p detent -i rustls`, for the default and for `--all-features` (dev-dependencies are left out: the test client above enables `tls12` on purpose). |
| ALPN h2 negotiated | protocol confusion; forces the security-header/CSRF assumptions that depend on HTTP semantics | `crates/detent-web/src/tls.rs` | `a_server_config_advertises_the_requested_alpn` (`tls.rs`); end-to-end via `a_tls13_client_negotiates_tls13_and_h2` (`tests/tls.rs`); externally via `scripts/tls-check.sh` (checks ALPN as part of its TLS 1.3 check; not yet CI-wired). |
| Client that speaks no TLS at all / an untrusted client | remote attacker; malformed-connection DoS | `crates/detent-web/src/tls.rs`, `server.rs` | `a_client_that_speaks_no_tls_at_all_is_dropped_quietly`, `an_untrusting_client_is_refused_by_its_own_verifier` (`tests/tls.rs`) |
| Concurrent-connection cap | remote attacker; connection-exhaustion DoS | `crates/detent-web/src/server.rs` | `a_connection_over_the_cap_is_dropped_without_a_handshake`; a peer that sends no request within the header timeout loses its permit, over HTTP/1.1 and HTTP/2: `an_idle_connection_does_not_hold_a_permit`, `an_idle_h2_connection_does_not_hold_a_permit`, `a_served_connection_outlives_the_first_request_deadline` (`tests/tls.rs`) |
| Bootstrap self-signed cert, fingerprint logged for TOFU | MITM during first boot before ACME succeeds | `crates/detent-web/src/tls.rs` | `a_bootstrap_certificate_loads_into_the_provider`, `the_fingerprint_is_uppercase_colon_separated_sha256` (`tls.rs`) |
| Cert store hot reload, `0600` under `0700` dir | local unprivileged user reading key material; stale-cert outage | `crates/detent-web/src/tls.rs` | `the_store_is_written_0600_under_a_0700_directory`, `a_pre_existing_store_directory_is_narrowed_to_0700`, `the_store_swaps_what_it_resolves`, `a_poisoned_store_still_serves_and_still_reloads` (`tls.rs`) |
| Private key never in debug output / logs | key exfiltration via logs | `crates/detent-web/src/tls.rs` | `the_debug_output_never_carries_the_private_key` (`tls.rs`) |
| Short-lived certs (ACME `shortlived` profile, dns-01, device-attest-01) | stolen-cert reuse window | `detent-acme` (Phase 6) | **library only, no production caller.** The `instant-acme` order/account flow, dns-01 providers (Cloudflare, acme-dns and deSEC send over a TLS 1.3, https-only client with a 30 s deadline and a 1 MiB response cap, and errors that never quote a header: `https.rs` tests `a_request_round_trips_over_tls13`, `plain_http_is_refused_without_a_connection`, `an_untrusted_certificate_is_refused_and_the_error_holds_no_secret`, `a_silent_server_hits_the_deadline`, `an_oversize_response_is_refused`; RFC 2136 sends TSIG-signed UPDATEs over TCP with HMAC-SHA2 only (hmac-md5 and hmac-sha1 refused) and accepts only an answer with a valid TSIG from the same key, full-length MAC checked in constant time, TTL 0, time within the fudge, and RCODE NOERROR: `tsig.rs` tests `a_signed_update_matches_the_bytes_dnspython_verified`, `a_dnspython_signed_answer_verifies`, `every_changed_byte_of_a_signed_answer_is_refused`, `an_answer_outside_the_clock_skew_is_refused`, `an_unsigned_answer_is_refused_and_names_its_rcode`; fixtures checked by dnspython in `testdata/tsig_fixture.py`), renewal scheduling, ARI helpers and the device-attest-01 seam exist; live issuance runs only in the CI `acme-pebble` job. `detent serve` refuses `bootstrap = "acme"` (`cli-serve-acme-unsupported`, `preflight_refuses_a_malformed_file_a_privileged_port_and_acme` in `serve.rs`). See [Gaps](#gaps). |
| dns-01 provider secret in `secrets.toml`, checked before use: opened `O_NOFOLLOW` (a symlink is refused), regular file only, at most 64 KiB, no group or other permission bit, owned by the effective uid; unknown tables and keys refused; the secret is zeroed on drop and `Debug` prints `[redacted]`; no error quotes the file (a TOML error gives only line and column) | local user who plants or reads the secret file; secret leak through logs or error text | `crates/detent-web/src/secrets.rs`, `crates/detent/src/serve.rs` (`preflight_dns_provider`) | `a_symlink_is_refused_even_to_a_good_file`, `a_file_that_is_not_regular_is_refused`, `a_file_over_64_kib_is_refused_and_64_kib_is_accepted`, `any_group_or_other_permission_bit_is_refused`, `a_file_owned_by_another_user_is_refused`, `unknown_tables_and_keys_are_refused`, `a_parse_error_names_the_place_but_never_quotes_the_file`, `debug_output_redacts_the_secret` (`secrets.rs`); `detent serve` checks the file before the fork only when `[acme.provider]` is set, and refuses to start on a bad file, a missing secret, or a provider that does not build, without quoting the secret: `preflight_refuses_a_secrets_file_it_cannot_trust`, `preflight_refuses_a_provider_without_its_secret`, `preflight_does_not_read_secrets_when_no_provider_is_set`, `preflight_builds_each_configured_provider`, `preflight_refuses_a_provider_that_does_not_build_and_quotes_no_secret` (`crates/detent/src/serve.rs`, `--all-features`), `preflight_refuses_a_provider_this_build_cannot_use` (default features) |
| HSTS `max-age=63072000; includeSubDomains` | protocol downgrade via a stripped first request | `crates/detent-web/src/headers.rs` | `every_header_is_present_with_its_exact_value` (asserts the exact `Strict-Transport-Security` value; `headers.rs`) |

## Web (Argon2id + rate limits + sessions/CSRF/CSP)

| Control | Defends against | Implemented in | Proven by |
|---|---|---|---|
| Argon2id password hashing, configurable cost | offline password cracking after a leak | `crates/detent-web/src/auth/password.rs` | `a_hash_verifies_against_its_own_password_and_no_other`, `two_hashes_of_one_password_differ_because_the_salt_does`, `the_cost_comes_from_the_configuration_and_the_host` (`password.rs`) |
| Login hashing capped: Argon2 runs in `spawn_blocking` behind a 2-permit semaphore; a login that finds no free permit is refused at once with 503 `web-auth-busy` (not queued, not audited, not counted by the limiter) | remote attacker; CPU/memory exhaustion and request pile-up through a login flood | `crates/detent-web/src/auth/routes.rs` (`attempt`), `crates/detent-web/src/state.rs` (`MAX_CONCURRENT_ARGON2`) | `logins_beyond_the_hashing_cap_are_refused_not_queued` (`routes.rs`); `every_auth_failure_maps_to_a_status_and_a_code` (`error.rs`) |
| Constant-time verify, dummy-hash on unknown user | username enumeration via timing | `crates/detent-web/src/auth/password.rs`, `auth/users.rs`, `auth/routes.rs` | `the_dummy_hash_always_refuses_and_costs_what_a_real_one_costs` (functional); `unknown_user_and_wrong_password_cost_the_same` (`password.rs`) is the actual **statistical timing** test PLAN task 2 asks for, but it is `#[ignore]`d by default (wall-clock assertions are flaky on shared CI runners) — run explicitly with `cargo test -p detent-web -- --ignored unknown_user_and_wrong_password`. `an_unknown_user_and_a_wrong_password_are_indistinguishable` (`routes.rs`) and `an_unknown_user_and_a_wrong_password_answer_the_same` (`users.rs`) cover the response-shape side without timing. |
| Passwords/hashes never logged or rendered in debug | credential exfiltration via logs/panics | `password.rs`, `users.rs` | `the_debug_output_carries_no_password_and_no_hash` (`password.rs`); `the_request_body_never_renders_its_password` (`routes.rs`) |
| Login rate limiting, per-IP and per-user, exponential backoff, lockout | credential stuffing / brute force | `crates/detent-web/src/auth/ratelimit.rs` | `the_first_failures_are_free_and_the_next_one_locks_out`, `the_backoff_doubles_and_is_capped`, `a_lockout_expires_on_its_own`, `the_two_buckets_are_independent` (`ratelimit.rs`); end-to-end via `repeated_failures_lock_the_account_out_and_the_lockout_is_audited` (`routes.rs`, also proves the lockout is audited) |
| Rate-limiter table bounded (no unbounded memory growth from spoofed names) | remote attacker; memory-exhaustion DoS | `ratelimit.rs` | `the_maps_are_bounded_by_eviction`, `eviction_drops_the_least_recently_seen_entry`, `a_name_that_does_not_exist_is_still_throttled` (`ratelimit.rs`) |
| Auth audit log bounded: a rate-limited attempt writes no record (the lockout was already audited); `detent-auth.jsonl` rotates to `.1` at 16 MiB; the file is `0600` and a directory the sink creates is `0700` | remote attacker filling the disk with refused logins; other local users reading auth events | `crates/detent-web/src/auth/routes.rs` (`audit_failure`), `auth/audit.rs` (`FileAuthAudit::append`) | `rate_limited_attempts_do_not_grow_the_audit_log` (`routes.rs`); `a_log_at_16_mib_is_rotated_to_dot_1_before_the_next_append`, `the_sink_creates_the_audit_directory_0700`, `the_file_sink_appends_json_lines_0600` (`audit.rs`) |
| Sessions: 32-byte CSPRNG id, `__Host-` cookie, `Secure`/`HttpOnly`/`SameSite=Strict`, idle 15 min, absolute 8 h, rotate on login | session fixation/hijack; cookie theft via XSS; stale sessions | `crates/detent-web/src/auth/session.rs` | `a_new_session_is_found_by_its_id_and_by_nothing_else`, `the_idle_timeout_removes_the_session_rather_than_refusing_it`, `the_absolute_timeout_ends_a_session_that_is_still_being_used`, `rotation_replaces_the_id_and_the_csrf_token_at_once`, `the_cookie_carries_the_three_attributes_the_host_prefix_requires` (`session.rs`); login rotation: `signing_in_again_invalidates_the_session_the_request_arrived_with` (`routes.rs`); the expiry sweep runs under `serve`: `prepare_worker_reaches_a_bound_listener` (`crates/detent/src/serve.rs`) |
| Explicit logout invalidates immediately | stolen-cookie reuse after logout | `session.rs`, `auth/routes.rs` | `logout_invalidates_immediately_and_only_once` (`session.rs`); `logging_out_ends_the_session_and_clears_the_cookie` (`routes.rs`) |
| Session id/view never leaks the raw id | session-fixation via a leaked identifier | `session.rs` | `the_view_says_when_it_expires_and_never_carries_the_id`, `nothing_here_prints_a_secret` (`session.rs`) |
| CSRF: `Sec-Fetch-Site`, `Origin`, `X-Detent-CSRF` all required on non-GET; Bearer bypass only with no cookie ambient authority | CSRF from a compromised browser tab | `crates/detent-web/src/csrf.rs` | `each_missing_or_wrong_condition_is_a_refusal` (table-driven, one case per PLAN task 3 condition), `a_bearer_token_skips_the_checks_entirely`, `a_repeated_authorization_header_does_not_bypass`, `an_expired_session_is_not_treated_as_a_csrf_failure` (`csrf.rs`) |
| GET never mutates | CSRF via a simple cross-site GET/image tag | `csrf.rs`; the route tables in `api/*.rs` and `auth/routes.rs` | `no_get_route_is_registered_for_a_mutating_operation`, `a_mutating_route_refuses_a_get` (`csrf.rs`); `the_router_answers_exactly_the_table` (`api/mod.rs`) proves the tables these tests walk are the router: the router registers exactly the tabled paths (auth routes included), and every method on every path is routed if and only if a table lists it |
| API tokens: 32-byte random, stored as SHA-256 digest only, scoped, revocable, expirable; the token and user stores re-read their file before each use and inside each write, so a revocation or user removal made by another process holds and a stale store cannot write it back | token database leak; stolen-token misuse; a revoked token or removed user brought back by a stale in-memory copy | `crates/detent-web/src/auth/token.rs`, `auth/users.rs` (`refresh`, `mutate`) | `a_token_is_shown_once_and_stored_only_as_a_digest`, `an_expired_token_is_refused_exactly_like_an_unknown_one`, `a_revoked_token_stops_working_at_once`, `token_revoked_through_another_store_stops_working`, `a_stale_store_write_does_not_bring_back_a_revoked_token`, `nothing_here_prints_a_token_or_a_digest` (`token.rs`); `removed_user_neither_accepted_nor_resurrected`, `a_stale_store_write_does_not_bring_back_a_removed_user` (`users.rs`) |
| Token scopes: `read`/`write`, write implies read; the engine checks the caller's `ScopedAuthz` on every web and MCP operation (`AllowAll` only for the CLI) and audits a refusal as `denied` | over-privileged token misuse; an unaudited refusal | `crates/detent-web/src/authz.rs`, `crates/detent-ops/src/engine.rs` (`execute(op, who, authz)`), `crates/detent-web/src/engine.rs`, `crates/detent/src/mcp.rs` (`SessionExecutor`) | `the_required_scope_is_write_exactly_for_mutating_operations`, `write_implies_read_and_read_does_not_imply_write`, `a_read_only_caller_may_read_everything_and_write_nothing` (`authz.rs`); `a_scope_denial_is_audited` (`detent-web/src/engine.rs`); `authorize_refuses_and_audits_a_write_operation_for_a_read_caller` (`detent-web/src/api/mod.rs`); `a_read_scope_permits_reads_and_the_engine_denies_and_audits_mutations` (`detent/src/mcp.rs`) |
| TOTP: RFC 6238 vectors, ±1 step window, anti-replay | credential-stuffing after a password leak (2FA); code replay | `crates/detent-web/src/auth/totp.rs` | `the_rfc_6238_test_vectors_produce_the_published_codes`, `the_window_accepts_one_step_either_side_and_no_more`, `a_code_cannot_be_used_twice` (`totp.rs`); end-to-end login with TOTP via `an_enrolled_account_must_present_a_fresh_code`, `a_host_that_requires_totp_refuses_an_account_without_one` (`routes.rs`) |
| Security headers: CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP/COEP, `Cache-Control: no-store` on API | XSS, MIME sniffing, cross-origin leaks, referrer leakage, API response caching | `crates/detent-web/src/headers.rs` | `every_header_is_present_with_its_exact_value`, `the_csp_is_the_policy_from_the_plan`, `only_api_paths_are_marked_no_store`, `error_responses_carry_the_headers_too` (`headers.rs`) |
| CSP script hash matches the actual inline theme script | script injection via a hash that no longer matches the shipped script | `headers.rs`, `spa.rs` | `theme_script_sha256_matches_the_file_it_hashes`, `the_inline_script_in_index_html_is_the_file_byte_for_byte` (`headers.rs`) |
| Body size limit (256 KiB) | remote attacker; memory-exhaustion DoS via oversized bodies | `crates/detent-web/src/server.rs` | `a_body_over_the_limit_is_refused` (`server.rs`) |
| Request timeouts | slow-loris / hung-handler DoS | `server.rs` | `a_slow_handler_is_timed_out_with_the_security_headers_intact` (`server.rs`) |
| `GET /system/update` cannot make the host poll the release feed: it prefers the on-disk stamp, a live check writes the stamp, and a failed live check keeps the next one off the network for 10 minutes | a read-scoped caller using the host to hammer GitHub (rate-limit exhaustion, traffic amplification) | `crates/detent-web/src/api/system.rs` (`update`, `guarded_live_check`, `FAILED_CHECK_BACKOFF`) | `a_second_uncached_check_does_not_reach_the_network` (`system.rs`) |
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
| Capability bounding set shrunk to the computed minimum | a compromised process using an unneeded capability (e.g. `CAP_SYS_ADMIN`) | `crates/detent-platform/src/sandbox/linux.rs` | `capability_bounding_set_shrinks_to_the_policy_set` (`linux.rs`), which asserts the shrunk mask where `CAP_SETPCAP` is held and, where it is not, asserts only that the refusal is reported rather than mistaken for success. The monitor's policy sets `require_caps: true`: when the drop is refused (no `CAP_SETPCAP`), `confine` returns `CapsRequired` and start-up stops; `caps_that_do_not_drop_are_fatal_only_when_required` (`sandbox/mod.rs`). The worker (`require_caps: false`) has no capabilities after its uid drop, which `drop_capabilities` treats as the required outcome. |
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
| Commit-confirm: apply arms a timer, every monitor exit rolls back an unconfirmed apply and clears its marker, and the next monitor start recovers a leftover marker before serving; one-shot CLI applies to commit-confirm modules are refused | an apply that breaks network/service reachability locking the admin out of the host | `crates/detent-platform/src/privsep/monitor.rs` (`PENDING_COMMIT_MARKER`, `recover_pending`, `serve_locked`), `crates/detent/src/{serve,run}.rs` | `shutdown_with_a_pending_commit_rolls_back`, `run_monitor_recovers_a_leftover_marker`, `a_cli_apply_on_a_commit_confirm_module_never_leaves_an_unenforced_commit`; the web console can confirm the window, also after a reload (it rehydrates from `GET /api/v1/commits/pending`): `an armed window survives a reload and is confirmed` (`web/e2e/console.e2e.ts`, Playwright, API stubbed), `PendingCommit.test.tsx` |
| Only one pending commit at a time | overlapping applies corrupting the rollback state | `monitor.rs` | covered by the `pending: Option<Pending>` single-slot design exercised through `confirm_commit_and_start_confirm_timer_log_through_tracing`; no test explicitly asserts a second `Apply` is refused while one is pending — see [Gaps](#gaps). |
| Audit log: intent fail-closed (`Started` persistence failure aborts via `AuditUnavailable`); every line is fsynced, sequenced, and SHA-256 hash-chained; `query` reads backwards from the end and verifies the chain over the records it reads, `verify` checks the whole file; above 16 MiB the log moves to `.1` and the new file continues the chain; a torn final line (crash mid-append) is kept out of the chain and its digest is noted in the next record; the directory is `0700` and its parent is fsynced when the log is created; the worker owns the file, so the chain detects edits but does not stop a rewrite; terminal anchors must be retained externally to detect tail truncation; outcome/denial persistence is best-effort; journald is the independent copy; no secrets/full bodies | undetected mutation, reordering, insertion, or tail truncation; accidental secret leakage into the audit trail | `crates/detent-ops/src/audit.rs` (`FileAudit`, `scan_records`, fsynced append), `crates/detent-ops/src/engine.rs` (intent `Started` → `AuditUnavailable`) | `the_file_sink_appends_one_line_per_record_and_reads_them_newest_first`, `verification_detects_tampering_and_truncation_against_an_anchor`, `a_deleted_middle_record_breaks_the_chain`, `a_torn_final_line_does_not_block_later_records`, `a_second_crash_before_the_note_is_still_recovered`, `an_unnoted_bad_line_in_the_middle_breaks_the_chain`, `the_audit_directory_is_private`, `a_tail_query_reads_backwards_and_verifies_only_what_it_reads`, `a_full_log_rotates_and_the_chain_continues` (`audit.rs`); `an_unwritable_audit_sink_refuses_the_mutation` (`engine.rs`) |

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
| Sigstore verification of release artifacts (in-tree verifier, ADR-014) | a malicious or coerced release build; a forged or replayed Rekor entry; a backdated `integratedTime` | `crates/detent-update/src/{bundle,verify,trust}.rs`; called by the monitor before `UpdateApply` swaps the binary | `tests/verify_fixtures.rs` (one test per ADR-014 fixture, incl. `a_bad_set_is_refused`, `corrupted_inclusion_path_is_refused_at_step_6`, `a_forged_integrated_time_is_refused`); `verify.rs` `a_real_public_good_set_verifies` and `a_real_set_does_not_cover_a_changed_field` (a production Rekor SET); `the_leaf_hash_is_the_rfc6962_hash_of_the_body`, `a_real_rekor_proof_reaches_its_root_from_the_body_leaf`, `the_leaf_hash_covers_the_body_only`. The Merkle leaf is `SHA-256(0x00 ‖ canonicalizedBody)` as Rekor computes it, and the Rekor SET, verified with the embedded Rekor key, is what binds `integratedTime` (the forged-time test fails with the SET check removed). **Partial:** fixtures are self-minted, not a captured release bundle; the embedded trust files are placeholders (every real update refuses closed); `release.yml` does not yet publish the DSSE bundle the verifier needs; embedded SCTs are checked for presence only; the checkpoint parser does not yet read Rekor's signed-note format (STAGE3 H17 steps 1, 5, 7, 8). |
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

1. **Closed: the capability bounding-set drop no longer fails open for the
   monitor.** `Policy::monitor` sets `require_caps: true`, so a refused drop
   stops start-up (`caps_verdict`, `sandbox/mod.rs`). Still unproven on a host
   without `CAP_SETPCAP` outside the unit test.
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
11. **Reproducible builds, SBOM, provenance and immutable releases** are
   Phase 9 work with no evidence in this document. Sigstore verification of
   a release bundle exists in `detent-update` (see its row above); it is not
   yet proven against a real release bundle. `detent-acme` is a library with
   no production caller: issuance is exercised only by the CI Pebble job, and
   `serve` refuses `bootstrap = "acme"` until the renewal loop is wired
   (STAGE4 §4.3).
12. **`testssl.sh` is not invoked anywhere in this repository.** PLAN Phase 4
    task 1 names it explicitly ("CI job, allow network"); no such job exists.
    `scripts/tls-check.sh` (added by this change) covers the
    `openssl s_client`/ALPN portion of task 1 but not the weak-cipher-suite
    sweep `testssl.sh` performs.
13. **Output escaping in the admin UI (React) is not yet applicable** — `web/src`
    has Phase 4's bootstrap only (`index.html`, the theme script, base CSS);
    no application/form code exists yet (Phase 5).
