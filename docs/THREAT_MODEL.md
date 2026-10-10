# detent threat model

STRIDE per component, mapped to the tests that prove each control (PLAN §3,
PLAN Phase 12, BUGFIX Track F). State as of 2026-10-09 (`main` at
`b2686f9`).

This document does not repeat the control tables. For each control it names
the threat, the asset, the attacker, the control and the test, then links
the [`SECURITY_HARDENING.md`](SECURITY_HARDENING.md) row that holds the full
detail. [`ARCHITECTURE.md`](ARCHITECTURE.md) explains the process model and
the write path. [`PENTEST_CHECKLIST.md`](PENTEST_CHECKLIST.md) maps the same
evidence to OWASP ASVS 4.0.3 Level 2.

**Rules for this document**

- Every test name was found with `rg -n 'fn <name>'` in this tree. Run one
  with `cargo test -p <crate> <name>` (root tests: `--all-features`, as root,
  `--test-threads=1`; see ARCHITECTURE §12).
- **Status** is one of: **Covered** (a test proves the control), **Partial**
  (a test proves part of it; the rest is named), **Gap** (no test, or no
  control), **Accepted** (an ADR, PLAN or an owner decision in BUGFIX §4
  accepts the risk; the source is named).
- A gap has an id (`TM-G<n>`). [§8](#8-gaps) lists them with a severity.
  The owner decides which gaps to accept.

---

## 1. Scope

In scope: the `detent` binary on a tier-1 Linux host (systemd), all of its
processes, its state on disk, the embedded SPA, the MCP server, the CLI,
the self-updater, the release pipeline that produces the binary, and the
packaged unit.

Out of scope:

- The security of the managed daemons themselves (Samba, dnsmasq, Kea,
  chrony, NFS, unbound). detent writes their configuration; it does not
  sandbox them.
- The host kernel, init system, and libc. detent relies on them.
- GitHub, Sigstore (Fulcio, Rekor, TSA), the ACME CA and the dns-01
  provider as services. Their compromise is an assumption break (§4), not a
  threat detent can stop. The verifier limits what a single compromise can
  do.
- FreeBSD and other tier-2 hosts (PLAN §1.6). Their sandbox is not built.
- An authorized administrator who acts in bad faith. detent records what
  they do (audit log); it does not stop them.
- Physical access to the device.
- `libdetent` (`detent-ffi`) callers: the C ABI has no file, network or
  process access (`docs/FFI.md`). Memory safety at the ABI edge is in
  [SH-M] (Miri job "FFI soundness").

## 2. System and trust boundaries

```text
                         Internet / LAN
   admin browser ─┐          │            ┌─ GitHub releases, Sigstore
   (SPA, A4)      │   TB1    │            │  (TB5, TB7)
   API client ────┼──TLS 1.3─┤            │
                  │          ▼            │       ACME CA, dns-01 provider
                  │   ┌─────────────┐     │       (TB9)
                  │   │   worker    │     │          ▲
                  │   │ uid detent  │     │          │ outbound only
                  │   │ web, API,   │◀────┼──────────┤
                  │   │ ops engine  │ socketpair  ┌──┴─────────┐
                  │   └──────┬──────┘ (Install,   │ acme       │
                  │      TB2 │ socketpair RenewNow)│ uid detent │
                  │          ▼                     └────────────┘
                  │   ┌─────────────┐
                  │   │  monitor    │──▶ allow-listed targets (/etc/...)
                  │   │ root, conf. │──▶ backups, state lock, staging
                  │   └──────┬──────┘
                  │      TB3 │ socketpair
                  │          ▼
                  │   ┌─────────────┐   TB4: candidate bytes
                  │   │  runner     │──▶ validators, systemctl,
                  │   │ root, open  │    systemd-run detent-update ──┐
                  │   └─────────────┘                                │
                  │                                                  ▼
   local operator ── TB6 ──▶ CLI / `detent mcp` (no privsep)   CLI updater
   MCP client ──────────────▶ (same process holds the monitor)  (root, TB5)
```

| # | Boundary | Untrusted side | Main controls |
|---|---|---|---|
| TB1 | Network → worker | any TCP peer | TLS 1.3, connection cap, deadlines, auth, CSRF ([SH-T], [SH-W]) |
| TB2 | Worker → monitor | the worker (assume taken) | closed request enum, 1 MiB frames, allow-list ids, content re-validation ([SH-L]) |
| TB3 | Monitor → runner | the monitor (assume taken) | runner's own allow-list copy, staged file name only, fixed update argv ([SH-L]) |
| TB4 | Candidate content → root daemons | bytes the worker sends | module parser and validator, execution deny-list ([SH-L], [SH-I]) |
| TB5 | Release feed → installed binary | GitHub, the network | SHA256SUMS, in-tree Sigstore verifier, self-test, rollback ([SH-S]) |
| TB6 | Local operator → CLI / MCP | local users | Unix permissions; the CLI needs the privilege it uses (ARCHITECTURE §3.2) |
| TB7 | Source and CI → release | dependencies, actions, a stolen token | pins, cooldown, deny/audit, reproducibility gate, attestations ([SH-S]) |
| TB8 | Other browser origins → SPA | a hostile tab or site | CSRF, CSP, `SameSite=Strict`, COOP/CORP/COEP ([SH-W]) |
| TB9 | acme process → CA and DNS provider | the network, the CA answer | TLS 1.3 client, size and time caps, TSIG checks ([SH-T]) |

TB1–TB6 are ARCHITECTURE §4. TB7–TB9 are added here.

## 3. Assets

| Id | Asset | Where | Who can read / write | Rotation |
|---|---|---|---|---|
| AS1 | Managed configuration files | allow-listed targets, e.g. `/etc/hosts` | root daemons read; only the monitor writes | backups, keep 20 |
| AS2 | Service control | systemd through the runner | runner only | — |
| AS3 | TLS private key | `tls.cert_dir` (state root), `0600` in `0700` | worker | ACME renewal; bootstrap pair regenerated near expiry |
| AS4 | ACME account key | `acme.credentials_path`, `0600` | acme process | manual |
| AS5 | dns-01 provider secret | `/etc/detent/secrets.toml`, `0600` root | privileged parent before fork; then acme process memory | manual |
| AS6 | Admin password hashes, TOTP secrets | `users.json` under the state root, `0600` | worker reads; CLI writes | `detent user passwd`; TOTP: no tool (TM-G1) |
| AS7 | API token digests | `tokens.json`, `0600` | worker reads; CLI writes | `detent token revoke`, expiry |
| AS8 | Session ids and CSRF tokens | worker memory only | worker | rotate on login; 15 min idle, 8 h absolute |
| AS9 | The detent binary | install path | root; the CLI updater swaps it | releases |
| AS10 | Audit logs | `audit/detent-audit.jsonl`, `audit/detent-auth.jsonl` | worker writes (owns the files) | 16 MiB rotation |
| AS11 | Commit-confirm state | `pending-commit.json`, in-place marker | monitor | per apply |
| AS12 | Release signing identity | GitHub OIDC for `release.yml` at a tag | GitHub Actions | keyless, per run |
| AS13 | Device availability and reachability | the host | — | commit-confirm rollback |

## 4. Attackers and assumptions

| Id | Attacker position |
|---|---|
| A1 | Remote, unauthenticated, on the network path to the listener |
| A2 | Authenticated caller with a `read` token or a read session |
| A3 | Authenticated caller with `write` (in scope only where detent claims to limit them, e.g. tag checks, rate limits) |
| A4 | A hostile page in the admin's browser (CSRF, XSS, clickjacking) |
| A5 | Local unprivileged user on the device |
| A6 | Code execution in the worker (post-exploitation of TB1) |
| A7 | Code execution in the monitor (post-exploitation of TB2) |
| A8 | Code execution in the acme process, or a hostile CA / DNS answer |
| A9 | Network attacker on outbound paths (GitHub, Sigstore, CA, DNS provider) |
| A10 | Compromised upstream crate, npm package or GitHub Action |
| A11 | Stolen maintainer credential that can push a tag or edit a release |
| A12 | Hostile text that reaches an MCP client's model (prompt injection) |

Assumptions (a break voids the listed controls):

1. The kernel enforces seccomp, `no_new_privs` and capabilities. Landlock is
   present on most hosts but not all (TM-G13).
2. systemd runs the unit as packaged and starts transient units on request.
3. Sigstore public-good roots embedded at build time are honest. A Fulcio
   or Rekor compromise together with a GitHub OIDC compromise could sign a
   release.
4. The admin checks the bootstrap certificate fingerprint on first use, or
   ACME is configured before the first login (PLAN §2.8).
5. The host clock is roughly right (TOTP, session expiry, certificate and
   Sigstore validity). detent does not defend against a hostile clock.
6. Only trusted operators have a shell as root or as `detent`.

---

## 5. STRIDE per component

Column **S/T/R/I/D/E** is the STRIDE class. Test names are in the file
named in brackets, relative to `crates/` unless the path starts otherwise.

### 5.1 Monitor (`detent-platform/src/privsep/monitor.rs`)

| Id | S/T/R/I/D/E | Threat (asset ← attacker) | Control | Proven by | Status |
|---|---|---|---|---|---|
| MON-1 | S | Worker skips the handshake or speaks another protocol version (AS1 ← A6) | `Hello` first, once, with `PROTO_VERSION` | `dispatch_requires_the_handshake_before_anything_else` (`monitor.rs`); `hello_rejects_a_version_mismatch_and_closes_the_channel` (`detent-platform/tests/privsep_e2e.rs`) | Covered |
| MON-2 | T, E | Worker names a path, program or unit (AS1, AS2 ← A6) | Closed request enum; every request names an allow-list index | `ids_outside_the_tables_resolve_to_nothing` (`privsep/allowlist.rs`); `every_request_variant_round_trips` (`privsep/proto.rs`). [SH-L] row "Privilege separation" | Covered |
| MON-3 | T, E | Worker gains root through config content (`root preexec`, `dhcp-script`, `hooks-libraries`) (AS1 ← A6) | Module parser and validator, per-daemon execution deny-list in `revalidate` | `every_known_bypass_is_refused`, `ordinary_edits_are_allowed` (`privsep/exec_deny.rs`); `write_target_refuses_new_root_exec_directives` (`monitor.rs`). [SH-L] row "Content written … re-validated" | Accepted (ADR-001: the deny-list is best effort; a directive it does not list still reaches root) |
| MON-4 | T | Lost update between two sessions; torn write on power loss (AS1 ← A3, crash) | `expected_prev` digest; `O_EXCL` temp, `fsync`, `rename`; in-place marker for read-only dirs | `write_target_conflict_leaves_the_file_untouched_then_succeeds` (`detent-platform/tests/privsep_e2e.rs`); `a_torn_in_place_write_is_restored_at_start` (`monitor.rs`); `the_in_place_path_refuses_a_symlink_target` (`detent-platform/tests/fs_atomic.rs`). [SH-L] row "Atomic write protocol" | Covered |
| MON-5 | D | Oversized or malformed frames crash or exhaust the monitor (AS13 ← A6) | 1 MiB cap before allocation; undecodable frame closes the channel | `oversize_frames_are_rejected_before_allocating` (`privsep/proto.rs`); `an_undecodable_frame_terminates_the_session_with_a_protocol_violation` (`privsep_e2e.rs`); fuzz target `fuzz/fuzz_targets/fuzz_privsep_decode.rs` | Covered |
| MON-6 | T, D | Two monitors write the same state root (AS1, AS11 ← A5, operator error) | Exclusive state lock; no lock means no state change | `a_monitor_without_the_state_lock_refuses_every_state_change` (`monitor.rs`); `a_second_monitor_cannot_take_the_pending_commit_lock` (`privsep_e2e.rs`) | Covered |
| MON-7 | E | A taken monitor uses root beyond its task (AS1, AS9 ← A7) | Bounding set cut (`require_caps`), `no_new_privs`, Landlock writes to target dirs only, `MONITOR` seccomp table with no process creation, kill on violation | `capability_bounding_set_shrinks_to_the_policy_set`, `no_new_privs_is_set_afterwards`, `enforce_mode_monitor_dies_by_sigsys_on_execve` (`sandbox/linux.rs`, root); `the_monitor_table_has_no_process_creation_calls`, `no_table_allows_linkat` (`sandbox/seccomp.rs`); `no_policy_grants_a_write_on_the_binary_directory` (`sandbox/mod.rs`). [SH-L] | Partial: Landlock absent on Raspberry Pi OS (TM-G13); `PR_SET_DUMPABLE=0` has no test (TM-G14); root `enforce_mode_*` tests for E16 not yet run in CI or on the test host (TM-G18) |
| MON-8 | I | Error answers leak paths or OS messages to the worker (AS1 ← A6) | `ProtoError` carries no path; `atomic_to_proto` maps errors | `atomic_to_proto_maps_relative_path_to_an_io_error` (`monitor.rs`) | Covered |
| MON-9 | R | A taken worker writes through the monitor and omits the audit record (AS10 ← A6) | Every write makes a backup in a monitor-owned directory | backups: `list_backups_and_restore_round_trip` (`privsep_e2e.rs`) | Gap TM-G5: the monitor logs no line per `WriteTarget`, `Restore` or `Service`; the ops audit is worker-owned |
| MON-10 | D | A bad network or resolver apply locks the admin out (AS13 ← A3, mistake) | Commit-confirm timer in the monitor; rollback on timeout, on exit and at the next start | `commit_confirm_expiry_rolls_back_unconfirmed_writes` (`privsep_e2e.rs`); `shutdown_with_a_pending_commit_rolls_back` (`monitor.rs`); `a_second_commit_confirm_apply_while_one_is_pending_writes_nothing` (`detent-ops/tests/engine.rs`). [SH-I] row "Commit-confirm" | Covered |

### 5.2 Worker process (`detent serve`, `Role::Worker`)

The web layer that runs in the worker is §5.5. This section is the process
boundary.

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| WRK-1 | E | Remote code execution in the worker becomes root (AS1–AS9 ← A6) | uid `detent`, empty bounding set, `no_new_privs`, Landlock writes only in the state root, `WORKER` seccomp table | `hooks_confine_both_roles_across_a_forked_pair`, `enforce_mode_worker_drops_the_bounding_set_before_its_uid_change` (`sandbox/linux.rs`, root); `worker_policy_is_state_root_only_with_no_capabilities` (`sandbox/mod.rs`) | Covered |
| WRK-2 | I | A taken worker sends data out (AS3, AS6, AS7 ← A6) | `WORKER` has no `connect` (ADR-015) | `the_acme_table_connects_out_and_never_accepts` (`sandbox/seccomp.rs`) asserts the worker and the monitor cannot `connect` | Gap TM-G2: `WORKER` allows `socket` and `sendto` with no argument filter, so a taken worker can send UDP datagrams to any address without `connect`. Inferred from the table; not demonstrated |
| WRK-3 | I | A taken worker reads the dns-01 secret or the ACME account key (AS4, AS5 ← A6) | The provider is built before the fork and dropped by the parent; the worker cannot re-read `secrets.toml` (`0600` root) | `the_parent_drops_the_issuer_at_the_fork_and_keeps_what_it_passed` (`detent/src/acme.rs`); `acme_policy_writes_only_its_directory_with_no_capabilities` (`sandbox/mod.rs`) | Covered |
| WRK-4 | E | Worker keeps the runner descriptor it inherits and drives the root runner (AS2 ← A6) | The worker drops it first (`serve.rs`, `Role::Worker` arm) | none | Gap (already listed in [SH-L] row "Validators … runner": no test observes the drop) |
| WRK-5 | D | A reachable panic aborts the worker (`panic = "abort"`) and logs everyone out (AS13 ← A1) | `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` denied (ADR-010); fuzzing; `Restart=always` | clippy `-D warnings` in CI job "Rust"; `no_bodied_endpoint_ever_answers_5xx` (`detent-web/src/api/integration_tests.rs`); fuzz targets `fuzz_api_json`, `fuzz_session_cookie` | Partial: lint and fuzz evidence, no proof that no panic is reachable |

### 5.3 Runner (`detent-platform/src/privsep/runner.rs`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| RUN-1 | E | A taken monitor runs an arbitrary program as root through the unconfined runner (AS1, AS2 ← A7) | Only allow-list ids, a staged file name, a declared action, or a release tag; argv built from static declarations | `the_runner_refuses_anything_outside_the_allow_list`, `the_runner_refuses_anything_but_a_candidate_in_a_target_directory`, `the_runner_refuses_a_reload_no_module_declares` (`runner.rs`). [SH-L] row "Validators … runner" | Covered |
| RUN-2 | T, E | Monitor injects an argument into the update start (AS9 ← A7) | Tag checked again (`is_release_tag`); one fixed argv; binary path never from the socket | `the_runner_refuses_a_tag_that_is_not_a_release_tag` (`runner.rs`); `systemd_starts_the_update_unit_with_the_fixed_argv`, `systemd_refuses_a_bad_tag_or_binary_before_running_anything` (`detent-platform/tests/service_manager.rs`); `the_adapter_starts_the_update_with_this_process_executable` (`service/mod.rs`) | Covered (live `systemd-run` under the packaged unit: [SH-L] says unproven until a Linux run) |
| RUN-3 | E | The runner is root and unconfined (AS1–AS9 ← A7) | Its only input is the monitor's socket | — | Accepted (ADR-001: a seccomp filter binds every child, so the runner is forked before confinement) |
| RUN-4 | D | Runner channel fails mid-apply and apply goes on without checks (AS1 ← A7, crash) | Any channel error disables the client; apply fails closed | `a_runner_that_is_gone_makes_every_later_call_unavailable` (`runner.rs`) | Covered |
| RUN-5 | E | Mount activation mounts over a system path (AS13 ← A6) | Units computed from the target; `/` and ancestors of `/etc`, `/usr`, `/boot`, state root, binary dir refused | `protected_mount_points_are_refused_and_never_reach_the_init_system` (`privsep/mounts.rs`) | Covered |

### 5.4 ACME process (`detent-platform/src/privsep/acme.rs`, `detent/src/acme.rs`, ADR-015)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| ACM-1 | E | A hostile CA or DNS answer takes the acme process and then listens or reaches the runner (AS2 ← A8) | uid `detent`, no caps, `no_new_privs`, `ACME` table with no `listen`/`accept4`; the runner handle is dropped first | `enforce_mode_acme_reaches_out_but_cannot_listen` (`sandbox/linux.rs`, root); `the_acme_child_drops_what_it_inherits_and_the_parent_keeps_it` (`privsep/spawn.rs`) | Covered |
| ACM-2 | I | Provider secret or account key leaks through logs or errors (AS4, AS5 ← A5 reading logs) | Redacted `Debug`; errors never quote a header or the secret | `a_failed_present_through_a_real_provider_leaves_no_secret_in_the_log` (`detent/src/acme.rs`); `no_http_provider_error_holds_the_credential` (`detent-acme/src/providers.rs`); `debug_never_prints_the_key` (`privsep/acme.rs`). [SH-T] row "dns-01 provider secret" | Covered |
| ACM-3 | S, T | MITM on the CA or the DNS provider API (AS3 ← A9) | TLS 1.3, https only, 30 s deadline, 1 MiB cap; RFC 2136 answers need a valid TSIG (SHA-2 only) | `plain_http_is_refused_without_a_connection`, `an_untrusted_certificate_is_refused_and_the_error_holds_no_secret` (`detent-acme/src/https.rs`); `every_changed_byte_of_a_signed_answer_is_refused`, `only_the_sha2_algorithms_parse` (`detent-acme/src/tsig.rs`) | Covered |
| ACM-4 | T | The acme process hands the worker a pair for other names (AS3 ← A8) | The worker checks the pair covers the configured domains | `a_pair_the_worker_must_not_serve_is_refused_without_quoting_it` (`detent/src/acme.rs`) | Covered |
| ACM-5 | D | Repeated "renew now" uses up the CA's rate limit (AS13 ← A3) | Write scope; forced orders limited by `MIN_FORCED_INTERVAL` | `two_renew_now_within_the_interval_order_only_once`, `a_forced_check_within_the_min_interval_orders_nothing` (`detent/src/acme.rs`) | Covered. The [SH-L] residual "no rate limit in detent" is out of date |
| ACM-6 | I | A taken acme process receives UDP on a port it binds (AS4 ← A8) | — | — | Accepted (ADR-015 amendment, owner 2026-09-26: `bind` is needed by musl's resolver) |
| ACM-7 | S | First boot before ACME: a MITM presents its own certificate (AS6 ← A1) | Bootstrap fingerprint logged every start for TOFU | `the_fingerprint_is_uppercase_colon_separated_sha256` (`detent-web/src/tls.rs`) | Accepted (PLAN §2.8, assumption 4) |

### 5.5 Web server, API and authentication (`detent-web`)

Full rows: [SH-T] and [SH-W].

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| WEB-1 | I, T | Downgrade or MITM of the admin connection (AS6, AS8 ← A1) | TLS 1.3 only, no `tls12` code in the binary, HSTS | `a_tls12_only_client_is_refused`, `a_tls13_client_negotiates_tls13_and_h2` (`detent-web/tests/tls.rs`); `every_header_is_present_with_its_exact_value` (`headers.rs`) | Partial: no `testssl.sh` run; `scripts/tls-check.sh` not in CI (TM-G16) |
| WEB-2 | S | Password guessing and credential stuffing (AS6 ← A1) | Argon2id, per-IP and per-user limits with lockout, bounded tables | `the_first_failures_are_free_and_the_next_one_locks_out`, `the_maps_are_bounded_by_eviction` (`auth/ratelimit.rs`); `repeated_failures_lock_the_account_out_and_the_lockout_is_audited` (`auth/routes.rs`) | Partial: 12 to 128 character policy since 2026-10-09; no breach check (TM-G8) |
| WEB-3 | I | User enumeration through timing or answers (AS6 ← A1) | Dummy hash; one answer shape | `an_unknown_user_and_a_wrong_password_are_indistinguishable` (`auth/routes.rs`); `unknown_user_and_wrong_password_cost_the_same` (`auth/password.rs`, `#[ignore]`) | Partial: the timing test does not run in CI |
| WEB-4 | S | Second factor bypass or code replay (AS6 ← A1 with the password) | RFC 6238, ±1 step, counter kept, `totp_required` | `a_code_cannot_be_used_twice`, `the_window_accepts_one_step_either_side_and_no_more` (`auth/totp.rs`); `an_enrolled_account_must_present_a_fresh_code` (`auth/routes.rs`) | Gap TM-G1: nothing enrols a TOTP secret (`UserStore::set_totp` has no caller outside tests), so the second factor cannot be turned on |
| WEB-5 | S | Session hijack or fixation (AS8 ← A1, A4) | 32-byte id, `__Host-` cookie, `Secure`/`HttpOnly`/`SameSite=Strict`, rotation on login, timeouts | `the_cookie_carries_the_three_attributes_the_host_prefix_requires`, `rotation_replaces_the_id_and_the_csrf_token_at_once`, `the_idle_timeout_removes_the_session_rather_than_refusing_it` (`auth/session.rs`); `signing_in_again_invalidates_the_session_the_request_arrived_with`, `logging_in_as_another_user_never_reuses_the_presented_session` (`auth/routes.rs`); `rotation_for_another_subject_removes_the_session_and_hands_out_nothing` (`auth/session.rs`) | Covered |
| WEB-6 | S, E | Stolen or over-scoped API token (AS7 ← A2) | SHA-256 digest only, scopes, expiry, revocation re-read from disk | `a_token_is_shown_once_and_stored_only_as_a_digest`, `token_revoked_through_another_store_stops_working` (`auth/token.rs`); `a_read_only_caller_may_read_everything_and_write_nothing` (`authz.rs`); `authorize_refuses_and_audits_a_write_operation_for_a_read_caller` (`api/mod.rs`) | Covered |
| WEB-7 | T | CSRF from a hostile tab (AS1 ← A4) | `Sec-Fetch-Site`, `Origin`, `X-Detent-CSRF` on every non-GET; GET never mutates | `each_missing_or_wrong_condition_is_a_refusal`, `no_get_route_is_registered_for_a_mutating_operation` (`csrf.rs`); `cert_renew_refuses_a_session_without_the_csrf_token` (`api/integration_tests.rs`) | Covered |
| WEB-8 | E | A new route ships without authentication (AS1 ← A1) | Every handler takes `Caller`; sweep off the route table | `no_api_route_is_reachable_without_a_credential`, `openapi_document_needs_a_credential` (`api/integration_tests.rs`); `the_router_answers_exactly_the_table` (`api/mod.rs`) | Covered |
| WEB-9 | T | Unexpected fields or deep JSON (AS1 ← A2, A3) | `deny_unknown_fields`, depth limit, 256 KiB body | `the_apply_body_refuses_unknown_fields` (`api/system.rs`); `a_pathologically_nested_body_is_refused_without_crashing`, `no_bodied_endpoint_ever_answers_5xx` (`api/integration_tests.rs`); `a_body_over_the_limit_is_refused` (`server.rs`) | Covered |
| WEB-10 | I | A read caller reads secrets in a rendered config (Samba passwords, keys) (AS1 ← A2) | Module views redact secret pointers; read tokens never get rendered files | `redaction_reaches_every_string_under_a_secret_pointer_or_secret_key` (`api/modules.rs`); `a_read_token_never_sees_a_rendered_file` (`api/integration_tests.rs`) | Covered |
| WEB-11 | I | Error bodies leak internals (AS1 ← A1) | Code plus Fluent id only | `the_body_is_a_code_and_a_fluent_id_and_nothing_else` (`error.rs`) | Covered |
| WEB-12 | I | TLS key leaks through files or logs (AS3 ← A5) | `0600` in `0700`; redacted `Debug` | `the_store_is_written_0600_under_a_0700_directory`, `the_debug_output_never_carries_the_private_key` (`tls.rs`) | Covered |
| WEB-13 | D | Connection, slow-loris, Argon2 or table exhaustion (AS13 ← A1) | Connection cap, first-request deadline, request timeout, 2 Argon2 permits, capped session and token tables | `a_connection_over_the_cap_is_dropped_without_a_handshake`, `an_idle_connection_does_not_hold_a_permit` (`tests/tls.rs`); `logins_beyond_the_hashing_cap_are_refused_not_queued` (`auth/routes.rs`); `the_table_is_capped_and_expired_entries_make_room` (`auth/session.rs`); `the_store_is_capped` (`auth/token.rs`) | Covered |
| WEB-14 | R | Auth events cannot be traced (AS10 ← A1, A2) | Auth log: login ok/failed, lockout, logout, scope denial, renew request, rejected credential (coalesced per address, bounded table: `auth/coalesce.rs`) | `a_good_login_sets_the_host_cookie_and_answers_the_session_view`, `repeated_failures_lock_the_account_out_and_the_lockout_is_audited` (`auth/routes.rs`); `a_scope_denial_is_audited` (`engine.rs`); `a_bad_bearer_token_is_audited_once_per_client_per_window`, `an_expired_token_and_an_unknown_session_are_audited_with_their_kind`, `the_record_after_the_window_counts_what_was_held_back` (`auth/extract.rs`); `the_table_is_bounded_and_evicts_the_one_logged_longest_ago` (`auth/coalesce.rs`) | Covered (TM-G4, fixed 2026-10-10): a rejected bearer token or session cookie is logged as `credential_rejected`, subject `-`, at most once a minute per client address, with a `suppressed` count; a request with no credential is not logged |
| WEB-15 | I | Update check from the worker hammers GitHub (A2) | `GET /system/update` reads the on-disk stamp only | `system_update_without_a_stamp_says_the_check_has_not_run` (`api/integration_tests.rs`) | Covered |
| WEB-16 | E | Long sessions act without fresh proof of the admin (AS1 ← A4 with a live session) | 15 min idle, 8 h absolute | `the_absolute_timeout_ends_a_session_that_is_still_being_used` (`auth/session.rs`) | Gap TM-G9: no re-authentication before apply, restore or update; no list of active sessions |
| WEB-17 | S | Sessions do not survive a restart | — | — | Accepted (ADR-007) |

### 5.6 SPA (`web/`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| SPA-1 | T, E | Stored or reflected XSS from host data (module names, audit callers, config values) (AS8 ← A1 who wrote a config value, A4) | React escaping; no `dangerouslySetInnerHTML` (none in `web/src`; Biome `recommended` preset in CI job "Web"); CSP `script-src 'self' 'sha256-…'` | `the_csp_is_the_policy_from_the_plan`, `theme_script_sha256_matches_the_file_it_hashes` (`detent-web/src/headers.rs`); e2e "the audit log shows a mixed-case caller verbatim" (`web/e2e/console.e2e.ts`) | Covered |
| SPA-2 | I | Token or CSRF value leaks to storage or URLs (AS8 ← A4, A5) | CSRF token in memory only; `localStorage` holds theme and locale only | "keeps the token out of the url and out of storage" (`web/src/api/__tests__/client.test.ts`); "posts the credentials and never puts them in the url" (`web/src/routes/__tests__/LoginPage.test.tsx`) | Covered |
| SPA-3 | S | Open redirect after login (A4) | `safeRedirect` accepts a same-site path only; the value comes from in-app history state, not the URL | code path `web/src/routes/paths.ts` | Partial: no unit test; a `/\` prefix is not refused (low impact: history state only) |
| SPA-4 | T | Clickjacking (A4) | `frame-ancestors 'none'`, COOP | `every_header_is_present_with_its_exact_value` (`detent-web/src/headers.rs`) | Covered |
| SPA-5 | E | UI shows a write control to a read session | Server enforces scope; UI disables controls | "disables it for a read-only session and says why" (`web/src/auth/__tests__/ScopeGate.test.tsx`); e2e "a read-only session cannot apply, and is told why" (`web/e2e/console.e2e.ts`) | Covered (server is the enforcement point, WEB-6) |

### 5.7 MCP server (`detent mcp`, `detent-mcp`, `detent/src/mcp.rs`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| MCP-1 | S | Unauthenticated tool calls (AS1 ← A5) | Bearer token required at start; live in `tokens.json`; checked per call | `mcp_without_a_token_refuses_to_start` (`detent/tests/binary.rs`); `the_bearer_gate_admits_only_the_live_startup_token`, `a_revoked_token_is_refused_on_the_next_call` (`detent/src/mcp.rs`) | Covered |
| MCP-2 | S | A browser page or DNS rebinding reaches the HTTP transport (A4) | Loopback bind; `Origin` validation | `bind_table_keeps_bearer_on_loopback`, `http_config_enforces_origin_validation` (`detent/src/mcp.rs`) | Covered |
| MCP-3 | E | A read token mutates | The engine checks scope and audits the refusal | `a_read_scope_permits_reads_and_the_engine_denies_and_audits_mutations` (`detent/src/mcp.rs`); `an_engine_denial_is_a_policy_refusal_on_the_wire` (`detent-mcp/src/mcp.rs`) | Covered |
| MCP-4 | E | The HTTP parser runs in the process that holds the monitor (no privsep) (AS1 ← A5) | HTTP transport refused for root and for a caller with capabilities | `http_transport_refused_for_root`, `http_transport_refused_for_a_non_root_caller_holding_capabilities` (`detent/src/mcp.rs`); `mcp_http_refuses_root_and_gates_every_request_on_the_bearer` (`detent/tests/binary.rs`) | Partial: stdio and one-shot CLI are not privilege-separated by design (ARCHITECTURE §3.2); owner acceptance not recorded (TM-G10) |
| MCP-5 | I | Token in tool answers, errors or logs (AS7 ← A12) | `Zeroizing`, never rendered | `the_token_never_reaches_a_tool_answer_an_error_or_a_log_line` (`detent/src/serve.rs`); `mcp_cert_tools_answer_over_stdio_without_leaking_the_token` (`detent/tests/binary.rs`) | Covered |
| MCP-6 | T | Prompt injection in data the agent reads steers it to call write tools (AS1 ← A12) | Scope, validators, deny-list, commit-confirm | — | Gap TM-G11: no detent-side control beyond the token scope; the operator guidance to give agents a `read` token by default is not written |
| MCP-7 | D | A client hangs the stdio server | Startup ends when the client hangs up | `mcp_stdio_fails_when_the_client_hangs_up_before_initialize` (`detent/tests/binary.rs`) | Covered |

### 5.8 CLI (`detent/src/{run,webadmin,renew,doctor}.rs`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| CLI-1 | E | A local user changes config through the CLI (AS1 ← A5) | The CLI needs the privilege it uses (Unix permissions); the monitor thread uses the same allow-list and checks | `state_commands_are_refused_as_root_and_touch_nothing`, `a_one_shot_command_on_a_busy_state_root_is_refused` (`detent/src/run.rs`) | Covered |
| CLI-2 | T | Wide permissions on config or state let A5 plant files | `doctor` fails on wide modes and symlinks | `config_permissions_decide_the_status`, `a_world_writable_state_directory_is_a_failure`, `doctor_refuses_symlink_targets` (`detent/src/doctor.rs`) | Covered |
| CLI-3 | I | Password echo; secrets in argv or shell history (AS6, AS7 ← A5) | No-echo prompt; tokens from `0600` file or env, never argv | `the_echo_guard_hides_input_and_restores_the_terminal` (`detent/src/webadmin.rs`); `setup_prompts_twice_on_the_terminal_without_echo` (`detent/tests/binary.rs`); `unsafe_or_unusable_token_files_are_refused`, `the_request_carries_the_token_only_in_its_header` (`detent/src/renew.rs`) | Covered |
| CLI-4 | T | Terminal escape or bidi injection through host data in CLI output | Control and bidi characters stripped | `cli_arguments_lose_control_and_bidi_characters`, `rendered_text_never_carries_bidi_isolation_marks` (`detent/src/i18n.rs`) | Covered |
| CLI-5 | S | `detent cert renew` talks to a fake server | TLS 1.3 pinned to the served certificate or a `--ca-file`; https only | `cert_renew_trusts_only_the_served_certificate_or_the_ca_file` (`detent/src/serve.rs`); `cert_renew_parses_and_refuses_plain_http` (`detent/src/cli.rs`) | Covered |
| CLI-6 | R | User, password and token changes leave no audit record (AS6, AS7 ← A5 with `detent` rights) | `setup`, `user add/passwd/rm`, `user totp enable/disable` and `token create/revoke` append a `local_user` record (subject: the account, or `token:<id>`; never a secret) to the auth log; a log that cannot be written is a note on stderr | `user_changes_made_on_the_command_line_are_audited`, `setup_is_audited_as_a_creation_and_a_forced_rerun_as_a_password_change`, `turning_the_second_factor_on_is_audited_only_after_the_code_checks`, `turning_the_second_factor_off_is_audited`, `token_changes_are_audited_by_id_and_never_carry_the_token`, `a_log_that_cannot_be_written_is_a_note_not_a_failure` (`detent/src/webadmin.rs`) | Covered (TM-G3, fixed 2026-10-10); the auth log is worker-owned like the ops log, so A5 with `detent` rights can still rewrite it (AUD-2) |
| CLI-7 | T | `--dryrun` writes anyway | Dry run withholds every mutation | `a_dry_run_withholds_every_other_mutation_too` (`detent/src/run.rs`) | Covered |
| CLI-8 | S | A stored "must change password" flag is ignored | — | — | `a_flagged_account_gets_a_session_that_only_changes_the_password`, `a_session_that_must_change_its_password_reaches_no_api_route`; fixed 2026-10-09 (TM-G7) |

### 5.9 Updater (`detent update`, transient `detent-update` unit, `detent-update`)

The updater runs as root, outside the sandbox, and parses network data.
Full row: [SH-S] row "Sigstore verification".

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| UPD-1 | S | A binary not built by `release.yml` at the tag (AS9 ← A9, A11 without CI) | Pinned SAN and issuer; Fulcio chain, SCT, Rekor inclusion and checkpoint, SET or RFC 3161 time | `pinned_identity_is_the_release_workflow_at_the_tag` (`detent-update/src/verify.rs`); `wrong_identity_is_refused_at_step_3`, `a_forged_integrated_time_is_refused` (`detent-update/tests/verify_fixtures.rs`); `real_rekor_v2_bundle_verifies`, `real_rekor_v2_bundle_is_refused_for_another_tag` (`detent-update/tests/real_bundle.rs`) | Covered |
| UPD-2 | T | Swapped asset or digest (AS9 ← A9) | SHA256SUMS and the bundle subject digest must both match | `verify_bundle_fails_naming_a_digest_mismatch` (`detent/src/run.rs`); `a_wrong_subject_digest_is_refused` (`verify_fixtures.rs`) | Covered |
| UPD-3 | T | Downgrade or replay of an old signed release (AS9 ← A9) | Semver monotonic; `--allow-downgrade` only by hand; `bad.json` | `refuses_downgrade_by_default` (`detent-update/src/policy.rs`); `bare_update_refuses_a_downgrade_without_allow_downgrade` (`detent/src/run.rs`); `check_skips_a_bad_tag` (`detent-update/src/update.rs`) | Covered |
| UPD-4 | T, E | A just-published malicious release from a stolen maintainer token (AS9 ← A11) | `min_age_days` gate; `detent-security: true` bypasses it; release notes step refuses an accidental marker | `refuses_younger_release`, `security_marker_bypasses_age_gate`, `marker_embedded_in_sentence_does_not_bypass` (`policy.rs`) | Gap TM-G12: anyone who can push a `v*` tag gets a validly signed release; the marker in the release body skips the only delay |
| UPD-5 | D | A broken release bricks a headless device (AS13) | `--self-test` feature check, swap, `/healthz` with pinned TLS, rollback and `bad.json` | `refusal_order_verify_then_self_test_then_swap`, `an_unhealthy_restart_rolls_back_and_restores_the_previous_binary` (`detent/src/run.rs`); `the_wrong_certificate_is_not_trusted` (`detent-update/src/health.rs`) | Covered |
| UPD-6 | T | Symlink or path tricks at swap time (AS9 ← A5) | Refuse a symlinked or non-file target | `a_symlinked_target_is_refused`, `a_missing_or_non_file_target_is_refused_not_created` (`detent-update/src/install.rs`) | Covered |
| UPD-7 | T, D | Parser bugs in root code fed by the network (AS9 ← A9) | Size caps; https only; redirect caps; fuzzing of the bundle and TSA parsers | `refuses_oversized` (`detent-update/src/bundle.rs`); `refuses_redirect_to_http`, `caps_redirect_loop` (`detent-update/tests/real_transport.rs`); `list_releases_rejects_malformed_json` (`detent-update/src/fetch.rs`); fuzz targets `fuzz_bundle_parse`, `fuzz_tsa_verify` | Covered |
| UPD-8 | D | Update withheld (freeze attack) or Sigstore unreachable (AS9 ← A9) | Fails closed; a bundle no embedded root covers is "unavailable", not "invalid" | `update_check_offline_fails_closed` (`detent/src/run.rs`); `a_bundle_with_no_covering_root_is_unavailable_not_invalid` (`verify_fixtures.rs`) | Accepted (ADR-005: no unverified fallback; a frozen host stays on its version) |
| UPD-9 | E | Web or MCP install injects into the update start (AS9 ← A6, A3) | Tag only; monitor and runner both check it; fixed argv (RUN-2) | `start_update_refuses_a_bad_or_old_tag_before_the_hook`, `the_retired_update_requests_are_refused` (`monitor.rs`); `system_apply_refuses_a_bad_or_not_newer_tag_with_a_4xx` (`api/integration_tests.rs`) | Covered |

### 5.10 Config modules and validators (`crates/modules/*`, `detent-core`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| MOD-1 | T | A field value breaks out of its syntax and injects a directive (AS1 ← A3, A6) | Per-format quoting; injection probes rejected | `invariant_5_injection_probes_are_rejected` (conformance macro in `detent-core/src/conformance.rs`, instantiated in each `crates/modules/*/tests/conformance.rs`) | Covered |
| MOD-2 | T | Unmanaged content is lost or changed (AS1) | Lossless model; only changed lines differ | `invariant_1_render_parse_roundtrip`, `invariant_2_apply_of_own_model_is_a_noop` (same macro) | Covered |
| MOD-3 | D | Hostile file content hangs or crashes a parser (AS13 ← A5 who can edit a target) | Linear parsers; adversarial input test; fuzzing per module | `invariant_6_one_mib_of_adversarial_input` (same macro); `fuzz/fuzz_targets/fuzz_*_parse.rs` | Covered |
| MOD-4 | T | A config that the daemon cannot load is applied (AS13) | Upstream validators in `plan` and `apply`, again in the monitor; fail closed when a validator cannot run | `apply_refuses_when_an_external_check_fails`, `plan_runs_the_upstream_validator_through_the_monitor` (`detent-ops/tests/engine.rs`) | Covered (owner decision H5, 2026-10-06: fail closed) |
| MOD-5 | E | `plan` (read scope) runs root validators on caller bytes (AS2 ← A2) | Validators get a staged copy; nothing is written | `plan_diffs_the_candidate_and_writes_nothing` (`detent-ops/tests/engine.rs`) | Accepted (owner decision M5, 2026-10-06) |
| MOD-6 | E | Execution directives in content (MON-3) | Deny-list | see MON-3 | Accepted (ADR-001) |

### 5.11 Audit logs (`detent-ops/src/audit.rs`, `detent-web/src/auth/audit.rs`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| AUD-1 | R | A mutation happens with no record (AS10) | Intent record first; write failure refuses the mutation | `an_unwritable_audit_sink_refuses_the_mutation`, `apply_writes_the_candidate_and_audits_exactly_once` (`detent-ops/tests/engine.rs`) | Covered |
| AUD-2 | T | Records edited, deleted or reordered (AS10 ← A5 with `detent` rights, A6) | SHA-256 hash chain, sequence, torn-line notes | `a_deleted_middle_record_breaks_the_chain`, `verification_detects_tampering_and_truncation_against_an_anchor` (`detent-ops/src/audit.rs`) | Partial: the worker owns the file and can rewrite the whole chain; journald is the independent copy. TM-G6: `FileAudit::verify` and terminal anchors have no operator command |
| AUD-3 | I | Secrets or config bodies in the audit trail (AS1, AS6 ← A2 via `/api/v1/audit`) | Digests and error ids only | `the_audit_log_never_contains_the_configuration_body` (`detent-ops/tests/engine.rs`); `a_record_carries_hashes_and_an_error_id_but_no_payload` (`detent-ops/src/audit.rs`); `a_record_carries_the_event_and_nothing_secret` (`detent-web/src/auth/audit.rs`) | Covered |
| AUD-4 | D | Refused logins fill the disk (AS13 ← A1) | Rate-limited attempts not logged; 16 MiB rotation | `rate_limited_attempts_do_not_grow_the_audit_log` (`auth/routes.rs`); `a_log_at_16_mib_is_rotated_to_dot_1_before_the_next_append` (`auth/audit.rs`) | Covered |
| AUD-5 | I, T | Other local users read or plant audit files (AS10 ← A5) | `0700` dir, `0600` file, symlink and foreign owner refused | `a_symlinked_audit_directory_is_refused`, `the_audit_directory_is_private` (`detent-ops/src/audit.rs`) | Covered |
| AUD-6 | T | Log injection through names or values | JSON lines through `serde_json` | code path `FileAudit` / `FileAuthAudit::append` | Covered (no dedicated test) |

### 5.12 Packaging and systemd unit (`packaging/`)

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| PKG-1 | E | The service holds more than it needs (AS1–AS9 ← A6, A7) | `ProtectSystem=strict`, `NoNewPrivileges=yes`, computed `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies`, `UMask=0077` | `the_bounding_set_lets_the_monitor_drop_what_it_does_not_keep`, `the_unit_keeps_setuid_for_the_worker_drop`, `the_unit_does_not_take_the_state_root_from_the_worker` (`detent/tests/packaging.rs`) | Partial TM-G15: `systemd-analyze security` (PLAN target ≤ 2.5) is spike evidence only; no CI job re-measures it |
| PKG-2 | D | A missing optional path stops the unit (`226/NAMESPACE`) | `-` prefix on optional `ReadWritePaths` | `every_module_path_in_read_write_paths_is_optional` (`detent/tests/packaging.rs`) | Covered |
| PKG-3 | E | Capability-user mode: monitor and worker share uid `detent` (AS1 ← A6) | Landlock, seccomp, worker capability drop | — | Gap TM-G17 (Track F: polkit rule and doctor check not done; [SH-L] Gaps item 14) |
| PKG-4 | I, D | Unit omits `IPAddressDeny=` and `PrivateUsers=` | — | — | Accepted (PLAN §2.4: they break LAN access and root-owned writes) |

### 5.13 Release pipeline and supply chain (`.github/workflows/`, ADR-005, ADR-011)

Full rows: [SH-S]. Several [SH-S] rows ("Reproducible builds", "SBOM",
"Provenance") still say "not yet — Phase 9"; `release.yml` now has the jobs
named below.

| Id | S/T/R/I/D/E | Threat | Control | Proven by | Status |
|---|---|---|---|---|---|
| SUP-1 | T | Malicious new crate or npm version (AS9 ← A10) | 7-day cooldown; `cargo deny`, `cargo audit` | CI job "Supply chain (deny, audit, cooldown)" (`ci.yml`); `scripts/cooldown-check.sh` | Covered (CI evidence) |
| SUP-2 | T | Re-tagged GitHub Action (AS9 ← A10) | SHA pins with version comment | CI job "Action pins (SHA + version comment)" (`ci.yml`) | Partial: the job checks the format, not that the SHA exists upstream ([SH-S]) |
| SUP-3 | T, I | A build step exfiltrates or fetches code (AS12 ← A10) | `permissions: contents: read` by default; `step-security/harden-runner` with `egress-policy: block` on Linux jobs | `release.yml` "Harden Runner" steps | Partial: macOS legs run `egress-policy: audit` |
| SUP-4 | T | Release binary differs from source (AS9 ← A10, A11) | Two builds compared by SHA-256; weekly rebuild against published assets | `release.yml` job "Reproducibility gate (two builds, SHA-256)"; `rebuild-verify.yml` | Covered (CI evidence) |
| SUP-5 | R, I | Unknown contents after an incident | CycloneDX SBOM (cargo and web), attested | `release.yml` job "SBOM (cargo + web, merged CycloneDX)", step "Attest SBOM" | Covered (CI evidence) |
| SUP-6 | T | A release bundle the updater cannot verify ships | Pre-publish gate runs detent's own verifier on each bundle | `release.yml` step "Check updater bundles" (`verify-bundle --tag`); `verify_bundle_bytes_checks_the_tag_and_the_digest` (`detent/src/run.rs`) | Covered |
| SUP-7 | T | Assets changed after publication (AS9 ← A11) | Repository setting "immutable releases" | `docs/RELEASING.md` | Partial: a repository setting; nothing checks it is on |
| SUP-8 | E | Stolen maintainer token pushes a tag (AS12 ← A11) | Tag must equal the crate version; min-age gate on hosts | `release.yml` step "Tag must equal the crate version"; UPD-4 | Gap TM-G12 (see UPD-4) |
| SUP-9 | T | `unsafe` or memory bugs in dependencies and own code | `unsafe_code` forbidden outside two crates; Miri on `detent-ffi`; fuzzing | [SH-M] | Covered (CI evidence) |

---

## 6. Future change: the Jev / TypeSafe egress (BUGFIX §5)

BUGFIX §5 is a post-v1 experiment. Its gate requires this document to
cover the egress it adds before any product code. **It is not in the model
above.** If the owner says yes, update this document first. The change adds:

- **A new outbound data flow** (new boundary TB10: worker → third-party
  model endpoint) carrying `ApplyFeatures`: module id, service action, unit
  names, counts, check results, Fluent ids. Threat: information disclosure
  of host structure to the endpoint and to A9. Required test (from §5): a
  secret in `PlanReport.rendered` never reaches the request.
- **A new asset**: the API key file (`0600`), redacted in `Debug`, logs,
  audit and every endpoint. Needs the same file checks as `secrets.toml`
  (`detent-web/src/secrets.rs`) and the same log-capture test as ACM-2.
- **A conflict with WRK-2**: §5 says "calls run in the worker only", but
  the worker has no `connect` (ADR-015). Either the worker table gains
  `connect` and DNS calls (this reverses the ADR-015 control and widens
  TM-G2), or the call moves to a separate confined process like the acme
  process. Decide this before the design is accepted.
- **A new tampering path**: a hostile or spoofed answer. §5 limits it: the
  answer may only add friction, never skip a confirm, override a failing
  check or shorten a window; any error means "feature off". Each rule needs
  a test before it ships.
- **A new availability dependency**: timeout ≤ 1 s, fail safe.

## 7. Out-of-date statements found during this pass

Fixed 2026-10-09 in a docs-only pass, except the last item, which that pass did not cover.

- [SH-I] row "Only one pending commit at a time" and SH Gaps item 9 say no
  negative test exists; `a_second_commit_confirm_apply_while_one_is_pending_writes_nothing`
  (`detent-ops/tests/engine.rs`) is that test. **Fixed 2026-10-09.**
- [SH-S] rows "Reproducible builds", "SBOM", "Provenance / immutable
  releases" and SH Gaps item 11 say "not yet — Phase 9"; see SUP-4 to SUP-7.
  **Fixed 2026-10-09** (immutable releases are a repository setting, which the row now says).
- [SH-W] row "Output escaping" and SH Gaps item 13 say the UI is not built;
  see SPA-1. **Fixed 2026-10-09.**
- [SH-L] row "The ACME client …" says there is no renew rate limit; see
  ACM-5. **Fixed 2026-10-09:** the row now states the one-per-hour limit on forced renewals.
- [SH-L] row "seccomp allow-list" cites
  `every_table_entry_resolves_on_both_tier_one_architectures`, which does
  not exist in this tree. **Fixed 2026-10-09:** the row now cites `every_table_entry_resolves_or_is_arch_specific`.
- ARCHITECTURE §11 item 2 says the monitor table still lists
  `clone`/`execve`; they were removed (`the_monitor_table_has_no_process_creation_calls`). **Fixed 2026-10-09.**
- ADR-012 says `recover_pending` has no production caller; it is wired
  (`run_monitor_recovers_a_leftover_marker`, `detent/src/serve.rs`). **Fixed 2026-10-09** (update note added to the ADR).
- SH Gaps item 7 (Landlock degradation not tied to `doctor`) is partly
  closed: `doctor_reports_the_confinement_each_role_recorded`
  (`detent/src/doctor.rs`), `a_missing_landlock_is_reported_at_startup`
  (`detent/src/serve.rs`).

## 8. Gaps

Severity: **High** (remote attacker reaches an asset), **Medium** (a
control the plan promises is missing or can be bypassed after a first
compromise), **Low** (defence in depth, evidence, or audit quality).

| Id | Severity | Gap | Rows | In BUGFIX or SH before this pass? |
|---|---|---|---|---|
| TM-G1 | Medium | No TOTP enrolment path: `UserStore::set_totp` has no production caller, so MFA cannot be turned on, and `auth.totp_required = true` locks every account out | WEB-4 | No |
| TM-G2 | Medium | `WORKER` seccomp allows `socket` and `sendto` without argument filters: a taken worker can send UDP to any address without `connect`; the unit has no `IPAddressDeny=` (PKG-4) | WRK-2 | No |
| TM-G3 | Low | ~~CLI user, password and token changes are not audited; `TokenIssued`/`TokenRevoked` have no producer~~ Fixed 2026-10-10 | CLI-6 | No |
| TM-G4 | Low | ~~A bad bearer token or an expired session on the API is not logged~~ Fixed 2026-10-10 | WEB-14 | No |
| TM-G5 | Low | The monitor logs no line per `WriteTarget`, `Restore` or `Service`; a taken worker can omit the ops audit record | MON-9 | No |
| TM-G6 | Low | No operator command runs `FileAudit::verify` or exports a terminal anchor, so tail truncation cannot be detected in practice | AUD-2 | No |
| TM-G7 | Low | `must_change_password` is stored but never enforced | CLI-8 | No |
| TM-G8 | Medium | Password policy: only non-empty (no 12-character minimum), no breached-password check; login accepts up to 1024 bytes | WEB-2 | No |
| TM-G9 | Low | No re-authentication before apply, restore or update; no list or revoke of other sessions | WEB-16 | No |
| TM-G10 | Low | `detent mcp` (stdio) and one-shot CLI run without privilege separation; design in ARCHITECTURE §3.2, owner acceptance not recorded | MCP-4 | Documented, not accepted |
| TM-G11 | Low | MCP write tools: no detent-side control against prompt injection beyond scope; no "read token by default" guidance | MCP-6 | No |
| TM-G12 | Medium | A stolen tag-push credential yields a validly signed release; the `detent-security: true` marker skips the min-age gate | UPD-4, SUP-8 | No |
| TM-G13 | Medium | Landlock absent on Raspberry Pi OS kernels (`require_landlock` off by default) | MON-7 | SH Gaps 2 |
| TM-G14 | Low | `PR_SET_DUMPABLE=0` has no test | MON-7 | SH Gaps 6 |
| TM-G15 | Low | `systemd-analyze security` not re-measured in CI (PLAN Phase 12 acceptance) | PKG-1 | SH Gaps 8 |
| TM-G16 | Low | No `testssl.sh` run; `scripts/tls-check.sh` not in CI | WEB-1 | SH Gaps 12 |
| TM-G17 | Medium (capability-user mode only) | Monitor and worker share a uid; polkit rule and doctor check not done | PKG-3 | SH Gaps 14, BUGFIX Track F |
| TM-G18 | Low | Root `enforce_mode_*` tests for the E16 changes not yet run in CI or on the test host; aarch64 confinement not run on hardware | MON-7 | BUGFIX Track E, ARCHITECTURE §11 |

Smaller evidence gaps that stay in their rows: WRK-4 (runner descriptor
drop untested), WRK-5 (panic reachability), WEB-3 (timing test ignored),
SPA-3 (no `safeRedirect` test), SUP-2, SUP-3, SUP-7.

[SH-T]: SECURITY_HARDENING.md#transport-tls-13--short-lived-certs
[SH-W]: SECURITY_HARDENING.md#web-argon2id--rate-limits--sessionscsrfcsp
[SH-L]: SECURITY_HARDENING.md#local-privilege-privsep--landlock--seccomp--caps--allow-lists
[SH-I]: SECURITY_HARDENING.md#integrityavailability-lossless-model--injection-safe-rendering--external-validators--backups--commit-confirm
[SH-S]: SECURITY_HARDENING.md#supply-chain-reproducible-builds--sbom--provenance--immutable-releases--sigstore-verification--cooldowns
[SH-M]: SECURITY_HARDENING.md#memory-safetycorrectness-denyunsafe_code-outside-two-crates-fuzzing-100-coverage-gate
