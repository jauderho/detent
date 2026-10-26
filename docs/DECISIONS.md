# Owner decisions

This file is the record of owner decisions and accepted risks. Other documents
cite it by item (for example `E16`, `D9`). Newest decisions carry their date in
the entry. Item ids and Track names come from the retired work queue. The fix of each
item is in [`PROGRESS.md`](PROGRESS.md), under the item id.

## Decisions

Format: `- <ITEM>: <question> — proposed: <default> — owner answer:`

- H5: apply refuses when a declared validator cannot run (binary missing), not
  only when it fails. — proposed: keep fail-closed — owner answer: keep
  fail-closed (2026-10-06).
- M5: `plan` runs root validators but needs only read scope. — proposed: keep
  read scope (plan writes nothing; validators get a staged copy) — owner
  answer: keep read scope (2026-10-06).
- C1-b: chunked `StageUpdate`, so the worker never writes update bytes to a
  path the monitor reads. The interim (`4b098d0`, `95f6b01`) copies into
  monitor staging with no-follow opens and owner checks. — proposed: confirm
  the interim, defer chunking — owner answer (2026-10-06): do chunked
  `StageUpdate` now. Done 2026-10-07 (`PROGRESS.md`): `StageBegin` and
  `StageUpdate` over the socket into the monitor's own stage; the interim
  code is removed. Unproven until a Linux run: the two `enforce_mode_*`
  update tests.
- E16: how does the web/MCP install get the release? (a) the runner starts
  one fixed transient unit, `systemd-run --unit=detent-update detent update
  --tag <tag>`, so the CLI flow does the self-test, swap, restart, `/healthz`
  and rollback; (b) add `connect` and DNS calls to `WORKER` (reverses an
  ADR-015 control; restart and rollback still missing); (c) MCP only, the
  Dashboard shows the `detent update` command. — proposed: (a) — owner
  answer (2026-10-07): (a), the runner starts the transient unit. Done
  2026-10-07 (`PROGRESS.md`). The monitor's Landlock rule for the binary
  directory and the `MONITOR` row `linkat` served only the removed swap;
  narrow them? — owner answer (2026-10-08): remove both. Done 2026-10-09
  (`PROGRESS.md`). Unproven until CI or testhost: the root `enforce_mode_*` tests.
  No packaged schedule runs `detent update --check`, so the console shows no
  update until it runs; ship a timer? — owner answer (2026-10-09): document
  only (README "Updates").
- Track F mTLS: optional client-certificate auth for v1? — owner answer
  (2026-10-09): no; defer past v1.
- TM-G2: the `WORKER` seccomp table allows `socket` and `sendto` with no
  argument filter, so a taken worker can send UDP without `connect`. Add an
  argument filter (for example `socket` only for `AF_UNIX`)? — proposed: yes,
  after a trace on the test host shows what the worker needs — owner answer:
  yes (2026-10-10, below). Done 2026-10-10 (`PROGRESS.md`).
- Track F passkeys: ADR-016 recommends deferring past v1 (a WebAuthn RP ID
  needs a DNS name; the default install is reached by IP). — owner answer:
- Track F `capability-user` mode for v1 (monitor as `detent` with ambient
  capabilities, polkit for service control, unit drop-in and polkit rule
  changes, doctor checks)? — owner answer (2026-10-09): implement for v1;
  root-confined stays the default. Done in code 2026-10-09; test-host run open.
- Capability-user web/MCP update: polkit sees only the name and verb of a
  transient unit, so a grant for `detent-update.service` lets the `detent`
  uid run any command as root. — proposed: ship a root-owned template unit
  `detent-update@.service` (`ExecStart=/usr/local/bin/detent update --tag
  %i`) and grant only `start` of `detent-update@*.service` in
  capability-user mode; until then the install is refused in that mode —
  owner answer: see 2026-10-10 below (done).
- Owner answers (2026-10-10):
  - E16 in capability-user mode: ship a root-owned template unit
    `detent-update@.service` (runs only `detent update --tag %i`) and grant
    only `start` of `detent-update@*.service`; root-confined uses the same
    template. Done 2026-10-10 (`PROGRESS.md`); test-host run partly done (install open: no newer release).
  - Hardening score: accept 2.6 for the unchanged root-confined unit on
    systemd 261 (the newer `systemd-analyze` scores it higher); capability-user
    keeps 1.8.
  - TM-G2: trace the worker on the test host, then add a seccomp argument
    filter (`socket` limited to what the worker needs, e.g. `AF_UNIX`).
    Done 2026-10-10: the trace showed no `AF_UNIX` `socket` call, only the
    TCP listener; `socket` takes a TCP stream only, `sendto` a NULL address
    only (`PROGRESS.md`).
  - Passkeys: deferred past v1 (ADR-016).
- Owner answers (2026-10-14):
  - ASVS 1.7.2 / 7.3.3 remote audit sink: journal forwarding only, no
    built-in sink. Each audit record also goes to the journal as the
    `detent audit` event (`emit` in `detent-ops/src/engine.rs`; the web
    sign-in log in `detent-web/src/auth/audit.rs`), at `RUST_LOG=info`, which
    the packaged unit sets. Done 2026-10-14: README forwarding how-to; the
    checklist rows are Accepted risk (deployment control); gap 16 and
    TM-G6/AUD-2 updated.
  - TOTP keys at rest in `users.json` (`0600`, owned by the service
    account): accepted for v1 as a residual, with the same protection as the
    password hash file. Done 2026-10-14: PENTEST 2.8.2 and THREAT_MODEL §8.
  - Credential-change notice (ASVS 2.2.3, 2.5.5): a console banner. Done
    2026-10-14 (`PROGRESS.md`). Owner confirmed (2026-10-14): token issue and
    revoke events are shown to every account (tokens are host-wide).
  - Worker RSS against the PLAN §4.1 30 MiB figure (three-process idle RSS
    57.5 MiB): investigate and trim. Done 2026-10-14 (`PROGRESS.md`): 22.8 MiB idle total.
- D4: remove build toolchains from testhost. — proposed: after Track C A1–A3 —
  owner answer:
- libbz2 on testhost: `libbz2-1.0` was downgraded to `1.0.8-6build2` by an earlier
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
- A2-b: `sudo detent setup` wrote root-owned state the worker could not
  read. — owner answer (2026-10-01): refuse as root. Done: `setup`, `user`
  and `token` exit 3 as root and name `sudo -u detent detent <command>`.
- Track G: defer `hickory-client`, the TPM attestor and the LE staging run past
  v1, so Phase 6 can close? — proposed: defer the TPM attestor; keep the other
  two for v1 — owner answer: defer past v1 (2026-10-14); see ADR-017.
- D1 optional mount: after an fstab apply, the monitor mounts new entries.
  Needs `CAP_SYS_ADMIN` and the mount syscalls in the monitor. — owner
  answer (2026-10-06): yes, behind a config flag (PLAN §2.4: the capability
  only when mount apply is enabled). Superseded by the route below.
- D1 mount route (2026-10-06, after the design report): use systemd, not
  `CAP_SYS_ADMIN` — the monitor's Landlock forbids `mount(2)` and the unit's
  private mount namespace would hide the mount. `[mounts]
  activate_new_entries = false` by default; when on, after apply and
  daemon-reload the runner starts the `.mount`/`.automount` units of new or
  changed entries (names computed from the allow-listed file, never sent over
  the socket); non-systemd hosts: Unsupported with a note. A failed or pending
  mount is reported and the commit stays pending. Rollback stops only the
  units this apply started, then restores and reloads; nothing else is ever
  unmounted. No remount on option-only changes. Never mount over `/` or an
  ancestor of `/etc`, `/usr`, `/boot`, the state root or the binary
  directory. Phase 12 capability-user polkit rule: allow start/stop of
  `.mount`/`.automount` units. (done in code, `666572d`…`792c4dc`; the
  Phase 12 polkit rule done 2026-10-09; testhost runs passed 2026-10-07 and
  2026-10-10, `PROGRESS.md`)

- Security-review answers (owner, 2026-10-14). Accepted for v1: ASVS 2.1.7 and
  2.1.8 (no common-password list: offline device, 12 to 128 character policy,
  size budget); 2.4.5 (no pepper); 6.4.1 (secrets in `0600` files); 4.3.1
  (MFA optional; `auth.totp_required = true` is the hardening step); TM-G12
  (the security marker skips min-age); TM-G13 (no Landlock on Raspberry Pi
  OS); TM-G17 (shared uid in capability-user mode); 9.1.2 (no `testssl.sh`;
  `scripts/tls-check.sh` and the rustls tests); PLAN Phase 6 `detent-acme`
  coverage of 93 to 94 percent. Open, being implemented for v1: ~~3.3.4 (session
  list and revoke)~~ done 2026-10-14; ~~3.7.1 and 4.3.3 (step-up re-authentication before apply,
  restore and update)~~ done 2026-10-14; ~~8.1.4 and 11.1.4 (per-token rate limit with an
  auth-log event)~~ Done 2026-10-14 (`PROGRESS.md`); ~~1.2.4 (token creation needs a TOTP-satisfied session when
  `totp_required` is set)~~ done 2026-10-14.
- Releases (owner, 2026-10-14): skip cutting a release for now; Phase 9 stays
  `[~]`.
- Final step before v1.0.0 (owner, 2026-10-14): run the `security-review`
  skill over the full diff (PLAN Phase 12).
- D9 (owner, 2026-10-15): allow the include lines of the stock distribution
  files only, exact key and value per directive, kept byte for byte and not
  followed, with a warning that the included files are not managed; every
  other include stays an error; `validate` exits non-zero on an error. Done
  2026-10-15 (`PROGRESS.md`).
