# detent — Implementation Plan

> **Status:** DRAFT — awaiting approval. Nothing in this plan is implemented.
> **Audience:** the orchestrator (Fable Medium, or Opus 5 High as fallback) and the
> implementor agents it delegates to. This document is written so that a fresh
> session with no conversation context can pick up any phase and finish it.
> **Authority:** `AGENTS.md` (behavioral rules) and `AESTHETIC_CONTRACT.md` (UI
> rules) remain binding. Where this plan and those files disagree, those files win
> and the disagreement must be raised, not silently resolved. Deviations that are
> *already* reconciled are listed in §1.4.

---

## 0. How to use this document

1. Read §1 (goals, decisions, open questions) and §2 (architecture) in full before
   touching any phase.
2. Phases in §5 are sequential unless marked parallelizable. Each phase has
   **Deliverables**, **Tasks with verification**, **Acceptance criteria**, and
   **Delegation guidance**. A phase is done only when every acceptance criterion
   has been *demonstrated* (command run, output observed), not when code exists.
3. The orchestrator delegates each task as a self-contained prompt (exact paths,
   behavior, constraints, acceptance checks) and reviews the diff, not the report.
4. Every architectural decision has an ADR in `docs/adr/`. Phase 0 writes the
   initial set (§1.3). Changing a decision requires a superseding ADR.
5. Keep this file current: when a phase completes, flip its status line and record
   deviations in §9 (Change log).

Model contract reminder (from `AGENTS.md`): orchestrator plans/reviews; implementor
ceiling is **Fable Low**; mechanical work goes to Sonnet/Haiku. Per-phase guidance is
in each phase's *Delegation* block.

---

## 1. Goals, decisions, and open questions

### 1.1 Product goal

`detent` is a single static Rust binary (default port **3333**) that manages and
configures common system service config files on Linux (tier 1; x86_64 and aarch64 only) and macOS (tier 1 for build, test, core, CLI, and web; modules where the file format exists). BSD, armv7, and riscv64 are deferred to a later pass (see §1.6)
— the "busybox of config files" for SBC/IoT/GPS-server deployments. It ships:

- A **core library** (`detent-core`, C‑ABI exposed as `libdetent`) that parses,
  edits, validates, and renders config files losslessly, one module per service.
- A **privilege-separated daemon** that applies changes with least privilege
  (Linux capabilities, Landlock, seccomp; Capsicum on FreeBSD), never setuid.
- A **web admin UI** (shadcn/ui, styled per `AESTHETIC_CONTRACT.md`, dark default,
  i18n from day one) served over **TLS 1.3 only**, with certs provisioned by ACME
  (`dns-01` and `device-attest-01`) using **short-lived** certificates.
- A **CLI** with the same capabilities as the UI (headless use, scripting, tests).
- A **self-update** mechanism that verifies GitHub-published, attested,
  reproducible release artifacts before swapping the binary.
- Feature flags so a build can contain only the modules a device needs.

Initial modules: hosts, DNS resolver, chrony, mount points (fstab), NFS exports,
Samba, DHCP (dnsmasq, Kea), network interfaces (systemd-networkd, NetworkManager
keyfiles, ifupdown, netplan; FreeBSD `rc.conf` in tier 2).

### 1.2 Non-goals (v1)

- Not a general-purpose remote shell or file editor. Only allow-listed paths.
- No plaintext HTTP listener, ever. No TLS < 1.3. No `http-01` ACME (needs port 80).
- No multi-tenant RBAC in v1 (single admin role + scoped API tokens). Structure
  allows adding roles later.
- No ISC `dhcpd` (EOL since 2022); Kea and dnsmasq instead.
- No mobile app; but the operations layer is designed so an API/MCP client can
  drive everything (§2.6).

### 1.3 Decisions already taken (ADRs to be written in Phase 0)

| ADR | Decision | Why |
|---|---|---|
| ADR‑001 | **Privilege separation, OpenSSH style:** one binary, a small privileged *monitor* and an unprivileged *worker* joined by a `socketpair`, fixed message protocol, path/unit allow-lists (§2.4). No setuid. | Confines the network-facing code; portable to BSD (no systemd dependency). |
| ADR‑002 | **Crypto provider:** rustls with `aws-lc-rs` (rustls default, hybrid PQ key exchange `X25519MLKEM768`). Fallback to `ring` behind feature `crypto-ring` only if the Phase 0 cross-build spike fails. | Security over compatibility; PQ-hybrid KEX is available today. |
| ADR‑003 | **i18n format:** Project Fluent (`.ftl`) everywhere: `fluent-bundle` + `i18n-embed` in Rust, `@fluent/react` in the web app. One `locales/<lang>/` tree. | One format for contributors; proper plurals/gender; Weblate-compatible. |
| ADR‑004 | **One crate per module** under `crates/modules/`, feature-gated in the binary. | Isolation, independent fuzz targets, parallel compile, obvious template for new modules. |
| ADR‑005 | **Update verification:** Sigstore bundle verification (GitHub artifact attestations) with pinned identity, plus SHA‑256 sums, semver monotonicity, atomic swap, health-checked rollback. | Keyless signing means no long-lived signing secret to leak. |
| ADR‑006 | **Aesthetic reconciliation:** shadcn/ui primitives, themed with the catfu tokens; `--radius: 0`; fonts self-hosted; §7/§8 of the contract (landing-page hero/instrument modules) do not apply to the admin UI. | The user asked for shadcn; the contract fixes look and feel. Both satisfied (§1.4). |
| ADR‑007 | **Sessions & CSRF:** server-side in-memory sessions, `__Host-` cookie, `SameSite=Strict`, Fetch‑Metadata + Origin checks, per-session CSRF token header for unsafe methods. | Defense in depth; no cookie-only reliance. |
| ADR‑008 | **Lossless document model:** each module parses into a concrete-syntax tree preserving comments, whitespace, order, and unknown directives; edits are minimal; `render(parse(s)) == s` is a hard invariant. | Users' hand edits and comments survive; diff previews are honest. |
| ADR‑009 | **Runtime:** tokio current-thread runtime; axum 0.8; no `reqwest` (single hyper‑rustls client shared by ACME and update). | Memory footprint and dependency surface. |
| ADR‑010 | **Panic policy:** `panic = "abort"`, and `clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing` denied in non-test code. FFI never unwinds. | Size, security, ABI safety. |
| ADR‑011 | **Supply-chain cooldown of 7 days** for Cargo, Bun, GitHub Actions, and the Rust toolchain (§6.4). Security advisories bypass cooldown. | Requested; catches nearly all historical registry compromises. |
| ADR‑012 | **Commit‑confirm** for network/resolver/mount changes: auto-rollback unless the admin confirms within a timeout (§2.5). | Headless SBCs must not be bricked by a bad interface config. |

### 1.4 Reconciled deviations from `AESTHETIC_CONTRACT.md`

The contract was written for a static landing page (`index.html`). For a shadcn +
Vite admin app the following are applied deliberately (record in ADR‑006):

- **Fonts self-hosted** (`web/public/fonts`, OFL licenses vendored) instead of a
  Google Fonts `<link>`. Devices are often offline and CSP is `font-src 'self'`.
- **Pre-paint theme script** is an inline `<script>` allow-listed by CSP hash
  (`script-src 'self' 'sha256-…'`), generated at build time. Behavior identical.
- **Tokens live in `web/src/styles/tokens.css`** (mapped onto shadcn's CSS
  variables) rather than `index.html`. `--radius: 0`.
- **§7 hero device and §8 instrument modules are not built.** The admin UI keeps
  the instrument-panel language via status LEDs (§6 LED), silk-screen labels,
  hairline-zoned grids, readouts with `tabular-nums`, and the rocker toggle.
- `AGENTS.md` mentions a "HeroInsight results pattern" and "Tufte chart
  conventions" that the contract does not define. Treat as not applicable; if
  charts are added later, follow the `dataviz` skill and the contract's tokens.

### 1.6 Platform and architecture tiers (directed by the owner, 2026‑09‑03; ADR‑013)

| Tier | Platforms | Meaning |
|---|---|---|
| 1 | Linux x86_64-musl, Linux aarch64-musl | Full feature set, release artifacts, privileged CI, budgets enforced. |
| 1 (host/dev) | macOS aarch64, macOS x86_64 | Everything builds and tests here; `detent-core`, CLI, `libdetent`, web run natively. Modules whose file exists on macOS (`/etc/hosts`, `/etc/resolv.conf` read-only view, `/etc/fstab`, `/etc/exports`) work; service control and Linux sandboxing are `cfg(target_os = "linux")` with a documented no-op/`doctor` warning on macOS. Release artifacts built on GitHub macOS runners (no code signing/notarization in v1). |
| 3 (deferred) | FreeBSD/OpenBSD/NetBSD, armv7, riscv64 | Keep the code portable (no design decisions that preclude them), but no CI, no artifacts, no phase work until a later pass. Phase 11 is parked. |

### 1.5 Open questions (answer before Phase 0 closes; defaults apply otherwise)

| # | Question | Default if unanswered |
|---|---|---|
| Q1 | "Secured by short-lived certs" — server certs only, or also **mTLS client certs** for admin access? | Server certs (LE `shortlived` 6‑day profile or private CA). mTLS is an optional hardening in Phase 12. |
| Q2 | Private CA support: is **step-ca** the intended `device-attest-01` server (Let's Encrypt does not offer that challenge)? | Yes; CI tests device-attest-01 against step-ca and dns-01 against Pebble. |
| Q3 | GitHub repo for update pinning is `jauderho/detent`? | Yes (from `git remote`). |
| Q4 | Password auth + optional **TOTP**, with passkeys later? | Yes. Passkeys deferred (Phase 12 candidate). |
| Q5 | DNS providers for `dns-01` in v1: RFC 2136 (TSIG), Cloudflare, acme-dns, deSEC, "external hook script"? | Those five. Others by PR via the provider trait. |
| Q6 | Module priority if time-boxed: hosts → resolver → chrony → mounts → NFS → Samba → network → DHCP? | Yes, in that order. |
| Q7 | Self-update **minimum age**: apply the 7‑day cooldown to detent's own releases too? | Configurable `update.min_age_days`, default **2**; security releases (flagged in release notes metadata) bypass. |
| Q8 | License stays BSD‑3‑Clause (current `LICENSE`)? | Yes. |
| Q9 | Supported init systems in v1: systemd, OpenRC, FreeBSD rc? (runit/s6 later) | Yes. |

---

## 2. Architecture

### 2.1 Repository layout

```
detent/
├── Cargo.toml                 # workspace, resolver = "3", edition = "2024"
├── rust-toolchain.toml        # pinned stable (e.g. "1.98.0"), profile = minimal + clippy, rustfmt, llvm-tools
├── .cargo/config.toml         # lints, target cfgs, [registry] global-min-publish-age (when stable)
├── deny.toml                  # cargo-deny: advisories, licenses, bans, sources = crates.io only
├── bunfig.toml                # [install] minimumReleaseAge = 604800, exact = true
├── crates/
│   ├── detent-core/           # pure: doc model, schema types, diagnostics, planning. #![forbid(unsafe_code)], no I/O, no async
│   ├── detent-modules/        # facade: registry of enabled modules (cfg(feature) per module)
│   ├── modules/
│   │   ├── hosts/             # reference module (Phase 1)
│   │   ├── resolver/          # /etc/resolv.conf, systemd-resolved, unbound
│   │   ├── chrony/
│   │   ├── mounts/            # /etc/fstab
│   │   ├── nfs/               # /etc/exports
│   │   ├── samba/             # smb.conf
│   │   ├── dhcp/              # dnsmasq, kea
│   │   └── network/           # networkd, NM keyfile, ifupdown, netplan, (bsd rc.conf)
│   ├── detent-platform/       # OS layer: atomic file ops, backups, privsep monitor/worker, sandboxing, service managers, host detection, shared HTTP client
│   ├── detent-ops/            # operation layer: typed Operations, authz hooks, audit log, commit-confirm state machine
│   ├── detent-acme/           # ACME: dns-01 providers, device-attest-01 attestors, renewal scheduler, cert store
│   ├── detent-update/         # self-update client + verifier
│   ├── detent-web/            # axum server: TLS, auth, sessions, CSRF, API v1, embedded SPA
│   ├── detent-i18n/           # Fluent loader (embedded locales), message ids
│   ├── detent-ffi/            # libdetent: cdylib + staticlib, cbindgen → include/detent.h
│   ├── detent-mcp/            # (Phase 10, optional) rmcp server over ops
│   └── detent/                # the binary: clap CLI, wiring, feature gates
├── web/                       # Vite + React 19 + TS strict + Tailwind v4 + shadcn/ui; bun; biome
├── locales/                   # Fluent: locales/en-US/{core,cli,web}.ftl, locales/<lang>/…
├── fixtures/                  # upstream sample configs: fixtures/<module>/<upstream-version>/*
├── fuzz/                      # cargo-fuzz targets + seed corpora
├── packaging/                 # systemd unit, sysusers.d, tmpfiles.d, polkit rules, FreeBSD rc.d, OpenRC init, install.sh
├── include/                   # generated detent.h (checked in, CI verifies it is up to date)
├── examples/ffi-c/            # minimal C consumer of libdetent, built in CI
├── docs/                      # PLAN.md, adr/, THREAT_MODEL.md, MODULE_GUIDE.md, TRANSLATING.md, SECURITY_HARDENING.md, API.md
├── scripts/                   # existing GH-actions helpers + new: coverage-merge.sh, size-check.sh, contrast-check.ts
└── .github/workflows/         # ci, fuzz, release, rebuild-verify, upstream-watch, scorecard, semgrep, codespell, linter, dependency-review
```

Crate dependency direction (no cycles):
`detent-core ← modules/* ← detent-modules ← detent-ops ← {detent-web, detent-mcp, detent (cli)}`;
`detent-platform` is used by `detent-ops`, `detent-acme`, `detent-update`;
`detent-ffi` depends on `detent-core` + `detent-modules` only (no I/O, no tokio).

### 2.2 Cargo features (binary crate `detent`)

| Feature | Default | Pulls in |
|---|---|---|
| `module-hosts`, `module-resolver`, `module-chrony`, `module-mounts`, `module-nfs`, `module-samba`, `module-dhcp`, `module-network` | on | the module crate |
| `web` | on | detent-web, embedded SPA |
| `acme-dns01` | on | detent-acme + DNS providers (`dns-rfc2136`, `dns-cloudflare`, `dns-acmedns`, `dns-desec`, `dns-hook` sub-features, all on) |
| `acme-attest` | **off** | device-attest-01 + `attest-tpm` (tss-esapi, needs libtss2 at build/run) |
| `update` | on | detent-update (sigstore verification) |
| `mcp` | off | detent-mcp |
| `init-systemd`, `init-openrc`, `init-bsdrc` | systemd on Linux; bsdrc on FreeBSD | service manager backends |
| `crypto-aws-lc`, `crypto-ring` | aws-lc | rustls provider; at least one required (compile error otherwise); if both are on, aws-lc takes precedence so `--all-features` builds |

`cargo build --no-default-features --features "module-resolver,web,init-systemd"`
must compile and run; CI builds a matrix of minimal/typical/full feature sets.
Module enablement is explicit code in `detent-modules` registry under `cfg(feature)`;
no link-time registration magic.

### 2.3 Module SDK (the extension point)

Every module is a crate exposing one type implementing `ConfigModule`
(in `detent-core`). Shape (final signatures decided in Phase 1):

```rust
pub trait ConfigModule: Send + Sync + 'static {
    /// Stable id, e.g. "chrony". Used in URLs, CLI, audit log, feature names.
    const ID: &'static str;
    /// Lossless concrete syntax tree (comments, whitespace, order, unknown directives preserved).
    type Doc: LosslessDoc;
    /// Typed model exposed to UI/API/FFI. serde + schemars (JSON Schema with `x-detent` UI hints).
    type Model: Serialize + DeserializeOwned + JsonSchema + PartialEq + Clone;

    fn descriptor() -> &'static ModuleDescriptor;         // targets (files), upstream tracking, service bindings, external checks, capability needs
    fn parse(src: &str) -> Result<Self::Doc, ParseError>;  // never panics; total on any &str
    fn render(doc: &Self::Doc) -> String;                  // render(parse(s)) == s
    fn to_model(doc: &Self::Doc) -> Result<Self::Model, ModelError>;
    fn apply(doc: &mut Self::Doc, model: &Self::Model) -> Result<EditReport, EditError>; // minimal edit; apply(to_model(doc)) is a no-op
    fn validate(model: &Self::Model, ctx: &ValidationCtx) -> Diagnostics;               // errors, warnings, recommendations (ids → Fluent)
    fn defaults(profile: &HostProfile) -> Self::Model;      // smart, secure defaults for this host
}
```

Supporting types:

- `ModuleDescriptor { id, display_name_id, targets: &[Target], upstream: Upstream, services: &[ServiceBinding], checks: &[ExternalCheck], commit_confirm: bool, security_notes: &[MessageId] }`
- `Target { path: PathSpec, kind: File | DropInDir | Directory, mode: 0o644, owner: Root, backend_detect: fn(&HostProfile) -> bool }` — paths are static templates; **never** user-supplied.
- `Upstream { project, repo_url, tracked_version, release_feed, docs: &[UrlSpec] }`.
- `ExternalCheck { program: AbsolutePath, args: &[ArgTemplate], expects: ExitZero | Regex }` e.g. `chronyd -p -f <tmp>`, `testparm -s <tmp>`, `exportfs -s`-style dry validation, `named-checkconf`, `unbound-checkconf`, `dnsmasq --test -C <tmp>`, `kea-dhcp4 -t <tmp>`, `findmnt --verify --tab-file <tmp>`, `networkctl`/`netplan generate --root-dir <tmp>`.
- `ServiceBinding { unit: { systemd: "chronyd.service" | "chrony.service" (alternatives), openrc: "chronyd", bsdrc: "chronyd" }, actions: Restart | Reload | Start | Stop }`.
- JSON Schema `x-detent` hints per field: `group: basic|advanced`, `tooltip: <fluent-id>`, `recommendation: <fluent-id>`, `security_impact: none|low|high`, `since: "4.5"`, `deprecated_in`, `requires_restart: bool`.

Object-safe wrapper `dyn DynModule` (JSON in/out) is what `detent-ops`, `detent-web`,
`detent-ffi` consume; generics stay inside the module crate.

Invariants, enforced by tests generated from a shared macro (`detent_core::module_conformance!(HostsModule)`):
1. `render(parse(s)) == s` for every `s` (proptest + fuzz).
2. `apply(doc, to_model(doc))` changes nothing.
3. For any valid model `m`: `to_model(apply(parse(s), m)) == m` (edit fidelity).
4. Rendered output re-parses to the same Doc (idempotence).
5. Values containing `\n`, `\r`, `\0`, or format-specific delimiters are rejected or quoted per format; never emitted raw (directive injection).
6. `parse` completes in bounded time on 1 MiB adversarial input (fuzz timeout).

Upstream tracking:
- `crates/modules/<id>/upstream.toml` records `tracked_version`, feeds, doc URLs.
- `fixtures/<id>/<version>/` holds upstream sample configs and man-page-derived option lists; conformance tests parse every fixture losslessly.
- `.github/workflows/upstream-watch.yml` (weekly) compares latest upstream release to `tracked_version` and opens an issue with a checklist: diff docs, add/deprecate options in the schema, add fixtures, bump `tracked_version`, add `since`.
- At runtime `HostProfile` records the installed version of each service (`chronyd --version`, `smbd -V`, …); the UI hides or warns on options newer than installed.

Adding a module = copy `crates/modules/_template/` (created in Phase 1), fill in
descriptor/parser/model, add fixtures, add the feature flag in `detent` and the
registry entry in `detent-modules`, add Fluent strings, add fuzz targets via the
template's `fuzz/` stub. `docs/MODULE_GUIDE.md` is the authoritative walkthrough.

### 2.4 Privilege separation and sandboxing (ADR‑001)

```
init (systemd / rc) ──starts──▶ detent serve  (monitor, privileged, tiny)
                                   │ fork + socketpair(AF_UNIX, SOCK_SEQPACKET)
                                   ▼
                                worker (uid detent, no caps, network-facing: TLS, HTTP, ACME, update, UI)
```

**Monitor** (in `detent-platform::privsep::monitor`):
- No tokio, no TLS, no HTTP. Blocking loop over the socketpair. ≤ 1 MiB message cap, `postcard`-encoded, versioned `Request`/`Response` enums with `deny_unknown_fields` semantics (unknown discriminant → close connection, log, exit non-zero → systemd restarts everything).
- Request set (closed): `ReadTarget{target_id}`, `WriteTarget{target_id, bytes, expected_prev_hash}`, `RunCheck{check_id, bytes}`, `Service{binding_id, action}`, `ListBackups{module}`, `Restore{module, backup_id}`, `Mount{target_id}` (mounts feature), `ReplaceBinary{path_hint}` (update feature), `Shutdown`. All ids index allow-lists computed at startup from enabled modules and the detent config. **No path, unit name, or program name ever crosses the socket.**
- At startup, before accepting requests, on Linux: drop capability bounding set to the computed minimum (typically `CAP_DAC_OVERRIDE, CAP_CHOWN, CAP_FOWNER`; `+CAP_SYS_ADMIN` only with `module-mounts` and only when mount apply is enabled), `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`, install a **Landlock** ruleset restricting writes to target directories + backup dir + (update) the binary's directory (require ABI 1 / kernel 5.13, probe higher ABIs with `CompatLevel::BestEffort`; if Landlock is absent: warn once, mark degraded in `doctor`/UI, continue with no_new_privs + caps + seccomp, hard-fail only under `privilege.require_landlock = true`), and a **seccomp** allow-list (`seccompiler`; per-architecture tables for aarch64, x86_64, armv7, riscv64, derived under `SCMP_ACT_LOG` before enforcing). On FreeBSD: `cap_enter()` after pre-opening directory fds (Capsicum via `capsicum` crate) where feasible; otherwise document the reduced sandbox honestly.
- Privilege mode is configurable in `/etc/detent/detent.toml`:
  - `privilege.mode = "root-confined"` (default): monitor keeps uid 0 but confined as above. Service control via systemd D‑Bus (`zbus`, system bus) or absolute-path `rc-service`/`service` execution (no shell, argv from allow-list).
  - `privilege.mode = "capability-user"` (hardened, Phase 12): monitor switches to uid `detent` retaining ambient caps; service control via a shipped **polkit rule** limited to the allow-listed units. `detent doctor` verifies prerequisites.
- Atomic write protocol: read current file → verify `expected_prev_hash` (optimistic concurrency, defeats lost updates between UI sessions) → copy to `/var/lib/detent/backups/<module>/<utc-ts>/` (rotation: keep 20) → write temp in same dir (`O_EXCL`, same mode/owner/xattrs/SELinux label via `copy_file_range`/`fgetxattr`) → `fsync` → `rename` → `fsync(dir)`.

**Worker** (`detent-platform::privsep::worker`): after fork: `setgroups`/`setgid`/`setuid` to `detent`, clear all caps, `no_new_privs`, Landlock (read-only everywhere except `/var/lib/detent/{state,certs,sessions,audit}`), seccomp allow-list. Owns TLS keys (`0600`, dir `0700`), runs axum. Talks only to the monitor for anything under `/etc` or service control.

systemd unit (`packaging/detent.service`, generated by `detent install --systemd` with `ReadWritePaths` computed from enabled modules): `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables/Modules/Logs=yes`, `ProtectControlGroups=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`, `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`, `CapabilityBoundingSet=` (computed), `UMask=0077`, `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectProc=invisible`, `ProcSubset=pid`, `Restart=always`, `RestartSec=2`. Acceptance (revised by spike 02): `systemd-analyze security detent.service` ≤ **2.5** in `root-confined` mode and ≤ **1.8** in `capability-user` mode. The spike measured 2.9 for the first draft, 2.3 with extra directives, 1.6 for the capability-user variant; `PrivateUsers=self` and `IPAddressDeny=any` were excluded from the targets because they break root-owned file writes and LAN access respectively. `≤ 2.0` for root-confined is arithmetically impossible (User=root, AF_INET, CAP_SETUID/SETGID each carry fixed weight).

### 2.5 Operations layer, commit-confirm, audit (`detent-ops`)

All mutations flow through one enum, `Operation`, executed by `OpsEngine`. Fronts
(web, CLI, MCP, FFI-driven hosts) only construct operations; they never touch
files or services directly. This is what makes API/MCP "free" later.

Operations (v1): `ListModules`, `GetModule{id}` (schema + model + diagnostics + host facts), `Validate{id, model}`, `Plan{id, model}` (returns unified diff + affected services + external-check results), `Apply{id, model, expected_hash, service_action, confirm: Option<Duration>}`, `ConfirmCommit{commit_id}`, `RollbackCommit{commit_id}`, `ListBackups{id}`, `Restore{id, backup_id}`, `ServiceStatus{id}`, `ServiceAction{id, action}`, `HostProfile`, `CertStatus`, `CertRenew`, `UpdateCheck`, `UpdateApply{version}`, `AuditQuery{…}`, plus auth/user/token admin ops.

Commit-confirm (ADR‑012): `Apply` on a module with `commit_confirm = true` (network, resolver, mounts) writes files, restarts services, and starts a timer in the **monitor** (default 90 s). The UI/CLI must call `ConfirmCommit` (which, arriving over the network, proves reachability). On timeout, or if the monitor restarts and finds a `pending-commit` marker, it restores the backup and re-applies the service action. Only one pending commit at a time.

Audit log: append-only JSONL under `/var/lib/detent/audit/` (`who, when, op, module, prev_hash, new_hash, result, client_ip, ua`), also emitted to journald/syslog. Never logs secrets or full config bodies (diff hash only).

### 2.6 Fronts

- **CLI** (`detent`): `serve`, `setup` (first run: admin user, listen addr, ACME), `config <module> get|validate|plan|apply|defaults` (JSON/TOML I/O via stdin/stdout; `--service restart`, `--confirm 90s`), `service <id> status|start|stop|restart`, `cert status|renew`, `update [--check] [--min-age N] [--allow-downgrade]`, `install --systemd|--openrc|--freebsd-rc`, `doctor`, `user add|passwd|rm`, `token create|revoke`, `completions`. Global: `--dryrun`, `--verbose/-v`, `--json`, `--config <path>`. `setup` and `install` have `--dryrun`.
- **Web** (`detent-web`): axum 0.8 over rustls (TLS 1.3 only, ALPN h2 + http/1.1), API under `/api/v1`, OpenAPI at `/api/v1/openapi.json` (utoipa), SPA embedded (pre-compressed brotli/gzip, content-negotiated, immutable cache headers on hashed assets).
- **MCP** (Phase 10, feature `mcp`): `rmcp` server exposing each `Operation` as a tool with the same JSON schemas; auth via API token; stdio and streamable-HTTP transports. Not in the default build.
- **libdetent** (`detent-ffi`): C ABI for the pure core (§2.3): `detent_module_list`, `detent_parse`, `detent_render`, `detent_to_model_json`, `detent_apply_json`, `detent_validate_json`, `detent_defaults_json`, `detent_schema_json`, `detent_free`, opaque handles, error codes + `detent_last_error_message`. No I/O, no threads, no panics across the boundary. `cbindgen` header checked in; `cargo-semver-checks` + a C example compiled in CI. ABI versioned via `detent_abi_version()`; SONAME `libdetent.so.0`.

### 2.7 Web security controls (implemented in Phase 4; re-verified in Phase 12)

- **TLS:** `ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])`; suites = TLS 1.3 defaults; key exchange prefers `X25519MLKEM768`; ECDSA P‑256 cert keys (or Ed25519 for private CA); OCSP stapling not needed for short-lived certs; HSTS `max-age=63072000; includeSubDomains`.
- **Auth:** username + password; Argon2id (`m=64 MiB, t=3, p=1`, configurable down to OWASP minimum for tiny boards), constant-time verify, dummy-hash on unknown user; login rate limit (per-IP and per-user token buckets; 5 failures → exponential backoff, lockout logged); optional TOTP (Phase 5). Passwords never logged; `Setup` prints nothing secret to logs.
- **Sessions:** 32‑byte CSPRNG id, server-side store (in-memory; restart = logout), `__Host-detent_session; Secure; HttpOnly; SameSite=Strict; Path=/`, idle 15 min, absolute 8 h, rotate on login/privilege change, explicit logout invalidates.
- **CSRF (ADR‑007):** for all non-GET: `Sec-Fetch-Site ∈ {same-origin}` required (or absent only for non-browser token auth), `Origin` must equal the configured host, and `X-Detent-CSRF` must equal the per-session token (delivered via `/api/v1/auth/session`). GET never mutates.
- **API tokens:** `Authorization: Bearer`, 32‑byte random, stored SHA‑256, scopes `read|write`, optional expiry, revocable; CSRF checks skipped only when a Bearer token is presented (no cookie ambient authority).
- **Headers:** `Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-<theme>'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (deny all), `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Cache-Control: no-store` on API.
- **Input:** all bodies typed with `serde(deny_unknown_fields)`; `DefaultBodyLimit` 256 KiB; path params validated against module/service ids from the registry; hostnames RFC 1123, IPs via `std::net`, CIDR via typed parser; every string field has a max length; JSON depth limit; no user-controlled file paths anywhere.
- **Output:** React escapes by default; config rendering per-format quoting (§2.3 invariant 5); API errors are codes + Fluent ids, never raw internal errors.
- **Misc:** request timeouts, concurrent-connection cap, `Server` header removed, error pages static, no directory listing, `/metrics` absent in v1 (attack surface), audit for every auth event.

### 2.8 ACME (`detent-acme`)

- Client: `instant-acme` 0.8 (supports `Dns01`, `DeviceAttest01` (experimental), profiles, ARI). CA is any RFC 8555 server; presets: Let's Encrypt (production/staging) and "custom directory URL" (step-ca).
- **Profiles:** default `shortlived` on Let's Encrypt (160 h certs, GA since 2026‑01‑15). Renewal scheduler polls ARI daily and renews at the ARI window or at 1/3 lifetime remaining, whichever first; jittered; retries with backoff; failure → UI/CLI warning well before expiry; never serves an expired cert silently (falls back to self-signed bootstrap + loud banner).
- **dns-01:** provider trait `DnsProvider { present(name, txt) ; cleanup ; propagation_check }` with implementations: RFC 2136 TSIG (via `hickory-client`), Cloudflare API token, acme-dns, deSEC, external hook (executes an admin-provided script through the monitor with fixed argv; disabled unless explicitly configured). Propagation verified by querying authoritative NS before finalizing.
- **device-attest-01** (feature `acme-attest`): `Attestor` trait producing a WebAuthn-format attestation statement. v1 implementation: **TPM 2.0** (`tss-esapi`; AK-signed `TPM2_Certify` over the new key with key-authorization hash as qualifying data; `tpm` format as accepted by step-ca). Identifier types `permanent-identifier` / `hardware-module` per draft‑ietf‑acme‑device‑attest. Tested in CI against step-ca + `swtpm`. Apple/YubiKey formats out of scope.
- **Bootstrap:** before the first ACME cert exists, `serve` starts with an ephemeral self-signed cert only if `tls.bootstrap = "self-signed"` is set (default set by `setup`, cleared once ACME succeeds). Fingerprint printed to the console/journal for TOFU. Private key material lives only under `/var/lib/detent/certs` (worker-owned, `0600`).
- Secrets for DNS providers are stored in `/etc/detent/secrets.toml` (`0600`, root) and passed to the worker at startup via the socketpair once (never re-readable).

### 2.9 Self-update (`detent-update`, ADR‑005)

1. `GET https://api.github.com/repos/jauderho/detent/releases` via the shared hyper‑rustls client (roots: `webpki-roots`, pinned at build), 1 MiB cap, timeout.
2. Choose the newest non-draft, non-prerelease release with `tag > current` (semver; downgrades refused unless `--allow-downgrade`), published ≥ `update.min_age_days` ago unless the release body carries `detent-security: true` metadata.
3. Download `detent-<target-triple>` and its Sigstore bundle (`*.sigstore.json`) + `SHA256SUMS`; stream to a temp file in the binary's directory (via monitor `ReplaceBinary`), size cap 64 MiB.
4. Verify: SHA‑256 matches SUMS; Sigstore bundle verifies (certificate SAN = `https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/<tag>`, issuer = `https://token.actions.githubusercontent.com`, Rekor inclusion, subject digest = file digest, trust root embedded from Sigstore TUF and refreshed with detent releases). **Mechanism (decided by spike 01):** an in-tree minimal verifier, not the `sigstore` crate — the crate pulls `reqwest`, duplicates the RustCrypto stack, and panics without a system CA store on musl. The verifier is its own Phase 9 design task: embedded Fulcio roots + refresh policy, leaf certificate chain and SAN/issuer extension checks, SCT verification against embedded CT log keys, Rekor signed entry timestamp (SET) verification against the embedded Rekor key, DSSE/in-toto statement digest match. Tested against real bundles produced by `actions/attest` on the rc release.
5. Run `new-binary --self-test` (prints version, checks feature set ⊇ current), then atomic rename; keep `detent.prev`; restart via init; health-check `GET /healthz` within 30 s or roll back to `detent.prev` and mark the release bad in state.
6. Daily background check (opt-in `update.auto_install`; default only notifies). CLI `detent update --check --json` for external automation.

Spike 01 measured the `sigstore` crate at +1.95 MiB and +139 crates on aarch64-musl; size alone was acceptable, the dependency and runtime problems above were not. The in-tree verifier is still keyless and still has no long-lived secret.

### 2.10 Configuration and state

- `/etc/detent/detent.toml` (root, `0640` root:detent): `[listen] addr="0.0.0.0:3333"`, `[tls] acme|bootstrap`, `[acme] ca, email, profile="shortlived", challenge="dns-01"|"device-attest-01", dns.provider…`, `[auth] argon2 params, session timeouts, totp`, `[update] min_age_days=2, auto_install=false`, `[privilege] mode`, `[modules] enabled=[…]` (subset of compiled), `[ui] default_locale`.
- `/etc/detent/secrets.toml` (`0600` root).
- `/var/lib/detent/` (`0700` detent): `certs/`, `state/`, `audit/`, `backups/` (backups dir is monitor-written, `0700` root).
- `sysusers.d`/`tmpfiles.d` snippets in `packaging/` create user and dirs.

---

## 3. Security model summary (full text in `docs/THREAT_MODEL.md`, Phase 12)

Assets: the device's config files, service control, TLS keys, admin credentials,
the binary itself. Adversaries: remote unauthenticated network attacker; a
compromised browser tab on the admin's machine (CSRF/XSS); a compromised upstream
crate/action (supply chain); a local unprivileged user on the device; a malicious
GitHub release (compromised token).

Controls map: TLS 1.3 + short-lived certs (transport); Argon2id + rate limits +
sessions/CSRF/CSP (web); privsep + Landlock + seccomp + caps + allow-lists (local
privilege); lossless model + injection-safe rendering + external validators +
backups + commit-confirm (integrity/availability); reproducible builds + SBOM +
provenance + immutable releases + Sigstore verification + cooldowns (supply
chain); `deny(unsafe_code)` outside two crates, fuzzing, 100 % coverage gate
(memory safety/correctness).

---

## 4. Cross-cutting standards

### 4.1 Build profile and budgets

```toml
[profile.release]
opt-level = "z"     # re-evaluate "s" if perf is unacceptable; size wins
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
debug = false
overflow-checks = true   # keep in release: correctness over speed

[profile.release.package."*"]
opt-level = "z"
```

`#[global_allocator] static GLOBAL: mimalloc::MiMalloc` with `features = ["secure"]`
(guard pages, encrypted free lists, randomized allocation; ~10 % cost accepted).

Budgets (targets; Phase 0 spike sets the initial measured baseline, CI `size-check`
fails on > 3 % regression without an explicit override in the PR body):

| Build | Binary (stripped, aarch64-musl) | Idle RSS |
|---|---|---|
| Full default features | ≤ 12 MiB | ≤ 30 MiB |
| `module-resolver,web` only | ≤ 6 MiB | ≤ 20 MiB |
| `module-*` only, no web, no acme, no update (CLI) | ≤ 3 MiB | ≤ 10 MiB |

Spike 00 baseline (aarch64-musl, stripped, TLS+HTTP+ACME+argon2+mimalloc-secure, no modules, no SPA): 2.77 MiB with aws-lc-rs, 2.30 MiB with ring. The CLI row therefore requires the CLI build to exclude the TLS/HTTP/ACME/update stack (features off), not a smaller TLS stack. All three rows are re-derived from real builds at the end of Phase 4 and recorded in `size-baseline.json`. FreeBSD artifacts are dynamically linked against the base system libc (zig sysroot pins the minimum FreeBSD version, currently 14.0); "single static binary" applies to Linux musl targets.

Rust: latest stable pinned in `rust-toolchain.toml` (currently 1.98.0), edition 2024,
`resolver = "3"`. Use let-chains, `LazyLock`, `impl Trait` args, `NumBuffer`/`format_into`
where formatting hot paths matter (1.98), `str::substr_range` where useful. MSRV = pinned
stable; no compatibility promises for older compilers.

Lints (`[workspace.lints]`): `rust: unsafe_code = "forbid"` (overridden to `deny`+allow-listed
in `detent-platform` and `detent-ffi`), `missing_docs = "warn"`, `clippy::all`, `clippy::pedantic`,
`clippy::unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`
(core/modules), `clippy::cargo`. CI runs `clippy --all-targets --all-features -- -D warnings`.

### 4.2 Dependency policy

- `deny.toml`: `sources = crates.io only`; licenses allow-list (MIT, Apache‑2.0, BSD‑2/3, ISC, MPL‑2.0, Zlib, Unicode, OpenSSL for aws-lc); `bans` on duplicate major versions where avoidable; advisories = deny.
- Prefer: axum, tokio (`rt`, `net`, `time`, `sync`, `signal`, `macros`, `io-util`), hyper + hyper-rustls, rustls, instant-acme, rcgen (**`default-features = false`** — its defaults link `ring` even in aws-lc builds; CI asserts `cargo tree -i ring` is empty for the default feature set), argon2, zeroize, subtle, serde/serde_json, schemars, postcard, clap (derive), tracing + tracing-journald/syslog, landlock, caps, seccompiler, capsicum (BSD), zbus (feature `init-systemd`), tss-esapi (feature), sigstore (feature), hickory-client (dns-01 rfc2136 + propagation checks), fluent-bundle/i18n-embed, rust-embed, utoipa, proptest, arbitrary, cargo-fuzz.
- Avoid: reqwest, openssl, anything pulling in a second TLS or HTTP stack, `inventory`/`linkme`.
- Cooldown: see §6.4.

### 4.3 i18n (ADR‑003)

- `locales/en-US/{core,cli,web}.ftl` are the source of truth. Every user-facing
  string in Rust and TSX is a Fluent id; a CI script fails on string literals in
  JSX (biome rule `noJsxLiterals`-equivalent custom check) and on Fluent ids that
  are missing in `en-US`.
- Web: `@fluent/react` (`LocalizationProvider`), locale from user setting →
  `navigator.languages` → `en-US`. Dates/numbers via `Intl` with the active locale.
- Rust: `i18n-embed` with fallback to `en-US`; CLI locale from `LANG`/`LC_MESSAGES`
  or `--locale`.
- Contributions: `docs/TRANSLATING.md` — copy `locales/en-US/` to `locales/<lang>/`,
  translate, run `bun run i18n:check` (reports missing/extra ids), open a PR. A
  `pseudo` locale (`locales/qps-ploc/`) generated at test time catches hardcoded text
  and layout overflow. Weblate-compatible layout.

### 4.4 UI standards (contract + `AGENTS.md`)

- shadcn/ui components themed via `web/src/styles/tokens.css` to the catfu tokens;
  `--radius: 0`; IBM Plex Mono body (lowercase), Archivo for titles, Archivo
  Expanded for readouts; Press Start 2P unused in v1 (no LCD screens) — keep the
  font out of the bundle unless a screen element is added.
- Theme: dark default, hardware rocker toggle top-right in the status bar, set
  before paint, persisted to `localStorage['detent-theme']` (helper guards SSR/quota).
- Every module page: **Basic** section (smart secure defaults) and a **Advanced**
  disclosure. Every field: label, silk-screen unit/hint, tooltip (`x-detent.tooltip`),
  and a recommendation callout when the current value is worse than the recommended
  one (`x-detent.recommendation` + `security_impact`).
- Apply flow: Plan → diff preview (unified, syntax-highlighted) + external-check
  results + affected services → choose service action (none/reload/restart/start/stop)
  → Apply → (commit-confirm countdown banner with **confirm** button).
- Status LEDs (contract §6): green = active, amber = pending/commit-confirm, blinking
  amber = failed/expiring cert, unlit = stopped.
- A11y: WCAG AA contrast verified by `scripts/contrast-check.ts` (bounding-rect
  color math per contract §11) in CI; full keyboard operability; axe-core in
  Playwright; `prefers-reduced-motion` honored (only `steps()`/`linear`).
- Responsive at 390 / 768 / 1280 px, verified by Playwright screenshots in CI.

---

## 5. Phases

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done (acceptance demonstrated).

Milestones: **M1** (end of Phase 3) headless CLI can safely edit `/etc/hosts` and
`resolv.conf` on a real box. **M2** (end of Phase 5) web UI usable behind a
bootstrap cert. **M3** (end of Phase 9) first signed, attested, immutable release
with self-update. **M4** (end of Phase 12) v1.0.

---

### Phase 0 — Foundations and spikes `[x]` (2026-09-03, branch `phase-0-foundations`)

**Goal:** a compiling workspace, CI skeleton, ADRs, and answers to the three
technical unknowns before any feature work.

**Deliverables**
- `Cargo.toml` workspace with empty crates listed in §2.1 (each with `lib.rs` and a
  doc comment), `rust-toolchain.toml`, `.cargo/config.toml`, `deny.toml`,
  `bunfig.toml`, `web/` scaffold (Vite + React + TS strict + Tailwind v4 + shadcn init
  with `--radius 0`, biome), `locales/en-US/*.ftl` (empty), `docs/adr/ADR-001…012.md`.
- `.github/workflows/ci.yml` running: fmt, clippy (`-D warnings`), test, `cargo deny`,
  `cargo audit`, `cargo llvm-cov` (gate wired but threshold set at current value and
  documented as ratcheting to 100 % by Phase 1), web `biome ci`, `bun test`,
  size-check placeholder. Harden-runner + SHA-pinned actions (use existing
  `scripts/useCommitHash.sh`).
- `.github/dependabot.yml` extended: `cargo`, `bun`, `github-actions`, each with
  `cooldown.default-days: 7`.
- `docs/adr/` set; `docs/MODULE_GUIDE.md` stub; `CONTRIBUTING.md`; `CODEOWNERS`.
- Spike reports in `docs/spikes/` (short, with measured numbers):
  1. **Cross-build spike:** `cargo zigbuild` for `x86_64/aarch64/armv7/riscv64gc` musl
     and `x86_64-unknown-freebsd` with rustls+aws-lc-rs, mimalloc secure, tokio, axum,
     landlock, seccompiler. Record binary sizes. If aws-lc-rs cannot cross-build for a
     tier-1 target, flip ADR‑002 to ring.
  2. **Sigstore size spike:** add `sigstore` (verify only) to the spike binary; record
     size delta; decide §2.9 fallback.
  3. **Sandbox spike:** on a Raspberry Pi OS (kernel ≥ 6.1) VM or board and on a Fedora
     VM: Landlock ABI version available, seccomp filter loads, `systemd-analyze security`
     for the draft unit. Record which Landlock ABI to require (fallback behavior when
     absent: warn + continue with caps/seccomp only).

**Tasks**
1. Scaffold workspace and crates → verify: `cargo build --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` clean.
2. Scaffold `web/` → verify: `bun install --frozen-lockfile && bun run build && bun run lint` clean; bundle served statically shows a placeholder page with the rocker toggle and tokens.
3. Write ADR‑001…012 from §1.3 (one file each, context/decision/consequences) → verify: reviewed by orchestrator.
4. CI workflows → verify: green run on a PR; `scripts/checkWorkflows.sh` passes.
5. Spikes 1–3 → verify: numbers recorded in `docs/spikes/*.md`; budgets in §4.1 adjusted with justification if needed.

**Acceptance:** all verifies above; open questions §1.5 answered or defaults recorded in ADRs.

**Delegation:** scaffolding + CI → Sonnet; ADR drafting → Sonnet, orchestrator edits; spikes → Fable Low (they decide architecture). Orchestrator reviews every ADR personally.

---

### Phase 1 — Core model, module SDK, reference module (`hosts`) `[ ]`

**Goal:** the extension point exists, is proven on the simplest real file, and the
test/fuzz/coverage harness is in place at 100 %.

**Deliverables**
- `detent-core`: `LosslessDoc` primitives (line-oriented CST with spans; token kinds: comment, blank, directive, continuation, unknown), `Diagnostics` (severity, Fluent id, field path, span), `ModuleDescriptor` + `Target` + `Upstream` + `ServiceBinding` + `ExternalCheck`, `HostProfile` type, JSON Schema `x-detent` extension types, `module_conformance!` test macro, `proptest` strategies helpers.
- `crates/modules/_template/` (copy-me crate with TODOs, fuzz stubs, fixture dir, `upstream.toml`).
- `crates/modules/hosts/`: `/etc/hosts` module — model: entries `{ip, hostnames[], comment?}`, validation (RFC 1123 names, unique canonical names, IPv4/IPv6 literal checks, localhost sanity), defaults (loopback entries + hostname), lossless CST, fixtures from glibc/musl/FreeBSD samples.
- `fuzz/`: `fuzz_hosts_parse`, `fuzz_hosts_roundtrip`, `fuzz_hosts_edit` with seed corpora; `.github/workflows/fuzz.yml` (60 s per target on PR, 20 min nightly, crash artifacts uploaded, regression test auto-added policy documented).
- Coverage gate: `cargo llvm-cov --workspace --all-features --lcov` + `scripts/coverage-merge.sh`; CI fails under **100 % lines** for `detent-core` and `modules/*`; regions reported and ratcheted (never decreases; stored in `coverage-baseline.json`).
- `docs/MODULE_GUIDE.md` written against the hosts module (end-to-end walkthrough).

**Tasks**
1. Core types + CST → verify: unit tests, `render(parse(s)) == s` proptest over generated and fixture inputs.
2. Conformance macro → verify: expands to the six invariants in §2.3 for a dummy module.
3. Hosts module → verify: conformance tests pass; fixtures parse losslessly; adversarial cases (CRLF, tabs, trailing spaces, `\0`, 1 MiB line, 10k entries, IPv6 zone ids, comments inline) covered.
4. Fuzz targets + CI → verify: `cargo fuzz run fuzz_hosts_parse -- -max_total_time=60` clean locally and in CI.
5. Coverage gate → verify: CI red on a deliberately uncovered line in a scratch branch, green on main.
6. MODULE_GUIDE → verify: a Sonnet agent, given only the guide, produces a compiling `_template` copy for a fictional module in one attempt (dry run, not merged).

**Acceptance:** 100 % line coverage on core + hosts; fuzz clean; guide validated by the task‑6 dry run.

**Delegation:** core CST + macro → Fable Low (subtle); hosts module → Fable Low first (sets the pattern); fuzz/CI → Sonnet; guide → Sonnet, orchestrator reviews.

---

### Phase 2 — Platform layer: files, privsep, sandbox, services `[ ]`

**Goal:** the monitor/worker split works with real files on a real Linux box,
confined, with backups and rollback.

**Deliverables** (`detent-platform`)
- `fs::atomic`: the write protocol in §2.4 with owner/mode/xattr/SELinux-label preservation; backup rotation; `expected_prev_hash` check.
- `privsep::{proto, monitor, worker}`: `postcard` protocol, `SOCK_SEQPACKET` socketpair, fork/exec-free spawn (fork then role switch), request allow-list tables built from `ModuleDescriptor`s, size caps, structured errors, protocol version handshake.
- `sandbox::{linux, freebsd}`: caps bounding set, `no_new_privs`, `dumpable`, Landlock (ABI detection, best-effort compat mode with explicit warning), seccomp allow-list generated per role (monitor/worker) and tested by a "tripwire" test that expects `SIGSYS` on a forbidden syscall; FreeBSD stubs with Capsicum where possible (finished in Phase 11).
- `service::{systemd (zbus), openrc, bsdrc}` behind `ServiceManager` trait: `status|start|stop|restart|reload`, unit alternatives resolution (`chronyd.service` vs `chrony.service`), no shell, absolute program paths, argv from allow-list only.
- `host::HostProfile` detection: distro (`/etc/os-release`), init system, installed service versions (via `ExternalCheck`-style version probes), active network backend (networkd/NM/ifupdown/netplan/rc.conf) and resolver backend (resolved/NM/static/unbound), CPU/RAM class (for Argon2 param defaults).
- `http::Client`: single hyper‑rustls client with timeouts, size caps, `webpki-roots`.
- `packaging/`: `detent.service` (hardened), `sysusers.d/detent.conf`, `tmpfiles.d/detent.conf`, polkit rules (for Phase 12 mode), OpenRC and FreeBSD rc scripts (finished in Phase 11), `install.sh` (`set -euo pipefail`, `--dryrun`, `--verbose`, shellcheck/shfmt clean).

**Tasks**
1. Atomic fs → verify: tests on tmpfs and ext4 (CI) for crash-consistency (kill between temp write and rename leaves original intact), permission/xattr preservation, hash mismatch rejection.
2. Protocol → verify: exhaustive serde round-trip tests; fuzz target `fuzz_privsep_decode`; oversize and unknown-discriminant tests close the channel.
3. Monitor/worker → verify: integration test spawns the pair as root in a CI container (`--privileged` docker job, documented) and as unprivileged (expects graceful refusal); worker cannot open `/etc/shadow` (Landlock) and receives `SIGSYS` on `ptrace` (seccomp). Spike 02 showed Landlock/seccomp/caps work unprivileged, so only root-owned-file tests need the privileged job. Add a Raspberry Pi OS kernel image and one Landlock-less (5.10-era) kernel to this job: the ABI-1 minimum and the degrade path are reasoned, not yet measured.
4. Service managers → verify: systemd path tested in a systemd-enabled container (`jrei/systemd-*` style image or `vmactions`), OpenRC on Alpine container; unit-name allow-list rejects arbitrary names.
5. Host detection → verify: fixture-driven tests for Debian/RPi OS, Ubuntu, Fedora, Arch, Alpine, FreeBSD `os-release`/backend layouts.
6. Packaging → verify: `systemd-analyze security --offline=true` ≤ 2.5 (root-confined) on Fedora and Debian images; `install.sh --dryrun` prints plan; shellcheck clean.

**Acceptance:** all verifies; coverage 100 % lines on `detent-platform` on Linux (BSD-only paths measured in Phase 11 and merged); `unsafe` blocks each carry `// SAFETY:` and are reviewed by the orchestrator.

**Delegation:** privsep + sandbox → **Fable Low** (security-critical; orchestrator self-escalates to Fable High for the review of the monitor protocol and Landlock/seccomp policy, then drops back). fs/atomic → Fable Low. Service managers, host detection, packaging → Sonnet.

---

### Phase 3 — Operations layer and CLI (Milestone M1) `[ ]`

**Goal:** everything is usable headless. `detent config hosts apply` edits a real
box safely with backup, validation, and audit.

**Deliverables**
- `detent-ops`: `Operation` enum (§2.5), `OpsEngine`, `Authz` hook trait (identity + scope), audit log writer (JSONL + tracing), commit-confirm state machine (timer in monitor, marker file, one-pending rule), `Plan` producing unified diff (`similar` crate or in-tree Myers; keep small).
- `detent-i18n`: Fluent loader, message ids for all diagnostics; `locales/en-US/core.ftl`, `cli.ftl`.
- `detent` binary: clap CLI per §2.6 (except `serve`/web-specific), `--dryrun`, `--verbose`, `--json`, `setup` (non-interactive flags + interactive TTY), `doctor` (checks user/dirs/permissions/sandbox availability/unit hardening), `install`.
- `detent config <module> get|validate|plan|apply|defaults` working for hosts.

**Tasks**
1. Ops engine + audit → verify: unit tests for every Operation path incl. failures; audit entries schema-validated.
2. Commit-confirm → verify: integration test: apply with `--confirm 2s`, no confirm → file restored and service action re-run; monitor kill mid-window → restored on restart via marker.
3. CLI → verify: `trycmd`/snapshot tests for help, JSON output, error codes; `--dryrun` performs zero writes (checked with a tmp root and inotify/`strace`-free assertion on mtime/hash).
4. End-to-end on a VM (Debian + Fedora): edit `/etc/hosts`, verify backup, audit, rollback → verify: recorded in `docs/spikes/m1-e2e.md` with commands and outputs.

**Acceptance:** M1 demo recorded; 100 % lines on ops/i18n/cli crates.

**Delegation:** ops engine + commit-confirm → Fable Low; CLI → Sonnet; e2e → Sonnet with orchestrator verifying outputs.

---

### Phase 4 — Web server, auth, API `[ ]`

**Goal:** the API is live over TLS 1.3 with a bootstrap cert, all §2.7 controls in
place, fully covered by tests.

**Deliverables** (`detent-web`)
- rustls config (TLS 1.3 only, PQ‑hybrid KEX), bootstrap self-signed via `rcgen` with fingerprint logging, hot reload of certs (watch the cert store; ACME lands in Phase 6).
- Auth: user store (`/var/lib/detent/state/users.json`, Argon2id), login/logout, session store, TOTP (Phase 5 UI; backend here), API tokens, rate limiter.
- CSRF middleware (§2.7), security headers middleware, body limits, timeouts, request ids, structured access log (no query strings with secrets).
- API v1 (utoipa): `/auth/*`, `/session`, `/modules`, `/modules/{id}`, `/modules/{id}/validate|plan|apply`, `/commits/{id}/confirm|rollback`, `/backups`, `/services/{id}`, `/system/profile`, `/audit`, `/healthz` (unauthenticated, constant body, no version). OpenAPI JSON generated and checked in (`docs/API.md` links it).
- Static SPA serving with precompressed assets and hashed-asset caching; `index.html` with CSP hash for the theme script.

**Tasks**
1. TLS → verify: `openssl s_client -tls1_2` fails, `-tls1_3` succeeds; `testssl.sh` (CI job, allow network) reports no weak suites; ALPN h2 negotiated.
2. Auth → verify: tests for unknown-user timing parity (statistical, ±10 %), lockout, session expiry/rotation, token scopes, TOTP window/replay.
3. CSRF/headers → verify: tests for each rejected condition (missing `Sec-Fetch-Site`, cross-site, wrong Origin, missing token) and for Bearer bypass; header snapshot test on every route.
4. API → verify: contract tests from the OpenAPI file (`schemathesis`-style fuzz via `arbitrary` bodies for each endpoint; 4xx never 5xx; `deny_unknown_fields`).
5. Threat-model checklist pass (§3) → verify: `docs/SECURITY_HARDENING.md` checklist with each item linked to a test.

**Acceptance:** 100 % lines on `detent-web`; fuzz targets `fuzz_api_json`, `fuzz_session_cookie` clean; security header and TLS checks automated in CI.

**Delegation:** TLS/auth/CSRF → **Fable Low**; API handlers/OpenAPI → Sonnet; test authoring → Sonnet with Fable Low review of auth tests.

---

### Phase 5 — Web UI (Milestone M2) `[ ]`

**Goal:** a beautiful, simple admin page per `AESTHETIC_CONTRACT.md` + §4.4, fully
localized, with schema-driven module forms.

**Deliverables** (`web/`)
- Design system: `tokens.css` (catfu tokens mapped to shadcn vars; dark/light), self-hosted fonts, status bar with wordmark, LEDs, clock, rocker toggle; hairline-zoned layout primitives.
- i18n: `@fluent/react`, `locales/en-US/web.ftl`, pseudo-locale, language switcher, `bun run i18n:check`.
- Pages: Login (+TOTP), Dashboard (service LEDs, cert status readout, update status, pending commit banner), Module page (schema-driven form: Basic/Advanced, tooltips, recommendations, diff/plan modal, apply + service action, commit-confirm countdown), Services, Backups/Restore, Audit, Settings (users, tokens, locale, update policy), Certificates.
- Schema-driven form engine: JSON Schema + `x-detent` → shadcn fields (Input, Select, Switch, Combobox, Tag list, IP/CIDR inputs with validation mirroring the backend), array/table editors for entries (hosts rows, exports, shares).
- State: TanStack Query; no global client state beyond theme/locale/session.
- Tests: vitest + testing-library (components, form engine, i18n fallback), Playwright e2e against the real binary with bootstrap cert (login, edit hosts, plan, apply, confirm), axe-core, contrast check script, viewport screenshots 390/768/1280.

**Tasks**
1. Tokens/theme/status bar → verify: contract §13 checklist run and recorded; contrast script passes both themes.
2. Form engine → verify: renders every field type from a synthetic schema fixture; validation parity tests with backend via shared fixtures.
3. Pages → verify: Playwright flows; keyboard-only run of the apply flow.
4. i18n → verify: pseudo-locale run shows no untranslated strings; `i18n:check` in CI.
5. `improve-it` and `frontend-design` skill passes → verify: findings triaged in a doc, applied ones referenced.

**Acceptance:** M2 demo (screenshots in `docs/spikes/m2-ui.md`); vitest 100 % lines on `web/src` (exclude generated shadcn primitives only, listed explicitly); e2e green.

**Delegation:** design system + form engine → Fable Low (design quality matters); pages → Sonnet; tests → Sonnet; orchestrator does the contract compliance review.

---

### Phase 6 — ACME: dns-01, short-lived certs, device-attest-01 `[ ]`

**Goal:** real certs, renewed automatically, from public and private CAs.

**Deliverables** (`detent-acme`)
- Account management (key stored `0600`, EAB support), order flow with `instant-acme`, profile selection (`shortlived` default on LE), ARI-driven renewal scheduler, cert store + hot reload into `detent-web`, status/renew ops and UI.
- `DnsProvider` trait + RFC 2136, Cloudflare, acme-dns, deSEC, hook implementations; propagation checks against authoritative NS via `hickory-client`.
- `Attestor` trait + TPM 2.0 attestor (feature `acme-attest`), `permanent-identifier`/`hardware-module` identifiers.
- Failure UX: expiry warnings in UI/CLI/journal at 50 %/25 % lifetime; never silent.

**Tasks**
1. dns-01 against **Pebble** (with `challtestsrv` as the DNS) in CI → verify: end-to-end issuance + ARI renewal test with time shortened.
2. Each provider → verify: unit tests with recorded HTTP/DNS fixtures; secrets never logged (log-capture assertion).
3. Short-lived flow → verify: staging LE issuance documented manually once (`docs/spikes/acme-le.md`), CI uses Pebble with a 160 h profile analog.
4. device-attest-01 → verify: CI job with `step-ca` + `swtpm` issues a cert to detent via TPM attestation; negative tests for wrong AK chain.
5. Hot reload → verify: new cert served without restart (`openssl s_client` shows new serial).

**Acceptance:** 100 % lines (attest paths measured in the swtpm job); fuzz targets for ACME JSON responses and DNS provider responses.

**Delegation:** ACME core + attestor → **Fable Low**; providers → Sonnet from a provider template written by Fable Low; CI containers → Sonnet.

---

### Phase 7 — Modules wave 1: resolver, chrony, mounts, NFS, Samba `[ ]`

**Goal:** the most-used SBC configs, with smart secure defaults and upstream tracking.

Per module (each is one subtask following `MODULE_GUIDE.md`): lossless CST, model, schema with `x-detent` hints, validation + recommendations, defaults, external check, service binding, fixtures from the tracked upstream version, fuzz targets, Fluent strings, UI page (generic engine; custom widgets only where necessary), `upstream.toml`.

| Module | Files / backends | Secure smart defaults | External check | Notes |
|---|---|---|---|---|
| **resolver** | `/etc/resolv.conf` (detect symlink to resolved/NM; refuse to edit managed file, offer the managing backend instead), `systemd-resolved` `resolved.conf` + drop-in, `unbound.conf` | resolved: DoT opportunistic→strict option, DNSSEC allow-downgrade→yes option, DNS over Tor no; unbound: `qname-minimisation`, `harden-*` on, `aggressive-nsec`, DoT forwarders | `resolvectl`/`unbound-checkconf` | commit-confirm on |
| **chrony** | `chrony.conf`, `sources.d/`, `conf.d/` | NTS pool sources, `makestep 1 3`, `rtcsync`, GPS refclocks: `refclock SHM 0 refid GPS precision 1e-1 offset …`, `refclock PPS /dev/pps0 lock GPS`; `allow` only when serving; `cmdport 0` unless needed | `chronyd -p -f <tmp>` | version-gated options (`since`) |
| **mounts** | `/etc/fstab` | `nosuid,nodev,noexec` recommendations per mount type, `nofail` for removable, `x-systemd.automount` hint | `findmnt --verify --tab-file <tmp>` | commit-confirm on; apply = `daemon-reload` + optional mount via monitor |
| **nfs** | `/etc/exports`, `exports.d/` | `root_squash`, `sec=sys` warning → recommend `krb5p`, subnet-scoped, `no_subtree_check` | `exportfs -s` style parse via `exportfs -ra` in dryrun where available | |
| **samba** | `smb.conf` (INI with `include`, `%` macros preserved verbatim) | `server min protocol = SMB3_00`, signing/encryption required, no guest, `map to guest = Never`, `restrict anonymous = 2`, disable printing | `testparm -s <tmp>` | version-gated options |

**Tasks** (per module): implement → conformance + fuzz → fixtures → strings → UI check → verify on VM (`docs/spikes/m-<module>.md`).

**Acceptance:** 100 % lines per module crate; upstream-watch issues auto-open for each (test with a fake old `tracked_version`).

**Delegation:** resolver + chrony → Fable Low (multi-backend, version-gated); mounts, nfs, samba → Sonnet using the guide, orchestrator reviews each diff against the invariants.

---

### Phase 8 — Modules wave 2: network, DHCP `[ ]`

**Goal:** interface configuration across the tier-1 backends, and DHCP servers.

| Module | Backends | Secure smart defaults | External check |
|---|---|---|---|
| **network** | systemd-networkd `.network`/`.netdev` (INI, drop-ins), NetworkManager keyfiles (`*.nmconnection`, `0600`), ifupdown `/etc/network/interfaces` (+`interfaces.d/`), netplan YAML (comment-preserving YAML via a lossless YAML CST — scope: subset used by netplan; unknown keys preserved) | DHCP client with IPv6 privacy extensions, RA acceptance sane, no promiscuous, static IPs with gateway/DNS validation, VLAN/bridge basics | `networkctl`, `nmcli connection load` (dryrun), `ifup -n`, `netplan generate --root-dir <tmp>` |
| **dhcp** | dnsmasq (`dnsmasq.conf`, `dnsmasq.d/`), Kea DHCPv4/v6 (JSON with comments — lossless JSONC CST) | bind to interface, authoritative off unless chosen, sane lease times, DNS rebind protection on, `dhcp-ignore` unknown clients option, no `dhcp-authoritative` by default | `dnsmasq --test -C <tmp>`, `kea-dhcp4 -t <tmp>` |

Both are commit-confirm modules. Network model is backend-neutral (interface → addresses/dhcp/routes/dns/vlan/bridge) with backend adapters; unsupported constructs remain preserved-but-opaque in the CST and shown as "advanced: raw section" in the UI.

**Acceptance:** VM tests on Debian (ifupdown + NM), Ubuntu (netplan), Fedora (NM), Arch (networkd); commit-confirm rollback demonstrated by deliberately misconfiguring an interface (recorded).

**Delegation:** network model + networkd/NM adapters → **Fable Low**; ifupdown/netplan adapters and dhcp → Sonnet from the adapter pattern; YAML/JSONC CSTs → Fable Low (subtle, fuzz-heavy).

---

### Phase 9 — Release pipeline and self-update (Milestone M3) `[ ]`

**Goal:** reproducible, attested, immutable releases; detent updates itself safely.

**Deliverables**
- `.github/workflows/release.yml` (on `v*` tags): harden-runner (egress audit→block); build matrix via `cargo zigbuild` + `cargo auditable` with `--locked`, `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)`, `RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME=/cargo"`, `bun install --frozen-lockfile` for the SPA; targets (per §1.6): `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (zigbuild on Linux runners), `aarch64-apple-darwin`, `x86_64-apple-darwin` (native on macOS runners; reproducibility gate applies to both OSes). armv7/riscv64/FreeBSD are out of the matrix until the deferred pass. **Two independent builds per target** on different runners; job fails unless SHA‑256 matches (reproducibility gate).
- SBOMs: `cargo cyclonedx` (with `SOURCE_DATE_EPOCH`) + `cdxgen` for the web lockfile, merged; `actions/attest` (build provenance) and `actions/attest-sbom` for every artifact; `SHA256SUMS` + per-artifact `.sigstore.json` bundles published as assets; `gh release create --verify-tag`; repo setting **immutable releases** on.
- `.github/workflows/rebuild-verify.yml`: weekly and on demand, rebuild the latest tag from source and compare to published hashes; `gh attestation verify` for each asset.
- Repo rulesets documented in `docs/RELEASING.md`: main requires PR + review + status checks + signed commits + linear history; `v*` tags protected; force-push disabled; Actions SHA-pinned; Dependabot cooldowns.
- `detent-update` per §2.9, `detent update` CLI, UI status + apply, `--self-test`.
- **Sigstore bundle verifier design + implementation** (separate subtask, Fable Low/Opus): `docs/adr/ADR-014-sigstore-verifier.md`, embedded trust roots with a documented refresh procedure, test vectors from real `actions/attest` bundles (valid, wrong identity, wrong digest, expired leaf, bad SCT, bad SET).

**Tasks**
1. Release workflow → verify: a `v0.0.1-rc` tag produces a full release; both builds match; `gh attestation verify detent-aarch64-unknown-linux-musl -R jauderho/detent` passes; `gh release verify`.
2. rebuild-verify → verify: green on the rc; red when an asset is tampered in a fork test.
3. Updater → verify: tests with a mocked GitHub API + real Sigstore bundle fixtures (valid, wrong identity, wrong digest, expired cert, missing Rekor proof); downgrade refusal; min-age gating; rollback on failed health-check (integration test with a fake bad binary).
4. Size/RSS budget gate → verify: `scripts/size-check.sh` in CI compares to `size-baseline.json`.

**Acceptance:** M3: v0.1.0 immutable release with SBOM + provenance; a device updates from v0.0.x to v0.1.0 via `detent update` and rolls back from a deliberately broken v0.1.1-test.

**Delegation:** updater verifier → **Fable Low**; workflows → Sonnet with Fable Low review of the trust-identity checks; ADR‑013 (BSD target strategy) → orchestrator.

---

### Phase 10 — libdetent C ABI and API/MCP readiness `[ ]`

**Goal:** the core is consumable from C/Swift/Kotlin; operations are exposable via MCP.

**Deliverables**
- `detent-ffi`: functions in §2.6, `#[repr(C)]` structs, opaque handles, `catch_unwind`-free design (no panics possible: lints + fuzz), `cbindgen.toml`, `include/detent.h` checked in and CI-verified (`cbindgen --verify`), `examples/ffi-c/main.c` built and run in CI (parses a fixture, edits, renders), `cargo-semver-checks` on the crate, Miri run on FFI unit tests.
- `docs/FFI.md`: ABI stability policy (`detent_abi_version`, SONAME), memory ownership rules, thread-safety statement.
- `detent-mcp` (feature `mcp`): rmcp server mapping every `Operation` to a tool with the same JSON Schemas as the REST API; token auth; stdio + streamable HTTP; documented in `docs/API.md`. Default build excludes it; CI builds and smoke-tests it.
- OpenAPI ↔ MCP schema parity test.

**Acceptance:** C example runs on Linux and FreeBSD CI; `cbindgen --verify` clean; MCP smoke test lists tools and executes `ListModules`/`GetModule`.

**Delegation:** FFI → Fable Low; MCP → Sonnet.

---

### Phase 11 — BSD tier 2 (FreeBSD first) `[deferred]` — parked per §1.6; do not schedule

**Goal:** detent runs confined on FreeBSD; OpenBSD/NetBSD build but are documented as best-effort.

**Deliverables**
- `sandbox::freebsd`: Capsicum (`cap_enter`) in the monitor with pre-opened directory descriptors and `openat`-only file ops; worker likewise; document exactly what is and is not confined.
- `service::bsdrc`; `packaging/freebsd/detent` rc.d script; `install --freebsd-rc`.
- `network` backend for `/etc/rc.conf` (`ifconfig_<if>`, `defaultrouter`, `ipv6_*`) and `resolver` for FreeBSD `resolvconf`; `mounts` fstab dialect differences; `nfs` `/etc/exports` FreeBSD syntax variant; `chrony`/`samba` paths.
- CI: `vmactions/freebsd-vm` job runs unit + integration tests and contributes an LCOV slice merged by `coverage-merge.sh`.

**Acceptance:** FreeBSD VM: e2e hosts/resolver/rc.conf edit with rollback; coverage merge shows BSD-only lines covered; OpenBSD/NetBSD `cargo check` job green (no runtime claims).

**Delegation:** Capsicum → Fable Low; rc.conf backend → Sonnet; CI → Sonnet.

---

### Phase 12 — Hardening, docs, and v1.0 (Milestone M4) `[ ]`

**Deliverables**
- `docs/THREAT_MODEL.md` (STRIDE per component, mapped to tests), `docs/SECURITY_HARDENING.md` (operator checklist: unit hardening, polkit mode, TOTP, mTLS option), `docs/PENTEST_CHECKLIST.md` (OWASP ASVS L2 items mapped to tests; run `security-review` skill on the full diff).
- `privilege.mode = "capability-user"` + polkit rules; `detent doctor` verifies.
- Optional mTLS client-cert auth (`tls.client_auth = "required"` with a configured CA) if Q1 answered yes.
- Passkeys spike decision (ADR‑014) — implement only if cheap.
- Translations bootstrap: `de`, `ja` (machine-drafted, marked `# needs-review`), pseudo-locale in CI.
- `cargo-mutants` weekly job (advisory), `cargo geiger` report in CI, `cargo semver-checks` for `detent-core`/`detent-ffi`.
- Final size/RSS measurements published in README; `improve-it` skill pass on the UI.
- v1.0.0 immutable release.

**Acceptance:** every §2.7 control has a linked test; `systemd-analyze security` ≤ 2.5 (root-confined) and ≤ 1.8 (capability-user); all budgets met; PENTEST checklist all green or explicitly accepted risks with owner.

**Delegation:** threat model + pentest checklist → orchestrator (self-escalate to Fable High for the threat model review); mode/polkit → Fable Low; translations/docs → Haiku/Sonnet.

---

## 6. CI, supply chain, and release governance

### 6.1 Workflows

| Workflow | Trigger | Content |
|---|---|---|
| `ci.yml` | PR, push main | fmt, clippy `-D warnings` (all features + minimal feature sets matrix), test (Linux x86_64 + aarch64 via QEMU for musl), `cargo deny`, `cargo audit`, `cargo llvm-cov` (100 % lines gate), web `biome ci` + vitest + Playwright, `i18n:check`, contrast check, `cbindgen --verify`, size-check, shellcheck/shfmt, `checkWorkflows.sh` |
| `fuzz.yml` | PR (60 s/target), nightly (20 min/target) | cargo-fuzz all targets; crash artifacts uploaded; corpus cached |
| `privileged-tests.yml` | PR | docker `--privileged` job for privsep/sandbox tests; systemd container; Alpine OpenRC container |
| `freebsd.yml` | deferred (§1.6) | — |
| `ci.yml` macOS job | PR | `cargo test --workspace` and web checks on `macos-latest` (aarch64) |
| `acme.yml` | PR (paths: acme), nightly | Pebble + challtestsrv; step-ca + swtpm |
| `release.yml` | `v*` tag | §Phase 9 |
| `rebuild-verify.yml` | weekly, manual | rebuild + compare + `gh attestation verify` |
| `upstream-watch.yml` | weekly | compare `upstream.toml` vs latest releases; open issues |
| existing: `scorecard`, `semgrep`, `codespell`, `linter`, `dependency-review`, `gitlabsync` | as is | keep; ensure SHA pins |

All jobs: `permissions: read-all` default with per-job elevation; `step-security/harden-runner` with `egress-policy: block` and an explicit allow-list (crates.io, github, static.rust-lang.org, registry.npmjs.org, Sigstore endpoints).

### 6.2 Coverage policy

- Gate: **100 % line coverage** across the workspace, measured by `cargo llvm-cov` with LCOV slices from Linux (unprivileged), Linux privileged container, FreeBSD VM, and ACME containers merged by `scripts/coverage-merge.sh` (lcov `-a`), then checked by the script (no third-party service).
- Region coverage reported and ratcheted (`coverage-baseline.json`, never decreases).
- No `#[cfg(not(coverage))]` or `// LCOV_EXCL` in the codebase. Platform-only code is covered on its platform. If something is genuinely unreachable it should not exist.
- Web: vitest `--coverage` lines 100 % on `web/src` excluding the explicit list of copied shadcn primitives (which have their own tests upstream).

### 6.3 Testing pyramid

Unit (every crate) → conformance macro (every module) → property tests (proptest strategies per format) → fuzz (cargo-fuzz per parser, protocol, API JSON, ACME/DNS responses, update manifest) → integration (spawned monitor/worker, real files in temp roots, real service managers in containers) → e2e (Playwright vs real binary + bootstrap TLS) → VM acceptance (Debian, Ubuntu, Fedora, Arch, Alpine, FreeBSD; recorded per phase) → mutation (cargo-mutants weekly, advisory) → external (testssl.sh, axe, `systemd-analyze security`).

Test data policy: fixtures are real upstream samples with version directories; adversarial corpora checked in under `fuzz/corpus/<target>/`; every fuzz crash becomes a named regression test before the fix merges.

### 6.4 Cooldown (7 days) implementation (ADR‑011)

| Ecosystem | Mechanism |
|---|---|
| Cargo | `dependabot.yml` `cooldown.default-days: 7` (security updates bypass). `.cargo/config.toml` `[registry] global-min-publish-age = "7 days"` added the day Cargo stabilizes it (tracked: rust-lang/cargo#17335, expected 1.100); until then CI runs `cargo-cooldown --days 7 -- fetch` as a lockfile check. |
| Bun/npm | `bunfig.toml` `[install] minimumReleaseAge = 604800`; Dependabot `bun` ecosystem with the same cooldown. |
| GitHub Actions | already configured (`cooldown.default-days: 7`); SHA pins. |
| Rust toolchain | `rust-toolchain.toml` bumped by a scheduled workflow only when the release is ≥ 7 days old (point releases for security exempt). |
| Container images in CI | pinned by digest; bumped by Dependabot `docker` ecosystem with cooldown 7. |

### 6.5 Commit and PR conventions

Signed commits (`git commit -S -s`, SSH signing), one logical change per commit,
ASD‑STE100 imperative messages, PR template includes: phase/task id, acceptance
evidence (command + output), coverage delta, size delta, ADR references.

---

## 7. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| aws-lc-rs cross-compilation friction (zig, FreeBSD) | build breaks | Phase 0 spike; `crypto-ring` fallback feature kept compiling in CI |
| In-tree Sigstore verifier correctness (SCT/SET checks are easy to get wrong) | accepting a forged update | dedicated design task + ADR-014, real-bundle test vectors, orchestrator review at Fable High |
| Argon2id m=64 MiB on 256 MiB boards (128 ms measured on fast virtualised aarch64) | slow logins / RSS spikes | `HostProfile` RAM class picks 64/32/19 MiB; measure on a Pi in Phase 4 |
| Landlock unavailable on old SBC kernels | weaker sandbox | ABI detection; caps + seccomp still apply; `doctor` reports; documented minimum kernel (5.13+, recommend 6.1+) |
| `device-attest-01` still a draft; `instant-acme` marks it experimental | API churn | feature-gated, tested against step-ca; pin draft version in docs |
| Netplan YAML lossless editing is hard | fidelity bugs | scope to netplan's schema subset; unknown nodes preserved opaque; heavy fuzzing |
| 100 % coverage on platform code | CI complexity | multi-slice LCOV merge; privileged/VM jobs from Phase 2 |
| macOS host support drifts (module paths, no sandbox) | dev/test breakage | `cfg(target_os)` gates with unit tests on both OSes in CI (`macos-latest` job) |
| Single-admin session store in memory | logout on restart | acceptable and documented; revisit if multi-admin arrives |
| Cargo native cooldown not yet stable | window for malicious crates | Dependabot cooldown + `cargo-cooldown` CI check in the interim |

---

## 8. Appendices

### A. Module authoring checklist (mirrors `docs/MODULE_GUIDE.md`)

- [ ] `crates/modules/<id>/` from `_template`; `Cargo.toml` with `[lints] workspace = true`
- [ ] `upstream.toml` (`tracked_version`, feed, docs) and `fixtures/<id>/<version>/`
- [ ] `Doc` CST: comments/blank/unknown preserved; spans; `render(parse(s)) == s`
- [ ] `Model` with serde + schemars, `deny_unknown_fields`, `x-detent` hints on every field (group, tooltip, recommendation, security_impact, since)
- [ ] `validate`: errors/warnings/recommendations as Fluent ids; injection checks (newline/NUL/delimiters)
- [ ] `defaults(profile)`: secure and smart; explained in `docs/modules/<id>.md`
- [ ] `ExternalCheck` and `ServiceBinding` with alternatives per init
- [ ] `module_conformance!` + adversarial unit tests + proptest strategy
- [ ] fuzz targets `fuzz_<id>_parse|roundtrip|edit` with seeds
- [ ] `locales/en-US/core.ftl` strings (`<id>-field-…`, `<id>-tip-…`, `<id>-rec-…`)
- [ ] feature flag in `detent/Cargo.toml`, registry entry in `detent-modules`
- [ ] 100 % lines; VM check recorded in `docs/spikes/m-<id>.md`

### B. Privsep message sketch

```rust
#[derive(Serialize, Deserialize)]           // postcard; every enum #[non_exhaustive] is NOT used (closed set on purpose)
pub enum Request {
    Hello { proto: u16 },
    ReadTarget { target: TargetId },
    WriteTarget { target: TargetId, expected_prev: Option<Sha256>, bytes: Vec<u8> /* ≤ 1 MiB */ },
    RunCheck { check: CheckId, bytes: Vec<u8> },
    Service { binding: BindingId, action: ServiceAction },
    ListBackups { module: ModuleId },
    Restore { module: ModuleId, backup: BackupId },
    StartConfirmTimer { commit: CommitId, timeout_s: u16 },
    ConfirmCommit { commit: CommitId },
    Mount { target: TargetId },              // cfg(feature = "module-mounts")
    ReplaceBinary { len: u64, sha256: Sha256 }, // cfg(feature = "update"); bytes streamed in fixed chunks after
    Shutdown,
}
```
Ids are `u16` indices into tables the monitor builds itself; the worker only learns ids from the monitor's `HelloAck { targets, checks, bindings }`.

### C. systemd unit sketch

```ini
[Service]
ExecStart=/usr/local/bin/detent serve
User=root
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID CAP_KILL
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/hosts /etc/resolv.conf /etc/chrony /etc/fstab /etc/exports /etc/samba /var/lib/detent
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes            # with acme-attest: PrivateDevices=no + DeviceAllow=/dev/tpmrm0 rw (detent never needs /dev/pps*; chronyd does)
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077
Restart=always
```
`detent install --systemd` generates `ReadWritePaths` and the bounding set from enabled modules; `CAP_SETUID/SETGID` are used once to drop the worker and then removed from the monitor's bounding set at runtime.

### D. Web request checklist (every mutating handler)

TLS 1.3 → session or Bearer → (cookie path) `Sec-Fetch-Site` + `Origin` + `X-Detent-CSRF` → body ≤ 256 KiB, typed, `deny_unknown_fields` → ids validated against registry → `Operation` → authz scope → audit → response with no-store.

### E. Research facts this plan relies on (verified 2026‑09‑03)

- `device-attest-01`: IETF WG draft `draft-ietf-acme-device-attest`, in IESG review, not yet RFC; Let's Encrypt does not offer it; step-ca supports `tpm`, `apple`, `step` formats. ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/), [smallstep](https://smallstep.com/docs/step-ca/provisioners/))
- `instant-acme` 0.8.5: `ChallengeType::{Http01, Dns01, TlsAlpn01, DeviceAttest01 (experimental), Unknown(String)}`, ARI and profiles supported. ([docs.rs](https://docs.rs/instant-acme/latest/instant_acme/enum.ChallengeType.html))
- Let's Encrypt `shortlived` profile (160 h) GA since 2026‑01‑15; renew every 2–3 days; ARI daily. ([letsencrypt.org](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability), [profiles](https://letsencrypt.org/docs/profiles/))
- GitHub immutable releases GA 2025‑10‑28; release attestations verifiable via `gh release verify`. ([changelog](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/))
- `actions/attest` supersedes `attest-build-provenance`; slsa-github-generator is in maintenance. ([attest-build-provenance](https://github.com/actions/attest-build-provenance), [slsa-verifier](https://github.com/slsa-framework/slsa-verifier))
- `cargo cyclonedx` ≥ 0.5.9 honors `SOURCE_DATE_EPOCH`; `cargo auditable` embeds a reproducible dependency list. ([cyclonedx-rust-cargo](https://github.com/CycloneDX/cyclonedx-rust-cargo/releases), [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable))
- Cargo `min-publish-age`: nightly-only (`-Zmin-publish-age`); stabilization PR rust-lang/cargo#17335 targets 1.100. Dependabot `cooldown` supports Cargo. ([RFC 3923](https://rust-lang.github.io/rfcs/3923-cargo-min-publish-age.html), [Dependabot changelog](https://github.blog/changelog/2025-07-01-dependabot-supports-configuration-of-a-minimum-package-age/))
- `mimalloc` crate 0.1.52, feature `secure`, defaults to mimalloc v3. ([docs.rs](https://docs.rs/crate/mimalloc/latest))
- Rust 1.98.0 (2026‑08‑20) stabilizations relevant here: `NumBuffer`/`format_into`, `str::substr_range`, `NonZero::from_str_radix`. ([release](https://github.com/rust-lang/rust/releases/tag/1.98.0))
- Crate versions at planning time: axum 0.8.9, tokio 1.53.1, rustls 0.23.43, instant-acme 0.8.5, landlock 0.4.7, caps 0.5.6, seccompiler 0.5.0, argon2 0.6.0, zbus 5.19.0, rmcp 3.2.0, utoipa 5.5.0, cbindgen 0.29.4, rust-embed 8.12.0, fluent-bundle 0.16.0, i18n-embed 0.16.0, sigstore 0.14.0, proptest 1.11.0, arbitrary 1.4.2, postcard 1.1.3, tss-esapi 7.7.0, hickory-client 0.25.2.

---

## 9. Change log

| Date | Change | By |
|---|---|---|
| 2026‑09‑03 | Initial draft for approval. | orchestrator (Fable) |
| 2026‑09‑03 | Owner narrowed scope: x86_64 + aarch64 only; Linux and macOS first; BSD/armv7/riscv64 deferred (§1.6, ADR‑013, Phase 11 parked). | orchestrator (Fable) |
| 2026‑09‑03 | Approved with all §1.5 defaults. Phase 0 done. Spike results folded in: §2.4 (Landlock ABI 1 minimum, degrade path, systemd score targets 2.5/1.8), §2.9 (in-tree Sigstore verifier instead of the `sigstore` crate), §4.1 (budgets re-based, CLI row excludes TLS stack, FreeBSD dynamic linking), §4.2 (rcgen default-features off), §2.2 (both crypto features may coexist, aws-lc wins), Phase 2/9/12 tasks, risks. | orchestrator (Fable) |

## 10. Checkpoint for the next session (read this first if resuming cold)

**State on 2026‑09‑03, branch `phase-0-foundations` (from `main`):** Phase 0 complete; Phase 1 not started.

What exists and passes locally:
- Workspace of 19 crates (`crates/*`, `crates/modules/*`), all empty except the `detent` binary (clap skeleton, mimalloc secure). `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace`, `cargo deny check` pass. Toolchain pinned to 1.98.0.
- `web/`: Vite + React 19 + TS strict + Tailwind v4 + shadcn (radius 0) + biome + Fluent i18n + vitest (13 tests). Catfu tokens in `web/src/styles/tokens.css`; components `StatusBar`, `ThemeRocker`, `Led`, `Label`, `KickerTag`; nameplate page per `docs/DESIGN_SEED.md`. `bun run lint|typecheck|test|i18n:check|build` pass. Preview via `.claude/launch.json` (`web-preview`, port 4173).
- `docs/adr/ADR-001…012`, `docs/DESIGN_SEED.md`, `docs/spikes/00-02`, `CONTRIBUTING.md`, `.github/CODEOWNERS`, stubs for `MODULE_GUIDE.md`/`TRANSLATING.md`.
- CI: `.github/workflows/ci.yml` (rust, supply-chain incl. cargo-cooldown, coverage gate at 0 % ratchet, web, shell, size, pins) and `fuzz.yml`; Dependabot cooldown 7 days for cargo/bun/docker/actions; `scripts/size-check.sh`, `scripts/coverage-merge.sh`. **Not yet executed on GitHub** — first PR will prove it.
- Local tooling installed: cargo-llvm-cov, cargo-deny, cargo-audit, cbindgen, cargo-cyclonedx, cargo-auditable, cargo-zigbuild (zig via `uv`; shim at `spikes/bin/zig`), musl/FreeBSD rustup targets. Docker is OrbStack.

Known gaps carried into later phases: coverage gate must be raised to 100 % for `detent-core` and modules in Phase 1; `cargo tree -i ring` CI assertion lands with the first TLS dependency (Phase 4); Landlock-less kernel and Pi kernel untested (Phase 2); Capsicum untested (Phase 11); aarch64-freebsd unattempted (ADR-013, Phase 9).

**Scope note:** §1.6 supersedes every earlier mention of BSD/armv7/riscv64 as active work.

**Next action:** start Phase 1 task 1 (`detent-core` CST + `module_conformance!`) with an Opus/Fable-Low implementor; the prompt must cite §2.3 invariants 1–6 and Appendix A.
