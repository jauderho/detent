# ADR-016: Passkeys (WebAuthn) — defer past v1
Status: Accepted (2026-10-09)
Deciders: project owner (approved PLAN.md 2026-09-03; spike decision requested by PLAN.md Phase 12)

## Context

PLAN.md Q4 answered "password auth + optional TOTP, with passkeys later" and
Phase 12 asks for a passkeys spike decision, "implement only if cheap". (The
Phase 12 text calls it ADR-014; that number went to the Sigstore verifier, so
this record is ADR-016.) The question: should v1 add WebAuthn passkeys, as a
second factor, as a passwordless login, or not at all?

What exists today (§2.7, ADR-007): username + Argon2id password, optional
TOTP with a replay guard, in-memory sessions in a `__Host-` cookie, CSRF by
three checks, scoped Bearer tokens for automation. The expected deployment is a
LAN appliance on `:3333`. It is reached by an IP address or a short name, and
by default it uses a self-signed bootstrap certificate (§2.8). A public name
with an ACME certificate is optional.

This record was made by reading the code and the PLAN, and from crates.io
metadata. Nothing was built or measured. Figures marked "estimate" are
estimates.

## Findings

### 1. The origin constraint (decisive)

A WebAuthn credential is bound to an RP ID. The RP ID must be a valid domain
string that is equal to, or a registrable-domain suffix of, the effective
domain of the page origin (WebAuthn Level 2, sections 5.1.3 and 5.1.4).
Consequences for detent:

- **A raw IP origin cannot be used.** An IP address is not a valid domain
  string, so browsers reject `https://192.0.2.10:3333` with a `SecurityError`.
  The default listener serves the UI on an IP address or on `localhost`
  (`Origin::for_config` falls back to both). So the default install cannot
  register a passkey.
- **A secure context is needed.** HTTPS is required, except for `localhost`.
  Chrome is also reported to refuse WebAuthn on a page whose certificate was
  accepted by a click-through. The self-signed bootstrap certificate (§2.8)
  is therefore probably not enough. Not verified here: this needs a test with
  each browser before any implementation.
- **A real hostname is needed.** A passkey works only when the operator has
  set `[tls] hostnames` to a DNS name (a public name with an ACME certificate,
  or a private name with a private CA that the browser trusts). `.local` and
  split-horizon names are valid domains, but the certificate must still be
  trusted.
- **The RP ID is permanent.** A passkey is useless if the hostname changes
  (rename, move to another domain, IP-only fallback). The user then needs a
  recovery path that does not depend on the passkey.
- Origin matching in `csrf.rs` already uses the first configured hostname, so
  the RP ID would come from the same setting. No new origin logic is needed,
  but a config change would silently orphan every credential.

So passkeys can only be an opt-in feature for installs that already have a
trusted certificate on a DNS name. That is a minority of first-run LAN
installs, and these are not the installs that most need a second factor.

### 2. Candidate implementations

| Candidate | Role | Verdict |
|---|---|---|
| `webauthn-rs` / `webauthn-rs-core` (Kanidm) | Relying-party library, the usual choice. Maintained (a release in 2026-04). | Rejected. The stable `webauthn-rs-core` 0.5.5 depends on `openssl` and `openssl-sys` (crates.io metadata). OpenSSL is excluded by §4.2 ("a second TLS stack"), and a vendored OpenSSL on the musl and FreeBSD cross targets puts at risk the cross-build result of Phase 0 spike 1 (ADR-002). It also adds `x509-parser`, `der-parser`, `nom`, `serde_cbor_2`, `uuid`, `url`, `rand_chacha` and `webauthn-attestation-ca`: 19 direct dependencies and an estimated 60 to 100 transitive crates (not counted with `cargo tree`). It parses all attestation formats, which is more attack surface than a LAN appliance needs. |
| `passkey` (`passkey-rs`, 1Password) | Authenticator and client side. A release on 2026-10-01. | Rejected. It is not a relying-party verifier. |
| Hand-rolled verifier on `p256` and `sha2` | RP side with `none` attestation only. | Feasible, see below. |

**Hand-rolled verifier.** The workspace already has `p256` (`ecdsa`), `sha2`,
`base64` and `getrandom`, and the aws-lc-rs provider from ADR-002. A verifier
for ES256 needs these parts:
- a small CBOR reader for the attestation object and the COSE key (a
  restricted subset of maps, byte strings and integers, 150 to 250 lines,
  with a fuzz target; or one new CBOR crate);
- authenticator data parsing (RP ID hash, flags UP/UV/BE/BS, sign count,
  attested credential data);
- `clientDataJSON` checks (type, challenge, origin, no `crossOrigin`);
- ES256 verification of `authData || SHA-256(clientDataJSON)`;
- a sign-count rollback check;
- attestation format `none` only, and ES256 (`-7`) only. EdDSA and RS256 are
  refused.

Attestation is not needed. Detent has one admin class and does not need to
know which authenticator model was used. Accepting only `none` removes the
largest part of the WebAuthn surface (packed, TPM, Android, FIDO-U2F and the
metadata service).

**ADR-011.** `webauthn-rs` has `-dev` pre-releases, and its new versions would
go through the 7-day cooldown (Dependabot and `cargo-cooldown`) over a larger
graph. `cargo deny` (`multiple-versions = "warn"`) would probably warn about
duplicate `x509-parser`/`der-parser` and RustCrypto versions. The hand-rolled
path adds none, or one CBOR crate.

### 3. Binary size (estimate)

`size-baseline.json` rows (aarch64-musl, stripped): full default 5 455 472 B
(budget 12 MiB), `full-ui` 6 279 088 B (12 MiB), resolver+web 5 020 144 B
(budget 6 MiB, about 1.2 MiB headroom), CLI 2 271 736 B (3 MiB, does not link
`web`).

- Hand-rolled ES256, `none` only, with routes: an estimate of 25 to 60 KB of
  Rust, plus about 40 KB of SPA assets for the register and login flows. No
  row is at risk. Each re-cut still needs the usual owner approval
  (`scripts/size-check.sh`, tolerance 3 %).
- `webauthn-rs` with vendored OpenSSL: an estimate of +1 to +2 MiB (for
  comparison, spike 01 measured the `sigstore` crate at +1.95 MiB and +139
  crates). It would strain the resolver+web row. Size is not the deciding
  factor; it is a second reason to refuse this crate.

### 4. Security trade-offs

For:
- Phishing resistance: the authenticator checks the RP ID, so a lookalike
  host cannot get an assertion. TOTP codes can be relayed. This has real
  value for an admin tool that is reachable beyond one network segment.
- The server holds a public key only, no shared secret.

Against, for this product:
- The default install cannot use it (finding 1). The shipped default would
  stay password + optional TOTP, and the feature protects only the installs
  that did the extra work.
- New persistent state (credential id, public key, sign count, per-user list)
  next to `users.rs`, and new audit events. The user store gains a version.
- A second factor is only as strong as its recovery path. TOTP in detent has
  no recovery codes today. Passkeys need recovery codes (or a root-only CLI
  reset) designed first, with their own tests. That is the largest open item.
- Synced passkeys (BE/BS flags) move the trust anchor to a cloud account. An
  admin tool for DNS and mounts should be able to refuse backup-eligible
  credentials by policy; that policy would need to be built and explained.
- Stolen-session risk is unchanged: sessions, CSRF and Bearer tokens (§2.7)
  are the larger remaining exposure and passkeys do not touch them.
- The existing controls stay: Argon2id, per-IP and per-user rate limits, the
  TOTP replay guard. For phishing resistance, optional mTLS (Q1, Phase 12)
  needs no WebAuthn parser, has no RP ID problem (it works on an IP address),
  and uses no new browser API. It is cheaper for the same threat.

### 5. Implementation effort (hand-rolled, second factor only)

| Part | Work |
|---|---|
| Verifier module (`detent-web` auth) | CBOR/COSE/authData parsing, ES256, challenge store; unit tests from published test vectors; a fuzz target. About 600 lines with tests. |
| Storage | Credential records in the user store, store version bump, migration test. |
| Routes | 4 routes: register begin/finish, assert begin/finish; OpenAPI entries, the CSRF checklist (Appendix D), audit events, rate limit. |
| Login flow | Challenge after password; TOTP and passkey as alternatives; session rotation on privilege change. |
| SPA | Register and manage keys (settings), login step, error states, i18n strings in all locales; checks in Chrome, Safari and Firefox (AGENTS.md). |
| Recovery | Design and implement (see above); a `doctor` warning when the RP ID changes. |
| Verification | Cross-browser manual test with real authenticators and a trusted certificate on a DNS name. It cannot be done on an IP address, and CI has no such hardware. |

An estimate of 3 to 5 working days for the server and 2 to 3 for the SPA and
recovery. This is not "cheap" in the sense of the Phase 12 condition.
Passwordless mode adds more: the passkey becomes the only barrier, so user
verification (UV) must be forced, and the recovery path becomes the weak point.

## Decision

**Do not implement passkeys in v1. Defer to a post-v1 release.**

1. v1 authentication stays as in §2.7: password (Argon2id), optional TOTP,
   scoped tokens. No WebAuthn code, no new dependency, no change to
   `Cargo.toml`, `deny.toml` or the size baselines.
2. If implemented later, it is **second factor only, ES256, `none`
   attestation, hand-rolled on `p256`/`sha2`**, behind a cargo feature and a
   config switch that is off by default. It is not passwordless. `webauthn-rs`
   stays rejected while it depends on OpenSSL.
3. Operators who need a phishing-resistant factor in v1 use the optional mTLS
   client-certificate mode (Q1, Phase 12), which works on a LAN IP.
4. `docs/SECURITY_HARDENING.md` may state that passkeys are not supported and
   why (the RP ID needs a DNS name with a trusted certificate).

## Revisit when all of these are true

- Recovery codes (or a root-only CLI reset) exist for TOTP, so one design
  serves passkeys too.
- A meaningful share of installs run on a trusted DNS name (ACME is the usual
  path, or the owner makes a DNS name part of `setup`).
- A test with Chrome, Safari and Firefox on a hostname with a trusted
  certificate confirms finding 1, and shows what happens on a click-through
  self-signed certificate.
- Either a maintained RP library without OpenSSL exists (only `aws-lc-rs` or
  RustCrypto, past the ADR-011 cooldown), or the owner accepts the
  hand-rolled verifier and its fuzz target.

Passwordless login needs its own ADR (forced UV, a recovery path, a policy on
synced credentials).

## Consequences

Positive:
- No new attack surface, dependency, or size change in v1.
- No OpenSSL, and no change to the cross-build matrix.
- The owner keeps a cheaper hardening option (mTLS) that fits the IP-address
  deployment.

Negative:
- v1 has no phishing-resistant browser login. TOTP codes can be relayed.
- A later change adds a user-store version and a recovery design.

## Alternatives considered

- `webauthn-rs` as second factor — rejected: OpenSSL, large graph, all
  attestation formats (finding 2).
- Hand-rolled verifier in v1, second factor only — rejected for now: 5 to 8
  days plus a recovery design, usable only on trusted DNS names, no CI
  hardware.
- Passwordless passkeys — rejected: the passkey becomes the only barrier, the
  recovery path becomes the weak point, and the origin constraint blocks the
  default install.
- `passkey` (`passkey-rs`) — rejected: authenticator side only.
- mTLS instead — not decided here; it remains the Phase 12 option (Q1).

## References

PLAN.md Q4 (decisions table), §2.7, §2.8, §4.1 and §4.2 (size and dependency
budgets), §7 and Phase 12; ADR-002 (crypto provider), ADR-007 (sessions and
CSRF), ADR-011 (cooldown), ADR-014 (spike 01 `sigstore` size data point);
`size-baseline.json`; `scripts/size-check.sh`; `deny.toml`; crates.io metadata
for `webauthn-rs-core` 0.5.5 and `passkey` (read 2026-10-09); W3C Web
Authentication Level 2, sections 5.1.3 and 5.1.4 (RP ID and valid domain
string).
