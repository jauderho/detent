# ADR-005: Update verification via Sigstore / GitHub attestations
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` self-updates by downloading a new binary from GitHub releases and
swapping it in (§1.1, §2.9). A compromised release channel or a
man-in-the-middle download must not be able to install an untrusted binary.
Long-lived signing keys are themselves a liability if leaked.

## Decision

Verify updates with Sigstore bundle verification against GitHub artifact
attestations, with a pinned identity, plus SHA-256 sums, semver monotonicity
(downgrades refused unless `--allow-downgrade`), atomic binary swap, and a
health-checked rollback (§1.3, §2.9). Concretely: the Sigstore bundle's
certificate SAN must equal
`https://github.com/jauderho/detent/.github/workflows/release.yml@refs/tags/<tag>`,
issuer `https://token.actions.githubusercontent.com`, with Rekor inclusion
and subject digest matching the downloaded file's digest; the trust root is
embedded from the Sigstore TUF root and refreshed with detent releases
(§2.9 step 4). Releases must be published at least `update.min_age_days` ago
unless flagged `detent-security: true` in the release notes (§2.9 step 2).
After swap, `new-binary --self-test` runs, then `GET /healthz` must succeed
within 30 s or the update rolls back to `detent.prev` and the release is
marked bad (§2.9 step 5).

**Size-risk fallback:** the `sigstore` crate is large. The Phase 0 spike
measures its size delta; if it pushes the full binary over the §4.1 budget,
the fallback is a minimal in-tree verifier (x509 chain to embedded Fulcio
roots + Rekor SET verification) — still keyless, still with no long-lived
signing secret (§2.9, §7 risk register).

## Consequences

Positive:
- Keyless signing means there is no long-lived signing secret that can leak
  and be used to forge a malicious update.
- The pinned workflow identity means only builds produced by detent's own
  `release.yml` on a tagged ref can pass verification.
- Health-checked rollback protects headless devices from a bad update
  bricking them.

Negative:
- The `sigstore` crate is a known size risk (§7 risk register); if it forces
  the fallback path, `detent-update` must maintain a hand-rolled x509/Rekor
  verifier instead of relying on an upstream-maintained library.
- Verification depends on GitHub's attestation and Rekor infrastructure being
  reachable; the update path must handle their unavailability without
  falling back to unverified installs.

## Alternatives considered

- A long-lived project signing key (traditional code signing) — rejected:
  "Keyless signing means no long-lived signing secret to leak" (§1.3 Why).
- Trusting the SHA-256 sums file alone without Sigstore/Rekor — rejected:
  §2.9 requires both the sums match *and* Sigstore bundle verification; sums
  alone do not prove provenance.

## References

PLAN.md §1.3 (ADR-005 row), §2.9, §4.1 (size budgets), §7 (risk register),
§8.E (GitHub immutable releases GA 2025-10-28; `actions/attest` supersedes
`attest-build-provenance`; sigstore crate 0.14.0 pinned version).

## Spike outcome (2026-09-03)

Spike 01 (`docs/spikes/01-sigstore-size.md`) measured the `sigstore` crate at +1.95 MiB and +139 crates, and found that it pulls `reqwest`, duplicates the RustCrypto stack, and panics without a system CA store on musl. The decision (keyless Sigstore/GitHub-attestation verification with pinned identity) stands; the mechanism is an in-tree minimal verifier designed in Phase 9 under ADR-014. See PLAN.md §2.9.
