# ADR-002: Crypto provider — aws-lc-rs with ring fallback
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` terminates TLS 1.3 for the web UI and speaks TLS as a client for
ACME and self-update (§2.7, §2.8, §2.9). rustls needs a crypto provider, and
the project must cross-build for `x86_64/aarch64/armv7/riscv64gc` musl and
`x86_64/aarch64-unknown-freebsd` (§2.1, Phase 0 spike 1, Phase 9). This choice
is explicitly provisional: Phase 0 task 5 runs a cross-build spike before it
is considered settled (§2.1 "Spike reports").

## Decision

Use rustls with `aws-lc-rs` (rustls's default provider), enabling the hybrid
post-quantum key exchange `X25519MLKEM768`. A `crypto-ring` feature exists as
a fallback to `ring`, but it is used **only if** the Phase 0 cross-build spike
finds that `aws-lc-rs` cannot cross-build for a tier-1 target (§2.1 spike 1;
Risk register §7). The two provider features are mutually exclusive; enabling
both is a compile error (§2.2).

**Flip condition:** if the Phase 0 cross-build spike (`cargo zigbuild` across
the tier-1 target matrix, §2.1) shows `aws-lc-rs` fails to cross-build for any
tier-1 target, ADR-002 flips to `ring` as the default and this file must be
superseded, not edited in place.

## Consequences

Positive:
- Security over compatibility: PQ-hybrid key exchange is available today with
  `aws-lc-rs`, ahead of a compliance requirement.
- Keeping `crypto-ring` compiling in CI at all times means the fallback is a
  feature-flag flip, not an emergency rewrite, if the spike or later builds
  fail (§7 mitigation).

Negative:
- `aws-lc-rs` cross-compilation is the primary size/build risk called out in
  the risk register (§7): friction is expected on `zig`-based cross builds
  and on FreeBSD.
- Carrying two provider code paths (`crypto-aws-lc`, `crypto-ring`) as
  mutually exclusive features adds a permanent matrix cell to CI (§2.2).

## Alternatives considered

- `ring` as the primary provider — rejected as default per §1.3 ("Security
  over compatibility; PQ-hybrid KEX is available today"); kept as the
  documented fallback instead.
- OpenSSL — excluded by the dependency policy ("Avoid: … openssl … a second
  TLS or HTTP stack", §4.2).

## References

PLAN.md §1.3 (ADR-002 row), §2.1 (spike 1), §2.2, §2.7, §4.2, §7 (risk
register), §8.E (rustls 0.23.43 pinned version).

## Spike outcome (2026-09-03)

Spike 00 (`docs/spikes/00-cross-build.md`) cross-built aws-lc-rs and ring for all five targets with `cargo zigbuild` on the first attempt, FreeBSD included. The flip condition was not met; aws-lc-rs stays the default. Measured cost on aarch64-musl: 2 900 840 B (aws-lc) vs 2 407 864 B (ring), +14–20 % across targets. `crypto-ring` remains a CI-built fallback. `rcgen` must be depended on with `default-features = false`, or aws-lc builds also link ring. FreeBSD binaries are dynamically linked against the base libc.
