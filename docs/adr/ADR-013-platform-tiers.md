# ADR-013: Platform and architecture tiers
Status: Accepted (2026-09-03)
Deciders: project owner (direction given 2026-09-03 after Phase 0)

## Context
PLAN.md originally targeted Linux (tier 1) and BSD (tier 2) across x86_64, aarch64, armv7, and riscv64. Spike 00 showed all of these build, but each extra target multiplies CI, reproducibility checks, seccomp tables, and test surface. The owner develops on macOS.

## Decision
Tier 1: Linux x86_64 and aarch64 (musl, static). Tier 1 host/dev: macOS aarch64 and x86_64 (build, test, core, CLI, libdetent, web; modules only where the file exists; no service control or Linux sandboxing). Deferred (tier 3): FreeBSD/OpenBSD/NetBSD, armv7, riscv64 — code stays portable, but no CI, artifacts, or phase work until a later pass. Phase 11 is parked. See PLAN.md §1.6.

## Consequences
Positive: two seccomp tables instead of four; release matrix of four artifacts; privileged CI on one OS; macOS CI catches host-portability regressions early.
Negative: Raspberry Pi Zero/1/2 (armv7) and RISC-V boards are unsupported until the deferred pass; Capsicum and rc.conf work stays unverified.

## Alternatives considered
- Keep the full matrix — rejected: cost without a current user.
- Drop macOS entirely — rejected: it is the development host and the core/CLI run there at no design cost.

## References
PLAN.md §1.6, §2.4, Phase 9, Phase 11; docs/spikes/00-cross-build.md.
