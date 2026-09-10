# ADR-011: 7-day supply-chain cooldown
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

Malicious package releases in Cargo, npm/Bun, and GitHub Actions ecosystems
are typically discovered and pulled within days of publication. `detent`
depends on all three ecosystems plus the Rust toolchain itself (§4.2, §6.4).

## Decision

Apply a 7-day cooldown before consuming new releases from Cargo, Bun, GitHub
Actions, and the Rust toolchain; security advisories bypass the cooldown
(§1.3, §6.4). Implementation per ecosystem (§6.4):

| Ecosystem | Mechanism |
|---|---|
| Cargo | `dependabot.yml` `cooldown.default-days: 7`; `.cargo/config.toml` `[registry] global-min-publish-age = "7 days"` once Cargo stabilizes it (tracked: rust-lang/cargo#17335); until then CI runs `cargo-cooldown --days 7 -- fetch` as a lockfile check. |
| Bun/npm | `bunfig.toml` `[install] minimumReleaseAge = 604800`, placed **next to each `package.json`** (today only `web/`); Dependabot `bun` ecosystem, same cooldown. |
| GitHub Actions | `cooldown.default-days: 7`; SHA pins. |
| Rust toolchain | `rust-toolchain.toml` bumped by a scheduled workflow only when the release is ≥ 7 days old; point releases for security are exempt. |
| CI container images | pinned by digest; bumped by Dependabot `docker` ecosystem with cooldown 7. |

## Consequences

Positive:
- Catches nearly all historical registry-compromise incidents, which are
  typically caught and pulled within the cooldown window (§1.3 Why).
- Applies uniformly across every ecosystem the project touches, not just
  Cargo.

Negative:
- Security fixes are delayed by up to 7 days unless explicitly flagged as an
  advisory bypass, which requires operator discipline to use correctly.
- Bun's cooldown fails **silently** when it is not configured: `bun install`
  succeeds and simply ignores a `bunfig.toml` that is not in its working
  directory, so a misplaced file looks exactly like a correct one. The repo
  originally kept `bunfig.toml` at the root while every install ran in `web/`,
  which meant no cooldown at all; `scripts/cooldown-check.sh` runs in CI ahead
  of `bun install` so that arrangement cannot silently return.
- Cargo's native `min-publish-age` is nightly-only as of this writing
  (stabilization targets 1.100 per rust-lang/cargo#17335), so the interim
  `cargo-cooldown` CI check is an extra tool to maintain until that lands
  (§6.4, §7 risk register).

## Alternatives considered

- No cooldown, rely on `cargo audit`/Dependabot advisories alone — rejected:
  the cooldown is explicitly "Requested" and justified as catching incidents
  advisories would only report after the fact (§1.3 Why).

## References

PLAN.md §1.3 (ADR-011 row), §4.2, §6.4, §7 (risk register: "Cargo native
cooldown not yet stable"), §8.E (RFC 3923 min-publish-age; Dependabot
cooldown changelog, 2025-07-01).
