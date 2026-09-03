# ADR-004: One crate per module
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` supports an extensible set of config modules (hosts, resolver,
chrony, mounts, NFS, Samba, DHCP, network, …) and a build must be able to
contain only the modules a device needs, via feature flags (§1.1, §2.2).
Modules also need independent fuzz targets and a clear, repeatable template
for adding new ones (§2.3, Appendix A).

## Decision

Every module is its own crate under `crates/modules/<id>/`, feature-gated in
the `detent` binary (`module-hosts`, `module-resolver`, …, §2.2), and
registered explicitly under `cfg(feature)` in `detent-modules` — no
link-time registration magic (§2.1, §2.2, §2.3). Each module crate exposes
one type implementing `ConfigModule` and owns its own `upstream.toml`,
fixtures, fuzz targets, and Fluent strings (§2.3, Appendix A). New modules are
created by copying `crates/modules/_template/` (Phase 1 deliverable).

## Consequences

Positive:
- Isolation: a bug or panic surface in one module's parser cannot leak into
  another module's crate boundary.
- Independent fuzz targets and independent, parallel compilation per module.
- An obvious, mechanical template for adding a new module (Appendix A
  checklist), which is what lets mechanical module work be delegated to
  Sonnet in Phases 7–8 while the pattern-setting modules go to Fable Low.

Negative:
- More crates in the workspace to manage (`Cargo.toml` boilerplate,
  `[lints] workspace = true` per crate, per-crate `upstream.toml`).
- Cross-module code reuse must go through `detent-core` or shared traits
  rather than direct crate-to-crate imports between modules, since modules
  do not depend on each other (§2.1 dependency direction).

## Alternatives considered

- A single `detent-modules` crate with all module implementations inlined —
  rejected implicitly: this would prevent the independent fuzz targets and
  the explicit `cfg(feature)`-gated builds required by §2.2 ("build a binary
  that contains only the modules a device needs").

## References

PLAN.md §1.3 (ADR-004 row), §2.1, §2.2, §2.3, Appendix A.
