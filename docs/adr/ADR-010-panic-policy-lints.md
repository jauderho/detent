# ADR-010: Panic policy and lints
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` exposes a C ABI (`libdetent`, §2.6, §2.1) where an unwind across the
FFI boundary is undefined behavior, and it runs as a privileged daemon where
an unexpected panic is a denial-of-service risk on devices it manages (§1.1,
§4.1).

## Decision

`panic = "abort"` in the release profile; `clippy::unwrap_used`,
`expect_used`, `panic`, and `indexing_slicing` are denied in non-test code
(§1.3, §4.1). FFI never unwinds (§1.3, §2.6: `detent-ffi` is designed to make
panics impossible via lints and fuzzing, not `catch_unwind`). The full
workspace lint set (§4.1) also denies `unsafe_code` by default (`forbid`,
overridden to `deny` + allow-listed only in `detent-platform` and
`detent-ffi`), and enables `clippy::pedantic`, `clippy::arithmetic_side_effects`
(core/modules), and `clippy::cargo`, run in CI as
`clippy --all-targets --all-features -- -D warnings`.

## Consequences

Positive:
- Size: `panic = "abort"` drops unwinding tables, helping the strict binary
  size budgets (§4.1 table).
- Security/ABI safety: denying `unwrap`/`expect`/`panic`/`indexing_slicing`
  forces explicit error handling at every fallible call site, and rules out
  the class of bug where a panic crosses the FFI boundary into C/Swift/Kotlin
  callers (§2.6).
- `parse` in the module SDK is contractually "never panics; total on any
  `&str`" (§2.3), and this lint set is what makes that a checkable property.

Negative:
- Every `Result`-returning call must be handled explicitly, which is more
  verbose than `.unwrap()` during development and raises the bar for
  contributors unfamiliar with the deny-list.
- `panic = "abort"` means no unwinding-based cleanup; graceful shutdown must
  be handled through explicit signal handling, not `Drop` during unwind.

## Alternatives considered

- `panic = "unwind"` with `catch_unwind` at the FFI boundary — rejected in
  favor of making panics structurally impossible via lints and fuzzing
  instead of catching them at the boundary (§2.6: "`catch_unwind`-free
  design (no panics possible: lints + fuzz)").

## References

PLAN.md §1.3 (ADR-010 row), §2.3 (`parse` never panics), §2.6 (`detent-ffi`
panic-free design), §4.1 (build profile and lints).
