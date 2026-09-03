# ADR-003: i18n format — Project Fluent
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`detent` ships i18n from day one across three surfaces: the Rust core/CLI, the
web app, and translator-facing files (§1.1, §4.3). The format needs to
support plurals and gender correctly and to be usable by non-developer
translators through a standard translation tool.

## Decision

Use Project Fluent (`.ftl`) everywhere: `fluent-bundle` + `i18n-embed` in
Rust, `@fluent/react` in the web app, one `locales/<lang>/` tree (§1.3, §4.3).
Source of truth is `locales/en-US/{core,cli,web}.ftl`. Every user-facing
string in Rust and TSX must be a Fluent id; CI fails on JSX string literals
and on Fluent ids missing from `en-US` (§4.3). Rust falls back to `en-US` via
`i18n-embed`; CLI locale comes from `LANG`/`LC_MESSAGES` or `--locale`. Web
locale comes from user setting → `navigator.languages` → `en-US`, with
`Intl` for locale-aware dates/numbers. A pseudo locale (`locales/qps-ploc/`)
is generated at test time to catch hardcoded text and layout overflow, and
the layout is kept Weblate-compatible for outside contributors (§4.3,
`docs/TRANSLATING.md`).

## Consequences

Positive:
- One format for all contributors, in both Rust and TypeScript.
- Fluent's plural/gender/selector syntax is correct where simple string
  interpolation is not.
- Weblate-compatible layout lowers the bar for translation contributions
  (§4.3, ADR referenced from `docs/TRANSLATING.md`).

Negative:
- Every module adds a `.ftl` block per language target it wants translated
  (Appendix A: `<id>-field-…`, `<id>-tip-…`, `<id>-rec-…`), which is more
  bookkeeping than inline strings.
- CI must enforce the no-literal-strings rule and the missing-id check, which
  is extra tooling (`bun run i18n:check`) that must stay in sync with both
  the Rust and web string sets.

## Alternatives considered

- Inline string literals with a lighter i18n library — rejected implicitly:
  §4.3 requires plurals/gender handling and Fluent id enforcement in CI,
  which ties the decision to Fluent specifically.

## References

PLAN.md §1.3 (ADR-003 row), §4.3, Appendix A (Fluent id naming), §8.E
(fluent-bundle 0.16.0, i18n-embed 0.16.0 pinned versions).
