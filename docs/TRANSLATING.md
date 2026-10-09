# Translating detent

detent's user-facing strings use Project Fluent (`.ftl`); see
`docs/adr/ADR-003-i18n-fluent.md` for why.

Contribution flow (`docs/PLAN.md` §4.3):

1. Copy `locales/en-US/` to `locales/<lang>/` (BCP-47 code, e.g. `de`, `ja`).
2. Translate each `.ftl` string, keeping the Fluent id unchanged.
3. Register the new locale with the Rust loader: add one `LocaleSource` entry
   to `CATALOGUE` in `crates/detent-i18n/src/lib.rs` (one line) plus one
   `include_str!` per `.ftl` file you copied. Until a locale is registered
   there, the CLI/daemon binaries cannot select it, even though the `.ftl`
   files exist on disk — see "The Rust loader" below.
   The web console registers its locales separately: add the locale to
   `AVAILABLE_LOCALES` and `RESOURCES` in `web/src/i18n/index.tsx` (one
   `?raw` import of `web.ftl`), and to `TRANSLATED_LOCALES` in
   `web/scripts/i18n-check.ts`.
4. Run `bun run i18n:check` to report missing or extra ids, and changed
   placeables (`{$var}`), against `en-US` (web strings) — the Rust-side
   equivalents are
   `cargo test -p detent-i18n catalogue_locales_have_id_parity_with_en_us` and
   `catalogue_locales_use_the_same_placeables_as_en_us`, which run
   automatically in CI and fail with the exact ids for every locale
   registered in `CATALOGUE`.
5. Check plurals and selectors render correctly for your language's rules,
   not just English's two-form plural.
6. Open a PR. CI runs the pseudo-locale (`locales/qps-ploc/`) and the same
   `i18n:check` to catch anything missed.
7. Layout stays Weblate-compatible so translators can work outside a PR flow
   later.

## Review status: `# needs-review`

A machine-drafted translation starts with the comment line
`# needs-review: …` at the top of each `.ftl` file. The marker is per file.
`de` and `ja` shipped this way (2026-10-09). A native speaker who has checked
a whole file removes its first line in the same PR; a partial review leaves
the marker in place. Keep code-like tokens (`detent update --check`, paths,
unit names, HTTP codes, flags, option values) untranslated.

## The Rust loader (`detent-i18n`)

The CLI, the web layer, and diagnostics rendering all go through
`detent-i18n::Localizer`. Two things worth knowing as a translator or a
contributor touching Rust code:

- **Locales are compiled into the binary**, not read from `locales/` at
  runtime (the daemon runs on appliances with no guaranteed filesystem layout,
  and shipping a second, disk-based copy would blow the size budget in
  `docs/PLAN.md` §4.1). `docs/adr/ADR-003-i18n-fluent.md` and `docs/PLAN.md`
  §4.3 name `i18n-embed`/`rust-embed` for this; `detent-i18n` uses plain
  `include_str!` over an explicit, one-line-per-locale `CATALOGUE` instead —
  see the crate-level doc comment in `crates/detent-i18n/src/lib.rs` for the
  full rationale. Functionally this is the same "compiled in, fallback to
  `en-US`" contract §4.3 describes; it is a smaller mechanism to get there.
- **`web.ftl` is feature-gated**: `CATALOGUE` includes each locale's `web.ftl`
  only with the `web` feature of `detent-i18n` (enabled by `detent`'s `web`).
  Only the web server and its API look those ids up, and a build without it
  (the CLI-only size row) would otherwise carry about 60 KB of unused text.
  `cargo test -p detent-i18n` runs without the feature and
  `cargo test -p detent-i18n --features web` with it; both must pass.
- **Locale selection**: `Localizer::new` takes an explicit requested-locale
  list and negotiates it against `CATALOGUE` (exact match, then language-only
  match, e.g. `de-AT` matches a compiled `de`), falling back to `en-US`.
  `Localizer::for_env` builds that list from `LC_ALL`/`LC_MESSAGES`/`LANG`, in
  that precedence, ignoring `C`/`POSIX` and stripping `.<codeset>`/`@<modifier>`
  suffixes (matching POSIX locale resolution). Any id missing from the active
  locale falls back to `en-US`; an id missing everywhere renders as the bare
  id itself, so a broken lookup is visible instead of blank.

### Two `qps-ploc` fixtures, not one

There are two pseudo-locale fixtures serving different purposes:

1. **Web app** (`locales/qps-ploc/web.ftl`): generated at build time by
   `bun scripts/gen-pseudo.ts` (or `bun run i18n:pseudo`) from
   `locales/en-US/web.ftl`. Every simple message value is wrapped in `[...]`
   markers; Fluent select blocks are left unwrapped. This catches untranslated
   strings (they lack brackets) and layout overflow (brackets lengthen text).
   The file is gitignored and regenerated before `bun run test` and
   `bun run build`. The web UI includes a locale selector in the status bar
   so operators can switch to `qps-ploc` and visually audit all text.

2. **Rust test fixture** (`crates/detent-i18n/tests/fixtures/qps-ploc/core.ftl`):
   deliberately partial — translates a handful of ids and adds one extra id
   that `en-US` does not have. Used only by
   `cargo test -p detent-i18n` to prove the id-parity check catches missing
   and extra ids. It is not compiled into `CATALOGUE`, is never selectable by
   `Localizer::new`/`Localizer::for_env`, and is not a real translation — do
   not extend it as if it were one.
