# Translating detent

detent's user-facing strings use Project Fluent (`.ftl`); see
`docs/adr/ADR-003-i18n-fluent.md` for why.

## Shipped locales

Twelve locales ship (owner decision, 2026-10-10). The directory name under
`locales/` is the tag, written exactly as below.

| Tag | Language | Script | Web font |
|---|---|---|---|
| `en-US` | English (United States), the source of every id | Latin | embedded |
| `en-GB` | English (United Kingdom) | Latin | embedded |
| `de-DE` | German | Latin | embedded |
| `es-ES` | Spanish (Spain) | Latin | embedded |
| `fr-FR` | French | Latin | embedded |
| `pt-BR` | Portuguese (Brazil) | Latin | embedded |
| `ru-RU` | Russian | Cyrillic | embedded (IBM Plex Mono only) |
| `ja-JP` | Japanese | Han, Kana | system font |
| `zh-CN` | Chinese, Simplified | Han | system font |
| `zh-TW` | Chinese, Traditional | Han | system font |
| `hi-IN` | Hindi | Devanagari | system font |
| `bn-BD` | Bengali | Bengali | system font |

No right-to-left locale ships (no Arabic, Hebrew, Persian or Urdu). The
pseudo-locale `qps-ploc` is for testing and is not a language.

The web console embeds the `latin` and `cyrillic` font subsets
(`web/scripts/build-finish.ts`). `latin` holds all of Latin-1 and Œ/œ, so the
Latin-script locales need no `latin-ext`. Chinese, Japanese, Hindi and Bengali
fall back to the browser's system font, because a CJK or Indic web font would
add megabytes to every binary. Archivo, the display font, has no Cyrillic, so
Russian headings use the system sans-serif.

## Adding a locale

A locale is a directory. There is no list to edit for the twelve above.

1. Copy `locales/en-US/` to `locales/<tag>/`, with one of the tags above
   (`cp -R locales/en-US locales/fr-FR`). The directory needs all three files:
   `core.ftl`, `cli.ftl` and `web.ftl`.
2. Translate each string. Keep the Fluent ids and the placeables (`{$var}`)
   unchanged. Keep code-like tokens (`detent update --check`, paths, unit
   names, HTTP codes, flags, option values) untranslated.
3. Put `# needs-review: machine-drafted <language> translation; not yet
   checked by a native speaker.` as the first line of each file if the text is
   machine-drafted (see "Review status").
4. Check plurals and selectors for your language's rules, not just English's
   two-form plural.
5. Run the checks:
   - `cd web && bun run i18n:check` compares `web.ftl` of every locale
     directory that exists to `en-US` (ids and placeables).
   - `cargo test -p detent-i18n --features web` (and without `--features web`)
     compares all three files of every locale to `en-US`
     (`catalogue_locales_have_id_parity_with_en_us`,
     `catalogue_locales_use_the_same_placeables_as_en_us`) and proves that the
     compressed copy in the binary is the file on disk.
6. Open a PR.

What picks the directory up, with no edit:

- **Rust.** `crates/detent-i18n/build.rs` scans `locales/*/`. It fails the
  build, naming the path, if a directory lacks one of the three files, if its
  name is not a language tag, or if `en-US` is gone. A name that starts with
  `qps-` is a pseudo-locale and is left out.
- **Web.** `bun run build` turns each `locales/<tag>/web.ftl` into its own
  chunk, loaded when that locale is chosen. The status-bar picker lists the
  twelve tags (`SHIPPED_LOCALES` in `web/src/i18n/locales.ts`) and the
  pseudo-locale; a tag whose directory does not exist yet loads as English.
  A new directory under another name fails `bun run i18n:check` until the owner
  adds the tag to `SHIPPED_LOCALES` and to the table above.
- **CI.** `codespell.yml` skips the non-English directories. A new tag beyond
  the twelve needs its directory added to `SKIP` there.

Layout stays Weblate-compatible so translators can work outside a PR flow.

## Which locale a request gets

The CLI (`--locale`, then `LC_ALL`, `LC_MESSAGES`, `LANG`) and the web console
(the stored choice, then `navigator.languages`) negotiate the same way. Every
step names a compiled-in locale or fails over to the next:

1. An exact tag: `de-DE` is `de-DE`.
2. A row of this table, when its target ships:

   | Requested | Gets |
   |---|---|
   | `en` | `en-US` |
   | `en-AU`, `en-HK`, `en-IE`, `en-IN`, `en-NZ`, `en-SG`, `en-ZA` | `en-GB` |
   | `zh`, `zh-Hans`, `zh-SG` | `zh-CN` |
   | `zh-Hant`, `zh-HK`, `zh-MO` | `zh-TW` |
   | `pt` | `pt-BR` |
   | `es` | `es-ES` |

   The most specific key wins and a script beats a region, so `zh-Hant-CN` is
   `zh-TW` and `zh-Hans-HK` is `zh-CN`.
3. The first locale of the same language: `de`, `de-AT` and `de-CH` are
   `de-DE`; `pt-PT` is `pt-BR`; `es-MX` and `es-419` are `es-ES`; `fr-CA` is
   `fr-FR`; `en-CA` is `en-US`.
4. `en-US`.

The table is `ALIASES` in `crates/detent-i18n/src/lib.rs` and in
`web/src/i18n/locales.ts`; a web test fails if the two differ. The Rust loader
takes the exact pass over the whole requested list before the alias pass (so
`["zh-HK", "en-US"]` is `en-US`); the web console keeps every match, in
priority order, as its bundle fallback chain.

## Review status: `# needs-review`

A machine-drafted translation starts with the comment line
`# needs-review: …` at the top of each `.ftl` file. The marker is per file.
`de-DE` and `ja-JP` shipped this way (2026-10-09). A native speaker who has
checked a whole file removes its first line in the same PR; a partial review
leaves the marker in place.

## The Rust loader (`detent-i18n`)

The CLI, the web layer, and diagnostics rendering all go through
`detent-i18n::Localizer`. Things worth knowing as a contributor touching Rust
code:

- **Locales are compiled into the binary**, not read from `locales/` at
  runtime (the daemon runs on appliances with no guaranteed filesystem layout,
  and shipping a second, disk-based copy would blow the size budget in
  `docs/PLAN.md` §4.1). `docs/adr/ADR-003-i18n-fluent.md` and `docs/PLAN.md`
  §4.3 name `i18n-embed`/`rust-embed` for this; `detent-i18n` uses a build
  script and `include_bytes!` instead — see the crate-level doc comment in
  `crates/detent-i18n/src/lib.rs`. Functionally this is the same "compiled in,
  fallback to `en-US`" contract §4.3 describes.
- **The text is stored compressed.** `build.rs` packs each `.ftl` file as raw
  DEFLATE with `miniz_oxide` (safe Rust, one small dependency). A `Localizer`
  inflates the negotiated locale and `en-US` on first use, once per file; the
  other locales are never unpacked. Fluent text packs to about a third: the
  three locales of 2026-10-10 (194 KB as text) pack to 64 KB. Twelve locales as
  plain text would take an estimated 800 KB of the binary.
- **`web.ftl` is feature-gated**: the catalogue includes each locale's
  `web.ftl` only with the `web` feature of `detent-i18n` (enabled by
  `detent`'s `web`). Only the web server and its API look those ids up.
  `cargo test -p detent-i18n` runs without the feature and
  `cargo test -p detent-i18n --features web` with it; both must pass.
- **Locale selection**: `Localizer::new` takes an explicit requested-locale
  list and negotiates it against the catalogue (see above), falling back to
  `en-US`. `Localizer::for_env` builds that list from
  `LC_ALL`/`LC_MESSAGES`/`LANG`, in that precedence, ignoring `C`/`POSIX` and
  stripping `.<codeset>`/`@<modifier>` suffixes (matching POSIX locale
  resolution). Any id missing from the active locale falls back to `en-US`; an
  id missing everywhere renders as the bare id itself, so a broken lookup is
  visible instead of blank.

### Two `qps-ploc` fixtures, not one

There are two pseudo-locale fixtures serving different purposes:

1. **Web app** (`locales/qps-ploc/web.ftl`): generated at build time by
   `bun scripts/gen-pseudo.ts` (or `bun run i18n:pseudo`) from
   `locales/en-US/web.ftl`. Every simple message value is wrapped in `[...]`
   markers; Fluent select blocks are left unwrapped. This catches untranslated
   strings (they lack brackets) and layout overflow (brackets lengthen text).
   The file is gitignored and regenerated before `bun run test` and
   `bun run build`. The web UI includes a locale selector in the status bar
   so operators can switch to `qps-ploc` and visually audit all text. The
   Rust build leaves the directory out (it starts with `qps-`).

2. **Rust test fixture** (`crates/detent-i18n/tests/fixtures/qps-ploc/core.ftl`):
   deliberately partial — translates a handful of ids and adds one extra id
   that `en-US` does not have. Used only by
   `cargo test -p detent-i18n` to prove the id-parity check catches missing
   and extra ids. It is not compiled into `CATALOGUE`, is never selectable by
   `Localizer::new`/`Localizer::for_env`, and is not a real translation — do
   not extend it as if it were one.
