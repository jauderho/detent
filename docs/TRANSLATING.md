# Translating detent

detent's user-facing strings use Project Fluent (`.ftl`); see
`docs/adr/ADR-003-i18n-fluent.md` for why.

Contribution flow (`docs/PLAN.md` §4.3):

1. Copy `locales/en-US/` to `locales/<lang>/` (BCP-47 code, e.g. `de`, `ja`).
2. Translate each `.ftl` string, keeping the Fluent id unchanged.
3. Run `bun run i18n:check` to report missing or extra ids against `en-US`.
4. Check plurals and selectors render correctly for your language's rules,
   not just English's two-form plural.
5. Open a PR. CI runs the pseudo-locale (`locales/qps-ploc/`) and the same
   `i18n:check` to catch anything missed.
6. Layout stays Weblate-compatible so translators can work outside a PR flow
   later.

TODO(Phase 5): expand with a Weblate setup walkthrough and screenshots once
the web app's `@fluent/react` integration lands.
