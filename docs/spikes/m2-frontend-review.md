# Phase 5 frontend review — design quality and over-engineering triage

**Date:** 2026-09-17 · scope: `web/src/` + `web/scripts/`

Ponytail-level scan: what to delete, simplify, or standardize. Correctness
and feature gaps are out of scope — those are covered by the test/e2e gates.

## Findings

| # | Location | Finding | Action |
|---|---|---|---|
| 1 | `i18n/index.tsx:52` | `useLocale` wraps `setLocaleState` in `useCallback` — the setter is already stable. Pure rename. | **Deferred.** Defensive pattern, 1 line, no cost. Add when the hook grows. |
| 2 | `i18n/index.tsx:37` | `isLocale` type guard is a one-liner `(AVAILABLE_LOCALES as readonly string[]).includes(value ?? '')` | **Kept.** Type guards preserve narrowing — explicitly allowed by ts-no-tiny-functions. |
| 3 | `components/StatusBar.tsx` | Locale selector is a bare `<select>` — no combobox, no search, no ARIA listbox. | **Correct.** Two locales don't need a combobox. Upgrade when ≥5 locales ship. |
| 4 | `scripts/gen-pseudo.ts` | Fluent select blocks pass through unwrapped — variant strings inside them don't get `[...]` markers. | **Accepted.** Wrapping variant text would break Fluent parsing. The select expressions themselves are short enough that layout overflow from them is unlikely. |
| 5 | `index.css` | Responsive breakpoint at 560px hides `.online-label` — only addresses the status bar. | **Minimal.** Other components (nav, forms) already use CSS grid reflow. The status bar is the only fixed-width segment. |
| 6 | `lib/utils.ts` | `cn()` is a standard shadcn utility (clsx + twMerge). | **Keep.** Every shadcn component depends on it. |
| 7 | `lib/storage.ts` | `getItem`/`setItem`/`removeItem` are thin wrappers around `localStorage`. | **Keep.** SSR-safety + quota-error swallowing. Used by theme and locale hooks. |
| 8 | `lib/format.ts` | 7 formatting functions, all tested. `localeOf` extracts the active locale from a `ReactLocalization`. | **Keep.** Every function is used by at least one page and tested. |
| 9 | `forms/` | Schema-driven form engine with validation, diagnostics, hints, l10n, keys, json, context. 9 files. | **Keep.** The form engine IS the product — modules need it. It's well-tested (100% coverage). |
| 10 | `package.json` deps | 13 runtime deps, 14 dev deps. No unused, no duplicate major versions. | **Clean.** |

## Summary

The codebase is lean. No findings warrant immediate changes. The most
impactful future simplification would be upgrading the locale `<select>` to
a proper combobox when real translations ship — but that's YAGNI today with
two locales.
