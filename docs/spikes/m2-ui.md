# Milestone M2 — the console is usable behind a bootstrap cert

**Date:** 2026-09-17 · **Phase 5** (`docs/PLAN.md` §5, Phase 5) ·
**Acceptance:** web UI usable behind a bootstrap cert: sign in, read modules
and host state, plan and apply a change with commit-confirm, read audit.

**What was shown:** the built console (`bun run build` → `vite preview` on
`web/dist`, the exact bytes `detent-web`'s `ui` feature embeds) against a
stubbed API shaped by `docs/openapi.json` (`web/e2e/api.ts`). The binary's
own HTTP surface is covered by the Rust suite, including the assembled
router; what needs a browser is the front end, so the stub keeps these runs
hermetic and off `/etc/hosts`. E2e against the *real binary* stays deferred
per PLAN §5: it needs a host whose `/etc/hosts` may be written.

## Evidence

| Check | Command | Result |
|---|---|---|
| Unit | `cd web && bun run coverage:check` | 72 in-scope files at 100% lines (only `src/components/ui/button.tsx` + `tooltip.tsx` excluded, named in `web/scripts/coverage-check.ts`) |
| Lint | `cd web && bun run lint` | clean (biome) |
| Types | `cd web && bun run typecheck` | clean |
| i18n | `cd web && bun run i18n:check` | 247 ids, all referenced, all resolved |
| Contrast | `cd web && bun run contrast:check` | every pairing ≥ 4.5:1, both themes |
| API drift | `cd web && bun run api:check` | `schema.d.ts` matches `docs/openapi.json` |
| E2e | `cd web && bun run e2e` | 22 passed (console + axe suites) |
| Responsive | throwaway `noOverflow` spec (deleted after use) | 390 / 1280 pass; see below |

Screenshots below are from the stubbed preview bundle at 1280px (dashboard,
module detail) and 390px (sign-in). They were captured to `/tmp` by a
throwaway Playwright spec (`web/e2e/m2shots.e2e.ts`, removed after the run),
viewed, and described here rather than checked in — the permanent suite
(`web/e2e/console.e2e.ts`, `a11y.e2e.ts`) is the regression record, not stills.

## What this demonstrates

- **Sign-in works, including the second factor.** `LoginPage` posts
  username + password through the real form; the TOTP field appears on
  request and after the first refusal (`web/src/routes/LoginPage.tsx`). A
  read-only session is told why it cannot apply, and is blocked from doing
  so (`e2e/console.e2e.ts`: "a read-only session cannot apply").
- **The dashboard reads host state.** Hostname, OS, init, distro, memory,
  network/resolver backends, detection notes, module count, recent audit —
  all from `GET /api/v1/system/profile` + `/audit` (`/tmp/m2-dashboard-1280.png`).
- **Module pages plan and apply.** Schema-driven form (`src/forms/`),
  validate → plan (unified diff + upstream checks + affected services) →
  apply with service action → commit-confirm countdown (`PendingCommitSlot`).
  The plan dialog returns focus to the control that opened it; the apply
  dialog shares `serviceLabels.ts` with the services page.
- **Host text survives the stylesheet.** The body is `text-transform:
  lowercase`, so every host-supplied string (unit names, paths, digests,
  diffs) renders inside `.read` / `.readout` / `.verbatim` opt-outs.
  `NetworkManager` stays `NetworkManager`; the plan diff is the bytes that
  would be written (`e2e/console.e2e.ts`: "host text survives the
  stylesheet", `/tmp/m2-module-1280.png` shows mixed-case values intact).
- **Keyboard and focus hold.** Focus moves into the dialog on open and back
  to the trigger on close; the full apply flow runs keyboard-only; the modal
  no longer restores focus to `document.body` (`Modal.tsx`,
  `ModuleDetailPage.tsx`).
- **Both themes hold.** `contrast:check` proves the tokens clear 4.5:1;
  axe-core over every section in both themes proves the composed pairings do
  (`e2e/a11y.e2e.ts`, WCAG 2.2 AA). The default is dark, not the OS
  preference (`theme.ts` + `theme-init.js`, byte-identical via
  `build-finish.ts` and pinned in `headers.rs` CSP).
- **390px fits.** The four fixed nowrap status segments overflowed
  (`scrollWidth` 487 > 390). Below 560px the segments tighten to 8px padding
  and the verbose online label hides — the LED still reports it
  (`index.css`, `StatusBar.tsx` `online-label`, regression test in
  `StatusBar.test.tsx`). Verified by the throwaway `noOverflow` run:
  dashboard + module @1280 and login @390 all pass
  (`/tmp/m2-dashboard-1280.png`, `/tmp/m2-module-1280.png`,
  `/tmp/m2-login-390.png`).

## Deliberately not shown

- **Certificates / settings sections** are named placeholders
  (`src/routes/pages.tsx`): neither has an API to drive. Certificates waits
  on Phase 6 (ACME); settings needs user/token endpoints that do not exist.
- **Real-binary browser run** stays deferred per PLAN §5 (see above).
- **Pseudo-locale + language switcher**: still open (only `en-US` ships;
  `src/i18n/index.tsx` `AVAILABLE_LOCALES`). Next slice after this demo.
