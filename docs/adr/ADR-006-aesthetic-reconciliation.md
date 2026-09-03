# ADR-006: Aesthetic reconciliation — shadcn/ui + catfu tokens
Status: Accepted (2026-09-03)
Deciders: project owner (approved PLAN.md 2026-09-03)

## Context

`AESTHETIC_CONTRACT.md` is the binding design contract, but it was written
for a static landing page (`index.html`), not a shadcn + Vite admin app. The
project owner also asked for shadcn/ui specifically. PLAN.md §1.4 records the
deliberate deviations needed to satisfy both; §4.4 records the resulting UI
standards.

## Decision

Use shadcn/ui primitives, themed with the catfu tokens (`--radius: 0`), with
fonts self-hosted rather than a Google Fonts link, because devices are often
offline and CSP is `font-src 'self'` (§1.4). Tokens live in
`web/src/styles/tokens.css` mapped onto shadcn's CSS variables, not in
`index.html` (§1.4). The contract's §7 hero device and §8 instrument modules
(built for the landing page) are **not** built for the admin UI; instead the
admin UI keeps the instrument-panel language through status LEDs, silk-screen
labels, hairline-zoned grids, `tabular-nums` readouts, and the rocker toggle
(§1.4, §4.4). The pre-paint theme script is an inline `<script>` allow-listed
by a CSP hash generated at build time, behaviorally identical to the
contract's approach (§1.4).

`docs/DESIGN_SEED.md` fixes the deterministic details the contract leaves
open. Seed `9f94de491806d2475883e738` (`openssl rand -hex 12`, generated
2026-09-03) selects: model number **dt-7**, revision **e**; four instrument
motifs — **hstats readout strip** (dashboard header, 5 readouts: services
active, pending commit, cert time-to-expiry, update state, uptime), **LCD
readout** (certificate panel time-to-expiry countdown, the only "screen" in
v1), **segmented VU meter** (password strength and the commit-confirm
countdown), and **CRT diagnostics panel** (the `doctor` / system-monitor
view); **ghosted-outline** section ordinals (`-webkit-text-stroke`); **inset
cutout** wordmark mark, as in catfu. Mandatory elements regardless of seed:
status bar with wordmark, LEDs, UTC clock, hardware rocker toggle,
silk-screen labels, hairline-zoned grids, `tabular-nums` readouts, lowercase
body, zero radius, mechanical motion (`docs/DESIGN_SEED.md`).

`AGENTS.md` mentions a "HeroInsight results pattern" and "Tufte chart
conventions" that the contract does not define; these are treated as not
applicable to this app, and if charts are added later they follow the
`dataviz` skill plus the contract's tokens (§1.4).

## Consequences

Positive:
- Both stated requirements are satisfied: shadcn/ui as requested, and the
  contract's look-and-feel rules (tokens, fonts, motion, LEDs) preserved.
- Self-hosted fonts and a hash-pinned inline theme script work under a strict
  offline-friendly CSP (`font-src 'self'`, `script-src 'self' 'sha256-…'`).
- The seed's determinism means any fresh session can re-derive the same
  motif choices without re-litigating them.

Negative:
- The admin UI deliberately diverges from the contract's landing-page
  patterns (§7/§8 not built); anyone applying the contract literally to this
  app will find components missing on purpose.
- Four extra bespoke instrument-motif components (hstats strip, LCD readout,
  VU meter, CRT panel) must be built and kept accessible (contrast, keyboard
  operability) beyond stock shadcn primitives.

## Alternatives considered

- Building the contract's §7/§8 hero and instrument modules as-is on the
  admin UI — rejected: those modules target a landing page, not an admin
  tool (§1.4).
- Letting the theme script run unpinned instead of CSP-hashed — rejected:
  contract fonts/CSP requirements are treated as binding; behavior is kept
  identical via a build-time hash (§1.4).

## References

PLAN.md §1.3 (ADR-006 row), §1.4, §4.4; `AESTHETIC_CONTRACT.md`;
`docs/DESIGN_SEED.md` (seed, motif derivation, and rationale for skipped
motifs — knob/fader/sequencer as physical-only, ticker as noise).
