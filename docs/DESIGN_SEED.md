# Design seed

Seed (generated 2026-09-03, `openssl rand -hex 12`):

```
9f94de491806d2475883e738
```

The seed picks *which* instrument motifs from the catfu reference page
(`~/projects/frontend-styles/catfu/index.html`, the reference implementation of
`AESTHETIC_CONTRACT.md`) the detent admin UI adopts, and the nameplate details.
It never changes tokens, fonts, motion rules, or anything the contract fixes.
Derivations are deterministic so a fresh session can re-check them.

Bytes: `9f 94 de 49 18 06 d2 47 58 83 e7 38`

| Byte(s) | Rule | Result |
|---|---|---|
| `9f` = 159 | model number = (b % 9) + 1 | **dt-7** |
| `94` = 148 | revision = letter[(b % 6)] of a–f | **rev. e** |
| `de 49 18 06 d2 47 58` | motif = candidates[b % 11], skip duplicates and physical-only controls (knob, fader, sequencer), take first four | see below |
| `83` = 131 | section ordinal style: 0 = solid accent, 1 = ghosted outline (`-webkit-text-stroke`) | **ghosted outline** |
| `e7` = 231 | wordmark mark: 0 = inset cutout, 1 = double inset, 2 = offset notch | **inset cutout** (as catfu) |
| `38` = 56 | dashboard readout count on the hstats strip = 3 + (b % 3) | **5 readouts** |

Motif candidates (index): 0 CRT diagnostics panel · 1 ticker · 2 hstats readout
strip · 3 spec grid cells · 4 sequencer grid · 5 segmented VU meter · 6 LCD
readout · 7 knob · 8 fader · 9 big ordinals · 10 kicker chips.

Draw: `de`→2 hstats · `49`→7 knob (skipped, physical control) · `18`→2 (dup) ·
`06`→6 LCD · `d2`→1 ticker (skipped: a marquee is noise in an admin tool and
fails "every element earns its place") · `47`→5 VU · `58`→0 CRT.

## What the UI adopts

Mandatory from the contract regardless of seed: status bar with wordmark, LEDs,
UTC clock, hardware rocker toggle; silk-screen labels; hairline-zoned grids;
`tabular-nums` readouts; lowercase body; zero radius; mechanical motion.

Seed-selected motifs and where they live:

1. **hstats readout strip** — dashboard header: 5 readouts (services active,
   pending commit, cert time-to-expiry, update state, uptime).
2. **LCD readout** — certificate panel: the time-to-expiry countdown is a dark
   always-lit LCD (`#06121f` / `--screen-blue`), the only "screen" in v1.
3. **Segmented VU meter** — password strength on setup/user forms and the
   commit-confirm countdown (discrete segments draining, `--amber` at the end).
4. **CRT diagnostics panel** — the `doctor` / system-monitor view (amber
   phosphor, dotted key/value rows, blinking block cursor).

Nameplate: login page designation **detent.** in Archivo Expanded; kicker chips
`dt-7` · `config console` · `rev. e`. Section heads use ghosted-outline ordinals.
Spec-grid cells are the module overview (one cell per module: index, name,
backend, upstream version, status LED).
