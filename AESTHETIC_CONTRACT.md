# AESTHETIC_CONTRACT.md — "catfu"

> **Purpose.** This is the binding design contract for **catfu** (cassette‑futurism). You (the implementing model — Claude, Codex, or otherwise) did not author this visual direction; it is fixed here and realized in `index.html`. Your job is to produce UI that looks as if it came from a single, opinionated industrial designer who builds physical instruments. Do not improvise the aesthetic. Do not "modernize" it with soft shadows, rounded corners, or organic easing. Follow the rules; deviate only where this document explicitly grants latitude.
>
> **How to use.** Read the whole file before writing UI code. Treat the token block in §3 as the single source of truth for color, type, and surface values. Reference tokens by CSS variable name — never invent a color. The governing mental model is a **machined instrument panel**: every pixel is a function, a label, a control, or a lit display. When in doubt, add a label and remove a radius.
>
> **Provenance.** This language originated in `catfu/index.html` — the cobalt *cm‑1 field sampler* landing page. The blue accent palette is sampled pixel‑for‑pixel from a real device (`media/tm_4_sampler_1.jpeg.avif`); the structural rules derive from `cassette-futurism-design-language.md`. The shipped page is the reference implementation — when this document and the code disagree, flag it; don't silently pick one.

---

## 0. Design philosophy (the "why," in six lines)

1. **Constraints are the aesthetic.** Every rule below replaces an arbitrary choice with a principled one traceable to a physical origin: no border‑radius because enclosures are machined, not molded round; no gradients because matte polycarbonate and phosphor screens have none; no eased motion because mechanical switches have no easing curve.
2. **Function‑first density.** Instrument panels have no decorative whitespace — every millimeter is occupied by a control, a readout, or a silk‑screen label. Information density is a feature, not a problem to solve.
3. **Blue is the signal.** One accent — cobalt blue, sampled from the device — carries action, selection, and "lit." Amber and green survive *only* as true CRT/LED semantics (record, peak, online). There is no second decorative hue.
4. **Two material layers.** The **chassis** (page chrome) is matte and themeable; the **screens** (LCD, CRT, sequencer, readouts) are always dark and always lit. This split is the heart of catfu (§4) and is what makes light mode work.
5. **Lowercase by default.** Hierarchy comes from layout, size, and weight — not grammar. The sole exception is the silk‑screened hardware label: 3–4 character UPPERCASE mono, like the engraving on a real control.
6. **Dark‑first, light‑equal.** The default theme is the dark instrument panel. Light (a cream chassis) is a first‑class equal, never an afterthought. A hardware‑style toggle is mandatory.

---

## 1. Non‑negotiables (violating any of these is a failed task)

- **Zero border‑radius on structure.** Containers, cards, buttons, inputs, panels, the chassis itself — all hard right angles. The *only* round elements are physical rotary controls (knobs) and indicator LEDs/dots, because those are round in the world.
- **No box‑shadows for elevation, no gradients for fill.** Define zones with **1px hairline borders** in `--line` / `--line-2`. Depth on physical controls (knobs, pads, keycaps) is implied with inset/outset hairline bevels (`inset 0 1px 0 …`, `inset 0 -2px 0 …`), never a drop shadow. The *only* sanctioned gradients are the radial shading inside a rotary knob and an optional soft contact shadow under a rendered device. Screens may use flat dark fills only.
- **Tokens only.** Every color comes from §3. No new hex outside the sanctioned screen‑internal constants (§4). No second accent hue.
- **Fonts are fixed (§2):** Archivo / Archivo Expanded (display & nameplates), IBM Plex Mono (body, labels, readouts), Press Start 2P (pixel/LCD accent only). **Forbidden as primary faces:** Inter, Roboto, Arial, SF Pro, Geist, and — explicitly — **Space Grotesk** (an over‑used convergence default; do not reach for it).
- **Lowercase body.** `text-transform: lowercase` at the body level. UPPERCASE is reserved for silk‑screen labels and 3–4‑char control captions (`rec`, `play`, `clr`, `snd`).
- **Tabular numerals on every readout.** `font-variant-numeric: tabular-nums` on clocks, meters, BPM, spec values, prices — anything that updates or aligns.
- **Mechanical motion only (§9).** `steps()` and `step-end` easing; 50–80ms snaps; blink as the primary animation. No `ease-in-out`, no smooth scroll, no parallax, no shimmer. `prefers-reduced-motion` fully honored.
- **Screens stay dark in both themes.** LCD, CRT, sequencer grid, and bezel readouts never invert with the theme — pure dark is reserved for displays, and their lit text uses the always‑bright screen tokens (`--screen-blue`, `--amber`, `--green`).
- **Accessibility floor:** WCAG AA contrast on all text (§11) — small text (<18px) ≥ 4.5:1, verified via bounding‑rect color math, not eyeballed; visible focus state; full keyboard operability; theme set before paint to avoid flash.

---

## 2. Typography

```
Display / nameplates / device legends:  'Archivo Expanded' (800/900) and 'Archivo' (500–700)
                                        fallback: system-ui, sans-serif
Body / labels / readouts / UI:          'IBM Plex Mono' (300/400/500/600)
                                        fallback: ui-monospace, 'SF Mono', monospace
Pixel / LCD accent:                     'Press Start 2P'  (LCD tags & CRT titles only)
```

Loaded via a single Google Fonts `<link>`. `IBM Plex Mono` at weight **300** is the spiritual match to a light narrow grotesque silk‑screen and is the *default body face* — set the whole page in it, lowercase.

| Role | Face | Size | Weight | Notes |
|---|---|---|---|---|
| Hero designation (the device name) | Archivo Expanded | clamp(56px, 9vw, 128px) | 900 | lowercase, line‑height **0.86**, letter‑spacing −0.03em |
| Section title (h2) | Archivo | clamp(22px, 3vw, 34px) | 700 | lowercase, −0.02em |
| Sub‑headline / lede | Archivo | clamp(15px, 1.6vw, 19px) | 500 | the one place body copy leaves mono, for voice |
| Module / card title (h3) | Archivo | 16–18px | 700 | lowercase, −0.01em |
| Spec value / big readout | Archivo Expanded | 30–40px | 700 | `tabular-nums`, line‑height 1; unit suffix in mono |
| Body / paragraph | IBM Plex Mono | 12–14px | 300–400 | lowercase, line‑height 1.4–1.55 |
| **Silk‑screen label** (`.lbl`) | IBM Plex Mono | **9px** | 400 | **UPPERCASE**, letter‑spacing 0.14–0.16em, `--ink-dim`, `user-select:none` |
| Readout / clock / meter value | IBM Plex Mono | 12–18px | 400 | `tabular-nums`, letter‑spacing 0.04–0.06em |
| Control caption | IBM Plex Mono | 9–11px | 400 | UPPERCASE, 0.1em, 3–4 chars where possible |
| LCD tag / CRT title | Press Start 2P | 6–8px | — | screen tokens only, with glow `text-shadow` |
| Big section ordinal ("01") | Archivo Expanded | 13–40px | 800–900 | accent or ghosted outline (`-webkit-text-stroke`) |

Archivo Expanded is reserved for *nameplate voice* (the hero device name, spec values, big ordinals). Everything operational — labels, readouts, controls, body — is IBM Plex Mono. Never set body paragraphs in Archivo Expanded; never set a readout in anything but mono.

---

## 3. Design tokens — single source of truth

Defined once on `:root, html[data-theme="dark"]` and overridden on `html[data-theme="light"]`. **Dark first, light second.** The blue system is sampled from the device and does not change meaning across themes.

```css
/* ── SURFACES (chassis — themeable) ───────────────────────────── */
--bg        #121316  /  #ece7dc   page base (dark panel / aged cream chassis)
--chrome    #0e0f11  /  #f4f0e7   status bar, ticker, footer (distinct from bg)
--panel     #1a1a18  /  #f6f2ea   primary panel surface
--panel-2   #202123  /  #fbf8f1   raised: buttons, inputs, hover
--panel-3   #2a2b2e  /  #ffffff   highest raise / active hover

/* ── INK (contrast‑tuned to Apple HIG / WCAG AA) ──────────────── */
--ink       #efece5  /  #1a1a18   primary text          (never pure #fff/#000)
--ink-dim   #b2b2ac  /  #54544d   secondary copy & labels   (≥5.8 / ≥6.2 :1)
--ink-faint #909089  /  #61615a   smallest labels & fine print (≥5.8 / ≥5.1 :1)
--line      #303134  /  #cfc9bb   hairline zone borders
--line-2    #43444a  /  #b3ac9b   emphasized / hover borders
--alu       #d4d4d4  /  #6b6b62   brushed‑aluminium structural tone

/* ── BLUE SYSTEM (sampled from the device) ────────────────────── */
--blue        #3282cc / #1f6fb8   primary accent: CTA, active, selected
                                  (dark lightened from the sampled #2e7dc4 —
                                   see the note under §11)
--blue-bright #5fb0f0 / #145ea6   chrome text accent: numbers, section nums, links
                                  (adapts per theme so it stays readable on the page)
--blue-core   #235594 / #235594   signature CHASSIS blue (the device body) — fixed
--blue-deep   #15364f / #15364f   navy fill / ghost ordinals — fixed
--blue-dim    #2a5e93 / #4a6e93   secondary blue, dim controls
--cyan        #58c8df / #58c8df   keycap cyan, rare cool highlight — fixed
--cta-ink     #04101c / #f6fbff   text ON a blue fill (dark‑on‑blue / light‑on‑blue)

/* ── LIT TOKENS (displays & LEDs — ALWAYS BRIGHT, both themes) ─── */
--screen-blue #6bb6f5 (both)      lit readouts, beat markers, active sequencer cells, blue LEDs
--amber       #ff6a00 (both)      rec indicator, VU peak, CRT phosphor, alert LED
--green       #36e27b (both)      online / ready / VU low LED
--brass       #c9a24b (both)      keycap edge / warm metal accent (rare)

/* ── BACKGROUND TEXTURE ───────────────────────────────────────── */
--scan  rgba(255,255,255,.012) / rgba(0,0,0,.018)   1px scanline
--dot   rgba(95,176,240,.05)   / rgba(35,85,148,.07) PCB dot‑grid

/* ── METRICS ──────────────────────────────────────────────────── */
--grid 8px        --maxw 1320px
```

**Why two blue tokens.** `--blue-bright` is page‑chrome text — it *darkens* in light mode (`#145ea6`) to stay ≥4.5:1 on cream. `--screen-blue` is for things inside the always‑dark screens and for lit LEDs — it must stay bright in *both* themes or indicators go muddy on cream. Never use `--blue-bright` inside a screen; never use `--screen-blue` for page body text.

---

## 4. The two‑layer surface model (catfu's core idea)

Every surface is either **chassis** or **screen**. This is what lets light mode exist without betraying the aesthetic.

**Chassis** (themeable): the page itself — `--bg`, `--chrome`, `--panel*`, with `--ink*` text and `--line*` borders. Dark = matte black instrument panel; light = aged cream/aluminium. The rendered device body is chassis too, but pinned to `--blue-core` in both themes (it's a blue object photographed on any background).

**Screen** (never themed): the LCD, the CRT diagnostics, the sequencer grid, and any inset readout. These keep fixed dark constants regardless of theme, because "pure black is reserved for display/screen elements only."

Sanctioned screen‑internal constants (the *only* hex allowed outside §3):

```
LCD            bg #06121f  border #0a3252   text --screen-blue (glow), amber peaks
CRT panel      bg #080705  border #1c150a   text --amber, highlights #ffb066
  scanline overlay: repeating-linear-gradient(rgba(255,106,0,.04) 0 1px, transparent 1px 3px)
Sequencer box  bg #0c0d0f  border --line-2
  step cell    #15171a  border #232427 ; beat divider #34363a
  step.on      bg --screen-blue  border #9fd4ff ; .on.play bg #9fd4ff + screen-blue glow
  inner text   row names #9a9b95 ; ruler nums #73746f ; labels #9a9b95 / dim #74756f
BPM readout    bg #06121f  border #0a3252  text --screen-blue + glow
```

When you build a new screen element, copy these constants — do **not** wire its text to `--ink*` (it would vanish on the dark screen in light mode).

---

## 5. Spacing & layout

- **8px base grid** (4px for fine control gaps). Strict scale, no in‑between values: `4 · 8 · 12 · 16 · 24 · 32`. Padding is functional clearance, not breathing room.
- **Flush, edge‑to‑edge composition.** Everything snaps to a column grid; nothing floats or loosely centers. Sections are full‑bleed with an inner `.wrap` (`max-width: var(--maxw); padding: 0 24px`).
- **Hairline zoning.** Grids are 1px‑separated cells (`border-right` / `border-bottom` on each cell, stripped on the last column/row). Spec grid, hero stat strip, feature columns, order table all follow this. Cells `:hover` shift to `--panel`, never to a new hue.
- **Dense panels over airy ones.** Spec cells are ~128px min‑height with a corner index (`[01]`), an UPPERCASE label, and a large Archivo Expanded value bottom‑anchored (`margin-top:auto`). Mimic an instrument readout, not a marketing card.
- **Responsive reflow** at ~980 / 880 / 820 / 780 / 560 / 520 / 460px (match the page). Multi‑column grids collapse to 2‑up then 1‑up; the rendered device sheds its non‑essential columns (right block, grille) below 560px rather than shrinking illegibly. Verify 375 / 768 / 1280px.

---

## 6. Components (match `index.html`; don't invent parallel ones)

- **Status bar / function‑key row** — sticky top, `--chrome` background, `--line-2` bottom border, fixed 38px height. Horizontal `.seg` cells divided by 1px `--line`. Holds the wordmark, status LEDs, lowercase nav, a live UTC clock, and the theme toggle. No hamburger, no dropdown — flat label row like a synth function strip. Nav links snap to `--blue` fill + `--cta-ink` on hover; active link is `--blue-bright`.
- **Wordmark mark** — a solid `--blue` square with a `--chrome`‑colored inset cutout (`::after`, `inset:4px`). Hard‑edged, geometric.
- **Button (`.btn`)** — `--panel-2` fill, 1px `--line-2`, **radius 0**, `transition:none` (snap). Caption 11px UPPERCASE, 0.1em tracking. Grouped buttons share an edge (`border-left:none` on the joint). `.primary` = `--blue` fill + `--cta-ink`; `:hover` → `--blue-bright`; `:active` → `translateY(1px)` (a physical press).
- **Tiny button (`.tinybtn`)** — 9px UPPERCASE module control (play/clr/rnd/snd, ±). `.on` state = `--blue` fill + `--cta-ink`.
- **Knob** — circular, radial‑shaded `--blue-core` body with hairline bevels and a `--screen-blue`/white indicator line; the *whole knob* is `rotate(var(--rot))` so the indicator tracks position. The one place a radial gradient and a circle are allowed.
- **Fader** — narrow dark track (`#0c2438`) with a rectangular bevelled cap; `ns-resize` cursor; cap position is a `top:%`.
- **VU meter** — segmented, never a continuous bar. Discrete `.seg` cells: low = `--green`, mid = `--screen-blue`, peak = `--amber`; unlit = dark. Gap 2px.
- **Silk‑screen label (`.lbl`)** — see §2; the universal annotation. `.dim` variant uses `--ink-faint`. On a screen, use the fixed screen grays instead.
- **Theme toggle (the rocker)** — see §10. A hardware slide switch, top‑right of the status bar.
- **Ticker / marquee** — `--chrome` strip, 10px UPPERCASE items separated by an amber `✳`, scrolling `linear` and infinite (duplicate the track in JS for a seamless loop; pause under reduced motion).
- **LED** — 7px square (not round unless a status dot), unlit `--ink-faint`; lit variants glow via matching `box-shadow`: `.on` green, `.rec` amber (blinking), `.blue` `--screen-blue`. A lit LED must glow in both themes.
- **Spec / feature / order grids** — hairline‑zoned cells (§5). Order pricing uses Archivo Expanded with a superscript `--blue-bright` currency mark.
- **Footer** — `--chrome`, dense link columns under UPPERCASE `.lbl` headers, closing with a fine‑print legal block (9px `--ink-faint`) echoing real hardware spec sheets ("all specifications subject to change…").

---

## 7. The hero device pattern (the showpiece)

Every catfu landing surface leads with **one instrument rendered entirely in CSS/HTML** — no product photo. The cobalt cm‑1 in `index.html` is the reference: a `--blue-core` chassis with bevel insets, laid out as a CSS grid of functional columns:

```
[ pad grid 2×4 ] [ LCD + two knobs ] [ fader ] [ big knob + VU ] [ speaker grille ]
```

Rules:
- The chassis is `--blue-core` in **both** themes (it pops on dark and on cream).
- Controls are real components from §6 (pads, knobs, fader, VU, LCD), not images.
- Tiny on‑device legends use a fixed light‑blue (`#bcd9f5`) at 7px UPPERCASE — silk‑screen on a blue body, not `--ink`.
- The device sits on a `device-stage` with a single soft blurred contact shadow (the one sanctioned shadow).
- Below 560px the device drops its right block and grille rather than scaling to mush.

Pair the device with: a `kicker` row of bordered tag chips (model · class · revision), the Archivo Expanded **designation**, an Archivo lede, a snap CTA row, and a hairline `hstats` strip of four headline readouts. This is the catfu analog of a hero — the instrument *is* the hero.

---

## 8. Interactive instrument modules

Static beauty is not enough — a catfu page proves it is an instrument by **working**. Build at least one live module; the reference page ships four.

- **16‑step sequencer** — a 4‑voice × 16‑step LED grid on a dark screen. Cells toggle on click (`--screen-blue` lit). A playhead column sweeps in discrete steps (interval = `60000 / bpm / 4`), lighting `.play`; transport = play/stop, clr, rnd, and a BPM readout with ± controls. Ship a tasteful seeded pattern so it looks alive before interaction. Optional Web Audio voices (kick/snare/hat/perc via oscillators) behind a default‑**off** `snd` toggle — never autoplay sound.
- **LCD equalizer** — a `<canvas>` dot‑matrix in the device. Render discrete blocks (no anti‑aliased curves); columns ease toward random targets; top rows peak amber, body `--screen-blue`/cyan on `#06121f`. Freeze to a static frame under reduced motion.
- **VU meter** — stepped random walk on a JS interval (~140ms), occasional full peak. Discrete segments only.
- **CRT diagnostics** — an amber‑phosphor sub‑panel (`#080705`) with a scanline overlay, dotted‑rule key/value rows, a Press Start 2P title, a live‑updating readout block, and a blinking block cursor (`█`). This is where amber lives.
- **Ambient life** — a live UTC clock and a drifting fader keep the panel feeling powered‑on.

All of these read off `requestAnimationFrame` or `setInterval` and must no‑op (or render one static frame) under `prefers-reduced-motion`.

---

## 9. Motion

Animation is **mechanical, not biological** — a relay clicking, a switch toggling, a terminal redraw.

- **Easing:** `linear`, `steps(n)`, or `step-end` only. **Never** `ease`, `ease-in-out`, or a cubic‑bezier. State changes on controls are instant (`transition: none`) or ≤80ms.
- **Blink is the primary animation** — LEDs, cursors, rec dots: `@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.12} }` at `step-end`.
- **Entrance:** a single stepped clip‑reveal — `clip-path: inset(0 100% 0 0)` → `inset(0 0 0 0)` via `steps(7,end)` ~0.35s, staggered with `animation-delay` across hero elements. A ratcheting swipe, never a smooth fade‑slide.
- **Marquee:** `transform: translateX` `linear` infinite; duplicate content for a seamless loop.
- **No smooth scroll** (`scroll-behavior: auto`), no parallax, no float, no shimmer loaders, no bounce.
- **`prefers-reduced-motion: reduce`** → reveals appear instantly (`clip-path:none; opacity:1`), the ticker stops, the LCD paints one static frame, JS loops should bail. Honor it everywhere.

---

## 10. Theme system & the toggle

- **Default dark.** Set `data-theme` on `<html>` **before paint** via a tiny inline script in `<head>`: read `localStorage['cobalt-theme']`, else fall back to `prefers-color-scheme`, else `dark`. This prevents a flash. Persist the user's choice to `localStorage`.
- **The toggle is a hardware rocker**, top‑right in the status bar, fitting the chassis: a bordered `--panel-2` track, ~56×22px, with a sliding `--blue` knob and two glyph cells (`☾` left, `☀` right). The knob sits left for dark, right for light (`html[data-theme="light"] .tog-knob { left:auto; right:1px }`); the active glyph flips to `--cta-ink`. Snap, no transition. Labeled `mode` with a `.lbl`. It is the catfu equivalent of a panel switch — never a generic pill toggle, never a sun/moon icon button floating off‑grid.
- **Light mode is a real design, not an inversion.** Cream chassis, aluminium hairlines, near‑black ink, the blue device unchanged. Screens stay dark and lit (§4). LEDs and screen tokens stay bright. Re‑check the whole page in light deliberately — borders, LED glow, screen text — not just the hero.

---

## 11. Contrast & legibility (Apple HIG)

Apple HIG favors high contrast and clear legibility; catfu's dense small labels make this load‑bearing. The `--ink-dim` / `--ink-faint` tokens in §3 are tuned so **all small text clears WCAG AA (≥4.5:1)**. Measured against the shipped page:

| Element | Size | Dark | Light |
|---|---|---|---|
| body / lede | 14–19px | 8.7:1 | 6.2:1 |
| feature copy | 12px | 8.7:1 | 6.2:1 |
| spec description | 10px | 5.8:1 | 5.1:1 |
| section meta / labels | 9px | 5.8:1 | 5.1:1 |
| legal fine print | 9px | 6.0:1 | 5.5:1 |
| CRT phosphor (screen) | 11px | 7.0:1 | 7.0:1 |
| sequencer row name (screen) | 9px | 6.9:1 | 6.9:1 |

Rules of thumb: never drop `--ink-faint` below the §3 values "to look more subtle"; screen text uses the fixed bright screen tokens (so it stays high‑contrast in both themes); a lit LED/indicator must glow in both themes (use `--screen-blue` / `--amber` / `--green`, never the theming `--blue-bright`). Verify ratios with bounding‑rect color math, not by eye.

**Two corrections from the first machine audit** (`web/scripts/contrast-check.ts`, which now computes every pairing below and gates CI). The table above was written from the elements the reference page renders, so two pairings it never listed had never been measured — and both were under the floor:

- **`--cta-ink` on `--blue`, dark: was 4.42:1.** This is the §6 primary‑button caption, so the contract mandated a pairing that missed its own AA floor. Dark `--blue` is lightened from the sampled `#2e7dc4` to **`#3282cc`**, which scores **4.74:1**. This is a deliberate, minimal departure from the pixel‑sampled accent, taken in preference to darkening `--cta-ink` (which reached only 4.60:1) because the decision rule was to take the higher contrast. `--blue-core`, the rendered device chassis, is untouched — the device's own blue keeps its provenance.
- **`--ink-faint` on `--panel-3`, dark: 4.41:1.** Resolved by **prohibition, not by moving a token** — darkening `--ink-faint` would cost the intended fine‑print dimness on the four surfaces where it already passes. `--panel-3` (highest raise / active hover) must never carry `--ink-faint` text; use `--ink-dim` (6.64:1) there. `contrast-check.ts` scans `src/` and fails if anything starts using the pairing, so this is enforced rather than remembered.

---

## 12. Anti‑patterns — DO NOT

- ❌ Add `border-radius` to any container, card, button, input, or panel. Round is for knobs and dots only.
- ❌ Use a box‑shadow for elevation, or a gradient for a fill (knob radial + one device contact shadow are the sole exceptions).
- ❌ Introduce a second accent hue, or use amber/green/blue as decoration instead of meaning.
- ❌ Reach for Space Grotesk, Inter, Roboto, SF Pro, or any non‑mono face for body/labels.
- ❌ Set body text in UPPERCASE, or set labels/readouts in anything but IBM Plex Mono.
- ❌ Theme a screen (LCD/CRT/sequencer) with the page, or wire screen text to `--ink*` (it vanishes on cream).
- ❌ Use `--blue-bright` inside a dark screen, or `--screen-blue` for page body text.
- ❌ Use `ease`/`ease-in-out`/cubic‑bezier, smooth scroll, parallax, float, or shimmer.
- ❌ Pure `#000`/`#fff` for chassis text or background — use the §3 off‑tones (screens may use near‑black).
- ❌ Ship a static page with no working instrument module, or autoplay audio.
- ❌ Build the hero from a product photo instead of a CSS‑rendered device.
- ❌ Float the theme toggle off‑grid or render it as a generic switch/icon button.
- ❌ Let a default theme flash on load (always set `data-theme` before paint).
- ❌ Invent a parallel component when §6 already defines one.

---

## 13. Compliance checklist (run before declaring done)

- [ ] Zero `border-radius` on structure; only knobs/LEDs are round. No elevation shadows; zones defined by 1px hairlines.
- [ ] Every color maps to §3 (or a sanctioned screen constant from §4). No second accent hue; amber/green/blue carry meaning only.
- [ ] Archivo Expanded for nameplates/values, Archivo for titles/lede, IBM Plex Mono for everything else; Press Start 2P confined to LCD/CRT. No Space Grotesk.
- [ ] Body is lowercase; UPPERCASE only on silk‑screen labels and 3–4‑char captions. `tabular-nums` on all readouts.
- [ ] Two‑layer model honored: chassis themes, screens stay dark and lit in both themes; screen text uses fixed screen tokens.
- [ ] Dark is default; the hardware rocker toggle works, persists, and `data-theme` is set before paint (no flash). Light mode re‑checked deliberately (borders, LED glow, screen text).
- [ ] All small text ≥4.5:1 in both themes (verify via bounding‑rect color math, per §11); lit LEDs glow in both themes.
- [ ] Hero is a CSS‑rendered device (§7); at least one interactive instrument module works (§8); no autoplay sound.
- [ ] Motion is `steps()`/`step-end`/`linear` only, ≤80ms snaps, blink for indicators; `prefers-reduced-motion` stops marquee, freezes LCD, snaps reveals.
- [ ] Hairline‑zoned grids strip last‑column/row borders; cells hover to `--panel`, not a new hue.
- [ ] 375 / 768 / 1280px verified; the device sheds columns below 560px rather than shrinking illegibly.

---

## 14. Where things live

| Concern | Home in `index.html` |
|---|---|
| Token definitions | `:root, html[data-theme="dark"]` and `html[data-theme="light"]` blocks at the top of `<style>` |
| Screen constants | inline in `.lcd`, `.crt`, `.seq`, `.bpm .display` rules (§4) |
| Pre‑paint theme set | inline `<script>` immediately after `<title>` |
| Toggle behavior | `.tog` CSS in the status‑bar section + the toggle `<script>` |
| Instrument logic | per‑module IIFEs at the bottom: LCD canvas, VU, fader, CRT, 16‑step sequencer, clock, scroll‑spy |
| Accent provenance | sampled from `media/tm_4_sampler_1.jpeg.avif`; structural rules from `cassette-futurism-design-language.md` |

Preview for visual checks: `.claude/launch.json` serves the page (the repo uses a static server on port 8731). When this contract and `index.html` disagree, fix the contract or the code deliberately — never let them drift.
