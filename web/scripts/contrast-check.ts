#!/usr/bin/env bun
/**
 * contrast-check — WCAG 2.1 contrast audit of the catfu design tokens.
 *
 * Parses web/src/styles/tokens.css, resolves the dark and light token sets
 * (light inherits every token it does not override), and computes the WCAG 2.1
 * relative-luminance contrast ratio for every ink-on-surface pairing the admin
 * UI actually renders. Prints one row per pairing and exits non-zero if any
 * pairing falls below the AA small-text floor, so it can gate CI.
 *
 * It also enforces the pairings that are resolved by prohibition rather than
 * by a token change: --ink-faint on --panel-3 is below the floor and is simply
 * never to be used, so the audit scans src/ and fails if anything starts using
 * it. See FORBIDDEN_PAIRINGS for the list and the limits of that scan.
 *
 * The screen pairings use the AESTHETIC_CONTRACT.md §4 constants imported from
 * src/styles/screen-constants.ts — the same module the Screen component uses,
 * so the audit cannot drift from the rendered surface.
 *
 * Usage:
 *   bun run contrast:check              audit every pairing, table + summary
 *   bun run contrast:check -- --verbose show parsed tokens and luminances
 *   bun run contrast:check -- --help    print this usage block
 *
 * CLI switches:
 *   --verbose, -v   Emit the resolved token table for each theme and the
 *                   relative luminance of both colors in every pairing.
 *   --help, -h      Print usage and exit 0.
 *
 * Exit codes:
 *   0  every pairing meets the small-text floor
 *   1  at least one pairing is below the floor
 *   2  the token file could not be parsed (missing block or token)
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SCREEN_BG } from '../src/styles/screen-constants.ts'

// ── thresholds (AESTHETIC_CONTRACT.md §1 "accessibility floor" / §11) ────────

/** WCAG 2.1 SC 1.4.3 AA floor for text below 18px — the catfu label size. */
const AA_SMALL_TEXT_RATIO = 4.5

/** sRGB channel value below which the linearization is the linear branch. */
const SRGB_LINEAR_CUTOFF = 0.04045
const SRGB_LINEAR_DIVISOR = 12.92
const SRGB_GAMMA_OFFSET = 0.055
const SRGB_GAMMA_SCALE = 1.055
const SRGB_GAMMA_EXPONENT = 2.4

/** CIE luminance coefficients used by WCAG 2.1. */
const LUMA_R = 0.2126
const LUMA_G = 0.7152
const LUMA_B = 0.0722

/** WCAG contrast formula constant: (L1 + 0.05) / (L2 + 0.05). */
const CONTRAST_OFFSET = 0.05

const EXIT_OK = 0
const EXIT_FAIL = 1
const EXIT_PARSE_ERROR = 2

/**
 * Resolved lazily: under the vitest runner `import.meta.url` is not a `file:`
 * URL, and the pure helpers below must stay importable from the test suite.
 */
function tokensPath(): string {
  return fileURLToPath(new URL('../src/styles/tokens.css', import.meta.url))
}

// ── color math ───────────────────────────────────────────────────────────────

export type Rgb = { r: number; g: number; b: number }

/** Parses `#rgb` / `#rrggbb`. Returns null for anything else (var(), rgba(), …). */
export function parseHex(value: string): Rgb | null {
  const hex = value.trim().replace(/^#/, '')
  if (!/^([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(hex)) return null
  const full =
    hex.length === 3
      ? hex
          .split('')
          .map((c) => c + c)
          .join('')
      : hex
  return {
    r: Number.parseInt(full.slice(0, 2), 16),
    g: Number.parseInt(full.slice(2, 4), 16),
    b: Number.parseInt(full.slice(4, 6), 16),
  }
}

function linearize(channel8Bit: number): number {
  const c = channel8Bit / 255
  return c <= SRGB_LINEAR_CUTOFF
    ? c / SRGB_LINEAR_DIVISOR
    : ((c + SRGB_GAMMA_OFFSET) / SRGB_GAMMA_SCALE) ** SRGB_GAMMA_EXPONENT
}

/** WCAG 2.1 relative luminance of an sRGB color. */
export function relativeLuminance(color: Rgb): number {
  return LUMA_R * linearize(color.r) + LUMA_G * linearize(color.g) + LUMA_B * linearize(color.b)
}

/** WCAG 2.1 contrast ratio between two hex colors; 21 for #000 vs #fff. */
export function contrastRatio(foreground: string, background: string): number {
  const fg = parseHex(foreground)
  const bg = parseHex(background)
  if (fg === null || bg === null) {
    throw new Error(`contrast-check: not a hex color: "${fg === null ? foreground : background}"`)
  }
  const lighter = Math.max(relativeLuminance(fg), relativeLuminance(bg))
  const darker = Math.min(relativeLuminance(fg), relativeLuminance(bg))
  return (lighter + CONTRAST_OFFSET) / (darker + CONTRAST_OFFSET)
}

// ── token parsing ────────────────────────────────────────────────────────────

export type TokenSet = Record<string, string>

/** Extracts the `--name: value` declarations of the first block matching `selector`. */
export function parseBlock(css: string, selector: RegExp): TokenSet | null {
  const match = selector.exec(css)
  if (match === null) return null
  const start = css.indexOf('{', match.index)
  const end = css.indexOf('}', start)
  if (start === -1 || end === -1) return null
  const body = css.slice(start + 1, end)

  const tokens: TokenSet = {}
  for (const declaration of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
    const name = declaration[1]
    const value = declaration[2]
    if (name === undefined || value === undefined) continue
    const hex = parseHex(value)
    if (hex !== null) tokens[name] = value.trim()
  }
  return tokens
}

/**
 * Resolves both theme token sets. The light block only overrides part of the
 * palette (the lit tokens deliberately do not change), so it inherits dark.
 */
export function parseThemes(css: string): { dark: TokenSet; light: TokenSet } | null {
  const dark = parseBlock(css, /:root,\s*html\[data-theme="dark"\]\s*\{/)
  const lightOverrides = parseBlock(css, /^html\[data-theme="light"\]\s*\{/m)
  if (dark === null || lightOverrides === null) return null
  return { dark, light: { ...dark, ...lightOverrides } }
}

// ── the pairings the UI actually renders ─────────────────────────────────────

const INKS = ['--ink', '--ink-dim', '--ink-faint'] as const
const SURFACES = ['--bg', '--chrome', '--panel', '--panel-2', '--panel-3'] as const

type Pairing = {
  /** Human-readable pairing name for the table. */
  name: string
  foreground: string
  background: string
}

/**
 * Chassis pairings: every ink token over every themeable surface, plus the
 * blue system's two text roles. `--cta-ink` on `--blue` is the button caption;
 * `--blue-bright` is page-chrome text (§3) and only ever sits on --bg/--panel.
 */
function chassisPairings(tokens: TokenSet): Pairing[] {
  const pairings: Pairing[] = []
  for (const ink of INKS) {
    for (const surface of SURFACES) {
      // Forbidden pairings are governed by `findForbiddenUsages`, not by a
      // ratio row: they are known to be below the floor, and listing them
      // here would make the audit permanently red instead of enforcing the
      // rule that nothing may use them.
      if (isForbidden(ink, surface)) continue
      pairings.push({ name: `${ink} on ${surface}`, foreground: ink, background: surface })
    }
  }
  pairings.push({ name: '--cta-ink on --blue', foreground: '--cta-ink', background: '--blue' })
  pairings.push({
    name: '--blue-bright on --bg',
    foreground: '--blue-bright',
    background: '--bg',
  })
  pairings.push({
    name: '--blue-bright on --panel',
    foreground: '--blue-bright',
    background: '--panel',
  })
  return pairings.map((pairing) => ({
    name: pairing.name,
    foreground: tokens[pairing.foreground] ?? '',
    background: tokens[pairing.background] ?? '',
  }))
}

/**
 * Screen pairings (§4). These are theme-invariant by construction — both the
 * lit tokens and the screen constants are fixed — but they are evaluated in
 * each theme anyway, so a regression that themed a screen would show up here.
 */
function screenPairings(tokens: TokenSet): Pairing[] {
  return [
    {
      name: '--screen-blue on screen bg',
      foreground: tokens['--screen-blue'] ?? '',
      background: SCREEN_BG,
    },
    {
      name: '--amber on screen bg',
      foreground: tokens['--amber'] ?? '',
      background: SCREEN_BG,
    },
  ]
}

export function pairingsFor(tokens: TokenSet): Pairing[] {
  return [...chassisPairings(tokens), ...screenPairings(tokens)]
}

// ── forbidden pairings ───────────────────────────────────────────────────────

/**
 * Combinations that are below the floor and are resolved by never using them,
 * rather than by moving a token.
 *
 * `--ink-faint` on `--panel-3` measures 4.41:1 in the dark theme. `--panel-3`
 * is the "highest raise / active hover" surface; darkening `--ink-faint` to
 * clear it would cost the deliberate fine-print dimness the contract wants on
 * the four surfaces where it does pass. So the pairing is prohibited instead,
 * and this check keeps it prohibited.
 */
const FORBIDDEN_PAIRINGS: readonly { foreground: string; background: string }[] = [
  { foreground: '--ink-faint', background: '--panel-3' },
]

export function isForbidden(foreground: string, background: string): boolean {
  return FORBIDDEN_PAIRINGS.some(
    (pairing) => pairing.foreground === foreground && pairing.background === background,
  )
}

/** Extensions searched for a forbidden pairing. */
const SOURCE_EXTENSIONS = /\.(tsx?|css)$/

/**
 * Files excluded from that search, relative to `web/`.
 *
 * `tokens.css` is where every token is *defined*, so every pairing co-occurs
 * there by construction. Definition is not use.
 */
const SOURCE_EXCLUDE = ['src/styles/tokens.css']

/**
 * Reports every place a forbidden pairing appears to be applied to the same
 * element.
 *
 * This is a textual check, and deliberately a conservative one: it flags a CSS
 * rule body, or a single JSX `className`/`style` string, that names both
 * tokens. It cannot see a pairing assembled across two files — an `--ink-faint`
 * element dropped inside a `--panel-3` container elsewhere — so it is a
 * tripwire for the common case, not a proof. The reviewer still owns the
 * cross-file case.
 */
export function findForbiddenUsages(
  sources: readonly { path: string; text: string }[],
): { path: string; pairing: string; excerpt: string }[] {
  const found: { path: string; pairing: string; excerpt: string }[] = []
  for (const { path, text } of sources) {
    for (const { foreground, background } of FORBIDDEN_PAIRINGS) {
      // CSS rule bodies and JSX attribute strings both bottom out as
      // brace- or quote-delimited runs; scanning either kind of run keeps
      // this independent of which syntax a component happens to use.
      const runs = text.match(/\{[^{}]*\}|"[^"]*"|'[^']*'|`[^`]*`/g) ?? []
      // `var(--x)` rather than `--x`, so a block that *declares* a token is
      // not mistaken for one that applies it.
      const usesForeground = `var(${foreground})`
      const usesBackground = `var(${background})`
      for (const run of runs) {
        if (run.includes(usesForeground) && run.includes(usesBackground)) {
          found.push({
            path,
            pairing: `${foreground} on ${background}`,
            excerpt: run.replace(/\s+/g, ' ').slice(0, 120),
          })
        }
      }
    }
  }
  return found
}

// ── reporting ────────────────────────────────────────────────────────────────

type Result = Pairing & { ratio: number; pass: boolean }

function evaluate(pairings: Pairing[]): Result[] {
  return pairings.map((pairing) => {
    const ratio = contrastRatio(pairing.foreground, pairing.background)
    return { ...pairing, ratio, pass: ratio >= AA_SMALL_TEXT_RATIO }
  })
}

function printTable(theme: string, results: Result[], verbose: boolean): void {
  const nameWidth = Math.max(...results.map((r) => r.name.length))
  console.log(`\n  ${theme.toUpperCase()}`)
  console.log(`  ${'pairing'.padEnd(nameWidth)}  fg       bg       ratio   result`)
  console.log(`  ${'-'.repeat(nameWidth)}  -------  -------  ------  ------`)
  for (const result of results) {
    const ratio = result.ratio.toFixed(2).padStart(6)
    console.log(
      `  ${result.name.padEnd(nameWidth)}  ${result.foreground.padEnd(7)}  ` +
        `${result.background.padEnd(7)}  ${ratio}  ${result.pass ? 'PASS' : 'FAIL'}`,
    )
    if (verbose) {
      const fg = parseHex(result.foreground)
      const bg = parseHex(result.background)
      if (fg !== null && bg !== null) {
        console.log(
          `  ${' '.repeat(nameWidth)}  L(fg)=${relativeLuminance(fg).toFixed(6)}  ` +
            `L(bg)=${relativeLuminance(bg).toFixed(6)}`,
        )
      }
    }
  }
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      walk(full, out)
    } else if (SOURCE_EXTENSIONS.test(entry)) {
      out.push(full)
    }
  }
  return out
}

/** Reads every source file the forbidden-pairing scan looks at. */
function readSources(verbose: boolean): { path: string; text: string }[] {
  const root = fileURLToPath(new URL('..', import.meta.url))
  const paths = walk(join(root, 'src'))
    .map((full) => relative(root, full))
    .filter((path) => !SOURCE_EXCLUDE.includes(path))
    .sort()
  if (verbose) {
    console.log(`\n  scanning ${paths.length.toString()} source file(s) for forbidden pairings`)
  }
  return paths.map((path) => ({ path, text: readFileSync(join(root, path), 'utf8') }))
}

function printTokens(theme: string, tokens: TokenSet): void {
  console.log(`\n  resolved tokens — ${theme}`)
  for (const [name, value] of Object.entries(tokens).sort()) {
    console.log(`    ${name.padEnd(16)} ${value}`)
  }
}

export function main(argv: readonly string[]): number {
  const verbose = argv.includes('--verbose') || argv.includes('-v')
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(
      [
        'contrast-check — WCAG 2.1 contrast audit of the catfu design tokens.',
        '',
        'Usage: bun run contrast:check [-- --verbose] [-- --help]',
        '',
        '  --verbose, -v  print resolved tokens and per-color relative luminance',
        '  --help, -h     print this message',
        '',
        `Fails when any pairing is below ${AA_SMALL_TEXT_RATIO.toFixed(1)}:1 (WCAG 2.1 AA, text < 18px).`,
      ].join('\n'),
    )
    return EXIT_OK
  }

  const path = tokensPath()
  const css = readFileSync(path, 'utf8')
  const themes = parseThemes(css)
  if (themes === null) {
    console.error(`contrast-check: could not parse token blocks from ${path}`)
    return EXIT_PARSE_ERROR
  }

  let failures = 0
  for (const [theme, tokens] of Object.entries(themes)) {
    if (verbose) printTokens(theme, tokens)
    const results = evaluate(pairingsFor(tokens))
    for (const result of results) {
      if (result.foreground === '' || result.background === '') {
        console.error(`contrast-check: unresolved token in pairing "${result.name}" (${theme})`)
        return EXIT_PARSE_ERROR
      }
      if (!result.pass) failures += 1
    }
    printTable(theme, results, verbose)
  }

  const forbidden = findForbiddenUsages(readSources(verbose))
  if (forbidden.length > 0) {
    console.error('\n  FORBIDDEN PAIRINGS IN USE')
    for (const { path, pairing, excerpt } of forbidden) {
      console.error(`  ${path}: ${pairing}\n    ${excerpt}`)
    }
  } else if (verbose) {
    console.log(
      `\n  forbidden pairings: none in use (${FORBIDDEN_PAIRINGS.map(
        (p) => `${p.foreground} on ${p.background}`,
      ).join(', ')})`,
    )
  }

  console.log('')
  if (failures > 0 || forbidden.length > 0) {
    const parts: string[] = []
    if (failures > 0) {
      parts.push(
        `${failures.toString()} pairing(s) below ${AA_SMALL_TEXT_RATIO.toFixed(1)}:1 ` +
          '(WCAG 2.1 AA, text < 18px)',
      )
    }
    if (forbidden.length > 0) {
      parts.push(`${forbidden.length.toString()} use(s) of a forbidden pairing`)
    }
    console.error(`contrast-check: FAIL — ${parts.join('; ')}.`)
    return EXIT_FAIL
  }
  console.log(
    `contrast-check: OK — every pairing meets ${AA_SMALL_TEXT_RATIO.toFixed(1)}:1 in both ` +
      `themes, and no forbidden pairing is in use.`,
  )
  return EXIT_OK
}

// Run only when invoked as a script, so the pure helpers above stay importable
// from the vitest suite without the process exiting on import.
const entry = process.argv[1]
if (entry !== undefined && import.meta.url.startsWith('file:')) {
  if (fileURLToPath(import.meta.url) === entry) {
    process.exit(main(process.argv.slice(2)))
  }
}
