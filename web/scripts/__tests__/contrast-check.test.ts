import { describe, expect, it } from 'bun:test'
import {
  contrastRatio,
  findForbiddenUsages,
  isForbidden,
  pairingsFor,
  parseBlock,
  parseHex,
  parseThemes,
  relativeLuminance,
} from '../contrast-check.ts'

const FIXTURE_CSS = `
:root,
html[data-theme="dark"] {
  --bg: #121316;
  --ink: #efece5;
  --skip: var(--bg);
  --amber: #ff6a00;
}

html[data-theme="light"] {
  --bg: #ece7dc;
  --ink: #1a1a18;
}
`

describe('parseHex', () => {
  it('parses six-digit and three-digit hex', () => {
    expect(parseHex('#2e7dc4')).toEqual({ r: 0x2e, g: 0x7d, b: 0xc4 })
    expect(parseHex('#fff')).toEqual({ r: 255, g: 255, b: 255 })
  })

  it('rejects anything that is not hex', () => {
    expect(parseHex('var(--bg)')).toBeNull()
    expect(parseHex('rgba(255,255,255,.012)')).toBeNull()
    expect(parseHex('#12345')).toBeNull()
  })
})

describe('relativeLuminance', () => {
  it('anchors at the WCAG endpoints', () => {
    expect(relativeLuminance({ r: 255, g: 255, b: 255 })).toBeCloseTo(1, 10)
    expect(relativeLuminance({ r: 0, g: 0, b: 0 })).toBeCloseTo(0, 10)
  })

  it('matches the published mid-gray luminance', () => {
    // #808080 — WCAG relative luminance 0.2158605001139
    expect(relativeLuminance({ r: 128, g: 128, b: 128 })).toBeCloseTo(0.2158605, 6)
  })
})

describe('contrastRatio', () => {
  it('returns 21:1 for black on white', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 10)
    expect(contrastRatio('#ffffff', '#000000')).toBeCloseTo(21, 10)
  })

  it('returns 1:1 for a color against itself', () => {
    expect(contrastRatio('#2e7dc4', '#2e7dc4')).toBeCloseTo(1, 10)
  })

  it('matches known WCAG reference pairs', () => {
    // #767676 is the canonical smallest gray that clears 4.5:1 on white.
    expect(contrastRatio('#767676', '#ffffff')).toBeCloseTo(4.54, 2)
    expect(contrastRatio('#777777', '#ffffff')).toBeCloseTo(4.48, 2)
    expect(contrastRatio('#0000ff', '#ffffff')).toBeCloseTo(8.59, 2)
  })

  it('is symmetric in its arguments', () => {
    expect(contrastRatio('#efece5', '#121316')).toBeCloseTo(contrastRatio('#121316', '#efece5'), 10)
  })
})

describe('token parsing', () => {
  it('extracts only literal hex declarations from a block', () => {
    const dark = parseBlock(FIXTURE_CSS, /:root,\s*html\[data-theme="dark"\]\s*\{/)

    expect(dark).toEqual({ '--bg': '#121316', '--ink': '#efece5', '--amber': '#ff6a00' })
  })

  it('lets the light theme inherit every token it does not override', () => {
    const themes = parseThemes(FIXTURE_CSS)

    expect(themes?.light['--bg']).toBe('#ece7dc')
    expect(themes?.light['--ink']).toBe('#1a1a18')
    // Lit tokens are deliberately absent from the light block (§3).
    expect(themes?.light['--amber']).toBe('#ff6a00')
  })

  it('returns null when a block is missing', () => {
    expect(parseThemes('html[data-theme="light"] { --bg: #fff; }')).toBeNull()
  })
})

describe('pairingsFor', () => {
  it('covers every ink-on-surface combination plus the blue and screen roles', () => {
    const tokens = Object.fromEntries(
      [
        '--ink',
        '--ink-dim',
        '--ink-faint',
        '--bg',
        '--chrome',
        '--panel',
        '--panel-2',
        '--panel-3',
        '--cta-ink',
        '--blue',
        '--blue-bright',
        '--screen-blue',
        '--amber',
      ].map((name) => [name, '#808080']),
    )

    const pairings = pairingsFor(tokens)

    // 3 inks x 5 surfaces, less the 1 forbidden combination, + cta-ink/blue
    // + 2 blue-bright + 2 screen pairings
    expect(pairings).toHaveLength(19)
    expect(pairings.every((pairing) => pairing.foreground !== '')).toBe(true)
    expect(pairings.every((pairing) => pairing.background !== '')).toBe(true)
  })

  it('omits forbidden pairings, which prohibition covers instead of a ratio row', () => {
    const tokens = Object.fromEntries(
      [
        '--ink',
        '--ink-dim',
        '--ink-faint',
        '--bg',
        '--chrome',
        '--panel',
        '--panel-2',
        '--panel-3',
        '--cta-ink',
        '--blue',
        '--blue-bright',
        '--screen-blue',
        '--amber',
      ].map((name) => [name, '#808080']),
    )

    expect(pairingsFor(tokens).map((pairing) => pairing.name)).not.toContain(
      '--ink-faint on --panel-3',
    )
    expect(isForbidden('--ink-faint', '--panel-3')).toBe(true)
    expect(isForbidden('--ink-dim', '--panel-3')).toBe(false)
  })
})

describe('findForbiddenUsages', () => {
  it('flags a className that applies both halves of a forbidden pairing', () => {
    const usages = findForbiddenUsages([
      {
        path: 'src/components/Bad.tsx',
        text: '<div className="bg-[var(--panel-3)] text-[var(--ink-faint)]">x</div>',
      },
    ])

    expect(usages).toHaveLength(1)
    expect(usages[0]?.pairing).toBe('--ink-faint on --panel-3')
  })

  it('flags a CSS rule that applies both halves', () => {
    const usages = findForbiddenUsages([
      {
        path: 'src/index.css',
        text: '.bad { background: var(--panel-3); color: var(--ink-faint); }',
      },
    ])

    expect(usages).toHaveLength(1)
  })

  it('does not flag a block that merely declares the tokens', () => {
    const usages = findForbiddenUsages([
      {
        path: 'src/styles/tokens.css',
        text: ':root { --panel-3: #2a2b2e; --ink-faint: #909089; }',
      },
    ])

    expect(usages).toEqual([])
  })

  it('does not flag the two tokens used on separate elements', () => {
    const usages = findForbiddenUsages([
      {
        path: 'src/components/Fine.tsx',
        text: '<div className="bg-[var(--panel-3)]"><span className="text-[var(--ink-dim)]">x</span></div>',
      },
    ])

    expect(usages).toEqual([])
  })
})
