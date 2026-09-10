import { describe, expect, it } from 'vitest'
import { cspDigest, dropLegacyWoff, inlineScript, pinnedCspHash } from '../build-finish.ts'

describe('cspDigest', () => {
  it('produces the base64 sha256 a CSP source expression uses', () => {
    // Reference value: sha256("") base64-encoded.
    expect(cspDigest('')).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
  })

  it('is whitespace-sensitive, which is why the build can break the CSP', () => {
    expect(cspDigest('a')).not.toBe(cspDigest('a '))
    expect(cspDigest('a\n')).not.toBe(cspDigest('a'))
  })
})

describe('pinnedCspHash', () => {
  it('reads the constant out of headers.rs', () => {
    const source = 'pub const THEME_SCRIPT_SHA256: &str = "AbC+/123=";\n'
    expect(pinnedCspHash(source)).toBe('AbC+/123=')
  })

  it('returns null rather than guessing when the constant is gone', () => {
    expect(pinnedCspHash('pub const SOMETHING_ELSE: &str = "x";')).toBeNull()
  })
})

describe('inlineScript', () => {
  it('takes the inline script and not a src= one', () => {
    const html = '<script type="module" src="/a.js"></script><script>let x</script>'
    expect(inlineScript(html)).toBe('let x')
  })

  it('preserves the text exactly, because the digest covers it byte for byte', () => {
    expect(inlineScript('<script>\n  let x\n</script>')).toBe('\n  let x\n')
  })

  it('returns null when there is no inline script at all', () => {
    expect(inlineScript('<script src="/a.js"></script>')).toBeNull()
  })
})

describe('dropLegacyWoff', () => {
  const face =
    '@font-face{font-family:X;src:url(/assets/x-abc.woff2)format("woff2"),' +
    'url(/assets/x-def.woff)format("woff");unicode-range:U+0-FF}'

  it('removes the woff fallback and reports the orphaned file', () => {
    const { css, dropped } = dropLegacyWoff(face)

    expect(css).toContain('url(/assets/x-abc.woff2)format("woff2")')
    expect(css).not.toContain('.woff)')
    expect(css).not.toContain('format("woff")')
    expect(dropped).toEqual(['x-def.woff'])
  })

  it('leaves a woff-only face alone rather than stripping it to nothing', () => {
    const only = '@font-face{font-family:X;src:url(/assets/x-def.woff)format("woff")}'
    const { css, dropped } = dropLegacyWoff(only)

    expect(css).toBe(only)
    expect(dropped).toEqual([])
  })

  it('handles every face in a stylesheet', () => {
    const { dropped } = dropLegacyWoff(face + face.replace(/abc|def/g, (m) => `${m}2`))

    expect(dropped).toHaveLength(2)
  })

  it('leaves the rest of the declaration intact', () => {
    const { css } = dropLegacyWoff(face)

    expect(css).toContain('unicode-range:U+0-FF')
    expect(css).toContain('font-family:X')
  })
})
