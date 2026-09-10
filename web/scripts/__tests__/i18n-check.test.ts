import { describe, expect, it } from 'vitest'
import { findHardcodedJsxText, findReferencedIds, loadFtlIdsFrom } from '../i18n-check.ts'

describe('findReferencedIds', () => {
  it('finds both the component and the imperative form', () => {
    const source = `<Localized id="a-b"><span>x</span></Localized>; l10n.getString('c-d')`

    expect(findReferencedIds(source)).toEqual(['a-b', 'c-d'])
  })
})

describe('loadFtlIdsFrom', () => {
  it('reads message ids and ignores comments and attributes', () => {
    const ftl = ['## a section', 'first-id = hello', 'second-id = world', '    .attr = x'].join(
      '\n',
    )

    expect([...loadFtlIdsFrom(ftl)].sort()).toEqual(['first-id', 'second-id'])
  })
})

describe('findHardcodedJsxText', () => {
  it('flags real untranslated copy', () => {
    expect(findHardcodedJsxText('<p>save changes</p>')).toEqual(['save changes'])
  })

  it('does not flag the fallback children of a Localized element', () => {
    const source = '<Localized id="x"><span>save changes</span></Localized>'

    expect(findHardcodedJsxText(source)).toEqual([])
  })

  // The regression this file exists for: an expression container is not copy.
  it('does not flag JavaScript that happens to sit between > and <', () => {
    const source = [
      'const client = useMemo(() => queryClient ?? createQueryClient(), [queryClient])',
      '',
      'return (',
      '  <QueryClientProvider client={client}>{children}</QueryClientProvider>',
      ')',
    ].join('\n')

    expect(findHardcodedJsxText(source)).toEqual([])
  })

  it('does not flag a ternary or a call inside a JSX expression', () => {
    expect(findHardcodedJsxText('<p>{ok ? render(a) : render(b)}</p>')).toEqual([])
    expect(findHardcodedJsxText('<p>{format(value)}</p>')).toEqual([])
  })

  it('does not flag single-letter or symbol-only nodes', () => {
    expect(findHardcodedJsxText('<span>x</span>')).toEqual([])
    expect(findHardcodedJsxText('<span>—</span>')).toEqual([])
  })
})
