import { describe, expect, it } from 'vitest'
import {
  findHardcodedJsxText,
  findIdLiterals,
  findReferencedIds,
  loadFtlIdsFrom,
} from '../i18n-check.ts'

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

describe('findIdLiterals', () => {
  const known = new Set(['forms-error-required', 'ops-denied'])

  it('sees an id reached through a helper rather than getString', () => {
    const source = `issues.push(issue(path, 'forms-error-required'))`

    expect(findIdLiterals(source, known)).toEqual(['forms-error-required'])
  })

  it('sees an id listed in a table of ids', () => {
    const source = `export const API_MESSAGE_IDS = [\n  'ops-denied',\n] as const`

    expect(findIdLiterals(source, known)).toEqual(['ops-denied'])
  })

  // The bound that keeps this from matching every string in the codebase: a
  // literal counts only when it spells an id that actually exists.
  it('ignores a string that is not a defined id', () => {
    expect(findIdLiterals(`const unit = 'chronyd.service'`, known)).toEqual([])
    expect(findIdLiterals(`getString('ops-denied-typo')`, known)).toEqual([])
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
