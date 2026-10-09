import { describe, expect, it } from 'bun:test'
import {
  compareLocale,
  findHardcodedJsxText,
  findIdLiterals,
  findReferencedIds,
  loadFtlIdsFrom,
  loadPlaceablesFrom,
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

describe('loadPlaceablesFrom', () => {
  it('collects variables per message, including a selector head', () => {
    const ftl = [
      'a = {$x} and {$y} and {$x}',
      'b = no variables',
      'c = {$count ->',
      '    [one] one thing',
      '   *[other] {$count} things in {$where}',
      '}',
      '## comment {$ignored}',
    ].join('\n')

    expect([...loadPlaceablesFrom(ftl)]).toEqual([
      ['a', ['x', 'y']],
      ['b', []],
      ['c', ['count', 'where']],
    ])
  })
})

describe('compareLocale', () => {
  const source = ['a = hi {$name}', 'b = plain', 'c = {$n ->', '   *[other] {$n} items', '}'].join(
    '\n',
  )

  it('accepts a faithful translation', () => {
    const translation = [
      '# needs-review',
      'a = hallo {$name}',
      'b = einfach',
      'c = {$n ->',
      '   *[other] {$n} Dinge',
      '}',
    ].join('\n')

    expect(compareLocale(source, translation)).toEqual({ missing: [], extra: [], placeables: [] })
  })

  it('reports a missing id, an extra id and a changed placeable', () => {
    const translation = [
      'a = hallo {$nom}',
      'z = extra',
      'c = {$n ->',
      '   *[other] Dinge',
      '}',
    ].join('\n')
    const drift = compareLocale(source, translation)

    expect(drift.missing).toEqual(['b'])
    expect(drift.extra).toEqual(['z'])
    expect(drift.placeables).toEqual([{ id: 'a', expected: ['name'], actual: ['nom'] }])
  })

  it('reports a placeable dropped from a selector arm', () => {
    const translation = ['a = hallo {$name}', 'b = einfach', 'c = Dinge'].join('\n')

    expect(compareLocale(source, translation).placeables).toEqual([
      { id: 'c', expected: ['n'], actual: [] },
    ])
  })
})
