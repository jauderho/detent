import { describe, expect, it } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { FluentBundle, FluentResource } from '@fluent/bundle'
import { SHIPPED_LOCALES } from '@/i18n/locales'

/**
 * WCAG 2.5.3 (Label in Name): a row or item control shows a short caption and
 * carries a longer `aria-label`. In every locale the name must start with the
 * caption as a whole word, so a voice-control user can say what they see.
 */
const NAMES: readonly (readonly [caption: string, name: string])[] = [
  ['forms-item-add-caption', 'forms-row-add'],
  ['forms-item-add-caption', 'forms-tag-add'],
  ['forms-item-move-up-caption', 'forms-row-move-up'],
  ['forms-item-move-up-caption', 'forms-tag-move-up'],
  ['forms-item-move-down-caption', 'forms-row-move-down'],
  ['forms-item-move-down-caption', 'forms-tag-move-down'],
  ['forms-item-remove-caption', 'forms-row-remove'],
  ['forms-item-remove-caption', 'forms-tag-remove'],
]

function bundleFor(locale: string): FluentBundle {
  const source = readFileSync(
    join(import.meta.dir, '..', '..', '..', '..', 'locales', locale, 'web.ftl'),
    'utf8',
  )
  const bundle = new FluentBundle(locale, { useIsolating: false })
  expect(bundle.addResource(new FluentResource(source))).toEqual([])
  return bundle
}

function format(bundle: FluentBundle, id: string): string {
  const pattern = bundle.getMessage(id)?.value
  if (pattern === null || pattern === undefined) throw new Error(`${bundle.locales[0]}: no ${id}`)
  return bundle.formatPattern(pattern, { field: 'entries', index: 1 })
}

describe('row and item control names', () => {
  for (const locale of SHIPPED_LOCALES) {
    it(`start with the visible caption in ${locale}`, () => {
      const bundle = bundleFor(locale)
      for (const [captionId, nameId] of NAMES) {
        const caption = format(bundle, captionId)
        const name = format(bundle, nameId)
        expect(caption.length).toBeGreaterThan(0)
        expect(name).toStartWith(caption)
        expect(name.charAt(caption.length)).toMatch(/[\s:]/)
      }
    })
  }
})
