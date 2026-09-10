/**
 * Stable React keys for the editable lists.
 *
 * Reorder is a first-class operation here, and a positional key would keep the
 * DOM node — and therefore focus — behind when a row moves. `json.ts` shares
 * structure, so a row object that was only moved is the *same reference* it was
 * before: a `WeakMap` gives it an identity that survives add, remove and
 * reorder without holding it alive. Scalar items have no identity, so they fall
 * back to their own text, disambiguated by occurrence for duplicates.
 */

import type { JsonValue } from './json'

const IDENTITIES = new WeakMap<object, string>()
let counter = 0

function identity(item: JsonValue): string {
  if (typeof item !== 'object' || item === null) return `v:${String(item)}`

  const existing = IDENTITIES.get(item)
  if (existing !== undefined) return existing
  counter += 1
  const assigned = `o:${counter}`
  IDENTITIES.set(item, assigned)
  return assigned
}

export type KeyedItem = {
  readonly key: string
  readonly value: JsonValue
  readonly index: number
}

/** Pairs each item with a key that is stable across reorder. */
export function keyItems(items: readonly JsonValue[]): readonly KeyedItem[] {
  const seen = new Map<string, number>()

  return items.map((value, index) => {
    const base = identity(value)
    const occurrence = seen.get(base) ?? 0
    seen.set(base, occurrence + 1)
    return { key: occurrence === 0 ? base : `${base}#${occurrence}`, value, index }
  })
}
