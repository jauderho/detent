/**
 * The JSON value model the form engine edits, plus immutable path helpers.
 *
 * Round-trip fidelity rests entirely on this file. Every edit is a
 * structural-sharing replacement of one leaf: an object update spreads the
 * original (which preserves key order and leaves every sibling
 * *reference-identical*) and an array update copies only the spine. A field the
 * form never wrote is therefore the very same object that arrived, so
 * re-serializing the model cannot perturb it — including fields whose schema
 * shape the engine does not understand.
 */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue }

export type JsonObject = { readonly [key: string]: JsonValue }

/** A model path in the diagnostic spelling: a JSON pointer without the leading slash. */
export type ModelPath = readonly string[]

export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function isJsonArray(value: JsonValue | undefined): value is readonly JsonValue[] {
  return Array.isArray(value)
}

/**
 * Narrows arbitrary parsed input to {@link JsonValue} without an unchecked
 * cast. Non-JSON leaves (`undefined`, functions, symbols, `NaN`) collapse to
 * `null`; keys holding `undefined` are dropped, matching `JSON.stringify`.
 */
export function parseJsonValue(input: unknown): JsonValue {
  if (input === null) return null
  if (typeof input === 'boolean' || typeof input === 'string') return input
  if (typeof input === 'number') return Number.isFinite(input) ? input : null
  if (Array.isArray(input)) return input.map((item: unknown) => parseJsonValue(item))
  if (typeof input === 'object') {
    const out: Record<string, JsonValue> = {}
    for (const [key, value] of Object.entries(input)) {
      if (value === undefined) continue
      out[key] = parseJsonValue(value)
    }
    return out
  }
  return null
}

export function pathKey(path: ModelPath): string {
  return path.join('/')
}

export function parsePath(key: string): ModelPath {
  return key.length === 0 ? [] : key.split('/')
}

function toIndex(segment: string): number | undefined {
  return /^\d+$/.test(segment) ? Number.parseInt(segment, 10) : undefined
}

export function getAtPath(root: JsonValue, path: ModelPath): JsonValue | undefined {
  let current: JsonValue | undefined = root
  for (const segment of path) {
    if (isJsonArray(current)) {
      const index = toIndex(segment)
      current = index === undefined ? undefined : current[index]
    } else if (isJsonObject(current)) {
      current = Object.hasOwn(current, segment) ? current[segment] : undefined
    } else {
      return undefined
    }
  }
  return current
}

/** Picks the container an intermediate segment needs when the model has none yet. */
function containerFor(existing: JsonValue | undefined, next: string | undefined): JsonValue {
  if (isJsonObject(existing) || isJsonArray(existing)) return existing
  return next !== undefined && toIndex(next) !== undefined ? [] : {}
}

/**
 * Replaces the value at `path`, sharing every untouched branch. Out-of-range
 * array indices are refused (the model is returned unchanged) rather than
 * creating a sparse array.
 */
export function setAtPath(root: JsonValue, path: ModelPath, value: JsonValue): JsonValue {
  if (path.length === 0) return value
  const head = path[0]
  if (head === undefined) return value
  const rest = path.slice(1)

  if (isJsonArray(root)) {
    const index = toIndex(head)
    if (index === undefined || index < 0 || index >= root.length) return root
    const next = root.slice()
    next[index] = setAtPath(
      rest.length === 0 ? null : containerFor(root[index], rest[0]),
      rest,
      value,
    )
    return next
  }

  if (isJsonObject(root)) {
    const existing = Object.hasOwn(root, head) ? root[head] : undefined
    const child = rest.length === 0 ? null : containerFor(existing, rest[0])
    return { ...root, [head]: setAtPath(child, rest, value) }
  }

  // A scalar stands where a container was expected; refuse rather than
  // overwrite data the form cannot account for.
  return root
}

export function updateArrayAtPath(
  root: JsonValue,
  path: ModelPath,
  update: (items: readonly JsonValue[]) => readonly JsonValue[],
): JsonValue {
  const current = getAtPath(root, path)
  return setAtPath(root, path, update(isJsonArray(current) ? current : []))
}

export function appendItem(items: readonly JsonValue[], item: JsonValue): readonly JsonValue[] {
  return [...items, item]
}

export function removeAt(items: readonly JsonValue[], index: number): readonly JsonValue[] {
  if (index < 0 || index >= items.length) return items
  return [...items.slice(0, index), ...items.slice(index + 1)]
}

/** Moves one item, preserving the order of every other item exactly. */
export function moveItem(
  items: readonly JsonValue[],
  from: number,
  to: number,
): readonly JsonValue[] {
  if (from === to) return items
  if (from < 0 || from >= items.length) return items
  if (to < 0 || to >= items.length) return items
  const moved = items[from]
  if (moved === undefined) return items
  const without = removeAt(items, from)
  return [...without.slice(0, to), moved, ...without.slice(to)]
}
