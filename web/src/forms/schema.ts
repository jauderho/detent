/**
 * The schema walker: JSON Schema draft 2020-12 as `schemars` emits it, turned
 * into a renderable {@link FieldNode} tree.
 *
 * Deliberately not a general-purpose JSON Schema engine — this ships inside the
 * `detent` binary and every byte is budgeted. It understands exactly the
 * constructs the modules emit:
 *
 * * `$defs` + `$ref`, **local pointers only** (`#/...`). A remote or absolute
 *   `$ref` is refused, never fetched.
 * * `properties` / `required` / `additionalProperties: false` objects, nested.
 * * `array` of `string` (a tag list) and `array` of object (a row editor).
 * * the nullable-union spelling `"type": ["string", "null"]`.
 * * `enum`, and the `oneOf`/`anyOf`-of-`const` spelling `schemars` uses for a
 *   documented fieldless Rust enum.
 * * `minLength` / `maxLength` / `pattern` / `format`, `minimum` / `maximum`,
 *   `default`, `description`, and the `x-detent` hint object.
 *
 * Anything else — a tuple (`prefixItems`), a multi-type union, a free-form map,
 * an unresolvable `$ref`, a `$ref` cycle, or a tree deeper than
 * {@link MAX_SCHEMA_DEPTH} — becomes an `unsupported` control rather than
 * disappearing. A dropped field would be erased from the file on the next
 * apply, so "render it read-only" is the only safe failure mode.
 *
 * The input is untrusted-shaped: it is normalized through
 * {@link parseJsonValue} and read with guards, never asserted.
 */

import { DEFAULT_HINTS, type FieldHints, parseHints, type UiGroup } from './hints'
import {
  isJsonArray,
  isJsonObject,
  type JsonObject,
  type JsonValue,
  type ModelPath,
  parseJsonValue,
} from './json'

/**
 * How deep the walker will descend before it gives up. A self-referential
 * schema is normally caught by `$ref` cycle detection; this is the backstop
 * that guarantees termination for any other shape, so a bad schema reports
 * instead of hanging the browser.
 */
export const MAX_SCHEMA_DEPTH = 12

/** Why a node could not be mapped onto a control. */
export type UnsupportedReason = 'shape' | 'ref' | 'cycle' | 'depth'

/** The validation facts carried on a leaf. Mirrored, never trusted — see validate.ts. */
export type Constraints = {
  readonly required: boolean
  /** The `"null"` member of a `"type"` union. */
  readonly nullable: boolean
  readonly minLength: number | undefined
  readonly maxLength: number | undefined
  readonly minimum: number | undefined
  readonly maximum: number | undefined
  readonly pattern: string | undefined
  /** A `format` annotation, e.g. `"ip"`. Resolved against the format registry. */
  readonly format: string | undefined
}

export const NO_CONSTRAINTS: Constraints = {
  required: false,
  nullable: false,
  minLength: undefined,
  maxLength: undefined,
  minimum: undefined,
  maximum: undefined,
  pattern: undefined,
  format: undefined,
}

export type Control =
  | { readonly type: 'text' }
  | { readonly type: 'number'; readonly integer: boolean }
  | { readonly type: 'switch' }
  | { readonly type: 'select'; readonly options: readonly string[] }
  /** `array` of `string`. `item` carries the item schema's own constraints. */
  | { readonly type: 'tags'; readonly item: Constraints }
  /** A nested object. Field paths are relative to the same walk root as the parent. */
  | { readonly type: 'object'; readonly fields: readonly FieldNode[] }
  /** `array` of object. Field paths are relative to *one row*, not to the walk root. */
  | { readonly type: 'rows'; readonly fields: readonly FieldNode[] }
  | { readonly type: 'unsupported'; readonly reason: UnsupportedReason }

/**
 * One rendered control.
 *
 * `path` is relative to the nearest **walk root** — the model root for the
 * top-level tree, or a single row for the fields of a `rows` control. The
 * renderer accumulates a `basePath` as it descends, so a row's field resolves
 * to `entries/3/ip` without the walker having to know how many rows exist.
 */
export type FieldNode = {
  readonly path: ModelPath
  /** The property key. Doubles as the silk-screen caption: it *is* the config key. */
  readonly name: string
  /** The upstream doc comment, when the schema carries one. */
  readonly description: string | undefined
  readonly hints: FieldHints
  readonly constraints: Constraints
  readonly control: Control
  readonly defaultValue: JsonValue | undefined
}

export type ParsedSchema = {
  readonly title: string | undefined
  readonly description: string | undefined
  readonly fields: readonly FieldNode[]
}

// ── defensive readers ────────────────────────────────────────────────────────

function member(node: JsonObject, key: string): JsonValue | undefined {
  return Object.hasOwn(node, key) ? node[key] : undefined
}

function readString(node: JsonObject, key: string): string | undefined {
  const value = member(node, key)
  return typeof value === 'string' ? value : undefined
}

function readNumber(node: JsonObject, key: string): number | undefined {
  const value = member(node, key)
  return typeof value === 'number' ? value : undefined
}

function readObject(node: JsonObject, key: string): JsonObject | undefined {
  const value = member(node, key)
  return isJsonObject(value) ? value : undefined
}

function readStringSet(node: JsonObject, key: string): ReadonlySet<string> {
  const value = member(node, key)
  if (!isJsonArray(value)) return new Set()
  const out = new Set<string>()
  for (const item of value) {
    if (typeof item === 'string') out.add(item)
  }
  return out
}

// ── $ref resolution ──────────────────────────────────────────────────────────

/** RFC 6901 token unescaping. */
function unescapeToken(token: string): string {
  return token.replaceAll('~1', '/').replaceAll('~0', '~')
}

/**
 * Resolves a local JSON pointer against the schema document. Only `#`-rooted
 * refs resolve; anything else (an absolute URL, a bare filename, a `$id`
 * anchor) returns `undefined` so the caller can report it — the form never
 * dereferences a schema over the network.
 */
export function resolveRef(root: JsonObject, ref: string): JsonObject | undefined {
  if (ref === '#') return root
  if (!ref.startsWith('#/')) return undefined

  let current: JsonValue = root
  for (const token of ref.slice(2).split('/')) {
    if (!isJsonObject(current)) return undefined
    const next = member(current, unescapeToken(token))
    if (next === undefined) return undefined
    current = next
  }
  return isJsonObject(current) ? current : undefined
}

type DerefResult =
  | { readonly ok: true; readonly node: JsonObject; readonly chain: readonly string[] }
  | { readonly ok: false; readonly reason: 'ref' | 'cycle' }

/** Follows a `$ref` chain, refusing to revisit a ref already on the stack. */
function deref(root: JsonObject, node: JsonObject, chain: readonly string[]): DerefResult {
  let current = node
  let seen = chain

  for (;;) {
    const ref = readString(current, '$ref')
    if (ref === undefined) return { ok: true, node: current, chain: seen }
    if (seen.includes(ref)) return { ok: false, reason: 'cycle' }

    const target = resolveRef(root, ref)
    if (target === undefined) return { ok: false, reason: 'ref' }

    seen = [...seen, ref]
    current = target
  }
}

// ── type + enum reading ──────────────────────────────────────────────────────

type TypeInfo = { readonly base: string | undefined; readonly nullable: boolean }

/**
 * Splits `"type"` into its single non-null member plus a nullable flag. A union
 * with more than one non-null member has no single control, so `base` is
 * `undefined` and the field falls back.
 */
function readTypeInfo(node: JsonObject): TypeInfo {
  const raw = member(node, 'type')
  if (typeof raw === 'string') {
    return raw === 'null' ? { base: undefined, nullable: true } : { base: raw, nullable: false }
  }
  if (!isJsonArray(raw)) return { base: undefined, nullable: false }

  const names: string[] = []
  let nullable = false
  for (const item of raw) {
    if (typeof item !== 'string') return { base: undefined, nullable: false }
    if (item === 'null') nullable = true
    else names.push(item)
  }
  return { base: names.length === 1 ? names[0] : undefined, nullable }
}

type EnumInfo = { readonly options: readonly string[]; readonly nullable: boolean }

/** Reads a plain `enum` list, or the `oneOf`/`anyOf`-of-`const` spelling. */
function readEnumInfo(node: JsonObject): EnumInfo | undefined {
  const direct = member(node, 'enum')
  if (isJsonArray(direct)) {
    const options: string[] = []
    let nullable = false
    for (const item of direct) {
      if (item === null) nullable = true
      else if (typeof item === 'string') options.push(item)
      else return undefined
    }
    return options.length > 0 ? { options, nullable } : undefined
  }

  const branches = member(node, 'oneOf') ?? member(node, 'anyOf')
  if (!isJsonArray(branches)) return undefined

  const options: string[] = []
  let nullable = false
  for (const branch of branches) {
    if (!isJsonObject(branch)) return undefined
    const constant = member(branch, 'const')
    if (typeof constant === 'string') {
      options.push(constant)
      continue
    }
    if (readTypeInfo(branch).nullable && constant === undefined) {
      nullable = true
      continue
    }
    return undefined
  }
  return options.length > 0 ? { options, nullable } : undefined
}

// ── the walk ─────────────────────────────────────────────────────────────────

function readConstraints(node: JsonObject, required: boolean, nullable: boolean): Constraints {
  return {
    required,
    nullable,
    minLength: readNumber(node, 'minLength'),
    maxLength: readNumber(node, 'maxLength'),
    minimum: readNumber(node, 'minimum'),
    maximum: readNumber(node, 'maximum'),
    pattern: readString(node, 'pattern'),
    format: readString(node, 'format'),
  }
}

type WalkCtx = {
  readonly root: JsonObject
  readonly depth: number
  readonly chain: readonly string[]
}

function unsupported(
  path: ModelPath,
  name: string,
  raw: JsonObject,
  required: boolean,
  reason: UnsupportedReason,
): FieldNode {
  return {
    path,
    name,
    description: readString(raw, 'description'),
    hints: parseHints(raw),
    constraints: { ...NO_CONSTRAINTS, required },
    control: { type: 'unsupported', reason },
    defaultValue: member(raw, 'default'),
  }
}

function walkObject(node: JsonObject, basePath: ModelPath, ctx: WalkCtx): readonly FieldNode[] {
  const properties = readObject(node, 'properties')
  if (properties === undefined) return []
  const required = readStringSet(node, 'required')

  return Object.entries(properties).flatMap(([key, child]) =>
    isJsonObject(child) ? [buildField(key, child, basePath, required.has(key), ctx)] : [],
  )
}

function buildField(
  name: string,
  raw: JsonObject,
  basePath: ModelPath,
  required: boolean,
  ctx: WalkCtx,
): FieldNode {
  const path: ModelPath = [...basePath, name]
  if (ctx.depth > MAX_SCHEMA_DEPTH) return unsupported(path, name, raw, required, 'depth')

  const resolved = deref(ctx.root, raw, ctx.chain)
  if (!resolved.ok) return unsupported(path, name, raw, required, resolved.reason)

  const schema = resolved.node
  const inner: WalkCtx = { root: ctx.root, depth: ctx.depth + 1, chain: resolved.chain }

  // `x-detent`, `description` and `default` live on the property site, which for
  // a `$ref` property is the node *before* dereferencing. `parseHints` returns
  // the shared DEFAULT_HINTS when a node carries none, so this falls through to
  // the target only when the property site really said nothing.
  const rawHints = parseHints(raw)
  const hints = rawHints === DEFAULT_HINTS ? parseHints(schema) : rawHints
  const description = readString(raw, 'description') ?? readString(schema, 'description')
  const defaultValue = member(raw, 'default') ?? member(schema, 'default')

  const enumInfo = readEnumInfo(schema)
  const typeInfo = readTypeInfo(schema)
  const nullable = typeInfo.nullable || (enumInfo?.nullable ?? false)

  const base = {
    path,
    name,
    description,
    hints,
    constraints: readConstraints(schema, required, nullable),
    defaultValue,
  }

  if (enumInfo !== undefined) {
    return { ...base, control: { type: 'select', options: enumInfo.options } }
  }

  switch (typeInfo.base) {
    case 'string':
      return { ...base, control: { type: 'text' } }
    case 'integer':
      return { ...base, control: { type: 'number', integer: true } }
    case 'number':
      return { ...base, control: { type: 'number', integer: false } }
    case 'boolean':
      return { ...base, control: { type: 'switch' } }
    case 'object': {
      const fields = walkObject(schema, path, inner)
      if (fields.length === 0) return unsupported(path, name, raw, required, 'shape')
      return { ...base, control: { type: 'object', fields } }
    }
    case 'array':
      return buildArrayField(base, schema, raw, required, inner)
    default:
      return unsupported(path, name, raw, required, 'shape')
  }
}

type FieldBase = Omit<FieldNode, 'control'>

function buildArrayField(
  base: FieldBase,
  schema: JsonObject,
  raw: JsonObject,
  required: boolean,
  ctx: WalkCtx,
): FieldNode {
  const fallback = (reason: UnsupportedReason = 'shape'): FieldNode =>
    unsupported(base.path, base.name, raw, required, reason)

  if (ctx.depth > MAX_SCHEMA_DEPTH) return fallback('depth')
  // Tuples (`prefixItems`) and the draft-07 array-of-schemas `items` spelling
  // have no editor here; they fall back rather than lose their contents.
  if (member(schema, 'prefixItems') !== undefined) return fallback()
  const items = readObject(schema, 'items')
  if (items === undefined) return fallback()

  const resolved = deref(ctx.root, items, ctx.chain)
  if (!resolved.ok) return fallback(resolved.reason)

  const itemSchema = resolved.node
  const itemCtx: WalkCtx = { root: ctx.root, depth: ctx.depth + 1, chain: resolved.chain }
  const itemType = readTypeInfo(itemSchema)

  if (itemType.base === 'string' && readEnumInfo(itemSchema) === undefined) {
    return {
      ...base,
      control: { type: 'tags', item: readConstraints(itemSchema, true, itemType.nullable) },
    }
  }

  if (itemType.base === 'object') {
    // A row starts a new walk root: its field paths are relative to the row, so
    // the renderer can splice the row index in between.
    const fields = walkObject(itemSchema, [], itemCtx)
    if (fields.length === 0) return fallback()
    return { ...base, control: { type: 'rows', fields } }
  }

  return fallback()
}

/**
 * Reads a module schema. Never throws: an input that is not an object, or an
 * object with no `properties`, yields a single read-only fallback field holding
 * the whole model, so no configuration can be silently dropped.
 */
export function parseSchema(input: unknown): ParsedSchema {
  const root = parseJsonValue(input)
  if (!isJsonObject(root)) {
    return { title: undefined, description: undefined, fields: [] }
  }

  const ctx: WalkCtx = { root, depth: 0, chain: [] }
  const fields = walkObject(root, [], ctx)

  return {
    title: readString(root, 'title'),
    description: readString(root, 'description'),
    fields:
      fields.length > 0
        ? fields
        : [unsupported([], readString(root, 'title') ?? '', root, false, 'shape')],
  }
}

/**
 * Whether any field in the tree — including one nested in an object or a row —
 * belongs to `group`. The advanced disclosure lives at the top of the form but
 * governs advanced fields at every depth, so it has to look all the way down.
 */
export function hasGroup(fields: readonly FieldNode[], group: UiGroup): boolean {
  return fields.some((field) => {
    if (field.hints.group === group) return true
    const control = field.control
    if (control.type === 'object' || control.type === 'rows') {
      return hasGroup(control.fields, group)
    }
    return false
  })
}

/**
 * A value for a freshly added row or list item. Uses the schema `default` when
 * there is one, otherwise the empty value of the control's type. Optional
 * fields are left out entirely rather than filled with `null`, so a new row
 * serializes the way the module's own `Default` would.
 */
export function defaultValueForNode(node: FieldNode): JsonValue {
  if (node.defaultValue !== undefined) return node.defaultValue

  switch (node.control.type) {
    case 'text':
      return ''
    case 'number':
      return node.constraints.minimum ?? 0
    case 'switch':
      return false
    case 'select':
      return node.control.options[0] ?? ''
    case 'tags':
    case 'rows':
      return []
    case 'object':
      return defaultObject(node.control.fields)
    case 'unsupported':
      return null
  }
}

/** Builds the object a `rows` editor inserts: every required field, nothing else. */
export function defaultObject(fields: readonly FieldNode[]): JsonValue {
  const out: Record<string, JsonValue> = {}
  for (const field of fields) {
    if (!field.constraints.required && field.defaultValue === undefined) continue
    out[field.name] = defaultValueForNode(field)
  }
  return out
}
