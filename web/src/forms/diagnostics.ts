/**
 * Server diagnostics, and how they find their way onto a control.
 *
 * `validate`, `plan`, and a rejected `apply` all return the same array
 * (`crates/detent-core/src/diag.rs`): a severity, a Fluent id owned by the
 * module's locale file, an optional `field` path in the JSON-pointer-without-
 * the-leading-slash spelling `"entries/3/hostnames/0"`, an optional source
 * span, and named arguments.
 *
 * Mapping rule: a diagnostic attaches to the **longest rendered prefix** of its
 * field path. An exact hit lands on that control; `entries/3/hostnames/0` lands
 * on the `hostnames` tag list when individual tags are not addressable. A path
 * with no rendered prefix at all — a field the schema does not describe, a stale
 * path, a typo — is surfaced at form level. Nothing is ever dropped: a
 * diagnostic the UI cannot place is still a diagnostic the operator must see.
 */

import { getAtPath, isJsonArray, type JsonValue, pathKey } from './json'
import type { FieldNode } from './schema'

export type DiagnosticSeverity = 'error' | 'warning' | 'recommendation'

export type DiagnosticSpan = { readonly start: number; readonly end: number }

export type FormDiagnostic = {
  readonly severity: DiagnosticSeverity
  /** Fluent id, in the module's own locale file. */
  readonly id: string
  /** Model field path, in the diagnostic spelling. */
  readonly field: string | undefined
  readonly span: DiagnosticSpan | undefined
  readonly args: Readonly<Record<string, string>>
}

const SEVERITIES: readonly DiagnosticSeverity[] = ['error', 'warning', 'recommendation']

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function readSpan(raw: unknown): DiagnosticSpan | undefined {
  if (!isObject(raw)) return undefined
  const { start, end } = raw
  return typeof start === 'number' && typeof end === 'number' ? { start, end } : undefined
}

function readArgs(raw: unknown): Readonly<Record<string, string>> {
  if (!isObject(raw)) return {}
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === 'string') out[key] = value
    else if (typeof value === 'number' || typeof value === 'boolean') out[key] = String(value)
  }
  return out
}

/**
 * Narrows an API payload to {@link FormDiagnostic}s. Entries without a usable
 * severity and id are dropped — they carry nothing renderable — but everything
 * else survives, including an unrecognized `field`.
 */
export function parseDiagnostics(input: unknown): readonly FormDiagnostic[] {
  if (!Array.isArray(input)) return []

  const out: FormDiagnostic[] = []
  for (const entry of input) {
    if (!isObject(entry)) continue
    const severity = SEVERITIES.find((candidate) => candidate === entry.severity)
    const id = entry.id
    if (severity === undefined || typeof id !== 'string' || id.length === 0) continue

    const field = entry.field
    out.push({
      severity,
      id,
      field: typeof field === 'string' && field.length > 0 ? field : undefined,
      span: readSpan(entry.span),
      args: readArgs(entry.args),
    })
  }
  return out
}

/** Splits a diagnostic field path. Tolerates the leading slash of a raw pointer. */
export function parseFieldPath(field: string): readonly string[] {
  const trimmed = field.startsWith('/') ? field.slice(1) : field
  return trimmed.length === 0 ? [] : trimmed.split('/')
}

/**
 * Every path the form will actually render for `model`, array fields expanded
 * against the rows the model holds. This is the address book the mapper looks
 * a diagnostic up in.
 */
export function collectFieldPaths(
  fields: readonly FieldNode[],
  model: JsonValue,
  basePath: readonly string[] = [],
): ReadonlySet<string> {
  const out = new Set<string>()

  const visit = (node: FieldNode, base: readonly string[]): void => {
    const path = [...base, ...node.path]
    out.add(pathKey(path))

    if (node.control.type === 'object') {
      for (const child of node.control.fields) visit(child, base)
      return
    }
    if (node.control.type === 'rows') {
      const rows = getAtPath(model, path)
      if (!isJsonArray(rows)) return
      const rowFields = node.control.fields
      for (let index = 0; index < rows.length; index += 1) {
        for (const child of rowFields) visit(child, [...path, String(index)])
      }
    }
  }

  for (const field of fields) visit(field, basePath)
  return out
}

export type DiagnosticMap = {
  /** Keyed by {@link pathKey}. */
  readonly byPath: ReadonlyMap<string, readonly FormDiagnostic[]>
  /** Diagnostics with no field, or whose field matches nothing rendered. */
  readonly formLevel: readonly FormDiagnostic[]
}

export const EMPTY_DIAGNOSTIC_MAP: DiagnosticMap = { byPath: new Map(), formLevel: [] }

/** Finds the longest prefix of `path` that names a rendered control. */
function longestRenderedPrefix(
  path: readonly string[],
  rendered: ReadonlySet<string>,
): string | undefined {
  for (let length = path.length; length > 0; length -= 1) {
    const key = pathKey(path.slice(0, length))
    if (rendered.has(key)) return key
  }
  return undefined
}

export function mapDiagnostics(
  diagnostics: readonly FormDiagnostic[],
  rendered: ReadonlySet<string>,
): DiagnosticMap {
  const byPath = new Map<string, FormDiagnostic[]>()
  const formLevel: FormDiagnostic[] = []

  for (const diagnostic of diagnostics) {
    const key =
      diagnostic.field === undefined
        ? undefined
        : longestRenderedPrefix(parseFieldPath(diagnostic.field), rendered)

    if (key === undefined) {
      formLevel.push(diagnostic)
      continue
    }
    const bucket = byPath.get(key)
    if (bucket === undefined) byPath.set(key, [diagnostic])
    else bucket.push(diagnostic)
  }

  return { byPath, formLevel }
}
