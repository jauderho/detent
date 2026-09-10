/**
 * Client-side validation that **mirrors** the backend's constraints.
 *
 * This is UX only. The server is the sole authority on whether a model is
 * acceptable: it runs the module's own `validate`, then the upstream binary's
 * check (`chronyd -p -f …`, `testparm -s …`), neither of which is reproduced
 * here. A clean pass in this file therefore says only "the form has nothing
 * further to tell you" — it must never be read as, or presented as, a promise
 * that `apply` will succeed. Always render the diagnostics the server returns.
 *
 * Adding a format is one call to {@link registerFormat}.
 */

import { getAtPath, isJsonArray, isJsonObject, type JsonValue, type ModelPath } from './json'
import type { Constraints, FieldNode } from './schema'

/** One failed constraint, addressed at the field that failed it. */
export type FieldIssue = {
  readonly path: ModelPath
  /** Fluent id in `locales/en-US/web.ftl`. */
  readonly messageId: string
  readonly args: Readonly<Record<string, string | number>>
}

export type FormatValidator = (value: string) => boolean

type FormatEntry = { readonly check: FormatValidator; readonly messageId: string }

const FORMATS = new Map<string, FormatEntry>()

/** Registers a `format` annotation and the Fluent id its failure reports. */
export function registerFormat(name: string, check: FormatValidator, messageId: string): void {
  FORMATS.set(name, { check, messageId })
}

const IPV4_OCTETS = 4
const IPV6_GROUPS = 8
const OCTET_MAX = 255
const HEX_GROUP_MAX_DIGITS = 4

/** Strict dotted quad: no leading zeros, matching Rust's `Ipv4Addr` parser. */
function isIpv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== IPV4_OCTETS) return false
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false
    if (part.length > 1 && part.startsWith('0')) return false
    return Number.parseInt(part, 10) <= OCTET_MAX
  })
}

function isHexGroup(part: string): boolean {
  return part.length >= 1 && part.length <= HEX_GROUP_MAX_DIGITS && /^[0-9a-fA-F]+$/.test(part)
}

/** Handles `::` compression and a trailing IPv4 tail (`::ffff:127.0.0.1`). */
function isIpv6(value: string): boolean {
  const halves = value.split('::')
  if (halves.length > 2) return false

  const countSide = (side: string): number | undefined => {
    if (side.length === 0) return 0
    const parts = side.split(':')
    let groups = 0
    for (const [index, part] of parts.entries()) {
      const isLast = index === parts.length - 1
      if (isLast && part.includes('.')) {
        if (!isIpv4(part)) return undefined
        groups += 2
        continue
      }
      if (!isHexGroup(part)) return undefined
      groups += 1
    }
    return groups
  }

  const head = countSide(halves[0] ?? '')
  if (head === undefined) return false
  if (halves.length === 1) return head === IPV6_GROUPS

  const tail = countSide(halves[1] ?? '')
  if (tail === undefined) return false
  // `::` must stand for at least one elided group.
  return head + tail < IPV6_GROUPS
}

export function isIpAddress(value: string): boolean {
  return value.includes(':') ? isIpv6(value) : isIpv4(value)
}

registerFormat('ip', isIpAddress, 'forms-error-format-ip')
registerFormat('ipv4', isIpv4, 'forms-error-format-ip')
registerFormat('ipv6', isIpv6, 'forms-error-format-ip')

function issue(
  path: ModelPath,
  messageId: string,
  args: Readonly<Record<string, string | number>> = {},
): FieldIssue {
  return { path, messageId, args }
}

/** Compiles a schema `pattern`. An un-compilable one is skipped, not reported. */
function matchesPattern(pattern: string, value: string): boolean {
  try {
    return new RegExp(pattern, 'u').test(value)
  } catch {
    return true
  }
}

function checkString(path: ModelPath, value: string, constraints: Constraints): FieldIssue[] {
  const issues: FieldIssue[] = []
  const { minLength, maxLength, pattern, format } = constraints

  if (minLength !== undefined && value.length < minLength) {
    issues.push(issue(path, 'forms-error-min-length', { min: minLength }))
  }
  if (maxLength !== undefined && value.length > maxLength) {
    issues.push(issue(path, 'forms-error-max-length', { max: maxLength }))
  }
  if (pattern !== undefined && !matchesPattern(pattern, value)) {
    issues.push(issue(path, 'forms-error-pattern', { pattern }))
  }
  if (format !== undefined) {
    const entry = FORMATS.get(format)
    if (entry !== undefined && !entry.check(value)) {
      issues.push(issue(path, entry.messageId, { format }))
    }
  }
  return issues
}

function checkNumber(
  path: ModelPath,
  value: number,
  constraints: Constraints,
  integer: boolean,
): FieldIssue[] {
  const issues: FieldIssue[] = []
  if (integer && !Number.isInteger(value)) {
    issues.push(issue(path, 'forms-error-integer'))
  }
  if (constraints.minimum !== undefined && value < constraints.minimum) {
    issues.push(issue(path, 'forms-error-minimum', { min: constraints.minimum }))
  }
  if (constraints.maximum !== undefined && value > constraints.maximum) {
    issues.push(issue(path, 'forms-error-maximum', { max: constraints.maximum }))
  }
  return issues
}

function checkNode(node: FieldNode, model: JsonValue, basePath: ModelPath): FieldIssue[] {
  const path: ModelPath = [...basePath, ...node.path]
  const value = getAtPath(model, path)
  const { required, nullable } = node.constraints

  if (value === undefined || value === null) {
    const missing = value === undefined ? required : required && !nullable
    return missing ? [issue(path, 'forms-error-required')] : []
  }

  switch (node.control.type) {
    case 'text':
      return typeof value === 'string'
        ? checkString(path, value, node.constraints)
        : [issue(path, 'forms-error-type')]

    case 'select': {
      if (typeof value !== 'string') return [issue(path, 'forms-error-type')]
      return node.control.options.includes(value)
        ? checkString(path, value, node.constraints)
        : [issue(path, 'forms-error-enum')]
    }

    case 'number':
      return typeof value === 'number'
        ? checkNumber(path, value, node.constraints, node.control.integer)
        : [issue(path, 'forms-error-type')]

    case 'switch':
      return typeof value === 'boolean' ? [] : [issue(path, 'forms-error-type')]

    case 'tags': {
      if (!isJsonArray(value)) return [issue(path, 'forms-error-type')]
      const item = node.control.item
      return value.flatMap((entry, index) =>
        typeof entry === 'string'
          ? checkString([...path, String(index)], entry, item)
          : [issue([...path, String(index)], 'forms-error-type')],
      )
    }

    case 'object':
      return isJsonObject(value)
        ? node.control.fields.flatMap((field) => checkNode(field, model, basePath))
        : [issue(path, 'forms-error-type')]

    case 'rows': {
      if (!isJsonArray(value)) return [issue(path, 'forms-error-type')]
      const fields = node.control.fields
      return value.flatMap((row, index) =>
        isJsonObject(row)
          ? fields.flatMap((field) => checkNode(field, model, [...path, String(index)]))
          : [issue([...path, String(index)], 'forms-error-type')],
      )
    }

    // A shape the walker could not map carries no mirrored constraint: the
    // server checks it, and the form shows it read-only.
    case 'unsupported':
      return []
  }
}

/**
 * Runs every mirrored constraint over `model`, expanding array fields against
 * the rows the model actually holds so an issue lands on a real control.
 */
export function validateModel(
  fields: readonly FieldNode[],
  model: JsonValue,
): readonly FieldIssue[] {
  return fields.flatMap((field) => checkNode(field, model, []))
}
