/**
 * The `x-detent` UI hint object that `detent-core`'s `FieldHints::to_json`
 * injects into every field of a module's JSON Schema
 * (crates/detent-core/src/descriptor.rs).
 *
 * The shape is contractual on the Rust side, but the schema arrives over HTTP,
 * so nothing here asserts: an absent or malformed hint object degrades to
 * {@link DEFAULT_HINTS} rather than throwing. `tooltip` and `recommendation`
 * are Fluent ids owned by the *module's* locale file, not `web.ftl`, so a
 * consumer must treat a missing message as "no tooltip" and never render the
 * bare id.
 */

import { isJsonObject, type JsonObject, type JsonValue } from './json'

export type UiGroup = 'basic' | 'advanced'
export type SecurityImpact = 'none' | 'low' | 'high'

export type FieldHints = {
  readonly group: UiGroup
  /** Fluent id of the field's tooltip, in the module's own locale file. */
  readonly tooltipId: string | undefined
  /** Fluent id of a recommended value or practice. */
  readonly recommendationId: string | undefined
  readonly securityImpact: SecurityImpact
  /** Upstream version that introduced the option, e.g. `"4.5"`. */
  readonly since: string | undefined
  /** Upstream version that deprecated the option. */
  readonly deprecatedIn: string | undefined
  readonly requiresRestart: boolean
}

/** What a field gets when the schema carries no usable `x-detent` object. */
export const DEFAULT_HINTS: FieldHints = {
  group: 'basic',
  tooltipId: undefined,
  recommendationId: undefined,
  securityImpact: 'none',
  since: undefined,
  deprecatedIn: undefined,
  requiresRestart: false,
}

const GROUPS: readonly UiGroup[] = ['basic', 'advanced']
const IMPACTS: readonly SecurityImpact[] = ['none', 'low', 'high']

function member(node: JsonObject, key: string): JsonValue | undefined {
  return Object.hasOwn(node, key) ? node[key] : undefined
}

function readString(node: JsonObject, key: string): string | undefined {
  const value = member(node, key)
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function readEnum<T extends string>(
  node: JsonObject,
  key: string,
  allowed: readonly T[],
  fallback: T,
): T {
  const value = member(node, key)
  return allowed.find((candidate) => candidate === value) ?? fallback
}

/** The schema key the Rust side writes its hints under. */
export const HINTS_KEY = 'x-detent'

/** Reads the `x-detent` object off a schema node, defaulting every absent part. */
export function parseHints(node: JsonObject | undefined): FieldHints {
  const raw = node === undefined ? undefined : member(node, HINTS_KEY)
  if (!isJsonObject(raw)) return DEFAULT_HINTS

  const requiresRestart = member(raw, 'requires_restart')

  return {
    group: readEnum(raw, 'group', GROUPS, DEFAULT_HINTS.group),
    tooltipId: readString(raw, 'tooltip'),
    recommendationId: readString(raw, 'recommendation'),
    securityImpact: readEnum(raw, 'security_impact', IMPACTS, DEFAULT_HINTS.securityImpact),
    since: readString(raw, 'since'),
    deprecatedIn: readString(raw, 'deprecated_in'),
    requiresRestart: requiresRestart === true,
  }
}
