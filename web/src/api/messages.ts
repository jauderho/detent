/**
 * Resolving an API failure to a sentence a person can read.
 *
 * docs/API.md: every failure is `{ code, message_id }`, and `message_id` is a
 * Fluent id — never a sentence, never an implementation detail. The console
 * must therefore look every id up, and must never fall through to printing
 * the id itself.
 *
 * The ids below are the server's own, reused verbatim as the ids of messages
 * in `locales/en-US/web.ftl`. That keeps the two sides greppable against each
 * other with no translation table in between. The browser copy is not the
 * same text as `locales/en-US/core.ftl` carries for the same ids: core.ftl is
 * the Rust bundle and its messages interpolate arguments (`{$module}`,
 * `{$path}`) the API deliberately does not send, so the web bundle states the
 * same fact without them.
 *
 * `API_MESSAGE_IDS` is what this build can name. Anything else — a newly
 * added module error, a message from a newer server — resolves to
 * `api-error-unknown` rather than leaking an id into the interface.
 */

import type { ReactLocalization } from '@fluent/react'
import type { ApiError } from './client'

/** Every `message_id` this console has copy for. */
export const API_MESSAGE_IDS = [
  // core — parsing and editing a configuration model
  'core-edit-index-out-of-range',
  'core-edit-line-break',
  'core-edit-unsupported',
  'core-model-shape',
  'core-model-unrepresentable',
  'core-parse-malformed',
  // ops — the operations engine
  'ops-audit-failed',
  'ops-audit-unavailable',
  'ops-check-failed',
  'ops-denied',
  'ops-hash-conflict',
  'ops-invalid-model',
  'ops-no-service',
  'ops-no-target',
  'ops-privsep-failed',
  'ops-service-failed',
  'ops-unknown-module',
  'ops-unsupported',
  // web — the API surface itself
  'web-api-unexpected-outcome',
  'web-auth-ambiguous-credentials',
  'web-auth-argon2-params',
  'web-auth-csrf-rejected',
  'web-auth-entropy-unavailable',
  'web-auth-hash-failed',
  'web-auth-invalid-credentials',
  'web-auth-rate-limited',
  'web-auth-session-limit',
  'web-auth-store-malformed',
  'web-auth-store-unreadable',
  'web-auth-store-unwritable',
  'web-auth-store-write-failed',
  'web-auth-token-limit',
  'web-auth-token-unknown',
  'web-auth-totp-secret-invalid',
  'web-auth-unauthenticated',
  'web-auth-user-exists',
  'web-auth-user-name-invalid',
  'web-auth-user-unknown',
  'web-denied-scope',
  'web-engine-stopped',
  'web-request-malformed',
  'web-request-too-deep',
  'web-update-check-failed',
] as const

export type ApiMessageId = (typeof API_MESSAGE_IDS)[number]

const KNOWN: ReadonlySet<string> = new Set<string>(API_MESSAGE_IDS)

/**
 * The one string in this console that is not a Fluent message, used only when
 * the bundle itself cannot answer.
 *
 * `en-US` is compiled into the binary as the fallback bundle, so reaching this
 * means `web.ftl` lost `api-error-unknown` — a broken build, not a locale a
 * user chose. Even then the rule holds: a person sees a sentence, never a
 * `message_id`.
 */
const GENERIC_FALLBACK = 'this host reported a failure the console has no description for.'

function isApiMessageId(value: string): value is ApiMessageId {
  return KNOWN.has(value)
}

/** The Fluent id for a server `message_id`, or `null` when this build has none. */
export function fluentIdForMessageId(messageId: string): ApiMessageId | null {
  return isApiMessageId(messageId) ? messageId : null
}

/**
 * One localized sentence for any failure the client can produce.
 *
 * Never returns a raw `message_id`, a `code`, or anything the server wrote.
 *
 * `getString` returns the id itself when a bundle has no such message, so
 * every lookup that could miss passes the generic sentence as the fallback
 * argument. That is belt and braces over `API_MESSAGE_IDS` — an id can only
 * be in that list and absent from the bundle if a translation is incomplete,
 * and a missing translation must still not print an id.
 */
export function resolveApiError(l10n: ReactLocalization, error: ApiError): string {
  const generic = l10n.getString('api-error-unknown', null, GENERIC_FALLBACK)
  if (error.kind === 'network') return l10n.getString('api-error-network', null, generic)
  if (error.kind === 'malformed') return l10n.getString('api-error-malformed', null, generic)
  const id = fluentIdForMessageId(error.messageId)
  if (id === null) return generic
  return l10n.getString(id, null, generic)
}
