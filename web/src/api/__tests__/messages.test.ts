/**
 * The hard rule, tested directly: a `message_id` never reaches a person.
 */

import { describe, expect, it } from 'vitest'
import { createLocalization } from '@/i18n'
import type { ApiError } from '../client'
import { API_MESSAGE_IDS, fluentIdForMessageId, resolveApiError } from '../messages'
import { ApiRequestError, toApiError } from '../query'

const l10n = createLocalization(['en-US'])

function httpError(messageId: string): ApiError {
  return {
    kind: 'http',
    status: 400,
    code: 'bad_request',
    messageId,
    retryAfterSeconds: null,
    diagnostics: null,
  }
}

describe('resolveApiError', () => {
  it('has a sentence for every message id this build names', () => {
    for (const id of API_MESSAGE_IDS) {
      const text = resolveApiError(l10n, httpError(id))
      expect(text, id).not.toBe(id)
      expect(text.length, id).toBeGreaterThan(0)
      // The web bundle states each fact argument-free; an unresolved
      // placeholder would render as literal `{$arg}` text.
      expect(text, id).not.toContain('{$')
    }
  })

  it('degrades an id it does not know to a generic sentence', () => {
    const text = resolveApiError(l10n, httpError('web-auth-something-from-the-future'))

    expect(text).not.toContain('web-auth-something-from-the-future')
    expect(text).toContain('no description for')
    expect(fluentIdForMessageId('web-auth-something-from-the-future')).toBeNull()
  })

  it('describes the failures that carry no message id at all', () => {
    expect(resolveApiError(l10n, { kind: 'network' })).toContain('could not reach')
    expect(resolveApiError(l10n, { kind: 'malformed', status: 502 })).toContain('could not read')
  })
})

describe('toApiError', () => {
  it('unwraps the error an api call rejected with', () => {
    const original = httpError('ops-unknown-module')

    expect(toApiError(new ApiRequestError(original))).toBe(original)
  })

  it('describes anything else without leaking what it was', () => {
    const text = resolveApiError(l10n, toApiError(new Error('connect ECONNREFUSED 10.0.0.1:443')))

    expect(text).not.toContain('ECONNREFUSED')
    expect(text).toContain('could not read')
  })
})
