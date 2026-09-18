/**
 * The small bridge from value-shaped API failures to thrown React Query errors.
 */

import { describe, expect, it } from 'bun:test'
import { createLocalization } from '@/i18n'
import type { ApiError } from '../client'
import { resolveApiError } from '../messages'
import { ApiRequestError, toApiError, unwrap } from '../query'

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

describe('toApiError', () => {
  it('unwraps an ApiRequestError to the ApiError it carries', () => {
    const original = httpError('ops-unknown-module')

    expect(toApiError(new ApiRequestError(original))).toBe(original)
  })

  it('reports anything else as a malformed error', () => {
    const error = toApiError(new Error('something else'))

    expect(error).toEqual({ kind: 'malformed', status: 0 })
    expect(resolveApiError(l10n, error)).toContain('could not read')
  })
})

describe('unwrap', () => {
  it('returns data for an ok result', async () => {
    const result = unwrap(Promise.resolve({ ok: true as const, status: 200, data: { id: 1 } }))

    await expect(result).resolves.toEqual({ id: 1 })
  })

  it('rejects with an ApiRequestError for a failed result', async () => {
    const apiError: ApiError = { kind: 'network' }

    const result = unwrap(Promise.resolve({ ok: false as const, error: apiError }))

    await expect(result).rejects.toBeInstanceOf(ApiRequestError)
    await expect(result).rejects.toMatchObject({ apiError })
  })
})
