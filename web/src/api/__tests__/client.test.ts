/**
 * The two rules `client.ts` exists to enforce, and the one shape it has to
 * parse.
 *
 * Nothing here touches the network: `fetch` is a stub, and every assertion is
 * about the request the client built or the value it resolved to.
 */

import { describe, expect, it, mock } from 'bun:test'
import { jsonResponse, type StubCall, stubFetch } from '@/test/providers'
import { CSRF_HEADER, createApiClient } from '../client'

const CSRF_TOKEN = 'csrf-token-value'

function headerOf(call: StubCall | undefined, name: string): string | null {
  if (call === undefined) return null
  return new Headers(call.init.headers).get(name)
}

describe('createApiClient — CSRF', () => {
  it('sends the CSRF header on every non-GET request', async () => {
    const { fetch, calls } = stubFetch([new Response(null, { status: 204 })])
    const client = createApiClient({ fetch })
    client.setCsrfToken(CSRF_TOKEN)

    await client.post('/api/v1/auth/logout', {})
    await client.post('/api/v1/commits/{id}/confirm', { path: { id: 1 } })
    await client.post('/api/v1/services/{id}', {
      path: { id: 'hosts' },
      body: { action: 'restart' },
    })

    expect(calls).toHaveLength(3)
    for (const call of calls) {
      expect(call.init.method).toBe('POST')
      expect(headerOf(call, CSRF_HEADER)).toBe(CSRF_TOKEN)
      expect(call.init.credentials).toBe('same-origin')
    }
  })

  it('never sends the CSRF header on a GET, which the server never checks', async () => {
    const { fetch, calls } = stubFetch([jsonResponse([])])
    const client = createApiClient({ fetch })
    client.setCsrfToken(CSRF_TOKEN)

    await client.get('/api/v1/modules', {})

    expect(calls[0]?.init.method).toBe('GET')
    expect(headerOf(calls[0], CSRF_HEADER)).toBeNull()
  })

  it('keeps the token out of the url and out of storage', async () => {
    const { fetch, calls } = stubFetch([new Response(null, { status: 204 })])
    const client = createApiClient({ fetch })
    client.setCsrfToken(CSRF_TOKEN)

    await client.post('/api/v1/auth/logout', {})

    expect(calls[0]?.url).toBe('/api/v1/auth/logout')
    expect(calls[0]?.url).not.toContain(CSRF_TOKEN)
    expect(JSON.stringify(localStorage)).not.toContain(CSRF_TOKEN)
    expect(JSON.stringify(sessionStorage)).not.toContain(CSRF_TOKEN)
  })

  it('sends no header at all until a session has supplied a token', async () => {
    const { fetch, calls } = stubFetch([new Response(null, { status: 204 })])
    const client = createApiClient({ fetch })

    expect(client.hasCsrfToken()).toBe(false)
    await client.post('/api/v1/auth/logout', {})
    expect(headerOf(calls[0], CSRF_HEADER)).toBeNull()
  })
})

describe('createApiClient — error shapes', () => {
  it('parses the documented `{ code, message_id }` body', async () => {
    const { fetch } = stubFetch([
      jsonResponse({ code: 'not_found', message_id: 'ops-unknown-module' }, { status: 404 }),
    ])
    const client = createApiClient({ fetch })

    const result = await client.get('/api/v1/modules/{id}', { path: { id: 'nope' } })

    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error).toEqual({
      kind: 'http',
      status: 404,
      code: 'not_found',
      messageId: 'ops-unknown-module',
      retryAfterSeconds: null,
      diagnostics: null,
    })
  })

  it('reads Retry-After off a 429', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'rate_limited', message_id: 'web-auth-rate-limited' },
        { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '42' } },
      ),
    ])
    const client = createApiClient({ fetch })

    const result = await client.post('/api/v1/auth/login', {
      body: { username: 'op', password: 'secret' },
    })

    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.error.kind).toBe('http')
    if (result.error.kind !== 'http') return
    expect(result.error.status).toBe(429)
    expect(result.error.retryAfterSeconds).toBe(42)
  })

  it('reports a body that is not the documented shape as malformed', async () => {
    const { fetch } = stubFetch([jsonResponse({ detail: 'boom' }, { status: 500 })])
    const client = createApiClient({ fetch })

    const result = await client.get('/api/v1/modules', {})

    expect(result).toEqual({ ok: false, error: { kind: 'malformed', status: 500 } })
  })

  it('reports a transport failure as a network error rather than throwing', async () => {
    const fetch = mock(() => Promise.reject(new TypeError('offline')))
    const client = createApiClient({ fetch: fetch as unknown as typeof globalThis.fetch })

    const result = await client.get('/api/v1/modules', {})

    expect(result).toEqual({ ok: false, error: { kind: 'network' } })
  })

  it('narrows the diagnostics a rejected apply carries', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        {
          code: 'unprocessable',
          message_id: 'ops-invalid-model',
          diagnostics: [{ args: { name: 'x' }, id: 'hosts-invalid-hostname', severity: 'error' }],
        },
        { status: 422 },
      ),
    ])
    const client = createApiClient({ fetch })

    const result = await client.post('/api/v1/modules/{id}/apply', {
      path: { id: 'hosts' },
      body: { model: {} },
    })

    expect(result.ok).toBe(false)
    if (result.ok || result.error.kind !== 'http') return
    expect(result.error.diagnostics).toEqual([
      { args: { name: 'x' }, id: 'hosts-invalid-hostname', severity: 'error' },
    ])
  })
})

describe('createApiClient — 401', () => {
  it('fires the signed-out handler once per unsuppressed 401', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'unauthorized', message_id: 'web-auth-unauthenticated' },
        { status: 401 },
      ),
    ])
    const client = createApiClient({ fetch })
    const onUnauthorized = mock()
    client.setUnauthorizedHandler(onUnauthorized)

    await client.get('/api/v1/modules', {})

    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  it('does not fire it for the session probe or the login attempt', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'unauthorized', message_id: 'web-auth-unauthenticated' },
        { status: 401 },
      ),
    ])
    const client = createApiClient({ fetch })
    const onUnauthorized = mock()
    client.setUnauthorizedHandler(onUnauthorized)

    await client.get('/api/v1/auth/session', { suppressUnauthorizedEvent: true })
    await client.post('/api/v1/auth/login', {
      body: { username: 'op', password: 'wrong' },
      suppressUnauthorizedEvent: true,
    })

    expect(onUnauthorized).not.toHaveBeenCalled()
  })

  it('still returns the 401 to its caller so a form can show it', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'unauthorized', message_id: 'web-auth-invalid-credentials' },
        { status: 401 },
      ),
    ])
    const client = createApiClient({ fetch })
    client.setUnauthorizedHandler(mock())

    const result = await client.get('/api/v1/modules', {})

    expect(result.ok).toBe(false)
    if (result.ok || result.error.kind !== 'http') return
    expect(result.error.status).toBe(401)
    expect(result.error.messageId).toBe('web-auth-invalid-credentials')
  })

  it('stops firing once the handler is removed', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'unauthorized', message_id: 'web-auth-unauthenticated' },
        { status: 401 },
      ),
    ])
    const client = createApiClient({ fetch })
    const onUnauthorized = mock()
    client.setUnauthorizedHandler(onUnauthorized)
    client.setUnauthorizedHandler(null)

    await client.get('/api/v1/modules', {})

    expect(onUnauthorized).not.toHaveBeenCalled()
  })
})

describe('createApiClient — request method', () => {
  it('exposes a generic request entry point', async () => {
    const { fetch } = stubFetch([jsonResponse({ ok: true })])
    const client = createApiClient({ fetch })

    const result = await client.request('/api/v1/modules', 'get', {} as never)

    expect(result.ok).toBe(true)
  })
})

describe('createApiClient — path parameters', () => {
  it('throws when a path parameter is missing', async () => {
    const { fetch } = stubFetch([new Response(null, { status: 204 })])
    const client = createApiClient({ fetch })

    await expect(client.get('/api/v1/modules/{id}', {} as never)).rejects.toThrow(
      'missing path parameter "id"',
    )
  })
})

describe('createApiClient — diagnostics narrowing', () => {
  it('keeps a valid span when one is present', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        {
          code: 'unprocessable',
          message_id: 'ops-invalid-model',
          diagnostics: [
            {
              args: { name: 'x' },
              id: 'hosts-invalid-hostname',
              severity: 'error',
              span: { start: 1, end: 5 },
            },
          ],
        },
        { status: 422 },
      ),
    ])
    const client = createApiClient({ fetch })

    const result = await client.post('/api/v1/modules/{id}/apply', {
      path: { id: 'hosts' },
      body: { model: {} },
    })

    expect(result.ok).toBe(false)
    if (result.ok || result.error.kind !== 'http') return
    expect(result.error.diagnostics).toEqual([
      {
        args: { name: 'x' },
        id: 'hosts-invalid-hostname',
        severity: 'error',
        span: { start: 1, end: 5 },
      },
    ])
  })
})

describe('createApiClient — Retry-After parsing', () => {
  it('parses an HTTP-date Retry-After header', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'rate_limited', message_id: 'web-auth-rate-limited' },
        { status: 429, headers: { 'Retry-After': 'Wed, 21 Oct 2025 07:28:00 GMT' } },
      ),
    ])
    const now = Date.parse('Wed, 21 Oct 2025 07:00:00 GMT')
    const client = createApiClient({ fetch, now: () => now })

    const result = await client.post('/api/v1/auth/login', {
      body: { username: 'op', password: 'secret' },
    })

    expect(result.ok).toBe(false)
    if (result.ok || result.error.kind !== 'http') return
    expect(result.error.retryAfterSeconds).toBe(1680)
  })

  it('treats a non-numeric, non-date Retry-After header as absent', async () => {
    const { fetch } = stubFetch([
      jsonResponse(
        { code: 'rate_limited', message_id: 'web-auth-rate-limited' },
        { status: 429, headers: { 'Retry-After': 'soon' } },
      ),
    ])
    const client = createApiClient({ fetch })

    const result = await client.post('/api/v1/auth/login', {
      body: { username: 'op', password: 'secret' },
    })

    expect(result.ok).toBe(false)
    if (result.ok || result.error.kind !== 'http') return
    expect(result.error.retryAfterSeconds).toBeNull()
  })
})
