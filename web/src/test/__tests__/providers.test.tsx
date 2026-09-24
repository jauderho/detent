import { describe, expect, it } from 'bun:test'
import { stubFetch, stubFetchByUrl } from '@/test/providers'

describe('stubFetchByUrl', () => {
  it('matches a method-prefixed rule', async () => {
    const { fetch, calls } = stubFetchByUrl([
      ['POST /api/v1/test', () => new Response('created', { status: 201 })],
    ])

    const response = await fetch('http://localhost/api/v1/test', { method: 'POST' })
    expect(response.status).toBe(201)
    expect(calls.length).toBe(1)
    expect(calls[0]?.url).toContain('/api/v1/test')
  })

  it('rejects when no rule matches', async () => {
    const { fetch } = stubFetchByUrl([['/api/v1/other', () => new Response('ok')]])

    await expect(fetch('http://localhost/api/v1/missing')).rejects.toThrow(
      'stubFetchByUrl: no rule matches GET http://localhost/api/v1/missing',
    )
  })
})

describe('stubFetch', () => {
  it('rejects when no response is configured', async () => {
    const { fetch } = stubFetch()

    await expect(fetch('http://localhost/api/v1/test')).rejects.toThrow(
      'stubFetch: no response configured',
    )
  })
})

