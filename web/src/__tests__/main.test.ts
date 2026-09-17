/**
 * The entrypoint contract, both branches.
 *
 * `main.tsx` is one `mountApp(document.getElementById('root'))` call, so a
 * missing `#root` reaches the seam as null and throws. With a `#root`
 * present, mounting the shell proves the seam the entrypoint calls: the
 * status bar lands in the document. The session probe underneath is stubbed
 * to 401 through the dynamic entrypoint import below, so the probe fails
 * closed without touching the network; routing stays whatever the URL already
 * is (the sign-in screen itself is covered by `LoginPage.test.tsx`, the guard
 * by `routing.test.tsx`, and the full flows by Playwright).
 */

import { afterEach, describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import { errorResponse, stubFetchByUrl } from '@/test/providers'
import { mountApp } from '../mount'

const AUTH_ROUTE = '/api/v1/auth/session'

afterEach(() => {
  document.body.innerHTML = ''
})

describe('main', () => {
  it('throws when #root is missing', () => {
    expect(() => mountApp(document.getElementById('root'))).toThrow('#root element not found')
  })

  it('mounts the shell when #root exists', async () => {
    const stub = stubFetchByUrl([
      [AUTH_ROUTE, () => errorResponse(401, 'web-auth-unauthenticated', 'unauthorized')],
    ])
    const originalFetch = globalThis.fetch
    globalThis.fetch = stub.fetch

    const el = document.createElement('div')
    el.id = 'root'
    document.body.append(el)

    try {
      await import('../main')

      expect(await screen.findByText('detent')).toBeInTheDocument()
      expect(await screen.findByText('system online')).toBeInTheDocument()
    } finally {
      el.remove()
      globalThis.fetch = originalFetch
    }
  })
})
