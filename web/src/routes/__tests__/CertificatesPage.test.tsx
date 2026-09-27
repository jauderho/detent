/**
 * The certificates screen: the serving certificate, full-page.
 *
 * Shares the one `useCert` query shape and the 30-day/expired amber rule
 * with the dashboard panel; only the failed-query banner words are shared
 * (`audit-filter-*` copy stays on the audit page).
 */

import { describe, expect, it } from 'bun:test'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView } from '@/api/auth'
import type { CertReport } from '@/api/system'
import { errorResponse, jsonResponse, renderWithProviders, stubFetchByUrl } from '@/test/providers'
import { CertificatesPage } from '../CertificatesPage'

const READ_ONLY_SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read'],
  subject: 'operator',
  totp_satisfied: false,
}

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
}

function report(overrides: Partial<CertReport> = {}): CertReport {
  return {
    fingerprint: 'AA:BB:CC:DD',
    lifetime_used_percent: 10,
    not_after_unix: 2_000_000_000,
    ...overrides,
  }
}

function handlers(cert: CertReport | null) {
  return [
    ['/auth/session', () => jsonResponse(SESSION)],
    [
      '/system/cert',
      () => (cert === null ? errorResponse(500, 'web-engine-stopped') : jsonResponse(cert)),
    ],
  ] as const
}

describe('CertificatesPage', () => {
  it('renders fingerprint, expiry, and lifetime used', async () => {
    const stub = stubFetchByUrl([...handlers(report())])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })

    expect(await screen.findByText('AA:BB:CC:DD')).toBeInTheDocument()
    expect(screen.getByText('10%')).toBeInTheDocument()
    expect(screen.getByText('certificates')).toBeInTheDocument()
  })

  it('warns when half the lifetime is used', async () => {
    const far = Math.floor(Date.now() / 1000) + 300 * 86_400
    const stub = stubFetchByUrl([
      ...handlers(report({ not_after_unix: far, lifetime_used_percent: 60 })),
    ])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })
    expect(
      await screen.findByText('half the certificate lifetime is used; renewal is scheduled.'),
    ).toBeInTheDocument()
  })

  it('warns when three quarters of the lifetime is used', async () => {
    const far = Math.floor(Date.now() / 1000) + 300 * 86_400
    const stub = stubFetchByUrl([
      ...handlers(report({ not_after_unix: far, lifetime_used_percent: 80 })),
    ])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })
    expect(
      await screen.findByText('three quarters of the certificate lifetime is used; renew soon.'),
    ).toBeInTheDocument()
  })

  it('warns when the certificate is expiring soon', async () => {
    const soon = Math.floor(Date.now() / 1000) + 10 * 86_400
    const stub = stubFetchByUrl([...handlers(report({ not_after_unix: soon }))])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })
    expect(await screen.findByText('expires within 30 days; plan renewal.')).toBeInTheDocument()
  })

  it('warns when the certificate is expired', async () => {
    const past = Math.floor(Date.now() / 1000) - 60
    const stubExpired = stubFetchByUrl([...handlers(report({ not_after_unix: past }))])
    renderWithProviders(<CertificatesPage />, { fetch: stubExpired.fetch })
    expect(await screen.findByText('expired; replace this certificate.')).toBeInTheDocument()
  })

  it('shows the backend error when the certificate query fails', async () => {
    const stub = stubFetchByUrl([...handlers(null)])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText(
        'the operations engine is no longer running; retry once the service is back.',
      ),
    ).toBeInTheDocument()
  })
})

describe('CertificatesPage — renew now', () => {
  function renewHandlers(respond: () => Response) {
    return [
      ['/auth/session', () => jsonResponse(SESSION)],
      ['GET /system/cert', () => jsonResponse(report())],
      ['POST /system/cert/renew', respond],
    ] as const
  }

  it('disables the button for a read-only session and states why', async () => {
    const stub = stubFetchByUrl([
      ['/auth/session', () => jsonResponse(READ_ONLY_SESSION)],
      ['GET /system/cert', () => jsonResponse(report())],
    ])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })

    const button = await screen.findByRole('button', { name: 'renew now' })
    expect(button).toBeDisabled()
    await waitFor(() => {
      expect(button).toHaveAttribute(
        'title',
        'this session carries read access only; it cannot change anything on this host.',
      )
    })
  })

  it('shows the success text and refetches the certificate after 202', async () => {
    const user = userEvent.setup()
    let posts = 0
    const stub = stubFetchByUrl([
      ...renewHandlers(() => {
        posts += 1
        return jsonResponse({ requested: true }, { status: 202 })
      }),
    ])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: 'renew now' }))
    expect(
      await screen.findByText(
        'renewal requested. The new certificate is installed when the CA issues it.',
      ),
    ).toBeInTheDocument()
    await waitFor(() => {
      expect(posts).toBe(1)
    })
    const gets = stub.calls.filter(
      (call) => call.url.includes('/system/cert') && call.init.method !== 'POST',
    )
    // Initial load plus the refetch the mutation triggers on success.
    expect(gets.length).toBeGreaterThanOrEqual(2)
  })

  it('shows the server message when no ACME client runs', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl([
      ...renewHandlers(() => errorResponse(409, 'web-cert-renew-not-acme')),
    ])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: 'renew now' }))
    expect(
      await screen.findByText('renewal needs `tls.bootstrap = "acme"` in detent.toml.'),
    ).toBeInTheDocument()
  })

  it('shows the server message when the ACME client is gone', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl([
      ...renewHandlers(() => errorResponse(503, 'web-cert-renew-unavailable')),
    ])
    renderWithProviders(<CertificatesPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: 'renew now' }))
    expect(
      await screen.findByText('the acme client did not get the renewal request; try again later.'),
    ).toBeInTheDocument()
  })

  it('disables the button while the request runs', async () => {
    // The stub clones every answer, so a deferred responder cannot work
    // here (a promise has no `clone`). Delay the POST one level up, at a
    // fetch wrapper, so the mutation stays pending in between.
    const stub = stubFetchByUrl([
      ...renewHandlers(() => jsonResponse({ requested: true }, { status: 202 })),
    ])
    const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const response = await stub.fetch(input, init)
      if ((init?.method ?? 'GET').toUpperCase() === 'POST') {
        await new Promise((resolve) => setTimeout(resolve, 500))
      }
      return response
    }) as unknown as typeof globalThis.fetch
    renderWithProviders(<CertificatesPage />, { fetch })

    const button = await screen.findByRole('button', { name: 'renew now' })
    await waitFor(() => {
      expect(button).not.toBeDisabled()
    })
    fireEvent.click(button)
    await waitFor(() => {
      expect(button).toBeDisabled()
    })
    await screen.findByText(
      'renewal requested. The new certificate is installed when the CA issues it.',
    )
  })
})
