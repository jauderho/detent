/**
 * The certificates screen: the serving certificate, full-page.
 *
 * Shares the one `useCert` query shape and the 30-day/expired amber rule
 * with the dashboard panel; only the failed-query banner words are shared
 * (`audit-filter-*` copy stays on the audit page).
 */

import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import type { SessionView } from '@/api/auth'
import type { CertReport } from '@/api/system'
import { errorResponse, jsonResponse, renderWithProviders, stubFetchByUrl } from '@/test/providers'
import { CertificatesPage } from '../CertificatesPage'

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
