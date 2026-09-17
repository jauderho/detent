/**
 * The dashboard: three panels, three independent queries. The central claim
 * under test is that they fail independently — a host profile the server
 * cannot answer must not blank the module count or the audit tail sitting
 * next to it.
 *
 * Like `AuditPage.test.tsx`, this page fires several queries at once
 * (host profile, modules, audit, plus `AuthProvider`'s session probe), so
 * responses are matched by URL rather than by call order.
 */

import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import type { SessionView } from '@/api/auth'
import type { ModuleDescriptor } from '@/api/modules'
import type { AuditRecord, HostReport } from '@/api/system'
import {
  errorResponse,
  jsonResponse,
  renderWithProviders,
  stubFetchByUrl,
  type UrlRule,
} from '@/test/providers'
import { DashboardPage } from '../DashboardPage'

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
}

const HOST_REPORT: HostReport = {
  distro_id: 'ubuntu',
  distro_version_id: '24.04',
  network_backend: 'networkd',
  notes: [],
  profile: {
    hostname: 'nas-01',
    init: 'systemd',
    os: 'linux',
    ram_mib: 8192,
    service_versions: {},
  },
  resolver_backend: 'unbound',
}

function moduleDescriptor(id: string): ModuleDescriptor {
  return {
    checks: [],
    commit_confirm: false,
    display_name_id: `module-${id}-name`,
    id,
    security_notes: [],
    services: [],
    targets: [],
    upstream: {
      docs: [],
      project: id,
      repo_url: `https://example.invalid/${id}`,
      tracked_version: '1.0.0',
    },
  }
}

const MODULES: ModuleDescriptor[] = [moduleDescriptor('hosts'), moduleDescriptor('chrony')]

function record(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    kind: 'session',
    op: 'apply',
    result: 'ok',
    ts: '2026-01-01T12:00:00Z',
    who: 'operator',
    ...overrides,
  }
}

function allHandlers(
  overrides: Partial<Record<'profile' | 'modules' | 'audit', UrlRule[1]>> = {},
): UrlRule[] {
  return [
    ['/auth/session', () => jsonResponse(SESSION)],
    ['/system/profile', overrides.profile ?? (() => jsonResponse(HOST_REPORT))],
    ['/modules', overrides.modules ?? (() => jsonResponse(MODULES))],
    ['/audit', overrides.audit ?? (() => jsonResponse([record()]))],
  ]
}

describe('DashboardPage — loading and independence', () => {
  it('shows a loading state before any panel resolves', () => {
    const stub = stubFetchByUrl(allHandlers())
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(screen.getAllByText('loading').length).toBeGreaterThan(0)
  })

  it('keeps the other two panels working when the host profile fails', async () => {
    const stub = stubFetchByUrl(
      allHandlers({ profile: () => errorResponse(500, 'web-engine-stopped') }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(
      'the operations engine is no longer running; retry once the service is back.',
    )
    // `l10n.getString` wraps the interpolated `{$count}` in bidi-isolate
    // marks, so the count is matched as its own substring rather than as
    // part of one exact sentence.
    const moduleCount = await screen.findByText(/modules are compiled into this build\.$/)
    expect(moduleCount).toHaveTextContent('2')
    expect(screen.getByText('operator')).toBeInTheDocument()
  })

  it('keeps the host and audit panels working when modules fails', async () => {
    const stub = stubFetchByUrl(
      allHandlers({ modules: () => errorResponse(500, 'ops-unsupported') }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(await screen.findByText('nas-01')).toBeInTheDocument()
    expect(await screen.findByText('operator')).toBeInTheDocument()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('that is not supported in this build.')
  })
})

describe('DashboardPage — empty and populated', () => {
  it('renders zero modules and an empty audit tail without erroring', async () => {
    const stub = stubFetchByUrl(
      allHandlers({ modules: () => jsonResponse([]), audit: () => jsonResponse([]) }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    const moduleCount = await screen.findByText(/modules are compiled into this build\.$/)
    expect(moduleCount).toHaveTextContent('0')
    expect(
      await screen.findByText('nothing has been recorded on this host yet.'),
    ).toBeInTheDocument()
  })

  it('renders the populated host panel, module count, and audit tail', async () => {
    const stub = stubFetchByUrl(allHandlers())
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(await screen.findByText('nas-01')).toBeInTheDocument()
    expect(screen.getByText('linux')).toBeInTheDocument()
    expect(screen.getByText('systemd')).toBeInTheDocument()
    expect(screen.getByText('ubuntu 24.04')).toBeInTheDocument()
    // en-US grouping from Intl.NumberFormat, with the IEC unit appended.
    expect(screen.getByText('8,192 MiB')).toBeInTheDocument()
    expect(screen.getByText('networkd')).toBeInTheDocument()
    expect(screen.getByText('unbound')).toBeInTheDocument()

    expect(screen.getByText(/modules are compiled into this build\.$/)).toHaveTextContent('2')

    expect(screen.getByText('operator')).toBeInTheDocument()
    expect(screen.getByText('apply')).toBeInTheDocument()
    expect(screen.getByText('ok')).toBeInTheDocument()

    expect(screen.getAllByRole('link', { name: 'view all' })).toHaveLength(2)
  })

  it('falls back to the shared unknown placeholder for a host with no distro', async () => {
    const stub = stubFetchByUrl(
      allHandlers({
        profile: () => jsonResponse({ ...HOST_REPORT, distro_id: null, distro_version_id: null }),
      }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await screen.findByText('nas-01')
    expect(screen.getByText('unknown')).toBeInTheDocument()
  })

  it('shows the host detection notes when the report carries any', async () => {
    const stub = stubFetchByUrl(
      allHandlers({
        profile: () =>
          jsonResponse({ ...HOST_REPORT, notes: ['resolver falls back to systemd-resolved'] }),
      }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(await screen.findByText('resolver falls back to systemd-resolved')).toBeInTheDocument()
  })

  it('omits the notes block entirely when there are none', async () => {
    const stub = stubFetchByUrl(allHandlers())
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await screen.findByText('nas-01')
    expect(screen.queryByText('detection notes')).toBeNull()
  })
})
