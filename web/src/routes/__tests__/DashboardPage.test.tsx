/**
 * The dashboard: four panels, four independent queries. The central claim
 * under test is that they fail independently — a host profile the server
 * cannot answer must not blank the module count or the audit tail sitting
 * next to it.
 *
 * Like `AuditPage.test.tsx`, this page fires several queries at once
 * (host profile, certificate, modules, audit, plus `AuthProvider`'s session
 * probe), so responses are matched by URL rather than by call order.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView } from '@/api/auth'
import type { ModuleDescriptor } from '@/api/modules'
import type { AuditRecord, CertReport, HostReport, UpdateReport } from '@/api/system'
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
  must_change_password: false,
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

const CERT_REPORT: CertReport = {
  fingerprint: 'AA:BB:CC:DD',
  lifetime_used_percent: 10,
  not_after_unix: 2_000_000_000,
}

const UPDATE_REPORT: UpdateReport = {
  current: '0.0.1',
  published: '2026-09-10T00:00:00Z',
  security: false,
  tag: 'v0.0.2',
  update_available: true,
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
  overrides: Partial<Record<'profile' | 'cert' | 'modules' | 'audit' | 'update', UrlRule[1]>> = {},
): UrlRule[] {
  return [
    ['/auth/session', () => jsonResponse(SESSION)],
    ['/system/profile', overrides.profile ?? (() => jsonResponse(HOST_REPORT))],
    ['/system/cert', overrides.cert ?? (() => jsonResponse(CERT_REPORT))],
    ['/system/update', overrides.update ?? (() => jsonResponse(UPDATE_REPORT))],
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

  it('renders the populated host panel, certificate, module count, and audit tail', async () => {
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

    // Certificate: fingerprint verbatim, unknown-free expiry, percent used.
    expect(screen.getByText('AA:BB:CC:DD')).toBeInTheDocument()
    expect(screen.getByText('10%')).toBeInTheDocument()

    expect(screen.getByText(/modules are compiled into this build\.$/)).toHaveTextContent('2')

    expect(screen.getByText('operator')).toBeInTheDocument()
    expect(screen.getByText('apply')).toBeInTheDocument()
    expect(screen.getByText('ok')).toBeInTheDocument()

    expect(screen.getAllByRole('link', { name: 'view all' })).toHaveLength(2)
  })

  it('keeps the host panel working when the certificate fails', async () => {
    const stub = stubFetchByUrl(
      allHandlers({ cert: () => errorResponse(500, 'web-engine-stopped') }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(await screen.findByText('nas-01')).toBeInTheDocument()
    expect(screen.queryByText('AA:BB:CC:DD')).not.toBeInTheDocument()
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(
      'the operations engine is no longer running; retry once the service is back.',
    )
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

describe('DashboardPage — update status', () => {
  it('shows the available release read-only, with no apply control', async () => {
    const stub = stubFetchByUrl(allHandlers())
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    // `l10n.getString` wraps the interpolated `{$tag}` in bidi-isolate
    // marks, so the tag is matched as its own substring.
    expect(await screen.findByText(/release .* is available for this build\./)).toHaveTextContent(
      'v0.0.2',
    )
    expect(screen.getByText('0.0.1')).toBeInTheDocument()
    // The swap (PLAN §2.9 steps 5b–5c) is not wired: the panel reports and
    // installs nothing, so the page carries no button, only readouts.
    expect(screen.queryByRole('button', { name: 'install' })).toBeNull()
  })

  it('reports an up-to-date build without a published date', async () => {
    const stub = stubFetchByUrl(
      allHandlers({
        update: () => jsonResponse({ ...UPDATE_REPORT, update_available: false, published: null }),
      }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText('no newer release is offered for this build.'),
    ).toBeInTheDocument()
    expect(screen.queryByText('published')).toBeNull()
  })

  it('flags a security release', async () => {
    const stub = stubFetchByUrl(
      allHandlers({ update: () => jsonResponse({ ...UPDATE_REPORT, security: true }) }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText(
        'this release is flagged as a security update; it bypasses the age gate.',
      ),
    ).toBeInTheDocument()
  })

  it('says so when the update check has not run, and blanks only this panel', async () => {
    const stub = stubFetchByUrl(
      allHandlers({ update: () => errorResponse(404, 'web-update-not-checked') }),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(
      'no update check has run on this host yet; run `detent update --check` as root.',
    )
    // The neighbours are untouched.
    expect(await screen.findByText('nas-01')).toBeInTheDocument()
    expect(await screen.findByText(/modules are compiled into this build\.$/)).toHaveTextContent(
      '2',
    )
  })
})

describe('DashboardPage — install update', () => {
  const READ_ONLY: SessionView = { ...SESSION, scopes: ['read'] }

  function installHandlers(session: SessionView, respond: () => Response): UrlRule[] {
    return [
      ['/auth/session', () => jsonResponse(session)],
      ['POST /system/update', respond],
      ...allHandlers().filter(([pattern]) => pattern !== '/auth/session'),
    ]
  }

  function posts(stub: ReturnType<typeof stubFetchByUrl>) {
    return stub.calls.filter(
      (call) => call.url.includes('/system/update') && call.init.method === 'POST',
    )
  }

  it('shows the install button for a write session with an update available', async () => {
    const stub = stubFetchByUrl(installHandlers(SESSION, () => jsonResponse({ version: 'v0.0.2' })))
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(await screen.findByRole('button', { name: /install.*v0\.0\.2/ })).toBeEnabled()
  })

  it('hides the button for a read-only session', async () => {
    const stub = stubFetchByUrl(
      installHandlers(READ_ONLY, () => jsonResponse({ version: 'v0.0.2' })),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(await screen.findByText(/release .*v0\.0\.2.* is available/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /install/ })).not.toBeInTheDocument()
  })

  it('hides the button when no update is available', async () => {
    const stub = stubFetchByUrl([
      ['/system/update', () => jsonResponse({ ...UPDATE_REPORT, update_available: false })],
      ...installHandlers(SESSION, () => jsonResponse({ version: 'v0.0.2' })),
    ])
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText('no newer release is offered for this build.'),
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /install/ })).not.toBeInTheDocument()
  })

  it('asks first, naming the restart, and sends nothing until confirmed', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(installHandlers(SESSION, () => jsonResponse({ version: 'v0.0.2' })))
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: /install.*v0\.0\.2/ }))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent(/in the background/)
    expect(dialog).toHaveTextContent(/restarts/)
    expect(dialog).toHaveTextContent(/reconnect/)
    expect(dialog).toHaveTextContent(/rolls back/)
    expect(posts(stub)).toHaveLength(0)

    await user.click(screen.getByRole('button', { name: 'cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(posts(stub)).toHaveLength(0)
  })

  it('closes the dialog on Escape and sends nothing', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(installHandlers(SESSION, () => jsonResponse({ version: 'v0.0.2' })))
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: /install.*v0\.0\.2/ }))
    await screen.findByRole('dialog')
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(posts(stub)).toHaveLength(0)
  })

  it('posts the tag on confirm and says the update started', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(
      installHandlers(SESSION, () => jsonResponse({ version: 'v0.0.2' }, { status: 202 })),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: /install.*v0\.0\.2/ }))
    await user.click(await screen.findByRole('button', { name: 'install' }))

    expect(
      await screen.findByText(/update to .*v0\.0\.2.* started in the background/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/is installed/)).not.toBeInTheDocument()
    await waitFor(() => {
      expect(posts(stub)).toHaveLength(1)
    })
    expect(JSON.parse(String(posts(stub)[0]?.init.body))).toEqual({ version: 'v0.0.2' })
    // The mutation refetches the update status.
    const gets = stub.calls.filter(
      (call) => call.url.includes('/system/update') && call.init.method !== 'POST',
    )
    expect(gets.length).toBeGreaterThanOrEqual(2)
  })

  it('says so when an update is already running', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(
      installHandlers(SESSION, () => errorResponse(409, 'ops-update-running')),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: /install.*v0\.0\.2/ }))
    await user.click(await screen.findByRole('button', { name: 'install' }))

    expect(
      await screen.findByText(
        'an update is already running; wait for it to finish, then check the running version.',
      ),
    ).toBeInTheDocument()
  })

  it('shows the mapped server message when the install fails', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(
      installHandlers(SESSION, () => errorResponse(409, 'ops-update-not-newer')),
    )
    renderWithProviders(<DashboardPage />, { fetch: stub.fetch })

    await user.click(await screen.findByRole('button', { name: /install.*v0\.0\.2/ }))
    await user.click(await screen.findByRole('button', { name: 'install' }))

    expect(
      await screen.findByText(
        'that release is not newer than the running version; nothing was started.',
      ),
    ).toBeInTheDocument()
  })
})
