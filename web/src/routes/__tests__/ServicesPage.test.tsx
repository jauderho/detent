/**
 * The services screen: there is no "list every service" endpoint, so this
 * page fans out per module. The tests below cover the module-list query, a
 * row's own status query failing independently of its siblings, the confirm
 * flow through to the mutation, and the write gate disabling the controls.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView } from '@/api/auth'
import type { ModuleDescriptor } from '@/api/modules'
import type { ServiceCommand, ServiceReport, ServiceStatus } from '@/api/services'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { ServicesPage } from '../ServicesPage'

const READ_WRITE_SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: true,
}

const READ_ONLY_SESSION: SessionView = { ...READ_WRITE_SESSION, scopes: ['read'] }

function buildModule(id: string, actions: readonly ServiceCommand[]): ModuleDescriptor {
  return {
    checks: [],
    commit_confirm: false,
    display_name_id: `module-${id}`,
    id,
    security_notes: [],
    services:
      actions.length === 0
        ? []
        : [{ actions: [...actions], units: { bsdrc: [], openrc: [], systemd: [`${id}.service`] } }],
    targets: [],
    upstream: {
      docs: [],
      project: id,
      repo_url: `https://example.test/${id}`,
      tracked_version: '1.0.0',
    },
  }
}

function buildStatus(overrides: Partial<ServiceStatus> = {}): ServiceStatus {
  return {
    enabled: true,
    since: { nanos_since_epoch: 0, secs_since_epoch: 1_700_000_000 },
    state: 'active',
    unit: 'demo.service',
    ...overrides,
  }
}

describe('ServicesPage — module list', () => {
  it('shows the loading state before the module list answers', () => {
    const stub = stubFetch([])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    expect(screen.getAllByText('loading').length).toBeGreaterThan(0)
  })

  it('shows the resolved sentence when the module list fails, never the message id', async () => {
    const stub = stubFetch([
      errorResponse(500, 'ops-unknown-module', 'server_error'),
      jsonResponse(READ_WRITE_SESSION),
    ])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('there is no module by that name in this build.')
    expect(alert.textContent).not.toContain('ops-unknown-module')
  })

  it('shows the empty message when no module declares a service', async () => {
    const stub = stubFetch([
      jsonResponse([buildModule('noservice', [])]),
      jsonResponse(READ_WRITE_SESSION),
    ])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText('no module in this build controls a service on this host.'),
    ).toBeInTheDocument()
  })
})

describe('ServicesPage — rows', () => {
  it('renders one row per service-bearing module and shows a failed row without breaking the others', async () => {
    const modules = [buildModule('alpha', ['restart']), buildModule('beta', ['restart'])]
    const stub = stubFetch([
      jsonResponse(modules),
      jsonResponse(READ_WRITE_SESSION),
      errorResponse(500, 'ops-service-failed', 'server_error'),
      jsonResponse(buildStatus({ unit: 'beta.service' })),
    ])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    const alphaRow = (await screen.findByText('alpha')).closest('tr')
    const betaRow = (await screen.findByText('beta')).closest('tr')
    expect(alphaRow).not.toBeNull()
    expect(betaRow).not.toBeNull()
    if (alphaRow === null || betaRow === null) throw new Error('unreachable')

    await waitFor(() => {
      expect(
        within(alphaRow).getAllByText('the service action did not complete.').length,
      ).toBeGreaterThan(0)
    })
    await waitFor(() => {
      expect(within(betaRow).getByText('beta.service')).toBeInTheDocument()
    })
  })

  it('renders the populated status columns', async () => {
    const stub = stubFetch([
      jsonResponse([buildModule('alpha', ['restart', 'stop'])]),
      jsonResponse(READ_WRITE_SESSION),
      jsonResponse(buildStatus({ enabled: false, state: 'failed', unit: 'alpha.service' })),
    ])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    const row = (await screen.findByText('alpha')).closest('tr')
    expect(row).not.toBeNull()
    if (row === null) throw new Error('unreachable')

    expect(await within(row).findByText('alpha.service')).toBeInTheDocument()
    expect(within(row).getByText('failed')).toBeInTheDocument()
    expect(within(row).getByText('no')).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: 'restart' })).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: 'stop' })).toBeInTheDocument()
  })
})

describe('ServicesPage — acting on a service', () => {
  it('confirms through the modal and posts the command, then shows the result', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([
      jsonResponse([buildModule('alpha', ['restart'])]),
      jsonResponse(READ_WRITE_SESSION),
      jsonResponse(buildStatus({ unit: 'alpha.service' })),
    ])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    const restoreButton = await screen.findByRole('button', { name: 'restart' })
    await waitFor(() => {
      expect(restoreButton).not.toBeDisabled()
    })
    await user.click(restoreButton)

    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('restart')
    expect(dialog).toHaveTextContent('alpha.service')
    expect(
      within(dialog).getByText('this acts on the running service immediately.'),
    ).toBeInTheDocument()

    const report: ServiceReport = {
      action: 'restart',
      active: true,
      detail: 'unit restarted',
      unit: 'alpha.service',
    }
    stub.push(jsonResponse(report))
    stub.push(jsonResponse(buildStatus({ unit: 'alpha.service' })))

    await user.click(within(dialog).getByRole('button', { name: 'restart' }))

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })

    const postCall = stub.calls.find((call) => call.init.method === 'POST')
    expect(postCall).toBeDefined()
    expect(postCall?.url).toBe('/api/v1/services/alpha')
    expect(typeof postCall?.init.body === 'string' ? JSON.parse(postCall.init.body) : null).toEqual(
      { action: 'restart' },
    )

    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('alpha.service')
    expect(banner).toHaveTextContent('unit restarted')
  })

  it('disables the action and states the reason for a read-only session', async () => {
    const stub = stubFetch([
      jsonResponse([buildModule('alpha', ['restart'])]),
      jsonResponse(READ_ONLY_SESSION),
      jsonResponse(buildStatus({ unit: 'alpha.service' })),
    ])
    renderWithProviders(<ServicesPage />, { fetch: stub.fetch })

    const restartButton = await screen.findByRole('button', { name: 'restart' })
    expect(restartButton).toBeDisabled()
    await waitFor(() => {
      expect(restartButton).toHaveAttribute(
        'title',
        'this session carries read access only; it cannot change anything on this host.',
      )
    })
  })
})
