/**
 * The backups screen: there is no "list every backup" endpoint, so this page
 * fans out per module, one panel and one query each. The tests below cover
 * the module-list query, one module's listing failing independently of
 * another's, the restore confirm flow through to the mutation, and the write
 * gate disabling the restore control.
 */

import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import type { SessionView } from '@/api/auth'
import type { BackupInfo, RestoredView } from '@/api/backups'
import type { ModuleDescriptor } from '@/api/modules'
import { errorResponse, jsonResponse, renderWithProviders, stubFetch } from '@/test/providers'
import { BackupsPage } from '../BackupsPage'

const READ_WRITE_SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: true,
}

const READ_ONLY_SESSION: SessionView = { ...READ_WRITE_SESSION, scopes: ['read'] }

function buildModule(id: string): ModuleDescriptor {
  return {
    checks: [],
    commit_confirm: false,
    display_name_id: `module-${id}`,
    id,
    security_notes: [],
    services: [],
    targets: [],
    upstream: {
      docs: [],
      project: id,
      repo_url: `https://example.test/${id}`,
      tracked_version: '1.0.0',
    },
  }
}

function buildBackup(overrides: Partial<BackupInfo> = {}): BackupInfo {
  return {
    created_unix_s: 1_700_000_000,
    digest: 'a'.repeat(64),
    id: 0,
    len: 2048,
    name: 'backup-0.tar',
    target: 0,
    ...overrides,
  }
}

describe('BackupsPage — module list', () => {
  it('shows the loading state before the module list answers', () => {
    const stub = stubFetch([])
    renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    expect(screen.getAllByText('loading').length).toBeGreaterThan(0)
  })

  it('shows the resolved sentence when the module list fails, never the message id', async () => {
    const stub = stubFetch([
      errorResponse(500, 'ops-unknown-module', 'server_error'),
      jsonResponse(READ_WRITE_SESSION),
    ])
    renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('there is no module by that name in this build.')
    expect(alert.textContent).not.toContain('ops-unknown-module')
  })
})

describe('BackupsPage — per-module panels', () => {
  it('renders one panel per module and shows a failed listing without breaking the others', async () => {
    const modules = [buildModule('alpha'), buildModule('beta')]
    const stub = stubFetch([
      jsonResponse(modules),
      jsonResponse(READ_WRITE_SESSION),
      errorResponse(500, 'ops-unknown-module', 'server_error'),
      jsonResponse([buildBackup({ name: 'beta-backup.tar' })]),
    ])
    const { container } = renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    // Panel labels interpolate the module id (`{$module} backups`), and
    // Fluent wraps interpolated values in bidi-isolation marks — so the
    // panels are picked out by DOM order (modules render in list order)
    // rather than by matching that label text verbatim.
    await waitFor(() => {
      expect(container.querySelectorAll('section.panel')).toHaveLength(2)
    })
    const [alphaPanel, betaPanel] = Array.from(
      container.querySelectorAll<HTMLElement>('section.panel'),
    )
    if (alphaPanel === undefined || betaPanel === undefined) throw new Error('unreachable')

    await waitFor(() => {
      expect(
        within(alphaPanel).getByText('there is no module by that name in this build.'),
      ).toBeInTheDocument()
    })
    await waitFor(() => {
      expect(within(betaPanel).getByText('beta-backup.tar')).toBeInTheDocument()
    })
  })

  it('shows the empty message when a module has no retained backups', async () => {
    const stub = stubFetch([
      jsonResponse([buildModule('alpha')]),
      jsonResponse(READ_WRITE_SESSION),
      jsonResponse([]),
    ])
    renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText('nothing has been backed up for this module yet.'),
    ).toBeInTheDocument()
  })

  it('renders the populated columns', async () => {
    const stub = stubFetch([
      jsonResponse([buildModule('alpha')]),
      jsonResponse(READ_WRITE_SESSION),
      jsonResponse([
        buildBackup({ name: 'alpha-1.tar', len: 2048, digest: 'b'.repeat(64), id: 1 }),
      ]),
    ])
    renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    expect(await screen.findByText('alpha-1.tar')).toBeInTheDocument()
    expect(screen.getByText('2.0 KiB')).toBeInTheDocument()
    expect(screen.getByText(`${'b'.repeat(12)}…`)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'restore' })).toBeInTheDocument()
  })
})

describe('BackupsPage — restoring a backup', () => {
  it('confirms through the modal and posts the restore, then shows the result', async () => {
    const user = userEvent.setup()
    const stub = stubFetch([
      jsonResponse([buildModule('alpha')]),
      jsonResponse(READ_WRITE_SESSION),
      jsonResponse([buildBackup({ name: 'alpha-1.tar', id: 7 })]),
    ])
    renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    const restoreButton = await screen.findByRole('button', { name: 'restore' })
    await waitFor(() => {
      expect(restoreButton).not.toBeDisabled()
    })
    await user.click(restoreButton)

    const dialog = await screen.findByRole('dialog', { name: 'restore this backup?' })
    expect(dialog).toHaveTextContent('alpha-1.tar')

    const restored: RestoredView = { new_hash: 'c'.repeat(64), target: 0 }
    stub.push(jsonResponse(restored))
    stub.push(jsonResponse([buildBackup({ name: 'alpha-1.tar', id: 7 })]))

    await user.click(within(dialog).getByRole('button', { name: 'restore' }))

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })

    const postCall = stub.calls.find((call) => call.init.method === 'POST')
    expect(postCall).toBeDefined()
    expect(postCall?.url).toBe('/api/v1/modules/alpha/backups/7/restore')

    expect(await screen.findByText('the backup was restored.')).toBeInTheDocument()
  })

  it('disables the restore control and states the reason for a read-only session', async () => {
    const stub = stubFetch([
      jsonResponse([buildModule('alpha')]),
      jsonResponse(READ_ONLY_SESSION),
      jsonResponse([buildBackup({ name: 'alpha-1.tar', id: 7 })]),
    ])
    renderWithProviders(<BackupsPage />, { fetch: stub.fetch })

    const restoreButton = await screen.findByRole('button', { name: 'restore' })
    expect(restoreButton).toBeDisabled()
    await waitFor(() => {
      expect(restoreButton).toHaveAttribute(
        'title',
        'this session carries read access only; it cannot change anything on this host.',
      )
    })
  })
})
