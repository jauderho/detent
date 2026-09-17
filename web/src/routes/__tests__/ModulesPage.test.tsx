/**
 * The module list: loading, a failed fetch, the empty build, and the
 * populated table with its link, counts and commit-confirm column.
 *
 * `renderWithProviders` always mounts `AuthProvider`, which fires its own
 * session probe concurrently with this page's `useModules()` query — the two
 * requests race, so responses are dispatched by URL rather than call order.
 */

import { describe, expect, it } from 'bun:test'
import { screen, within } from '@testing-library/react'
import type { ModuleDescriptor } from '@/api/modules'
import { errorResponse, jsonResponse, renderWithProviders, type StubCall } from '@/test/providers'
import { ModulesPage } from '../ModulesPage'

/**
 * A `fetch` keyed by exact URL rather than call order. Every page test mounts
 * alongside `AuthProvider`'s own session probe, a request with no ordering
 * guarantee relative to the page's own query.
 */
function routedFetch(routes: Readonly<Record<string, () => Response | Promise<Response>>>): {
  fetch: typeof globalThis.fetch
  calls: StubCall[]
} {
  const calls: StubCall[] = []
  const fetch = (url: string | URL | Request, init?: RequestInit) => {
    const key = String(url)
    calls.push({ url: key, init: init ?? {} })
    const factory = routes[key]
    if (factory === undefined) {
      return Promise.reject(new TypeError(`routedFetch: no stub for ${key}`))
    }
    // Cloned so the same fixture `Response` can answer more than one call —
    // across tests here, and within a test when a route fires more than once
    // — without "body already read" on the second consumer.
    return Promise.resolve(factory()).then((response) => response.clone())
  }
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls }
}

const AUTH_ROUTE = '/api/v1/auth/session'
const MODULES_ROUTE = '/api/v1/modules'

const SESSION = jsonResponse({
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: true,
})

const HOSTS: ModuleDescriptor = {
  checks: [],
  commit_confirm: false,
  display_name_id: 'core-hosts-display-name',
  id: 'hosts',
  security_notes: [],
  services: [],
  targets: [{ kind: 'file', mode: 0o644, owner: 'root', path: '/etc/hosts' }],
  upstream: {
    docs: [],
    project: 'hosts',
    release_feed: null,
    repo_url: 'https://example.test/hosts',
    tracked_version: '1.0',
  },
}

const CHRONY: ModuleDescriptor = {
  checks: [],
  commit_confirm: true,
  display_name_id: 'core-chrony-display-name',
  id: 'chrony',
  security_notes: [],
  services: [
    { actions: ['restart'], units: { systemd: ['chronyd.service'], openrc: [], bsdrc: [] } },
  ],
  targets: [{ kind: 'file', mode: 0o644, owner: 'root', path: '/etc/chrony.conf' }],
  upstream: {
    docs: [],
    project: 'chrony',
    release_feed: null,
    repo_url: 'https://example.test/chrony',
    tracked_version: '4.5',
  },
}

describe('ModulesPage', () => {
  it('shows the loading state while the list is in flight', async () => {
    const stub = routedFetch({
      [AUTH_ROUTE]: () => SESSION,
      [MODULES_ROUTE]: () => new Promise(() => {}),
    })
    renderWithProviders(<ModulesPage />, { fetch: stub.fetch })

    expect(screen.getByText('loading')).toBeInTheDocument()
  })

  it('shows a banner for a failed fetch, never the raw message id', async () => {
    const stub = routedFetch({
      [AUTH_ROUTE]: () => SESSION,
      [MODULES_ROUTE]: () => errorResponse(500, 'web-engine-stopped'),
    })
    renderWithProviders(<ModulesPage />, { fetch: stub.fetch })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('the operations engine is no longer running')
    expect(alert.textContent).not.toContain('web-engine-stopped')
  })

  it('shows the empty message when this build has no modules', async () => {
    const stub = routedFetch({
      [AUTH_ROUTE]: () => SESSION,
      [MODULES_ROUTE]: () => jsonResponse([]),
    })
    renderWithProviders(<ModulesPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText('this build has no modules compiled into it.'),
    ).toBeInTheDocument()
  })

  it('renders every module with its link, counts and commit-confirm state', async () => {
    const stub = routedFetch({
      [AUTH_ROUTE]: () => SESSION,
      [MODULES_ROUTE]: () => jsonResponse([HOSTS, CHRONY]),
    })
    renderWithProviders(<ModulesPage />, { fetch: stub.fetch })

    const hostsLink = await screen.findByRole('link', { name: 'hosts' })
    expect(hostsLink).toHaveAttribute('href', '/modules/hosts')
    const hostsRow = hostsLink.closest('tr')
    if (hostsRow === null) throw new Error('expected a table row')
    expect(within(hostsRow).getByText('not required')).toBeInTheDocument()

    const chronyLink = screen.getByRole('link', { name: 'chrony' })
    expect(chronyLink).toHaveAttribute('href', '/modules/chrony')
    const chronyRow = chronyLink.closest('tr')
    if (chronyRow === null) throw new Error('expected a table row')
    expect(within(chronyRow).getByText('required')).toBeInTheDocument()
    // one target, one service, per the CHRONY fixture above.
    expect(within(chronyRow).getAllByText('1')).toHaveLength(2)
  })
})
