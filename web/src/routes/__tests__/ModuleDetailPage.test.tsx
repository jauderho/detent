/**
 * One module's page: its facts, the validate/plan/apply cycle against the
 * schema-driven form, the write gate, and the hash-conflict guard.
 *
 * `renderWithProviders` always mounts `AuthProvider`, which fires its own
 * session probe concurrently with this page's `useModule()` query — the two
 * requests race, so every test dispatches responses by URL rather than call
 * order.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route, Routes } from 'react-router'
import type { ApplyReport, ModuleDescriptor, ModuleView, PlanReport } from '@/api/modules'
import { PendingCommitSlot } from '@/app/PendingCommit'
import { errorResponse, jsonResponse, renderWithProviders, type StubCall } from '@/test/providers'
import { ModuleDetailPage } from '../ModuleDetailPage'
import { moduleDetailPath, ROUTES } from '../paths'

/**
 * A `fetch` keyed by exact URL rather than call order — see the file header.
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

function bodyOf(call: StubCall | undefined): unknown {
  if (call === undefined) return null
  const raw = call.init.body
  return typeof raw === 'string' ? JSON.parse(raw) : null
}

const AUTH_ROUTE = '/api/v1/auth/session'
const MODULE_ROUTE = '/api/v1/modules/hosts'
const VALIDATE_ROUTE = '/api/v1/modules/hosts/validate'
const PLAN_ROUTE = '/api/v1/modules/hosts/plan'
const APPLY_ROUTE = '/api/v1/modules/hosts/apply'

function session(scopes: readonly string[]): Response {
  return jsonResponse({
    csrf_token: 'csrf-abc',
    expires_in_secs: 900,
    scopes,
    subject: 'operator',
    totp_satisfied: true,
  })
}

const WRITE_SESSION = session(['read', 'write'])
const READ_ONLY_SESSION = session(['read'])

const CURRENT_HASH = '0123456789abcdef'.repeat(4)

/**
 * `ModuleView.model` and `.schema` are generated as `Record<string, never>` —
 * openapi-typescript's placeholder for "arbitrary JSON", since utoipa has no
 * schema for one. Fixtures need the real shape, so this is the one place a
 * fixture is cast into that placeholder.
 */
function arbitraryJson<T>(value: T): Record<string, never> {
  return value as unknown as Record<string, never>
}

const SCHEMA = {
  type: 'object',
  properties: {
    hostname: { type: 'string' },
  },
  required: ['hostname'],
} as const

const DESCRIPTOR: ModuleDescriptor = {
  checks: [],
  commit_confirm: true,
  display_name_id: 'core-hosts-display-name',
  id: 'hosts',
  security_notes: ['core-hosts-security-note-lockout'],
  services: [
    {
      actions: ['restart', 'reload'],
      units: { systemd: ['hosts.service'], openrc: [], bsdrc: [] },
    },
  ],
  targets: [{ kind: 'file', mode: 0o644, owner: 'root', path: '/etc/hosts' }],
  upstream: {
    docs: [],
    project: 'hosts',
    release_feed: null,
    repo_url: 'https://example.test/hosts',
    tracked_version: '1.0',
  },
}

const VIEW: ModuleView = {
  current_hash: CURRENT_HASH,
  descriptor: DESCRIPTOR,
  diagnostics: [],
  model: arbitraryJson({ hostname: 'box' }),
  schema: arbitraryJson(SCHEMA),
}

const VIEW_NO_MODEL: ModuleView = {
  ...VIEW,
  current_hash: null,
  model: null,
}

function renderDetail(routes: Readonly<Record<string, () => Response | Promise<Response>>>): {
  fetch: typeof globalThis.fetch
  calls: StubCall[]
} {
  const stub = routedFetch(routes)
  renderWithProviders(
    <>
      <PendingCommitSlot />
      <Routes>
        <Route path={ROUTES.moduleDetail} element={<ModuleDetailPage />} />
      </Routes>
    </>,
    { fetch: stub.fetch, route: moduleDetailPath('hosts') },
  )
  return stub
}

describe('ModuleDetailPage — states', () => {
  it('shows the loading state while the module is in flight', () => {
    renderDetail({ [AUTH_ROUTE]: () => WRITE_SESSION, [MODULE_ROUTE]: () => new Promise(() => {}) })

    expect(screen.getByText('loading')).toBeInTheDocument()
  })

  it('redirects to the module list when the route carries no id', async () => {
    const stub = routedFetch({ [AUTH_ROUTE]: () => WRITE_SESSION })
    renderWithProviders(
      <Routes>
        <Route path="/modules" element={<p>modules list</p>} />
        <Route path="/no-id-here" element={<ModuleDetailPage />} />
      </Routes>,
      { fetch: stub.fetch, route: '/no-id-here' },
    )

    expect(await screen.findByText('modules list')).toBeInTheDocument()
  })

  it('shows a banner for a failed fetch, never the raw message id', async () => {
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => errorResponse(404, 'ops-unknown-module'),
    })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('there is no module by that name in this build.')
    expect(alert.textContent).not.toContain('ops-unknown-module')
  })

  it('offers the module defaults and says so when no file exists on this host yet', async () => {
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW_NO_MODEL),
    })

    expect(
      await screen.findByText(/the form below starts from the module's own defaults/),
    ).toBeInTheDocument()
    expect(screen.getByLabelText('hostname')).toHaveValue('')
    expect(screen.getByText('unknown')).toBeInTheDocument()
  })

  it('renders the module facts', async () => {
    renderDetail({ [AUTH_ROUTE]: () => WRITE_SESSION, [MODULE_ROUTE]: () => jsonResponse(VIEW) })

    await screen.findByLabelText('hostname')
    expect(screen.getByText('hosts 1.0')).toBeInTheDocument()
    expect(screen.getByText('/etc/hosts')).toBeInTheDocument()
    expect(screen.getByText('hosts.service')).toBeInTheDocument()
    expect(screen.getByText('0123456789ab…')).toBeInTheDocument()
    expect(screen.getByText('core-hosts-security-note-lockout')).toBeInTheDocument()
    expect(screen.getByLabelText('hostname')).toHaveValue('box')
  })
})

describe('ModuleDetailPage — editing', () => {
  it('clears the validate-clean and applied banners when the model changes', async () => {
    const user = userEvent.setup()
    const stub = renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [VALIDATE_ROUTE]: () => jsonResponse([]),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'validate' }))
    expect(
      await screen.findByText('this configuration passed every check this host runs.'),
    ).toBeInTheDocument()

    await user.clear(screen.getByLabelText('hostname'))
    await user.type(screen.getByLabelText('hostname'), 'changed')

    expect(screen.queryByText('this configuration passed every check this host runs.')).toBeNull()
    expect(stub.calls.filter((each) => each.url === VALIDATE_ROUTE)).toHaveLength(1)
  })

  it('resets the form to the on-disk model when discard is clicked', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
    })
    const field = await screen.findByLabelText('hostname')

    await user.clear(field)
    await user.type(field, 'changed')
    expect(field).toHaveValue('changed')

    await user.click(screen.getByRole('button', { name: 'discard edits' }))

    await waitFor(() => {
      expect(screen.getByLabelText('hostname')).toHaveValue('box')
    })
  })
})

describe('ModuleDetailPage — validate', () => {
  it('shows the clean banner and sends the current model', async () => {
    const user = userEvent.setup()
    const stub = renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [VALIDATE_ROUTE]: () => jsonResponse([]),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'validate' }))

    expect(
      await screen.findByText('this configuration passed every check this host runs.'),
    ).toBeInTheDocument()
    const call = stub.calls.find((each) => each.url === VALIDATE_ROUTE)
    expect(bodyOf(call)).toEqual({ model: { hostname: 'box' } })
  })

  it('feeds returned diagnostics to the form instead of the clean banner', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [VALIDATE_ROUTE]: () =>
        jsonResponse([{ severity: 'warning', id: 'core-hosts-note', field: 'hostname', args: {} }]),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'validate' }))

    expect(
      await screen.findByText(
        /this host reported a check result this build has no description for/,
      ),
    ).toBeInTheDocument()
    expect(screen.queryByText('this configuration passed every check this host runs.')).toBeNull()
  })

  it('shows a banner when validation fails on the server', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [VALIDATE_ROUTE]: () => errorResponse(422, 'ops-invalid-model', 'invalid_model'),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'validate' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('that configuration is not valid.')
  })
})

describe('ModuleDetailPage — plan', () => {
  it('says there is nothing to apply when the plan would not change anything', async () => {
    const user = userEvent.setup()
    const NO_CHANGE: PlanReport = {
      affected_services: [],
      checks: [],
      current_hash: CURRENT_HASH,
      diagnostics: [],
      diff: [],
      module: 'hosts',
      path: '/etc/hosts',
      rendered: 'unchanged\n',
      unified_diff: '',
      would_change: false,
    }
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [PLAN_ROUTE]: () => jsonResponse(NO_CHANGE),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'plan' }))

    const dialog = await screen.findByRole('dialog', { name: 'planned change' })
    expect(
      within(dialog).getByText(
        'this configuration matches what is already on disk; there is nothing to apply.',
      ),
    ).toBeInTheDocument()
  })

  it('shows the diff, the check results and the affected services', async () => {
    const user = userEvent.setup()
    const CHANGE: PlanReport = {
      affected_services: [{ actions: ['restart'], unit: 'hosts.service' }],
      checks: [
        { detail: 'ok', exit_code: 0, passed: true, program: '/usr/bin/checkhosts', ran: true },
        {
          detail: 'missing binary',
          exit_code: null,
          passed: false,
          program: '/usr/bin/other',
          ran: false,
        },
      ],
      current_hash: CURRENT_HASH,
      diagnostics: [],
      diff: [],
      module: 'hosts',
      path: '/etc/hosts',
      rendered: 'localhost 127.0.0.1\n',
      unified_diff: '-old line\n+new line\n',
      would_change: true,
    }
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [PLAN_ROUTE]: () => jsonResponse(CHANGE),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'plan' }))
    await screen.findByRole('dialog', { name: 'planned change' })

    expect(screen.getByText(/new line/)).toBeInTheDocument()
    const passedItem = screen.getByText(/checkhosts/).closest('li')
    expect(passedItem).toHaveTextContent('passed')
    // Fluent wraps `{$code}` in Unicode bidi-isolate marks, so a literal
    // "exit 0" substring never appears; match around the boundary instead.
    expect(passedItem?.textContent).toMatch(/exit\D*0/)
    const failedItem = screen.getByText(/\/usr\/bin\/other/).closest('li')
    expect(failedItem).toHaveTextContent('failed')
    expect(failedItem).not.toHaveTextContent('exit')
    expect(screen.getAllByText('hosts.service').length).toBeGreaterThan(0)
  })

  it('shows a banner when planning fails on the server', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [PLAN_ROUTE]: () => errorResponse(409, 'ops-hash-conflict', 'conflict'),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'plan' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(
      'the file changed on disk since it was read; re-read it and try again.',
    )
  })

  it('closes the plan dialog and returns focus to the plan button', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [PLAN_ROUTE]: () =>
        jsonResponse({
          affected_services: [],
          checks: [],
          current_hash: CURRENT_HASH,
          diagnostics: [],
          diff: [],
          module: 'hosts',
          path: '/etc/hosts',
          rendered: 'unchanged\n',
          unified_diff: '',
          would_change: false,
        }),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'plan' }))
    const dialog = await screen.findByRole('dialog', { name: 'planned change' })
    await user.click(within(dialog).getByRole('button', { name: 'cancel' }))

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })
    expect(screen.getByRole('button', { name: 'plan' })).toHaveFocus()
  })

  it('opens the apply dialog from the plan dialog', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [PLAN_ROUTE]: () =>
        jsonResponse({
          affected_services: [],
          checks: [],
          current_hash: CURRENT_HASH,
          diagnostics: [],
          diff: [],
          module: 'hosts',
          path: '/etc/hosts',
          rendered: 'localhost 127.0.0.1\n',
          unified_diff: '-old line\n+new line\n',
          would_change: true,
        }),
    })
    await screen.findByLabelText('hostname')

    await user.click(screen.getByRole('button', { name: 'plan' }))
    const planDialog = await screen.findByRole('dialog', { name: 'planned change' })
    await user.click(within(planDialog).getByRole('button', { name: 'apply this change' }))

    const applyDialog = await screen.findByRole('dialog', { name: 'apply this change?' })
    expect(applyDialog).toHaveTextContent('/etc/hosts')
  })
})

describe('ModuleDetailPage — apply dialog', () => {
  it('closes the apply dialog with the cancel button', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
    })
    await screen.findByLabelText('hostname')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'apply' })).not.toBeDisabled()
    })

    await user.click(screen.getByRole('button', { name: 'apply' }))
    const dialog = await screen.findByRole('dialog', { name: 'apply this change?' })
    await user.click(within(dialog).getByRole('button', { name: 'cancel' }))

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })
  })
})

describe('ModuleDetailPage — apply', () => {
  it('confirms, sends expected_hash and the chosen service action, and arms the pending commit', async () => {
    const user = userEvent.setup()
    const REPORT: ApplyReport = {
      backed_up: true,
      checks: [],
      commit: {
        commit_id: 7,
        deadline: new Date(Date.now() + 60_000).toISOString(),
        rollback_targets: 1,
        timeout_s: 60,
      },
      created: false,
      module: 'hosts',
      new_hash: 'f'.repeat(64),
      path: '/etc/hosts',
      prev_hash: CURRENT_HASH,
      service: null,
    }
    const stub = renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [APPLY_ROUTE]: () => jsonResponse(REPORT),
    })
    await screen.findByLabelText('hostname')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'apply' })).not.toBeDisabled()
    })

    await user.click(screen.getByRole('button', { name: 'apply' }))
    const dialog = await screen.findByRole('dialog', { name: 'apply this change?' })
    // `{$path}` arrives wrapped in Fluent's bidi-isolate marks, so check the
    // surrounding prose and the path as separate substrings.
    const body = within(dialog).getByText(/this writes/)
    expect(body.textContent).toContain('/etc/hosts')
    expect(
      within(dialog).getByText(/this module can lock an administrator out/),
    ).toBeInTheDocument()

    await user.selectOptions(within(dialog).getByLabelText('afterwards'), 'restart')
    await user.click(within(dialog).getByRole('button', { name: 'apply' }))

    const applied = await screen.findByText(/the change was written to/)
    expect(applied.textContent).toContain('/etc/hosts')
    expect(screen.queryByRole('dialog', { name: 'apply this change?' })).toBeNull()
    expect(
      await screen.findByText(
        'a configuration change is waiting to be confirmed; it rolls back on its own when this window closes.',
      ),
    ).toBeInTheDocument()

    const call = stub.calls.find((each) => each.url === APPLY_ROUTE)
    expect(bodyOf(call)).toEqual({
      model: { hostname: 'box' },
      expected_hash: CURRENT_HASH,
      service_action: 'restart',
    })
  })

  it('disables apply and states the reason for a read-only session', async () => {
    renderDetail({
      [AUTH_ROUTE]: () => READ_ONLY_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
    })
    await screen.findByLabelText('hostname')

    const button = await waitFor(() => {
      const candidate = screen.getByRole('button', { name: 'apply' })
      expect(candidate).toBeDisabled()
      return candidate
    })
    expect(button).toHaveAttribute(
      'title',
      'this session carries read access only; it cannot change anything on this host.',
    )
  })

  it('shows a banner and feeds diagnostics back when apply is rejected', async () => {
    const user = userEvent.setup()
    renderDetail({
      [AUTH_ROUTE]: () => WRITE_SESSION,
      [MODULE_ROUTE]: () => jsonResponse(VIEW),
      [APPLY_ROUTE]: () =>
        jsonResponse(
          {
            code: 'invalid_model',
            diagnostics: [
              { severity: 'error', id: 'core-hosts-note', field: 'hostname', args: {} },
            ],
            message_id: 'ops-invalid-model',
          },
          { status: 422 },
        ),
    })
    await screen.findByLabelText('hostname')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'apply' })).not.toBeDisabled()
    })

    await user.click(screen.getByRole('button', { name: 'apply' }))
    const dialog = await screen.findByRole('dialog', { name: 'apply this change?' })
    await user.click(within(dialog).getByRole('button', { name: 'apply' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('that configuration is not valid.')
    expect(
      await screen.findByText(
        /this host reported a check result this build has no description for/,
      ),
    ).toBeInTheDocument()
  })
})
