/**
 * The audit log page: the table, the filter row, and every enum this build
 * must render as a caption rather than a raw value.
 *
 * `AuditPage` fires its own `useAudit` query alongside `AuthProvider`'s
 * session probe, so a plain call-order queue (`stubFetch`) cannot promise the
 * session response lands on the session request and the audit response on
 * the audit request. `stubFetchByUrl` below answers by matching the request
 * URL instead, which is the only thing that stays correct regardless of which
 * of the two concurrent queries fires first.
 */

import { describe, expect, it } from 'bun:test'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { SessionView } from '@/api/auth'
import type { components } from '@/api/schema'
import type { AuditRecord } from '@/api/system'
import {
  errorResponse,
  jsonResponse,
  renderWithProviders,
  type StubCall,
  stubFetchByUrl,
  type UrlRule,
} from '@/test/providers'
import { AuditPage } from '../AuditPage'

type OpKind = components['schemas']['OpKind']
type AuditResult = components['schemas']['AuditResult']
type IdentityKind = components['schemas']['IdentityKind']

const SESSION: SessionView = {
  csrf_token: 'csrf-abc',
  expires_in_secs: 900,
  scopes: ['read', 'write'],
  subject: 'operator',
  totp_satisfied: false,
}

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

function baseHandlers(auditResponse: () => Response): UrlRule[] {
  return [
    ['/auth/session', () => jsonResponse(SESSION)],
    ['/audit', auditResponse],
  ]
}

describe('AuditPage — loading, failure, empty', () => {
  it('shows the loading state before the query resolves', () => {
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([record()])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    expect(screen.getByText('loading')).toBeInTheDocument()
  })

  it('reports a query failure as a sentence, never the message id', async () => {
    const stub = stubFetchByUrl(baseHandlers(() => errorResponse(500, 'ops-audit-failed')))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('the audit log could not be read.')
    expect(alert.textContent).not.toContain('ops-audit-failed')
  })

  it('shows the empty message when the host has recorded nothing', async () => {
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    expect(
      await screen.findByText('nothing has been recorded on this host yet.'),
    ).toBeInTheDocument()
  })
})

describe('AuditPage — populated table', () => {
  it('renders every column, formatting the timestamp and falling back for a null module', async () => {
    const stub = stubFetchByUrl(
      baseHandlers(() =>
        jsonResponse([
          record({ who: 'root', kind: 'local_user', module: 'hosts', ts: '2026-01-01T12:00:00Z' }),
          record({ who: 'ci-token', kind: 'token', module: null, ts: '2026-01-02T00:00:00Z' }),
        ]),
      ),
    )
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    expect(await screen.findByText('root')).toBeInTheDocument()
    expect(screen.getByText('ci-token')).toBeInTheDocument()
    expect(screen.getByText('local user')).toBeInTheDocument()
    expect(screen.getByText('api token')).toBeInTheDocument()
    expect(screen.getByText('hosts')).toBeInTheDocument()
    // The record with no module falls back to the shared placeholder.
    expect(screen.getByText('unknown')).toBeInTheDocument()
    // The RFC 3339 timestamp is never shown raw.
    expect(screen.queryByText('2026-01-01T12:00:00Z')).toBeNull()
  })

  const OP_CASES: readonly [OpKind, string][] = [
    ['list_modules', 'list modules'],
    ['get_module', 'read module'],
    ['validate', 'validate'],
    ['plan', 'plan'],
    ['apply', 'apply'],
    ['confirm_commit', 'confirm commit'],
    ['rollback_commit', 'roll back commit'],
    ['list_backups', 'list backups'],
    ['restore', 'restore backup'],
    ['service_status', 'read service status'],
    ['service_action', 'act on service'],
    ['host_profile', 'read host profile'],
    ['audit_query', 'read audit log'],
    ['cert_status', 'read certificate status'],
    ['update_status', 'read update status'],
    ['cert_renew', 'renew certificate'],
  ]

  it.each(OP_CASES)('renders a caption for op %s, not the raw value', async (op, caption) => {
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([record({ op })])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    expect(await screen.findByText(caption)).toBeInTheDocument()
  })

  const IDENTITY_CASES: readonly [IdentityKind, string][] = [
    ['local_user', 'local user'],
    ['session', 'session'],
    ['token', 'api token'],
  ]

  it.each(IDENTITY_CASES)('renders a caption for identity kind %s', async (kind, caption) => {
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([record({ kind })])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    expect(await screen.findByText(caption)).toBeInTheDocument()
  })

  const RESULT_CASES: readonly [AuditResult, string][] = [
    ['ok', 'ok'],
    ['denied', 'denied'],
    ['error', 'failed'],
  ]

  it.each(RESULT_CASES)('renders a caption for result %s', async (result, caption) => {
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([record({ result })])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })

    expect(await screen.findByText(caption)).toBeInTheDocument()
  })

  it('lights the result LED green for ok and amber for a refusal or a failure', async () => {
    const stub = stubFetchByUrl(
      baseHandlers(() =>
        jsonResponse([
          record({ result: 'ok', ts: '2026-01-01T00:00:00Z' }),
          record({ result: 'denied', ts: '2026-01-01T00:00:01Z' }),
          record({ result: 'error', ts: '2026-01-01T00:00:02Z' }),
        ]),
      ),
    )
    const { container } = renderWithProviders(<AuditPage />, { fetch: stub.fetch })
    await screen.findByText('ok')

    const leds = container.querySelectorAll('td [aria-hidden="true"]')
    expect(leds).toHaveLength(3)
    expect(leds[0]?.className).toContain('--green')
    expect(leds[1]?.className).toContain('--amber')
    expect(leds[2]?.className).toContain('--amber')
  })
})

describe('AuditPage — filtering', () => {
  it('does not request per keystroke, and commits the filter only on apply', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([record()])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })
    await screen.findByText('operator')

    function auditCalls(): StubCall[] {
      return stub.calls.filter((call) => call.url.includes('/audit'))
    }

    // The unfiltered mount request carries no query string at all.
    expect(auditCalls()).toHaveLength(1)
    expect(auditCalls()[0]?.url).toBe('/api/v1/audit')

    await user.type(screen.getByLabelText('module'), 'hosts')
    expect(auditCalls()).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: 'filter' }))

    await waitFor(() => {
      expect(auditCalls()).toHaveLength(2)
    })
    const filtered = auditCalls()[1]?.url ?? ''
    expect(filtered).toContain('module=hosts')
    // "who" was left blank: it must be absent, not sent as an empty string.
    expect(filtered).not.toContain('who')
  })

  it('sends limit as a number, and clear resets the committed query, not just the fields', async () => {
    const user = userEvent.setup()
    const stub = stubFetchByUrl(baseHandlers(() => jsonResponse([record()])))
    renderWithProviders(<AuditPage />, { fetch: stub.fetch })
    await screen.findByText('operator')

    function auditCalls(): StubCall[] {
      return stub.calls.filter((call) => call.url.includes('/audit'))
    }

    await user.type(screen.getByLabelText('module'), 'hosts')
    await user.type(screen.getByLabelText('rows'), '10')
    await user.click(screen.getByRole('button', { name: 'filter' }))
    await waitFor(() => {
      expect(auditCalls()).toHaveLength(2)
    })
    expect(auditCalls()[1]?.url).toContain('module=hosts')
    expect(auditCalls()[1]?.url).toContain('limit=10')

    await user.click(screen.getByRole('button', { name: 'clear' }))
    expect(screen.getByLabelText('module')).toHaveValue('')
    expect(screen.getByLabelText('rows')).toHaveValue(null)

    // Requesting a query with a *different* field, right after clear, proves
    // the committed query was actually reset: if "clear" had only wiped the
    // visible drafts and left the previous `module`/`limit` committed, this
    // request would still carry them alongside `who`.
    await user.type(screen.getByLabelText('caller'), 'alice')
    await user.click(screen.getByRole('button', { name: 'filter' }))
    await waitFor(() => {
      expect(auditCalls()).toHaveLength(3)
    })
    const finalUrl = auditCalls()[2]?.url ?? ''
    expect(finalUrl).toContain('who=alice')
    expect(finalUrl).not.toContain('module')
    expect(finalUrl).not.toContain('limit')
  })
})
