/**
 * The audit log: every operation this host recorded, filterable by module and
 * caller, newest first (the server's own order — `useAudit` does not re-sort).
 *
 * `auditWhenText`, `auditOpText` and `auditResultNode` are exported so
 * `DashboardPage`'s "recent activity" panel renders the same cells from the
 * same five records the full page would show for the same query, rather than
 * carrying a second copy of the `OpKind` → caption table that could drift
 * from this one.
 */

import { Localized, type ReactLocalization, useLocalization } from '@fluent/react'
import { type FormEvent, type ReactNode, useState } from 'react'
import { useApiErrorMessage } from '@/api/query'
import type { components } from '@/api/schema'
import type { AuditQuery, AuditRecord } from '@/api/system'
import { useAudit } from '@/api/system'
import { Banner } from '@/components/Banner'
import { Button } from '@/components/Button'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Led } from '@/components/Led'
import { NumberField } from '@/components/NumberField'
import { Panel } from '@/components/Panel'
import { TextField } from '@/components/TextField'
import { TinyButton } from '@/components/TinyButton'
import { formatRfc3339, localeOf } from '@/lib/format'

type OpKind = components['schemas']['OpKind']
type AuditResult = components['schemas']['AuditResult']
type IdentityKind = components['schemas']['IdentityKind']

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 22,
  letterSpacing: '-0.02em',
  marginBottom: 16,
} as const

const FILTER_STYLE = {
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'flex-end',
  gap: 12,
  marginBottom: 16,
} as const

const FILTER_FIELD_STYLE = { flex: '1 1 160px' } as const
const FILTER_LIMIT_STYLE = { flex: '0 1 120px' } as const
const FILTER_ACTIONS_STYLE = { display: 'flex', gap: 8 } as const

const RESULT_CELL_STYLE = { display: 'flex', alignItems: 'center', gap: 6 } as const

/** The `when` cell, or the shared unknown placeholder for a value this build cannot parse. */
export function auditWhenText(l10n: ReactLocalization, record: AuditRecord): string {
  return formatRfc3339(localeOf(l10n), record.ts) ?? l10n.getString('state-unknown')
}

/**
 * The `op` cell. A `switch` over the schema's literal union, each arm calling
 * `getString` with a literal id — `bun run i18n:check` reads ids out of the
 * source text, so a computed `audit-op-${op}` would be invisible to it.
 */
export function auditOpText(l10n: ReactLocalization, op: OpKind): string {
  switch (op) {
    case 'list_modules':
      return l10n.getString('audit-op-list-modules')
    case 'get_module':
      return l10n.getString('audit-op-get-module')
    case 'validate':
      return l10n.getString('audit-op-validate')
    case 'plan':
      return l10n.getString('audit-op-plan')
    case 'apply':
      return l10n.getString('audit-op-apply')
    case 'confirm_commit':
      return l10n.getString('audit-op-confirm-commit')
    case 'rollback_commit':
      return l10n.getString('audit-op-rollback-commit')
    case 'list_backups':
      return l10n.getString('audit-op-list-backups')
    case 'restore':
      return l10n.getString('audit-op-restore')
    case 'service_status':
      return l10n.getString('audit-op-service-status')
    case 'service_action':
      return l10n.getString('audit-op-service-action')
    case 'host_profile':
      return l10n.getString('audit-op-host-profile')
    case 'audit_query':
      return l10n.getString('audit-op-audit-query')
  }
}

/** The `how` cell: which kind of credential authenticated the caller. */
function auditIdentityText(l10n: ReactLocalization, kind: IdentityKind): string {
  switch (kind) {
    case 'local_user':
      return l10n.getString('audit-identity-local-user')
    case 'session':
      return l10n.getString('audit-identity-session')
    case 'token':
      return l10n.getString('audit-identity-token')
  }
}

/** The `result` cell: an LED plus the localized outcome — never the raw enum value. */
export function auditResultNode(l10n: ReactLocalization, result: AuditResult): ReactNode {
  switch (result) {
    case 'ok':
      return (
        <span style={RESULT_CELL_STYLE}>
          <Led variant="on" />
          <span>{l10n.getString('audit-result-ok')}</span>
        </span>
      )
    case 'denied':
      return (
        <span style={RESULT_CELL_STYLE}>
          <Led variant="rec" />
          <span>{l10n.getString('audit-result-denied')}</span>
        </span>
      )
    case 'error':
      return (
        <span style={RESULT_CELL_STYLE}>
          <Led variant="rec" />
          <span>{l10n.getString('audit-result-error')}</span>
        </span>
      )
  }
}

/**
 * A record carries no id of its own, so the row key is the fields that
 * together identify one audit line — stable across re-renders and unique for
 * anything short of two identical operations landing in the same second.
 */
export function auditRowKey(record: AuditRecord): string {
  return `${record.ts}|${record.who}|${record.op}|${record.result}|${record.module ?? ''}`
}

function auditColumns(l10n: ReactLocalization): DataTableColumn<AuditRecord>[] {
  return [
    {
      key: 'when',
      header: l10n.getString('audit-col-when'),
      render: (record) => auditWhenText(l10n, record),
    },
    {
      key: 'who',
      header: l10n.getString('audit-col-who'),
      render: (record) => record.who,
    },
    {
      key: 'how',
      header: l10n.getString('audit-col-how'),
      render: (record) => auditIdentityText(l10n, record.kind),
    },
    {
      key: 'op',
      header: l10n.getString('audit-col-op'),
      render: (record) => auditOpText(l10n, record.op),
    },
    {
      key: 'module',
      header: l10n.getString('audit-col-module'),
      render: (record) => record.module ?? l10n.getString('state-unknown'),
    },
    {
      key: 'result',
      header: l10n.getString('audit-col-result'),
      render: (record) => auditResultNode(l10n, record.result),
    },
  ]
}

/**
 * Builds the committed query from the filter drafts, omitting anything blank
 * rather than sending it empty — `AuditQuery`'s fields are optional and
 * `exactOptionalPropertyTypes` forbids writing `undefined` into them, so an
 * empty field is left out of the object entirely.
 */
function buildAuditQuery(moduleDraft: string, whoDraft: string, limitDraft: string): AuditQuery {
  const moduleValue = moduleDraft.trim()
  const whoValue = whoDraft.trim()
  const limitValue = limitDraft.trim()
  const limit = limitValue === '' ? null : Number(limitValue)
  return {
    ...(moduleValue === '' ? {} : { module: moduleValue }),
    ...(whoValue === '' ? {} : { who: whoValue }),
    ...(limit === null || !Number.isFinite(limit) ? {} : { limit }),
  }
}

export function AuditPage() {
  const { l10n } = useLocalization()
  const errorMessage = useApiErrorMessage()

  const [moduleDraft, setModuleDraft] = useState('')
  const [whoDraft, setWhoDraft] = useState('')
  const [limitDraft, setLimitDraft] = useState('')
  const [query, setQuery] = useState<AuditQuery>({})

  const auditQuery = useAudit(query)

  function applyFilters(): void {
    setQuery(buildAuditQuery(moduleDraft, whoDraft, limitDraft))
  }

  function onSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    applyFilters()
  }

  function onClear(): void {
    setModuleDraft('')
    setWhoDraft('')
    setLimitDraft('')
    setQuery({})
  }

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>
        <Localized id="page-audit-title">
          <span>audit log</span>
        </Localized>
      </h1>
      <Panel label={l10n.getString('audit-panel-label')}>
        <form onSubmit={onSubmit} style={FILTER_STYLE}>
          <div style={FILTER_FIELD_STYLE}>
            <TextField
              label={l10n.getString('audit-filter-module-label')}
              name="module"
              value={moduleDraft}
              onChange={(event) => {
                setModuleDraft(event.target.value)
              }}
            />
          </div>
          <div style={FILTER_FIELD_STYLE}>
            <TextField
              label={l10n.getString('audit-filter-who-label')}
              name="who"
              value={whoDraft}
              onChange={(event) => {
                setWhoDraft(event.target.value)
              }}
            />
          </div>
          <div style={FILTER_LIMIT_STYLE}>
            <NumberField
              label={l10n.getString('audit-filter-limit-label')}
              name="limit"
              value={limitDraft}
              onChange={(event) => {
                setLimitDraft(event.target.value)
              }}
            />
          </div>
          <div style={FILTER_ACTIONS_STYLE}>
            <Button type="submit" variant="primary">
              <Localized id="audit-filter-apply">
                <span>filter</span>
              </Localized>
            </Button>
            <TinyButton
              onClick={() => {
                onClear()
              }}
            >
              <Localized id="audit-filter-clear">
                <span>clear</span>
              </Localized>
            </TinyButton>
          </div>
        </form>

        {auditQuery.isPending ? (
          <Localized id="state-loading">
            <p>loading</p>
          </Localized>
        ) : auditQuery.isError ? (
          <Banner tone="amber">{errorMessage(auditQuery.error)}</Banner>
        ) : (
          <DataTable
            columns={auditColumns(l10n)}
            rows={auditQuery.data}
            getRowKey={auditRowKey}
            emptyMessage={l10n.getString('audit-empty')}
          />
        )}
      </Panel>
    </section>
  )
}
