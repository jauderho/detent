/**
 * The module list: every module compiled into this build, with enough of its
 * descriptor to decide which one to open.
 *
 * `useModules()` is a plain `GET`, so there is no mutation state here — just
 * the three states any query-backed page has to answer for (loading, failed,
 * empty) plus the populated table.
 */

import { Localized, useLocalization } from '@fluent/react'
import { Link } from 'react-router'
import { resolveApiError } from '@/api/messages'
import { type ModuleDescriptor, useModules } from '@/api/modules'
import { Banner } from '@/components/Banner'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Panel } from '@/components/Panel'
import { moduleDetailPath } from './paths'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 18,
  letterSpacing: '-0.01em',
  marginBottom: 16,
} as const

export function ModulesPage() {
  const { l10n } = useLocalization()
  const query = useModules()

  const columns: readonly DataTableColumn<ModuleDescriptor>[] = [
    {
      key: 'module',
      header: l10n.getString('modules-col-module'),
      render: (row) => <Link to={moduleDetailPath(row.id)}>{row.id}</Link>,
    },
    {
      key: 'targets',
      header: l10n.getString('modules-col-targets'),
      numeric: true,
      render: (row) => row.targets.length,
    },
    {
      key: 'services',
      header: l10n.getString('modules-col-services'),
      numeric: true,
      render: (row) => row.services.length,
    },
    {
      key: 'commit-confirm',
      header: l10n.getString('modules-col-commit-confirm'),
      render: (row) =>
        row.commit_confirm
          ? l10n.getString('modules-commit-confirm-required')
          : l10n.getString('modules-commit-confirm-not-required'),
    },
  ]

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>
        <Localized id="page-modules-title">
          <span>modules</span>
        </Localized>
      </h1>

      <Panel label={l10n.getString('modules-panel-label')}>
        {query.isPending ? (
          <p>
            <Localized id="state-loading">
              <span>loading</span>
            </Localized>
          </p>
        ) : query.isError ? (
          <Banner tone="amber">{resolveApiError(l10n, query.error.apiError)}</Banner>
        ) : (
          <DataTable
            columns={columns}
            rows={query.data}
            getRowKey={(row) => row.id}
            emptyMessage={l10n.getString('modules-empty')}
          />
        )}
      </Panel>
    </section>
  )
}
