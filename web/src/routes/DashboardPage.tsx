/**
 * The landing page: what detection found about this host, the serving
 * certificate, how many modules this build carries, and the tail of the audit
 * log.
 *
 * Four independent panels, four independent queries — a host that cannot
 * answer `audit` should not blank the module count next to it, so each panel
 * owns its own loading and error state rather than the page gating on all
 * four together.
 */

import { Localized, type ReactLocalization, useLocalization } from '@fluent/react'
import { Link } from 'react-router'
import { useModules } from '@/api/modules'
import { useApiErrorMessage } from '@/api/query'
import type { AuditRecord, CertReport, HostReport } from '@/api/system'
import { useAudit, useCert, useHostProfile } from '@/api/system'
import { Banner } from '@/components/Banner'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { GridCell, HairlineGrid } from '@/components/HairlineGrid'
import { Label } from '@/components/Label'
import { Panel } from '@/components/Panel'
import { Readout, Screen } from '@/components/Screen'
import { certExpired, certGridItems, certTone } from '@/lib/cert'
import { localeOf } from '@/lib/format'
import { auditOpText, auditResultNode, auditRowKey, auditWhenText } from './AuditPage'
import { ROUTES } from './paths'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 22,
  letterSpacing: '-0.02em',
  marginBottom: 16,
} as const

const PANELS_STYLE = { display: 'grid', gap: 16 } as const

const NOTES_STYLE = {
  marginTop: 12,
  display: 'flex',
  flexDirection: 'column',
  gap: 4,
} as const

const NOTES_LIST_STYLE = { margin: 0, paddingLeft: 18 } as const

const PANEL_ACTIONS_STYLE = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: 12,
  flexWrap: 'wrap',
} as const

const VIEW_ALL_ROW_STYLE = { marginTop: 12 } as const

/** Unit suffix on the memory readout — an IEC symbol, never translated. */
const RAM_UNIT = 'MiB'

const RECENT_AUDIT_LIMIT = 5

type HostGridItem = { readonly label: string; readonly value: string }

/**
 * The host panel's definition-list rows. `os` and `init` are the server's raw
 * enum values (`linux`, `systemd`, …) rather than a localized word: the ids
 * this build has copy for name the *field*, not each possible value.
 */
function hostGridItems(l10n: ReactLocalization, report: HostReport): HostGridItem[] {
  const locale = localeOf(l10n)
  const unknown = l10n.getString('state-unknown')
  const distro =
    report.distro_id === null || report.distro_id === undefined
      ? unknown
      : report.distro_version_id === null || report.distro_version_id === undefined
        ? report.distro_id
        : `${report.distro_id} ${report.distro_version_id}`
  const ram = `${new Intl.NumberFormat(locale).format(report.profile.ram_mib)} ${RAM_UNIT}`

  return [
    { label: l10n.getString('dashboard-host-hostname'), value: report.profile.hostname },
    { label: l10n.getString('dashboard-host-os'), value: report.profile.os },
    { label: l10n.getString('dashboard-host-init'), value: report.profile.init },
    { label: l10n.getString('dashboard-host-distro'), value: distro },
    { label: l10n.getString('dashboard-host-ram'), value: ram },
    { label: l10n.getString('dashboard-host-network-backend'), value: report.network_backend },
    { label: l10n.getString('dashboard-host-resolver-backend'), value: report.resolver_backend },
  ]
}

function HostGrid({ items }: { items: HostGridItem[] }) {
  return (
    <HairlineGrid columns={3}>
      {items.map((item) => (
        <GridCell key={item.label}>
          <Label>{item.label}</Label>
          <Screen>
            <Readout value={item.value} />
          </Screen>
        </GridCell>
      ))}
    </HairlineGrid>
  )
}

function HostPanel() {
  const { l10n } = useLocalization()
  const query = useHostProfile()
  const errorMessage = useApiErrorMessage()

  return (
    <Panel label={l10n.getString('dashboard-host-panel')}>
      {query.isPending ? (
        <Localized id="state-loading">
          <p>loading</p>
        </Localized>
      ) : query.isError ? (
        <Banner tone="amber">{errorMessage(query.error)}</Banner>
      ) : (
        <>
          <HostGrid items={hostGridItems(l10n, query.data)} />
          {query.data.notes.length > 0 ? (
            <div style={NOTES_STYLE}>
              <Label>{l10n.getString('dashboard-host-notes')}</Label>
              <ul className="verbatim" style={NOTES_LIST_STYLE}>
                {query.data.notes.map((note) => (
                  // The host's own text, never a Fluent message — left as sent.
                  <li key={note}>{note}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </>
      )}
    </Panel>
  )
}
function CertPanel() {
  const { l10n } = useLocalization()
  const query = useCert()
  const errorMessage = useApiErrorMessage()

  return (
    <Panel label={l10n.getString('dashboard-cert-panel')}>
      {query.isPending ? (
        <Localized id="state-loading">
          <p>loading</p>
        </Localized>
      ) : query.isError ? (
        <Banner tone="amber">{errorMessage(query.error)}</Banner>
      ) : (
        <CertGrid report={query.data} />
      )}
    </Panel>
  )
}

function CertGrid({ report }: { report: CertReport }) {
  const { l10n } = useLocalization()
  const [fingerprint, expires, used] = certGridItems(l10n, report)
  const expired = certExpired(report)
  const expiringSoon = !expired && certTone(report) === 'amber'
  const tone = certTone(report)
  return (
    <>
      <HairlineGrid columns={3}>
        <GridCell>
          <Label>{l10n.getString('dashboard-cert-fingerprint')}</Label>
          <Screen>
            {/* Host text, never localized — verbatim so case survives. */}
            <span className="verbatim" style={{ wordBreak: 'break-all' }}>
              <Readout value={fingerprint} tone={tone} />
            </span>
          </Screen>
        </GridCell>
        <GridCell>
          <Label>{l10n.getString('dashboard-cert-expires')}</Label>
          <Screen>
            <Readout value={expires} tone={tone} />
          </Screen>
        </GridCell>
        <GridCell>
          <Label>{l10n.getString('dashboard-cert-lifetime-used')}</Label>
          <Screen>
            <Readout value={used} tone={tone} />
          </Screen>
        </GridCell>
      </HairlineGrid>
      {expired ? (
        <Banner tone="amber">{l10n.getString('dashboard-cert-expired')}</Banner>
      ) : expiringSoon ? (
        <Banner tone="amber">{l10n.getString('dashboard-cert-expiring-soon')}</Banner>
      ) : null}
    </>
  )
}
function ModulesPanel() {
  const { l10n } = useLocalization()
  const query = useModules()
  const errorMessage = useApiErrorMessage()

  return (
    <Panel label={l10n.getString('dashboard-modules-panel')}>
      {query.isPending ? (
        <Localized id="state-loading">
          <p>loading</p>
        </Localized>
      ) : query.isError ? (
        <Banner tone="amber">{errorMessage(query.error)}</Banner>
      ) : (
        <div style={PANEL_ACTIONS_STYLE}>
          <p>{l10n.getString('dashboard-modules-count', { count: query.data.length })}</p>
          <Link className="btn" to={ROUTES.modules}>
            <Localized id="dashboard-view-all">
              <span>view all</span>
            </Localized>
          </Link>
        </div>
      )}
    </Panel>
  )
}

function RecentAuditPanel() {
  const { l10n } = useLocalization()
  const query = useAudit({ limit: RECENT_AUDIT_LIMIT })
  const errorMessage = useApiErrorMessage()

  const columns: DataTableColumn<AuditRecord>[] = [
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
      key: 'op',
      header: l10n.getString('audit-col-op'),
      render: (record) => auditOpText(l10n, record.op),
    },
    {
      key: 'result',
      header: l10n.getString('audit-col-result'),
      render: (record) => auditResultNode(l10n, record.result),
    },
  ]

  return (
    <Panel label={l10n.getString('dashboard-audit-panel')}>
      {query.isPending ? (
        <Localized id="state-loading">
          <p>loading</p>
        </Localized>
      ) : query.isError ? (
        <Banner tone="amber">{errorMessage(query.error)}</Banner>
      ) : (
        <>
          <DataTable
            columns={columns}
            rows={query.data}
            getRowKey={auditRowKey}
            emptyMessage={l10n.getString('audit-empty')}
          />
          <div style={VIEW_ALL_ROW_STYLE}>
            <Link className="btn" to={ROUTES.audit}>
              <Localized id="dashboard-view-all">
                <span>view all</span>
              </Localized>
            </Link>
          </div>
        </>
      )}
    </Panel>
  )
}

export function DashboardPage() {
  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>
        <Localized id="page-dashboard-title">
          <span>dashboard</span>
        </Localized>
      </h1>
      <div style={PANELS_STYLE}>
        <HostPanel />
        <CertPanel />
        <ModulesPanel />
        <RecentAuditPanel />
      </div>
    </section>
  )
}
