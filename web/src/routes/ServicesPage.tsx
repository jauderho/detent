/**
 * The services screen: the run state of every service a module configures,
 * and the four commands `docs/API.md` lets an operator issue against it.
 *
 * There is no endpoint that lists every service on the host — a service is
 * addressed by its module id (`GET /api/v1/services/{id}`), so this page
 * fans out from `useModules()` to one status query per service-bearing
 * module. Each status query is its own row's concern: a row whose query
 * fails shows that failure in its own cells rather than pulling down the
 * whole table, and the four columns that read the status (`unit`, `state`,
 * `enabled`, `since`, `actions`) all read the same query — react-query dedupes
 * the identical key into one request per module.
 */

import { Localized, useLocalization } from '@fluent/react'
import { type ReactNode, useState } from 'react'
import type { ModuleDescriptor } from '@/api/modules'
import { useModules } from '@/api/modules'
import { useApiErrorMessage } from '@/api/query'
import type { ServiceCommand, ServiceStatus } from '@/api/services'
import { useServiceAction, useServiceStatus } from '@/api/services'
import { useWriteGate } from '@/auth/ScopeGate'
import { Banner, type BannerTone } from '@/components/Banner'
import { Button, ButtonGroup } from '@/components/Button'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Led } from '@/components/Led'
import { Modal } from '@/components/Modal'
import { Panel } from '@/components/Panel'
import { TinyButton } from '@/components/TinyButton'
import { formatSystemTime, localeOf } from '@/lib/format'
import { serviceActionCaption, serviceStateLabel, serviceStateLed } from './serviceLabels'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 18,
  letterSpacing: '-0.01em',
  marginBottom: 16,
} as const

type ActionBanner = { tone: BannerTone; message: string }

/** The distinct commands every service-bearing binding on a module allows. */
function actionsFor(descriptor: ModuleDescriptor): ServiceCommand[] {
  const seen = new Set<ServiceCommand>()
  const ordered: ServiceCommand[] = []
  for (const binding of descriptor.services) {
    for (const action of binding.actions) {
      if (seen.has(action)) continue
      seen.add(action)
      ordered.push(action)
    }
  }
  return ordered
}

/**
 * One row's status query, shared by every column that reads it. Loading and
 * error states are rendered here so a failed row never fails the table.
 */
function StatusField({
  moduleId,
  children,
}: {
  moduleId: string
  children: (status: ServiceStatus) => ReactNode
}) {
  const { l10n } = useLocalization()
  const errorMessage = useApiErrorMessage()
  const query = useServiceStatus(moduleId)

  if (query.isPending) return <>{l10n.getString('state-loading')}</>
  if (query.isError) return <>{errorMessage(query.error)}</>
  return <>{children(query.data)}</>
}

function ServiceActionsCell({
  moduleId,
  unit,
  actions,
  onResult,
}: {
  moduleId: string
  unit: string
  actions: readonly ServiceCommand[]
  onResult: (banner: ActionBanner) => void
}) {
  const { l10n } = useLocalization()
  const gate = useWriteGate()
  const mutation = useServiceAction(moduleId)
  const errorMessage = useApiErrorMessage()
  const [confirming, setConfirming] = useState<ServiceCommand | null>(null)

  function confirm(): void {
    if (confirming === null) return
    const command = confirming
    mutation.mutate(command, {
      onSuccess: (report) => {
        onResult({
          tone: 'blue',
          message: l10n.getString('services-acted', { unit: report.unit, detail: report.detail }),
        })
      },
      onError: (error) => {
        onResult({ tone: 'amber', message: errorMessage(error) })
      },
    })
    setConfirming(null)
  }

  return (
    <>
      <ButtonGroup label={l10n.getString('services-col-actions')}>
        {actions.map((command) => (
          <TinyButton
            key={command}
            disabled={!gate.canWrite}
            title={gate.reason}
            onClick={() => {
              setConfirming(command)
            }}
          >
            {serviceActionCaption(l10n, command)}
          </TinyButton>
        ))}
      </ButtonGroup>
      <Modal
        open={confirming !== null}
        onClose={() => {
          setConfirming(null)
        }}
        title={
          confirming === null
            ? ''
            : l10n.getString('services-confirm-title', {
                action: serviceActionCaption(l10n, confirming),
                unit,
              })
        }
        footer={
          <ButtonGroup>
            <Button variant="primary" onClick={confirm}>
              {confirming === null ? '' : serviceActionCaption(l10n, confirming)}
            </Button>
            <Button
              onClick={() => {
                setConfirming(null)
              }}
            >
              {l10n.getString('services-confirm-cancel')}
            </Button>
          </ButtonGroup>
        }
      >
        {l10n.getString('services-confirm-body')}
      </Modal>
    </>
  )
}

export function ServicesPage() {
  const { l10n } = useLocalization()
  const errorMessage = useApiErrorMessage()
  const modulesQuery = useModules()
  const [banner, setBanner] = useState<ActionBanner | null>(null)

  const columns: DataTableColumn<ModuleDescriptor>[] = [
    {
      key: 'module',
      header: l10n.getString('services-col-module'),
      render: (row) => row.id,
    },
    {
      key: 'unit',
      header: l10n.getString('services-col-unit'),
      render: (row) => <StatusField moduleId={row.id}>{(status) => status.unit}</StatusField>,
    },
    {
      key: 'state',
      header: l10n.getString('services-col-state'),
      render: (row) => (
        <StatusField moduleId={row.id}>
          {(status) => (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <Led variant={serviceStateLed(status.state)} />
              {serviceStateLabel(l10n, status.state)}
            </span>
          )}
        </StatusField>
      ),
    },
    {
      key: 'enabled',
      header: l10n.getString('services-col-enabled'),
      render: (row) => (
        <StatusField moduleId={row.id}>
          {(status) => {
            if (status.enabled === null || status.enabled === undefined) {
              return l10n.getString('state-unknown')
            }
            return status.enabled ? l10n.getString('value-yes') : l10n.getString('value-no')
          }}
        </StatusField>
      ),
    },
    {
      key: 'since',
      header: l10n.getString('services-col-since'),
      render: (row) => (
        <StatusField moduleId={row.id}>
          {(status) =>
            status.since === null || status.since === undefined
              ? l10n.getString('state-unknown')
              : (formatSystemTime(localeOf(l10n), status.since) ?? l10n.getString('state-unknown'))
          }
        </StatusField>
      ),
    },
    {
      key: 'actions',
      header: l10n.getString('services-col-actions'),
      render: (row) => (
        <StatusField moduleId={row.id}>
          {(status) => (
            <ServiceActionsCell
              moduleId={row.id}
              unit={status.unit}
              actions={actionsFor(row)}
              onResult={setBanner}
            />
          )}
        </StatusField>
      ),
    },
  ]

  const rows = (modulesQuery.data ?? []).filter((descriptor) => descriptor.services.length > 0)

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>
        <Localized id="page-services-title">
          <span>services</span>
        </Localized>
      </h1>

      {banner === null ? null : (
        <div style={{ marginBottom: 12 }}>
          <Banner tone={banner.tone}>
            <span className="verbatim">{banner.message}</span>
          </Banner>
        </div>
      )}

      <Panel label={l10n.getString('services-panel-label')}>
        {modulesQuery.isPending ? (
          <p>{l10n.getString('state-loading')}</p>
        ) : modulesQuery.isError ? (
          <Banner tone="amber">{errorMessage(modulesQuery.error)}</Banner>
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            getRowKey={(row) => row.id}
            emptyMessage={l10n.getString('services-empty')}
          />
        )}
      </Panel>
    </section>
  )
}
