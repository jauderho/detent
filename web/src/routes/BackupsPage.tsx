/**
 * The backups screen: what every module retained, and putting one back.
 *
 * There is no endpoint that lists every backup on the host — a listing is
 * addressed by its module id (`GET /api/v1/modules/{id}/backups`), so this
 * page fans out from `useModules()` to one backups panel per module. Each
 * panel owns its own query, its own restore confirmation, and its own
 * success/failure banner, so one module's failure never blocks another's
 * table from rendering.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useState } from 'react'
import type { BackupInfo } from '@/api/backups'
import { useBackups, useRestoreBackup } from '@/api/backups'
import { type ModuleDescriptor, useModule, useModules } from '@/api/modules'
import { useApiErrorMessage } from '@/api/query'
import { useWriteGate } from '@/auth/ScopeGate'
import { Banner, type BannerTone } from '@/components/Banner'
import { Button, ButtonGroup } from '@/components/Button'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Modal } from '@/components/Modal'
import { Panel } from '@/components/Panel'
import { TinyButton } from '@/components/TinyButton'
import { formatBytes, formatUnixSeconds, localeOf, shortDigest } from '@/lib/format'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 18,
  letterSpacing: '-0.01em',
  marginBottom: 16,
} as const

const PANELS_STYLE = { display: 'grid', gap: 16 } as const

type ActionBanner = { tone: BannerTone; message: string }

function BackupsPanel({ descriptor }: { descriptor: ModuleDescriptor }) {
  const { l10n } = useLocalization()
  const errorMessage = useApiErrorMessage()
  const moduleQuery = useModule(descriptor.id)
  const backupsQuery = useBackups(descriptor.id)
  const gate = useWriteGate()
  const restore = useRestoreBackup(descriptor.id)
  const [confirming, setConfirming] = useState<BackupInfo | null>(null)
  const [banner, setBanner] = useState<ActionBanner | null>(null)

  function confirmRestore(): void {
    if (confirming === null || moduleQuery.data?.current_hash == null) return
    restore.mutate(
      { backupId: confirming.id, expectedHash: moduleQuery.data.current_hash },
      {
        onSuccess: () => {
          setBanner({ tone: 'blue', message: l10n.getString('backups-restored') })
        },
        onError: (error) => {
          setBanner({ tone: 'amber', message: errorMessage(error) })
        },
      },
    )
    setConfirming(null)
  }

  const columns: DataTableColumn<BackupInfo>[] = [
    {
      key: 'name',
      header: l10n.getString('backups-col-name'),
      render: (row) => row.name,
    },
    {
      key: 'created',
      header: l10n.getString('backups-col-created'),
      render: (row) =>
        formatUnixSeconds(localeOf(l10n), row.created_unix_s) ?? l10n.getString('state-unknown'),
    },
    {
      key: 'size',
      header: l10n.getString('backups-col-size'),
      numeric: true,
      render: (row) => formatBytes(localeOf(l10n), row.len) ?? l10n.getString('state-unknown'),
    },
    {
      key: 'digest',
      header: l10n.getString('backups-col-digest'),
      render: (row) => <span className="read">{shortDigest(row.digest)}</span>,
    },
    {
      key: 'actions',
      header: l10n.getString('backups-col-actions'),
      render: (row) => (
        <TinyButton
          disabled={!gate.canWrite}
          title={gate.reason}
          onClick={() => {
            setConfirming(row)
          }}
        >
          {l10n.getString('backups-action-restore')}
        </TinyButton>
      ),
    },
  ]

  return (
    <Panel label={l10n.getString('backups-module-panel', { module: descriptor.id })}>
      {banner === null ? null : (
        <div style={{ marginBottom: 12 }}>
          <Banner tone={banner.tone}>{banner.message}</Banner>
        </div>
      )}

      {backupsQuery.isPending ? (
        <p>{l10n.getString('state-loading')}</p>
      ) : backupsQuery.isError ? (
        <Banner tone="amber">{errorMessage(backupsQuery.error)}</Banner>
      ) : (
        <DataTable
          columns={columns}
          rows={backupsQuery.data}
          getRowKey={(row) => String(row.id)}
          emptyMessage={l10n.getString('backups-empty')}
        />
      )}

      <Modal
        open={confirming !== null}
        onClose={() => {
          setConfirming(null)
        }}
        title={l10n.getString('backups-confirm-title')}
        footer={
          <ButtonGroup>
            <Button variant="primary" onClick={confirmRestore}>
              {l10n.getString('backups-action-restore')}
            </Button>
            <Button
              onClick={() => {
                setConfirming(null)
              }}
            >
              {l10n.getString('backups-confirm-cancel')}
            </Button>
          </ButtonGroup>
        }
      >
        {confirming === null
          ? ''
          : l10n.getString('backups-confirm-body', { target: confirming.name })}
      </Modal>
    </Panel>
  )
}

export function BackupsPage() {
  const { l10n } = useLocalization()
  const errorMessage = useApiErrorMessage()
  const modulesQuery = useModules()

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>
        <Localized id="page-backups-title">
          <span>backups</span>
        </Localized>
      </h1>

      {modulesQuery.isPending ? (
        <p>{l10n.getString('state-loading')}</p>
      ) : modulesQuery.isError ? (
        <Banner tone="amber">{errorMessage(modulesQuery.error)}</Banner>
      ) : (
        <div style={PANELS_STYLE}>
          {modulesQuery.data.map((descriptor) => (
            <BackupsPanel key={descriptor.id} descriptor={descriptor} />
          ))}
        </div>
      )}
    </section>
  )
}
