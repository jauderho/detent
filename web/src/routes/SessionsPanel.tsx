/**
 * The active sessions of the signed-in account (ASVS 3.3.4, docs/API.md
 * "Active sessions"): every browser signed in to it, and a way to end any
 * of them.
 *
 * A session is named by the random handle the host gives it, never by its
 * id. The current session is marked and has no "end" control here: signing
 * out is the status bar's job. Each end asks for confirmation first; the list
 * is read again after every answer, so what is shown is what the host holds.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useApiClient } from '@/api/ApiProvider'
import {
  fetchSessions,
  revokeOtherSessions,
  revokeSession,
  SESSIONS_QUERY_KEY,
  type SessionSummary,
} from '@/api/auth'
import { unwrap, useApiErrorMessage } from '@/api/query'
import { Banner, type BannerTone } from '@/components/Banner'
import { Button, ButtonGroup } from '@/components/Button'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Modal } from '@/components/Modal'
import { Panel } from '@/components/Panel'
import { TinyButton } from '@/components/TinyButton'
import { formatUnixSeconds, localeOf } from '@/lib/format'

const SECONDS_PER_MINUTE = 60

const BODY_STYLE = { display: 'grid', gap: 12 } as const

/** What the confirmation dialog is about to end. */
type Confirming = { kind: 'one'; session: SessionSummary } | { kind: 'others' }

type Notice = { tone: BannerTone; message: string }

export function SessionsPanel() {
  const { l10n } = useLocalization()
  const client = useApiClient()
  const queryClient = useQueryClient()
  const errorMessage = useApiErrorMessage()
  const [confirming, setConfirming] = useState<Confirming | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)

  const sessions = useQuery({
    queryKey: SESSIONS_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchSessions(client, signal)),
  })

  const end = useMutation({
    mutationFn: async (target: Confirming): Promise<string> => {
      if (target.kind === 'one') {
        await unwrap(revokeSession(client, target.session.handle))
        return l10n.getString('sessions-ended-one')
      }
      const { ended } = await unwrap(revokeOtherSessions(client))
      return l10n.getString('sessions-ended-others', { count: ended })
    },
    onSuccess: (message) => {
      setNotice({ tone: 'blue', message })
    },
    onError: (error) => {
      setNotice({ tone: 'amber', message: errorMessage(error) })
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: SESSIONS_QUERY_KEY })
    },
  })

  const locale = localeOf(l10n)

  function timeOf(seconds: number): string {
    return formatUnixSeconds(locale, seconds) ?? l10n.getString('state-unknown')
  }

  function confirm(): void {
    if (confirming === null) return
    setNotice(null)
    end.mutate(confirming)
    setConfirming(null)
  }

  const columns: DataTableColumn<SessionSummary>[] = [
    {
      key: 'created',
      header: l10n.getString('sessions-col-created'),
      render: (row) => timeOf(row.created_unix_s),
    },
    {
      key: 'last-seen',
      header: l10n.getString('sessions-col-last-seen'),
      render: (row) => timeOf(row.last_seen_unix_s),
    },
    {
      key: 'expires',
      header: l10n.getString('sessions-col-expires'),
      numeric: true,
      render: (row) =>
        l10n.getString('sessions-expires-minutes', {
          minutes: Math.ceil(row.expires_in_secs / SECONDS_PER_MINUTE),
        }),
    },
    {
      key: 'totp',
      header: l10n.getString('sessions-col-totp'),
      render: (row) =>
        row.totp_satisfied
          ? l10n.getString('sessions-totp-yes')
          : l10n.getString('sessions-totp-no'),
    },
    {
      key: 'actions',
      header: l10n.getString('sessions-col-actions'),
      render: (row) =>
        row.current ? (
          <strong>{l10n.getString('sessions-current')}</strong>
        ) : (
          <TinyButton
            disabled={end.isPending}
            aria-label={l10n.getString('sessions-end-label', {
              time: timeOf(row.created_unix_s),
            })}
            onClick={() => {
              setConfirming({ kind: 'one', session: row })
            }}
          >
            {l10n.getString('sessions-end')}
          </TinyButton>
        ),
    },
  ]

  const others = sessions.data?.filter((row) => !row.current).length ?? 0

  return (
    <Panel
      label={l10n.getString('sessions-panel-label')}
      action={
        <Button
          disabled={others === 0 || end.isPending}
          onClick={() => {
            setConfirming({ kind: 'others' })
          }}
        >
          {l10n.getString('sessions-end-others')}
        </Button>
      }
    >
      <div style={BODY_STYLE}>
        {notice === null ? null : <Banner tone={notice.tone}>{notice.message}</Banner>}
        <Localized id="sessions-intro">
          <p>every browser signed in to this account. end any you do not recognize.</p>
        </Localized>
        {sessions.isPending ? (
          <Localized id="sessions-loading">
            <p>reading the active sessions.</p>
          </Localized>
        ) : sessions.isError ? (
          <Banner tone="amber">{errorMessage(sessions.error)}</Banner>
        ) : (
          <DataTable
            columns={columns}
            rows={sessions.data}
            getRowKey={(row) => row.handle}
            caption={l10n.getString('sessions-caption')}
          />
        )}
      </div>

      <Modal
        open={confirming !== null}
        onClose={() => {
          setConfirming(null)
        }}
        title={
          confirming?.kind === 'others'
            ? l10n.getString('sessions-confirm-others-title')
            : l10n.getString('sessions-confirm-one-title')
        }
        footer={
          <ButtonGroup>
            <Button variant="primary" onClick={confirm}>
              {confirming?.kind === 'others'
                ? l10n.getString('sessions-end-others')
                : l10n.getString('sessions-end')}
            </Button>
            <Button
              onClick={() => {
                setConfirming(null)
              }}
            >
              {l10n.getString('sessions-confirm-cancel')}
            </Button>
          </ButtonGroup>
        }
      >
        {confirming === null
          ? ''
          : confirming.kind === 'others'
            ? l10n.getString('sessions-confirm-others-body')
            : l10n.getString('sessions-confirm-one-body', {
                time: timeOf(confirming.session.created_unix_s),
              })}
      </Modal>
    </Panel>
  )
}
