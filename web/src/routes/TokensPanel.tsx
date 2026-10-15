/**
 * The API tokens of this host (ASVS 1.2.4, docs/API.md "API tokens"): the
 * list, a form that mints one, and a way to revoke one.
 *
 * Minting and revoking go through the step-up guard (`useStepUp`), so the
 * host can ask for the password first. A new token's value is in the create
 * answer only: it is shown once, in a read-only field with a copy control,
 * and dropped when the operator closes it or leaves the page. The list never
 * carries a value. Each revoke asks for confirmation first; the list is read
 * again after every answer, so what is shown is what the host holds.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { type FormEvent, useEffect, useRef, useState } from 'react'
import { useApiClient } from '@/api/ApiProvider'
import {
  createToken,
  fetchTokens,
  type IssuedToken,
  revokeToken,
  TOKENS_QUERY_KEY,
  type TokenRequest,
  type TokenView,
} from '@/api/auth'
import { unwrap, useApiErrorMessage } from '@/api/query'
import { useStepUp } from '@/app/StepUp'
import { Banner, type BannerTone } from '@/components/Banner'
import { Button, ButtonGroup } from '@/components/Button'
import { DataTable, type DataTableColumn } from '@/components/DataTable'
import { Modal } from '@/components/Modal'
import { NumberField } from '@/components/NumberField'
import { Panel } from '@/components/Panel'
import { SelectField } from '@/components/SelectField'
import { TextField } from '@/components/TextField'
import { TinyButton } from '@/components/TinyButton'
import { formatRfc3339, formatUnixSeconds, localeOf } from '@/lib/format'

/** The longest label the host accepts. */
const MAX_LABEL_LENGTH = 64

const SECONDS_PER_DAY = 86_400

const MS_PER_SECOND = 1000

const BODY_STYLE = { display: 'grid', gap: 12 } as const

const FORM_STYLE = { display: 'grid', gap: 12, maxWidth: 420 } as const

const ROW_STYLE = { display: 'flex', gap: 12, alignItems: 'center' } as const

type Scope = TokenRequest['scope']

type Notice = { tone: BannerTone; message: string }

export function TokensPanel() {
  const { l10n } = useLocalization()
  const client = useApiClient()
  const queryClient = useQueryClient()
  const stepUp = useStepUp()
  const errorMessage = useApiErrorMessage()
  const [label, setLabel] = useState('')
  const [scope, setScope] = useState<Scope>('read')
  const [days, setDays] = useState('')
  const [issued, setIssued] = useState<IssuedToken | null>(null)
  const [copied, setCopied] = useState(false)
  const [revoking, setRevoking] = useState<TokenView | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const secretField = useRef<HTMLInputElement>(null)

  const tokens = useQuery({
    queryKey: TOKENS_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchTokens(client, signal)),
  })

  function refresh(): void {
    void queryClient.invalidateQueries({ queryKey: TOKENS_QUERY_KEY })
  }

  const create = useMutation({
    mutationFn: (request: TokenRequest) => unwrap(stepUp(() => createToken(client, request))),
    onSuccess: (answer) => {
      setIssued(answer)
      setCopied(false)
      setLabel('')
      setDays('')
    },
    onError: (error) => {
      setNotice({ tone: 'amber', message: errorMessage(error) })
    },
    onSettled: refresh,
  })

  const revoke = useMutation({
    mutationFn: (token: TokenView) => unwrap(stepUp(() => revokeToken(client, token.id))),
    onSuccess: () => {
      setNotice({ tone: 'blue', message: l10n.getString('tokens-revoked-notice') })
    },
    onError: (error) => {
      setNotice({ tone: 'amber', message: errorMessage(error) })
    },
    onSettled: refresh,
  })

  // The value is the next thing to act on once it is on screen.
  useEffect(() => {
    if (issued !== null) secretField.current?.focus()
  }, [issued])

  const locale = localeOf(l10n)
  const busy = create.isPending || revoke.isPending

  function onCreate(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    setNotice(null)
    setIssued(null)
    // The field's `min` and `step` keep anything but whole days of 1 or more
    // from being submitted; the host checks again.
    create.mutate(
      days === ''
        ? { label, scope }
        : { label, scope, expires_in_secs: Number(days) * SECONDS_PER_DAY },
    )
  }

  function onCopy(value: string): void {
    void navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true)
      },
      () => {
        setCopied(false)
      },
    )
  }

  function onConfirmRevoke(): void {
    if (revoking === null) return
    setNotice(null)
    revoke.mutate(revoking)
    setRevoking(null)
  }

  function expiryOf(row: TokenView): string {
    if (row.expires_at === null || row.expires_at === undefined) {
      return l10n.getString('tokens-expires-never')
    }
    if (row.expires_at * MS_PER_SECOND <= Date.now()) {
      return l10n.getString('tokens-expired')
    }
    return formatUnixSeconds(locale, row.expires_at) ?? l10n.getString('state-unknown')
  }

  const columns: DataTableColumn<TokenView>[] = [
    {
      key: 'label',
      header: l10n.getString('tokens-col-label'),
      // Host text, never localized.
      render: (row) => <span className="verbatim">{row.label}</span>,
    },
    {
      key: 'scope',
      header: l10n.getString('tokens-col-scope'),
      render: (row) =>
        row.scopes.includes('write')
          ? l10n.getString('tokens-scope-write')
          : l10n.getString('tokens-scope-read'),
    },
    {
      key: 'created',
      header: l10n.getString('tokens-col-created'),
      render: (row) => formatRfc3339(locale, row.created) ?? l10n.getString('state-unknown'),
    },
    {
      key: 'expires',
      header: l10n.getString('tokens-col-expires'),
      render: expiryOf,
    },
    {
      key: 'actions',
      header: l10n.getString('tokens-col-actions'),
      render: (row) => (
        <TinyButton
          disabled={busy}
          aria-label={l10n.getString('tokens-revoke-label', { label: row.label })}
          onClick={() => {
            setRevoking(row)
          }}
        >
          {l10n.getString('tokens-revoke')}
        </TinyButton>
      ),
    },
  ]

  return (
    <Panel label={l10n.getString('tokens-panel-label')}>
      <div style={BODY_STYLE}>
        {notice === null ? null : <Banner tone={notice.tone}>{notice.message}</Banner>}
        <Localized id="tokens-intro">
          <p>
            a token lets a script use the api without a session. it holds read, or read and write.
          </p>
        </Localized>

        {issued === null ? null : (
          <section aria-label={l10n.getString('tokens-secret-region')} style={BODY_STYLE}>
            <TextField
              ref={secretField}
              label={l10n.getString('tokens-secret-label', { label: issued.label })}
              description={l10n.getString('tokens-secret-note')}
              name="token"
              value={issued.token}
              readOnly
              autoComplete="off"
              spellCheck={false}
              onFocus={(event) => {
                event.currentTarget.select()
              }}
            />
            <div style={ROW_STYLE}>
              <Button
                variant="primary"
                onClick={() => {
                  onCopy(issued.token)
                }}
              >
                {l10n.getString('tokens-secret-copy')}
              </Button>
              <Button
                onClick={() => {
                  setIssued(null)
                }}
              >
                {l10n.getString('tokens-secret-done')}
              </Button>
              <span role="status">{copied ? l10n.getString('tokens-secret-copied') : ''}</span>
            </div>
          </section>
        )}

        {tokens.isPending ? (
          <Localized id="tokens-loading">
            <p>reading the api tokens.</p>
          </Localized>
        ) : tokens.isError ? (
          <Banner tone="amber">{errorMessage(tokens.error)}</Banner>
        ) : (
          <DataTable
            columns={columns}
            rows={tokens.data}
            getRowKey={(row) => row.id}
            caption={l10n.getString('tokens-caption')}
            emptyMessage={l10n.getString('tokens-empty')}
          />
        )}

        <form
          method="post"
          aria-label={l10n.getString('tokens-create-form-label')}
          onSubmit={onCreate}
          style={FORM_STYLE}
        >
          <TextField
            label={l10n.getString('tokens-label-label')}
            description={l10n.getString('tokens-label-description')}
            name="label"
            value={label}
            maxLength={MAX_LABEL_LENGTH}
            autoComplete="off"
            required
            disabled={busy}
            onChange={(event) => {
              setLabel(event.target.value)
            }}
          />
          <SelectField
            label={l10n.getString('tokens-scope-label')}
            name="scope"
            value={scope}
            disabled={busy}
            options={[
              { value: 'read', label: l10n.getString('tokens-scope-read') },
              { value: 'write', label: l10n.getString('tokens-scope-write') },
            ]}
            onChange={(event) => {
              setScope(event.target.value === 'write' ? 'write' : 'read')
            }}
          />
          <NumberField
            label={l10n.getString('tokens-expiry-label')}
            description={l10n.getString('tokens-expiry-description')}
            name="expires_in_days"
            value={days}
            min={1}
            step={1}
            disabled={busy}
            onChange={(event) => {
              setDays(event.target.value)
            }}
          />
          <div style={ROW_STYLE}>
            <Button type="submit" variant="primary" disabled={busy}>
              {create.isPending
                ? l10n.getString('tokens-create-submitting')
                : l10n.getString('tokens-create-submit')}
            </Button>
          </div>
        </form>
      </div>

      <Modal
        open={revoking !== null}
        onClose={() => {
          setRevoking(null)
        }}
        title={l10n.getString('tokens-confirm-title')}
        footer={
          <ButtonGroup>
            <Button variant="primary" onClick={onConfirmRevoke}>
              {l10n.getString('tokens-revoke')}
            </Button>
            <Button
              onClick={() => {
                setRevoking(null)
              }}
            >
              {l10n.getString('tokens-confirm-cancel')}
            </Button>
          </ButtonGroup>
        }
      >
        {revoking === null ? '' : l10n.getString('tokens-confirm-body', { label: revoking.label })}
      </Modal>
    </Panel>
  )
}
