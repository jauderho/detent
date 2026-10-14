/**
 * The second factor of the signed-in account: turn it on, turn it off
 * (docs/API.md "Second factor").
 *
 * Turning it on is two steps. The password asks the host for a new key, which
 * the host keeps for this session only and answers once; the page shows it as
 * a QR code and as text, and stores nothing. A code from the authenticator
 * then confirms it. Turning it off takes the password and a code. Both
 * successful steps answer a new session, which `AuthProvider` takes on.
 *
 * Passwords, codes and the key live in component state and are cleared after
 * each answer. The host decides everything; the field limits here only save
 * a round trip.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { type FormEvent, useEffect, useRef, useState } from 'react'
import { useApiClient } from '@/api/ApiProvider'
import {
  fetchTotpStatus,
  startTotpEnrolment,
  TOTP_QUERY_KEY,
  type TotpEnrolment,
  type TotpStatus,
} from '@/api/auth'
import type { ApiError } from '@/api/client'
import { resolveApiError } from '@/api/messages'
import { unwrap, useApiErrorMessage } from '@/api/query'
import { useAuth } from '@/auth/AuthProvider'
import { Banner } from '@/components/Banner'
import { Button } from '@/components/Button'
import { Label } from '@/components/Label'
import { Panel } from '@/components/Panel'
import { QrCode } from '@/components/QrCode'
import { TextField } from '@/components/TextField'

/** Digits in a code (RFC 6238 as the host runs it). */
const TOTP_CODE_LENGTH = 6

const SECONDS_PER_MINUTE = 60

const HTTP_CONFLICT = 409

/** Characters per group when the key is shown as text. */
const KEY_GROUP = 4

const FORM_STYLE = { display: 'grid', gap: 12, maxWidth: 420 } as const

const ROW_STYLE = { display: 'flex', gap: 12, alignItems: 'center' } as const

const KEY_STYLE = {
  fontVariantNumeric: 'tabular-nums',
  wordBreak: 'break-all',
  userSelect: 'all',
} as const

/** Work deferred until it is called: a form submission's request. */
type Thunk<T> = () => T

/** `ABCD EFGH …`: easier to read off and type in by hand. */
function groupKey(key: string): string {
  return key.match(new RegExp(`.{1,${KEY_GROUP}}`, 'g'))?.join(' ') ?? key
}

export function TotpPanel() {
  const { l10n } = useLocalization()
  const client = useApiClient()
  const queryClient = useQueryClient()
  const { confirmTotp, disableTotp } = useAuth()
  const queryError = useApiErrorMessage()

  const status = useQuery({
    queryKey: TOTP_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchTotpStatus(client, signal)),
  })

  const [enrolment, setEnrolment] = useState<TotpEnrolment | null>(null)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const codeField = useRef<HTMLInputElement>(null)

  // The code field is the next thing to fill once the key is on screen.
  useEffect(() => {
    if (enrolment !== null) codeField.current?.focus()
  }, [enrolment])

  function refuse(error: ApiError): void {
    setMessage(resolveApiError(l10n, error))
  }

  function settle(next: TotpStatus, text: string): void {
    queryClient.setQueryData<TotpStatus>(TOTP_QUERY_KEY, next)
    setEnrolment(null)
    setPassword('')
    setCode('')
    setMessage(null)
    setNotice(text)
  }

  async function run(action: Thunk<Promise<void>>): Promise<void> {
    if (busy) return
    setBusy(true)
    setNotice(null)
    await action()
    setBusy(false)
  }

  function onStart(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault()
    void run(async () => {
      const result = await startTotpEnrolment(client, { current_password: password })
      setPassword('')
      if (!result.ok) {
        refuse(result.error)
        return
      }
      setMessage(null)
      setEnrolment(result.data)
    })
  }

  function onConfirm(event: FormEvent<HTMLFormElement>, required: boolean): void {
    event.preventDefault()
    void run(async () => {
      const result = await confirmTotp({ code })
      setCode('')
      if (!result.ok) {
        refuse(result.error)
        // 409: the key expired, or a key was enrolled elsewhere. This key is
        // finished either way; read the status again.
        if (result.error.kind === 'http' && result.error.status === HTTP_CONFLICT) {
          setEnrolment(null)
          void queryClient.invalidateQueries({ queryKey: TOTP_QUERY_KEY })
        }
        return
      }
      settle({ enrolled: true, required }, l10n.getString('totp-enabled-notice'))
    })
  }

  function onDisable(event: FormEvent<HTMLFormElement>, required: boolean): void {
    event.preventDefault()
    void run(async () => {
      const result = await disableTotp({ current_password: password, code })
      setPassword('')
      setCode('')
      if (!result.ok) {
        refuse(result.error)
        return
      }
      settle({ enrolled: false, required }, l10n.getString('totp-disabled-notice'))
    })
  }

  function onCancel(): void {
    setEnrolment(null)
    setCode('')
    setMessage(null)
  }

  const passwordField = (
    <TextField
      label={l10n.getString('totp-password-label')}
      name="current_password"
      type="password"
      value={password}
      autoComplete="current-password"
      required
      disabled={busy}
      onChange={(event) => {
        setPassword(event.target.value)
      }}
    />
  )

  const codeInput = (
    <TextField
      ref={codeField}
      label={l10n.getString('totp-code-label')}
      description={l10n.getString('totp-code-description')}
      name="code"
      value={code}
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={TOTP_CODE_LENGTH}
      required
      disabled={busy}
      onChange={(event) => {
        setCode(event.target.value)
      }}
    />
  )

  function body(current: TotpStatus) {
    if (current.enrolled) {
      return (
        <>
          <Localized id="totp-status-on">
            <p>the second factor is on. each sign-in asks for a code from your authenticator.</p>
          </Localized>
          {current.required ? (
            <Localized id="totp-required-note">
              <p>this host requires a second factor, so it cannot be turned off here.</p>
            </Localized>
          ) : (
            <form
              method="post"
              aria-label={l10n.getString('totp-disable-form-label')}
              onSubmit={(event) => {
                onDisable(event, current.required)
              }}
              style={FORM_STYLE}
            >
              {passwordField}
              {codeInput}
              <div style={ROW_STYLE}>
                <Button type="submit" disabled={busy}>
                  {busy ? (
                    <Localized id="totp-disable-submitting">
                      <span>turning off</span>
                    </Localized>
                  ) : (
                    <Localized id="totp-disable-submit">
                      <span>turn off</span>
                    </Localized>
                  )}
                </Button>
              </div>
            </form>
          )}
        </>
      )
    }
    if (enrolment !== null) {
      return (
        <>
          <Localized id="totp-scan-intro">
            <p>
              scan this code with your authenticator application, or type the key in by hand. then
              enter the code it shows.
            </p>
          </Localized>
          <QrCode value={enrolment.uri} label={l10n.getString('totp-qr-label')} />
          <div>
            <Label>{l10n.getString('totp-key-label')}</Label>
            {/* The key is host text, never localized. */}
            <p className="verbatim" style={KEY_STYLE}>
              {groupKey(enrolment.secret)}
            </p>
          </div>
          <Localized
            id="totp-expiry-note"
            vars={{ minutes: Math.round(enrolment.expires_in_secs / SECONDS_PER_MINUTE) }}
          >
            <p>this key waits for a code for a few minutes, and is shown only once.</p>
          </Localized>
          <form
            method="post"
            aria-label={l10n.getString('totp-confirm-form-label')}
            onSubmit={(event) => {
              onConfirm(event, current.required)
            }}
            style={FORM_STYLE}
          >
            {codeInput}
            <div style={ROW_STYLE}>
              <Button type="submit" variant="primary" disabled={busy}>
                {busy ? (
                  <Localized id="totp-confirm-submitting">
                    <span>confirming</span>
                  </Localized>
                ) : (
                  <Localized id="totp-confirm-submit">
                    <span>confirm</span>
                  </Localized>
                )}
              </Button>
              <Button disabled={busy} onClick={onCancel}>
                <Localized id="totp-cancel">
                  <span>cancel</span>
                </Localized>
              </Button>
            </div>
          </form>
        </>
      )
    }
    return (
      <>
        <Localized id="totp-status-off">
          <p>the second factor is off. sign-in asks for the password only.</p>
        </Localized>
        <form
          method="post"
          aria-label={l10n.getString('totp-enable-form-label')}
          onSubmit={onStart}
          style={FORM_STYLE}
        >
          {passwordField}
          <div style={ROW_STYLE}>
            <Button type="submit" variant="primary" disabled={busy}>
              {busy ? (
                <Localized id="totp-enable-submitting">
                  <span>checking password</span>
                </Localized>
              ) : (
                <Localized id="totp-enable-submit">
                  <span>turn on</span>
                </Localized>
              )}
            </Button>
          </div>
        </form>
      </>
    )
  }

  return (
    <Panel label={l10n.getString('totp-panel-label')}>
      <div style={{ display: 'grid', gap: 12 }}>
        {notice === null ? null : <Banner tone="blue">{notice}</Banner>}
        {message === null ? null : <Banner tone="amber">{message}</Banner>}
        {status.isPending ? (
          <Localized id="totp-loading">
            <p>reading the second factor status.</p>
          </Localized>
        ) : status.isError ? (
          <Banner tone="amber">{queryError(status.error)}</Banner>
        ) : (
          body(status.data)
        )}
      </div>
    </Panel>
  )
}
