/**
 * The forced password change (TM-G7).
 *
 * `RequireAuth` renders this in place of every page while the session carries
 * `must_change_password`. The server enforces the same rule on its own: every
 * other route answers 403 to that session, so hiding the pages here is
 * courtesy, not the control.
 *
 * Length is checked here only to save a round trip, with the bounds the server
 * applies (12 to 128 characters, counted as characters). The server's answer is
 * still authoritative. Nothing reaches storage; the passwords live in
 * component state for one submission.
 */

import { Localized, useLocalization } from '@fluent/react'
import { type FormEvent, useState } from 'react'
import type { ApiError } from '@/api/client'
import { resolveApiError } from '@/api/messages'
import { useAuth } from '@/auth/AuthProvider'
import { Banner } from '@/components/Banner'
import { Button } from '@/components/Button'
import { Panel } from '@/components/Panel'
import { TextField } from '@/components/TextField'
import { TinyButton } from '@/components/TinyButton'

const MIN_PASSWORD_CHARS = 12
const MAX_PASSWORD_CHARS = 128

const PAGE_STYLE = { paddingTop: 48, paddingBottom: 48, maxWidth: 420 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 18,
  letterSpacing: '-0.01em',
  marginBottom: 16,
} as const

const FORM_STYLE = { display: 'grid', gap: 12 } as const

export function ChangePasswordPage() {
  const { l10n } = useLocalization()
  const { changePassword, logout } = useAuth()

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  /** The refusal to show before asking the host, or `null` when it may go. */
  function localRefusal(): string | null {
    if (next !== confirm) return l10n.getString('password-change-mismatch')
    const length = [...next].length
    if (length < MIN_PASSWORD_CHARS) return l10n.getString('web-auth-password-too-short')
    if (length > MAX_PASSWORD_CHARS) return l10n.getString('web-auth-password-too-long')
    return null
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy) return
    const refusal = localRefusal()
    if (refusal !== null) {
      setMessage(refusal)
      return
    }
    setBusy(true)
    setMessage(null)
    const result = await changePassword({ current_password: current, new_password: next })
    setBusy(false)
    if (result.ok) return
    setCurrent('')
    setMessage(resolveApiError(l10n, result.error satisfies ApiError))
  }

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <Panel label={l10n.getString('password-change-panel-label')}>
        <h1 style={TITLE_STYLE}>
          <Localized id="password-change-title">
            <span>change your password</span>
          </Localized>
        </h1>
        <p style={{ marginBottom: 12 }}>
          <Localized id="password-change-intro">
            <span>this account must set a new password before it can do anything else.</span>
          </Localized>
        </p>

        {message === null ? null : (
          <div style={{ marginBottom: 12 }}>
            <Banner tone="amber">{message}</Banner>
          </div>
        )}

        <form
          method="post"
          onSubmit={(event) => {
            void onSubmit(event)
          }}
          style={FORM_STYLE}
        >
          <TextField
            label={l10n.getString('password-change-current-label')}
            name="current_password"
            type="password"
            value={current}
            autoComplete="current-password"
            required
            disabled={busy}
            onChange={(event) => {
              setCurrent(event.target.value)
            }}
          />
          <TextField
            label={l10n.getString('password-change-new-label')}
            description={l10n.getString('password-change-new-description')}
            name="new_password"
            type="password"
            value={next}
            autoComplete="new-password"
            required
            disabled={busy}
            onChange={(event) => {
              setNext(event.target.value)
            }}
          />
          <TextField
            label={l10n.getString('password-change-confirm-label')}
            name="confirm_password"
            type="password"
            value={confirm}
            autoComplete="new-password"
            required
            disabled={busy}
            onChange={(event) => {
              setConfirm(event.target.value)
            }}
          />
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <Button type="submit" variant="primary" disabled={busy}>
              {busy ? (
                <Localized id="password-change-submitting">
                  <span>changing password</span>
                </Localized>
              ) : (
                <Localized id="password-change-submit">
                  <span>change password</span>
                </Localized>
              )}
            </Button>
            <TinyButton
              onClick={() => {
                void logout()
              }}
            >
              <Localized id="auth-sign-out">
                <span>sign out</span>
              </Localized>
            </TinyButton>
          </div>
        </form>
      </Panel>
    </section>
  )
}
