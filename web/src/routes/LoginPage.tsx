/**
 * The sign-in screen.
 *
 * On the second factor, deliberately: the server cannot tell the console that
 * a code is required *before* an attempt, and that is by design.
 * `crates/detent-web/src/auth/mod.rs` documents `InvalidCredentials` as "the
 * *only* answer a failed login produces, so no caller can tell an unknown user
 * from a wrong password, a missing TOTP code from a replayed one" — an
 * unauthenticated "this account has a second factor" oracle is exactly what
 * that lumpiness exists to deny. So the code field is not guessed at: it
 * appears when the operator asks for it, and it appears on its own the first
 * time the host refuses a sign-in, which is the only moment the server has
 * said anything at all about what was missing.
 *
 * Nothing here reaches storage. The password and the code live in component
 * state for the length of one submission; the session arrives as a `HttpOnly`
 * cookie the console cannot read, and the CSRF token goes into the API
 * client's closure. The form is `method="post"` although it never submits
 * natively: were the handler ever to not run, a default `GET` submission would
 * put the password in the address bar.
 */

import { Localized, useLocalization } from '@fluent/react'
import { type FormEvent, useState } from 'react'
import { Navigate, useLocation } from 'react-router'
import type { ApiError } from '@/api/client'
import { resolveApiError } from '@/api/messages'
import { useAuth } from '@/auth/AuthProvider'
import { Banner } from '@/components/Banner'
import { Button } from '@/components/Button'
import { Panel } from '@/components/Panel'
import { TextField } from '@/components/TextField'
import { TinyButton } from '@/components/TinyButton'
import { safeRedirect } from './paths'

const PAGE_STYLE = { paddingTop: 48, paddingBottom: 48, maxWidth: 420 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 18,
  letterSpacing: '-0.01em',
  marginBottom: 16,
} as const

const FORM_STYLE = { display: 'grid', gap: 12 } as const

const TOTP_CODE_LENGTH = 6

/** Reads `state.from` without trusting the shape history handed back. */
function fromLocationState(state: unknown): string | undefined {
  if (state === null || typeof state !== 'object') return undefined
  if (!('from' in state)) return undefined
  const from = state.from
  return typeof from === 'string' ? from : undefined
}

export function LoginPage() {
  const { l10n } = useLocalization()
  const { status, login } = useAuth()
  const location = useLocation()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [totpShown, setTotpShown] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const destination = safeRedirect(fromLocationState(location.state))

  /**
   * A `429` carries `Retry-After`, and the seconds are the whole point of the
   * message — `web-auth-rate-limited` states the fact without them, so the
   * count gets its own id rather than a number spliced into a sentence.
   */
  function describe(error: ApiError): string {
    if (error.kind === 'http' && error.status === 429 && error.retryAfterSeconds !== null) {
      return l10n.getString('login-retry-after', { seconds: error.retryAfterSeconds })
    }
    return resolveApiError(l10n, error)
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setMessage(null)
    const result = await login({
      username,
      password,
      ...(totpShown && totpCode !== '' ? { totp_code: totpCode } : {}),
    })
    setBusy(false)
    if (result.ok) return
    // The host refused the credentials: a missing second factor is one of the
    // things that answer looks like, so offer the field from here on.
    if (result.error.kind === 'http' && result.error.status === 401) {
      setTotpShown(true)
    }
    setTotpCode('')
    setMessage(describe(result.error))
  }

  if (status === 'authenticated') {
    return <Navigate to={destination} replace />
  }

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <Panel label={l10n.getString('login-panel-label')}>
        <h1 style={TITLE_STYLE}>
          <Localized id="login-title">
            <span>sign in</span>
          </Localized>
        </h1>

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
            label={l10n.getString('login-username-label')}
            name="username"
            value={username}
            autoComplete="username"
            required
            disabled={busy}
            onChange={(event) => {
              setUsername(event.target.value)
            }}
          />
          <TextField
            label={l10n.getString('login-password-label')}
            name="password"
            type="password"
            value={password}
            autoComplete="current-password"
            required
            disabled={busy}
            onChange={(event) => {
              setPassword(event.target.value)
            }}
          />
          {totpShown ? (
            <TextField
              label={l10n.getString('login-totp-label')}
              description={l10n.getString('login-totp-description')}
              name="totp_code"
              value={totpCode}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={TOTP_CODE_LENGTH}
              disabled={busy}
              onChange={(event) => {
                setTotpCode(event.target.value)
              }}
            />
          ) : (
            <div>
              <TinyButton
                onClick={() => {
                  setTotpShown(true)
                }}
              >
                <Localized id="login-totp-reveal">
                  <span>use an authenticator code</span>
                </Localized>
              </TinyButton>
            </div>
          )}
          <div>
            <Button type="submit" variant="primary" disabled={busy}>
              {busy ? (
                <Localized id="login-submitting">
                  <span>signing in</span>
                </Localized>
              ) : (
                <Localized id="login-submit">
                  <span>sign in</span>
                </Localized>
              )}
            </Button>
          </div>
        </form>
      </Panel>
    </section>
  )
}
