/**
 * Step-up re-authentication (ASVS 3.7.1, docs/API.md "Step-up").
 *
 * The host refuses an apply, a restore, an update and a certificate renewal
 * from a session that has not entered its password in the last five minutes:
 * `403 web-auth-step-up-required`. `useStepUp` wraps those four calls in one
 * place (`withStepUp` in `api/stepup.ts`). On that refusal it opens a dialog
 * for the password (and a code, when the account has a second factor), sends
 * it to `POST /api/v1/auth/reauth`, and on success sends the original request
 * once more. Cancel gives the caller the original refusal.
 *
 * The password and the code live in component state and are cleared after
 * each answer. Calls that hit the refusal while the dialog is open wait for
 * the same dialog.
 */

import { Localized, useLocalization } from '@fluent/react'
import { useQuery } from '@tanstack/react-query'
import {
  createContext,
  type FormEvent,
  type ReactNode,
  useCallback,
  useContext,
  useRef,
  useState,
} from 'react'
import { useApiClient } from '@/api/ApiProvider'
import { fetchTotpStatus, reauth, TOTP_QUERY_KEY } from '@/api/auth'
import { resolveApiError } from '@/api/messages'
import { unwrap } from '@/api/query'
import { type StepUpGuard, withStepUp } from '@/api/stepup'
import { Banner } from '@/components/Banner'
import { Button, ButtonGroup } from '@/components/Button'
import { Modal } from '@/components/Modal'
import { PasswordField } from '@/components/PasswordField'
import { TextField } from '@/components/TextField'

/** Digits in a code (RFC 6238 as the host runs it). */
const TOTP_CODE_LENGTH = 6

const FORM_STYLE = { display: 'grid', gap: 12 } as const

const StepUpContext = createContext<StepUpGuard | null>(null)

export function StepUpProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const waiting = useRef<((stepped: boolean) => void)[]>([])

  const settle = useCallback((stepped: boolean) => {
    const waiters = waiting.current
    waiting.current = []
    setOpen(false)
    for (const resolve of waiters) resolve(stepped)
  }, [])

  const guard = useCallback<StepUpGuard>(
    (call) =>
      withStepUp(
        call,
        () =>
          new Promise<boolean>((resolve) => {
            waiting.current.push(resolve)
            setOpen(true)
          }),
      ),
    [],
  )

  return (
    <StepUpContext.Provider value={guard}>
      {children}
      {open ? <StepUpDialog onSettle={settle} /> : null}
    </StepUpContext.Provider>
  )
}

/** The guard the apply, restore, update and renewal requests go through. */
export function useStepUp(): StepUpGuard {
  const guard = useContext(StepUpContext)
  if (guard === null) {
    throw new Error('useStepUp must be used inside <StepUpProvider>')
  }
  return guard
}

function StepUpDialog({ onSettle }: { onSettle: (stepped: boolean) => void }) {
  const { l10n } = useLocalization()
  const client = useApiClient()
  const totp = useQuery({
    queryKey: TOTP_QUERY_KEY,
    queryFn: ({ signal }) => unwrap(fetchTotpStatus(client, signal)),
  })
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Shown until the host says the account has no second factor: an unused
  // code field costs nothing, a missing one blocks the operator.
  const needsCode = totp.data?.enrolled !== false

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    const result = await reauth(client, {
      password,
      ...(needsCode && code !== '' ? { totp_code: code } : {}),
    })
    setPassword('')
    setCode('')
    setBusy(false)
    if (result.ok) {
      onSettle(true)
      return
    }
    setMessage(resolveApiError(l10n, result.error))
  }

  return (
    <Modal
      open
      onClose={() => {
        onSettle(false)
      }}
      title={l10n.getString('step-up-title')}
    >
      <form
        method="post"
        aria-label={l10n.getString('step-up-form-label')}
        onSubmit={(event) => {
          void submit(event)
        }}
        style={FORM_STYLE}
      >
        <Localized id="step-up-intro">
          <p>this change needs your password again. it is not asked again for five minutes.</p>
        </Localized>
        {message === null ? null : <Banner tone="amber">{message}</Banner>}
        <PasswordField
          label={l10n.getString('totp-password-label')}
          name="password"
          value={password}
          autoComplete="current-password"
          required
          disabled={busy}
          onChange={(event) => {
            setPassword(event.target.value)
          }}
        />
        {needsCode ? (
          <TextField
            label={l10n.getString('totp-code-label')}
            description={l10n.getString('totp-code-description')}
            name="code"
            value={code}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={TOTP_CODE_LENGTH}
            required={totp.data?.enrolled === true}
            disabled={busy}
            onChange={(event) => {
              setCode(event.target.value)
            }}
          />
        ) : null}
        <ButtonGroup>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? l10n.getString('step-up-submitting') : l10n.getString('step-up-submit')}
          </Button>
          <Button
            disabled={busy}
            onClick={() => {
              onSettle(false)
            }}
          >
            {l10n.getString('step-up-cancel')}
          </Button>
        </ButtonGroup>
      </form>
    </Modal>
  )
}
