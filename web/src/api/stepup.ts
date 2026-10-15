/**
 * Step-up re-authentication on the wire (docs/API.md "Step-up").
 *
 * The host refuses an apply, a restore, an update and a certificate renewal
 * from a session without a recent step-up with `403
 * web-auth-step-up-required`. `withStepUp` is the one place that answer is
 * acted on: it asks for the password, and on success sends the request once
 * more. The dialog that asks lives in `app/StepUp.tsx`.
 */

import type { ApiError, ApiResult } from './client'

/** The id the host refuses a call with when it needs a step-up first. */
export const STEP_UP_REQUIRED_ID = 'web-auth-step-up-required'

/** Sends a request, asking for a step-up and sending it once more if needed. */
export type StepUpGuard = <T>(call: () => Promise<ApiResult<T>>) => Promise<ApiResult<T>>

/** Whether `error` is the host asking for a step-up. */
export function isStepUpRequired(error: ApiError): boolean {
  return error.kind === 'http' && error.messageId === STEP_UP_REQUIRED_ID
}

/**
 * Sends `call`. When the host asks for a step-up, waits for `ask` and, if it
 * reports a step-up, sends `call` once more; otherwise answers the first
 * refusal. A second refusal is answered as it is, never asked again.
 */
export async function withStepUp<T>(
  call: () => Promise<ApiResult<T>>,
  ask: () => Promise<boolean>,
): Promise<ApiResult<T>> {
  const first = await call()
  if (first.ok || !isStepUpRequired(first.error)) return first
  return (await ask()) ? call() : first
}
