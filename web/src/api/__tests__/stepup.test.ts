/**
 * The one place a step-up refusal is acted on: ask, then send once more.
 */

import { describe, expect, it } from 'bun:test'
import type { ApiError, ApiResult } from '../client'
import { isStepUpRequired, STEP_UP_REQUIRED_ID, withStepUp } from '../stepup'

function refused(messageId: string): ApiResult<string> {
  const error: ApiError = {
    kind: 'http',
    status: 403,
    code: 'forbidden',
    messageId,
    retryAfterSeconds: null,
    diagnostics: null,
  }
  return { ok: false, error }
}

const DONE: ApiResult<string> = { ok: true, status: 200, data: 'done' }

/** A call that answers `answers` in order, counting how often it was sent. */
function calls(...answers: ApiResult<string>[]) {
  let sent = 0
  const call = () => {
    const answer = answers[Math.min(sent, answers.length - 1)]
    sent += 1
    if (answer === undefined) throw new Error('no answer')
    return Promise.resolve(answer)
  }
  return { call, sent: () => sent }
}

/** An `ask` that answers `stepped`, counting how often it was asked. */
function asker(stepped: boolean) {
  let asked = 0
  const ask = () => {
    asked += 1
    return Promise.resolve(stepped)
  }
  return { ask, asked: () => asked }
}

describe('isStepUpRequired', () => {
  it('is true only for the step-up refusal', () => {
    const stepUp = refused(STEP_UP_REQUIRED_ID)
    const scope = refused('web-denied-scope')
    expect(!stepUp.ok && isStepUpRequired(stepUp.error)).toBe(true)
    expect(!scope.ok && isStepUpRequired(scope.error)).toBe(false)
    expect(isStepUpRequired({ kind: 'network' })).toBe(false)
    expect(isStepUpRequired({ kind: 'malformed', status: 403 })).toBe(false)
  })
})

describe('withStepUp', () => {
  it('answers a success without asking', async () => {
    const request = calls(DONE)
    const prompt = asker(true)
    expect(await withStepUp(request.call, prompt.ask)).toEqual(DONE)
    expect(request.sent()).toBe(1)
    expect(prompt.asked()).toBe(0)
  })

  it('answers any other refusal without asking', async () => {
    const scope = refused('web-denied-scope')
    const request = calls(scope)
    const prompt = asker(true)
    expect(await withStepUp(request.call, prompt.ask)).toEqual(scope)
    expect(request.sent()).toBe(1)
    expect(prompt.asked()).toBe(0)
  })

  it('asks, then sends the request once more', async () => {
    const request = calls(refused(STEP_UP_REQUIRED_ID), DONE)
    const prompt = asker(true)
    expect(await withStepUp(request.call, prompt.ask)).toEqual(DONE)
    expect(request.sent()).toBe(2)
    expect(prompt.asked()).toBe(1)
  })

  it('answers the first refusal when the step-up is cancelled', async () => {
    const first = refused(STEP_UP_REQUIRED_ID)
    const request = calls(first, DONE)
    const prompt = asker(false)
    expect(await withStepUp(request.call, prompt.ask)).toBe(first)
    expect(request.sent()).toBe(1)
  })

  it('never asks twice for one request', async () => {
    const request = calls(refused(STEP_UP_REQUIRED_ID))
    const prompt = asker(true)
    const result = await withStepUp(request.call, prompt.ask)
    expect(result.ok).toBe(false)
    expect(request.sent()).toBe(2)
    expect(prompt.asked()).toBe(1)
  })
})
