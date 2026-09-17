/**
 * Localized captions for service states, indicators, and actions.
 *
 * The services page exercises only `active`, `failed`, and `restart` in
 * integration tests; this file covers the remaining arms of each switch.
 */

import { describe, expect, it } from 'bun:test'
import type { ServiceCommand } from '@/api/services'
import { createLocalization } from '@/i18n'
import {
  type ServiceState,
  serviceActionCaption,
  serviceStateLabel,
  serviceStateLed,
} from '../serviceLabels'

const L10N = createLocalization(['en-US'])

describe('serviceStateLabel', () => {
  it('returns a localized word for every service state', () => {
    const cases: { state: ServiceState; expected: string }[] = [
      { state: 'active', expected: 'active' },
      { state: 'inactive', expected: 'inactive' },
      { state: 'failed', expected: 'failed' },
      { state: 'activating', expected: 'starting' },
      { state: 'deactivating', expected: 'stopping' },
      { state: 'unknown', expected: 'unknown' },
    ]
    for (const { state, expected } of cases) {
      expect(serviceStateLabel(L10N, state)).toBe(expected)
    }
  })
})

describe('serviceStateLed', () => {
  it('lights only active and failed states', () => {
    expect(serviceStateLed('active')).toBe('on')
    expect(serviceStateLed('failed')).toBe('rec')
    expect(serviceStateLed('inactive')).toBe('off')
    expect(serviceStateLed('activating')).toBe('off')
    expect(serviceStateLed('deactivating')).toBe('off')
    expect(serviceStateLed('unknown')).toBe('off')
  })
})

describe('serviceActionCaption', () => {
  it('returns a localized caption for every service command', () => {
    const cases: { command: ServiceCommand; expected: string }[] = [
      { command: 'restart', expected: 'restart' },
      { command: 'reload', expected: 'reload' },
      { command: 'start', expected: 'start' },
      { command: 'stop', expected: 'stop' },
    ]
    for (const { command, expected } of cases) {
      expect(serviceActionCaption(L10N, command)).toBe(expected)
    }
  })
})
