import { describe, expect, it } from 'vitest'
import { DEFAULT_HINTS, parseHints } from '../hints'

describe('parseHints', () => {
  it('reads a complete x-detent object', () => {
    expect(
      parseHints({
        'x-detent': {
          group: 'advanced',
          tooltip: 'chrony-tip-makestep',
          recommendation: 'chrony-rec-makestep',
          security_impact: 'high',
          requires_restart: true,
          since: '4.5',
          deprecated_in: '4.9',
        },
      }),
    ).toEqual({
      group: 'advanced',
      tooltipId: 'chrony-tip-makestep',
      recommendationId: 'chrony-rec-makestep',
      securityImpact: 'high',
      requiresRestart: true,
      since: '4.5',
      deprecatedIn: '4.9',
    })
  })

  it('defaults every absent optional part', () => {
    expect(
      parseHints({
        'x-detent': {
          group: 'basic',
          tooltip: 'a',
          security_impact: 'none',
          requires_restart: false,
        },
      }),
    ).toEqual({ ...DEFAULT_HINTS, tooltipId: 'a' })
  })

  it('falls back to the defaults for a node with no hints at all', () => {
    expect(parseHints({ type: 'string' })).toBe(DEFAULT_HINTS)
    expect(parseHints(undefined)).toBe(DEFAULT_HINTS)
  })

  it('ignores values outside the contract rather than trusting them', () => {
    expect(
      parseHints({
        'x-detent': {
          group: 'expert',
          tooltip: 42,
          security_impact: 'catastrophic',
          requires_restart: 'yes',
          deprecated_in: '',
        },
      }),
    ).toEqual(DEFAULT_HINTS)
  })

  it('ignores an x-detent that is not an object', () => {
    expect(parseHints({ 'x-detent': 'basic' })).toBe(DEFAULT_HINTS)
    expect(parseHints({ 'x-detent': ['basic'] })).toBe(DEFAULT_HINTS)
  })
})
