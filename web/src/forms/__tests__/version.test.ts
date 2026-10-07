import { describe, expect, it } from 'bun:test'
import { compareVersions, isTooOld } from '../version'

describe('compareVersions', () => {
  it('compares numerically, not textually', () => {
    expect(compareVersions('4.10', '4.9')).toBe(1)
    expect(compareVersions('4.9', '4.10')).toBe(-1)
    expect(compareVersions('4.19.5', '4.24')).toBe(-1)
    expect(compareVersions('10.0', '9.9.9')).toBe(1)
  })

  it('counts missing trailing components as zero', () => {
    expect(compareVersions('4.9', '4.9.0')).toBe(0)
    expect(compareVersions('4.9.0.0', '4.9')).toBe(0)
    expect(compareVersions('4.9', '4.9.1')).toBe(-1)
    expect(compareVersions('4', '4.0.0')).toBe(0)
  })

  it('ignores leading zeros and anything after the numeric run', () => {
    expect(compareVersions('4.09', '4.9')).toBe(0)
    expect(compareVersions('4.19.5-Debian', '4.19.5')).toBe(0)
    expect(compareVersions('4.5+dfsg', '4.5')).toBe(0)
    expect(compareVersions('  4.9 ', '4.9')).toBe(0)
    expect(compareVersions('4.9.', '4.9')).toBe(0)
  })

  it('answers undefined for text that is not a version', () => {
    for (const bad of ['', ' ', 'abc', 'v4.9', '-4.9', '.9', '4..9', 'Version 4.9']) {
      expect(compareVersions(bad, '4.9')).toBeUndefined()
      expect(compareVersions('4.9', bad)).toBeUndefined()
    }
  })

  it('answers undefined for a component that is not a safe integer', () => {
    expect(compareVersions('4.99999999999999999999999', '4.9')).toBeUndefined()
  })
})

describe('isTooOld', () => {
  it('is true only for a known, older version', () => {
    expect(isTooOld('4.5', '4.9')).toBe(true)
    expect(isTooOld('4.19.5-Debian', '4.24')).toBe(true)
  })

  it('is false when the version is new enough', () => {
    expect(isTooOld('4.9', '4.9')).toBe(false)
    expect(isTooOld('4.10', '4.9')).toBe(false)
  })

  it('is false when the installed version is unknown', () => {
    expect(isTooOld(undefined, '4.9')).toBe(false)
    expect(isTooOld('garbled', '4.9')).toBe(false)
  })

  it('is false when the required version does not parse', () => {
    expect(isTooOld('4.5', 'next')).toBe(false)
  })
})
