import { describe, expect, it } from 'bun:test'
import {
  appendItem,
  getAtPath,
  type JsonValue,
  moveItem,
  parseJsonValue,
  parsePath,
  pathKey,
  removeAt,
  setAtPath,
  updateArrayAtPath,
} from '../json'

const MODEL: JsonValue = {
  entries: [
    { ip: '127.0.0.1', hostnames: ['localhost'] },
    { ip: '10.0.0.4', hostnames: ['nas', 'nas.lan'] },
  ],
  trailer: { kept: true },
}

describe('parseJsonValue', () => {
  it('narrows parsed input and collapses non-JSON leaves', () => {
    expect(parseJsonValue({ a: 1, b: undefined, c: Number.NaN, d: () => 1 })).toEqual({
      a: 1,
      c: null,
      d: null,
    })
    expect(parseJsonValue([1, 'two', null])).toEqual([1, 'two', null])
    expect(parseJsonValue(Symbol('x'))).toBeNull()
  })
})

describe('path helpers', () => {
  it('round-trips a path through its diagnostic spelling', () => {
    expect(pathKey(['entries', '1', 'ip'])).toBe('entries/1/ip')
    expect(parsePath('entries/1/ip')).toEqual(['entries', '1', 'ip'])
    expect(parsePath('')).toEqual([])
  })

  it('reads through objects and arrays, and reports a missing branch', () => {
    expect(getAtPath(MODEL, ['entries', '1', 'hostnames', '0'])).toBe('nas')
    expect(getAtPath(MODEL, ['entries', '9'])).toBeUndefined()
    expect(getAtPath(MODEL, ['entries', 'ip'])).toBeUndefined()
    expect(getAtPath(MODEL, ['trailer', 'kept', 'deeper'])).toBeUndefined()
  })
})

describe('setAtPath', () => {
  it('shares every untouched branch', () => {
    const next = setAtPath(MODEL, ['entries', '0', 'ip'], '10.0.0.1')

    expect(getAtPath(next, ['entries', '0', 'ip'])).toBe('10.0.0.1')
    expect(getAtPath(next, ['entries', '1'])).toBe(getAtPath(MODEL, ['entries', '1']))
    expect(getAtPath(next, ['trailer'])).toBe(getAtPath(MODEL, ['trailer']))
    expect(getAtPath(next, ['entries', '0', 'hostnames'])).toBe(
      getAtPath(MODEL, ['entries', '0', 'hostnames']),
    )
  })

  it('refuses an out-of-range array index rather than making the array sparse', () => {
    for (const path of [
      ['entries', '5', 'ip'],
      ['entries', '-1'],
      ['entries', 'ip'],
    ]) {
      const next = setAtPath(MODEL, path, 'x')
      expect(next).toEqual(MODEL)
      // The array itself is handed straight back, so nothing was rebuilt.
      expect(getAtPath(next, ['entries'])).toBe(getAtPath(MODEL, ['entries']))
    }
  })

  it('refuses to write into a scalar root', () => {
    expect(setAtPath('a scalar', ['a'], 1)).toBe('a scalar')
    expect(setAtPath(7, ['a', 'b'], 1)).toBe(7)
  })

  it('creates the container an intermediate segment needs', () => {
    expect(setAtPath({}, ['a', 'b'], 1)).toEqual({ a: { b: 1 } })
  })
})

describe('array helpers', () => {
  const items: readonly JsonValue[] = ['a', 'b', 'c']

  it('appends, removes and moves without disturbing the rest of the order', () => {
    expect(appendItem(items, 'd')).toEqual(['a', 'b', 'c', 'd'])
    expect(removeAt(items, 1)).toEqual(['a', 'c'])
    expect(moveItem(items, 2, 0)).toEqual(['c', 'a', 'b'])
    expect(moveItem(items, 0, 2)).toEqual(['b', 'c', 'a'])
  })

  it('leaves the list alone for a no-op or an out-of-range move', () => {
    expect(moveItem(items, 1, 1)).toBe(items)
    expect(moveItem(items, 0, 9)).toBe(items)
    expect(moveItem(items, 9, 0)).toBe(items)
    expect(removeAt(items, 9)).toBe(items)
  })

  it('treats a non-array as empty when updating in place', () => {
    expect(updateArrayAtPath({ a: 'scalar' }, ['a'], (list) => appendItem(list, 1))).toEqual({
      a: [1],
    })
  })
})
