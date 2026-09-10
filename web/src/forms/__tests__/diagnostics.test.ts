import { describe, expect, it } from 'vitest'
import hostsSchemaSource from '../__fixtures__/hosts.schema.json?raw'
import {
  collectFieldPaths,
  type FormDiagnostic,
  mapDiagnostics,
  parseDiagnostics,
  parseFieldPath,
} from '../diagnostics'
import { parseSchema } from '../schema'

const hostsSchema: unknown = JSON.parse(hostsSchemaSource)

const MODEL = {
  entries: [
    { ip: '127.0.0.1', hostnames: ['localhost'], comment: null },
    { ip: '::1', hostnames: ['ip6-localhost', 'ip6-loopback'] },
  ],
}

function rendered(): ReadonlySet<string> {
  return collectFieldPaths(parseSchema(hostsSchema).fields, MODEL)
}

function diagnostic(overrides: Partial<FormDiagnostic> = {}): FormDiagnostic {
  return {
    severity: 'error',
    id: 'hosts-bad-ip',
    field: undefined,
    span: undefined,
    args: {},
    ...overrides,
  }
}

describe('parseDiagnostics', () => {
  it('reads the wire shape the API returns', () => {
    const parsed = parseDiagnostics([
      {
        severity: 'error',
        id: 'hosts-bad-ip',
        field: 'entries/1/ip',
        span: { start: 4, end: 9 },
        args: { value: 'bogus', line: 3 },
      },
    ])

    expect(parsed).toEqual([
      {
        severity: 'error',
        id: 'hosts-bad-ip',
        field: 'entries/1/ip',
        span: { start: 4, end: 9 },
        args: { value: 'bogus', line: '3' },
      },
    ])
  })

  it('treats a missing field and span as absent rather than throwing', () => {
    const parsed = parseDiagnostics([{ severity: 'warning', id: 'hosts-dup' }])
    expect(parsed[0]).toEqual({
      severity: 'warning',
      id: 'hosts-dup',
      field: undefined,
      span: undefined,
      args: {},
    })
  })

  it('drops entries that carry nothing renderable, and non-arrays', () => {
    expect(
      parseDiagnostics([
        null,
        'nope',
        { severity: 'fatal', id: 'x' },
        { severity: 'error' },
        { severity: 'error', id: '' },
      ]),
    ).toEqual([])
    expect(parseDiagnostics(undefined)).toEqual([])
    expect(parseDiagnostics({ diagnostics: [] })).toEqual([])
  })
})

describe('parseFieldPath', () => {
  it('accepts both the pointer and the diagnostic spelling', () => {
    expect(parseFieldPath('entries/1/ip')).toEqual(['entries', '1', 'ip'])
    expect(parseFieldPath('/entries/1/ip')).toEqual(['entries', '1', 'ip'])
    expect(parseFieldPath('')).toEqual([])
  })
})

describe('collectFieldPaths', () => {
  it('expands array fields against the rows the model actually holds', () => {
    const paths = rendered()

    expect(paths.has('entries')).toBe(true)
    expect(paths.has('entries/0/ip')).toBe(true)
    expect(paths.has('entries/1/hostnames')).toBe(true)
    expect(paths.has('entries/1/comment')).toBe(true)
    expect(paths.has('entries/2/ip')).toBe(false)
  })
})

describe('mapDiagnostics', () => {
  it('lands an exact field path on that control', () => {
    const entry = diagnostic({ field: 'entries/1/ip' })
    const mapped = mapDiagnostics([entry], rendered())

    expect(mapped.byPath.get('entries/1/ip')).toEqual([entry])
    expect(mapped.formLevel).toEqual([])
  })

  it('lands a sub-path on the nearest rendered ancestor', () => {
    const entry = diagnostic({ field: 'entries/0/hostnames/0' })
    const mapped = mapDiagnostics([entry], rendered())

    expect(mapped.byPath.get('entries/0/hostnames')).toEqual([entry])
    expect(mapped.formLevel).toEqual([])
  })

  it('collects several diagnostics on one control in order', () => {
    const first = diagnostic({ field: 'entries/0/ip', id: 'hosts-one' })
    const second = diagnostic({ field: 'entries/0/ip', id: 'hosts-two', severity: 'warning' })
    const mapped = mapDiagnostics([first, second], rendered())

    expect(mapped.byPath.get('entries/0/ip')).toEqual([first, second])
  })

  it('surfaces a diagnostic with no field at form level', () => {
    const entry = diagnostic({ field: undefined })
    const mapped = mapDiagnostics([entry], rendered())

    expect(mapped.formLevel).toEqual([entry])
    expect(mapped.byPath.size).toBe(0)
  })

  it('surfaces an unmappable field path at form level instead of dropping it', () => {
    const unknownField = diagnostic({ field: 'resolver/nameservers/0' })
    const emptyPath = diagnostic({ field: '/' })
    const mapped = mapDiagnostics([unknownField, emptyPath], rendered())

    expect(mapped.formLevel).toEqual([unknownField, emptyPath])
    expect(mapped.byPath.size).toBe(0)
  })

  it('keeps a stale row index on the array editor it addresses', () => {
    // `entries/9` names no row, but `entries` itself is rendered, so the
    // finding still reaches the operator rather than vanishing.
    const mapped = mapDiagnostics([diagnostic({ field: 'entries/9/ip' })], rendered())

    expect(mapped.byPath.get('entries')).toHaveLength(1)
    expect(mapped.formLevel).toEqual([])
  })
})
