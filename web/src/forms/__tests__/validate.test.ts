import { describe, expect, it } from 'vitest'
import hostsSchemaSource from '../__fixtures__/hosts.schema.json?raw'
import type { JsonValue } from '../json'
import { parseSchema } from '../schema'
import { isIpAddress, registerFormat, validateModel } from '../validate'

const hostsSchema: unknown = JSON.parse(hostsSchemaSource)

function messages(schema: unknown, model: JsonValue): readonly string[] {
  return validateModel(parseSchema(schema).fields, model).map((issue) => issue.messageId)
}

function rootWith(property: unknown, required: readonly string[] = []): unknown {
  return { type: 'object', properties: { subject: property }, required }
}

describe('validateModel — required', () => {
  it('reports a missing required field', () => {
    expect(messages(rootWith({ type: 'string' }, ['subject']), {})).toEqual([
      'forms-error-required',
    ])
  })

  it('accepts an absent optional field', () => {
    expect(messages(rootWith({ type: 'string' }), {})).toEqual([])
  })

  it('accepts null in a required nullable field', () => {
    const schema = rootWith({ type: ['string', 'null'] }, ['subject'])
    expect(messages(schema, { subject: null })).toEqual([])
  })

  it('reports null in a required non-nullable field', () => {
    const schema = rootWith({ type: 'string' }, ['subject'])
    expect(messages(schema, { subject: null })).toEqual(['forms-error-required'])
  })
})

describe('validateModel — string constraints', () => {
  it('reports minLength and maxLength', () => {
    const short = rootWith({ type: 'string', minLength: 3 })
    expect(messages(short, { subject: 'ab' })).toEqual(['forms-error-min-length'])
    expect(messages(short, { subject: 'abc' })).toEqual([])

    const long = rootWith({ type: 'string', maxLength: 3 })
    expect(messages(long, { subject: 'abcd' })).toEqual(['forms-error-max-length'])
    expect(messages(long, { subject: 'abc' })).toEqual([])
  })

  it('reports a pattern mismatch and carries the pattern as an argument', () => {
    const schema = rootWith({ type: 'string', pattern: '^[a-z]+$' })
    const issues = validateModel(parseSchema(schema).fields, { subject: 'Nope1' })

    expect(issues.map((issue) => issue.messageId)).toEqual(['forms-error-pattern'])
    expect(issues[0]?.args).toEqual({ pattern: '^[a-z]+$' })
    expect(messages(schema, { subject: 'ok' })).toEqual([])
  })

  it('ignores a pattern it cannot compile rather than reporting a false failure', () => {
    const schema = rootWith({ type: 'string', pattern: '(?<broken' })
    expect(messages(schema, { subject: 'anything' })).toEqual([])
  })
})

describe('validateModel — numeric constraints', () => {
  it('reports minimum and maximum', () => {
    const schema = rootWith({ type: 'integer', minimum: 1, maximum: 10 })
    expect(messages(schema, { subject: 0 })).toEqual(['forms-error-minimum'])
    expect(messages(schema, { subject: 11 })).toEqual(['forms-error-maximum'])
    expect(messages(schema, { subject: 5 })).toEqual([])
  })

  it('reports a fractional value in an integer field', () => {
    expect(messages(rootWith({ type: 'integer' }), { subject: 1.5 })).toEqual([
      'forms-error-integer',
    ])
    expect(messages(rootWith({ type: 'number' }), { subject: 1.5 })).toEqual([])
  })

  it('reports a value of the wrong kind', () => {
    expect(messages(rootWith({ type: 'integer' }), { subject: 'five' })).toEqual([
      'forms-error-type',
    ])
  })
})

describe('validateModel — enum membership', () => {
  const schema = rootWith({ type: 'string', enum: ['dhcp', 'static'] }, ['subject'])

  it('accepts a listed value and reports one that is not listed', () => {
    expect(messages(schema, { subject: 'static' })).toEqual([])
    expect(messages(schema, { subject: 'pppoe' })).toEqual(['forms-error-enum'])
  })
})

describe('validateModel — format', () => {
  it('accepts the dotted quads and compressed v6 forms the module writes', () => {
    for (const address of [
      '0.0.0.0',
      '127.0.0.1',
      '255.255.255.255',
      '::1',
      '::',
      'fe80::1',
      '2001:db8::8a2e:370:7334',
      '2001:0db8:0000:0000:0000:8a2e:0370:7334',
      '::ffff:192.168.1.1',
    ]) {
      expect(isIpAddress(address), address).toBe(true)
    }
  })

  it('rejects the near misses', () => {
    for (const address of [
      '',
      '1.2.3',
      '1.2.3.4.5',
      '256.0.0.1',
      '01.2.3.4',
      '1.2.3.-4',
      'localhost',
      ':::1',
      '2001:db8:::1',
      'fe80::1::2',
      '12345::1',
      '1:2:3:4:5:6:7',
      'gggg::1',
    ]) {
      expect(isIpAddress(address), address).toBe(false)
    }
  })

  it('reports a bad address on the hosts fixture', () => {
    const model = { entries: [{ ip: 'not-an-ip', hostnames: ['nas'] }] }
    const issues = validateModel(parseSchema(hostsSchema).fields, model)

    expect(issues).toHaveLength(1)
    expect(issues[0]?.messageId).toBe('forms-error-format-ip')
    expect(issues[0]?.path).toEqual(['entries', '0', 'ip'])
  })

  it('takes a new format in one registration', () => {
    registerFormat('even-length', (value) => value.length % 2 === 0, 'forms-error-pattern')
    const schema = rootWith({ type: 'string', format: 'even-length' })

    expect(messages(schema, { subject: 'abc' })).toEqual(['forms-error-pattern'])
    expect(messages(schema, { subject: 'abcd' })).toEqual([])
  })

  it('ignores a format nothing has registered', () => {
    const schema = rootWith({ type: 'string', format: 'uri-template' })
    expect(messages(schema, { subject: 'whatever' })).toEqual([])
  })
})

describe('validateModel — containers', () => {
  it('addresses an issue at the row that produced it', () => {
    const model = {
      entries: [
        { ip: '127.0.0.1', hostnames: ['localhost'] },
        { ip: 'bogus', hostnames: ['nas'] },
      ],
    }
    const issues = validateModel(parseSchema(hostsSchema).fields, model)

    expect(issues.map((issue) => issue.path)).toEqual([['entries', '1', 'ip']])
  })

  it('checks each item of a tag list against the item constraints', () => {
    const schema = rootWith({ type: 'array', items: { type: 'string', minLength: 2 } })
    const issues = validateModel(parseSchema(schema).fields, { subject: ['ok', 'x'] })

    expect(issues).toHaveLength(1)
    expect(issues[0]?.path).toEqual(['subject', '1'])
  })

  it('mirrors nothing for a shape the walker could not map', () => {
    const schema = rootWith({ type: ['string', 'number'] }, ['subject'])
    expect(messages(schema, { subject: [1, 'two'] })).toEqual([])
  })

  it('reports the clean hosts fixture as clean', () => {
    const model = {
      entries: [
        { ip: '127.0.0.1', hostnames: ['localhost'], comment: null },
        { ip: '::1', hostnames: ['ip6-localhost', 'ip6-loopback'] },
      ],
    }
    expect(validateModel(parseSchema(hostsSchema).fields, model)).toEqual([])
  })
})
