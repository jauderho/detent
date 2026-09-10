import { describe, expect, it } from 'vitest'
import hostsSchemaSource from '../__fixtures__/hosts.schema.json?raw'
import type { FieldNode } from '../schema'
import { defaultObject, MAX_SCHEMA_DEPTH, parseSchema, resolveRef } from '../schema'

const hostsSchema: unknown = JSON.parse(hostsSchemaSource)

function field(fields: readonly FieldNode[], name: string): FieldNode {
  const found = fields.find((candidate) => candidate.name === name)
  if (found === undefined) throw new Error(`no field named ${name}`)
  return found
}

/** A single-property root, so a test only has to spell the interesting node. */
function rootWith(property: unknown, extra: Record<string, unknown> = {}): unknown {
  return {
    type: 'object',
    additionalProperties: false,
    properties: { subject: property },
    ...extra,
  }
}

function only(schema: unknown): FieldNode {
  const parsed = parseSchema(schema)
  return field(parsed.fields, 'subject')
}

describe('parseSchema — $ref resolution', () => {
  it('resolves a local $defs pointer through to the target object', () => {
    const parsed = parseSchema(hostsSchema)
    const entries = field(parsed.fields, 'entries')

    expect(entries.control.type).toBe('rows')
    if (entries.control.type !== 'rows') throw new Error('unreachable')
    expect(entries.control.fields.map((node) => node.name)).toEqual(['comment', 'hostnames', 'ip'])
  })

  it('unescapes RFC 6901 tokens', () => {
    const root = { $defs: { 'a/b': { type: 'string' }, 'c~d': { type: 'number' } } }
    expect(resolveRef(root, '#/$defs/a~1b')).toEqual({ type: 'string' })
    expect(resolveRef(root, '#/$defs/c~0d')).toEqual({ type: 'number' })
  })

  it('refuses a remote $ref rather than fetching it', () => {
    const node = only(rootWith({ $ref: 'https://example.invalid/Entry.json' }))
    expect(node.control).toEqual({ type: 'unsupported', reason: 'ref' })
  })

  it('reports an unresolvable local $ref', () => {
    const node = only(rootWith({ $ref: '#/$defs/Missing' }, { $defs: {} }))
    expect(node.control).toEqual({ type: 'unsupported', reason: 'ref' })
  })
})

describe('parseSchema — field mapping', () => {
  it('maps a string to a text control and keeps its constraints', () => {
    const node = only(
      rootWith(
        { type: 'string', minLength: 2, maxLength: 8, pattern: '^[a-z]+$', format: 'ip' },
        { required: ['subject'] },
      ),
    )

    expect(node.control).toEqual({ type: 'text' })
    expect(node.constraints).toMatchObject({
      required: true,
      nullable: false,
      minLength: 2,
      maxLength: 8,
      pattern: '^[a-z]+$',
      format: 'ip',
    })
  })

  it('maps integer and number to a numeric control, keeping minimum and maximum', () => {
    const integer = only(rootWith({ type: 'integer', minimum: 1, maximum: 65535 }))
    expect(integer.control).toEqual({ type: 'number', integer: true })
    expect(integer.constraints.minimum).toBe(1)
    expect(integer.constraints.maximum).toBe(65535)

    expect(only(rootWith({ type: 'number' })).control).toEqual({ type: 'number', integer: false })
  })

  it('maps a boolean to a switch', () => {
    expect(only(rootWith({ type: 'boolean' })).control).toEqual({ type: 'switch' })
  })

  it('maps an enum to a select', () => {
    const node = only(rootWith({ type: 'string', enum: ['dhcp', 'static'] }))
    expect(node.control).toEqual({ type: 'select', options: ['dhcp', 'static'] })
  })

  it('maps the oneOf-of-const spelling to a select', () => {
    const node = only(rootWith({ oneOf: [{ const: 'off' }, { const: 'on' }] }))
    expect(node.control).toEqual({ type: 'select', options: ['off', 'on'] })
  })

  it('maps an array of string to a tag list, carrying the item constraints', () => {
    const node = only(rootWith({ type: 'array', items: { type: 'string', maxLength: 63 } }))
    expect(node.control.type).toBe('tags')
    if (node.control.type !== 'tags') throw new Error('unreachable')
    expect(node.control.item.maxLength).toBe(63)
  })

  it('maps an array of object to a row editor whose paths are row-relative', () => {
    const parsed = parseSchema(hostsSchema)
    const entries = field(parsed.fields, 'entries')
    if (entries.control.type !== 'rows') throw new Error('unreachable')

    expect(entries.path).toEqual(['entries'])
    expect(field(entries.control.fields, 'ip').path).toEqual(['ip'])
  })

  it('maps a nested object to walk-root-relative paths', () => {
    const node = only(
      rootWith({
        type: 'object',
        properties: { inner: { type: 'string' } },
        required: ['inner'],
      }),
    )

    expect(node.control.type).toBe('object')
    if (node.control.type !== 'object') throw new Error('unreachable')
    expect(field(node.control.fields, 'inner').path).toEqual(['subject', 'inner'])
  })

  it('reads the x-detent hints off the property site', () => {
    const parsed = parseSchema(hostsSchema)
    const entries = field(parsed.fields, 'entries')
    if (entries.control.type !== 'rows') throw new Error('unreachable')

    expect(entries.hints).toMatchObject({
      group: 'basic',
      tooltipId: 'hosts-tip-entries',
      securityImpact: 'low',
      requiresRestart: false,
    })
    expect(field(entries.control.fields, 'comment').hints.group).toBe('advanced')
  })
})

describe('parseSchema — the nullable union', () => {
  it('reads ["string", "null"] as a nullable text control', () => {
    const parsed = parseSchema(hostsSchema)
    const entries = field(parsed.fields, 'entries')
    if (entries.control.type !== 'rows') throw new Error('unreachable')
    const comment = field(entries.control.fields, 'comment')

    expect(comment.control).toEqual({ type: 'text' })
    expect(comment.constraints.nullable).toBe(true)
    expect(comment.constraints.required).toBe(false)
  })

  it('reads a nullable enum', () => {
    const node = only(rootWith({ type: ['string', 'null'], enum: ['a', 'b', null] }))
    expect(node.control).toEqual({ type: 'select', options: ['a', 'b'] })
    expect(node.constraints.nullable).toBe(true)
  })

  it('marks required fields required and the rest not', () => {
    const parsed = parseSchema(hostsSchema)
    expect(field(parsed.fields, 'entries').constraints.required).toBe(true)
  })
})

describe('parseSchema — the unmapped-shape fallback', () => {
  const cases: readonly (readonly [string, unknown])[] = [
    ['a multi-type union', { type: ['string', 'number'] }],
    ['an array of array', { type: 'array', items: { type: 'array', items: { type: 'string' } } }],
    ['a tuple', { type: 'array', prefixItems: [{ type: 'string' }], items: { type: 'string' } }],
    ['a free-form map', { type: 'object', additionalProperties: { type: 'string' } }],
    ['an untyped node', { description: 'anything at all' }],
    ['a bare null', { type: 'null' }],
  ]

  for (const [label, shape] of cases) {
    it(`falls back for ${label} instead of dropping it`, () => {
      const node = only(rootWith(shape))
      expect(node.control).toEqual({ type: 'unsupported', reason: 'shape' })
      expect(node.name).toBe('subject')
    })
  }

  it('falls back for a root that is not an object schema', () => {
    const parsed = parseSchema('not a schema')
    expect(parsed.fields).toEqual([])
  })

  it('falls back to a whole-model field when the root has no properties', () => {
    const parsed = parseSchema({ type: 'object', title: 'Model' })
    expect(parsed.fields).toHaveLength(1)
    expect(parsed.fields[0]?.control).toEqual({ type: 'unsupported', reason: 'shape' })
    expect(parsed.fields[0]?.path).toEqual([])
  })
})

describe('parseSchema — the recursion bound', () => {
  it('reports a $ref cycle instead of hanging', () => {
    const schema = {
      type: 'object',
      properties: { node: { $ref: '#/$defs/Node' } },
      $defs: {
        Node: {
          type: 'object',
          properties: { child: { $ref: '#/$defs/Node' }, name: { type: 'string' } },
        },
      },
    }

    const parsed = parseSchema(schema)
    const node = field(parsed.fields, 'node')
    if (node.control.type !== 'object') throw new Error('unreachable')

    expect(field(node.control.fields, 'child').control).toEqual({
      type: 'unsupported',
      reason: 'cycle',
    })
    expect(field(node.control.fields, 'name').control).toEqual({ type: 'text' })
  })

  it('reports a self-referential array of itself', () => {
    const schema = {
      type: 'object',
      properties: { tree: { $ref: '#/$defs/Tree' } },
      $defs: {
        Tree: {
          type: 'object',
          properties: { children: { type: 'array', items: { $ref: '#/$defs/Tree' } } },
        },
      },
    }

    const parsed = parseSchema(schema)
    const tree = field(parsed.fields, 'tree')
    if (tree.control.type !== 'object') throw new Error('unreachable')
    expect(field(tree.control.fields, 'children').control).toEqual({
      type: 'unsupported',
      reason: 'cycle',
    })
  })

  it('stops at MAX_SCHEMA_DEPTH on a deep but finite schema', () => {
    let leaf: unknown = { type: 'string' }
    for (let level = 0; level < MAX_SCHEMA_DEPTH + 5; level += 1) {
      leaf = { type: 'object', properties: { next: leaf }, required: ['next'] }
    }

    const parsed = parseSchema(leaf)
    let current = parsed.fields[0]
    let depth = 0
    while (current !== undefined && current.control.type === 'object') {
      depth += 1
      current = current.control.fields[0]
    }

    expect(current?.control).toEqual({ type: 'unsupported', reason: 'depth' })
    expect(depth).toBeLessThanOrEqual(MAX_SCHEMA_DEPTH + 1)
  })
})

describe('defaultObject', () => {
  it('builds a new row from the required fields only', () => {
    const parsed = parseSchema(hostsSchema)
    const entries = field(parsed.fields, 'entries')
    if (entries.control.type !== 'rows') throw new Error('unreachable')

    expect(defaultObject(entries.control.fields)).toEqual({ ip: '', hostnames: [] })
  })
})
