import { describe, expect, it } from 'bun:test'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { type ReactNode, useState } from 'react'
import { renderWithL10n } from '@/test/l10n'
import hostsSchemaSource from '../__fixtures__/hosts.schema.json?raw'
import { getAtPath, isJsonObject, type JsonValue, parseJsonValue } from '../json'
import { SchemaForm } from '../SchemaForm'

/**
 * Round-trip fidelity is the correctness bar for this engine: schema + model
 * in, edit one field, model out, with every untouched field byte-identical.
 *
 * These tests drive the real component with real events, so they exercise the
 * whole path — the walker, the control, the change handler and `setAtPath` —
 * rather than the helpers in isolation. They assert two things at once:
 * byte-identity of the serialized untouched branches, and *reference* identity
 * of the untouched objects, which is the mechanism that makes byte-identity
 * inevitable rather than coincidental.
 */

const hostsSchema: unknown = JSON.parse(hostsSchemaSource)

/**
 * The hosts schema with a property whose shape the walker does not understand
 * (an array of arrays), plus one the schema never mentions at all. Both must
 * survive an edit to a neighbouring field untouched.
 */
function schemaWithUnmappedField(): unknown {
  const base = parseJsonValue(hostsSchema)
  if (!isJsonObject(base)) throw new Error('fixture is not an object')

  const defs = base.$defs
  if (!isJsonObject(defs)) throw new Error('fixture has no $defs')

  const entry = defs.Entry
  if (!isJsonObject(entry)) throw new Error('fixture has no Entry')

  const properties = entry.properties
  if (!isJsonObject(properties)) throw new Error('Entry has no properties')

  return {
    ...base,
    $defs: {
      ...defs,
      Entry: {
        ...entry,
        properties: {
          ...properties,
          routes: {
            type: 'array',
            items: { type: 'array', items: { type: 'string' } },
            'x-detent': {
              group: 'basic',
              tooltip: 'hosts-tip-routes',
              security_impact: 'none',
              requires_restart: false,
            },
          },
        },
      },
    },
  }
}

const MODEL: JsonValue = {
  entries: [
    {
      ip: '127.0.0.1',
      hostnames: ['localhost', 'localhost.localdomain'],
      comment: 'the loopback',
      routes: [['a', 'b'], ['c']],
    },
    { ip: '10.0.0.4', hostnames: ['nas', 'nas.lan'], comment: null },
    { ip: 'fe80::1', hostnames: ['router'] },
  ],
  // A key the schema does not describe at all: the walker never sees it, so
  // nothing can write over it.
  trailer: { preserved: [1, 2, 3], nested: { deep: true } },
}

function Harness({ onModel }: { onModel: (next: JsonValue) => void }): ReactNode {
  const [model, setModel] = useState<JsonValue>(MODEL)

  return (
    <SchemaForm
      schema={schemaWithUnmappedField()}
      value={model}
      onChange={(next) => {
        setModel(next)
        onModel(next)
      }}
    />
  )
}

function latest(calls: readonly JsonValue[]): JsonValue {
  const last = calls.at(-1)
  if (last === undefined) throw new Error('the form emitted no model')
  return last
}

describe('round-trip fidelity', () => {
  it('leaves every untouched field byte-identical after editing one control', async () => {
    const emitted: JsonValue[] = []
    renderWithL10n(<Harness onModel={(next) => emitted.push(next)} />)

    const ipControls = screen.getAllByLabelText('ip')
    const first = ipControls[0]
    if (first === undefined) throw new Error('no ip control')

    await userEvent.type(first, '0')
    const next = latest(emitted)

    // The edited leaf changed, and only it.
    expect(getAtPath(next, ['entries', '0', 'ip'])).toBe('127.0.0.10')

    for (const path of [
      ['entries', '0', 'hostnames'],
      ['entries', '0', 'comment'],
      ['entries', '0', 'routes'],
      ['entries', '1'],
      ['entries', '2'],
      ['trailer'],
    ]) {
      expect(JSON.stringify(getAtPath(next, path))).toBe(JSON.stringify(getAtPath(MODEL, path)))
      // Structural sharing, not a deep rebuild that happens to match.
      expect(getAtPath(next, path)).toBe(getAtPath(MODEL, path))
    }
  })

  it('keeps the value of a field whose shape it cannot map', async () => {
    const emitted: JsonValue[] = []
    renderWithL10n(<Harness onModel={(next) => emitted.push(next)} />)

    const routes = screen.getAllByLabelText('routes')
    const control = routes[0]
    if (control === undefined) throw new Error('no routes control')
    expect(control).toHaveAttribute('readonly')

    const ipControls = screen.getAllByLabelText('ip')
    const second = ipControls[1]
    if (second === undefined) throw new Error('no second ip control')

    await userEvent.type(second, '2')

    expect(getAtPath(latest(emitted), ['entries', '0', 'routes'])).toBe(
      getAtPath(MODEL, ['entries', '0', 'routes']),
    )
  })

  it('preserves row order and the untouched rows across a reorder', async () => {
    const emitted: JsonValue[] = []
    renderWithL10n(<Harness onModel={(next) => emitted.push(next)} />)

    const buttons = screen
      .getAllByRole('button')
      .filter(
        (button) =>
          (button.getAttribute('aria-label') ?? '').replace(/[⁨⁩]/g, '') === 'move entries row 3 up',
      )
    const moveUp = buttons[0]
    if (moveUp === undefined) throw new Error('no move control for row 3')

    await userEvent.click(moveUp)
    const next = latest(emitted)

    const before = getAtPath(MODEL, ['entries'])
    const after = getAtPath(next, ['entries'])
    if (!Array.isArray(before) || !Array.isArray(after)) throw new Error('entries is not an array')

    expect(after).toHaveLength(3)
    expect(after[0]).toBe(before[0])
    expect(after[1]).toBe(before[2])
    expect(after[2]).toBe(before[1])
    expect(getAtPath(next, ['trailer'])).toBe(getAtPath(MODEL, ['trailer']))
  })

  it('serializes identically when nothing at all is edited', () => {
    const emitted: JsonValue[] = []
    renderWithL10n(<Harness onModel={(next) => emitted.push(next)} />)

    expect(emitted).toEqual([])
  })

  it('serializes the whole model unchanged apart from the edited leaf', async () => {
    const emitted: JsonValue[] = []
    renderWithL10n(<Harness onModel={(next) => emitted.push(next)} />)

    const hostname = screen.getAllByLabelText(
      (content) => content.replace(/[⁨⁩]/g, '') === 'hostnames item 2',
    )[0]
    if (hostname === undefined) throw new Error('no hostname control')

    await userEvent.type(hostname, 'x')

    const expected = JSON.parse(JSON.stringify(MODEL)) as Record<string, unknown>
    const entries = expected.entries as { hostnames: string[] }[]
    const row = entries[0]
    if (row === undefined) throw new Error('no first row')
    row.hostnames[1] = 'localhost.localdomainx'

    expect(JSON.stringify(latest(emitted))).toBe(JSON.stringify(expected))
  })
})
