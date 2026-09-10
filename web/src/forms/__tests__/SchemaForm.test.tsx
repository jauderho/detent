import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { type ReactNode, useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { renderWithL10n } from '@/test/l10n'
import hostsSchemaSource from '../__fixtures__/hosts.schema.json?raw'
import type { FormDiagnostic } from '../diagnostics'
import type { JsonValue } from '../json'
import { SchemaForm } from '../SchemaForm'

const hostsSchema: unknown = JSON.parse(hostsSchemaSource)

const HOSTS_MODEL: JsonValue = {
  entries: [
    { ip: '127.0.0.1', hostnames: ['localhost'], comment: null },
    { ip: '10.0.0.4', hostnames: ['nas', 'nas.lan'] },
  ],
}

function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`expected ${what}`)
  return value
}

/**
 * Fluent wraps every placeable in bidi isolate marks (U+2068 / U+2069), so an
 * accessible name built from a message with an argument never matches a plain
 * string. Strip them before comparing.
 */
const ISOLATES = /[\u2068\u2069]/g

function named(expected: string): (accessibleName: string) => boolean {
  return (accessibleName) => accessibleName.replace(ISOLATES, '') === expected
}

function labelled(expected: string): (content: string) => boolean {
  return (content) => content.replace(ISOLATES, '') === expected
}

/** Owns the model the way a module page does, and reports every emitted value. */
function Harness({
  schema = hostsSchema,
  initial = HOSTS_MODEL,
  diagnostics,
  onModel,
}: {
  schema?: unknown
  initial?: JsonValue
  diagnostics?: readonly FormDiagnostic[]
  onModel?: (next: JsonValue) => void
}): ReactNode {
  const [model, setModel] = useState<JsonValue>(initial)

  return (
    <SchemaForm
      schema={schema}
      value={model}
      diagnostics={diagnostics}
      onChange={(next) => {
        setModel(next)
        onModel?.(next)
      }}
    />
  )
}

describe('SchemaForm — mapping onto the component layer', () => {
  it('renders one labelled control per schema field', () => {
    renderWithL10n(<Harness />)

    expect(screen.getAllByLabelText('ip')).toHaveLength(2)
    expect(screen.getAllByLabelText(labelled('hostnames item 1'))[0]).toBeInTheDocument()
    expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0)
  })

  it('maps a boolean to a switch and an enum to a select', async () => {
    const schema = {
      type: 'object',
      properties: {
        enabled: { type: 'boolean' },
        mode: { type: 'string', enum: ['dhcp', 'static'] },
      },
      required: ['enabled', 'mode'],
    }
    const onModel = vi.fn()
    renderWithL10n(
      <Harness schema={schema} initial={{ enabled: false, mode: 'dhcp' }} onModel={onModel} />,
    )

    const toggle = screen.getByRole('switch', { name: 'enabled' })
    expect(toggle).toHaveAttribute('aria-checked', 'false')
    await userEvent.click(toggle)
    expect(onModel).toHaveBeenLastCalledWith({ enabled: true, mode: 'dhcp' })

    await userEvent.selectOptions(screen.getByLabelText('mode'), 'static')
    expect(onModel).toHaveBeenLastCalledWith({ enabled: true, mode: 'static' })
  })

  it('maps a number and honours minimum and maximum on the control', async () => {
    const schema = {
      type: 'object',
      properties: { port: { type: 'integer', minimum: 1, maximum: 65535 } },
      required: ['port'],
    }
    const onModel = vi.fn()
    renderWithL10n(<Harness schema={schema} initial={{ port: 53 }} onModel={onModel} />)

    const input = screen.getByLabelText('port')
    expect(input).toHaveAttribute('type', 'number')
    expect(input).toHaveAttribute('min', '1')
    expect(input).toHaveAttribute('max', '65535')

    await userEvent.type(input, '1')
    expect(onModel).toHaveBeenLastCalledWith({ port: 531 })
  })

  it('writes null when a nullable text field is emptied', async () => {
    const onModel = vi.fn()
    renderWithL10n(
      <Harness
        initial={{ entries: [{ ip: '127.0.0.1', hostnames: ['a'], comment: 'x' }] }}
        onModel={onModel}
      />,
    )

    await userEvent.click(screen.getByRole('button', { name: 'advanced' }))
    await userEvent.clear(screen.getByLabelText('comment'))

    expect(onModel).toHaveBeenLastCalledWith({
      entries: [{ ip: '127.0.0.1', hostnames: ['a'], comment: null }],
    })
  })
})

describe('SchemaForm — the unmapped-shape fallback', () => {
  const schema = {
    type: 'object',
    properties: {
      name: { type: 'string' },
      matrix: { type: 'array', items: { type: 'array', items: { type: 'string' } } },
    },
    required: ['name'],
  }

  it('shows the raw value read-only rather than dropping the field', () => {
    renderWithL10n(<Harness schema={schema} initial={{ name: 'a', matrix: [['x', 'y']] }} />)

    const control = screen.getByLabelText('matrix')
    expect(control).toHaveAttribute('readonly')
    expect(control).toHaveValue(JSON.stringify([['x', 'y']], null, 2))
    expect(screen.getByText(/cannot edit this value/)).toBeInTheDocument()
  })

  it('falls back when the model value disagrees with the mapped control', () => {
    renderWithL10n(<Harness schema={schema} initial={{ name: { unexpected: true } }} />)

    const control = screen.getByLabelText('name')
    expect(control).toHaveAttribute('readonly')
    expect(control).toHaveValue(JSON.stringify({ unexpected: true }, null, 2))
  })
})

describe('SchemaForm — basic / advanced disclosure', () => {
  it('hides advanced fields behind an announced, keyboard-operable control', async () => {
    renderWithL10n(<Harness />)

    const toggle = screen.getByRole('button', { name: 'advanced' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByLabelText('comment')).not.toBeInTheDocument()

    toggle.focus()
    await userEvent.keyboard('{Enter}')

    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getAllByLabelText('comment')).toHaveLength(2)

    const controlled = must(toggle.getAttribute('aria-controls'), 'aria-controls')
    expect(document.getElementById(controlled)).not.toBeNull()
  })

  it('marks a high security impact and a deprecated option in either group', () => {
    const schema = {
      type: 'object',
      properties: {
        risky: {
          type: 'string',
          'x-detent': {
            group: 'basic',
            tooltip: 'mod-tip-risky',
            security_impact: 'high',
            requires_restart: false,
          },
        },
        old: {
          type: 'string',
          'x-detent': {
            group: 'basic',
            tooltip: 'mod-tip-old',
            security_impact: 'none',
            requires_restart: false,
            deprecated_in: '4.9',
          },
        },
      },
    }
    renderWithL10n(<Harness schema={schema} initial={{ risky: 'a', old: 'b' }} />)

    expect(screen.getByText('high security impact')).toBeInTheDocument()
    expect(screen.getByText(/deprecated in/)).toHaveTextContent('4.9')
  })

  it('never renders a module tooltip id the loaded bundle does not define', () => {
    renderWithL10n(<Harness />)
    expect(screen.queryByText(/hosts-tip-/)).not.toBeInTheDocument()
  })
})

describe('SchemaForm — the row editor', () => {
  it('adds a row built from the required fields, at the end', async () => {
    const onModel = vi.fn()
    renderWithL10n(<Harness onModel={onModel} />)

    await userEvent.click(screen.getByRole('button', { name: named('add a row to entries') }))

    expect(onModel).toHaveBeenLastCalledWith({
      entries: [
        { ip: '127.0.0.1', hostnames: ['localhost'], comment: null },
        { ip: '10.0.0.4', hostnames: ['nas', 'nas.lan'] },
        { ip: '', hostnames: [] },
      ],
    })
  })

  it('removes a row and closes the gap without disturbing the others', async () => {
    const onModel = vi.fn()
    renderWithL10n(<Harness onModel={onModel} />)

    await userEvent.click(screen.getByRole('button', { name: named('remove entries row 1') }))

    expect(onModel).toHaveBeenLastCalledWith({
      entries: [{ ip: '10.0.0.4', hostnames: ['nas', 'nas.lan'] }],
    })
  })

  it('reorders rows, preserving the order of every other row exactly', async () => {
    const initial: JsonValue = {
      entries: [
        { ip: '1.1.1.1', hostnames: ['a'] },
        { ip: '2.2.2.2', hostnames: ['b'] },
        { ip: '3.3.3.3', hostnames: ['c'] },
      ],
    }
    const onModel = vi.fn()
    renderWithL10n(<Harness initial={initial} onModel={onModel} />)

    await userEvent.click(screen.getByRole('button', { name: named('move entries row 3 up') }))

    expect(onModel).toHaveBeenLastCalledWith({
      entries: [
        { ip: '1.1.1.1', hostnames: ['a'] },
        { ip: '3.3.3.3', hostnames: ['c'] },
        { ip: '2.2.2.2', hostnames: ['b'] },
      ],
    })

    await userEvent.click(screen.getByRole('button', { name: named('move entries row 1 down') }))

    expect(onModel).toHaveBeenLastCalledWith({
      entries: [
        { ip: '3.3.3.3', hostnames: ['c'] },
        { ip: '1.1.1.1', hostnames: ['a'] },
        { ip: '2.2.2.2', hostnames: ['b'] },
      ],
    })
  })

  it('disables the move controls at the ends of the list', () => {
    renderWithL10n(<Harness />)

    expect(screen.getByRole('button', { name: named('move entries row 1 up') })).toBeDisabled()
    expect(screen.getByRole('button', { name: named('move entries row 2 down') })).toBeDisabled()
    expect(screen.getByRole('button', { name: named('move entries row 1 down') })).toBeEnabled()
  })

  it('is fully reachable from the keyboard', async () => {
    renderWithL10n(<Harness initial={{ entries: [{ ip: '1.1.1.1', hostnames: ['a'] }] }} />)

    const add = screen.getByRole('button', { name: named('add a row to entries') })
    add.focus()
    await userEvent.keyboard('{Enter}')

    expect(screen.getAllByLabelText('ip')).toHaveLength(2)
  })
})

describe('SchemaForm — the tag list', () => {
  it('adds, edits, removes and reorders items in place', async () => {
    const onModel = vi.fn()
    renderWithL10n(
      <Harness
        initial={{ entries: [{ ip: '1.1.1.1', hostnames: ['a', 'b'] }] }}
        onModel={onModel}
      />,
    )

    await userEvent.click(screen.getByRole('button', { name: named('add an item to hostnames') }))
    expect(onModel).toHaveBeenLastCalledWith({
      entries: [{ ip: '1.1.1.1', hostnames: ['a', 'b', ''] }],
    })

    await userEvent.click(screen.getByRole('button', { name: named('move hostnames item 2 up') }))
    expect(onModel).toHaveBeenLastCalledWith({
      entries: [{ ip: '1.1.1.1', hostnames: ['b', 'a', ''] }],
    })

    await userEvent.click(screen.getByRole('button', { name: named('remove hostnames item 3') }))
    expect(onModel).toHaveBeenLastCalledWith({
      entries: [{ ip: '1.1.1.1', hostnames: ['b', 'a'] }],
    })
  })
})

describe('SchemaForm — validation feedback', () => {
  it('marks a field invalid and describes it with the mirrored message', () => {
    renderWithL10n(<Harness initial={{ entries: [{ ip: 'nope', hostnames: ['a'] }] }} />)

    const input = must(screen.getAllByLabelText('ip')[0], 'the ip control')
    expect(input).toHaveAttribute('aria-invalid', 'true')

    const describedBy = must(input.getAttribute('aria-describedby'), 'aria-describedby')
    const described = describedBy
      .split(' ')
      .map((id) => document.getElementById(id)?.textContent ?? '')
      .join(' ')
    expect(described).toContain('not a valid ip address')
  })
})

describe('SchemaForm — diagnostics', () => {
  const diagnostic = (overrides: Partial<FormDiagnostic>): FormDiagnostic => ({
    severity: 'error',
    id: 'hosts-diag',
    field: undefined,
    span: undefined,
    args: {},
    ...overrides,
  })

  it('shows a field diagnostic inline on the control it names', () => {
    renderWithL10n(<Harness diagnostics={[diagnostic({ field: 'entries/1/ip' })]} />)

    const input = must(screen.getAllByLabelText('ip')[1], 'the second ip control')
    expect(input).toHaveAttribute('aria-invalid', 'true')

    const describedBy = must(input.getAttribute('aria-describedby'), 'aria-describedby')
    const described = describedBy
      .split(' ')
      .map((id) => document.getElementById(id)?.textContent ?? '')
      .join(' ')
    expect(described).toContain('hosts-diag')
  })

  it('lands a sub-path diagnostic on the list that contains it', () => {
    renderWithL10n(<Harness diagnostics={[diagnostic({ field: 'entries/0/hostnames/0' })]} />)

    const first = must(screen.getAllByLabelText(labelled('hostnames item 1'))[0], 'the first tag')
    expect(first).toHaveAttribute('aria-invalid', 'true')
  })

  it('surfaces an unmappable diagnostic at form level rather than dropping it', () => {
    renderWithL10n(
      <Harness diagnostics={[diagnostic({ field: 'resolver/search/0', id: 'hosts-orphan' })]} />,
    )

    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('resolver/search/0')
    expect(alert).toHaveTextContent('hosts-orphan')
  })

  it('surfaces a diagnostic with no field at form level', () => {
    renderWithL10n(<Harness diagnostics={[diagnostic({ id: 'hosts-whole-file' })]} />)
    expect(screen.getByRole('alert')).toHaveTextContent('hosts-whole-file')
  })

  it('puts a recommendation on the description line, not the error line', () => {
    renderWithL10n(
      <Harness
        diagnostics={[
          diagnostic({ field: 'entries/0/ip', severity: 'recommendation', id: 'hosts-hint' }),
        ]}
      />,
    )

    const input = must(screen.getAllByLabelText('ip')[0], 'the ip control')
    expect(input).toHaveAttribute('aria-invalid', 'false')
    const describedBy = must(input.getAttribute('aria-describedby'), 'aria-describedby')
    expect(document.getElementById(describedBy)).toHaveTextContent('hosts-hint')
  })
})
