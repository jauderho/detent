import { describe, expect, it, mock } from 'bun:test'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithL10n } from '@/test/l10n'
import { NumberField } from '../NumberField'
import { SelectField } from '../SelectField'
import { SwitchField } from '../SwitchField'
import { TextField } from '../TextField'

describe('TextField', () => {
  it('associates the silk-screen caption with the control', () => {
    renderWithL10n(<TextField label="hostname" />)
    const input = screen.getByLabelText('hostname')

    expect(input).toHaveClass('field-control')
    expect(input).toHaveAttribute('type', 'text')
    expect(input).toHaveAttribute('aria-invalid', 'false')
    expect(input).not.toHaveAttribute('aria-describedby')
  })

  it('wires aria-describedby to the description line', () => {
    renderWithL10n(<TextField label="hostname" description="fully qualified" />)
    const input = screen.getByLabelText('hostname')
    const describedBy = input.getAttribute('aria-describedby')

    expect(describedBy).not.toBeNull()
    expect(document.getElementById(describedBy ?? '')).toHaveTextContent('fully qualified')
  })

  it('wires aria-invalid and aria-describedby when an error is present', () => {
    renderWithL10n(
      <TextField label="hostname" description="fully qualified" error="must not be empty" />,
    )
    const input = screen.getByLabelText('hostname')

    expect(input).toHaveAttribute('aria-invalid', 'true')
    const ids = (input.getAttribute('aria-describedby') ?? '').split(' ')
    expect(ids).toHaveLength(2)
    const described = ids.map((id) => document.getElementById(id)?.textContent ?? '').join(' ')
    expect(described).toContain('fully qualified')
    expect(described).toContain('must not be empty')
  })

  it('accepts typed input', async () => {
    const onChange = mock()
    renderWithL10n(<TextField label="hostname" onChange={onChange} />)

    await userEvent.type(screen.getByLabelText('hostname'), 'nas')

    expect(onChange).toHaveBeenCalledTimes(3)
  })

  it('renders a keyboard-reachable tooltip trigger', async () => {
    renderWithL10n(<TextField label="hostname" tooltip="the machine name" />)
    const trigger = screen.getByRole('button', { name: 'more information' })

    await userEvent.tab()
    expect(trigger).toHaveFocus()
  })
})

describe('NumberField', () => {
  it('renders a tabular-nums numeric control', () => {
    renderWithL10n(<NumberField label="port" defaultValue={53} />)
    const input = screen.getByLabelText('port')

    expect(input).toHaveClass('field-control', 'num')
    expect(input).toHaveAttribute('type', 'number')
  })

  it('marks itself invalid when an error is supplied', () => {
    renderWithL10n(<NumberField label="port" error="out of range" />)

    expect(screen.getByLabelText('port')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText('out of range')).toBeInTheDocument()
  })
})

describe('SelectField', () => {
  const options = [
    { value: 'dhcp', label: 'dhcp' },
    { value: 'static', label: 'static' },
  ] as const

  it('renders its options and is selectable from the keyboard', async () => {
    const onChange = mock()
    renderWithL10n(
      <SelectField label="addressing" options={options} defaultValue="dhcp" onChange={onChange} />,
    )
    const select = screen.getByLabelText('addressing')

    expect(select).toHaveClass('field-control')
    expect(screen.getAllByRole('option')).toHaveLength(2)

    await userEvent.selectOptions(select, 'static')
    expect(onChange).toHaveBeenCalledTimes(1)
    expect(select).toHaveValue('static')
  })

  it('wires the error line', () => {
    renderWithL10n(<SelectField label="addressing" options={options} error="pick one" />)
    const select = screen.getByLabelText('addressing')

    expect(select).toHaveAttribute('aria-invalid', 'true')
    const describedBy = select.getAttribute('aria-describedby') ?? ''
    expect(document.getElementById(describedBy)).toHaveTextContent('pick one')
  })
})

describe('SwitchField', () => {
  it('is a labelled role=switch, not a checkbox pill', () => {
    renderWithL10n(<SwitchField label="ipv6" checked={false} onCheckedChange={mock()} />)
    const toggle = screen.getByRole('switch', { name: 'ipv6' })

    expect(toggle).toHaveClass('switch')
    expect(toggle).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByLabelText('ipv6')).toBe(toggle)
  })

  it('toggles from the keyboard', async () => {
    const onCheckedChange = mock()
    renderWithL10n(<SwitchField label="ipv6" checked={false} onCheckedChange={onCheckedChange} />)

    screen.getByRole('switch', { name: 'ipv6' }).focus()
    await userEvent.keyboard(' ')

    expect(onCheckedChange).toHaveBeenCalledWith(true)
  })

  it('reflects the checked state and localizes its on/off cells', () => {
    renderWithL10n(<SwitchField label="ipv6" checked onCheckedChange={mock()} />)

    expect(screen.getByRole('switch', { name: 'ipv6' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByText('on')).toHaveClass('switch-cell', 'is-on')
    expect(screen.getByText('off')).toHaveClass('switch-cell', 'is-off')
  })

  it('wires aria-invalid and the error line', () => {
    renderWithL10n(
      <SwitchField
        label="ipv6"
        checked={false}
        onCheckedChange={mock()}
        error="locked by policy"
      />,
    )
    const toggle = screen.getByRole('switch', { name: 'ipv6' })

    expect(toggle).toHaveAttribute('aria-invalid', 'true')
    const describedBy = toggle.getAttribute('aria-describedby') ?? ''
    expect(document.getElementById(describedBy)).toHaveTextContent('locked by policy')
  })
})
