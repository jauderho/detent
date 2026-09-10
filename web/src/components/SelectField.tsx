import type { ComponentProps } from 'react'
import { type FieldBaseProps, FieldFrame, useFieldIds } from './FieldFrame'

/**
 * Native `<select>` styled as a machined control — AESTHETIC_CONTRACT.md §6.
 * Native rather than a custom listbox because the platform control is already
 * keyboard-operable and screen-reader correct; only its skin is themed
 * (`appearance: none`, radius 0, `--panel-2` fill, 1px `--line-2`).
 */
export type SelectOption = {
  value: string
  /** Localized display text supplied by the caller. */
  label: string
  disabled?: boolean | undefined
}

export type SelectFieldProps = FieldBaseProps &
  Omit<ComponentProps<'select'>, 'id' | 'className' | 'children'> & {
    options: readonly SelectOption[]
  }

export function SelectField({
  label,
  id,
  description,
  error,
  tooltip,
  className,
  options,
  ...selectProps
}: SelectFieldProps) {
  const ids = useFieldIds({
    id,
    hasDescription: description !== undefined,
    hasError: error !== undefined,
  })

  return (
    <FieldFrame
      ids={ids}
      label={label}
      description={description}
      error={error}
      tooltip={tooltip}
      className={className}
    >
      <select
        {...selectProps}
        id={ids.controlId}
        className="field-control"
        aria-invalid={error !== undefined}
        aria-describedby={ids.describedBy}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} disabled={option.disabled}>
            {option.label}
          </option>
        ))}
      </select>
    </FieldFrame>
  )
}
