import type { ComponentProps } from 'react'
import { type FieldBaseProps, FieldFrame, useFieldIds } from './FieldFrame'

/**
 * Numeric input — AESTHETIC_CONTRACT.md §6, plus the §1 non-negotiable that
 * every readout carries `tabular-nums`.
 */
export type NumberFieldProps = FieldBaseProps &
  Omit<ComponentProps<'input'>, 'id' | 'className' | 'type'>

export function NumberField({
  label,
  id,
  description,
  error,
  tooltip,
  className,
  ...inputProps
}: NumberFieldProps) {
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
      <input
        inputMode="numeric"
        {...inputProps}
        id={ids.controlId}
        type="number"
        className="field-control num"
        aria-invalid={error !== undefined}
        aria-describedby={ids.describedBy}
      />
    </FieldFrame>
  )
}
