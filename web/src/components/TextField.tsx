import type { ComponentProps } from 'react'
import { type FieldBaseProps, FieldFrame, useFieldIds } from './FieldFrame'

/**
 * Single-line text input — AESTHETIC_CONTRACT.md §6. Zero radius, `--panel-2`
 * fill, 1px `--line-2` border, silk-screen caption above.
 */
export type TextFieldProps = FieldBaseProps &
  Omit<ComponentProps<'input'>, 'id' | 'className' | 'type'> & {
    type?: 'text' | 'email' | 'password' | 'search' | 'url' | undefined
  }

export function TextField({
  label,
  id,
  description,
  error,
  tooltip,
  className,
  type,
  ...inputProps
}: TextFieldProps) {
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
        {...inputProps}
        id={ids.controlId}
        type={type ?? 'text'}
        className="field-control"
        aria-invalid={error !== undefined}
        aria-describedby={ids.describedBy}
      />
    </FieldFrame>
  )
}
