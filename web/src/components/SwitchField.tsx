import { useLocalization } from '@fluent/react'
import { type FieldBaseProps, FieldFrame, useFieldIds } from './FieldFrame'

/**
 * A hardware toggle in the rocker idiom of AESTHETIC_CONTRACT.md §10 — a
 * bordered `--panel-2` track with a rectangular sliding knob that snaps with
 * no transition. Explicitly *not* a rounded pill (§12).
 *
 * Rendered as `role="switch"` so the on/off state is announced; the caption is
 * bound with `aria-labelledby` because a `<button>` is not a labelable element.
 */
export type SwitchFieldProps = FieldBaseProps & {
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  disabled?: boolean | undefined
  name?: string | undefined
}

export function SwitchField({
  label,
  id,
  description,
  error,
  tooltip,
  className,
  checked,
  onCheckedChange,
  disabled,
  name,
}: SwitchFieldProps) {
  const { l10n } = useLocalization()
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
      <button
        type="button"
        id={ids.controlId}
        name={name}
        role="switch"
        aria-checked={checked}
        aria-labelledby={ids.labelId}
        aria-invalid={error !== undefined}
        aria-describedby={ids.describedBy}
        disabled={disabled}
        className="switch"
        onClick={() => {
          onCheckedChange(!checked)
        }}
      >
        <span className="switch-cell is-off" aria-hidden="true">
          {l10n.getString('component-switch-off')}
        </span>
        <span className="switch-cell is-on" aria-hidden="true">
          {l10n.getString('component-switch-on')}
        </span>
        <span className="switch-knob" aria-hidden="true" />
      </button>
    </FieldFrame>
  )
}
