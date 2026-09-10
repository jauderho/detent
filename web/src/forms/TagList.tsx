import { useLocalization } from '@fluent/react'
import { useId } from 'react'
import { Button } from '@/components/Button'
import { Led } from '@/components/Led'
import { TinyButton } from '@/components/TinyButton'
import { appendItem, type JsonValue, moveItem, removeAt } from './json'
import { keyItems } from './keys'

/**
 * The editor for an `array` of `string` — `hostnames` in the hosts module.
 *
 * Order is meaningful (canonical name first, then aliases), so the list carries
 * move controls and every mutation goes through the order-preserving helpers in
 * `json.ts`. Every control is a real `<button>` or `<input>`, so the whole
 * editor is on the keyboard path with no custom key handling.
 *
 * Rendered by hand rather than through `TextField` because the caption belongs
 * to the *list*, not to any one row: the list is a `<ul>` labelled by the
 * silk-screen caption, and each row is named positionally with `aria-label`.
 */
export type TagListProps = {
  /** Silk-screen caption — the property key. */
  label: string
  items: readonly string[]
  description?: string | undefined
  error?: string | undefined
  onChange: (next: readonly JsonValue[]) => void
}

export function TagList({ label, items, description, error, onChange }: TagListProps) {
  const { l10n } = useLocalization()
  const generated = useId()
  const labelId = `${generated}-label`
  const descriptionId = `${generated}-desc`
  const errorId = `${generated}-error`
  const described = [
    description === undefined ? undefined : descriptionId,
    error === undefined ? undefined : errorId,
  ].filter((id): id is string => id !== undefined)
  const describedBy = described.length > 0 ? described.join(' ') : undefined

  const rows = keyItems(items)
  const last = items.length - 1

  return (
    <div className="field">
      <div className="field-head">
        <span className="lbl" id={labelId}>
          {label}
        </span>
      </div>

      <ul aria-labelledby={labelId} aria-describedby={describedBy} className="flex flex-col gap-1">
        {rows.map((row) => (
          <li key={row.key} className="flex items-center gap-2">
            <input
              className="field-control"
              type="text"
              value={typeof row.value === 'string' ? row.value : ''}
              aria-label={l10n.getString('forms-tag-item', { field: label, index: row.index + 1 })}
              aria-invalid={error !== undefined}
              onChange={(event) => {
                const next = items.slice()
                next[row.index] = event.target.value
                onChange(next)
              }}
            />
            <TinyButton
              aria-label={l10n.getString('forms-tag-move-up', {
                field: label,
                index: row.index + 1,
              })}
              disabled={row.index === 0}
              onClick={() => {
                onChange(moveItem(items, row.index, row.index - 1))
              }}
            >
              {l10n.getString('forms-item-move-up-caption')}
            </TinyButton>
            <TinyButton
              aria-label={l10n.getString('forms-tag-move-down', {
                field: label,
                index: row.index + 1,
              })}
              disabled={row.index === last}
              onClick={() => {
                onChange(moveItem(items, row.index, row.index + 1))
              }}
            >
              {l10n.getString('forms-item-move-down-caption')}
            </TinyButton>
            <TinyButton
              aria-label={l10n.getString('forms-tag-remove', {
                field: label,
                index: row.index + 1,
              })}
              onClick={() => {
                onChange(removeAt(items, row.index))
              }}
            >
              {l10n.getString('forms-item-remove-caption')}
            </TinyButton>
          </li>
        ))}
      </ul>

      <div>
        <Button
          aria-label={l10n.getString('forms-tag-add', { field: label })}
          onClick={() => {
            onChange(appendItem(items, ''))
          }}
        >
          {l10n.getString('forms-item-add-caption')}
        </Button>
      </div>

      {description === undefined ? null : (
        <p className="field-desc" id={descriptionId}>
          {description}
        </p>
      )}
      {error === undefined ? null : (
        <p className="field-error" id={errorId}>
          <Led variant="rec" />
          <span>{error}</span>
        </p>
      )}
    </div>
  )
}
