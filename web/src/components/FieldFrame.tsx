import { useLocalization } from '@fluent/react'
import { type ReactNode, useId } from 'react'
import { cn } from '@/lib/utils'
import { Led } from './Led'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'

/**
 * Shared chrome for the field primitives — AESTHETIC_CONTRACT.md §6. Every
 * field is a silk-screen `.lbl` caption over a machined control, with an
 * optional `--ink-faint` description line, an optional error line, and an
 * optional tooltip trigger.
 *
 * Accessibility contract: the caption is a real `<label htmlFor>` (controls
 * that are not labelable elements additionally point at `labelId` with
 * `aria-labelledby`), and `aria-invalid` / `aria-describedby` are wired
 * whenever a description or an error is present.
 */
export type FieldBaseProps = {
  /** Silk-screen caption. Caller supplies the localized string. */
  label: string
  /** Overrides the generated control id — useful when a page owns the ids. */
  id?: string | undefined
  /** Fine-print line under the control, in `--ink-faint`. */
  description?: string | undefined
  /** When set the control is marked `aria-invalid` and described by this text. */
  error?: string | undefined
  /** Body of the tooltip attached to the caption's info trigger. */
  tooltip?: string | undefined
  className?: string | undefined
}

export type FieldIds = {
  controlId: string
  labelId: string
  descriptionId: string
  errorId: string
  /** Space-separated id list for `aria-describedby`, or undefined when empty. */
  describedBy: string | undefined
}

export function useFieldIds(options: {
  id?: string | undefined
  hasDescription: boolean
  hasError: boolean
}): FieldIds {
  const generated = useId()
  const controlId = options.id ?? `${generated}-control`
  const descriptionId = `${generated}-desc`
  const errorId = `${generated}-error`
  const described: string[] = []
  if (options.hasDescription) described.push(descriptionId)
  if (options.hasError) described.push(errorId)

  return {
    controlId,
    labelId: `${generated}-label`,
    descriptionId,
    errorId,
    describedBy: described.length > 0 ? described.join(' ') : undefined,
  }
}

export type FieldFrameProps = FieldBaseProps & {
  ids: FieldIds
  /** The control itself. */
  children: ReactNode
}

export function FieldFrame({
  ids,
  label,
  description,
  error,
  tooltip,
  className,
  children,
}: FieldFrameProps) {
  const { l10n } = useLocalization()

  return (
    <div className={cn('field', className)}>
      <div className="field-head">
        <label className="lbl" id={ids.labelId} htmlFor={ids.controlId}>
          {label}
        </label>
        {tooltip === undefined ? null : (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  className="tinybtn"
                  aria-label={l10n.getString('component-field-info')}
                >
                  ?
                </button>
              </TooltipTrigger>
              <TooltipContent>{tooltip}</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </div>
      {children}
      {description === undefined ? null : (
        <p className="field-desc" id={ids.descriptionId}>
          {description}
        </p>
      )}
      {error === undefined ? null : (
        <p className="field-error" id={ids.errorId}>
          <Led variant="rec" />
          <span>{error}</span>
        </p>
      )}
    </div>
  )
}
