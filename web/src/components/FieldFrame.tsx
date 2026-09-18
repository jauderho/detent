import { useLocalization } from '@fluent/react'
import { Tooltip as TooltipPrimitive } from 'radix-ui'
import { type ReactNode, useId } from 'react'
import { cn } from '@/lib/utils'
import { Led } from './Led'

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
          <TooltipPrimitive.Provider data-slot="tooltip-provider" delayDuration={0}>
            <TooltipPrimitive.Root data-slot="tooltip">
              <TooltipPrimitive.Trigger data-slot="tooltip-trigger" asChild>
                <button
                  type="button"
                  className="tinybtn"
                  aria-label={l10n.getString('component-field-info')}
                >
                  ?
                </button>
              </TooltipPrimitive.Trigger>
              <TooltipPrimitive.Portal>
                <TooltipPrimitive.Content
                  data-slot="tooltip-content"
                  sideOffset={0}
                  className="z-50 w-fit origin-(--radix-tooltip-content-transform-origin) animate-in rounded-md bg-foreground px-3 py-1.5 text-xs text-balance text-background fade-in-0 zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95"
                >
                  {tooltip}
                  <TooltipPrimitive.Arrow className="z-50 size-2.5 translate-y-[calc(-50%_-_2px)] rotate-45 rounded-[2px] bg-foreground fill-foreground" />
                </TooltipPrimitive.Content>
              </TooltipPrimitive.Portal>
            </TooltipPrimitive.Root>
          </TooltipPrimitive.Provider>
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
