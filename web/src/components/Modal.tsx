import { useLocalization } from '@fluent/react'
import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useId, useRef } from 'react'
import { cn } from '@/lib/utils'
import { TinyButton } from './TinyButton'

/**
 * A hairline-bordered dialog on a dim scrim — AESTHETIC_CONTRACT.md §1 (zero
 * radius, no elevation shadow, zones defined by 1px hairlines). The scrim is
 * `--blue-deep`, which is fixed in both themes, so the chassis dims on cream
 * as well as on black.
 *
 * Behavior: focus moves into the dialog on open and is trapped there, Escape
 * closes, and focus returns to whatever was focused before opening. Carries
 * `role="dialog"`, `aria-modal="true"` and an accessible name from `title`.
 */
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR))
}

export type ModalProps = {
  open: boolean
  onClose: () => void
  /** Localized dialog title; also the accessible name. */
  title: string
  children: ReactNode
  /** Footer slot — typically a ButtonGroup of confirm/cancel controls. */
  footer?: ReactNode | undefined
  className?: string | undefined
}

export function Modal({ open, onClose, title, children, footer, className }: ModalProps) {
  const { l10n } = useLocalization()
  const dialogRef = useRef<HTMLDivElement>(null)
  const titleId = useId()

  useEffect(() => {
    if (!open) return
    // `document.body` is not a place focus was: it is where focus *fell* when
    // whatever the operator was on stopped being focusable — a trigger button
    // that disabled itself while its request was in flight, most often.
    // Restoring to it on close would move focus back to the top of the page
    // and silently discard a keyboard user's position, so a caller that knows
    // better is left to place focus itself.
    const active = document.activeElement
    const previouslyFocused =
      active instanceof HTMLElement && active !== document.body ? active : null
    const dialog = dialogRef.current
    const first = dialog === null ? null : focusableWithin(dialog)[0]
    ;(first ?? dialog)?.focus()
    return () => {
      previouslyFocused?.focus()
    }
  }, [open])

  const onKeyDown = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        onClose()
        return
      }
      if (event.key !== 'Tab') return

      const dialog = dialogRef.current
      if (dialog === null) return
      const items = focusableWithin(dialog)
      const first = items[0]
      const last = items[items.length - 1]
      if (first === undefined || last === undefined) {
        event.preventDefault()
        return
      }
      const active = document.activeElement
      if (event.shiftKey && (active === first || active === dialog)) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && active === last) {
        event.preventDefault()
        first.focus()
      }
    },
    [onClose],
  )

  if (!open) return null

  return (
    <div className="modal-backdrop">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cn('modal', className)}
        onKeyDown={onKeyDown}
      >
        <div className="modal-head">
          <h2 className="modal-title" id={titleId}>
            {title}
          </h2>
          <TinyButton onClick={onClose} aria-label={l10n.getString('component-modal-close')}>
            ✕
          </TinyButton>
        </div>
        <div className="modal-body">{children}</div>
        {footer === undefined ? null : <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  )
}
