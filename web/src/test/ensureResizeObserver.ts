/**
 * Installs a `ResizeObserver` no-op shim when the DOM shim has none.
 *
 * radix-ui's popper (used by the tooltip in `components/FieldFrame.tsx`)
 * measures its content with one as soon as a tooltip opens. Current happy-dom
 * provides it, but an older shim (or a future swap) may not — and a missing constructor
 * would crash the tooltip open path, not just a test. Kept as a tiny exported
 * helper (rather than inline in `preload.ts`, which cannot be imported by a
 * test without re-running its side effects) so the fallback branch is covered.
 */
export function ensureResizeObserver(target: Record<string, unknown>): void {
  if ('ResizeObserver' in target) return
  target.ResizeObserver = class {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }
}
