import { useLocalization } from '@fluent/react'
import { useTheme } from '@/lib/theme'
import { Label } from './Label'

/**
 * The hardware slide switch — AESTHETIC_CONTRACT.md §10. 56×22, `--panel-2`
 * track, sliding `--blue` knob, ☾ left / ☀ right. Snap, no transition.
 */
export function ThemeRocker() {
  const { theme, toggleTheme } = useTheme()
  const { l10n } = useLocalization()
  const isLight = theme === 'light'

  return (
    <div className="flex items-center gap-2">
      <Label variant="dim">{l10n.getString('status-mode-label')}</Label>
      <button
        type="button"
        className="relative flex h-[22px] w-[56px] cursor-pointer border border-[var(--line-2)] bg-[var(--panel-2)] p-0 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] transition-none hover:bg-[var(--panel-3)] active:translate-y-px"
        onClick={toggleTheme}
        aria-label={l10n.getString('theme-toggle-aria')}
        title={l10n.getString('theme-toggle-title')}
        aria-pressed={isLight}
      >
        <span
          aria-hidden="true"
          className={`z-[2] flex flex-1 items-center justify-center text-[11px] leading-none select-none ${
            isLight ? 'text-[var(--ink-dim)]' : 'text-[var(--cta-ink)]'
          }`}
        >
          ☾
        </span>
        <span
          aria-hidden="true"
          className={`z-[2] flex flex-1 items-center justify-center text-[11px] leading-none select-none ${
            isLight ? 'text-[var(--cta-ink)]' : 'text-[var(--ink-dim)]'
          }`}
        >
          ☀
        </span>
        <span
          aria-hidden="true"
          className="absolute top-px bottom-px z-[1] w-[26px] bg-[var(--blue)] shadow-[inset_0_1px_0_rgba(255,255,255,0.25)] transition-none"
          style={isLight ? { left: 'auto', right: '1px' } : { left: '1px' }}
        />
      </button>
    </div>
  )
}
