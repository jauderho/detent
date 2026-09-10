/**
 * The section strip under the status bar.
 *
 * A flat label row, not a menu — AESTHETIC_CONTRACT.md §6: "no hamburger, no
 * dropdown". Links are `.btn` cells sharing an edge, and the active one takes
 * the `.primary` blue fill, which is how the panel says "you are here".
 *
 * It renders only for a signed-in operator: the sign-out control belongs to it,
 * and there is nothing to navigate to from the login screen.
 */

import { Localized, useLocalization } from '@fluent/react'
import type { ReactNode } from 'react'
import { NavLink } from 'react-router'
import { useAuth } from '@/auth/AuthProvider'
import { Button } from '@/components/Button'
import { cn } from '@/lib/utils'
import { ROUTES } from './paths'

const NAV_STYLE = {
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'center',
  paddingTop: 12,
  paddingBottom: 12,
} as const

/**
 * The captions are elements, not ids passed to `<Localized id={…}>`: a
 * variable id resolves at run time but is invisible to `bun run i18n:check`,
 * which reads literal ids out of the source, and a caption dropped from
 * `web.ftl` would then reach the panel as a raw id.
 *
 * `end` keeps the dashboard from matching every address below it.
 */
const LINKS: readonly { key: string; to: string; end: boolean; label: ReactNode }[] = [
  {
    key: 'dashboard',
    to: ROUTES.dashboard,
    end: true,
    label: (
      <Localized id="nav-dashboard">
        <span>dashboard</span>
      </Localized>
    ),
  },
  {
    key: 'modules',
    to: ROUTES.modules,
    end: false,
    label: (
      <Localized id="nav-modules">
        <span>modules</span>
      </Localized>
    ),
  },
  {
    key: 'services',
    to: ROUTES.services,
    end: false,
    label: (
      <Localized id="nav-services">
        <span>services</span>
      </Localized>
    ),
  },
  {
    key: 'backups',
    to: ROUTES.backups,
    end: false,
    label: (
      <Localized id="nav-backups">
        <span>backups</span>
      </Localized>
    ),
  },
  {
    key: 'audit',
    to: ROUTES.audit,
    end: false,
    label: (
      <Localized id="nav-audit">
        <span>audit</span>
      </Localized>
    ),
  },
  {
    key: 'certificates',
    to: ROUTES.certificates,
    end: false,
    label: (
      <Localized id="nav-certificates">
        <span>certificates</span>
      </Localized>
    ),
  },
  {
    key: 'settings',
    to: ROUTES.settings,
    end: false,
    label: (
      <Localized id="nav-settings">
        <span>settings</span>
      </Localized>
    ),
  },
]

export function AppNav() {
  const { l10n } = useLocalization()
  const { status, logout } = useAuth()

  if (status !== 'authenticated') {
    return null
  }

  return (
    <nav className="wrap" style={NAV_STYLE} aria-label={l10n.getString('nav-label')}>
      <div className="btngroup">
        {LINKS.map((link) => (
          <NavLink
            key={link.key}
            to={link.to}
            end={link.end}
            className={({ isActive }) => cn('btn', isActive && 'primary')}
          >
            {link.label}
          </NavLink>
        ))}
      </div>
      <div style={{ marginLeft: 'auto' }}>
        <Button
          onClick={() => {
            void logout()
          }}
        >
          <Localized id="auth-sign-out">
            <span>sign out</span>
          </Localized>
        </Button>
      </div>
    </nav>
  )
}
