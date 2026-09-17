/**
 * Localized captions for the service vocabulary the API speaks.
 *
 * Two pages name these values: the services screen, which lists a unit's run
 * state and offers the commands, and the module page, whose apply dialog
 * offers the same commands as "what to do afterwards". One table rather than
 * two keeps them from drifting into two different words for `reload`.
 *
 * Each arm calls `getString` with a **literal** id. `bun run i18n:check` reads
 * ids out of the source text, so `getString(`services-action-${command}`)`
 * would be invisible to it and a caption dropped from `web.ftl` would reach an
 * operator as a raw id.
 */

import type { ReactLocalization } from '@fluent/react'
import type { ServiceCommand, ServiceStatus } from '@/api/services'
import type { LedVariant } from '@/components/Led'

export type ServiceState = ServiceStatus['state']

/** What `systemctl` reports, as a word rather than an enum value. */
export function serviceStateLabel(l10n: ReactLocalization, state: ServiceState): string {
  switch (state) {
    case 'active':
      return l10n.getString('services-state-active')
    case 'inactive':
      return l10n.getString('services-state-inactive')
    case 'failed':
      return l10n.getString('services-state-failed')
    case 'activating':
      return l10n.getString('services-state-activating')
    case 'deactivating':
      return l10n.getString('services-state-deactivating')
    case 'unknown':
      return l10n.getString('services-state-unknown')
  }
}

/**
 * The indicator beside that word. Only `active` is green and only `failed` is
 * the attention colour; a unit that is merely stopped is unlit rather than
 * alarming, per AESTHETIC_CONTRACT.md §12 (tone carries meaning, never
 * decoration).
 */
export function serviceStateLed(state: ServiceState): LedVariant {
  switch (state) {
    case 'active':
      return 'on'
    case 'failed':
      return 'rec'
    case 'inactive':
    case 'activating':
    case 'deactivating':
    case 'unknown':
      return 'off'
  }
}

/** A command an operator may issue against a unit. */
export function serviceActionCaption(l10n: ReactLocalization, command: ServiceCommand): string {
  switch (command) {
    case 'restart':
      return l10n.getString('services-action-restart')
    case 'reload':
      return l10n.getString('services-action-reload')
    case 'start':
      return l10n.getString('services-action-start')
    case 'stop':
      return l10n.getString('services-action-stop')
  }
}
