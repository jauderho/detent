/**
 * Fluent lookups that are allowed to miss.
 *
 * A field's `tooltip` / `recommendation` and a diagnostic's `id` are ids in the
 * *module's* locale file (`locales/<lang>/hosts.ftl`), not in `web.ftl`. The
 * form bundle may not carry them at all, so a lookup must degrade to "no
 * tooltip" — it must never render the raw id and never throw.
 *
 * `l10n.getString` falls back to returning the id itself, which is exactly the
 * leak we are avoiding, so presence is probed with `getBundle` first.
 */

import type { FluentVariable } from '@fluent/bundle'
import type { ReactLocalization } from '@fluent/react'

export type MessageArgs = Readonly<Record<string, FluentVariable>>

/** The message for `id`, or `undefined` when no loaded bundle defines it. */
export function optionalMessage(
  l10n: ReactLocalization,
  id: string | undefined,
  args?: MessageArgs,
): string | undefined {
  if (id === undefined || id.length === 0) return undefined
  if (l10n.getBundle(id) === null) return undefined
  return l10n.getString(id, args ?? null)
}

/** Joins the parts of a composed description line, dropping the absent ones. */
export function joinLines(parts: readonly (string | undefined)[]): string | undefined {
  const present = parts.filter((part): part is string => part !== undefined && part.length > 0)
  return present.length > 0 ? present.join(' · ') : undefined
}
