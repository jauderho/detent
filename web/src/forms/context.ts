/**
 * The shared state a rendered field needs, threaded through React context
 * rather than through every intermediate row and panel.
 *
 * Editing is a single call: {@link FormContextValue.setValue} replaces exactly
 * one leaf via `setAtPath`, which shares every untouched branch. No renderer is
 * allowed to rebuild an object or re-serialize a subtree — that is what keeps
 * a field the form does not understand byte-identical across a round trip.
 */

import { createContext, useContext } from 'react'
import { type DiagnosticMap, EMPTY_DIAGNOSTIC_MAP } from './diagnostics'
import type { JsonValue, ModelPath } from './json'
import type { FieldIssue } from './validate'

/**
 * What the installed service looks like, for fields whose `x-detent.since` it
 * may be too old to know. `installed` is `undefined` when detection found
 * nothing, and an undetected version disables nothing.
 */
export type VersionGate = {
  /** The service's name as the host profile files it, e.g. `chrony`. */
  readonly service: string
  readonly installed: string | undefined
}

export type FormContextValue = {
  readonly model: JsonValue
  /** Replaces one leaf. */
  readonly setValue: (path: ModelPath, value: JsonValue) => void
  /** Replaces one array, for add / remove / reorder. */
  readonly updateArray: (
    path: ModelPath,
    update: (items: readonly JsonValue[]) => readonly JsonValue[],
  ) => void
  /** Whether the advanced disclosure is open, everywhere in the form at once. */
  readonly showAdvanced: boolean
  /** Client-side issues, keyed by `pathKey`. */
  readonly issues: ReadonlyMap<string, readonly FieldIssue[]>
  readonly diagnostics: DiagnosticMap
  /** The installed service, when the page knows which one the module configures. */
  readonly versionGate: VersionGate | undefined
}

const FALLBACK: FormContextValue = {
  model: null,
  setValue: () => {},
  updateArray: () => {},
  showAdvanced: false,
  issues: new Map(),
  diagnostics: EMPTY_DIAGNOSTIC_MAP,
  versionGate: undefined,
}

export const FormContext = createContext<FormContextValue>(FALLBACK)

export function useFormContext(): FormContextValue {
  return useContext(FormContext)
}
