import { type ReactLocalization, useLocalization } from '@fluent/react'
import { useCallback, useId, useMemo, useState } from 'react'
import { Banner } from '@/components/Banner'
import { TinyButton } from '@/components/TinyButton'
import { FormContext, type FormContextValue } from './context'
import {
  collectFieldPaths,
  type FormDiagnostic,
  mapDiagnostics,
  parseFieldPath,
} from './diagnostics'
import { FieldList } from './FieldControl'
import { type JsonValue, type ModelPath, pathKey, setAtPath, updateArrayAtPath } from './json'
import { optionalMessage } from './l10n'
import { hasGroup, parseSchema } from './schema'
import { type FieldIssue, validateModel } from './validate'

/**
 * The form engine's public surface: hand it a module schema, the model the API
 * returned, and a change handler.
 *
 * ```tsx
 * const [model, setModel] = useState<JsonValue>(fetched.model)
 *
 * <SchemaForm
 *   schema={fetched.schema}
 *   value={model}
 *   onChange={setModel}
 *   diagnostics={parseDiagnostics(lastValidateResponse.diagnostics)}
 * />
 * ```
 *
 * `onChange` receives a whole new model. It is *not* a rebuild: every edit is
 * one `setAtPath` call, so every branch the user did not touch comes back as
 * the same object reference that went in — including the parts of the model
 * this form has no control for. Feed the value straight back to `validate` /
 * `plan` / `apply`.
 *
 * `schema` and `diagnostics` are typed `unknown` / already-parsed on purpose:
 * both arrive over HTTP and are read defensively, never asserted.
 */
export type SchemaFormProps = {
  /**
   * The module's JSON Schema document, as served. Held by identity: keep it
   * stable (the API response object, or a `useMemo`) so the walk is not redone
   * on every keystroke.
   */
  schema: unknown
  /** The model being edited. */
  value: JsonValue
  onChange: (next: JsonValue) => void
  /** Diagnostics from the last `validate` / `plan` / rejected `apply`. */
  diagnostics?: readonly FormDiagnostic[] | undefined
  className?: string | undefined
}

function groupIssues(issues: readonly FieldIssue[]): ReadonlyMap<string, readonly FieldIssue[]> {
  const map = new Map<string, FieldIssue[]>()
  for (const issue of issues) {
    const key = pathKey(issue.path)
    const bucket = map.get(key)
    if (bucket === undefined) map.set(key, [issue])
    else bucket.push(issue)
  }
  return map
}

export function SchemaForm({ schema, value, onChange, diagnostics, className }: SchemaFormProps) {
  const { l10n } = useLocalization()
  const [showAdvanced, setShowAdvanced] = useState(false)
  const advancedId = useId()

  const parsed = useMemo(() => parseSchema(schema), [schema])
  const issues = useMemo(
    () => groupIssues(validateModel(parsed.fields, value)),
    [parsed.fields, value],
  )
  const rendered = useMemo(() => collectFieldPaths(parsed.fields, value), [parsed.fields, value])
  const mapped = useMemo(() => mapDiagnostics(diagnostics ?? [], rendered), [diagnostics, rendered])

  const setValue = useCallback(
    (path: ModelPath, next: JsonValue) => {
      onChange(setAtPath(value, path, next))
    },
    [onChange, value],
  )

  const updateArray = useCallback(
    (path: ModelPath, update: (items: readonly JsonValue[]) => readonly JsonValue[]) => {
      onChange(updateArrayAtPath(value, path, update))
    },
    [onChange, value],
  )

  const context: FormContextValue = useMemo(
    () => ({ model: value, setValue, updateArray, showAdvanced, issues, diagnostics: mapped }),
    [value, setValue, updateArray, showAdvanced, issues, mapped],
  )

  const hasAdvanced = hasGroup(parsed.fields, 'advanced')

  return (
    <FormContext.Provider value={context}>
      <div className={className}>
        <div className="flex flex-col gap-3">
          {mapped.formLevel.map((diagnostic) => (
            <Banner
              key={`${diagnostic.severity}:${diagnostic.id}:${diagnostic.field ?? ''}`}
              tone={diagnostic.severity === 'recommendation' ? 'blue' : 'amber'}
            >
              {formLevelText(l10n, diagnostic)}
            </Banner>
          ))}

          <FieldList fields={parsed.fields} basePath={[]} group="basic" />

          {hasAdvanced ? (
            <div className="flex flex-col gap-3 border-t border-[var(--line)] pt-3">
              <div>
                <TinyButton
                  aria-expanded={showAdvanced}
                  aria-controls={advancedId}
                  on={showAdvanced}
                  onClick={() => {
                    setShowAdvanced((open) => !open)
                  }}
                >
                  {l10n.getString('forms-advanced-toggle')}
                </TinyButton>
              </div>
              <div id={advancedId} hidden={!showAdvanced}>
                {showAdvanced ? (
                  <FieldList fields={parsed.fields} basePath={[]} group="advanced" />
                ) : null}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </FormContext.Provider>
  )
}

/**
 * A diagnostic the form could not place on a control still has to be read, so
 * it is shown at form level with whatever address it carried. An id the loaded
 * bundles do not define degrades to a message naming the id — never the bare id
 * rendered as if it were prose.
 */
function formLevelText(l10n: ReactLocalization, diagnostic: FormDiagnostic): string {
  const body =
    optionalMessage(l10n, diagnostic.id, diagnostic.args) ??
    l10n.getString('forms-diagnostic-unknown', { id: diagnostic.id })

  if (diagnostic.field === undefined) return body
  return l10n.getString('forms-diagnostic-at-field', {
    field: parseFieldPath(diagnostic.field).join('/'),
    message: body,
  })
}
