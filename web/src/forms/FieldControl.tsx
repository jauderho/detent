import { useLocalization } from '@fluent/react'
import { type ReactNode, useState } from 'react'
import { Button } from '@/components/Button'
import { FieldFrame, useFieldIds } from '@/components/FieldFrame'
import { Led } from '@/components/Led'
import { NumberField } from '@/components/NumberField'
import { Panel } from '@/components/Panel'
import { SelectField } from '@/components/SelectField'
import { SwitchField } from '@/components/SwitchField'
import { TextField } from '@/components/TextField'
import { TinyButton } from '@/components/TinyButton'
import { useFormContext } from './context'
import type { FormDiagnostic } from './diagnostics'
import type { FieldHints, UiGroup } from './hints'
import {
  appendItem,
  getAtPath,
  isJsonArray,
  isJsonObject,
  type JsonValue,
  type ModelPath,
  moveItem,
  pathKey,
  removeAt,
} from './json'
import { keyItems } from './keys'
import { joinLines, optionalMessage } from './l10n'
import { type Control, defaultObject, type FieldNode } from './schema'
import { TagList } from './TagList'

/**
 * Maps one {@link FieldNode} onto a control from `src/components/`.
 *
 * The mapping is: `enum` → `SelectField`, `boolean` → `SwitchField`,
 * `integer`/`number` → `NumberField`, `string` → `TextField`, `array` of
 * `string` → `TagList`, `array` of object → a row editor, nested object → a
 * `Panel` of fields.
 *
 * Two things fall through to {@link FallbackField}, and both fall through
 * *visibly*: a schema shape the walker could not map, and a model value whose
 * runtime type disagrees with the mapped control. Neither is dropped — a
 * dropped field would be erased from the file the next time the form is
 * applied, so the raw value is shown read-only instead.
 */

// ── chrome ───────────────────────────────────────────────────────────────────

type FieldMessages = {
  readonly description: string | undefined
  readonly error: string | undefined
  readonly tooltip: string | undefined
}

/**
 * Composes the three text slots of a field from four sources: the schema's own
 * description, the `x-detent` recommendation, the client-side issues, and the
 * server diagnostics addressed at this path. Errors win the error line;
 * warnings and recommendations join the description line.
 */
function useFieldMessages(node: FieldNode, path: ModelPath): FieldMessages {
  const { l10n } = useLocalization()
  const { issues, diagnostics } = useFormContext()
  const key = pathKey(path)

  const render = (diagnostic: FormDiagnostic): string =>
    optionalMessage(l10n, diagnostic.id, diagnostic.args) ??
    l10n.getString('forms-diagnostic-unknown', { id: diagnostic.id })

  const attached = diagnostics.byPath.get(key) ?? []
  const errors = [
    ...(issues.get(key) ?? []).map((issue) => l10n.getString(issue.messageId, issue.args)),
    ...attached.filter((entry) => entry.severity === 'error').map(render),
  ]
  const notes = attached.filter((entry) => entry.severity !== 'error').map(render)

  return {
    tooltip: optionalMessage(l10n, node.hints.tooltipId),
    description: joinLines([
      node.description,
      optionalMessage(l10n, node.hints.recommendationId),
      ...notes,
    ]),
    error: errors.length > 0 ? errors.join(' · ') : undefined,
  }
}

/**
 * The two hint states the contract requires to be visible: a high security
 * impact in either group, and a deprecated option. Both are `.tag` chips.
 *
 * The security chip carries an amber LED rather than amber type or an amber
 * border: amber type on the cream chassis misses the §11 4.5:1 floor, a lit LED
 * glows in both themes (§6 / §11), and this is the same tone-to-LED mapping
 * `Banner` already uses for "needs attention". The chip's own border stays
 * `--line-2` because `.tag` is unlayered CSS and a utility cannot override it.
 */
function FieldBadges({ hints }: { hints: FieldHints }) {
  const { l10n } = useLocalization()
  const badges: ReactNode[] = []

  if (hints.securityImpact === 'high') {
    badges.push(
      <span key="security" className="tag inline-flex items-center gap-2">
        <Led variant="rec" />
        {l10n.getString('forms-badge-security-high')}
      </span>,
    )
  }
  if (hints.deprecatedIn !== undefined) {
    badges.push(
      <span key="deprecated" className="tag">
        {l10n.getString('forms-badge-deprecated', { version: hints.deprecatedIn })}
      </span>,
    )
  }

  if (badges.length === 0) return null
  return <div className="flex flex-wrap items-center gap-2">{badges}</div>
}

/** The description / error pair a hand-rolled container renders for itself. */
function ContainerNotes({ messages }: { messages: FieldMessages }) {
  return (
    <>
      {messages.description === undefined ? null : (
        <p className="field-desc">{messages.description}</p>
      )}
      {messages.error === undefined ? null : (
        <p className="field-error">
          <Led variant="rec" />
          <span>{messages.error}</span>
        </p>
      )}
    </>
  )
}

// ── fallback ─────────────────────────────────────────────────────────────────

const FALLBACK_MAX_ROWS = 10

/**
 * The read-only escape hatch. Shows the raw JSON of a value the form cannot
 * edit, clearly captioned, and never writes to the model — so the value
 * survives the round trip untouched.
 */
export function FallbackField({
  node,
  value,
  messages,
}: {
  node: FieldNode
  value: JsonValue | undefined
  messages: FieldMessages
}) {
  const { l10n } = useLocalization()
  const text = value === undefined ? '' : JSON.stringify(value, null, 2)
  const description = joinLines([l10n.getString('forms-unsupported-note'), messages.description])
  const ids = useFieldIds({ hasDescription: description !== undefined, hasError: false })

  return (
    <FieldFrame ids={ids} label={node.name} description={description} tooltip={messages.tooltip}>
      <textarea
        id={ids.controlId}
        className="field-control"
        readOnly
        rows={Math.min(FALLBACK_MAX_ROWS, text.split('\n').length)}
        value={text}
        aria-describedby={ids.describedBy}
      />
    </FieldFrame>
  )
}

// ── scalar controls ──────────────────────────────────────────────────────────

type ControlProps = {
  node: FieldNode
  path: ModelPath
  value: JsonValue | undefined
  messages: FieldMessages
}

/**
 * `minLength` / `maxLength` are mirrored onto the DOM as well as checked, so
 * assistive tech reads the same limits the validator enforces. `pattern` is
 * deliberately *not* mirrored: the schema's expression is a Rust `regex`, whose
 * dialect is not JavaScript's, and a browser that disagreed would contradict
 * the message the validator shows.
 */
function TextControl({ node, path, value, messages }: ControlProps) {
  const { setValue } = useFormContext()
  const { nullable, required, minLength, maxLength } = node.constraints

  return (
    <TextField
      label={node.name}
      description={messages.description}
      error={messages.error}
      tooltip={messages.tooltip}
      required={required}
      minLength={minLength}
      maxLength={maxLength}
      value={typeof value === 'string' ? value : ''}
      onChange={(event) => {
        const next = event.target.value
        setValue(path, nullable && next.length === 0 ? null : next)
      }}
    />
  )
}

/**
 * Keeps the typed text while it is not a number, so backspacing through `10`
 * cannot silently write `1` and then nothing. The model is only written when
 * the draft parses; the draft is dropped on blur so the control resyncs.
 */
function NumberControl({ node, path, value, messages }: ControlProps) {
  const { setValue } = useFormContext()
  const [draft, setDraft] = useState<string | undefined>(undefined)
  const { minimum, maximum, nullable } = node.constraints

  return (
    <NumberField
      label={node.name}
      description={messages.description}
      error={messages.error}
      tooltip={messages.tooltip}
      required={node.constraints.required}
      min={minimum}
      max={maximum}
      value={draft ?? (typeof value === 'number' ? String(value) : '')}
      onChange={(event) => {
        const next = event.target.value
        setDraft(next)
        if (next.length === 0) {
          if (nullable) setValue(path, null)
          return
        }
        const parsed = Number(next)
        if (Number.isFinite(parsed)) setValue(path, parsed)
      }}
      onBlur={() => {
        setDraft(undefined)
      }}
    />
  )
}

function SwitchControl({ node, path, value, messages }: ControlProps) {
  const { setValue } = useFormContext()

  return (
    <SwitchField
      label={node.name}
      description={messages.description}
      error={messages.error}
      tooltip={messages.tooltip}
      checked={value === true}
      onCheckedChange={(checked) => {
        setValue(path, checked)
      }}
    />
  )
}

function SelectControl({
  node,
  path,
  value,
  messages,
  options,
}: ControlProps & { options: readonly string[] }) {
  const { l10n } = useLocalization()
  const { setValue } = useFormContext()
  const { nullable } = node.constraints
  const current = typeof value === 'string' ? value : ''
  const showEmpty = nullable || current.length === 0

  const entries = [
    ...(showEmpty ? [{ value: '', label: l10n.getString('forms-option-none') }] : []),
    ...options.map((option) => ({ value: option, label: option })),
  ]

  return (
    <SelectField
      label={node.name}
      description={messages.description}
      error={messages.error}
      tooltip={messages.tooltip}
      required={node.constraints.required}
      options={entries}
      value={current}
      onChange={(event) => {
        const next = event.target.value
        setValue(path, next.length === 0 && nullable ? null : next)
      }}
    />
  )
}

// ── container controls ───────────────────────────────────────────────────────

function ObjectControl({
  node,
  fields,
  basePath,
  messages,
}: {
  node: FieldNode
  fields: readonly FieldNode[]
  basePath: ModelPath
  messages: FieldMessages
}) {
  return (
    <Panel label={node.name}>
      <div className="flex flex-col gap-3">
        <GroupedFields fields={fields} basePath={basePath} />
        <ContainerNotes messages={messages} />
      </div>
    </Panel>
  )
}

/**
 * The row editor for an `array` of object — `entries` in the hosts module.
 *
 * Row order is the file's order, so add appends, remove closes the gap, and
 * move swaps exactly one neighbour; all three go through the `json.ts` helpers,
 * which rebuild only the array spine and leave every row object
 * reference-identical. The controls are plain buttons, so reordering is fully
 * keyboard-operable.
 */
function RowsControl({
  node,
  path,
  fields,
  rows,
  messages,
}: {
  node: FieldNode
  path: ModelPath
  fields: readonly FieldNode[]
  rows: readonly JsonValue[]
  messages: FieldMessages
}) {
  const { l10n } = useLocalization()
  const { updateArray } = useFormContext()
  const keyed = keyItems(rows)
  const last = rows.length - 1

  return (
    <Panel
      label={node.name}
      action={
        <Button
          aria-label={l10n.getString('forms-row-add', { field: node.name })}
          onClick={() => {
            updateArray(path, (items) => appendItem(items, defaultObject(fields)))
          }}
        >
          {l10n.getString('forms-item-add-caption')}
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        {rows.length === 0 ? (
          <p className="field-desc">{l10n.getString('forms-list-empty')}</p>
        ) : null}

        <ol aria-label={node.name} className="flex flex-col gap-3">
          {keyed.map((row) => (
            <li key={row.key} className="flex flex-col gap-3 border border-[var(--line)] p-3">
              <div className="flex items-center justify-between gap-3">
                <span className="lbl">
                  {l10n.getString('forms-row-label', { index: row.index + 1 })}
                </span>
                <div className="flex items-center gap-2">
                  <TinyButton
                    aria-label={l10n.getString('forms-row-move-up', {
                      field: node.name,
                      index: row.index + 1,
                    })}
                    disabled={row.index === 0}
                    onClick={() => {
                      updateArray(path, (items) => moveItem(items, row.index, row.index - 1))
                    }}
                  >
                    {l10n.getString('forms-item-move-up-caption')}
                  </TinyButton>
                  <TinyButton
                    aria-label={l10n.getString('forms-row-move-down', {
                      field: node.name,
                      index: row.index + 1,
                    })}
                    disabled={row.index === last}
                    onClick={() => {
                      updateArray(path, (items) => moveItem(items, row.index, row.index + 1))
                    }}
                  >
                    {l10n.getString('forms-item-move-down-caption')}
                  </TinyButton>
                  <TinyButton
                    aria-label={l10n.getString('forms-row-remove', {
                      field: node.name,
                      index: row.index + 1,
                    })}
                    onClick={() => {
                      updateArray(path, (items) => removeAt(items, row.index))
                    }}
                  >
                    {l10n.getString('forms-item-remove-caption')}
                  </TinyButton>
                </div>
              </div>
              <GroupedFields fields={fields} basePath={[...path, String(row.index)]} />
            </li>
          ))}
        </ol>

        <ContainerNotes messages={messages} />
      </div>
    </Panel>
  )
}

// ── dispatch ─────────────────────────────────────────────────────────────────

/** Whether the model value can be edited by the control the schema chose. */
function matchesControl(control: Control, value: JsonValue | undefined): boolean {
  if (value === undefined || value === null) return control.type !== 'unsupported'

  switch (control.type) {
    case 'text':
    case 'select':
      return typeof value === 'string'
    case 'number':
      return typeof value === 'number'
    case 'switch':
      return typeof value === 'boolean'
    case 'tags':
      return isJsonArray(value) && value.every((item) => typeof item === 'string')
    case 'rows':
      return isJsonArray(value) && value.every(isJsonObject)
    case 'object':
      return isJsonObject(value)
    case 'unsupported':
      return false
  }
}

export function FieldControl({ node, basePath }: { node: FieldNode; basePath: ModelPath }) {
  const { model, updateArray } = useFormContext()
  const path: ModelPath = [...basePath, ...node.path]
  const value = getAtPath(model, path)
  const messages = useFieldMessages(node, path)
  const control = node.control

  if (!matchesControl(control, value)) {
    return (
      <FieldSlot hints={node.hints}>
        <FallbackField node={node} value={value} messages={messages} />
      </FieldSlot>
    )
  }

  const props: ControlProps = { node, path, value, messages }

  return (
    <FieldSlot hints={node.hints}>
      {control.type === 'text' ? <TextControl {...props} /> : null}
      {control.type === 'number' ? <NumberControl {...props} /> : null}
      {control.type === 'switch' ? <SwitchControl {...props} /> : null}
      {control.type === 'select' ? <SelectControl {...props} options={control.options} /> : null}
      {control.type === 'tags' ? (
        <TagList
          label={node.name}
          items={isJsonArray(value) ? value.filter((item) => typeof item === 'string') : []}
          description={joinLines([messages.description, messages.tooltip])}
          error={messages.error}
          onChange={(next) => {
            updateArray(path, () => next)
          }}
        />
      ) : null}
      {control.type === 'object' ? (
        <ObjectControl
          node={node}
          fields={control.fields}
          basePath={basePath}
          messages={{
            ...messages,
            description: joinLines([messages.description, messages.tooltip]),
          }}
        />
      ) : null}
      {control.type === 'rows' ? (
        <RowsControl
          node={node}
          path={path}
          fields={control.fields}
          rows={isJsonArray(value) ? value : []}
          messages={{
            ...messages,
            description: joinLines([messages.description, messages.tooltip]),
          }}
        />
      ) : null}
    </FieldSlot>
  )
}

function FieldSlot({ hints, children }: { hints: FieldHints; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <FieldBadges hints={hints} />
      {children}
    </div>
  )
}

/** Renders `fields` of one disclosure group, in schema order. */
export function FieldList({
  fields,
  basePath,
  group,
}: {
  fields: readonly FieldNode[]
  basePath: ModelPath
  group: UiGroup
}) {
  const selected = fields.filter((field) => field.hints.group === group)
  if (selected.length === 0) return null

  return (
    <div className="flex flex-col gap-3">
      {selected.map((field) => (
        <FieldControl key={pathKey(field.path)} node={field} basePath={basePath} />
      ))}
    </div>
  )
}

/**
 * Basic fields, then advanced ones when the form-level disclosure is open. Used
 * inside a row or a nested object, where the group split still applies but the
 * disclosure control itself lives at the top of the form.
 */
export function GroupedFields({
  fields,
  basePath,
}: {
  fields: readonly FieldNode[]
  basePath: ModelPath
}) {
  const { showAdvanced } = useFormContext()

  return (
    <>
      <FieldList fields={fields} basePath={basePath} group="basic" />
      {showAdvanced ? <FieldList fields={fields} basePath={basePath} group="advanced" /> : null}
    </>
  )
}
