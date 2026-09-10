/**
 * The schema-driven form engine.
 *
 * A module page hands {@link SchemaForm} three things — the module's JSON
 * Schema, the model the API returned, and a change handler — and gets back a
 * rendered instrument panel:
 *
 * ```tsx
 * import { SchemaForm, parseDiagnostics } from '@/forms'
 *
 * function HostsPage({ schema, initial }: { schema: unknown; initial: JsonValue }) {
 *   const [model, setModel] = useState(initial)
 *   const [diagnostics, setDiagnostics] = useState<readonly FormDiagnostic[]>([])
 *
 *   return (
 *     <SchemaForm
 *       schema={schema}
 *       value={model}
 *       onChange={setModel}
 *       diagnostics={diagnostics}
 *     />
 *   )
 * }
 * ```
 *
 * Three properties the page can rely on:
 *
 * 1. **Round-trip fidelity.** `onChange` hands back a model in which every
 *    branch the user did not edit is the *same object reference* that arrived,
 *    so re-serializing it cannot perturb a field — including one whose schema
 *    shape the engine does not understand, which is rendered read-only rather
 *    than dropped.
 * 2. **The server is the authority.** {@link validateModel} mirrors the
 *    schema's constraints for immediate feedback only. Always send the model to
 *    `validate` / `plan` / `apply` and render the diagnostics that come back.
 * 3. **Nothing vanishes.** A diagnostic whose field path names a rendered
 *    control appears on that control; one that does not appears at form level.
 */

export {
  collectFieldPaths,
  type DiagnosticMap,
  type DiagnosticSeverity,
  type DiagnosticSpan,
  EMPTY_DIAGNOSTIC_MAP,
  type FormDiagnostic,
  mapDiagnostics,
  parseDiagnostics,
  parseFieldPath,
} from './diagnostics'
export { FieldControl, FieldList, GroupedFields } from './FieldControl'
export { DEFAULT_HINTS, type FieldHints, type SecurityImpact, type UiGroup } from './hints'
export {
  getAtPath,
  isJsonArray,
  isJsonObject,
  type JsonObject,
  type JsonValue,
  type ModelPath,
  parseJsonValue,
  parsePath,
  pathKey,
  setAtPath,
} from './json'
export { SchemaForm, type SchemaFormProps } from './SchemaForm'
export {
  type Constraints,
  type Control,
  defaultObject,
  defaultValueForNode,
  type FieldNode,
  hasGroup,
  MAX_SCHEMA_DEPTH,
  type ParsedSchema,
  parseSchema,
  type UnsupportedReason,
} from './schema'
export {
  type FieldIssue,
  type FormatValidator,
  isIpAddress,
  registerFormat,
  validateModel,
} from './validate'
