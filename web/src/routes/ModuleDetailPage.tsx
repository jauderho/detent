/**
 * One module: what it is (`module-about-panel`), and the schema-driven form
 * that edits its candidate model (`module-configuration-panel`).
 *
 * The edit cycle is validate / plan / apply, all against the same in-memory
 * `model` — nothing is written to disk until an operator confirms an apply,
 * and that confirmation always carries `expected_hash` (docs/API.md,
 * "the hash-conflict guard"): the freshest digest this page has seen, so a
 * concurrent edit from elsewhere is refused with `409` rather than silently
 * overwritten.
 */

import { useLocalization } from '@fluent/react'
import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react'
import { Navigate, useParams } from 'react-router'
import { resolveApiError } from '@/api/messages'
import {
  type ApplyRequest,
  type ModuleDescriptor,
  type ModuleView,
  type PlanReport,
  useApplyModule,
  useModule,
  usePlanModule,
  useValidateModule,
} from '@/api/modules'
import { usePendingCommit } from '@/app/PendingCommit'
import { useWriteGate } from '@/auth/ScopeGate'
import { Banner } from '@/components/Banner'
import { Button, ButtonGroup } from '@/components/Button'
import { Label } from '@/components/Label'
import { Modal } from '@/components/Modal'
import { Panel } from '@/components/Panel'
import { Readout, Screen } from '@/components/Screen'
import { SelectField } from '@/components/SelectField'
import {
  defaultObject,
  type FormDiagnostic,
  type JsonValue,
  parseDiagnostics,
  parseSchema,
  SchemaForm,
} from '@/forms'
import { shortDigest } from '@/lib/format'
import { cn } from '@/lib/utils'
import { ROUTES } from './paths'
import { serviceActionCaption } from './serviceLabels'

const PAGE_STYLE = { paddingTop: 24, paddingBottom: 24 } as const

const TITLE_STYLE = {
  fontFamily: '"Archivo Variable", "Archivo", sans-serif',
  fontWeight: 700,
  fontSize: 18,
  letterSpacing: '-0.01em',
  marginBottom: 16,
} as const

const DIFF_STYLE = {
  margin: 0,
  color: 'var(--screen-blue)',
  fontSize: 12,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
} as const

type ServiceActionValue = ModuleDescriptor['services'][number]['actions'][number]

/** Where an apply confirm dialog got its `expected_hash` and target path from. */
type ApplyContext = {
  readonly hash: string | null
  readonly path: string
}

/**
 * `ModelRequest.model` and `ApplyRequest.model` are generated as
 * `Record<string, never>` — openapi-typescript's placeholder for "arbitrary
 * JSON object", since utoipa has no schema for one (schema.d.ts notes the
 * same limitation the other way round, on `ErrorBody.diagnostics`). The
 * candidate model this page actually holds is `JsonValue`, the form engine's
 * own type; this is the one bridge between the two.
 */
function modelBody(model: JsonValue): Record<string, never> {
  return model as unknown as Record<string, never>
}

/** The model to edit: what is on disk, or the schema's own defaults when there is none yet. */
function seedModel(view: ModuleView): JsonValue {
  return view.model ?? defaultObject(parseSchema(view.schema).fields)
}

/** The first configured unit name for a service binding, preferring systemd. */
function primaryUnit(service: ModuleDescriptor['services'][number]): string {
  return service.units.systemd[0] ?? service.units.openrc[0] ?? service.units.bsdrc[0] ?? ''
}

function FactRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:gap-2">
      <dt>
        <Label>{label}</Label>
      </dt>
      <dd>{children}</dd>
    </div>
  )
}

/** A bordered tag chip for the `.kicker` row — model · class · revision. */
function KickerTag({
  children,
  variant,
  className,
}: {
  children: ReactNode
  variant?: 'blue'
  className?: string
}) {
  return <span className={cn('tag', variant, className)}>{children}</span>
}

export function ModuleDetailPage() {
  const { id } = useParams()
  if (id === undefined) {
    return <Navigate to={ROUTES.modules} replace />
  }
  return <ModuleDetailView id={id} />
}

function ModuleDetailView({ id }: { id: string }) {
  const { l10n } = useLocalization()
  const query = useModule(id)
  const writeGate = useWriteGate()
  const pendingCommit = usePendingCommit()

  const [model, setModel] = useState<JsonValue | null>(null)
  const [diagnostics, setDiagnostics] = useState<readonly FormDiagnostic[]>([])
  const [validateClean, setValidateClean] = useState(false)
  const [mutationError, setMutationError] = useState<string | null>(null)
  const [appliedMessage, setAppliedMessage] = useState<{
    readonly path: string
    readonly created: boolean
  } | null>(null)
  const [planReport, setPlanReport] = useState<PlanReport | null>(null)
  const [planOpen, setPlanOpen] = useState(false)
  const [applyContext, setApplyContext] = useState<ApplyContext | null>(null)
  const [serviceAction, setServiceAction] = useState<ServiceActionValue | ''>('')

  // The control that opened the plan dialog, so closing the dialog can put
  // focus back on it. `Modal` cannot work this out for itself here: the button
  // disables itself while the plan request is in flight, which drops focus to
  // the body before the dialog ever opens, so there is nothing for the dialog
  // to have captured.
  const planTrigger = useRef<HTMLButtonElement | null>(null)

  const validate = useValidateModule(id)
  const plan = usePlanModule(id)
  const apply = useApplyModule(id)

  const viewData = query.data

  // Seeds once per module load; a refetch (e.g. after apply invalidates the
  // cache) must not clobber edits the operator has not asked to discard, so
  // this only fires while `model` is still the unset `null` it starts at.
  useEffect(() => {
    if (model !== null || viewData === undefined) return
    setModel(seedModel(viewData))
    setDiagnostics(parseDiagnostics(viewData.diagnostics))
  }, [viewData, model])

  const serviceOptions = useMemo<readonly ServiceActionValue[]>(() => {
    if (viewData === undefined) return []
    const seen = new Set<ServiceActionValue>()
    for (const service of viewData.descriptor.services) {
      for (const action of service.actions) seen.add(action)
    }
    return Array.from(seen)
  }, [viewData])

  const anyPending = validate.isPending || plan.isPending || apply.isPending

  function toServiceAction(value: string): ServiceActionValue | '' {
    return serviceOptions.find((option) => option === value) ?? ''
  }

  /**
   * Every banner on this panel reports the outcome of a call about a *specific*
   * model. The moment the operator edits a field, that model no longer exists,
   * so "passed every check" or "the change was written" is describing something
   * that is no longer on screen — the most misleading state this page can be
   * in, since it is the one that says it is safe to stop. Editing clears them.
   *
   * The diagnostics on the fields themselves are left alone: they are anchored
   * to field paths, the engine re-validates locally on every keystroke, and a
   * stale one is visibly attached to the value that produced it.
   */
  function onModelChange(next: JsonValue) {
    setModel(next)
    setValidateClean(false)
    setAppliedMessage(null)
    setMutationError(null)
  }

  function onValidate() {
    if (model === null) return
    setMutationError(null)
    setValidateClean(false)
    validate.mutate(
      { model: modelBody(model) },
      {
        onSuccess: (result) => {
          const parsed = parseDiagnostics(result)
          setDiagnostics(parsed)
          setValidateClean(parsed.length === 0)
        },
        onError: (error) => {
          setMutationError(resolveApiError(l10n, error.apiError))
        },
      },
    )
  }

  function onPlan() {
    if (model === null) return
    setMutationError(null)
    plan.mutate(
      { model: modelBody(model) },
      {
        onSuccess: (report) => {
          setPlanReport(report)
          setPlanOpen(true)
          setDiagnostics(parseDiagnostics(report.diagnostics))
        },
        onError: (error) => {
          setMutationError(resolveApiError(l10n, error.apiError))
        },
      },
    )
  }

  function onDiscard() {
    // Resetting to `null` re-triggers the seeding effect above, so this stays
    // the one place that knows how to build a fresh model from `view`.
    setModel(null)
    setDiagnostics([])
    setValidateClean(false)
    setAppliedMessage(null)
    setMutationError(null)
  }

  function openApplyFromMain() {
    if (viewData === undefined) return
    setServiceAction('')
    setApplyContext({
      hash: viewData.current_hash ?? null,
      path: viewData.descriptor.targets[0]?.path ?? '',
    })
  }

  /** Closes the plan dialog and returns focus to the control that opened it. */
  function closePlan() {
    setPlanOpen(false)
    planTrigger.current?.focus()
  }

  function openApplyFromPlan() {
    if (planReport === null) return
    setServiceAction('')
    setApplyContext({ hash: planReport.current_hash, path: planReport.path })
    setPlanOpen(false)
  }

  function closeApplyModal() {
    setApplyContext(null)
    setServiceAction('')
  }

  function onApplyConfirm() {
    if (model === null || applyContext === null) return
    setMutationError(null)
    const body: ApplyRequest = {
      model: modelBody(model),
      expected_hash: applyContext.hash,
      service_action: serviceAction === '' ? null : serviceAction,
    }
    apply.mutate(body, {
      onSuccess: (report) => {
        setApplyContext(null)
        setAppliedMessage({ path: report.path, created: report.created })
        if (report.commit !== null && report.commit !== undefined) {
          pendingCommit.arm(report.commit)
        }
      },
      onError: (error) => {
        setApplyContext(null)
        setMutationError(resolveApiError(l10n, error.apiError))
        if (error.apiError.kind === 'http' && error.apiError.diagnostics !== null) {
          setDiagnostics(parseDiagnostics(error.apiError.diagnostics))
        }
      },
    })
  }

  if (query.isPending) {
    return (
      <section className="wrap" style={PAGE_STYLE}>
        <h1 style={TITLE_STYLE}>{l10n.getString('page-module-detail-title', { module: id })}</h1>
        <p>{l10n.getString('state-loading')}</p>
      </section>
    )
  }

  if (query.isError) {
    return (
      <section className="wrap" style={PAGE_STYLE}>
        <h1 style={TITLE_STYLE}>{l10n.getString('page-module-detail-title', { module: id })}</h1>
        <Banner tone="amber">{resolveApiError(l10n, query.error.apiError)}</Banner>
      </section>
    )
  }

  const view = query.data
  const descriptor = view.descriptor

  return (
    <section className="wrap" style={PAGE_STYLE}>
      <h1 style={TITLE_STYLE}>{l10n.getString('page-module-detail-title', { module: id })}</h1>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel label={l10n.getString('module-about-panel')}>
          <dl className="flex flex-col gap-3">
            <FactRow label={l10n.getString('module-upstream-label')}>
              <span className="verbatim">{`${descriptor.upstream.project} ${descriptor.upstream.tracked_version}`}</span>
            </FactRow>
            <FactRow label={l10n.getString('module-targets-label')}>
              <ul className="verbatim flex flex-col gap-1">
                {descriptor.targets.map((target) => (
                  <li key={target.path}>{target.path}</li>
                ))}
              </ul>
            </FactRow>
            <FactRow label={l10n.getString('module-services-label')}>
              {descriptor.services.length === 0 ? (
                l10n.getString('modules-none')
              ) : (
                <ul className="flex flex-col gap-1">
                  {descriptor.services.map((service, index) => (
                    // biome-ignore lint/suspicious/noArrayIndexKey: a binding carries no stable id of its own
                    <li key={index}>{primaryUnit(service)}</li>
                  ))}
                </ul>
              )}
            </FactRow>
            <FactRow label={l10n.getString('module-current-hash-label')}>
              {view.current_hash === null || view.current_hash === undefined ? (
                l10n.getString('state-unknown')
              ) : (
                // A `Readout` lights its value with `--screen-blue`, which
                // only clears 4.5:1 against the never-themed screen fill — on
                // the chassis it is a contrast failure, which is how axe found
                // it. AESTHETIC_CONTRACT.md §4/§12: a lit value belongs on a
                // `Screen` or it is not a lit value.
                <Screen className="inline-block px-2 py-1">
                  <Readout value={shortDigest(view.current_hash)} />
                </Screen>
              )}
            </FactRow>
            {descriptor.security_notes.length === 0 ? null : (
              <FactRow label={l10n.getString('module-security-notes-label')}>
                <div className="flex flex-wrap gap-2">
                  {descriptor.security_notes.map((note) => (
                    <KickerTag key={note}>{note}</KickerTag>
                  ))}
                </div>
              </FactRow>
            )}
          </dl>
        </Panel>

        <Panel label={l10n.getString('module-configuration-panel')}>
          <div className="flex flex-col gap-3">
            {view.model === null || view.model === undefined ? (
              <Banner tone="blue">{l10n.getString('module-model-missing')}</Banner>
            ) : null}
            {validateClean ? (
              <Banner tone="blue">{l10n.getString('module-validate-clean')}</Banner>
            ) : null}
            {appliedMessage === null ? null : (
              <Banner tone="blue">
                {appliedMessage.created
                  ? l10n.getString('module-applied-created', { path: appliedMessage.path })
                  : l10n.getString('module-applied', { path: appliedMessage.path })}
              </Banner>
            )}
            {mutationError === null ? null : <Banner tone="amber">{mutationError}</Banner>}

            {model === null ? (
              <p>{l10n.getString('state-loading')}</p>
            ) : (
              <SchemaForm
                schema={view.schema}
                value={model}
                onChange={onModelChange}
                diagnostics={diagnostics}
              />
            )}

            <ButtonGroup label={l10n.getString('module-configuration-panel')}>
              <Button onClick={onValidate} disabled={anyPending || model === null}>
                {validate.isPending
                  ? l10n.getString('module-busy')
                  : l10n.getString('module-action-validate')}
              </Button>
              <Button ref={planTrigger} onClick={onPlan} disabled={anyPending || model === null}>
                {plan.isPending
                  ? l10n.getString('module-busy')
                  : l10n.getString('module-action-plan')}
              </Button>
              <Button
                variant="primary"
                onClick={openApplyFromMain}
                disabled={anyPending || model === null || !writeGate.canWrite}
                title={writeGate.reason}
              >
                {apply.isPending
                  ? l10n.getString('module-busy')
                  : l10n.getString('module-action-apply')}
              </Button>
              <Button onClick={onDiscard} disabled={anyPending || model === null}>
                {l10n.getString('module-action-discard')}
              </Button>
            </ButtonGroup>
          </div>
        </Panel>
      </div>

      <Modal
        open={planOpen}
        onClose={closePlan}
        title={l10n.getString('module-plan-title')}
        footer={
          <ButtonGroup>
            <Button
              variant="primary"
              onClick={openApplyFromPlan}
              disabled={!writeGate.canWrite}
              title={writeGate.reason}
            >
              {l10n.getString('module-plan-apply')}
            </Button>
            <Button onClick={closePlan}>{l10n.getString('module-cancel')}</Button>
          </ButtonGroup>
        }
      >
        {planReport === null ? null : !planReport.would_change ? (
          <Banner tone="blue">{l10n.getString('module-plan-no-change')}</Banner>
        ) : (
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label>{l10n.getString('module-plan-diff-label')}</Label>
              <Screen>
                <pre className="verbatim" style={DIFF_STYLE}>
                  {planReport.unified_diff}
                </pre>
              </Screen>
            </div>
            <div className="flex flex-col gap-2">
              <Label>{l10n.getString('module-plan-checks-label')}</Label>
              <ul className="flex flex-col gap-1">
                {planReport.checks.map((check) => (
                  <li key={check.program}>
                    <span className="verbatim">{check.program}</span> —{' '}
                    {check.passed
                      ? l10n.getString('module-plan-check-passed')
                      : l10n.getString('module-plan-check-failed')}
                    {check.exit_code === null || check.exit_code === undefined
                      ? null
                      : ` ${l10n.getString('module-plan-check-exit', { code: check.exit_code })}`}
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex flex-col gap-2">
              <Label>{l10n.getString('module-plan-services-label')}</Label>
              <ul className="flex flex-col gap-1">
                {planReport.affected_services.map((service) => (
                  <li className="verbatim" key={service.unit}>
                    {service.unit}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        open={applyContext !== null}
        onClose={closeApplyModal}
        title={l10n.getString('module-apply-title')}
        footer={
          <ButtonGroup>
            <Button
              variant="primary"
              onClick={onApplyConfirm}
              disabled={apply.isPending || !writeGate.canWrite}
              title={writeGate.reason}
            >
              {apply.isPending
                ? l10n.getString('module-busy')
                : l10n.getString('module-action-apply')}
            </Button>
            <Button onClick={closeApplyModal} disabled={apply.isPending}>
              {l10n.getString('module-apply-cancel')}
            </Button>
          </ButtonGroup>
        }
      >
        {applyContext === null ? null : (
          <div className="flex flex-col gap-3">
            <p>{l10n.getString('module-apply-body', { path: applyContext.path })}</p>
            {descriptor.commit_confirm ? (
              <Banner tone="amber">{l10n.getString('module-apply-commit-confirm')}</Banner>
            ) : null}
            {descriptor.services.length === 0 ? null : (
              <SelectField
                label={l10n.getString('module-apply-service-label')}
                value={serviceAction}
                onChange={(event) => {
                  setServiceAction(toServiceAction(event.target.value))
                }}
                options={[
                  { value: '', label: l10n.getString('module-apply-service-none') },
                  ...serviceOptions.map((action) => ({
                    value: action,
                    label: serviceActionCaption(l10n, action),
                  })),
                ]}
              />
            )}
          </div>
        )}
      </Modal>
    </section>
  )
}
