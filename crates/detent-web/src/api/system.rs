//! `/api/v1/system/profile`, `/api/v1/system/cert` (`GET` for status; `POST
//! .../renew` asks the ACME client to renew now), `/api/v1/system/update`
//! (`GET` for status, `POST` to install), and `/api/v1/audit`: host,
//! certificate, update, and history views. Only the two `POST`s mutate.

use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use detent_core::diag::MessageId;
use detent_ops::Operation;
use detent_ops::audit::{AuditQuery, AuditRecord, AuditResult};
use detent_ops::report::{CertReport, HostReport};
use detent_update::update::CheckReport;
use serde::{Deserialize, Serialize};

use crate::auth::audit::{AuthEvent, AuthRecord};
use crate::auth::extract::{Caller, WriteCaller};
use crate::error::ApiError;
use crate::state::{AppState, CertRenewer};

use super::{authorize, bad_request, json_rejection, query_rejection, unexpected_outcome};
use detent_ops::OpOutcome;

/// `GET /api/v1/system/profile`.
pub const PROFILE_PATH: &str = "/api/v1/system/profile";
/// `GET /api/v1/system/cert`.
pub const CERT_PATH: &str = "/api/v1/system/cert";
/// `POST /api/v1/system/cert/renew`.
pub const CERT_RENEW_PATH: &str = "/api/v1/system/cert/renew";
/// `GET /api/v1/system/update`.
pub const UPDATE_PATH: &str = "/api/v1/system/update";
/// `GET /api/v1/audit`.
pub const AUDIT_PATH: &str = "/api/v1/audit";

/// Longest `module` or `who` filter accepted in the audit query string.
pub const MAX_FILTER_LEN: usize = 128;

/// Most records `?limit=` may ask for in one answer.
pub const MAX_AUDIT_LIMIT: usize = 1000;

/// Fluent id of a renewal request when no ACME client runs
/// (`tls.bootstrap` is not `acme`).
pub const RENEW_NOT_ACME_ID: &str = "web-cert-renew-not-acme";

/// Fluent id of a renewal request that did not reach the ACME client.
pub const RENEW_UNAVAILABLE_ID: &str = "web-cert-renew-unavailable";

/// Fluent id of `GET /api/v1/system/update` when no stamp exists: the
/// `detent update --check` has not run (or an install removed its
/// stamp). The confined worker has no network (ADR-015), so it never checks
/// by itself.
pub const UPDATE_NOT_CHECKED_ID: &str = "web-update-not-checked";

/// This module's routes.
#[must_use]
pub fn table() -> Vec<crate::auth::routes::Route> {
    use crate::auth::routes::Route;
    use axum::http::Method;
    vec![
        Route {
            method: Method::GET,
            path: PROFILE_PATH,
            mutating: false,
        },
        Route {
            method: Method::GET,
            path: CERT_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: CERT_RENEW_PATH,
            mutating: true,
        },
        Route {
            method: Method::GET,
            path: UPDATE_PATH,
            mutating: false,
        },
        Route {
            method: Method::POST,
            path: UPDATE_PATH,
            mutating: true,
        },
        Route {
            method: Method::GET,
            path: AUDIT_PATH,
            mutating: false,
        },
    ]
}

/// This module's router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(PROFILE_PATH, get(profile))
        .route(CERT_PATH, get(cert))
        .route(CERT_RENEW_PATH, post(renew_cert))
        .route(UPDATE_PATH, get(update).post(apply_update))
        .route(AUDIT_PATH, get(audit))
}

/// `GET /api/v1/system/cert`.
#[cfg_attr(test, utoipa::path(
    get,
    path = CERT_PATH,
    tag = "system",
    responses((status = 200, description = "Serving certificate status", body = CertReport)),
))]
pub(super) async fn cert(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<CertReport>, ApiError> {
    // Gated against this operation's own identity, not `HostProfile`'s: the
    // two are separate entries in the policy and in the audit log, so a
    // future policy that distinguishes them must see the right one here.
    //
    // No `Operation` crosses to the engine thread — this reads the live
    // resolver `AppState` already holds, the same `Arc` handshakes answer
    // from — so nothing is audited on success, exactly as every other
    // read-only operation behaves (PLAN §2.5).
    authorize(&state, &caller, &Operation::CertStatus)?;
    Ok(Json(cert_report(&state)))
}

/// `POST /api/v1/system/cert/renew`.
///
/// Asks the ACME client to renew the served certificate now, also when it
/// is not due. The request goes to the acme process over its channel
/// (ADR-015) and returns before the renewal starts: `202` means the request
/// was sent, not that a certificate was issued. `GET /api/v1/system/cert`
/// shows the new certificate once the worker installs it. Every answer
/// after authorization is audited (`cert_renew_requested` in the auth log),
/// because the operations engine cannot answer `CertRenew`.
#[cfg_attr(test, utoipa::path(
    post,
    path = CERT_RENEW_PATH,
    tag = "system",
    responses(
        (status = 202, description = "The ACME client was asked to renew now", body = RenewRequested),
        (status = 409, description = "No ACME client runs: `tls.bootstrap` is not `acme`", body = crate::error::ErrorBody),
        (status = 503, description = "The request did not reach the ACME client", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn renew_cert(
    State(state): State<AppState>,
    caller: WriteCaller,
) -> Result<(StatusCode, Json<RenewRequested>), ApiError> {
    let caller = caller.caller();
    authorize(&state, caller, &Operation::CertRenew)?;
    let answer = request_renewal(state.cert_renewer.as_deref());
    let record = AuthRecord::new(
        AuthEvent::CertRenewRequested,
        caller.identity().subject.clone(),
        if answer.is_ok() {
            AuditResult::Ok
        } else {
            AuditResult::Error
        },
    )
    .with_kind(caller.identity().kind);
    state.auth.record(&match &answer {
        Ok(()) => record,
        Err(error) => record.with_detail(error.message_id()),
    });
    answer.map(|()| {
        (
            StatusCode::ACCEPTED,
            Json(RenewRequested { requested: true }),
        )
    })
}

/// Send the renewal request through `renewer`.
///
/// # Errors
///
/// `409` [`RENEW_NOT_ACME_ID`] without a renewer, `503`
/// [`RENEW_UNAVAILABLE_ID`] when the request did not reach the ACME client.
fn request_renewal(renewer: Option<&dyn CertRenewer>) -> Result<(), ApiError> {
    let renewer = renewer
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, MessageId::new(RENEW_NOT_ACME_ID)))?;
    renewer.renew_now().map_err(|reason| {
        tracing::warn!(%reason, "the renewal request did not reach the acme process");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            MessageId::new(RENEW_UNAVAILABLE_ID),
        )
    })
}

/// Answer to `POST /api/v1/system/cert/renew`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct RenewRequested {
    /// Always `true`: the ACME client got the request.
    pub requested: bool,
}

/// The certificate report for one DER leaf, shared by the HTTP handler and
/// the `detent cert status` shell view (which holds a pair, not an
/// `AppState`). Everything the shell prints comes from here; nothing is
/// copied.
#[must_use]
pub fn cert_report_for_der(der: &[u8]) -> CertReport {
    use time::OffsetDateTime;
    let fingerprint = crate::tls::fingerprint(der);
    let (not_after_unix, lifetime_used_percent, renewal_due, expiry_warning) =
        match crate::tls::validity_unix(der) {
            Some((not_before, not_after)) => {
                let now = OffsetDateTime::now_utc().unix_timestamp();
                // `not_after > not_before` is checked first, so the subtraction
                // cannot underflow; `saturating_*` on the rest keeps the percent
                // inside 0-100 even across clock skew.
                #[allow(clippy::arithmetic_side_effects)]
                let pct = if not_after > not_before {
                    let elapsed = now.saturating_sub(not_before).max(0);
                    let total = not_after - not_before;
                    u8::try_from((i128::from(elapsed) * 100 / i128::from(total)).clamp(0, 100)).ok()
                } else {
                    None
                };
                let due = crate::tls::renewal_due_at(not_before, not_after, now);
                let warning = detent_ops::warning_for_percent(pct);
                (Some(not_after), pct, Some(due), warning)
            }
            None => (None, None, None, None),
        };
    CertReport {
        fingerprint,
        not_after_unix,
        lifetime_used_percent,
        renewal_due,
        expiry_warning,
    }
}

/// `not_after_unix` as RFC 3339 UTC (`None` stays `None`). The shell view
/// formats here because the CLI crate has no clock dependency of its own.
#[must_use]
pub fn not_after_rfc3339(not_after_unix: Option<i64>) -> Option<String> {
    let at = time::OffsetDateTime::from_unix_timestamp(not_after_unix?).ok()?;
    at.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// The certificate answer, pulled out of [`cert`] so tests need no caller.
pub(super) fn cert_report(state: &AppState) -> CertReport {
    let current = state.cert_store.current();
    cert_report_for_der(current.cert.first().map_or(&[], |c| c.as_ref()))
}
/// `GET /api/v1/system/update`.
///
/// The update status the web layer answers directly, from the stamp
/// `detent update --check` (run as root, for example from a timer) writes to
/// `<state_root>/update/check.json`. The confined worker has no network
/// (ADR-015), so this never reaches the release feed; with no stamp it
/// answers `404` ([`UPDATE_NOT_CHECKED_ID`]) at once. `current` is the
/// running version and `update_available` is the stamp's offer only while
/// its tag is newer than that version, so a stamp that is older than an
/// install does not offer the installed release. Read-only — **installing**
/// an update is the `write`-scoped, CSRF-checked `POST` on this same path,
/// answered by [`apply_update`]; nothing here installs anything.
#[cfg_attr(test, utoipa::path(
    get,
    path = UPDATE_PATH,
    tag = "system",
    responses(
        (status = 200, description = "The update status from the last `detent update --check`", body = UpdateReport),
        (status = 404, description = "`detent update --check` has not run yet", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn update(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<UpdateReport>, ApiError> {
    // Gated against this operation's own identity, not `HostProfile`'s: the
    // engine cannot answer an update status (the stamp lives in
    // `detent-update`), but the policy decision and the audit label for a
    // refusal must still be this endpoint's. No engine call happens, and a
    // read-only operation writes no audit record on success (PLAN §2.5).
    authorize(&state, &caller, &Operation::UpdateStatus)?;
    let cached = detent_update::update::read_cached(&state.update_stamp());
    let bad = detent_update::update::read_bad(&state.bad_stamp());
    status_from_stamp(cached.map(|cached| cached.report), &bad, RUNNING_VERSION).map(Json)
}

/// The version of this build, which is the version of the running binary
/// (a release is refused unless its tag equals the crate version).
const RUNNING_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The answer for `stamp`, pulled out of [`update`] so tests need no caller.
///
/// # Errors
///
/// `404` [`UPDATE_NOT_CHECKED_ID`] without a stamp.
fn status_from_stamp(
    stamp: Option<CheckReport>,
    bad: &[String],
    running: &str,
) -> Result<UpdateReport, ApiError> {
    let stamp = stamp.ok_or_else(|| {
        ApiError::new(StatusCode::NOT_FOUND, MessageId::new(UPDATE_NOT_CHECKED_ID))
    })?;
    let running_version = semver::Version::parse(running).ok();
    let offered_is_newer = stamp
        .tag
        .as_deref()
        .and_then(|tag| semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag)).ok())
        .zip(running_version)
        .is_some_and(|(offered, running)| offered > running);
    let rejected = stamp
        .tag
        .as_deref()
        .is_some_and(|tag| bad.iter().any(|b| b == tag));
    Ok(UpdateReport {
        update_available: stamp.update_available && offered_is_newer && !rejected,
        current: running.to_owned(),
        tag: stamp.tag,
        published: stamp.published,
        security: stamp.security,
    })
}
/// `POST /api/v1/system/update`.
///
/// Starts installing the named release in the background: the monitor asks
/// the runner to run `detent update --tag <version>` in the transient
/// systemd unit `detent-update`, which downloads and verifies the release,
/// swaps it in, restarts the service, and rolls back if the restarted
/// service is not healthy. `202` means the unit runs, not that the release
/// is installed; `GET` shows the running version afterwards. `400`
/// (`ops-update-tag-invalid`) when the version is not a release tag; `409`
/// (`ops-update-not-newer`) when it is not newer than the running version,
/// (`ops-update-running`) while an update runs; `500` (`ops-unsupported`)
/// on a host without systemd.
#[cfg_attr(test, utoipa::path(
    post,
    path = UPDATE_PATH,
    tag = "system",
    request_body = UpdateApplyRequest,
    responses(
        (status = 202, description = "The update started in the background", body = UpdateStartedView),
        (status = 400, description = "The version is not a release tag", body = crate::error::ErrorBody),
        (status = 409, description = "The release is not newer than the running version, or an update is already running", body = crate::error::ErrorBody),
        (status = 500, description = "The update could not be started on this host", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn apply_update(
    State(state): State<AppState>,
    caller: WriteCaller,
    body: Result<Json<UpdateApplyRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<UpdateStartedView>), ApiError> {
    let Json(request) = body.map_err(json_rejection)?;
    let op = Operation::UpdateApply {
        version: request.version,
    };
    authorize(&state, caller.caller(), &op)?;
    let outcome = state
        .engine
        .execute(
            op,
            caller.caller().identity().clone(),
            caller.caller().authz(),
        )
        .await?;
    render_started(outcome)
}

/// The body of `POST /api/v1/system/update`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct UpdateApplyRequest {
    /// The update version to install, e.g. `v1.2.3`.
    pub version: String,
}

/// Answer to `UpdateApply`: the update started; it says nothing about its
/// outcome.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct UpdateStartedView {
    /// The version being installed.
    pub version: String,
}

/// The `OpOutcome::UpdateStarted` branch, pulled out of [`apply_update`] so
/// the mismatch arm can be exercised with a synthetic outcome.
fn render_started(outcome: OpOutcome) -> Result<(StatusCode, Json<UpdateStartedView>), ApiError> {
    match outcome {
        OpOutcome::UpdateStarted { version } => {
            Ok((StatusCode::ACCEPTED, Json(UpdateStartedView { version })))
        }
        _ => Err(unexpected_outcome()),
    }
}

/// The answer body of `GET /api/v1/system/update`.
///
/// A mirror of [`CheckReport`], not a re-export: `detent-update` has no
/// `utoipa` dependency by design (PLAN §2.1 keeps the update crate
/// front-end agnostic), so this is the thin mirror that documents the schema,
/// the same move [`super::ApiServiceCommand`] makes for `ServiceCommand`.
/// Field-for-field identical and converted, never copied by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct UpdateReport {
    /// Whether a qualifying release exists.
    pub update_available: bool,
    /// The running version.
    pub current: String,
    /// The qualifying tag, when one exists.
    pub tag: Option<String>,
    /// When the release was published, RFC 3339.
    pub published: Option<String>,
    /// Whether it bypassed the age gate via `detent-security: true`.
    pub security: bool,
}

impl From<CheckReport> for UpdateReport {
    fn from(report: CheckReport) -> Self {
        Self {
            update_available: report.update_available,
            current: report.current,
            tag: report.tag,
            published: report.published,
            security: report.security,
        }
    }
}

/// The query string of `GET /api/v1/audit`.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(test, derive(utoipa::IntoParams))]
#[serde(default, deny_unknown_fields)]
#[cfg_attr(test, into_params(parameter_in = Query))]
pub struct AuditQueryParams {
    /// Only records about this module. At most [`MAX_FILTER_LEN`] bytes.
    pub module: Option<String>,
    /// Only records from this subject. At most [`MAX_FILTER_LEN`] bytes.
    pub who: Option<String>,
    /// At most this many records, newest first, capped at
    /// [`MAX_AUDIT_LIMIT`].
    pub limit: Option<usize>,
}

impl AuditQueryParams {
    /// Whether every field is inside its bound.
    fn within_limits(&self) -> bool {
        self.module
            .as_ref()
            .is_none_or(|m| m.len() <= MAX_FILTER_LEN)
            && self.who.as_ref().is_none_or(|w| w.len() <= MAX_FILTER_LEN)
            && self.limit.is_none_or(|limit| limit <= MAX_AUDIT_LIMIT)
    }
}

impl From<AuditQueryParams> for AuditQuery {
    fn from(params: AuditQueryParams) -> Self {
        Self {
            module: params.module,
            who: params.who,
            limit: params.limit,
        }
    }
}

/// `GET /api/v1/system/profile`.
#[cfg_attr(test, utoipa::path(
    get,
    path = PROFILE_PATH,
    tag = "system",
    responses((status = 200, description = "What was detected about this host", body = HostReport)),
))]
pub(super) async fn profile(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Box<HostReport>>, ApiError> {
    let op = Operation::HostProfile;
    authorize(&state, &caller, &op)?;
    let outcome = state
        .engine
        .execute(op, caller.identity().clone(), caller.authz())
        .await?;
    render_host(outcome)
}

/// The `OpOutcome::Host` branch, pulled out of [`profile`] so the mismatch
/// arm can be exercised with a synthetic outcome.
fn render_host(outcome: OpOutcome) -> Result<Json<Box<HostReport>>, ApiError> {
    match outcome {
        OpOutcome::Host(report) => Ok(Json(report)),
        _ => Err(unexpected_outcome()),
    }
}

/// `GET /api/v1/audit`.
#[cfg_attr(test, utoipa::path(
    get,
    path = AUDIT_PATH,
    tag = "system",
    params(AuditQueryParams),
    responses((status = 200, description = "Matching audit records, newest first", body = Vec<AuditRecord>)),
))]
pub(super) async fn audit(
    State(state): State<AppState>,
    caller: Caller,
    query: Result<Query<AuditQueryParams>, QueryRejection>,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    let Query(params) = query.map_err(query_rejection)?;
    if !params.within_limits() {
        return Err(bad_request());
    }
    let op = Operation::AuditQuery(params.into());
    authorize(&state, &caller, &op)?;
    let outcome = state
        .engine
        .execute(op, caller.identity().clone(), caller.authz())
        .await?;
    render_audit(outcome)
}

/// The `OpOutcome::Audit` branch, pulled out of [`audit`] so the mismatch arm
/// can be exercised with a synthetic outcome.
fn render_audit(outcome: OpOutcome) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    match outcome {
        OpOutcome::Audit(records) => Ok(Json(records)),
        _ => Err(unexpected_outcome()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuditQueryParams, MAX_AUDIT_LIMIT, MAX_FILTER_LEN, UPDATE_NOT_CHECKED_ID, UpdateReport,
        UpdateStartedView, render_audit, render_host, render_started, status_from_stamp,
    };
    use detent_core::descriptor::HostProfile;
    use detent_ops::OpOutcome;
    use detent_ops::audit::AuditQuery;
    use detent_ops::report::HostReport;
    use detent_platform::privsep::proto::CommitId;
    use detent_update::update::CheckReport;

    type R = Result<(), Box<dyn std::error::Error>>;

    const CATALOGUE: &str = include_str!("../../../../locales/en-US/core.ftl");

    /// An outcome no handler in this file expects, for the mismatch arm.
    fn wrong_outcome() -> OpOutcome {
        OpOutcome::CommitConfirmed {
            commit_id: CommitId(0),
        }
    }

    #[test]
    fn render_host_maps_the_matching_outcome_and_rejects_any_other() {
        let report = HostReport {
            profile: HostProfile::default(),
            distro_id: None,
            distro_version_id: None,
            network_backend: "unknown",
            resolver_backend: "unknown",
            notes: Vec::new(),
        };
        assert!(render_host(OpOutcome::Host(Box::new(report))).is_ok());
        assert!(render_host(wrong_outcome()).is_err());
    }

    #[test]
    fn render_audit_maps_the_matching_outcome_and_rejects_any_other() {
        assert!(render_audit(OpOutcome::Audit(Vec::new())).is_ok());
        assert!(render_audit(wrong_outcome()).is_err());
    }

    #[test]
    fn query_params_are_bounded() {
        let within = AuditQueryParams {
            module: Some("hosts".to_owned()),
            who: Some("alice".to_owned()),
            limit: Some(10),
        };
        assert_eq!(
            AuditQuery::from(within.clone()),
            AuditQuery {
                module: Some("hosts".to_owned()),
                who: Some("alice".to_owned()),
                limit: Some(10),
            }
        );
        assert!(within.within_limits());

        let oversized_module = AuditQueryParams {
            module: Some("x".repeat(MAX_FILTER_LEN + 1)),
            ..AuditQueryParams::default()
        };
        assert!(!oversized_module.within_limits());

        let oversized_who = AuditQueryParams {
            who: Some("x".repeat(MAX_FILTER_LEN + 1)),
            ..AuditQueryParams::default()
        };
        assert!(!oversized_who.within_limits());

        let oversized_limit = AuditQueryParams {
            limit: Some(MAX_AUDIT_LIMIT + 1),
            ..AuditQueryParams::default()
        };
        assert!(!oversized_limit.within_limits());
    }

    // -- GET /api/v1/system/update -------------------------------------------

    #[test]
    fn the_update_not_checked_id_is_catalogued() {
        assert!(
            CATALOGUE.lines().any(|line| line
                .split('=')
                .next()
                .is_some_and(|k| k.trim() == super::UPDATE_NOT_CHECKED_ID)),
            "{} is missing from core.ftl",
            super::UPDATE_NOT_CHECKED_ID
        );
    }

    #[test]
    fn the_renewal_ids_are_catalogued() {
        for id in [super::RENEW_NOT_ACME_ID, super::RENEW_UNAVAILABLE_ID] {
            assert!(
                CATALOGUE
                    .lines()
                    .any(|line| line.split('=').next().is_some_and(|k| k.trim() == id)),
                "{id} is missing from core.ftl"
            );
        }
    }

    #[test]
    fn shared_report_matches_handler_state_and_formats_its_expiry() -> R {
        let bootstrap = crate::tls::bootstrap_self_signed(&["box.example".to_owned()])?;
        let from_pair = super::cert_report_for_der(bootstrap.cert_der());
        assert_eq!(from_pair.fingerprint, bootstrap.fingerprint());
        assert_eq!(from_pair.not_after_unix, bootstrap.not_after_unix());
        let text = super::not_after_rfc3339(from_pair.not_after_unix)
            .ok_or("a fresh bootstrap pair must format its expiry")?;
        assert!(text.ends_with('Z') && text.contains('T'), "{text}");
        assert_eq!(super::not_after_rfc3339(None), None);
        assert!(super::not_after_rfc3339(Some(from_pair.not_after_unix.unwrap_or(0))).is_some());
        assert_eq!(
            super::cert_report_for_der(&[]).not_after_unix,
            None,
            "garbage DER is unknown, never a failure"
        );
        Ok(())
    }

    #[test]
    fn update_report_converts_the_check_report_field_for_field() -> R {
        let report = UpdateReport::from(detent_update::update::CheckReport {
            update_available: true,
            current: "0.0.1".to_owned(),
            tag: Some("v0.0.2".to_owned()),
            published: Some("2026-01-01T00:00:00Z".to_owned()),
            security: true,
            held: None,
        });
        assert_eq!(
            serde_json::to_value(&report)?,
            serde_json::json!({
                "update_available": true,
                "current": "0.0.1",
                "tag": "v0.0.2",
                "published": "2026-01-01T00:00:00Z",
                "security": true,
            })
        );
        Ok(())
    }

    fn stamp(tag: Option<&str>, available: bool) -> CheckReport {
        CheckReport {
            update_available: available,
            current: "0.0.1".to_owned(),
            tag: tag.map(str::to_owned),
            published: Some("2026-01-01T00:00:00Z".to_owned()),
            security: true,
            held: None,
        }
    }

    #[test]
    fn no_stamp_is_a_404_that_names_the_missing_check() -> R {
        let Err(error) = status_from_stamp(None, &[], "0.1.1") else {
            return Err("no stamp must not answer a report".into());
        };
        assert_eq!(error.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(error.message_id().as_str(), UPDATE_NOT_CHECKED_ID);
        Ok(())
    }

    #[test]
    fn the_stamp_offer_counts_only_while_newer_than_the_running_version() -> R {
        let offered = |tag: &str, running: &str, bad: &[String]| -> Result<bool, &'static str> {
            status_from_stamp(Some(stamp(Some(tag), true)), bad, running)
                .map(|report| report.update_available)
                .map_err(|_| "a stamp must answer")
        };
        assert!(offered("v0.2.0", "0.1.1", &[])?);
        assert!(!offered("v0.1.1", "0.1.1", &[])?, "the running release");
        assert!(!offered("v0.1.0", "0.1.1", &[])?, "an older release");
        assert!(!offered("v0.1.1", "0.1.1-rc.1", &["v0.1.1".to_owned()])?);
        assert!(
            !offered("v0.2.0", "0.1.1", &["v0.2.0".to_owned()])?,
            "a rolled-back release"
        );
        // A tag that is not semver is never an offer.
        assert!(!offered("latest", "0.1.1", &[])?);
        Ok(())
    }

    #[test]
    fn the_stamp_never_widens_what_it_offered() -> R {
        // A held release (too young) has no offer in the stamp; a newer tag
        // alone must not create one.
        let report = status_from_stamp(Some(stamp(Some("v0.2.0"), false)), &[], "0.1.1")
            .map_err(|_| "a stamp must answer")?;
        assert!(!report.update_available);
        assert_eq!(report.tag.as_deref(), Some("v0.2.0"));
        assert_eq!(report.current, "0.1.1", "current is the running version");
        Ok(())
    }

    // -- POST /api/v1/system/update ------------------------------------------

    #[test]
    fn render_started_maps_the_matching_outcome_and_rejects_any_other() -> R {
        let (status, view) = render_started(OpOutcome::UpdateStarted {
            version: "v1.2.3".to_owned(),
        })
        .map(|(status, axum::Json(view))| (status, view))
        .map_err(|_| "matching outcome must render")?;
        assert_eq!(status, axum::http::StatusCode::ACCEPTED);
        assert_eq!(view.version, "v1.2.3");
        assert_eq!(
            serde_json::to_value(UpdateStartedView {
                version: "v1.2.3".to_owned()
            })?,
            serde_json::json!({ "version": "v1.2.3" })
        );
        assert!(render_started(wrong_outcome()).is_err());
        Ok(())
    }

    #[test]
    fn the_apply_body_refuses_unknown_fields() {
        use super::UpdateApplyRequest;
        let bad = serde_json::json!({"version": "v1.2.3", "extra": 1});
        assert!(serde_json::from_value::<UpdateApplyRequest>(bad).is_err());
        let ok = serde_json::json!({"version": "v1.2.3"});
        assert!(serde_json::from_value::<UpdateApplyRequest>(ok).is_ok());
    }
}
