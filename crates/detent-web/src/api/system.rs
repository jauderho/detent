//! `/api/v1/system/profile`, `/api/v1/system/cert`, `/api/v1/system/update`
//! (`GET` for status, `POST` to install), and `/api/v1/audit`: host,
//! certificate, update, and history views. Only the update `POST` mutates.

use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use detent_core::diag::MessageId;
use detent_ops::Operation;
use detent_ops::audit::{AuditQuery, AuditRecord};
use detent_ops::report::{CertReport, HostReport};
use detent_update::fetch::Transport;
use detent_update::policy::Policy;
use detent_update::update::CheckReport;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::extract::{Caller, WriteCaller};
use crate::error::ApiError;
use crate::state::AppState;

use super::{authorize, bad_request, json_rejection, query_rejection, unexpected_outcome};
use detent_ops::OpOutcome;

/// `GET /api/v1/system/profile`.
pub const PROFILE_PATH: &str = "/api/v1/system/profile";
/// `GET /api/v1/system/cert`.
pub const CERT_PATH: &str = "/api/v1/system/cert";
/// `GET /api/v1/system/update`.
pub const UPDATE_PATH: &str = "/api/v1/system/update";
/// `GET /api/v1/audit`.
pub const AUDIT_PATH: &str = "/api/v1/audit";

/// Longest `module` or `who` filter accepted in the audit query string.
pub const MAX_FILTER_LEN: usize = 128;

/// Most records `?limit=` may ask for in one answer.
pub const MAX_AUDIT_LIMIT: usize = 1000;

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
    authorize(&caller, &Operation::CertStatus)?;
    Ok(Json(cert_report(&state)))
}

/// The certificate answer, pulled out of [`cert`] so tests need no caller.
pub(super) fn cert_report(state: &AppState) -> CertReport {
    use time::OffsetDateTime;
    let current = state.cert_store.current();
    let der: &[u8] = current.cert.first().map_or(&[], |c| c.as_ref());
    let fingerprint = crate::tls::fingerprint(der);
    let (not_after_unix, lifetime_used_percent, renewal_due) = match crate::tls::validity_unix(der)
    {
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
            (Some(not_after), pct, Some(due))
        }
        None => (None, None, None),
    };
    CertReport {
        fingerprint,
        not_after_unix,
        lifetime_used_percent,
        renewal_due,
    }
}
/// `GET /api/v1/system/update`.
///
/// The update status the web layer answers directly: `detent-update` owns the
/// check (release feed over the network), which the operations engine does
/// not depend on and cannot answer for. Read-only — **installing** an update
/// is the `write`-scoped, CSRF-checked `POST` on this same path, answered by
/// [`apply_update`]; nothing here installs anything.
///
/// Interval-guarded (PLAN §2.9 steps 5a and 6): `detent update --check`
/// (the daily cron) writes `<state_root>/update/check.json` at most once
/// per 24 h; this handler prefers that stamp and only reaches the network
/// when no stamp exists yet. A read-scoped caller can no longer make this
/// host poll GitHub in a loop.
#[cfg_attr(test, utoipa::path(
    get,
    path = UPDATE_PATH,
    tag = "system",
    responses(
        (status = 200, description = "The update status under the configured policy", body = UpdateReport),
        (status = 503, description = "The release feed could not be reached", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn update(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<UpdateReport>, ApiError> {
    // Gated against this operation's own identity, not `HostProfile`'s: the
    // engine cannot answer an update check (the feed lives in
    // `detent-update`), but the policy decision and the audit label for a
    // refusal must still be this endpoint's. No engine call happens, and a
    // read-only operation writes no audit record on success (PLAN §2.5).
    authorize(&caller, &Operation::UpdateStatus)?;
    let stamp = state.update_stamp();
    let rejected = state.bad_stamp();
    let (cached, bad) = tokio::task::spawn_blocking(move || {
        let cached = detent_update::update::read_cached(&stamp);
        let bad = detent_update::update::read_bad(&rejected);
        (cached, bad)
    })
    .await
    .map_err(|_| update_check_failed())?;
    if let Some(cached) = cached {
        let poisoned = cached
            .report
            .tag
            .as_deref()
            .is_some_and(|tag| bad.iter().any(|b| b == tag));
        if !poisoned {
            return Ok(Json(cached.report.into()));
        }
    }
    let policy = Policy {
        min_age_days: u64::from(state.config.update.min_age_days),
        allow_downgrade: false,
    };
    // No stamp yet: one live check. Off the async workers — synchronous
    // network I/O with a 30 s cap per GET.
    let report = tokio::task::spawn_blocking(move || {
        let transport =
            detent_update::fetch::RealTransport::new().map_err(|_| update_check_failed())?;
        update_report(&transport, &policy, &bad)
    })
    .await
    .map_err(|_| update_check_failed())?;
    Ok(Json(report?))
}
/// `POST /api/v1/system/update`.
///
/// Installs the named update: the engine bridges the release tag to the
/// content-addressed staged file and drives the monitor's `ReplaceBinary`
/// swap. Refused as `Unsupported` (`ops-unsupported`, 500 with a reason)
/// when the staged file is missing or the request is unsafe; the route,
/// authz (`write`), and audit record are the stable shape the UI builds on.
#[cfg_attr(test, utoipa::path(
    post,
    path = UPDATE_PATH,
    tag = "system",
    request_body = UpdateApplyRequest,
    responses(
        (status = 200, description = "The update was installed", body = UpdateAppliedView),
        (status = 500, description = "No staged binary to install", body = crate::error::ErrorBody),
    ),
))]
pub(super) async fn apply_update(
    State(state): State<AppState>,
    caller: WriteCaller,
    body: Result<Json<UpdateApplyRequest>, JsonRejection>,
) -> Result<Json<UpdateAppliedView>, ApiError> {
    let Json(request) = body.map_err(json_rejection)?;
    let op = Operation::UpdateApply {
        version: request.version,
    };
    authorize(caller.caller(), &op)?;
    let outcome = state
        .engine
        .execute(op, caller.caller().identity().clone())
        .await?;
    render_applied(outcome)
}

/// The body of `POST /api/v1/system/update`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct UpdateApplyRequest {
    /// The update version to install, e.g. `v1.2.3`.
    pub version: String,
}

/// Answer to `UpdateApply`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct UpdateAppliedView {
    /// The version that was installed.
    pub version: String,
}

/// The `OpOutcome::UpdateApplied` branch, pulled out of [`apply_update`] so
/// the mismatch arm can be exercised with a synthetic outcome.
fn render_applied(outcome: OpOutcome) -> Result<Json<UpdateAppliedView>, ApiError> {
    match outcome {
        OpOutcome::UpdateApplied { version } => Ok(Json(UpdateAppliedView { version })),
        _ => Err(unexpected_outcome()),
    }
}

/// `web-update-check-failed` — the release feed could not be reached.
fn update_check_failed() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        MessageId::new("web-update-check-failed"),
    )
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

/// The update answer, pulled out of [`update`] so tests need no caller and no
/// network: they hand it a mock [`Transport`].
///
/// # Errors
///
/// [`update_check_failed`] when the release feed cannot be reached
/// (refuse-closed: an unreachable feed is never folded into "no update").
pub(super) fn update_report(
    transport: &dyn Transport,
    policy: &Policy,
    bad: &[String],
) -> Result<UpdateReport, ApiError> {
    let current =
        semver::Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| update_check_failed())?;
    detent_update::update::check(transport, &current, policy, OffsetDateTime::now_utc(), bad)
        .map(UpdateReport::from)
        .map_err(|_| update_check_failed())
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
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
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
    authorize(&caller, &op)?;
    let outcome = state.engine.execute(op, caller.identity().clone()).await?;
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
        AuditQueryParams, MAX_AUDIT_LIMIT, MAX_FILTER_LEN, UpdateAppliedView, UpdateReport,
        render_applied, render_audit, render_host, update_check_failed, update_report,
    };
    use detent_core::descriptor::HostProfile;
    use detent_ops::OpOutcome;
    use detent_ops::audit::AuditQuery;
    use detent_ops::report::HostReport;
    use detent_platform::privsep::proto::CommitId;
    use detent_update::fetch::{FetchError, Transport, target_triple};
    use detent_update::policy::Policy;

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

    /// A transport that answers every GET with one canned body: the boundary
    /// `detent-update::fetch` mocks in its own tests, rebuilt here because
    /// the web tests need only the releases feed.
    struct Feed(String);

    impl Transport for Feed {
        fn get(
            &self,
            _url: &str,
            cap: u64,
            sink: &mut dyn std::io::Write,
        ) -> Result<u64, FetchError> {
            sink.write_all(self.0.as_bytes())
                .map_err(|err| FetchError::Unreachable {
                    url: String::new(),
                    reason: err.to_string(),
                })?;
            u64::try_from(self.0.len()).map_err(|_| FetchError::TooLarge { cap })
        }
    }

    /// A transport that cannot reach anything, for the refuse-closed path.
    struct Dead;

    impl Transport for Dead {
        fn get(
            &self,
            _url: &str,
            _cap: u64,
            _sink: &mut dyn std::io::Write,
        ) -> Result<u64, FetchError> {
            Err(FetchError::Unreachable {
                url: String::new(),
                reason: "test".to_owned(),
            })
        }
    }

    /// One release in the shape `detent-update::fetch` parses, with the three
    /// assets `list_releases` requires to keep a release at all.
    fn feed(tag: &str, body: &str, published: &str) -> String {
        let triple = target_triple();
        format!(
            r#"[{{"tag_name":"{tag}","draft":false,"prerelease":false,"published_at":{published},"body":"{body}","assets":[{{"name":"detent-{triple}","browser_download_url":"u"}},{{"name":"SHA256SUMS","browser_download_url":"u"}},{{"name":"detent-{triple}.sigstore.json","browser_download_url":"u"}}]}}]"#
        )
    }

    #[test]
    fn the_update_failure_id_is_catalogued() {
        assert!(
            CATALOGUE.lines().any(|line| line
                .split('=')
                .next()
                .is_some_and(|k| k.trim() == "web-update-check-failed")),
            "web-update-check-failed is missing from core.ftl"
        );
    }

    #[test]
    fn update_report_maps_a_qualifying_release() -> R {
        let feed = feed("v0.0.2", "", r#""2026-01-01T00:00:00Z""#);
        let report = update_report(&Feed(feed), &Policy::default(), &[])
            .map_err(|_| "a newer, old-enough release should qualify")?;
        assert!(report.update_available);
        assert_eq!(report.tag.as_deref(), Some("v0.0.2"));
        assert_eq!(report.current, env!("CARGO_PKG_VERSION"));
        assert!(report.published.is_some());
        assert!(!report.security);
        Ok(())
    }

    #[test]
    fn update_report_folds_policy_refusals_into_the_report() -> R {
        // A release older than the running one is refused, but named, so a
        // client can explain why it is not offered (detent-update's own
        // `DowngradeRefused` report).
        let older = feed("v0.0.0", "", r#""2026-01-01T00:00:00Z""#);
        let report = update_report(&Feed(older), &Policy::default(), &[])
            .map_err(|_| "a refusal is a report, not an error")?;
        assert!(!report.update_available);
        assert_eq!(report.tag.as_deref(), Some("v0.0.0"));
        assert_eq!(report.published, None);
        assert!(!report.security);

        // An empty feed has nothing at all: no tag, no date.
        let report = update_report(&Feed("[]".to_owned()), &Policy::default(), &[])
            .map_err(|_| "no candidates is a report, not an error")?;
        assert!(!report.update_available);
        assert_eq!(report.tag, None);
        assert_eq!(report.published, None);
        assert!(!report.security);
        Ok(())
    }

    #[test]
    fn update_report_carries_the_security_flag() -> R {
        // `detent-security: true` bypasses the age gate, so an unpublished
        // release still qualifies — and is reported as a security one.
        let feed = feed("v0.0.2", "detent-security: true", "null");
        let report = update_report(&Feed(feed), &Policy::default(), &[])
            .map_err(|_| "a security release should qualify")?;
        assert!(report.update_available);
        assert!(report.security);
        Ok(())
    }

    #[test]
    fn update_report_refuses_closed_when_the_feed_is_unreachable() -> R {
        let error = match update_report(&Dead, &Policy::default(), &[]) {
            Ok(report) => {
                return Err(format!("an unreachable feed must not answer {report:?}").into());
            }
            Err(error) => error,
        };
        assert_eq!(error.status(), update_check_failed().status());
        assert_eq!(
            error.message_id().as_str(),
            update_check_failed().message_id().as_str()
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

    #[test]
    fn update_report_skips_a_bad_tag() -> R {
        let feed = feed("v0.0.2", "", r#""2026-01-01T00:00:00Z""#);
        let bad = vec!["v0.0.2".to_owned()];
        let report = update_report(&Feed(feed), &Policy::default(), &bad)
            .map_err(|_| "a bad tag must not be offered")?;
        assert!(
            !report.update_available,
            "bad tag is filtered before select"
        );
        assert_eq!(report.tag, None);
        Ok(())
    }

    // -- POST /api/v1/system/update ------------------------------------------

    #[test]
    fn render_applied_maps_the_matching_outcome_and_rejects_any_other() -> R {
        let view = render_applied(OpOutcome::UpdateApplied {
            version: "v1.2.3".to_owned(),
        })
        .map(|axum::Json(view)| view)
        .map_err(|_| "matching outcome must render")?;
        assert_eq!(view.version, "v1.2.3");
        assert_eq!(
            serde_json::to_value(UpdateAppliedView {
                version: "v1.2.3".to_owned()
            })?,
            serde_json::json!({ "version": "v1.2.3" })
        );
        assert!(render_applied(wrong_outcome()).is_err());
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
