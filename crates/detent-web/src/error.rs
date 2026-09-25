//! The one error body the API ever answers with (PLAN §2.7, "Output").
//!
//! ```text
//!   AuthError ────────────────────▶ ApiError ──▶ { "code": …, "message_id": … }
//!   EngineError ─┬─▶ Stopped ─────▶                 (+ Retry-After on 429)
//!                └─▶ Ops(OpsError)                  (+ diagnostics on 422)
//! ```
//!
//! # Guarantees
//!
//! * **No internal string ever reaches a client.** The body is a stable
//!   machine `code` and a Fluent `message_id`; the `Display` of the underlying
//!   error goes to the log, never to the response.
//! * **The code cannot drift from the status.** It is derived from the status
//!   by [`code_for`], so a handler cannot answer 403 with `"not_found"`.
//! * **Every id is catalogued.** The tests in each module assert their ids
//!   exist in `locales/en-US/core.ftl`.
//! * **An [`OpsError`] never reaches a client as a bare 500.** Every variant
//!   that names a client mistake or a state conflict — an unknown module, a
//!   rejected candidate, a stale hash, a settled commit, a module with
//!   nothing to act on — gets its own 4xx; only a genuine operator-side
//!   failure (privsep, the service manager, the audit log, an unsupported
//!   operation) answers 500. See `impl From<OpsError> for ApiError`.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use detent_core::diag::{Diagnostics, MessageId};
use detent_ops::OpsError;
use detent_platform::privsep::proto::ProtoError;
use detent_platform::privsep::worker::ClientError;
use serde::Serialize;

use crate::auth::AuthError;
use crate::engine::EngineError;

/// The JSON body of every API failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(utoipa::ToSchema))]
pub struct ErrorBody {
    /// A stable machine-readable class, derived from the status.
    pub code: &'static str,
    /// The Fluent id a front end renders.
    pub message_id: String,
    /// Validation findings, only present for a rejected [`Operation::Apply`]
    /// (PLAN §2.5: any `Severity::Error` diagnostic stops an apply before
    /// anything is written). Mirrors `detent_core::diag::Diagnostics`, which
    /// cannot derive `ToSchema` without giving `detent-core` a dependency on
    /// `utoipa`.
    ///
    /// [`Operation::Apply`]: detent_ops::Operation::Apply
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(test, schema(value_type = Object))]
    pub diagnostics: Option<Diagnostics>,
}

/// A failure on its way to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status.
    status: StatusCode,
    /// The Fluent id.
    message_id: MessageId,
    /// Seconds to wait, for a 429.
    retry_after_secs: Option<u64>,
    /// Validation findings, for a rejected apply.
    diagnostics: Option<Diagnostics>,
}

/// The machine-readable class for a status.
#[must_use]
pub const fn code_for(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNPROCESSABLE_ENTITY => "unprocessable",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::SERVICE_UNAVAILABLE => "unavailable",
        _ => "internal",
    }
}

impl ApiError {
    /// A failure with an explicit status and id.
    #[must_use]
    pub const fn new(status: StatusCode, message_id: MessageId) -> Self {
        Self {
            status,
            message_id,
            retry_after_secs: None,
            diagnostics: None,
        }
    }

    /// Attach the diagnostics a rejected apply carries.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Diagnostics) -> Self {
        self.diagnostics = Some(diagnostics);
        self
    }

    /// The status this failure answers with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The Fluent id this failure carries.
    #[must_use]
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// The body this failure serializes to.
    #[must_use]
    pub fn body(&self) -> ErrorBody {
        ErrorBody {
            code: code_for(self.status),
            message_id: self.message_id.as_str().to_owned(),
            diagnostics: self.diagnostics.clone(),
        }
    }
}

impl From<AuthError> for ApiError {
    /// Keeps the status and the id [`AuthError`] chose, and carries the
    /// backoff of a rate-limited attempt into `Retry-After`.
    fn from(error: AuthError) -> Self {
        let retry_after_secs = match error {
            AuthError::RateLimited { retry_after_secs } => Some(retry_after_secs),
            _ => None,
        };
        Self {
            status: error.status(),
            message_id: error.message_id(),
            retry_after_secs,
            diagnostics: None,
        }
    }
}

/// Whether `error` is the shape [`Operation::ConfirmCommit`] and
/// [`Operation::RollbackCommit`] take when the id names no pending commit —
/// already confirmed, already rolled back on its own deadline, or never
/// armed. The caller's request conflicts with the commit's current state
/// rather than naming something that never existed, so this is a 409 rather
/// than the 500 every other [`OpsError::Privsep`] answers with.
///
/// [`Operation::ConfirmCommit`]: detent_ops::Operation::ConfirmCommit
/// [`Operation::RollbackCommit`]: detent_ops::Operation::RollbackCommit
fn is_unknown_wire_id(error: &ClientError) -> bool {
    matches!(error, ClientError::Remote(ProtoError::UnknownId { .. }))
}

impl From<OpsError> for ApiError {
    /// Maps each [`OpsError`] variant to the status PLAN §2.7 ("Output")
    /// implies for it. `OpsError` is `#[non_exhaustive]`, so a variant this
    /// build does not know about — there are none today — falls into the same
    /// arm as a genuine internal failure: 500, code only, no message beyond
    /// the catalogued id.
    fn from(error: OpsError) -> Self {
        let message_id = error.message_id();
        match error {
            // The id named no module this build compiled in.
            OpsError::UnknownModule { .. } => Self::new(StatusCode::NOT_FOUND, message_id),
            // The scope policy refused the operation.
            OpsError::Denied(_) => Self::new(StatusCode::FORBIDDEN, message_id),
            // The candidate has at least one error diagnostic; the caller can
            // act on exactly which one.
            OpsError::Invalid { diagnostics } => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, message_id)
                    .with_diagnostics(*diagnostics)
            }
            // The target changed since the caller's `expected_hash` was read:
            // optimistic-concurrency conflict, not a client mistake.
            OpsError::HashConflict { .. } => Self::new(StatusCode::CONFLICT, message_id),
            // The module exists but declares no writable target or no service
            // binding on this host — a module/allow-list mismatch — or its
            // file is missing: the requested action conflicts with the host's
            // state rather than naming an absent API resource.
            OpsError::NoTarget { .. } | OpsError::NoService { .. } | OpsError::TargetMissing => {
                Self::new(StatusCode::CONFLICT, message_id)
            }
            // A stale or already-settled commit id: see `is_unknown_wire_id`.
            OpsError::Privsep(ref client) if is_unknown_wire_id(client) => {
                Self::new(StatusCode::CONFLICT, message_id)
            }
            // Everything else — a parse/schema failure, any other privsep or
            // service-manager failure, an audit-log I/O error, an
            // unsupported operation, or (since `OpsError` is
            // `#[non_exhaustive]`) a future variant this build does not know
            // the shape of — is the operator's problem, not the caller's:
            // 500, and the body carries only the code.
            OpsError::Module(_)
            | OpsError::Privsep(_)
            | OpsError::Service(_)
            | OpsError::Audit(_)
            | OpsError::Unsupported { .. }
            | _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, message_id),
        }
    }
}

impl From<EngineError> for ApiError {
    /// An operation that failed keeps the operation layer's own id, so the
    /// web API renders the sentence the CLI renders for the same cause.
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::Ops(ops_error) => Self::from(ops_error),
            EngineError::Stopped => Self::new(StatusCode::SERVICE_UNAVAILABLE, error.message_id()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body())).into_response();
        if let Some(seconds) = self.retry_after_secs
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiError, code_for};
    use crate::auth::AuthError;
    use crate::engine::EngineError;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse as _;
    use detent_core::diag::MessageId;

    type R = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn the_body_is_a_code_and_a_fluent_id_and_nothing_else() -> R {
        let error = ApiError::new(
            StatusCode::UNAUTHORIZED,
            MessageId::new("web-auth-invalid-credentials"),
        );
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(error.message_id().as_str(), "web-auth-invalid-credentials");

        let response = error.clone().into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            json,
            serde_json::json!({
                "code": "unauthorized",
                "message_id": "web-auth-invalid-credentials",
            })
        );
        assert_eq!(error, ApiError::from(AuthError::InvalidCredentials));
        Ok(())
    }

    #[tokio::test]
    async fn a_rate_limited_answer_carries_retry_after() -> R {
        let error = ApiError::from(AuthError::RateLimited {
            retry_after_secs: 42,
        });
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .map(|value| value.to_str())
                .transpose()?,
            Some("42")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(
            json.pointer("/code").and_then(|v| v.as_str()),
            Some("rate_limited")
        );
        Ok(())
    }

    #[test]
    fn every_auth_failure_maps_to_a_status_and_a_code() {
        let cases = [
            (AuthError::InvalidCredentials, StatusCode::UNAUTHORIZED),
            (AuthError::Unauthenticated, StatusCode::UNAUTHORIZED),
            (AuthError::CsrfRejected, StatusCode::FORBIDDEN),
            (AuthError::UnknownToken, StatusCode::NOT_FOUND),
            (AuthError::UserExists, StatusCode::CONFLICT),
            (AuthError::TokenLimit, StatusCode::CONFLICT),
            (AuthError::AmbiguousCredentials, StatusCode::BAD_REQUEST),
            (AuthError::SessionLimit, StatusCode::SERVICE_UNAVAILABLE),
            (AuthError::Hash, StatusCode::INTERNAL_SERVER_ERROR),
        ];
        for (error, status) in cases {
            let id = error.message_id();
            let api = ApiError::from(error);
            assert_eq!(api.status(), status);
            assert_eq!(api.message_id().as_str(), id.as_str());
            assert_eq!(api.body().code, code_for(status));
            assert!(!api.body().code.is_empty());
        }
    }

    #[test]
    fn an_engine_failure_keeps_the_operation_layers_id() {
        let stopped = ApiError::from(EngineError::Stopped);
        assert_eq!(stopped.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(stopped.message_id().as_str(), "web-engine-stopped");
        assert_eq!(stopped.body().code, "unavailable");

        let denied = ApiError::from(EngineError::Ops(detent_ops::OpsError::Denied(
            detent_ops::authz::Denied::with_scope(MessageId::new("web-denied-scope"), "write"),
        )));
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(denied.message_id().as_str(), "web-denied-scope");

        let unknown = ApiError::from(EngineError::Ops(detent_ops::OpsError::UnknownModule {
            id: "nope".to_owned(),
        }));
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(unknown.body().code, "not_found");
    }

    /// Every [`detent_ops::OpsError`] variant maps to the status PLAN §2.7
    /// implies for it, and never to a bare 500 when the cause is the
    /// caller's.
    #[test]
    fn every_ops_error_variant_maps_to_its_documented_status() {
        use detent_core::diag::{Diagnostic, Diagnostics, Severity};
        use detent_ops::OpsError;
        use detent_ops::authz::Denied;
        use detent_platform::fs::atomic::Sha256Digest;
        use detent_platform::privsep::proto::{IdKind, ProtoError};
        use detent_platform::privsep::worker::ClientError;

        let diagnostics = || -> Diagnostics {
            std::iter::once(Diagnostic::new(
                Severity::Error,
                MessageId::new("hosts-invalid-ip"),
            ))
            .collect()
        };

        let cases: Vec<(OpsError, StatusCode)> = vec![
            (
                OpsError::UnknownModule {
                    id: "nope".to_owned(),
                },
                StatusCode::NOT_FOUND,
            ),
            (
                OpsError::from(Denied::new(MessageId::new("web-denied-scope"))),
                StatusCode::FORBIDDEN,
            ),
            (
                OpsError::Invalid {
                    diagnostics: Box::new(diagnostics()),
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                OpsError::HashConflict {
                    expected: Sha256Digest::of(b"a"),
                    actual: Some(Sha256Digest::of(b"b")),
                },
                StatusCode::CONFLICT,
            ),
            (
                OpsError::NoTarget {
                    module: "hosts".to_owned(),
                },
                StatusCode::CONFLICT,
            ),
            (
                OpsError::NoService {
                    module: "hosts".to_owned(),
                },
                StatusCode::CONFLICT,
            ),
            (OpsError::TargetMissing, StatusCode::CONFLICT),
            (
                // A stale or already-settled commit/backup id.
                OpsError::from(ClientError::Remote(ProtoError::UnknownId {
                    kind: IdKind::Commit,
                    id: 4,
                })),
                StatusCode::CONFLICT,
            ),
            (
                // Any other privsep failure is the operator's problem.
                OpsError::from(ClientError::NotGreeted),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (error, status) in cases {
            let id = error.message_id();
            let api = ApiError::from(error);
            assert_eq!(api.status(), status, "{id:?}");
            assert_eq!(api.message_id().as_str(), id.as_str());
        }

        // The diagnostics travel with a 422, and with nothing else.
        let invalid = ApiError::from(OpsError::Invalid {
            diagnostics: Box::new(diagnostics()),
        });
        assert_eq!(invalid.body().diagnostics, Some(diagnostics()));
        let denied = ApiError::from(OpsError::from(Denied::new(MessageId::new(
            "web-denied-scope",
        ))));
        assert_eq!(denied.body().diagnostics, None);
    }

    #[test]
    fn the_code_is_derived_from_the_status() {
        for (status, code) in [
            (StatusCode::BAD_REQUEST, "bad_request"),
            (StatusCode::UNAUTHORIZED, "unauthorized"),
            (StatusCode::FORBIDDEN, "forbidden"),
            (StatusCode::NOT_FOUND, "not_found"),
            (StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed"),
            (StatusCode::CONFLICT, "conflict"),
            (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            (StatusCode::UNPROCESSABLE_ENTITY, "unprocessable"),
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            (StatusCode::IM_A_TEAPOT, "internal"),
        ] {
            assert_eq!(code_for(status), code, "{status}");
        }
    }
}
