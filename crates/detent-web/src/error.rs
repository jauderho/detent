//! The one error body the API ever answers with (PLAN §2.7, "Output").
//!
//! ```text
//!   AuthError / EngineError ──▶ ApiError ──▶ { "code": …, "message_id": … }
//!                                              (+ Retry-After on 429)
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

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use detent_core::diag::MessageId;
use serde::Serialize;

use crate::auth::AuthError;
use crate::engine::EngineError;

/// The JSON body of every API failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// A stable machine-readable class, derived from the status.
    pub code: &'static str,
    /// The Fluent id a front end renders.
    pub message_id: String,
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
        }
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
        }
    }
}

impl From<EngineError> for ApiError {
    /// An operation that failed keeps the operation layer's own id, so the
    /// web API renders the sentence the CLI renders for the same cause.
    fn from(error: EngineError) -> Self {
        let status = match error {
            EngineError::Ops(detent_ops::OpsError::Denied(_)) => StatusCode::FORBIDDEN,
            EngineError::Stopped => StatusCode::SERVICE_UNAVAILABLE,
            EngineError::Ops(_) => StatusCode::BAD_REQUEST,
        };
        Self {
            status,
            message_id: error.message_id(),
            retry_after_secs: None,
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
        assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
        assert_eq!(unknown.body().code, "bad_request");
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
