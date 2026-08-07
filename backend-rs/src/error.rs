//! Error type that mirrors FastAPI's `HTTPException` wire shape:
//! `{"detail": "<string>"}` with a matching HTTP status code.
//!
//! Every handler returns `Result<T, AppError>`, and `IntoResponse` produces
//! the exact `{"detail": ...}` body the Python backend emits today.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    UnprocessableEntity(String),
    #[error("{0}")]
    ServiceUnavailable(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn detail(&self) -> String {
        match self {
            // Surface the inner sqlx error to the client. Earlier this was
            // masked behind a generic "Internal server error" — well-intended
            // (avoid leaking schema detail) but it made every 500 an opaque
            // wall. The pattern was that the user would hit a 500, the real
            // error was buried in CloudWatch, and a round-trip was needed
            // every time. For a dogfood/self-hosted enterprise tool the
            // tradeoff is wrong: actionable errors win.
            //
            // sqlx::Error's Display already collapses to "<error class>:
            // <postgres message>" for ::Database variants, which is what
            // we want (e.g. "invalid input value for enum assessmenttype:
            // 'foo'"). Other variants (PoolClosed, Decode, etc.) carry
            // enough text to diagnose locally too.
            AppError::Database(e) => format!("Database error: {e}"),
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if matches!(self, AppError::Database(_) | AppError::Internal(_)) {
            tracing::error!(error = %self, "request failed");
        }
        let body = Json(json!({ "detail": self.detail() }));
        (self.status(), body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
