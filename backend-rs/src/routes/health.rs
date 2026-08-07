//! Health / readiness / liveness endpoints. Public (no auth).
//! Wire-compatible with `backend/app/routers/health.py`.

use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness_check))
        .route("/health/live", get(liveness_check))
}

async fn health_check(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": state.settings.app_name,
        "version": state.settings.app_version,
    }))
}

async fn readiness_check(State(state): State<AppState>) -> Json<Value> {
    let db_status = match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => "connected".to_string(),
        Err(e) => format!("error: {}", e),
    };
    let status = if db_status == "connected" {
        "ready"
    } else {
        "not_ready"
    };
    Json(json!({
        "status": status,
        "database": db_status,
        "auth_provider": state.settings.auth_provider,
        "storage_provider": state.settings.storage_provider,
    }))
}

async fn liveness_check() -> Json<Value> {
    Json(json!({ "status": "alive" }))
}
