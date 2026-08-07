//! `/scan-policies` — reusable attack-library subsets (Scheduled DAST).
//!
//! A policy selects categories and/or explicit test_ids from the attack library
//! (config/test-matrix.yml). The deterministic pipeline runs only the selected
//! attacks. The list returns built-in presets (`builtin:*`, read-only) followed
//! by the org's custom policies. Org-scoped via JWT `custom:org_id`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/scan-policies", get(list).post(create))
        .route("/scan-policies/:id", axum::routing::patch(update).delete(remove))
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct ScanPolicy {
    id: String,
    org_id: String,
    name: String,
    description: Option<String>,
    categories: Vec<String>,
    test_ids: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Built-in presets — returned first, not editable. `builtin:full-assessment`
/// has empty selection (= run everything). Categories are test_id prefixes.
fn builtin_policies() -> Vec<JsonValue> {
    vec![
        json!({
            "id": "builtin:full-assessment", "builtin": true,
            "name": "Full assessment", "description": "Every in-scope attack (no filter).",
            "categories": [], "test_ids": [],
        }),
        json!({
            "id": "builtin:full-dast", "builtin": true,
            "name": "Full web/API (DAST)", "description": "All 73 web/API attacks.",
            "categories": ["RECON","TLS","AUTH","AUTHZ","HDR","CORS","INJ","SSRF","GQL","API","CLI","VSCAN","UPLOAD","BIZ","PROTO","DESER"],
            "test_ids": [],
        }),
        json!({
            "id": "builtin:quick-recon", "builtin": true,
            "name": "Quick recon + headers", "description": "Recon, TLS, and security headers only — fast, low-impact.",
            "categories": ["RECON","TLS","HDR"], "test_ids": [],
        }),
        json!({
            "id": "builtin:injection", "builtin": true,
            "name": "Injection focus", "description": "SQLi / XSS / SSTI / SSRF and friends.",
            "categories": ["INJ","SSRF"], "test_ids": [],
        }),
        json!({
            "id": "builtin:api-graphql", "builtin": true,
            "name": "API & GraphQL", "description": "REST + GraphQL attack surface.",
            "categories": ["API","GQL"], "test_ids": [],
        }),
    ]
}

async fn list(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<JsonValue>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let custom: Vec<ScanPolicy> = sqlx::query_as(
        "SELECT * FROM scan_policies WHERE org_id = $1 ORDER BY name ASC",
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;

    let mut out = builtin_policies();
    for p in &custom {
        out.push(json!({
            "id": p.id, "builtin": false, "name": p.name, "description": p.description,
            "categories": p.categories, "test_ids": p.test_ids,
            "created_at": p.created_at, "updated_at": p.updated_at,
        }));
    }
    Ok(Json(out))
}

#[derive(Debug, Deserialize)]
struct UpsertBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    test_ids: Vec<String>,
}

async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpsertBody>,
) -> AppResult<(StatusCode, Json<ScanPolicy>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest("name is required".into()));
    }
    let id = Uuid::new_v4().to_string();
    let row: ScanPolicy = sqlx::query_as(
        r#"INSERT INTO scan_policies (id, org_id, name, description, categories, test_ids)
           VALUES ($1,$2,$3,$4,$5,$6) RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.categories)
    .bind(&req.test_ids)
    .fetch_one(&state.pool)
    .await?;
    audit::record(&state.pool, &user, "scan_policy.create", "scan_policy", Some(&row.id), None).await;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn update(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<UpsertBody>,
) -> AppResult<Json<ScanPolicy>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    if id.starts_with("builtin:") {
        return Err(AppError::BadRequest("Built-in policies are read-only".into()));
    }
    let row: Option<ScanPolicy> = sqlx::query_as(
        r#"UPDATE scan_policies SET
               name = $3, description = $4, categories = $5, test_ids = $6, updated_at = NOW()
           WHERE id = $1 AND org_id = $2 RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.categories)
    .bind(&req.test_ids)
    .fetch_optional(&state.pool)
    .await?;
    row.map(Json).ok_or_else(|| AppError::NotFound("Policy not found".into()))
}

async fn remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;
    let res = sqlx::query("DELETE FROM scan_policies WHERE id = $1 AND org_id = $2")
        .bind(&id)
        .bind(&org_id)
        .execute(&state.pool)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Policy not found".into()));
    }
    audit::record(&state.pool, &user, "scan_policy.delete", "scan_policy", Some(&id), None).await;
    Ok(StatusCode::NO_CONTENT)
}
