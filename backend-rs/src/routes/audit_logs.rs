//! `/audit-logs` GET — paginated, filterable audit trail.
//!
//! Read-only endpoint scoped by JWT org_id. Filters: tool/action,
//! target/resource_id, time range. Most recent first. Used by the
//! desktop's Audit Logs page; the rows themselves are written by the
//! various entity routes (assessments/findings/etc.) when they perform
//! mutations — that side is already in place from earlier migrations.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::auth::AuthUser;
use crate::error::AppResult;
use crate::schemas::common::{pages_for, PaginatedResponse, PaginationQuery};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/audit-logs", get(list_audit_logs))
}

#[derive(Debug, Deserialize)]
struct ListFilters {
    #[serde(flatten)]
    page: PaginationQuery,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    from: Option<DateTime<Utc>>,
    #[serde(default)]
    to: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow, Serialize)]
struct AuditLogRow {
    id: String,
    action: String,
    resource_type: String,
    resource_id: Option<String>,
    details: Option<JsonValue>,
    user_id: Option<String>,
    user_email: Option<String>,
    org_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

async fn list_audit_logs(
    State(state): State<AppState>,
    Query(q): Query<ListFilters>,
    user: AuthUser,
) -> AppResult<Json<PaginatedResponse>> {
    let mut sql = String::from("SELECT * FROM audit_logs WHERE 1=1");
    let mut count_sql = String::from("SELECT COUNT(*) FROM audit_logs WHERE 1=1");
    let mut binds: Vec<String> = Vec::new();

    if let Some(org) = user.org_id.as_ref() {
        binds.push(org.clone());
        let clause = format!(" AND org_id = ${}", binds.len());
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }
    if let Some(t) = q.tool.as_ref() {
        binds.push(t.clone());
        let clause = format!(" AND action = ${}", binds.len());
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }
    if let Some(t) = q.target.as_ref() {
        binds.push(t.clone());
        let clause = format!(" AND resource_id = ${}", binds.len());
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }

    // Time-range binds use timestamptz so we keep them in their own loop.
    let mut ts_binds: Vec<DateTime<Utc>> = Vec::new();
    if let Some(from) = q.from {
        ts_binds.push(from);
        let n = binds.len() + ts_binds.len();
        let clause = format!(" AND created_at >= ${n}");
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }
    if let Some(to) = q.to {
        ts_binds.push(to);
        let n = binds.len() + ts_binds.len();
        let clause = format!(" AND created_at <= ${n}");
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }

    // Total count for pagination metadata.
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        count_q = count_q.bind(b);
    }
    for b in &ts_binds {
        count_q = count_q.bind(b);
    }
    let total: i64 = count_q.fetch_one(&state.pool).await?;

    let limit = q.page.limit.max(1).min(200);
    let offset = (q.page.page.max(1) - 1) * limit;
    let lim_idx = binds.len() + ts_binds.len() + 1;
    let off_idx = lim_idx + 1;
    sql.push_str(&format!(
        " ORDER BY created_at DESC LIMIT ${lim_idx} OFFSET ${off_idx}"
    ));

    let mut data_q = sqlx::query_as::<_, AuditLogRow>(&sql);
    for b in &binds {
        data_q = data_q.bind(b);
    }
    for b in &ts_binds {
        data_q = data_q.bind(b);
    }
    data_q = data_q.bind(limit).bind(offset);
    let rows: Vec<AuditLogRow> = data_q.fetch_all(&state.pool).await?;

    let data = rows
        .into_iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();

    let pages = pages_for(total, limit);
    Ok(Json(PaginatedResponse {
        data,
        total,
        page: q.page.page,
        limit,
        pages,
        has_more: q.page.page < pages,
    }))
}
