//! `/cloud/attack-paths` — escalation-graph persistence (W5 enrichment).
//!
//! Endpoints:
//!   POST /cloud/attack-paths              — ingest a graph (replaces prior for
//!                                           the same org/target/source)
//!   GET  /cloud/attack-paths?target_id=X  — graphs for a target + org-wide ones
//!
//! Promoted at end-of-run by the MCP `record_attack_paths` tool (Shape A). The
//! backend is a passthrough store: nodes/edges are opaque JSONB in the frontend
//! GraphNode/GraphEdge shape. Per-org scoped via JWT `custom:org_id`.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use std::collections::HashSet;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::attack_path::{AttackPathGraphRow, ATTACK_PATH_SOURCES};
use crate::routes::graph::{accumulate_edge, accumulate_node, validate_kinds, EdgeInput, NodeInput};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/cloud/attack-paths", post(ingest_graph).get(list_graphs))
}

fn empty_array() -> JsonValue {
    JsonValue::Array(vec![])
}

#[derive(Debug, Deserialize)]
struct IngestBody {
    #[serde(default)]
    target_id: Option<String>,
    #[serde(default)]
    assessment_id: Option<String>,
    source: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default = "empty_array")]
    nodes: JsonValue,
    #[serde(default = "empty_array")]
    edges: JsonValue,
}

#[derive(Debug, Serialize)]
struct GraphView {
    id: String,
    target_id: Option<String>,
    assessment_id: Option<String>,
    source: String,
    label: Option<String>,
    nodes: JsonValue,
    edges: JsonValue,
}

impl From<&AttackPathGraphRow> for GraphView {
    fn from(g: &AttackPathGraphRow) -> Self {
        Self {
            id: g.id.clone(),
            target_id: g.target_id.clone(),
            assessment_id: g.assessment_id.clone(),
            source: g.source.clone(),
            label: g.label.clone(),
            nodes: g.nodes.clone(),
            edges: g.edges.clone(),
        }
    }
}

async fn ingest_graph(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<IngestBody>,
) -> AppResult<(StatusCode, Json<GraphView>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    if !ATTACK_PATH_SOURCES.contains(&body.source.as_str()) {
        return Err(AppError::BadRequest(format!(
            "Invalid source '{}'. Must be one of: {}",
            body.source,
            ATTACK_PATH_SOURCES.join(", ")
        )));
    }
    if !body.nodes.is_array() || !body.edges.is_array() {
        return Err(AppError::BadRequest(
            "nodes and edges must be JSON arrays".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await?;

    // Replace the prior graph for this (org, target, source) — re-runs refresh.
    // IS NOT DISTINCT FROM handles the nullable target_id (org-wide graphs).
    sqlx::query(
        "DELETE FROM attack_path_graphs
         WHERE org_id = $1 AND target_id IS NOT DISTINCT FROM $2 AND source = $3",
    )
    .bind(&org_id)
    .bind(&body.target_id)
    .bind(&body.source)
    .execute(&mut *tx)
    .await?;

    let id = Uuid::new_v4().to_string();
    let row: AttackPathGraphRow = sqlx::query_as(
        r#"INSERT INTO attack_path_graphs
              (id, org_id, target_id, assessment_id, source, label, nodes, edges,
               created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
           RETURNING id, org_id, target_id, assessment_id, source, label,
                     nodes, edges, created_at, updated_at"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&body.target_id)
    .bind(&body.assessment_id)
    .bind(&body.source)
    .bind(&body.label)
    .bind(&body.nodes)
    .bind(&body.edges)
    .fetch_one(&mut *tx)
    .await?;

    // Dual-write into the normalized substrate (migration 0046) within the SAME
    // tx, so the snapshot and the accumulating union are atomic. This is the
    // agent-ingest path: every kind must already be registered (built-in or via
    // /graph/kinds) — an unregistered kind rolls back the whole ingest.
    let nodes: Vec<NodeInput> = serde_json::from_value(body.nodes.clone())
        .map_err(|e| AppError::BadRequest(format!("invalid nodes: {e}")))?;
    let edges: Vec<EdgeInput> = serde_json::from_value(body.edges.clone())
        .map_err(|e| AppError::BadRequest(format!("invalid edges: {e}")))?;

    let mut used: HashSet<String> = nodes.iter().map(|n| n.kind.clone()).collect();
    used.extend(edges.iter().map(|e| e.kind_or_default()));
    validate_kinds(&mut tx, &org_id, &used).await?;

    let aid = body.assessment_id.as_deref();
    let tid = body.target_id.as_deref();
    for n in &nodes {
        accumulate_node(&mut tx, &org_id, n, &body.source, aid, tid).await?;
    }
    for e in &edges {
        accumulate_edge(&mut tx, &org_id, e, &body.source, aid, tid).await?;
    }

    tx.commit().await?;

    Ok((StatusCode::OK, Json(GraphView::from(&row))))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    target_id: Option<String>,
}

async fn list_graphs(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<GraphView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // With a target filter: that target's graphs PLUS org-wide (target_id NULL)
    // graphs. Without: everything for the org.
    let rows: Vec<AttackPathGraphRow> = match q.target_id {
        Some(tid) => {
            sqlx::query_as(
                r#"SELECT id, org_id, target_id, assessment_id, source, label,
                          nodes, edges, created_at, updated_at
                   FROM attack_path_graphs
                   WHERE org_id = $1 AND (target_id = $2 OR target_id IS NULL)
                   ORDER BY created_at DESC"#,
            )
            .bind(&org_id)
            .bind(&tid)
            .fetch_all(&state.pool)
            .await?
        }
        None => {
            sqlx::query_as(
                r#"SELECT id, org_id, target_id, assessment_id, source, label,
                          nodes, edges, created_at, updated_at
                   FROM attack_path_graphs
                   WHERE org_id = $1
                   ORDER BY created_at DESC"#,
            )
            .bind(&org_id)
            .fetch_all(&state.pool)
            .await?
        }
    };

    Ok(Json(rows.iter().map(GraphView::from).collect()))
}
