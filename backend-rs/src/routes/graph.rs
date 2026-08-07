//! `/graph/*` — the attack-graph substrate (migration 0046).
//!
//! The normalized, accumulating node/edge union underneath the
//! `attack_path_graphs` JSONB snapshot. Where `/cloud/attack-paths` stores one
//! opaque snapshot per producer (replaced on every re-run), this surface owns
//! the persistent union and the graph queries that snapshot can't answer:
//!
//!   GET    /graph/kinds                 — built-in + caller's custom kinds (FE styling)
//!   POST   /graph/kinds                 — register a custom node/edge kind bundle
//!   DELETE /graph/kinds/:kind           — drop a caller-owned custom kind
//!   GET    /graph/nodes?kind&target_id&q&limit
//!   GET    /graph/edges?src_key&dst_key&exploited&limit
//!   POST   /graph/ingest                — generic dual-write ingest (nodes/edges/kinds)
//!   POST   /graph/paths                 — recursive-CTE pathfinding / reachability
//!
//! Multi-tenant: every handler extracts `AuthUser.org_id` (403 if absent) and
//! every query/join is org-scoped. Built-in kinds live under the `''` sentinel
//! org and are visible to all. The recursive join in `/graph/paths` is the
//! highest cross-org-leakage-risk spot — it filters org_id on EVERY join and is
//! covered by a dedicated cross-org contract test.

use std::collections::HashSet;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::graph::{GraphEdgeRow, GraphKindRow, GraphNodeRow, DEFAULT_EDGE_KIND};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/graph/kinds", get(list_kinds).post(register_kinds))
        .route("/graph/kinds/:kind", delete(delete_kind))
        .route("/graph/nodes", get(list_nodes))
        .route("/graph/edges", get(list_edges))
        .route("/graph/ingest", post(ingest))
        .route("/graph/paths", post(find_paths))
}

fn require_org(user: &AuthUser) -> AppResult<String> {
    user.org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))
}

// =============================================================================
// Shared input shapes + accumulate-upsert helpers
//
// `pub(crate)` so the dual-write producers (attack_paths::ingest_graph and
// correlation::correlate_dast) accumulate into the same union with identical
// merge semantics.
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct NodeInput {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub kind: String,
    #[serde(default)]
    pub layer: Option<i32>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub is_goal: Option<bool>,
    #[serde(default)]
    pub attrs: Option<JsonValue>,
    /// Capabilities that landing on this node yields (loot pickup). Post-ex Layer A.
    #[serde(default)]
    pub grants: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EdgeInput {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub exploited: Option<bool>,
    #[serde(default)]
    pub attrs: Option<JsonValue>,
    /// Preconditions ⊆ held to traverse this edge (the planner's gate). Post-ex Layer A.
    #[serde(default)]
    pub requires: Option<Vec<String>>,
    /// Capabilities this action yields on success. Post-ex Layer A.
    #[serde(default)]
    pub grants: Option<Vec<String>>,
    /// Migration 0050: the finding whose oracle receipt backs this edge. Only a
    /// POINTER — the edge's verdict is derived by joining to that finding, so
    /// naming a finding here cannot make an unverified edge look verified.
    #[serde(default)]
    pub verified_by_finding_id: Option<String>,
}

impl EdgeInput {
    pub(crate) fn kind_or_default(&self) -> String {
        self.kind
            .clone()
            .filter(|k| !k.is_empty())
            .unwrap_or_else(|| DEFAULT_EDGE_KIND.to_string())
    }
}

/// Accumulate-upsert one node into the union. Re-ingests merge: sources /
/// assessments arrays union (deduped), attrs shallow-merge, last_seen advances,
/// mutable fields take the newest non-empty value.
pub(crate) async fn accumulate_node(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    n: &NodeInput,
    source: &str,
    assessment_id: Option<&str>,
    target_id: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO graph_nodes
              (org_id, node_key, kind, label, layer, severity, sub, is_goal,
               target_id, attrs, sources, assessments, grants, first_seen_at, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, COALESCE($10::jsonb,'{}'::jsonb),
                   ARRAY[$11]::text[],
                   CASE WHEN $12::text IS NULL THEN ARRAY[]::text[] ELSE ARRAY[$12] END,
                   COALESCE($13::text[], ARRAY[]::text[]),
                   NOW(), NOW())
           ON CONFLICT (org_id, node_key) DO UPDATE SET
               kind         = EXCLUDED.kind,
               label        = CASE WHEN EXCLUDED.label <> '' THEN EXCLUDED.label
                                   ELSE graph_nodes.label END,
               layer        = EXCLUDED.layer,
               severity     = COALESCE(EXCLUDED.severity, graph_nodes.severity),
               sub          = COALESCE(EXCLUDED.sub, graph_nodes.sub),
               is_goal      = COALESCE(EXCLUDED.is_goal, graph_nodes.is_goal),
               target_id    = COALESCE(EXCLUDED.target_id, graph_nodes.target_id),
               attrs        = graph_nodes.attrs || EXCLUDED.attrs,
               sources      = ARRAY(SELECT DISTINCT e
                                    FROM unnest(graph_nodes.sources || EXCLUDED.sources) AS e),
               assessments  = ARRAY(SELECT DISTINCT e
                                    FROM unnest(graph_nodes.assessments || EXCLUDED.assessments) AS e),
               grants       = ARRAY(SELECT DISTINCT g
                                    FROM unnest(graph_nodes.grants || EXCLUDED.grants) AS g),
               last_seen_at = NOW()"#,
    )
    .bind(org_id)
    .bind(&n.id)
    .bind(&n.kind)
    .bind(n.label.clone().unwrap_or_default())
    .bind(n.layer.unwrap_or(0))
    .bind(&n.severity)
    .bind(&n.sub)
    .bind(n.is_goal)
    .bind(target_id)
    .bind(&n.attrs)
    .bind(source)
    .bind(assessment_id)
    .bind(n.grants.clone().unwrap_or_default())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Accumulate-upsert one edge. `exploited` is sticky-true (once any run exploits
/// the edge it stays exploited); everything else merges like nodes.
pub(crate) async fn accumulate_edge(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    e: &EdgeInput,
    source: &str,
    assessment_id: Option<&str>,
    target_id: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"INSERT INTO graph_edges
              (org_id, src_key, dst_key, kind, exploited, target_id, attrs,
               sources, assessments, requires, grants, verified_by_finding_id,
               first_seen_at, last_seen_at)
           VALUES ($1,$2,$3,$4,$5,$6, COALESCE($7::jsonb,'{}'::jsonb),
                   ARRAY[$8]::text[],
                   CASE WHEN $9::text IS NULL THEN ARRAY[]::text[] ELSE ARRAY[$9] END,
                   COALESCE($10::text[], ARRAY[]::text[]),
                   COALESCE($11::text[], ARRAY[]::text[]),
                   $12,
                   NOW(), NOW())
           ON CONFLICT (org_id, src_key, dst_key, kind) DO UPDATE SET
               exploited    = graph_edges.exploited OR EXCLUDED.exploited,
               target_id    = COALESCE(EXCLUDED.target_id, graph_edges.target_id),
               attrs        = graph_edges.attrs || EXCLUDED.attrs,
               sources      = ARRAY(SELECT DISTINCT x
                                    FROM unnest(graph_edges.sources || EXCLUDED.sources) AS x),
               assessments  = ARRAY(SELECT DISTINCT x
                                    FROM unnest(graph_edges.assessments || EXCLUDED.assessments) AS x),
               requires     = ARRAY(SELECT DISTINCT r
                                    FROM unnest(graph_edges.requires || EXCLUDED.requires) AS r),
               grants       = ARRAY(SELECT DISTINCT g
                                    FROM unnest(graph_edges.grants || EXCLUDED.grants) AS g),
               verified_by_finding_id = COALESCE(EXCLUDED.verified_by_finding_id,
                                                 graph_edges.verified_by_finding_id),
               last_seen_at = NOW()"#,
    )
    .bind(org_id)
    .bind(&e.from)
    .bind(&e.to)
    .bind(e.kind_or_default())
    .bind(e.exploited.unwrap_or(false))
    .bind(target_id)
    .bind(&e.attrs)
    .bind(source)
    .bind(assessment_id)
    .bind(e.requires.clone().unwrap_or_default())
    .bind(e.grants.clone().unwrap_or_default())
    .bind(&e.verified_by_finding_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The kinds known to an org: built-ins (`''`) + the org's own custom kinds.
async fn known_kinds(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
) -> AppResult<HashSet<String>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT kind FROM graph_kinds WHERE org_id IN ($1, '')")
            .bind(org_id)
            .fetch_all(&mut **tx)
            .await?;
    Ok(rows.into_iter().map(|(k,)| k).collect())
}

/// Reject any kind not in the registry. Used by agent-driven ingest paths so a
/// typo'd / unregistered kind fails loudly instead of polluting the union.
pub(crate) async fn validate_kinds(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    kinds: &HashSet<String>,
) -> AppResult<()> {
    if kinds.is_empty() {
        return Ok(());
    }
    let known = known_kinds(tx, org_id).await?;
    let mut unknown: Vec<&str> = kinds
        .iter()
        .filter(|k| !known.contains(*k))
        .map(|s| s.as_str())
        .collect();
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(AppError::BadRequest(format!(
            "Unknown graph kind(s): {}. Register them via POST /graph/kinds, \
             or pass auto_register=true.",
            unknown.join(", ")
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KindInput {
    pub kind: String,
    #[serde(default)]
    pub is_edge: bool,
    #[serde(default)]
    pub is_goal: bool,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub display: Option<JsonValue>,
    #[serde(default)]
    pub schema: Option<JsonValue>,
}

/// Register (upsert) one custom kind for an org. Rejects any name that collides
/// with a built-in — the extension registry can extend the graph, never shadow
/// the core kinds the producers + FE depend on.
async fn upsert_custom_kind(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    k: &KindInput,
) -> AppResult<()> {
    if k.kind.is_empty() {
        return Err(AppError::BadRequest("kind name must be non-empty".into()));
    }
    let collides: Vec<(i32,)> =
        sqlx::query_as("SELECT 1 FROM graph_kinds WHERE kind = $1 AND is_builtin = TRUE")
            .bind(&k.kind)
            .fetch_all(&mut **tx)
            .await?;
    if !collides.is_empty() {
        return Err(AppError::BadRequest(format!(
            "'{}' is a built-in kind and cannot be redefined.",
            k.kind
        )));
    }
    sqlx::query(
        r#"INSERT INTO graph_kinds
              (org_id, kind, is_builtin, is_edge, is_goal, label, display, schema)
           VALUES ($1,$2,FALSE,$3,$4,$5, COALESCE($6::jsonb,'{}'::jsonb), COALESCE($7::jsonb,'{}'::jsonb))
           ON CONFLICT (org_id, kind) DO UPDATE SET
               is_edge = EXCLUDED.is_edge,
               is_goal = EXCLUDED.is_goal,
               label   = EXCLUDED.label,
               display = EXCLUDED.display,
               schema  = EXCLUDED.schema"#,
    )
    .bind(org_id)
    .bind(&k.kind)
    .bind(k.is_edge)
    .bind(k.is_goal)
    .bind(k.label.clone().unwrap_or_else(|| k.kind.clone()))
    .bind(&k.display)
    .bind(&k.schema)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// =============================================================================
// Views
// =============================================================================

#[derive(Debug, Serialize)]
struct KindView {
    kind: String,
    is_builtin: bool,
    is_edge: bool,
    is_goal: bool,
    label: String,
    display: JsonValue,
    schema: JsonValue,
}

impl From<&GraphKindRow> for KindView {
    fn from(k: &GraphKindRow) -> Self {
        Self {
            kind: k.kind.clone(),
            is_builtin: k.is_builtin,
            is_edge: k.is_edge,
            is_goal: k.is_goal,
            label: k.label.clone(),
            display: k.display.clone(),
            schema: k.schema.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct NodeView {
    /// The GraphNode.id — `id` to match the FE shape; `node_key` in storage.
    id: String,
    kind: String,
    label: String,
    layer: i32,
    severity: Option<String>,
    sub: Option<String>,
    is_goal: Option<bool>,
    target_id: Option<String>,
    attrs: JsonValue,
    sources: Vec<String>,
    assessments: Vec<String>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
}

impl From<&GraphNodeRow> for NodeView {
    fn from(n: &GraphNodeRow) -> Self {
        Self {
            id: n.node_key.clone(),
            kind: n.kind.clone(),
            label: n.label.clone(),
            layer: n.layer,
            severity: n.severity.clone(),
            sub: n.sub.clone(),
            is_goal: n.is_goal,
            target_id: n.target_id.clone(),
            attrs: n.attrs.clone(),
            sources: n.sources.clone(),
            assessments: n.assessments.clone(),
            last_seen_at: n.last_seen_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct EdgeView {
    from: String,
    to: String,
    kind: String,
    exploited: bool,
    target_id: Option<String>,
    sources: Vec<String>,
    assessments: Vec<String>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
}

impl From<&GraphEdgeRow> for EdgeView {
    fn from(e: &GraphEdgeRow) -> Self {
        Self {
            from: e.src_key.clone(),
            to: e.dst_key.clone(),
            kind: e.kind.clone(),
            exploited: e.exploited,
            target_id: e.target_id.clone(),
            sources: e.sources.clone(),
            assessments: e.assessments.clone(),
            last_seen_at: e.last_seen_at,
        }
    }
}

// =============================================================================
// GET /graph/kinds — built-ins + caller's custom kinds
// =============================================================================

async fn list_kinds(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<KindView>>> {
    let org_id = require_org(&user)?;
    let rows: Vec<GraphKindRow> = sqlx::query_as(
        r#"SELECT org_id, kind, is_builtin, is_edge, is_goal, label, display, schema, created_at
           FROM graph_kinds
           WHERE org_id IN ($1, '')
           ORDER BY is_builtin DESC, kind"#,
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows.iter().map(KindView::from).collect()))
}

// =============================================================================
// POST /graph/kinds — register an extension bundle (node + edge kinds)
// =============================================================================

/// Accepts either a bundle `{ "kinds": [...] }` or a bare single kind
/// `{ "kind": "...", ... }`. Untagged so the MCP `register_graph_kinds` tool can
/// pass an extension bundle straight through.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegisterKindsBody {
    Bundle { kinds: Vec<KindInput> },
    Single(KindInput),
}

async fn register_kinds(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<RegisterKindsBody>,
) -> AppResult<(StatusCode, Json<Vec<KindView>>)> {
    let org_id = require_org(&user)?;

    let to_register = match body {
        RegisterKindsBody::Bundle { kinds } => kinds,
        RegisterKindsBody::Single(k) => vec![k],
    };
    if to_register.is_empty() {
        return Err(AppError::BadRequest(
            "Provide a `kind` or a `kinds` array to register.".into(),
        ));
    }

    let mut tx = state.pool.begin().await?;
    for k in &to_register {
        upsert_custom_kind(&mut tx, &org_id, k).await?;
    }
    tx.commit().await?;

    // Return the org's full custom set so the FE can refresh its style map.
    let names: Vec<String> = to_register.iter().map(|k| k.kind.clone()).collect();
    let rows: Vec<GraphKindRow> = sqlx::query_as(
        r#"SELECT org_id, kind, is_builtin, is_edge, is_goal, label, display, schema, created_at
           FROM graph_kinds WHERE org_id = $1 AND kind = ANY($2)"#,
    )
    .bind(&org_id)
    .bind(&names)
    .fetch_all(&state.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(rows.iter().map(KindView::from).collect())))
}

// =============================================================================
// DELETE /graph/kinds/:kind — drop a caller-owned custom kind
// =============================================================================

async fn delete_kind(
    State(state): State<AppState>,
    user: AuthUser,
    Path(kind): Path<String>,
) -> AppResult<StatusCode> {
    let org_id = require_org(&user)?;
    let res = sqlx::query(
        "DELETE FROM graph_kinds WHERE org_id = $1 AND kind = $2 AND is_builtin = FALSE",
    )
    .bind(&org_id)
    .bind(&kind)
    .execute(&state.pool)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "No custom kind '{kind}' for this org (built-ins cannot be deleted)."
        )));
    }
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// GET /graph/nodes — paged, org-scoped node listing
// =============================================================================

fn clamp_limit(v: Option<i64>, default: i64, max: i64) -> i64 {
    v.unwrap_or(default).clamp(1, max)
}

#[derive(Debug, Deserialize)]
struct NodeQuery {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    target_id: Option<String>,
    /// ILIKE match on label or node_key.
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_nodes(
    State(state): State<AppState>,
    Query(q): Query<NodeQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<NodeView>>> {
    let org_id = require_org(&user)?;
    let limit = clamp_limit(q.limit, 200, 2000);
    let like = q.q.as_ref().map(|s| format!("%{s}%"));
    let rows: Vec<GraphNodeRow> = sqlx::query_as(
        r#"SELECT org_id, node_key, kind, label, layer, severity, sub, is_goal,
                  target_id, attrs, sources, assessments, first_seen_at, last_seen_at
           FROM graph_nodes
           WHERE org_id = $1
             AND ($2::text IS NULL OR kind = $2)
             AND ($3::text IS NULL OR target_id = $3)
             AND ($4::text IS NULL OR label ILIKE $4 OR node_key ILIKE $4)
           ORDER BY last_seen_at DESC
           LIMIT $5"#,
    )
    .bind(&org_id)
    .bind(&q.kind)
    .bind(&q.target_id)
    .bind(&like)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows.iter().map(NodeView::from).collect()))
}

// =============================================================================
// GET /graph/edges — paged, org-scoped edge listing
// =============================================================================

#[derive(Debug, Deserialize)]
struct EdgeQuery {
    #[serde(default)]
    src_key: Option<String>,
    #[serde(default)]
    dst_key: Option<String>,
    #[serde(default)]
    exploited: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn list_edges(
    State(state): State<AppState>,
    Query(q): Query<EdgeQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<EdgeView>>> {
    let org_id = require_org(&user)?;
    let limit = clamp_limit(q.limit, 500, 5000);
    let rows: Vec<GraphEdgeRow> = sqlx::query_as(
        r#"SELECT org_id, src_key, dst_key, kind, exploited, target_id, attrs,
                  sources, assessments, first_seen_at, last_seen_at
           FROM graph_edges
           WHERE org_id = $1
             AND ($2::text IS NULL OR src_key = $2)
             AND ($3::text IS NULL OR dst_key = $3)
             AND ($4::bool IS NULL OR exploited = $4)
           ORDER BY last_seen_at DESC
           LIMIT $5"#,
    )
    .bind(&org_id)
    .bind(&q.src_key)
    .bind(&q.dst_key)
    .bind(q.exploited)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows.iter().map(EdgeView::from).collect()))
}

// =============================================================================
// POST /graph/ingest — generic dual-write ingest (the successor to record_attack_paths)
// =============================================================================

#[derive(Debug, Deserialize)]
struct IngestBody {
    source: String,
    #[serde(default)]
    target_id: Option<String>,
    #[serde(default)]
    assessment_id: Option<String>,
    #[serde(default)]
    nodes: Vec<NodeInput>,
    #[serde(default)]
    edges: Vec<EdgeInput>,
    /// Custom kinds referenced by the nodes/edges, registered before ingest.
    #[serde(default)]
    kinds: Vec<KindInput>,
    /// When true, any node/edge kind not in the registry is auto-registered as a
    /// minimal custom kind instead of being rejected.
    #[serde(default)]
    auto_register: bool,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    nodes: usize,
    edges: usize,
    kinds_registered: usize,
}

async fn ingest(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<IngestBody>,
) -> AppResult<(StatusCode, Json<IngestResponse>)> {
    let org_id = require_org(&user)?;
    if body.source.trim().is_empty() {
        return Err(AppError::BadRequest("source is required".into()));
    }

    let mut tx = state.pool.begin().await?;

    // 1. Explicit kind registrations first.
    for k in &body.kinds {
        upsert_custom_kind(&mut tx, &org_id, k).await?;
    }

    // 2. Resolve the kinds the payload uses; reject or auto-register unknowns.
    let mut used: HashSet<String> = body.nodes.iter().map(|n| n.kind.clone()).collect();
    let edge_kinds: HashSet<String> = body.edges.iter().map(|e| e.kind_or_default()).collect();
    used.extend(edge_kinds.iter().cloned());

    if body.auto_register {
        let known = known_kinds(&mut tx, &org_id).await?;
        for n in &body.nodes {
            if !known.contains(&n.kind) {
                upsert_custom_kind(
                    &mut tx,
                    &org_id,
                    &KindInput {
                        kind: n.kind.clone(),
                        is_edge: false,
                        is_goal: false,
                        label: None,
                        display: None,
                        schema: None,
                    },
                )
                .await?;
            }
        }
        for ek in &edge_kinds {
            if !known.contains(ek) {
                upsert_custom_kind(
                    &mut tx,
                    &org_id,
                    &KindInput {
                        kind: ek.clone(),
                        is_edge: true,
                        is_goal: false,
                        label: None,
                        display: None,
                        schema: None,
                    },
                )
                .await?;
            }
        }
    } else {
        validate_kinds(&mut tx, &org_id, &used).await?;
    }

    // 3. Accumulate.
    let aid = body.assessment_id.as_deref();
    let tid = body.target_id.as_deref();
    for n in &body.nodes {
        accumulate_node(&mut tx, &org_id, n, &body.source, aid, tid).await?;
    }
    for e in &body.edges {
        accumulate_edge(&mut tx, &org_id, e, &body.source, aid, tid).await?;
    }

    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(IngestResponse {
            nodes: body.nodes.len(),
            edges: body.edges.len(),
            kinds_registered: body.kinds.len(),
        }),
    ))
}

// =============================================================================
// POST /graph/paths — recursive-CTE pathfinding + reachability
// =============================================================================

#[derive(Debug, Deserialize)]
struct PathsBody {
    #[serde(default)]
    source_kind: Option<String>,
    #[serde(default)]
    source_keys: Option<Vec<String>>,
    #[serde(default)]
    goal_kind: Option<String>,
    #[serde(default = "default_max_depth")]
    max_depth: i32,
    #[serde(default)]
    exploited_only: bool,
    /// Post-ex Layer B: capabilities the attacker starts holding at every entry node
    /// (the seed frontier). Empty/absent → plain reachability (every edge traverses).
    #[serde(default)]
    seed_caps: Option<Vec<String>>,
    /// Post-ex Layer B: goal reached when these capabilities are all held (⊆ held), in
    /// addition to is_goal nodes / goal_kind. Empty/absent → goal = is_goal / goal_kind only.
    #[serde(default)]
    goal_caps: Option<Vec<String>>,
    #[serde(default = "default_path_limit")]
    limit: i64,
    /// Reachability-only: return distinct reachable goals (near-linear), no path
    /// enumeration — answers "can X reach a crown jewel?" without the blowup.
    #[serde(default)]
    reachable_only: bool,
    /// Migration 0050: restrict traversal to edges whose backing finding an oracle
    /// actually re-proved. `exploited_only` asks "did a run walk this?";
    /// `verified_only` asks "was each step re-proven?" — the difference between a
    /// path an agent reported and one a customer can replay end to end.
    #[serde(default)]
    verified_only: bool,
}

fn default_max_depth() -> i32 {
    6
}
fn default_path_limit() -> i64 {
    500
}

#[derive(Debug, sqlx::FromRow)]
struct PathRow {
    start_key: String,
    path: Vec<String>,
    edges: JsonValue,
    depth: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct ReachableRow {
    goal_key: String,
    kind: String,
    reached_from: Vec<String>,
}

// The base/recursive term shared by both modes. Params:
//   $1 org   $2 source_keys(text[]?)  $3 source_kind(text?)  $4 goal_kind(text?)
//   $5 max_depth(int)  $6 exploited_only(bool)  $8 seed_caps(text[]?)  $9 goal_caps(text[]?)
//   $10 verified_only(bool)
//   ($7 is the outer LIMIT, bound in find_paths.)
//
// Post-ex Layer B (capability-gated planning): `held` accumulates the attacker's
// capabilities along a path — seed_caps ∪ start.grants at the base, then ∪ edge.grants
// ∪ dst.grants on each hop. An edge traverses only if `e.requires <@ held` (requires ⊆
// held). BACKWARD-COMPATIBLE: with no seed_caps and the migration-0047 default-empty
// requires/grants, held = '{}' and `'{}' <@ '{}'` is TRUE for every edge, so plain
// reachability is preserved exactly; gating only bites once an edge has non-empty
// `requires`. goal_caps (when non-empty) reaches goal when ⊆ held, alongside is_goal /
// goal_kind. held is COALESCE'd to '{}' so it is never NULL (a NULL would silently kill
// the `<@` gate and break traversal). See docs/RFC-POST-EXPLOITATION-LAYER.md §5.
//
// Mandatory guards: cycle guard (visited `path` array), depth cap, stop-at-goal.
// Every join is org-scoped. graph_kinds joins the org's kinds + built-ins ('').
const WALK_CTE: &str = r#"
WITH RECURSIVE walk AS (
    SELECT
        n.node_key AS start_key,
        n.node_key AS cur,
        n.kind     AS cur_kind,
        ARRAY[n.node_key] AS path,
        '[]'::jsonb AS edges,
        0 AS depth,
        COALESCE((SELECT array_agg(DISTINCT x) FROM unnest(
            COALESCE($8::text[], ARRAY[]::text[]) || COALESCE(n.grants, ARRAY[]::text[])) AS x),
            ARRAY[]::text[]) AS held,
        (CASE WHEN $4::text IS NOT NULL THEN (n.kind = $4)
              ELSE COALESCE(n.is_goal, k.is_goal, FALSE) END
         OR ($9::text[] IS NOT NULL AND cardinality($9::text[]) > 0 AND $9::text[] <@
             COALESCE((SELECT array_agg(DISTINCT x) FROM unnest(
                 COALESCE($8::text[], ARRAY[]::text[]) || COALESCE(n.grants, ARRAY[]::text[])) AS x),
                 ARRAY[]::text[]))) AS at_goal
    FROM graph_nodes n
    LEFT JOIN graph_kinds k ON k.kind = n.kind AND k.org_id IN ($1, '')
    WHERE n.org_id = $1
      AND ($2::text[] IS NULL OR n.node_key = ANY($2::text[]))
      AND ($3::text   IS NULL OR n.kind = $3)
      AND ($2::text[] IS NOT NULL OR $3::text IS NOT NULL OR n.kind = 'source')

    UNION ALL

    SELECT
        w.start_key,
        e.dst_key,
        COALESCE(dn.kind, ''),
        w.path || e.dst_key,
        w.edges || jsonb_build_array(jsonb_build_object(
            'from', e.src_key, 'to', e.dst_key, 'kind', e.kind, 'exploited', e.exploited,
            -- Derived, never stored (migration 0050): an edge is verified iff the
            -- finding backing it earned a verdict from an oracle. `exploited`
            -- says a run walked it; `verdict` says a machine re-proved it.
            'verdict', CASE WHEN vf.verdict = 'verified' THEN 'verified' ELSE 'candidate' END,
            'verified_by', e.verified_by_finding_id,
            'oracle_kind', vf.oracle_kind)),
        w.depth + 1,
        COALESCE((SELECT array_agg(DISTINCT x) FROM unnest(
            w.held || COALESCE(e.grants, ARRAY[]::text[]) || COALESCE(dn.grants, ARRAY[]::text[])) AS x),
            ARRAY[]::text[]) AS held,
        (CASE WHEN $4::text IS NOT NULL THEN (dn.kind = $4)
              ELSE COALESCE(dn.is_goal, dk.is_goal, FALSE) END
         OR ($9::text[] IS NOT NULL AND cardinality($9::text[]) > 0 AND $9::text[] <@
             COALESCE((SELECT array_agg(DISTINCT x) FROM unnest(
                 w.held || COALESCE(e.grants, ARRAY[]::text[]) || COALESCE(dn.grants, ARRAY[]::text[])) AS x),
                 ARRAY[]::text[]))) AS at_goal
    FROM walk w
    JOIN graph_edges e ON e.org_id = $1 AND e.src_key = w.cur
    LEFT JOIN graph_nodes dn ON dn.org_id = $1 AND dn.node_key = e.dst_key
    LEFT JOIN graph_kinds dk ON dk.kind = dn.kind AND dk.org_id IN ($1, '')
    LEFT JOIN findings vf ON vf.id = e.verified_by_finding_id AND vf.org_id = $1
    WHERE w.depth < $5
      AND NOT w.at_goal
      AND NOT (e.dst_key = ANY(w.path))
      AND (NOT $6::bool OR e.exploited)
      -- verified_only ($10): every edge on the path must be backed by a finding
      -- an oracle actually re-proved. This is the difference between "an agent
      -- says this path is walkable" and "each step of this path has a replay
      -- capsule a customer can run".
      AND (NOT $10::bool OR vf.verdict = 'verified')
      AND e.requires <@ w.held
)
"#;

async fn find_paths(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<PathsBody>,
) -> AppResult<Json<JsonValue>> {
    let org_id = require_org(&user)?;
    let max_depth = body.max_depth.clamp(1, 12);
    let limit = body.limit.clamp(1, 5000);
    // Fetch one extra row to detect truncation.
    let fetch = limit + 1;

    // statement_timeout caps the blast radius of a pathological / cyclic graph
    // even with the cycle guard — wrapped in a tx so SET LOCAL is scoped.
    let mut tx = state.pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut *tx)
        .await?;

    let resp = if body.reachable_only {
        let sql = format!(
            "{WALK_CTE}
             SELECT cur AS goal_key, cur_kind AS kind, array_agg(DISTINCT start_key) AS reached_from
             FROM walk
             WHERE at_goal
             GROUP BY cur, cur_kind
             LIMIT $7"
        );
        let rows: Vec<ReachableRow> = sqlx::query_as(&sql)
            .bind(&org_id)
            .bind(&body.source_keys)
            .bind(&body.source_kind)
            .bind(&body.goal_kind)
            .bind(max_depth)
            .bind(body.exploited_only)
            .bind(fetch)
            .bind(&body.seed_caps)
            .bind(&body.goal_caps)
            .bind(body.verified_only)
            .fetch_all(&mut *tx)
            .await?;
        let truncated = rows.len() as i64 > limit;
        let reachable: Vec<JsonValue> = rows
            .iter()
            .take(limit as usize)
            .map(|r| json!({ "goal_key": r.goal_key, "kind": r.kind, "reached_from": r.reached_from }))
            .collect();
        json!({ "reachable": reachable, "truncated": truncated })
    } else {
        let sql = format!(
            "{WALK_CTE}
             SELECT start_key, path, edges, depth
             FROM walk
             WHERE at_goal
             ORDER BY depth ASC, start_key
             LIMIT $7"
        );
        let rows: Vec<PathRow> = sqlx::query_as(&sql)
            .bind(&org_id)
            .bind(&body.source_keys)
            .bind(&body.source_kind)
            .bind(&body.goal_kind)
            .bind(max_depth)
            .bind(body.exploited_only)
            .bind(fetch)
            .bind(&body.seed_caps)
            .bind(&body.goal_caps)
            .bind(body.verified_only)
            .fetch_all(&mut *tx)
            .await?;
        let truncated = rows.len() as i64 > limit;
        let paths: Vec<JsonValue> = rows
            .iter()
            .take(limit as usize)
            .map(|r| json!({
                "start_key": r.start_key,
                "nodes": r.path,
                "edges": r.edges,
                "depth": r.depth,
            }))
            .collect();
        json!({ "paths": paths, "truncated": truncated })
    };

    tx.commit().await?;
    Ok(Json(resp))
}
