//! Attack-graph substrate rows (migration 0046) — the normalized, accumulating
//! node/edge union underneath the `attack_path_graphs` JSONB snapshot.
//!
//! `graph_kinds` is the kind registry (the OpenGraph analog: built-in + per-org
//! custom node/edge kinds, with display + goal metadata). `graph_nodes` /
//! `graph_edges` are the union, keyed (org_id, node_key) / (org_id, src, dst,
//! kind) — cross-target by design so lateral-movement paths emerge.
//!
//! Runtime sqlx (no compile-time macros) — these mirror models/attack_path.rs.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

/// Built-in kind sentinel: `org_id = ''` rows are global, visible to every org.
pub const BUILTIN_ORG: &str = "";

/// Default edge kind when an ingested edge omits one (matches the seed).
pub const DEFAULT_EDGE_KIND: &str = "leads_to";

#[derive(Debug, Clone, FromRow)]
pub struct GraphKindRow {
    pub org_id: String,
    pub kind: String,
    pub is_builtin: bool,
    pub is_edge: bool,
    pub is_goal: bool,
    pub label: String,
    pub display: JsonValue,
    pub schema: JsonValue,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct GraphNodeRow {
    pub org_id: String,
    pub node_key: String,
    pub kind: String,
    pub label: String,
    pub layer: i32,
    pub severity: Option<String>,
    pub sub: Option<String>,
    pub is_goal: Option<bool>,
    pub target_id: Option<String>,
    pub attrs: JsonValue,
    pub sources: Vec<String>,
    pub assessments: Vec<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct GraphEdgeRow {
    pub org_id: String,
    pub src_key: String,
    pub dst_key: String,
    pub kind: String,
    pub exploited: bool,
    pub target_id: Option<String>,
    pub attrs: JsonValue,
    pub sources: Vec<String>,
    pub assessments: Vec<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}
