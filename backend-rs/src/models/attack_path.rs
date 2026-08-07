//! `attack_path_graphs` row (migration 0027) — persisted escalation graphs
//! (PMapper IAM-privesc + chain-analysis chains) for the dashboard W5 widget.
//! nodes/edges are opaque JSONB in the frontend GraphNode/GraphEdge shape.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

/// Valid `source` values (the producers of an escalation graph).
pub const ATTACK_PATH_SOURCES: &[&str] = &["cloud-analysis", "chain-analysis", "reachability"];

#[derive(Debug, Clone, FromRow)]
pub struct AttackPathGraphRow {
    pub id: String,
    pub org_id: String,
    pub target_id: Option<String>,
    pub assessment_id: Option<String>,
    pub source: String,
    pub label: Option<String>,
    pub nodes: JsonValue,
    pub edges: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
