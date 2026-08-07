//! The post-exploitation foothold / loot store (migration 0048).
//!
//! An assessment-scoped record of acquired access the post-exploit-operator
//! deposits on acquire and operates through on later steps. Runtime sqlx (no
//! compile-time macros) — mirrors models/graph.rs.

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;
use sqlx::FromRow;

/// Foothold kinds the operator can hold + operate through.
pub const FOOTHOLD_KINDS: &[&str] = &["session", "token", "credential", "assumed_role", "shell"];

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FootholdRow {
    pub id: String,
    pub org_id: String,
    pub assessment_id: String,
    pub kind: String,
    pub target: String,
    pub material: JsonValue,
    pub grants: Vec<String>,
    pub how_acquired: Option<String>,
    pub node_key: Option<String>,
    pub status: String,
    pub established_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub evidence_ref: Option<String>,
}
