//! `cloud_assets` + `asset_reachability` rows (W2-B of the cloud build plan).
//!
//! Durable substrate for the reachability-correlation layer. Populated at
//! end-of-run by the MCP `promote_cloud_inventory` tool (Shape A promotion,
//! same transport as `complete_assessment`). Joined against `findings` (Trivy
//! CVEs) by the W2-C correlation to surface "deployed + reachable + vulnerable".
//!
//! Migration: `migrations/0024_cloud_inventory.sql`.
//! Per-(org, target) scoped exactly like `recon_cache_entries` (0022).

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

/// Mirror of the PostgreSQL `cloudresourcetype` enum (migration 0024). Held as
/// TEXT in Rust; the route casts on bind with `::cloudresourcetype` and validates
/// the inbound value against this set.
pub const CLOUD_RESOURCE_TYPES: &[&str] =
    &["ecs_service", "lambda_function", "ecr_image", "load_balancer"];

/// Mirror of the PostgreSQL `exposurekind` enum (migration 0024).
pub const EXPOSURE_KINDS: &[&str] = &["alb", "nlb", "function_url", "public_ip", "api_gateway"];

#[derive(Debug, Clone, FromRow)]
pub struct CloudAssetRow {
    pub id: String,
    pub org_id: String,
    pub target_id: String,
    pub assessment_id: Option<String>,
    pub resource_type: String,
    pub resource_arn: String,
    pub name: Option<String>,
    pub region: Option<String>,
    pub image_refs: JsonValue,
    pub image_digests: JsonValue,
    pub exposed: bool,
    pub exposure_ids: JsonValue,
    pub metadata: JsonValue,
    pub observed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AssetReachabilityRow {
    pub id: String,
    pub org_id: String,
    pub target_id: String,
    pub assessment_id: Option<String>,
    pub exposed_via: String,
    pub endpoint: Option<String>,
    pub internet_facing: bool,
    pub source: String,
    pub target_resource_arns: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
