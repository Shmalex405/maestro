//! `/org-settings` — per-org cache configuration knobs.
//!
//! Phase 6 of the caching plan.
//!
//! Endpoints:
//!   GET  /org-settings   — read (auto-creates a default row if missing)
//!   PUT  /org-settings   — update; accepts partial body (any field can be omitted)
//!
//! Auth: per-org via JWT `custom:org_id`. The endpoint always operates
//! on the caller's own org — there's no path parameter, no cross-org
//! lookup, no admin escape hatch. If a customer needs to view another
//! org's settings (e.g., MSP scenario), that goes through a separate
//! admin endpoint not yet built.

use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::org_settings::OrgSettings;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/org-settings", get(read).put(update))
}

#[derive(Debug, Serialize)]
struct OrgSettingsResponse {
    org_id: String,
    caching_enabled: bool,
    full_revalidation_interval: i32,
    sast_cache_ttl_days: i32,
    recon_cache_ttl_days: i32,
    baseline_max_age_days: i32,
    drift_alert_threshold: i32,
    // DAST triage SLA + auto-escalate (migration 0036).
    sla_critical_days: i32,
    sla_high_days: i32,
    sla_medium_days: i32,
    sla_low_days: i32,
    dast_auto_escalate_enabled: bool,
    dast_auto_escalate_severities: String,
    dast_webhook_url: Option<String>,
}

impl From<&OrgSettings> for OrgSettingsResponse {
    fn from(s: &OrgSettings) -> Self {
        Self {
            org_id: s.org_id.clone(),
            caching_enabled: s.caching_enabled,
            full_revalidation_interval: s.full_revalidation_interval,
            sast_cache_ttl_days: s.sast_cache_ttl_days,
            recon_cache_ttl_days: s.recon_cache_ttl_days,
            baseline_max_age_days: s.baseline_max_age_days,
            drift_alert_threshold: s.drift_alert_threshold,
            sla_critical_days: s.sla_critical_days,
            sla_high_days: s.sla_high_days,
            sla_medium_days: s.sla_medium_days,
            sla_low_days: s.sla_low_days,
            dast_auto_escalate_enabled: s.dast_auto_escalate_enabled,
            dast_auto_escalate_severities: s.dast_auto_escalate_severities.clone(),
            dast_webhook_url: s.dast_webhook_url.clone(),
        }
    }
}

async fn read(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<OrgSettingsResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Bootstrap a default row if missing. The migration already inserts
    // a default for every org that had findings at migration time, but
    // brand-new orgs (signed up after the migration) need this path.
    let row: OrgSettings = sqlx::query_as(
        r#"INSERT INTO org_settings (org_id) VALUES ($1)
           ON CONFLICT (org_id) DO UPDATE SET updated_at = org_settings.updated_at
           RETURNING *"#,
    )
    .bind(&org_id)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(OrgSettingsResponse::from(&row)))
}

/// Partial-update body — every field is optional. NULL = leave unchanged.
#[derive(Debug, Deserialize)]
struct UpdateBody {
    #[serde(default)]
    caching_enabled: Option<bool>,
    #[serde(default)]
    full_revalidation_interval: Option<i32>,
    #[serde(default)]
    sast_cache_ttl_days: Option<i32>,
    #[serde(default)]
    recon_cache_ttl_days: Option<i32>,
    #[serde(default)]
    baseline_max_age_days: Option<i32>,
    #[serde(default)]
    drift_alert_threshold: Option<i32>,
    // DAST triage SLA + auto-escalate (migration 0036).
    #[serde(default)]
    sla_critical_days: Option<i32>,
    #[serde(default)]
    sla_high_days: Option<i32>,
    #[serde(default)]
    sla_medium_days: Option<i32>,
    #[serde(default)]
    sla_low_days: Option<i32>,
    #[serde(default)]
    dast_auto_escalate_enabled: Option<bool>,
    #[serde(default)]
    dast_auto_escalate_severities: Option<String>,
    #[serde(default)]
    dast_webhook_url: Option<String>,
}

async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<UpdateBody>,
) -> AppResult<Json<OrgSettingsResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Validate inputs against the CHECK constraints in the migration so
    // we get a clean 400 instead of a 500 with a PG constraint violation.
    if let Some(v) = req.full_revalidation_interval {
        if v < 0 {
            return Err(AppError::BadRequest(
                "full_revalidation_interval must be >= 0".into(),
            ));
        }
    }
    for (name, val) in [
        ("sast_cache_ttl_days", req.sast_cache_ttl_days),
        ("recon_cache_ttl_days", req.recon_cache_ttl_days),
        ("baseline_max_age_days", req.baseline_max_age_days),
        ("drift_alert_threshold", req.drift_alert_threshold),
        ("sla_critical_days", req.sla_critical_days),
        ("sla_high_days", req.sla_high_days),
        ("sla_medium_days", req.sla_medium_days),
        ("sla_low_days", req.sla_low_days),
    ] {
        if let Some(v) = val {
            if v <= 0 {
                return Err(AppError::BadRequest(format!("{} must be > 0", name)));
            }
        }
    }

    // COALESCE pattern: keep existing value when the request omitted the
    // field. This makes partial updates trivial without a read-modify-write.
    let row: OrgSettings = sqlx::query_as(
        r#"INSERT INTO org_settings (
              org_id,
              caching_enabled,
              full_revalidation_interval,
              sast_cache_ttl_days,
              recon_cache_ttl_days,
              baseline_max_age_days,
              drift_alert_threshold,
              sla_critical_days,
              sla_high_days,
              sla_medium_days,
              sla_low_days,
              dast_auto_escalate_enabled,
              dast_auto_escalate_severities,
              dast_webhook_url
           )
           VALUES (
              $1,
              COALESCE($2, true),
              COALESCE($3, 4),
              COALESCE($4, 30),
              COALESCE($5, 7),
              COALESCE($6, 30),
              COALESCE($7, 3),
              COALESCE($8, 7),
              COALESCE($9, 14),
              COALESCE($10, 30),
              COALESCE($11, 90),
              COALESCE($12, false),
              COALESCE($13, 'critical,high'),
              $14
           )
           ON CONFLICT (org_id) DO UPDATE SET
               caching_enabled            = COALESCE($2, org_settings.caching_enabled),
               full_revalidation_interval = COALESCE($3, org_settings.full_revalidation_interval),
               sast_cache_ttl_days        = COALESCE($4, org_settings.sast_cache_ttl_days),
               recon_cache_ttl_days       = COALESCE($5, org_settings.recon_cache_ttl_days),
               baseline_max_age_days      = COALESCE($6, org_settings.baseline_max_age_days),
               drift_alert_threshold      = COALESCE($7, org_settings.drift_alert_threshold),
               sla_critical_days          = COALESCE($8, org_settings.sla_critical_days),
               sla_high_days              = COALESCE($9, org_settings.sla_high_days),
               sla_medium_days            = COALESCE($10, org_settings.sla_medium_days),
               sla_low_days               = COALESCE($11, org_settings.sla_low_days),
               dast_auto_escalate_enabled = COALESCE($12, org_settings.dast_auto_escalate_enabled),
               dast_auto_escalate_severities = COALESCE($13, org_settings.dast_auto_escalate_severities),
               dast_webhook_url           = COALESCE($14, org_settings.dast_webhook_url),
               updated_at                 = NOW()
           RETURNING *"#,
    )
    .bind(&org_id)
    .bind(req.caching_enabled)
    .bind(req.full_revalidation_interval)
    .bind(req.sast_cache_ttl_days)
    .bind(req.recon_cache_ttl_days)
    .bind(req.baseline_max_age_days)
    .bind(req.drift_alert_threshold)
    .bind(req.sla_critical_days)
    .bind(req.sla_high_days)
    .bind(req.sla_medium_days)
    .bind(req.sla_low_days)
    .bind(req.dast_auto_escalate_enabled)
    .bind(&req.dast_auto_escalate_severities)
    .bind(&req.dast_webhook_url)
    .fetch_one(&state.pool)
    .await?;

    Ok(Json(OrgSettingsResponse::from(&row)))
}
