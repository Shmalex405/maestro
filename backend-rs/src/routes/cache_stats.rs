//! `/cache-stats` — per-assessment LLM cost + cache telemetry.
//!
//! Phase 0 of the caching plan (see `docs/caching-plan-2026-05-22.md`).
//!
//! Endpoints:
//!   POST /cache-stats           — upsert (increment) a row by (org_id, assessment_id)
//!   GET  /cache-stats/:id       — read a specific assessment's stats
//!   GET  /cache-stats           — list / aggregate org-wide
//!
//! The write side accepts *deltas* (token counts from one request or one
//! batch) and atomically adds them to the running totals. This lets the
//! proxy-aggregator (Layer 1 of the planned ingestion) push at whatever
//! cadence makes sense without needing to compute totals client-side.
//!
//! Per-org isolation is row-level on `org_id`, mirroring the rest of
//! the routes in this crate.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::cache_stats::CacheStats;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/cache-stats", post(upsert_stats).get(list_or_aggregate))
        .route("/cache-stats/:assessment_id", get(get_for_assessment))
}

// ── Pricing constants (per 1M tokens, USD) ────────────────────────────────
//
// Frozen on write because the price tables shift and we don't want
// historical cost numbers to drift retroactively. If pricing changes,
// future rows pick up new rates; existing rows are unchanged.
//
// Anthropic per-model rates ($/MTok): (input, output, cache_read, cache_write_5m).
// Source: https://platform.claude.com/docs/en/docs/about-claude/pricing
//   Opus 4.5/4.6/4.7/4.8 (Maestro default = opus-4-8): $5 / $25 / $0.50 / $6.25
//   Sonnet 4.5/4.6:                                    $3 / $15 / $0.30 / $3.75
//   Haiku 4.5:                                         $1 / $5  / $0.10 / $1.25
//   (cache_read = 0.1x input, cache_write_5m = 1.25x input)
//
// NOTE: $15/$75 is the DEPRECATED Opus 4 / 4.1 rate — do NOT use it for 4.5+.
// The old single-tier constants billed every agent (including Sonnet/Haiku
// workers) at Opus, AND used the deprecated 3x rate, overstating cost ~2.4x.
// Pick the tier from the row's `model`; rates are still frozen on write so
// historical rows don't drift if pricing changes.
fn anthropic_rates(model: Option<&str>) -> (f64, f64, f64, f64) {
    let m = model.unwrap_or("").to_ascii_lowercase();
    if m.contains("haiku") {
        (1.0, 5.0, 0.10, 1.25)
    } else if m.contains("sonnet") {
        (3.0, 15.0, 0.30, 3.75)
    } else {
        // Opus 4.5+ — also the default when model is unknown (Maestro pins opus-4-8).
        (5.0, 25.0, 0.50, 6.25)
    }
}

// OpenAI o4 / GPT-5 (Codex) — placeholder, refine when Codex
// pricing stabilizes. The metering side doesn't care which row uses
// which constants; cost lives entirely server-side here.
const OPENAI_INPUT_PRICE_PER_MTOK: f64 = 10.0;
const OPENAI_OUTPUT_PRICE_PER_MTOK: f64 = 30.0;
const OPENAI_CACHE_READ_PRICE_PER_MTOK: f64 = 2.50;

fn compute_costs(
    provider: &str,
    model: Option<&str>,
    input_tokens: i64,
    output_tokens: i64,
    cache_read: i64,
    cache_create: i64,
) -> (f64, f64, f64, f64) {
    let (in_p, out_p, cr_p, cw_p) = match provider {
        "openai" => (
            OPENAI_INPUT_PRICE_PER_MTOK,
            OPENAI_OUTPUT_PRICE_PER_MTOK,
            OPENAI_CACHE_READ_PRICE_PER_MTOK,
            // OpenAI doesn't break out cache writes; the prompt_tokens
            // already include the cost of caching at full rate.
            OPENAI_INPUT_PRICE_PER_MTOK,
        ),
        // Anthropic: the rate tier depends on the model (Opus/Sonnet/Haiku).
        _ => anthropic_rates(model),
    };

    let mtok = 1_000_000.0;
    let cost_with_cache = (input_tokens as f64 * in_p
        + output_tokens as f64 * out_p
        + cache_read as f64 * cr_p
        + cache_create as f64 * cw_p)
        / mtok;

    // Counterfactual: if there was no caching, the total input the model
    // saw (input + cache_read + cache_create) would all bill at fresh input
    // rate. Compare to what we actually paid to derive savings.
    let cost_without_cache = ((input_tokens + cache_read + cache_create) as f64 * in_p
        + output_tokens as f64 * out_p)
        / mtok;

    let savings = cost_without_cache - cost_with_cache;

    let total_input = input_tokens + cache_read + cache_create;
    let cache_hit_pct = if total_input > 0 {
        (cache_read as f64 / total_input as f64) * 100.0
    } else {
        0.0
    };

    (cost_with_cache, cost_without_cache, savings, cache_hit_pct)
}

/// Request body for POST /cache-stats. Accepts a *delta* — the server
/// adds these counts to the existing row's running totals. To overwrite
/// instead, send `replace: true`.
#[derive(Debug, Deserialize)]
struct CacheStatsUpsert {
    /// Assessment this delta belongs to. Required — this endpoint only
    /// tracks per-assessment cache stats.
    assessment_id: String,
    /// 'anthropic' | 'openai'. Defaults to 'anthropic'.
    #[serde(default = "default_provider")]
    provider: String,
    #[serde(default)]
    model: Option<String>,

    #[serde(default)]
    input_tokens: i64,
    #[serde(default)]
    output_tokens: i64,
    #[serde(default)]
    cache_read_input_tokens: i64,
    #[serde(default)]
    cache_creation_input_tokens: i64,

    #[serde(default)]
    request_count: i32,
    #[serde(default)]
    requests_with_extended_ttl: i32,
    #[serde(default)]
    requests_without_cache_beta: i32,

    /// When true, overwrite running totals instead of adding to them.
    /// Used by reconciliation passes or test fixtures.
    #[serde(default)]
    replace: bool,
}

/// Optional query params for POST /cache-stats. The only one is
/// `service_org_id` which lets the cache-stats-router Lambda specify
/// which org to write under without sharing the caller's JWT org_id
/// (the service token doesn't have one). Honored only when the caller
/// is the cache-stats-router service identity.
#[derive(Debug, Deserialize)]
struct UpsertQuery {
    #[serde(default)]
    service_org_id: Option<String>,
}

fn default_provider() -> String {
    "anthropic".to_string()
}

#[derive(Debug, Serialize)]
struct CacheStatsResponse {
    id: String,
    org_id: String,
    assessment_id: Option<String>,
    provider: String,
    model: Option<String>,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_input_tokens: i64,
    cache_creation_input_tokens: i64,
    effective_input_tokens: i64,
    cost_usd: f64,
    cost_usd_without_cache: f64,
    savings_usd: f64,
    cache_hit_pct: f64,
    request_count: i32,
    requests_with_extended_ttl: i32,
    requests_without_cache_beta: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<&CacheStats> for CacheStatsResponse {
    fn from(c: &CacheStats) -> Self {
        Self {
            id: c.id.clone(),
            org_id: c.org_id.clone(),
            assessment_id: c.assessment_id.clone(),
            provider: c.provider.clone(),
            model: c.model.clone(),
            input_tokens: c.input_tokens,
            output_tokens: c.output_tokens,
            cache_read_input_tokens: c.cache_read_input_tokens,
            cache_creation_input_tokens: c.cache_creation_input_tokens,
            effective_input_tokens: c.effective_input_tokens,
            cost_usd: c.cost_usd,
            cost_usd_without_cache: c.cost_usd_without_cache,
            savings_usd: c.savings_usd,
            cache_hit_pct: c.cache_hit_pct,
            request_count: c.request_count,
            requests_with_extended_ttl: c.requests_with_extended_ttl,
            requests_without_cache_beta: c.requests_without_cache_beta,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

async fn upsert_stats(
    State(state): State<AppState>,
    Query(q): Query<UpsertQuery>,
    user: AuthUser,
    Json(req): Json<CacheStatsUpsert>,
) -> AppResult<(StatusCode, Json<CacheStatsResponse>)> {
    // Resolution order for the effective org_id:
    //   1. Service caller (cache-stats-router) with ?service_org_id=X →
    //      use X. Validates that the caller is in fact the router and
    //      not a random token with a misplaced query param.
    //   2. Regular user JWT → use the JWT's custom:org_id.
    //   3. Neither → 403.
    let org_id = if let Some(target) = q.service_org_id {
        if !user.is_cache_stats_router() {
            return Err(AppError::Forbidden(
                "service_org_id is only honored for cache-stats-router service tokens".into(),
            ));
        }
        if target.is_empty() {
            return Err(AppError::BadRequest("service_org_id must be non-empty".into()));
        }
        target
    } else {
        user.org_id
            .clone()
            .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?
    };

    // The cost computation needs the *cumulative* token counts after this
    // delta lands. For replace mode, that's just the deltas themselves;
    // for additive mode, we have to read the existing row first.
    let (cum_input, cum_output, cum_read, cum_create) = if req.replace {
        (
            req.input_tokens,
            req.output_tokens,
            req.cache_read_input_tokens,
            req.cache_creation_input_tokens,
        )
    } else {
        let existing: Option<CacheStats> = sqlx::query_as(
            "SELECT * FROM cache_stats WHERE org_id = $1 AND assessment_id = $2",
        )
        .bind(&org_id)
        .bind(&req.assessment_id)
        .fetch_optional(&state.pool)
        .await?;
        match existing {
            Some(e) => (
                e.input_tokens + req.input_tokens,
                e.output_tokens + req.output_tokens,
                e.cache_read_input_tokens + req.cache_read_input_tokens,
                e.cache_creation_input_tokens + req.cache_creation_input_tokens,
            ),
            None => (
                req.input_tokens,
                req.output_tokens,
                req.cache_read_input_tokens,
                req.cache_creation_input_tokens,
            ),
        }
    };

    let (cost_with, cost_without, savings, hit_pct) =
        compute_costs(&req.provider, req.model.as_deref(), cum_input, cum_output, cum_read, cum_create);

    // Effective input weights cache reads at 0.1x and cache writes at 1.25x,
    // matching Anthropic's prompt-cache pricing, so the reported dollars
    // reflect true cache-adjusted cost.
    let effective_input = cum_input
        + (cum_read as f64 * 0.1) as i64
        + (cum_create as f64 * 1.25) as i64;

    let id = Uuid::new_v4().to_string();

    // Upsert atomically. ON CONFLICT path either ADDS (replace=false) or
    // OVERWRITES (replace=true) — easier to express by computing the
    // cumulative values above and always overwriting here. The
    // distinguishing logic lives client-side in `cum_*` above.
    let row: CacheStats = sqlx::query_as(
        r#"INSERT INTO cache_stats (
            id, org_id, assessment_id, provider, model,
            input_tokens, output_tokens,
            cache_read_input_tokens, cache_creation_input_tokens,
            effective_input_tokens,
            cost_usd, cost_usd_without_cache, savings_usd, cache_hit_pct,
            request_count, requests_with_extended_ttl, requests_without_cache_beta,
            created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5,
                   $6, $7,
                   $8, $9,
                   $10,
                   $11, $12, $13, $14,
                   $15, $16, $17,
                   NOW(), NOW())
           ON CONFLICT (org_id, COALESCE(assessment_id, ''))
             WHERE assessment_id IS NOT NULL
           DO UPDATE SET
               provider = EXCLUDED.provider,
               model = COALESCE(EXCLUDED.model, cache_stats.model),
               input_tokens = EXCLUDED.input_tokens,
               output_tokens = EXCLUDED.output_tokens,
               cache_read_input_tokens = EXCLUDED.cache_read_input_tokens,
               cache_creation_input_tokens = EXCLUDED.cache_creation_input_tokens,
               effective_input_tokens = EXCLUDED.effective_input_tokens,
               cost_usd = EXCLUDED.cost_usd,
               cost_usd_without_cache = EXCLUDED.cost_usd_without_cache,
               savings_usd = EXCLUDED.savings_usd,
               cache_hit_pct = EXCLUDED.cache_hit_pct,
               request_count = cache_stats.request_count + $15,
               requests_with_extended_ttl = cache_stats.requests_with_extended_ttl + $16,
               requests_without_cache_beta = cache_stats.requests_without_cache_beta + $17,
               updated_at = NOW()
           RETURNING *"#,
    )
    .bind(&id)
    .bind(&org_id)
    .bind(&req.assessment_id)
    .bind(&req.provider)
    .bind(&req.model)
    .bind(cum_input)
    .bind(cum_output)
    .bind(cum_read)
    .bind(cum_create)
    .bind(effective_input)
    .bind(cost_with)
    .bind(cost_without)
    .bind(savings)
    .bind(hit_pct)
    .bind(req.request_count)
    .bind(req.requests_with_extended_ttl)
    .bind(req.requests_without_cache_beta)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(CacheStatsResponse::from(&row))))
}

async fn get_for_assessment(
    State(state): State<AppState>,
    Path(assessment_id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<Option<CacheStatsResponse>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let row: Option<CacheStats> = sqlx::query_as(
        "SELECT * FROM cache_stats WHERE org_id = $1 AND assessment_id = $2",
    )
    .bind(&org_id)
    .bind(&assessment_id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(Json(row.as_ref().map(CacheStatsResponse::from)))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    /// When set to "org", return org-wide aggregates across all
    /// assessments (single summary row). Default: return all rows.
    #[serde(default)]
    aggregate: Option<String>,
    /// Optional time-window filter on created_at (ISO 8601).
    #[serde(default)]
    from: Option<DateTime<Utc>>,
    #[serde(default)]
    to: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct OrgAggregate {
    org_id: String,
    total_assessments: i64,
    total_input_tokens: i64,
    total_output_tokens: i64,
    total_cache_read_tokens: i64,
    total_cache_create_tokens: i64,
    total_cost_usd: f64,
    total_cost_without_cache_usd: f64,
    total_savings_usd: f64,
    /// Weighted average cache hit across all assessments in the window.
    avg_cache_hit_pct: f64,
}

async fn list_or_aggregate(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    if q.aggregate.as_deref() == Some("org") {
        // Single-row aggregate across all assessments in the window.
        let mut sql = String::from(
            r#"SELECT
                $1::text AS org_id,
                COUNT(*) AS total_assessments,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                COALESCE(SUM(cache_read_input_tokens), 0) AS total_cache_read_tokens,
                COALESCE(SUM(cache_creation_input_tokens), 0) AS total_cache_create_tokens,
                COALESCE(SUM(cost_usd), 0) AS total_cost_usd,
                COALESCE(SUM(cost_usd_without_cache), 0) AS total_cost_without_cache_usd,
                COALESCE(SUM(savings_usd), 0) AS total_savings_usd,
                COALESCE(AVG(cache_hit_pct), 0) AS avg_cache_hit_pct
               FROM cache_stats
               WHERE org_id = $1"#,
        );
        let mut next_arg = 2;
        let mut from_arg: Option<DateTime<Utc>> = None;
        let mut to_arg: Option<DateTime<Utc>> = None;
        if let Some(f) = q.from {
            sql.push_str(&format!(" AND created_at >= ${next_arg}"));
            next_arg += 1;
            from_arg = Some(f);
        }
        if let Some(t) = q.to {
            sql.push_str(&format!(" AND created_at <= ${next_arg}"));
            to_arg = Some(t);
        }
        let mut query = sqlx::query_as::<_, OrgAggregateRow>(&sql).bind(&org_id);
        if let Some(f) = from_arg {
            query = query.bind(f);
        }
        if let Some(t) = to_arg {
            query = query.bind(t);
        }
        let agg: OrgAggregateRow = query.fetch_one(&state.pool).await?;
        let resp = OrgAggregate {
            org_id: agg.org_id,
            total_assessments: agg.total_assessments,
            total_input_tokens: agg.total_input_tokens,
            total_output_tokens: agg.total_output_tokens,
            total_cache_read_tokens: agg.total_cache_read_tokens,
            total_cache_create_tokens: agg.total_cache_create_tokens,
            total_cost_usd: agg.total_cost_usd,
            total_cost_without_cache_usd: agg.total_cost_without_cache_usd,
            total_savings_usd: agg.total_savings_usd,
            avg_cache_hit_pct: agg.avg_cache_hit_pct,
        };
        return Ok(Json(serde_json::to_value(resp).map_err(|e| {
            AppError::Internal(format!("serialize org aggregate failed: {e}"))
        })?));
    }

    // Default: list all rows for the org, most-recent first.
    let rows: Vec<CacheStats> = sqlx::query_as(
        "SELECT * FROM cache_stats WHERE org_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;

    let resp: Vec<CacheStatsResponse> = rows.iter().map(CacheStatsResponse::from).collect();
    Ok(Json(serde_json::to_value(resp).map_err(|e| {
        AppError::Internal(format!("serialize cache_stats list failed: {e}"))
    })?))
}

#[derive(Debug, sqlx::FromRow)]
struct OrgAggregateRow {
    org_id: String,
    total_assessments: i64,
    total_input_tokens: i64,
    total_output_tokens: i64,
    total_cache_read_tokens: i64,
    total_cache_create_tokens: i64,
    total_cost_usd: f64,
    total_cost_without_cache_usd: f64,
    total_savings_usd: f64,
    avg_cache_hit_pct: f64,
}
