//! `/findings` CRUD + `/stats`.
//! Mirror of `backend/app/routers/findings.py`.

use axum::{
    extract::{Path, Query, State},
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
use crate::models::finding::Finding;
use crate::models::sql_enums::{FindingStatusDb, SeverityDb, WireName};
use crate::schemas::common::{pages_for, PaginatedResponse, PaginationQuery};
use crate::schemas::finding::{
    source_patterns_for_category, FindingCreate, FindingResponse, FindingUpdate,
};
use crate::state::AppState;

const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const FINDING_STATUSES: [&str; 5] = [
    "open",
    "in_progress",
    "remediated",
    "accepted",
    "false_positive",
];
// Surface-based taxonomy. Dropped technique-categories vuln_scan + exploitation
// (vuln_scan folds into web_app; "exploited" is the cross-cutting `exploitable`
// filter, not a tab). Added cloud / identity / ai as first-class surfaces.
const CATEGORIES: [&str; 7] = [
    "web_app",
    "code_security",
    "cloud",
    "infrastructure",
    "identity",
    "ai",
    "other",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/findings", get(list_findings).post(create_finding))
        .route("/findings/stats", get(stats))
        .route("/findings/baseline", get(baseline_for_target))
        .route("/findings/coverage", get(coverage))
        // Static path — must precede "/findings/:id" so PATCH /findings/bulk
        // isn't captured as id="bulk" (matchit prioritizes static, but be explicit).
        .route("/findings/bulk", axum::routing::patch(bulk_update))
        .route(
            "/findings/:id/comments",
            get(list_comments).post(create_comment),
        )
        .route(
            "/findings/:id",
            get(get_finding).patch(update_finding).delete(delete_finding),
        )
}

#[derive(Debug, Deserialize)]
struct ListFilters {
    #[serde(flatten)]
    page: PaginationQuery,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    assessment_id: Option<String>,
    /// Narrows to findings whose assessment belongs to this project — same
    /// subquery the stats route uses (`assessment_id IN (SELECT id FROM
    /// assessments WHERE project_id = ?)`).
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    search: Option<String>,
    /// One of: vuln_scan, web_app, code_security, infrastructure,
    /// exploitation, other. Translates to a `source ILIKE ANY(...)`
    /// clause via `source_patterns_for_category`.
    #[serde(default)]
    category: Option<String>,
    /// One of: 'true', 'potentially', 'false', 'any'.
    /// 'any' = true OR potentially (everything that was at least partially
    /// exploited). Drives the Exploited tab + Fully/Partial sub-filter.
    #[serde(default)]
    exploitable: Option<String>,
    /// 'true' → only findings re-tested as no-longer-exploitable
    /// (remediated_at IS NOT NULL). Drives the cross-cutting "Remediated" tab.
    /// Migration 0034.
    #[serde(default)]
    remediated: Option<String>,
    /// Exact scan attribution — only findings produced by this scan
    /// (scan_id = ?). Powers the per-scan drill-down. Migration 0035.
    #[serde(default)]
    scan_id: Option<String>,
    /// 'true' → only scheduled-DAST findings (scan_id IS NOT NULL), excluding
    /// LLM-assessment findings. Drives the Scheduled DAST → Vulnerabilities
    /// view. Migration 0035.
    #[serde(default)]
    scan_only: Option<String>,
}

/// SQL fragment + bound args for filtering by category. Returns
/// (clause, list_of_params_to_push). The clause uses `${N}` placeholders
/// starting at `start_arg_index`. Empty result when category is None.
fn category_clause(
    category: Option<&str>,
    start_arg_index: usize,
) -> (String, Vec<String>) {
    let Some(cat) = category else {
        return (String::new(), Vec::new());
    };
    // Surface-lens union: a comma-separated list of categories (e.g.
    // "cloud,infrastructure" for the Cloud / Infra surface) filters to the
    // union of their source-pattern sets. Single values fall through to the
    // logic below unchanged.
    if cat.contains(',') {
        let mut binds: Vec<String> = Vec::new();
        for part in cat.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            for p in source_patterns_for_category(part) {
                binds.push((*p).to_string());
            }
        }
        if binds.is_empty() {
            // No known categories in the list — match nothing.
            return (" AND 1=0".to_string(), Vec::new());
        }
        let placeholders: Vec<String> = (0..binds.len())
            .map(|i| format!("${}", start_arg_index + i))
            .collect();
        let clause = format!(" AND source ILIKE ANY(ARRAY[{}])", placeholders.join(", "));
        return (clause, binds);
    }
    // "other" must be checked BEFORE the empty-patterns guard:
    // source_patterns_for_category("other") returns &[] by design (no
    // positive patterns), and the special NOT-clause below is what
    // actually defines membership in "other". Without this ordering, every
    // request for ?category=other would short-circuit to AND 1=0 and
    // return zero findings — exactly the bug observed in v0.1.65 stats.
    if cat == "other" {
        let mut placeholders: Vec<String> = Vec::new();
        let mut binds: Vec<String> = Vec::new();
        let known: Vec<&'static str> = ["web_app", "code_security", "cloud", "infrastructure", "identity", "ai"]
            .iter()
            .flat_map(|c| source_patterns_for_category(c).iter().copied())
            .collect();
        for (i, p) in known.iter().enumerate() {
            placeholders.push(format!("${}", start_arg_index + i));
            binds.push((*p).to_string());
        }
        let clause = format!(
            " AND (source IS NULL OR NOT (source ILIKE ANY(ARRAY[{}])))",
            placeholders.join(", ")
        );
        return (clause, binds);
    }
    let patterns = source_patterns_for_category(cat);
    if patterns.is_empty() {
        // Unknown category — match nothing rather than match everything.
        return (" AND 1=0".to_string(), Vec::new());
    }
    let mut placeholders: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for (i, p) in patterns.iter().enumerate() {
        placeholders.push(format!("${}", start_arg_index + i));
        binds.push((*p).to_string());
    }
    let clause = format!(
        " AND source ILIKE ANY(ARRAY[{}])",
        placeholders.join(", ")
    );
    (clause, binds)
}

async fn list_findings(
    State(state): State<AppState>,
    Query(q): Query<ListFilters>,
    user: AuthUser,
) -> AppResult<Json<PaginatedResponse>> {
    let mut sql = String::from("SELECT * FROM findings WHERE 1=1");
    let mut count_sql = String::from("SELECT COUNT(*) FROM findings WHERE 1=1");
    let mut args: Vec<String> = Vec::new();

    if let Some(org) = user.org_id.as_ref() {
        args.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND org_id = ${}", args.len()));
    }
    if let Some(sev) = q.severity.as_ref() {
        // Filter on the *effective* severity — calibrated when present,
        // original otherwise. Mirrors how the FindingResponse builds
        // `severity`; without this COALESCE the user clicking the High
        // tile would see a different set of rows than what the High
        // count claims.
        args.push(sev.clone());
        sql.push_str(&format!(
            " AND COALESCE(calibrated_severity, severity) = ${}::severity",
            args.len()
        ));
        count_sql.push_str(&format!(
            " AND COALESCE(calibrated_severity, severity) = ${}::severity",
            args.len()
        ));
    }
    if let Some(st) = q.status.as_ref() {
        args.push(st.clone());
        sql.push_str(&format!(" AND status = ${}::findingstatus", args.len()));
        count_sql.push_str(&format!(" AND status = ${}::findingstatus", args.len()));
    }
    if let Some(a) = q.assessment_id.as_ref() {
        args.push(a.clone());
        sql.push_str(&format!(" AND assessment_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND assessment_id = ${}", args.len()));
    }
    if let Some(p) = q.project_id.as_ref() {
        args.push(p.clone());
        let clause = format!(
            " AND assessment_id IN (SELECT id FROM assessments WHERE project_id = ${})",
            args.len()
        );
        sql.push_str(&clause);
        count_sql.push_str(&clause);
    }
    if let Some(s) = q.search.as_ref() {
        let like = format!("%{s}%");
        args.push(like);
        let n = args.len();
        sql.push_str(&format!(" AND (title ILIKE ${n} OR target ILIKE ${n})"));
        count_sql.push_str(&format!(" AND (title ILIKE ${n} OR target ILIKE ${n})"));
    }
    let (cat_clause, cat_binds) = category_clause(q.category.as_deref(), args.len() + 1);
    if !cat_clause.is_empty() {
        sql.push_str(&cat_clause);
        count_sql.push_str(&cat_clause);
        for b in cat_binds {
            args.push(b);
        }
    }
    if let Some(exp) = q.exploitable.as_ref() {
        match exp.as_str() {
            "any" => {
                sql.push_str(" AND exploitable IN ('true','potentially')");
                count_sql.push_str(" AND exploitable IN ('true','potentially')");
            }
            "true" | "potentially" | "false" => {
                args.push(exp.clone());
                sql.push_str(&format!(" AND exploitable = ${}", args.len()));
                count_sql.push_str(&format!(" AND exploitable = ${}", args.len()));
            }
            _ => {} // ignore unknown values rather than 400
        }
    }
    if q.remediated.as_deref() == Some("true") {
        // No bind needed — a pure NOT NULL predicate.
        sql.push_str(" AND remediated_at IS NOT NULL");
        count_sql.push_str(" AND remediated_at IS NOT NULL");
    }
    if let Some(sid) = q.scan_id.as_ref() {
        // Exact per-scan attribution (migration 0035).
        args.push(sid.clone());
        sql.push_str(&format!(" AND scan_id = ${}", args.len()));
        count_sql.push_str(&format!(" AND scan_id = ${}", args.len()));
    } else if q.scan_only.as_deref() == Some("true") {
        // DAST-only view — exclude LLM-assessment findings. Pure NOT NULL,
        // no bind. (Ignored when scan_id is set, which is already narrower.)
        sql.push_str(" AND scan_id IS NOT NULL");
        count_sql.push_str(" AND scan_id IS NOT NULL");
    }
    sql.push_str(" ORDER BY created_at DESC OFFSET $");
    let offset_pos = args.len() + 1;
    sql.push_str(&offset_pos.to_string());
    sql.push_str(" LIMIT $");
    sql.push_str(&(offset_pos + 1).to_string());

    let page = q.page.page.max(1);
    let limit = q.page.limit.clamp(1, 100);
    let offset = (page - 1) * limit;

    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for a in &args {
        cq = cq.bind(a);
    }
    let total: i64 = cq.fetch_one(&state.pool).await?;

    let mut lq = sqlx::query_as::<_, Finding>(&sql);
    for a in &args {
        lq = lq.bind(a);
    }
    lq = lq.bind(offset).bind(limit);
    let rows = lq.fetch_all(&state.pool).await?;

    let data: Vec<JsonValue> = rows
        .iter()
        .map(|f| serde_json::to_value(FindingResponse::from(f)).unwrap())
        .collect();

    let pages = pages_for(total, limit);
    Ok(Json(PaginatedResponse {
        data,
        total,
        page,
        limit,
        pages,
        has_more: page < pages,
    }))
}

/// Stats query filters. The endpoint applies these to total, by_severity,
/// and by_status — so when the desktop is on the "Web App" tab the severity
/// cards reflect just web-app findings. by_category stays unfiltered (it's
/// the tab partition itself), and exploitable_count / fully_exploited_count
/// / partial_exploited_count are also unfiltered so the Exploited sub-pill
/// counts stay stable as the user clicks them.
#[derive(Debug, Deserialize)]
struct StatsFilters {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    exploitable: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    target: Option<String>,
    /// 'true' → scope all tiles to scheduled-DAST findings only
    /// (scan_id IS NOT NULL). Powers the DAST Vulnerabilities donut. Migration 0035.
    #[serde(default)]
    scan_only: Option<String>,
}

async fn stats(
    State(state): State<AppState>,
    Query(q): Query<StatsFilters>,
    user: AuthUser,
) -> AppResult<Json<JsonValue>> {
    // Build (clause, binds) from the active filters. project_id maps to
    // assessment.project_id via subquery; everything else is direct on
    // findings columns.
    let build_filters = |args_start: usize| -> (String, Vec<String>) {
        let mut clause = String::new();
        let mut binds: Vec<String> = Vec::new();
        if let Some(org) = user.org_id.as_ref() {
            binds.push(org.clone());
            clause.push_str(&format!(" AND org_id = ${}", args_start + binds.len() - 1));
        }
        if let Some(s) = q.search.as_ref() {
            binds.push(format!("%{s}%"));
            let n = args_start + binds.len() - 1;
            clause.push_str(&format!(" AND (title ILIKE ${n} OR target ILIKE ${n})"));
        }
        if let Some(t) = q.target.as_ref() {
            binds.push(t.clone());
            clause.push_str(&format!(" AND target = ${}", args_start + binds.len() - 1));
        }
        if let Some(p) = q.project_id.as_ref() {
            binds.push(p.clone());
            clause.push_str(&format!(
                " AND assessment_id IN (SELECT id FROM assessments WHERE project_id = ${})",
                args_start + binds.len() - 1
            ));
        }
        if let Some(exp) = q.exploitable.as_ref() {
            match exp.as_str() {
                "any" => clause.push_str(" AND exploitable IN ('true','potentially')"),
                "true" | "potentially" | "false" => {
                    binds.push(exp.clone());
                    clause.push_str(&format!(" AND exploitable = ${}", args_start + binds.len() - 1));
                }
                _ => {}
            }
        }
        if q.scan_only.as_deref() == Some("true") {
            // Pure NOT NULL predicate — no bind. Scopes every tile to DAST.
            clause.push_str(" AND scan_id IS NOT NULL");
        }
        (clause, binds)
    };

    // base = base_filters_without_category — used for by_category (unfiltered
    // by category) and for the unfiltered exploitable counts.
    let (base_clause, base_binds) = build_filters(1);

    // filtered = base + category — used for total, by_severity, by_status
    // (the cards that should reflect the active tab).
    let (cat_clause, cat_binds) = category_clause(q.category.as_deref(), 1 + base_binds.len());
    let mut filtered_clause = base_clause.clone();
    filtered_clause.push_str(&cat_clause);
    let mut filtered_binds = base_binds.clone();
    filtered_binds.extend(cat_binds);

    let bind_all = |sql: String, binds: Vec<String>| {
        let pool = state.pool.clone();
        async move {
            let mut q = sqlx::query_scalar::<_, i64>(&sql);
            for b in &binds {
                q = q.bind(b);
            }
            q.fetch_one(&pool).await
        }
    };

    let mut by_severity = serde_json::Map::new();
    for sev in SEVERITIES {
        // by_severity reports counts of the *effective* severity that
        // the dashboard tiles render. Calibrated wins when present;
        // original is the fallback. Without the COALESCE, a vulnerability
        // calibrated from HIGH→MEDIUM would still inflate the High tile
        // and undercount Medium — the exact "dashboard != report" bug
        // we're fixing.
        let sql = format!(
            "SELECT COUNT(*) FROM findings WHERE COALESCE(calibrated_severity, severity) = '{sev}'{filtered_clause}"
        );
        let c: i64 = bind_all(sql, filtered_binds.clone()).await?;
        by_severity.insert(sev.to_string(), json!(c));
    }

    let mut by_status = serde_json::Map::new();
    for st in FINDING_STATUSES {
        let sql = format!(
            "SELECT COUNT(*) FROM findings WHERE status = '{st}'{filtered_clause}"
        );
        let c: i64 = bind_all(sql, filtered_binds.clone()).await?;
        by_status.insert(st.to_string(), json!(c));
    }

    let total: i64 = bind_all(
        format!("SELECT COUNT(*) FROM findings WHERE 1=1{filtered_clause}"),
        filtered_binds.clone(),
    )
    .await?;

    // Exploitable counts: use `base_clause` (no category filter, no exploitable
    // filter). Their job is to power the Exploited sub-pill counts which need
    // to stay stable as the user clicks pills.
    // We strip the user's exploitable filter for these by building a
    // dedicated clause without it.
    let mut nonexp_clause = String::new();
    let mut nonexp_binds: Vec<String> = Vec::new();
    if let Some(org) = user.org_id.as_ref() {
        nonexp_binds.push(org.clone());
        nonexp_clause.push_str(&format!(" AND org_id = ${}", nonexp_binds.len()));
    }
    if let Some(s) = q.search.as_ref() {
        nonexp_binds.push(format!("%{s}%"));
        let n = nonexp_binds.len();
        nonexp_clause.push_str(&format!(" AND (title ILIKE ${n} OR target ILIKE ${n})"));
    }
    if let Some(t) = q.target.as_ref() {
        nonexp_binds.push(t.clone());
        nonexp_clause.push_str(&format!(" AND target = ${}", nonexp_binds.len()));
    }
    if let Some(p) = q.project_id.as_ref() {
        nonexp_binds.push(p.clone());
        nonexp_clause.push_str(&format!(
            " AND assessment_id IN (SELECT id FROM assessments WHERE project_id = ${})",
            nonexp_binds.len()
        ));
    }
    if q.scan_only.as_deref() == Some("true") {
        nonexp_clause.push_str(" AND scan_id IS NOT NULL");
    }
    let fully_exploited_count: i64 = bind_all(
        format!("SELECT COUNT(*) FROM findings WHERE exploitable = 'true'{nonexp_clause}"),
        nonexp_binds.clone(),
    )
    .await?;
    let partial_exploited_count: i64 = bind_all(
        format!("SELECT COUNT(*) FROM findings WHERE exploitable = 'potentially'{nonexp_clause}"),
        nonexp_binds.clone(),
    )
    .await?;
    let exploitable_count = fully_exploited_count + partial_exploited_count;

    // Remediated count: findings re-tested as no-longer-exploitable. Uses the
    // same nonexp_clause (org + search + target + project) so the tab badge
    // stays stable as the user clicks category / exploitable pills.
    let remediated_count: i64 = bind_all(
        format!("SELECT COUNT(*) FROM findings WHERE remediated_at IS NOT NULL{nonexp_clause}"),
        nonexp_binds.clone(),
    )
    .await?;

    // by_category: same base (project_id + search + exploitable), no category.
    // We deliberately keep these scoped by base filters so the tab badge
    // counts adjust to project narrowing, but stay stable across category
    // selection (clicking "Web App" doesn't make the other tab counts shift).
    let mut by_category = serde_json::Map::new();
    for cat in CATEGORIES {
        let (this_cat_clause, this_cat_binds) =
            category_clause(Some(cat), 1 + base_binds.len());
        let mut sql = String::from("SELECT COUNT(*) FROM findings WHERE 1=1");
        sql.push_str(&base_clause);
        sql.push_str(&this_cat_clause);
        let mut binds = base_binds.clone();
        binds.extend(this_cat_binds);
        let c: i64 = bind_all(sql, binds).await?;
        by_category.insert(cat.to_string(), json!(c));
    }

    Ok(Json(json!({
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_category": by_category,
        "exploitable_count": exploitable_count,
        "fully_exploited_count": fully_exploited_count,
        "partial_exploited_count": partial_exploited_count,
        "remediated_count": remediated_count,
    })))
}

async fn get_finding(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<FindingResponse>> {
    let f = fetch_scoped(&state, &id, &user).await?;
    Ok(Json(FindingResponse::from(&f)))
}

/// Derive the network port a finding lives on from a URL target, so the DAST
/// correlation join has its key without per-scanner work. Explicit port in the
/// URL wins; otherwise the scheme default (http=80, https=443). Returns None for
/// non-URL targets (bare host, image ref, file path) — those are left to the
/// scanner's explicit value or the backfill extractor.
fn derive_port_from_target(target: &str) -> Option<i32> {
    let url = url::Url::parse(target).ok()?;
    if let Some(p) = url.port() {
        return Some(p as i32);
    }
    match url.scheme() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

async fn create_finding(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<FindingCreate>,
) -> AppResult<(StatusCode, Json<JsonValue>)> {
    use crate::schemas::finding::fingerprint;

    let id = Uuid::new_v4().to_string();
    // Auto-derive the join key from a URL target when the scanner didn't set one.
    let port = req.port.or_else(|| derive_port_from_target(&req.target));
    let fp = fingerprint(
        &req.title,
        &req.target,
        req.source.as_deref(),
        req.cwe.as_deref(),
    );

    // Upsert on (fingerprint, org_id). On conflict, the existing row's
    // occurrence_count is incremented, last_seen_at is bumped to NOW(),
    // and a few overwriteable fields (assessment_id, evidence,
    // exploitable status) are refreshed so the dashboard always reflects
    // the latest run's view of the vulnerability. Returns:
    //   xmax = 0  → fresh insert (new vuln)
    //   xmax != 0 → update (re-confirmation)
    // System columns let us tell which path the row took without a
    // pre-flight SELECT.
    // Upsert returns the row's id + xmax (system column). xmax = 0 on a
    // fresh insert, non-zero when the ON CONFLICT branch fired. We use
    // this to tell "new vuln" from "re-confirmation" without a separate
    // SELECT.
    let upsert_row: (String, bool) = sqlx::query_as(
        r#"INSERT INTO findings
              (id, title, description, severity, target, target_type,
               evidence, remediation, "references", cve, cwe, cvss_score,
               source, source_id, exploitable, fingerprint,
               assessment_id, org_id, created_by, client_id,
               calibrated_severity, calibration_rule, calibration_justification,
               validation_source, prior_assessment_id, baseline_skip_reason,
               port, service, component, image_digest, scan_id,
               verdict, oracle_kind, receipt_json, capsule_json,
               replay_n, replay_successes, verified_at, claimed_mechanism,
               first_seen_at, last_seen_at)
           VALUES ($1,$2,$3,$4::severity,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                   $17,$18,$19,$20,
                   $21::severity,$22,$23,
                   $24::validationsource,$25,$26,
                   $27,$28,$29,$30,$31,
                   COALESCE($32,'candidate'),$33,$34,$35,$36,$37,$38,$39,
                   NOW(),NOW())
           ON CONFLICT (fingerprint, org_id) WHERE fingerprint IS NOT NULL
           DO UPDATE SET
               occurrence_count = findings.occurrence_count + 1,
               last_seen_at     = NOW(),
               assessment_id    = EXCLUDED.assessment_id,
               evidence         = COALESCE(EXCLUDED.evidence, findings.evidence),
               remediation      = COALESCE(EXCLUDED.remediation, findings.remediation),
               exploitable      = COALESCE(EXCLUDED.exploitable, findings.exploitable),
               severity         = EXCLUDED.severity,
               -- Calibration: NEW value wins when present (re-runs that
               -- re-calibrated update); else preserve the existing row's
               -- prior calibration so we don't blow it away with NULL.
               calibrated_severity      = COALESCE(EXCLUDED.calibrated_severity, findings.calibrated_severity),
               calibration_rule         = COALESCE(EXCLUDED.calibration_rule, findings.calibration_rule),
               calibration_justification= COALESCE(EXCLUDED.calibration_justification, findings.calibration_justification),
               -- Validation source: NEW value always wins (the current run's
               -- crossval-qa decision is authoritative; never preserve a
               -- prior run's source value, since that would lie about what
               -- happened in THIS assessment).
               validation_source        = EXCLUDED.validation_source,
               prior_assessment_id      = EXCLUDED.prior_assessment_id,
               baseline_skip_reason     = EXCLUDED.baseline_skip_reason,
               -- Oracle verdict: NEW value always wins, same reasoning as
               -- validation_source above. A verdict is evidence about THIS run.
               -- If this assessment did not re-prove the finding, carrying a
               -- previous run's `verified` forward would assert a proof we did
               -- not perform — precisely the failure the oracle layer exists to
               -- prevent. A finding that is still real will simply re-verify.
               verdict                  = EXCLUDED.verdict,
               oracle_kind              = EXCLUDED.oracle_kind,
               receipt_json             = EXCLUDED.receipt_json,
               capsule_json             = EXCLUDED.capsule_json,
               replay_n                 = EXCLUDED.replay_n,
               replay_successes         = EXCLUDED.replay_successes,
               verified_at              = EXCLUDED.verified_at,
               claimed_mechanism        = COALESCE(EXCLUDED.claimed_mechanism, findings.claimed_mechanism),
               -- Correlation keys: new non-NULL value wins, else keep prior.
               port             = COALESCE(EXCLUDED.port, findings.port),
               service          = COALESCE(EXCLUDED.service, findings.service),
               component        = COALESCE(EXCLUDED.component, findings.component),
               image_digest     = COALESCE(EXCLUDED.image_digest, findings.image_digest),
               -- scan_id is sticky: a DAST scan stamps it, and a later LLM
               -- re-POST (scan_id NULL) preserves the DAST attribution so the
               -- finding stays in the Scheduled DAST → Vulnerabilities view.
               scan_id          = COALESCE(EXCLUDED.scan_id, findings.scan_id),
               -- Remediation / "patched" detection (migration 0034). Computed
               -- purely from the existing-row vs incoming exploitable values —
               -- `findings.exploitable` here is the PRE-update value, EXCLUDED
               -- is the incoming one. Three cases, applied identically below:
               --   1. PATCHED: was exploitable, re-test says 'false'  → stamp it
               --   2. REGRESSION / still exploitable: incoming true/potentially → clear
               --   3. otherwise (incoming exploitable is NULL/'false' unchanged) → preserve
               -- We only treat an EXPLICIT incoming 'false' as a fix — a NULL
               -- (test BLOCKED / didn't run) never marks a finding patched.
               remediated_at = CASE
                   WHEN EXCLUDED.exploitable = 'false'
                        AND findings.exploitable IN ('true','potentially') THEN NOW()
                   WHEN EXCLUDED.exploitable IN ('true','potentially') THEN NULL
                   ELSE findings.remediated_at
               END,
               prior_exploitable = CASE
                   WHEN EXCLUDED.exploitable = 'false'
                        AND findings.exploitable IN ('true','potentially') THEN findings.exploitable
                   WHEN EXCLUDED.exploitable IN ('true','potentially') THEN NULL
                   ELSE findings.prior_exploitable
               END,
               remediated_in_assessment_id = CASE
                   WHEN EXCLUDED.exploitable = 'false'
                        AND findings.exploitable IN ('true','potentially') THEN EXCLUDED.assessment_id
                   WHEN EXCLUDED.exploitable IN ('true','potentially') THEN NULL
                   ELSE findings.remediated_in_assessment_id
               END,
               updated_at       = NOW()
           RETURNING findings.id, (xmax = 0) AS is_new"#,
    )
    .bind(&id)
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.severity)
    .bind(&req.target)
    .bind(&req.target_type)
    .bind(&req.evidence)
    .bind(&req.remediation)
    .bind(&req.references)
    .bind(&req.cve)
    .bind(&req.cwe)
    .bind(&req.cvss_score)
    .bind(&req.source)
    .bind(&req.source_id)
    .bind(&req.exploitable)
    .bind(&fp)
    .bind(&req.assessment_id)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(&req.client_id)
    .bind(&req.calibrated_severity)
    .bind(&req.calibration_rule)
    .bind(&req.calibration_justification)
    .bind(&req.validation_source)
    .bind(&req.prior_assessment_id)
    .bind(&req.baseline_skip_reason)
    .bind(port)
    .bind(&req.service)
    .bind(&req.component)
    .bind(&req.image_digest)
    .bind(&req.scan_id)
    .bind(&req.verdict)
    .bind(&req.oracle_kind)
    .bind(&req.receipt_json)
    .bind(&req.capsule_json)
    .bind(req.replay_n)
    .bind(req.replay_successes)
    .bind(req.verified_at)
    .bind(&req.claimed_mechanism)
    .fetch_one(&state.pool)
    .await?;

    let (final_id, is_new) = upsert_row;
    let f: Finding = sqlx::query_as("SELECT * FROM findings WHERE id = $1")
        .bind(&final_id)
        .fetch_one(&state.pool)
        .await?;

    audit::record(
        &state.pool,
        &user,
        if is_new { "finding.create" } else { "finding.update" },
        "finding",
        Some(&f.id),
        Some(serde_json::json!({
            "title": req.title,
            "severity": req.severity,
            "target": req.target,
            "assessment_id": req.assessment_id,
            "is_new": is_new,
            "occurrence_count": f.occurrence_count,
        })),
    )
    .await;

    // Add is_new to the response envelope so the MCP server / desktop can
    // tell the user "newly discovered vulnerability" vs "still vulnerable
    // (3rd run)".
    let mut body = serde_json::to_value(FindingResponse::from(&f)).unwrap();
    if let serde_json::Value::Object(ref mut map) = body {
        map.insert("is_new".to_string(), serde_json::Value::Bool(is_new));
    }
    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(body)))
}

async fn update_finding(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<FindingUpdate>,
) -> AppResult<Json<FindingResponse>> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    let f: Finding = sqlx::query_as(
        r#"UPDATE findings
              SET title = COALESCE($2, title),
                  description = COALESCE($3, description),
                  severity = COALESCE($4::severity, severity),
                  status = COALESCE($5::findingstatus, status),
                  remediation = COALESCE($6, remediation),
                  jira_ticket = COALESCE($7, jira_ticket),
                  jira_url = COALESCE($8, jira_url),
                  calibrated_severity = COALESCE($9::severity, calibrated_severity),
                  calibration_rule = COALESCE($10, calibration_rule),
                  calibration_justification = COALESCE($11, calibration_justification),
                  -- Triage (migration 0036). assigned_to: ''→clear, NULL→unchanged.
                  assigned_to = CASE WHEN $12 IS NULL THEN assigned_to
                                     WHEN $12 = '' THEN NULL ELSE $12 END,
                  tags = COALESCE($13, tags),
                  -- attest tri-state: NULL→unchanged, true→stamp, false→clear.
                  attested_at = CASE WHEN $14::boolean IS NULL THEN attested_at
                                     WHEN $14 THEN NOW() ELSE NULL END,
                  attested_by = CASE WHEN $14::boolean IS NULL THEN attested_by
                                     WHEN $14 THEN $15 ELSE NULL END,
                  updated_at = NOW()
            WHERE id = $1
            RETURNING *"#,
    )
    .bind(&id)
    .bind(&req.title)
    .bind(&req.description)
    .bind(&req.severity)
    .bind(&req.status)
    .bind(&req.remediation)
    .bind(&req.jira_ticket)
    .bind(&req.jira_url)
    .bind(&req.calibrated_severity)
    .bind(&req.calibration_rule)
    .bind(&req.calibration_justification)
    .bind(&req.assigned_to)
    .bind(&req.tags)
    .bind(req.attest)
    .bind(&user.id)
    .fetch_one(&state.pool)
    .await?;

    audit::record(
        &state.pool,
        &user,
        "finding.update",
        "finding",
        Some(&f.id),
        Some(serde_json::json!({
            "status": req.status,
            "severity": req.severity,
            "title": req.title,
        })),
    )
    .await;

    Ok(Json(FindingResponse::from(&f)))
}

async fn delete_finding(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let f = fetch_scoped(&state, &id, &user).await?;
    sqlx::query("DELETE FROM findings WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit::record(
        &state.pool,
        &user,
        "finding.delete",
        "finding",
        Some(&f.id),
        Some(serde_json::json!({
            "title": f.title,
            "severity": f.severity,
        })),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

async fn fetch_scoped(state: &AppState, id: &str, user: &AuthUser) -> AppResult<Finding> {
    let mut sql = String::from("SELECT * FROM findings WHERE id = $1");
    let mut binds: Vec<String> = vec![id.to_string()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut q = sqlx::query_as::<_, Finding>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let row: Option<Finding> = q.fetch_optional(&state.pool).await?;
    row.ok_or_else(|| AppError::NotFound("Finding not found".into()))
}

// ── Bulk triage (workbench action bar) ─────────────────────────────────────
// One UPDATE over a set of ids, org-scoped. Any field omitted is left alone.
// tags are merged (add_tags) + filtered (remove_tags) per row; status/assignee/
// attest applied uniformly. Returns the number of rows updated.

#[derive(Debug, Deserialize)]
struct BulkUpdateBody {
    ids: Vec<String>,
    #[serde(default)]
    status: Option<String>,
    /// '' clears, NULL leaves unchanged, else sets.
    #[serde(default)]
    assigned_to: Option<String>,
    #[serde(default)]
    add_tags: Option<Vec<String>>,
    #[serde(default)]
    remove_tags: Option<Vec<String>>,
    /// true → attest (stamp), false → un-attest (clear), NULL → unchanged.
    #[serde(default)]
    attest: Option<bool>,
}

async fn bulk_update(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<BulkUpdateBody>,
) -> AppResult<Json<JsonValue>> {
    if req.ids.is_empty() {
        return Ok(Json(json!({ "updated": 0 })));
    }
    let res = sqlx::query(
        r#"UPDATE findings SET
               status      = COALESCE($2::findingstatus, status),
               assigned_to = CASE WHEN $3 IS NULL THEN assigned_to
                                  WHEN $3 = '' THEN NULL ELSE $3 END,
               tags        = ARRAY(
                   SELECT DISTINCT e
                   FROM unnest(array_cat(tags, COALESCE($4, '{}'::text[]))) AS e
                   WHERE NOT (e = ANY(COALESCE($5, '{}'::text[])))
               ),
               attested_at = CASE WHEN $6::boolean IS NULL THEN attested_at
                                  WHEN $6 THEN NOW() ELSE NULL END,
               attested_by = CASE WHEN $6::boolean IS NULL THEN attested_by
                                  WHEN $6 THEN $7 ELSE NULL END,
               updated_at  = NOW()
           WHERE id = ANY($1) AND ($8::text IS NULL OR org_id = $8)"#,
    )
    .bind(&req.ids)
    .bind(&req.status)
    .bind(&req.assigned_to)
    .bind(&req.add_tags)
    .bind(&req.remove_tags)
    .bind(req.attest)
    .bind(&user.id)
    .bind(&user.org_id)
    .execute(&state.pool)
    .await?;

    let updated = res.rows_affected();
    audit::record(
        &state.pool,
        &user,
        "finding.bulk_update",
        "finding",
        None,
        Some(json!({
            "ids": req.ids,
            "status": req.status,
            "assigned_to": req.assigned_to,
            "updated": updated,
        })),
    )
    .await;

    Ok(Json(json!({ "updated": updated })))
}

// ── Finding comments / activity ────────────────────────────────────────────
// Mirrors assessment_events: org-scoped via the parent finding's visibility.

#[derive(Debug, sqlx::FromRow, Serialize)]
struct FindingComment {
    id: String,
    finding_id: String,
    org_id: Option<String>,
    author: Option<String>,
    body: String,
    created_at: DateTime<Utc>,
}

async fn list_comments(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<Vec<FindingComment>>> {
    // Visibility: 404 if the finding isn't in the caller's org.
    fetch_scoped(&state, &id, &user).await?;
    let rows: Vec<FindingComment> = sqlx::query_as(
        "SELECT id, finding_id, org_id, author, body, created_at
           FROM finding_comments WHERE finding_id = $1 ORDER BY created_at ASC",
    )
    .bind(&id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize)]
struct CreateCommentReq {
    body: String,
}

async fn create_comment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<CreateCommentReq>,
) -> AppResult<(StatusCode, Json<FindingComment>)> {
    fetch_scoped(&state, &id, &user).await?;
    if req.body.trim().is_empty() {
        return Err(AppError::BadRequest("Comment body is empty".into()));
    }
    let comment_id = Uuid::new_v4().to_string();
    let row: FindingComment = sqlx::query_as(
        r#"INSERT INTO finding_comments (id, finding_id, org_id, author, body)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, finding_id, org_id, author, body, created_at"#,
    )
    .bind(&comment_id)
    .bind(&id)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(&req.body)
    .fetch_one(&state.pool)
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

// ── /findings/baseline ─────────────────────────────────────────────────
//
// Phase 3 of caching plan (docs/caching-cross-assessment-design.md).
//
// Returns prior findings for a given target_id (with their last validation
// state) plus the org's revalidation cadence counter. The team lead calls
// this at Phase 1.5 of an assessment and passes the result to crossval-qa
// via the dispatch payload; crossval-qa applies its baseline-aware
// decision tree to choose VALIDATED_FROM_BASELINE vs RE_VALIDATED per
// finding.
//
// The cadence counter (`assessments_since_last_full_revalidation`) drives
// the safety net: every Nth assessment is a forced full re-validation
// pass (default N=4, configurable per-org via org_settings).

#[derive(Debug, Deserialize)]
struct BaselineQuery {
    target_id: String,
    /// Override the org's default `baseline_max_age_days`. Findings whose
    /// last_seen_at is older than this are excluded — they're considered
    /// too stale for VALIDATED_FROM_BASELINE eligibility anyway, so the
    /// dispatch payload doesn't need them.
    #[serde(default)]
    max_age_days: Option<i32>,
}

#[derive(Debug, Serialize)]
struct BaselineFinding {
    id: String,
    fingerprint: Option<String>,
    title: String,
    severity: String,
    calibrated_severity: Option<String>,
    calibration_rule: Option<String>,
    exploitable: Option<String>,
    status: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    /// (NOW() - last_seen_at) in days, integer. Drives the agent's
    /// age-vs-severity decision tree.
    validation_age_days: i32,
    occurrence_count: i32,
    file_path: Option<String>,
    line_start: Option<i32>,
    /// First 500 chars of evidence — enough context for the agent to
    /// decide whether the prior validation is still credible without
    /// blowing up the dispatch payload size.
    evidence_excerpt: Option<String>,
    /// Last assessment that touched this finding. crossval-qa uses this
    /// for the prior_assessment_id link when it marks VALIDATED_FROM_BASELINE.
    last_assessment_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct BaselineResponse {
    target_id: String,
    baseline: Vec<BaselineFinding>,
    /// True when the org's revalidation cadence demands this run skip
    /// caching entirely. crossval-qa MUST re-validate everything if true.
    force_full_revalidation: bool,
    /// How many assessments since the last forced full revalidation pass
    /// against THIS target. Lets the lead surface "Next full revalidation
    /// in N assessments" in the UI.
    assessments_since_last_full_revalidation: i64,
    /// Configured per-org cadence. NULL when caching is fully disabled.
    full_revalidation_interval: Option<i32>,
    /// Active per-org max age — what crossval-qa should treat as "too
    /// old to trust" by default. Severity-specific overrides still apply
    /// in the agent's decision tree.
    baseline_max_age_days: i32,
    /// Master kill switch — when false the baseline list is still
    /// returned (so the UI can show what would've been reused) but
    /// force_full_revalidation will be true.
    caching_enabled: bool,
}

#[derive(Debug, sqlx::FromRow)]
struct OrgSettingsRow {
    caching_enabled: bool,
    full_revalidation_interval: i32,
    baseline_max_age_days: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct BaselineRow {
    id: String,
    fingerprint: Option<String>,
    title: String,
    severity: SeverityDb,
    calibrated_severity: Option<SeverityDb>,
    calibration_rule: Option<String>,
    exploitable: Option<String>,
    status: Option<FindingStatusDb>,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    occurrence_count: i32,
    file_path: Option<String>,
    line_start: Option<i32>,
    evidence: Option<String>,
    assessment_id: Option<String>,
}

async fn baseline_for_target(
    State(state): State<AppState>,
    Query(q): Query<BaselineQuery>,
    user: AuthUser,
) -> AppResult<Json<BaselineResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // 1. Read org_settings — bootstrap a default row if none exists.
    let settings: OrgSettingsRow = sqlx::query_as(
        r#"INSERT INTO org_settings (org_id) VALUES ($1)
           ON CONFLICT (org_id) DO UPDATE SET updated_at = org_settings.updated_at
           RETURNING caching_enabled, full_revalidation_interval, baseline_max_age_days"#,
    )
    .bind(&org_id)
    .fetch_one(&state.pool)
    .await?;

    let max_age = q.max_age_days.unwrap_or(settings.baseline_max_age_days);

    // 2. Revalidation cadence: count completed assessments for this
    //    target since the last forced full revalidation pass. The pass
    //    is identified by `config->>'force_full_revalidation' = 'true'`
    //    on the assessment row.
    let assessments_since: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM assessments a
           WHERE a.org_id = $1
             AND a.target_ids @> jsonb_build_array($2::text)
             AND a.status = 'completed'
             AND a.archived_at IS NULL
             AND a.completed_at > COALESCE(
                 (SELECT MAX(b.completed_at) FROM assessments b
                  WHERE b.org_id = $1
                    AND b.target_ids @> jsonb_build_array($2::text)
                    AND (b.config->>'force_full_revalidation')::boolean = true),
                 '1970-01-01T00:00:00Z'::timestamptz
             )"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .fetch_one(&state.pool)
    .await?;

    let force_full = !settings.caching_enabled
        || (settings.full_revalidation_interval > 0
            && assessments_since >= settings.full_revalidation_interval as i64);

    // 3. The baseline rows themselves. Constraint: only findings still
    //    "open" or in a re-testable state are worth shipping — accepted /
    //    false-positive are deliberately excluded (the crossval-qa agent
    //    has its own re-validation logic for status=false_positive cases).
    let rows: Vec<BaselineRow> = sqlx::query_as(
        r#"SELECT
              id,
              fingerprint,
              title,
              severity,
              calibrated_severity,
              calibration_rule,
              exploitable,
              status,
              first_seen_at,
              last_seen_at,
              occurrence_count,
              file_path,
              line_start,
              evidence,
              assessment_id
           FROM findings
           WHERE org_id = $1
             AND target_id = $2
             AND last_seen_at > NOW() - ($3 || ' days')::interval
             AND status NOT IN ('accepted'::findingstatus, 'false_positive'::findingstatus)
           ORDER BY
               -- Critical/High first (calibrated wins), then by recency.
               -- Agent processes top-priority findings first; truncation
               -- at LIMIT 500 leaves the lowest-impact off the wire.
               CASE COALESCE(calibrated_severity, severity)
                   WHEN 'critical' THEN 1
                   WHEN 'high'     THEN 2
                   WHEN 'medium'   THEN 3
                   WHEN 'low'      THEN 4
                   WHEN 'info'     THEN 5
                   ELSE 6
               END,
               last_seen_at DESC
           LIMIT 500"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .bind(max_age.to_string())
    .fetch_all(&state.pool)
    .await?;

    let now = Utc::now();
    let baseline: Vec<BaselineFinding> = rows
        .into_iter()
        .map(|r| BaselineFinding {
            id: r.id,
            fingerprint: r.fingerprint,
            title: r.title,
            severity: r.severity.wire_name().to_string(),
            calibrated_severity: r.calibrated_severity.as_ref().map(|s| s.wire_name().to_string()),
            calibration_rule: r.calibration_rule,
            exploitable: r.exploitable,
            status: r
                .status
                .as_ref()
                .map(|s| s.wire_name().to_string())
                .unwrap_or_else(|| "open".to_string()),
            first_seen_at: r.first_seen_at,
            last_seen_at: r.last_seen_at,
            validation_age_days: (now - r.last_seen_at).num_days() as i32,
            occurrence_count: r.occurrence_count,
            file_path: r.file_path,
            line_start: r.line_start,
            evidence_excerpt: r.evidence.map(|e| {
                if e.len() > 500 {
                    format!("{}…", &e[..500])
                } else {
                    e
                }
            }),
            last_assessment_id: r.assessment_id,
        })
        .collect();

    Ok(Json(BaselineResponse {
        target_id: q.target_id,
        baseline,
        force_full_revalidation: force_full,
        assessments_since_last_full_revalidation: assessments_since,
        full_revalidation_interval: if settings.full_revalidation_interval > 0 {
            Some(settings.full_revalidation_interval)
        } else {
            None
        },
        baseline_max_age_days: max_age,
        caching_enabled: settings.caching_enabled,
    }))
}

pub(crate) async fn upsert_from_sync(
    state: &AppState,
    user: &AuthUser,
    incoming: &crate::schemas::sync::SyncFindingIn,
) -> AppResult<Finding> {
    // Normalize hyphenated enum values from the desktop's local SQLite.
    // See `routes/assessments.rs::normalize_enum` for the full story.
    let norm_severity = incoming.severity.replace('-', "_");
    let norm_status = incoming.status.as_deref().map(|s| s.replace('-', "_"));
    let client_id = incoming.client_id.as_deref();
    let existing: Option<Finding> = match (client_id, user.org_id.as_ref()) {
        (Some(cid), Some(org)) => sqlx::query_as(
            "SELECT * FROM findings WHERE client_id = $1 AND org_id = $2",
        )
        .bind(cid)
        .bind(org)
        .fetch_optional(&state.pool)
        .await?
        ,
        (Some(cid), None) => sqlx::query_as("SELECT * FROM findings WHERE client_id = $1")
            .bind(cid)
            .fetch_optional(&state.pool)
            .await?,
        _ => None,
    };

    // Resolve assessment_id: could be the server ID, or the client_id of an
    // assessment. Match the Python behavior in sync.py:92-104.
    let resolved_assessment_id = if let Some(aid) = incoming.assessment_id.as_deref() {
        let mut sql = String::from(
            "SELECT id FROM assessments WHERE (id = $1 OR client_id = $1)",
        );
        let mut binds: Vec<String> = vec![aid.to_string()];
        if let Some(org) = user.org_id.as_ref() {
            sql.push_str(" AND org_id = $2");
            binds.push(org.clone());
        }
        let mut q = sqlx::query_scalar::<_, String>(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        q.fetch_optional(&state.pool).await?
    } else {
        None
    };

    if let Some(f) = existing {
        let row: Finding = sqlx::query_as(
            r#"UPDATE findings
                  SET title = $2,
                      description = COALESCE($3, description),
                      severity = $4::severity,
                      target = $5,
                      target_type = COALESCE($6, target_type),
                      evidence = COALESCE($7, evidence),
                      remediation = COALESCE($8, remediation),
                      "references" = COALESCE($9, "references"),
                      cve = COALESCE($10, cve),
                      cwe = COALESCE($11, cwe),
                      cvss_score = COALESCE($12, cvss_score),
                      source = COALESCE($13, source),
                      source_id = COALESCE($14, source_id),
                      assessment_id = COALESCE($15, assessment_id),
                      status = COALESCE($16::findingstatus, status),
                      updated_at = NOW()
                WHERE id = $1
                RETURNING *"#,
        )
        .bind(&f.id)
        .bind(&incoming.title)
        .bind(&incoming.description)
        .bind(&norm_severity)
        .bind(&incoming.target)
        .bind(&incoming.target_type)
        .bind(&incoming.evidence)
        .bind(&incoming.remediation)
        .bind(&incoming.references)
        .bind(&incoming.cve)
        .bind(&incoming.cwe)
        .bind(&incoming.cvss_score)
        .bind(&incoming.source)
        .bind(&incoming.source_id)
        .bind(&resolved_assessment_id)
        .bind(&norm_status)
        .fetch_one(&state.pool)
        .await?;
        return Ok(row);
    }

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO findings
              (id, title, description, severity, target, target_type,
               evidence, remediation, "references", cve, cwe, cvss_score,
               source, source_id, assessment_id, status,
               org_id, created_by, client_id)
           VALUES ($1,$2,$3,$4::severity,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
                   COALESCE($16::findingstatus,'open'),$17,$18,$19)"#,
    )
    .bind(&id)
    .bind(&incoming.title)
    .bind(&incoming.description)
    .bind(&norm_severity)
    .bind(&incoming.target)
    .bind(&incoming.target_type)
    .bind(&incoming.evidence)
    .bind(&incoming.remediation)
    .bind(&incoming.references)
    .bind(&incoming.cve)
    .bind(&incoming.cwe)
    .bind(&incoming.cvss_score)
    .bind(&incoming.source)
    .bind(&incoming.source_id)
    .bind(&resolved_assessment_id)
    .bind(&norm_status)
    .bind(&user.org_id)
    .bind(&user.id)
    .bind(client_id)
    .execute(&state.pool)
    .await?;

    let row: Finding = sqlx::query_as("SELECT * FROM findings WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(row)
}

// ---------------------------------------------------------------------------
// Coverage rollup for the dashboard W3 heatmap. Groups findings by
// (category, surface) and returns the count + worst severity per cell. Reuses
// `category_from_source` (the canonical category mapping) so heatmap rows match
// the rest of the app; surface is derived the same way the frontend lens does.
//
// Honest note: this is finding-density coverage (where issues are), not per-test
// execution coverage (ran vs not-run) — that needs a per-test record we don't
// store yet. Empty (category, surface) cells = no findings, surfaced as gaps.
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CoverageCell {
    category: String,
    /// web / cloud / identity
    surface: String,
    count: i64,
    worst_severity: Option<String>,
}

fn coverage_surface_of(source: Option<&str>, target_type: Option<&str>) -> &'static str {
    let s = source.unwrap_or("").to_ascii_lowercase();
    if target_type == Some("cloud_account")
        || s.starts_with("cloud")
        || s.contains("cloud-correlation")
        || s.starts_with("test_iam")
        || s.starts_with("test_k8s")
        || s.starts_with("test_cloud")
        || s.starts_with("test_container")
        || s.starts_with("test_lambda")
    {
        return "cloud";
    }
    if s.starts_with("identity") {
        return "identity";
    }
    "web"
}

fn coverage_sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

async fn coverage(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<Vec<CoverageCell>>> {
    use crate::schemas::finding::category_from_source;

    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: Vec<(Option<String>, Option<String>, String)> = sqlx::query_as(
        r#"SELECT source, target_type, severity::text AS severity
           FROM findings
           -- NULL-safe: findings currently have NULL status in the DB (the API
           -- defaults it to 'open'); a bare `status <> 'false_positive'` is NULL
           -- for those rows and drops them, emptying the coverage heatmap.
           WHERE org_id = $1 AND (status IS NULL OR status <> 'false_positive')"#,
    )
    .bind(&org_id)
    .fetch_all(&state.pool)
    .await?;

    // (category, surface) -> (count, worst_rank, worst_severity)
    let mut agg: std::collections::HashMap<(String, String), (i64, u8, String)> =
        std::collections::HashMap::new();
    for (source, target_type, severity) in &rows {
        let cat = category_from_source(source.as_deref()).to_string();
        let surf = coverage_surface_of(source.as_deref(), target_type.as_deref()).to_string();
        let rank = coverage_sev_rank(severity);
        let entry = agg.entry((cat, surf)).or_insert((0, 0, String::new()));
        entry.0 += 1;
        if rank > entry.1 {
            entry.1 = rank;
            entry.2 = severity.clone();
        }
    }

    let cells: Vec<CoverageCell> = agg
        .into_iter()
        .map(|((category, surface), (count, _rank, worst))| CoverageCell {
            category,
            surface,
            count,
            worst_severity: if worst.is_empty() { None } else { Some(worst) },
        })
        .collect();

    Ok(Json(cells))
}
