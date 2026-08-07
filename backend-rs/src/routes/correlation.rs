//! DAST correlation (P2 Phase 2) — the network/web analog of the cloud
//! reachability join in `cloud_inventory::correlate`.
//!
//! Endpoints:
//!   POST /correlate/dast            — join recon-discovered open ports/services
//!                                     against vulnerable findings on those ports,
//!                                     emitting "dast-correlation" findings + a
//!                                     computed reachability attack-path graph
//!   POST /findings/backfill-keys    — best-effort extractor that populates the
//!                                     structured join keys (port/service/
//!                                     component/image_digest) on existing rows
//!                                     from free-text target/evidence
//!
//! Both are deterministic and transactional. Per-org scoped via JWT custom:org_id.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/correlate/dast", post(correlate_dast))
        .route("/findings/backfill-keys", post(backfill_keys))
}

// =============================================================================
// POST /correlate/dast
// =============================================================================

#[derive(Debug, Deserialize)]
struct CorrelateDastBody {
    target_id: String,
    #[serde(default)]
    assessment_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CorrelateDastResponse {
    correlated: usize,
    finding_ids: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct DastMatch {
    target: String,
    severity: String,
    cve: Option<String>,
    cwe: Option<String>,
    exploitable: Option<String>,
    port: Option<i32>,
    service: Option<String>,
}

async fn correlate_dast(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CorrelateDastBody>,
) -> AppResult<(StatusCode, Json<CorrelateDastResponse>)> {
    use crate::schemas::finding::fingerprint;

    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Open ports discovered by recon for this target (latest 'ports' snapshot).
    let snapshot: Option<(JsonValue,)> = sqlx::query_as(
        r#"SELECT snapshot FROM recon_cache_entries
           WHERE org_id = $1 AND target_id = $2 AND scan_type = 'ports'
           ORDER BY scan_completed_at DESC LIMIT 1"#,
    )
    .bind(&org_id)
    .bind(&body.target_id)
    .fetch_optional(&state.pool)
    .await?;

    let open_ports: Vec<i32> = snapshot
        .as_ref()
        .and_then(|(s,)| s.get("open"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_i64().map(|n| n as i32)).collect())
        .unwrap_or_default();

    if open_ports.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(CorrelateDastResponse { correlated: 0, finding_ids: vec![] }),
        ));
    }

    // Vulnerable findings (CVE present) sitting on a reachable port. Scoped to this
    // target (or org-wide rows with no target_id yet), excluding the correlation
    // outputs themselves so re-runs don't correlate their own findings.
    let matches: Vec<DastMatch> = sqlx::query_as(
        r#"SELECT f.target, f.severity::text AS severity,
                  f.cve, f.cwe, f.exploitable, f.port, f.service
             FROM findings f
            WHERE f.org_id = $1
              AND f.cve IS NOT NULL
              AND f.port = ANY($2)
              AND (f.target_id = $3 OR f.target_id IS NULL)
              AND COALESCE(f.source, '') NOT IN ('dast-correlation', 'cloud-correlation')"#,
    )
    .bind(&org_id)
    .bind(&open_ports)
    .bind(&body.target_id)
    .fetch_all(&state.pool)
    .await?;

    let mut finding_ids: Vec<String> = Vec::new();
    let mut nodes: HashMap<String, JsonValue> = HashMap::new();
    let mut edges: Vec<JsonValue> = Vec::new();
    let mut edge_keys: HashSet<(String, String)> = HashSet::new();
    let mut tx = state.pool.begin().await?;

    for m in &matches {
        let cve_label = m.cve.clone().unwrap_or_else(|| "known CVE".to_string());
        let port = m.port.unwrap_or(0);
        let svc_label = m.service.clone().unwrap_or_else(|| format!("port {port}"));
        let title = format!("Reachable vulnerable service: {cve_label} on {svc_label}");
        let description = format!(
            "{} on {} (port {}) carries {}. This is a reachable + vulnerable correlation: a CVE \
             on a service exposed on a recon-confirmed open port — proven from observed network \
             state, not a theoretical path.",
            svc_label, m.target, port, cve_label
        );
        let evidence = format!(
            "target={}\nport={}\nservice={}\ncve={}",
            m.target, port, svc_label, cve_label
        );
        let source = "dast-correlation";
        let fp = fingerprint(&title, &m.target, Some(source), m.cwe.as_deref());
        let id = Uuid::new_v4().to_string();

        let row: (String,) = sqlx::query_as(
            r#"INSERT INTO findings
                  (id, title, description, severity, target, target_type,
                   evidence, cve, cwe, source, fingerprint, assessment_id,
                   org_id, created_by, port, service, first_seen_at, last_seen_at)
               VALUES ($1,$2,$3,$4::severity,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW())
               ON CONFLICT (fingerprint, org_id) WHERE fingerprint IS NOT NULL
               DO UPDATE SET
                   occurrence_count = findings.occurrence_count + 1,
                   last_seen_at     = NOW(),
                   severity         = EXCLUDED.severity,
                   evidence         = COALESCE(EXCLUDED.evidence, findings.evidence),
                   assessment_id    = EXCLUDED.assessment_id,
                   updated_at       = NOW()
               RETURNING id"#,
        )
        .bind(&id)
        .bind(&title)
        .bind(&description)
        .bind(&m.severity)
        .bind(&m.target)
        .bind("service")
        .bind(&evidence)
        .bind(&m.cve)
        .bind(&m.cwe)
        .bind(source)
        .bind(&fp)
        .bind(&body.assessment_id)
        .bind(&org_id)
        .bind(&user.id)
        .bind(m.port)
        .bind(&m.service)
        .fetch_one(&mut *tx)
        .await?;
        let fid = row.0;
        finding_ids.push(fid.clone());

        // graph chain: open-port exposure → service → vulnerability
        let exposure_id = format!("port:{port}");
        let service_id = format!("service:{}:{port}", m.target);
        let vuln_id = format!("vuln:{}:{port}:{cve_label}", m.target);

        nodes.entry(exposure_id.clone()).or_insert_with(|| {
            json!({ "id": exposure_id, "label": format!("open port {port}"), "kind": "exposure", "layer": 0 })
        });
        nodes.entry(service_id.clone()).or_insert_with(|| {
            json!({ "id": service_id, "label": svc_label, "kind": "workload", "layer": 1, "sub": m.target })
        });
        // attrs.finding_id links the vuln node back to its finding for drill-through.
        nodes.entry(vuln_id.clone()).or_insert_with(|| {
            json!({ "id": vuln_id, "label": cve_label, "kind": "vulnerability", "layer": 2, "severity": m.severity, "attrs": { "finding_id": fid } })
        });

        let exploited_vuln = m.exploitable.as_deref() == Some("true");
        for (from, to, exploited) in [
            (&exposure_id, &service_id, true),
            (&service_id, &vuln_id, exploited_vuln),
        ] {
            if edge_keys.insert((from.clone(), to.clone())) {
                edges.push(json!({ "from": from, "to": to, "exploited": exploited }));
            }
        }
    }

    // Persist the computed graph (replace prior reachability graph for this target).
    if !nodes.is_empty() {
        // Dual-write into the normalized substrate (migration 0046) — same tx, so
        // the reachability graph accumulates into the cross-assessment union too.
        // Server-generated kinds are all built-ins, so no kind validation needed.
        use crate::routes::graph::{accumulate_edge, accumulate_node, EdgeInput, NodeInput};
        let aid = body.assessment_id.as_deref();
        let tid = Some(body.target_id.as_str());
        for nv in nodes.values() {
            if let Ok(n) = serde_json::from_value::<NodeInput>(nv.clone()) {
                accumulate_node(&mut tx, &org_id, &n, "reachability", aid, tid).await?;
            }
        }
        for ev in &edges {
            if let Ok(e) = serde_json::from_value::<EdgeInput>(ev.clone()) {
                accumulate_edge(&mut tx, &org_id, &e, "reachability", aid, tid).await?;
            }
        }

        sqlx::query(
            "DELETE FROM attack_path_graphs
             WHERE org_id = $1 AND target_id IS NOT DISTINCT FROM $2 AND source = 'reachability'",
        )
        .bind(&org_id)
        .bind(&body.target_id)
        .execute(&mut *tx)
        .await?;

        let nodes_json = JsonValue::Array(nodes.into_values().collect());
        let edges_json = JsonValue::Array(edges);
        let graph_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"INSERT INTO attack_path_graphs
                  (id, org_id, target_id, assessment_id, source, label, nodes, edges,
                   created_at, updated_at)
               VALUES ($1, $2, $3, $4, 'reachability', $5, $6, $7, NOW(), NOW())"#,
        )
        .bind(&graph_id)
        .bind(&org_id)
        .bind(&body.target_id)
        .bind(&body.assessment_id)
        .bind(format!("Reachable vulnerable services ({} chains)", matches.len()))
        .bind(&nodes_json)
        .bind(&edges_json)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(CorrelateDastResponse {
            correlated: matches.len(),
            finding_ids,
        }),
    ))
}

// =============================================================================
// POST /findings/backfill-keys — best-effort extraction of correlation keys.
// =============================================================================

static PORT_IN_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r"://[^/\s]*?:(\d{1,5})\b").unwrap());
static PORT_KV: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bport[=:\s]+(\d{1,5})\b").unwrap());
static DIGEST: Lazy<Regex> = Lazy::new(|| Regex::new(r"sha256:[0-9a-f]{64}").unwrap());
static SERVICE_KV: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bservice[=:\s]+([A-Za-z0-9._/-]+)").unwrap());
static COMPONENT_KV: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:component|package|pkg)[=:\s]+([A-Za-z0-9._/@-]+)").unwrap());

#[derive(Debug, Deserialize)]
struct BackfillBody {
    /// Optional: scope to one assessment. Omitted = every finding in the org.
    #[serde(default)]
    assessment_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct BackfillResponse {
    scanned: usize,
    updated: usize,
    /// Finding ids from which no key could be extracted — surfaced, never hidden,
    /// so the caller knows what the backfill could NOT structure.
    unparsable: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct BackfillRow {
    id: String,
    target: String,
    evidence: Option<String>,
}

fn extract_port(haystack: &str) -> Option<i32> {
    PORT_IN_URL
        .captures(haystack)
        .or_else(|| PORT_KV.captures(haystack))
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<i32>().ok())
        .filter(|p| *p > 0 && *p <= 65535)
}

async fn backfill_keys(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<BackfillBody>,
) -> AppResult<(StatusCode, Json<BackfillResponse>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Only rows still missing every key — idempotent re-runs do nothing.
    let rows: Vec<BackfillRow> = match &body.assessment_id {
        Some(aid) => {
            sqlx::query_as(
                r#"SELECT id, target, evidence FROM findings
                   WHERE org_id = $1 AND assessment_id = $2
                     AND port IS NULL AND service IS NULL
                     AND component IS NULL AND image_digest IS NULL"#,
            )
            .bind(&org_id)
            .bind(aid)
            .fetch_all(&state.pool)
            .await?
        }
        None => {
            sqlx::query_as(
                r#"SELECT id, target, evidence FROM findings
                   WHERE org_id = $1
                     AND port IS NULL AND service IS NULL
                     AND component IS NULL AND image_digest IS NULL"#,
            )
            .bind(&org_id)
            .fetch_all(&state.pool)
            .await?
        }
    };

    let scanned = rows.len();
    let mut updated = 0usize;
    let mut unparsable: Vec<String> = Vec::new();
    let mut tx = state.pool.begin().await?;

    for r in &rows {
        let hay = format!("{}\n{}", r.target, r.evidence.clone().unwrap_or_default());
        let port = extract_port(&hay);
        let image_digest = DIGEST.find(&hay).map(|m| m.as_str().to_string());
        let service = SERVICE_KV
            .captures(&hay)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        let component = COMPONENT_KV
            .captures(&hay)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        if port.is_none() && image_digest.is_none() && service.is_none() && component.is_none() {
            unparsable.push(r.id.clone());
            continue;
        }

        sqlx::query(
            r#"UPDATE findings
                  SET port = COALESCE($2, port),
                      service = COALESCE($3, service),
                      component = COALESCE($4, component),
                      image_digest = COALESCE($5, image_digest),
                      updated_at = NOW()
                WHERE id = $1"#,
        )
        .bind(&r.id)
        .bind(port)
        .bind(&service)
        .bind(&component)
        .bind(&image_digest)
        .execute(&mut *tx)
        .await?;
        updated += 1;
    }

    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(BackfillResponse { scanned, updated, unparsable }),
    ))
}
