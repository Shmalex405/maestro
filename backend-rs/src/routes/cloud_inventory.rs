//! `/cloud/inventory` — W2-B of the cloud build plan.
//!
//! Endpoints:
//!   POST /cloud/inventory                  — ingest a typed cloud asset inventory
//!                                            (assets + reachability) for a target
//!   GET  /cloud/inventory?target_id=X      — list persisted assets + reachability
//!
//! Populated at end-of-run by the MCP `promote_cloud_inventory` tool (Shape A:
//! local during the run, curated promotion at the end). The correlation join that
//! turns this + Trivy findings into "deployed + reachable + vulnerable" lives in
//! the sibling correlate route (W2-C).
//!
//! All per-org scoped via JWT `custom:org_id`.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::cloud_inventory::{
    AssetReachabilityRow, CloudAssetRow, CLOUD_RESOURCE_TYPES, EXPOSURE_KINDS,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/cloud/inventory", post(ingest_inventory).get(list_inventory))
        .route("/cloud/inventory/correlate", post(correlate))
        .route("/cloud/inventory/correlations", get(list_correlations))
}

fn empty_array() -> JsonValue {
    JsonValue::Array(vec![])
}
fn empty_object() -> JsonValue {
    JsonValue::Object(serde_json::Map::new())
}

#[derive(Debug, Deserialize)]
struct AssetInput {
    resource_type: String,
    resource_arn: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default = "empty_array")]
    image_refs: JsonValue,
    #[serde(default = "empty_array")]
    image_digests: JsonValue,
    #[serde(default)]
    exposed: bool,
    #[serde(default = "empty_array")]
    exposure_ids: JsonValue,
    #[serde(default = "empty_object")]
    metadata: JsonValue,
}

#[derive(Debug, Deserialize)]
struct ReachabilityInput {
    id: String,
    exposed_via: String,
    #[serde(default)]
    endpoint: Option<String>,
    internet_facing: bool,
    source: String,
    #[serde(default = "empty_array")]
    target_resource_arns: JsonValue,
}

#[derive(Debug, Deserialize)]
struct IngestBody {
    target_id: String,
    #[serde(default)]
    assessment_id: Option<String>,
    /// When the inventory was collected (the MCP tool stamps this).
    observed_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    assets: Vec<AssetInput>,
    #[serde(default)]
    reachability: Vec<ReachabilityInput>,
}

#[derive(Debug, Serialize)]
struct IngestResponse {
    assets_upserted: usize,
    reachability_upserted: usize,
}

async fn ingest_inventory(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<IngestBody>,
) -> AppResult<(StatusCode, Json<IngestResponse>)> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // Validate enum values up front so a single bad row doesn't half-commit.
    for a in &body.assets {
        if !CLOUD_RESOURCE_TYPES.contains(&a.resource_type.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid resource_type '{}'. Must be one of: {}",
                a.resource_type,
                CLOUD_RESOURCE_TYPES.join(", ")
            )));
        }
    }
    for r in &body.reachability {
        if !EXPOSURE_KINDS.contains(&r.exposed_via.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid exposed_via '{}'. Must be one of: {}",
                r.exposed_via,
                EXPOSURE_KINDS.join(", ")
            )));
        }
    }

    let mut tx = state.pool.begin().await?;

    for a in &body.assets {
        sqlx::query(
            r#"INSERT INTO cloud_assets (
                  id, org_id, target_id, assessment_id, resource_type, resource_arn,
                  name, region, image_refs, image_digests, exposed, exposure_ids,
                  metadata, observed_at, created_at, updated_at
               )
               VALUES ($1, $2, $3, $4, $5::cloudresourcetype, $6, $7, $8, $9, $10,
                       $11, $12, $13, $14, NOW(), NOW())
               ON CONFLICT (org_id, target_id, resource_arn)
               DO UPDATE SET
                   assessment_id = EXCLUDED.assessment_id,
                   resource_type = EXCLUDED.resource_type,
                   name          = EXCLUDED.name,
                   region        = EXCLUDED.region,
                   image_refs    = EXCLUDED.image_refs,
                   image_digests = EXCLUDED.image_digests,
                   exposed       = EXCLUDED.exposed,
                   exposure_ids  = EXCLUDED.exposure_ids,
                   metadata      = EXCLUDED.metadata,
                   observed_at   = EXCLUDED.observed_at,
                   updated_at    = NOW()"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&org_id)
        .bind(&body.target_id)
        .bind(&body.assessment_id)
        .bind(&a.resource_type)
        .bind(&a.resource_arn)
        .bind(&a.name)
        .bind(&a.region)
        .bind(&a.image_refs)
        .bind(&a.image_digests)
        .bind(a.exposed)
        .bind(&a.exposure_ids)
        .bind(&a.metadata)
        .bind(body.observed_at)
        .execute(&mut *tx)
        .await?;
    }

    for r in &body.reachability {
        sqlx::query(
            r#"INSERT INTO asset_reachability (
                  id, org_id, target_id, assessment_id, exposed_via, endpoint,
                  internet_facing, source, target_resource_arns, created_at, updated_at
               )
               VALUES ($1, $2, $3, $4, $5::exposurekind, $6, $7, $8, $9, NOW(), NOW())
               ON CONFLICT (org_id, target_id, id)
               DO UPDATE SET
                   assessment_id        = EXCLUDED.assessment_id,
                   exposed_via          = EXCLUDED.exposed_via,
                   endpoint             = EXCLUDED.endpoint,
                   internet_facing      = EXCLUDED.internet_facing,
                   source               = EXCLUDED.source,
                   target_resource_arns = EXCLUDED.target_resource_arns,
                   updated_at           = NOW()"#,
        )
        .bind(&r.id)
        .bind(&org_id)
        .bind(&body.target_id)
        .bind(&body.assessment_id)
        .bind(&r.exposed_via)
        .bind(&r.endpoint)
        .bind(r.internet_facing)
        .bind(&r.source)
        .bind(&r.target_resource_arns)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(IngestResponse {
            assets_upserted: body.assets.len(),
            reachability_upserted: body.reachability.len(),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    target_id: String,
}

#[derive(Debug, Serialize)]
struct ListResponse {
    assets: Vec<AssetView>,
    reachability: Vec<ReachabilityView>,
}

#[derive(Debug, Serialize)]
struct AssetView {
    id: String,
    target_id: String,
    assessment_id: Option<String>,
    resource_type: String,
    resource_arn: String,
    name: Option<String>,
    region: Option<String>,
    image_refs: JsonValue,
    image_digests: JsonValue,
    exposed: bool,
    exposure_ids: JsonValue,
    metadata: JsonValue,
}

impl From<&CloudAssetRow> for AssetView {
    fn from(a: &CloudAssetRow) -> Self {
        Self {
            id: a.id.clone(),
            target_id: a.target_id.clone(),
            assessment_id: a.assessment_id.clone(),
            resource_type: a.resource_type.clone(),
            resource_arn: a.resource_arn.clone(),
            name: a.name.clone(),
            region: a.region.clone(),
            image_refs: a.image_refs.clone(),
            image_digests: a.image_digests.clone(),
            exposed: a.exposed,
            exposure_ids: a.exposure_ids.clone(),
            metadata: a.metadata.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ReachabilityView {
    id: String,
    exposed_via: String,
    endpoint: Option<String>,
    internet_facing: bool,
    source: String,
    target_resource_arns: JsonValue,
}

impl From<&AssetReachabilityRow> for ReachabilityView {
    fn from(r: &AssetReachabilityRow) -> Self {
        Self {
            id: r.id.clone(),
            exposed_via: r.exposed_via.clone(),
            endpoint: r.endpoint.clone(),
            internet_facing: r.internet_facing,
            source: r.source.clone(),
            target_resource_arns: r.target_resource_arns.clone(),
        }
    }
}

async fn list_inventory(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
    user: AuthUser,
) -> AppResult<Json<ListResponse>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let assets: Vec<CloudAssetRow> = sqlx::query_as(
        r#"SELECT
              id, org_id, target_id, assessment_id,
              resource_type::text AS resource_type, resource_arn, name, region,
              image_refs, image_digests, exposed, exposure_ids, metadata,
              observed_at, created_at, updated_at
           FROM cloud_assets
           WHERE org_id = $1 AND target_id = $2
           ORDER BY resource_type, name"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .fetch_all(&state.pool)
    .await?;

    let reachability: Vec<AssetReachabilityRow> = sqlx::query_as(
        r#"SELECT
              id, org_id, target_id, assessment_id,
              exposed_via::text AS exposed_via, endpoint, internet_facing, source,
              target_resource_arns, created_at, updated_at
           FROM asset_reachability
           WHERE org_id = $1 AND target_id = $2"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ListResponse {
        assets: assets.iter().map(AssetView::from).collect(),
        reachability: reachability.iter().map(ReachabilityView::from).collect(),
    }))
}

// -----------------------------------------------------------------------------
// W2-C: the reachability correlation join.
//
// Joins persisted cloud_assets (internet-reachable workloads + the images they
// run) against findings (container CVEs, matched by image digest [reliable] or
// repo:tag [best-effort]) and, for each match, upserts a distinct
// "deployed + reachable + vulnerable" correlation finding. This is the thing CSPM
// tools only model theoretically — here it is a proven join over real deployed
// state. Server-side + transactional so it runs once and atomically; the MCP
// `correlate_cloud_findings` tool calls it after promotion at end-of-run, and the
// continuous runner (W4) calls the same route.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CorrelateBody {
    target_id: String,
    #[serde(default)]
    assessment_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CorrelateResponse {
    correlated: usize,
    finding_ids: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct CorrelationMatch {
    cve: Option<String>,
    cwe: Option<String>,
    severity: String,
    image_ref: String,
    resource_arn: String,
    asset_name: Option<String>,
    resource_type: String,
    endpoint: Option<String>,
    exploitable: Option<String>,
}

async fn correlate(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CorrelateBody>,
) -> AppResult<(StatusCode, Json<CorrelateResponse>)> {
    use crate::schemas::finding::fingerprint;

    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    // image-digest match is reliable (Trivy reports the digest it scanned);
    // repo:tag membership is the best-effort fallback. jsonb_exists() is the
    // function form of the `?` operator (avoids the `?`-as-placeholder ambiguity).
    let matches: Vec<CorrelationMatch> = sqlx::query_as(
        r#"SELECT
              f.cve,
              f.cwe,
              f.severity::text          AS severity,
              f.exploitable,
              f.target                  AS image_ref,
              a.resource_arn,
              a.name                    AS asset_name,
              a.resource_type::text     AS resource_type,
              (SELECT r.endpoint FROM asset_reachability r
                 WHERE r.org_id = a.org_id AND r.target_id = a.target_id
                   AND r.internet_facing = TRUE
                   AND jsonb_exists(r.target_resource_arns, a.resource_arn)
                 LIMIT 1)               AS endpoint
           FROM findings f
           JOIN cloud_assets a
             ON a.org_id = f.org_id
            AND a.target_id = $2
            AND a.exposed = TRUE
            AND (
                  EXISTS (SELECT 1 FROM jsonb_array_elements_text(a.image_digests) d
                           WHERE f.target LIKE '%' || d)
                  OR jsonb_exists(a.image_refs, f.target)
                )
           WHERE f.org_id = $1
             AND f.cve IS NOT NULL"#,
    )
    .bind(&org_id)
    .bind(&body.target_id)
    .fetch_all(&state.pool)
    .await?;

    let mut finding_ids: Vec<String> = Vec::new();
    let mut tx = state.pool.begin().await?;

    // Accumulate a deterministic reachability attack-path graph alongside the
    // correlation findings: exposure → workload → vulnerability, one chain per
    // match. Nodes are deduped by id (matches share workloads/exposures); this
    // replaces the LLM-narrated graph for the reachable-vuln case with a computed
    // one. Persisted below under source = "reachability".
    let mut nodes: HashMap<String, JsonValue> = HashMap::new();
    let mut edges: Vec<JsonValue> = Vec::new();
    let mut edge_keys: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for m in &matches {
        let cve_label = m.cve.clone().unwrap_or_else(|| "known CVE".to_string());
        let asset_label = m.asset_name.clone().unwrap_or_else(|| m.resource_arn.clone());
        let title = format!("Reachable vulnerable workload: {cve_label} on {asset_label}");
        let endpoint_clause = match &m.endpoint {
            Some(e) => format!(" (internet-reachable at {e})"),
            None => " (internet-reachable)".to_string(),
        };
        let description = format!(
            "Container image `{}` running on {} `{}` carries {}{}. This is a deployed + \
             reachable + vulnerable correlation: a CVE on an image that is actually running on \
             an internet-facing workload — proven from deployed state, not a theoretical path.",
            m.image_ref, m.resource_type, asset_label, cve_label, endpoint_clause
        );
        let evidence = format!(
            "image_ref={}\nworkload={} ({})\ncve={}\nexposure={}",
            m.image_ref,
            m.resource_arn,
            m.resource_type,
            cve_label,
            m.endpoint.clone().unwrap_or_else(|| "internet-facing".to_string())
        );
        let target = m.resource_arn.clone();
        let source = "cloud-correlation";
        let fp = fingerprint(&title, &target, Some(source), m.cwe.as_deref());
        let id = Uuid::new_v4().to_string();

        let row: (String,) = sqlx::query_as(
            r#"INSERT INTO findings
                  (id, title, description, severity, target, target_type,
                   evidence, cve, cwe, source, fingerprint, assessment_id,
                   org_id, created_by, first_seen_at, last_seen_at)
               VALUES ($1,$2,$3,$4::severity,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),NOW())
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
        .bind(&target)
        .bind("cloud_resource")
        .bind(&evidence)
        .bind(&m.cve)
        .bind(&m.cwe)
        .bind(source)
        .bind(&fp)
        .bind(&body.assessment_id)
        .bind(&org_id)
        .bind(&user.id)
        .fetch_one(&mut *tx)
        .await?;

        let fid = row.0;
        finding_ids.push(fid.clone());

        // --- graph chain for this match (exposure → workload → vulnerability) ---
        let exposure_label = m
            .endpoint
            .clone()
            .unwrap_or_else(|| "internet-facing".to_string());
        let exposure_id = format!("exposure:{exposure_label}");
        let workload_id = format!("workload:{}", m.resource_arn);
        let vuln_id = format!("vuln:{}:{cve_label}", m.resource_arn);

        nodes.entry(exposure_id.clone()).or_insert_with(|| {
            json!({ "id": exposure_id, "label": exposure_label, "kind": "exposure", "layer": 0 })
        });
        nodes.entry(workload_id.clone()).or_insert_with(|| {
            json!({
                "id": workload_id,
                "label": asset_label,
                "kind": "workload",
                "layer": 1,
                "sub": m.resource_type,
            })
        });
        // attrs.finding_id links the vuln node back to its finding for drill-through.
        nodes.entry(vuln_id.clone()).or_insert_with(|| {
            json!({
                "id": vuln_id,
                "label": cve_label,
                "kind": "vulnerability",
                "layer": 2,
                "severity": m.severity,
                "attrs": { "finding_id": fid },
            })
        });

        // exposure→workload is exploited (the asset is genuinely internet-facing —
        // the join already filtered exposed = TRUE). workload→vuln is exploited only
        // when the finding was confirmed exploitable.
        let exploited_vuln = m.exploitable.as_deref() == Some("true");
        for (from, to, exploited) in [
            (&exposure_id, &workload_id, true),
            (&workload_id, &vuln_id, exploited_vuln),
        ] {
            if edge_keys.insert((from.clone(), to.clone())) {
                edges.push(json!({ "from": from, "to": to, "exploited": exploited }));
            }
        }
    }

    // Persist the computed graph (replace prior reachability graph for this target
    // so re-runs refresh rather than accumulate — mirrors the attack_paths ingest).
    if !nodes.is_empty() {
        // Dual-write into the normalized substrate (migration 0046) — same tx, so
        // the cloud reachability graph also accumulates into the cross-assessment
        // union. Server-generated kinds are built-ins, so no validation needed.
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
        .bind(format!("Reachable vulnerable workloads ({} chains)", matches.len()))
        .bind(&nodes_json)
        .bind(&edges_json)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(CorrelateResponse {
            correlated: matches.len(),
            finding_ids,
        }),
    ))
}

// -----------------------------------------------------------------------------
// Read-only correlations for the Coverage Dashboard (W4 "deployed + reachable +
// vulnerable" cards). Same join as `correlate` but SELECT-only — never mutates.
// Optional ?target_id=X scopes to one cloud target; omitted = org-wide.
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CorrelationsQuery {
    #[serde(default)]
    target_id: Option<String>,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
struct CorrelationView {
    finding_id: String,
    cve: Option<String>,
    severity: String,
    /// 'true' / 'potentially' / 'false' — drives EXPLOITED vs detected-only edges.
    exploitable: Option<String>,
    image_ref: String,
    resource_arn: String,
    asset_name: Option<String>,
    resource_type: String,
    endpoint: Option<String>,
    exposed_via: Option<String>,
}

async fn list_correlations(
    State(state): State<AppState>,
    Query(q): Query<CorrelationsQuery>,
    user: AuthUser,
) -> AppResult<Json<Vec<CorrelationView>>> {
    let org_id = user
        .org_id
        .clone()
        .ok_or_else(|| AppError::Forbidden("Missing org_id on caller".to_string()))?;

    let rows: Vec<CorrelationView> = sqlx::query_as(
        r#"SELECT
              f.id                      AS finding_id,
              f.cve,
              f.severity::text          AS severity,
              f.exploitable,
              f.target                  AS image_ref,
              a.resource_arn,
              a.name                    AS asset_name,
              a.resource_type::text     AS resource_type,
              (SELECT r.endpoint FROM asset_reachability r
                 WHERE r.org_id = a.org_id AND r.target_id = a.target_id
                   AND r.internet_facing = TRUE
                   AND jsonb_exists(r.target_resource_arns, a.resource_arn)
                 LIMIT 1)               AS endpoint,
              (SELECT r.exposed_via::text FROM asset_reachability r
                 WHERE r.org_id = a.org_id AND r.target_id = a.target_id
                   AND r.internet_facing = TRUE
                   AND jsonb_exists(r.target_resource_arns, a.resource_arn)
                 LIMIT 1)               AS exposed_via
           FROM findings f
           JOIN cloud_assets a
             ON a.org_id = f.org_id
            AND a.exposed = TRUE
            AND ($2::text IS NULL OR a.target_id = $2)
            AND (
                  EXISTS (SELECT 1 FROM jsonb_array_elements_text(a.image_digests) d
                           WHERE f.target LIKE '%' || d)
                  OR jsonb_exists(a.image_refs, f.target)
                )
           WHERE f.org_id = $1
             AND f.cve IS NOT NULL
           ORDER BY
             CASE f.severity
               WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
               WHEN 'low' THEN 3 ELSE 4 END"#,
    )
    .bind(&org_id)
    .bind(&q.target_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}
