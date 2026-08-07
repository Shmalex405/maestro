//! End-to-end golden-path test.
//!
//! Exercises the full assessment lifecycle through the backend-rs HTTP
//! API in a single test so we catch the class of bug where the
//! individual layers each pass their own contract test but the flow
//! between them is broken.
//!
//! Flow:
//!   1. Create a project
//!   2. Create an assessment in that project
//!   3. Persist a finding against the assessment
//!   4. List findings filtered by assessment_id — finding shows up
//!   5. Snapshot the assessment's findings
//!   6. List snapshots — snapshot shows up
//!   7. Delete the assessment — cascades through related rows
//!
//! Needs Postgres on :5433 (same as the other backend-rs tests). The MCP
//! tool layer and Tauri shell each have their own registration + contract
//! tests; this one stays in the HTTP layer so it stays cheap and fast.

mod common;

use common::prelude::*;
use serde_json::json;

#[tokio::test]
async fn assessment_to_finding_to_snapshot_round_trip() {
    let app = TestApp::new().await;
    app.ensure_org("e2e").await;
    let token = app.token_for("e2e-user", Some("e2e"));

    // 1. Create a project ------------------------------------------------
    let (s, project) = app
        .post_json("/api/v1/projects", &token, json!({ "name": "Golden path" }))
        .await;
    assert!(s.is_success(), "create project: {s} {project}");
    let project_id = project["id"].as_str().expect("project id");

    // 2. Create an assessment in the project -----------------------------
    let (s, assessment) = app
        .post_json(
            "/api/v1/assessments",
            &token,
            json!({
                "type": "recon",
                "name": "Round-trip",
                "project_id": project_id,
            }),
        )
        .await;
    assert!(s.is_success(), "create assessment: {s} {assessment}");
    let assessment_id = assessment["id"].as_str().expect("assessment id");
    assert_eq!(assessment["project_id"], project_id);

    // 3. Persist a finding against the assessment ------------------------
    let (s, finding) = app
        .post_json(
            "/api/v1/findings",
            &token,
            json!({
                "title": "Open port on staging",
                "severity": "medium",
                "target": "staging.example.com:8080",
                "description": "TCP/8080 open on staging — Tomcat default page exposed.",
                "source": "vuln_scan",
                "assessment_id": assessment_id,
            }),
        )
        .await;
    assert!(s.is_success(), "create finding: {s} {finding}");
    let finding_id = finding["id"].as_str().expect("finding id");
    // The route derives `category` from `source` — confirm the derivation ran
    // rather than the column being NULL or echoing source verbatim. Source
    // "vuln_scan" folds into web_app under the surface taxonomy (vuln_scan is
    // no longer its own category), which proves the derivation (non-echo).
    assert_eq!(finding["category"], "web_app");

    // 4. Listing findings by assessment_id surfaces our finding ----------
    let by_assessment = app
        .get_json(
            &format!("/api/v1/findings?assessment_id={assessment_id}&limit=50"),
            &token,
        )
        .await;
    assert_eq!(by_assessment["total"], 1, "should see exactly 1 finding for this assessment");
    let items = by_assessment["data"].as_array().expect("data array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], finding_id);

    // Fetching the finding by id round-trips the row.
    let single = app
        .get_json(&format!("/api/v1/findings/{finding_id}"), &token)
        .await;
    assert_eq!(single["id"], finding_id);
    assert_eq!(single["title"], "Open port on staging");

    // 5. Snapshot the assessment ----------------------------------------
    let (s, snapshot) = app
        .post_json(
            "/api/v1/scan-snapshots",
            &token,
            json!({
                "assessment_id": assessment_id,
                "label": "Baseline",
            }),
        )
        .await;
    assert!(s.is_success(), "create snapshot: {s} {snapshot}");
    let snapshot_id = snapshot["id"].as_str().expect("snapshot id");

    // 6. List snapshots ------------------------------------------------
    let snapshots = app
        .get_json(
            &format!("/api/v1/scan-snapshots?assessment_id={assessment_id}"),
            &token,
        )
        .await;
    let snap_items = snapshots["data"]
        .as_array()
        .or_else(|| snapshots.as_array())
        .expect("snapshot list");
    assert!(
        snap_items.iter().any(|s| s["id"] == snapshot_id),
        "snapshot {snapshot_id} should appear in list: {snapshots}"
    );

    // 7. Tear-down: DELETE soft-archives the assessment -----------------
    // Migration 0015 + the v1.0.10 dashboard change moved DELETE from a
    // hard row drop to `UPDATE assessments SET archived_at = NOW()`.
    // The user wanted past engagements to stay on record. So the cascade
    // FKs on findings + reports no longer fire — both rows survive — and
    // the assessment itself is still fetchable by id, just hidden from
    // the default list view (include_archived=true brings it back).
    let s = app
        .delete(&format!("/api/v1/assessments/{assessment_id}"), &token)
        .await;
    assert!(
        s.is_success() || s == axum::http::StatusCode::NO_CONTENT,
        "delete assessment: {s} — should soft-archive (204), see migration 0015"
    );

    // The assessment row is still there, with archived_at populated.
    let archived = app
        .get_json(&format!("/api/v1/assessments/{assessment_id}"), &token)
        .await;
    assert_eq!(archived["id"], assessment_id);
    assert!(
        archived["archived_at"].as_str().is_some(),
        "archived_at should be set after DELETE: {archived}"
    );

    // Default list hides archived runs.
    let default_list = app.get_json("/api/v1/assessments?limit=50", &token).await;
    let default_items = default_list["data"].as_array().expect("data array");
    assert!(
        default_items.iter().all(|a| a["id"] != assessment_id),
        "archived assessment should not appear in default list"
    );

    // include_archived=true brings it back.
    let with_archived = app
        .get_json("/api/v1/assessments?include_archived=true&limit=50", &token)
        .await;
    let archived_items = with_archived["data"].as_array().expect("data array");
    assert!(
        archived_items.iter().any(|a| a["id"] == assessment_id),
        "archived assessment should appear when include_archived=true"
    );

    // And the finding survives — it's part of the historical record now,
    // not cascaded away. (Re-running the assessment will update the
    // existing row via the (fingerprint, org_id) upsert.)
    let surviving = app
        .get_json(&format!("/api/v1/findings/{finding_id}"), &token)
        .await;
    assert_eq!(surviving["id"], finding_id);
}
