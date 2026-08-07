//! Integration tests for the deterministic correlation engine (P2).
//!
//! Exercises the real SQL joins end-to-end against Postgres:
//!   - POST /correlate/dast joins recon-discovered open ports against vulnerable
//!     findings and emits a "dast-correlation" finding + a computed reachability
//!     attack-path graph.
//!   - POST /findings/backfill-keys extracts structured join keys from free text.
//!
//! Seeds via the public ingest APIs (targets/resolve, recon-cache, findings) so
//! the test mirrors how data actually lands in the backend.

mod common;

use common::prelude::*;

async fn resolve_target(app: &TestApp, token: &str, raw: &str, ttype: &str) -> String {
    let (status, body) = app
        .post_json(
            "/api/v1/targets/resolve",
            token,
            json!({ "raw_value": raw, "target_type": ttype }),
        )
        .await;
    assert!(status.is_success(), "resolve failed: {status} {body}");
    body["id"].as_str().expect("target id").to_string()
}

#[tokio::test]
async fn dast_correlation_emits_finding_and_reachability_graph() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let target_id = resolve_target(&app, &token, "https://staging.example.com", "web").await;

    // Recon found port 8080 open on the target.
    let (s, b) = app
        .post_json(
            "/api/v1/recon-cache",
            &token,
            json!({
                "target_id": target_id,
                "scan_type": "ports",
                "snapshot": { "open": [8080, 443], "services": { "8080": "nginx-1.24" } },
                "scan_completed_at": "2026-06-10T00:00:00Z"
            }),
        )
        .await;
    assert!(s.is_success(), "recon-cache upsert failed: {s} {b}");

    // A CVE-bearing finding sitting on that open port.
    let (s, b) = app
        .post_json(
            "/api/v1/findings",
            &token,
            json!({
                "title": "Outdated nginx with known CVE",
                "severity": "high",
                "target": "https://staging.example.com:8080/",
                "cve": "CVE-2024-7347",
                "source": "nuclei",
                "port": 8080,
                "exploitable": "true"
            }),
        )
        .await;
    assert!(s.is_success(), "finding create failed: {s} {b}");

    // Run the correlation.
    let (s, corr) = app
        .post_json(
            "/api/v1/correlate/dast",
            &token,
            json!({ "target_id": target_id }),
        )
        .await;
    assert!(s.is_success(), "correlate/dast failed: {s} {corr}");
    assert_eq!(corr["correlated"], 1, "expected one reachable+vulnerable match");

    // A dast-correlation finding was upserted.
    let findings = app.get_json("/api/v1/findings?limit=100", &token).await;
    let items = findings["data"].as_array().expect("findings data");
    assert!(
        items.iter().any(|f| f["source"] == "dast-correlation"),
        "expected a dast-correlation finding among {items:?}"
    );

    // A computed reachability attack-path graph exists for the target.
    let graphs = app
        .get_json(
            &format!("/api/v1/cloud/attack-paths?target_id={target_id}"),
            &token,
        )
        .await;
    let glist = graphs.as_array().expect("graphs array");
    let reach = glist
        .iter()
        .find(|g| g["source"] == "reachability")
        .expect("a reachability graph was produced");
    let nodes = reach["nodes"].as_array().expect("nodes");
    // exposure → workload → vulnerability = 3 node kinds in one chain.
    assert!(nodes.len() >= 3, "expected >=3 graph nodes, got {}", nodes.len());
    assert!(
        nodes.iter().any(|n| n["kind"] == "vulnerability"),
        "graph should contain a vulnerability node"
    );
}

#[tokio::test]
async fn dast_correlation_is_zero_when_port_not_reachable() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));
    let target_id = resolve_target(&app, &token, "https://staging.example.com", "web").await;

    // Recon found only 443 open — the finding's port 8080 is NOT reachable.
    app.post_json(
        "/api/v1/recon-cache",
        &token,
        json!({
            "target_id": target_id,
            "scan_type": "ports",
            "snapshot": { "open": [443] },
            "scan_completed_at": "2026-06-10T00:00:00Z"
        }),
    )
    .await;
    app.post_json(
        "/api/v1/findings",
        &token,
        json!({
            "title": "CVE on an unreachable port",
            "severity": "high",
            "target": "internal-host:8080",
            "cve": "CVE-2024-0001",
            "source": "nuclei",
            "port": 8080
        }),
    )
    .await;

    let (_s, corr) = app
        .post_json(
            "/api/v1/correlate/dast",
            &token,
            json!({ "target_id": target_id }),
        )
        .await;
    assert_eq!(corr["correlated"], 0, "unreachable port must not correlate");
}

#[tokio::test]
async fn backfill_keys_extracts_port_from_evidence() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    // Bare-host target (no URL → no auto-derive); the port lives in evidence.
    app.post_json(
        "/api/v1/findings",
        &token,
        json!({
            "title": "Service on a non-standard port",
            "severity": "medium",
            "target": "internal-host",
            "evidence": "observed banner on port=9000 service=redis",
            "cve": "CVE-2024-1234",
            "source": "nmap"
        }),
    )
    .await;

    let (s, res) = app
        .post_json("/api/v1/findings/backfill-keys", &token, json!({}))
        .await;
    assert!(s.is_success(), "backfill failed: {s} {res}");
    assert!(res["updated"].as_u64().unwrap() >= 1, "expected >=1 row updated: {res}");
}
