//! Integration tests for `/api/v1/assessments/:id/tool-executions` (P1).
//!
//! Hits the real Axum router with a real Postgres pool. Guards the tool-execution
//! provenance ingest/list roundtrip — including the `"binary"` column, which is a
//! Postgres reserved word and must stay quoted in the migration + queries.

mod common;

use common::prelude::*;

fn tools_body() -> Value {
    json!({
        "tools": [
            {
                "tool_name": "scan_ports",
                "binary": "nmap",
                "installed": true,
                "version": "Nmap 7.94",
                "run_count": 2,
                "ok_count": 2,
                "fail_count": 0,
                "last_exit_code": 0
            },
            {
                "tool_name": "run_prowler",
                "binary": "prowler",
                "installed": false,
                "version": null,
                "run_count": 0,
                "ok_count": 0,
                "fail_count": 0,
                "last_exit_code": null
            }
        ]
    })
}

#[tokio::test]
async fn ingest_then_list_roundtrips_including_binary_column() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));
    let aid = "assess-1";

    let (status, body) = app
        .post_json(
            &format!("/api/v1/assessments/{aid}/tool-executions"),
            &token,
            tools_body(),
        )
        .await;
    assert!(status.is_success(), "ingest failed: {status} {body}");
    assert_eq!(body["upserted"], 2);

    let list = app
        .get_json(&format!("/api/v1/assessments/{aid}/tool-executions"), &token)
        .await;
    let rows = list.as_array().expect("list returns an array");
    assert_eq!(rows.len(), 2);

    // Ordered by tool_name ASC → run_prowler before scan_ports.
    let prowler = &rows[0];
    assert_eq!(prowler["tool_name"], "run_prowler");
    assert_eq!(prowler["binary"], "prowler");
    assert_eq!(prowler["installed"], false);

    let nmap = &rows[1];
    assert_eq!(nmap["tool_name"], "scan_ports");
    assert_eq!(nmap["binary"], "nmap");
    assert_eq!(nmap["installed"], true);
    assert_eq!(nmap["ok_count"], 2);
}

#[tokio::test]
async fn re_ingest_replaces_prior_summary() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));
    let aid = "assess-2";
    let path = format!("/api/v1/assessments/{aid}/tool-executions");

    app.post_json(&path, &token, tools_body()).await;

    // Re-promote with a single, different tool — must replace, not accumulate.
    let (status, _) = app
        .post_json(
            &path,
            &token,
            json!({ "tools": [{ "tool_name": "run_nuclei", "binary": "nuclei",
                                "installed": true, "run_count": 1, "ok_count": 1,
                                "fail_count": 0, "last_exit_code": 0 }] }),
        )
        .await;
    assert!(status.is_success());

    let list = app.get_json(&path, &token).await;
    let rows = list.as_array().unwrap();
    assert_eq!(rows.len(), 1, "re-ingest should replace the prior set");
    assert_eq!(rows[0]["tool_name"], "run_nuclei");
}

#[tokio::test]
async fn tool_executions_are_org_scoped() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    app.ensure_org("other").await;
    let aid = "shared-id";
    let path = format!("/api/v1/assessments/{aid}/tool-executions");

    let token_a = app.token_for("a", Some("groovy"));
    app.post_json(&path, &token_a, tools_body()).await;

    // A different org with the same assessment id sees none of org A's rows.
    let token_b = app.token_for("b", Some("other"));
    let list = app.get_json(&path, &token_b).await;
    assert_eq!(list.as_array().unwrap().len(), 0);
}
