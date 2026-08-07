//! Functional tests for the post-exploitation foothold store (migration 0048 + /footholds).
//!
//! Covers the operator's lifecycle: deposit on acquire, enumerate live footholds,
//! consume material, revoke (one + end-of-run all), expiry exclusion, kind validation.

mod common;

use axum::http::StatusCode;
use common::prelude::*;

async fn one_org(app: &TestApp) -> String {
    app.ensure_org("acme").await;
    app.token_for("u", Some("acme"))
}

#[tokio::test]
async fn establish_list_consume_revoke() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    let (s, fh) = app
        .post_json(
            "/api/v1/footholds",
            &tok,
            json!({
                "assessment_id": "a1",
                "kind": "token",
                "target": "api.example.com",
                "material": { "bearer": "eyJ...stolen" },
                "grants": ["api_session", "pii_read"],
                "how_acquired": "FINDING-12"
            }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "establish: {fh}");
    let id = fh["id"].as_str().expect("id").to_string();
    assert_eq!(fh["status"], "live");
    assert_eq!(fh["grants"], json!(["api_session", "pii_read"]), "grants seed the planner: {fh}");

    // Enumerate live footholds for the assessment.
    let live = app
        .get_json("/api/v1/footholds?assessment_id=a1&status=live", &tok)
        .await;
    assert_eq!(live.as_array().unwrap().len(), 1, "one live foothold: {live}");

    // Consume returns the held material (internal, never redacted).
    let got = app.get_json(&format!("/api/v1/footholds/{id}"), &tok).await;
    assert_eq!(got["material"]["bearer"], "eyJ...stolen", "consume returns material: {got}");

    // Revoke → no longer live.
    let (s, _) = app
        .post_json(&format!("/api/v1/footholds/{id}/revoke"), &tok, json!({}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let live = app
        .get_json("/api/v1/footholds?assessment_id=a1&status=live", &tok)
        .await;
    assert_eq!(live.as_array().unwrap().len(), 0, "revoked foothold not live: {live}");
}

#[tokio::test]
async fn invalid_kind_rejected() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;
    let (s, _) = app
        .post_json(
            "/api/v1/footholds",
            &tok,
            json!({ "assessment_id": "a1", "kind": "implant", "target": "x" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown foothold kind rejected (no C2/implant)");
}

#[tokio::test]
async fn revoke_all_at_end_of_run() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;
    for k in ["token", "credential", "assumed_role"] {
        app.post_json(
            "/api/v1/footholds",
            &tok,
            json!({ "assessment_id": "a2", "kind": k, "target": "t" }),
        )
        .await;
    }
    let live = app
        .get_json("/api/v1/footholds?assessment_id=a2&status=live", &tok)
        .await;
    assert_eq!(live.as_array().unwrap().len(), 3);

    let (s, res) = app
        .post_json("/api/v1/footholds/revoke?assessment_id=a2", &tok, json!({}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(res["revoked"], 3, "all three revoked at end-of-run: {res}");
    let live = app
        .get_json("/api/v1/footholds?assessment_id=a2&status=live", &tok)
        .await;
    assert_eq!(live.as_array().unwrap().len(), 0, "none live after revoke-all");
}

#[tokio::test]
async fn expired_foothold_excluded_from_live() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;
    app.post_json(
        "/api/v1/footholds",
        &tok,
        json!({
            "assessment_id": "a3", "kind": "assumed_role", "target": "arn:aws:iam::1:role/x",
            "expires_at": "2000-01-01T00:00:00Z"
        }),
    )
    .await;
    let live = app
        .get_json("/api/v1/footholds?assessment_id=a3&status=live", &tok)
        .await;
    assert_eq!(
        live.as_array().unwrap().len(),
        0,
        "past-expiry foothold excluded from live so the operator never plans through it: {live}"
    );
    let all = app.get_json("/api/v1/footholds?assessment_id=a3", &tok).await;
    assert_eq!(all.as_array().unwrap().len(), 1, "still present unfiltered: {all}");
}
