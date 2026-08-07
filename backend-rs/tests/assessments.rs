//! Integration tests for `/api/v1/assessments`.
//!
//! Covers create-with-project (the v0.1.72 modal flow), list filter
//! by project_id, the assign_project PUT endpoint, and basic status
//! transitions.

mod common;

use common::prelude::*;

async fn create_project(app: &TestApp, token: &str, name: &str) -> Value {
    let (status, json) = app
        .post_json(
            "/api/v1/projects",
            token,
            json!({ "name": name }),
        )
        .await;
    assert!(status.is_success(), "create project failed: {status} {json}");
    json
}

async fn create_assessment(
    app: &TestApp,
    token: &str,
    name: &str,
    project_id: Option<&str>,
) -> Value {
    let mut body = json!({
        "type": "recon",
        "name": name,
    });
    if let Some(pid) = project_id {
        body["project_id"] = json!(pid);
    }
    let (status, json) = app.post_json("/api/v1/assessments", token, body).await;
    assert!(status.is_success(), "create assessment failed: {status} {json}");
    json
}

#[tokio::test]
async fn create_with_project_id_attaches_to_project() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let project = create_project(&app, &token, "Acme Q2 audits").await;
    let project_id = project["id"].as_str().unwrap();

    let assessment = create_assessment(&app, &token, "Staging recon", Some(project_id)).await;
    assert_eq!(assessment["name"], "Staging recon");
    assert_eq!(assessment["project_id"], project_id);
}

#[tokio::test]
async fn list_filter_by_project_narrows_correctly() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let p1 = create_project(&app, &token, "Project One").await;
    let p2 = create_project(&app, &token, "Project Two").await;
    let p1_id = p1["id"].as_str().unwrap();
    let p2_id = p2["id"].as_str().unwrap();

    create_assessment(&app, &token, "A1", Some(p1_id)).await;
    create_assessment(&app, &token, "A2", Some(p1_id)).await;
    create_assessment(&app, &token, "B1", Some(p2_id)).await;
    create_assessment(&app, &token, "C", None).await;

    let only_p1 = app
        .get_json(
            &format!("/api/v1/assessments?project_id={p1_id}&limit=50"),
            &token,
        )
        .await;
    assert_eq!(only_p1["total"], 2);

    let all = app.get_json("/api/v1/assessments?limit=50", &token).await;
    assert_eq!(all["total"], 4);
}

#[tokio::test]
async fn assign_project_endpoint_updates_attachment() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let project = create_project(&app, &token, "Eventually owned").await;
    let project_id = project["id"].as_str().unwrap();

    // Create unattached.
    let assessment = create_assessment(&app, &token, "Drift later", None).await;
    let aid = assessment["id"].as_str().unwrap();
    assert!(assessment["project_id"].is_null());

    // Attach via PUT /:id/project.
    let (status, _) = app
        .put_json(
            &format!("/api/v1/assessments/{aid}/project"),
            &token,
            json!({ "project_id": project_id }),
        )
        .await;
    assert!(status.is_success(), "attach failed: {status}");

    // Verify.
    let after = app
        .get_json(&format!("/api/v1/assessments/{aid}"), &token)
        .await;
    assert_eq!(after["project_id"], project_id);

    // Detach with null.
    let (status, _) = app
        .put_json(
            &format!("/api/v1/assessments/{aid}/project"),
            &token,
            json!({ "project_id": null }),
        )
        .await;
    assert!(status.is_success(), "detach failed: {status}");
    let detached = app
        .get_json(&format!("/api/v1/assessments/{aid}"), &token)
        .await;
    assert!(detached["project_id"].is_null());
}

/// Regression guard for the v0.1.89 enum-mismatch 500.
///
/// The frontend's `AssessmentType` (frontend/lib/types.ts) declares 11
/// values; the postgres `assessmenttype` enum only carried 7 until
/// migration 0008. The wizard sent `combined` for multi-cap selections,
/// the SQL `$2::assessmenttype` cast failed, sqlx::Error fell into
/// `AppError::Database`, and the user saw an opaque 500.
///
/// This test pins both halves of the contract:
///
///   1. Every type the frontend's TypeScript enum claims to support MUST
///      be accepted (201 Created). If anyone trims a value from the
///      postgres enum or the Rust `AssessmentTypeDb` without removing it
///      from the frontend, this test breaks loudly.
///
///   2. An unknown type MUST return a clean 400 with a `detail` body —
///      never a 500. The `ALLOWED_ASSESSMENT_TYPES` allowlist in
///      `routes/assessments.rs` is the enforcement point; this test
///      proves the allowlist catches it before the SQL cast.
///
/// The list mirrors `frontend/lib/types.ts::AssessmentType` verbatim.
/// Keep these in sync whenever a new capability ships.
#[tokio::test]
async fn create_accepts_every_declared_assessment_type() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let declared = [
        "full",
        "recon",
        "vuln_scan",
        "web_app",
        "api_security",
        "cloud_assessment",
        "combined",
        "code_scan",
        "cycode_validation",
        "exploit_validation",
        "custom",
    ];

    for ty in declared {
        let (status, json) = app
            .post_json(
                "/api/v1/assessments",
                &token,
                json!({ "type": ty, "name": format!("{ty}-smoke") }),
            )
            .await;
        assert!(
            status.is_success(),
            "type '{ty}' should be accepted but got {status}: {json}"
        );
        assert_eq!(json["type"], ty, "round-trip type mismatch for {ty}");
    }
}

#[tokio::test]
async fn create_rejects_unknown_type_with_400_not_500() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let (status, json) = app
        .post_json(
            "/api/v1/assessments",
            &token,
            json!({ "type": "not_a_real_type", "name": "bogus" }),
        )
        .await;
    // A bogus value used to fall through to sqlx's enum cast and become a
    // masked 500; the v0.1.89 allowlist returns 400 with a clear detail.
    assert_eq!(
        status.as_u16(),
        400,
        "unknown type should be 400, got {status}: {json}"
    );
    let detail = json["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("unknown assessment type") && detail.contains("not_a_real_type"),
        "expected helpful detail naming the offender, got: {detail}"
    );
}

/// The desktop wizard sends `options: {...}` on create; backend's column
/// is `config`. v0.1.89 added a serde alias so both names deserialize to
/// the same JSONB blob, and the response now emits both keys so any
/// reader can pick. This guards against either half being reverted.
#[tokio::test]
async fn create_accepts_options_alias_and_round_trips_both_keys() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let payload = json!({
        "type": "web_app",
        "name": "options-alias-smoke",
        "options": {
            "brain": "claude",
            "capabilities": ["web_app"],
            "pending_prompt": "Run a full web app security assessment.",
        },
    });
    let (status, body) = app
        .post_json("/api/v1/assessments", &token, payload)
        .await;
    assert!(status.is_success(), "options-alias create failed: {status} {body}");

    // Both keys present, identical content.
    assert_eq!(body["config"], body["options"]);
    assert_eq!(body["options"]["brain"], "claude");
    assert_eq!(body["options"]["pending_prompt"], "Run a full web app security assessment.");
}

#[tokio::test]
async fn cross_org_isolation() {
    let app = TestApp::new().await;
    app.ensure_org("alpha").await;
    app.ensure_org("beta").await;
    let token_a = app.token_for("ua", Some("alpha"));
    let token_b = app.token_for("ub", Some("beta"));

    create_assessment(&app, &token_a, "alpha-only", None).await;
    create_assessment(&app, &token_b, "beta-only", None).await;

    let alpha_list = app.get_json("/api/v1/assessments", &token_a).await;
    assert_eq!(alpha_list["total"], 1);
    assert_eq!(alpha_list["data"][0]["name"], "alpha-only");

    let beta_list = app.get_json("/api/v1/assessments", &token_b).await;
    assert_eq!(beta_list["total"], 1);
    assert_eq!(beta_list["data"][0]["name"], "beta-only");
}
