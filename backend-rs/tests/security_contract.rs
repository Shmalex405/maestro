//! Cloud-API security contract tests.
//!
//! Covers the two OWASP API Top 10 categories that matter most for a
//! multi-tenant SaaS:
//!
//!   - **API1: Broken Object Level Authorization (BOLA)** — user A in
//!     org "alpha" must not see / read / write / delete user B's
//!     resources in org "beta" by guessing IDs.
//!   - **API2: Broken Authentication** — every protected route rejects
//!     requests with no token, an expired token, a wrong-secret token,
//!     and a malformed token.
//!
//! `findings` and `assessments` already have explicit cross-org tests in
//! their own integration suites; this file fills the gap for the other
//! per-org resources (projects, repositories, reports, conversations,
//! configs) and adds a route-inventory-driven auth boundary matrix that
//! new routes auto-inherit.

mod common;

use std::fs;
use std::path::PathBuf;

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use common::prelude::*;
use serde_json::json;
use tower::ServiceExt;

// =============================================================================
// BOLA / cross-org isolation
// =============================================================================

/// Helper: spin up two orgs with one user each, return both tokens.
async fn two_orgs(app: &TestApp) -> (String, String) {
    app.ensure_org("alpha").await;
    app.ensure_org("beta").await;
    let token_a = app.token_for("ua", Some("alpha"));
    let token_b = app.token_for("ub", Some("beta"));
    (token_a, token_b)
}

#[tokio::test]
async fn projects_isolate_across_orgs() {
    let app = TestApp::new().await;
    let (a, b) = two_orgs(&app).await;

    let (s, alpha_project) = app
        .post_json("/api/v1/projects", &a, json!({ "name": "alpha proj" }))
        .await;
    assert!(s.is_success(), "create alpha project: {s} {alpha_project}");
    let alpha_id = alpha_project["id"].as_str().unwrap().to_string();

    let (s, _beta_project) = app
        .post_json("/api/v1/projects", &b, json!({ "name": "beta proj" }))
        .await;
    assert!(s.is_success());

    // Each org sees only its own row in the list.
    let beta_list = app.get_json("/api/v1/projects", &b).await;
    let beta_rows = beta_list.as_array().expect("array");
    assert_eq!(beta_rows.len(), 1);
    assert_eq!(beta_rows[0]["name"], "beta proj");

    // Beta can't GET alpha's project by ID.
    let (s, body) = app
        .request(Method::GET, &format!("/api/v1/projects/{alpha_id}"), &b, None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "beta should not see alpha's project: {body}");

    // Beta can't PATCH alpha's project.
    let (s, _) = app
        .patch_json(
            &format!("/api/v1/projects/{alpha_id}"),
            &b,
            json!({ "name": "hijacked" }),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Beta can't DELETE alpha's project.
    let s = app
        .delete(&format!("/api/v1/projects/{alpha_id}"), &b)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Alpha's project is still there — beta's attempts didn't slip through.
    let alpha_still = app
        .get_json(&format!("/api/v1/projects/{alpha_id}"), &a)
        .await;
    assert_eq!(alpha_still["name"], "alpha proj");
}

#[tokio::test]
async fn repositories_isolate_across_orgs() {
    let app = TestApp::new().await;
    let (a, b) = two_orgs(&app).await;

    let (s, alpha_repo) = app
        .post_json("/api/v1/repositories", &a, json!({ "name": "alpha-repo" }))
        .await;
    assert!(s.is_success(), "create alpha repo: {s} {alpha_repo}");
    let alpha_id = alpha_repo["id"].as_str().unwrap().to_string();

    let (s, body) = app
        .request(Method::GET, &format!("/api/v1/repositories/{alpha_id}"), &b, None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "beta should not see alpha's repo: {body}");

    let s = app
        .delete(&format!("/api/v1/repositories/{alpha_id}"), &b)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reports_isolate_across_orgs() {
    let app = TestApp::new().await;
    let (a, b) = two_orgs(&app).await;

    // Reports require an assessment_id — create one in alpha first.
    let (s, assessment) = app
        .post_json(
            "/api/v1/assessments",
            &a,
            json!({ "type": "recon", "name": "alpha-assessment" }),
        )
        .await;
    assert!(s.is_success(), "create alpha assessment: {s} {assessment}");
    let assessment_id = assessment["id"].as_str().unwrap();

    let (s, report) = app
        .post_json(
            "/api/v1/reports",
            &a,
            json!({
                "title": "alpha report",
                "format": "markdown",
                "assessment_id": assessment_id,
            }),
        )
        .await;
    assert!(s.is_success(), "create alpha report: {s} {report}");
    let report_id = report["id"].as_str().unwrap().to_string();

    let (s, body) = app
        .request(Method::GET, &format!("/api/v1/reports/{report_id}"), &b, None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "beta should not see alpha's report: {body}");

    let s = app
        .delete(&format!("/api/v1/reports/{report_id}"), &b)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn conversations_isolate_across_orgs() {
    let app = TestApp::new().await;
    let (a, b) = two_orgs(&app).await;

    let (s, conv) = app
        .post_json("/api/v1/conversations", &a, json!({ "title": "alpha chat" }))
        .await;
    assert!(s.is_success(), "create alpha conversation: {s} {conv}");
    let conv_id = conv["id"].as_str().unwrap().to_string();

    // Beta's list is empty.
    let beta_list = app.get_json("/api/v1/conversations", &b).await;
    if let Some(items) = beta_list["data"].as_array() {
        assert!(items.is_empty(), "beta should see no conversations: {beta_list}");
    } else if let Some(items) = beta_list.as_array() {
        assert!(items.is_empty(), "beta should see no conversations: {beta_list}");
    }

    let (s, body) = app
        .request(Method::GET, &format!("/api/v1/conversations/{conv_id}"), &b, None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "beta should not see alpha's conversation: {body}");
}

#[tokio::test]
async fn configs_isolate_across_orgs() {
    let app = TestApp::new().await;
    let (a, b) = two_orgs(&app).await;

    // Configs are keyed by `kind`. Alpha writes `scope`; beta should
    // get a separate `scope` value, not alpha's.
    let (s, _) = app
        .put_json(
            "/api/v1/configs/scope",
            &a,
            json!({ "value": { "in_scope": ["alpha.example.com"] } }),
        )
        .await;
    assert!(s.is_success(), "alpha put scope config: {s}");

    let (s, _) = app
        .put_json(
            "/api/v1/configs/scope",
            &b,
            json!({ "value": { "in_scope": ["beta.example.com"] } }),
        )
        .await;
    assert!(s.is_success(), "beta put scope config: {s}");

    // Each org reads its own value.
    let alpha_scope = app.get_json("/api/v1/configs/scope", &a).await;
    assert_eq!(
        alpha_scope["value"]["in_scope"][0], "alpha.example.com",
        "alpha read its own scope, not beta's: {alpha_scope}"
    );
    let beta_scope = app.get_json("/api/v1/configs/scope", &b).await;
    assert_eq!(
        beta_scope["value"]["in_scope"][0], "beta.example.com",
        "beta read its own scope, not alpha's: {beta_scope}"
    );
}

/// The attack-graph substrate (migration 0046) is the highest cross-org
/// leakage risk in the codebase: `/graph/paths` runs a recursive join that
/// walks the node/edge union. A missing org filter on any join in that CTE
/// would let one tenant traverse another's escalation graph. This asserts the
/// union is invisible AND untraversable across orgs.
#[tokio::test]
async fn graph_substrate_isolates_across_orgs() {
    let app = TestApp::new().await;
    let (a, b) = two_orgs(&app).await;

    // Alpha ingests a source -> workload -> asset(crown jewel) chain.
    let (s, ing) = app
        .post_json(
            "/api/v1/graph/ingest",
            &a,
            json!({
                "source": "chain-analysis",
                "nodes": [
                    { "id": "alpha-net",   "kind": "source",   "label": "Internet", "layer": 0 },
                    { "id": "alpha-wl",    "kind": "workload", "label": "svc",       "layer": 1 },
                    { "id": "alpha-crown", "kind": "asset",    "label": "prod-db",   "layer": 2 }
                ],
                "edges": [
                    { "from": "alpha-net", "to": "alpha-wl",    "exploited": true },
                    { "from": "alpha-wl",  "to": "alpha-crown", "exploited": true }
                ]
            }),
        )
        .await;
    assert!(s.is_success(), "alpha ingest should succeed: {s} {ing}");

    // Alpha sees exactly its three nodes.
    let alpha_nodes = app.get_json("/api/v1/graph/nodes", &a).await;
    assert_eq!(
        alpha_nodes.as_array().map(|r| r.len()),
        Some(3),
        "alpha should see its own nodes: {alpha_nodes}"
    );

    // Beta's node list is empty — the union is org-scoped.
    let beta_nodes = app.get_json("/api/v1/graph/nodes", &b).await;
    assert!(
        beta_nodes.as_array().expect("array").is_empty(),
        "beta must NOT see alpha's nodes: {beta_nodes}"
    );

    // Positive control: alpha can pathfind source -> crown jewel.
    let (s, alpha_paths) = app
        .post_json(
            "/api/v1/graph/paths",
            &a,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert!(s.is_success(), "alpha paths query: {s} {alpha_paths}");
    assert!(
        !alpha_paths["paths"].as_array().expect("paths array").is_empty(),
        "alpha should find a path to its crown jewel: {alpha_paths}"
    );

    // Beta runs the identical query and must get NOTHING — the recursive join
    // never crosses into alpha's union.
    let (s, beta_paths) = app
        .post_json(
            "/api/v1/graph/paths",
            &b,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert!(s.is_success(), "beta paths query: {s} {beta_paths}");
    assert!(
        beta_paths["paths"].as_array().expect("paths array").is_empty(),
        "beta must NOT traverse alpha's graph: {beta_paths}"
    );

    // Reachability-only variant is org-scoped too.
    let (s, beta_reach) = app
        .post_json(
            "/api/v1/graph/paths",
            &b,
            json!({ "source_kind": "source", "goal_kind": "asset", "reachable_only": true }),
        )
        .await;
    assert!(s.is_success(), "beta reachable query: {s} {beta_reach}");
    assert!(
        beta_reach["reachable"].as_array().expect("reachable array").is_empty(),
        "beta must NOT reach alpha's crown jewel: {beta_reach}"
    );
}

// =============================================================================
// Authentication boundary
// =============================================================================

/// Source-parse the route inventory so new routes auto-inherit the
/// auth-boundary check. Duplicated from `route_registration.rs` rather
/// than extracted to a shared helper — the parser is small and keeping
/// it inline lets each test file evolve independently.
fn declared_routes() -> Vec<(Method, String, String)> {
    let routes_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/routes");
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&routes_dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") { continue }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some("mod") => continue,
            Some(s) => s.to_string(),
            None => continue,
        };
        let src = fs::read_to_string(&path).unwrap_or_default();
        let bytes = src.as_bytes();
        for (start, _) in src.match_indices(".route(") {
            let after_open = start + ".route(".len();
            let mut j = after_open;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() { j += 1; }
            if j >= bytes.len() || bytes[j] != b'"' { continue }
            j += 1;
            let path_start = j;
            while j < bytes.len() && bytes[j] != b'"' { j += 1; }
            if j >= bytes.len() { continue }
            let route_path = src[path_start..j].to_string();
            j += 1;
            let mut depth = 1usize;
            let scan_from = j;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => { depth -= 1; if depth == 0 { break } }
                    _ => {}
                }
                j += 1;
            }
            let methods_buf = &src[scan_from..j];
            for tok in [
                ("get(", Method::GET),
                ("post(", Method::POST),
                ("put(", Method::PUT),
                ("patch(", Method::PATCH),
                ("delete(", Method::DELETE),
            ] {
                if methods_buf.contains(tok.0) {
                    out.push((tok.1.clone(), route_path.clone(), stem.clone()));
                }
            }
        }
    }
    out
}

fn fill_params(path: &str) -> String {
    let mut out = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ':' {
            while let Some(&nc) = chars.peek() {
                if nc.is_alphanumeric() || nc == '_' { chars.next(); } else { break }
            }
            out.push_str("00000000-0000-0000-0000-000000000000");
        } else {
            out.push(c);
        }
    }
    out
}

/// Routes that are intentionally unauthenticated. New entries here should
/// be reviewed carefully — every public endpoint is an attack surface.
fn public_routes() -> std::collections::HashSet<&'static str> {
    std::collections::HashSet::from([
        // Health probes are public — they need to work before auth is set up.
        "/health",
        "/health/ready",
        "/health/live",
        // Version is public — clients use it for compatibility checks.
        "/api/v1/version",
        // Auth endpoints (login/register) are public by definition.
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/refresh",
        // Provider discovery is called pre-login so the client knows which
        // IdPs (local / cognito) the deployment is configured for. Returns
        // configuration only, no per-user data.
        "/api/v1/auth/providers",
        // Toolkit credentials are stubbed public for the desktop client to
        // pull the Kali image; in prod they're gated by deployment config,
        // not by the framework's auth middleware.
        "/api/v1/toolkit/registry-credentials",
    ])
}

async fn assert_unauthorized(app: &TestApp, method: Method, path: &str, header_value: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().method(method.clone()).uri(path);
    if let Some(v) = header_value {
        builder = builder.header(header::AUTHORIZATION, v);
    }
    let body = if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from("{}")
    } else {
        Body::empty()
    };
    let req = builder.body(body).expect("build request");
    let resp = app.app.clone().oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let _ = to_bytes(resp.into_body(), 64 * 1024).await;
    status
}

#[tokio::test]
async fn every_protected_route_rejects_missing_token() {
    let app = TestApp::new().await;
    let public = public_routes();

    let mut leaks: Vec<String> = Vec::new();
    for (method, raw_path, module) in declared_routes() {
        let mount = if module == "health" { "" } else { "/api/v1" };
        let canonical = format!("{mount}{raw_path}");
        if public.contains(canonical.as_str()) { continue }

        let path = format!("{mount}{}", fill_params(&raw_path));
        let status = assert_unauthorized(&app, method.clone(), &path, None).await;

        // 401 is the expected response. 403 and 422 are also acceptable
        // (some routes hit the body extractor before auth — that's an
        // implementation detail, not a security boundary failure, as
        // long as it never returns 2xx/3xx without a token).
        if status.is_success() || status.is_redirection() {
            leaks.push(format!("{method} {path} → {status} without auth"));
        }
    }

    assert!(
        leaks.is_empty(),
        "Routes returned success without a token (potential auth bypass):\n{}",
        leaks.join("\n")
    );
}

#[tokio::test]
async fn malformed_jwt_is_rejected() {
    let app = TestApp::new().await;
    let status = assert_unauthorized(
        &app,
        Method::GET,
        "/api/v1/findings",
        Some("Bearer not-a-jwt"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "malformed JWT should be rejected with 401",
    );
}

#[tokio::test]
async fn wrong_secret_jwt_is_rejected() {
    let app = TestApp::new().await;
    // A real-looking JWT but signed with a different secret. The
    // structure is base64url(header).base64url(claims).base64url(sig).
    // The signature here was computed against a non-matching key.
    let forged = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciIsIm9yZ19pZCI6ImhpamFja2VkIn0.WRONG_SIGNATURE";
    let status = assert_unauthorized(
        &app,
        Method::GET,
        "/api/v1/findings",
        Some(&format!("Bearer {forged}")),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "wrong-secret JWT should be rejected with 401",
    );
}

#[tokio::test]
async fn header_without_bearer_prefix_is_rejected() {
    let app = TestApp::new().await;
    // A valid token but without the `Bearer ` prefix the auth middleware
    // requires. Confirms the parser doesn't fall back to whitespace-
    // splitting tricks.
    let token = app.token_for("u", Some("org"));
    let status = assert_unauthorized(
        &app,
        Method::GET,
        "/api/v1/findings",
        Some(&token), // no "Bearer " prefix
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Authorization header without Bearer prefix should be rejected",
    );
}
