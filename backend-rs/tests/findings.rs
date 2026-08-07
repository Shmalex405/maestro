//! Integration tests for `/api/v1/findings`.
//!
//! Hits the real Axum router with a real Postgres pool (per-test ephemeral
//! database via `common::TestApp`). Auth uses the `local` JWT provider so
//! tests don't depend on Cognito.
//!
//! What we cover:
//!   - Create returns the row + derives `category` from `source`
//!   - List paginates + scopes by org
//!   - List filter `?category=foo` narrows the right way (incl. `other`)
//!   - Stats `by_category` partitions cleanly + sums to `total`
//!   - Stats `by_severity` narrows when `?category=` is passed (the
//!     v0.1.69 fix that made severity cards reflect the active tab)
//!   - Stats `exploitable_count` + `fully_exploited_count` + `partial_exploited_count`
//!   - The `exploitable` filter on list (`?exploitable=true|potentially|any`)
//!   - Cross-org isolation — user A cannot see user B's findings

mod common;

use common::prelude::*;

async fn create_finding(
    app: &TestApp,
    token: &str,
    title: &str,
    severity: &str,
    target: &str,
    source: Option<&str>,
    exploitable: Option<&str>,
) -> Value {
    let mut body = json!({
        "title": title,
        "severity": severity,
        "target": target,
    });
    if let Some(s) = source {
        body["source"] = json!(s);
    }
    if let Some(e) = exploitable {
        body["exploitable"] = json!(e);
    }
    let (status, json) = app.post_json("/api/v1/findings", token, body).await;
    assert!(status.is_success(), "create finding failed: {status} {json}");
    json
}

async fn fetch_stats(app: &TestApp, token: &str, query: &str) -> Value {
    app.get_json(&format!("/api/v1/findings/stats{query}"), token)
        .await
}

#[tokio::test]
async fn create_returns_category_derived_from_source() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let f = create_finding(
        &app,
        &token,
        "SQL injection in /users",
        "high",
        "https://staging.example.com/users",
        Some("sqlmap"),
        Some("true"),
    )
    .await;
    assert_eq!(f["title"], "SQL injection in /users");
    assert_eq!(f["category"], "web_app");
    assert_eq!(f["exploitable"], "true");
}

#[tokio::test]
async fn list_filter_by_category_narrows_correctly() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    // Mixed sources across categories (surface taxonomy).
    create_finding(&app, &token, "X1", "high", "t1", Some("sqlmap"), None).await; // web_app
    // cloud-only source (matches %cloud%, NOT web_app's broad test_%) so the
    // category filter stays disjoint for this assertion.
    create_finding(&app, &token, "X2", "low", "t2", Some("cloud-recon:CLOUD-05"), None).await; // cloud
    create_finding(&app, &token, "X3", "low", "t3", Some("semgrep"), None).await; // code_security
    create_finding(&app, &token, "X4", "low", "t4", Some("nmap"), None).await; // infrastructure
    create_finding(&app, &token, "X5", "low", "t5", Some("garbage-source"), None).await; // other

    let webapp = app
        .get_json("/api/v1/findings?category=web_app&limit=50", &token)
        .await;
    assert_eq!(webapp["total"], 1);
    assert_eq!(webapp["data"][0]["title"], "X1");

    // Cloud is its own first-class category now (split out of infrastructure).
    let cloud = app
        .get_json("/api/v1/findings?category=cloud&limit=50", &token)
        .await;
    assert_eq!(cloud["total"], 1);
    assert_eq!(cloud["data"][0]["title"], "X2");

    let other = app
        .get_json("/api/v1/findings?category=other&limit=50", &token)
        .await;
    assert_eq!(other["total"], 1);
    assert_eq!(other["data"][0]["title"], "X5");

    let bad = app
        .get_json("/api/v1/findings?category=does_not_exist&limit=50", &token)
        .await;
    // Unknown category short-circuits to AND 1=0 → empty result.
    assert_eq!(bad["total"], 0);
}

#[tokio::test]
async fn stats_by_category_sums_to_total() {
    // The v0.1.66 regression we shipped: `other` was returning 0 because
    // the category_clause empty-patterns guard fired before the special
    // 'other' branch, leaving uncategorized findings invisible. This
    // test fails on that bug.
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    create_finding(&app, &token, "v1", "high", "t1", Some("nuclei"), None).await;
    create_finding(&app, &token, "v2", "high", "t2", Some("nuclei"), None).await;
    create_finding(&app, &token, "w1", "low", "t3", Some("sqlmap"), None).await;
    create_finding(&app, &token, "c1", "low", "t4", Some("semgrep"), None).await;
    create_finding(&app, &token, "i1", "low", "t5", Some("nmap"), None).await;
    create_finding(&app, &token, "o1", "low", "t6", Some("weird-tool"), None).await;
    create_finding(&app, &token, "e1", "low", "t7", Some("metasploit"), Some("true")).await;

    let stats = fetch_stats(&app, &token, "").await;
    assert_eq!(stats["total"], 7);
    let bc = &stats["by_category"];
    // Surface taxonomy: nuclei (scanner) + metasploit (exploit) both fold into
    // web_app → 2 nuclei + sqlmap + metasploit = 4.
    assert_eq!(bc["web_app"], 4);
    assert_eq!(bc["code_security"], 1);
    assert_eq!(bc["infrastructure"], 1);
    assert_eq!(bc["other"], 1);

    let sum: i64 = ["web_app", "code_security", "cloud", "infrastructure", "identity", "ai", "other"]
        .iter()
        .map(|k| bc[k].as_i64().unwrap())
        .sum();
    assert_eq!(sum, stats["total"].as_i64().unwrap());
}

#[tokio::test]
async fn stats_severity_narrows_when_category_passed() {
    // The v0.1.69 fix: severity cards reflect the active tab. Was
    // pre-fix returning all-findings totals regardless of ?category=.
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    // 1 critical web_app, 1 high web_app, 2 low code_security
    create_finding(&app, &token, "w-c", "critical", "t1", Some("sqlmap"), None).await;
    create_finding(&app, &token, "w-h", "high", "t2", Some("sqlmap"), None).await;
    create_finding(&app, &token, "c-1", "low", "t3", Some("semgrep"), None).await;
    create_finding(&app, &token, "c-2", "low", "t4", Some("semgrep"), None).await;

    let global = fetch_stats(&app, &token, "").await;
    assert_eq!(global["total"], 4);
    assert_eq!(global["by_severity"]["critical"], 1);
    assert_eq!(global["by_severity"]["high"], 1);
    assert_eq!(global["by_severity"]["low"], 2);

    let webapp_stats = fetch_stats(&app, &token, "?category=web_app").await;
    assert_eq!(webapp_stats["total"], 2);
    assert_eq!(webapp_stats["by_severity"]["critical"], 1);
    assert_eq!(webapp_stats["by_severity"]["high"], 1);
    assert_eq!(webapp_stats["by_severity"]["low"], 0);

    let code_stats = fetch_stats(&app, &token, "?category=code_security").await;
    assert_eq!(code_stats["total"], 2);
    assert_eq!(code_stats["by_severity"]["low"], 2);
}

#[tokio::test]
async fn stats_exploitable_counts_split_into_fully_and_partial() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    create_finding(&app, &token, "f1", "high", "t1", Some("sqlmap"), Some("true")).await;
    create_finding(&app, &token, "f2", "high", "t2", Some("sqlmap"), Some("true")).await;
    create_finding(&app, &token, "p1", "low", "t3", Some("semgrep"), Some("potentially")).await;
    create_finding(&app, &token, "n1", "low", "t4", Some("nmap"), Some("false")).await;
    create_finding(&app, &token, "u1", "low", "t5", Some("nuclei"), None).await;

    let stats = fetch_stats(&app, &token, "").await;
    assert_eq!(stats["fully_exploited_count"], 2);
    assert_eq!(stats["partial_exploited_count"], 1);
    assert_eq!(stats["exploitable_count"], 3);
}

#[tokio::test]
async fn list_filter_by_exploitable_supports_any_true_potentially() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    create_finding(&app, &token, "ft", "high", "t1", Some("sqlmap"), Some("true")).await;
    create_finding(&app, &token, "fp", "low", "t2", Some("semgrep"), Some("potentially")).await;
    create_finding(&app, &token, "ff", "low", "t3", Some("nmap"), Some("false")).await;
    create_finding(&app, &token, "fn", "low", "t4", Some("nuclei"), None).await;

    let any = app.get_json("/api/v1/findings?exploitable=any", &token).await;
    assert_eq!(any["total"], 2);

    let only_true = app.get_json("/api/v1/findings?exploitable=true", &token).await;
    assert_eq!(only_true["total"], 1);
    assert_eq!(only_true["data"][0]["title"], "ft");

    let only_partial = app
        .get_json("/api/v1/findings?exploitable=potentially", &token)
        .await;
    assert_eq!(only_partial["total"], 1);
    assert_eq!(only_partial["data"][0]["title"], "fp");
}

#[tokio::test]
async fn cross_org_isolation() {
    // user A in org "alpha" must not see user B in org "beta"'s findings.
    let app = TestApp::new().await;
    app.ensure_org("alpha").await;
    app.ensure_org("beta").await;
    let token_a = app.token_for("ua", Some("alpha"));
    let token_b = app.token_for("ub", Some("beta"));

    create_finding(&app, &token_a, "alpha-only", "high", "t1", Some("nuclei"), None).await;
    create_finding(&app, &token_b, "beta-1", "low", "t1", Some("sqlmap"), None).await;
    create_finding(&app, &token_b, "beta-2", "low", "t2", Some("semgrep"), None).await;

    let alpha = app.get_json("/api/v1/findings", &token_a).await;
    assert_eq!(alpha["total"], 1);
    assert_eq!(alpha["data"][0]["title"], "alpha-only");

    let beta = app.get_json("/api/v1/findings", &token_b).await;
    assert_eq!(beta["total"], 2);
    let titles: Vec<&str> = beta["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap())
        .collect();
    assert!(titles.contains(&"beta-1"));
    assert!(titles.contains(&"beta-2"));
}

#[tokio::test]
async fn create_dedups_on_repeat_with_same_fingerprint() {
    // Phase B (v0.1.74) — re-creating the same finding (same title +
    // target + source + cwe) does NOT pile up a second row. Instead the
    // existing row's occurrence_count is incremented, last_seen_at is
    // bumped, and the response carries is_new=false so the MCP server
    // can render "still vulnerable (3rd run)" instead of acting like
    // the vuln is freshly discovered.
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let body = json!({
        "title": "SQL injection in /users",
        "severity": "high",
        "target": "https://x.com/users",
        "source": "sqlmap",
        "cwe": "CWE-89",
        "evidence": "first run",
    });

    let (status1, first) = app.post_json("/api/v1/findings", &token, body.clone()).await;
    assert_eq!(status1.as_u16(), 201, "first create should be 201 CREATED");
    assert_eq!(first["is_new"], true);
    assert_eq!(first["occurrence_count"], 1);

    // Re-post the same vuln with refreshed evidence.
    let mut body2 = body.clone();
    body2["evidence"] = json!("second run, retested still vulnerable");
    let (status2, second) = app.post_json("/api/v1/findings", &token, body2).await;
    assert_eq!(
        status2.as_u16(),
        200,
        "second create on conflict should be 200 OK, not 201"
    );
    assert_eq!(second["is_new"], false);
    assert_eq!(second["occurrence_count"], 2);
    assert_eq!(second["id"], first["id"], "same row, not a new one");
    assert_eq!(
        second["evidence"], "second run, retested still vulnerable",
        "evidence should refresh to latest run's view"
    );

    // Total findings count should still be 1.
    let list = app.get_json("/api/v1/findings", &token).await;
    assert_eq!(list["total"], 1, "no duplicate row");
}

#[tokio::test]
async fn create_dedups_per_org_not_globally() {
    // Two different orgs with identical vulns get separate rows.
    let app = TestApp::new().await;
    app.ensure_org("alpha").await;
    app.ensure_org("beta").await;
    let token_a = app.token_for("ua", Some("alpha"));
    let token_b = app.token_for("ub", Some("beta"));

    let body = json!({
        "title": "Same vuln",
        "severity": "high",
        "target": "https://shared.example/api",
        "source": "nuclei",
    });

    let (s1, _) = app.post_json("/api/v1/findings", &token_a, body.clone()).await;
    let (s2, _) = app.post_json("/api/v1/findings", &token_b, body.clone()).await;
    assert_eq!(s1.as_u16(), 201);
    assert_eq!(s2.as_u16(), 201, "different org gets its own row, not dedup");

    let alpha_list = app.get_json("/api/v1/findings", &token_a).await;
    let beta_list = app.get_json("/api/v1/findings", &token_b).await;
    assert_eq!(alpha_list["total"], 1);
    assert_eq!(beta_list["total"], 1);
}

#[tokio::test]
async fn create_response_includes_seen_at_timestamps() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let body = json!({
        "title": "Vuln",
        "severity": "low",
        "target": "t",
        "source": "nuclei",
    });
    let (_, f) = app.post_json("/api/v1/findings", &token, body).await;
    assert!(f["first_seen_at"].is_string());
    assert!(f["last_seen_at"].is_string());
    assert!(f["fingerprint"].as_str().unwrap().len() == 64);
}

#[tokio::test]
async fn unauthenticated_request_is_rejected() {
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    let app = TestApp::new().await;
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/findings")
        .body(Body::empty())
        .unwrap();
    let resp = app.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Drain the body so the connection can close cleanly — without
    // this, the Drop on TestApp can race with axum holding a buffer
    // open and hang on cleanup.
    let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
}

// ── Oracle verdicts (migration 0049) ───────────────────────────────────
//
// The earned-verdict invariant end-to-end, through the real route. A verdict
// must be earned in code by a named oracle; the API must not be a way around
// that. See docs/oracle-verification-layer.md.

#[tokio::test]
async fn finding_defaults_to_candidate_verdict() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let f = create_finding(&app, &token, "IDOR", "high", "t", Some("test_idor"), Some("true")).await;

    // An agent asserting `exploitable: true` gets a CLAIM, not a proof.
    assert_eq!(f["verdict"], "candidate");
    assert_eq!(f["validation_tier"], "ai_confirmed");
    assert!(f["oracle_kind"].is_null());
    assert!(f["capsule_json"].is_null());
}

#[tokio::test]
async fn verified_verdict_without_a_receipt_is_rejected() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    // The self-certification attempt: claim the verdict directly on the wire.
    let (status, _) = app
        .post_json(
            "/api/v1/findings",
            &token,
            json!({
                "title": "Self-certified",
                "severity": "critical",
                "target": "t",
                "verdict": "verified",
            }),
        )
        .await;

    assert!(
        !status.is_success(),
        "a `verified` verdict with no oracle receipt must be refused by the DB constraint"
    );
}

#[tokio::test]
async fn verified_verdict_with_incomplete_replays_is_rejected() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    // Names an oracle and carries a receipt, but only 1 of 2 replays landed.
    // Intermittent success is indistinguishable from coincidence.
    let (status, _) = app
        .post_json(
            "/api/v1/findings",
            &token,
            json!({
                "title": "Flaky",
                "severity": "high",
                "target": "t",
                "verdict": "verified",
                "oracle_kind": "idempotent_replay",
                "receipt_json": { "observations": [] },
                "replay_n": 2,
                "replay_successes": 1,
            }),
        )
        .await;

    assert!(!status.is_success(), "verified requires replay_successes == replay_n");
}

#[tokio::test]
async fn earned_verdict_is_accepted_and_outranks_an_ai_claim() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let (status, f) = app
        .post_json(
            "/api/v1/findings",
            &token,
            json!({
                "title": "BOLA on /api/orders/{id}",
                "severity": "high",
                "target": "https://staging.example.com/api/orders/42",
                "source": "test_idor",
                "exploitable": "true",
                "verdict": "verified",
                "oracle_kind": "differential",
                "receipt_json": { "successes": 2, "n": 2 },
                "capsule_json": { "spec": { "kind": "differential" }, "n": 2 },
                "replay_n": 2,
                "replay_successes": 2,
                "claimed_mechanism": "idor",
            }),
        )
        .await;

    assert!(status.is_success(), "a fully-earned verdict must be accepted: {f}");
    assert_eq!(f["verdict"], "verified");
    assert_eq!(f["oracle_kind"], "differential");
    assert_eq!(f["claimed_mechanism"], "idor");
    // Oracle proof outranks an agent's claim in the validation ladder.
    assert_eq!(f["validation_tier"], "oracle_verified");
    // The capsule is surfaced so a human signer can replay the proof.
    assert!(f["capsule_json"].is_object());
}

#[tokio::test]
async fn a_rerun_that_did_not_reverify_drops_the_verdict() {
    let app = TestApp::new().await;
    app.ensure_org("groovy").await;
    let token = app.token_for("u1", Some("groovy"));

    let verified = json!({
        "title": "Same vuln",
        "severity": "high",
        "target": "t",
        "source": "test_idor",
        "verdict": "verified",
        "oracle_kind": "differential",
        "receipt_json": { "n": 2 },
        "capsule_json": { "n": 2 },
        "replay_n": 2,
        "replay_successes": 2,
    });
    let (status, first) = app.post_json("/api/v1/findings", &token, verified).await;
    assert!(status.is_success());
    assert_eq!(first["verdict"], "verified");

    // Same fingerprint, but this run never re-proved it. Carrying the old
    // `verified` forward would assert a proof we did not perform.
    let (status, second) = app
        .post_json(
            "/api/v1/findings",
            &token,
            json!({
                "title": "Same vuln",
                "severity": "high",
                "target": "t",
                "source": "test_idor",
                "verdict": "candidate",
            }),
        )
        .await;

    assert!(status.is_success());
    assert_eq!(second["id"], first["id"], "should upsert the same row");
    assert_eq!(
        second["verdict"], "candidate",
        "a verdict describes THIS run; it must not survive a run that didn't re-prove it"
    );
}
