//! Functional tests for the attack-graph substrate (migration 0046 + /graph/*).
//!
//! Covers the mechanics the cross-org contract test (security_contract.rs)
//! doesn't: accumulation across re-runs, the recursive-CTE pathfinder
//! (ordering, exploited_only filter, cycle safety, reachability-only variant),
//! and the kind registry (custom kinds, built-in collision, validation, delete).

mod common;

use axum::http::StatusCode;
use common::prelude::*;

/// One org + a token for it.
async fn one_org(app: &TestApp) -> String {
    app.ensure_org("acme").await;
    app.token_for("u", Some("acme"))
}

#[tokio::test]
async fn ingest_accumulates_across_runs() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    let body = json!({
        "source": "chain-analysis",
        "nodes": [{ "id": "n1", "kind": "workload", "label": "svc", "layer": 1 }],
        "edges": []
    });
    let (s, _) = app.post_json("/api/v1/graph/ingest", &tok, body.clone()).await;
    assert!(s.is_success());

    // Re-ingest the SAME node under a different producer — must merge, not dup.
    let (s, _) = app
        .post_json(
            "/api/v1/graph/ingest",
            &tok,
            json!({
                "source": "cloud-analysis",
                "nodes": [{ "id": "n1", "kind": "workload", "label": "svc-renamed", "layer": 1 }],
                "edges": []
            }),
        )
        .await;
    assert!(s.is_success());

    let nodes = app.get_json("/api/v1/graph/nodes", &tok).await;
    let rows = nodes.as_array().expect("array");
    assert_eq!(rows.len(), 1, "re-ingest must accumulate, not duplicate: {nodes}");
    let sources = rows[0]["sources"].as_array().expect("sources array");
    assert_eq!(sources.len(), 2, "both producers recorded: {nodes}");
    assert_eq!(rows[0]["label"], "svc-renamed", "newest non-empty label wins");
}

#[tokio::test]
async fn pathfinder_returns_ordered_chain() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // internet(source) -> exposure -> workload -> crown(asset, the goal).
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet", "kind": "source",   "layer": 0 },
                { "id": "exp",      "kind": "exposure", "layer": 1 },
                { "id": "wl",       "kind": "workload", "layer": 2 },
                { "id": "crown",    "kind": "asset",    "layer": 3 }
            ],
            "edges": [
                { "from": "internet", "to": "exp",   "exploited": true },
                { "from": "exp",      "to": "wl",    "exploited": true },
                { "from": "wl",       "to": "crown", "exploited": true }
            ]
        }),
    )
    .await;

    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert!(s.is_success(), "{s} {res}");
    let paths = res["paths"].as_array().expect("paths");
    assert_eq!(paths.len(), 1, "exactly one chain to the crown jewel: {res}");
    let nodes = paths[0]["nodes"].as_array().expect("nodes");
    let keys: Vec<&str> = nodes.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(keys, vec!["internet", "exp", "wl", "crown"], "ordered path: {res}");
    assert_eq!(paths[0]["depth"], 3);
    assert_eq!(res["truncated"], false);
}

#[tokio::test]
async fn exploited_only_drops_detected_edges() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // internet -> wl (exploited) -> crown (DETECTED-ONLY, exploited:false).
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet", "kind": "source",   "layer": 0 },
                { "id": "wl",       "kind": "workload", "layer": 1 },
                { "id": "crown",    "kind": "asset",    "layer": 2 }
            ],
            "edges": [
                { "from": "internet", "to": "wl",    "exploited": true },
                { "from": "wl",       "to": "crown", "exploited": false }
            ]
        }),
    )
    .await;

    // Without the filter: the goal is reachable.
    let (_, all) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert_eq!(all["paths"].as_array().unwrap().len(), 1, "{all}");

    // exploited_only: the dashed wl->crown edge drops out, so the crown is
    // no longer reachable.
    let (_, only) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset", "exploited_only": true }),
        )
        .await;
    assert!(
        only["paths"].as_array().unwrap().is_empty(),
        "detected-only edge must not be traversed under exploited_only: {only}"
    );
}

#[tokio::test]
async fn cycle_does_not_hang_or_duplicate() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // a(source) -> b -> c -> goal, plus a c -> b back-edge (cycle b<->c).
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "a",    "kind": "source",   "layer": 0 },
                { "id": "b",    "kind": "workload", "layer": 1 },
                { "id": "c",    "kind": "workload", "layer": 2 },
                { "id": "goal", "kind": "asset",    "layer": 3 }
            ],
            "edges": [
                { "from": "a", "to": "b" },
                { "from": "b", "to": "c" },
                { "from": "c", "to": "b" },
                { "from": "c", "to": "goal" }
            ]
        }),
    )
    .await;

    // The cycle guard must let this terminate and find a -> b -> c -> goal.
    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert!(s.is_success(), "cycle query must terminate: {s} {res}");
    let paths = res["paths"].as_array().expect("paths");
    assert_eq!(paths.len(), 1, "exactly one acyclic path despite the cycle: {res}");
    let keys: Vec<&str> = paths[0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(keys, vec!["a", "b", "c", "goal"], "{res}");
}

#[tokio::test]
async fn reachable_only_variant() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "src",   "kind": "source", "layer": 0 },
                { "id": "crown", "kind": "asset",  "layer": 1 }
            ],
            "edges": [{ "from": "src", "to": "crown", "exploited": true }]
        }),
    )
    .await;

    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset", "reachable_only": true }),
        )
        .await;
    assert!(s.is_success(), "{s} {res}");
    let reachable = res["reachable"].as_array().expect("reachable");
    assert_eq!(reachable.len(), 1, "{res}");
    assert_eq!(reachable[0]["goal_key"], "crown");
    assert_eq!(reachable[0]["kind"], "asset");
    assert_eq!(reachable[0]["reached_from"][0], "src");
}

#[tokio::test]
async fn builtin_kinds_seeded_and_listed() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    let kinds = app.get_json("/api/v1/graph/kinds", &tok).await;
    let rows = kinds.as_array().expect("array");
    // 10 built-ins: 6 node + 1 edge kind (0046) + foothold/credential/loot (0047).
    let builtins = rows.iter().filter(|k| k["is_builtin"] == true).count();
    assert_eq!(builtins, 10, "10 built-in kinds seeded: {kinds}");
    for k in ["foothold", "credential", "loot"] {
        assert!(
            rows.iter().any(|r| r["kind"] == k && r["is_builtin"] == true),
            "post-ex kind {k} seeded by 0047: {kinds}"
        );
    }
    assert!(
        rows.iter().any(|k| k["kind"] == "asset" && k["is_goal"] == true),
        "asset is the default crown jewel: {kinds}"
    );
}

#[tokio::test]
async fn custom_kind_register_ingest_delete() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // Register an okta-identity extension (a custom node kind).
    let (s, reg) = app
        .post_json(
            "/api/v1/graph/kinds",
            &tok,
            json!({
                "kind": "okta-app",
                "is_edge": false,
                "display": { "fill": "#101", "stroke": "#abc", "text": "#fff" }
            }),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "register custom kind: {reg}");

    // Now a node of that kind ingests WITHOUT auto_register (it's registered).
    let (s, _) = app
        .post_json(
            "/api/v1/graph/ingest",
            &tok,
            json!({
                "source": "identity-analysis",
                "nodes": [{ "id": "okta:0oa1", "kind": "okta-app", "label": "SSO app" }],
                "edges": []
            }),
        )
        .await;
    assert!(s.is_success());
    let nodes = app
        .get_json("/api/v1/graph/nodes?kind=okta-app", &tok)
        .await;
    assert_eq!(nodes.as_array().unwrap().len(), 1, "custom-kind node visible: {nodes}");

    // Built-in collision is rejected.
    let (s, _) = app
        .post_json("/api/v1/graph/kinds", &tok, json!({ "kind": "asset" }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "cannot redefine a built-in");

    // Delete the custom kind; built-ins cannot be deleted.
    assert_eq!(
        app.delete("/api/v1/graph/kinds/okta-app", &tok).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.delete("/api/v1/graph/kinds/asset", &tok).await,
        StatusCode::NOT_FOUND,
        "built-in kind cannot be deleted"
    );
}

#[tokio::test]
async fn unknown_kind_rejected_unless_auto_register() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // Unregistered kind, no auto_register → rejected.
    let (s, body) = app
        .post_json(
            "/api/v1/graph/ingest",
            &tok,
            json!({
                "source": "chain-analysis",
                "nodes": [{ "id": "x", "kind": "made-up-kind" }],
                "edges": []
            }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown kind must be rejected: {body}");

    // Same payload with auto_register → accepted, and the kind is registered.
    let (s, _) = app
        .post_json(
            "/api/v1/graph/ingest",
            &tok,
            json!({
                "source": "chain-analysis",
                "nodes": [{ "id": "x", "kind": "made-up-kind" }],
                "edges": [],
                "auto_register": true
            }),
        )
        .await;
    assert!(s.is_success(), "auto_register accepts unknown kinds");
    let kinds = app.get_json("/api/v1/graph/kinds", &tok).await;
    assert!(
        kinds.as_array().unwrap().iter().any(|k| k["kind"] == "made-up-kind"),
        "auto-registered kind now in registry: {kinds}"
    );
}

// ── Post-exploitation Layer B: capability-gated planning (migration 0047) ──────

#[tokio::test]
async fn capability_gate_blocks_until_seed_caps() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // internet(source) --requires[foothold_cap]--> wl --> crown(asset).
    // The first edge is capability-gated; it is only crossed while holding foothold_cap.
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet", "kind": "source",   "layer": 0 },
                { "id": "wl",       "kind": "workload", "layer": 2 },
                { "id": "crown",    "kind": "asset",    "layer": 3 }
            ],
            "edges": [
                { "from": "internet", "to": "wl",    "requires": ["foothold_cap"] },
                { "from": "wl",       "to": "crown" }
            ]
        }),
    )
    .await;

    // Without the capability the gated edge is impassable → no path to the crown.
    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert!(s.is_success(), "{s} {res}");
    assert_eq!(
        res["paths"].as_array().unwrap().len(),
        0,
        "capability-gated edge blocks the path when the cap is not held: {res}"
    );

    // Seed the attacker with the capability → the gate opens, crown is reachable.
    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset", "seed_caps": ["foothold_cap"] }),
        )
        .await;
    assert!(s.is_success(), "{s} {res}");
    let paths = res["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 1, "seed_caps unlocks the gated edge: {res}");
    let keys: Vec<&str> = paths[0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(keys, vec!["internet", "wl", "crown"], "full chain once unlocked: {res}");
}

#[tokio::test]
async fn node_grant_unlocks_downstream_edge() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // internet --> loot_node(grants[db_cred]) --requires[db_cred]--> crown.
    // Landing on loot_node picks up db_cred, which the final edge requires — no seed needed.
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet",  "kind": "source",     "layer": 0 },
                { "id": "loot_node", "kind": "credential", "layer": 2, "grants": ["db_cred"] },
                { "id": "crown",     "kind": "asset",      "layer": 3 }
            ],
            "edges": [
                { "from": "internet",  "to": "loot_node" },
                { "from": "loot_node", "to": "crown", "requires": ["db_cred"] }
            ]
        }),
    )
    .await;

    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert!(s.is_success(), "{s} {res}");
    let paths = res["paths"].as_array().unwrap();
    assert_eq!(
        paths.len(),
        1,
        "a node's grant unlocks the downstream gated edge with no seed: {res}"
    );
    let keys: Vec<&str> = paths[0]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(keys, vec!["internet", "loot_node", "crown"], "{res}");
}

#[tokio::test]
async fn goal_caps_define_the_goal() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // internet --grants[admin]--> wl. No is_goal node; the GOAL is "hold admin".
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet", "kind": "source",   "layer": 0 },
                { "id": "wl",       "kind": "workload", "layer": 2 }
            ],
            "edges": [
                { "from": "internet", "to": "wl", "grants": ["admin"] }
            ]
        }),
    )
    .await;

    let (s, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_caps": ["admin"] }),
        )
        .await;
    assert!(s.is_success(), "{s} {res}");
    let paths = res["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 1, "goal reached by acquiring the goal capability: {res}");
    let last = paths[0]["nodes"].as_array().unwrap().last().unwrap();
    assert_eq!(last, "wl", "path ends where the goal capability was granted: {res}");
}

// ── Per-edge receipts (migration 0050) ─────────────────────────────────
//
// `exploited` says a run walked an edge — an agent's report. `verified_only`
// demands that each step be backed by a finding an ORACLE re-proved. This is
// what turns "here is a path we believe in" into "here is a path, and every
// step has a replay capsule you can run yourself".

#[tokio::test]
async fn verified_only_gates_paths_on_the_oracle_verdict() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    // A finding that genuinely earned its verdict, and one that only claims it.
    let (s, verified) = app
        .post_json(
            "/api/v1/findings",
            &tok,
            json!({
                "title": "SSRF to metadata", "severity": "high", "target": "t",
                "verdict": "verified", "oracle_kind": "artifact",
                "receipt_json": { "n": 2 }, "capsule_json": { "n": 2 },
                "replay_n": 2, "replay_successes": 2,
            }),
        )
        .await;
    assert!(s.is_success(), "{verified}");

    let (s, claimed) = app
        .post_json(
            "/api/v1/findings",
            &tok,
            json!({
                "title": "Assumed lateral hop", "severity": "high", "target": "t2",
                "exploitable": "true",  // an agent's claim, never re-proven
            }),
        )
        .await;
    assert!(s.is_success(), "{claimed}");
    assert_eq!(claimed["verdict"], "candidate");

    // internet -> wl -> crown. First hop is oracle-backed, second is not.
    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet", "kind": "source",   "layer": 0 },
                { "id": "wl",       "kind": "workload", "layer": 1 },
                { "id": "crown",    "kind": "asset",    "layer": 2 }
            ],
            "edges": [
                { "from": "internet", "to": "wl", "exploited": true,
                  "verified_by_finding_id": verified["id"] },
                { "from": "wl", "to": "crown", "exploited": true,
                  "verified_by_finding_id": claimed["id"] }
            ]
        }),
    )
    .await;

    // Unfiltered: the crown jewel looks reachable.
    let (_, all) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;
    assert_eq!(all["paths"].as_array().unwrap().len(), 1, "reachable unfiltered: {all}");

    // verified_only: the unproven second hop drops out, so the crown jewel is
    // NOT provably reachable. Claiming otherwise is the overclaim we're closing.
    let (_, only) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset", "verified_only": true }),
        )
        .await;
    assert_eq!(
        only["paths"].as_array().unwrap().len(),
        0,
        "a path is only provably-traversable if EVERY edge is oracle-backed: {only}"
    );

    // Discriminating check: the FIRST hop really is verified, so a walk that
    // stops at the workload does survive the filter. Without this, the zero
    // above could be passing simply because no edge is verified at all.
    let (_, hop) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "workload", "verified_only": true }),
        )
        .await;
    assert_eq!(
        hop["paths"].as_array().unwrap().len(),
        1,
        "the oracle-backed hop must survive verified_only: {hop}"
    );
    assert_eq!(hop["paths"][0]["edges"][0]["verdict"], "verified");
}

#[tokio::test]
async fn path_edges_carry_their_derived_verdict() {
    let app = TestApp::new().await;
    let tok = one_org(&app).await;

    let (_, f) = app
        .post_json(
            "/api/v1/findings",
            &tok,
            json!({
                "title": "Proven hop", "severity": "high", "target": "t",
                "verdict": "verified", "oracle_kind": "differential",
                "receipt_json": { "n": 2 }, "capsule_json": { "n": 2 },
                "replay_n": 2, "replay_successes": 2,
            }),
        )
        .await;

    app.post_json(
        "/api/v1/graph/ingest",
        &tok,
        json!({
            "source": "chain-analysis",
            "nodes": [
                { "id": "internet", "kind": "source", "layer": 0 },
                { "id": "crown",    "kind": "asset",  "layer": 1 }
            ],
            "edges": [
                { "from": "internet", "to": "crown", "exploited": true,
                  "verified_by_finding_id": f["id"] }
            ]
        }),
    )
    .await;

    let (_, res) = app
        .post_json(
            "/api/v1/graph/paths",
            &tok,
            json!({ "source_kind": "source", "goal_kind": "asset" }),
        )
        .await;

    let edge = &res["paths"][0]["edges"][0];
    assert_eq!(edge["verdict"], "verified", "verdict is derived from the finding: {res}");
    assert_eq!(edge["oracle_kind"], "differential");
    assert_eq!(edge["verified_by"], f["id"]);
}
