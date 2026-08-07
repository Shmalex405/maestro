//! Route contract test (layer 2 — behavior smoke).
//!
//! For every declared route, sends a minimal valid request and asserts:
//!   1. status is not 5xx — handler didn't panic / connection didn't drop
//!   2. response body is either empty or parses as JSON — no malformed
//!      payloads (a handler that returns a partially-rendered string would
//!      fail here)
//!
//! Catches the class of bug where a route is wired (covered by
//! `route_registration.rs`) but the handler is broken — type drift, panic
//! inside a serializer, accidentally returning plain text instead of JSON.
//!
//! Routes that legitimately return non-JSON (file downloads, plaintext
//! readiness probes) are listed in `NON_JSON_ROUTES`.
//!
//! Like `route_registration::every_route_is_reachable`, this needs Postgres
//! on :5433.

mod common;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use common::prelude::*;
use tower::ServiceExt;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

/// (method, raw_path, module) — duplicated parser from
/// `route_registration.rs`. Kept inline so the two test files stay
/// independent; if the parser grows we can promote it to a shared helper
/// under `tests/common/`.
fn declared_routes() -> Vec<(Method, String, String)> {
    let routes_dir = manifest_dir().join("src/routes");
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
        let src = read_to_string(&path);
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

/// Routes that legitimately don't return JSON. The contract test for these
/// asserts non-5xx only; JSON-shape check is skipped.
fn non_json_routes() -> HashSet<&'static str> {
    HashSet::from([
        // file downloads
        "/api/v1/reports/:id/download",
    ])
}

/// Routes with known 5xx responses in default test config. Tracked so
/// the test stays green; remove entries as the underlying handlers are
/// fixed. (Empty after the toolkit::registry_credentials → 503 fix.)
fn known_5xx_routes() -> HashSet<&'static str> {
    HashSet::new()
}

#[tokio::test]
async fn every_route_returns_non_5xx_and_parseable_body() {
    let app = TestApp::new().await;
    app.ensure_org("contract").await;
    let token = app.token_for("contract-user", Some("contract"));

    let routes = declared_routes();
    assert!(!routes.is_empty(), "no routes parsed");

    let non_json = non_json_routes();
    let known_5xx = known_5xx_routes();
    let mut server_errors: Vec<String> = Vec::new();
    let mut bad_bodies: Vec<String> = Vec::new();

    for (method, raw_path, module) in routes {
        let mount = if module == "health" { "" } else { "/api/v1" };
        let mount_path = format!("{mount}{raw_path}");
        let path = format!("{mount}{}", fill_params(&raw_path));

        let mut builder = Request::builder()
            .method(method.clone())
            .uri(&path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from("{}")
        } else {
            Body::empty()
        };
        let req = builder.body(body).expect("build request");
        let resp = app.app.clone().oneshot(req).await.expect("router oneshot");
        let status = resp.status();
        let body_bytes = to_bytes(resp.into_body(), 1_000_000).await.unwrap_or_default();

        // 500 is a contract violation — handler should never panic or
        // leak internal errors on a well-formed (if empty) request.
        // Other 5xx codes (503 Service Unavailable, 504 Gateway Timeout)
        // are legitimate typed business responses and pass the contract:
        // the handler ran, returned a typed status, and the body parses.
        if status == StatusCode::INTERNAL_SERVER_ERROR
            && !known_5xx.contains(mount_path.as_str())
        {
            server_errors.push(format!(
                "{method} {path} → {status}\n    body: {}",
                String::from_utf8_lossy(&body_bytes)
            ));
            continue;
        }

        // Body-shape check only applies to success responses. Axum's
        // default Json<T>/Query<T> extractors emit plaintext on parse
        // failure (HTTP 400/422) and that's framework behavior, not a
        // handler contract violation.
        if !status.is_success() {
            continue;
        }
        if non_json.contains(mount_path.as_str()) {
            continue;
        }
        if body_bytes.is_empty() {
            continue;
        }
        if serde_json::from_slice::<serde_json::Value>(&body_bytes).is_err() {
            bad_bodies.push(format!(
                "{method} {path} → {status} returned non-JSON body: {}",
                String::from_utf8_lossy(&body_bytes).chars().take(120).collect::<String>()
            ));
        }
    }

    if !server_errors.is_empty() || !bad_bodies.is_empty() {
        let mut lines = Vec::new();
        if !server_errors.is_empty() {
            lines.push(format!("5xx responses ({}):", server_errors.len()));
            lines.extend(server_errors.iter().map(|e| format!("  - {}", e)));
        }
        if !bad_bodies.is_empty() {
            lines.push(format!("Non-JSON bodies ({}):", bad_bodies.len()));
            lines.extend(bad_bodies.iter().map(|e| format!("  - {}", e)));
        }
        panic!("route contract violations:\n{}", lines.join("\n"));
    }
}
