//! Route registration smoke test.
//!
//! Catches the class of bug where a route handler is implemented in a
//! module but the module is never merged into `build_router`, or where a
//! `.route("/path", ...)` declaration silently disappears.
//!
//! Two layers:
//!   1. Source-parse — every `pub mod` in `routes/mod.rs` is `.merge()`'d
//!      into `build_router`, and every merged module has a `pub fn router`.
//!   2. Runtime — every `.route("/...", ...)` declared in `src/routes/*.rs`
//!      returns something other than 404 when hit on the live Axum app.
//!      A 401/403/422/500 is fine — proves the route is wired and the
//!      handler executed (vs. axum's fall-through 404).
//!
//! The runtime test needs Postgres on `:5433` (same as the other backend-rs
//! integration tests). See `tests/common/mod.rs`.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::prelude::*;
use tower::ServiceExt;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_to_string(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

// ---------- source parsing ----------

/// Parses `src/routes/mod.rs` and returns the list of modules declared
/// with `pub mod X;`.
fn declared_modules() -> BTreeSet<String> {
    let src = read_to_string(&manifest_dir().join("src/routes/mod.rs"));
    src.lines()
        .filter_map(|l| l.trim().strip_prefix("pub mod "))
        .filter_map(|rest| rest.split(';').next().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parses `src/routes/mod.rs` and returns the modules referenced via
/// `X::router()` inside `build_router`. We include the root `health::router`
/// merge too — anything that calls `<name>::router()`.
fn merged_modules() -> BTreeSet<String> {
    let src = read_to_string(&manifest_dir().join("src/routes/mod.rs"));
    let mut out = BTreeSet::new();
    for line in src.lines() {
        // Match patterns like `.merge(health::router())` or `.merge(version::router())`.
        let trimmed = line.trim();
        let Some(after) = trimmed.strip_prefix(".merge(") else { continue };
        let Some(inner) = after.split("::router").next() else { continue };
        let name = inner.trim().trim_start_matches('(').to_string();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// Walks `src/routes/` and extracts every `.route("/...", METHODS)` call,
/// returning (HTTP method, mount-relative path) tuples. The path is in
/// axum's `:param` form. Mount prefix (`/api/v1` or root for `health`) is
/// added by the caller.
fn declared_routes() -> Vec<(Method, String, String)> {
    let routes_dir = manifest_dir().join("src/routes");
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(&routes_dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some("mod") => continue,
            Some(s) => s.to_string(),
            None => continue,
        };
        let src = read_to_string(&path);
        // Iterate `.route(` occurrences using `match_indices` so we stay on
        // valid char boundaries (route files contain non-ASCII like `—`).
        let bytes = src.as_bytes();
        for (start, _) in src.match_indices(".route(") {
            let after_open = start + ".route(".len();
            // Skip ASCII whitespace.
            let mut j = after_open;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() { j += 1; }
            if j >= bytes.len() || bytes[j] != b'"' { continue; }
            j += 1;
            let path_start = j;
            while j < bytes.len() && bytes[j] != b'"' { j += 1; }
            if j >= bytes.len() { continue; }
            let route_path = src[path_start..j].to_string();
            j += 1; // past closing "
            // Collect bytes until the matching `)` for this `.route(...)` call.
            // We only branch on `(` / `)` so byte-level scanning is safe even
            // through multibyte sequences (they never include 0x28/0x29).
            let mut depth = 1usize;
            let scan_from = j;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => { depth -= 1; if depth == 0 { break; } }
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

// ---------- tests ----------

#[test]
fn every_pub_mod_is_merged_in_build_router() {
    let declared = declared_modules();
    let merged = merged_modules();
    assert!(!declared.is_empty(), "no `pub mod` in routes/mod.rs?");

    let missing: Vec<&String> = declared.iter().filter(|m| !merged.contains(*m)).collect();
    assert!(
        missing.is_empty(),
        "modules declared but never `.merge()`'d in build_router:\n{}",
        missing
            .iter()
            .map(|m| format!("  - {}", m))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_merge_reference_has_a_declared_module() {
    let declared = declared_modules();
    let merged = merged_modules();
    let orphan: Vec<&String> = merged.iter().filter(|m| !declared.contains(*m)).collect();
    assert!(
        orphan.is_empty(),
        "build_router merges modules with no `pub mod` declaration:\n{}",
        orphan
            .iter()
            .map(|m| format!("  - {}", m))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn route_parser_finds_routes() {
    // Sanity check on the source parser itself — if this returns empty
    // the parser is broken and the runtime test below would silently
    // pass on an empty set.
    let routes = declared_routes();
    assert!(
        routes.len() > 20,
        "route parser returned only {} routes — parser is broken",
        routes.len()
    );
}

/// Substitute axum path params (`:id`, `:assessment_id`, etc.) with a
/// valid-looking placeholder so the handler doesn't 422 on parse and the
/// router can resolve the route.
fn fill_params(path: &str) -> String {
    let mut out = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ':' {
            // Consume the param name (alphanumeric + underscore)
            while let Some(&nc) = chars.peek() {
                if nc.is_alphanumeric() || nc == '_' {
                    chars.next();
                } else {
                    break;
                }
            }
            // UUID-shaped placeholder works for `:id` and similar.
            out.push_str("00000000-0000-0000-0000-000000000000");
        } else {
            out.push(c);
        }
    }
    out
}

#[tokio::test]
async fn every_route_is_reachable() {
    let app = TestApp::new().await;
    app.ensure_org("smoke").await;
    let token = app.token_for("smoke-user", Some("smoke"));

    let routes = declared_routes();
    let mut failures: Vec<String> = Vec::new();
    for (method, raw_path, module) in routes {
        // `health` is the only module mounted at root; everything else is
        // under `/api/v1` (the default `api_prefix`).
        let mount = if module == "health" { "" } else { "/api/v1" };
        let path = format!("{mount}{}", fill_params(&raw_path));

        // Bypass `TestApp::request` because it insists on JSON-parsing the
        // response body, and axum's error responses for missing fields are
        // plaintext. We only need the status code.
        let mut builder = Request::builder()
            .method(method.clone())
            .uri(&path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let req_body = if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from("{}")
        } else {
            Body::empty()
        };
        let req = builder.body(req_body).expect("build request");
        let resp = app.app.clone().oneshot(req).await.expect("router oneshot");
        let status = resp.status();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap_or_default();

        // Distinguish two kinds of 404:
        //   - axum's router fallback: empty body (route literally not matched)
        //   - handler-returned 404 (`AppError::NotFound`): non-empty JSON body
        // Only the first means the route is missing from the router.
        if status == StatusCode::NOT_FOUND && body_bytes.is_empty() {
            failures.push(format!("{method} {path} → 404 (route not wired)"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} route(s) returned 404 — handlers exist in source but axum couldn't match them:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
