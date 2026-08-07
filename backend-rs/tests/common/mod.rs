//! Test harness for backend-rs integration tests.
//!
//! Each test gets a freshly-created Postgres database with all migrations
//! applied. The `TestDb` guard cleans the database up on drop so a
//! failing test doesn't leak state between runs.
//!
//! # Connecting
//!
//! Set `TEST_DATABASE_URL` to a Postgres connection that the test runner
//! is allowed to `CREATE DATABASE` against. The default
//! (`postgres://postgres:postgres@localhost:5433/postgres`) matches the
//! local docker-compose dev DB.
//!
//! # Usage
//!
//! ```ignore
//! mod common;
//! use common::TestApp;
//!
//! #[tokio::test]
//! async fn lists_findings() {
//!     let app = TestApp::new().await;
//!     let token = app.token_for("u1", Some("groovy"));
//!     let resp: serde_json::Value = app
//!         .get_json("/api/v1/findings", &token)
//!         .await
//!         .unwrap();
//!     assert_eq!(resp["total"], 0);
//! }
//! ```

#![allow(dead_code)]

use std::sync::Once;

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    Router,
};

use serde_json::Value;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

use maestro_backend::auth::jwt::create_access_token;
use maestro_backend::config::Settings;
use maestro_backend::routes::build_router;
use maestro_backend::state::{new_state, AppState};

static INIT: Once = Once::new();

fn init_logging() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
                    .unwrap_or_else(|_| "warn".into()),
            )
            .with_test_writer()
            .try_init();
    });
}

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/postgres".to_string())
}

fn db_url(name: &str) -> String {
    let admin = admin_url();
    // Replace the path component (database name) with `name`.
    if let Some(idx) = admin.rfind('/') {
        format!("{}/{}", &admin[..idx], name)
    } else {
        format!("{}/{}", admin, name)
    }
}

/// Wraps a freshly-provisioned test database. Drops the database when the
/// guard goes out of scope so test runs are self-cleaning.
pub struct TestDb {
    pub pool: PgPool,
    pub name: String,
}

impl TestDb {
    pub async fn new() -> Self {
        init_logging();
        // Random db name avoids collision with concurrent tests.
        let name = format!("backend_rs_test_{}", Uuid::new_v4().simple());
        let admin = admin_url();
        let mut conn = PgConnection::connect(&admin)
            .await
            .expect("connect to postgres admin DB — is the dev postgres up on :5433?");
        conn.execute(format!(r#"CREATE DATABASE "{}""#, name).as_str())
            .await
            .expect("create test database");
        drop(conn);

        let pool = PgPool::connect(&db_url(&name))
            .await
            .expect("connect to test database");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("apply migrations to test database");

        TestDb { pool, name }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Best-effort cleanup spawned on a detached thread — we don't
        // join because the test process is about to exit anyway, and
        // joining can deadlock if there's an outstanding async task
        // holding a pool connection. Worst case the test database
        // sticks around until the next run; we always create with
        // unique uuid-suffixed names so collisions are impossible.
        let admin = admin_url();
        let name = self.name.clone();
        let pool = self.pool.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                pool.close().await;
                let mut conn = match PgConnection::connect(&admin).await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let _ = conn
                    .execute(
                        format!(
                            r#"SELECT pg_terminate_backend(pid)
                               FROM pg_stat_activity
                               WHERE datname = '{}' AND pid <> pg_backend_pid()"#,
                            name
                        )
                        .as_str(),
                    )
                    .await;
                let _ = conn
                    .execute(format!(r#"DROP DATABASE IF EXISTS "{}""#, name).as_str())
                    .await;
            });
        });
    }
}

/// A composed test harness: ephemeral DB + axum router + token helper.
pub struct TestApp {
    db: TestDb,
    pub state: AppState,
    pub app: Router,
}

impl TestApp {
    pub async fn new() -> Self {
        let db = TestDb::new().await;
        // Tests run against the local-JWT auth provider. The default is
        // unrestricted org tenancy — individual tests that need to pin
        // org_id mutate `state.settings.allowed_org_id` before calling
        // request().
        let settings = Settings {
            auth_provider: "local".to_string(),
            jwt_secret: "test-secret-do-not-use-in-prod".to_string(),
            jwt_algorithm: "HS256".to_string(),
            allowed_org_id: None,
            ..Settings::default()
        };
        let state = new_state(settings, db.pool.clone());
        let app = build_router(state.clone());
        TestApp { db, state, app }
    }

    /// Mint a local JWT for a fake user. Sets sub + org_id; email defaults
    /// to `<sub>@test.local`.
    pub fn token_for(&self, sub: &str, org_id: Option<&str>) -> String {
        create_access_token(
            &self.state.settings,
            sub,
            Some(&format!("{sub}@test.local")),
            org_id,
            &["user".to_string()],
            None,
        )
        .expect("mint test token")
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = if let Some(json) = body {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(serde_json::to_vec(&json).unwrap())
        } else {
            Body::empty()
        };
        let req = builder.body(body).unwrap();
        let resp = self
            .app
            .clone()
            .oneshot(req)
            .await
            .expect("router oneshot");
        let status = resp.status();
        let body = to_bytes(resp.into_body(), 1_000_000)
            .await
            .expect("read body");
        let json = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or_else(|e| {
                panic!(
                    "test response was not valid JSON: {} — body: {}",
                    e,
                    String::from_utf8_lossy(&body)
                )
            })
        };
        (status, json)
    }

    pub async fn get_json(&self, path: &str, token: &str) -> Value {
        let (status, json) = self.request(Method::GET, path, token, None).await;
        assert!(
            status.is_success(),
            "GET {path} returned {status}: {json}"
        );
        json
    }

    pub async fn post_json(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.request(Method::POST, path, token, Some(body)).await
    }

    pub async fn patch_json(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.request(Method::PATCH, path, token, Some(body)).await
    }

    pub async fn put_json(&self, path: &str, token: &str, body: Value) -> (StatusCode, Value) {
        self.request(Method::PUT, path, token, Some(body)).await
    }

    pub async fn delete(&self, path: &str, token: &str) -> StatusCode {
        let (status, _) = self.request(Method::DELETE, path, token, None).await;
        status
    }

    /// Hand-insert an org row so FK references are satisfied. Returns the
    /// org id.
    pub async fn ensure_org(&self, id: &str) -> &Self {
        sqlx::query(
            r#"INSERT INTO organizations (id, name, slug)
               VALUES ($1, $1, $1)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(id)
        .execute(&self.db.pool)
        .await
        .expect("insert org");
        self
    }
}

// Tiny prelude makes test files less noisy.
pub mod prelude {
    pub use super::TestApp;
    pub use serde_json::{json, Value};
}
