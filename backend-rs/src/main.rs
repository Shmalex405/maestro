//! `maestro-backend` — Rust port of `backend/app/main.py`.
//!
//! Axum on tokio. Loads settings from env, opens a Postgres pool, runs
//! migrations on startup (same behavior as the Python `init_db()` call),
//! attaches CORS matching FastAPI's CORSMiddleware config, and binds to
//! `0.0.0.0:8000`.

use std::net::SocketAddr;

use axum::http::{HeaderValue, Method};
use tower_http::{
    cors::{AllowHeaders, AllowOrigin, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// Module declarations live in src/lib.rs so integration tests can import
// them too. main.rs just consumes the library API.
use maestro_backend::{config, db, routes, state};

use crate::config::Settings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let settings = Settings::from_env()?;
    tracing::info!(
        app = %settings.app_name,
        version = %settings.app_version,
        auth = %settings.auth_provider,
        storage = %settings.storage_provider,
        "starting maestro-backend"
    );

    let pool = db::connect(&settings).await?;
    db::run_migrations(&pool).await?;
    db::seed_org(&pool, &settings).await?;
    tracing::info!("database ready");

    let cors = build_cors(&settings)?;
    // Request-level tracing so CloudWatch logs show method/path/status/latency
    // for every hit. `DefaultOnResponse::new().level(Level::INFO)` emits a
    // single `INFO` line per request at the point the response is written.
    let trace = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::DEBUG))
        .on_response(DefaultOnResponse::new().level(Level::INFO));
    let state = state::new_state(settings.clone(), pool);
    let app = routes::build_router(state).layer(trace).layer(cors);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, app).await?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(fmt::layer())
        .init();
}

fn build_cors(settings: &Settings) -> anyhow::Result<CorsLayer> {
    let mut origins = Vec::with_capacity(settings.cors_origins.len());
    for o in &settings.cors_origins {
        origins.push(HeaderValue::from_str(o)?);
    }
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ])
        .allow_headers(AllowHeaders::mirror_request()))
}
