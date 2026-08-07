//! Postgres connection pool + migration runner.
//!
//! The Python backend calls `Base.metadata.create_all` on startup to create
//! tables. We do the equivalent via `sqlx::migrate!()` — the migration
//! checksum protects against drift.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

use crate::config::Settings;

pub type Pool = PgPool;

pub async fn connect(settings: &Settings) -> anyhow::Result<Pool> {
    let url = settings.postgres_url();
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .test_before_acquire(true) // matches SQLAlchemy pool_pre_ping=True
        .connect(&url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &Pool) -> anyhow::Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Ensure the org this backend is tenanted to (`ALLOWED_ORG_ID`) exists in
/// the `organizations` table. Without this, FK-referencing INSERTs (repos,
/// configs, etc.) fail on a fresh deployment because no migration seeds
/// the row — every per-org backend has its own org_id and we can't bake
/// it into a static seed file. Idempotent via ON CONFLICT.
pub async fn seed_org(pool: &Pool, settings: &Settings) -> anyhow::Result<()> {
    let Some(org_id) = settings.allowed_org_id.as_deref() else {
        return Ok(()); // local/multi-tenant builds with no fixed tenancy
    };
    sqlx::query(
        r#"INSERT INTO organizations (id, name, slug, is_active)
           VALUES ($1, $2, $1, TRUE)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(org_id)
    .bind(org_id) // display name defaults to slug; can be overridden later
    .execute(pool)
    .await?;
    tracing::info!(org_id = %org_id, "seeded org row (idempotent)");
    Ok(())
}
