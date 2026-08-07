//! Lightweight audit-log writer.
//!
//! Entity routes call `record(...)` after a successful mutation. The write
//! is best-effort — failures get logged but never propagate, so a logging
//! glitch can't fail the user's create/update/delete. The `audit_logs` GET
//! endpoint (routes/audit_logs.rs) reads what's written here.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::auth::AuthUser;

/// Record an audit-log entry. Errors are logged and swallowed.
pub async fn record(
    pool: &PgPool,
    user: &AuthUser,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    details: Option<JsonValue>,
) {
    let id = Uuid::new_v4().to_string();
    let user_email = if user.email.is_empty() { None } else { Some(user.email.as_str()) };

    let result = sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, action, resource_type, resource_id, details,
             user_id, user_email, org_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        "#,
    )
    .bind(&id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(details)
    .bind(&user.id)
    .bind(user_email)
    .bind(user.org_id.as_deref())
    .execute(pool)
    .await;

    if let Err(e) = result {
        warn!(
            error = %e,
            action,
            resource_type,
            resource_id,
            "audit log write failed (swallowed)"
        );
    }
}
