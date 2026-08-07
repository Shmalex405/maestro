//! `users` table row. Mirrors `backend/app/models/user.py:User`.
//!
//! sqlx is used with `query_as!`-free plain queries so the crate can be
//! compiled without a live Postgres in the environment.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct User {
    pub id: String,
    pub email: String,
    pub hashed_password: Option<String>,
    pub name: Option<String>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
    pub roles: Option<JsonValue>,
    pub org_id: Option<String>,
    pub external_id: Option<String>,
    pub auth_provider: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn roles_vec(&self) -> Vec<String> {
        self.roles
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}
