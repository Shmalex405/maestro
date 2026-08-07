//! Request / response shapes for the `/auth/*` endpoints.
//! Byte-for-byte mirror of the Pydantic schemas in
//! `backend/app/models/schemas.py`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::user::User;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize)]
pub struct UserCreate {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub roles: Vec<String>,
    pub org_id: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

impl From<&User> for UserResponse {
    fn from(u: &User) -> Self {
        UserResponse {
            id: u.id.clone(),
            email: u.email.clone(),
            name: u.name.clone(),
            is_active: u.is_active.unwrap_or(false),
            is_admin: u.is_admin.unwrap_or(false),
            roles: u.roles_vec(),
            org_id: u.org_id.clone(),
            created_at: u.created_at,
        }
    }
}
