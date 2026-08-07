//! Wire types for the `/api/v1/users` endpoints — admin user management
//! against the backing Cognito user pool.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Serialize)]
pub struct UserListItem {
    /// Cognito `sub` — stable UUID.
    pub id: String,
    pub email: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InviteUserRequest {
    #[validate(email)]
    pub email: String,
    /// Optional role for the new user:
    ///   - "admin"      → pool-wide `admin` group (can manage users)
    ///   - "read_only"  → pool-wide `read_only` group (view-only access)
    ///   - anything else / omitted → regular org member (default)
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InviteUserResponse {
    pub id: String,
    pub email: String,
    pub status: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    /// Target role: "admin", "read_only", or "user" (plain org member).
    pub role: String,
}
