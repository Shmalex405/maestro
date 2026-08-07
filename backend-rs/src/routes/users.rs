//! `/api/v1/users` — admin user management for Cognito-backed
//! deployments.
//!
//! Only admins can invite/disable users (`AuthUser.has_any_role(&["admin"])`).
//! All callers must be authenticated (ALLOWED_ORG_ID tenancy guard already
//! applies on the AuthUser extractor).
//!
//! The backing store is Cognito — local Postgres `users` rows are
//! provisioned on login via `/auth/me`, not here.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use aws_sdk_cognitoidentityprovider::types::{AttributeType, MessageActionType};
use chrono::{DateTime, TimeZone, Utc};
use validator::Validate;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::schemas::user_mgmt::{
    InviteUserRequest, InviteUserResponse, UpdateRoleRequest, UserListItem,
};
use crate::state::AppState;

/// Pool-wide group that marks admin users. Any user in this group can
/// manage other users in their org (ALLOWED_ORG_ID tenancy guard still
/// prevents cross-tenant access).
const ADMIN_GROUP: &str = "admin";

/// Pool-wide group that marks read-only users. Membership is surfaced in the
/// user's roles so the desktop app can gate every write action (view-only
/// experience). Backend route-level enforcement of read-only lives in the
/// cloud API repo; this module only assigns the group.
const READONLY_GROUP: &str = "read_only";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(invite_user))
        .route(
            "/users/:id",
            axum::routing::delete(disable_user),
        )
        .route("/users/:id/resend-invite", post(resend_invite))
        .route("/users/:id/role", axum::routing::patch(update_role))
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

fn cognito_not_available() -> AppError {
    AppError::BadRequest(
        "User management is only supported for Cognito-backed deployments".into(),
    )
}

fn require_cognito_pool(state: &AppState) -> AppResult<String> {
    if state.settings.auth_provider != "cognito" {
        return Err(cognito_not_available());
    }
    state
        .settings
        .cognito_user_pool_id
        .clone()
        .ok_or_else(|| AppError::Internal("COGNITO_USER_POOL_ID not set".into()))
}

fn require_admin(user: &AuthUser) -> AppResult<()> {
    if !user.has_any_role(&[ADMIN_GROUP]) {
        return Err(AppError::Forbidden(
            "Admin role required for user management".into(),
        ));
    }
    Ok(())
}

async fn add_to_group(
    client: &aws_sdk_cognitoidentityprovider::Client,
    pool_id: &str,
    username: &str,
    group: &str,
) -> AppResult<()> {
    client
        .admin_add_user_to_group()
        .user_pool_id(pool_id)
        .username(username)
        .group_name(group)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AdminAddUserToGroup({group}): {e}")))?;
    Ok(())
}

async fn remove_from_group(
    client: &aws_sdk_cognitoidentityprovider::Client,
    pool_id: &str,
    username: &str,
    group: &str,
) -> AppResult<()> {
    client
        .admin_remove_user_from_group()
        .user_pool_id(pool_id)
        .username(username)
        .group_name(group)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AdminRemoveUserFromGroup({group}): {e}")))?;
    Ok(())
}

fn org_group(user: &AuthUser) -> AppResult<String> {
    let org = user.org_id.as_deref().ok_or_else(|| {
        AppError::Forbidden("Authenticated user has no org_id — cannot scope listing".into())
    })?;
    Ok(format!("org:{org}"))
}

fn attr<'a>(attrs: &'a [AttributeType], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.name() == name)
        .and_then(|a| a.value())
}

fn convert_user(
    u: &aws_sdk_cognitoidentityprovider::types::UserType,
    roles: Vec<String>,
) -> UserListItem {
    let attrs = u.attributes();
    let email = attr(attrs, "email")
        .map(str::to_string)
        .unwrap_or_default();
    let id = attr(attrs, "sub")
        .map(str::to_string)
        .unwrap_or_else(|| u.username().unwrap_or("").to_string());
    UserListItem {
        id,
        email,
        status: u
            .user_status()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "UNKNOWN".to_string()),
        enabled: Some(u.enabled()),
        roles,
        created_at: u.user_create_date().and_then(aws_to_chrono),
        last_modified_at: u.user_last_modified_date().and_then(aws_to_chrono),
    }
}

fn aws_to_chrono(t: &aws_sdk_cognitoidentityprovider::primitives::DateTime) -> Option<DateTime<Utc>> {
    let secs = t.secs();
    let nanos = t.subsec_nanos();
    Utc.timestamp_opt(secs, nanos).single()
}

// ──────────────────────────────────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────────────────────────────────

async fn list_users(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<UserListItem>>> {
    let pool_id = require_cognito_pool(&state)?;
    let group_name = org_group(&user)?;
    let client = state.cognito_client().await;

    let resp = client
        .list_users_in_group()
        .user_pool_id(&pool_id)
        .group_name(&group_name)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("ListUsersInGroup: {e}")))?;

    // Enrich with group membership so the UI can render roles (admin vs not).
    let mut out = Vec::with_capacity(resp.users().len());
    for u in resp.users() {
        let username = u.username().unwrap_or_default();
        let groups = client
            .admin_list_groups_for_user()
            .user_pool_id(&pool_id)
            .username(username)
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("AdminListGroupsForUser: {e}")))?;
        let roles: Vec<String> = groups
            .groups()
            .iter()
            .filter_map(|g| g.group_name().map(str::to_string))
            .collect();
        out.push(convert_user(u, roles));
    }
    Ok(Json(out))
}

async fn invite_user(
    State(state): State<AppState>,
    admin: AuthUser,
    Json(req): Json<InviteUserRequest>,
) -> AppResult<(StatusCode, Json<InviteUserResponse>)> {
    require_admin(&admin)?;
    req.validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let pool_id = require_cognito_pool(&state)?;
    let group_name = org_group(&admin)?;
    let org_id = admin.org_id.clone().unwrap();
    let client = state.cognito_client().await;

    let email_attr = AttributeType::builder()
        .name("email")
        .value(&req.email)
        .build()
        .map_err(|e| AppError::Internal(format!("email attr: {e}")))?;
    let verified_attr = AttributeType::builder()
        .name("email_verified")
        .value("true")
        .build()
        .map_err(|e| AppError::Internal(format!("email_verified attr: {e}")))?;
    let org_attr = AttributeType::builder()
        .name("custom:org_id")
        .value(&org_id)
        .build()
        .map_err(|e| AppError::Internal(format!("custom:org_id attr: {e}")))?;

    let create_resp = client
        .admin_create_user()
        .user_pool_id(&pool_id)
        .username(&req.email)
        .user_attributes(email_attr)
        .user_attributes(verified_attr)
        .user_attributes(org_attr)
        .desired_delivery_mediums(
            aws_sdk_cognitoidentityprovider::types::DeliveryMediumType::Email,
        )
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AdminCreateUser: {e}")))?;

    let created = create_resp
        .user()
        .ok_or_else(|| AppError::Internal("AdminCreateUser returned no user".into()))?;
    let username = created.username().unwrap_or_default().to_string();

    // Add to the org group so list_users sees them.
    client
        .admin_add_user_to_group()
        .user_pool_id(&pool_id)
        .username(&username)
        .group_name(&group_name)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AdminAddUserToGroup(org): {e}")))?;

    let mut roles = vec![group_name.clone()];

    match req.role.as_deref() {
        Some("admin") => {
            add_to_group(&client, &pool_id, &username, ADMIN_GROUP).await?;
            roles.push(ADMIN_GROUP.to_string());
        }
        Some("read_only") | Some("readonly") | Some("viewer") => {
            add_to_group(&client, &pool_id, &username, READONLY_GROUP).await?;
            roles.push(READONLY_GROUP.to_string());
        }
        // Anything else (incl. "user"/None) is a plain org member.
        _ => {}
    }

    let id = attr(created.attributes(), "sub")
        .map(str::to_string)
        .unwrap_or(username);
    let status = created
        .user_status()
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "FORCE_CHANGE_PASSWORD".to_string());

    Ok((
        StatusCode::CREATED,
        Json(InviteUserResponse {
            id,
            email: req.email,
            status,
            roles,
        }),
    ))
}

async fn disable_user(
    State(state): State<AppState>,
    admin: AuthUser,
    Path(id_or_email): Path<String>,
) -> AppResult<StatusCode> {
    require_admin(&admin)?;
    // Self-service guard — don't let an admin lock themselves out.
    if admin.id == id_or_email || admin.email == id_or_email {
        return Err(AppError::BadRequest(
            "Cannot disable your own account".into(),
        ));
    }
    let pool_id = require_cognito_pool(&state)?;
    let client = state.cognito_client().await;
    client
        .admin_disable_user()
        .user_pool_id(&pool_id)
        .username(&id_or_email)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AdminDisableUser: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn resend_invite(
    State(state): State<AppState>,
    admin: AuthUser,
    Path(id_or_email): Path<String>,
) -> AppResult<StatusCode> {
    require_admin(&admin)?;
    let pool_id = require_cognito_pool(&state)?;
    let client = state.cognito_client().await;

    // Re-send the welcome email. AdminCreateUser with MessageAction=RESEND
    // does not create a new user — it re-sends the existing invitation.
    client
        .admin_create_user()
        .user_pool_id(&pool_id)
        .username(&id_or_email)
        .message_action(MessageActionType::Resend)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("AdminCreateUser(Resend): {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

async fn update_role(
    State(state): State<AppState>,
    admin: AuthUser,
    Path(id_or_email): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> AppResult<StatusCode> {
    require_admin(&admin)?;
    let pool_id = require_cognito_pool(&state)?;
    let client = state.cognito_client().await;

    match req.role.as_str() {
        "admin" => {
            // Promote to admin and clear any read-only restriction so the
            // two roles never coexist (admin always wins, but keep groups tidy).
            add_to_group(&client, &pool_id, &id_or_email, ADMIN_GROUP).await?;
            remove_from_group(&client, &pool_id, &id_or_email, READONLY_GROUP).await?;
        }
        "read_only" | "readonly" | "viewer" => {
            // Self-service guard — don't let an admin lock themselves out of
            // user management by making their own account view-only.
            if admin.id == id_or_email || admin.email == id_or_email {
                return Err(AppError::BadRequest(
                    "Cannot make your own account read-only".into(),
                ));
            }
            add_to_group(&client, &pool_id, &id_or_email, READONLY_GROUP).await?;
            remove_from_group(&client, &pool_id, &id_or_email, ADMIN_GROUP).await?;
        }
        "user" | "member" => {
            // Self-service guard — don't let an admin demote themselves out.
            if admin.id == id_or_email || admin.email == id_or_email {
                return Err(AppError::BadRequest(
                    "Cannot remove admin role from your own account".into(),
                ));
            }
            // Plain org member: neither admin nor read-only.
            remove_from_group(&client, &pool_id, &id_or_email, ADMIN_GROUP).await?;
            remove_from_group(&client, &pool_id, &id_or_email, READONLY_GROUP).await?;
        }
        other => {
            return Err(AppError::BadRequest(format!(
                "Unknown role '{other}' — expected 'admin', 'user', or 'read_only'"
            )));
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
