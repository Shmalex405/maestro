//! `/auth/login`, `/auth/register`, `/auth/me`, `/auth/providers`.
//! Mirror of `backend/app/routers/auth.py`.

use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::password::{hash_password, verify_password};
use crate::auth::{jwt, AuthUser};
use crate::error::{AppError, AppResult};
use crate::models::user::User;
use crate::schemas::auth::{LoginRequest, TokenResponse, UserCreate, UserResponse};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/me", get(me))
        .route("/auth/providers", get(providers))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    if state.settings.auth_provider != "local" {
        return Err(AppError::BadRequest(format!(
            "Local login not available. Use {} authentication.",
            state.settings.auth_provider
        )));
    }

    let user: Option<User> =
        sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(&req.email)
            .fetch_optional(&state.pool)
            .await?;

    let user = match user.as_ref() {
        Some(u) if u.hashed_password.is_some() => u,
        _ => return Err(AppError::Unauthorized("Invalid email or password".into())),
    };

    let hashed = user.hashed_password.as_ref().unwrap();
    if !verify_password(&req.password, hashed) {
        return Err(AppError::Unauthorized("Invalid email or password".into()));
    }

    if !user.is_active.unwrap_or(false) {
        return Err(AppError::Unauthorized("Account is disabled".into()));
    }

    // Update last_login_at (best-effort; don't fail login if this errors).
    let _ = sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(&user.id)
        .execute(&state.pool)
        .await;

    let roles = user.roles_vec();
    let token = jwt::create_access_token(
        &state.settings,
        &user.id,
        Some(&user.email),
        user.org_id.as_deref(),
        &roles,
        None,
    )?;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "bearer".to_string(),
        expires_in: state.settings.jwt_expiration_hours * 3600,
    }))
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<UserCreate>,
) -> AppResult<(StatusCode, Json<UserResponse>)> {
    if state.settings.auth_provider != "local" {
        return Err(AppError::BadRequest(format!(
            "Local registration not available. Use {}.",
            state.settings.auth_provider
        )));
    }

    // Email uniqueness.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(&req.email)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_some() {
        return Err(AppError::BadRequest("Email already registered".into()));
    }

    let id = Uuid::new_v4().to_string();
    let hashed = hash_password(&req.password)?;
    let roles_json = serde_json::to_value(["user"]).unwrap();

    sqlx::query(
        r#"INSERT INTO users
              (id, email, hashed_password, name, auth_provider, roles, is_active, is_admin)
           VALUES ($1, $2, $3, $4, 'local', $5, TRUE, FALSE)"#,
    )
    .bind(&id)
    .bind(&req.email)
    .bind(&hashed)
    .bind(&req.name)
    .bind(&roles_json)
    .execute(&state.pool)
    .await?;

    let user: User = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;

    Ok((StatusCode::CREATED, Json(UserResponse::from(&user))))
}

async fn me(
    State(state): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<UserResponse>> {
    let existing: Option<User> = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&user.id)
        .fetch_optional(&state.pool)
        .await?;

    if let Some(u) = existing {
        return Ok(Json(UserResponse::from(&u)));
    }

    // Just-in-time provisioning for external auth providers, matching
    // `backend/app/routers/auth.py::get_current_user_info`.
    let roles_json = serde_json::to_value(&user.roles).unwrap_or(Value::Array(vec![]));
    sqlx::query(
        r#"INSERT INTO users
              (id, email, org_id, external_id, auth_provider, roles, is_active, is_admin)
           VALUES ($1, $2, $3, $1, $4, $5, TRUE, FALSE)"#,
    )
    .bind(&user.id)
    .bind(&user.email)
    .bind(&user.org_id)
    .bind(&state.settings.auth_provider)
    .bind(&roles_json)
    .execute(&state.pool)
    .await?;

    let u: User = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&user.id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(UserResponse::from(&u)))
}

async fn providers(State(state): State<AppState>) -> Json<Value> {
    let mut list: Vec<Value> = Vec::new();
    match state.settings.auth_provider.as_str() {
        "local" => {
            list.push(json!({
                "type": "local",
                "name": "Email & Password",
                "login_url": "/api/v1/auth/login",
            }));
        }
        "cognito" => {
            list.push(json!({
                "type": "cognito",
                "name": "AWS Cognito",
                "region": state.settings.cognito_region,
                "user_pool_id": state.settings.cognito_user_pool_id,
                "client_id": state.settings.cognito_app_client_id,
            }));
        }
        "oidc" | "okta" => {
            list.push(json!({
                "type": state.settings.auth_provider,
                "name": "Single Sign-On",
                "issuer": state.settings.oidc_issuer,
                "client_id": state.settings.oidc_client_id,
            }));
        }
        _ => {}
    }
    Json(json!({
        "providers": list,
        "default": state.settings.auth_provider,
    }))
}
