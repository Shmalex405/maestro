//! JWT encode/decode for all three auth providers.
//!
//! Port of `backend/app/core/security.py`:
//!   - `verify_local_token`  → HS256 with `JWT_SECRET`
//!   - `verify_cognito_token` → RS256, JWKS from Cognito user pool
//!   - `verify_oidc_token`    → RS256, JWKS from OIDC discovery
//!   - `create_access_token`  → HS256, claims match Python TokenData

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::auth::jwks_cache::JwksCache;
use crate::config::Settings;
use crate::error::{AppError, AppResult};

/// Claims for locally-issued tokens. Shape matches
/// `backend/app/core/security.py:TokenData` exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalClaims {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub exp: i64,
}

/// Cognito's claims use `custom:org_id` and `cognito:groups`.
#[derive(Debug, Clone, Deserialize)]
struct CognitoClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, rename = "custom:org_id")]
    custom_org_id: Option<String>,
    #[serde(default, rename = "cognito:groups")]
    cognito_groups: Vec<String>,
    /// Phase 6 caching plan: M2M service-account tokens carry this
    /// custom claim (e.g. `custom:service_caller = "cache-stats-router"`)
    /// to identify themselves as cross-tenant service callers. The
    /// auth middleware honors the claim by bypassing the per-tenant
    /// `ALLOWED_ORG_ID` check ONLY when the route explicitly opts in
    /// via the ServiceWriter extractor — never for user-facing routes.
    #[serde(default, rename = "custom:service_caller")]
    custom_service_caller: Option<String>,
    #[allow(dead_code)]
    exp: i64,
}

/// OIDC claims use `org_id` and `groups`.
#[derive(Debug, Clone, Deserialize)]
struct OidcClaims {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[allow(dead_code)]
    exp: i64,
}

/// Normalized token data used by the middleware after verification.
#[derive(Debug, Clone)]
pub struct TokenData {
    pub sub: String,
    pub email: Option<String>,
    pub org_id: Option<String>,
    pub roles: Vec<String>,
    /// Non-empty when the token is an M2M service-account JWT (Phase 6
    /// caching plan). The value identifies which service (e.g.
    /// "cache-stats-router"). User tokens always have None here.
    pub service_caller: Option<String>,
}

/// Create a local HS256 token. `expires_in_hours` overrides the default.
pub fn create_access_token(
    settings: &Settings,
    sub: &str,
    email: Option<&str>,
    org_id: Option<&str>,
    roles: &[String],
    expires_in_hours: Option<i64>,
) -> AppResult<String> {
    let hours = expires_in_hours.unwrap_or(settings.jwt_expiration_hours);
    let exp = (Utc::now() + Duration::hours(hours)).timestamp();
    let claims = LocalClaims {
        sub: sub.to_string(),
        email: email.map(str::to_string),
        org_id: org_id.map(str::to_string),
        roles: roles.to_vec(),
        exp,
    };
    let alg = algorithm_for(&settings.jwt_algorithm)?;
    encode(
        &Header::new(alg),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("jwt encode failed: {e}")))
}

pub fn verify_local_token(settings: &Settings, token: &str) -> AppResult<TokenData> {
    let alg = algorithm_for(&settings.jwt_algorithm)?;
    let mut validation = Validation::new(alg);
    // Python's python-jose defaults: verify exp (yes), no audience/issuer check.
    validation.validate_aud = false;
    let data = decode::<LocalClaims>(
        token,
        &DecodingKey::from_secret(settings.jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| AppError::Unauthorized(format!("Invalid token: {e}")))?;
    Ok(TokenData {
        sub: data.claims.sub,
        email: data.claims.email,
        org_id: data.claims.org_id,
        roles: data.claims.roles,
        // Local HS256 tokens (dev/test) don't carry service_caller claims;
        // service tokens always flow through Cognito.
        service_caller: None,
    })
}

pub async fn verify_cognito_token(
    settings: &Settings,
    token: &str,
    jwks: &JwksCache,
) -> AppResult<TokenData> {
    let region = settings
        .cognito_region
        .as_ref()
        .ok_or_else(|| AppError::Internal("COGNITO_REGION not set".into()))?;
    let pool_id = settings
        .cognito_user_pool_id
        .as_ref()
        .ok_or_else(|| AppError::Internal("COGNITO_USER_POOL_ID not set".into()))?;
    let audience = settings
        .cognito_app_client_id
        .as_ref()
        .ok_or_else(|| AppError::Internal("COGNITO_APP_CLIENT_ID not set".into()))?;

    let issuer = format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}");
    let jwks_url = format!("{issuer}/.well-known/jwks.json");
    let key_set = jwks.fetch(&jwks_url).await?;
    let key = pick_jwk(token, &key_set.keys)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[&issuer]);
    let decoding = DecodingKey::from_jwk(&key)
        .map_err(|e| AppError::Unauthorized(format!("Invalid Cognito token key: {e}")))?;
    let data = decode::<CognitoClaims>(token, &decoding, &validation)
        .map_err(|e| AppError::Unauthorized(format!("Invalid Cognito token: {e}")))?;

    Ok(TokenData {
        sub: data.claims.sub,
        email: data.claims.email,
        org_id: data.claims.custom_org_id,
        roles: data.claims.cognito_groups,
        service_caller: data.claims.custom_service_caller,
    })
}

pub async fn verify_oidc_token(
    settings: &Settings,
    token: &str,
    jwks: &JwksCache,
) -> AppResult<TokenData> {
    let issuer = settings
        .oidc_issuer
        .as_ref()
        .ok_or_else(|| AppError::Internal("OIDC_ISSUER not set".into()))?;
    let audience = settings
        .oidc_client_id
        .as_ref()
        .ok_or_else(|| AppError::Internal("OIDC_CLIENT_ID not set".into()))?;

    let jwks_url = jwks.fetch_oidc_discovery(issuer).await?;
    let key_set = jwks.fetch(&jwks_url).await?;
    let key = pick_jwk(token, &key_set.keys)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);
    let decoding = DecodingKey::from_jwk(&key)
        .map_err(|e| AppError::Unauthorized(format!("Invalid OIDC token key: {e}")))?;
    let data = decode::<OidcClaims>(token, &decoding, &validation)
        .map_err(|e| AppError::Unauthorized(format!("Invalid OIDC token: {e}")))?;

    Ok(TokenData {
        sub: data.claims.sub,
        email: data.claims.email,
        org_id: data.claims.org_id,
        roles: data.claims.groups,
        // OIDC/Okta don't issue service tokens for cache fan-out today;
        // leave None. If we add an Okta service-account integration later,
        // mirror the Cognito custom claim here.
        service_caller: None,
    })
}

fn algorithm_for(name: &str) -> AppResult<Algorithm> {
    match name.to_ascii_uppercase().as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        other => Err(AppError::Internal(format!(
            "unsupported JWT algorithm: {other}"
        ))),
    }
}

fn pick_jwk(token: &str, keys: &[serde_json::Value]) -> AppResult<jsonwebtoken::jwk::Jwk> {
    let header =
        decode_header(token).map_err(|e| AppError::Unauthorized(format!("Invalid token: {e}")))?;
    let kid = header
        .kid
        .ok_or_else(|| AppError::Unauthorized("Invalid token key".into()))?;
    let key_value = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid.as_str()))
        .ok_or_else(|| AppError::Unauthorized("Invalid token key".into()))?;
    serde_json::from_value::<jsonwebtoken::jwk::Jwk>(key_value.clone())
        .map_err(|e| AppError::Unauthorized(format!("Invalid JWK: {e}")))
}
