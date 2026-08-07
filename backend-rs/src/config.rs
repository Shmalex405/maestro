//! Settings loaded from environment variables.
//!
//! Field-by-field mirror of `backend/app/core/config.py:Settings`. Defaults
//! match the Python backend exactly so the Rust image can be swapped in
//! without customers touching their env.

use serde::Deserialize;

fn default_app_name() -> String {
    "Pentest Platform API".to_string()
}
fn default_app_version() -> String {
    "1.0.0".to_string()
}
fn default_api_prefix() -> String {
    "/api/v1".to_string()
}
fn default_database_url() -> String {
    "postgresql://postgres:postgres@localhost:5432/pentest".to_string()
}
fn default_auth_provider() -> String {
    "local".to_string()
}
fn default_jwt_secret() -> String {
    "change-me-in-production-use-secrets-manager".to_string()
}
fn default_jwt_algorithm() -> String {
    "HS256".to_string()
}
fn default_jwt_expiration_hours() -> i64 {
    24
}
fn default_storage_provider() -> String {
    "local".to_string()
}
fn default_storage_local_path() -> String {
    "./storage".to_string()
}
fn default_cors_origins() -> Vec<String> {
    vec![
        "http://localhost:3000".to_string(),
        "tauri://localhost".to_string(),
    ]
}
fn default_debug() -> bool {
    false
}
fn default_ghcr_registry() -> String {
    "ghcr.io".to_string()
}
fn default_ghcr_username() -> String {
    "shmalex405".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    #[serde(default = "default_app_name")]
    pub app_name: String,
    #[serde(default = "default_app_version")]
    pub app_version: String,
    #[serde(default = "default_debug")]
    pub debug: bool,

    #[serde(default = "default_api_prefix")]
    pub api_prefix: String,

    #[serde(default = "default_database_url")]
    pub database_url: String,

    #[serde(default = "default_auth_provider")]
    pub auth_provider: String,
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,
    #[serde(default = "default_jwt_algorithm")]
    pub jwt_algorithm: String,
    #[serde(default = "default_jwt_expiration_hours")]
    pub jwt_expiration_hours: i64,

    pub cognito_region: Option<String>,
    pub cognito_user_pool_id: Option<String>,
    pub cognito_app_client_id: Option<String>,

    /// Tenancy guard — reject JWTs whose `org_id` claim differs.
    pub allowed_org_id: Option<String>,

    /// Default assessment role ARN the cloud-credential broker assumes
    /// (`POST /cloud/assume`) when the request doesn't specify one. The
    /// role must trust this deployment's ECS task role. IAM on the task
    /// role is the backstop for which roles are actually assumable.
    pub assessment_role_arn: Option<String>,

    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,

    #[serde(default = "default_storage_provider")]
    pub storage_provider: String,
    #[serde(default = "default_storage_local_path")]
    pub storage_local_path: String,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,

    #[serde(default = "default_cors_origins")]
    pub cors_origins: Vec<String>,

    // ----- GHCR credentials for the toolkit pull proxy -----
    // The backend exposes `/api/v1/toolkit/registry-credentials` so the
    // desktop app can pull the private `ghcr.io/.../docker-kali` image
    // without every customer laptop holding a PAT directly. These fields
    // are sourced from ECS secrets (see customer-deploy/terraform.tfvars
    // → `ghcr_pat_secret_arn`), which injects GHCR_PAT at container
    // start. Registry/username have sensible defaults baked in.
    #[serde(default = "default_ghcr_registry")]
    pub ghcr_registry: String,
    #[serde(default = "default_ghcr_username")]
    pub ghcr_username: String,
    pub ghcr_pat: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            app_name: default_app_name(),
            app_version: default_app_version(),
            debug: default_debug(),
            api_prefix: default_api_prefix(),
            database_url: default_database_url(),
            auth_provider: default_auth_provider(),
            jwt_secret: default_jwt_secret(),
            jwt_algorithm: default_jwt_algorithm(),
            jwt_expiration_hours: default_jwt_expiration_hours(),
            cognito_region: None,
            cognito_user_pool_id: None,
            cognito_app_client_id: None,
            allowed_org_id: None,
            assessment_role_arn: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            storage_provider: default_storage_provider(),
            storage_local_path: default_storage_local_path(),
            s3_bucket: None,
            s3_region: None,
            cors_origins: default_cors_origins(),
            ghcr_registry: default_ghcr_registry(),
            ghcr_username: default_ghcr_username(),
            ghcr_pat: None,
        }
    }
}

impl Settings {
    /// Load from process env, applying the same defaults as pydantic-settings.
    ///
    /// Env var names match pydantic's lowercase convention (e.g. `DATABASE_URL`,
    /// `AUTH_PROVIDER`, `JWT_SECRET`). Lists (`CORS_ORIGINS`) parse as JSON
    /// arrays, same as pydantic.
    pub fn from_env() -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv();
        let mut s = Settings::default();

        if let Ok(v) = std::env::var("APP_NAME") {
            s.app_name = v;
        }
        if let Ok(v) = std::env::var("APP_VERSION") {
            s.app_version = v;
        }
        if let Ok(v) = std::env::var("DEBUG") {
            s.debug = parse_bool(&v);
        }
        if let Ok(v) = std::env::var("API_PREFIX") {
            s.api_prefix = v;
        }
        if let Ok(v) = std::env::var("DATABASE_URL") {
            s.database_url = v;
        }
        if let Ok(v) = std::env::var("AUTH_PROVIDER") {
            s.auth_provider = v;
        }
        if let Ok(v) = std::env::var("JWT_SECRET") {
            s.jwt_secret = v;
        }
        if let Ok(v) = std::env::var("JWT_ALGORITHM") {
            s.jwt_algorithm = v;
        }
        if let Ok(v) = std::env::var("JWT_EXPIRATION_HOURS") {
            s.jwt_expiration_hours = v.parse()?;
        }
        s.cognito_region = opt("COGNITO_REGION");
        s.cognito_user_pool_id = opt("COGNITO_USER_POOL_ID");
        s.cognito_app_client_id = opt("COGNITO_APP_CLIENT_ID");
        s.allowed_org_id = opt("ALLOWED_ORG_ID");
        s.assessment_role_arn = opt("ASSESSMENT_ROLE_ARN");
        s.oidc_issuer = opt("OIDC_ISSUER");
        s.oidc_client_id = opt("OIDC_CLIENT_ID");
        s.oidc_client_secret = opt("OIDC_CLIENT_SECRET");
        if let Ok(v) = std::env::var("STORAGE_PROVIDER") {
            s.storage_provider = v;
        }
        if let Ok(v) = std::env::var("STORAGE_LOCAL_PATH") {
            s.storage_local_path = v;
        }
        s.s3_bucket = opt("S3_BUCKET");
        s.s3_region = opt("S3_REGION");
        if let Ok(v) = std::env::var("CORS_ORIGINS") {
            s.cors_origins = parse_origins(&v);
        }
        if let Ok(v) = std::env::var("GHCR_REGISTRY") {
            s.ghcr_registry = v;
        }
        if let Ok(v) = std::env::var("GHCR_USERNAME") {
            s.ghcr_username = v;
        }
        s.ghcr_pat = opt("GHCR_PAT");
        Ok(s)
    }

    /// Postgres URL with the SQLAlchemy dialect prefix stripped. The Python
    /// backend reads `postgresql+asyncpg://...`; sqlx wants plain
    /// `postgres://...` or `postgresql://...`.
    pub fn postgres_url(&self) -> String {
        self.database_url
            .replacen("postgresql+asyncpg://", "postgresql://", 1)
            .replacen("postgres+asyncpg://", "postgres://", 1)
    }
}

fn opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn parse_bool(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_origins(v: &str) -> Vec<String> {
    // Accept either JSON array or comma-separated (pydantic behavior).
    if let Ok(arr) = serde_json::from_str::<Vec<String>>(v) {
        return arr;
    }
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
