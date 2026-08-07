//! `/api/v1/toolkit/*` — credential proxy for the Kali toolkit image.
//!
//! The desktop app needs to pull `ghcr.io/shmalex405/docker-kali` to run
//! an assessment, but we don't ship a GHCR PAT to every customer laptop.
//! Instead the backend holds one read-only PAT (injected at container
//! start via AWS Secrets Manager — see `customer-deploy/*.tfvars`
//! → `ghcr_pat_secret_arn`) and hands it out to Cognito-authenticated
//! clients on demand.
//!
//! This keeps the trust model narrow:
//! - secret never lands in a terraform state file
//! - secret never lands in a tauri config file or client binary
//! - only authenticated desktop clients belonging to the backend's
//!   configured org can request it (AuthUser extractor enforces both)
//! - rotating the PAT is a one-liner (`scripts/create-ghcr-secret.sh`)
//!   plus an ECS task refresh — no client rebuild required
//!
//! NOTE on credential choice: this MUST be a classic PAT (`read:packages`,
//! set to *No expiration* to avoid the silent-expiry outage that stranded a
//! customer). A GitHub App installation token was tried and removed — GitHub
//! Apps CANNOT authenticate to GHCR (the App `Packages:read` permission only
//! covers package billing via REST; the token mints fine but the docker pull
//! returns 403 denied). See community discussion #24636. The durable
//! no-standing-credential successor is ECR brokering via the assume-role
//! infra — see FOLLOWUPS.md #8 in the infra repo.

use axum::{extract::State, routing::get, Json, Router};

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::schemas::toolkit::RegistryCredentials;
use crate::state::AppState;

/// Default image pin when `KALI_IMAGE_TAG` isn't set. `latest` is fine
/// because the image tag is immutable-by-date (`YYYY.MM.DD.{sha}`) plus
/// a moving `:latest` — customers always get the freshest build until
/// we start per-release pinning.
const DEFAULT_IMAGE_TAG: &str = "latest";

pub fn router() -> Router<AppState> {
    Router::new().route("/toolkit/registry-credentials", get(registry_credentials))
}

async fn registry_credentials(
    State(state): State<AppState>,
    _user: AuthUser,
) -> AppResult<Json<RegistryCredentials>> {
    let settings = &state.settings;

    let tag = std::env::var("KALI_IMAGE_TAG").unwrap_or_else(|_| DEFAULT_IMAGE_TAG.to_string());
    let image = format!(
        "{}/{}:{}",
        settings.ghcr_registry, "shmalex405/docker-kali", tag
    );

    let password = settings.ghcr_pat.clone().ok_or_else(|| {
        AppError::ServiceUnavailable(
            "Toolkit credentials not configured on this backend (set GHCR_PAT)".into(),
        )
    })?;
    Ok(Json(RegistryCredentials {
        registry: settings.ghcr_registry.clone(),
        username: settings.ghcr_username.clone(),
        password,
        image,
        expires_at: None,
    }))
}
