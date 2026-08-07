//! Wire shapes for the toolkit-credentials endpoint.
//!
//! The backend proxies GHCR pull credentials to authenticated desktop
//! clients so the private `docker-kali` image can be pulled without
//! distributing a PAT to every laptop. See `routes/toolkit.rs`.

use serde::Serialize;

/// Credential set the desktop uses for bollard `DockerCredentials` before
/// pulling the toolkit image. Today this is a classic read-only GHCR PAT
/// (no expiration). `expires_at` is reserved for the future short-lived
/// path (ECR brokering) where the desktop must re-fetch before it lapses.
#[derive(Debug, Serialize)]
pub struct RegistryCredentials {
    pub registry: String,
    pub username: String,
    pub password: String,
    /// Fully-qualified image reference the desktop should pull. Lets the
    /// backend pin a specific tag per desktop release without baking one
    /// into the client binary.
    pub image: String,
    /// Unix-seconds expiry of `password`. `None` for the long-lived PAT.
    /// When short-lived creds return (ECR brokering), the desktop uses this
    /// to cache the credential and re-fetch before it lapses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}
