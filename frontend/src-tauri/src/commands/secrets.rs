// Per-user secret storage for split configs.
//
// `org_configs` holds the org-shared metadata for integrations/credentials
// (Jira project key, GitHub org, app URLs, etc.). The personal secrets —
// API tokens, passwords, OAuth client secrets — never leave the user's
// machine. This module exposes a generic JSON-blob keyring API keyed by
// `kind` so the desktop frontend can split / merge in `tauri-api.ts`
// without each integration needing its own custom Tauri command pair.
//
// Storage:
//   - macOS: Keychain (Login keychain by default)
//   - Linux: Secret Service (libsecret)
//   - Windows: Credential Manager
//   `keyring = "3"` with the platform-native features handles all three.
//
// Layout:
//   service = "com.groovysec.maestro"
//   user    = "secrets.{kind}"          e.g. "secrets.integrations"
//   value   = JSON.stringify({ ... })   the per-user secret tree
//
// One blob per kind — small enough to fit in keyring limits (macOS is
// generous; Linux libsecret has no hard cap; Windows Credential Manager
// has 2.5 KB per blob which is plenty for token-shaped data).

use keyring::Entry;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, Result};

const KEYRING_SERVICE: &str = "com.groovysec.maestro";

/// Whitelist of kinds the frontend can read/write here. Keep aligned with
/// backend-rs `routes/configs.rs::ALLOWED_KINDS` minus the org-shared-only
/// kinds (scope, llm, tools, agents — those have no per-user secrets).
const ALLOWED_KINDS: &[&str] = &[
    "integrations",
    "credentials",
    // AWS source credentials cached by the cloud-account setup wizard:
    // either an SSO session (access_token + expiry + start_url + region)
    // or long-term IAM access keys or a profile name. Used by the
    // cloud_validation probe to authenticate before sts:AssumeRole.
    // LEGACY single-source blob — superseded by "aws_sources" (a named
    // library). Still read as a migration fallback.
    "aws_source",
    // AWS source-credential LIBRARY. Shape:
    //   { "default_id": "<id|null>",
    //     "sources": [ { "id", "name", "kind": "sso|access_keys|profile",
    //                    "sso"|"access_keys"|"profile": {...} } ] }
    // Lets a single Maestro deployment hold multiple assume-from
    // identities and pick one per assessment (default + override).
    "aws_sources",
];

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretBlob {
    pub kind: String,
    /// Opaque JSON tree — the desktop side defines its shape; the Rust
    /// side just reads/writes the string verbatim.
    pub value: serde_json::Value,
}

fn check_kind(kind: &str) -> Result<()> {
    if !ALLOWED_KINDS.iter().any(|k| *k == kind) {
        return Err(AppError::Validation(format!(
            "Unknown secret kind '{kind}'. Allowed: {}",
            ALLOWED_KINDS.join(", ")
        )));
    }
    Ok(())
}

fn entry_for(kind: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, &format!("secrets.{kind}"))
        .map_err(|e| AppError::Other(format!("Keyring init failed for {kind}: {}", e)))
}

/// Returns the stored secret blob for the given kind, or an empty object
/// if nothing has been written yet. Empty-blob-on-miss matches how the
/// desktop's config helpers handle a fresh install — the UI shows
/// defaults until the user saves.
#[tauri::command]
pub async fn get_secret_blob(kind: String) -> Result<SecretBlob> {
    check_kind(&kind)?;
    let entry = entry_for(&kind)?;
    let value = match entry.get_password() {
        Ok(stored) => serde_json::from_str(&stored).unwrap_or(serde_json::json!({})),
        Err(keyring::Error::NoEntry) => serde_json::json!({}),
        Err(e) => {
            return Err(AppError::Other(format!(
                "Keyring read failed for {kind}: {e}"
            )))
        }
    };
    Ok(SecretBlob { kind, value })
}

/// Replace the stored blob for the given kind. The desktop side is
/// responsible for sending the FULL secret tree — partial updates aren't
/// supported here so we don't need locking / merge logic.
#[tauri::command]
pub async fn set_secret_blob(kind: String, value: serde_json::Value) -> Result<()> {
    check_kind(&kind)?;
    let serialized = serde_json::to_string(&value)
        .map_err(|e| AppError::Other(format!("Failed to serialize {kind} secrets: {e}")))?;
    entry_for(&kind)?
        .set_password(&serialized)
        .map_err(|e| AppError::Other(format!("Keyring write failed for {kind}: {e}")))?;
    Ok(())
}

/// Wipe the stored blob for the given kind. Used during sign-out and
/// when the user removes an integration entirely.
#[tauri::command]
pub async fn clear_secret_blob(kind: String) -> Result<()> {
    check_kind(&kind)?;
    let entry = entry_for(&kind)?;
    match entry.delete_credential() {
        Ok(_) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Other(format!(
            "Keyring delete failed for {kind}: {e}"
        ))),
    }
}
