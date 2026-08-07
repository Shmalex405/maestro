use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

fn get_config_dir() -> Result<PathBuf> {
    let config_dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Could not determine home directory".to_string()))?
        .join(".kali-mcp-pentest");

    std::fs::create_dir_all(&config_dir)?;
    Ok(config_dir)
}

// =============================================================================
// Scope Configuration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScope {
    pub cidr: String,
    pub environment: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainScope {
    pub pattern: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExclusionScope {
    pub pattern: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudAccountScope {
    pub id: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_arn: Option<String>,
    /// Optional external ID for cross-account role assumption.
    /// Pairs with `role_arn` when AWS auth_method is "role".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Named AWS CLI profile from ~/.aws/credentials. Used when
    /// auth_method is "profile" — Maestro sets AWS_PROFILE before
    /// invoking the AWS SDK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_profile: Option<String>,
    /// AWS access key ID (the public half of a long-lived IAM user
    /// credential). Used when auth_method is "access_key".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// AWS secret access key (sensitive). The Rust side hands this to
    /// the AWS SDK and never logs it. Used when auth_method is
    /// "access_key".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_key: Option<String>,
    #[serde(default)]
    pub services_in_scope: Vec<String>,
    #[serde(default)]
    pub resource_groups_in_scope: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

/// A `scope.yml` `identity_targets[]` entry — an AD domain, Entra/M365
/// tenant, Okta org, Google Workspace customer, or Ping environment that
/// the identity red-team agents are authorized to assess. Mirrors the
/// shape of `CloudAccountScope` and fails closed like `cloud_accounts`:
/// no entry, no identity testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityTargetScope {
    pub id: String,
    /// active_directory | entra_id | m365 | okta | google_workspace | ping
    pub kind: String,
    /// Mirror of `kind`; the mcp-server validator reads `.provider`.
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Primary domain / customer id / tenant id / Okta org / Ping env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Okta org url / Ping base.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// service_account | api_token | service_principal | domain_creds | oauth | none
    #[serde(default)]
    pub auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// google_workspace SA-JSON credential ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sa_key_ref: Option<String>,
    /// google_workspace delegated admin email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject: Option<String>,
    /// Lockout Mandate — accounts never to touch.
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockout_threshold: Option<u32>,
    #[serde(default)]
    pub notes: String,
}

/// A `scope.yml` `ai_targets[]` entry — a customer-owned AI/LLM system (chatbot,
/// tool-using agent, RAG app, MCP server, or raw model API) the AI red-team agents
/// are authorized to assess. Mirrors `IdentityTargetScope` and fails closed like
/// `cloud_accounts` / `identity_targets`: no entry, no AI testing. See
/// docs/ai-surface-plan.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTargetScope {
    pub id: String,
    /// model_api | chat_app | agent | rag_app | mcp_server
    pub kind: String,
    /// custom | openai | anthropic | azure_openai | bedrock | vertex
    #[serde(default)]
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// HTTP endpoint — MUST also resolve into an in-scope domains/networks entry
    /// (the mcp-server AI scope validator enforces this).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Alternate base url (some MCP/agent targets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The model the customer claims is behind the endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The endpoint's request body shape — a JSON template with a {{PROMPT}}
    /// placeholder. REQUIRED to run the probes; no default is assumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_template: Option<String>,
    /// Dot/bracket path to the assistant reply in the response JSON
    /// (e.g. `choices.0.message.content`). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_path: Option<String>,
    /// bearer | api_key | session | none
    #[serde(default)]
    pub auth_method: String,
    /// Name of a Config → Credentials application whose login this AI target
    /// reuses. When set, the assessment mints a FRESH bearer per run via that
    /// app's server-side login (shared with the web/API assessment) instead of a
    /// static token — so it never expires mid-run. Takes precedence over
    /// `credential_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_credential: Option<String>,
    /// Key into credentials.yml for the endpoint's secret. Static-token fallback
    /// when no `app_credential` is linked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    /// Declared system prompt, if the customer shares it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt_known: Option<String>,
    /// For `agent` targets — the exposed tool set (the excessive-agency blast radius).
    #[serde(default)]
    pub declared_tools: Vec<String>,
    /// Declared input/output guardrails the customer claims.
    #[serde(default)]
    pub declared_guardrails: Vec<String>,
    /// N-trials default for nondeterministic tests (see ai-surface-plan §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trials: Option<u32>,
    /// Probe for cross-kind capabilities (agent/rag/mcp) beyond the declared kind
    /// (AI-RECON-05). Default true (None = on); false honors the declared kind only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_kind_probe: Option<bool>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sClusterScope {
    pub id: String,
    #[serde(default)]
    pub cluster: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub auth_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubeconfig_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default)]
    pub namespaces_in_scope: Vec<String>,
    #[serde(default)]
    pub namespaces_excluded: Vec<String>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    #[serde(default)]
    pub networks: Vec<NetworkScope>,
    #[serde(default)]
    pub domains: Vec<DomainScope>,
    #[serde(default)]
    pub exclusions: Vec<ExclusionScope>,
    #[serde(default)]
    pub cloud_accounts: Vec<CloudAccountScope>,
    #[serde(default)]
    pub identity_targets: Vec<IdentityTargetScope>,
    #[serde(default)]
    pub ai_targets: Vec<AiTargetScope>,
    #[serde(default, alias = "k8s_clusters")]
    pub kubernetes: Vec<K8sClusterScope>,
}

#[tauri::command]
pub async fn get_scope_config() -> Result<ScopeConfig> {
    info!("Getting scope configuration");

    let config_path = get_config_dir()?.join("scope.yml");

    if !config_path.exists() {
        return Ok(ScopeConfig {
            networks: vec![],
            domains: vec![],
            exclusions: vec![],
            cloud_accounts: vec![],
            identity_targets: vec![],
            ai_targets: vec![],
            kubernetes: vec![],
        });
    }

    let content = std::fs::read_to_string(&config_path)?;

    // Try to parse as the new structured format first
    if let Ok(config) = serde_yaml::from_str::<ScopeConfig>(&content) {
        return Ok(config);
    }

    // Fall back to parsing the old simple string format
    let config: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| AppError::Config(format!("Invalid scope config: {}", e)))?;

    Ok(ScopeConfig {
        networks: config["networks"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .filter_map(|v| {
                        if let Some(cidr) = v.as_str() {
                            // Old format: just a string
                            Some(NetworkScope {
                                cidr: cidr.to_string(),
                                environment: "staging".to_string(),
                                notes: String::new(),
                            })
                        } else if v.is_mapping() {
                            // New format: object
                            Some(NetworkScope {
                                cidr: v["cidr"].as_str().unwrap_or_default().to_string(),
                                environment: v["environment"].as_str().unwrap_or("staging").to_string(),
                                notes: v["notes"].as_str().unwrap_or_default().to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        domains: config["domains"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .filter_map(|v| {
                        if let Some(pattern) = v.as_str() {
                            Some(DomainScope {
                                pattern: pattern.to_string(),
                                environment: "staging".to_string(),
                            })
                        } else if v.is_mapping() {
                            Some(DomainScope {
                                pattern: v["pattern"].as_str().unwrap_or_default().to_string(),
                                environment: v["environment"].as_str().unwrap_or("staging").to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        exclusions: config["exclusions"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .filter_map(|v| {
                        if let Some(pattern) = v.as_str() {
                            Some(ExclusionScope {
                                pattern: pattern.to_string(),
                                reason: String::new(),
                            })
                        } else if v.is_mapping() {
                            Some(ExclusionScope {
                                pattern: v["pattern"].as_str().unwrap_or_default().to_string(),
                                reason: v["reason"].as_str().unwrap_or_default().to_string(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default(),
        cloud_accounts: config["cloud_accounts"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .filter_map(|v| serde_yaml::from_value::<CloudAccountScope>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default(),
        identity_targets: config["identity_targets"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .filter_map(|v| serde_yaml::from_value::<IdentityTargetScope>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default(),
        ai_targets: config["ai_targets"]
            .as_sequence()
            .map(|s| {
                s.iter()
                    .filter_map(|v| serde_yaml::from_value::<AiTargetScope>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default(),
        kubernetes: config["kubernetes"]
            .as_sequence()
            .or_else(|| config["k8s_clusters"].as_sequence())
            .map(|s| {
                s.iter()
                    .filter_map(|v| serde_yaml::from_value::<K8sClusterScope>(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default(),
    })
}

#[tauri::command]
pub async fn save_scope_config(config: ScopeConfig) -> Result<()> {
    info!("Saving scope configuration");

    let config_path = get_config_dir()?.join("scope.yml");

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| AppError::Config(format!("Failed to serialize config: {}", e)))?;

    std::fs::write(&config_path, yaml)?;
    info!("Scope configuration saved to {:?}", config_path);

    Ok(())
}

// =============================================================================
// Cloud Scope Validation
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudScopeValidation {
    pub ok: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Validate a (account_id, regions, services) tuple against the saved scope
/// before launching a cloud assessment. Confirms the account exists, the
/// requested regions are within the configured regions for that account, and
/// the requested services are within the configured services_in_scope.
///
/// Returns ok=true with no warnings/errors when everything matches; ok=false
/// for hard errors (account not found); warnings for soft mismatches (extra
/// regions/services) so the wizard can prompt before launching.
#[tauri::command]
pub async fn validate_cloud_scope(
    account_id: String,
    regions: Vec<String>,
    services: Vec<String>,
) -> Result<CloudScopeValidation> {
    info!(
        "Validating cloud scope: account={} regions={:?} services={:?}",
        account_id, regions, services
    );

    let scope = get_scope_config().await?;

    let account = match scope.cloud_accounts.iter().find(|a| a.id == account_id) {
        Some(a) => a,
        None => {
            return Ok(CloudScopeValidation {
                ok: false,
                warnings: vec![],
                errors: vec![format!(
                    "Cloud account '{}' is not configured in scope.yml",
                    account_id
                )],
            });
        }
    };

    let mut warnings = Vec::new();

    if !account.regions.is_empty() {
        for region in &regions {
            if !account.regions.contains(region) {
                warnings.push(format!(
                    "Region '{}' is not in configured regions for account '{}' ({})",
                    region,
                    account_id,
                    account.regions.join(", ")
                ));
            }
        }
    }

    if !account.services_in_scope.is_empty() {
        for service in &services {
            if !account.services_in_scope.contains(service) {
                warnings.push(format!(
                    "Service '{}' is not in services_in_scope for account '{}' ({})",
                    service,
                    account_id,
                    account.services_in_scope.join(", ")
                ));
            }
        }
    }

    Ok(CloudScopeValidation {
        ok: true,
        warnings,
        errors: vec![],
    })
}

// =============================================================================
// Credentials Configuration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialsConfig {
    #[serde(default)]
    pub applications: std::collections::HashMap<String, ApplicationCredentials>,
    #[serde(default)]
    pub test_accounts: std::collections::HashMap<String, TestAccount>,
    #[serde(default)]
    pub identity_credentials: std::collections::HashMap<String, IdentityCredential>,
}

/// A `credentials.yml` `identity_credentials` map VALUE — the secret
/// material an identity target references by `credential_ref` / `sa_key_ref`.
/// Mirrors the serde style of the other credential structs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCredential {
    /// sa_json | okta_token | entra_sp | domain_creds | ping_oauth | oauth_token
    pub kind: String,
    /// File path for SA JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Inline token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationCredentials {
    pub name: Option<String>,
    pub environment: Option<String>,
    pub base_url: Option<String>,
    pub auth_type: String,
    /// Intended privilege level of this credential's identity
    /// (admin | privileged | standard | readonly). Lets the assessment tell
    /// expected-for-role behavior apart from a real access-control flaw.
    /// Unset ⇒ unknown ⇒ no severity downgrade (fail-safe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    // Basic auth
    pub username: Option<String>,
    pub password: Option<String>,
    // Bearer / API key
    pub token: Option<String>,
    pub header_name: Option<String>,
    // Session
    pub login_url: Option<String>,
    pub login_payload: Option<std::collections::HashMap<String, String>>,
    pub token_field: Option<String>,
    // OAuth2
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub token_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    // OTP
    pub initiate_url: Option<String>,
    pub verify_url: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAccount {
    pub username: String,
    pub password: Option<String>,
    pub role: Option<String>,
}

#[tauri::command]
pub async fn get_credentials_config() -> Result<CredentialsConfig> {
    info!("Getting credentials configuration");

    let config_path = get_config_dir()?.join("credentials.yml");

    if !config_path.exists() {
        return Ok(CredentialsConfig {
            applications: std::collections::HashMap::new(),
            test_accounts: std::collections::HashMap::new(),
            identity_credentials: Default::default(),
        });
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: CredentialsConfig = serde_yaml::from_str(&content)
        .map_err(|e| AppError::Config(format!("Invalid credentials config: {}", e)))?;

    Ok(config)
}

#[tauri::command]
pub async fn save_credentials_config(config: CredentialsConfig) -> Result<()> {
    info!("Saving credentials configuration");

    let config_path = get_config_dir()?.join("credentials.yml");

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| AppError::Config(format!("Failed to serialize config: {}", e)))?;

    std::fs::write(&config_path, yaml)?;
    info!("Credentials configuration saved to {:?}", config_path);

    Ok(())
}

// =============================================================================
// Identity Target Validation
// =============================================================================

/// Structurally validate an identity target's configuration before it is
/// persisted. This is HONEST config validation — it confirms the required
/// fields for the chosen `kind` are present and well-formed; it does NOT
/// perform a live probe against the IDP (that runs at assessment time).
/// Always returns (never hangs / shells out), so the wizard's Add button
/// can gate on `ok` synchronously.
#[tauri::command]
pub async fn validate_identity_target(
    target: IdentityTargetScope,
) -> Result<crate::commands::cloud_validation::ValidationResult> {
    use crate::commands::cloud_validation::ValidationResult;

    info!(
        "Validating identity target: kind={} auth_method={}",
        target.kind, target.auth_method
    );

    let has = |o: &Option<String>| o.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    let auth_none = target.auth_method == "none";

    let result = match target.kind.as_str() {
        "google_workspace" => {
            let mut missing: Vec<&str> = Vec::new();
            if !has(&target.tenant_id) {
                missing.push("tenant_id (Workspace customer ID / primary domain)");
            }
            let has_sa_key = has(&target.sa_key_ref);
            if !has_sa_key && !auth_none {
                missing.push("sa_key_ref (or set auth_method=none)");
            }
            // delegated_subject is required (and must look like an email)
            // only when a service-account key is configured.
            if has_sa_key {
                match target.delegated_subject.as_deref() {
                    Some(s) if s.contains('@') => {}
                    Some(_) => missing.push("delegated_subject (must be an admin email)"),
                    None => missing.push("delegated_subject (delegated admin email)"),
                }
            }
            if missing.is_empty() {
                let tenant = target.tenant_id.as_deref().unwrap_or("<unknown>");
                let delegated = target.delegated_subject.as_deref().unwrap_or("none");
                ValidationResult {
                    ok: true,
                    identity: format!(
                        "google_workspace:{} (delegated {})",
                        tenant, delegated
                    ),
                    details:
                        "Configuration validated. A live Admin SDK probe runs at assessment time."
                            .to_string(),
                    error: String::new(),
                    needs_reauth: false,
                }
            } else {
                identity_err(format!("Missing or invalid: {}", missing.join(", ")))
            }
        }
        "okta" | "ping" => {
            let mut missing: Vec<&str> = Vec::new();
            if !has(&target.tenant_id) && !has(&target.base_url) {
                missing.push("tenant_id or base_url (org / environment URL)");
            }
            if !has(&target.credential_ref) && !auth_none {
                missing.push("credential_ref (or set auth_method=none)");
            }
            if missing.is_empty() {
                let who = target
                    .base_url
                    .as_deref()
                    .or(target.tenant_id.as_deref())
                    .unwrap_or("<unknown>");
                ValidationResult {
                    ok: true,
                    identity: format!("{}:{}", target.kind, who),
                    details:
                        "Configuration validated. A live API probe runs at assessment time."
                            .to_string(),
                    error: String::new(),
                    needs_reauth: false,
                }
            } else {
                identity_err(format!("Missing or invalid: {}", missing.join(", ")))
            }
        }
        "entra_id" | "m365" => {
            if has(&target.tenant_id) {
                ValidationResult {
                    ok: true,
                    identity: format!(
                        "{}:{}",
                        target.kind,
                        target.tenant_id.as_deref().unwrap_or("<unknown>")
                    ),
                    details:
                        "Configuration validated. A live Graph probe runs at assessment time."
                            .to_string(),
                    error: String::new(),
                    needs_reauth: false,
                }
            } else {
                identity_err("Missing or invalid: tenant_id".to_string())
            }
        }
        "active_directory" => {
            if has(&target.domain) || has(&target.tenant_id) {
                let who = target
                    .domain
                    .as_deref()
                    .or(target.tenant_id.as_deref())
                    .unwrap_or("<unknown>");
                ValidationResult {
                    ok: true,
                    identity: format!("active_directory:{}", who),
                    details:
                        "Configuration validated. A live domain probe runs at assessment time."
                            .to_string(),
                    error: String::new(),
                    needs_reauth: false,
                }
            } else {
                identity_err("Missing or invalid: domain or tenant_id".to_string())
            }
        }
        other => identity_err(format!(
            "Unknown identity kind '{}'. Expected one of: active_directory, entra_id, m365, okta, google_workspace, ping",
            other
        )),
    };

    Ok(result)
}

// =============================================================================
// AI Target Validation
// =============================================================================

/// Structurally validate an AI/LLM target before it is persisted. HONEST config
/// validation — confirms the required fields for the chosen `kind` are present and
/// well-formed; it does NOT live-probe the endpoint (that runs at assessment time).
/// Always returns (never hangs / shells out), so the AI Targets wizard's Add button
/// can gate on `ok` synchronously. Mirrors `validate_identity_target`.
#[tauri::command]
pub async fn validate_ai_target(
    target: AiTargetScope,
) -> Result<crate::commands::cloud_validation::ValidationResult> {
    use crate::commands::cloud_validation::ValidationResult;

    info!(
        "Validating AI target: kind={} auth_method={}",
        target.kind, target.auth_method
    );

    let has = |o: &Option<String>| o.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(false);
    let auth_none = target.auth_method == "none";

    let valid_kind = matches!(
        target.kind.as_str(),
        "model_api" | "chat_app" | "agent" | "rag_app" | "mcp_server"
    );
    if !valid_kind {
        return Ok(identity_err(format!(
            "Unknown AI kind '{}'. Expected one of: model_api, chat_app, agent, rag_app, mcp_server",
            target.kind
        )));
    }

    let mut missing: Vec<&str> = Vec::new();

    // Every AI target needs an endpoint (or base_url) to test against.
    let endpoint = if has(&target.endpoint) {
        target.endpoint.as_deref()
    } else if has(&target.base_url) {
        target.base_url.as_deref()
    } else {
        missing.push("endpoint (the AI system's HTTP URL — must also be in scope domains/networks)");
        None
    };

    // The endpoint must look like an HTTP(S) URL (the scope validator normalizes it
    // to a hostname and requires it to be in domains/networks — we sanity-check the
    // shape here so a bare hostname doesn't slip through).
    if let Some(ep) = endpoint {
        if !(ep.starts_with("http://") || ep.starts_with("https://")) {
            missing.push("endpoint must be a full http(s):// URL");
        }
    }

    // A credential is required unless auth_method is explicitly none.
    if !has(&target.credential_ref) && !auth_none {
        missing.push("credential_ref (or set auth_method=none)");
    }

    // The endpoint's request body shape must be DECLARED — we assume no default.
    match target.request_template.as_deref() {
        Some(t) if t.contains("{{PROMPT}}") => {}
        Some(_) => missing.push("request_template must contain a {{PROMPT}} placeholder"),
        None => missing.push(
            "request_template (the endpoint's JSON request body, with {{PROMPT}} where the user message goes — no default shape is assumed)",
        ),
    }

    // An agent target with no declared tools can't have its excessive-agency blast
    // radius scoped — require at least one.
    if target.kind == "agent" && target.declared_tools.is_empty() {
        missing.push("declared_tools (the exposed tool set — needed for excessive-agency testing)");
    }

    let result = if missing.is_empty() {
        let ep = endpoint.unwrap_or("<unknown>");
        let model = target.model.as_deref().unwrap_or("unstated");
        ValidationResult {
            ok: true,
            identity: format!("{}:{} (model {})", target.kind, ep, model),
            details:
                "Configuration validated. The endpoint must resolve into an in-scope domains/networks entry; a live probe runs at assessment time."
                    .to_string(),
            error: String::new(),
            needs_reauth: false,
        }
    } else {
        identity_err(format!("Missing or invalid: {}", missing.join(", ")))
    };

    Ok(result)
}

/// Construct a failed `ValidationResult` for identity validation. The
/// `ValidationResult` constructors in cloud_validation are private, so we
/// build the struct directly here.
fn identity_err(error: String) -> crate::commands::cloud_validation::ValidationResult {
    crate::commands::cloud_validation::ValidationResult {
        ok: false,
        identity: String::new(),
        details: String::new(),
        error,
        needs_reauth: false,
    }
}

/// Persist a Google Workspace service-account JSON key to the identity
/// credential store and return the CONTAINER path the mcp-server reads.
/// The host `~/.kali-mcp-pentest` is bind-mounted at
/// `/mnt/host-home/.kali-mcp-pentest` inside the Kali container (docker.rs),
/// so the returned path is valid for tools running in the container.
#[tauri::command]
pub async fn save_identity_sa_key(cred_ref: String, key_json: String) -> Result<String> {
    // Sanitize the ref to a safe filename to avoid path traversal — only
    // [A-Za-z0-9_-] survives.
    let safe_ref: String = cred_ref
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if safe_ref.is_empty() {
        return Err(AppError::Config(
            "Credential ref must contain at least one of [A-Za-z0-9_-]".to_string(),
        ));
    }

    // Validate the JSON parses and looks like a GCP service-account key.
    let parsed: serde_json::Value = serde_json::from_str(&key_json).map_err(|_| {
        AppError::Config(
            "Service Account JSON is not valid JSON. Make sure you pasted the entire file."
                .to_string(),
        )
    })?;
    let is_sa = parsed.get("type").and_then(|v| v.as_str()) == Some("service_account");
    if !is_sa {
        return Err(AppError::Config(
            "JSON does not look like a GCP service-account key (`type` is not \"service_account\")."
                .to_string(),
        ));
    }
    if parsed
        .get("client_email")
        .and_then(|v| v.as_str())
        .map(|s| s.is_empty())
        .unwrap_or(true)
    {
        return Err(AppError::Config(
            "Service Account JSON is missing a `client_email` field.".to_string(),
        ));
    }

    let identity_dir = get_config_dir()?.join("identity");
    std::fs::create_dir_all(&identity_dir)
        .map_err(|e| AppError::Config(format!("Could not create identity dir: {e}")))?;
    let key_path = identity_dir.join(format!("{}.json", safe_ref));
    std::fs::write(&key_path, &key_json)
        .map_err(|e| AppError::Config(format!("Could not write SA key: {e}")))?;

    // Lock the secret down to the owner on Unix. No-op on Windows.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    info!("Saved identity SA key for ref '{}' to {:?}", safe_ref, key_path);

    Ok(format!(
        "/mnt/host-home/.kali-mcp-pentest/identity/{}.json",
        safe_ref
    ))
}

// =============================================================================
// Tools Configuration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    pub nmap: NmapConfig,
    pub nuclei: NucleiConfig,
    pub sqlmap: SqlmapConfig,
    pub ffuf: FfufConfig,
    pub metasploit: MetasploitConfig,
    pub semgrep: Option<SemgrepConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapConfig {
    pub default_ports: String,
    pub timing_template: i32,
    pub max_rate: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiConfig {
    pub templates: Vec<String>,
    pub severity: String,
    pub rate_limit: i32,
    pub bulk_size: i32,
    pub concurrency: i32,
    pub custom_templates_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlmapConfig {
    pub level: i32,
    pub risk: i32,
    pub threads: i32,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfufConfig {
    pub wordlist: String,
    pub rate: i32,
    pub timeout: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitConfig {
    pub check_mode: bool,
    pub threads: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepConfig {
    pub rulesets: Vec<String>,
    pub severity: String,
    pub timeout: i32,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            nmap: NmapConfig {
                default_ports: "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443".to_string(),
                timing_template: 4,
                max_rate: 1000,
            },
            nuclei: NucleiConfig {
                templates: vec!["cve".to_string(), "owasp-top-10".to_string(), "vulnerabilities".to_string()],
                severity: "medium,high,critical".to_string(),
                rate_limit: 150,
                bulk_size: 25,
                concurrency: 25,
                custom_templates_path: None,
            },
            sqlmap: SqlmapConfig {
                level: 2,
                risk: 1,
                threads: 5,
                technique: "BEUSTQ".to_string(),
            },
            ffuf: FfufConfig {
                wordlist: "/usr/share/wordlists/dirb/common.txt".to_string(),
                rate: 100,
                timeout: 10,
            },
            metasploit: MetasploitConfig {
                check_mode: true,
                threads: 5,
            },
            semgrep: Some(SemgrepConfig {
                rulesets: vec!["p/security-audit".to_string(), "p/owasp-top-ten".to_string()],
                severity: "warning".to_string(),
                timeout: 300,
            }),
        }
    }
}

#[tauri::command]
pub async fn get_tools_config() -> Result<ToolsConfig> {
    info!("Getting tools configuration");

    let config_path = get_config_dir()?.join("tools.yml");

    if !config_path.exists() {
        return Ok(ToolsConfig::default());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: ToolsConfig = serde_yaml::from_str(&content)
        .map_err(|e| AppError::Config(format!("Invalid tools config: {}", e)))?;

    Ok(config)
}

#[tauri::command]
pub async fn save_tools_config(config: ToolsConfig) -> Result<()> {
    info!("Saving tools configuration");

    let config_path = get_config_dir()?.join("tools.yml");

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| AppError::Config(format!("Failed to serialize config: {}", e)))?;

    std::fs::write(&config_path, yaml)?;
    info!("Tools configuration saved to {:?}", config_path);

    Ok(())
}

// =============================================================================
// Agents Configuration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub enabled: bool,
    pub timeout_minutes: Option<i32>,
    pub auto_start: Option<bool>,
    pub requires_approval: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentsConfig {
    pub recon: AgentConfig,
    pub vuln_scan: AgentConfig,
    pub web_app: AgentConfig,
    pub exploit: AgentConfig,
    pub security_scan: AgentConfig,
    pub report: AgentConfig,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            recon: AgentConfig {
                enabled: true,
                timeout_minutes: Some(30),
                auto_start: Some(false),
                requires_approval: Some(false),
            },
            vuln_scan: AgentConfig {
                enabled: true,
                timeout_minutes: Some(60),
                auto_start: Some(false),
                requires_approval: Some(false),
            },
            web_app: AgentConfig {
                enabled: true,
                timeout_minutes: Some(60),
                auto_start: Some(false),
                requires_approval: Some(false),
            },
            exploit: AgentConfig {
                enabled: true,
                timeout_minutes: Some(30),
                auto_start: Some(false),
                requires_approval: Some(true),
            },
            security_scan: AgentConfig {
                enabled: true,
                timeout_minutes: Some(45),
                auto_start: Some(false),
                requires_approval: Some(false),
            },
            report: AgentConfig {
                enabled: true,
                timeout_minutes: Some(15),
                auto_start: Some(false),
                requires_approval: Some(false),
            },
        }
    }
}

#[tauri::command]
pub async fn get_agents_config() -> Result<AgentsConfig> {
    info!("Getting agents configuration");

    let config_path = get_config_dir()?.join("agents.yml");

    if !config_path.exists() {
        return Ok(AgentsConfig::default());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: AgentsConfig = serde_yaml::from_str(&content)
        .map_err(|e| AppError::Config(format!("Invalid agents config: {}", e)))?;

    Ok(config)
}

#[tauri::command]
pub async fn save_agents_config(config: AgentsConfig) -> Result<()> {
    info!("Saving agents configuration");

    let config_path = get_config_dir()?.join("agents.yml");

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| AppError::Config(format!("Failed to serialize config: {}", e)))?;

    std::fs::write(&config_path, yaml)?;
    info!("Agents configuration saved to {:?}", config_path);

    Ok(())
}

// =============================================================================
// Integrations Configuration
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitHubIntegration {
    #[serde(default)]
    pub enabled: bool,
    pub personal_access_token: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JiraIntegration {
    #[serde(default)]
    pub enabled: bool,
    pub url: Option<String>,
    pub email: Option<String>,
    pub api_token: Option<String>,
    pub project_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub github: Option<GitHubIntegration>,
    #[serde(default)]
    pub jira: Option<JiraIntegration>,
}

#[tauri::command]
pub async fn get_integrations_config() -> Result<IntegrationsConfig> {
    info!("Getting integrations configuration");

    let config_path = get_config_dir()?.join("integrations.yml");

    if !config_path.exists() {
        return Ok(IntegrationsConfig::default());
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: IntegrationsConfig = serde_yaml::from_str(&content)
        .map_err(|e| AppError::Config(format!("Invalid integrations config: {}", e)))?;

    Ok(config)
}

#[tauri::command]
pub async fn save_integrations_config(config: IntegrationsConfig) -> Result<IntegrationsConfig> {
    info!("Saving integrations configuration");

    let config_path = get_config_dir()?.join("integrations.yml");
    let content = serde_yaml::to_string(&config)
        .map_err(|e| AppError::Config(format!("Failed to serialize config: {}", e)))?;

    std::fs::write(&config_path, content)?;

    Ok(config)
}
