use crate::commands::credentials::{self, CredentialMode};
use crate::database::Database;
use crate::docker::{kali_image, CreateImageInfo, DockerManager};
use crate::error::{AppError, Result};
use crate::mcp::McpClient;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerStatusInfo {
    pub available: bool,
    pub kali_running: bool,
    /// Deep health: the container is running AND on the expected image.
    /// No longer "running == healthy" — a container on a stale toolkit
    /// image reports running=true but kali_healthy=false (update pending).
    pub kali_healthy: bool,
    /// The toolkit image this app build pins (KALI_IMAGE / `kali_image()`).
    pub image_expected: String,
    /// The image the running container was actually created from.
    pub image_actual: Option<String>,
    /// Whether the running container matches the pinned image (no drift).
    pub image_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub healthy: bool,
    pub docker: DockerStatusInfo,
    pub database_connected: bool,
    pub mcp_server_connected: bool,
    /// Number of tools the MCP server actually advertises. Proof it's
    /// functional, not merely answering `/health` — `None` when the MCP
    /// server is unreachable or couldn't enumerate its tools.
    pub mcp_tool_count: Option<u32>,
    /// Active Claude credential mode: "oauth" or "api_key".
    /// Replaces the legacy `llm_provider` field after Ollama removal.
    pub claude_auth_mode: String,
    pub claude_authenticated: bool,
    pub uptime_seconds: u64,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestModeFlags {
    /// When true, the frontend startup gate skips discovery + auth + Docker
    /// + MCP checks and renders the main app immediately. Driven by the
    /// `MAESTRO_TEST_BYPASS_AUTH` env var at process start. Used by the
    /// desktop end-to-end suite (tests-e2e-desktop/) so tests don't have
    /// to drive a real Cognito sign-in or have a working Docker daemon
    /// available inside the test runner.
    ///
    /// Production builds set this env var to nothing and the gate runs
    /// normally — there's no in-app way to enable test mode.
    pub bypass_auth: bool,
}

/// The toolkit image tag this app build pins (`KALI_IMAGE` / [`kali_image`]).
///
/// `get_system_status` already reports this as `docker.image_expected`, but that
/// call also probes the MCP server and the database. Startup error paths need
/// just the tag — e.g. telling a self-hoster which image they still have to
/// build — and shouldn't depend on the rest of the stack being up to say so.
#[tauri::command(rename_all = "snake_case")]
pub async fn get_configured_kali_image() -> Result<String> {
    Ok(kali_image().to_string())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_test_mode_flags() -> Result<TestModeFlags> {
    Ok(TestModeFlags {
        bypass_auth: std::env::var("MAESTRO_TEST_BYPASS_AUTH").as_deref() == Ok("1"),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressStats {
    /// Whether Tier 3 outbound egress filtering is enabled (read from
    /// MAESTRO_TIER3_EGRESS at process start). The flag drives both the
    /// container's iptables rules and this stats payload — when false,
    /// blocked_packets is always 0 because there are no rules to block.
    pub enabled: bool,
    /// Total packets matched by the LOG-and-drop rule since container
    /// start. Cumulative; the UI displays a delta over a window if it
    /// wants. Zero when Tier 3 is off or no out-of-scope traffic
    /// originated yet.
    pub blocked_packets: u64,
    /// Total OUTPUT-chain rules currently loaded. Useful for the UI to
    /// show "egress allowlist: N rules" — gives the user confidence the
    /// allowlist actually loaded vs silently no-op'd.
    pub rule_count: usize,
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_egress_stats(state: State<'_, Arc<RwLock<AppState>>>) -> Result<EgressStats> {
    let enabled = std::env::var("MAESTRO_TIER3_EGRESS").as_deref() == Ok("1");
    if !enabled {
        return Ok(EgressStats { enabled: false, blocked_packets: 0, rule_count: 0 });
    }
    let app_state = state.read().await;
    let docker_opt = app_state.docker.as_ref();
    let result = match docker_opt {
        Some(d) => d.get_egress_stats().await,
        None => return Ok(EgressStats { enabled: true, blocked_packets: 0, rule_count: 0 }),
    };
    match result {
        Ok((blocked_packets, rule_count)) => Ok(EgressStats {
            enabled: true,
            blocked_packets,
            rule_count,
        }),
        Err(_) => Ok(EgressStats { enabled: true, blocked_packets: 0, rule_count: 0 }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerStatus {
    // Renamed from `running` to match the frontend TS interface and to be
    // consistent with `DockerStatusInfo.kali_running` returned by
    // get_system_status. Both shapes now use `kali_running`.
    pub kali_running: bool,
    pub container_id: Option<String>,
    pub image: Option<String>,
    pub status: String,
    pub ports: Vec<PortInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeValidationResult {
    pub valid: bool,
    pub reason: Option<String>,
}

#[tauri::command]
pub async fn get_system_status(
    _state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<SystemStatus> {
    info!("Getting system status");

    // Try to connect to Docker and check container status — BOUNDED (A1). A
    // slow/hung docker daemon must not block this poll: it runs every few
    // seconds, and an unbounded call here starved the runtime serving the UI and
    // froze the app mid-assessment. Time out and report docker-unavailable.
    let (docker_available, container_status) = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            let dm = DockerManager::new().await.ok();
            let cs = match dm {
                Some(ref d) => d.get_container_status().await.ok(),
                None => None,
            };
            (dm.is_some(), cs)
        },
    )
    .await
    {
        Ok(v) => v,
        Err(_) => {
            info!("get_system_status: docker probe timed out (daemon slow) — reporting docker unavailable");
            (false, None)
        }
    };

    let kali_running = container_status
        .as_ref()
        .map(|s| s.running)
        .unwrap_or(false);

    // Image-drift check — the headline of the deep panel. "Running" is NOT
    // "healthy": a container left on a stale toolkit tag (the bug that hid a
    // 2-week-old image behind a green check) must report image_current=false.
    let image_expected = kali_image().to_string();
    let image_actual = container_status.as_ref().and_then(|s| s.image.clone());
    let image_current =
        kali_running && image_actual.as_deref() == Some(image_expected.as_str());
    let kali_healthy = kali_running && image_current;

    // MCP server — deep check. Not just `/health` 200: actually enumerate the
    // tools, so "green" means the server can serve tool calls. tool_count is
    // the proof.
    let (mcp_available, mcp_tool_count) = if kali_running {
        match McpClient::new() {
            Ok(client) => {
                if client.health_check().await.unwrap_or(false) {
                    match client.list_tools().await {
                        Ok(tools) => (true, Some(tools.len() as u32)),
                        // Answers /health but can't list tools → degraded, not "up".
                        Err(_) => (false, None),
                    }
                } else {
                    (false, None)
                }
            }
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    // Database — deep check. Open the connection AND run a real query that
    // confirms the schema exists, not just that the file opened.
    let database_connected = Database::new()
        .map(|db| db.health_check())
        .unwrap_or(false);

    // Resolve Claude credential mode + whether the active mode actually
    // has the credential it needs. We don't ping Anthropic from here —
    // that's a per-launch concern. This is just "is the auth set up at all?"
    let auth_state = credentials::get_claude_auth_state().await.ok();
    let (claude_auth_mode, claude_authenticated) = match auth_state {
        Some(s) => {
            let mode_str = match s.mode {
                CredentialMode::Oauth => "oauth",
                CredentialMode::ApiKey => "api_key",
            }
            .to_string();
            let ok = match s.mode {
                CredentialMode::Oauth => s.oauth_authenticated,
                CredentialMode::ApiKey => s.api_key_present,
            };
            (mode_str, ok)
        }
        None => ("oauth".to_string(), false),
    };

    // Overall health: container up, on the CURRENT image, with a queryable
    // DB. A stale toolkit image drops this to false (degraded) even though
    // the container is running. Auth is reported but not gated on — first-run
    // users haven't signed in yet and we still want the rest of the app usable.
    let healthy = database_connected && kali_running && image_current;

    Ok(SystemStatus {
        healthy,
        docker: DockerStatusInfo {
            available: docker_available,
            kali_running,
            kali_healthy,
            image_expected,
            image_actual,
            image_current,
        },
        database_connected,
        mcp_server_connected: mcp_available,
        mcp_tool_count,
        claude_auth_mode,
        claude_authenticated,
        uptime_seconds: 0, // Simplified for now
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[tauri::command]
pub async fn get_docker_status() -> Result<DockerStatus> {
    info!("Getting Docker status");

    // Bounded (A1): a slow/hung daemon must not block this poll forever.
    let status = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let docker = DockerManager::new().await?;
        docker.get_container_status().await
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => {
            return Err(AppError::Config(
                "docker status timed out — daemon slow or unresponsive".into(),
            ))
        }
    };

    Ok(DockerStatus {
        kali_running: status.running,
        container_id: status.container_id,
        image: status.image,
        status: status.status,
        ports: status
            .ports
            .into_iter()
            .map(|p| PortInfo {
                host_port: p.host_port,
                container_port: p.container_port,
                protocol: p.protocol,
            })
            .collect(),
    })
}

/// Cache the backend-brokered GHCR credential (a short-lived GitHub App
/// installation token) so the Rust container lifecycle can pull the private
/// toolkit image authenticated. The frontend calls this immediately after
/// fetching credentials from `/api/v1/toolkit/registry-credentials`, BEFORE
/// starting the container — so a Maestro Cloud login is all the user needs.
#[tauri::command]
pub async fn set_toolkit_credentials(
    state: State<'_, Arc<RwLock<AppState>>>,
    username: String,
    password: String,
    expires_at: Option<i64>,
) -> Result<()> {
    let mut app_state = state.write().await;
    app_state.registry_credentials = Some(crate::docker::BrokeredRegistryCredentials {
        username,
        password,
        expires_at,
    });
    info!(
        "Cached brokered toolkit credentials (expires_at={:?})",
        expires_at
    );
    Ok(())
}

#[tauri::command]
pub async fn start_kali_container(
    state: State<'_, Arc<RwLock<AppState>>>,
    app_handle: AppHandle,
) -> Result<DockerStatus> {
    info!("Starting Kali container");

    // Hand the brokered GHCR credential to the manager so create/recreate
    // pulls authenticate to the private toolkit registry.
    let creds = state.read().await.registry_credentials.clone();
    let docker = DockerManager::new_with_credentials(creds).await?;
    let status = docker.start_container().await?;

    // Start the MCP server process inside the container
    if status.running {
        match prepare_mcp_server_workspace(&app_handle) {
            Ok(mcp_path) => {
                info!("Starting MCP server from container path: {}", mcp_path);
                if let Err(e) = docker.start_mcp_server(&mcp_path).await {
                    warn!("Failed to start MCP server (will retry via health check): {}", e);
                }
            }
            Err(e) => warn!("Could not prepare MCP server workspace: {}", e),
        }
    }

    Ok(DockerStatus {
        kali_running: status.running,
        container_id: status.container_id,
        image: status.image,
        status: status.status,
        ports: status
            .ports
            .into_iter()
            .map(|p| PortInfo {
                host_port: p.host_port,
                container_port: p.container_port,
                protocol: p.protocol,
            })
            .collect(),
    })
}

/// Sync the bundled MCP server (shipped as Tauri resources) to a writable
/// host path the Kali container can mount. Returns the container path the
/// caller should pass to `docker.start_mcp_server()`.
///
/// Why this exists: pre-v0.1.13 we resolved the MCP server location via
/// `env!("CARGO_MANIFEST_DIR")`, which is baked at compile time. On CI
/// runners that's `/home/runner/work/...` — and customer machines don't
/// have that path, so `strip_prefix(home_dir)` returned None and the
/// MCP server never started in any production install. The fix bundles
/// `mcp-server/dist` + `package.json` + `package-lock.json` as Tauri
/// resources, copies them to `~/.kali-mcp-pentest/mcp-server/` on first
/// launch (and on every launch — cheap freshness check), and uses that
/// runtime-resolved path. The container reads via the existing
/// `${HOME}:/mnt/host-home` bind mount.
fn prepare_mcp_server_workspace(app_handle: &AppHandle) -> Result<String> {
    use tauri::Manager;

    let resource_dir = app_handle
        .path()
        .resource_dir()
        .map_err(|e| AppError::Config(format!("resource_dir failed: {e}")))?;

    // Tauri 2 preserves the relative-path structure of `resources` from
    // tauri.conf.json — paths with `..` get encoded as `_up_/`. Our
    // config bundles `../../mcp-server/...` (two levels up from
    // frontend/src-tauri/), so the actual on-disk path is
    // `<resource_dir>/_up_/_up_/mcp-server/`. Fall back to the legacy
    // top-level layout in case Tauri's encoding changes.
    let candidate_roots = [
        resource_dir.join("_up_").join("_up_").join("mcp-server"),
        resource_dir.join("mcp-server"),
    ];
    let bundled_root = candidate_roots
        .iter()
        .find(|p| p.join("dist").is_dir())
        .ok_or_else(|| {
            AppError::Config(format!(
                "Bundled MCP server dist/ not found under {} (tried _up_/_up_/mcp-server and mcp-server) — Tauri resources may not have been bundled. Reinstall the app.",
                resource_dir.display(),
            ))
        })?;

    let bundled_dist = bundled_root.join("dist");
    let bundled_pkg = bundled_root.join("package.json");
    let bundled_lock = bundled_root.join("package-lock.json");

    let home_dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Home directory not resolvable".into()))?;
    let host_dest = home_dir.join(".kali-mcp-pentest").join("mcp-server");
    let host_dest_dist = host_dest.join("dist");
    std::fs::create_dir_all(&host_dest)
        .map_err(|e| AppError::Config(format!("create host_dest dir: {e}")))?;

    // Stamp file detects whether the bundled MCP server has changed since
    // the last sync — only re-copy when it has, to avoid hammering the disk
    // on every container start.
    let stamp_path = host_dest.join(".version-stamp");
    let current_version = app_version(app_handle);
    let stamp_matches = std::fs::read_to_string(&stamp_path)
        .ok()
        .map(|s| s.trim() == current_version)
        .unwrap_or(false);

    if !stamp_matches {
        if host_dest_dist.exists() {
            std::fs::remove_dir_all(&host_dest_dist).ok();
        }
        copy_dir_recursive(&bundled_dist, &host_dest_dist)
            .map_err(|e| AppError::Config(format!("copy MCP dist: {e}")))?;
        if bundled_pkg.exists() {
            std::fs::copy(&bundled_pkg, host_dest.join("package.json"))
                .map_err(|e| AppError::Config(format!("copy package.json: {e}")))?;
        }
        if bundled_lock.exists() {
            std::fs::copy(&bundled_lock, host_dest.join("package-lock.json"))
                .map_err(|e| AppError::Config(format!("copy package-lock.json: {e}")))?;
        }
        std::fs::write(&stamp_path, &current_version).ok();
        info!("Synced MCP server v{} to {}", current_version, host_dest.display());
    }

    let relative = host_dest.strip_prefix(&home_dir).map_err(|_| {
        AppError::Config("MCP host path is not under home directory".into())
    })?;
    // Forward-slash the relative segment: on Windows `display()` emits
    // backslashes, which are invalid inside the Linux container path.
    Ok(format!(
        "/mnt/host-home/{}",
        relative.to_string_lossy().replace('\\', "/")
    ))
}

/// The shipped app version (from tauri.conf.json `version`), NOT the rarely
/// bumped Cargo crate version (`CARGO_PKG_VERSION` stays e.g. 0.1.102 across
/// releases). Resource-sync version stamps MUST key off this, or a per-release
/// upgrade is skipped and bundled changes (e.g. a new mcp-server dist) never
/// reach the container. Falls back to the crate version if config lacks one.
fn app_version(app_handle: &AppHandle) -> String {
    app_handle
        .config()
        .version
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn stop_kali_container() -> Result<DockerStatus> {
    info!("Stopping Kali container");

    let docker = DockerManager::new().await?;
    let status = docker.stop_container().await?;

    Ok(DockerStatus {
        kali_running: status.running,
        container_id: status.container_id,
        image: status.image,
        status: status.status,
        ports: status
            .ports
            .into_iter()
            .map(|p| PortInfo {
                host_port: p.host_port,
                container_port: p.container_port,
                protocol: p.protocol,
            })
            .collect(),
    })
}

#[tauri::command]
pub async fn get_available_tools() -> Result<Vec<ToolInfo>> {
    info!("Getting available tools");

    let mcp = McpClient::new()?;

    if !mcp.health_check().await.unwrap_or(false) {
        return Err(AppError::ContainerNotRunning);
    }

    let tools = mcp.list_tools().await?;

    Ok(tools
        .into_iter()
        .map(|t| {
            // Categorize tools based on name
            let category = if t.name.contains("scan") || t.name.contains("discover") || t.name.contains("enumerate") {
                "recon"
            } else if t.name.contains("nuclei") || t.name.contains("nikto") || t.name.contains("wpscan") {
                "vuln-scan"
            } else if t.name.contains("sql") || t.name.contains("xss") || t.name.contains("ffuf") {
                "web-app"
            } else if t.name.contains("exploit") || t.name.contains("metasploit") {
                "exploit"
            } else if t.name.contains("semgrep") || t.name.contains("bandit") || t.name.contains("secret") {
                "code-scan"
            } else if t.name.contains("report") || t.name.contains("finding") {
                "reporting"
            } else {
                "other"
            }
            .to_string();

            ToolInfo {
                name: t.name,
                description: t.description,
                category,
            }
        })
        .collect())
}

#[tauri::command]
pub async fn validate_scope(target: String) -> Result<ScopeValidationResult> {
    info!("Validating scope for target: {}", target);

    // Load scope configuration
    let config_path = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Could not determine home directory".to_string()))?
        .join(".kali-mcp-pentest")
        .join("scope.yml");

    if !config_path.exists() {
        return Ok(ScopeValidationResult {
            valid: false,
            reason: Some("Scope configuration not found".to_string()),
        });
    }

    let content = std::fs::read_to_string(&config_path)?;
    let scope: serde_yaml::Value = serde_yaml::from_str(&content)
        .map_err(|e| AppError::Config(format!("Invalid scope config: {}", e)))?;

    // Check if target is in scope
    // This is a simplified check - in production you'd want proper CIDR/domain matching
    let networks = scope["networks"]
        .as_sequence()
        .map(|s| s.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    let domains = scope["domains"]
        .as_sequence()
        .map(|s| s.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    let exclusions = scope["exclusions"]
        .as_sequence()
        .map(|s| s.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    // Check exclusions first
    for exclusion in &exclusions {
        if target.contains(exclusion) {
            return Ok(ScopeValidationResult {
                valid: false,
                reason: Some(format!("Target matches exclusion pattern: {}", exclusion)),
            });
        }
    }

    // Check if target matches any allowed network or domain
    let in_scope = networks.iter().any(|n| target.starts_with(n.split('/').next().unwrap_or("")))
        || domains.iter().any(|d| target.contains(d));

    if in_scope {
        Ok(ScopeValidationResult {
            valid: true,
            reason: None,
        })
    } else {
        Ok(ScopeValidationResult {
            valid: false,
            reason: Some("Target is not in the defined scope".to_string()),
        })
    }
}

// =============================================================================
// Startup Gate Commands
// =============================================================================

#[tauri::command]
pub async fn check_docker_installed() -> Result<bool> {
    info!("Checking if Docker CLI is installed");
    Ok(resolve_docker_binary_opt().is_some())
}

/// Resolve the absolute path to the `docker` binary. macOS GUI apps inherit
/// a minimal PATH that usually omits Homebrew + /usr/local/bin, so spawning
/// PTYs with the bare command "docker" fails — the terminal pane then
/// silently goes blank. Have JS call this command before `tauriPty.spawn`.
#[tauri::command]
pub async fn resolve_docker_path() -> Result<String> {
    resolve_docker_binary_opt()
        .ok_or_else(|| AppError::Config("docker binary not found".to_string()))
}

pub fn resolve_docker_binary() -> String {
    resolve_docker_binary_opt().unwrap_or_else(|| "docker".to_string())
}

pub fn resolve_docker_binary_opt() -> Option<String> {
    // A2 (UI-freeze fix): cache the resolution. The probe below touches the
    // filesystem and — last resort — spawns a BLOCKING `docker --version`. This
    // runs on every system-status poll via DockerManager::new(), so without a
    // cache it re-resolves (and can block a runtime thread on a slow daemon)
    // every few seconds, which starved the runtime serving the UI and froze the
    // app mid-assessment. The docker path doesn't move within a session.
    static DOCKER_BINARY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    DOCKER_BINARY
        .get_or_init(resolve_docker_binary_uncached)
        .clone()
}

fn resolve_docker_binary_uncached() -> Option<String> {
    if let Ok(p) = which::which("docker") {
        return Some(p.to_string_lossy().to_string());
    }
    // Windows: Docker Desktop normally adds itself to the system PATH (so the
    // `which` check above succeeds), but probe the standard install locations
    // as a fallback for environments where the GUI app didn't inherit it.
    #[cfg(windows)]
    for path in &[
        "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
        "C:\\Program Files (x86)\\Docker\\Docker\\resources\\bin\\docker.exe",
    ] {
        if std::path::Path::new(path).exists() {
            info!("Found docker at {} (not in PATH but exists)", path);
            return Some(path.to_string());
        }
    }
    for path in &[
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        "/usr/bin/docker",
        "/Applications/Docker.app/Contents/Resources/bin/docker",
    ] {
        if std::path::Path::new(path).exists() {
            info!("Found docker at {} (not in PATH but exists)", path);
            return Some(path.to_string());
        }
    }
    // Last resort — let the OS resolve it via the shell. Returns "docker"
    // and hopes for the best.
    if let Ok(output) = std::process::Command::new("docker").arg("--version").output() {
        if output.status.success() {
            return Some("docker".to_string());
        }
    }
    None
}

#[tauri::command]
pub async fn open_docker_desktop() -> Result<()> {
    info!("Opening Docker Desktop");

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg("-a")
            .arg("Docker")
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to open Docker Desktop: {}", e)))?;
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["start", "docker"])
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to start Docker: {}", e)))?;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", "Docker Desktop"])
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to open Docker Desktop: {}", e)))?;
    }

    Ok(())
}

/// Result of diagnosing Docker's local state. Returned by
/// `diagnose_docker`; the desktop's startup gate uses it to render
/// targeted error messages + action buttons instead of a generic "didn't
/// start in 60s" timeout.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DockerDiagnosis {
    /// Docker.app is not installed (macOS) — user needs to install first.
    NotInstalled,
    /// Docker.app exists but the GUI process isn't running yet — the
    /// gate should call `open_docker_desktop` and wait.
    NotRunning,
    /// Docker.app process IS running, but the daemon socket isn't
    /// responding to /_ping. Most common cause: the Linux VM that
    /// hosts the daemon is hung. The fix is `restart_docker_desktop`.
    DaemonUnresponsive,
    /// Daemon responded; healthy.
    Healthy,
}

#[tauri::command]
pub async fn diagnose_docker() -> Result<DockerDiagnosis> {
    info!("Diagnosing Docker state");
    // 1. Is Docker.app installed?
    #[cfg(target_os = "macos")]
    let installed = std::path::Path::new("/Applications/Docker.app").exists();
    #[cfg(not(target_os = "macos"))]
    let installed = resolve_docker_binary_opt().is_some();
    if !installed {
        return Ok(DockerDiagnosis::NotInstalled);
    }

    // 2. Is the GUI / engine running? On unix we probe the docker socket
    //    directly with a `/_ping`. On Windows the daemon listens on a
    //    named pipe (\\.\pipe\docker_engine) which Rust std doesn't have
    //    a UnixStream-equivalent for; we fall back to `bollard`'s
    //    cross-platform connect (which is what DockerManager already does
    //    everywhere else in this app). That's slower than a raw socket
    //    poke but the diagnose path runs once per startup so it's fine.
    #[cfg(unix)]
    {
        let socket_path = if cfg!(target_os = "macos") {
            format!(
                "{}/.docker/run/docker.sock",
                std::env::var("HOME").unwrap_or_default()
            )
        } else {
            "/var/run/docker.sock".to_string()
        };
        if !std::path::Path::new(&socket_path).exists() {
            return Ok(DockerDiagnosis::NotRunning);
        }
        let ping_ok = match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                use std::io::{Read, Write};
                use std::os::unix::net::UnixStream;
                let mut stream = UnixStream::connect(&socket_path).ok()?;
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                stream
                    .write_all(b"GET /_ping HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    .ok()?;
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).ok()?;
                let resp = std::str::from_utf8(&buf[..n]).ok()?;
                Some(resp.contains(" 200 "))
            }),
        )
        .await
        {
            Ok(Ok(Some(true))) => true,
            _ => false,
        };
        return Ok(if ping_ok {
            DockerDiagnosis::Healthy
        } else {
            DockerDiagnosis::DaemonUnresponsive
        });
    }

    #[cfg(not(unix))]
    {
        // Windows: rely on the bollard client (named-pipe transport) with
        // a 3-second timeout to call the daemon's version endpoint. Any
        // error → daemon is unresponsive (or not started yet).
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            crate::docker::DockerManager::new(),
        )
        .await;
        match result {
            Ok(Ok(_)) => Ok(DockerDiagnosis::Healthy),
            // Timed out OR the connect itself errored. We can't easily
            // distinguish "named pipe missing" (NotRunning) from "pipe
            // exists but daemon hung" (DaemonUnresponsive) on Windows
            // without a deeper probe; default to NotRunning so the user
            // gets the (Open Docker Desktop) action button which
            // is the right move in either case.
            _ => Ok(DockerDiagnosis::NotRunning),
        }
    }
}

/// Hard restart of Docker Desktop: send a quit AppleEvent, wait for the
/// process to fully exit, then relaunch. Used by the startup gate when
/// `diagnose_docker` returns DaemonUnresponsive — the GUI still claims
/// "Engine running" but the API isn't reachable, which is a known
/// hung-VM state on Docker Desktop for Mac.
#[tauri::command]
pub async fn restart_docker_desktop() -> Result<()> {
    info!("Restarting Docker Desktop");

    #[cfg(target_os = "macos")]
    {
        // Quit via osascript so the app gets a clean shutdown signal.
        let _ = std::process::Command::new("osascript")
            .args(["-e", "quit app \"Docker Desktop\""])
            .output();

        // Poll for full exit (com.docker.backend going away).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let still_running = std::process::Command::new("pgrep")
                .arg("-f")
                .arg("com.docker.backend")
                .output()
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(false);
            if !still_running {
                break;
            }
            if std::time::Instant::now() > deadline {
                // Force-kill if it didn't quit cleanly.
                let _ = std::process::Command::new("pkill")
                    .arg("-f")
                    .arg("com.docker.backend")
                    .output();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }

        // Relaunch.
        std::process::Command::new("open")
            .arg("-a")
            .arg("Docker")
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to relaunch Docker Desktop: {}", e)))?;
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["restart", "docker"])
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to restart Docker: {}", e)))?;
    }

    #[cfg(target_os = "windows")]
    {
        // Best-effort on Windows: kill the GUI process, then re-launch.
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "Docker Desktop.exe"])
            .output();
        std::process::Command::new("cmd")
            .args(["/C", "start", "", "Docker Desktop"])
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to relaunch Docker Desktop: {}", e)))?;
    }

    Ok(())
}

#[tauri::command]
pub async fn check_kali_image_exists() -> Result<bool> {
    info!("Checking if Kali Docker image exists");
    let docker = DockerManager::new().await?;
    docker.image_exists().await
}

/// Structured progress payload emitted to the front-end so the startup
/// gate can render a real percentage bar + transfer rate + stall warning
/// instead of a wall of "Pulling fs layer" lines. Bytes are reported in
/// MB (1e6) so the UI doesn't need to convert. `mbps` is computed from a
/// 5-second sliding window so it doesn't whiplash on burst layers.
#[derive(Debug, Clone, Serialize)]
struct PullProgressPayload {
    /// 0.0 – 100.0. Only meaningful once at least one layer has reported
    /// a `total` byte count; the UI should treat <0 as "warming up".
    pct: f64,
    mb_done: f64,
    mb_total: f64,
    mbps: f64,
    /// How many distinct layers are in the pull (helps users see that
    /// "Downloading" lines aren't all the same thing).
    layers: usize,
    /// Number of layers that have finished extracting. Lets the UI show
    /// "12 of 47 layers complete" alongside the bar.
    layers_done: usize,
    /// Latest status string from docker — surfaced so the UI can keep
    /// showing the existing log-style scroll if the user expands it.
    status: Option<String>,
}

/// Per-layer state snapshot. Total may arrive late (only after the layer
/// manifest is fetched) so we treat 0 as "unknown" and exclude such
/// layers from the denominator until they report.
#[derive(Debug, Default, Clone, Copy)]
struct LayerState {
    current: u64,
    total: u64,
    done: bool,
}

/// Aggregates per-layer `CreateImageInfo` frames into a single overall
/// progress snapshot. Shared between the anonymous and authenticated
/// pull command handlers — keeps both paths emitting identical payloads.
struct PullProgressTracker {
    layers: HashMap<String, LayerState>,
    started_at: Instant,
    last_emit: Option<Instant>,
}

impl PullProgressTracker {
    fn new() -> Self {
        Self {
            layers: HashMap::new(),
            started_at: Instant::now(),
            last_emit: None,
        }
    }

    /// Apply a single docker frame. Returns Some(payload) if the UI
    /// should be re-rendered (we throttle to ~5 Hz to avoid flooding
    /// the event channel on multi-gig pulls with thousands of frames).
    fn observe(&mut self, info: &CreateImageInfo) -> Option<PullProgressPayload> {
        let id = info.id.as_deref()?;
        let status = info.status.as_deref().unwrap_or("");

        // Docker uses status strings to signal lifecycle transitions per
        // layer. "Pull complete" / "Already exists" mean the layer is
        // fully accounted for regardless of whether its progress_detail
        // ever caught up to total — treat both as done.
        let layer = self.layers.entry(id.to_string()).or_default();
        if let Some(detail) = info.progress_detail.as_ref() {
            if let Some(c) = detail.current {
                layer.current = c.max(0) as u64;
            }
            if let Some(t) = detail.total {
                layer.total = t.max(0) as u64;
            }
        }
        if matches!(status, "Pull complete" | "Already exists") {
            layer.done = true;
            if layer.total == 0 {
                layer.total = layer.current;
            }
            layer.current = layer.total;
        }

        // Throttle: emit at most every 200 ms. The first frame always
        // emits so the UI flips from "warming up" to a real bar quickly.
        let now = Instant::now();
        let should_emit = match self.last_emit {
            None => true,
            Some(t) => now.duration_since(t).as_millis() >= 200,
        };
        if !should_emit {
            return None;
        }
        self.last_emit = Some(now);

        // Sum bytes only across layers that have reported a total. Layers
        // with total=0 are still "warming up" — counting them would make
        // the bar bounce backwards as new layers register.
        let mut sum_current: u64 = 0;
        let mut sum_total: u64 = 0;
        let mut layers_done = 0;
        for l in self.layers.values() {
            if l.total > 0 {
                sum_current += l.current.min(l.total);
                sum_total += l.total;
            }
            if l.done {
                layers_done += 1;
            }
        }

        let pct = if sum_total > 0 {
            (sum_current as f64 / sum_total as f64) * 100.0
        } else {
            -1.0 // sentinel for "warming up"
        };

        // Rate: bytes added since the start, divided by elapsed seconds.
        // Smooth enough for a download spanning minutes; we don't bother
        // with a windowed average because per-frame jitter is invisible
        // on a 5 Hz UI update.
        let elapsed = self.started_at.elapsed().as_secs_f64().max(0.001);
        let mbps = (sum_current as f64 / 1_000_000.0) / elapsed;

        Some(PullProgressPayload {
            pct,
            mb_done: sum_current as f64 / 1_000_000.0,
            mb_total: sum_total as f64 / 1_000_000.0,
            mbps,
            layers: self.layers.len(),
            layers_done,
            status: info.status.clone(),
        })
    }
}

/// Build the closure passed to docker.rs that (a) tracks per-layer bytes
/// in a shared `PullProgressTracker` and (b) emits the structured
/// `startup:pull-progress` event whenever the tracker says to. Also
/// keeps the legacy `startup:build-progress` line-stream alive so the
/// existing log scroll in the UI still works.
fn make_pull_progress_callback(
    handle: AppHandle,
) -> impl Fn(&CreateImageInfo) + Send + Sync + 'static {
    let tracker = Arc::new(Mutex::new(PullProgressTracker::new()));
    move |info: &CreateImageInfo| {
        if let Some(status) = info.status.as_deref() {
            let _ = handle.emit("startup:build-progress", status);
        }
        let snapshot = tracker
            .lock()
            .ok()
            .and_then(|mut t| t.observe(info));
        if let Some(payload) = snapshot {
            let _ = handle.emit("startup:pull-progress", payload);
        }
    }
}

#[tauri::command]
pub async fn pull_kali_image(app_handle: AppHandle) -> Result<()> {
    info!("Pulling Kali Docker image from GHCR (anonymous)");
    let docker = DockerManager::new().await?;
    docker
        .pull_image_with_progress(Some(make_pull_progress_callback(app_handle)), None)
        .await
}

/// Pull the Kali image using credentials brokered by the backend. The
/// desktop fetches these from `/api/v1/toolkit/registry-credentials`
/// after a successful Cognito login; the PAT never lives in the client
/// binary. See the matching frontend call in `startup-gate.tsx`.
#[tauri::command]
pub async fn pull_kali_image_with_auth(
    app_handle: AppHandle,
    username: String,
    password: String,
) -> Result<()> {
    info!("Pulling Kali Docker image from GHCR (authenticated)");
    let docker = DockerManager::new().await?;
    docker
        .pull_image_with_auth(
            &username,
            &password,
            Some(make_pull_progress_callback(app_handle)),
        )
        .await
}

// NOTE: the old `build_kali_image` command was removed in 1.0.49. It resolved
// the docker/ build context via env!("CARGO_MANIFEST_DIR"), which bakes the CI
// runner path at compile time and can never exist on a user's machine — so on
// released binaries it only ever produced a misleading "Docker directory not
// found at /Users/runner/work/..." error. The toolkit image is a licensed
// artifact obtained via the cloud-brokered GHCR pull; there is no local-build
// path in production. Resilience now lives in docker.rs `start_container`
// (obtain-before-teardown + degraded fallback).

#[tauri::command]
pub async fn ensure_mcp_server(app_handle: AppHandle) -> Result<bool> {
    info!("Ensuring MCP server is running");

    let docker = DockerManager::new().await?;
    let status = docker.get_container_status().await?;
    if !status.running {
        return Err(AppError::ContainerNotRunning);
    }

    // Check if already healthy
    let mcp = McpClient::new()?;
    if mcp.health_check().await.unwrap_or(false) {
        return Ok(true);
    }

    // Not running — sync bundled resources to writable host path, then start
    let mcp_path = prepare_mcp_server_workspace(&app_handle)?;
    docker.start_mcp_server(&mcp_path).await?;
    Ok(false) // started but not yet healthy — caller should poll
}


// =============================================================================
// Tests
// =============================================================================
//
// Lightweight unit tests for the deterministic pieces of these commands.
// The DB, Docker daemon, and Tauri app handle are real-world dependencies
// we don't mock here — those paths are exercised by the desktop app
// during development and by the integration tests in
// `backend-rs/tests/`. What we DO test:
//   - DockerDiagnosis serializes to the wire shape the frontend parses
//     (frontend/lib/tauri-api.ts → diagnoseDocker)
//   - resolve_docker_binary_opt returns Some when docker exists and None
//     when it doesn't (only meaningful when run on a machine with or
//     without docker installed — the test asserts whichever is true)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_diagnosis_serializes_to_expected_wire_shape() {
        // The frontend matches on `state` as one of these literal
        // strings. If the serde rename or variant names drift, the
        // gate goes back to its old "did not start within 60s"
        // generic-timeout behavior because no panel matches.
        assert_eq!(
            serde_json::to_value(&DockerDiagnosis::NotInstalled).unwrap(),
            serde_json::json!({"state": "not_installed"})
        );
        assert_eq!(
            serde_json::to_value(&DockerDiagnosis::NotRunning).unwrap(),
            serde_json::json!({"state": "not_running"})
        );
        assert_eq!(
            serde_json::to_value(&DockerDiagnosis::DaemonUnresponsive).unwrap(),
            serde_json::json!({"state": "daemon_unresponsive"})
        );
        assert_eq!(
            serde_json::to_value(&DockerDiagnosis::Healthy).unwrap(),
            serde_json::json!({"state": "healthy"})
        );
    }

    #[test]
    fn resolve_docker_binary_returns_a_path_or_fallback() {
        // resolve_docker_binary always returns something — either an
        // absolute path it found, or "docker" as a hopeful default.
        // Test machines without docker won't see Some, so we only
        // assert non-empty.
        let bin = resolve_docker_binary();
        assert!(!bin.is_empty(), "resolve_docker_binary should never return empty");
    }
}
