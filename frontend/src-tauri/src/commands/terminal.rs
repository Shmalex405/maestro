use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use tracing::info;

use crate::database::{AssessmentChatMessage, Database};
use crate::error::Result;

use crate::commands::system::resolve_docker_binary as docker_binary;

// =============================================================================
// TMUX HELPERS
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmuxSessionInfo {
    pub name: String,
    pub last_activity: String,
    pub is_attached: bool,
}

/// Resolve tmux binary: bundled sidecar → system PATH → common locations → None
fn find_tmux() -> Option<String> {
    // 1. Try bundled sidecar (relative to executable)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sidecar = dir.join("tmux");
            if sidecar.exists() {
                return Some(sidecar.to_string_lossy().to_string());
            }
            // macOS .app bundle: ../Resources/binaries/tmux
            let macos_sidecar = dir.join("../Resources/binaries/tmux");
            if macos_sidecar.exists() {
                if let Ok(canonical) = macos_sidecar.canonicalize() {
                    return Some(canonical.to_string_lossy().to_string());
                }
            }
        }
    }
    // 2. System PATH
    if let Ok(path) = which::which("tmux") {
        return Some(path.to_string_lossy().to_string());
    }
    // 3. Common locations
    for path in &["/opt/homebrew/bin/tmux", "/usr/local/bin/tmux", "/usr/bin/tmux"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

#[tauri::command]
pub async fn check_tmux_installed() -> Result<bool> {
    Ok(find_tmux().is_some())
}

#[tauri::command]
pub async fn get_tmux_path() -> Result<Option<String>> {
    Ok(find_tmux())
}

#[tauri::command]
pub async fn check_tmux_session(session_name: String) -> Result<bool> {
    let tmux = match find_tmux() {
        Some(t) => t,
        None => return Ok(false),
    };

    let output = tokio::process::Command::new(&tmux)
        .args(["has-session", "-t", &session_name])
        .output()
        .await
        .map_err(|e| crate::error::AppError::Other(format!("Failed to run tmux: {}", e)))?;

    Ok(output.status.success())
}

#[tauri::command]
pub async fn list_tmux_sessions() -> Result<Vec<TmuxSessionInfo>> {
    let tmux = match find_tmux() {
        Some(t) => t,
        None => return Ok(vec![]),
    };

    let output = tokio::process::Command::new(&tmux)
        .args([
            "list-sessions",
            "-F",
            "#{session_name}:#{session_activity}:#{?session_attached,1,0}",
        ])
        .output()
        .await
        .map_err(|e| crate::error::AppError::Other(format!("Failed to run tmux: {}", e)))?;

    if !output.status.success() {
        // No sessions running is not an error
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sessions: Vec<TmuxSessionInfo> = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 3 && parts[0].starts_with("assess-") {
                Some(TmuxSessionInfo {
                    name: parts[0].to_string(),
                    last_activity: parts[1].to_string(),
                    is_attached: parts[2] == "1",
                })
            } else {
                None
            }
        })
        .collect();

    Ok(sessions)
}

#[tauri::command]
pub async fn capture_tmux_pane(session_name: String) -> Result<String> {
    let tmux = match find_tmux() {
        Some(t) => t,
        None => {
            return Err(crate::error::AppError::Other(
                "tmux not found".to_string(),
            ))
        }
    };

    let output = tokio::process::Command::new(&tmux)
        .args(["capture-pane", "-t", &session_name, "-p", "-S", "-", "-e"])
        .output()
        .await
        .map_err(|e| crate::error::AppError::Other(format!("Failed to capture tmux pane: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::AppError::Other(format!(
            "tmux capture-pane failed: {}",
            stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tauri::command]
pub async fn kill_tmux_session(session_name: String) -> Result<()> {
    let tmux = match find_tmux() {
        Some(t) => t,
        None => {
            return Err(crate::error::AppError::Other(
                "tmux not found".to_string(),
            ))
        }
    };

    let output = tokio::process::Command::new(&tmux)
        .args(["kill-session", "-t", &session_name])
        .output()
        .await
        .map_err(|e| crate::error::AppError::Other(format!("Failed to kill tmux session: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        info!("tmux kill-session warning: {}", stderr);
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSession {
    pub id: String,
    pub assessment_id: Option<String>,
    pub status: String,
    pub command: String,
    pub created_at: String,
    pub ended_at: Option<String>,
    pub exit_code: Option<i32>,
    pub transcript: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnTerminalParams {
    pub assessment_id: Option<String>,
    pub assessment_type: Option<String>,
    pub targets: Option<Vec<String>>,
    pub initial_prompt: Option<String>,
    pub cols: Option<u16>,
    pub rows: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnTerminalResult {
    pub session_id: String,
    pub claude_available: bool,
    pub working_dir: String,
    /// Same project root, but rewritten to the writable container path
    /// (`/mnt/host-home/...`). Used by the Terminal pane to `cd` before
    /// launching claude so the project's `.claude/agents/` and
    /// `.claude/commands/` get picked up by claude's discovery walk.
    pub working_dir_container: String,
    pub cli_command: String,
}

/// Resolve the path to the bundled maestro CLI (cli/dist/cli.js in the project root).
/// Returns the path as a string if found.
fn find_bundled_maestro() -> Option<String> {
    // Try CARGO_MANIFEST_DIR first (dev builds)
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let bundled = PathBuf::from(&manifest_dir)
            .parent() // frontend/src-tauri -> frontend
            .and_then(|p| p.parent()) // frontend -> project root
            .map(|p| p.join("cli/dist/cli.js"));
        if let Some(path) = bundled {
            if path.exists() {
                return Some(path.to_string_lossy().to_string());
            }
        }
    }

    // Fallback: look relative to project root from get_project_root()
    let root = get_project_root();
    let bundled = PathBuf::from(&root).join("cli/dist/cli.js");
    if bundled.exists() {
        return Some(bundled.to_string_lossy().to_string());
    }

    None
}

/// Common host locations to search when `which::which` comes up empty.
/// Tauri's macOS GUI PATH doesn't include `/opt/homebrew/bin` or the user's
/// `~/.local/bin` — apps launched from Finder/launchd inherit a stripped
/// down PATH (`/usr/bin:/bin:/usr/sbin:/sbin`). We probe the common dev
/// locations directly so `npm link` / Homebrew / asdf installs are still
/// findable.
fn common_cli_paths(name: &str) -> Vec<String> {
    let mut paths = vec![
        format!("/usr/local/bin/{}", name),
        format!("/opt/homebrew/bin/{}", name),
    ];
    if let Some(home) = dirs::home_dir() {
        paths.push(format!("{}/.local/bin/{}", home.display(), name));
    }
    paths
}

/// Check if maestro is available (bundled, on PATH, or in a common location).
/// Returns (available, command_or_path).
fn find_maestro() -> (bool, String) {
    if which::which("maestro").is_ok() {
        return (true, "maestro".to_string());
    }
    for p in common_cli_paths("maestro") {
        if std::path::Path::new(&p).exists() {
            return (true, p);
        }
    }
    if let Some(path) = find_bundled_maestro() {
        return (true, format!("node {}", path));
    }
    (false, "maestro".to_string())
}

/// Check which CLI is available: prefers `claude`, falls back to `maestro`.
/// The terminal pane spawns into the Kali container where claude is always
/// installed at /usr/local/bin/claude (see docker/Dockerfile.kali), so claude
/// is effectively always available so long as the container is running. We
/// still probe the host as a courtesy for users running outside the container
/// flow. Returns (available, command_name).
fn check_cli_available() -> (bool, String) {
    if which::which("claude").is_ok() {
        return (true, "claude".to_string());
    }
    for p in common_cli_paths("claude") {
        if std::path::Path::new(&p).exists() {
            return (true, p);
        }
    }
    // Container path — assume claude is always there per Dockerfile.kali. The
    // Terminal pane gates separately on container_running before spawn, and
    // the new Connect-Claude CTA handles missing-auth.
    (true, "claude".to_string())
}

/// Translate a host path to its writable container path. The Kali container
/// bind-mounts `$HOME → /mnt/host-home` (rw) so anything under the user's
/// home becomes reachable inside the container at the prefixed path. Paths
/// outside `$HOME` (rare on macOS for projects) are returned unchanged so
/// the caller still has *something* to `cd` to — it just won't be writable.
fn host_path_to_container(host: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy().to_string();
        if !home_str.is_empty() && host.starts_with(&home_str) {
            return format!("/mnt/host-home{}", &host[home_str.len()..]);
        }
    }
    host.to_string()
}

/// Get the project root directory (where `.mcp.json` lives).
///
/// Resolution order:
///   1. `MAESTRO_PROJECT_ROOT` env var (overrides everything — useful for CI
///      or a one-shot bash launch)
///   2. `~/.kali-mcp-pentest/project-root` config file (single-line path the
///      user can set explicitly without the GUI)
///   3. Common dev install locations under $HOME
///   4. `current_dir()` + walk-up to find `.mcp.json` (legacy path)
///
/// Why this matters: for a packaged macOS app launched from /Applications,
/// `current_dir()` typically returns `/`. The legacy walk-up never finds a
/// `.mcp.json` parent and we'd fall back to $HOME — Claude ends up `cd`'d
/// into the home dir mount with no `.claude/commands` or `.claude/agents`
/// to discover, so `/assess` and friends silently don't exist in the slash
/// command picker.
pub(crate) fn get_project_root() -> String {
    fn has_marker(p: &std::path::Path) -> bool {
        p.join(".mcp.json").exists()
    }

    // 1. Env var override
    if let Ok(v) = std::env::var("MAESTRO_PROJECT_ROOT") {
        if !v.is_empty() && has_marker(std::path::Path::new(&v)) {
            return v;
        }
    }

    if let Some(home) = dirs::home_dir() {
        // 2. Config file: ~/.kali-mcp-pentest/project-root
        //    Single line containing the absolute path. Trim whitespace so
        //    `echo "/path" > ...` works without surprises.
        let cfg = home.join(".kali-mcp-pentest").join("project-root");
        if let Ok(s) = std::fs::read_to_string(&cfg) {
            let path = s.trim();
            if !path.is_empty() && has_marker(std::path::Path::new(path)) {
                return path.to_string();
            }
        }

        // 3. Common dev locations relative to $HOME. First match wins.
        for rel in &[
            "Desktop/kali-mcp-pentest",
            "kali-mcp-pentest",
            "Projects/kali-mcp-pentest",
            "code/kali-mcp-pentest",
            "work/kali-mcp-pentest",
            "src/kali-mcp-pentest",
        ] {
            let path = home.join(rel);
            if has_marker(&path) {
                return path.to_string_lossy().to_string();
            }
        }
    }

    // 4. Legacy fallback — walk up from current_dir() looking for
    //    `.mcp.json`. Works in dev mode (cargo tauri dev) where
    //    current_dir is the project root; useless for packaged apps
    //    where current_dir is "/".
    let project_dir = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()));

            if let Some(dir) = exe_dir {
                let mut current = dir.as_path();
                while let Some(parent) = current.parent() {
                    if has_marker(parent) {
                        return parent.to_string_lossy().to_string();
                    }
                    current = parent;
                }
            }

            dirs::home_dir()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().to_string())
        });

    let current = std::path::Path::new(&project_dir);
    let mut search = current;
    while let Some(parent) = search.parent() {
        if has_marker(parent) {
            return parent.to_string_lossy().to_string();
        }
        search = parent;
    }

    project_dir
}

#[tauri::command]
pub async fn spawn_terminal_session(
    params: SpawnTerminalParams,
) -> Result<SpawnTerminalResult> {
    let (cli_available, cli_command) = check_cli_available();
    let working_dir = get_project_root();
    let working_dir_container = host_path_to_container(&working_dir);
    let session_id = Uuid::new_v4().to_string();

    info!("Spawning terminal session: {} (cli: {}, available: {})", session_id, cli_command, cli_available);

    // Record session in database
    let db = Database::new()?;
    let _ = db.create_terminal_session(
        &session_id,
        params.assessment_id.as_deref(),
        &cli_command,
    );

    Ok(SpawnTerminalResult {
        session_id,
        claude_available: cli_available,
        working_dir,
        working_dir_container,
        cli_command,
    })
}

#[tauri::command]
pub async fn list_terminal_sessions() -> Result<Vec<TerminalSession>> {
    let db = Database::new()?;
    db.list_terminal_sessions()
}

#[tauri::command]
pub async fn get_terminal_session(id: String) -> Result<Option<TerminalSession>> {
    let db = Database::new()?;
    db.get_terminal_session(&id)
}

#[tauri::command]
pub async fn end_terminal_session(
    id: String,
    exit_code: Option<i32>,
) -> Result<()> {
    info!("Ending terminal session: {} (exit_code: {:?})", id, exit_code);

    let db = Database::new()?;
    db.end_terminal_session(&id, exit_code)
}

#[tauri::command]
pub async fn link_session_to_assessment(
    session_id: String,
    assessment_id: String,
) -> Result<()> {
    info!("Linking session {} to assessment {}", session_id, assessment_id);

    let db = Database::new()?;
    db.link_terminal_session_to_assessment(&session_id, &assessment_id)
}

#[tauri::command]
pub async fn check_claude_installed() -> Result<bool> {
    let (available, _) = check_cli_available();
    Ok(available)
}

/// Mirror of `check_claude_installed` for the Codex CLI. Like claude, codex
/// is baked into the Kali container by Dockerfile.kali, so as long as the
/// container is running it's effectively always available. Probes the host
/// PATH first as a courtesy for users running outside the container flow.
#[tauri::command]
pub async fn check_codex_installed() -> Result<bool> {
    if which::which("codex").is_ok() {
        return Ok(true);
    }
    for p in common_cli_paths("codex") {
        if std::path::Path::new(&p).exists() {
            return Ok(true);
        }
    }
    // Container path — codex is baked into Dockerfile.kali alongside claude.
    Ok(true)
}

/// Lightweight telemetry: log when the user picks a brain (Claude or Codex)
/// in the assessment terminal view. Emits a structured `tracing::info!`
/// line that whatever log shipper the desktop runs through (Datadog,
/// CloudWatch via the cloud-sync worker, or local stdout) can aggregate
/// into a usage-split chart.
///
/// Only fires on actual tab change (deduped client-side), so the log
/// volume is bounded — at most a handful of events per assessment.
#[tauri::command]
pub async fn record_brain_selected(brain: String, assessment_id: Option<String>) -> Result<()> {
    let assessment = assessment_id.as_deref().unwrap_or("__none__");
    info!(
        target: "brain_selected",
        brain = %brain,
        assessment_id = %assessment,
        "user switched brain in assessment terminal view"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableClis {
    pub maestro: bool,
    pub claude: bool,
    pub codex: bool,
    pub maestro_command: String,
}

#[tauri::command]
pub async fn check_available_clis() -> Result<AvailableClis> {
    let (maestro_ok, maestro_cmd) = find_maestro();
    let claude_ok = which::which("claude").is_ok();
    let codex_ok = which::which("codex").is_ok();
    info!(
        "Available CLIs - maestro: {} ({}), claude: {}, codex: {}",
        maestro_ok, maestro_cmd, claude_ok, codex_ok,
    );
    Ok(AvailableClis {
        maestro: maestro_ok,
        claude: claude_ok,
        codex: codex_ok,
        maestro_command: maestro_cmd,
    })
}

/// Returns `true` when a Claude OAuth credential blob is structurally usable —
/// i.e. it parses and carries a non-empty access token *and* refresh token.
///
/// Deliberately does **not** treat an expired access token as unusable. The
/// `claude` CLI silently mints a fresh access token from the (long-lived)
/// refresh token on its next API call, so an expired `expiresAt` is normal and
/// self-healing — gating on it would pop the re-login CTA every few hours for a
/// perfectly healthy login (and could interrupt a live run on reattach). The
/// one thing the file *can't* tell us is whether the refresh token itself is
/// dead; that only surfaces as a runtime 401, which the terminal watches for
/// and converts into the same CTA (see `terminal-view.tsx`). So this gate
/// catches the cheap structural failures (missing/empty/corrupt creds) and
/// leaves true staleness to the runtime detector.
fn claude_credentials_usable(json: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return false;
    };
    let oauth = &value["claudeAiOauth"];
    let non_empty = |k: &str| oauth[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    non_empty("accessToken") && non_empty("refreshToken")
}

/// Checks whether Claude Code is authenticated *inside* the kali-pentest
/// container. Auth lives in `/root/.claude/.credentials.json` which is
/// bind-mounted from `~/.kali-mcp-pentest/claude-home/` — different from
/// the host's `~/.claude` (host uses macOS keychain, container needs its
/// own login).
///
/// Returns `false` if the container isn't running, the credentials file is
/// missing, or the credential is structurally unusable (unparseable / missing
/// tokens). The Terminal pane uses this to gate between "show login CTA" and
/// "spawn `exec claude` directly". See `claude_credentials_usable` for why an
/// expired access token is *not* treated as unauthed.
#[tauri::command]
pub async fn check_claude_auth_in_container() -> Result<bool> {
    // Timeout the docker exec at 4s. Without it, a container that's
    // still booting (e.g. just-recreated by the drift detector) makes
    // the exec hang forever and the UI gets stuck on "Checking Claude
    // authentication…". 4s is enough for a healthy container's exec
    // to round-trip; anything longer means the container isn't ready,
    // and the UI flips to the "not authed" CTA so the user can decide
    // (sign in, start container, etc.) instead of staring at a spinner.
    //
    // We `cat` the credential (rather than `test -f`) so we can parse it and
    // reject a present-but-broken creds file that would otherwise pass an
    // existence check and then 401 mid-session.
    let fut = tokio::process::Command::new(docker_binary())
        .args(["exec", "kali-pentest", "cat", "/root/.claude/.credentials.json"])
        .output();
    let output = tokio::time::timeout(std::time::Duration::from_secs(4), fut).await;

    match output {
        Ok(Ok(o)) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            Ok(claude_credentials_usable(&body))
        }
        Ok(Ok(_)) => Ok(false), // file missing (cat exits non-zero)
        Ok(Err(_)) => Ok(false), // container not running, docker missing
        Err(_) => Ok(false),     // exec timed out (container still booting)
    }
}

/// Mirror of `check_claude_auth_in_container` for the Codex CLI. Auth lives
/// in `/root/.codex/auth.json`, written by `codex login` (browser OAuth) or
/// `codex login --device-auth` (the headless flow we use inside the
/// container, since there's no browser to spawn). The path is bind-mounted
/// from `~/.kali-mcp-pentest/codex-home/` so the credential persists across
/// container rebuilds.
#[tauri::command]
pub async fn check_codex_auth_in_container() -> Result<bool> {
    // Same timeout rationale as check_claude_auth_in_container — don't
    // let a booting container hang the UI on a spinner.
    let fut = tokio::process::Command::new(docker_binary())
        .args(["exec", "kali-pentest", "test", "-f", "/root/.codex/auth.json"])
        .output();
    let output = tokio::time::timeout(std::time::Duration::from_secs(4), fut).await;

    match output {
        Ok(Ok(o)) => Ok(o.status.success()),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

/// Find the most recent Codex session file in the container that was
/// created/modified after `after_unix`. Returns the bare UUID portion of
/// the filename (e.g. `~/.codex/sessions/abc123.jsonl` → `"abc123"`),
/// or None if no qualifying file exists yet.
///
/// Used by `codex-terminal-view.tsx` to capture the session ID Codex
/// allocated for an assessment's first spawn — Codex doesn't have a
/// `--session-id` pin like Claude, so we have to discover the UUID it
/// chose by watching the on-disk session store. The frontend polls this
/// every few seconds after spawn until a file appears, then persists the
/// UUID to `assessment.options.codex_session_id` for future resume.
///
/// `after_unix` filters out pre-existing session files from earlier
/// assessments so we only ever capture the file this assessment created.
#[tauri::command]
pub async fn capture_codex_session_id(after_unix: i64) -> Result<Option<String>> {
    // Sort by mtime DESC, take first that's newer than the cutoff. Strip
    // the `.jsonl` extension to get the bare UUID Codex's `resume`
    // subcommand expects as a positional arg.
    let script = format!(
        r#"
        cd /root/.codex/sessions 2>/dev/null || exit 0
        # Newest .jsonl with mtime > after_unix. POSIX-safe via stat.
        for f in $(ls -t *.jsonl 2>/dev/null); do
            mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)
            if [ "$mtime" -gt {} ]; then
                echo "${{f%.jsonl}}"
                exit 0
            fi
        done
        "#,
        after_unix
    );
    let output = tokio::process::Command::new(docker_binary())
        .args(["exec", "kali-pentest", "sh", "-c", &script])
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        _ => Ok(None),
    }
}

/// Container path to the in-image MCP server (baked by Dockerfile.kali).
/// The container is amd64-only; pointing claude/codex at the host's
/// `mcp-server/node_modules/` would fail on Apple Silicon hosts because
/// the native modules (better-sqlite3 etc.) are arm64 ELF and won't load
/// in an amd64 process. The baked copy has the right-arch native modules.
const CONTAINER_MCP_SERVER_DIR: &str = "/opt/pentest/mcp-server";
/// Container paths the in-container MCP server uses for the rest of the
/// project tree. The codex/claude configs we write below point at these.
const CONTAINER_PROJECT_DIR: &str = "/mnt/host-home/Desktop/kali-mcp-pentest";

/// Ensures the Claude CLI inside the container has an MCP config registering
/// the kali-pentest MCP server using the container's amd64 `mcp-server/`
/// install (`/opt/pentest/mcp-server/`), NOT the host's. The host copy
/// fails inside the container when running cross-arch (Apple Silicon ↔
/// amd64 container) because native node modules don't match the runtime.
///
/// Writes to `~/.kali-mcp-pentest/claude-home/maestro-mcp.json`, which is
/// bind-mounted at `/root/.claude/maestro-mcp.json` inside the container.
/// `terminal-view.tsx` passes `--mcp-config <that path> --strict-mcp-config`
/// to claude so the project's `.mcp.json` (which points at host paths for
/// host-run claude) is ignored when running in-container.
///
/// Idempotent — safe to call before every Claude session spawn.
#[tauri::command]
pub async fn ensure_claude_mcp_config() -> Result<()> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        crate::error::AppError::Config("Home directory not resolvable".into())
    })?;
    let claude_home = home_dir.join(".kali-mcp-pentest").join("claude-home");
    std::fs::create_dir_all(&claude_home)?;

    let body = serde_json::json!({
        "_comment": "Generated by Maestro — do not edit by hand. Used only when claude runs inside the kali-pentest container; the project's .mcp.json points at host paths for host-run claude.",
        "mcpServers": {
            "kali-pentest": {
                "command": "node",
                "args": [format!("{}/dist/index.js", CONTAINER_MCP_SERVER_DIR)],
                "cwd": CONTAINER_MCP_SERVER_DIR,
                "env": {
                    "DOCKER_CONTAINER": "kali-pentest",
                    "CONFIG_PATH": format!("{}/config", CONTAINER_PROJECT_DIR),
                    "SCOPE_CONFIG_PATH": format!("{}/config/scope.yml", CONTAINER_PROJECT_DIR),
                    "LOG_PATH": format!("{}/logs", CONTAINER_PROJECT_DIR),
                    "DATA_PATH": format!("{}/data", CONTAINER_PROJECT_DIR),
                },
            }
        }
    });

    let path = claude_home.join("maestro-mcp.json");
    std::fs::write(&path, serde_json::to_string_pretty(&body).unwrap())?;
    info!("Wrote Claude MCP config to {}", path.display());
    Ok(())
}

/// Ensures the Codex CLI inside the container has an MCP config registering
/// the kali-pentest MCP server. Codex reads `~/.codex/config.toml` (mapped to
/// `/root/.codex/config.toml` in the container, bind-mounted from the host's
/// `~/.kali-mcp-pentest/codex-home/`); we write directly to the host-side
/// path so it materializes inside the container without needing a
/// `docker exec` call.
///
/// Like `ensure_claude_mcp_config`, this points at the container's amd64
/// install (`/opt/pentest/mcp-server/`) — never the host's — so cross-arch
/// hosts (Apple Silicon ↔ amd64 container) work.
///
/// Idempotent — safe to call before every Codex session spawn.
#[tauri::command]
pub async fn ensure_codex_mcp_config(project_root: String) -> Result<()> {
    let home_dir = dirs::home_dir().ok_or_else(|| {
        crate::error::AppError::Config("Home directory not resolvable".into())
    })?;
    let codex_home = home_dir.join(".kali-mcp-pentest").join("codex-home");
    std::fs::create_dir_all(&codex_home)?;

    // `project_root` is the host project dir — used for log/data/config
    // paths only (those still live under the bind-mounted host home), NOT
    // for the mcp-server binary itself.
    let trimmed_root = project_root.trim_end_matches('/');
    let toml_body = format!(
        "# Generated by Maestro — do not edit by hand. Maestro rewrites this file\n\
         # before every Codex session start so the kali-pentest MCP server is\n\
         # registered for the Codex CLI inside the Kali container.\n\
         \n\
         [mcp_servers.kali-pentest]\n\
         command = \"node\"\n\
         args = [\"{srv}/dist/index.js\"]\n\
         cwd = \"{srv}\"\n\
         startup_timeout_sec = 30\n\
         tool_timeout_sec = 600\n\
         \n\
         [mcp_servers.kali-pentest.env]\n\
         DOCKER_CONTAINER = \"kali-pentest\"\n\
         CONFIG_PATH = \"{root}/config\"\n\
         SCOPE_CONFIG_PATH = \"{root}/config/scope.yml\"\n\
         LOG_PATH = \"{root}/logs\"\n\
         DATA_PATH = \"{root}/data\"\n",
        srv = CONTAINER_MCP_SERVER_DIR,
        root = trimmed_root,
    );

    let path = codex_home.join("config.toml");
    std::fs::write(&path, toml_body)?;
    info!("Wrote Codex MCP config to {}", path.display());
    Ok(())
}

/// Checks whether the assessment's tmux session is alive *inside* the
/// kali-pentest container. The session may have been spawned by either
/// brain — Claude uses `assess-<id>`, Codex uses `codex-assess-<id>`.
/// Returns true if EITHER prefix is live. Used by the assessment header
/// to render a live-session badge so users know whether reopening the
/// pane will reattach to a running CLI or start fresh.
///
/// Note: distinct from `check_tmux_session` above, which probes the host's
/// tmux. The host has no tmux for our use case — the session lives only
/// inside the container.
#[tauri::command]
pub async fn check_assessment_session_live(assessment_id: String) -> Result<bool> {
    if assessment_id.is_empty() {
        return Ok(false);
    }
    for prefix in &["assess-", "codex-assess-"] {
        let session_name = format!("{}{}", prefix, assessment_id);
        let output = tokio::process::Command::new(docker_binary())
            .args(["exec", "kali-pentest", "tmux", "has-session", "-t", &session_name])
            .output()
            .await;
        if let Ok(o) = output {
            if o.status.success() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Returns true iff Claude's conversation file for `session_id` still exists
/// inside the container. Claude Code keeps each session at
/// `/root/.claude/projects/<cwd-hash>/<session-id>.jsonl`, which lives on the
/// bind-mounted `/root/.claude`, so it normally survives a container restart.
/// It is gone, though, when claude-home is reset, or when the stored id never
/// got a file (e.g. `--session-id` was dropped during the auth phase). In
/// those cases `claude --resume <id>` silently starts an empty session — so
/// the UI calls this first and offers a clearly-labeled fresh start instead of
/// dropping the user into a blank prompt that looks like lost work.
#[tauri::command]
pub async fn check_claude_session_resumable(session_id: String) -> Result<bool> {
    // Claude session ids are UUIDs; only let through chars safe to splice into
    // the in-container shell glob (defense-in-depth — the value is app-sourced).
    if session_id.is_empty()
        || !session_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Ok(false);
    }
    // `ls` over the glob: sh expands it; no match → ls exits non-zero → false.
    let script = format!(
        "ls /root/.claude/projects/*/{}.jsonl >/dev/null 2>&1",
        session_id
    );
    let output = tokio::process::Command::new(docker_binary())
        .args(["exec", "kali-pentest", "sh", "-c", &script])
        .output()
        .await;
    Ok(matches!(output, Ok(o) if o.status.success()))
}

/// Kills the assessment's tmux session(s) *inside* the kali-pentest
/// container for BOTH brains (`assess-<id>` and `codex-assess-<id>`).
/// Best-effort: a missing session is a no-op, and any docker/tmux error is
/// swallowed so deletion never blocks on a flaky container. Called when an
/// assessment is deleted so the running CLI stops immediately instead of
/// lingering as an orphaned process that keeps the live badge lit.
#[tauri::command]
pub async fn kill_assessment_sessions(assessment_id: String) -> Result<()> {
    if assessment_id.is_empty() {
        return Ok(());
    }
    for prefix in &["assess-", "codex-assess-"] {
        let session_name = format!("{}{}", prefix, assessment_id);
        let _ = tokio::process::Command::new(docker_binary())
            .args(["exec", "kali-pentest", "tmux", "kill-session", "-t", &session_name])
            .output()
            .await;
    }
    Ok(())
}

/// Returns the assessment IDs whose tmux sessions are currently alive in
/// the container. Cheaper than calling `check_assessment_session_live` per
/// row when rendering an assessment list — one `docker exec tmux ls` call
/// covers any number of assessments. Strips both `assess-` (Claude) and
/// `codex-assess-` (Codex) prefixes; an assessment with sessions in both
/// brains appears once.
#[tauri::command]
pub async fn list_live_assessment_sessions() -> Result<Vec<String>> {
    let output = tokio::process::Command::new(docker_binary())
        .args(["exec", "kali-pentest", "tmux", "ls", "-F", "#{session_name}"])
        .output()
        .await;

    let stdout = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return Ok(Vec::new()),
    };

    let mut seen = std::collections::HashSet::<String>::new();
    let mut ids = Vec::<String>::new();
    for line in stdout.lines() {
        let name = line.trim();
        // Order matters: check `codex-assess-` first because `assess-` is
        // a prefix of it.
        let id = name
            .strip_prefix("codex-assess-")
            .or_else(|| name.strip_prefix("assess-"));
        if let Some(id) = id {
            if id.is_empty() {
                continue;
            }
            if seen.insert(id.to_string()) {
                ids.push(id.to_string());
            }
        }
    }
    Ok(ids)
}

#[tauri::command]
pub async fn get_terminal_working_dir() -> Result<String> {
    Ok(get_project_root())
}

#[tauri::command]
pub async fn save_terminal_transcript(
    session_id: String,
    transcript: String,
) -> Result<()> {
    info!("Saving transcript for session: {} ({} chars)", session_id, transcript.len());

    let db = Database::new()?;
    db.save_terminal_transcript(&session_id, &transcript)
}

#[tauri::command]
pub async fn get_terminal_sessions_for_assessment(
    assessment_id: String,
) -> Result<Vec<TerminalSession>> {
    let db = Database::new()?;
    db.get_terminal_sessions_for_assessment(&assessment_id)
}

#[tauri::command]
pub async fn save_assessment_chat_messages(
    assessment_id: String,
    messages: Vec<AssessmentChatMessage>,
) -> Result<()> {
    let db = Database::new()?;
    db.save_assessment_chat_messages(&assessment_id, &messages)
}

#[tauri::command]
pub async fn load_assessment_chat_messages(
    assessment_id: String,
) -> Result<Vec<AssessmentChatMessage>> {
    let db = Database::new()?;
    db.load_assessment_chat_messages(&assessment_id)
}

#[cfg(test)]
mod tests {
    use super::claude_credentials_usable;

    #[test]
    fn healthy_credential_is_usable() {
        // Note the past `expiresAt` — an expired access token is still usable
        // because the CLI refreshes from `refreshToken`.
        let json = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-abc","refreshToken":"sk-ant-ort01-def","expiresAt":1}}"#;
        assert!(claude_credentials_usable(json));
    }

    #[test]
    fn missing_refresh_token_is_not_usable() {
        let json = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-abc","expiresAt":9999999999999}}"#;
        assert!(!claude_credentials_usable(json));
    }

    #[test]
    fn empty_tokens_are_not_usable() {
        let json = r#"{"claudeAiOauth":{"accessToken":"","refreshToken":""}}"#;
        assert!(!claude_credentials_usable(json));
    }

    #[test]
    fn corrupt_or_empty_blob_is_not_usable() {
        assert!(!claude_credentials_usable(""));
        assert!(!claude_credentials_usable("not json"));
        assert!(!claude_credentials_usable("{}"));
    }
}
