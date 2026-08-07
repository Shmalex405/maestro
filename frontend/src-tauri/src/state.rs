use crate::cloud::SyncStatus;
use crate::docker::DockerManager;
use crate::error::{AppError, Result};
use crate::mcp::McpClient;
use chrono::{DateTime, Utc};
use directories::ProjectDirs;
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

/// Represents a running agent task
pub struct RunningAgent {
    pub id: Uuid,
    pub agent_type: String,
    pub started_at: DateTime<Utc>,
    pub status: AgentStatus,
}

#[derive(Clone, Debug)]
pub enum AgentStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Chat message in history
#[derive(Clone, Debug)]
pub struct ChatMessage {
    pub id: Uuid,
    pub role: String, // "user" | "assistant"
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Clone, Debug)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
    pub result: Option<serde_json::Value>,
}

/// Application state managed by Tauri
pub struct AppState {
    pub docker: Option<DockerManager>,
    pub mcp: Option<McpClient>,
    pub running_agents: HashMap<Uuid, RunningAgent>,
    pub chat_history: Vec<ChatMessage>,
    pub sync_status: SyncStatus,
    config_dir: Option<PathBuf>,
    /// Backend-brokered GHCR pull credential (short-lived GitHub App
    /// installation token), cached so the Rust container lifecycle pulls the
    /// private toolkit image authenticated. Set by `set_toolkit_credentials`
    /// after the frontend fetches it from the broker.
    pub registry_credentials: Option<crate::docker::BrokeredRegistryCredentials>,
}

impl AppState {
    pub fn new() -> Self {
        // Get config directory
        let config_dir = ProjectDirs::from("com", "pentest-platform", "PentestPlatform")
            .map(|dirs| dirs.config_dir().to_path_buf());

        // Ensure config dir exists
        if let Some(ref dir) = config_dir {
            let _ = std::fs::create_dir_all(dir);
        }

        Self {
            docker: None,
            mcp: None,
            running_agents: HashMap::new(),
            chat_history: Vec::new(),
            sync_status: SyncStatus::default(),
            config_dir,
            registry_credentials: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Initialize Docker manager. MCP client is lazily initialized when
        // the container comes up. There is no longer an LLM client here —
        // the `claude` CLI inside the container drives all model calls.
        self.docker = Some(DockerManager::new().await?);
        Ok(())
    }

    pub fn is_docker_available(&self) -> bool {
        self.docker.is_some()
    }

    pub fn is_container_running(&self) -> bool {
        // This will be checked dynamically
        false
    }

    /// Get the configuration directory
    pub fn get_config_dir(&self) -> Result<PathBuf> {
        self.config_dir
            .clone()
            .ok_or_else(|| AppError::Config("Config directory not available".into()))
    }

    /// Get sync status
    pub fn get_sync_status(&self) -> SyncStatus {
        self.sync_status.clone()
    }

    /// Update sync status
    pub fn update_sync_status(&mut self, sync_at: DateTime<Utc>, error: Option<String>) {
        self.sync_status.last_sync_at = Some(sync_at);
        self.sync_status.last_error = error;
        self.sync_status.sync_in_progress = false;
        self.sync_status.pending_changes = 0;
    }

    /// Set sync in progress
    pub fn set_sync_in_progress(&mut self, in_progress: bool) {
        self.sync_status.sync_in_progress = in_progress;
    }

    /// Increment pending changes
    pub fn increment_pending_changes(&mut self) {
        self.sync_status.pending_changes += 1;
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
