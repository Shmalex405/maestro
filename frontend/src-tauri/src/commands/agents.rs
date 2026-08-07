use crate::error::{AppError, Result};
use crate::mcp::{McpClient, McpToolCall};
use crate::state::{AgentStatus, AppState, RunningAgent};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAgentParams {
    pub agent_type: String,
    pub targets: Vec<String>,
    pub options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOrchestratorParams {
    pub mode: String, // "full", "selective", "pipelined", "dual-track", "extreme", "sequential"
    pub targets: Vec<String>,
    pub agents: Option<Vec<String>>,
    pub repo_paths: Option<Vec<String>>,
    pub jira_project: Option<String>,
    pub email_recipients: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusResponse {
    pub id: String,
    pub agent_type: String,
    pub status: String,
    pub started_at: String,
    pub message: Option<String>,
    pub progress: Option<f32>,
    pub findings_count: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunAgentResponse {
    pub id: String,
    pub agent_type: String,
    pub status: String,
    pub message: String,
}

#[tauri::command]
pub async fn run_orchestrator(
    state: State<'_, Arc<RwLock<AppState>>>,
    params: RunOrchestratorParams,
) -> Result<RunAgentResponse> {
    info!("Starting orchestrator in {} mode", params.mode);

    // Determine which agents to run
    let agents_to_run: Vec<String> = match params.mode.as_str() {
        "full" => vec![
            "recon".to_string(), "infra-security".to_string(), "vuln-scan".to_string(),
            "web-app".to_string(), "api-security".to_string(), "chain-analysis".to_string(),
            "exploit".to_string(), "chain-analysis".to_string(), "security-scan".to_string(),
            "qa".to_string(), "compliance".to_string(), "report".to_string(),
        ],
        "selective" => params.agents.clone().unwrap_or_default(),
        "pipelined" | "dual-track" | "extreme" | "sequential" => {
            // These modes are handled by the MCP orchestrator directly
            vec![]
        },
        _ => return Err(AppError::Validation(format!(
            "Invalid mode: {}. Use 'full', 'selective', 'pipelined', 'dual-track', 'extreme', or 'sequential'",
            params.mode
        ))),
    };

    // Check if MCP server is available
    let mcp = McpClient::new()?;
    if !mcp.health_check().await.unwrap_or(false) {
        return Err(AppError::ContainerNotRunning);
    }

    // Create orchestrator record
    let orchestrator_id = Uuid::new_v4();
    let now = chrono::Utc::now();

    {
        let mut state_write = state.write().await;
        state_write.running_agents.insert(
            orchestrator_id,
            RunningAgent {
                id: orchestrator_id,
                agent_type: "orchestrator".to_string(),
                started_at: now,
                status: AgentStatus::Running,
            },
        );
    }

    // Call MCP to run orchestrator
    let result = mcp
        .call_tool(McpToolCall {
            name: "run_orchestrator".to_string(),
            arguments: serde_json::json!({
                "mode": params.mode,
                "targets": params.targets,
                "agents": agents_to_run,
                "repo_paths": params.repo_paths,
                "jira_project": params.jira_project,
                "email_recipients": params.email_recipients,
            }),
        })
        .await;

    // Update status based on result
    {
        let mut state_write = state.write().await;
        if let Some(agent) = state_write.running_agents.get_mut(&orchestrator_id) {
            agent.status = match &result {
                Ok(r) if r.success => AgentStatus::Completed,
                Ok(_) => AgentStatus::Failed("Orchestrator failed".to_string()),
                Err(e) => AgentStatus::Failed(e.to_string()),
            };
        }
    }

    match result {
        Ok(tool_result) => Ok(RunAgentResponse {
            id: orchestrator_id.to_string(),
            agent_type: "orchestrator".to_string(),
            status: if tool_result.success { "completed" } else { "failed" }.to_string(),
            message: tool_result.error.unwrap_or_else(|| "Orchestrator completed".to_string()),
        }),
        Err(e) => Ok(RunAgentResponse {
            id: orchestrator_id.to_string(),
            agent_type: "orchestrator".to_string(),
            status: "failed".to_string(),
            message: e.to_string(),
        }),
    }
}

#[tauri::command]
pub async fn run_agent(
    state: State<'_, Arc<RwLock<AppState>>>,
    params: RunAgentParams,
) -> Result<RunAgentResponse> {
    info!("Starting {} agent", params.agent_type);

    // Validate agent type
    let valid_agents = [
        "recon", "auth", "vuln-scan", "web-app", "exploit", "security-scan",
        "code-intel", "qa", "report", "api-security", "infra-security",
        "compliance", "chain-analysis",
    ];
    if !valid_agents.contains(&params.agent_type.as_str()) {
        return Err(AppError::Validation(format!(
            "Invalid agent type: {}. Valid types: {:?}",
            params.agent_type, valid_agents
        )));
    }

    // Check if MCP server is available
    let mcp = McpClient::new()?;
    if !mcp.health_check().await.unwrap_or(false) {
        return Err(AppError::ContainerNotRunning);
    }

    // Create agent record
    let agent_id = Uuid::new_v4();
    let now = chrono::Utc::now();

    {
        let mut state_write = state.write().await;
        state_write.running_agents.insert(
            agent_id,
            RunningAgent {
                id: agent_id,
                agent_type: params.agent_type.clone(),
                started_at: now,
                status: AgentStatus::Running,
            },
        );
    }

    // Call the appropriate MCP tool to run the agent
    let tool_name = format!("run_{}_agent", params.agent_type.replace('-', "_"));

    let result = mcp
        .call_tool(McpToolCall {
            name: tool_name,
            arguments: serde_json::json!({
                "targets": params.targets,
                "options": params.options,
            }),
        })
        .await;

    // Update agent status based on result
    {
        let mut state_write = state.write().await;
        if let Some(agent) = state_write.running_agents.get_mut(&agent_id) {
            agent.status = match &result {
                Ok(r) if r.success => AgentStatus::Completed,
                Ok(_) => AgentStatus::Failed("Tool execution failed".to_string()),
                Err(e) => AgentStatus::Failed(e.to_string()),
            };
        }
    }

    match result {
        Ok(tool_result) => Ok(RunAgentResponse {
            id: agent_id.to_string(),
            agent_type: params.agent_type,
            status: if tool_result.success {
                "completed"
            } else {
                "failed"
            }
            .to_string(),
            message: tool_result
                .error
                .unwrap_or_else(|| "Agent completed successfully".to_string()),
        }),
        Err(e) => Ok(RunAgentResponse {
            id: agent_id.to_string(),
            agent_type: params.agent_type,
            status: "failed".to_string(),
            message: e.to_string(),
        }),
    }
}

#[tauri::command]
pub async fn get_agent_status(
    state: State<'_, Arc<RwLock<AppState>>>,
    id: String,
) -> Result<AgentStatusResponse> {
    let agent_id = Uuid::parse_str(&id)
        .map_err(|_| AppError::Validation("Invalid agent ID format".to_string()))?;

    let state_read = state.read().await;
    let agent = state_read
        .running_agents
        .get(&agent_id)
        .ok_or_else(|| AppError::NotFound(format!("Agent not found: {}", id)))?;

    let (status, message) = match &agent.status {
        AgentStatus::Running => ("running".to_string(), None),
        AgentStatus::Completed => ("completed".to_string(), Some("Agent completed successfully".to_string())),
        AgentStatus::Failed(msg) => ("failed".to_string(), Some(msg.clone())),
        AgentStatus::Cancelled => ("cancelled".to_string(), Some("Agent was cancelled".to_string())),
    };

    Ok(AgentStatusResponse {
        id: agent.id.to_string(),
        agent_type: agent.agent_type.clone(),
        status,
        started_at: agent.started_at.to_rfc3339(),
        message,
        progress: None,
        findings_count: None,
    })
}

#[tauri::command]
pub async fn cancel_agent(
    state: State<'_, Arc<RwLock<AppState>>>,
    id: String,
) -> Result<()> {
    let agent_id = Uuid::parse_str(&id)
        .map_err(|_| AppError::Validation("Invalid agent ID format".to_string()))?;

    // Update local state
    {
        let mut state_write = state.write().await;
        let agent = state_write
            .running_agents
            .get_mut(&agent_id)
            .ok_or_else(|| AppError::NotFound(format!("Agent not found: {}", id)))?;

        agent.status = AgentStatus::Cancelled;
        info!("Agent {} cancelled locally", id);
    }

    // Call MCP cancel_agent tool to stop remote execution
    let mcp = McpClient::new()?;
    let _ = mcp
        .call_tool(McpToolCall {
            name: "cancel_agent".to_string(),
            arguments: serde_json::json!({
                "agent_id": id,
            }),
        })
        .await;

    info!("Agent {} cancel request sent to MCP", id);

    Ok(())
}

#[tauri::command]
pub async fn list_running_agents(
    state: State<'_, Arc<RwLock<AppState>>>,
) -> Result<Vec<AgentStatusResponse>> {
    let state_read = state.read().await;

    Ok(state_read
        .running_agents
        .values()
        .map(|agent| {
            let (status, message) = match &agent.status {
                AgentStatus::Running => ("running".to_string(), None),
                AgentStatus::Completed => ("completed".to_string(), Some("Completed".to_string())),
                AgentStatus::Failed(msg) => ("failed".to_string(), Some(msg.clone())),
                AgentStatus::Cancelled => ("cancelled".to_string(), Some("Cancelled".to_string())),
            };

            AgentStatusResponse {
                id: agent.id.to_string(),
                agent_type: agent.agent_type.clone(),
                status,
                started_at: agent.started_at.to_rfc3339(),
                message,
                progress: None,
                findings_count: None,
            }
        })
        .collect())
}
