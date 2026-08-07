use crate::error::{AppError, Result};
use crate::mcp::{McpClient, McpToolResult};
use serde::{Deserialize, Serialize};
use tracing::info;

// =============================================================================
// Tool Parameter Types
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPortsParams {
    pub target: String,
    pub ports: Option<String>,
    pub scan_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerateSubdomainsParams {
    pub domain: String,
    pub wordlist: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintServicesParams {
    pub target: String,
    pub ports: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverHostsParams {
    pub network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunNucleiParams {
    pub target: String,
    pub templates: Option<Vec<String>>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunNiktoParams {
    pub target: String,
    pub tuning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSqlmapParams {
    pub target: String,
    pub level: Option<i32>,
    pub risk: Option<i32>,
    pub technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunFfufParams {
    pub target: String,
    pub wordlist: Option<String>,
    pub extensions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunXssScanParams {
    pub target: String,
    pub params: Option<String>,
}

// =============================================================================
// Tool Commands
// =============================================================================

fn check_mcp_available() -> Result<McpClient> {
    McpClient::new()
}

#[tauri::command]
pub async fn scan_ports(params: ScanPortsParams) -> Result<McpToolResult> {
    info!("Scanning ports on target: {}", params.target);

    let mcp = check_mcp_available()?;

    mcp.scan_ports(
        &params.target,
        params.ports.as_deref(),
        params.scan_type.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn enumerate_subdomains(params: EnumerateSubdomainsParams) -> Result<McpToolResult> {
    info!("Enumerating subdomains for: {}", params.domain);

    let mcp = check_mcp_available()?;

    mcp.enumerate_subdomains(&params.domain, params.wordlist.as_deref())
        .await
}

#[tauri::command]
pub async fn fingerprint_services(params: FingerprintServicesParams) -> Result<McpToolResult> {
    info!(
        "Fingerprinting services on {} ports {}",
        params.target, params.ports
    );

    let mcp = check_mcp_available()?;

    mcp.fingerprint_services(&params.target, &params.ports)
        .await
}

#[tauri::command]
pub async fn discover_hosts(params: DiscoverHostsParams) -> Result<McpToolResult> {
    info!("Discovering hosts on network: {}", params.network);

    let mcp = check_mcp_available()?;

    mcp.discover_hosts(&params.network).await
}

#[tauri::command]
pub async fn run_nuclei(params: RunNucleiParams) -> Result<McpToolResult> {
    info!("Running Nuclei scan on: {}", params.target);

    let mcp = check_mcp_available()?;

    let templates: Option<Vec<&str>> = params
        .templates
        .as_ref()
        .map(|t| t.iter().map(|s| s.as_str()).collect());

    mcp.run_nuclei(&params.target, templates, params.severity.as_deref())
        .await
}

#[tauri::command]
pub async fn run_nikto(params: RunNiktoParams) -> Result<McpToolResult> {
    info!("Running Nikto scan on: {}", params.target);

    let mcp = check_mcp_available()?;

    mcp.run_nikto(&params.target, params.tuning.as_deref())
        .await
}

#[tauri::command]
pub async fn run_sqlmap(params: RunSqlmapParams) -> Result<McpToolResult> {
    info!("Running SQLMap on: {}", params.target);

    let mcp = check_mcp_available()?;

    mcp.run_sqlmap(
        &params.target,
        params.level.map(|l| l as u8),
        params.risk.map(|r| r as u8),
    )
    .await
}

#[tauri::command]
pub async fn run_ffuf(params: RunFfufParams) -> Result<McpToolResult> {
    info!("Running FFUF on: {}", params.target);

    let mcp = check_mcp_available()?;

    mcp.run_ffuf(
        &params.target,
        params.wordlist.as_deref(),
        params.extensions.as_deref(),
    )
    .await
}

#[tauri::command]
pub async fn run_xss_scan(params: RunXssScanParams) -> Result<McpToolResult> {
    info!("Running XSS scan on: {}", params.target);

    let mcp = check_mcp_available()?;

    mcp.run_xss_scan(&params.target, params.params.as_deref())
        .await
}
