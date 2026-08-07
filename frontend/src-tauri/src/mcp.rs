use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info};

use crate::error::{AppError, Result};

const MCP_SERVER_URL: &str = "http://127.0.0.1:3001";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes for long-running tools

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolResult {
    pub success: bool,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolsResponse {
    pub tools: Vec<McpTool>,
}

pub struct McpClient {
    client: Client,
    base_url: String,
}

impl McpClient {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AppError::Http(e))?;

        Ok(Self {
            client,
            base_url: MCP_SERVER_URL.to_string(),
        })
    }

    pub fn with_url(url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AppError::Http(e))?;

        Ok(Self {
            client,
            base_url: url.to_string(),
        })
    }

    /// Check if the MCP server is available
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.base_url);

        match self.client.get(&url).send().await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }

    /// Get list of available tools from the MCP server
    pub async fn list_tools(&self) -> Result<Vec<McpTool>> {
        let url = format!("{}/tools", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::Http(e))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AppError::Mcp(format!(
                "Failed to list tools: {} - {}",
                status, text
            )));
        }

        let tools_response: McpToolsResponse = response
            .json()
            .await
            .map_err(|e| AppError::Http(e))?;

        Ok(tools_response.tools)
    }

    /// Call a tool on the MCP server
    pub async fn call_tool(&self, tool_call: McpToolCall) -> Result<McpToolResult> {
        let url = format!("{}/tools/call", self.base_url);

        info!("Calling MCP tool: {}", tool_call.name);
        debug!("Tool arguments: {:?}", tool_call.arguments);

        let start = std::time::Instant::now();

        let response = self
            .client
            .post(&url)
            .json(&tool_call)
            .send()
            .await
            .map_err(|e| AppError::Http(e))?;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Ok(McpToolResult {
                success: false,
                result: None,
                error: Some(format!("HTTP {}: {}", status, text)),
                execution_time_ms,
            });
        }

        let result: Value = response
            .json()
            .await
            .map_err(|e| AppError::Http(e))?;

        info!(
            "Tool {} completed in {}ms",
            tool_call.name, execution_time_ms
        );

        Ok(McpToolResult {
            success: true,
            result: Some(result),
            error: None,
            execution_time_ms,
        })
    }

    // =========================================================================
    // Convenience methods for specific tools
    // =========================================================================

    /// Scan ports on a target
    pub async fn scan_ports(
        &self,
        target: &str,
        ports: Option<&str>,
        scan_type: Option<&str>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "target": target
        });

        if let Some(p) = ports {
            args["ports"] = serde_json::json!(p);
        }
        if let Some(st) = scan_type {
            args["scan_type"] = serde_json::json!(st);
        }

        self.call_tool(McpToolCall {
            name: "scan_ports".to_string(),
            arguments: args,
        })
        .await
    }

    /// Enumerate subdomains
    pub async fn enumerate_subdomains(
        &self,
        domain: &str,
        wordlist: Option<&str>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "domain": domain
        });

        if let Some(wl) = wordlist {
            args["wordlist"] = serde_json::json!(wl);
        }

        self.call_tool(McpToolCall {
            name: "enumerate_subdomains".to_string(),
            arguments: args,
        })
        .await
    }

    /// Discover hosts on a network
    pub async fn discover_hosts(&self, network: &str) -> Result<McpToolResult> {
        self.call_tool(McpToolCall {
            name: "discover_hosts".to_string(),
            arguments: serde_json::json!({
                "network": network
            }),
        })
        .await
    }

    /// Run Nuclei vulnerability scanner
    pub async fn run_nuclei(
        &self,
        target: &str,
        templates: Option<Vec<&str>>,
        severity: Option<&str>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "target": target
        });

        if let Some(t) = templates {
            args["templates"] = serde_json::json!(t);
        }
        if let Some(s) = severity {
            args["severity"] = serde_json::json!(s);
        }

        self.call_tool(McpToolCall {
            name: "run_nuclei".to_string(),
            arguments: args,
        })
        .await
    }

    /// Run Nikto web server scanner
    pub async fn run_nikto(&self, target: &str, tuning: Option<&str>) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "target": target
        });

        if let Some(t) = tuning {
            args["tuning"] = serde_json::json!(t);
        }

        self.call_tool(McpToolCall {
            name: "run_nikto".to_string(),
            arguments: args,
        })
        .await
    }

    /// Run SQLMap for SQL injection testing
    pub async fn run_sqlmap(
        &self,
        target: &str,
        level: Option<u8>,
        risk: Option<u8>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "target": target
        });

        if let Some(l) = level {
            args["level"] = serde_json::json!(l);
        }
        if let Some(r) = risk {
            args["risk"] = serde_json::json!(r);
        }

        self.call_tool(McpToolCall {
            name: "run_sqlmap".to_string(),
            arguments: args,
        })
        .await
    }

    /// Run FFUF directory fuzzer
    pub async fn run_ffuf(
        &self,
        target: &str,
        wordlist: Option<&str>,
        extensions: Option<&str>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "target": target
        });

        if let Some(wl) = wordlist {
            args["wordlist"] = serde_json::json!(wl);
        }
        if let Some(ext) = extensions {
            args["extensions"] = serde_json::json!(ext);
        }

        self.call_tool(McpToolCall {
            name: "run_ffuf".to_string(),
            arguments: args,
        })
        .await
    }

    /// Run XSS scanner
    pub async fn run_xss_scan(&self, target: &str, params: Option<&str>) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "target": target
        });

        if let Some(p) = params {
            args["params"] = serde_json::json!(p);
        }

        self.call_tool(McpToolCall {
            name: "run_xss_scan".to_string(),
            arguments: args,
        })
        .await
    }

    /// Fingerprint services on a target
    pub async fn fingerprint_services(&self, target: &str, ports: &str) -> Result<McpToolResult> {
        self.call_tool(McpToolCall {
            name: "fingerprint_services".to_string(),
            arguments: serde_json::json!({
                "target": target,
                "ports": ports
            }),
        })
        .await
    }

    /// Scan a local repository for security issues
    pub async fn scan_repository(
        &self,
        repo_path: &str,
        scan_types: Option<Vec<&str>>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "repo_path": repo_path
        });

        if let Some(st) = scan_types {
            args["scan_types"] = serde_json::json!(st);
        }

        self.call_tool(McpToolCall {
            name: "scan_repository".to_string(),
            arguments: args,
        })
        .await
    }

    /// Create a finding
    pub async fn create_finding(
        &self,
        title: &str,
        severity: &str,
        target: &str,
        description: &str,
        evidence: Option<&str>,
        remediation: Option<&str>,
    ) -> Result<McpToolResult> {
        let mut args = serde_json::json!({
            "title": title,
            "severity": severity,
            "target": target,
            "description": description
        });

        if let Some(e) = evidence {
            args["evidence"] = serde_json::json!(e);
        }
        if let Some(r) = remediation {
            args["remediation"] = serde_json::json!(r);
        }

        self.call_tool(McpToolCall {
            name: "create_finding".to_string(),
            arguments: args,
        })
        .await
    }
}

impl Default for McpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create MCP client")
    }
}
