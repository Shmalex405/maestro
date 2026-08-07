use crate::database::{Database, Finding, ScanSnapshot};
use crate::error::{AppError, Result};
use crate::mcp::{McpClient, McpToolCall};
use serde::{Deserialize, Serialize};
use tracing::info;

pub fn source_to_category(source: &str) -> &str {
    match source {
        // Scanner tools
        "nuclei" | "nikto" | "wpscan" | "searchsploit" | "nmap" => "vuln_scan",

        // Web app tools + agent
        "sqlmap" | "xss-test" | "ffuf" | "crawler" | "dalfox" | "manual"
        | "test_cors" | "test_ssrf" | "test_ssti" | "test_xss"
        | "test_http_smuggling" | "test_race_condition" | "test_cache_poisoning"
        | "test_websocket" | "test_file_upload" | "test_deserialization"
        | "test_session_fixation" | "test_session_management" | "test_password_policy"
        | "test_idor" | "test_graphql_security" | "fuzz_api_schema"
        | "test_api_rate_limiting"
        | "web-security" | "web-app" => "web_app",

        // API + GraphQL agent
        "api-graphql" | "api-security" => "web_app",

        // Code security tools + agents
        "semgrep" | "bandit" | "njsscan" | "gitleaks" | "trufflehog"
        | "grype" | "safety" | "checkov" | "trivy"
        | "scan_secrets" | "scan_dependencies" | "scan_iac"
        | "scan_semgrep" | "scan_bandit" | "scan_njsscan"
        | "sast-scan" | "sast-analysis" | "sast"
        | "cycode" | "cycode-validation" | "defense-analysis" => "code_security",

        // Exploitation tools → vuln_scan (exploitation is a cross-cutting view, not a source category)
        "metasploit" | "custom-exploit" | "exploit" => "vuln_scan",

        // Chain analysis → web_app (attack chains span categories)
        "chain-analysis" => "web_app",

        // Infrastructure tools + agent
        "scan_ssl_tls" | "check_certificate" | "scan_ssl_ciphers"
        | "check_dns_records" | "check_dnssec" | "test_zone_transfer"
        | "detect_subdomain_takeover" | "test_cloud_metadata" | "check_s3_bucket"
        | "scan_ports" | "discover_hosts" | "enumerate_subdomains"
        | "analyze_defenses" | "ssltls" | "dns-check"
        | "web_technology_scan" => "infrastructure",

        // Compound source names (e.g., "semgrep (p/security-audit)", "grype/npm-audit/safety")
        s if s.starts_with("nuclei") || s.starts_with("nikto") || s.starts_with("nmap") => "vuln_scan",
        s if s.starts_with("semgrep") || s.starts_with("gitleaks") || s.starts_with("grype")
            || s.starts_with("bandit") || s.starts_with("njsscan") || s.starts_with("trivy")
            || s.starts_with("checkov") || s.starts_with("trufflehog") || s.starts_with("safety") => "code_security",
        s if s.starts_with("metasploit") || s.starts_with("exploit") => "vuln_scan",
        s if s.starts_with("chain") => "web_app",

        // Agent name prefixes
        s if s.starts_with("recon") => "infrastructure",
        s if s.starts_with("crossval") || s.starts_with("qa") => "vuln_scan",
        s if s.starts_with("web") => "web_app",
        s if s.starts_with("sast") || s.starts_with("code") => "code_security",
        s if s.starts_with("api") => "web_app",
        s if s.starts_with("manual-api") || s.starts_with("manual-graphql") => "web_app",
        s if s.starts_with("manual-js") => "code_security",
        s if s.starts_with("manual") => "web_app",
        _ => "infrastructure",
    }
}

/// Maps a stored finding category to one of the 5 tab categories.
pub fn normalize_category(category: &str) -> &str {
    match category {
        // Already a tab category
        "vuln_scan" | "web_app" | "code_security" | "infrastructure" => category,
        "exploitation" => "vuln_scan",
        // Map semantic categories to tab categories
        "api-security" | "data-exposure" | "info-disclosure" | "authentication" => "web_app",
        "code-quality" | "secrets" | "supply-chain" | "cicd" => "code_security",
        "compliance" | "configuration" | "info" => "infrastructure",
        _ => "infrastructure",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginatedResult<T> {
    pub data: T,
    pub total: i32,
    pub page: i32,
    pub limit: i32,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListFindingsParams {
    pub assessment_id: Option<String>,
    pub severity: Option<Vec<String>>,
    pub status: Option<Vec<String>>,
    pub search: Option<String>,
    pub target: Option<String>,
    pub category: Option<String>,
    pub exploitable: Option<String>,
    pub project_id: Option<String>,
    pub limit: Option<i32>,
    pub page: Option<i32>,
    pub snapshot_id: Option<String>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFindingData {
    pub assessment_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub target: String,
    pub description: String,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub cvss_score: Option<f64>,
    pub cve_ids: Option<Vec<String>>,
    pub source: Option<String>,
    pub category: Option<String>,
    pub file_path: Option<String>,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub cwe: Option<String>,
}

#[tauri::command]
pub async fn list_findings(params: Option<ListFindingsParams>) -> Result<PaginatedResult<Vec<Finding>>> {
    info!("Listing findings with params: {:?}", params);

    let db = Database::new()?;
    let params = params.unwrap_or(ListFindingsParams {
        assessment_id: None,
        severity: None,
        status: None,
        search: None,
        target: None,
        category: None,
        exploitable: None,
        project_id: None,
        limit: None,
        page: None,
        snapshot_id: None,
        sort_by: None,
        sort_dir: None,
    });

    let limit = params.limit.unwrap_or(20);
    let page = params.page.unwrap_or(1);
    let offset = (page - 1) * limit;

    // Get the first severity from the array if provided
    let severity = params.severity.as_ref().and_then(|v| v.first()).map(|s| s.as_str());
    // Get the first status from the array if provided
    let status = params.status.as_ref().and_then(|v| v.first()).map(|s| s.as_str());

    // If snapshot_id is set, use snapshot-scoped queries
    if let Some(ref snap_id) = params.snapshot_id {
        let total = db.count_findings_by_snapshot(
            snap_id,
            severity,
            status,
            params.category.as_deref(),
        )?;

        let findings = db.list_findings_by_snapshot(
            snap_id,
            severity,
            status,
            params.category.as_deref(),
            Some(limit),
            Some(offset),
        )?;

        let has_more = (page * limit) < total;

        return Ok(PaginatedResult {
            data: findings,
            total,
            page,
            limit,
            has_more,
        });
    }

    // Get total count without fetching all rows
    let total = db.count_findings(
        params.assessment_id.as_deref(),
        severity,
        status,
        params.category.as_deref(),
        params.target.as_deref(),
        params.search.as_deref(),
        params.exploitable.as_deref(),
        params.project_id.as_deref(),
    )?;

    // Get paginated findings
    let findings = db.list_findings(
        params.assessment_id.as_deref(),
        severity,
        status,
        params.category.as_deref(),
        params.target.as_deref(),
        params.search.as_deref(),
        Some(limit),
        Some(offset),
        params.sort_by.as_deref(),
        params.sort_dir.as_deref(),
        params.exploitable.as_deref(),
        params.project_id.as_deref(),
    )?;

    let has_more = (page * limit) < total;

    Ok(PaginatedResult {
        data: findings,
        total,
        page,
        limit,
        has_more,
    })
}

#[tauri::command]
pub async fn get_finding(id: String) -> Result<Option<Finding>> {
    info!("Getting finding: {}", id);

    let db = Database::new()?;
    db.get_finding(&id)
}

#[tauri::command]
pub async fn create_finding(data: CreateFindingData) -> Result<Finding> {
    info!("Creating finding: {}", data.title);

    let db = Database::new()?;

    // Auto-derive category from source if not explicitly set
    let category = data.category.or_else(|| {
        data.source.as_deref().map(|s| source_to_category(s).to_string())
    });

    let finding = Finding {
        id: String::new(), // Will be generated
        assessment_id: data.assessment_id,
        title: data.title,
        severity: data.severity,
        status: "open".to_string(),
        target: data.target,
        description: data.description,
        evidence: data.evidence,
        remediation: data.remediation,
        cvss_score: data.cvss_score,
        cve_ids: data.cve_ids,
        source: data.source,
        category,
        file_path: data.file_path,
        line_start: data.line_start,
        line_end: data.line_end,
        code_snippet: data.code_snippet,
        cwe: data.cwe,
        created_at: String::new(), // Will be set
        updated_at: String::new(), // Will be set
        ..Default::default()
    };

    db.create_finding(&finding)
}

#[tauri::command]
pub async fn update_finding(id: String, data: serde_json::Value) -> Result<()> {
    info!("Updating finding: {}", id);

    let db = Database::new()?;
    db.update_finding(&id, &data)
}

#[tauri::command]
pub async fn delete_finding(id: String) -> Result<()> {
    info!("Deleting finding: {}", id);

    let db = Database::new()?;
    db.delete_finding(&id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsStats {
    pub total: i32,
    pub by_severity: std::collections::HashMap<String, i32>,
    pub by_status: std::collections::HashMap<String, i32>,
    pub by_category: std::collections::HashMap<String, i32>,
    pub exploitable_count: i32,
}

#[tauri::command]
pub async fn get_findings_stats(category: Option<String>, target: Option<String>, search: Option<String>, exploitable: Option<String>, project_id: Option<String>) -> Result<FindingsStats> {
    info!("Getting findings stats, category: {:?}, target: {:?}, exploitable: {:?}, project_id: {:?}", category, target, exploitable, project_id);

    let db = Database::new()?;
    let rows = db.get_findings_stats_grouped(category.as_deref(), target.as_deref(), search.as_deref(), exploitable.as_deref(), project_id.as_deref())?;

    let mut by_severity: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    let mut by_status: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    let mut by_category: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
    let mut total: i32 = 0;

    for (severity, status, cat, count) in rows {
        *by_severity.entry(severity).or_insert(0) += count;
        *by_status.entry(status).or_insert(0) += count;
        *by_category.entry(cat).or_insert(0) += count;
        total += count;
    }

    let exploitable_count = db.get_exploitable_count(target.as_deref(), search.as_deref(), project_id.as_deref())?;

    Ok(FindingsStats {
        total,
        by_severity,
        by_status,
        by_category,
        exploitable_count,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFindingsParams {
    pub format: String,
    pub severity: Option<String>,
    pub status: Option<String>,
}

#[tauri::command]
pub async fn export_findings(params: ExportFindingsParams) -> Result<String> {
    info!("Exporting findings as {}", params.format);

    let db = Database::new()?;
    let findings = db.list_findings(None, params.severity.as_deref(), params.status.as_deref(), None, None, None, Some(i32::MAX), None, None, None, None, None)?;

    match params.format.as_str() {
        "json" => Ok(serde_json::to_string_pretty(&findings).unwrap_or_default()),
        "csv" => {
            let mut csv = String::from("id,title,severity,status,target,created_at\n");
            for f in findings {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    f.id, f.title, f.severity, f.status, f.target, f.created_at
                ));
            }
            Ok(csv)
        }
        "markdown" => {
            let mut md = String::from("# Security Findings\n\n");
            for f in findings {
                md.push_str(&format!(
                    "## {} [{}]\n\n**Target:** {}\n**Status:** {}\n\n{}\n\n---\n\n",
                    f.title, f.severity, f.target, f.status, f.description
                ));
            }
            Ok(md)
        }
        _ => Ok(serde_json::to_string(&findings).unwrap_or_default()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateJiraTicketParams {
    pub finding_id: String,
    pub project_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraTicketResult {
    pub ticket_key: String,
    pub url: String,
}

#[tauri::command]
pub async fn create_jira_ticket(params: CreateJiraTicketParams) -> Result<JiraTicketResult> {
    info!("Creating Jira ticket for finding: {}", params.finding_id);

    // Call MCP create_jira_ticket tool
    let mcp = McpClient::new()?;
    let result = mcp
        .call_tool(McpToolCall {
            name: "create_jira_ticket".to_string(),
            arguments: serde_json::json!({
                "finding_id": params.finding_id,
                "project_key": params.project_key,
            }),
        })
        .await;

    match result {
        Ok(tool_result) if tool_result.success => {
            // Parse ticket info from MCP response
            let parsed = tool_result.result.unwrap_or(serde_json::json!({}));

            let ticket_key = parsed["ticket_key"]
                .as_str()
                .or_else(|| parsed["key"].as_str())
                .unwrap_or("UNKNOWN")
                .to_string();

            let url = parsed["url"]
                .as_str()
                .unwrap_or(&format!("https://jira.atlassian.net/browse/{}", ticket_key))
                .to_string();

            Ok(JiraTicketResult { ticket_key, url })
        }
        Ok(tool_result) => {
            let error_msg = tool_result.error.unwrap_or_else(|| "MCP tool failed".to_string());
            Err(AppError::Mcp(format!("Jira ticket creation failed: {}", error_msg)))
        }
        Err(e) => Err(e),
    }
}

#[tauri::command]
pub async fn create_scan_snapshot(assessment_id: String) -> Result<ScanSnapshot> {
    info!("Creating scan snapshot for assessment: {}", assessment_id);

    let db = Database::new()?;
    db.snapshot_assessment_findings(&assessment_id)
}

#[tauri::command]
pub async fn list_scan_history(target: Option<String>) -> Result<Vec<ScanSnapshot>> {
    info!("Listing scan history for target: {:?}", target);

    let db = Database::new()?;
    db.list_scan_snapshots(target.as_deref())
}
