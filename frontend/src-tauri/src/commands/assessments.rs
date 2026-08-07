use crate::database::{Assessment, Database, Finding};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use tauri::Emitter;
use tracing::{error, info, warn};
use chrono::Utc;

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
pub struct ListAssessmentsParams {
    pub limit: Option<i32>,
    pub page: Option<i32>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAssessmentData {
    /// Assessment type - maps from frontend's "type" field
    #[serde(rename = "type")]
    pub assessment_type: String,
    /// Targets to assess
    #[serde(default)]
    pub targets: Vec<String>,
    /// Optional name (auto-generated if not provided)
    pub name: Option<String>,
    /// Repository paths for code scanning
    #[serde(default)]
    pub repo_paths: Option<Vec<String>>,
    /// Assessment phases to run
    #[serde(default)]
    pub phases: Option<Vec<String>>,
    /// Credential app for authenticated testing
    pub credential_app: Option<String>,
    /// Jira project key for ticket creation
    pub jira_project: Option<String>,
    /// Email recipients for report delivery
    pub email_recipients: Option<Vec<String>>,
    /// Minimum severity threshold
    pub severity_threshold: Option<String>,
    /// Additional options
    pub options: Option<serde_json::Value>,
    /// Whether to start the assessment immediately (default: false for chat-based creation)
    #[serde(default)]
    pub start: bool,
}

#[tauri::command]
pub async fn list_assessments(
    params: Option<ListAssessmentsParams>,
) -> Result<PaginatedResult<Vec<Assessment>>> {
    info!("Listing assessments with params: {:?}", params);

    let db = Database::new()?;
    let params = params.unwrap_or(ListAssessmentsParams {
        limit: None,
        page: None,
        status: None,
    });

    let limit = params.limit.unwrap_or(20);
    let page = params.page.unwrap_or(1);
    let offset = (page - 1) * limit;

    // Get total count
    let all_assessments = db.list_assessments(None, None)?;
    let total = all_assessments.len() as i32;

    // Get paginated assessments
    let assessments = db.list_assessments(Some(limit), Some(offset))?;

    let has_more = (page * limit) < total;

    Ok(PaginatedResult {
        data: assessments,
        total,
        page,
        limit,
        has_more,
    })
}

#[tauri::command]
pub async fn get_assessment(id: String) -> Result<Option<Assessment>> {
    info!("Getting assessment: {}", id);

    let db = Database::new()?;
    db.get_assessment(&id)
}

#[tauri::command]
pub async fn create_assessment(
    app_handle: tauri::AppHandle,
    data: CreateAssessmentData,
) -> Result<Assessment> {
    // Generate name if not provided
    let name = data.name.unwrap_or_else(|| {
        format!("{} Assessment", data.assessment_type.replace("_", " ").to_uppercase())
    });

    info!("Creating assessment: {}", name);

    let db = Database::new()?;

    // Build options with all the extra fields
    let mut options = data.options.unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = options.as_object_mut() {
        if let Some(repo_paths) = &data.repo_paths {
            obj.insert("repo_paths".to_string(), serde_json::json!(repo_paths));
        }
        if let Some(phases) = &data.phases {
            obj.insert("phases".to_string(), serde_json::json!(phases));
        }
        if let Some(cred) = &data.credential_app {
            obj.insert("credential_app".to_string(), serde_json::json!(cred));
        }
        if let Some(jira) = &data.jira_project {
            obj.insert("jira_project".to_string(), serde_json::json!(jira));
        }
        if let Some(emails) = &data.email_recipients {
            obj.insert("email_recipients".to_string(), serde_json::json!(emails));
        }
        if let Some(severity) = &data.severity_threshold {
            obj.insert("severity_threshold".to_string(), serde_json::json!(severity));
        }
    }

    let assessment = db.create_assessment(
        &name,
        &data.assessment_type,
        &data.targets,
        Some(options),
    )?;

    // Only start the assessment if explicitly requested
    if data.start {
        // Update status to running and set started_at
        db.update_assessment_status(&assessment.id, "running")?;

        // Emit initial events to frontend
        let _ = app_handle.emit(
            &format!("assessment:{}:status", assessment.id),
            serde_json::json!({
                "status": "running",
                "message": "Assessment started"
            }),
        );

        let _ = app_handle.emit(
            &format!("assessment:{}:log", assessment.id),
            serde_json::json!({
                "level": "info",
                "message": format!("Starting {} assessment on targets: {}",
                    data.assessment_type,
                    data.targets.join(", "))
            }),
        );

        let _ = app_handle.emit(
            &format!("assessment:{}:progress", assessment.id),
            serde_json::json!({
                "percent": 0,
                "currentTool": "Initializing assessment..."
            }),
        );

        // Spawn background task to actually run the assessment
        let assessment_id = assessment.id.clone();
        let assessment_type = data.assessment_type.clone();
        let targets = data.targets.clone();
        let jira_project = data.jira_project.clone();
        let email_recipients = data.email_recipients.clone();
        let app_handle_clone = app_handle.clone();

        tokio::spawn(async move {
            run_assessment_background(
                app_handle_clone,
                assessment_id,
                assessment_type,
                targets,
                jira_project,
                email_recipients,
            )
            .await
        });

        // Return assessment with updated status
        Ok(Assessment {
            status: "running".to_string(),
            started_at: Some(chrono::Utc::now().to_rfc3339()),
            ..assessment
        })
    } else {
        // Return assessment in not_started state
        Ok(assessment)
    }
}

/// Background task that runs the actual assessment via MCP server
async fn run_assessment_background(
    app_handle: tauri::AppHandle,
    assessment_id: String,
    assessment_type: String,
    targets: Vec<String>,
    jira_project: Option<String>,
    email_recipients: Option<Vec<String>>,
) {
    // Small delay to allow frontend to set up event subscriptions
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    info!("Starting background assessment execution: {}", assessment_id);

    let assessment_id_clone = assessment_id.clone();

    // Helper to emit events
    let emit_log = |level: &str, message: &str| {
        let _ = app_handle.emit(
            &format!("assessment:{}:log", assessment_id_clone),
            serde_json::json!({ "level": level, "message": message }),
        );
    };

    let emit_progress = |percent: u32, current_tool: &str| {
        let _ = app_handle.emit(
            &format!("assessment:{}:progress", assessment_id_clone),
            serde_json::json!({ "percent": percent, "currentTool": current_tool }),
        );
    };

    let emit_status = |status: &str, message: &str| {
        let _ = app_handle.emit(
            &format!("assessment:{}:status", assessment_id_clone),
            serde_json::json!({ "status": status, "message": message }),
        );
    };

    const MCP_BASE_URL: &str = "http://127.0.0.1:3001";

    // Create HTTP client
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600)) // 10 min timeout for long assessments
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create HTTP client: {}", e);
            emit_log("error", &format!("Failed to create HTTP client: {}", e));
            emit_status("failed", "HTTP client creation failed");
            update_assessment_final_status(&assessment_id, "failed", Some(&e.to_string()));
            return;
        }
    };

    // Health check
    emit_progress(5, "Connecting to MCP server...");
    emit_log("info", "Checking MCP server connection...");

    match client.get(&format!("{}/health", MCP_BASE_URL)).send().await {
        Ok(resp) if resp.status().is_success() => {
            emit_log("info", "MCP server connected successfully");
            emit_progress(10, "MCP server connected");
        }
        Ok(resp) => {
            let err = format!("MCP server returned status: {}", resp.status());
            emit_log("error", &err);
            emit_status("failed", "MCP server not healthy");
            update_assessment_final_status(&assessment_id, "failed", Some(&err));
            return;
        }
        Err(e) => {
            emit_log("error", &format!("Cannot connect to MCP server: {}", e));
            emit_status("failed", "MCP server not available");
            update_assessment_final_status(&assessment_id, "failed", Some(&e.to_string()));
            return;
        }
    }

    // Determine endpoint and body based on assessment type
    let (endpoint, body) = match assessment_type.as_str() {
        "full" => {
            emit_progress(15, "Starting full assessment...");
            emit_log("info", "Running full assessment with all agents");
            (
                format!("{}/assess/full", MCP_BASE_URL),
                serde_json::json!({
                    "targets": targets,
                    "jira_project": jira_project,
                    "email_recipients": email_recipients,
                }),
            )
        }
        "recon" => {
            emit_progress(15, "Starting reconnaissance...");
            emit_log("info", "Running reconnaissance scan");
            (
                format!("{}/assess/recon", MCP_BASE_URL),
                serde_json::json!({ "targets": targets }),
            )
        }
        "vuln_scan" => {
            emit_progress(15, "Starting vulnerability scan...");
            emit_log("info", "Running vulnerability scan");
            (
                format!("{}/assess/vuln-scan", MCP_BASE_URL),
                serde_json::json!({ "targets": targets }),
            )
        }
        "code_scan" => {
            emit_progress(15, "Starting code security scan...");
            emit_log("info", "Running code security scan");
            (
                format!("{}/assess/code-scan", MCP_BASE_URL),
                serde_json::json!({ "repo_paths": targets }),
            )
        }
        _ => {
            warn!("Unknown assessment type: {}, defaulting to recon", assessment_type);
            emit_log("warning", &format!("Unknown type '{}', running reconnaissance", assessment_type));
            (
                format!("{}/assess/recon", MCP_BASE_URL),
                serde_json::json!({ "targets": targets }),
            )
        }
    };

    emit_log("info", &format!("Calling MCP endpoint: {}", endpoint));

    // Make the API call
    let result = client
        .post(&endpoint)
        .json(&body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            match resp.json::<serde_json::Value>().await {
                Ok(json) => {
                    if status.is_success() {
                        let success = json.get("success").and_then(|v| v.as_bool()).unwrap_or(true);
                        if success {
                            emit_progress(95, "Syncing findings...");
                            emit_log("info", "Syncing findings from MCP server");

                            // Sync findings from MCP server to Tauri database
                            let findings_count = sync_findings_from_mcp(&client, &assessment_id).await;

                            emit_progress(100, "Assessment completed");
                            emit_log("info", &format!("Assessment completed successfully with {} findings", findings_count));
                            emit_status("completed", "Assessment finished");
                            update_assessment_final_status(&assessment_id, "completed", None);

                            // Emit completed event
                            let _ = app_handle.emit(
                                &format!("assessment:{}:completed", assessment_id),
                                serde_json::json!({ "id": assessment_id, "findings_count": findings_count }),
                            );
                        } else {
                            let err_msg = json.get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Assessment returned failure");
                            emit_log("error", &format!("Assessment failed: {}", err_msg));
                            emit_status("failed", err_msg);
                            update_assessment_final_status(&assessment_id, "failed", Some(err_msg));
                        }
                    } else {
                        let err_msg = json.get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("HTTP request failed");
                        emit_log("error", &format!("Assessment failed: {}", err_msg));
                        emit_status("failed", err_msg);
                        update_assessment_final_status(&assessment_id, "failed", Some(err_msg));
                    }
                }
                Err(e) => {
                    let err_msg = format!("Failed to parse response: {}", e);
                    emit_log("error", &err_msg);
                    emit_status("failed", &err_msg);
                    update_assessment_final_status(&assessment_id, "failed", Some(&err_msg));
                }
            }
        }
        Err(e) => {
            error!("Assessment execution error: {}", e);
            emit_log("error", &format!("Assessment request failed: {}", e));
            emit_status("failed", &e.to_string());
            update_assessment_final_status(&assessment_id, "failed", Some(&e.to_string()));
        }
    }
}

/// Update assessment status in database when finished
fn update_assessment_final_status(assessment_id: &str, status: &str, error_message: Option<&str>) {
    if let Ok(db) = Database::new() {
        if let Err(e) = db.update_assessment_status(assessment_id, status) {
            error!("Failed to update assessment status: {}", e);
        }
        if let Some(err) = error_message {
            // Store error message if available
            if let Err(e) = db.set_assessment_error(assessment_id, err) {
                error!("Failed to set assessment error: {}", e);
            }
        }
    }
}

/// Sync findings from MCP server to Tauri database
async fn sync_findings_from_mcp(client: &reqwest::Client, assessment_id: &str) -> i32 {
    const MCP_BASE_URL: &str = "http://127.0.0.1:3001";

    // Fetch findings from MCP server
    let findings_result = client
        .get(&format!("{}/api/findings", MCP_BASE_URL))
        .send()
        .await;

    match findings_result {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(findings_array) = json.get("data").and_then(|d| d.as_array()) {
                    let db = match Database::new() {
                        Ok(db) => db,
                        Err(e) => {
                            error!("Failed to open database for sync: {}", e);
                            return 0;
                        }
                    };

                    let mut synced_count = 0;
                    let now = Utc::now().to_rfc3339();

                    for finding_json in findings_array {
                        // Extract finding data
                        let title = finding_json.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled").to_string();
                        let severity = finding_json.get("severity").and_then(|v| v.as_str()).unwrap_or("info").to_string();
                        let target = finding_json.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let description = finding_json.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let evidence = finding_json.get("evidence").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let remediation = finding_json.get("remediation").and_then(|v| v.as_str()).map(|s| s.to_string());

                        let source = finding_json.get("source").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let category = finding_json.get("category").and_then(|v| v.as_str()).map(|s| s.to_string());

                        let file_path = finding_json.get("file_path").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let line_start = finding_json.get("line_start").and_then(|v| v.as_i64()).map(|n| n as i32);
                        let line_end = finding_json.get("line_end").and_then(|v| v.as_i64()).map(|n| n as i32);
                        let code_snippet = finding_json.get("code_snippet").and_then(|v| v.as_str()).map(|s| s.to_string());
                        let cwe = finding_json.get("cwe").and_then(|v| v.as_str()).map(|s| s.to_string());

                        let finding = Finding {
                            id: String::new(), // Will be generated by create_finding
                            assessment_id: Some(assessment_id.to_string()),
                            title: title.clone(),
                            severity,
                            status: "open".to_string(),
                            target,
                            description,
                            evidence,
                            remediation,
                            cvss_score: None,
                            cve_ids: None,
                            source,
                            category,
                            file_path,
                            line_start,
                            line_end,
                            code_snippet,
                            cwe,
                            created_at: now.clone(),
                            updated_at: now.clone(),
                            ..Default::default()
                        };

                        // Create finding in Tauri database
                        match db.create_finding(&finding) {
                            Ok(_) => {
                                info!("Synced finding: {}", title);
                                synced_count += 1;
                            }
                            Err(e) => {
                                error!("Failed to sync finding {}: {}", title, e);
                            }
                        }
                    }

                    info!("Synced {} findings from MCP server", synced_count);
                    return synced_count;
                }
            }
            0
        }
        Err(e) => {
            error!("Failed to fetch findings from MCP server: {}", e);
            0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAssessmentData {
    /// Assessment type
    #[serde(rename = "type")]
    pub assessment_type: Option<String>,
    /// Assessment name
    pub name: Option<String>,
    /// Assessment status
    pub status: Option<String>,
    /// Targets to assess
    pub targets: Option<Vec<String>>,
}

#[tauri::command]
pub async fn update_assessment(
    id: String,
    data: UpdateAssessmentData,
) -> Result<Assessment> {
    info!("Updating assessment: {} with data: {:?}", id, data);

    let db = Database::new()?;

    // Update the assessment
    db.update_assessment(
        &id,
        data.assessment_type.as_deref(),
        data.name.as_deref(),
        data.status.as_deref(),
        data.targets.as_deref(),
    )?;

    // Return the updated assessment
    db.get_assessment(&id)?
        .ok_or_else(|| crate::error::AppError::NotFound(format!("Assessment {} not found", id)))
}

/// Replace the `options` JSON blob on an assessment. The frontend uses
/// this to persist fields that don't warrant their own column — most
/// notably the per-assessment Claude/Codex session UUIDs that drive the
/// Resume flow. Caller is responsible for merging existing options with
/// new fields (read-modify-write); we just write the full object.
#[tauri::command]
pub async fn update_assessment_options(
    id: String,
    options: serde_json::Value,
) -> Result<Assessment> {
    info!("Updating assessment options for {}", id);
    let db = Database::new()?;
    db.update_assessment_options(&id, &options)?;
    db.get_assessment(&id)?
        .ok_or_else(|| crate::error::AppError::NotFound(format!("Assessment {} not found", id)))
}

#[tauri::command]
pub async fn start_assessment(
    app_handle: tauri::AppHandle,
    id: String,
) -> Result<Assessment> {
    info!("Starting assessment: {}", id);

    let db = Database::new()?;

    // Get the assessment
    let assessment = db.get_assessment(&id)?
        .ok_or_else(|| crate::error::AppError::NotFound(format!("Assessment {} not found", id)))?;

    // Check if assessment can be started
    if assessment.status != "not_started" && assessment.status != "pending" {
        return Err(crate::error::AppError::InvalidState(
            format!("Assessment is in {} state and cannot be started", assessment.status)
        ));
    }

    // Update status to running
    db.update_assessment_status(&id, "running")?;

    // Emit initial events to frontend
    let _ = app_handle.emit(
        &format!("assessment:{}:status", id),
        serde_json::json!({
            "status": "running",
            "message": "Assessment started"
        }),
    );

    let _ = app_handle.emit(
        &format!("assessment:{}:log", id),
        serde_json::json!({
            "level": "info",
            "message": format!("Starting {} assessment on targets: {}",
                assessment.assessment_type,
                assessment.targets.join(", "))
        }),
    );

    let _ = app_handle.emit(
        &format!("assessment:{}:progress", id),
        serde_json::json!({
            "percent": 0,
            "currentTool": "Initializing assessment..."
        }),
    );

    // Extract options for the background task
    let jira_project = assessment.options.as_ref()
        .and_then(|o| o.get("jira_project"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let email_recipients = assessment.options.as_ref()
        .and_then(|o| o.get("email_recipients"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect());

    // Spawn background task to run the assessment
    let assessment_id = id.clone();
    let assessment_type = assessment.assessment_type.clone();
    let targets = assessment.targets.clone();
    let app_handle_clone = app_handle.clone();

    tokio::spawn(async move {
        run_assessment_background(
            app_handle_clone,
            assessment_id,
            assessment_type,
            targets,
            jira_project,
            email_recipients,
        )
        .await
    });

    // Return assessment with updated status
    Ok(Assessment {
        status: "running".to_string(),
        started_at: Some(chrono::Utc::now().to_rfc3339()),
        ..assessment
    })
}

#[tauri::command]
pub async fn cancel_assessment(id: String) -> Result<()> {
    info!("Cancelling assessment: {}", id);

    let db = Database::new()?;
    db.update_assessment_status(&id, "cancelled")
}

#[tauri::command]
pub async fn pause_assessment(id: String) -> Result<()> {
    info!("Pausing assessment: {}", id);

    let db = Database::new()?;
    // Record the intentional pause in `options` so the cloud reaper exempts it
    // from the 3-hour stale sweep (it would otherwise auto-fail a 'running' run
    // left idle while the laptop sleeps). The marker syncs up via options→config.
    db.set_assessment_paused(&id, true)?;
    db.update_assessment_status(&id, "paused")
}

#[tauri::command]
pub async fn resume_assessment(id: String) -> Result<Assessment> {
    info!("Resuming assessment from checkpoint: {}", id);

    let db = Database::new()?;
    // Clear the pause marker and mark running again. The conversation itself
    // resumes via `claude --resume <claude_session_id>` (terminal-view.tsx);
    // the MCP resume_assessment tool handles the deterministic-pipeline path.
    db.set_assessment_paused(&id, false)?;
    db.update_assessment_status(&id, "running")?;
    let assessment = db.get_assessment(&id)?
        .ok_or_else(|| crate::error::AppError::NotFound(format!("Assessment {} not found", id)))?;
    Ok(Assessment {
        status: "running".to_string(),
        ..assessment
    })
}

#[tauri::command]
pub async fn delete_assessment(id: String) -> Result<()> {
    info!("Deleting assessment: {}", id);

    let db = Database::new()?;
    db.delete_assessment(&id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub assessment_id: String,
    pub title: String,
    pub content: String,
    pub format: String,
    pub created_at: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub exploitable_count: i32,
}

#[tauri::command]
pub async fn get_assessment_report(id: String) -> Result<Option<Report>> {
    info!("Getting report for assessment: {}", id);

    let db = Database::new()?;
    if let Some(assessment) = db.get_assessment(&id)? {
        // Get findings for this assessment
        let findings = db.list_findings(Some(&id), None, None, None, None, None, None, None, None, None, None, None)?;

        let critical_count = findings.iter().filter(|f| f.severity == "critical").count() as i32;
        let high_count = findings.iter().filter(|f| f.severity == "high").count() as i32;
        // "confirmed" is the validated/exploited status set by the import-validation
        // flow — the only exploitation signal the local finding schema carries.
        let exploitable_count = findings.iter().filter(|f| f.status == "confirmed").count() as i32;

        Ok(Some(Report {
            id: format!("report-{}", id),
            assessment_id: id.clone(),
            title: format!("Security Assessment Report - {}", assessment.assessment_type),
            content: format!("# Security Assessment Report\n\n## Summary\n\nTotal findings: {}\n- Critical: {}\n- High: {}\n\n",
                findings.len(), critical_count, high_count),
            format: "markdown".to_string(),
            created_at: assessment.created_at,
            findings_count: findings.len() as i32,
            critical_count,
            high_count,
            exploitable_count,
        }))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateReportParams {
    pub format: Option<String>,
}

#[tauri::command]
pub async fn generate_assessment_report(id: String, format: Option<String>) -> Result<Report> {
    info!("Generating report for assessment: {}", id);

    let db = Database::new()?;
    let assessment = db.get_assessment(&id)?
        .ok_or_else(|| crate::error::AppError::NotFound(format!("Assessment {} not found", id)))?;

    let findings = db.list_findings(Some(&id), None, None, None, None, None, None, None, None, None, None, None)?;
    let report_format = format.unwrap_or_else(|| "markdown".to_string());

    let critical_count = findings.iter().filter(|f| f.severity == "critical").count() as i32;
    let high_count = findings.iter().filter(|f| f.severity == "high").count() as i32;
    let medium_count = findings.iter().filter(|f| f.severity == "medium").count() as i32;
    let low_count = findings.iter().filter(|f| f.severity == "low").count() as i32;
    // "confirmed" is the validated/exploited status the import-validation flow sets.
    let exploitable_count = findings.iter().filter(|f| f.status == "confirmed").count() as i32;

    let mut content = String::new();

    // Build report content
    content.push_str(&format!("# Security Assessment Report\n\n"));
    content.push_str(&format!("**Assessment Type:** {}\n", assessment.assessment_type));
    content.push_str(&format!("**Targets:** {}\n", assessment.targets.join(", ")));
    content.push_str(&format!("**Date:** {}\n\n", assessment.created_at));

    content.push_str("## Executive Summary\n\n");
    content.push_str(&format!("| Severity | Count |\n"));
    content.push_str(&format!("|----------|-------|\n"));
    content.push_str(&format!("| Critical | {} |\n", critical_count));
    content.push_str(&format!("| High | {} |\n", high_count));
    content.push_str(&format!("| Medium | {} |\n", medium_count));
    content.push_str(&format!("| Low | {} |\n\n", low_count));

    content.push_str("## Findings\n\n");
    for finding in &findings {
        content.push_str(&format!("### {} [{}]\n\n", finding.title, finding.severity.to_uppercase()));
        content.push_str(&format!("**Target:** {}\n\n", finding.target));
        content.push_str(&format!("{}\n\n", finding.description));
        if let Some(ref remediation) = finding.remediation {
            content.push_str(&format!("**Remediation:** {}\n\n", remediation));
        }
        content.push_str("---\n\n");
    }

    Ok(Report {
        id: format!("report-{}", id),
        assessment_id: id,
        title: format!("Security Assessment Report - {}", assessment.assessment_type),
        content,
        format: report_format,
        created_at: chrono::Utc::now().to_rfc3339(),
        findings_count: findings.len() as i32,
        critical_count,
        high_count,
        exploitable_count,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteAssessmentResult {
    pub assessment_id: String,
    pub mode: String,
    pub requested: i32,
    pub found_local: i32,
    pub pushed: i32,
    pub failed: i32,
    pub assessment_status: String,
    pub errors: serde_json::Value,
}

/// Manual "Complete & Push to dashboard" trigger from the desktop.
///
/// Calls the MCP server's `complete_assessment` tool, which:
///   1. Reads finalized findings from the in-container local SQLite
///   2. Bulk-POSTs them to the cloud `/findings` endpoint (fingerprint
///      upsert handles re-runs)
///   3. PATCHes the cloud assessment row to status='completed'
///
/// `finding_ids` empty (or omitted) means "push everything in local" —
/// the fallback used by this manual button. The agent-driven path
/// passes a curated subset from the report-writer.
#[tauri::command]
pub async fn complete_assessment(
    assessment_id: String,
    finding_ids: Option<Vec<String>>,
) -> Result<CompleteAssessmentResult> {
    use crate::mcp::{McpClient, McpToolCall};

    // Local mode has nowhere to push to. The MCP handler's job here is to
    // promote curated findings to the cloud backend and flip the assessment to
    // completed there; locally the findings are already the system of record, so
    // the only remaining step is the status flip. Calling the MCP tool anyway
    // would either no-op confusingly or error on a missing cloud session.
    if crate::commands::self_host::is_local_deployment() {
        info!(
            "complete_assessment: local mode — marking {} complete without cloud promotion",
            assessment_id
        );
        let requested = finding_ids.as_ref().map(|v| v.len()).unwrap_or(0) as i32;
        let db = crate::database::Database::new()?;
        // update_assessment_status also stamps completed_at, which the plain
        // field update would leave null.
        db.update_assessment_status(&assessment_id, "completed")?;
        return Ok(CompleteAssessmentResult {
            assessment_id,
            mode: "local".to_string(),
            requested,
            // Nothing is "found" or "pushed" because nothing moves — the rows
            // never left this machine.
            found_local: requested,
            pushed: 0,
            failed: 0,
            assessment_status: "completed".to_string(),
            errors: serde_json::json!([]),
        });
    }

    info!("complete_assessment: pushing findings for {}", assessment_id);

    let mcp = McpClient::new()?;
    let ids = finding_ids.unwrap_or_default();

    let res = mcp
        .call_tool(McpToolCall {
            name: "complete_assessment".to_string(),
            arguments: serde_json::json!({
                "assessment_id": assessment_id,
                "finding_ids": ids,
            }),
        })
        .await?;

    if !res.success {
        return Err(crate::error::AppError::Mcp(
            res.error.unwrap_or_else(|| "complete_assessment failed".into()),
        ));
    }

    // The MCP handler returns its JSON payload as a stringified body
    // inside `result.content[0].text`. Drill into the response.
    let parsed: CompleteAssessmentResult = res
        .result
        .as_ref()
        .and_then(extract_tool_text)
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or_else(|| {
            crate::error::AppError::Mcp(
                "complete_assessment returned an unexpected shape".into(),
            )
        })?;

    Ok(parsed)
}

/// MCP `/tools/call` wraps the handler's stringified JSON inside a
/// `{ content: [{ type: 'text', text: '...' }] }` envelope. Pull the
/// first text part out so we can parse the inner payload.
fn extract_tool_text(value: &serde_json::Value) -> Option<String> {
    value
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("text"))
        .and_then(|t| t.as_str())
        .map(String::from)
}
