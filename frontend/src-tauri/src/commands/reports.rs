use crate::database::Database;
use crate::error::{AppError, Result};
use crate::mcp::{McpClient, McpToolCall};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub assessment_id: String,
    pub name: String,
    pub format: String,
    pub content: Option<String>,
    pub file_path: Option<String>,
    pub created_at: String,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub exploitable_count: i32,
    pub title: Option<String>,
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
pub struct ListReportsParams {
    pub assessment_id: Option<String>,
    pub page: Option<i32>,
    pub limit: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateReportParams {
    pub assessment_id: String,
    pub format: String,
    pub include_evidence: Option<bool>,
    pub include_remediation: Option<bool>,
}

impl From<crate::database::Report> for Report {
    fn from(db: crate::database::Report) -> Self {
        // Extract title from content if markdown
        let title = db.content.as_deref().and_then(|c| {
            c.lines().find_map(|line| {
                line.trim().strip_prefix("# ").map(|t| t.trim().to_string())
            })
        });

        Report {
            id: db.id,
            assessment_id: db.assessment_id,
            name: db.name,
            format: db.format,
            content: db.content,
            file_path: db.file_path,
            created_at: db.created_at,
            findings_count: db.findings_count,
            critical_count: db.critical_count,
            high_count: db.high_count,
            medium_count: db.medium_count,
            low_count: db.low_count,
            exploitable_count: db.exploitable_count,
            title,
        }
    }
}

#[tauri::command]
pub async fn list_reports(params: Option<ListReportsParams>) -> Result<PaginatedResult<Vec<Report>>> {
    info!("Listing reports");

    let db = Database::new()?;
    let assessment_id = params.as_ref().and_then(|p| p.assessment_id.as_deref());
    let page = params.as_ref().and_then(|p| p.page).unwrap_or(1);
    let limit = params.as_ref().and_then(|p| p.limit).unwrap_or(20);

    let db_reports = db.list_reports(assessment_id)?;
    let total = db_reports.len() as i32;

    // Paginate
    let start = ((page - 1) * limit) as usize;
    let reports: Vec<Report> = db_reports
        .into_iter()
        .skip(start)
        .take(limit as usize)
        .map(Report::from)
        .collect();

    Ok(PaginatedResult {
        data: reports,
        total,
        page,
        limit,
        has_more: (start as i32 + limit) < total,
    })
}

#[tauri::command]
pub async fn get_report(id: String) -> Result<Option<Report>> {
    info!("Getting report: {}", id);

    let db = Database::new()?;
    Ok(db.get_report(&id)?.map(Report::from))
}

#[tauri::command]
pub async fn generate_report(params: GenerateReportParams) -> Result<Report> {
    info!(
        "Generating {} report for assessment: {}",
        params.format, params.assessment_id
    );

    let db = Database::new()?;

    // Get assessment
    let assessment = db
        .get_assessment(&params.assessment_id)?
        .ok_or_else(|| AppError::NotFound("Assessment not found".to_string()))?;

    // Get findings for this assessment
    let findings = db.list_findings(
        Some(&params.assessment_id),
        None,
        None,
        None,
        None,
        None,
        Some(1000),
        Some(0),
        None,
        None,
        None,
        None,
    )?;

    // Compute severity counts
    let critical_count = findings.iter().filter(|f| f.severity == "critical").count() as i32;
    let high_count = findings.iter().filter(|f| f.severity == "high").count() as i32;
    let medium_count = findings.iter().filter(|f| f.severity == "medium").count() as i32;
    let low_count = findings.iter().filter(|f| f.severity == "low").count() as i32;
    let findings_count = findings.len() as i32;

    // Generate report based on format
    let report_dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Could not determine home directory".to_string()))?
        .join(".kali-mcp-pentest")
        .join("reports");

    std::fs::create_dir_all(&report_dir)?;

    let file_name = format!(
        "{}_{}.{}",
        assessment.name.replace(' ', "_"),
        chrono::Utc::now().format("%Y%m%d_%H%M%S"),
        params.format
    );
    let file_path = report_dir.join(&file_name);

    // Generate content based on format
    let content = match params.format.as_str() {
        "markdown" | "md" => generate_markdown_report(&assessment, &findings),
        "json" => serde_json::to_string_pretty(&serde_json::json!({
            "assessment": assessment,
            "findings": findings,
            "generated_at": chrono::Utc::now().to_rfc3339(),
        }))?,
        "html" => generate_html_report(&assessment, &findings),
        _ => return Err(AppError::Validation(format!("Unsupported format: {}", params.format))),
    };

    std::fs::write(&file_path, &content)?;
    info!("Report generated: {:?}", file_path);

    // Persist to database
    let db_report = db.create_report(
        &params.assessment_id,
        &file_name,
        &params.format,
        Some(&content),
        Some(&file_path.to_string_lossy()),
        findings_count,
        critical_count,
        high_count,
        medium_count,
        low_count,
        0, // exploitable_count
    )?;

    Ok(Report::from(db_report))
}

#[tauri::command]
pub async fn export_report(id: String, destination: String) -> Result<String> {
    info!("Exporting report {} to {}", id, destination);

    let db = Database::new()?;
    let report = db.get_report(&id)?
        .ok_or_else(|| AppError::NotFound(format!("Report not found: {}", id)))?;

    // If report has a file_path, copy it to destination
    if let Some(src_path) = &report.file_path {
        let src = PathBuf::from(src_path);
        let dest = PathBuf::from(&destination);

        if src.exists() {
            // If destination is a directory, copy into it with same filename
            let final_dest = if dest.is_dir() {
                dest.join(src.file_name().unwrap_or_default())
            } else {
                dest
            };
            std::fs::copy(&src, &final_dest)?;
            return Ok(final_dest.to_string_lossy().to_string());
        }
    }

    // Fallback: write content directly
    if let Some(content) = &report.content {
        std::fs::write(&destination, content)?;
        return Ok(destination);
    }

    Err(AppError::NotFound("Report has no file or content to export".to_string()))
}

// =============================================================================
// FILESYSTEM REPORT COMMANDS
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportFileInfo {
    pub name: String,
    pub path: String,
    pub format: String,
    pub size: u64,
    pub modified_at: String,
    pub title: Option<String>,
}

/// Get the list of directories to scan for report files.
///
/// Production: only `~/.kali-mcp-pentest/reports/` (where MCP-generated PDFs
/// land, regardless of which machine is running). The legacy
/// `env!("CARGO_MANIFEST_DIR")` branch was dead code in shipped builds —
/// it pointed at the CI runner's path on customer machines, not the
/// customer's machine — and surfaced bugs like the v0.1.13 MCP path
/// resolution. Same fix pattern applied here for symmetry / future-proofing
/// against the same class of mistake.
fn get_report_directories() -> Vec<PathBuf> {
    let mut dirs_to_scan = Vec::new();

    // ~/.kali-mcp-pentest/reports/ — created if missing so MCP-generated
    // PDFs always have a known landing spot the desktop can list.
    if let Some(home) = dirs::home_dir() {
        let home_reports = home.join(".kali-mcp-pentest").join("reports");
        let _ = std::fs::create_dir_all(&home_reports);
        if home_reports.is_dir() {
            dirs_to_scan.push(home_reports);
        }
    }

    dirs_to_scan
}

/// Parse the title from the first `# ` heading line in a markdown file.
/// Only reads the first 4KB to avoid loading huge files.
fn parse_markdown_title(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("# ") {
            let title = heading.trim();
            if !title.is_empty() {
                return Some(title.to_string());
            }
        }
    }
    None
}

#[tauri::command]
pub async fn list_report_files() -> Result<Vec<ReportFileInfo>> {
    info!("Listing report files from filesystem");

    let report_dirs = get_report_directories();
    let mut results: Vec<ReportFileInfo> = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();

    for dir in &report_dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                info!("Could not read report directory {:?}: {}", dir, err);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Only .md and .pdf files
            let format = if name.ends_with(".md") {
                "markdown"
            } else if name.ends_with(".pdf") {
                "pdf"
            } else {
                continue;
            };

            let abs_path = match path.canonicalize() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => path.to_string_lossy().to_string(),
            };

            // Deduplicate by absolute path
            if !seen_paths.insert(abs_path.clone()) {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let modified_at = metadata
                .modified()
                .ok()
                .and_then(|t| {
                    let datetime: chrono::DateTime<chrono::Utc> = t.into();
                    Some(datetime.to_rfc3339())
                })
                .unwrap_or_default();

            let title = if format == "markdown" {
                parse_markdown_title(&path)
            } else {
                None
            };

            results.push(ReportFileInfo {
                name,
                path: abs_path,
                format: format.to_string(),
                size: metadata.len(),
                modified_at,
                title,
            });
        }
    }

    // Sort by modified_at descending (newest first)
    results.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));

    info!("Found {} report files", results.len());
    Ok(results)
}

#[tauri::command]
pub async fn read_report_file(file_path: String) -> Result<String> {
    info!("Reading report file: {}", file_path);

    let path = PathBuf::from(&file_path);

    // Security: validate the file is within an allowed reports directory
    let report_dirs = get_report_directories();
    let canonical = path
        .canonicalize()
        .map_err(|e| AppError::NotFound(format!("File not found: {} ({})", file_path, e)))?;

    let is_allowed = report_dirs.iter().any(|dir| {
        if let Ok(canonical_dir) = dir.canonicalize() {
            canonical.starts_with(&canonical_dir)
        } else {
            false
        }
    });

    if !is_allowed {
        return Err(AppError::Validation(format!(
            "File is not in an allowed reports directory: {}",
            file_path
        )));
    }

    let content = std::fs::read_to_string(&canonical)?;

    Ok(content)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratePdfParams {
    pub markdown_content: String,
    pub title: Option<String>,
    pub output_filename: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratePdfResult {
    pub path: Option<String>,
}

#[tauri::command]
pub async fn generate_pdf_report(params: GeneratePdfParams) -> Result<GeneratePdfResult> {
    info!("Generating PDF report via MCP");

    let mcp = McpClient::new()?;
    let result = mcp
        .call_tool(McpToolCall {
            name: "generate_pdf_report".to_string(),
            arguments: serde_json::json!({
                "markdown_content": params.markdown_content,
                "title": params.title.unwrap_or_else(|| "Security Findings Report".to_string()),
                "output_filename": params.output_filename.unwrap_or_else(|| "findings-report.pdf".to_string()),
            }),
        })
        .await;

    match result {
        Ok(tool_result) if tool_result.success => {
            let parsed = tool_result.result.unwrap_or(serde_json::json!({}));
            let path = parsed["output_path"]
                .as_str()
                .or_else(|| parsed["path"].as_str())
                .map(|s| s.to_string());
            Ok(GeneratePdfResult { path })
        }
        Ok(tool_result) => {
            let error_msg = tool_result.error.unwrap_or_else(|| "PDF generation failed".to_string());
            Err(AppError::Mcp(format!("PDF generation failed: {}", error_msg)))
        }
        Err(e) => Err(e),
    }
}

// open_report_file removed in cloud-only architecture — reports
// render inline via a presigned S3 URL in an iframe; there is no
// host-disk file to open. Downloads go through the same artifact
// URL with attachment disposition. See the Reports page (cloud-only)
// for the current flow.

// Downloading via the webview's `<a download href="blob:...">` route
// is unreliable on macOS in wry 0.53 / Tauri 2.9: WKWebView surfaces
// the Downloads-folder TCC prompt but doesn't actually retry the
// destination write after the user grants permission, so the file
// silently never lands. Do the GET in Rust against the presigned (or
// backend) URL and write the bytes ourselves — `std::fs::write`
// blocks until TCC resolves and just works.
#[tauri::command]
pub async fn download_url_to_downloads(
    url: String,
    filename: String,
    auth_header: Option<String>,
) -> Result<String> {
    let client = reqwest::Client::new();
    let mut req = client.get(&url);
    if let Some(auth) = auth_header {
        req = req.header(reqwest::header::AUTHORIZATION, auth);
    }
    let response = req.send().await?;
    if !response.status().is_success() {
        return Err(AppError::Other(format!(
            "Download failed: HTTP {}",
            response.status()
        )));
    }
    let bytes = response.bytes().await?;

    let downloads_dir = dirs::download_dir()
        .ok_or_else(|| AppError::Config("Could not locate Downloads folder".to_string()))?;
    std::fs::create_dir_all(&downloads_dir)?;

    let safe = filename.replace(['/', '\\'], "_");
    let initial = PathBuf::from(&safe);
    let stem = initial
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "download".to_string());
    let ext = initial
        .extension()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut target = downloads_dir.join(&safe);
    let mut i = 1;
    while target.exists() && i < 1000 {
        let candidate = if ext.is_empty() {
            format!("{} ({})", stem, i)
        } else {
            format!("{} ({}).{}", stem, i, ext)
        };
        target = downloads_dir.join(candidate);
        i += 1;
    }

    std::fs::write(&target, &bytes)?;
    info!("Saved report download to {}", target.display());
    Ok(target.to_string_lossy().to_string())
}

fn generate_markdown_report(
    assessment: &crate::database::Assessment,
    findings: &[crate::database::Finding],
) -> String {
    let mut md = String::new();

    md.push_str(&format!("# Security Assessment Report: {}\n\n", assessment.name));
    md.push_str(&format!("**Assessment Type:** {}\n\n", assessment.assessment_type));
    md.push_str(&format!("**Status:** {}\n\n", assessment.status));
    md.push_str(&format!("**Created:** {}\n\n", assessment.created_at));

    if let Some(completed) = &assessment.completed_at {
        md.push_str(&format!("**Completed:** {}\n\n", completed));
    }

    md.push_str("## Targets\n\n");
    for target in &assessment.targets {
        md.push_str(&format!("- {}\n", target));
    }
    md.push_str("\n");

    // Summary
    md.push_str("## Executive Summary\n\n");

    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();
    let info = findings.iter().filter(|f| f.severity == "info").count();

    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|-------|\n");
    md.push_str(&format!("| Critical | {} |\n", critical));
    md.push_str(&format!("| High | {} |\n", high));
    md.push_str(&format!("| Medium | {} |\n", medium));
    md.push_str(&format!("| Low | {} |\n", low));
    md.push_str(&format!("| Info | {} |\n", info));
    md.push_str("\n");

    // Findings
    md.push_str("## Findings\n\n");

    for (i, finding) in findings.iter().enumerate() {
        md.push_str(&format!("### {}. {} [{}]\n\n", i + 1, finding.title, finding.severity.to_uppercase()));
        md.push_str(&format!("**Target:** {}\n\n", finding.target));
        md.push_str(&format!("**Status:** {}\n\n", finding.status));

        if let Some(cvss) = finding.cvss_score {
            md.push_str(&format!("**CVSS Score:** {:.1}\n\n", cvss));
        }

        md.push_str("#### Description\n\n");
        md.push_str(&format!("{}\n\n", finding.description));

        if let Some(evidence) = &finding.evidence {
            md.push_str("#### Evidence\n\n");
            md.push_str(&format!("```\n{}\n```\n\n", evidence));
        }

        if let Some(remediation) = &finding.remediation {
            md.push_str("#### Remediation\n\n");
            md.push_str(&format!("{}\n\n", remediation));
        }

        md.push_str("---\n\n");
    }

    md
}

fn generate_html_report(
    assessment: &crate::database::Assessment,
    findings: &[crate::database::Finding],
) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
    html.push_str("<title>Security Assessment Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: Arial, sans-serif; margin: 40px; }\n");
    html.push_str("h1 { color: #333; }\n");
    html.push_str("table { border-collapse: collapse; width: 100%; }\n");
    html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    html.push_str(".critical { background-color: #dc3545; color: white; }\n");
    html.push_str(".high { background-color: #fd7e14; color: white; }\n");
    html.push_str(".medium { background-color: #ffc107; }\n");
    html.push_str(".low { background-color: #28a745; color: white; }\n");
    html.push_str(".info { background-color: #17a2b8; color: white; }\n");
    html.push_str("</style>\n");
    html.push_str("</head>\n<body>\n");

    html.push_str(&format!("<h1>Security Assessment Report: {}</h1>\n", assessment.name));
    html.push_str(&format!("<p><strong>Type:</strong> {}</p>\n", assessment.assessment_type));
    html.push_str(&format!("<p><strong>Status:</strong> {}</p>\n", assessment.status));

    html.push_str("<h2>Findings Summary</h2>\n");
    html.push_str("<table>\n<tr><th>Severity</th><th>Count</th></tr>\n");

    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();
    let low = findings.iter().filter(|f| f.severity == "low").count();
    let info = findings.iter().filter(|f| f.severity == "info").count();

    html.push_str(&format!("<tr class='critical'><td>Critical</td><td>{}</td></tr>\n", critical));
    html.push_str(&format!("<tr class='high'><td>High</td><td>{}</td></tr>\n", high));
    html.push_str(&format!("<tr class='medium'><td>Medium</td><td>{}</td></tr>\n", medium));
    html.push_str(&format!("<tr class='low'><td>Low</td><td>{}</td></tr>\n", low));
    html.push_str(&format!("<tr class='info'><td>Info</td><td>{}</td></tr>\n", info));
    html.push_str("</table>\n");

    html.push_str("<h2>Detailed Findings</h2>\n");

    for finding in findings {
        html.push_str(&format!(
            "<div class='finding'>\n<h3 class='{}'>{} [{}]</h3>\n",
            finding.severity, finding.title, finding.severity.to_uppercase()
        ));
        html.push_str(&format!("<p><strong>Target:</strong> {}</p>\n", finding.target));
        html.push_str(&format!("<p>{}</p>\n", finding.description));

        if let Some(remediation) = &finding.remediation {
            html.push_str(&format!("<p><strong>Remediation:</strong> {}</p>\n", remediation));
        }

        html.push_str("</div>\n<hr>\n");
    }

    html.push_str("</body>\n</html>");

    html
}

// translate_container_path / backfill_search_dirs / locate_report_file /
// backfill_report_artifact removed in cloud-only architecture.
// The MCP server uploads PDF bytes directly to the per-customer S3
// bucket at render time; there is no host-disk scavenge flow.
