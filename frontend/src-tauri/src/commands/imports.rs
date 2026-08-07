use crate::database::{Database, Import, ImportedFinding};
use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Parsed finding from CSV before import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedFinding {
    pub original_id: Option<String>,
    pub vulnerability_type: String,
    pub severity: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub code_snippet: Option<String>,
    pub description: String,
    pub remediation: Option<String>,
    pub cwe: Option<String>,
}

/// Result of CSV preview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewCsvResult {
    pub findings: Vec<ParsedFinding>,
    pub total_count: i32,
    pub errors: Vec<String>,
    pub column_mapping: ColumnMapping,
}

/// Result of CSV import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCsvResult {
    pub import: Import,
    pub imported_count: i32,
    pub errors: Vec<String>,
}

/// Column mapping detected from CSV headers
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ColumnMapping {
    pub id: Option<usize>,
    pub vulnerability_type: Option<usize>,
    pub severity: Option<usize>,
    pub file_path: Option<usize>,
    pub line_number: Option<usize>,
    pub code_snippet: Option<usize>,
    pub description: Option<usize>,
    pub remediation: Option<usize>,
    pub cwe: Option<usize>,
}

/// Parameters for listing imports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListImportsParams {
    pub source: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Parameters for listing imported findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListImportedFindingsParams {
    pub import_id: Option<String>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub repository_id: Option<String>,
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

/// Parameters for creating a validation assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateValidationAssessmentParams {
    pub finding_ids: Vec<String>,
    pub repository_id: Option<String>,
    pub name: Option<String>,
}

/// Parse CSV header to detect column mapping
fn detect_column_mapping(headers: &[&str]) -> ColumnMapping {
    let mut mapping = ColumnMapping::default();

    for (idx, header) in headers.iter().enumerate() {
        let header_lower = header.to_lowercase().trim().to_string();

        // ID column — match "id" standalone or as suffix (e.g., "finding_id", "ticket") but not "repository url"
        if (header_lower.contains("id") || header_lower.contains("ticket")) && !header_lower.contains("cwe") && !header_lower.contains("url") && !header_lower.contains("digest") {
            if mapping.id.is_none() {
                mapping.id = Some(idx);
            }
        }

        // Vulnerability type
        if header_lower.contains("type") || header_lower.contains("vuln") || header_lower.contains("category") || header_lower.contains("rule") {
            if mapping.vulnerability_type.is_none() {
                mapping.vulnerability_type = Some(idx);
            }
        }

        // Severity
        if header_lower.contains("severity") || header_lower.contains("risk") || header_lower.contains("priority") {
            if mapping.severity.is_none() {
                mapping.severity = Some(idx);
            }
        }

        // File path
        if header_lower.contains("file") || header_lower.contains("path") || header_lower.contains("location") {
            if !header_lower.contains("line") {
                if mapping.file_path.is_none() {
                    mapping.file_path = Some(idx);
                }
            }
        }

        // Line number
        if header_lower.contains("line") {
            if mapping.line_number.is_none() {
                mapping.line_number = Some(idx);
            }
        }

        // Code snippet
        if header_lower.contains("code") || header_lower.contains("snippet") || (header_lower.contains("source") && header_lower.contains("code")) {
            if mapping.code_snippet.is_none() {
                mapping.code_snippet = Some(idx);
            }
        }

        // Description
        if header_lower.contains("desc") || header_lower.contains("message") || header_lower.contains("detail") || header_lower.contains("title") || header_lower == "policy" {
            if mapping.description.is_none() {
                mapping.description = Some(idx);
            }
        }

        // Remediation
        if header_lower.contains("remed") || header_lower.contains("fix") || header_lower.contains("solution") || header_lower.contains("recommendation") {
            if mapping.remediation.is_none() {
                mapping.remediation = Some(idx);
            }
        }

        // CWE
        if header_lower.contains("cwe") {
            if mapping.cwe.is_none() {
                mapping.cwe = Some(idx);
            }
        }
    }

    mapping
}

/// Normalize severity string to standard values
fn normalize_severity(severity: &str) -> String {
    let lower = severity.to_lowercase().trim().to_string();

    if lower.contains("crit") {
        "critical".to_string()
    } else if lower.contains("high") || lower == "h" || lower == "3" {
        "high".to_string()
    } else if lower.contains("med") || lower == "m" || lower == "2" {
        "medium".to_string()
    } else if lower.contains("low") || lower == "l" || lower == "1" {
        "low".to_string()
    } else if lower.contains("info") || lower == "i" || lower == "0" {
        "info".to_string()
    } else {
        "medium".to_string() // Default to medium
    }
}

/// Parse CSV content into findings
fn parse_csv_content(csv_content: &str) -> std::result::Result<(Vec<ParsedFinding>, ColumnMapping, Vec<String>), String> {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    let lines: Vec<&str> = csv_content.lines().collect();
    if lines.is_empty() {
        return Err("CSV is empty".to_string());
    }

    // Parse headers (first line)
    let headers: Vec<&str> = lines[0].split(',').map(|s| s.trim().trim_matches('"')).collect();
    let mapping = detect_column_mapping(&headers);

    // Check for required columns
    if mapping.vulnerability_type.is_none() && mapping.description.is_none() {
        return Err("CSV must have at least a vulnerability type or description column".to_string());
    }

    // Parse data rows
    for (line_idx, line) in lines.iter().skip(1).enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        // Simple CSV parsing (handles quoted fields with commas)
        let fields = parse_csv_line(line);

        if fields.len() != headers.len() {
            errors.push(format!("Row {} has {} fields, expected {}", line_idx + 2, fields.len(), headers.len()));
            continue;
        }

        let get_field = |idx: Option<usize>| -> Option<String> {
            idx.and_then(|i| fields.get(i).map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
        };

        let vulnerability_type = get_field(mapping.vulnerability_type)
            .or_else(|| get_field(mapping.description))
            .unwrap_or_else(|| "Unknown".to_string());

        let description = get_field(mapping.description)
            .or_else(|| get_field(mapping.vulnerability_type))
            .unwrap_or_else(|| "No description".to_string());

        let severity = get_field(mapping.severity)
            .map(|s| normalize_severity(&s))
            .unwrap_or_else(|| "medium".to_string());

        let line_number = get_field(mapping.line_number)
            .and_then(|s| s.parse::<i32>().ok());

        findings.push(ParsedFinding {
            original_id: get_field(mapping.id),
            vulnerability_type,
            severity,
            file_path: get_field(mapping.file_path),
            line_number,
            code_snippet: get_field(mapping.code_snippet),
            description,
            remediation: get_field(mapping.remediation),
            cwe: get_field(mapping.cwe),
        });
    }

    Ok((findings, mapping, errors))
}

/// Parse a single CSV line handling quoted fields
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes {
                    // Check for escaped quote
                    if chars.peek() == Some(&'"') {
                        current_field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(current_field.trim().to_string());
                current_field = String::new();
            }
            _ => {
                current_field.push(c);
            }
        }
    }

    fields.push(current_field.trim().to_string());
    fields
}

// =========================================================================
// Tauri Commands
// =========================================================================

/// Preview CSV without importing
#[tauri::command]
pub async fn preview_csv(csv_content: String) -> Result<PreviewCsvResult> {
    info!("Previewing CSV content ({} bytes)", csv_content.len());

    let (findings, mapping, errors) = parse_csv_content(&csv_content)
        .map_err(|e| AppError::Validation(e))?;

    Ok(PreviewCsvResult {
        total_count: findings.len() as i32,
        findings,
        errors,
        column_mapping: mapping,
    })
}

/// Import CSV and save to database
#[tauri::command]
pub async fn import_csv(
    csv_content: String,
    name: Option<String>,
    source: Option<String>,
    filename: Option<String>,
    selected_indices: Option<Vec<usize>>,
) -> Result<ImportCsvResult> {
    info!("Importing CSV content ({} bytes)", csv_content.len());

    let (all_findings, _mapping, parse_errors) = parse_csv_content(&csv_content)
        .map_err(|e| AppError::Validation(e))?;

    // Filter to selected findings if indices provided
    let findings: Vec<ParsedFinding> = if let Some(indices) = selected_indices {
        indices.iter()
            .filter_map(|&i| all_findings.get(i).cloned())
            .collect()
    } else {
        all_findings
    };

    let db = Database::new()?;

    // Create import record
    let import_name = name.unwrap_or_else(|| {
        filename.as_ref()
            .map(|f| f.clone())
            .unwrap_or_else(|| format!("Import {}", chrono::Utc::now().format("%Y-%m-%d %H:%M")))
    });

    let import_source = source.unwrap_or_else(|| "csv".to_string());
    let import = db.create_import(&import_name, &import_source, filename.as_deref())?;

    // Create imported findings
    let mut import_errors: Vec<String> = parse_errors;
    let mut imported_count = 0;

    for finding in &findings {
        let imported_finding = ImportedFinding {
            id: String::new(),
            import_id: import.id.clone(),
            original_id: finding.original_id.clone(),
            vulnerability_type: finding.vulnerability_type.clone(),
            severity: finding.severity.clone(),
            file_path: finding.file_path.clone(),
            line_number: finding.line_number,
            code_snippet: finding.code_snippet.clone(),
            description: finding.description.clone(),
            remediation: finding.remediation.clone(),
            cwe: finding.cwe.clone(),
            status: "imported".to_string(),
            linked_finding_id: None,
            linked_assessment_id: None,
            repository_id: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        match db.create_imported_finding(&imported_finding) {
            Ok(_) => imported_count += 1,
            Err(e) => import_errors.push(format!("Failed to save finding: {}", e)),
        }
    }

    // Update import status
    let error_message = if import_errors.is_empty() {
        None
    } else {
        Some(import_errors.join("; "))
    };
    db.update_import_status(
        &import.id,
        "completed",
        Some(imported_count),
        error_message.as_deref(),
    )?;

    // Get updated import
    let updated_import = db.get_import(&import.id)?.unwrap_or(import);

    Ok(ImportCsvResult {
        import: updated_import,
        imported_count,
        errors: import_errors,
    })
}

/// List all imports
#[tauri::command]
pub async fn list_imports(params: Option<ListImportsParams>) -> Result<Vec<Import>> {
    info!("Listing imports");

    let db = Database::new()?;
    let params = params.unwrap_or_default();

    db.list_imports(
        params.source.as_deref(),
        params.limit,
        params.offset,
    )
}

impl Default for ListImportsParams {
    fn default() -> Self {
        Self {
            source: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}

/// Get a single import by ID
#[tauri::command]
pub async fn get_import(id: String) -> Result<Option<Import>> {
    info!("Getting import: {}", id);

    let db = Database::new()?;
    db.get_import(&id)
}

/// Delete an import and all its findings
#[tauri::command]
pub async fn delete_import(id: String) -> Result<()> {
    info!("Deleting import: {}", id);

    let db = Database::new()?;
    db.delete_import(&id)
}

/// List imported findings
#[tauri::command]
pub async fn list_imported_findings(params: Option<ListImportedFindingsParams>) -> Result<Vec<ImportedFinding>> {
    info!("Listing imported findings");

    let db = Database::new()?;
    let params = params.unwrap_or_default();

    db.list_imported_findings(
        params.import_id.as_deref(),
        params.status.as_deref(),
        params.severity.as_deref(),
        params.repository_id.as_deref(),
        params.limit,
        params.offset,
    )
}

impl Default for ListImportedFindingsParams {
    fn default() -> Self {
        Self {
            import_id: None,
            status: None,
            severity: None,
            repository_id: None,
            limit: Some(100),
            offset: Some(0),
        }
    }
}

/// Get a single imported finding by ID
#[tauri::command]
pub async fn get_imported_finding(id: String) -> Result<Option<ImportedFinding>> {
    info!("Getting imported finding: {}", id);

    let db = Database::new()?;
    db.get_imported_finding(&id)
}

/// Update imported finding status
#[tauri::command]
pub async fn update_imported_finding_status(
    id: String,
    status: String,
    linked_finding_id: Option<String>,
    linked_assessment_id: Option<String>,
) -> Result<()> {
    info!("Updating imported finding status: {} -> {}", id, status);

    let db = Database::new()?;
    db.update_imported_finding_status(
        &id,
        &status,
        linked_finding_id.as_deref(),
        linked_assessment_id.as_deref(),
    )
}

/// Link imported findings to a repository
#[tauri::command]
pub async fn link_findings_to_repository(finding_ids: Vec<String>, repository_id: String) -> Result<()> {
    info!("Linking {} findings to repository {}", finding_ids.len(), repository_id);

    let db = Database::new()?;
    for id in finding_ids {
        db.link_imported_finding_to_repository(&id, &repository_id)?;
    }
    Ok(())
}

/// Get import statistics
#[tauri::command]
pub async fn get_import_stats() -> Result<serde_json::Value> {
    info!("Getting import statistics");

    let db = Database::new()?;
    db.get_import_stats()
}

/// Create a validation assessment for imported findings
#[tauri::command]
pub async fn create_validation_assessment(params: CreateValidationAssessmentParams) -> Result<crate::database::Assessment> {
    info!("Creating validation assessment for {} findings", params.finding_ids.len());

    let db = Database::new()?;

    // Get the imported findings
    let mut targets = Vec::new();
    for id in &params.finding_ids {
        if let Some(finding) = db.get_imported_finding(id)? {
            // Add file paths as targets
            if let Some(file_path) = &finding.file_path {
                if !targets.contains(file_path) {
                    targets.push(file_path.clone());
                }
            }

            // Update status to validating
            db.update_imported_finding_status(
                id,
                "validating",
                None,
                None,
            )?;
        }
    }

    // Create assessment
    let assessment_name = params.name.unwrap_or_else(|| {
        format!("Validation Assessment - {}", chrono::Utc::now().format("%Y-%m-%d %H:%M"))
    });

    let options = serde_json::json!({
        "type": "import_validation",
        "finding_ids": params.finding_ids,
        "repository_id": params.repository_id,
    });

    let assessment = db.create_assessment(
        &assessment_name,
        "import_validation",
        &targets,
        Some(options),
    )?;

    // Link findings to assessment
    for id in &params.finding_ids {
        db.update_imported_finding_status(
            id,
            "validating",
            None,
            Some(&assessment.id),
        )?;
    }

    Ok(assessment)
}
