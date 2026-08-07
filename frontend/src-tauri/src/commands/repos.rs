use crate::commands::config::get_integrations_config;
use crate::commands::findings::source_to_category;
use crate::database::{Database, Finding, Repository};
use crate::error::{AppError, Result};
use crate::mcp::McpClient;
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRepositoryParams {
    pub name: String,
    pub path: String,
    pub source_type: Option<String>,
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRepositoryParams {
    pub id: String,
    pub scan_types: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub repository_id: String,
    pub findings_count: i32,
    pub scan_duration_ms: u64,
    pub findings: Vec<CodeFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFinding {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub file_path: String,
    pub line_start: i32,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
    pub cwe: Option<String>,
    pub scanner: Option<String>,
}

#[tauri::command]
pub async fn list_repositories() -> Result<Vec<Repository>> {
    info!("Listing repositories");

    let db = Database::new()?;
    let repos = db.list_repositories()?;
    // Best-effort: keep the host-side repo registry in sync so the
    // in-container /assess slash command can resolve repo names to
    // container paths without needing a Tauri callback.
    if let Err(e) = write_repo_registry(&repos) {
        warn!("Failed to write repo registry: {e}");
    }
    Ok(repos)
}

/// Write `~/.kali-mcp-pentest/repo-registry.json` describing all configured
/// repositories with their container-side paths. The in-container `/assess`
/// slash command reads this file to resolve a profile's `repo_name` to a
/// path the SAST tools can scan, supporting both local-directory repos and
/// GitHub-attached repos (whose clones live in
/// ~/.kali-mcp-pentest/repo-cache/<owner>_<repo>/).
fn write_repo_registry(repos: &[Repository]) -> Result<()> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("home dir not resolvable".into()))?;
    let dir = home_dir.join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir)?;
    let cache_dir = dir.join("repo-cache");

    let entries: Vec<serde_json::Value> = repos
        .iter()
        .map(|r| {
            let host_path: std::path::PathBuf = if r.source_type == "github" {
                // Match the clone destination scan_repository writes to.
                cache_dir.join(format!(
                    "{}_{}",
                    r.github_owner.as_deref().unwrap_or("unknown"),
                    r.github_repo.as_deref().unwrap_or("repo")
                ))
            } else {
                std::path::PathBuf::from(&r.path)
            };

            let container_path = match host_path.strip_prefix(&home_dir) {
                Ok(rel) => format!("/mnt/host-home/{}", rel.display()),
                Err(_) => host_path.to_string_lossy().to_string(),
            };

            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "source_type": r.source_type,
                "host_path": host_path.to_string_lossy(),
                "container_path": container_path,
                "github_owner": r.github_owner,
                "github_repo": r.github_repo,
                "languages": r.languages,
            })
        })
        .collect();

    let body = serde_json::json!({
        "repos": entries,
        "writtenAt": chrono::Utc::now().to_rfc3339(),
    });

    let path = dir.join("repo-registry.json");
    let tmp = dir.join(format!(
        "repo-registry.json.tmp.{}.{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(&body)
            .map_err(|e| AppError::Other(format!("serialize repo registry: {e}")))?,
    )?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[tauri::command]
pub async fn get_repository(id: String) -> Result<Repository> {
    info!("Getting repository: {}", id);

    let db = Database::new()?;
    let repos = db.list_repositories()?;
    repos
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| AppError::NotFound(format!("Repository not found: {}", id)))
}

#[tauri::command]
pub async fn add_repository(params: AddRepositoryParams) -> Result<Repository> {
    info!("Adding repository: {} at {}", params.name, params.path);

    // Default new adds to GitHub since v0.1.57 — local-directory repos
    // were retired. Existing local rows in the SQLite still list/scan
    // via the legacy code paths, but no new ones can be created.
    let source_type = params.source_type.as_deref().unwrap_or("github");
    let mut languages = Vec::new();

    if source_type == "local" {
        return Err(AppError::Validation(
            "Local-directory repositories are no longer supported. \
             Push your code to a Git host (GitHub) and re-add it here \
             via the GitHub Repository tab."
                .to_string(),
        ));
    }

    // For GitHub repos, languages are detected later when cloned for scanning.
    // The local-detection branch was removed in v0.1.57 — local source type
    // is rejected above, so by here `source_type` is always "github".
    let _ = &mut languages; // keep `languages` mutable signature for call site

    let db = Database::new()?;
    db.add_repository(
        &params.name,
        &params.path,
        source_type,
        params.github_owner.as_deref(),
        params.github_repo.as_deref(),
        &languages,
    )
}

#[tauri::command]
pub async fn remove_repository(id: String) -> Result<()> {
    info!("Removing repository: {}", id);

    let db = Database::new()?;
    db.remove_repository(&id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRepositoryParams {
    pub name: Option<String>,
    pub path: Option<String>,
}

#[tauri::command]
pub async fn update_repository(id: String, params: UpdateRepositoryParams) -> Result<Repository> {
    info!("Updating repository: {}", id);

    let db = Database::new()?;

    // Get existing repository
    let repos = db.list_repositories()?;
    let existing = repos
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| AppError::NotFound(format!("Repository not found: {}", id)))?;

    let new_name = params.name.unwrap_or(existing.name);
    let path_changed = params.path.is_some();
    let new_path = params.path.unwrap_or(existing.path.clone());

    // If path changed, verify it exists and detect languages
    let languages = if path_changed {
        let path = std::path::Path::new(&new_path);
        if !path.exists() {
            return Err(AppError::Validation(format!("Path does not exist: {}", new_path)));
        }
        if !path.is_dir() {
            return Err(AppError::Validation(format!("Path is not a directory: {}", new_path)));
        }
        detect_languages(&new_path)?
    } else {
        existing.languages
    };

    db.update_repository(&id, &new_name, &new_path, &languages)
}

#[tauri::command]
pub async fn scan_repository(params: ScanRepositoryParams) -> Result<ScanResult> {
    info!("Scanning repository: {}", params.id);

    let db = Database::new()?;

    // Get the repository
    let repos = db.list_repositories()?;
    let repo = repos
        .into_iter()
        .find(|r| r.id == params.id)
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

    let home_dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Could not determine home directory".to_string()))?;

    // Determine the container path based on source type
    let container_path = if repo.source_type == "github" {
        // For GitHub repos, clone to a cache directory first
        let cache_dir = home_dir.join(".kali-mcp-pentest").join("repo-cache");
        std::fs::create_dir_all(&cache_dir)?;

        let clone_dir = cache_dir.join(format!(
            "{}_{}",
            repo.github_owner.as_deref().unwrap_or("unknown"),
            repo.github_repo.as_deref().unwrap_or("repo")
        ));

        // Clone or update the repository
        if clone_dir.exists() {
            // Refresh the cached clone to the latest upstream commit. The old
            // code ran `git pull --ff-only` and ignored the result, so a stale
            // shallow clone silently persisted — a months-old snapshot got
            // scanned (the groovysec run scanned a Feb-17 checkout). Fetch +
            // hard-reset to the remote HEAD instead, and log non-zero exits so a
            // stale scan is visible rather than silent.
            info!("Refreshing existing clone at {:?}", clone_dir);
            let fetched = Command::new("git")
                .args(["fetch", "--depth", "1", "origin", "HEAD"])
                .current_dir(&clone_dir)
                .output();
            match fetched {
                Ok(out) if out.status.success() => {
                    let reset = Command::new("git")
                        .args(["reset", "--hard", "FETCH_HEAD"])
                        .current_dir(&clone_dir)
                        .output();
                    match reset {
                        Ok(r) if r.status.success() => {
                            info!("Clone refreshed to latest origin HEAD at {:?}", clone_dir);
                        }
                        Ok(r) => info!(
                            "git reset failed for {:?} (using stale clone): {}",
                            clone_dir,
                            String::from_utf8_lossy(&r.stderr)
                        ),
                        Err(e) => info!("git reset error for {:?}: {} (stale clone)", clone_dir, e),
                    }
                }
                Ok(out) => info!(
                    "git fetch non-zero for {:?} (using stale clone): {}",
                    clone_dir,
                    String::from_utf8_lossy(&out.stderr)
                ),
                Err(e) => info!("git fetch error for {:?}: {} (stale clone)", clone_dir, e),
            }
        } else {
            // Clone the repository
            info!("Cloning repository to {:?}", clone_dir);

            // Get GitHub token from integrations config for private repos
            let integrations = get_integrations_config().await.ok();
            let github_token = integrations
                .as_ref()
                .and_then(|i| i.github.as_ref())
                .and_then(|g| g.personal_access_token.clone());

            let clone_url = if let Some(token) = github_token {
                // Use token for authentication
                format!(
                    "https://{}@github.com/{}/{}.git",
                    token,
                    repo.github_owner.as_deref().unwrap_or(""),
                    repo.github_repo.as_deref().unwrap_or("")
                )
            } else {
                // Public repo or no token
                format!(
                    "https://github.com/{}/{}.git",
                    repo.github_owner.as_deref().unwrap_or(""),
                    repo.github_repo.as_deref().unwrap_or("")
                )
            };

            let output = Command::new("git")
                .args(["clone", "--depth", "1", &clone_url])
                .arg(&clone_dir)
                .output()
                .map_err(|e| AppError::Other(format!("Failed to clone repository: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(AppError::Other(format!(
                    "Failed to clone repository: {}",
                    stderr
                )));
            }
        }

        // Convert to container path
        clone_dir
            .to_string_lossy()
            .replace(&home_dir.to_string_lossy().to_string(), "/mnt/host-home")
    } else {
        // Local repo - convert path to container path
        if repo.path.starts_with(home_dir.to_string_lossy().as_ref()) {
            repo.path
                .replace(&home_dir.to_string_lossy().to_string(), "/mnt/host-home")
        } else {
            repo.path.clone()
        }
    };

    // Check MCP availability
    let mcp = McpClient::new()?;
    if !mcp.health_check().await.unwrap_or(false) {
        return Err(AppError::ContainerNotRunning);
    }

    let start = std::time::Instant::now();

    // Run scan via MCP
    let scan_types = params
        .scan_types
        .as_ref()
        .map(|st| st.iter().map(|s| s.as_str()).collect());

    info!("Scanning container path: {}", container_path);
    let result = mcp.scan_repository(&container_path, scan_types).await?;
    let duration_ms = start.elapsed().as_millis() as u64;

    info!("MCP scan_repository success={}, duration={}ms", result.success, duration_ms);
    if let Some(ref rv) = result.result {
        // Log a truncated version of the result for debugging
        let json_str = serde_json::to_string(rv).unwrap_or_default();
        let preview = if json_str.len() > 2000 { &json_str[..2000] } else { &json_str };
        debug!("MCP scan result (truncated): {}", preview);
        // Log top-level keys
        if let Some(obj) = rv.as_object() {
            let keys: Vec<&String> = obj.keys().collect();
            info!("MCP scan result top-level keys: {:?}", keys);
        } else if let Some(arr) = rv.as_array() {
            info!("MCP scan result is an array with {} elements", arr.len());
            // Check if the first element has a "content" key (MCP protocol wrapping)
            if let Some(first) = arr.first() {
                if let Some(obj) = first.as_object() {
                    info!("First array element keys: {:?}", obj.keys().collect::<Vec<_>>());
                }
            }
        } else {
            info!("MCP scan result is neither object nor array: {}", rv);
        }
    } else {
        warn!("MCP scan result is None, error: {:?}", result.error);
    }

    // Parse findings from result — handle both naming conventions from MCP
    let findings: Vec<CodeFinding> = if let Some(result_value) = &result.result {
        if let Some(findings_array) = result_value.get("findings").and_then(|f| f.as_array()) {
            findings_array
                .iter()
                .filter_map(|f| {
                    let rule_id = f.get("rule_id").or_else(|| f.get("id"))
                        .and_then(|v| v.as_str())?.to_string();
                    let severity = f.get("severity")
                        .and_then(|v| v.as_str())?.to_string();
                    let message = f.get("message").or_else(|| f.get("description")).or_else(|| f.get("title"))
                        .and_then(|v| v.as_str())?.to_string();
                    let file_path = f.get("file_path").or_else(|| f.get("file"))
                        .and_then(|v| v.as_str())?.to_string();
                    let line_start = f.get("line_start").or_else(|| f.get("line"))
                        .and_then(|v| v.as_i64())? as i32;
                    let line_end = f.get("line_end").and_then(|v| v.as_i64()).map(|l| l as i32);
                    let code_snippet = f.get("code_snippet").and_then(|c| c.as_str()).map(String::from);
                    let cwe = f.get("cwe").and_then(|v| v.as_str()).map(String::from);
                    let scanner = f.get("scanner").and_then(|v| v.as_str()).map(String::from);

                    Some(CodeFinding {
                        rule_id,
                        severity,
                        message,
                        file_path,
                        line_start,
                        line_end,
                        code_snippet,
                        cwe,
                        scanner,
                    })
                })
                .collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    let findings_count = findings.len() as i32;

    // Persist findings to the database so they appear on the Findings page
    if !findings.is_empty() {
        info!("Saving {} findings to database for repo {}", findings_count, repo.name);
        for cf in &findings {
            let source = cf.scanner.as_deref().unwrap_or("semgrep").to_string();
            let category = source_to_category(&source).to_string();

            let evidence = if let Some(ref snippet) = cf.code_snippet {
                Some(format!("{}:{}\n{}", cf.file_path, cf.line_start, snippet))
            } else {
                Some(format!("{}:{}", cf.file_path, cf.line_start))
            };

            let finding = Finding {
                id: String::new(), // auto-generated
                assessment_id: None,
                title: format!("[{}] {}", cf.rule_id, cf.message.chars().take(120).collect::<String>()),
                severity: cf.severity.clone(),
                status: "open".to_string(),
                target: repo.name.clone(),
                description: cf.message.clone(),
                evidence,
                remediation: None,
                cvss_score: None,
                cve_ids: None,
                source: Some(source),
                category: Some(category),
                file_path: Some(cf.file_path.clone()),
                line_start: Some(cf.line_start),
                line_end: cf.line_end,
                code_snippet: cf.code_snippet.clone(),
                cwe: cf.cwe.clone(),
                created_at: String::new(),
                updated_at: String::new(),
                ..Default::default()
            };

            if let Err(e) = db.create_finding(&finding) {
                warn!("Failed to save finding {}: {}", cf.rule_id, e);
            }
        }
    }

    // Update repository record
    db.update_repository_scan(&params.id, findings_count)?;

    // Detect languages for GitHub repos (they skip detection at add time)
    if repo.source_type == "github" && repo.languages.is_empty() {
        let cache_dir = home_dir.join(".kali-mcp-pentest").join("repo-cache");
        let clone_dir = cache_dir.join(format!(
            "{}_{}",
            repo.github_owner.as_deref().unwrap_or("unknown"),
            repo.github_repo.as_deref().unwrap_or("repo")
        ));
        if clone_dir.exists() {
            if let Ok(languages) = detect_languages(&clone_dir.to_string_lossy()) {
                if !languages.is_empty() {
                    info!("Detected languages for {}: {:?}", repo.name, languages);
                    let _ = db.update_repository(&params.id, &repo.name, &repo.path, &languages);
                }
            }
        }
    }

    Ok(ScanResult {
        repository_id: params.id,
        findings_count,
        scan_duration_ms: duration_ms,
        findings,
    })
}

/// Detect programming languages in a repository
fn detect_languages(path: &str) -> Result<Vec<String>> {
    use std::collections::HashSet;

    let mut languages = HashSet::new();

    let extension_map = [
        ("rs", "Rust"),
        ("py", "Python"),
        ("js", "JavaScript"),
        ("ts", "TypeScript"),
        ("tsx", "TypeScript"),
        ("jsx", "JavaScript"),
        ("go", "Go"),
        ("java", "Java"),
        ("rb", "Ruby"),
        ("php", "PHP"),
        ("cs", "C#"),
        ("cpp", "C++"),
        ("c", "C"),
        ("h", "C"),
        ("swift", "Swift"),
        ("kt", "Kotlin"),
        ("scala", "Scala"),
        ("sh", "Shell"),
        ("bash", "Shell"),
        ("yml", "YAML"),
        ("yaml", "YAML"),
        ("json", "JSON"),
        ("sql", "SQL"),
        ("html", "HTML"),
        ("css", "CSS"),
        ("scss", "SCSS"),
    ];

    fn scan_dir(path: &std::path::Path, languages: &mut HashSet<String>, ext_map: &[(&str, &str)]) {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();

                // Skip common non-source directories
                if entry_path.is_dir() {
                    let dir_name = entry_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if !["node_modules", ".git", "target", "build", "dist", "__pycache__", ".venv", "venv"]
                        .contains(&dir_name)
                    {
                        scan_dir(&entry_path, languages, ext_map);
                    }
                } else if let Some(ext) = entry_path.extension().and_then(|e| e.to_str()) {
                    for (file_ext, lang) in ext_map {
                        if ext == *file_ext {
                            languages.insert(lang.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }

    scan_dir(std::path::Path::new(path), &mut languages, &extension_map);

    Ok(languages.into_iter().collect())
}
