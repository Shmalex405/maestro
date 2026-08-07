// Per-user repo path mappings (item #6 — repository path split with provenance).
//
// Cloud `repositories` rows hold the org-shared metadata: name, description,
// languages, default_scan_config, plus a `default_path` field that stores
// the creator's clone path as a hint. Each user's actual local clone may be
// at a different filesystem path (Alice clones to `~/work/foo`, Bob to
// `~/dev/foo`), so we keep a per-machine override mapping that the desktop
// resolves at render time.
//
// Storage: ~/.kali-mcp-pentest/repo-paths.json — flat `{repo_id: local_path}`.
// Tiny file (kilobytes even with hundreds of repos), atomic-rename writes,
// no migration needed.
//
// The Tauri side just reads/writes the file. The desktop's `tauri-api.ts`
// wrappers around `repositories.list / get / add` merge cloud + local
// before handing the row to UI components, so callers see one consistent
// `Repository.path` field.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{AppError, Result};

const FILE: &str = "repo-paths.json";

fn paths_file() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| AppError::Config("Home directory not resolvable".into()))?
        .join(".kali-mcp-pentest");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(FILE))
}

fn load() -> Result<HashMap<String, String>> {
    let path = paths_file()?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&raw).unwrap_or_default())
}

fn save(map: &HashMap<String, String>) -> Result<()> {
    let path = paths_file()?;
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(map)
        .map_err(|e| AppError::Other(format!("serialize repo-paths: {e}")))?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Return the full {repo_id: local_path} mapping. Used by the frontend
/// to merge with the cloud `repositories` list in one call rather than
/// asking per-row.
#[tauri::command]
pub async fn get_local_repo_paths() -> Result<HashMap<String, String>> {
    load()
}

/// Set or clear the local path for a single repo. Pass `path = None` to
/// remove the override (the UI will fall back to the cloud `default_path`).
#[tauri::command]
pub async fn set_local_repo_path(repo_id: String, path: Option<String>) -> Result<()> {
    let mut map = load()?;
    match path {
        Some(p) if !p.is_empty() => {
            map.insert(repo_id, p);
        }
        _ => {
            map.remove(&repo_id);
        }
    }
    save(&map)
}
