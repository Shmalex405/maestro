//! Copy engine results into the desktop's database (local mode).
//!
//! The engine (MCP server in the Kali container) keeps its own SQLite DB on a
//! Docker volume; the desktop is the only process that writes
//! `~/.pentest/data/pentest.db`. Two writers on one SQLite file across the
//! Docker Desktop host/VM file share is unsafe (WAL cannot be used, and
//! rollback-journal locks are not shared), so instead the desktop pulls the
//! engine's findings and reports over its HTTP API and upserts them here.
//!
//! Sync is best-effort and idempotent: rows are keyed by the engine's ids, a
//! failed pull logs a warning and leaves the desktop DB unchanged, and the
//! next list/complete call simply tries again.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use tracing::{info, warn};

use crate::database::{Database, EngineFinding, EngineReport};
use crate::error::{AppError, Result};

/// The engine's REST API, published by the container on loopback only.
const ENGINE_API: &str = "http://127.0.0.1:3001/api";

/// Container path of the writable bind into `~/.kali-mcp-pentest` on the host.
const CONTAINER_CONFIG_PREFIX: &str = "/mnt/host-home/.kali-mcp-pentest/";

#[derive(Deserialize)]
struct ListResponse<T> {
    data: Vec<T>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SyncStats {
    pub findings: usize,
    pub reports: usize,
    /// Engine-sourced findings removed because the engine deleted them.
    pub removed: usize,
}

/// Map an engine file path (a container path) to where that file lives on
/// this machine. Only files under the writable `~/.kali-mcp-pentest` bind are
/// reachable from the host; anything else (e.g. container-only temp paths)
/// maps to `None` rather than a path that would not open.
fn host_path_for(container_path: &str) -> Option<String> {
    let rest = container_path.strip_prefix(CONTAINER_CONFIG_PREFIX)?;
    // Never let a `..` segment walk out of the config dir.
    if rest.split('/').any(|seg| seg == "..") {
        return None;
    }
    let mut path: PathBuf = dirs::home_dir()?.join(".kali-mcp-pentest");
    for seg in rest.split('/').filter(|s| !s.is_empty()) {
        path.push(seg);
    }
    Some(path.to_string_lossy().into_owned())
}

async fn fetch<T: for<'de> Deserialize<'de>>(client: &reqwest::Client, url: &str) -> Result<Vec<T>> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| AppError::Other(format!("engine request {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::Other(format!("engine request {url}: HTTP {}", resp.status())));
    }
    let body: ListResponse<T> = resp
        .json()
        .await
        .map_err(|e| AppError::Other(format!("engine response {url}: {e}")))?;
    Ok(body.data)
}

/// Pull one assessment's findings and reports from the engine and upsert them.
pub async fn sync_assessment(assessment_id: &str) -> Result<SyncStats> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| AppError::Other(format!("http client: {e}")))?;
    let id = urlencoding_path(assessment_id);
    let findings: Vec<EngineFinding> =
        fetch(&client, &format!("{ENGINE_API}/findings/assessment/{id}")).await?;
    let reports: Vec<EngineReport> =
        fetch(&client, &format!("{ENGINE_API}/reports/assessment/{id}")).await?;
    // Findings the engine deleted (by any path: clear_findings, the API, ...).
    // Applied by id, never inferred from absence — an empty or replaced
    // engine database must not wipe the desktop's copies.
    let deleted: Vec<String> = fetch(&client, &format!("{ENGINE_API}/findings/deleted")).await?;

    // All network I/O is done; now touch the DB (the connection is not held
    // across an await).
    let db = Database::new()?;
    for f in &findings {
        db.upsert_engine_finding(assessment_id, f)?;
    }
    for r in &reports {
        let host_path = r.file_path.as_deref().and_then(host_path_for);
        db.upsert_engine_report(r, host_path.as_deref())?;
    }
    let removed = db.delete_engine_findings(&deleted)?;
    let stats = SyncStats { findings: findings.len(), reports: reports.len(), removed };
    if stats.findings > 0 || stats.reports > 0 || stats.removed > 0 {
        info!(
            "engine sync {assessment_id}: {} findings, {} reports, {} removed",
            stats.findings, stats.reports, stats.removed
        );
    }
    Ok(stats)
}

/// How many recent assessments an unfiltered list (the Findings or Reports
/// page) syncs. Completed runs are included: an agent can still add a report
/// or clear findings after the run is marked completed.
const RECENT_ASSESSMENTS_TO_SYNC: u32 = 25;

/// Sync one assessment, or the most recent ones when `assessment_id` is None.
/// Never fails the caller: errors are logged and the desktop DB is left as is.
pub async fn sync_best_effort(assessment_id: Option<&str>) {
    if !crate::commands::self_host::is_local_deployment() {
        return;
    }
    let ids: Vec<String> = match assessment_id {
        Some(id) => vec![id.to_string()],
        None => match Database::new().and_then(|db| db.recent_assessment_ids(RECENT_ASSESSMENTS_TO_SYNC)) {
            Ok(ids) => ids,
            Err(e) => {
                warn!("engine sync: could not list recent assessments: {e}");
                return;
            }
        },
    };
    for id in ids {
        if let Err(e) = sync_assessment(&id).await {
            warn!("engine sync {id} skipped: {e}");
        }
    }
}

/// Percent-encode an id for use as one URL path segment.
fn urlencoding_path(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_reports_dir_to_host() {
        let p = host_path_for("/mnt/host-home/.kali-mcp-pentest/reports/abc/r.pdf").unwrap();
        assert!(p.ends_with(&format!(
            ".kali-mcp-pentest{0}reports{0}abc{0}r.pdf",
            std::path::MAIN_SEPARATOR
        )));
    }

    #[test]
    fn rejects_paths_outside_the_bind() {
        assert!(host_path_for("/opt/pentest/output/r.pdf").is_none());
        assert!(host_path_for("/mnt/host-home/.kali-mcp-pentest/../.ssh/id_rsa").is_none());
    }

    #[test]
    fn encodes_path_segment() {
        assert_eq!(urlencoding_path("eb860fc5-8f24"), "eb860fc5-8f24");
        assert_eq!(urlencoding_path("a/b c"), "a%2Fb%20c");
    }
}
