use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::cloud::{AssessmentSync, FindingSync, ReportSync};
use crate::commands::terminal::TerminalSession;
use crate::error::{AppError, Result};

/// SQL CASE expression to derive finding category from source when category is NULL.
/// Uses LIKE patterns to match agent-prefixed source values (e.g. "recon-infra-agent (...)").
const CATEGORY_FROM_SOURCE_SQL: &str = r#"CASE
    /* --- Step 1: Derive from source (exact match) — source indicates testing phase --- */
    WHEN f.source IN ('nuclei', 'nikto', 'wpscan', 'searchsploit', 'nmap') THEN 'vuln_scan'
    WHEN f.source IN ('sqlmap', 'xss-test', 'ffuf', 'crawler', 'dalfox', 'manual', 'test_cors', 'test_ssrf', 'test_ssti', 'test_xss', 'test_http_smuggling', 'test_race_condition', 'test_cache_poisoning', 'test_websocket', 'test_file_upload', 'test_deserialization', 'test_session_fixation', 'test_session_management', 'test_password_policy', 'test_idor', 'test_graphql_security', 'fuzz_api_schema', 'test_api_rate_limiting', 'web-security', 'web-app', 'api-graphql', 'api-security') THEN 'web_app'
    WHEN f.source IN ('semgrep', 'bandit', 'njsscan', 'gitleaks', 'trufflehog', 'grype', 'safety', 'checkov', 'trivy', 'scan_secrets', 'scan_dependencies', 'scan_iac', 'scan_semgrep', 'scan_bandit', 'scan_njsscan', 'sast-scan', 'sast-analysis', 'sast', 'cycode', 'cycode-validation', 'defense-analysis') THEN 'code_security'
    WHEN f.source IN ('metasploit', 'custom-exploit', 'exploit') THEN 'vuln_scan'
    WHEN f.source IN ('scan_ssl_tls', 'check_certificate', 'scan_ssl_ciphers', 'check_dns_records', 'check_dnssec', 'test_zone_transfer', 'detect_subdomain_takeover', 'test_cloud_metadata', 'check_s3_bucket', 'scan_ports', 'discover_hosts', 'enumerate_subdomains', 'analyze_defenses', 'ssltls', 'dns-check', 'web_technology_scan') THEN 'infrastructure'
    /* --- Step 3: Derive from source (prefix/LIKE match for compound names) --- */
    WHEN f.source LIKE 'nuclei%' OR f.source LIKE 'nikto%' OR f.source LIKE 'nmap%' THEN 'vuln_scan'
    WHEN f.source LIKE 'semgrep%' OR f.source LIKE 'gitleaks%' OR f.source LIKE 'grype%' OR f.source LIKE 'bandit%' OR f.source LIKE 'njsscan%' OR f.source LIKE 'trivy%' OR f.source LIKE 'checkov%' OR f.source LIKE 'trufflehog%' OR f.source LIKE 'safety%' THEN 'code_security'
    WHEN f.source LIKE 'metasploit%' OR f.source LIKE 'exploit%' THEN 'vuln_scan'
    WHEN f.source LIKE 'chain%' THEN 'web_app'
    WHEN f.source LIKE 'recon%' THEN 'infrastructure'
    WHEN f.source LIKE 'crossval%' OR f.source LIKE 'qa%' THEN 'vuln_scan'
    WHEN f.source LIKE 'web%' THEN 'web_app'
    WHEN f.source LIKE 'sast%' OR f.source LIKE 'code%' THEN 'code_security'
    WHEN f.source LIKE 'api%' THEN 'web_app'
    WHEN f.source LIKE 'manual-api%' OR f.source LIKE 'manual-graphql%' THEN 'web_app'
    WHEN f.source LIKE 'manual-js%' THEN 'code_security'
    WHEN f.source LIKE 'manual%' THEN 'web_app'
    /* --- Step 4: Fall back to stored category if source didn't match --- */
    WHEN f.category IN ('vuln_scan', 'web_app', 'code_security', 'infrastructure') THEN f.category
    WHEN f.category IN ('api-security', 'data-exposure', 'info-disclosure', 'authentication') THEN 'web_app'
    WHEN f.category IN ('code-quality', 'secrets', 'supply-chain', 'cicd') THEN 'code_security'
    WHEN f.category IN ('compliance', 'configuration', 'info') THEN 'infrastructure'
    ELSE 'infrastructure' END"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub assessment_type: String,
    pub targets: Vec<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub options: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub progress: i32,
    pub current_step: Option<String>,
    pub findings_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Finding {
    pub id: String,
    pub assessment_id: Option<String>,
    pub title: String,
    pub severity: String,
    pub status: String,
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
    pub created_at: String,
    pub updated_at: String,

    // ── Parity columns ──────────────────────────────────────────────────────
    // Added so LOCAL mode is a smaller product, not a degraded one. Without
    // these, a local install silently loses severity calibration and the
    // exploitable filter — the two things that make a findings list worth
    // reading. All Option/default so existing rows and existing create_finding
    // callers (the MCP server writes findings during a run) are unaffected.
    #[serde(default)]
    pub exploitable: Option<String>,
    #[serde(default)]
    pub original_severity: Option<String>,
    #[serde(default)]
    pub calibrated_severity: Option<String>,
    #[serde(default)]
    pub calibration_rule: Option<String>,
    #[serde(default)]
    pub calibration_justification: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub jira_ticket: Option<String>,
    #[serde(default)]
    pub jira_url: Option<String>,
    #[serde(default)]
    pub validated_at: Option<String>,
    #[serde(default)]
    pub validation_method: Option<String>,
    #[serde(default)]
    pub source_tool: Option<String>,
    #[serde(default)]
    pub evidence_type: Option<String>,
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub target: Option<String>,
    pub command: Option<String>,
    pub result: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub id: String,
    pub name: String,
    pub source: String, // "cycode", "csv", "manual"
    pub filename: Option<String>,
    pub findings_count: i32,
    pub status: String, // "pending", "processing", "completed", "failed"
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFinding {
    pub id: String,
    pub import_id: String,
    pub original_id: Option<String>, // Original ID from source (e.g., Cycode ID)
    pub vulnerability_type: String,
    pub severity: String,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub code_snippet: Option<String>,
    pub description: String,
    pub remediation: Option<String>,
    pub cwe: Option<String>,
    pub status: String, // "imported", "validating", "confirmed", "false_positive"
    pub linked_finding_id: Option<String>, // Link to validated finding in findings table
    pub linked_assessment_id: Option<String>, // Link to validation assessment
    pub repository_id: Option<String>, // Link to repository for context
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub id: String,
    pub name: String,
    pub path: String,
    pub container_path: String, // Path inside Kali container (/mnt/host-home/...)
    pub source_type: String,    // "local" or "github"
    pub github_owner: Option<String>,
    pub github_repo: Option<String>,
    pub languages: Vec<String>,
    pub last_scanned: Option<String>,
    pub findings_count: i32,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub assessment_id: Option<String>,
    pub repository_id: Option<String>,
    pub context_summary: Option<String>,
    pub is_archived: bool,
    pub message_count: i32,
    pub last_message_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String, // "active", "archived"
    pub assessment_count: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub role: String,
    pub content: String,
    pub timestamp: String,
    pub tool_calls: Option<String>,       // JSON array
    pub findings_created: Option<String>, // JSON array
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentChatMessage {
    pub id: String,
    pub msg_type: String,      // "welcome" | "user" | "terminal" | "system" | "findings"
    pub content: Option<String>,
    pub variant: Option<String>, // For system messages: "info" | "success" | "warning" | "error"
    pub session_key: Option<String>, // For terminal messages
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub id: String,
    pub assessment_id: String,
    pub target: String,
    pub scanned_at: String,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub info_count: i32,
    pub total_count: i32,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self> {
        let db_path = Self::get_db_path()?;

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)
            .map_err(|e| AppError::Database(e))?;

        // Set busy timeout for concurrent access (MCP server may also be writing)
        conn.execute_batch("PRAGMA busy_timeout = 5000;")
            .map_err(|e| AppError::Database(e))?;

        let db = Self { conn };
        db.initialize_schema()?;

        Ok(db)
    }

    /// Deep health check used by the System Status panel. Goes beyond "the
    /// file opened" (which `new()` already implies): runs a real query AND
    /// confirms the schema was actually created. A corrupt/locked DB or a
    /// failed migration can still let `Connection::open` succeed, so the
    /// open handle alone is not proof the database is usable.
    pub fn health_check(&self) -> bool {
        self.conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|table_count| table_count > 0)
            .unwrap_or(false)
    }

    fn get_db_path() -> Result<PathBuf> {
        // Priority: 1. DB_PATH env var, 2. config/database.yml, 3. default ~/.pentest/data/pentest.db

        // 1. Check environment variable
        if let Ok(db_path) = std::env::var("DB_PATH") {
            return Ok(Self::expand_path(&db_path));
        }

        // 2. Try to read from config file
        let config_paths = vec![
            // Development: relative to project root
            PathBuf::from("../../../config/database.yml"),
            PathBuf::from("../../config/database.yml"),
            PathBuf::from("config/database.yml"),
            // Production: relative to executable
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("../config/database.yml")))
                .unwrap_or_default(),
        ];

        for config_path in config_paths {
            if config_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    if let Ok(config) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        if let Some(path) = config.get("path").and_then(|v| v.as_str()) {
                            tracing::info!("Using database path from config: {}", path);
                            return Ok(Self::expand_path(path));
                        }
                    }
                }
            }
        }

        // 3. Default path: ~/.pentest/data/pentest.db
        let default_path = Self::expand_path("~/.pentest/data/pentest.db");
        tracing::info!("Using default database path: {:?}", default_path);
        Ok(default_path)
    }

    /// Expand ~ to home directory
    fn expand_path(path: &str) -> PathBuf {
        if path.starts_with("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(&path[2..]);
            }
        } else if path.starts_with("~") {
            if let Some(home) = dirs::home_dir() {
                return home.join(&path[1..]);
            }
        }
        PathBuf::from(path)
    }

    fn initialize_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                assessment_type TEXT NOT NULL,
                targets TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                options TEXT,
                error_message TEXT,
                progress INTEGER DEFAULT 0,
                current_step TEXT,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                assessment_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                target TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT,
                remediation TEXT,
                cvss_score REAL,
                cve_ids TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                name TEXT NOT NULL,
                format TEXT NOT NULL,
                content TEXT,
                file_path TEXT,
                created_at TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                exploitable_count INTEGER DEFAULT 0,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                command TEXT,
                result TEXT,
                user TEXT
            );

            CREATE TABLE IF NOT EXISTS repositories (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL DEFAULT 'local',
                github_owner TEXT,
                github_repo TEXT,
                languages TEXT,
                last_scanned TEXT,
                findings_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

            -- Import tracking tables
            CREATE TABLE IF NOT EXISTS imports (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                filename TEXT,
                findings_count INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS imported_findings (
                id TEXT PRIMARY KEY,
                import_id TEXT NOT NULL,
                original_id TEXT,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                file_path TEXT,
                line_number INTEGER,
                code_snippet TEXT,
                description TEXT NOT NULL,
                remediation TEXT,
                cwe TEXT,
                status TEXT NOT NULL DEFAULT 'imported',
                linked_finding_id TEXT,
                linked_assessment_id TEXT,
                repository_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (import_id) REFERENCES imports(id),
                FOREIGN KEY (linked_finding_id) REFERENCES findings(id),
                FOREIGN KEY (linked_assessment_id) REFERENCES assessments(id),
                FOREIGN KEY (repository_id) REFERENCES repositories(id)
            );

            CREATE INDEX IF NOT EXISTS idx_imports_source ON imports(source);
            CREATE INDEX IF NOT EXISTS idx_imports_status ON imports(status);
            CREATE INDEX IF NOT EXISTS idx_imports_created_at ON imports(created_at);
            CREATE INDEX IF NOT EXISTS idx_imported_findings_import ON imported_findings(import_id);
            CREATE INDEX IF NOT EXISTS idx_imported_findings_severity ON imported_findings(severity);
            CREATE INDEX IF NOT EXISTS idx_imported_findings_status ON imported_findings(status);
            CREATE INDEX IF NOT EXISTS idx_imported_findings_repository ON imported_findings(repository_id);

            -- Chat conversations table
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                assessment_id TEXT,
                repository_id TEXT,
                context_summary TEXT,
                is_archived INTEGER DEFAULT 0,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id),
                FOREIGN KEY (repository_id) REFERENCES repositories(id)
            );

            -- Chat messages table
            CREATE TABLE IF NOT EXISTS chat_messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                tool_calls TEXT,
                findings_created TEXT,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_conversations_updated_at ON conversations(updated_at);
            CREATE INDEX IF NOT EXISTS idx_conversations_archived ON conversations(is_archived);
            CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id, timestamp);

            -- Projects table for grouping assessments
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status);
            CREATE INDEX IF NOT EXISTS idx_projects_updated_at ON projects(updated_at);

            -- Terminal sessions table for PTY session tracking
            CREATE TABLE IF NOT EXISTS terminal_sessions (
                id TEXT PRIMARY KEY,
                assessment_id TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                command TEXT NOT NULL,
                created_at TEXT NOT NULL,
                ended_at TEXT,
                exit_code INTEGER,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            );

            CREATE INDEX IF NOT EXISTS idx_terminal_sessions_status ON terminal_sessions(status);
            CREATE INDEX IF NOT EXISTS idx_terminal_sessions_assessment ON terminal_sessions(assessment_id);

            -- Assessment chat messages for the chat-wrapped terminal UI
            CREATE TABLE IF NOT EXISTS assessment_chat_messages (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                content TEXT,
                variant TEXT,
                session_key TEXT,
                timestamp TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_acm_assessment ON assessment_chat_messages(assessment_id, sort_order);

            -- Scan snapshots for tracking findings per scan run
            CREATE TABLE IF NOT EXISTS scan_snapshots (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                target TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                total_count INTEGER DEFAULT 0,
                FOREIGN KEY (assessment_id) REFERENCES assessments(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scan_snapshots_target ON scan_snapshots(target);
            CREATE INDEX IF NOT EXISTS idx_scan_snapshots_assessment ON scan_snapshots(assessment_id);

            -- Junction table linking snapshots to their findings
            CREATE TABLE IF NOT EXISTS snapshot_findings (
                snapshot_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, finding_id),
                FOREIGN KEY (snapshot_id) REFERENCES scan_snapshots(id),
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );
            "#,
        ).map_err(|e| AppError::Database(e))?;

        // Migration: Add sync support columns if they don't exist
        self.migrate_sync_columns()?;

        // Migration: bring the local findings table to parity with the cloud
        // finding shape, so local mode keeps calibration + triage metadata.
        self.migrate_finding_parity_columns()?;

        Ok(())
    }

    /// Columns the local findings table needs to represent a full finding.
    ///
    /// The local DB predates severity calibration, the exploitable filter, and
    /// Jira/validation provenance, all of which the cloud schema carries. Local
    /// mode reads through this table, so without these columns a local install
    /// would show uncalibrated severities and no exploitable filter.
    ///
    /// Same idiom as `migrate_sync_columns`: discard the error, because SQLite
    /// has no ADD COLUMN IF NOT EXISTS and a duplicate-column error is the
    /// expected outcome on every boot after the first.
    fn migrate_finding_parity_columns(&self) -> Result<()> {
        for col in [
            "exploitable TEXT",
            "original_severity TEXT",
            "calibrated_severity TEXT",
            "calibration_rule TEXT",
            "calibration_justification TEXT",
            "tags TEXT",
            "jira_ticket TEXT",
            "jira_url TEXT",
            "validated_at TEXT",
            "validation_method TEXT",
            "source_tool TEXT",
            "evidence_type TEXT",
        ] {
            let _ = self
                .conn
                .execute(&format!("ALTER TABLE findings ADD COLUMN {col}"), []);
        }

        // The findings table is filtered by exploitable in the workbench.
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_exploitable ON findings(exploitable)",
            [],
        );

        Ok(())
    }

    fn migrate_sync_columns(&self) -> Result<()> {
        // Add server_id to assessments
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN server_id TEXT",
            [],
        );

        // Add server_id to findings
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN server_id TEXT",
            [],
        );

        // Add server_id and updated_at to reports
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN server_id TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN updated_at TEXT",
            [],
        );

        // Create indexes for server_id lookups
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessments_server_id ON assessments(server_id)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_server_id ON findings(server_id)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_server_id ON reports(server_id)",
            [],
        );

        // Create indexes for updated_at for sync queries
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessments_updated_at ON assessments(updated_at)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_updated_at ON findings(updated_at)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_updated_at ON reports(updated_at)",
            [],
        );

        // Migration: Add GitHub support columns to repositories
        let _ = self.conn.execute(
            "ALTER TABLE repositories ADD COLUMN source_type TEXT NOT NULL DEFAULT 'local'",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE repositories ADD COLUMN github_owner TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE repositories ADD COLUMN github_repo TEXT",
            [],
        );

        // Migration: Add assessment tracking columns
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN error_message TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN progress INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN current_step TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN findings_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN critical_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN high_count INTEGER DEFAULT 0",
            [],
        );

        // Migration: Add report tracking columns
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN content TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN findings_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN critical_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN high_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN exploitable_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN medium_count INTEGER DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN low_count INTEGER DEFAULT 0",
            [],
        );

        // Migration: Add project_id to assessments for project grouping
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN project_id TEXT REFERENCES projects(id)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessments_project ON assessments(project_id)",
            [],
        );

        // =========================================================================
        // MCP-specific columns (for unified database compatibility)
        // =========================================================================

        // Findings: MCP deduplication and tracking columns
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN fingerprint TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN vulnerability_type TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN source TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN first_seen_at TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN last_seen_at TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN occurrence_count INTEGER DEFAULT 1",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN cve TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN cycode_ref TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN jira_ticket TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN category TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN file_path TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN line_start INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN line_end INTEGER",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN code_snippet TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE findings ADD COLUMN cwe TEXT",
            [],
        );

        // Create fingerprint index for deduplication
        let _ = self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source)",
            [],
        );

        // MCP junction tables
        let _ = self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS assessment_findings (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                source TEXT,
                evidence_snapshot TEXT,
                discovered_at TEXT NOT NULL,
                UNIQUE(assessment_id, finding_id)
            );

            CREATE INDEX IF NOT EXISTS idx_assessment_findings_assessment ON assessment_findings(assessment_id);
            CREATE INDEX IF NOT EXISTS idx_assessment_findings_finding ON assessment_findings(finding_id);

            CREATE TABLE IF NOT EXISTS finding_evidence (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                source TEXT NOT NULL,
                assessment_id TEXT,
                evidence_content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence(finding_id);

            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                scope_snapshot TEXT,
                status TEXT DEFAULT 'running',
                findings_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                tool TEXT NOT NULL,
                target TEXT,
                arguments TEXT,
                user TEXT,
                session_id TEXT,
                result_status TEXT,
                execution_time_ms INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool);
            "#
        );

        // Assessments: MCP-specific columns
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN type TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN repo_paths TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN credential_app TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN jira_project TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN email_recipients TEXT",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE assessments ADD COLUMN severity_threshold TEXT DEFAULT 'medium'",
            [],
        );

        // Sync 'type' with 'assessment_type' for compatibility
        let _ = self.conn.execute(
            "UPDATE assessments SET type = assessment_type WHERE type IS NULL AND assessment_type IS NOT NULL",
            [],
        );
        let _ = self.conn.execute(
            "UPDATE assessments SET assessment_type = type WHERE assessment_type IS NULL AND type IS NOT NULL",
            [],
        );

        // Migration: Add transcript column to terminal_sessions
        let _ = self.conn.execute(
            "ALTER TABLE terminal_sessions ADD COLUMN transcript TEXT",
            [],
        );

        // Add title column to reports (used by filesystem report scanning)
        let _ = self.conn.execute(
            "ALTER TABLE reports ADD COLUMN title TEXT",
            [],
        );

        Ok(())
    }

    // =========================================================================
    // Assessments
    // =========================================================================

    pub fn list_assessments(&self, limit: Option<i32>, offset: Option<i32>) -> Result<Vec<Assessment>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let mut stmt = self.conn.prepare(
            r#"
            SELECT a.id, a.name, a.assessment_type, a.targets, a.status,
                   a.created_at, a.updated_at, a.started_at, a.completed_at, a.options,
                   a.error_message, a.progress, a.current_step,
                   (SELECT COUNT(DISTINCT f.id) FROM findings f
                    LEFT JOIN assessment_findings af ON f.id = af.finding_id
                    WHERE f.assessment_id = a.id OR af.assessment_id = a.id) as findings_count,
                   (SELECT COUNT(DISTINCT f.id) FROM findings f
                    LEFT JOIN assessment_findings af ON f.id = af.finding_id
                    WHERE (f.assessment_id = a.id OR af.assessment_id = a.id) AND f.severity = 'critical') as critical_count,
                   (SELECT COUNT(DISTINCT f.id) FROM findings f
                    LEFT JOIN assessment_findings af ON f.id = af.finding_id
                    WHERE (f.assessment_id = a.id OR af.assessment_id = a.id) AND f.severity = 'high') as high_count,
                   a.project_id
            FROM assessments a
            ORDER BY a.created_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let rows = stmt.query_map(params![limit, offset], |row| {
            let targets_json: String = row.get(3)?;
            let targets: Vec<String> = serde_json::from_str(&targets_json).unwrap_or_default();
            let options_json: Option<String> = row.get(9)?;
            let options = options_json.and_then(|s| serde_json::from_str(&s).ok());

            Ok(Assessment {
                id: row.get(0)?,
                name: row.get(1)?,
                assessment_type: row.get(2)?,
                targets,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                started_at: row.get(7)?,
                completed_at: row.get(8)?,
                options,
                error_message: row.get(10)?,
                progress: row.get::<_, Option<i32>>(11)?.unwrap_or(0),
                current_step: row.get(12)?,
                findings_count: row.get::<_, Option<i32>>(13)?.unwrap_or(0),
                critical_count: row.get::<_, Option<i32>>(14)?.unwrap_or(0),
                high_count: row.get::<_, Option<i32>>(15)?.unwrap_or(0),
                project_id: row.get(16)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut assessments = Vec::new();
        for row in rows {
            assessments.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(assessments)
    }

    pub fn get_assessment(&self, id: &str) -> Result<Option<Assessment>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT a.id, a.name, a.assessment_type, a.targets, a.status,
                   a.created_at, a.updated_at, a.started_at, a.completed_at, a.options,
                   a.error_message, a.progress, a.current_step,
                   (SELECT COUNT(DISTINCT f.id) FROM findings f
                    LEFT JOIN assessment_findings af ON f.id = af.finding_id
                    WHERE f.assessment_id = a.id OR af.assessment_id = a.id) as findings_count,
                   (SELECT COUNT(DISTINCT f.id) FROM findings f
                    LEFT JOIN assessment_findings af ON f.id = af.finding_id
                    WHERE (f.assessment_id = a.id OR af.assessment_id = a.id) AND f.severity = 'critical') as critical_count,
                   (SELECT COUNT(DISTINCT f.id) FROM findings f
                    LEFT JOIN assessment_findings af ON f.id = af.finding_id
                    WHERE (f.assessment_id = a.id OR af.assessment_id = a.id) AND f.severity = 'high') as high_count,
                   a.project_id
            FROM assessments a
            WHERE a.id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let result = stmt.query_row(params![id], |row| {
            let targets_json: String = row.get(3)?;
            let targets: Vec<String> = serde_json::from_str(&targets_json).unwrap_or_default();
            let options_json: Option<String> = row.get(9)?;
            let options = options_json.and_then(|s| serde_json::from_str(&s).ok());

            Ok(Assessment {
                id: row.get(0)?,
                name: row.get(1)?,
                assessment_type: row.get(2)?,
                targets,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                started_at: row.get(7)?,
                completed_at: row.get(8)?,
                options,
                error_message: row.get(10)?,
                progress: row.get::<_, Option<i32>>(11)?.unwrap_or(0),
                current_step: row.get(12)?,
                findings_count: row.get::<_, Option<i32>>(13)?.unwrap_or(0),
                critical_count: row.get::<_, Option<i32>>(14)?.unwrap_or(0),
                high_count: row.get::<_, Option<i32>>(15)?.unwrap_or(0),
                project_id: row.get(16)?,
            })
        });

        match result {
            Ok(assessment) => Ok(Some(assessment)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    pub fn create_assessment(
        &self,
        name: &str,
        assessment_type: &str,
        targets: &[String],
        options: Option<serde_json::Value>,
    ) -> Result<Assessment> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let targets_json = serde_json::to_string(targets)?;
        let options_json = options.as_ref().map(|o| serde_json::to_string(o)).transpose()?;

        self.conn.execute(
            r#"
            INSERT INTO assessments (id, name, assessment_type, targets, status, created_at, updated_at, options)
            VALUES (?1, ?2, ?3, ?4, 'not_started', ?5, ?5, ?6)
            "#,
            params![id, name, assessment_type, targets_json, now, options_json],
        ).map_err(|e| AppError::Database(e))?;

        Ok(Assessment {
            id,
            name: name.to_string(),
            assessment_type: assessment_type.to_string(),
            targets: targets.to_vec(),
            status: "not_started".to_string(),
            project_id: None,
            created_at: now.clone(),
            updated_at: now,
            started_at: None,
            completed_at: None,
            options,
            error_message: None,
            progress: 0,
            current_step: None,
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
        })
    }

    pub fn update_assessment_status(&self, id: &str, status: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        let started_at = if status == "running" { Some(now.clone()) } else { None };
        let completed_at = if status == "completed" || status == "failed" { Some(now.clone()) } else { None };

        self.conn.execute(
            r#"
            UPDATE assessments
            SET status = ?2, updated_at = ?3, started_at = COALESCE(?4, started_at), completed_at = ?5
            WHERE id = ?1
            "#,
            params![id, status, now, started_at, completed_at],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn set_assessment_error(&self, id: &str, error_message: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE assessments
            SET error_message = ?2, updated_at = ?3
            WHERE id = ?1
            "#,
            params![id, error_message, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn update_assessment(
        &self,
        id: &str,
        assessment_type: Option<&str>,
        name: Option<&str>,
        status: Option<&str>,
        targets: Option<&[String]>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let targets_json = targets.map(|t| serde_json::to_string(t).unwrap_or_default());

        self.conn.execute(
            r#"
            UPDATE assessments
            SET updated_at = ?2,
                assessment_type = COALESCE(?3, assessment_type),
                name = COALESCE(?4, name),
                status = COALESCE(?5, status),
                targets = COALESCE(?6, targets)
            WHERE id = ?1
            "#,
            params![id, now, assessment_type, name, status, targets_json],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    /// Replace the `options` JSON blob on an assessment. Used for fields
    /// that don't warrant their own column — currently
    /// `claude_session_id` (per-assessment Claude conversation UUID for
    /// resume) and `codex_session_id`. Caller passes the full new options
    /// object; we don't merge — let the frontend handle the merge so the
    /// Rust side stays generic.
    pub fn update_assessment_options(
        &self,
        id: &str,
        options: &serde_json::Value,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let options_json = serde_json::to_string(options).unwrap_or_else(|_| "{}".to_string());
        self.conn
            .execute(
                r#"
                UPDATE assessments
                SET updated_at = ?2, options = ?3
                WHERE id = ?1
                "#,
                params![id, now, options_json],
            )
            .map_err(|e| AppError::Database(e))?;
        Ok(())
    }

    /// Set or clear the intentional-pause marker inside an assessment's
    /// `options` JSON, preserving every other key (e.g. `claude_session_id`).
    /// The marker syncs up as part of `options → config` (see
    /// `map_assessment_sync_row`) so the cloud reaper can exempt a deliberately
    /// paused run from the 3-hour stale sweep. Bumps `updated_at`, which also
    /// (re)starts the abandoned-pause outer bound the reaper enforces.
    pub fn set_assessment_paused(&self, id: &str, paused: bool) -> Result<()> {
        let mut options = self
            .get_assessment(id)?
            .and_then(|a| a.options)
            .unwrap_or_else(|| serde_json::json!({}));
        if !options.is_object() {
            options = serde_json::json!({});
        }
        let obj = options.as_object_mut().expect("options is an object");
        if paused {
            obj.insert("pause_state".into(), serde_json::json!("paused"));
            obj.insert(
                "paused_at".into(),
                serde_json::json!(Utc::now().to_rfc3339()),
            );
        } else {
            obj.remove("pause_state");
            obj.remove("paused_at");
        }
        self.update_assessment_options(id, &options)
    }

    pub fn delete_assessment(&self, id: &str) -> Result<()> {
        // Delete all associated data in dependent tables
        self.conn.execute("DELETE FROM finding_evidence WHERE finding_id IN (SELECT id FROM findings WHERE assessment_id = ?1)", params![id])
            .map_err(|e| AppError::Database(e))?;
        self.conn.execute("DELETE FROM assessment_findings WHERE assessment_id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        self.conn.execute("DELETE FROM findings WHERE assessment_id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        self.conn.execute("DELETE FROM reports WHERE assessment_id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        self.conn.execute("DELETE FROM terminal_sessions WHERE assessment_id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        self.conn.execute("DELETE FROM chat_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE assessment_id = ?1)", params![id])
            .map_err(|e| AppError::Database(e))?;
        self.conn.execute("DELETE FROM conversations WHERE assessment_id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;

        // Finally delete the assessment itself
        self.conn.execute("DELETE FROM assessments WHERE id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    // =========================================================================
    // Findings
    // =========================================================================

    pub fn list_findings(
        &self,
        assessment_id: Option<&str>,
        severity: Option<&str>,
        status: Option<&str>,
        category: Option<&str>,
        target: Option<&str>,
        search: Option<&str>,
        limit: Option<i32>,
        offset: Option<i32>,
        sort_by: Option<&str>,
        sort_dir: Option<&str>,
        exploitable: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<Finding>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        // When viewing globally (no assessment_id), deduplicate by (title, severity)
        // keeping only the most recent finding per group.
        // When viewing a specific assessment, show all its findings.
        let dedup_global = assessment_id.is_none();

        let mut query = if dedup_global {
            String::from(
                r#"
                SELECT DISTINCT f.id, f.assessment_id, f.title, f.severity, f.status, f.target,
                       f.description, f.evidence, f.remediation, f.cvss_score, f.cve_ids,
                       f.source, f.category, f.created_at, f.updated_at,
                       f.file_path, f.line_start, f.line_end, f.code_snippet, f.cwe,
                       f.exploitable, f.original_severity, f.calibrated_severity,
                       f.calibration_rule, f.calibration_justification, f.tags,
                       f.jira_ticket, f.jira_url, f.validated_at,
                       f.validation_method, f.source_tool, f.evidence_type
                FROM findings f
                LEFT JOIN assessment_findings af ON f.id = af.finding_id
                WHERE f.id IN (
                    SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (PARTITION BY title, severity ORDER BY created_at DESC) as rn
                        FROM findings
                    ) WHERE rn = 1
                )
                "#
            )
        } else {
            String::from(
                r#"
                SELECT DISTINCT f.id, f.assessment_id, f.title, f.severity, f.status, f.target,
                       f.description, f.evidence, f.remediation, f.cvss_score, f.cve_ids,
                       f.source, f.category, f.created_at, f.updated_at,
                       f.file_path, f.line_start, f.line_end, f.code_snippet, f.cwe,
                       f.exploitable, f.original_severity, f.calibrated_severity,
                       f.calibration_rule, f.calibration_justification, f.tags,
                       f.jira_ticket, f.jira_url, f.validated_at,
                       f.validation_method, f.source_tool, f.evidence_type
                FROM findings f
                LEFT JOIN assessment_findings af ON f.id = af.finding_id
                WHERE 1=1
                "#
            )
        };

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(aid) = assessment_id {
            query.push_str(&format!(" AND (f.assessment_id = ?{0} OR af.assessment_id = ?{0})", param_idx));
            params_vec.push(Box::new(aid.to_string()));
            param_idx += 1;
        }

        if let Some(sev) = severity {
            query.push_str(&format!(" AND f.severity = ?{}", param_idx));
            params_vec.push(Box::new(sev.to_string()));
            param_idx += 1;
        }

        if let Some(stat) = status {
            query.push_str(&format!(" AND f.status = ?{}", param_idx));
            params_vec.push(Box::new(stat.to_string()));
            param_idx += 1;
        }

        if let Some(cat) = category {
            query.push_str(&format!(" AND {} = ?{}", CATEGORY_FROM_SOURCE_SQL, param_idx));
            params_vec.push(Box::new(cat.to_string()));
            param_idx += 1;
        }

        if let Some(expl) = exploitable {
            query.push_str(&format!(" AND f.exploitable = ?{}", param_idx));
            params_vec.push(Box::new(expl.to_string()));
            param_idx += 1;
        }

        if let Some(pid) = project_id {
            query.push_str(&format!(
                " AND f.assessment_id IN (SELECT id FROM assessments WHERE project_id = ?{})", param_idx
            ));
            params_vec.push(Box::new(pid.to_string()));
            param_idx += 1;
        }

        if let Some(tgt) = target {
            query.push_str(&format!(" AND f.target LIKE ?{}", param_idx));
            let target_pattern = tgt.replace("https://", "").replace("http://", "").replace("*.", "").replace("*", "");
            params_vec.push(Box::new(format!("%{}%", target_pattern)));
            param_idx += 1;
        }

        if let Some(q) = search {
            if !q.is_empty() {
                query.push_str(&format!(" AND (f.title LIKE ?{0} OR f.description LIKE ?{0} OR f.target LIKE ?{0})", param_idx));
                params_vec.push(Box::new(format!("%{}%", q)));
                param_idx += 1;
            }
        }

        // Build ORDER BY from sort params (whitelist columns to prevent injection)
        let order_col = match sort_by.unwrap_or("created_at") {
            "severity" => "CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END",
            "title" => "f.title",
            "target" => "f.target",
            "source" => "COALESCE(f.source, '')",
            "status" => "f.status",
            "created_at" => "f.created_at",
            _ => "f.created_at",
        };
        let order_dir = match sort_dir.unwrap_or("desc") {
            "asc" => "ASC",
            _ => "DESC",
        };
        query.push_str(&format!(" ORDER BY {} {} LIMIT ?{} OFFSET ?{}", order_col, order_dir, param_idx, param_idx + 1));
        params_vec.push(Box::new(limit));
        params_vec.push(Box::new(offset));

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let cve_ids_json: Option<String> = row.get(10)?;
            let cve_ids = cve_ids_json.and_then(|s| serde_json::from_str(&s).ok());
            let tags_json: Option<String> = row.get(25)?;
            let tags = tags_json.and_then(|s| serde_json::from_str(&s).ok());

            Ok(Finding {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                title: row.get(2)?,
                severity: row.get(3)?,
                status: row.get(4)?,
                target: row.get(5)?,
                description: row.get(6)?,
                evidence: row.get(7)?,
                remediation: row.get(8)?,
                cvss_score: row.get(9)?,
                cve_ids,
                source: row.get(11)?,
                category: row.get(12)?,
                file_path: row.get(15)?,
                line_start: row.get(16)?,
                line_end: row.get(17)?,
                code_snippet: row.get(18)?,
                cwe: row.get(19)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
                // Parity columns appended at 20+ so the indices above never shift.
                exploitable: row.get(20)?,
                original_severity: row.get(21)?,
                calibrated_severity: row.get(22)?,
                calibration_rule: row.get(23)?,
                calibration_justification: row.get(24)?,
                tags,
                jira_ticket: row.get(26)?,
                jira_url: row.get(27)?,
                validated_at: row.get(28)?,
                validation_method: row.get(29)?,
                source_tool: row.get(30)?,
                evidence_type: row.get(31)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(findings)
    }

    pub fn count_findings(
        &self,
        assessment_id: Option<&str>,
        severity: Option<&str>,
        status: Option<&str>,
        category: Option<&str>,
        target: Option<&str>,
        search: Option<&str>,
        exploitable: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<i32> {
        let dedup_global = assessment_id.is_none();

        let mut query = if dedup_global {
            String::from(
                r#"
                SELECT COUNT(DISTINCT f.id)
                FROM findings f
                LEFT JOIN assessment_findings af ON f.id = af.finding_id
                WHERE f.id IN (
                    SELECT id FROM (
                        SELECT id, ROW_NUMBER() OVER (PARTITION BY title, severity ORDER BY created_at DESC) as rn
                        FROM findings
                    ) WHERE rn = 1
                )
                "#
            )
        } else {
            String::from(
                r#"
                SELECT COUNT(DISTINCT f.id)
                FROM findings f
                LEFT JOIN assessment_findings af ON f.id = af.finding_id
                WHERE 1=1
                "#
            )
        };

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(aid) = assessment_id {
            query.push_str(&format!(" AND (f.assessment_id = ?{0} OR af.assessment_id = ?{0})", param_idx));
            params_vec.push(Box::new(aid.to_string()));
            param_idx += 1;
        }

        if let Some(sev) = severity {
            query.push_str(&format!(" AND f.severity = ?{}", param_idx));
            params_vec.push(Box::new(sev.to_string()));
            param_idx += 1;
        }

        if let Some(stat) = status {
            query.push_str(&format!(" AND f.status = ?{}", param_idx));
            params_vec.push(Box::new(stat.to_string()));
            param_idx += 1;
        }

        if let Some(cat) = category {
            query.push_str(&format!(" AND {} = ?{}", CATEGORY_FROM_SOURCE_SQL, param_idx));
            params_vec.push(Box::new(cat.to_string()));
            param_idx += 1;
        }

        if let Some(expl) = exploitable {
            query.push_str(&format!(" AND f.exploitable = ?{}", param_idx));
            params_vec.push(Box::new(expl.to_string()));
            param_idx += 1;
        }

        if let Some(pid) = project_id {
            query.push_str(&format!(
                " AND f.assessment_id IN (SELECT id FROM assessments WHERE project_id = ?{})", param_idx
            ));
            params_vec.push(Box::new(pid.to_string()));
            param_idx += 1;
        }

        if let Some(tgt) = target {
            query.push_str(&format!(" AND f.target LIKE ?{}", param_idx));
            let target_pattern = tgt.replace("https://", "").replace("http://", "").replace("*.", "").replace("*", "");
            params_vec.push(Box::new(format!("%{}%", target_pattern)));
            param_idx += 1;
        }

        if let Some(q) = search {
            if !q.is_empty() {
                query.push_str(&format!(" AND (f.title LIKE ?{0} OR f.description LIKE ?{0} OR f.target LIKE ?{0})", param_idx));
                params_vec.push(Box::new(format!("%{}%", q)));
            }
        }

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let count: i32 = stmt.query_row(params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| AppError::Database(e))?;

        Ok(count)
    }

    pub fn get_findings_stats_grouped(
        &self,
        category: Option<&str>,
        target: Option<&str>,
        search: Option<&str>,
        exploitable: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<Vec<(String, String, String, i32)>> {
        // Global stats always deduplicate by (title, severity)
        let mut query = format!(
            "SELECT f.severity, f.status, {} as cat, COUNT(DISTINCT f.id) \
             FROM findings f \
             LEFT JOIN assessment_findings af ON f.id = af.finding_id \
             WHERE f.id IN (\
                 SELECT id FROM (\
                     SELECT id, ROW_NUMBER() OVER (PARTITION BY title, severity ORDER BY created_at DESC) as rn \
                     FROM findings\
                 ) WHERE rn = 1\
             )",
            CATEGORY_FROM_SOURCE_SQL
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(cat) = category {
            query.push_str(&format!(" AND {} = ?{}", CATEGORY_FROM_SOURCE_SQL, param_idx));
            params_vec.push(Box::new(cat.to_string()));
            param_idx += 1;
        }

        if let Some(expl) = exploitable {
            query.push_str(&format!(" AND f.exploitable = ?{}", param_idx));
            params_vec.push(Box::new(expl.to_string()));
            param_idx += 1;
        }

        if let Some(pid) = project_id {
            query.push_str(&format!(
                " AND f.assessment_id IN (SELECT id FROM assessments WHERE project_id = ?{})", param_idx
            ));
            params_vec.push(Box::new(pid.to_string()));
            param_idx += 1;
        }

        if let Some(tgt) = target {
            query.push_str(&format!(" AND f.target LIKE ?{}", param_idx));
            let target_pattern = tgt.replace("https://", "").replace("http://", "").replace("*.", "").replace("*", "");
            params_vec.push(Box::new(format!("%{}%", target_pattern)));
            param_idx += 1;
        }

        if let Some(q) = search {
            if !q.is_empty() {
                query.push_str(&format!(" AND (f.title LIKE ?{0} OR f.description LIKE ?{0} OR f.target LIKE ?{0})", param_idx));
                params_vec.push(Box::new(format!("%{}%", q)));
            }
        }

        query.push_str(" GROUP BY f.severity, f.status, cat");

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i32>(3)?,
            ))
        }).map_err(|e| AppError::Database(e))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(results)
    }

    pub fn get_exploitable_count(
        &self,
        target: Option<&str>,
        search: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<i32> {
        let mut query = "SELECT COUNT(DISTINCT f.id) FROM findings f \
             LEFT JOIN assessment_findings af ON f.id = af.finding_id \
             WHERE f.exploitable = 'true' \
             AND f.id IN (\
                 SELECT id FROM (\
                     SELECT id, ROW_NUMBER() OVER (PARTITION BY title, severity ORDER BY created_at DESC) as rn \
                     FROM findings\
                 ) WHERE rn = 1\
             )".to_string();

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(pid) = project_id {
            query.push_str(&format!(
                " AND f.assessment_id IN (SELECT id FROM assessments WHERE project_id = ?{})", param_idx
            ));
            params_vec.push(Box::new(pid.to_string()));
            param_idx += 1;
        }

        if let Some(tgt) = target {
            query.push_str(&format!(" AND f.target LIKE ?{}", param_idx));
            let target_pattern = tgt.replace("https://", "").replace("http://", "").replace("*.", "").replace("*", "");
            params_vec.push(Box::new(format!("%{}%", target_pattern)));
            param_idx += 1;
        }

        if let Some(q) = search {
            if !q.is_empty() {
                query.push_str(&format!(" AND (f.title LIKE ?{0} OR f.description LIKE ?{0} OR f.target LIKE ?{0})", param_idx));
                params_vec.push(Box::new(format!("%{}%", q)));
            }
        }

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let count: i32 = stmt.query_row(params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| AppError::Database(e))?;

        Ok(count)
    }

    pub fn get_finding(&self, id: &str) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, assessment_id, title, severity, status, target,
                   description, evidence, remediation, cvss_score, cve_ids,
                   source, category, created_at, updated_at,
file_path, line_start, line_end, code_snippet, cwe,
                   exploitable, original_severity, calibrated_severity,
                   calibration_rule, calibration_justification, tags,
                   jira_ticket, jira_url, validated_at,
                   validation_method, source_tool, evidence_type
            FROM findings
            WHERE id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let result = stmt.query_row(params![id], |row| {
            let cve_ids_json: Option<String> = row.get(10)?;
            let cve_ids = cve_ids_json.and_then(|s| serde_json::from_str(&s).ok());
            let tags_json: Option<String> = row.get(25)?;
            let tags = tags_json.and_then(|s| serde_json::from_str(&s).ok());

            Ok(Finding {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                title: row.get(2)?,
                severity: row.get(3)?,
                status: row.get(4)?,
                target: row.get(5)?,
                description: row.get(6)?,
                evidence: row.get(7)?,
                remediation: row.get(8)?,
                cvss_score: row.get(9)?,
                cve_ids,
                source: row.get(11)?,
                category: row.get(12)?,
                file_path: row.get(15)?,
                line_start: row.get(16)?,
                line_end: row.get(17)?,
                code_snippet: row.get(18)?,
                cwe: row.get(19)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
                // Parity columns appended at 20+ so the indices above never shift.
                exploitable: row.get(20)?,
                original_severity: row.get(21)?,
                calibrated_severity: row.get(22)?,
                calibration_rule: row.get(23)?,
                calibration_justification: row.get(24)?,
                tags,
                jira_ticket: row.get(26)?,
                jira_url: row.get(27)?,
                validated_at: row.get(28)?,
                validation_method: row.get(29)?,
                source_tool: row.get(30)?,
                evidence_type: row.get(31)?,
            })
        });

        match result {
            Ok(finding) => Ok(Some(finding)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    pub fn create_finding(&self, finding: &Finding) -> Result<Finding> {
        let id = if finding.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            finding.id.clone()
        };
        let now = Utc::now().to_rfc3339();
        let cve_ids_json = finding.cve_ids.as_ref().map(|c| serde_json::to_string(c)).transpose()?;
        let tags_json = finding.tags.as_ref().map(|t| serde_json::to_string(t)).transpose()?;

        self.conn.execute(
            r#"
            INSERT INTO findings (id, assessment_id, title, severity, status, target,
                                  description, evidence, remediation, cvss_score, cve_ids,
                                  source, category, created_at, updated_at,
                                  file_path, line_start, line_end, code_snippet, cwe,
                                  exploitable, original_severity, calibrated_severity,
                                  calibration_rule, calibration_justification, tags,
                                  jira_ticket, jira_url, validated_at,
                                  validation_method, source_tool, evidence_type)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14,
                    ?15, ?16, ?17, ?18, ?19,
                    ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31)
            "#,
            params![
                id,
                finding.assessment_id,
                finding.title,
                finding.severity,
                finding.status,
                finding.target,
                finding.description,
                finding.evidence,
                finding.remediation,
                finding.cvss_score,
                cve_ids_json,
                finding.source,
                finding.category,
                now,
                finding.file_path,
                finding.line_start,
                finding.line_end,
                finding.code_snippet,
                finding.cwe,
                finding.exploitable,
                finding.original_severity,
                finding.calibrated_severity,
                finding.calibration_rule,
                finding.calibration_justification,
                tags_json,
                finding.jira_ticket,
                finding.jira_url,
                finding.validated_at,
                finding.validation_method,
                finding.source_tool,
                finding.evidence_type
            ],
        ).map_err(|e| AppError::Database(e))?;

        let mut new_finding = finding.clone();
        new_finding.id = id;
        new_finding.created_at = now.clone();
        new_finding.updated_at = now;

        Ok(new_finding)
    }

    pub fn update_finding(&self, id: &str, updates: &serde_json::Value) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = ?1".to_string()];
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now)];
        let mut param_idx = 2;

        if let Some(title) = updates.get("title").and_then(|v| v.as_str()) {
            set_clauses.push(format!("title = ?{}", param_idx));
            params_vec.push(Box::new(title.to_string()));
            param_idx += 1;
        }

        if let Some(severity) = updates.get("severity").and_then(|v| v.as_str()) {
            set_clauses.push(format!("severity = ?{}", param_idx));
            params_vec.push(Box::new(severity.to_string()));
            param_idx += 1;
        }

        if let Some(status) = updates.get("status").and_then(|v| v.as_str()) {
            set_clauses.push(format!("status = ?{}", param_idx));
            params_vec.push(Box::new(status.to_string()));
            param_idx += 1;
        }

        if let Some(description) = updates.get("description").and_then(|v| v.as_str()) {
            set_clauses.push(format!("description = ?{}", param_idx));
            params_vec.push(Box::new(description.to_string()));
            param_idx += 1;
        }

        // Parity fields. `calibrated_severity` in particular is how the severity
        // calibrator records its verdict — without it, a local run would show
        // only scanner-original severities and the calibration pass would be
        // silently lost.
        for key in [
            "exploitable",
            "original_severity",
            "calibrated_severity",
            "calibration_rule",
            "calibration_justification",
            "jira_ticket",
            "jira_url",
            "validated_at",
            "validation_method",
            "source_tool",
            "evidence_type",
        ] {
            if let Some(v) = updates.get(key).and_then(|v| v.as_str()) {
                set_clauses.push(format!("{key} = ?{param_idx}"));
                params_vec.push(Box::new(v.to_string()));
                param_idx += 1;
            }
        }

        // tags arrives as a JSON array and is stored as JSON TEXT, matching cve_ids.
        if let Some(tags) = updates.get("tags").and_then(|v| v.as_array()) {
            let encoded = serde_json::to_string(tags)?;
            set_clauses.push(format!("tags = ?{param_idx}"));
            params_vec.push(Box::new(encoded));
            param_idx += 1;
        }

        if let Some(remediation) = updates.get("remediation").and_then(|v| v.as_str()) {
            set_clauses.push(format!("remediation = ?{}", param_idx));
            params_vec.push(Box::new(remediation.to_string()));
            param_idx += 1;
        }

        params_vec.push(Box::new(id.to_string()));

        let query = format!(
            "UPDATE findings SET {} WHERE id = ?{}",
            set_clauses.join(", "),
            param_idx
        );

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        self.conn.execute(&query, params_refs.as_slice())
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn delete_finding(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM findings WHERE id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        Ok(())
    }

    // =========================================================================
    // Scan Snapshots
    // =========================================================================

    /// Snapshot all findings for an assessment into a scan_snapshots record.
    /// Called when an assessment completes to capture point-in-time findings.
    pub fn snapshot_assessment_findings(&self, assessment_id: &str) -> Result<ScanSnapshot> {
        // Get the assessment to determine target
        let assessment = self.get_assessment(assessment_id)?
            .ok_or_else(|| AppError::NotFound(format!("Assessment {} not found", assessment_id)))?;

        let target = assessment.targets.first()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        // Get all finding IDs linked to this assessment (via direct or junction table)
        let mut stmt = self.conn.prepare(
            r#"
            SELECT DISTINCT f.id, f.severity
            FROM findings f
            LEFT JOIN assessment_findings af ON f.id = af.finding_id
            WHERE f.assessment_id = ?1 OR af.assessment_id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let rows: Vec<(String, String)> = stmt.query_map(params![assessment_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| AppError::Database(e))?
        .filter_map(|r| r.ok())
        .collect();

        // Count by severity
        let mut critical = 0i32;
        let mut high = 0i32;
        let mut medium = 0i32;
        let mut low = 0i32;
        let mut info = 0i32;

        let finding_ids: Vec<String> = rows.iter().map(|(id, sev)| {
            match sev.as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                "low" => low += 1,
                _ => info += 1,
            }
            id.clone()
        }).collect();

        let total = finding_ids.len() as i32;

        // Create snapshot
        let snapshot_id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO scan_snapshots (id, assessment_id, target, scanned_at,
                                        critical_count, high_count, medium_count, low_count, info_count, total_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![snapshot_id, assessment_id, target, now, critical, high, medium, low, info, total],
        ).map_err(|e| AppError::Database(e))?;

        // Insert snapshot_findings junction rows
        for fid in &finding_ids {
            self.conn.execute(
                "INSERT OR IGNORE INTO snapshot_findings (snapshot_id, finding_id) VALUES (?1, ?2)",
                params![snapshot_id, fid],
            ).map_err(|e| AppError::Database(e))?;
        }

        Ok(ScanSnapshot {
            id: snapshot_id,
            assessment_id: assessment_id.to_string(),
            target,
            scanned_at: now,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            total_count: total,
        })
    }

    /// List scan snapshots, optionally filtered by target.
    pub fn list_scan_snapshots(&self, target: Option<&str>) -> Result<Vec<ScanSnapshot>> {
        let mut query = String::from(
            r#"
            SELECT id, assessment_id, target, scanned_at,
                   critical_count, high_count, medium_count, low_count, info_count, total_count
            FROM scan_snapshots
            WHERE 1=1
            "#
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(t) = target {
            query.push_str(" AND target = ?1");
            params_vec.push(Box::new(t.to_string()));
        }

        query.push_str(" ORDER BY scanned_at DESC");

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(ScanSnapshot {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                target: row.get(2)?,
                scanned_at: row.get(3)?,
                critical_count: row.get::<_, Option<i32>>(4)?.unwrap_or(0),
                high_count: row.get::<_, Option<i32>>(5)?.unwrap_or(0),
                medium_count: row.get::<_, Option<i32>>(6)?.unwrap_or(0),
                low_count: row.get::<_, Option<i32>>(7)?.unwrap_or(0),
                info_count: row.get::<_, Option<i32>>(8)?.unwrap_or(0),
                total_count: row.get::<_, Option<i32>>(9)?.unwrap_or(0),
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(snapshots)
    }

    /// List findings that belong to a specific snapshot.
    pub fn list_findings_by_snapshot(
        &self,
        snapshot_id: &str,
        severity: Option<&str>,
        status: Option<&str>,
        category: Option<&str>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<Finding>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let mut query = String::from(
            r#"
            SELECT DISTINCT f.id, f.assessment_id, f.title, f.severity, f.status, f.target,
                   f.description, f.evidence, f.remediation, f.cvss_score, f.cve_ids,
                   f.source, f.category, f.created_at, f.updated_at,
                   f.file_path, f.line_start, f.line_end, f.code_snippet, f.cwe,
                       f.exploitable, f.original_severity, f.calibrated_severity,
                       f.calibration_rule, f.calibration_justification, f.tags,
                       f.jira_ticket, f.jira_url, f.validated_at,
                       f.validation_method, f.source_tool, f.evidence_type
            FROM findings f
            INNER JOIN snapshot_findings sf ON f.id = sf.finding_id
            WHERE sf.snapshot_id = ?1
            "#
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        params_vec.push(Box::new(snapshot_id.to_string()));
        let mut param_idx = 2;

        if let Some(sev) = severity {
            query.push_str(&format!(" AND f.severity = ?{}", param_idx));
            params_vec.push(Box::new(sev.to_string()));
            param_idx += 1;
        }

        if let Some(stat) = status {
            query.push_str(&format!(" AND f.status = ?{}", param_idx));
            params_vec.push(Box::new(stat.to_string()));
            param_idx += 1;
        }

        if let Some(cat) = category {
            query.push_str(&format!(" AND {} = ?{}", CATEGORY_FROM_SOURCE_SQL, param_idx));
            params_vec.push(Box::new(cat.to_string()));
            param_idx += 1;
        }

        query.push_str(&format!(" ORDER BY f.created_at DESC LIMIT ?{} OFFSET ?{}", param_idx, param_idx + 1));
        params_vec.push(Box::new(limit));
        params_vec.push(Box::new(offset));

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let cve_ids_json: Option<String> = row.get(10)?;
            let cve_ids = cve_ids_json.and_then(|s| serde_json::from_str(&s).ok());
            let tags_json: Option<String> = row.get(25)?;
            let tags = tags_json.and_then(|s| serde_json::from_str(&s).ok());

            Ok(Finding {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                title: row.get(2)?,
                severity: row.get(3)?,
                status: row.get(4)?,
                target: row.get(5)?,
                description: row.get(6)?,
                evidence: row.get(7)?,
                remediation: row.get(8)?,
                cvss_score: row.get(9)?,
                cve_ids,
                source: row.get(11)?,
                category: row.get(12)?,
                file_path: row.get(15)?,
                line_start: row.get(16)?,
                line_end: row.get(17)?,
                code_snippet: row.get(18)?,
                cwe: row.get(19)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
                // Parity columns appended at 20+ so the indices above never shift.
                exploitable: row.get(20)?,
                original_severity: row.get(21)?,
                calibrated_severity: row.get(22)?,
                calibration_rule: row.get(23)?,
                calibration_justification: row.get(24)?,
                tags,
                jira_ticket: row.get(26)?,
                jira_url: row.get(27)?,
                validated_at: row.get(28)?,
                validation_method: row.get(29)?,
                source_tool: row.get(30)?,
                evidence_type: row.get(31)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(findings)
    }

    /// Count findings in a specific snapshot.
    pub fn count_findings_by_snapshot(
        &self,
        snapshot_id: &str,
        severity: Option<&str>,
        status: Option<&str>,
        category: Option<&str>,
    ) -> Result<i32> {
        let mut query = String::from(
            r#"
            SELECT COUNT(DISTINCT f.id)
            FROM findings f
            INNER JOIN snapshot_findings sf ON f.id = sf.finding_id
            WHERE sf.snapshot_id = ?1
            "#
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        params_vec.push(Box::new(snapshot_id.to_string()));
        let mut param_idx = 2;

        if let Some(sev) = severity {
            query.push_str(&format!(" AND f.severity = ?{}", param_idx));
            params_vec.push(Box::new(sev.to_string()));
            param_idx += 1;
        }

        if let Some(stat) = status {
            query.push_str(&format!(" AND f.status = ?{}", param_idx));
            params_vec.push(Box::new(stat.to_string()));
            param_idx += 1;
        }

        if let Some(cat) = category {
            query.push_str(&format!(" AND {} = ?{}", CATEGORY_FROM_SOURCE_SQL, param_idx));
            params_vec.push(Box::new(cat.to_string()));
        }

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let count: i32 = stmt.query_row(params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| AppError::Database(e))?;

        Ok(count)
    }

    // =========================================================================
    // Audit Logs
    // =========================================================================

    pub fn add_audit_log(
        &self,
        action: &str,
        target: Option<&str>,
        command: Option<&str>,
        result: Option<&str>,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO audit_logs (id, timestamp, action, target, command, result)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![id, now, action, target, command, result],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn get_audit_logs(&self, limit: Option<i32>, offset: Option<i32>) -> Result<Vec<AuditLog>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, timestamp, action, target, command, result, user
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT ?1 OFFSET ?2
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(AuditLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                command: row.get(4)?,
                result: row.get(5)?,
                user: row.get(6)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut logs = Vec::new();
        for row in rows {
            logs.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(logs)
    }

    // =========================================================================
    // Repositories
    // =========================================================================

    /// Compute the container path for a repository (maps host paths to /mnt/host-home/...)
    fn compute_container_path(path: &str, source_type: &str, github_owner: Option<&str>, github_repo: Option<&str>) -> String {
        let home_dir = dirs::home_dir()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();

        if source_type == "github" {
            let owner = github_owner.unwrap_or("unknown");
            let repo = github_repo.unwrap_or("repo");
            format!("/mnt/host-home/.kali-mcp-pentest/repo-cache/{}_{}", owner, repo)
        } else if !home_dir.is_empty() && path.starts_with(&home_dir) {
            path.replace(&home_dir, "/mnt/host-home")
        } else {
            path.to_string()
        }
    }

    pub fn list_repositories(&self) -> Result<Vec<Repository>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, name, path, source_type, github_owner, github_repo, languages, last_scanned, findings_count, created_at
            FROM repositories
            ORDER BY created_at DESC
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let rows = stmt.query_map([], |row| {
            let languages_json: Option<String> = row.get(6)?;
            let languages: Vec<String> = languages_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let path: String = row.get(2)?;
            let source_type = row.get::<_, Option<String>>(3)?.unwrap_or_else(|| "local".to_string());
            let github_owner: Option<String> = row.get(4)?;
            let github_repo: Option<String> = row.get(5)?;
            let container_path = Database::compute_container_path(
                &path, &source_type, github_owner.as_deref(), github_repo.as_deref()
            );

            Ok(Repository {
                id: row.get(0)?,
                name: row.get(1)?,
                path,
                container_path,
                source_type,
                github_owner,
                github_repo,
                languages,
                last_scanned: row.get(7)?,
                findings_count: row.get(8)?,
                created_at: row.get(9)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut repos = Vec::new();
        for row in rows {
            repos.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(repos)
    }

    pub fn add_repository(
        &self,
        name: &str,
        path: &str,
        source_type: &str,
        github_owner: Option<&str>,
        github_repo: Option<&str>,
        languages: &[String],
    ) -> Result<Repository> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        let languages_json = serde_json::to_string(languages)?;

        self.conn.execute(
            r#"
            INSERT INTO repositories (id, name, path, source_type, github_owner, github_repo, languages, findings_count, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
            "#,
            params![id, name, path, source_type, github_owner, github_repo, languages_json, now],
        ).map_err(|e| AppError::Database(e))?;

        let container_path = Database::compute_container_path(path, source_type, github_owner, github_repo);

        Ok(Repository {
            id,
            name: name.to_string(),
            path: path.to_string(),
            container_path,
            source_type: source_type.to_string(),
            github_owner: github_owner.map(String::from),
            github_repo: github_repo.map(String::from),
            languages: languages.to_vec(),
            last_scanned: None,
            findings_count: 0,
            created_at: now,
        })
    }

    pub fn remove_repository(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM repositories WHERE id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        Ok(())
    }

    pub fn update_repository_scan(&self, id: &str, findings_count: i32) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE repositories
            SET last_scanned = ?2, findings_count = ?3
            WHERE id = ?1
            "#,
            params![id, now, findings_count],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn update_repository(&self, id: &str, name: &str, path: &str, languages: &[String]) -> Result<Repository> {
        let languages_json = serde_json::to_string(languages)?;

        self.conn.execute(
            r#"
            UPDATE repositories
            SET name = ?2, path = ?3, languages = ?4
            WHERE id = ?1
            "#,
            params![id, name, path, languages_json],
        ).map_err(|e| AppError::Database(e))?;

        // Return the updated repository
        let repos = self.list_repositories()?;
        repos
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| AppError::NotFound(format!("Repository not found: {}", id)))
    }

    // =========================================================================
    // Cloud Sync Methods
    // =========================================================================

    /// Get assessments modified since last sync
    pub fn get_assessments_for_sync(&self, last_sync: Option<DateTime<Utc>>) -> Result<Vec<AssessmentSync>> {
        let mut assessments = Vec::new();

        if let Some(sync_time) = last_sync {
            let query = r#"
            SELECT id, server_id, name, assessment_type, targets, status, created_at, updated_at,
                   started_at, completed_at, options,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id) as findings_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'critical') as critical_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'high') as high_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'medium') as medium_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'low') as low_count
            FROM assessments a
            WHERE updated_at > ?1
            "#;
            let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
            let rows = stmt.query_map(params![sync_time.to_rfc3339()], |row| {
                Self::map_assessment_sync_row(row)
            }).map_err(|e| AppError::Database(e))?;
            for row in rows {
                assessments.push(row.map_err(|e| AppError::Database(e))?);
            }
        } else {
            let query = r#"
            SELECT id, server_id, name, assessment_type, targets, status, created_at, updated_at,
                   started_at, completed_at, options,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id) as findings_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'critical') as critical_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'high') as high_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'medium') as medium_count,
                   (SELECT COUNT(*) FROM findings f WHERE f.assessment_id = a.id AND f.severity = 'low') as low_count
            FROM assessments a
            "#;
            let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
            let rows = stmt.query_map([], |row| {
                Self::map_assessment_sync_row(row)
            }).map_err(|e| AppError::Database(e))?;
            for row in rows {
                assessments.push(row.map_err(|e| AppError::Database(e))?);
            }
        }

        Ok(assessments)
    }

    fn map_assessment_sync_row(row: &rusqlite::Row) -> rusqlite::Result<AssessmentSync> {
        let id: String = row.get(0)?;
        let server_id: Option<String> = row.get(1)?;
        let _name: String = row.get(2)?;
        let assessment_type: String = row.get(3)?;
        let targets_json: String = row.get(4)?;
        let targets: Vec<String> = serde_json::from_str(&targets_json).unwrap_or_default();
        let local_status: String = row.get(5)?;
        // The cloud `assessmentstatus` enum has no `paused` variant (by design —
        // pause is represented by a `pause_state` marker in options→config, not
        // a status). Syncing the literal "paused" would fail the
        // `::assessmentstatus` cast and reject the row, so present a paused run
        // to the cloud as the `running` it effectively still is; the marker
        // (carried in `config`) is what exempts it from the stale-run reaper.
        let status: String = if local_status == "paused" {
            "running".to_string()
        } else {
            local_status
        };
        let created_at: String = row.get(6)?;
        let _updated_at: String = row.get(7)?;
        let started_at: Option<String> = row.get(8)?;
        let completed_at: Option<String> = row.get(9)?;
        let options_json: Option<String> = row.get(10)?;
        let config: serde_json::Value = options_json
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::json!({}));
        let findings_count: i32 = row.get(11)?;
        let critical_count: i32 = row.get(12)?;
        let high_count: i32 = row.get(13)?;
        let medium_count: i32 = row.get(14)?;
        let low_count: i32 = row.get(15)?;

        let progress = if status == "completed" { 100 } else { 0 };

        Ok(AssessmentSync {
            id: server_id,
            client_id: id,
            assessment_type,
            status,
            targets,
            repo_paths: Vec::new(),
            progress,
            current_step: None,
            error_message: None,
            config,
            phases: Vec::new(),
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            started_at: DateTime::parse_from_rfc3339(&started_at.unwrap_or_else(|| created_at.clone()))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            completed_at: completed_at.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|dt| dt.with_timezone(&Utc))),
        })
    }

    /// Get findings modified since last sync
    pub fn get_findings_for_sync(&self, last_sync: Option<DateTime<Utc>>) -> Result<Vec<FindingSync>> {
        let mut findings = Vec::new();

        if let Some(sync_time) = last_sync {
            let query = r#"
            SELECT id, server_id, assessment_id, title, severity, status, target,
                   description, evidence, remediation, cvss_score, cve_ids,
                   created_at, updated_at
            FROM findings
            WHERE updated_at > ?1
            "#;
            let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
            let rows = stmt.query_map(params![sync_time.to_rfc3339()], |row| {
                Self::map_finding_sync_row(row)
            }).map_err(|e| AppError::Database(e))?;
            for row in rows {
                findings.push(row.map_err(|e| AppError::Database(e))?);
            }
        } else {
            let query = r#"
            SELECT id, server_id, assessment_id, title, severity, status, target,
                   description, evidence, remediation, cvss_score, cve_ids,
                   created_at, updated_at
            FROM findings
            "#;
            let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
            let rows = stmt.query_map([], |row| {
                Self::map_finding_sync_row(row)
            }).map_err(|e| AppError::Database(e))?;
            for row in rows {
                findings.push(row.map_err(|e| AppError::Database(e))?);
            }
        }

        Ok(findings)
    }

    fn map_finding_sync_row(row: &rusqlite::Row) -> rusqlite::Result<FindingSync> {
        let id: String = row.get(0)?;
        let server_id: Option<String> = row.get(1)?;
        let assessment_id: Option<String> = row.get(2)?;
        let title: String = row.get(3)?;
        let severity: String = row.get(4)?;
        let status: String = row.get(5)?;
        let target: String = row.get(6)?;
        let description: Option<String> = row.get(7)?;
        let evidence: Option<String> = row.get(8)?;
        let remediation: Option<String> = row.get(9)?;
        let cvss_score: Option<f64> = row.get(10)?;
        let cve_ids_json: Option<String> = row.get(11)?;
        let cve: Option<String> = cve_ids_json
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .and_then(|v| v.first().cloned());
        let created_at: String = row.get(12)?;
        let updated_at: String = row.get(13)?;

        Ok(FindingSync {
            id: server_id,
            client_id: id,
            title,
            description,
            severity,
            status,
            target,
            target_type: None,
            evidence,
            remediation,
            references: None,
            cve,
            cwe: None,
            cvss_score: cvss_score.map(|s| s.to_string()),
            jira_ticket: None,
            jira_url: None,
            source: Some("local".to_string()),
            source_id: None,
            assessment_id,
            created_at: DateTime::parse_from_rfc3339(&created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&updated_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    /// Get reports modified since last sync
    pub fn get_reports_for_sync(&self, last_sync: Option<DateTime<Utc>>) -> Result<Vec<ReportSync>> {
        let mut reports = Vec::new();

        if let Some(sync_time) = last_sync {
            let query = r#"
            SELECT id, server_id, assessment_id, name, format, file_path, created_at, updated_at
            FROM reports
            WHERE updated_at > ?1 OR (updated_at IS NULL AND created_at > ?1)
            "#;
            let sync_str = sync_time.to_rfc3339();
            let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
            let rows = stmt.query_map(params![sync_str, sync_str], |row| {
                Self::map_report_sync_row(row)
            }).map_err(|e| AppError::Database(e))?;
            for row in rows {
                reports.push(row.map_err(|e| AppError::Database(e))?);
            }
        } else {
            let query = r#"
            SELECT id, server_id, assessment_id, name, format, file_path, created_at, updated_at
            FROM reports
            "#;
            let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
            let rows = stmt.query_map([], |row| {
                Self::map_report_sync_row(row)
            }).map_err(|e| AppError::Database(e))?;
            for row in rows {
                reports.push(row.map_err(|e| AppError::Database(e))?);
            }
        }

        Ok(reports)
    }

    fn map_report_sync_row(row: &rusqlite::Row) -> rusqlite::Result<ReportSync> {
        let id: String = row.get(0)?;
        let server_id: Option<String> = row.get(1)?;
        let assessment_id: String = row.get(2)?;
        let name: String = row.get(3)?;
        let format: String = row.get(4)?;
        let file_path: Option<String> = row.get(5)?;
        let created_at: String = row.get(6)?;
        let updated_at: Option<String> = row.get(7)?;

        // Read content from file if available
        let content = file_path.as_ref().and_then(|path| {
            std::fs::read_to_string(path).ok()
        });

        Ok(ReportSync {
            id: server_id,
            client_id: id,
            title: name,
            format,
            content,
            executive_summary: None,
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            exploitable_count: 0,
            assessment_id,
            created_at: DateTime::parse_from_rfc3339(&created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            updated_at: DateTime::parse_from_rfc3339(&updated_at.unwrap_or_else(|| created_at.clone()))
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        })
    }

    /// Upsert assessment from sync response
    pub fn upsert_assessment_from_sync(&self, assessment: &AssessmentSync) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let targets_json = serde_json::to_string(&assessment.targets)?;
        let options_json = serde_json::to_string(&assessment.config)?;

        // Check if we have this assessment by server_id
        if let Some(server_id) = &assessment.id {
            let exists: bool = self.conn.query_row(
                "SELECT 1 FROM assessments WHERE server_id = ?1",
                params![server_id],
                |_| Ok(true),
            ).unwrap_or(false);

            if exists {
                // Update existing record
                self.conn.execute(
                    r#"
                    UPDATE assessments
                    SET assessment_type = ?2, targets = ?3, status = ?4, updated_at = ?5,
                        started_at = ?6, completed_at = ?7, options = ?8
                    WHERE server_id = ?1
                    "#,
                    params![
                        server_id,
                        assessment.assessment_type,
                        targets_json,
                        assessment.status,
                        now,
                        assessment.started_at.to_rfc3339(),
                        assessment.completed_at.map(|dt| dt.to_rfc3339()),
                        options_json
                    ],
                ).map_err(|e| AppError::Database(e))?;
                return Ok(());
            }
        }

        // Check if we have this assessment by client_id
        let exists_by_client: bool = self.conn.query_row(
            "SELECT 1 FROM assessments WHERE id = ?1",
            params![assessment.client_id],
            |_| Ok(true),
        ).unwrap_or(false);

        if exists_by_client {
            // Update existing record with server_id
            self.conn.execute(
                r#"
                UPDATE assessments
                SET server_id = ?2, assessment_type = ?3, targets = ?4, status = ?5,
                    updated_at = ?6, started_at = ?7, completed_at = ?8, options = ?9
                WHERE id = ?1
                "#,
                params![
                    assessment.client_id,
                    assessment.id,
                    assessment.assessment_type,
                    targets_json,
                    assessment.status,
                    now,
                    assessment.started_at.to_rfc3339(),
                    assessment.completed_at.map(|dt| dt.to_rfc3339()),
                    options_json
                ],
            ).map_err(|e| AppError::Database(e))?;
        } else {
            // Insert new record
            let id = if assessment.client_id.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                assessment.client_id.clone()
            };

            self.conn.execute(
                r#"
                INSERT INTO assessments (id, server_id, name, assessment_type, targets, status,
                                        created_at, updated_at, started_at, completed_at, options)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10)
                "#,
                params![
                    id,
                    assessment.id,
                    format!("Assessment {}", assessment.assessment_type),
                    assessment.assessment_type,
                    targets_json,
                    assessment.status,
                    now,
                    assessment.started_at.to_rfc3339(),
                    assessment.completed_at.map(|dt| dt.to_rfc3339()),
                    options_json
                ],
            ).map_err(|e| AppError::Database(e))?;
        }

        Ok(())
    }

    /// Upsert finding from sync response
    pub fn upsert_finding_from_sync(&self, finding: &FindingSync) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let cve_ids_json = finding.cve.as_ref().map(|cve| serde_json::to_string(&vec![cve.clone()])).transpose()?;
        let cvss_score: Option<f64> = finding.cvss_score.as_ref().and_then(|s| s.parse().ok());

        // Check if we have this finding by server_id
        if let Some(server_id) = &finding.id {
            let exists: bool = self.conn.query_row(
                "SELECT 1 FROM findings WHERE server_id = ?1",
                params![server_id],
                |_| Ok(true),
            ).unwrap_or(false);

            if exists {
                // Update existing record
                self.conn.execute(
                    r#"
                    UPDATE findings
                    SET title = ?2, severity = ?3, status = ?4, target = ?5,
                        description = ?6, evidence = ?7, remediation = ?8,
                        cvss_score = ?9, cve_ids = ?10, updated_at = ?11
                    WHERE server_id = ?1
                    "#,
                    params![
                        server_id,
                        finding.title,
                        finding.severity,
                        finding.status,
                        finding.target,
                        finding.description,
                        finding.evidence,
                        finding.remediation,
                        cvss_score,
                        cve_ids_json,
                        now
                    ],
                ).map_err(|e| AppError::Database(e))?;
                return Ok(());
            }
        }

        // Check if we have this finding by client_id
        let exists_by_client: bool = self.conn.query_row(
            "SELECT 1 FROM findings WHERE id = ?1",
            params![finding.client_id],
            |_| Ok(true),
        ).unwrap_or(false);

        if exists_by_client {
            // Update existing record with server_id
            self.conn.execute(
                r#"
                UPDATE findings
                SET server_id = ?2, title = ?3, severity = ?4, status = ?5,
                    target = ?6, description = ?7, evidence = ?8, remediation = ?9,
                    cvss_score = ?10, cve_ids = ?11, updated_at = ?12
                WHERE id = ?1
                "#,
                params![
                    finding.client_id,
                    finding.id,
                    finding.title,
                    finding.severity,
                    finding.status,
                    finding.target,
                    finding.description,
                    finding.evidence,
                    finding.remediation,
                    cvss_score,
                    cve_ids_json,
                    now
                ],
            ).map_err(|e| AppError::Database(e))?;
        } else {
            // Insert new record
            let id = if finding.client_id.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                finding.client_id.clone()
            };

            self.conn.execute(
                r#"
                INSERT INTO findings (id, server_id, assessment_id, title, severity, status,
                                     target, description, evidence, remediation,
                                     cvss_score, cve_ids, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)
                "#,
                params![
                    id,
                    finding.id,
                    finding.assessment_id,
                    finding.title,
                    finding.severity,
                    finding.status,
                    finding.target,
                    finding.description,
                    finding.evidence,
                    finding.remediation,
                    cvss_score,
                    cve_ids_json,
                    now
                ],
            ).map_err(|e| AppError::Database(e))?;
        }

        Ok(())
    }

    /// Upsert report from sync response
    pub fn upsert_report_from_sync(&self, report: &ReportSync) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        // Check if we have this report by server_id
        if let Some(server_id) = &report.id {
            let exists: bool = self.conn.query_row(
                "SELECT 1 FROM reports WHERE server_id = ?1",
                params![server_id],
                |_| Ok(true),
            ).unwrap_or(false);

            if exists {
                // Update existing record
                self.conn.execute(
                    r#"
                    UPDATE reports
                    SET name = ?2, format = ?3, updated_at = ?4
                    WHERE server_id = ?1
                    "#,
                    params![server_id, report.title, report.format, now],
                ).map_err(|e| AppError::Database(e))?;
                return Ok(());
            }
        }

        // Check if we have this report by client_id
        let exists_by_client: bool = self.conn.query_row(
            "SELECT 1 FROM reports WHERE id = ?1",
            params![report.client_id],
            |_| Ok(true),
        ).unwrap_or(false);

        if exists_by_client {
            // Update existing record with server_id
            self.conn.execute(
                r#"
                UPDATE reports
                SET server_id = ?2, name = ?3, format = ?4, updated_at = ?5
                WHERE id = ?1
                "#,
                params![report.client_id, report.id, report.title, report.format, now],
            ).map_err(|e| AppError::Database(e))?;
        } else {
            // Insert new record
            let id = if report.client_id.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                report.client_id.clone()
            };

            self.conn.execute(
                r#"
                INSERT INTO reports (id, server_id, assessment_id, name, format, created_at, updated_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                "#,
                params![
                    id,
                    report.id,
                    report.assessment_id,
                    report.title,
                    report.format,
                    now
                ],
            ).map_err(|e| AppError::Database(e))?;
        }

        Ok(())
    }

    /// Get report by ID
    pub fn get_report(&self, id: &str) -> Result<Option<Report>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, assessment_id, name, format, content, file_path, created_at,
                   COALESCE(findings_count, 0), COALESCE(critical_count, 0),
                   COALESCE(high_count, 0), COALESCE(medium_count, 0),
                   COALESCE(low_count, 0), COALESCE(exploitable_count, 0)
            FROM reports
            WHERE id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let result = stmt.query_row(params![id], |row| {
            Ok(Report {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                name: row.get(2)?,
                format: row.get(3)?,
                content: row.get(4)?,
                file_path: row.get(5)?,
                created_at: row.get(6)?,
                findings_count: row.get::<_, Option<i32>>(7)?.unwrap_or(0),
                critical_count: row.get::<_, Option<i32>>(8)?.unwrap_or(0),
                high_count: row.get::<_, Option<i32>>(9)?.unwrap_or(0),
                medium_count: row.get::<_, Option<i32>>(10)?.unwrap_or(0),
                low_count: row.get::<_, Option<i32>>(11)?.unwrap_or(0),
                exploitable_count: row.get::<_, Option<i32>>(12)?.unwrap_or(0),
            })
        });

        match result {
            Ok(report) => Ok(Some(report)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    /// List reports
    pub fn list_reports(&self, assessment_id: Option<&str>) -> Result<Vec<Report>> {
        let (query, params_vec): (&str, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(aid) = assessment_id {
            (
                r#"
                SELECT id, assessment_id, name, format, content, file_path, created_at,
                       COALESCE(findings_count, 0), COALESCE(critical_count, 0),
                       COALESCE(high_count, 0), COALESCE(medium_count, 0),
                       COALESCE(low_count, 0), COALESCE(exploitable_count, 0)
                FROM reports
                WHERE assessment_id = ?1
                ORDER BY created_at DESC
                "#,
                vec![Box::new(aid.to_string())]
            )
        } else {
            (
                r#"
                SELECT id, assessment_id, name, format, content, file_path, created_at,
                       COALESCE(findings_count, 0), COALESCE(critical_count, 0),
                       COALESCE(high_count, 0), COALESCE(medium_count, 0),
                       COALESCE(low_count, 0), COALESCE(exploitable_count, 0)
                FROM reports
                ORDER BY created_at DESC
                "#,
                vec![]
            )
        };

        let mut stmt = self.conn.prepare(query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(Report {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                name: row.get(2)?,
                format: row.get(3)?,
                content: row.get(4)?,
                file_path: row.get(5)?,
                created_at: row.get(6)?,
                findings_count: row.get::<_, Option<i32>>(7)?.unwrap_or(0),
                critical_count: row.get::<_, Option<i32>>(8)?.unwrap_or(0),
                high_count: row.get::<_, Option<i32>>(9)?.unwrap_or(0),
                medium_count: row.get::<_, Option<i32>>(10)?.unwrap_or(0),
                low_count: row.get::<_, Option<i32>>(11)?.unwrap_or(0),
                exploitable_count: row.get::<_, Option<i32>>(12)?.unwrap_or(0),
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut reports = Vec::new();
        for row in rows {
            reports.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(reports)
    }

    /// Create a report
    pub fn create_report(
        &self,
        assessment_id: &str,
        name: &str,
        format: &str,
        content: Option<&str>,
        file_path: Option<&str>,
        findings_count: i32,
        critical_count: i32,
        high_count: i32,
        medium_count: i32,
        low_count: i32,
        exploitable_count: i32,
    ) -> Result<Report> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO reports (id, assessment_id, name, format, content, file_path, created_at, updated_at,
                                 findings_count, critical_count, high_count, medium_count, low_count, exploitable_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![id, assessment_id, name, format, content, file_path, now,
                    findings_count, critical_count, high_count, medium_count, low_count, exploitable_count],
        ).map_err(|e| AppError::Database(e))?;

        Ok(Report {
            id,
            assessment_id: assessment_id.to_string(),
            name: name.to_string(),
            format: format.to_string(),
            content: content.map(|s| s.to_string()),
            file_path: file_path.map(|s| s.to_string()),
            created_at: now,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            exploitable_count,
        })
    }

    // =========================================================================
    // Imports
    // =========================================================================

    pub fn create_import(&self, name: &str, source: &str, filename: Option<&str>) -> Result<Import> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO imports (id, name, source, filename, findings_count, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, 0, 'pending', ?5, ?5)
            "#,
            params![id, name, source, filename, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(Import {
            id,
            name: name.to_string(),
            source: source.to_string(),
            filename: filename.map(|s| s.to_string()),
            findings_count: 0,
            status: "pending".to_string(),
            error_message: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn list_imports(&self, source: Option<&str>, limit: Option<i32>, offset: Option<i32>) -> Result<Vec<Import>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let (query, params_vec): (String, Vec<Box<dyn rusqlite::ToSql>>) = if let Some(src) = source {
            (
                r#"
                SELECT id, name, source, filename, findings_count, status, error_message, created_at, updated_at
                FROM imports
                WHERE source = ?1
                ORDER BY created_at DESC
                LIMIT ?2 OFFSET ?3
                "#.to_string(),
                vec![Box::new(src.to_string()), Box::new(limit), Box::new(offset)]
            )
        } else {
            (
                r#"
                SELECT id, name, source, filename, findings_count, status, error_message, created_at, updated_at
                FROM imports
                ORDER BY created_at DESC
                LIMIT ?1 OFFSET ?2
                "#.to_string(),
                vec![Box::new(limit), Box::new(offset)]
            )
        };

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(Import {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                filename: row.get(3)?,
                findings_count: row.get(4)?,
                status: row.get(5)?,
                error_message: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut imports = Vec::new();
        for row in rows {
            imports.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(imports)
    }

    pub fn get_import(&self, id: &str) -> Result<Option<Import>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, name, source, filename, findings_count, status, error_message, created_at, updated_at
            FROM imports
            WHERE id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let result = stmt.query_row(params![id], |row| {
            Ok(Import {
                id: row.get(0)?,
                name: row.get(1)?,
                source: row.get(2)?,
                filename: row.get(3)?,
                findings_count: row.get(4)?,
                status: row.get(5)?,
                error_message: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        });

        match result {
            Ok(import) => Ok(Some(import)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    pub fn update_import_status(&self, id: &str, status: &str, findings_count: Option<i32>, error_message: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE imports
            SET status = ?2, findings_count = COALESCE(?3, findings_count), error_message = ?4, updated_at = ?5
            WHERE id = ?1
            "#,
            params![id, status, findings_count, error_message, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn delete_import(&self, id: &str) -> Result<()> {
        // First delete all imported findings associated with this import
        self.conn.execute("DELETE FROM imported_findings WHERE import_id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        // Then delete the import itself
        self.conn.execute("DELETE FROM imports WHERE id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        Ok(())
    }

    // =========================================================================
    // Imported Findings
    // =========================================================================

    pub fn create_imported_finding(&self, finding: &ImportedFinding) -> Result<ImportedFinding> {
        let id = if finding.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            finding.id.clone()
        };
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO imported_findings (
                id, import_id, original_id, vulnerability_type, severity,
                file_path, line_number, code_snippet, description, remediation,
                cwe, status, linked_finding_id, linked_assessment_id, repository_id,
                created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?16)
            "#,
            params![
                id,
                finding.import_id,
                finding.original_id,
                finding.vulnerability_type,
                finding.severity,
                finding.file_path,
                finding.line_number,
                finding.code_snippet,
                finding.description,
                finding.remediation,
                finding.cwe,
                finding.status,
                finding.linked_finding_id,
                finding.linked_assessment_id,
                finding.repository_id,
                now
            ],
        ).map_err(|e| AppError::Database(e))?;

        let mut new_finding = finding.clone();
        new_finding.id = id;
        new_finding.created_at = now.clone();
        new_finding.updated_at = now;

        Ok(new_finding)
    }

    pub fn list_imported_findings(
        &self,
        import_id: Option<&str>,
        status: Option<&str>,
        severity: Option<&str>,
        repository_id: Option<&str>,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<ImportedFinding>> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let mut query = String::from(
            r#"
            SELECT id, import_id, original_id, vulnerability_type, severity,
                   file_path, line_number, code_snippet, description, remediation,
                   cwe, status, linked_finding_id, linked_assessment_id, repository_id,
                   created_at, updated_at
            FROM imported_findings
            WHERE 1=1
            "#
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut param_idx = 1;

        if let Some(iid) = import_id {
            query.push_str(&format!(" AND import_id = ?{}", param_idx));
            params_vec.push(Box::new(iid.to_string()));
            param_idx += 1;
        }

        if let Some(stat) = status {
            query.push_str(&format!(" AND status = ?{}", param_idx));
            params_vec.push(Box::new(stat.to_string()));
            param_idx += 1;
        }

        if let Some(sev) = severity {
            query.push_str(&format!(" AND severity = ?{}", param_idx));
            params_vec.push(Box::new(sev.to_string()));
            param_idx += 1;
        }

        if let Some(rid) = repository_id {
            query.push_str(&format!(" AND repository_id = ?{}", param_idx));
            params_vec.push(Box::new(rid.to_string()));
            param_idx += 1;
        }

        query.push_str(&format!(" ORDER BY created_at DESC LIMIT ?{} OFFSET ?{}", param_idx, param_idx + 1));
        params_vec.push(Box::new(limit));
        params_vec.push(Box::new(offset));

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(ImportedFinding {
                id: row.get(0)?,
                import_id: row.get(1)?,
                original_id: row.get(2)?,
                vulnerability_type: row.get(3)?,
                severity: row.get(4)?,
                file_path: row.get(5)?,
                line_number: row.get(6)?,
                code_snippet: row.get(7)?,
                description: row.get(8)?,
                remediation: row.get(9)?,
                cwe: row.get(10)?,
                status: row.get(11)?,
                linked_finding_id: row.get(12)?,
                linked_assessment_id: row.get(13)?,
                repository_id: row.get(14)?,
                created_at: row.get(15)?,
                updated_at: row.get(16)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut findings = Vec::new();
        for row in rows {
            findings.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(findings)
    }

    pub fn get_imported_finding(&self, id: &str) -> Result<Option<ImportedFinding>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, import_id, original_id, vulnerability_type, severity,
                   file_path, line_number, code_snippet, description, remediation,
                   cwe, status, linked_finding_id, linked_assessment_id, repository_id,
                   created_at, updated_at
            FROM imported_findings
            WHERE id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let result = stmt.query_row(params![id], |row| {
            Ok(ImportedFinding {
                id: row.get(0)?,
                import_id: row.get(1)?,
                original_id: row.get(2)?,
                vulnerability_type: row.get(3)?,
                severity: row.get(4)?,
                file_path: row.get(5)?,
                line_number: row.get(6)?,
                code_snippet: row.get(7)?,
                description: row.get(8)?,
                remediation: row.get(9)?,
                cwe: row.get(10)?,
                status: row.get(11)?,
                linked_finding_id: row.get(12)?,
                linked_assessment_id: row.get(13)?,
                repository_id: row.get(14)?,
                created_at: row.get(15)?,
                updated_at: row.get(16)?,
            })
        });

        match result {
            Ok(finding) => Ok(Some(finding)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    pub fn update_imported_finding_status(
        &self,
        id: &str,
        status: &str,
        linked_finding_id: Option<&str>,
        linked_assessment_id: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE imported_findings
            SET status = ?2, linked_finding_id = COALESCE(?3, linked_finding_id),
                linked_assessment_id = COALESCE(?4, linked_assessment_id), updated_at = ?5
            WHERE id = ?1
            "#,
            params![id, status, linked_finding_id, linked_assessment_id, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn link_imported_finding_to_repository(&self, id: &str, repository_id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE imported_findings
            SET repository_id = ?2, updated_at = ?3
            WHERE id = ?1
            "#,
            params![id, repository_id, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn get_import_stats(&self) -> Result<serde_json::Value> {
        let total_imports: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imports",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let total_imported_findings: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let pending_validation: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings WHERE status = 'imported'",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let validating: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings WHERE status = 'validating'",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let confirmed: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings WHERE status = 'confirmed'",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let false_positive: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings WHERE status = 'false_positive'",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let critical: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings WHERE severity = 'critical'",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        let high: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM imported_findings WHERE severity = 'high'",
            [],
            |row| row.get(0),
        ).map_err(|e| AppError::Database(e))?;

        Ok(serde_json::json!({
            "total_imports": total_imports,
            "total_findings": total_imported_findings,
            "by_status": {
                "pending_validation": pending_validation,
                "validating": validating,
                "confirmed": confirmed,
                "false_positive": false_positive
            },
            "by_severity": {
                "critical": critical,
                "high": high
            }
        }))
    }

    // =========================================================================
    // Conversations
    // =========================================================================

    pub fn create_conversation(
        &self,
        title: &str,
        assessment_id: Option<&str>,
        repository_id: Option<&str>,
    ) -> Result<Conversation> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO conversations (id, title, created_at, updated_at, assessment_id, repository_id, is_archived)
            VALUES (?1, ?2, ?3, ?3, ?4, ?5, 0)
            "#,
            params![id, title, now, assessment_id, repository_id],
        ).map_err(|e| AppError::Database(e))?;

        Ok(Conversation {
            id,
            title: title.to_string(),
            created_at: now.clone(),
            updated_at: now,
            assessment_id: assessment_id.map(String::from),
            repository_id: repository_id.map(String::from),
            context_summary: None,
            is_archived: false,
            message_count: 0,
            last_message_preview: None,
        })
    }

    pub fn list_conversations(&self, limit: Option<i32>, include_archived: bool, assessment_id: Option<&str>) -> Result<Vec<Conversation>> {
        let limit = limit.unwrap_or(50);

        // Build WHERE clauses based on filters
        let mut where_clauses = Vec::new();
        if !include_archived {
            where_clauses.push("c.is_archived = 0");
        }
        if assessment_id.is_some() {
            where_clauses.push("c.assessment_id = ?2");
        }

        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let query = format!(
            r#"
            SELECT c.id, c.title, c.created_at, c.updated_at, c.assessment_id, c.repository_id,
                   c.context_summary, c.is_archived,
                   (SELECT COUNT(*) FROM chat_messages m WHERE m.conversation_id = c.id) as message_count,
                   (SELECT content FROM chat_messages m WHERE m.conversation_id = c.id ORDER BY timestamp DESC LIMIT 1) as last_message
            FROM conversations c
            {}
            ORDER BY c.updated_at DESC
            LIMIT ?1
            "#,
            where_clause
        );

        let mut stmt = self.conn.prepare(&query).map_err(|e| AppError::Database(e))?;

        let map_row = |row: &rusqlite::Row| -> rusqlite::Result<Conversation> {
            let last_message: Option<String> = row.get(9)?;
            let preview = last_message.map(|m| {
                if m.len() > 100 {
                    format!("{}...", &m[..100])
                } else {
                    m
                }
            });

            Ok(Conversation {
                id: row.get(0)?,
                title: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                assessment_id: row.get(4)?,
                repository_id: row.get(5)?,
                context_summary: row.get(6)?,
                is_archived: row.get::<_, i32>(7)? != 0,
                message_count: row.get(8)?,
                last_message_preview: preview,
            })
        };

        let rows = if let Some(aid) = assessment_id {
            stmt.query_map(params![limit, aid], map_row).map_err(|e| AppError::Database(e))?
        } else {
            stmt.query_map(params![limit], map_row).map_err(|e| AppError::Database(e))?
        };

        let mut conversations = Vec::new();
        for row in rows {
            conversations.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(conversations)
    }

    pub fn get_conversation(&self, id: &str) -> Result<Option<Conversation>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT c.id, c.title, c.created_at, c.updated_at, c.assessment_id, c.repository_id,
                   c.context_summary, c.is_archived,
                   (SELECT COUNT(*) FROM chat_messages m WHERE m.conversation_id = c.id) as message_count,
                   (SELECT content FROM chat_messages m WHERE m.conversation_id = c.id ORDER BY timestamp DESC LIMIT 1) as last_message
            FROM conversations c
            WHERE c.id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let result = stmt.query_row(params![id], |row| {
            let last_message: Option<String> = row.get(9)?;
            let preview = last_message.map(|m| {
                if m.len() > 100 {
                    format!("{}...", &m[..100])
                } else {
                    m
                }
            });

            Ok(Conversation {
                id: row.get(0)?,
                title: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
                assessment_id: row.get(4)?,
                repository_id: row.get(5)?,
                context_summary: row.get(6)?,
                is_archived: row.get::<_, i32>(7)? != 0,
                message_count: row.get(8)?,
                last_message_preview: preview,
            })
        });

        match result {
            Ok(conversation) => Ok(Some(conversation)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Database(e)),
        }
    }

    pub fn update_conversation(&self, id: &str, title: Option<&str>, context_summary: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        if let Some(t) = title {
            self.conn.execute(
                "UPDATE conversations SET title = ?2, updated_at = ?3 WHERE id = ?1",
                params![id, t, now],
            ).map_err(|e| AppError::Database(e))?;
        }

        if let Some(cs) = context_summary {
            self.conn.execute(
                "UPDATE conversations SET context_summary = ?2, updated_at = ?3 WHERE id = ?1",
                params![id, cs, now],
            ).map_err(|e| AppError::Database(e))?;
        }

        Ok(())
    }

    pub fn archive_conversation(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "UPDATE conversations SET is_archived = 1, updated_at = ?2 WHERE id = ?1",
            params![id, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn delete_conversation(&self, id: &str) -> Result<()> {
        // Messages are deleted via ON DELETE CASCADE
        self.conn.execute("DELETE FROM conversations WHERE id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;
        Ok(())
    }

    // =========================================================================
    // Chat Messages
    // =========================================================================

    pub fn add_chat_message(
        &self,
        conversation_id: &str,
        role: &str,
        content: &str,
        tool_calls: Option<&str>,
        findings_created: Option<&str>,
    ) -> Result<DbChatMessage> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO chat_messages (id, conversation_id, role, content, timestamp, tool_calls, findings_created)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![id, conversation_id, role, content, now, tool_calls, findings_created],
        ).map_err(|e| AppError::Database(e))?;

        // Update conversation updated_at
        self.conn.execute(
            "UPDATE conversations SET updated_at = ?2 WHERE id = ?1",
            params![conversation_id, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(DbChatMessage {
            id,
            conversation_id: conversation_id.to_string(),
            role: role.to_string(),
            content: content.to_string(),
            timestamp: now,
            tool_calls: tool_calls.map(String::from),
            findings_created: findings_created.map(String::from),
        })
    }

    pub fn list_chat_messages(&self, conversation_id: &str) -> Result<Vec<DbChatMessage>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, conversation_id, role, content, timestamp, tool_calls, findings_created
            FROM chat_messages
            WHERE conversation_id = ?1
            ORDER BY timestamp ASC
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let rows = stmt.query_map(params![conversation_id], |row| {
            Ok(DbChatMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                role: row.get(2)?,
                content: row.get(3)?,
                timestamp: row.get(4)?,
                tool_calls: row.get(5)?,
                findings_created: row.get(6)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(messages)
    }

    pub fn search_chat_messages(&self, query: &str, limit: Option<i32>) -> Result<Vec<DbChatMessage>> {
        let limit = limit.unwrap_or(50);
        let search_pattern = format!("%{}%", query);

        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, conversation_id, role, content, timestamp, tool_calls, findings_created
            FROM chat_messages
            WHERE content LIKE ?1
            ORDER BY timestamp DESC
            LIMIT ?2
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let rows = stmt.query_map(params![search_pattern, limit], |row| {
            Ok(DbChatMessage {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                role: row.get(2)?,
                content: row.get(3)?,
                timestamp: row.get(4)?,
                tool_calls: row.get(5)?,
                findings_created: row.get(6)?,
            })
        }).map_err(|e| AppError::Database(e))?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.map_err(|e| AppError::Database(e))?);
        }

        Ok(messages)
    }

    // =========================================================================
    // Projects
    // =========================================================================

    pub fn list_projects(&self, status: Option<&str>) -> Result<Vec<Project>> {
        let mut projects = Vec::new();

        if let Some(s) = status {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT p.id, p.name, p.description, p.status, p.created_at, p.updated_at,
                       (SELECT COUNT(*) FROM assessments a WHERE a.project_id = p.id) as assessment_count
                FROM projects p
                WHERE p.status = ?1
                ORDER BY p.updated_at DESC
                "#
            ).map_err(|e| AppError::Database(e))?;

            let rows = stmt.query_map(params![s], |row| {
                Ok(Project {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    status: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    assessment_count: row.get::<_, Option<i32>>(6)?.unwrap_or(0),
                })
            }).map_err(|e| AppError::Database(e))?;

            for row in rows {
                projects.push(row.map_err(|e| AppError::Database(e))?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT p.id, p.name, p.description, p.status, p.created_at, p.updated_at,
                       (SELECT COUNT(*) FROM assessments a WHERE a.project_id = p.id) as assessment_count
                FROM projects p
                ORDER BY p.updated_at DESC
                "#
            ).map_err(|e| AppError::Database(e))?;

            let rows = stmt.query_map([], |row| {
                Ok(Project {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    status: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                    assessment_count: row.get::<_, Option<i32>>(6)?.unwrap_or(0),
                })
            }).map_err(|e| AppError::Database(e))?;

            for row in rows {
                projects.push(row.map_err(|e| AppError::Database(e))?);
            }
        }

        Ok(projects)
    }

    pub fn get_project(&self, id: &str) -> Result<Option<Project>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT p.id, p.name, p.description, p.status, p.created_at, p.updated_at,
                   (SELECT COUNT(*) FROM assessments a WHERE a.project_id = p.id) as assessment_count
            FROM projects p
            WHERE p.id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let mut rows = stmt.query_map(params![id], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                status: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
                assessment_count: row.get::<_, Option<i32>>(6)?.unwrap_or(0),
            })
        }).map_err(|e| AppError::Database(e))?;

        if let Some(row) = rows.next() {
            Ok(Some(row.map_err(|e| AppError::Database(e))?))
        } else {
            Ok(None)
        }
    }

    pub fn create_project(&self, name: &str, description: Option<&str>) -> Result<Project> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO projects (id, name, description, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, 'active', ?4, ?4)
            "#,
            params![id, name, description, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(Project {
            id,
            name: name.to_string(),
            description: description.map(String::from),
            status: "active".to_string(),
            created_at: now.clone(),
            updated_at: now,
            assessment_count: 0,
        })
    }

    pub fn update_project(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        status: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE projects
            SET name = COALESCE(?2, name),
                description = COALESCE(?3, description),
                status = COALESCE(?4, status),
                updated_at = ?5
            WHERE id = ?1
            "#,
            params![id, name, description, status, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn delete_project(&self, id: &str) -> Result<()> {
        // First, unlink all assessments from this project
        self.conn.execute(
            "UPDATE assessments SET project_id = NULL WHERE project_id = ?1",
            params![id],
        ).map_err(|e| AppError::Database(e))?;

        // Then delete the project
        self.conn.execute("DELETE FROM projects WHERE id = ?1", params![id])
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn assign_assessment_to_project(&self, assessment_id: &str, project_id: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE assessments
            SET project_id = ?2, updated_at = ?3
            WHERE id = ?1
            "#,
            params![assessment_id, project_id, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    // =========================================================================
    // Terminal Sessions
    // =========================================================================

    pub fn create_terminal_session(
        &self,
        id: &str,
        assessment_id: Option<&str>,
        command: &str,
    ) -> Result<TerminalSession> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            INSERT INTO terminal_sessions (id, assessment_id, status, command, created_at)
            VALUES (?1, ?2, 'running', ?3, ?4)
            "#,
            params![id, assessment_id, command, now],
        ).map_err(|e| AppError::Database(e))?;

        Ok(TerminalSession {
            id: id.to_string(),
            assessment_id: assessment_id.map(|s| s.to_string()),
            status: "running".to_string(),
            command: command.to_string(),
            created_at: now,
            ended_at: None,
            exit_code: None,
            transcript: None,
        })
    }

    pub fn list_terminal_sessions(&self) -> Result<Vec<TerminalSession>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, assessment_id, status, command, created_at, ended_at, exit_code, transcript
            FROM terminal_sessions
            ORDER BY created_at DESC
            LIMIT 50
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let sessions = stmt.query_map([], |row| {
            Ok(TerminalSession {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                status: row.get(2)?,
                command: row.get(3)?,
                created_at: row.get(4)?,
                ended_at: row.get(5)?,
                exit_code: row.get(6)?,
                transcript: row.get(7)?,
            })
        }).map_err(|e| AppError::Database(e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(sessions)
    }

    pub fn get_terminal_session(&self, id: &str) -> Result<Option<TerminalSession>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, assessment_id, status, command, created_at, ended_at, exit_code, transcript
            FROM terminal_sessions
            WHERE id = ?1
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let session = stmt.query_row(params![id], |row| {
            Ok(TerminalSession {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                status: row.get(2)?,
                command: row.get(3)?,
                created_at: row.get(4)?,
                ended_at: row.get(5)?,
                exit_code: row.get(6)?,
                transcript: row.get(7)?,
            })
        }).ok();

        Ok(session)
    }

    pub fn end_terminal_session(&self, id: &str, exit_code: Option<i32>) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            r#"
            UPDATE terminal_sessions
            SET status = 'exited', ended_at = ?2, exit_code = ?3
            WHERE id = ?1
            "#,
            params![id, now, exit_code],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn link_terminal_session_to_assessment(&self, session_id: &str, assessment_id: &str) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE terminal_sessions
            SET assessment_id = ?2
            WHERE id = ?1
            "#,
            params![session_id, assessment_id],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn save_terminal_transcript(&self, session_id: &str, transcript: &str) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE terminal_sessions
            SET transcript = ?2
            WHERE id = ?1
            "#,
            params![session_id, transcript],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    pub fn get_terminal_sessions_for_assessment(&self, assessment_id: &str) -> Result<Vec<TerminalSession>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, assessment_id, status, command, created_at, ended_at, exit_code, transcript
            FROM terminal_sessions
            WHERE assessment_id = ?1
            ORDER BY created_at DESC
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let sessions = stmt.query_map(params![assessment_id], |row| {
            Ok(TerminalSession {
                id: row.get(0)?,
                assessment_id: row.get(1)?,
                status: row.get(2)?,
                command: row.get(3)?,
                created_at: row.get(4)?,
                ended_at: row.get(5)?,
                exit_code: row.get(6)?,
                transcript: row.get(7)?,
            })
        }).map_err(|e| AppError::Database(e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(sessions)
    }

    // =========================================================================
    // Assessment Chat Messages
    // =========================================================================

    pub fn save_assessment_chat_messages(
        &self,
        assessment_id: &str,
        messages: &[AssessmentChatMessage],
    ) -> Result<()> {
        // Delete existing messages for this assessment and re-insert
        self.conn.execute(
            "DELETE FROM assessment_chat_messages WHERE assessment_id = ?1",
            params![assessment_id],
        ).map_err(|e| AppError::Database(e))?;

        let mut stmt = self.conn.prepare(
            r#"
            INSERT INTO assessment_chat_messages (id, assessment_id, msg_type, content, variant, session_key, timestamp, sort_order)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        ).map_err(|e| AppError::Database(e))?;

        for (i, msg) in messages.iter().enumerate() {
            stmt.execute(params![
                msg.id,
                assessment_id,
                msg.msg_type,
                msg.content,
                msg.variant,
                msg.session_key,
                msg.timestamp,
                i as i32,
            ]).map_err(|e| AppError::Database(e))?;
        }

        Ok(())
    }

    pub fn load_assessment_chat_messages(
        &self,
        assessment_id: &str,
    ) -> Result<Vec<AssessmentChatMessage>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, msg_type, content, variant, session_key, timestamp
            FROM assessment_chat_messages
            WHERE assessment_id = ?1
            ORDER BY sort_order ASC
            "#,
        ).map_err(|e| AppError::Database(e))?;

        let messages = stmt.query_map(params![assessment_id], |row| {
            Ok(AssessmentChatMessage {
                id: row.get(0)?,
                msg_type: row.get(1)?,
                content: row.get(2)?,
                variant: row.get(3)?,
                session_key: row.get(4)?,
                timestamp: row.get(5)?,
            })
        }).map_err(|e| AppError::Database(e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(messages)
    }

    pub fn delete_assessment_chat_messages(&self, assessment_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM assessment_chat_messages WHERE assessment_id = ?1",
            params![assessment_id],
        ).map_err(|e| AppError::Database(e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes access to the process-global `DB_PATH`.
    ///
    /// `set_var` followed by `Database::new()` is a read-after-write on shared
    /// process state, so two tests running concurrently can interleave and open
    /// each other's file. The window is small enough that it usually passes,
    /// which is exactly what makes it a bad thing to rely on — under CI load it
    /// would flake. The lock removes the race instead of hoping it doesn't fire.
    static DB_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Point `Database::new()` at a throwaway file. `get_db_path` checks the
    /// `DB_PATH` env var first, so this is the supported override.
    ///
    /// Returns the lock guard alongside the handle — the caller must hold it for
    /// the life of the test, so bind it (`let (_g, db) = ...`) rather than
    /// dropping it.
    fn temp_db(tag: &str) -> (std::sync::MutexGuard<'static, ()>, Database) {
        // Poisoning only happens if another test panicked while holding the
        // lock; that test has already failed, so recovering here keeps the rest
        // reporting real results instead of a cascade of poison errors.
        let guard = DB_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let path = std::env::temp_dir().join(format!(
            "maestro-test-{}-{}.db",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_file(&path);
        std::env::set_var("DB_PATH", &path);
        // new() runs initialize_schema() itself, which includes the parity
        // migration — so opening the file is all the setup a test needs.
        (guard, Database::new().expect("open temp db"))
    }

    fn minimal(title: &str) -> Finding {
        Finding {
            title: title.to_string(),
            severity: "high".to_string(),
            status: "open".to_string(),
            target: "https://app.example.com".to_string(),
            description: "d".to_string(),
            ..Default::default()
        }
    }

    /// The parity columns must survive a create → read round trip.
    ///
    /// This is the exact bug class the columns were added to fix: it is easy to
    /// add a column and the struct field, and forget the INSERT — leaving the
    /// value silently NULL forever. Reading it back is the only way to know.
    #[test]
    fn parity_columns_survive_create_and_read() {
        let (_guard, db) = temp_db("parity-create");

        let mut f = minimal("calibrated finding");
        f.exploitable = Some("TRUE".into());
        f.original_severity = Some("critical".into());
        f.calibrated_severity = Some("medium".into());
        f.calibration_rule = Some("Rule 1 — outcome anchored".into());
        f.calibration_justification = Some("not reachable from the internet".into());
        f.tags = Some(vec!["triaged".into(), "sast".into()]);
        f.jira_ticket = Some("SEC-42".into());
        f.jira_url = Some("https://example.atlassian.net/browse/SEC-42".into());
        f.validated_at = Some("2026-07-29T00:00:00Z".into());
        f.validation_method = Some("oracle".into());
        f.source_tool = Some("semgrep".into());
        f.evidence_type = Some("text".into());

        let created = db.create_finding(&f).expect("create");
        let read = db
            .get_finding(&created.id)
            .expect("get")
            .expect("finding exists");

        assert_eq!(read.exploitable.as_deref(), Some("TRUE"));
        assert_eq!(read.original_severity.as_deref(), Some("critical"));
        assert_eq!(read.calibrated_severity.as_deref(), Some("medium"));
        assert_eq!(read.calibration_rule.as_deref(), Some("Rule 1 — outcome anchored"));
        assert_eq!(
            read.calibration_justification.as_deref(),
            Some("not reachable from the internet")
        );
        assert_eq!(
            read.tags,
            Some(vec!["triaged".to_string(), "sast".to_string()])
        );
        assert_eq!(read.jira_ticket.as_deref(), Some("SEC-42"));
        assert_eq!(read.validation_method.as_deref(), Some("oracle"));
        assert_eq!(read.source_tool.as_deref(), Some("semgrep"));
        assert_eq!(read.evidence_type.as_deref(), Some("text"));
    }

    /// The severity calibrator writes its verdict through `update_finding`.
    /// If the field isn't in that whitelist the write is silently dropped and a
    /// local run shows only scanner-original severities.
    #[test]
    fn calibration_is_writable_through_update() {
        let (_guard, db) = temp_db("parity-update");
        let created = db.create_finding(&minimal("uncalibrated")).expect("create");

        db.update_finding(
            &created.id,
            &serde_json::json!({
                "calibrated_severity": "low",
                "calibration_rule": "Rule 3 — CLI-only path cap",
                "exploitable": "FALSE",
                "tags": ["downgraded"],
            }),
        )
        .expect("update");

        let read = db.get_finding(&created.id).expect("get").expect("exists");
        assert_eq!(read.calibrated_severity.as_deref(), Some("low"));
        assert_eq!(read.calibration_rule.as_deref(), Some("Rule 3 — CLI-only path cap"));
        assert_eq!(read.exploitable.as_deref(), Some("FALSE"));
        assert_eq!(read.tags, Some(vec!["downgraded".to_string()]));
    }

    /// list_findings uses positional row indices and its own SELECT list. A
    /// column appended to one SELECT but not the other would read garbage or
    /// panic, so exercise the list path too — not just get_finding.
    #[test]
    fn list_path_reads_parity_columns() {
        let (_guard, db) = temp_db("parity-list");
        let mut f = minimal("listed finding");
        f.calibrated_severity = Some("info".into());
        f.exploitable = Some("TRUE".into());
        db.create_finding(&f).expect("create");

        let rows = db
            .list_findings(None, None, None, None, None, None, Some(10), None, None, None, None, None)
            .expect("list");
        let row = rows.first().expect("one row");
        assert_eq!(row.calibrated_severity.as_deref(), Some("info"));
        assert_eq!(row.exploitable.as_deref(), Some("TRUE"));
    }
}
