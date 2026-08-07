import Database from "better-sqlite3";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import * as yaml from "js-yaml";

let db: Database.Database;

/**
 * Get the shared database path from config or defaults.
 * Priority: 1. DB_PATH env var, 2. config/database.yml, 3. default ~/.pentest/data/pentest.db
 */
function getSharedDbPath(): string {
  // 1. Check environment variable first
  if (process.env.DB_PATH) {
    return expandPath(process.env.DB_PATH);
  }

  // 2. Try to read from config file
  const configPath = path.join(__dirname, "../../../config/database.yml");
  try {
    if (fs.existsSync(configPath)) {
      const configContent = fs.readFileSync(configPath, "utf-8");
      const config = yaml.load(configContent) as { path?: string };
      if (config?.path) {
        return expandPath(config.path);
      }
    }
  } catch (e) {
    console.log("[Database] Could not read config file, using default path");
  }

  // 3. Default path
  return expandPath("~/.pentest/data/pentest.db");
}

/**
 * Expand ~ to home directory and resolve path
 */
function expandPath(p: string): string {
  if (p.startsWith("~/")) {
    return path.join(os.homedir(), p.slice(2));
  }
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return path.resolve(p);
}

export async function initializeDatabase(): Promise<void> {
  const dbPath = getSharedDbPath();

  // Ensure parent directory exists
  const dbDir = path.dirname(dbPath);
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log(`[Database] Created directory: ${dbDir}`);
  }

  console.log(`[Database] Using shared database at: ${dbPath}`);

  db = new Database(dbPath);

  // Enable WAL mode for better concurrent access
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("foreign_keys = ON");
  
  // Create tables
  db.exec(`
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

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      description TEXT,
      target TEXT NOT NULL,
      evidence TEXT,
      remediation TEXT,
      cve TEXT,
      cycode_ref TEXT,
      status TEXT DEFAULT 'open',
      created_at TEXT NOT NULL,
      updated_at TEXT,
      jira_ticket TEXT
    );

    CREATE TABLE IF NOT EXISTS scan_sessions (
      id TEXT PRIMARY KEY,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      scope_snapshot TEXT,
      status TEXT DEFAULT 'running',
      findings_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS assessments (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      targets TEXT,
      repo_paths TEXT,
      credential_app TEXT,
      jira_project TEXT,
      email_recipients TEXT,
      severity_threshold TEXT DEFAULT 'medium',
      options TEXT,
      progress INTEGER DEFAULT 0,
      current_step TEXT,
      started_at TEXT NOT NULL,
      completed_at TEXT,
      findings_count INTEGER DEFAULT 0,
      critical_count INTEGER DEFAULT 0,
      high_count INTEGER DEFAULT 0,
      error_message TEXT
    );

    -- Tool-execution provenance: one row per executeInKali call, tagged with the
    -- MCP tool / test it ran under (via AsyncLocalStorage). Captures the exit code
    -- the handler soft-fail (|| echo failed) would otherwise swallow. Local-first;
    -- promoted as a per-assessment summary at end-of-run (Shape A).
    CREATE TABLE IF NOT EXISTS tool_executions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      assessment_id TEXT,
      tool_name TEXT,
      test_id TEXT,
      binary TEXT,
      command TEXT,
      exit_code INTEGER,
      ran INTEGER NOT NULL DEFAULT 1,
      duration_ms INTEGER,
      stderr_excerpt TEXT,
      timestamp TEXT NOT NULL
    );

    -- Independent binary availability probe (command -v + --version). Distinct from
    -- exit codes because the || echo "NOT INSTALLED" pattern makes an absent tool
    -- still exit 0 — only an independent probe can prove the binary was actually present.
    CREATE TABLE IF NOT EXISTS tool_availability (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      assessment_id TEXT,
      binary TEXT NOT NULL,
      installed INTEGER NOT NULL,
      version TEXT,
      checked_at TEXT NOT NULL,
      UNIQUE(assessment_id, binary)
    );

    -- Per-test execution overview (Option B): one row per (assessment, agent, test_id)
    -- imported from the agents' reports/*-results.json checkpoints. enforced mirrors
    -- the deterministic provenance gate's verdict (a PASS/N_A whose backing tool was
    -- absent/never ran is enforced=1 with a reason). Local-first; promoted as a
    -- per-assessment summary at end-of-run (Shape A) via promote_execution_meta.
    CREATE TABLE IF NOT EXISTS assessment_test_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      assessment_id TEXT,
      agent TEXT,
      test_id TEXT NOT NULL,
      status TEXT NOT NULL,
      enforced INTEGER DEFAULT 0,
      enforced_reason TEXT,
      finding_count INTEGER DEFAULT 0,
      notes TEXT,
      created_at TEXT NOT NULL,
      UNIQUE(assessment_id, agent, test_id)
    );

    -- Scope decisions (Option B): one row per (assessment, target, in_scope) captured
    -- at each validateToolScope call. attempts counts how many times a target was
    -- resolved to the same in/out verdict; dimension is network/cloud/k8s/identity
    -- when determinable. Local-first; promoted at end-of-run via promote_execution_meta.
    CREATE TABLE IF NOT EXISTS scope_decisions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      assessment_id TEXT,
      target TEXT NOT NULL,
      dimension TEXT,
      in_scope INTEGER NOT NULL,
      reason TEXT,
      attempts INTEGER NOT NULL DEFAULT 1,
      last_seen TEXT NOT NULL,
      UNIQUE(assessment_id, target, in_scope)
    );

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_tool_exec_assessment ON tool_executions(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_tool_exec_tool ON tool_executions(tool_name);
    CREATE INDEX IF NOT EXISTS idx_tool_avail_assessment ON tool_availability(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_test_results_assessment ON assessment_test_results(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_scope_decisions_assessment ON scope_decisions(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
    CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
    CREATE INDEX IF NOT EXISTS idx_assessments_type ON assessments(type);
    CREATE INDEX IF NOT EXISTS idx_assessments_started_at ON assessments(started_at);
  `);

  // Run migrations (adds missing columns to existing tables)
  runMigrations(db);

  // Create indexes that depend on migrated columns (must run after migrations)
  try {
    db.exec(`CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool);`);
  } catch {
    // Column may not exist yet in legacy schemas
  }
}

function runMigrations(db: Database.Database): void {
  // Helper to safely add columns (ignores if exists)
  const addColumnSafely = (table: string, column: string, definition: string) => {
    try {
      db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run();
    } catch {
      // Column already exists, ignore
    }
  };

  // ==========================================================================
  // AUDIT_LOGS TABLE MIGRATIONS (legacy schema had action/command, new has tool/arguments)
  // ==========================================================================

  // Check if legacy 'action' column exists — if so, recreate the table with new schema
  const auditColumns = db.prepare("PRAGMA table_info(audit_logs)").all() as { name: string }[];
  const hasLegacyAction = auditColumns.some((c) => c.name === "action");
  if (hasLegacyAction) {
    console.log("[Migration] Recreating audit_logs table (legacy 'action' column detected)");
    db.exec(`
      ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
      CREATE TABLE audit_logs (
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
      INSERT OR IGNORE INTO audit_logs (id, timestamp, tool, target, arguments, user, session_id, result_status, execution_time_ms)
        SELECT id, timestamp, COALESCE(tool, action, 'unknown'), target, COALESCE(arguments, command), user, session_id, result_status, execution_time_ms
        FROM audit_logs_legacy;
      DROP TABLE audit_logs_legacy;
    `);
  } else {
    addColumnSafely("audit_logs", "tool", "TEXT");
    addColumnSafely("audit_logs", "arguments", "TEXT");
    addColumnSafely("audit_logs", "session_id", "TEXT");
    addColumnSafely("audit_logs", "result_status", "TEXT");
    addColumnSafely("audit_logs", "execution_time_ms", "INTEGER");
  }

  // ==========================================================================
  // FINDINGS TABLE MIGRATIONS (merge MCP + Tauri columns)
  // ==========================================================================

  // MCP deduplication columns
  addColumnSafely("findings", "fingerprint", "TEXT");
  addColumnSafely("findings", "vulnerability_type", "TEXT");
  addColumnSafely("findings", "source", "TEXT");
  addColumnSafely("findings", "first_seen_at", "TEXT");
  addColumnSafely("findings", "last_seen_at", "TEXT");
  addColumnSafely("findings", "occurrence_count", "INTEGER DEFAULT 1");

  // Code context columns
  addColumnSafely("findings", "file_path", "TEXT");
  addColumnSafely("findings", "line_start", "INTEGER");
  addColumnSafely("findings", "line_end", "INTEGER");
  addColumnSafely("findings", "code_snippet", "TEXT");
  addColumnSafely("findings", "cwe", "TEXT");
  addColumnSafely("findings", "category", "TEXT");

  // Code remediation columns (populated by code-context-enricher)
  addColumnSafely("findings", "remediation_code", "TEXT");
  addColumnSafely("findings", "remediation_explanation", "TEXT");

  // Exploitability and multi-file location columns
  addColumnSafely("findings", "exploitable", "TEXT DEFAULT 'potentially'"); // "true" | "false" | "potentially"
  addColumnSafely("findings", "file_locations", "TEXT"); // JSON array of {file, line, context, commit_hash, author}

  // Structured correlation keys (mirror backend migration 0030) — carried locally
  // so complete_assessment can promote any scanner-set value to the cloud.
  addColumnSafely("findings", "port", "INTEGER");
  addColumnSafely("findings", "service", "TEXT");
  addColumnSafely("findings", "component", "TEXT");
  addColumnSafely("findings", "image_digest", "TEXT");

  // Oracle verdict columns (mirror backend migration 0049). A verdict is EARNED
  // by a named oracle in code — create_finding can never write these, it can only
  // ever produce `candidate`. See verification/oracles.ts and
  // docs/oracle-verification-layer.md.
  addColumnSafely("findings", "verdict", "TEXT DEFAULT 'candidate'"); // candidate | verified | refuted
  addColumnSafely("findings", "oracle_kind", "TEXT");
  addColumnSafely("findings", "receipt_json", "TEXT"); // machine evidence the oracle observed
  addColumnSafely("findings", "capsule_json", "TEXT"); // the replay recipe, re-runnable standalone
  addColumnSafely("findings", "replay_n", "INTEGER");
  addColumnSafely("findings", "replay_successes", "INTEGER");
  addColumnSafely("findings", "verified_at", "TEXT");
  // The vulnerability mechanism the finding CLAIMS. An oracle can pass while
  // demonstrating a different bug than the one claimed (ExploitGym found 69 of
  // 226 successful exploits hit an unintended vulnerability); binding the receipt
  // to the claim is what lets us catch that in code rather than in prose.
  addColumnSafely("findings", "claimed_mechanism", "TEXT");

  // Tauri-expected columns (for frontend compatibility)
  addColumnSafely("findings", "assessment_id", "TEXT");
  addColumnSafely("findings", "cvss_score", "REAL");
  addColumnSafely("findings", "cve_ids", "TEXT"); // JSON array of CVE IDs

  // ==========================================================================
  // ASSESSMENTS TABLE MIGRATIONS (merge MCP + Tauri columns)
  // ==========================================================================

  // Tauri-expected columns
  addColumnSafely("assessments", "name", "TEXT");
  addColumnSafely("assessments", "assessment_type", "TEXT");
  addColumnSafely("assessments", "created_at", "TEXT");
  addColumnSafely("assessments", "updated_at", "TEXT");

  // Sync column name: MCP uses 'type', Tauri uses 'assessment_type'
  // Both will be populated, assessment_type mirrors type
  try {
    db.exec(`
      UPDATE assessments SET assessment_type = type WHERE assessment_type IS NULL AND type IS NOT NULL;
      UPDATE assessments SET name = 'Assessment ' || id WHERE name IS NULL;
    `);
  } catch {
    // Ignore if columns don't exist yet
  }

  // ==========================================================================
  // JUNCTION TABLES (MCP deduplication support)
  // ==========================================================================

  db.exec(`
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
  `);

  // ==========================================================================
  // TAURI TABLES (frontend features)
  // ==========================================================================

  // Repositories table
  db.exec(`
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
  `);

  // Imports tracking
  db.exec(`
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
      FOREIGN KEY (import_id) REFERENCES imports(id)
    );

    CREATE INDEX IF NOT EXISTS idx_imports_source ON imports(source);
    CREATE INDEX IF NOT EXISTS idx_imports_status ON imports(status);
    CREATE INDEX IF NOT EXISTS idx_imported_findings_import ON imported_findings(import_id);
    CREATE INDEX IF NOT EXISTS idx_imported_findings_severity ON imported_findings(severity);
    CREATE INDEX IF NOT EXISTS idx_imported_findings_status ON imported_findings(status);
  `);

  // Conversations and chat messages
  db.exec(`
    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      assessment_id TEXT,
      repository_id TEXT,
      context_summary TEXT,
      is_archived INTEGER DEFAULT 0
    );

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

    CREATE INDEX IF NOT EXISTS idx_conversations_assessment ON conversations(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id);
  `);

  // Reports table
  db.exec(`
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
      exploitable_count INTEGER DEFAULT 0
    );
  `);

  // Projects table (for grouping assessments)
  db.exec(`
    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  addColumnSafely("assessments", "project_id", "TEXT");

  // ==========================================================================
  // ASSESSMENT CHECKPOINTS (orchestrator resume support)
  // ==========================================================================

  db.exec(`
    CREATE TABLE IF NOT EXISTS assessment_checkpoints (
      id TEXT PRIMARY KEY,
      assessment_id TEXT NOT NULL,
      agent_name TEXT NOT NULL,
      phase_index INTEGER NOT NULL,
      shared_context TEXT,
      all_findings TEXT,
      completed_agents TEXT,
      orchestrator_config TEXT,
      status TEXT NOT NULL DEFAULT 'completed',
      error_message TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_checkpoints_assessment ON assessment_checkpoints(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_checkpoints_created ON assessment_checkpoints(created_at);
  `);

  // ==========================================================================
  // FINDING CHAINS (attack chain analysis)
  // ==========================================================================

  db.exec(`
    CREATE TABLE IF NOT EXISTS finding_chains (
      id TEXT PRIMARY KEY,
      assessment_id TEXT,
      pattern_id TEXT,
      name TEXT NOT NULL,
      description TEXT,
      severity_combined TEXT,
      confidence REAL,
      status TEXT DEFAULT 'hypothesized',
      finding_id TEXT,
      emergent INTEGER DEFAULT 0,
      steps_json TEXT,
      required_tests_json TEXT,
      exploit_results_json TEXT,
      created_at TEXT NOT NULL,
      validated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS finding_chain_links (
      id TEXT PRIMARY KEY,
      chain_id TEXT NOT NULL,
      finding_id TEXT NOT NULL,
      step_order INTEGER NOT NULL,
      grants_json TEXT,
      requires_json TEXT,
      role TEXT DEFAULT 'step',
      FOREIGN KEY (chain_id) REFERENCES finding_chains(id)
    );

    CREATE INDEX IF NOT EXISTS idx_finding_chains_assessment ON finding_chains(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_finding_chains_status ON finding_chains(status);
    CREATE INDEX IF NOT EXISTS idx_finding_chain_links_chain ON finding_chain_links(chain_id);
    CREATE INDEX IF NOT EXISTS idx_finding_chain_links_finding ON finding_chain_links(finding_id);
  `);

  // ==========================================================================
  // INDEXES
  // ==========================================================================

  try {
    db.prepare("CREATE UNIQUE INDEX idx_findings_fingerprint ON findings(fingerprint)").run();
  } catch {
    // Index already exists
  }

  try {
    db.prepare("CREATE INDEX idx_findings_assessment ON findings(assessment_id)").run();
  } catch {
    // Index already exists
  }
}

export function getDatabase(): Database.Database {
  return db;
}
