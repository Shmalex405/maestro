-- Imports, imported findings, and scan snapshots (v0.1.21).
--
-- Imports: a record of a CSV/Cycode bulk import. Holds metadata about the
-- batch + a count of rows; the parsed rows live in `imported_findings`
-- linked by `import_id`. Org-scoped, created_by tracks who pushed it.
--
-- Imported findings: rows from external sources (Cycode, custom CSV) that
-- are kept distinct from native findings until validated. Each row carries
-- enough source context (file/line/CVE) to spawn a validation assessment
-- against a live target. `linked_finding_id` set after promotion;
-- `linked_assessment_id` set after a validation run completes.
--
-- Scan snapshots: a frozen point-in-time count of findings per
-- assessment, captured at meaningful moments (assessment completed, manual
-- "freeze this baseline" action). Used for diff views and trend reports.

DO $$ BEGIN
    CREATE TYPE importedfindingstatus AS ENUM (
        'imported', 'validating', 'validated_exploitable',
        'validated_partial', 'validated_safe', 'duplicate', 'rejected'
    );
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS imports (
    id VARCHAR PRIMARY KEY,
    name VARCHAR(255),
    -- e.g. "cycode", "wiz", "snyk", "custom"
    source VARCHAR(64),
    filename VARCHAR(512),
    -- Total rows parsed from the input file
    row_count INTEGER DEFAULT 0,
    -- The raw CSV content kept on the import record for re-parsing /
    -- audit. Capped at ~1MB at the API layer.
    raw_csv TEXT,
    org_id VARCHAR REFERENCES organizations(id) ON DELETE CASCADE,
    created_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_imports_org_id ON imports(org_id);
CREATE INDEX IF NOT EXISTS idx_imports_created_by ON imports(created_by);

CREATE TABLE IF NOT EXISTS imported_findings (
    id VARCHAR PRIMARY KEY,
    import_id VARCHAR REFERENCES imports(id) ON DELETE CASCADE,
    -- Source-specific reference (Cycode finding ID, etc.)
    external_ref VARCHAR(255),
    title VARCHAR(512),
    severity severity,
    description TEXT,
    cve VARCHAR(64),
    cwe VARCHAR(64),
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    status importedfindingstatus DEFAULT 'imported',
    repository_id VARCHAR REFERENCES repositories(id) ON DELETE SET NULL,
    linked_finding_id VARCHAR REFERENCES findings(id) ON DELETE SET NULL,
    linked_assessment_id VARCHAR REFERENCES assessments(id) ON DELETE SET NULL,
    raw_row JSONB,
    org_id VARCHAR REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_imported_findings_import_id ON imported_findings(import_id);
CREATE INDEX IF NOT EXISTS idx_imported_findings_status ON imported_findings(status);
CREATE INDEX IF NOT EXISTS idx_imported_findings_org_id ON imported_findings(org_id);

CREATE TABLE IF NOT EXISTS scan_snapshots (
    id VARCHAR PRIMARY KEY,
    assessment_id VARCHAR REFERENCES assessments(id) ON DELETE CASCADE,
    target VARCHAR(512),
    -- Severity-bucketed counts at the moment of the freeze.
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    total_count INTEGER DEFAULT 0,
    -- Optional notes the user typed when snapshotting.
    notes TEXT,
    org_id VARCHAR REFERENCES organizations(id) ON DELETE CASCADE,
    created_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_snapshots_assessment_id ON scan_snapshots(assessment_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_org_id ON scan_snapshots(org_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_target ON scan_snapshots(target);
