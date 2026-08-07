-- Repositories + org-level config storage (v0.1.19).
--
-- Repositories are org-shared metadata: name, description, languages,
-- GitHub URL, default scan settings. The local clone PATH is per-user (each
-- machine has its own /Users/x/work/foo) so we don't make it authoritative
-- here — we store the creator's path as `default_path` for reference, and
-- each user keeps their own mapping client-side (future: a per-user
-- repo_paths table; for now, the desktop overrides at render time).
-- created_by tracks provenance.
--
-- org_configs is a generic key-value store per org for shared settings:
-- scope, integrations (Jira project, SharePoint base, email distros), llm
-- defaults, tools enabled. One row per (org_id, kind). Personal credentials
-- (Jira API tokens, etc.) stay client-side in the OS keychain and never
-- land here.
--
-- All CREATE TABLE / TYPE statements are idempotent so the backend can
-- be redeployed without manual schema teardown.

DO $$ BEGIN
    CREATE TYPE reposourcetype AS ENUM ('local', 'github', 'gitlab');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS repositories (
    id VARCHAR PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    -- The creator's clone path. Hint for teammates ("I cloned to ~/work/foo")
    -- but each user's actual path is per-machine — the desktop overrides at
    -- render time using a local mapping table.
    default_path TEXT,
    source_type reposourcetype DEFAULT 'local',
    github_owner VARCHAR(255),
    github_repo VARCHAR(255),
    github_url TEXT,
    -- detected languages, e.g. ["typescript", "python", "go"]
    languages JSONB DEFAULT '[]'::jsonb,
    -- {scan_types: [...], severity_threshold: "...", include_git_history: bool}
    default_scan_config JSONB DEFAULT '{}'::jsonb,
    last_scan_at TIMESTAMPTZ,
    -- {critical: n, high: n, medium: n, low: n} from the most recent scan
    last_scan_findings JSONB,
    org_id VARCHAR REFERENCES organizations(id) ON DELETE CASCADE,
    created_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_repositories_org_id ON repositories(org_id);
CREATE INDEX IF NOT EXISTS idx_repositories_created_by ON repositories(created_by);

CREATE TABLE IF NOT EXISTS org_configs (
    org_id VARCHAR NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Which config: 'scope', 'integrations', 'llm', 'tools', 'agents'.
    -- Whitelisted at the API layer so callers can't spam new kinds.
    kind VARCHAR(64) NOT NULL,
    -- The full config blob — shape is kind-specific, validated at the
    -- frontend/Tauri layer. Backend stores opaque JSON.
    value JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by VARCHAR REFERENCES users(id),
    PRIMARY KEY (org_id, kind)
);

CREATE INDEX IF NOT EXISTS idx_org_configs_org_id ON org_configs(org_id);
