-- Initial schema for maestro-backend.
--
-- Matches the Python backend's SQLAlchemy-generated schema byte-for-byte.
-- SQLAlchemy `Enum(PyEnum)` creates native Postgres `CREATE TYPE ... AS
-- ENUM (...)`; we do the same so queries that cast parameters to an enum
-- type (SELECT ... WHERE severity = $1::severity) work against both
-- backends without either side needing schema changes.
--
-- CREATE TYPE / CREATE TABLE are wrapped to be idempotent: whichever
-- backend boots first wins, and the other no-ops safely.

DO $$ BEGIN
    CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE findingstatus AS ENUM ('open', 'in_progress', 'remediated', 'accepted', 'false_positive');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE assessmentstatus AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled', 'not_started');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE assessmenttype AS ENUM ('full', 'recon', 'vuln_scan', 'web_app', 'code_scan', 'cycode_validation', 'exploit_validation');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE projectstatus AS ENUM ('active', 'archived');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE messagerole AS ENUM ('user', 'assistant', 'system');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(255),
    name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    roles JSONB DEFAULT '[]'::jsonb,
    org_id VARCHAR REFERENCES organizations(id),
    external_id VARCHAR(255) UNIQUE,
    auth_provider VARCHAR(50) DEFAULT 'local',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);

CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status projectstatus DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    org_id VARCHAR REFERENCES organizations(id),
    created_by VARCHAR REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS assessments (
    id VARCHAR PRIMARY KEY,
    name VARCHAR(255),
    type assessmenttype NOT NULL,
    status assessmentstatus DEFAULT 'pending',
    project_id VARCHAR REFERENCES projects(id) ON DELETE SET NULL,
    targets JSONB DEFAULT '[]'::jsonb,
    repo_paths JSONB DEFAULT '[]'::jsonb,
    progress INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    error_message TEXT,
    config JSONB DEFAULT '{}'::jsonb,
    phases JSONB DEFAULT '[]'::jsonb,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    org_id VARCHAR REFERENCES organizations(id),
    created_by VARCHAR REFERENCES users(id),
    client_id VARCHAR
);

CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity NOT NULL,
    status findingstatus DEFAULT 'open',
    target VARCHAR(500) NOT NULL,
    target_type VARCHAR(50),
    evidence TEXT,
    remediation TEXT,
    "references" TEXT,
    cve VARCHAR(50),
    cwe VARCHAR(50),
    cvss_score VARCHAR(10),
    jira_ticket VARCHAR(50),
    jira_url VARCHAR(500),
    source VARCHAR(100),
    source_id VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    assessment_id VARCHAR REFERENCES assessments(id),
    org_id VARCHAR REFERENCES organizations(id),
    created_by VARCHAR REFERENCES users(id),
    client_id VARCHAR
);

CREATE TABLE IF NOT EXISTS reports (
    id VARCHAR PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    format VARCHAR(50) DEFAULT 'markdown',
    content TEXT,
    executive_summary TEXT,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    exploitable_count INTEGER DEFAULT 0,
    file_path VARCHAR(500),
    file_url VARCHAR(1000),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    assessment_id VARCHAR NOT NULL REFERENCES assessments(id),
    org_id VARCHAR REFERENCES organizations(id),
    created_by VARCHAR REFERENCES users(id),
    client_id VARCHAR
);

CREATE TABLE IF NOT EXISTS conversations (
    id VARCHAR PRIMARY KEY,
    title VARCHAR(255),
    assessment_id VARCHAR REFERENCES assessments(id) ON DELETE SET NULL,
    context_summary TEXT,
    is_archived BOOLEAN DEFAULT FALSE,
    message_count INTEGER DEFAULT 0,
    last_message_preview VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    org_id VARCHAR REFERENCES organizations(id),
    created_by VARCHAR REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id VARCHAR PRIMARY KEY,
    conversation_id VARCHAR NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    role messagerole NOT NULL,
    content TEXT NOT NULL,
    tool_calls JSONB,
    findings_created JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_chat_messages_conversation
    ON chat_messages(conversation_id, created_at);

-- `audit_logs` has a model but no router in the Python backend — ported for
-- schema fidelity so both backends see identical tables.
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR,
    details JSONB DEFAULT '{}'::jsonb,
    previous_state JSONB,
    new_state JSONB,
    user_id VARCHAR REFERENCES users(id),
    user_email VARCHAR(255),
    ip_address VARCHAR(50),
    user_agent TEXT,
    org_id VARCHAR REFERENCES organizations(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
