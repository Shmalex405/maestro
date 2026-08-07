-- =============================================================================
-- Cloud asset inventory + reachability (W2-B of the cloud build plan) — 2026-06-08
-- =============================================================================
--
-- Durable, queryable substrate for the reachability-correlation layer
-- (docs/cloud-build-plan.md). The MCP tool `build_cloud_asset_inventory`
-- (mcp-server/src/tools/cloud-inventory.ts) parses AWS responses into typed
-- assets + reachability records; `promote_cloud_inventory` pushes them here at
-- end-of-run (Shape A: local during the run, curated promotion at the end, same
-- `cloudRequest` transport + JWT as complete_assessment).
--
-- WHY THIS EXISTS:
--   Nothing today records the image -> workload -> exposure mapping. ECR images
--   get Trivy-scanned for CVEs and assets get enumerated, but nothing ties
--   "vulnerable image X is running on reachable ECS service Y." These tables are
--   the join substrate: cloud_assets carries the deployed workloads + the images
--   they run; asset_reachability carries what is internet-facing. The W2-C
--   correlation joins findings(CVE by image ref) x cloud_assets x reachability to
--   surface "deployed + reachable + vulnerable" — the thing CSPM tools only model
--   theoretically.
--
--   Both tables are per-(org, target) scoped exactly like recon_cache_entries
--   (migration 0022), keyed to a `targets` row with target_type='cloud_account'
--   (e.g. canonical "aws:<account-id>").
-- =============================================================================

-- Resource taxonomy. Mirrors the W2-A `ResourceType` TS union. Idempotent create
-- (same pattern as reconscantype in 0022).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'cloudresourcetype') THEN
        CREATE TYPE cloudresourcetype AS ENUM (
            'ecs_service',
            'lambda_function',
            'ecr_image',
            'load_balancer'
        );
    END IF;
END$$;

-- How an asset is exposed. Mirrors the W2-A `ExposureKind` TS union.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'exposurekind') THEN
        CREATE TYPE exposurekind AS ENUM (
            'alb',
            'nlb',
            'function_url',
            'public_ip',
            'api_gateway'
        );
    END IF;
END$$;

-- -----------------------------------------------------------------------------
-- cloud_assets — one row per deployed resource observed in a run.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cloud_assets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,

    /* Which assessment run last observed this asset (for trend / provenance). */
    assessment_id TEXT,

    resource_type cloudresourcetype NOT NULL,
    resource_arn TEXT NOT NULL,
    name TEXT,
    region TEXT,

    /* Container image refs this asset runs (ECS task-def images / Lambda
       Code.ImageUri / the ECR image itself). The correlation join's tag-match
       key. JSONB array of strings. */
    image_refs JSONB NOT NULL DEFAULT '[]',

    /* Image digests (sha256:...). The correlation join's RELIABLE key — Trivy
       reports the digest it scanned. JSONB array of strings. */
    image_digests JSONB NOT NULL DEFAULT '[]',

    /* Derived: is this workload internet-reachable (any internet-facing exposure)? */
    exposed BOOLEAN NOT NULL DEFAULT FALSE,

    /* asset_reachability.id values that expose this asset. JSONB array. */
    exposure_ids JSONB NOT NULL DEFAULT '[]',

    metadata JSONB NOT NULL DEFAULT '{}',

    /* When the inventory observed it, distinct from row-touch time. */
    observed_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Upsert key: an ARN is globally unique + stable across runs, so re-running the
-- inventory updates the same row rather than duplicating it.
CREATE UNIQUE INDEX IF NOT EXISTS cloud_assets_key_idx
    ON cloud_assets (org_id, target_id, resource_arn);

-- GIN indexes power the correlation join (membership tests over image refs/digests).
CREATE INDEX IF NOT EXISTS cloud_assets_image_digests_idx
    ON cloud_assets USING GIN (image_digests);
CREATE INDEX IF NOT EXISTS cloud_assets_image_refs_idx
    ON cloud_assets USING GIN (image_refs);

-- -----------------------------------------------------------------------------
-- asset_reachability — one row per exposure (LB / function-url / etc).
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_reachability (
    /* Stable id from the W2-A ReachabilityRecord (e.g. "lb:<arn>", "funcurl:<arn>"). */
    id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    assessment_id TEXT,

    exposed_via exposurekind NOT NULL,
    endpoint TEXT,
    internet_facing BOOLEAN NOT NULL,

    /* The LB / function-url ARN that creates the exposure. */
    source TEXT NOT NULL,

    /* Asset ARNs this exposure fronts (best-effort). JSONB array. */
    target_resource_arns JSONB NOT NULL DEFAULT '[]',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (org_id, target_id, id)
);

CREATE INDEX IF NOT EXISTS asset_reachability_source_idx
    ON asset_reachability (org_id, target_id, source);
