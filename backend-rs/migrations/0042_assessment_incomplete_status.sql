-- =============================================================================
-- Add an `incomplete` value to the `assessmentstatus` enum.
-- =============================================================================
--
-- A run that went idle (no heartbeat for 3h) or was archived while still
-- `running` was previously reconciled to `failed` by reconcile_stale_running.
-- But "the agent stopped heartbeating before it called complete_assessment" is
-- NOT a failure — the run simply never finished. Showing it as `failed` (red,
-- error-looking) misrepresents what happened and buried real failures.
--
-- `incomplete` is the neutral terminal state for "ran but never completed":
-- distinct from `completed` (deliverables promoted) and from `failed` (an
-- actual error). The reaper now routes the stale/archived-without-deliverables
-- case here instead of to `failed`.
--
-- Mirrors migrations/0008_assessment_type_expanded.sql: `ADD VALUE IF NOT
-- EXISTS` is idempotent (Postgres 9.6+) and ALTER TYPE ADD VALUE runs outside a
-- transaction, so this is a single standalone statement.

ALTER TYPE assessmentstatus ADD VALUE IF NOT EXISTS 'incomplete';
