-- =============================================================================
-- Cache drift alerts (Phase 6.4 of caching plan) — 2026-05-22
-- =============================================================================
--
-- Records every event where a finding marked VALIDATED_FROM_BASELINE
-- in a prior assessment later failed to reproduce during a forced
-- full revalidation pass. These events are the canonical signal that
-- the cache is producing incorrect results — when enough of them
-- accumulate for an org within a window, the auto-disable circuit
-- breaker flips `org_settings.caching_enabled` to false until an
-- operator investigates.
--
-- WHO WRITES TO IT:
--   The crossval-qa agent, when in `force_full_revalidation` mode:
--     1. It re-tests a finding that the baseline marked as still-present
--     2. The re-test result differs (e.g., baseline said EXPLOITED, now
--        NOT_EXPLOITABLE — could mean the vuln was fixed, OR could mean
--        we missed a regression last time)
--     3. crossval-qa POSTs a drift_alert with `prior_status`, `new_status`,
--        and the assessment IDs on both sides
--
-- WHO READS IT:
--   - Desktop UI: "N drift alerts in the last 30 days" panel
--   - Auto-disable check: a periodic task (Phase 6 cron, not yet built)
--     counts rows in the last 30 days and toggles caching_enabled if
--     count >= org_settings.drift_alert_threshold
--   - Operator-facing report: lists drift alerts grouped by target so a
--     human can decide whether the cache should be flushed or rebuilt
--
-- WHAT IT MEANS:
--   A drift alert is NEUTRAL — it could mean:
--     - The vuln was actually fixed between runs (good news, cache was
--       just slightly stale)
--     - The baseline was wrong (cache was over-trusting)
--     - The current run has a bug (cache was right, current is wrong)
--   The operator triages from context. The auto-disable circuit just
--   stops digging the hole until that triage happens.
-- =============================================================================

CREATE TABLE IF NOT EXISTS cache_drift_alerts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,

    /* The finding's stable identity. NOT the row ID — fingerprints
       persist across assessments even when the row IDs rotate. */
    finding_fingerprint TEXT NOT NULL,

    /* Both sides of the drift. */
    prior_assessment_id TEXT,
    prior_status TEXT,           -- 'true' | 'potentially' | 'false' (exploitable)
    prior_severity TEXT,         -- calibrated or original at prior_assessment time

    current_assessment_id TEXT,
    current_status TEXT,
    current_severity TEXT,

    /* Operator notes: free-form short string from crossval-qa explaining
       what changed. E.g. "Token-forgery payload now returns 401 instead
       of 200 — auth middleware may have been added." */
    drift_summary TEXT,

    /* Auto-disable circuit support: a sticky flag flipped to true by the
       cron when this row contributes to a threshold breach. Lets ops
       distinguish "alert observed" from "alert caused us to disable
       caching" when reviewing the history. */
    triggered_auto_disable BOOLEAN NOT NULL DEFAULT false,

    /* Operator triage state. */
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    acknowledgement_notes TEXT,

    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for the auto-disable rolling window count:
-- "how many alerts for this org in the last 30 days?"
CREATE INDEX IF NOT EXISTS cache_drift_alerts_org_detected_idx
    ON cache_drift_alerts (org_id, detected_at DESC);

-- Index for per-target drilldown in the operator UI.
CREATE INDEX IF NOT EXISTS cache_drift_alerts_target_idx
    ON cache_drift_alerts (target_id, detected_at DESC)
    WHERE target_id IS NOT NULL;

-- Unack'd alerts only — the desktop's "needs review" list query is
-- partial-index-friendly because most older alerts will be acked.
CREATE INDEX IF NOT EXISTS cache_drift_alerts_unacked_idx
    ON cache_drift_alerts (org_id, detected_at DESC)
    WHERE acknowledged_at IS NULL;
