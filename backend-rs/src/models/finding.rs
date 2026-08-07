//! `findings` table row. Mirrors `backend/app/models/finding.py:Finding`.

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use crate::models::sql_enums::{FindingStatusDb, SeverityDb};

#[derive(Debug, Clone, FromRow)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: SeverityDb,
    pub status: Option<FindingStatusDb>,
    pub target: String,
    pub target_type: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    #[sqlx(rename = "references")]
    pub references: Option<String>,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub cvss_score: Option<String>,
    pub jira_ticket: Option<String>,
    pub jira_url: Option<String>,
    pub source: Option<String>,
    pub source_id: Option<String>,
    /// 'true' | 'potentially' | 'false' | NULL — see migration 0006 for semantics.
    pub exploitable: Option<String>,
    /// SHA256 of (title, target, source, cwe). Migration 0007 added this
    /// + the upsert path so re-running an assessment against the same
    /// target doesn't pile up duplicate rows. NULL only on rows
    /// inserted before the migration (effectively never in prod).
    pub fingerprint: Option<String>,
    pub occurrence_count: i32,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    /// Post-calibration severity (severity-calibrator agent output).
    /// NULL when calibration didn't run, or when the rule kept the
    /// original (no delta). Migration 0016. Stats / list queries use
    /// `COALESCE(calibrated_severity, severity)` so NULL is a clean
    /// fallback to scanner-original.
    pub calibrated_severity: Option<SeverityDb>,
    /// Which calibration rule fired (e.g. "Rule 1 — outcome anchored").
    /// Migration 0016. Surfaced in the desktop finding detail view.
    pub calibration_rule: Option<String>,
    /// Short prose justification for the calibrated severity. Migration 0016.
    pub calibration_justification: Option<String>,
    /// Optional FK to `targets.id` (migration 0018). Populated by the
    /// upsert path when a target_id can be resolved; NULL on legacy rows
    /// pending the Rust-app backfill repair pass.
    pub target_id: Option<String>,
    /// crossval-qa baseline-aware mode output. One of:
    ///   - "RE_VALIDATED": actively re-tested in this run
    ///   - "VALIDATED_FROM_BASELINE": trusted from a prior assessment
    ///   - "NEW_FINDING": discovered for the first time
    /// NULL on pre-Phase 3 assessments. Migration 0020.
    pub validation_source: Option<String>,
    /// When `validation_source` is VALIDATED_FROM_BASELINE, this points
    /// to the assessment whose result we trusted. Lets the report-writer
    /// link "see original proof in assessment ABC".
    pub prior_assessment_id: Option<String>,
    /// Human-readable explanation of the cache decision. Surfaced
    /// verbatim in the report so the reader can judge whether to trust
    /// the cached result.
    pub baseline_skip_reason: Option<String>,
    /// Set when a previously-exploitable finding was re-tested and no longer
    /// reproduces (exploitable 'true'|'potentially' → 'false'). NULL when the
    /// finding was never confirmed exploitable, or came back on a later run
    /// (regression clears it). Migration 0034. `remediated_at IS NOT NULL` is
    /// the canonical "patched" predicate.
    pub remediated_at: Option<DateTime<Utc>>,
    /// The exploitable value the finding held BEFORE it was patched
    /// ('true' | 'potentially'). Lets the UI say "was fully exploited, now
    /// fixed" without losing the prior state to the in-place upsert. Migration 0034.
    pub prior_exploitable: Option<String>,
    /// The assessment whose re-test proved the fix. Migration 0034.
    pub remediated_in_assessment_id: Option<String>,
    /// FK to `scans.id` (migration 0035) when this finding was produced by a
    /// scheduled/deterministic DAST scan. NULL for LLM-assessment findings and
    /// legacy rows. `scan_id IS NOT NULL` is the canonical "DAST-only" predicate
    /// powering the Scheduled DAST → Vulnerabilities view.
    pub scan_id: Option<String>,
    /// Triage owner (user id / email). Migration 0036.
    pub assigned_to: Option<String>,
    /// Free-form triage tags. Migration 0036.
    pub tags: Vec<String>,
    /// Human attestation timestamp — the top validation tier (a person confirmed
    /// the finding beyond the AI's exploitable verdict). NULL = not attested. Migration 0036.
    pub attested_at: Option<DateTime<Utc>>,
    pub attested_by: Option<String>,
    /// Oracle verdict (migration 0049): 'candidate' | 'verified' | 'refuted'.
    /// `verified` means a named oracle re-proved this finding in code — it is
    /// never something an agent could assert. See docs/oracle-verification-layer.md.
    pub verdict: Option<String>,
    /// Which oracle earned the verdict (idempotent_replay | differential | …).
    pub oracle_kind: Option<String>,
    /// Machine evidence the oracle observed, including its negative control.
    pub receipt_json: Option<serde_json::Value>,
    /// The re-runnable recipe a human signer replays before signing.
    pub capsule_json: Option<serde_json::Value>,
    pub replay_n: Option<i32>,
    pub replay_successes: Option<i32>,
    pub verified_at: Option<DateTime<Utc>>,
    /// The vulnerability mechanism this finding claims, so a receipt proving
    /// impact by a different mechanism can be caught rather than accepted.
    pub claimed_mechanism: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub assessment_id: Option<String>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
    pub client_id: Option<String>,
}
