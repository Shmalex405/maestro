-- 0049: oracle-earned verdicts + replay capsules on findings.
--
-- Until now a finding's `exploitable` field was whatever the LLM typed into
-- create_finding. Nothing checked that a tool ever ran against the target, that
-- the pasted HTTP response was ever received, or that the claimed exploit was
-- reproducible. The provenance gate (0029) answers "did the tool run?"; this is
-- the second deterministic gate, one level deeper: "did the finding re-prove
-- itself N/N under a named oracle?"
--
-- The invariant, enforced in mcp-server/src/tools/reporting.ts and
-- verification/oracles.ts rather than in a prompt:
--
--   A `verified` verdict MUST name the machine-checkable oracle_kind that earned
--   it, and MUST carry replay_successes = replay_n > 0. The LLM cannot assert a
--   verdict into existence; a finding without an oracle is at most a candidate.
--
-- `claimed_mechanism` binds the receipt to the vulnerability the finding CLAIMS.
-- An oracle can pass while demonstrating a different bug than the one asserted —
-- ExploitGym measured 69 of 226 successful exploits landing on an unintended
-- vulnerability — so an oracle that proves impact by a mechanism other than the
-- claimed one resolves to `refuted` with reason `mechanism_mismatch`, never to
-- `verified`. See docs/oracle-verification-layer.md.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS verdict TEXT NOT NULL DEFAULT 'candidate';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS oracle_kind TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS receipt_json JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS capsule_json JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS replay_n INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS replay_successes INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS claimed_mechanism TEXT;

-- Only the three verdicts exist. Anything else is a bug in the writer.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_verdict_check;
ALTER TABLE findings
  ADD CONSTRAINT findings_verdict_check
  CHECK (verdict IN ('candidate', 'verified', 'refuted'));

-- The invariant, enforced by the database itself so no writer — MCP server,
-- backend route, or manual SQL — can mint a verified finding without a receipt.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_verified_requires_oracle;
ALTER TABLE findings
  ADD CONSTRAINT findings_verified_requires_oracle
  CHECK (
    verdict <> 'verified'
    OR (
      oracle_kind IS NOT NULL
      AND receipt_json IS NOT NULL
      AND replay_n IS NOT NULL
      AND replay_successes IS NOT NULL
      AND replay_n > 0
      AND replay_successes = replay_n
    )
  );

-- The verified-only headline count is the common dashboard/report query.
CREATE INDEX IF NOT EXISTS idx_findings_verdict
  ON findings (assessment_id, verdict);
