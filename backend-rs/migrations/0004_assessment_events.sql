-- Persistent activity feed for assessments (item #14, Phase 2 of
-- assessment-liveness — Phase 1 was the live-session badge in v0.1.5).
--
-- Each row is one event during an assessment run: a tool call started, a
-- finding was detected, the orchestrator paused for OTP, etc. The
-- frontend's existing real-time activity-feed.tsx shows them as they
-- happen; persisting them to cloud means a teammate or post-run viewer
-- can scroll through the full timeline of what happened, regardless of
-- whether their app was open at the time.
--
-- Org-scoped via the assessment_id → assessments.org_id join — we don't
-- duplicate org_id on this table since assessment_id is required. The
-- index pair makes the typical "show me events for this assessment in
-- chronological order" query O(log n) seek + sequential scan.

CREATE TABLE IF NOT EXISTS assessment_events (
    id VARCHAR PRIMARY KEY,
    assessment_id VARCHAR NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    -- Logical event categories: 'tool_call', 'tool_result',
    -- 'finding_detected', 'phase_change', 'guidance_request',
    -- 'orchestrator_message', 'error'. Whitelist enforced at API layer.
    event_type VARCHAR(64) NOT NULL,
    -- For tool_call/tool_result: which MCP tool. NULL otherwise.
    tool VARCHAR(128),
    -- For tool_call/finding_detected: the target/host the event was
    -- about. Lets the UI filter "show me everything that touched X".
    target VARCHAR(512),
    -- Per-event-type structured payload. tool_call: args summary.
    -- tool_result: success/duration/output excerpt. finding_detected:
    -- finding_id + severity. Keep shapes consistent in the desktop's
    -- timeline renderer; backend treats the JSON as opaque.
    details JSONB DEFAULT '{}'::jsonb,
    -- Optional pointer to the finding/agent/tool-call this event references.
    -- Lets future UIs deep-link "this scan turned up that finding" without
    -- needing a join table.
    ref_finding_id VARCHAR REFERENCES findings(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assessment_events_assessment
  ON assessment_events(assessment_id, created_at);
CREATE INDEX IF NOT EXISTS idx_assessment_events_finding
  ON assessment_events(ref_finding_id) WHERE ref_finding_id IS NOT NULL;
