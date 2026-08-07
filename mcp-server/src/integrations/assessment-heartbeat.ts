// Liveness heartbeat for an in-flight assessment.
//
// The cloud reaper (`reconcile_stale_running` in backend-rs) closes out any
// assessment that has sat in `running` with no fresh `updated_at` for 3h. A
// long but live run can otherwise go quiet on the cloud row for hours (findings
// are written to the findings table, not the assessment row), so without a
// heartbeat the reaper can false-fail a legitimately-running assessment.
//
// We fix that here: every tool-call dispatch pulses a lightweight
// `POST /assessments/:id/heartbeat`, throttled to at most once per INTERVAL_MS
// regardless of tool volume. Any actively-working run therefore keeps a fresh
// `updated_at`, and the reaper only ever catches a run that has gone fully
// silent (genuinely dead). Fire-and-forget — it must never block or throw into
// the tool path; a missed beat is harmless (the 3h window absorbs it).
import { hasCloudSession, cloudRequest } from "./cloud-session";

const INTERVAL_MS = 5 * 60 * 1000; // at most one beat per 5 minutes
let lastBeatAt = 0;

export function pulseAssessmentHeartbeat(): void {
  const id = process.env.MAESTRO_ASSESSMENT_ID;
  // No-op outside a cloud-backed assessment (local/headless tool calls).
  if (!id || !hasCloudSession()) return;
  const now = Date.now();
  if (now - lastBeatAt < INTERVAL_MS) return;
  lastBeatAt = now;
  void cloudRequest(`/assessments/${id}/heartbeat`, { method: "POST" }).catch(
    () => {
      // best-effort; the reaper's 3h window tolerates a dropped beat
    }
  );
}
