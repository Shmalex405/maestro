// Chokepoint emission: turn one tool dispatch into a live ProgressEvent and
// publish it on the SSE bus. Called from both dispatch paths (server.ts STDIO
// and autonomous-runner.ts HTTP) right beside logCommand().
//
// Contract: this is fire-and-forget and MUST NEVER throw into the tool path —
// a dropped progress event is harmless; a thrown one would break a real scan.

import http from "http";
import { assessmentEvents } from "../api/event-bus";
import { resolveAttribution } from "./plan";
import { narrate } from "./narration";
import { ProgressEvent, ProgressStatus } from "./types";

// Cross-process bridge.
//
// The live assessment's `claude` CLI calls MCP tools over STDIO → those run in
// the `index.js` process. But the SSE endpoint that the desktop subscribes to is
// served by the SEPARATE `autonomous-runner.js` process on :3001. Each process
// has its own in-memory `assessmentEvents`, so a progress event emitted in the
// STDIO process would never reach SSE clients.
//
// Bridge: the STDIO process forwards each event to the HTTP process via a
// localhost POST to the ingest route, which re-emits it onto the bus the SSE
// route listens on. The HTTP process itself (marked by MAESTRO_IS_AUTONOMOUS_RUNNER)
// emits directly and skips the forward, so there's exactly one SSE delivery.
function forwardToIngest(assessmentId: string, event: ProgressEvent): void {
  try {
    const body = JSON.stringify(event);
    const req = http.request({
      host: "127.0.0.1",
      port: Number(process.env.AUTONOMOUS_PORT || 3001),
      path: `/api/assessments/${encodeURIComponent(assessmentId)}/progress`,
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
      },
    });
    req.on("error", () => {
      /* HTTP process not up / no listener — harmless, drop the beat */
    });
    req.write(body);
    req.end();
  } catch {
    /* never throw into the tool path */
  }
}

/** Strip a leading mcp__server__ wrapper if a fully-qualified name slips in. */
function bareToolName(name: string): string {
  const m = name.match(/^mcp__[^_]+(?:_[^_]+)*__(.+)$/);
  return m ? m[1] : name;
}

/**
 * Emit one progress event for a tool dispatch.
 *
 * No-ops outside a cloud-backed assessment (no MAESTRO_ASSESSMENT_ID) — there
 * is no SSE channel to address, so local/headless tool calls stay silent.
 */
export function emitProgress(input: {
  tool: string;
  status: ProgressStatus;
  target?: string;
  testId?: string;
  durationMs?: number;
}): void {
  try {
    const assessmentId = process.env.MAESTRO_ASSESSMENT_ID;
    if (!assessmentId) return;

    const tool = bareToolName(input.tool);
    const attribution = resolveAttribution(input.testId);

    const event: ProgressEvent = {
      assessmentId,
      ts: new Date().toISOString(),
      tool,
      target: input.target,
      testId: input.testId,
      agent: attribution?.agent,
      phase: attribution?.phase,
      status: input.status,
      durationMs: input.durationMs,
      narration: narrate({ tool, status: input.status, target: input.target }),
    };

    // Emit on this process's bus (delivers to SSE when we ARE the HTTP process;
    // harmless no-op in the STDIO process, which has no SSE listener).
    assessmentEvents.emit(`assessment:${assessmentId}`, {
      type: "progress_event",
      data: event,
    });

    // STDIO process → bridge to the HTTP process that owns the SSE bus.
    if (process.env.MAESTRO_IS_AUTONOMOUS_RUNNER !== "1") {
      forwardToIngest(assessmentId, event);
    }
  } catch {
    // Best-effort: never let telemetry break a tool call.
  }
}
