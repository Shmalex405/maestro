/**
 * Response-size guard.
 *
 * Large tool outputs (raw scanner stdout, HTTP/network logs, page HTML, etc.)
 * are expensive not when first produced but because they sit inline in an
 * agent's conversation and get re-read on EVERY subsequent turn — which is what
 * inflates prompt-cache cost (cache-read is ~79% of a run's API bill). This
 * guard, hooked at the single tool-dispatch chokepoint in `server.ts`, writes
 * the bulky parts of an oversized result to disk and replaces them inline with
 * a compact digest + a file `path`. Agents are told (via `_preamble.md`) to
 * grep / Read a TARGETED slice of `path` for detail, never the whole file.
 *
 * Design guarantees:
 *  - Lossless: full content is always written to disk before being elided.
 *  - Safe: structured findings the agent must act on are NEVER offloaded; only
 *    known-noisy raw fields and non-JSON text blobs are. Fails open (returns the
 *    raw result) on any error, so it can never break a tool call.
 *  - Reversible: `MAESTRO_TOOL_OFFLOAD=0` disables it entirely.
 */
import * as fs from "fs";
import * as path from "path";
import { isInsideContainer } from "./docker-exec";

/** Tools whose (small, structured) output the model must always see verbatim. */
const NEVER_OFFLOAD = new Set([
  "prompt_for_otp",
  "prompt_for_input",
  "respond_to_prompt",
  "check_pending_prompt",
  "create_finding",
  "authenticate",
  "analyze_jwt",
  "detect_languages",
  "generate_attack_surface",
  "generate_report",
  "generate_scan_report",
  "compare_assessments",
  "clear_findings",
  "validate_scope",
]);

/** Top-level JSON fields that carry verbose raw bulk (vs. structured findings). */
const BULKY_FIELDS = new Set([
  "raw_output",
  "raw",
  "stdout",
  "raw_results",
  "evidence_captures",
  "network_log",
  "html",
  "content",
  "page_content",
]);

/** Tools whose result is a top-level array of verbose (non-finding) records. */
const NOISY_ARRAY_TOOLS = new Set(["browser_network_log"]);

const FIELD_BULK_BYTES = 4096; // a field must exceed this to be worth offloading

function offloadEnabled(): boolean {
  return process.env.MAESTRO_TOOL_OFFLOAD !== "0";
}

function thresholdBytes(): number {
  // 8KB default: on small targets the 32KB default never tripped, leaving
  // mid-size raw outputs to accumulate in cache. 8KB sheds those verbose
  // bodies while structured findings always stay inline (see BULKY_FIELDS).
  const kb = Number(process.env.MAESTRO_TOOL_OFFLOAD_KB || "8");
  return (Number.isFinite(kb) && kb > 0 ? kb : 8) * 1024;
}

function toolCacheDir(): string {
  const base = isInsideContainer()
    ? "/opt/pentest/output/tool-cache"
    : path.join(
        process.env.DATA_PATH || path.join(process.cwd(), "..", "data"),
        "tool-cache",
      );
  fs.mkdirSync(base, { recursive: true });
  return base;
}

let seq = 0;
function writeBlob(label: string, content: string): { path: string; bytes: number; lines: number } {
  const safe = label.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 80);
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const file = path.join(toolCacheDir(), `${safe}-${ts}-${seq++}.txt`);
  fs.writeFileSync(file, content);
  return { path: file, bytes: Buffer.byteLength(content), lines: content.split("\n").length };
}

const NOTE = "Full content saved to disk. grep or Read a TARGETED slice of `path`; do NOT read the whole file (re-reading it defeats the optimization).";

function headTailDigest(result: string, toolName: string): string {
  const blob = writeBlob(toolName, result);
  const lines = result.split("\n");
  return JSON.stringify({
    _offloaded: true,
    path: blob.path,
    bytes: blob.bytes,
    lines: blob.lines,
    head: lines.slice(0, 60).join("\n"),
    tail: lines.length > 80 ? lines.slice(-20).join("\n") : "",
    note: NOTE,
  });
}

/**
 * If `result` (a tool handler's stringified output) is over the size threshold,
 * offload its bulky parts to disk and return a compact digest. Otherwise return
 * `result` unchanged.
 */
export function applyResponseSizeGuard(result: string, toolName: string): string {
  try {
    if (!offloadEnabled()) return result;
    if (typeof result !== "string") return result;
    if (NEVER_OFFLOAD.has(toolName)) return result;
    if (result.length <= thresholdBytes()) return result;

    let parsed: unknown;
    try {
      parsed = JSON.parse(result);
    } catch {
      // Non-JSON (raw scanner stdout, CSV, JSONL, raw HTML) → head/tail offload.
      return headTailDigest(result, toolName);
    }

    // Top-level array from a known-noisy tool → offload whole array w/ preview.
    if (Array.isArray(parsed)) {
      if (!NOISY_ARRAY_TOOLS.has(toolName)) return result; // could be findings — keep inline
      const blob = writeBlob(toolName, result);
      return JSON.stringify({
        _offloaded: true,
        path: blob.path,
        bytes: blob.bytes,
        lines: blob.lines,
        count: parsed.length,
        preview: parsed.slice(0, 5),
        note: NOTE,
      });
    }

    // Object → offload only known-noisy raw fields; keep findings/structure inline.
    if (parsed && typeof parsed === "object") {
      const obj = parsed as Record<string, unknown>;
      for (const key of Object.keys(obj)) {
        if (!BULKY_FIELDS.has(key)) continue;
        const value = obj[key];
        const serialized = typeof value === "string" ? value : JSON.stringify(value, null, 2);
        if (Buffer.byteLength(serialized) <= FIELD_BULK_BYTES) continue;
        const blob = writeBlob(`${toolName}-${key}`, serialized);
        obj[key] = {
          _offloaded: true,
          field: key,
          path: blob.path,
          bytes: blob.bytes,
          lines: blob.lines,
          count: Array.isArray(value) ? value.length : undefined,
          preview: typeof value === "string" ? value.slice(0, 500) : Array.isArray(value) ? value.slice(0, 3) : undefined,
          note: NOTE,
        };
      }
      return JSON.stringify(obj);
    }

    return result;
  } catch {
    // Never let the guard break a tool call.
    return result;
  }
}
