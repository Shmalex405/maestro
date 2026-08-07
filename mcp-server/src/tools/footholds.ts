// Post-exploitation foothold/loot store tools (backend migration 0048 + /footholds).
//
// The assessment-scoped record of ACQUIRED access the post-exploit-operator deposits
// on acquire and operates THROUGH on later steps (see executeThroughFoothold in
// utils/docker-exec.ts). Brain-agnostic and org-scoped via the cloud JWT session —
// these gate on hasCloudSession() and route through cloudRequest exactly like the
// graph tools. assessment_id defaults to MAESTRO_ASSESSMENT_ID.

import { cloudRequest, hasCloudSession, CloudSessionError } from "../integrations/cloud-session";
import { executeInKaliDetailed } from "../utils/docker-exec";
import { checkExclusions } from "../scope/exclusion-guard";

/** Single-quote a value for safe shell interpolation in a foothold env prologue. */
function shq(v: unknown): string {
  return `'${String(v).replace(/'/g, `'\\''`)}'`;
}

/**
 * Build the `export VAR=...; ` prologue that makes a foothold's held material
 * available to a command as environment variables — the v1 "operate through a
 * held foothold" mechanism (RFC §6.2, reconstructed-context). The operator's
 * command references these (e.g. `curl -H "$FOOTHOLD_AUTH_HEADER" ...`, or the aws
 * CLI picking up the exported AWS_* creds). No persistent PTY/C2 — by design.
 */
function buildFootholdEnv(fh: Record<string, any>): string {
  const m = (fh?.material ?? {}) as Record<string, unknown>;
  const exp: string[] = [];
  switch (fh?.kind) {
    case "token":
    case "session": {
      const token = m.bearer ?? m.token ?? m.access_token;
      if (token) {
        exp.push(`FOOTHOLD_TOKEN=${shq(token)}`);
        exp.push(`FOOTHOLD_AUTH_HEADER=${shq(`Authorization: Bearer ${token}`)}`);
      }
      if (m.cookie) exp.push(`FOOTHOLD_COOKIE=${shq(m.cookie)}`);
      break;
    }
    case "assumed_role": {
      if (m.access_key_id) exp.push(`AWS_ACCESS_KEY_ID=${shq(m.access_key_id)}`);
      if (m.secret_access_key) exp.push(`AWS_SECRET_ACCESS_KEY=${shq(m.secret_access_key)}`);
      if (m.session_token) exp.push(`AWS_SESSION_TOKEN=${shq(m.session_token)}`);
      break;
    }
    case "credential": {
      if (m.username) exp.push(`FOOTHOLD_USER=${shq(m.username)}`);
      if (m.password) exp.push(`FOOTHOLD_PASS=${shq(m.password)}`);
      if (m.api_key) exp.push(`FOOTHOLD_API_KEY=${shq(m.api_key)}`);
      break;
    }
    // shell: v1 reconstructed-context — no persistent session to inject.
    default:
      break;
  }
  exp.push(`FOOTHOLD_TARGET=${shq(fh?.target ?? "")}`);
  return exp.length ? `export ${exp.join(" ")}; ` : "";
}

/**
 * Operate THROUGH a held foothold: resolve its material, inject it as env, and run
 * `command` via executeInKaliDetailed — so the non-destructive backstop
 * (screenCommand) and tool-execution provenance still apply exactly as for a
 * one-shot tool. Refuses a non-live (expired/revoked) foothold. Reusable by other
 * tools; also exposed as the execute_through_foothold MCP tool.
 */
export async function executeThroughFoothold(footholdId: string, command: string) {
  if (!hasCloudSession()) {
    return { stdout: "", stderr: "executeThroughFoothold requires an active cloud session", exitCode: 1 };
  }
  let fh: Record<string, any>;
  try {
    fh = await cloudRequest<Record<string, any>>(`/footholds/${encodeURIComponent(footholdId)}`);
  } catch (e) {
    const msg = e instanceof CloudSessionError ? `${e.status}: ${e.message}` : String(e);
    return { stdout: "", stderr: `foothold ${footholdId} not resolvable (${msg})`, exitCode: 1 };
  }
  if (fh?.status && fh.status !== "live") {
    return {
      stdout: "",
      stderr: `foothold ${footholdId} is ${fh.status}, not live — re-establish before operating through it`,
      exitCode: 1,
    };
  }
  return executeInKaliDetailed(`${buildFootholdEnv(fh)}${command}`);
}

function noSession(what: string): string {
  return JSON.stringify({
    ok: false,
    error: `No active cloud session — ${what} requires a signed-in backend session (local-only run).`,
  });
}

function failure(e: unknown): string {
  const msg =
    e instanceof CloudSessionError
      ? `cloud request failed (${e.status}): ${e.message}`
      : e instanceof Error
        ? e.message
        : String(e);
  return JSON.stringify({ ok: false, error: msg });
}

function qs(params: Record<string, string | undefined | null>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") {
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
    }
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

const assessmentId = (given?: string): string | undefined =>
  given ?? process.env.MAESTRO_ASSESSMENT_ID ?? undefined;

export const footholdTools = [
  {
    name: "establish_foothold",
    description:
      "Deposit ACQUIRED access into the post-exploitation foothold store so later steps operate THROUGH it (instead of re-supplying the secret as a per-call argument). Call this the moment an exploit yields reusable access — a stolen session/token, harvested credential, assumed cloud role, or shell. kind ∈ {session, token, credential, assumed_role, shell}. material holds the real held secret (token / cookie-jar / temp creds / role-arn — internal, never redacted). grants lists the capabilities this foothold confers (seeds the planner's reachable frontier — e.g. ['api_session','pii_read']). how_acquired = the finding/step that yielded it; node_key = the graph foothold node it backs. Returns the stored foothold incl. its id. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: { type: "string", description: "Assessment run id (defaults to MAESTRO_ASSESSMENT_ID)" },
        kind: {
          type: "string",
          enum: ["session", "token", "credential", "assumed_role", "shell"],
          description: "The kind of held access",
        },
        target: { type: "string", description: "Where this foothold grants access (host / arn / tenant / url)" },
        material: { type: "object", description: "The held secret the operator injects per call (token/cookie-jar/temp-creds/role-arn). Internal — never redacted." },
        grants: { type: "array", items: { type: "string" }, description: "Capabilities this foothold confers (seeds the planner)" },
        how_acquired: { type: "string", description: "Provenance: the finding id / step that yielded it" },
        node_key: { type: "string", description: "The graph foothold node this backs" },
        expires_at: { type: "string", description: "ISO-8601 expiry for time-bounded access (assumed-role / OTP session)" },
        evidence_ref: { type: "string", description: "Reference to the evidence proving acquisition" },
      },
      required: ["kind", "target"],
    },
  },
  {
    name: "list_footholds",
    description:
      "Enumerate the footholds held in this assessment — what access the attacker currently has. status='live' returns only usable footholds (excludes revoked and past-expiry). Each foothold carries its grants (the capabilities to seed find_attack_paths with) and node_key. Use this to plan the next post-exploitation move. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: { type: "string", description: "Assessment run id (defaults to MAESTRO_ASSESSMENT_ID)" },
        status: { type: "string", enum: ["live", "expired", "revoked"], description: "Filter by status (status=live excludes past-expiry)" },
      },
      required: [],
    },
  },
  {
    name: "consume_foothold",
    description:
      "Fetch one foothold by id, including its material (the held secret) — the operator calls this just before operating through the foothold. Prefer executeThroughFoothold for command execution; use consume_foothold when you need the raw material for a custom request. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string", description: "Foothold id" } },
      required: ["id"],
    },
  },
  {
    name: "revoke_footholds",
    description:
      "Revoke all live footholds for the assessment — the end-of-run cleanup (complete_assessment calls this). After revocation a foothold can no longer be operated through. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: { type: "string", description: "Assessment run id (defaults to MAESTRO_ASSESSMENT_ID)" },
      },
      required: [],
    },
  },
  {
    name: "execute_through_foothold",
    description:
      "Operate THROUGH a held foothold: run `command` with the foothold's material injected as environment ($FOOTHOLD_AUTH_HEADER / $FOOTHOLD_TOKEN / $FOOTHOLD_COOKIE for token/session footholds; exported AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN for an assumed_role; $FOOTHOLD_USER/$FOOTHOLD_PASS/$FOOTHOLD_API_KEY for a credential). This is how the post-exploit-operator pivots/loots with stolen access instead of re-supplying it each call — e.g. `curl -s -H \"$FOOTHOLD_AUTH_HEADER\" https://$FOOTHOLD_TARGET/api/admin`. Runs through the same non-destructive backstop as every tool. Pass `target` (the host/resource the command hits) so the never-touch exclusion fence can screen it. Refuses an expired/revoked foothold.",
    inputSchema: {
      type: "object",
      properties: {
        foothold_id: { type: "string", description: "The foothold to operate through (from list_footholds)" },
        command: { type: "string", description: "Shell command to run; reference the injected $FOOTHOLD_* env vars" },
        target: {
          type: "string",
          description:
            "The host/resource this command hits — screened against never_touch (assumed-breach: runtime-discovered targets within the authorization boundary are allowed)",
        },
      },
      required: ["foothold_id", "command"],
    },
  },
];

export const footholdHandlers: Record<string, Function> = {
  establish_foothold: async (args: {
    assessment_id?: string;
    kind: string;
    target: string;
    material?: Record<string, unknown>;
    grants?: string[];
    how_acquired?: string;
    node_key?: string;
    expires_at?: string;
    evidence_ref?: string;
  }) => {
    if (!hasCloudSession()) return noSession("establish_foothold");
    const aid = assessmentId(args.assessment_id);
    if (!aid) return JSON.stringify({ ok: false, error: "assessment_id required (or set MAESTRO_ASSESSMENT_ID)" });
    try {
      const fh = await cloudRequest<Record<string, unknown>>("/footholds", {
        method: "POST",
        body: {
          assessment_id: aid,
          kind: args.kind,
          target: args.target,
          material: args.material ?? {},
          grants: Array.isArray(args.grants) ? args.grants : [],
          how_acquired: args.how_acquired ?? null,
          node_key: args.node_key ?? null,
          expires_at: args.expires_at ?? null,
          evidence_ref: args.evidence_ref ?? null,
        },
      });
      return JSON.stringify({ ok: true, foothold: fh }, null, 2);
    } catch (e) {
      return failure(e);
    }
  },

  list_footholds: async (args: { assessment_id?: string; status?: string }) => {
    if (!hasCloudSession()) return noSession("list_footholds");
    try {
      const footholds = await cloudRequest<unknown[]>(
        `/footholds${qs({ assessment_id: assessmentId(args.assessment_id), status: args.status })}`,
      );
      return JSON.stringify(
        { ok: true, footholds, count: Array.isArray(footholds) ? footholds.length : 0 },
        null,
        2,
      );
    } catch (e) {
      return failure(e);
    }
  },

  consume_foothold: async (args: { id: string }) => {
    if (!hasCloudSession()) return noSession("consume_foothold");
    if (!args.id) return JSON.stringify({ ok: false, error: "id required" });
    try {
      const fh = await cloudRequest<Record<string, unknown>>(`/footholds/${encodeURIComponent(args.id)}`);
      return JSON.stringify({ ok: true, foothold: fh }, null, 2);
    } catch (e) {
      return failure(e);
    }
  },

  revoke_footholds: async (args: { assessment_id?: string }) => {
    if (!hasCloudSession()) return noSession("revoke_footholds");
    const aid = assessmentId(args.assessment_id);
    if (!aid) return JSON.stringify({ ok: false, error: "assessment_id required (or set MAESTRO_ASSESSMENT_ID)" });
    try {
      const res = await cloudRequest<Record<string, unknown>>(`/footholds/revoke${qs({ assessment_id: aid })}`, {
        method: "POST",
        body: {},
      });
      return JSON.stringify({ ok: true, ...res }, null, 2);
    } catch (e) {
      return failure(e);
    }
  },

  execute_through_foothold: async (args: { foothold_id: string; command: string; target?: string }) => {
    if (!hasCloudSession()) return noSession("execute_through_foothold");
    if (!args.foothold_id || !args.command) {
      return JSON.stringify({ ok: false, error: "foothold_id and command are required" });
    }
    // Hard never-touch floor. The assumed-breach authorization boundary itself is
    // enforced by the operator agent per scope.yml post_exploitation; here we screen
    // the declared target against the exclusion fence (the one absolute deny).
    if (args.target) {
      const ex = await checkExclusions({ target: args.target });
      if (ex.blocked) return JSON.stringify({ ok: false, error: `SCOPE EXCLUSION: ${ex.reason}` });
    }
    const res = await executeThroughFoothold(args.foothold_id, args.command);
    return JSON.stringify({ ok: res.exitCode === 0, ...res }, null, 2);
  },
};
