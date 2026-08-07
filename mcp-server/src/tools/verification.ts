// Verification tools — the verdict gate (Phase 4.7).
//
// `verify_finding` is the only route by which a finding can become anything
// other than a candidate. It takes a RECIPE from the agent, runs it in the
// container, and lets the deterministic oracle in verification/oracles.ts decide
// the verdict. The agent never supplies the verdict, only the experiment.
//
// `replay_capsule` re-runs a stored capsule — this is what a human signer
// executes before putting their name on the report, and what CI runs to prove a
// finding still reproduces.

import { executeInKaliDetailed } from "../utils/docker-exec";
import { validateScope } from "../scope/validator";
import {
  ArtifactSpec,
  CanarySpec,
  CredentialUseSpec,
  DifferentialSpec,
  Intensity,
  ORACLE_STRENGTH,
  OastSpec,
  OracleKind,
  OracleSpec,
  ReplaySpec,
  RunResult,
  runOracle,
} from "../verification/oracles";
import { createOastSession } from "../verification/oast";
import { applyVerdict, getFindingById, getFindings } from "../integrations/findings-db";

const runner = async (command: string): Promise<RunResult> => executeInKaliDetailed(command);
const oracleDeps = { run: runner, oast: createOastSession };

/**
 * The dispatcher scope-checks the `target` argument, but every oracle command is
 * a free-form string that could name a different host entirely. Pull every URL
 * and bare hostname back out of the commands we are about to run and check each
 * one, so an in-scope `target` can't be used as cover for an out-of-scope attack.
 */
async function screenCommandTargets(commands: string[]): Promise<string | null> {
  const hosts = new Set<string>();
  for (const cmd of commands) {
    for (const m of cmd.matchAll(/https?:\/\/[^\s'"$;|&)\\]+/gi)) {
      try {
        hosts.add(new URL(m[0]).hostname);
      } catch {
        /* unparseable — the bare-host sweep below may still catch it */
      }
    }
    for (const m of cmd.matchAll(/(?:^|[\s'"@=])((?:\d{1,3}\.){3}\d{1,3})(?=[\s:'"/,)]|$)/g)) {
      hosts.add(m[1]);
    }
  }
  for (const host of hosts) {
    const check = await validateScope(host);
    if (!check.valid) {
      return `Oracle command references out-of-scope host "${host}": ${check.reason}. Verification refused.`;
    }
  }
  return null;
}

/** Required argument names per oracle, used for both validation and the error text. */
const REQUIRED: Record<string, { fields: string[]; why: string }> = {
  idempotent_replay: {
    fields: ["command", "success_pattern", "control_command"],
    why:
      "The control is mandatory: without a benign request that does NOT exhibit the pattern, " +
      "N/N reproduction cannot distinguish a real vulnerability from a response that always looks that way.",
  },
  differential: {
    fields: ["attacker_command", "authorized_command", "marker"],
    why:
      "Supply unauthenticated_command too — without it the receipt cannot rule out that the endpoint " +
      "needs no authentication at all, which would make this a missing-authentication finding rather " +
      "than the authorization failure being claimed.",
  },
  artifact: {
    fields: ["deposit_command", "read_command"],
    why:
      "Both commands must contain the literal {{TOKEN}} placeholder. The harness mints the marker, so " +
      "observing it come back is causally tied to your deposit — a marker you chose yourself is not.",
  },
  canary: {
    fields: ["exploit_command", "canary_value", "legitimate_command"],
    why:
      "legitimate_command is the control: if the canary is visible through the normal interface, the data " +
      "is public and no boundary was crossed.",
  },
  credential_use: {
    fields: ["authenticated_command", "success_pattern", "unauthenticated_command"],
    why:
      "unauthenticated_command is the control: it separates 'this recovered credential works' from " +
      "'this route was never protected'.",
  },
  oast: {
    fields: ["command"],
    why:
      "command must contain the literal {{OAST_DOMAIN}} placeholder. The harness owns the listener, so only " +
      "a domain it minted can prove the target called out.",
  },
};

function buildSpec(args: Record<string, any>): { spec?: OracleSpec; error?: string } {
  const kind = args.oracle_kind as string;
  const req = REQUIRED[kind];
  if (!req) {
    return {
      error: `Unknown oracle_kind "${kind}". Supported: ${Object.keys(REQUIRED).join(", ")}.`,
    };
  }

  const missing = req.fields.filter((f) => !args[f]);
  if (missing.length > 0) {
    return { error: `${kind} requires ${req.fields.join(", ")} — missing: ${missing.join(", ")}. ${req.why}` };
  }

  switch (kind) {
    case "idempotent_replay":
      return {
        spec: {
          kind: "idempotent_replay",
          command: args.command,
          success_pattern: args.success_pattern,
          control_command: args.control_command,
        } as ReplaySpec,
      };
    case "differential":
      return {
        spec: {
          kind: "differential",
          attacker_command: args.attacker_command,
          authorized_command: args.authorized_command,
          marker: args.marker,
          unauthenticated_command: args.unauthenticated_command,
        } as DifferentialSpec,
      };
    case "artifact":
      return {
        spec: {
          kind: "artifact",
          deposit_command: args.deposit_command,
          read_command: args.read_command,
        } as ArtifactSpec,
      };
    case "canary":
      return {
        spec: {
          kind: "canary",
          exploit_command: args.exploit_command,
          canary_value: args.canary_value,
          legitimate_command: args.legitimate_command,
        } as CanarySpec,
      };
    case "credential_use":
      return {
        spec: {
          kind: "credential_use",
          authenticated_command: args.authenticated_command,
          success_pattern: args.success_pattern,
          unauthenticated_command: args.unauthenticated_command,
        } as CredentialUseSpec,
      };
    default:
      return {
        spec: { kind: "oast", command: args.command, protocol: args.protocol } as OastSpec,
      };
  }
}

function commandsOf(spec: OracleSpec): string[] {
  switch (spec.kind) {
    case "idempotent_replay":
      return [spec.command, spec.control_command];
    case "differential":
      return [spec.attacker_command, spec.authorized_command, spec.unauthenticated_command].filter(
        Boolean
      ) as string[];
    case "artifact":
      return [spec.deposit_command, spec.read_command];
    case "canary":
      return [spec.exploit_command, spec.legitimate_command];
    case "credential_use":
      return [spec.authenticated_command, spec.unauthenticated_command];
    case "oast":
      return [spec.command];
  }
}

export const verificationTools = [
  {
    name: "verify_finding",
    description:
      "Earn a verdict for a finding by re-proving it in code. You supply the experiment; a deterministic oracle decides the verdict — you cannot assert one. " +
      "Returns verdict = verified | refuted | candidate plus the machine receipt and a replay capsule. " +
      "Pick the STRONGEST oracle the finding supports: artifact > oast > credential_use > canary > differential > idempotent_replay. " +
      "A finding that is never verified stays a CANDIDATE and is reported as unproven.",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: { type: "string", description: "Finding to verify (from create_finding)." },
        oracle_kind: {
          type: "string",
          enum: [
            "artifact",
            "oast",
            "credential_use",
            "canary",
            "differential",
            "idempotent_replay",
          ],
          description:
            "artifact = your attack deposits a harness-minted marker that is then read back (stored XSS, SQLi write, file write) — strongest. " +
            "oast = the target calls back to our listener (blind SSRF/SQLi/XXE/SSTI). " +
            "credential_use = a recovered or forged credential actually authenticates (cracked hash, forged JWT, assumed cloud role). " +
            "canary = a planted secret surfaces where only an attacker could reach it. " +
            "differential = attacker context obtains what only an authorized context should see (IDOR/BOLA/authz). " +
            "idempotent_replay = the attack reproduces N/N while a benign control does not (universal fallback).",
        },
        target: {
          type: "string",
          description: "The finding's target, for scope validation. Must be in scope.",
        },
        intensity: {
          type: "string",
          enum: ["safe", "aggressive"],
          description: "safe = 2 replays (default), aggressive = 5.",
          default: "safe",
        },
        // idempotent_replay
        command: {
          type: "string",
          description: "[idempotent_replay] The attack command, run in the Kali container.",
        },
        success_pattern: {
          type: "string",
          description:
            "[idempotent_replay] Regex matching content unique to the VULNERABLE response. A pattern that also matches the control is rejected as non-discriminating. " +
            "[credential_use] Regex matching content that appears only on a genuinely authenticated response.",
        },
        control_command: {
          type: "string",
          description:
            "[idempotent_replay] REQUIRED negative control: the same request with the payload removed or made benign. Must NOT exhibit success_pattern.",
        },
        // differential
        attacker_command: {
          type: "string",
          description: "[differential] The request in the attacker's context (their token, the victim's object).",
        },
        authorized_command: {
          type: "string",
          description: "[differential] The same resource fetched by the party legitimately entitled to it.",
        },
        marker: {
          type: "string",
          description:
            "[differential] A literal string unique to the protected resource (id, email, token, account name). Generic markers are rejected.",
        },
        unauthenticated_command: {
          type: "string",
          description:
            "[differential] The same request with NO credentials. If this also returns the marker the oracle refutes with mechanism_mismatch — the bug is missing authentication, not broken object-level authorization. " +
            "[credential_use] REQUIRED — the same request with the credential removed. Separates 'the credential works' from 'the route was never protected'.",
        },
        // artifact
        deposit_command: {
          type: "string",
          description:
            "[artifact] The attack that deposits the marker. MUST contain the literal {{TOKEN}} — the harness mints an unpredictable value and substitutes it, so you cannot know in advance what you will be asked to find.",
        },
        read_command: {
          type: "string",
          description:
            "[artifact] Reads the marker back, ideally through a different channel than the deposit. Also uses {{TOKEN}}. The harness reads BEFORE depositing as a control — a marker already present proves nothing.",
        },
        // canary
        exploit_command: {
          type: "string",
          description: "[canary] The attack that should surface a value only an attacker could reach.",
        },
        canary_value: {
          type: "string",
          description: "[canary] The planted value. Must be specific enough that it cannot occur incidentally.",
        },
        legitimate_command: {
          type: "string",
          description:
            "[canary] REQUIRED control — the normal interface. If the canary is visible here the data is public and the oracle refutes.",
        },
        // credential_use
        authenticated_command: {
          type: "string",
          description:
            "[credential_use] A protected action performed WITH the recovered/forged credential (cracked hash, forged JWT, assumed role, replayed token).",
        },
        // oast
        protocol: {
          type: "string",
          enum: ["dns", "http", "any"],
          description: "[oast] Which interaction protocol counts as proof. Default: any.",
        },
      },
      required: ["finding_id", "oracle_kind", "target"],
    },
  },
  {
    name: "replay_capsule",
    description:
      "Re-run a verified finding's stored replay capsule and report whether it still reproduces. This is the artifact a human signer executes before signing, and what CI runs to detect a finding that has been fixed or has gone flaky. Updates the verdict to reflect the current result.",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: { type: "string", description: "Finding whose capsule to replay." },
        target: { type: "string", description: "The finding's target, for scope validation." },
        intensity: { type: "string", enum: ["safe", "aggressive"], default: "safe" },
      },
      required: ["finding_id", "target"],
    },
  },
  {
    name: "list_verdicts",
    description:
      "Verdict rollup across findings — how many are verified (oracle-proven), refuted, or still candidates, with the reason each non-verified one failed. Call this before finalizing a report: only verified findings may be presented as proven.",
    inputSchema: {
      type: "object",
      properties: {
        finding_ids: {
          type: "array",
          items: { type: "string" },
          description: "Restrict to these findings. Omit for all findings in the local store.",
        },
      },
    },
  },
];

export const verificationHandlers: Record<string, Function> = {
  verify_finding: async (args: Record<string, any>) => {
    const finding = getFindingById(args.finding_id);
    if (!finding) {
      return JSON.stringify({ ok: false, error: `Finding ${args.finding_id} not found.` });
    }

    const { spec, error } = buildSpec(args);
    if (!spec) return JSON.stringify({ ok: false, error });

    const scopeError = await screenCommandTargets(commandsOf(spec));
    if (scopeError) return JSON.stringify({ ok: false, error: scopeError });

    const intensity: Intensity = args.intensity === "aggressive" ? "aggressive" : "safe";
    const { receipt, capsule } = await runOracle(spec, intensity, oracleDeps);

    const applied = applyVerdict({
      finding_id: finding.id,
      receipt,
      capsule,
      claimed_mechanism: finding.vulnerability_type || undefined,
    });

    return JSON.stringify({
      ok: true,
      finding_id: finding.id,
      title: finding.title,
      claimed_mechanism: finding.vulnerability_type || null,
      verdict: applied.verdict,
      oracle_kind: receipt.oracle_kind,
      // Surfaced so a weak proof reads as a weak proof. 6 = artifact (harness
      // owns the nonce) down to 1 = idempotent_replay (universal fallback).
      oracle_strength: ORACLE_STRENGTH[receipt.oracle_kind as OracleKind] ?? null,
      reason: receipt.reason,
      explanation: receipt.explanation,
      replays: `${receipt.successes}/${receipt.n}`,
      receipt,
      capsule,
      ...(applied.downgraded && {
        note: "Receipt claimed verified but did not satisfy the earned-verdict invariant; finding held at candidate.",
      }),
      guidance:
        applied.verdict === "verified"
          ? "Verdict earned. This finding may be reported as PROVEN and carries a replay capsule."
          : receipt.reason === "mechanism_mismatch"
            ? "The impact is real but the finding names the wrong vulnerability. Re-file it against the mechanism the oracle actually demonstrated, then verify that."
            : "Not verified. Fix the recipe and retry, or report this finding as an unproven candidate — do not describe it as confirmed.",
    });
  },

  replay_capsule: async (args: { finding_id: string; target: string; intensity?: Intensity }) => {
    const finding = getFindingById(args.finding_id);
    if (!finding) {
      return JSON.stringify({ ok: false, error: `Finding ${args.finding_id} not found.` });
    }
    if (!finding.capsule_json) {
      return JSON.stringify({
        ok: false,
        error: `Finding ${args.finding_id} has no replay capsule — it was never verified. Call verify_finding first.`,
      });
    }

    let stored: { spec: OracleSpec; n: number };
    try {
      stored = JSON.parse(finding.capsule_json);
    } catch {
      return JSON.stringify({ ok: false, error: "Stored capsule is not valid JSON." });
    }

    const scopeError = await screenCommandTargets(commandsOf(stored.spec));
    if (scopeError) return JSON.stringify({ ok: false, error: scopeError });

    const intensity: Intensity = args.intensity === "aggressive" ? "aggressive" : "safe";
    const previous = finding.verdict || "candidate";
    const { receipt, capsule } = await runOracle(stored.spec, intensity, oracleDeps);
    const applied = applyVerdict({ finding_id: finding.id, receipt, capsule });

    return JSON.stringify({
      ok: true,
      finding_id: finding.id,
      title: finding.title,
      previous_verdict: previous,
      current_verdict: applied.verdict,
      still_reproduces: applied.verdict === "verified",
      replays: `${receipt.successes}/${receipt.n}`,
      reason: receipt.reason,
      explanation: receipt.explanation,
      receipt,
      ...(previous === "verified" &&
        applied.verdict !== "verified" && {
          note: "This finding previously verified and no longer does. Either the vulnerability was remediated or the original receipt was flaky — both are worth stating explicitly in the report.",
        }),
    });
  },

  list_verdicts: async (args: { finding_ids?: string[] }) => {
    const findings = await getFindings(args.finding_ids);
    const rows = findings.map((f) => {
      let reason: string | null = null;
      try {
        reason = f.receipt_json ? JSON.parse(f.receipt_json).reason ?? null : null;
      } catch {
        reason = null;
      }
      return {
        finding_id: f.id,
        title: f.title,
        severity: f.severity,
        verdict: f.verdict || "candidate",
        oracle_kind: f.oracle_kind || null,
        replays: f.replay_n ? `${f.replay_successes ?? 0}/${f.replay_n}` : null,
        reason,
        has_capsule: !!f.capsule_json,
      };
    });

    const counts = rows.reduce<Record<string, number>>((acc, r) => {
      acc[r.verdict] = (acc[r.verdict] || 0) + 1;
      return acc;
    }, {});

    return JSON.stringify({
      total: rows.length,
      counts: {
        verified: counts.verified || 0,
        refuted: counts.refuted || 0,
        candidate: counts.candidate || 0,
      },
      findings: rows,
      note:
        "Only `verified` findings have been re-proven by an oracle and carry a replay capsule. " +
        "`candidate` findings are detections that were never independently re-proven — report them as unproven, not as confirmed.",
    });
  },
};
