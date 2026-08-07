// MCP tool: correlate_dast_findings (P2 Phase 2).
//
// The network/web analog of correlate_cloud_findings. Joins recon-discovered open
// ports/services against vulnerable findings on those ports to produce
// "dast-correlation" findings + a computed reachability attack-path graph —
// deterministically, in the backend. Call at end-of-run AFTER complete_assessment
// (findings promoted) and a recon scan (ports snapshot promoted).
//
// It first runs the backfill extractor so freshly-promoted findings get their
// structured port/service keys parsed from target/evidence, then runs the join.

import { cloudRequest, hasCloudSession, CloudSessionError } from "../integrations/cloud-session";

export const dastCorrelationTools = [
  {
    name: "correlate_dast_findings",
    description:
      "Run the reachable+vulnerable DAST correlation: backfills structured port/service keys on the assessment's findings, then joins them against recon-discovered open ports and upserts a distinct 'dast-correlation' finding + a computed reachability attack-path graph for each match. The network/web analog of correlate_cloud_findings — PROVES the attack path from observed network state rather than narrating it. Call at end-of-run AFTER complete_assessment and a port scan. No-op with ok:false if there is no active cloud session.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "The assessed target (URL or host), e.g. https://staging.example.com.",
        },
        assessment_id: {
          type: "string",
          description: "Optional; defaults to MAESTRO_ASSESSMENT_ID.",
        },
      },
      required: ["target"],
    },
  },
];

export const dastCorrelationHandlers: Record<string, Function> = {
  correlate_dast_findings: async (args: { target: string; assessment_id?: string }) => {
    const { target } = args;
    const assessment_id = args.assessment_id ?? process.env.MAESTRO_ASSESSMENT_ID ?? null;

    if (!hasCloudSession()) {
      return JSON.stringify({
        ok: false,
        error:
          "No active cloud session — DAST correlation needs the promoted findings + recon " +
          "ports in the cloud backend (run complete_assessment + a port scan first).",
      });
    }

    const target_type = /^https?:\/\//i.test(target) ? "web" : "host";

    try {
      const resolved = await cloudRequest<{ id: string }>("/targets/resolve", {
        method: "POST",
        body: { raw_value: target, target_type },
      });

      // Parse structured port/service keys onto findings that don't have them yet.
      const backfill = await cloudRequest<{ scanned: number; updated: number; unparsable: string[] }>(
        "/findings/backfill-keys",
        { method: "POST", body: { assessment_id } }
      );

      const resp = await cloudRequest<{ correlated: number; finding_ids: string[] }>(
        "/correlate/dast",
        { method: "POST", body: { target_id: resolved.id, assessment_id } }
      );

      return JSON.stringify(
        {
          ok: true,
          target_id: resolved.id,
          keys_backfilled: backfill.updated,
          keys_unparsable: backfill.unparsable.length,
          correlated: resp.correlated,
          finding_ids: resp.finding_ids,
          note:
            resp.correlated === 0
              ? "No reachable+vulnerable correlations (no CVE-bearing finding sits on a recon-confirmed open port, or recon ports / findings not yet promoted)."
              : `${resp.correlated} reachable vulnerable service(s) correlated into findings.`,
        },
        null,
        2
      );
    } catch (e) {
      const msg =
        e instanceof CloudSessionError
          ? `cloud request failed (${e.status}): ${e.message}`
          : e instanceof Error
            ? e.message
            : String(e);
      return JSON.stringify({ ok: false, error: msg });
    }
  },
};
