import { upsertFinding, getFindings, getFindingsForAssessment, generateReportContent, FindingInput, saveReportRecord, compareAssessments } from "../integrations/findings-db";
import { createJiraTicket, listJiraProjects, listJiraBoards } from "../integrations/jira";
import { uploadToSharePoint } from "../integrations/sharepoint";
import { sendEmail } from "../integrations/email";
import { generateProfessionalHtml } from "../integrations/report-html-template";
import { executeInKali } from "../utils/docker-exec";
import { hasCloudSession, cloudRequest, cloudUploadFile, CloudSessionError } from "../integrations/cloud-session";
import { buildProvenancePromotion, getAvailability, snapshotToolAvailability } from "../logging/tool-provenance";

export const reportingTools = [
  {
    name: "create_finding",
    description: "Create or update a security finding record. Automatically deduplicates based on target and vulnerability type.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Finding title" },
        severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
        description: { type: "string", description: "Detailed description" },
        target: { type: "string", description: "Affected target" },
        evidence: { type: "string", description: "Proof/evidence of vulnerability" },
        remediation: { type: "string", description: "Recommended fix" },
        cve: { type: "string", description: "Associated CVE if known" },
        cwe: { type: "string", description: "CWE identifier if known (e.g., CWE-89)" },
        cycode_ref: { type: "string", description: "Reference to Cycode finding if applicable" },
        source: { type: "string", description: "Tool or agent that found this. REQUIRED to be a specific identifier — never \"manual\". Use the MCP tool name (e.g., 'nuclei', 'sqlmap', 'test_xss', 'analyze_jwt'), the agent name (e.g., 'web-app-agent', 'recon-infra', 'api-graphql'), or a scoped test id (e.g., 'api-graphql:API-01'). Generic strings like 'manual' break the findings categorization pipeline." },
        assessment_id: { type: "string", description: "Assessment ID to link this finding to" },
        file_path: { type: "string", description: "Source file path (for SAST/code findings)" },
        line_start: { type: "number", description: "Starting line number" },
        line_end: { type: "number", description: "Ending line number" },
        code_snippet: { type: "string", description: "Relevant code snippet" },
        remediation_code: { type: "string", description: "Fixed code snippet" },
        remediation_explanation: { type: "string", description: "Why the fix works" },
        exploitable: { type: "string", enum: ["true", "false", "potentially"], description: "Exploitability status. 'true' = confirmed exploitable (this INCLUDES the EXPLOITED-but-DESTRUCTIVE-WITHHELD case: the vuln is confirmed but its destructive PoC was withheld for safety — still 'true', and state the withheld payload in the evidence/description), 'false' = tested and not exploitable, 'potentially' = code/config finding not live-testable (secrets, SAST, etc.)" },
        file_locations: { type: "string", description: "JSON-encoded array of affected file locations. Each entry: {file: string, line?: number, context?: string, commit_hash?: string, author?: string}. Use for findings that affect multiple files (secrets, SAST patterns)." },
        port: { type: "number", description: "Network port the finding lives on (correlation key for the DAST reachability join). Optional — auto-derived from a URL target when omitted; set explicitly for non-URL targets." },
        service: { type: "string", description: "Service/version on that port (e.g. 'nginx-1.24'), if known. Improves correlation graph labels." },
        component: { type: "string", description: "Affected package/component (e.g. 'lodash@4.17.20'), if known. Correlation key for component-level matching." },
        image_digest: { type: "string", description: "Container image digest (sha256:...) this finding pertains to, if known. Correlation key for container-CVE matching." },
      },
      required: ["title", "severity", "description", "target"],
    },
  },
  {
    name: "generate_report",
    description: "Generate a security assessment report. IMPORTANT: Use finding_ids to filter to the current assessment's findings only. Without finding_ids, this returns ALL findings ever created across all assessments.",
    inputSchema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["markdown", "html", "json"], default: "markdown" },
        include_evidence: { type: "boolean", default: true },
        finding_ids: { type: "array", items: { type: "string" }, description: "Specific finding IDs to include. Pass the finding_ids collected from agent completion messages to get only this assessment's findings." },
      },
      required: ["format"],
    },
  },
  {
    name: "create_jira_ticket",
    description: "Create a Jira ticket for a finding.",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: { type: "string", description: "Finding ID to create ticket for" },
        project_key: { type: "string", description: "Jira project key" },
        priority: { type: "string", enum: ["Lowest", "Low", "Medium", "High", "Highest"] },
      },
      required: ["finding_id", "project_key"],
    },
  },
  {
    name: "upload_report",
    description: "Upload report to SharePoint and optionally email it.",
    inputSchema: {
      type: "object",
      properties: {
        report_content: { type: "string", description: "Report content" },
        filename: { type: "string", description: "Report filename" },
        email_recipients: { type: "array", items: { type: "string" }, description: "Email addresses" },
      },
      required: ["report_content", "filename"],
    },
  },
  {
    name: "import_cycode_findings",
    description: "Import findings from Cycode CSV export.",
    inputSchema: {
      type: "object",
      properties: {
        csv_content: { type: "string", description: "CSV content from Cycode export" },
      },
      required: ["csv_content"],
    },
  },
  {
    name: "generate_pdf_report",
    description:
      "Generate a professional PDF report. Modes: (1 — PREFERRED) Pass markdown_path (absolute path to a .md file on disk) to render that file faithfully — the tool reads the file from disk so the FULL report renders with zero truncation/condensing. ALWAYS use this for a report already written to disk. (2) Pass markdown_content to render inline markdown — LEGACY; avoid for large reports because passing big content through a tool call lets the model silently condense it (this is exactly how a 67-page report once rendered to 7 pages). (3) Without either, builds a PDF from DB findings. The PDF is rendered AND uploaded to the cloud Reports page when assessment_id is set. AUTO-COMPLETE (default ON): when assessment_id is set, a successful upload also promotes the run's findings to the cloud and marks the assessment 'completed' — producing the report IS the completion signal, so an ad-hoc run needs no separate complete_assessment call. Pass auto_complete:false on companion reports and whenever you run your OWN curated complete_assessment afterward (e.g. the pdf-renderer agent), so this safety net doesn't push the uncurated full finding set ahead of your curated one.",
    inputSchema: {
      type: "object",
      properties: {
        markdown_path: {
          type: "string",
          description:
            "Absolute path to a .md report file on disk to render faithfully (PREFERRED). The tool reads the file directly — nothing passes through the model — so the complete report renders with no condensing. Use this instead of markdown_content whenever the report is already on disk (e.g. reports/<prefix>-assessment-<date>.md).",
        },
        markdown_content: {
          type: "string",
          description:
            "Full markdown report content to render as PDF (LEGACY inline mode). Prefer markdown_path for anything already on disk — passing large content inline risks the model condensing it.",
        },
        title: { type: "string", description: "Report title (default: 'Security Assessment Report')" },
        target: { type: "string", description: "Assessment target name" },
        include_evidence: { type: "boolean", default: true, description: "Include evidence in findings" },
        output_filename: { type: "string", description: "Output PDF filename (default: report.pdf)" },
        finding_ids: {
          type: "array",
          items: { type: "string" },
          description: "Specific finding IDs to include when building from DB (default: all)",
        },
        assessment_id: {
          type: "string",
          description: "Assessment ID to link the report to. When provided, a report record is saved to the database for the app's reports page.",
        },
        auto_complete: {
          type: "boolean",
          default: true,
          description: "Default true: on a successful upload with assessment_id, promote the run's findings to the cloud and mark the assessment 'completed' (the report is the completion signal — covers ad-hoc / chat runs that never call complete_assessment). Pass false for companion reports (SAST/cloud/identity/AI) and whenever a curated complete_assessment runs separately afterward (the pdf-renderer agent), so the uncurated full set isn't pushed ahead of the curated one.",
        },
        severity_overrides: {
          type: "object",
          description: "Optional calibration map keyed by local finding id → { calibrated_severity }. When present, the report-row severity counts (critical/high/medium/low) are computed from the CALIBRATED severity, falling back to scanner-original per finding when there is no override. Pass this for the MAIN assessment report so its dashboard card matches the calibrated findings list; OMIT it for SAST / cloud companion reports (those are not calibrated and should show scanner-original counts).",
        },
      },
    },
  },
  {
    name: "compare_assessments",
    description: "Compare findings between two assessments to identify new, fixed, unchanged, and severity-changed vulnerabilities. Useful for tracking remediation progress and generating delta reports.",
    inputSchema: {
      type: "object",
      properties: {
        old_assessment_id: { type: "string", description: "Assessment ID of the previous/baseline assessment" },
        new_assessment_id: { type: "string", description: "Assessment ID of the current/latest assessment" },
      },
      required: ["old_assessment_id", "new_assessment_id"],
    },
  },
  {
    name: "clear_findings",
    description: "Clear all findings from the local per-assessment store. Call at the START of a new assessment to ensure a clean slate. NOTE: only clears the in-container local SQLite — the cloud dashboard is unaffected. Cloud findings are managed exclusively via complete_assessment.",
    inputSchema: {
      type: "object",
      properties: {
        confirm: { type: "boolean", description: "Must be true to confirm deletion. Safety check to prevent accidental clearing." },
      },
      required: ["confirm"],
    },
  },
  {
    name: "complete_assessment",
    description: "FINAL STEP of an assessment. Promotes findings from the local per-assessment store to the cloud dashboard and marks the assessment as completed. Findings created via create_finding during the run live only in the local container store; this tool is the single bridge to the cloud DB. Pass the report-writer's curated finding_ids (post-calibration + dedup) — those will appear on the dashboard and match the rendered report. Pass an empty array (or omit) to push EVERY local finding instead (manual-fallback path used by the desktop's 'Complete & Push' button when no report has been written). Pass severity_overrides to populate the calibrated_severity / calibration_rule / calibration_justification columns on each cloud finding — the dashboard renders calibrated as the primary severity when present.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: { type: "string", description: "Assessment ID to mark completed. Falls back to MAESTRO_ASSESSMENT_ID env var." },
        finding_ids: { type: "array", items: { type: "string" }, description: "Curated finding IDs from local store to push to cloud. Empty array means push everything in the local store (uncurated fallback)." },
        severity_overrides: {
          type: "object",
          description: "Optional per-finding calibration metadata, keyed by local finding ID. Each value: { calibrated_severity: 'critical'|'high'|'medium'|'low'|'info', rule: string, justification: string }. Source from reports/severity-calibration-results.json after the severity-calibrator agent runs.",
          additionalProperties: {
            type: "object",
            properties: {
              calibrated_severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
              rule: { type: "string" },
              justification: { type: "string" },
            },
          },
        },
      },
    },
  },
  {
    name: "list_jira_projects",
    description: "List available Jira projects from the configured instance.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "list_jira_boards",
    description: "List available Jira boards from the configured instance. Optionally filter by project.",
    inputSchema: {
      type: "object",
      properties: {
        project_key: { type: "string", description: "Filter boards by project key (optional)" },
      },
    },
  },
];

/** Local verdict columns hold JSON strings; the cloud columns are JSONB. */
function safeJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

/**
 * Promote an assessment's local findings to the cloud dashboard and flip its
 * status to `completed`. This is the single completion bridge — shared by the
 * explicit `complete_assessment` tool, the desktop "Complete & Push" button,
 * and the auto-complete-on-main-report path in `generate_pdf_report`.
 *
 * Idempotent and safe to call more than once per assessment: the cloud
 * `/findings` POST upserts on fingerprint, and PATCH status=completed is a
 * terminal no-op on re-call.
 *
 * Caller must have already verified `hasCloudSession()`.
 */
async function promoteFindingsAndComplete(
  assessment_id: string,
  opts: {
    finding_ids?: string[];
    severity_overrides?: Record<
      string,
      { calibrated_severity?: string; rule?: string; justification?: string }
    >;
  } = {},
) {
  // Empty / missing finding_ids → fallback "push everything local" path. The
  // agent-driven flow passes a curated set; the manual "Complete & Push"
  // button and the auto-complete-without-a-curated-list path use "all".
  const explicitIds = Array.isArray(opts.finding_ids) ? opts.finding_ids : [];
  const mode: "curated" | "all" = explicitIds.length === 0 ? "all" : "curated";
  const localFindings =
    mode === "all" ? await getFindings() : await getFindings(explicitIds);
  const missing =
    mode === "all"
      ? []
      : explicitIds.filter((id) => !localFindings.find((f) => f.id === id));

  const result = {
    assessment_id,
    mode,
    requested: mode === "all" ? localFindings.length : explicitIds.length,
    found_local: localFindings.length,
    missing_local: missing,
    pushed: 0,
    failed: 0 as number,
    errors: [] as Array<{ id: string; error: string }>,
    assessment_status: "running" as "running" | "completed",
    // Verdict rollup over what is being promoted. `verified` is the headline
    // number — those findings were re-proven by an oracle and carry a replay
    // capsule. Everything else is a detection that was never independently
    // re-proven and must not be presented as confirmed.
    verdicts: localFindings.reduce(
      (acc, f) => {
        const v = (f.verdict || "candidate") as "verified" | "refuted" | "candidate";
        acc[v] = (acc[v] || 0) + 1;
        return acc;
      },
      { verified: 0, refuted: 0, candidate: 0 } as Record<string, number>,
    ),
  };

  const overrides = opts.severity_overrides ?? {};
  for (const f of localFindings) {
    // Per-finding calibration metadata — set when the calibrator agent
    // produced a delta; absent rows fall back to scanner-original severity on
    // the dashboard (clean COALESCE behavior server-side).
    const cal = overrides[f.id];
    try {
      await cloudRequest("/findings", {
        method: "POST",
        body: {
          // Cloud `/findings` POST upserts on fingerprint(title,target,source,cwe),
          // so re-runs that surface the same vuln bump occurrence_count
          // instead of duplicating rows.
          title: f.title,
          severity: f.severity,
          description: f.description,
          target: f.target,
          evidence: f.evidence,
          remediation: f.remediation,
          cve: f.cve,
          cwe: f.cwe,
          cycode_ref: f.cycode_ref,
          source: f.source,
          exploitable: f.exploitable,
          file_path: f.file_path,
          line_start: f.line_start,
          line_end: f.line_end,
          code_snippet: f.code_snippet,
          remediation_code: f.remediation_code,
          remediation_explanation: f.remediation_explanation,
          file_locations: f.file_locations,
          // Structured correlation keys (migration 0030). The backend also
          // auto-derives port from a URL target when omitted.
          port: f.port,
          service: f.service,
          component: f.component,
          image_digest: f.image_digest,
          assessment_id,
          calibrated_severity: cal?.calibrated_severity,
          calibration_rule: cal?.rule,
          calibration_justification: cal?.justification,
          // Oracle verdict (migration 0049). Promoted so the dashboard can show
          // which findings were re-proven in code and ship their replay capsule.
          // The backend CHECK constraint refuses a `verified` row without a
          // complete receipt, so a local bug cannot launder an unearned verdict
          // into the cloud.
          verdict: f.verdict || "candidate",
          oracle_kind: f.oracle_kind,
          receipt_json: f.receipt_json ? safeJson(f.receipt_json) : undefined,
          capsule_json: f.capsule_json ? safeJson(f.capsule_json) : undefined,
          replay_n: f.replay_n,
          replay_successes: f.replay_successes,
          verified_at: f.verified_at,
          claimed_mechanism: f.claimed_mechanism,
        },
      });
      result.pushed++;
    } catch (e: any) {
      result.failed++;
      result.errors.push({ id: f.id, error: e?.message ?? String(e) });
    }
  }

  try {
    await cloudRequest(`/assessments/${assessment_id}`, {
      method: "PATCH",
      body: { status: "completed" },
    });
    result.assessment_status = "completed";
  } catch (e: any) {
    result.errors.push({
      id: `assessment:${assessment_id}`,
      error: `status update failed: ${e?.message ?? String(e)}`,
    });
  }

  // Promote tool-execution provenance (P1) so the desktop "Tools" view shows
  // which tools actually ran. Best-effort: never fail completion over it.
  try {
    if (getAvailability(assessment_id).length === 0) {
      await snapshotToolAvailability(assessment_id);
    }
    const tools = buildProvenancePromotion(assessment_id);
    if (tools.length > 0) {
      const prov = await cloudRequest<{ upserted: number }>(
        `/assessments/${assessment_id}/tool-executions`,
        { method: "POST", body: { tools } }
      );
      (result as any).tool_provenance_promoted = prov.upserted;
    }
  } catch (e: any) {
    result.errors.push({
      id: `tool_provenance:${assessment_id}`,
      error: `provenance promotion failed: ${e?.message ?? String(e)}`,
    });
  }

  return result;
}

export const reportingHandlers: Record<string, Function> = {
  create_finding: async (args: any) => {
    // Local-only during an assessment. Findings live in the in-container
    // SQLite until complete_assessment() promotes the curated subset to
    // the cloud dashboard at the end of the run. This keeps the dashboard
    // free of raw scanner output and ensures it matches the rendered
    // report exactly (per Shape A — see project_shape_a_finding_finalize).
    const { assessment_id: explicitId, ...findingInput } = args;
    const assessment_id =
      explicitId || process.env.MAESTRO_ASSESSMENT_ID || undefined;

    const input: FindingInput = {
      title: findingInput.title,
      severity: findingInput.severity,
      description: findingInput.description,
      target: findingInput.target,
      evidence: findingInput.evidence,
      remediation: findingInput.remediation,
      cve: findingInput.cve,
      cwe: findingInput.cwe,
      cycode_ref: findingInput.cycode_ref,
      source: findingInput.source,
      file_path: findingInput.file_path,
      line_start: findingInput.line_start,
      line_end: findingInput.line_end,
      code_snippet: findingInput.code_snippet,
      remediation_code: findingInput.remediation_code,
      remediation_explanation: findingInput.remediation_explanation,
      exploitable: findingInput.exploitable,
      file_locations: findingInput.file_locations,
      port: findingInput.port,
      service: findingInput.service,
      component: findingInput.component,
      image_digest: findingInput.image_digest,
    };

    // The oracle invariant. A verdict is EARNED in code by a named oracle; it is
    // never something the caller can assert. Any verdict-shaped argument is
    // dropped here and reported back, so an agent that tries to self-certify sees
    // that it did not work rather than silently believing it did. The only writer
    // of these columns is applyVerdict(), reached exclusively through
    // verify_finding. See docs/oracle-verification-layer.md.
    const VERDICT_FIELDS = [
      "verdict",
      "oracle_kind",
      "receipt_json",
      "capsule_json",
      "replay_n",
      "replay_successes",
      "verified_at",
    ];
    const attempted = VERDICT_FIELDS.filter((f) => findingInput[f] !== undefined);

    const result = await upsertFinding(input, assessment_id);

    return JSON.stringify({
      status: result.isNew ? "created" : "updated",
      finding_id: result.finding.id,
      is_new: result.isNew,
      was_updated: result.wasUpdated,
      evidence_added: result.evidenceAdded,
      occurrence_count: result.finding.occurrence_count,
      finding: result.finding,
      source: "local",
      verdict: result.finding.verdict || "candidate",
      ...(attempted.length > 0 && {
        rejected_fields: attempted,
        rejected_reason:
          "A verdict must be earned by an oracle, not asserted. These fields were ignored. " +
          "Call verify_finding(finding_id, oracle_kind, spec) to have the harness re-prove this finding in code.",
      }),
      next_step:
        result.finding.verdict === "verified"
          ? undefined
          : "This finding is a CANDIDATE. Call verify_finding to earn a verdict before it counts as proven.",
    });
  },

  generate_report: async (args: { format: string; include_evidence?: boolean; finding_ids?: string[] }) => {
    const { format, include_evidence = true, finding_ids } = args;
    const findings = await getFindings(finding_ids);
    const report = await generateReportContent(findings, format, include_evidence);
    
    return JSON.stringify({
      status: "generated",
      format,
      findings_count: findings.length,
      report,
    });
  },

  create_jira_ticket: async (args: { finding_id: string; project_key: string; priority?: string }) => {
    const { finding_id, project_key, priority = "Medium" } = args;
    const result = await createJiraTicket(finding_id, project_key, priority);
    return JSON.stringify(result);
  },

  upload_report: async (args: { report_content: string; filename: string; email_recipients?: string[] }) => {
    const { report_content, filename, email_recipients } = args;
    
    // Upload to SharePoint
    const sharePointUrl = await uploadToSharePoint(report_content, filename);
    
    // Send email if recipients provided
    if (email_recipients && email_recipients.length > 0) {
      await sendEmail(email_recipients, `Security Report: ${filename}`, report_content, sharePointUrl);
    }
    
    return JSON.stringify({
      status: "uploaded",
      sharepoint_url: sharePointUrl,
      emailed_to: email_recipients || [],
    });
  },

  import_cycode_findings: async (args: { csv_content: string }) => {
    const { csv_content } = args;
    const { parseCycodeCSV } = await import("../integrations/cycode");
    const findings = await parseCycodeCSV(csv_content);

    return JSON.stringify({
      status: "imported",
      findings_count: findings.length,
      findings,
    });
  },

  generate_pdf_report: async (args: {
    markdown_path?: string;
    markdown_content?: string;
    title?: string;
    target?: string;
    include_evidence?: boolean;
    output_filename?: string;
    finding_ids?: string[];
    assessment_id?: string;
    auto_complete?: boolean;
    severity_overrides?: Record<
      string,
      { calibrated_severity?: string; rule?: string; justification?: string }
    >;
  }) => {
    const {
      markdown_path,
      markdown_content,
      title = "Security Assessment Report",
      target = "Target Application",
      include_evidence = true,
      output_filename = "report.pdf",
      finding_ids,
    } = args;
    // Fall back to MAESTRO_ASSESSMENT_ID env var when the caller omits
    // assessment_id. The desktop terminal spawn propagates that env var
    // into the container so any tool that needs to bind outputs to the
    // current assessment row can find it without each agent prompt
    // remembering to pass it explicitly. This is the safety net that
    // prevents PDFs from landing on disk but never showing up in the
    // Reports page — the pre-env-var pdf-renderer.md prompt didn't
    // mention assessment_id at all, so every assessment shipped with
    // 0 cloud-registered reports.
    const assessment_id = args.assessment_id || process.env.MAESTRO_ASSESSMENT_ID || undefined;

    // Calibration map (finding id → calibrated severity). The pdf-renderer
    // passes this for the MAIN report ONLY, so its dashboard card's severity
    // counts reflect the calibrated severities (matching the calibrated
    // findings list). Absent for SAST/cloud companions → scanner-original.
    const severityOverrides = args.severity_overrides ?? {};

    // Auto-complete the assessment when the report lands in the cloud:
    // producing the report IS the completion signal. The chat-continues flow
    // rarely calls complete_assessment explicitly, so without this an assessed
    // run sits `running` until the 3h reaper closes it as `incomplete`.
    //
    // Default ON, so an ad-hoc chat run / quick scan that just renders a PDF
    // auto-completes (promoting its findings + flipping status). Flows that run
    // their OWN curated complete_assessment afterward — notably the pdf-renderer
    // agent, which promotes a post-calibration/dedup finding_ids set in its
    // Step 3, and every companion-report render — pass auto_complete:false to
    // opt out, so this safety net never pushes the uncurated full set ahead of
    // the curated one.
    const autoComplete: boolean = args.auto_complete ?? true;
    async function maybeAutoComplete(
      uploadStatus: "ok" | "skipped_no_assessment_id" | "failed",
    ): Promise<Record<string, unknown>> {
      if (!autoComplete)
        return { auto_completed: false, reason: "auto_complete_disabled" };
      if (uploadStatus !== "ok")
        return { auto_completed: false, reason: `upload_${uploadStatus}` };
      if (!assessment_id)
        return { auto_completed: false, reason: "no_assessment_id" };
      if (!hasCloudSession())
        return { auto_completed: false, reason: "no_cloud_session" };
      try {
        const promotion = await promoteFindingsAndComplete(assessment_id, {
          finding_ids,
          severity_overrides: severityOverrides,
        });
        return { auto_completed: true, promotion };
      } catch (e) {
        return {
          auto_completed: false,
          reason: `error: ${e instanceof Error ? e.message : String(e)}`,
        };
      }
    }

    const mdPath = "/opt/pentest/output/report-temp.md";
    const outputPath = `/opt/pentest/output/${output_filename}`;

    /**
     * Cloud-only persistence. The PDF was rendered to `outputPath`
     * inside the container; we POST a row, multipart-upload the
     * bytes into the per-customer S3 bucket, then drop the local
     * temp file. The Reports page reads from cloud exclusively —
     * there is no host-disk copy.
     *
     * Returns `{ uploadStatus, uploadError? }` so the pdf-renderer
     * agent can verify the artifact actually landed in cloud
     * storage (uploadStatus === "ok"), not just that the row
     * exists.
     *
     * Legacy local-DB fallback (`saveReportRecord`) is kept only
     * for the rare no-cloud-session path that exists for dev mode.
     * Once dev mode is gone too, that branch can be removed.
     */
    async function persistReport(
      sizeKb: number,
      findingsCount?: number,
    ): Promise<{
      uploadStatus: "ok" | "skipped_no_assessment_id" | "failed";
      uploadError?: string;
    }> {
      if (!assessment_id) {
        // No assessment_id (neither arg nor MAESTRO_ASSESSMENT_ID env) — the
        // report can't be linked to a cloud row and would never appear on the
        // Reports dashboard. Surface this LOUDLY and KEEP the rendered PDF (do
        // NOT delete it) so the team lead can bind it manually. The old code
        // warned quietly and deleted the file, which is exactly how a whole run
        // shipped with 0 cloud-registered reports (the groovysec run rendered
        // PDFs to disk that never reached prod).
        console.error(
          "[generate_pdf_report] MISSING assessment_id (no arg, no MAESTRO_ASSESSMENT_ID env) — " +
          `PDF rendered to ${outputPath} but NOT uploaded to the cloud Reports page. ` +
          "The pdf-renderer agent must pass assessment_id explicitly (the 'Assessment ID' from its dispatched context).",
        );
        return { uploadStatus: "skipped_no_assessment_id" };
      }

      try {
        const findings = await getFindingsForAssessment(assessment_id);
        // Effective severity per finding: calibrated when an override exists
        // (main report), else scanner-original. Keeps the report card's counts
        // in lockstep with the calibrated findings list on the dashboard.
        const effSeverities = findings.map(
          (f) => severityOverrides[f.id]?.calibrated_severity ?? f.severity,
        );
        const counts = {
          total: findings.length,
          critical: effSeverities.filter((s) => s === "critical").length,
          high: effSeverities.filter((s) => s === "high").length,
          medium: effSeverities.filter((s) => s === "medium").length,
          low: effSeverities.filter((s) => s === "low").length,
        };
        const reportRecord = {
          assessment_id,
          name: output_filename,
          format: "pdf" as const,
          // file_path intentionally omitted — bytes go to S3, the
          // row's only artifact pointer is s3_key (set by the
          // upload endpoint). Storing a container-side host path
          // here causes more confusion than it's worth.
          findings_count: findingsCount ?? counts.total,
          critical_count: counts.critical,
          high_count: counts.high,
          medium_count: counts.medium,
          low_count: counts.low,
        };

        if (hasCloudSession()) {
          // Row first, then bytes. The bytes upload populates
          // s3_key on the row; without that step the report will
          // show as "unavailable" in the desktop's Reports page.
          const created = await cloudRequest<{ id: string }>("/reports", {
            method: "POST",
            body: reportRecord,
          });
          if (!created?.id) {
            throw new Error("Cloud /reports POST returned no id — cannot upload bytes");
          }
          try {
            await cloudUploadFile(`/reports/${created.id}/upload`, outputPath);
          } catch (uploadErr) {
            const msg = uploadErr instanceof Error ? uploadErr.message : String(uploadErr);
            console.error("[generate_pdf_report] Cloud row created but artifact upload failed:", msg);
            // Keep the temp file around so a manual retry could
            // re-upload — but the pdf-renderer agent should treat
            // this as a hard failure.
            return { uploadStatus: "failed", uploadError: `artifact_upload_failed: ${msg}` };
          }
        } else {
          // Dev/offline only — local-SQLite path. Tracks the row
          // in the desktop's local DB for testing without a cloud
          // backend. file_path here points at the temp render
          // output (not a stable location) so local-mode users
          // should re-render rather than rely on persistence.
          await saveReportRecord({
            assessmentId: assessment_id,
            name: output_filename,
            format: "pdf",
            filePath: outputPath,
            findingsCount: findingsCount ?? counts.total,
            criticalCount: counts.critical,
            highCount: counts.high,
            mediumCount: counts.medium,
            lowCount: counts.low,
          });
        }
        // Bytes are in cloud now; the temp render file has no
        // reason to live. Best-effort cleanup.
        await executeInKali(`rm -f ${outputPath}`).catch(() => {});
        return { uploadStatus: "ok" };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error("[generate_pdf_report] Failed to save report record:", msg);
        return { uploadStatus: "failed", uploadError: msg };
      }
    }

    if (markdown_path || markdown_content) {
      // ── Mode 1: Render an existing markdown report to PDF ──
      // PREFERRED: when markdown_path is provided, render the on-disk file
      // DIRECTLY — nothing passes through the model, so the FULL report
      // renders faithfully with no condensing/truncation. Only fall back to
      // writing inline markdown_content to a temp file for the legacy path
      // (which is what let a 67-page report ship as 7 pages once an agent
      // summarized the content while passing it through the tool call).
      let renderInput: string;
      let cleanupTemp = false;
      if (markdown_path) {
        renderInput = markdown_path;
      } else {
        const writeCmd = `cat > ${mdPath} << 'MDEOF'\n${markdown_content}\nMDEOF`;
        await executeInKali(writeCmd);
        renderInput = mdPath;
        cleanupTemp = true;
      }

      // Use md-to-pdf.js to convert (marked + playwright resolvable globally)
      const renderCmd = `NODE_PATH=$(npm root -g) node /opt/pentest/scripts/md-to-pdf.js ${renderInput} ${outputPath}`;
      const result = await executeInKali(renderCmd);

      // Clean up only our own temp markdown — never the caller's source file
      if (cleanupTemp) await executeInKali(`rm -f ${mdPath}`).catch(() => {});

      try {
        const parsed = JSON.parse(result);
        if (parsed.success) {
          const persisted = await persistReport(parsed.size_kb);
          const completion = await maybeAutoComplete(persisted.uploadStatus);
          return JSON.stringify({
            status: "generated",
            upload_status: persisted.uploadStatus,
            upload_error: persisted.uploadError,
            auto_completed: completion.auto_completed,
            completion,
            size_kb: parsed.size_kb,
            message: `PDF report generated from markdown (${parsed.size_kb} KB); cloud upload: ${persisted.uploadStatus}`,
          });
        } else {
          return JSON.stringify({ status: "error", message: parsed.error || "Failed to render PDF" });
        }
      } catch {
        return JSON.stringify({ status: "error", message: "Failed to parse result", raw: result.slice(0, 1000) });
      }
    }

    // ── Mode 2: Build PDF from database findings via HTML template ──
    const findings = await getFindings(finding_ids);
    if (findings.length === 0) {
      return JSON.stringify({
        status: "error",
        message: "No findings found. Create findings first, or pass markdown_content to render an existing report.",
      });
    }

    const html = generateProfessionalHtml(findings, {
      title,
      target,
      includeEvidence: include_evidence,
    });

    const htmlPath = "/opt/pentest/output/report-temp.html";

    // Write HTML to container
    const writeCmd = `cat > ${htmlPath} << 'HTMLEOF'\n${html}\nHTMLEOF`;
    await executeInKali(writeCmd);

    // Render HTML to PDF via Playwright
    const renderPayload = JSON.stringify({
      action: "render_pdf_from_file",
      params: { htmlPath, outputPath },
    });
    const escaped = renderPayload.replace(/'/g, "'\\''");
    const renderCmd = `node /opt/pentest/scripts/playwright-action.js '${escaped}'`;
    const result = await executeInKali(renderCmd);

    try {
      const parsed = JSON.parse(result);
      if (parsed.success) {
        await executeInKali(`rm -f ${htmlPath}`).catch(() => {});
        const persisted = await persistReport(parsed.data.size_kb, findings.length);
        const completion = await maybeAutoComplete(persisted.uploadStatus);
        return JSON.stringify({
          status: "generated",
          upload_status: persisted.uploadStatus,
          upload_error: persisted.uploadError,
          auto_completed: completion.auto_completed,
          completion,
          size_kb: parsed.data.size_kb,
          findings_count: findings.length,
          message: `PDF report generated with ${findings.length} findings (${parsed.data.size_kb} KB); cloud upload: ${persisted.uploadStatus}`,
        });
      } else {
        return JSON.stringify({
          status: "error",
          message: parsed.error || "Failed to render PDF",
          raw: result.slice(0, 1000),
        });
      }
    } catch {
      return JSON.stringify({
        status: "error",
        message: "Failed to parse Playwright result",
        raw: result.slice(0, 1000),
      });
    }
  },

  compare_assessments: async (args: { old_assessment_id: string; new_assessment_id: string }) => {
    const { old_assessment_id, new_assessment_id } = args;
    const result = await compareAssessments(old_assessment_id, new_assessment_id);
    return JSON.stringify(result);
  },

  clear_findings: async (args: { confirm: boolean }) => {
    if (!args.confirm) {
      return JSON.stringify({ status: "aborted", message: "confirm must be true to clear findings" });
    }

    // Local-only by design. The cloud dashboard is the canonical record
    // of completed assessments — wiping it from an in-flight tool call
    // would corrupt that history. Clearing the per-assessment intermediate
    // store at the start of a fresh run is what this tool is for.
    const { getDatabase } = await import("../logging/log-store");
    const db = getDatabase();
    const countBefore = (db.prepare("SELECT COUNT(*) as count FROM findings").get() as any).count;
    db.prepare("DELETE FROM assessment_findings").run();
    db.prepare("DELETE FROM finding_evidence").run();
    db.prepare("DELETE FROM findings").run();
    return JSON.stringify({
      status: "cleared",
      findings_deleted: countBefore,
      message: `Cleared ${countBefore} findings from local database. Ready for new assessment.`,
      source: "local",
    });
  },

  list_jira_projects: async () => {
    const result = await listJiraProjects();
    return JSON.stringify(result);
  },

  list_jira_boards: async (args: { project_key?: string }) => {
    const result = await listJiraBoards(args.project_key);
    return JSON.stringify(result);
  },

  complete_assessment: async (args: {
    assessment_id?: string;
    finding_ids?: string[];
    severity_overrides?: Record<
      string,
      { calibrated_severity?: string; rule?: string; justification?: string }
    >;
  }) => {
    const assessment_id =
      args.assessment_id || process.env.MAESTRO_ASSESSMENT_ID;
    if (!assessment_id) {
      throw new Error(
        "complete_assessment requires assessment_id (arg or MAESTRO_ASSESSMENT_ID env)"
      );
    }
    if (!hasCloudSession()) {
      throw new Error(
        "complete_assessment requires an active cloud session — desktop must be signed in"
      );
    }

    const result = await promoteFindingsAndComplete(assessment_id, {
      finding_ids: args.finding_ids,
      severity_overrides: args.severity_overrides,
    });

    return JSON.stringify(result);
  },
};
