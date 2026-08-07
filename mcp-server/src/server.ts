import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { reconTools, reconHandlers } from "./tools/recon";
import { vulnScanTools, vulnScanHandlers } from "./tools/vuln-scan";
import { webAppTools, webAppHandlers } from "./tools/web-app";
import { exploitTools, exploitHandlers } from "./tools/exploit";
import { reportingTools, reportingHandlers } from "./tools/reporting";
import { codeScanTools, codeScanHandlers } from "./tools/code-scan";
import { agentTools, agentHandlers } from "./tools/agent-tools";
import { interactiveTools, interactiveHandlers } from "./tools/interactive";
import { browserTools, browserHandlers } from "./tools/browser";
import { codeIntelTools, codeIntelHandlers } from "./tools/code-intel";
import { guidanceTools, guidanceHandlers } from "./tools/guidance";
import { sslTlsTools, sslTlsHandlers } from "./tools/ssl-tls";
import { dnsSecurityTools, dnsSecurityHandlers } from "./tools/dns-security";
import { tokenSecurityTools, tokenSecurityHandlers } from "./tools/token-security";
import { advancedWebTools, advancedWebHandlers } from "./tools/advanced-web";
import { apiSecurityTools, apiSecurityHandlers } from "./tools/api-security";
import { cloudSecurityTools, cloudSecurityHandlers } from "./tools/cloud-security";
import { cloudComputeTools, cloudComputeHandlers } from "./tools/cloud-compute";
import { sessionSecurityTools, sessionSecurityHandlers } from "./tools/session-security";
import { authTools, authHandlers } from "./tools/auth";
import { fileDeserSecurityTools, fileDeserSecurityHandlers } from "./tools/file-deser-security";
import { assessmentContextTools, assessmentContextHandlers } from "./tools/assessment-context";
import { cloudReconTools, cloudReconHandlers } from "./tools/cloud-recon";
import { cloudIamTools, cloudIamHandlers } from "./tools/cloud-iam";
import { cloudStorageTools, cloudStorageHandlers } from "./tools/cloud-storage";
import { kubernetesSecurityTools, kubernetesSecurityHandlers } from "./tools/kubernetes-security";
import { cloudInventoryTools, cloudInventoryHandlers } from "./tools/cloud-inventory";
import { identityEntraTools, identityEntraHandlers } from "./tools/identity-entra";
import { identityM365Tools, identityM365Handlers } from "./tools/identity-m365";
import { identityAdTools, identityAdHandlers } from "./tools/identity-ad";
import { identityOktaTools, identityOktaHandlers } from "./tools/identity-okta";
import { identityGoogleTools, identityGoogleHandlers } from "./tools/identity-google";
import { identityPingTools, identityPingHandlers } from "./tools/identity-ping";
import { validateToolScope } from "./scope/tool-scope";
import { logCommand } from "./logging/audit-logger";
import { runWithToolContext } from "./logging/tool-provenance";
import { emitProgress } from "./progress";
import { captureScopeDecision } from "./logging/test-results-store";
import { pulseAssessmentHeartbeat } from "./integrations/assessment-heartbeat";
import { runWithHandlerContext } from "./scope/handler-context";
import { provenanceTools, provenanceHandlers } from "./tools/provenance";
import { dastCorrelationTools, dastCorrelationHandlers } from "./tools/dast-correlation";
import { aiLlmTools, aiLlmHandlers } from "./tools/ai-llm";
import { graphTools, graphHandlers } from "./tools/graph";
import { footholdTools, footholdHandlers } from "./tools/footholds";
import { verificationTools, verificationHandlers } from "./tools/verification";
import { applyResponseSizeGuard } from "./utils/response-guard";

export const allTools = [
  ...reconTools,
  ...vulnScanTools,
  ...webAppTools,
  ...exploitTools,
  ...reportingTools,
  ...codeScanTools,
  ...agentTools,
  ...interactiveTools,
  ...browserTools,
  ...codeIntelTools,
  ...guidanceTools,
  ...sslTlsTools,
  ...dnsSecurityTools,
  ...tokenSecurityTools,
  ...advancedWebTools,
  ...apiSecurityTools,
  ...cloudSecurityTools,
  ...cloudComputeTools,
  ...sessionSecurityTools,
  ...authTools,
  ...fileDeserSecurityTools,
  ...assessmentContextTools,
  ...cloudReconTools,
  ...cloudIamTools,
  ...cloudStorageTools,
  ...kubernetesSecurityTools,
  ...cloudInventoryTools,
  ...identityEntraTools,
  ...identityM365Tools,
  ...identityAdTools,
  ...identityOktaTools,
  ...identityGoogleTools,
  ...identityPingTools,
  ...provenanceTools,
  ...dastCorrelationTools,
  ...aiLlmTools,
  ...graphTools,
  ...footholdTools,
  ...verificationTools,
];

export const allHandlers: Record<string, Function> = {
  ...reconHandlers,
  ...vulnScanHandlers,
  ...webAppHandlers,
  ...exploitHandlers,
  ...reportingHandlers,
  ...codeScanHandlers,
  ...agentHandlers,
  ...interactiveHandlers,
  ...browserHandlers,
  ...codeIntelHandlers,
  ...guidanceHandlers,
  ...sslTlsHandlers,
  ...dnsSecurityHandlers,
  ...tokenSecurityHandlers,
  ...advancedWebHandlers,
  ...apiSecurityHandlers,
  ...cloudSecurityHandlers,
  ...cloudComputeHandlers,
  ...sessionSecurityHandlers,
  ...authHandlers,
  ...fileDeserSecurityHandlers,
  ...assessmentContextHandlers,
  ...cloudReconHandlers,
  ...cloudIamHandlers,
  ...cloudStorageHandlers,
  ...kubernetesSecurityHandlers,
  ...cloudInventoryHandlers,
  ...identityEntraHandlers,
  ...identityM365Handlers,
  ...identityAdHandlers,
  ...identityOktaHandlers,
  ...identityGoogleHandlers,
  ...identityPingHandlers,
  ...provenanceHandlers,
  ...dastCorrelationHandlers,
  ...aiLlmHandlers,
  ...graphHandlers,
  ...footholdHandlers,
  ...verificationHandlers,
};

// Tools that don't require network scope validation (local file operations)
export const LOCAL_ONLY_TOOLS = [
  "scan_repository",
  "scan_semgrep",
  "scan_bandit",
  "scan_njsscan",
  "scan_secrets",
  "scan_dependencies",
  "scan_iac",
  "analyze_code_context",
  "detect_languages",
  "generate_scan_report",
  // Code intelligence tools - local file analysis only
  "map_entry_points",
  "trace_data_flows",
  "analyze_defenses",
  "generate_attack_surface",
  "create_finding",
  "generate_report",
  "generate_pdf_report",
  "import_cycode_findings",
  // Agent tools - these handle their own scope validation internally
  "run_orchestrator",
  "run_recon_agent",
  "run_vuln_scan_agent",
  "run_web_app_agent",
  "run_exploit_agent",
  "run_security_scan_agent",
  "run_code_intel_agent",
  "run_qa_agent",
  "run_report_agent",
  "resume_assessment",
  "pause_assessment",
  "get_agent_status",
  "cancel_agent",
  "list_running_agents",
  // Browser tools - scope validated at agent level, not per-tool
  "browser_navigate",
  "browser_click",
  "browser_fill",
  "browser_screenshot",
  "browser_evaluate",
  "browser_get_cookies",
  "browser_set_cookies",
  "browser_get_content",
  "browser_wait_for",
  "browser_network_log",
  "browser_close",
  // Browser state persistence tools
  "browser_save_state",
  "browser_restore_state",
  // Interactive tools - user prompts, no network access
  "prompt_for_otp",
  "prompt_for_input",
  "check_pending_prompt",
  "respond_to_prompt",
  // Auth context - local config read, no network
  "get_auth_role",
  // Guidance tool - user interaction, no network access
  "request_user_guidance",
  // Auth agent tool
  "run_auth_agent",
  // New agent tools
  "run_api_security_agent",
  "run_infra_security_agent",
  "run_compliance_agent",
  // Cloud agent tools - handle their own scope validation
  "run_cloud_recon_agent",
  "run_cloud_exploit_agent",
  // Container image scanning - operates on image references, not network targets
  "scan_container_image",
  // Assessment context tools - local file operations
  "save_assessment_context",
  "load_assessment_context",
  // Assessment comparison - database query
  "compare_assessments",
  // Database cleanup - clear findings between assessments
  "clear_findings",
  // Provenance gate - operates on local provenance DB + container binary probe
  "check_tool_provenance",
  // Provenance promotion - cloud push of the local summary, no network target
  "promote_tool_provenance",
  // Execution-overview promotion - cloud push of per-test results + scope decisions, no network target
  "promote_execution_meta",
  // DAST correlation - cloud-side join over already-promoted data, no scan target
  "correlate_dast_findings",
  // Attack-graph substrate - org-scoped graph queries/ingest over the JWT
  // session, no network/cloud scan target.
  "query_attack_paths",
  "find_attack_paths",
  "register_graph_kinds",
  "ingest_graph",
  // Foothold store - org-scoped post-exploitation state over the JWT session,
  // no network/cloud scan target.
  "establish_foothold",
  "list_footholds",
  "consume_foothold",
  "revoke_footholds",
  // Operates through a held foothold; assumed-breach means its target is screened
  // against never_touch in-handler (checkExclusions), not network-gated here.
  "execute_through_foothold",
  // Verdict rollup over the local findings store — no target, no traffic.
  // verify_finding and replay_capsule are deliberately NOT here: they send real
  // attack traffic and are scope-validated on `target`, then re-screen every host
  // named inside their oracle commands (see tools/verification.ts).
  "list_verdicts",
];

export async function setupTools(server: Server) {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: allTools,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    
    // Extract target for audit logging; scope validation is delegated to the
    // shared validateToolScope (network + identity + cloud + k8s) so this STDIO
    // path and the HTTP /tools/call path can never drift apart again.
    const argObj = args as Record<string, unknown> | undefined;
    const target = (argObj?.target || argObj?.domain || argObj?.cidr) as string | undefined;

    const scopeCheck = await validateToolScope(name, argObj, (n) => LOCAL_ONLY_TOOLS.includes(n));
    // Capture the scope decision (Option B) for the end-of-run execution overview.
    // Best-effort and target-derived; never affects the validation outcome.
    captureScopeDecision(argObj, scopeCheck);
    if (!scopeCheck.valid) {
      return {
        content: [{ type: "text", text: scopeCheck.error! }],
        isError: true,
      };
    }

    // Log the command
    await logCommand({
      tool: name,
      arguments: args,
      target: target || (argObj?.repo_path as string) || (argObj?.file_path as string),
      timestamp: new Date().toISOString(),
    });

    const handler = allHandlers[name];
    if (!handler) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }

    // Live progress for the desktop Assessment View: emit a "started" event now
    // and a terminal "ok"/"error" when the handler settles. test_id (when the
    // agent passes it) attributes this call to its agent + phase. Fire-and-forget.
    const progressTarget = target || (argObj?.repo_path as string) || (argObj?.file_path as string);
    const progressTestId = argObj?.test_id as string | undefined;
    emitProgress({ tool: name, status: "started", target: progressTarget, testId: progressTestId });
    const progressStartedAt = Date.now();

    try {
      // Keep the cloud assessment row alive while work is happening so the 3h
      // stale-run reaper never false-fails a long but active run (throttled).
      pulseAssessmentHeartbeat();
      // Tag every shell call this handler makes with the MCP tool / test it ran
      // under, so executeInKali can record attributable provenance (P1).
      const result = await runWithToolContext(
        { tool_name: name, test_id: argObj?.test_id as string | undefined },
        () =>
          // Expose the validated in-scope identity_target / ai_target (when
          // present) to the handler so identity + AI tools can resolve named
          // credential refs and per-target fields (endpoint, model,
          // declared_tools) without the LLM passing them. The dimension tells us
          // which context slot to fill. Nested inside the provenance context so
          // both apply.
          runWithHandlerContext(
            scopeCheck.dimension === "ai"
              ? { ai_target: scopeCheck.matched_target }
              : { identity_target: scopeCheck.matched_target },
            () => handler(args)
          )
      );
      // Offload oversized tool output to disk to keep it out of the agent's
      // re-read-every-turn context (prompt-cache cost reduction). No-op for
      // small/denylisted tools; disable with MAESTRO_TOOL_OFFLOAD=0.
      const guarded = applyResponseSizeGuard(result, name);
      emitProgress({ tool: name, status: "ok", target: progressTarget, testId: progressTestId, durationMs: Date.now() - progressStartedAt });
      return { content: [{ type: "text", text: guarded }] };
    } catch (error) {
      emitProgress({ tool: name, status: "error", target: progressTarget, testId: progressTestId, durationMs: Date.now() - progressStartedAt });
      return {
        content: [{ type: "text", text: `Error: ${error}` }],
        isError: true,
      };
    }
  });
}
