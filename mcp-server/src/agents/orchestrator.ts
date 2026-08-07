/**
 * Orchestrator
 *
 * Master controller that sequences agents and manages context passing
 * between them. Supports full assessments, selective agent runs,
 * single-agent execution, checkpointing, resume, and pipelined parallel execution.
 */

import { BaseAgent, AgentInput, AgentOutput, AgentState, AgentFinding, Severity } from "./base-agent";
import { cloudRequest, hasCloudSession } from "../integrations/cloud-session";
import { buildProvePrompt } from "../lib/prove-prompt";
import { ReconAgentImpl } from "./impl/recon-agent-impl";
import { VulnScanAgentImpl } from "./impl/vuln-scan-agent-impl";
import { WebAppAgentImpl } from "./impl/web-app-agent-impl";
import { ExploitAgentImpl } from "./impl/exploit-agent-impl";
import { SecurityScanAgentImpl } from "./impl/security-scan-agent-impl";
import { QaAgentImpl } from "./impl/qa-agent-impl";
import { ReportAgentImpl } from "./impl/report-agent-impl";
import { AuthAgentImpl } from "./impl/auth-agent-impl";
import { ApiSecurityAgentImpl } from "./impl/api-security-agent-impl";
import { InfraSecurityAgentImpl } from "./impl/infra-security-agent-impl";
import { ComplianceAgentImpl } from "./impl/compliance-agent-impl";
import { ChainAnalysisAgentImpl } from "./impl/chain-analysis-agent-impl";
import { CheckpointManager } from "./checkpoint-manager";
import { enrichFindingsWithCodeContext } from "./code-context-enricher";
import { AssessmentConfig, loadAssessmentConfig, createAssessmentConfig } from "../config/assessment-config";
import { setGuidanceMode } from "../tools/guidance";
import { browserHandlers } from "../tools/browser";
import { SequentialPipeline, PipelineConfig, PipelineOutput } from "./sequential-pipeline";

// Agent names
export type AgentName =
  | "code-intel"
  | "recon"
  | "auth"
  | "vuln-scan"
  | "web-app"
  | "exploit"
  | "security-scan"
  | "qa"
  | "report"
  | "api-security"
  | "infra-security"
  | "compliance"
  | "chain-analysis";

// Full assessment workflow order (QA validates before report)
// Auth phase is conditionally inserted based on assessmentConfig
const FULL_WORKFLOW: AgentName[] = ["recon", "vuln-scan", "web-app", "exploit", "qa", "report"];

// Full workflow with auth phase (used when browser_login is configured)
const FULL_WORKFLOW_WITH_AUTH: AgentName[] = ["recon", "auth", "vuln-scan", "web-app", "exploit", "qa", "report"];

// Full workflow with code intelligence pre-recon
const FULL_WITH_CODE_INTEL: AgentName[] = [
  "code-intel",
  "recon",
  "vuln-scan",
  "web-app",
  "exploit",
  "qa",
  "report",
];

// Full workflow with code-intel + auth
const FULL_WITH_CODE_INTEL_AND_AUTH: AgentName[] = [
  "code-intel",
  "recon",
  "auth",
  "vuln-scan",
  "web-app",
  "exploit",
  "qa",
  "report",
];

// Code-focused workflow (QA validates before report)
const CODE_WORKFLOW: AgentName[] = ["security-scan", "qa", "report"];

// Full V2 workflow with infrastructure and API security agents
const FULL_V2_WORKFLOW: AgentName[] = [
  "recon",
  "infra-security",
  "vuln-scan",
  "web-app",
  "api-security",
  "chain-analysis",  // Touch 1: hypothesize
  "exploit",
  "chain-analysis",  // Touch 2: validate
  "qa",
  "compliance",
  "report",
];

// Extreme workflow: all agents, code-intel + recon in parallel at start
const EXTREME_WORKFLOW: AgentName[] = [
  "code-intel",
  "recon",
  "infra-security",
  "vuln-scan",
  "web-app",
  "api-security",
  "chain-analysis",  // Touch 1: hypothesize
  "exploit",
  "chain-analysis",  // Touch 2: validate
  "security-scan",
  "qa",
  "compliance",
  "report",
];

// Pipeline stage definition for parallel execution
export interface PipelineStage {
  name: string;
  agents: AgentName[];
  waitForAll: boolean;
}

// Cross-validation target: maps a SAST finding to a live endpoint for DAST testing
export interface CrossValidationTarget {
  sastFindingId: string;
  sastTitle: string;
  vulnType: string;     // sqli, xss, ssrf, rce, path_traversal, etc.
  filePath: string;
  line?: number;
  endpoint: string;     // Mapped API route
  method: string;
  liveUrl: string;
  parameters: string[];
}

// Pipelined workflow - vuln-scan and web-app run in parallel
const PIPELINED_STAGES: PipelineStage[] = [
  { name: "recon", agents: ["recon"], waitForAll: true },
  { name: "scan-and-test", agents: ["vuln-scan", "web-app"], waitForAll: true },
  { name: "exploit", agents: ["exploit"], waitForAll: true },
  { name: "qa", agents: ["qa"], waitForAll: true },
  { name: "report", agents: ["report"], waitForAll: true },
];

// Pipelined with auth phase before scanning
const PIPELINED_STAGES_WITH_AUTH: PipelineStage[] = [
  { name: "recon", agents: ["recon"], waitForAll: true },
  { name: "auth", agents: ["auth"], waitForAll: true },
  { name: "scan-and-test", agents: ["vuln-scan", "web-app"], waitForAll: true },
  { name: "exploit", agents: ["exploit"], waitForAll: true },
  { name: "qa", agents: ["qa"], waitForAll: true },
  { name: "report", agents: ["report"], waitForAll: true },
];

const PIPELINED_WITH_CODE_INTEL: PipelineStage[] = [
  { name: "code-intel", agents: ["code-intel"], waitForAll: true },
  ...PIPELINED_STAGES,
];

const PIPELINED_WITH_CODE_INTEL_AND_AUTH: PipelineStage[] = [
  { name: "code-intel", agents: ["code-intel"], waitForAll: true },
  ...PIPELINED_STAGES_WITH_AUTH,
];

// Extreme pipelined stages — maximizes parallelism with all agents
const EXTREME_PIPELINED_STAGES: PipelineStage[] = [
  { name: "intel-and-recon", agents: ["code-intel", "recon"], waitForAll: true },
  { name: "infra-and-vuln", agents: ["infra-security", "vuln-scan"], waitForAll: true },
  { name: "web-and-api", agents: ["web-app", "api-security"], waitForAll: true },
  { name: "chain-hypothesize", agents: ["chain-analysis"], waitForAll: true },
  { name: "exploit", agents: ["exploit"], waitForAll: true },
  { name: "chain-validate", agents: ["chain-analysis"], waitForAll: true },
  { name: "security-scan", agents: ["security-scan"], waitForAll: true },
  { name: "qa", agents: ["qa"], waitForAll: true },
  { name: "compliance", agents: ["compliance"], waitForAll: true },
  { name: "report", agents: ["report"], waitForAll: true },
];

// Extreme pipelined stages with auth
const EXTREME_PIPELINED_STAGES_WITH_AUTH: PipelineStage[] = [
  { name: "intel-and-recon", agents: ["code-intel", "recon"], waitForAll: true },
  { name: "auth", agents: ["auth"], waitForAll: true },
  { name: "infra-and-vuln", agents: ["infra-security", "vuln-scan"], waitForAll: true },
  { name: "web-and-api", agents: ["web-app", "api-security"], waitForAll: true },
  { name: "chain-hypothesize", agents: ["chain-analysis"], waitForAll: true },
  { name: "exploit", agents: ["exploit"], waitForAll: true },
  { name: "chain-validate", agents: ["chain-analysis"], waitForAll: true },
  { name: "security-scan", agents: ["security-scan"], waitForAll: true },
  { name: "qa", agents: ["qa"], waitForAll: true },
  { name: "compliance", agents: ["compliance"], waitForAll: true },
  { name: "report", agents: ["report"], waitForAll: true },
];

// Dual-track pipeline stages
const DUAL_TRACK_A: PipelineStage[] = [
  { name: "recon", agents: ["recon"], waitForAll: true },
  { name: "scan-and-test", agents: ["vuln-scan", "web-app"], waitForAll: true },
  { name: "exploit", agents: ["exploit"], waitForAll: true },
  { name: "dast-qa", agents: ["qa"], waitForAll: true },
];

const DUAL_TRACK_A_WITH_AUTH: PipelineStage[] = [
  { name: "recon", agents: ["recon"], waitForAll: true },
  { name: "auth", agents: ["auth"], waitForAll: true },
  { name: "scan-and-test", agents: ["vuln-scan", "web-app"], waitForAll: true },
  { name: "exploit", agents: ["exploit"], waitForAll: true },
  { name: "dast-qa", agents: ["qa"], waitForAll: true },
];

const DUAL_TRACK_B: PipelineStage[] = [
  { name: "code-intel", agents: ["code-intel"], waitForAll: true },
  { name: "security-scan", agents: ["security-scan"], waitForAll: true },
  { name: "sast-qa", agents: ["qa"], waitForAll: true },
];

// Orchestrator configuration
export interface OrchestratorConfig {
  assessmentId?: string;
  targets?: string[];
  repoPaths?: string[];
  severity?: Severity;
  jiraProject?: string;
  emailRecipients?: string[];
  options?: Record<string, any>;
  assessmentConfig?: AssessmentConfig | Record<string, any>;
}

// Orchestrator result
export interface OrchestratorResult {
  success: boolean;
  agentResults: Partial<Record<AgentName, AgentOutput>>;
  allFindings: AgentFinding[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  executionTimeMs: number;
  agentsRun: AgentName[];
  errors: string[];
}

// Progress callback type
export type OrchestratorProgressCallback = (agentName: AgentName, state: AgentState) => void;

/**
 * Orchestrator class
 */
export class Orchestrator {
  private agentFactories: Record<string, (onProgress?: (state: AgentState) => void) => BaseAgent>;
  private currentAgent?: BaseAgent;
  private onProgress?: OrchestratorProgressCallback;
  private cancelled = false;
  private checkpointManager: CheckpointManager;
  private persistBrowserSession = false;
  private originalBrowserClose: Function | null = null;

  constructor(onProgress?: OrchestratorProgressCallback) {
    this.onProgress = onProgress;
    this.checkpointManager = new CheckpointManager();

    // Agent factory functions
    this.agentFactories = {
      recon: (cb) => new ReconAgentImpl(cb),
      auth: (cb) => new AuthAgentImpl(cb),
      "vuln-scan": (cb) => new VulnScanAgentImpl(cb),
      "web-app": (cb) => new WebAppAgentImpl(cb),
      exploit: (cb) => new ExploitAgentImpl(cb),
      "security-scan": (cb) => new SecurityScanAgentImpl(cb),
      qa: (cb) => new QaAgentImpl(cb),
      report: (cb) => new ReportAgentImpl(cb),
      "api-security": (cb) => new ApiSecurityAgentImpl(cb),
      "infra-security": (cb) => new InfraSecurityAgentImpl(cb),
      compliance: (cb) => new ComplianceAgentImpl(cb),
      "chain-analysis": (cb) => new ChainAnalysisAgentImpl(cb),
      // code-intel will be added via dynamic import when available
    };

    // Try to load code-intel agent (may not exist yet)
    this.loadCodeIntelAgent();
  }

  private async loadCodeIntelAgent() {
    try {
      const { CodeIntelAgentImpl } = await import("./impl/code-intel-agent-impl");
      this.agentFactories["code-intel"] = (cb) => new CodeIntelAgentImpl(cb);
    } catch {
      // Code intel agent not yet implemented
    }
  }

  /**
   * Run a full security assessment workflow
   * Uses code-intel pre-recon if repoPaths are provided
   * Includes auth phase if assessmentConfig.auth.browser_login is defined
   */
  async runFull(config: OrchestratorConfig): Promise<OrchestratorResult> {
    // Set up assessment config and browser lifecycle
    this.setupAssessment(config);

    const hasCodeIntel = config.repoPaths?.length && this.agentFactories["code-intel"];
    const hasAuth = this.hasAuthConfig(config);

    let workflow: AgentName[];
    if (hasCodeIntel && hasAuth) {
      workflow = FULL_WITH_CODE_INTEL_AND_AUTH;
    } else if (hasCodeIntel) {
      workflow = FULL_WITH_CODE_INTEL;
    } else if (hasAuth) {
      workflow = FULL_WORKFLOW_WITH_AUTH;
    } else {
      workflow = FULL_WORKFLOW;
    }

    // Apply phase overrides from assessment config
    workflow = this.applyPhaseOverrides(workflow, config);

    console.log(`[orchestrator] Starting full assessment (${workflow.join(" → ")})`);

    try {
      return await this.runSequential(config, workflow);
    } finally {
      // Clean up browser session after all agents complete
      await this.cleanupBrowserSession();
    }
  }

  /**
   * Run an extreme security assessment — all agents with maximum parallelism.
   * Combines code-intel + recon in parallel, infra + vuln in parallel, web + api in parallel.
   * Includes security-scan, compliance, and all validation steps.
   */
  async runExtreme(config: OrchestratorConfig): Promise<OrchestratorResult> {
    this.setupAssessment(config);
    this.enableBrowserSessionPersistence();

    const hasAuth = this.hasAuthConfig(config);
    const stages = hasAuth ? EXTREME_PIPELINED_STAGES_WITH_AUTH : EXTREME_PIPELINED_STAGES;

    console.log("[orchestrator] Starting EXTREME assessment (all agents, max parallelism)");
    console.log(`[orchestrator] Stages: ${stages.map((s) => s.name).join(" → ")}`);

    try {
      return await this.runPipelinedStages(config, stages);
    } finally {
      await this.cleanupBrowserSession();
    }
  }

  /**
   * Run a code-focused assessment
   */
  async runCodeScan(config: OrchestratorConfig): Promise<OrchestratorResult> {
    console.log("[orchestrator] Starting code scan assessment");
    return this.runSequential(config, CODE_WORKFLOW);
  }

  /**
   * Run only selected agents in order
   */
  async runSelective(
    config: OrchestratorConfig & { agents: AgentName[] }
  ): Promise<OrchestratorResult> {
    if (!config.agents || config.agents.length === 0) {
      return this.createErrorResult("No agents specified for selective mode");
    }

    // Set up assessment config and browser lifecycle
    this.setupAssessment(config);

    console.log(
      `[orchestrator] Starting selective assessment with agents: ${config.agents.join(", ")}`
    );

    try {
      return await this.runSequential(config, config.agents);
    } finally {
      await this.cleanupBrowserSession();
    }
  }

  /**
   * Run a pipelined assessment with parallel agent execution where possible
   */
  async runPipelined(config: OrchestratorConfig): Promise<OrchestratorResult> {
    // Set up assessment config and browser lifecycle
    this.setupAssessment(config);

    const hasCodeIntel = config.repoPaths?.length && this.agentFactories["code-intel"];
    const hasAuth = this.hasAuthConfig(config);

    let stages: PipelineStage[];
    if (hasCodeIntel && hasAuth) {
      stages = PIPELINED_WITH_CODE_INTEL_AND_AUTH;
    } else if (hasCodeIntel) {
      stages = PIPELINED_WITH_CODE_INTEL;
    } else if (hasAuth) {
      stages = PIPELINED_STAGES_WITH_AUTH;
    } else {
      stages = PIPELINED_STAGES;
    }

    console.log("[orchestrator] Starting pipelined assessment");

    try {
      return await this.runPipelinedStages(config, stages);
    } finally {
      await this.cleanupBrowserSession();
    }
  }

  /**
   * Run a single agent
   */
  async runSingle(agentName: AgentName, input: AgentInput): Promise<AgentOutput> {
    console.log(`[orchestrator] Running single agent: ${agentName}`);

    const factory = this.agentFactories[agentName];
    if (!factory) {
      return {
        success: false,
        agentName,
        findings: [],
        summary: `Unknown agent: ${agentName}`,
        errors: [`Unknown agent: ${agentName}`],
        context: {},
        executionTimeMs: 0,
        toolCallsCount: 0,
        iterations: 0,
      };
    }

    const agent = factory((state) => {
      if (this.onProgress) {
        this.onProgress(agentName, state);
      }
    });

    this.currentAgent = agent;

    try {
      return await agent.execute(input);
    } finally {
      this.currentAgent = undefined;
    }
  }

  /**
   * Run a dual-track assessment: DAST (Track A) and SAST (Track B) in parallel,
   * followed by cross-validation and a unified report.
   */
  async runDualTrack(config: OrchestratorConfig): Promise<OrchestratorResult> {
    const startTime = Date.now();

    // Set up assessment config and browser lifecycle
    this.setupAssessment(config);

    // Enable browser session persistence for Track A
    this.enableBrowserSessionPersistence();

    const hasAuth = this.hasAuthConfig(config);
    const trackAStages = hasAuth ? DUAL_TRACK_A_WITH_AUTH : DUAL_TRACK_A;
    const trackBStages = DUAL_TRACK_B;

    // Build separate configs: Track A gets targets only, Track B gets repoPaths only
    const trackAConfig: OrchestratorConfig = {
      ...config,
      repoPaths: undefined,
      assessmentId: config.assessmentId ? `${config.assessmentId}-track-a` : undefined,
      options: { ...config.options, _qaMode: "dast" },
    };

    const trackBConfig: OrchestratorConfig = {
      ...config,
      targets: undefined,
      assessmentId: config.assessmentId ? `${config.assessmentId}-track-b` : undefined,
      options: { ...config.options, _qaMode: "sast" },
    };

    console.log("[orchestrator] Starting dual-track assessment");
    console.log(`[orchestrator] Track A (DAST): ${trackAStages.map((s) => s.name).join(" → ")}`);
    console.log(`[orchestrator] Track B (SAST): ${trackBStages.map((s) => s.name).join(" → ")}`);

    // Run both tracks in parallel with 5s stagger
    const [trackASettled, trackBSettled] = await Promise.allSettled([
      this.runPipelinedStages(trackAConfig, trackAStages),
      new Promise<OrchestratorResult>((resolve) =>
        setTimeout(() => this.runPipelinedStages(trackBConfig, trackBStages).then(resolve), 5000)
      ),
    ]);

    // Merge results from both tracks
    const allFindings: AgentFinding[] = [];
    const agentResults: Partial<Record<AgentName, AgentOutput>> = {};
    const agentsRun: AgentName[] = [];
    const errors: string[] = [];

    if (trackASettled.status === "fulfilled") {
      const trackA = trackASettled.value;
      tagFindingsByTrack(trackA.allFindings, "dast");
      allFindings.push(...trackA.allFindings);
      Object.assign(agentResults, trackA.agentResults);
      agentsRun.push(...trackA.agentsRun);
      errors.push(...trackA.errors);
      console.log(`[orchestrator] Track A (DAST) completed: ${trackA.allFindings.length} findings`);
    } else {
      errors.push(`Track A (DAST) failed: ${trackASettled.reason}`);
      console.error("[orchestrator] Track A (DAST) failed:", trackASettled.reason);
    }

    if (trackBSettled.status === "fulfilled") {
      const trackB = trackBSettled.value;
      tagFindingsByTrack(trackB.allFindings, "sast");
      allFindings.push(...trackB.allFindings);
      Object.assign(agentResults, trackB.agentResults);
      agentsRun.push(...trackB.agentsRun);
      errors.push(...trackB.errors);
      console.log(`[orchestrator] Track B (SAST) completed: ${trackB.allFindings.length} findings`);
    } else {
      errors.push(`Track B (SAST) failed: ${trackBSettled.reason}`);
      console.error("[orchestrator] Track B (SAST) failed:", trackBSettled.reason);
    }

    // === Convergence: Cross-validation ===
    const sastFindings = allFindings.filter((f) => f.metadata?.track === "sast");
    const dastContext = trackASettled.status === "fulfilled" ? trackASettled.value.agentResults : {};

    // Build cross-validation targets from SAST findings + code-intel entry points
    const entryPoints = (dastContext as any)?.["code-intel"]?.context?.entryPoints ||
      (trackBSettled.status === "fulfilled" ? trackBSettled.value.agentResults?.["code-intel"]?.context?.entryPoints : undefined) ||
      [];
    const crossValTargets = buildCrossValidationTargets(sastFindings, entryPoints, config);

    if (crossValTargets.length > 0 && config.targets?.length) {
      console.log(`[orchestrator] Cross-validating ${crossValTargets.length} SAST findings against live endpoints`);

      try {
        const crossValOutput = await this.runSingle("web-app", {
          targets: config.targets,
          context: {
            crossValidationMode: true,
            crossValidationTargets: crossValTargets,
          },
        });

        // Tag cross-validated findings
        for (const finding of crossValOutput.findings) {
          finding.metadata = finding.metadata || {};
          finding.metadata.track = "cross-validated";
        }
        allFindings.push(...crossValOutput.findings);
        agentsRun.push("web-app");
        if (!crossValOutput.success) {
          errors.push(`Cross-validation: ${crossValOutput.errors.join(", ")}`);
        }
        console.log(`[orchestrator] Cross-validation produced ${crossValOutput.findings.length} findings`);
      } catch (error) {
        errors.push(`Cross-validation error: ${String(error)}`);
        console.error("[orchestrator] Cross-validation failed:", error);
      }
    } else {
      console.log("[orchestrator] No cross-validation targets found, skipping");
    }

    // Code context enrichment on all findings
    const findingsWithCode = allFindings.filter(
      (f) => f.metadata?.file || f.metadata?.file_path ||
        (f.target?.startsWith("/") && /\.\w+$/.test(f.target))
    );
    if (findingsWithCode.length > 0) {
      console.log("[orchestrator] Enriching findings with source code context");
      try {
        const enrichResult = await enrichFindingsWithCodeContext(
          allFindings,
          (msg) => console.log(`[orchestrator] ${msg}`)
        );
        console.log(`[orchestrator] Code context: ${enrichResult.codeContextCount} enriched, ${enrichResult.remediationCount} with fixes`);
      } catch (error) {
        errors.push(`Code context enrichment failed: ${String(error)}`);
      }
    }

    // Deduplicate findings
    const deduped = this.deduplicateFindings(allFindings);
    allFindings.length = 0;
    allFindings.push(...deduped);

    // Run report agent in dual-track mode
    console.log("[orchestrator] Generating dual-track report");
    try {
      const reportOutput = await this.runSingle("report", {
        targets: config.targets,
        repoPaths: config.repoPaths,
        options: {
          ...config.options,
          jiraProject: config.jiraProject,
          emailRecipients: config.emailRecipients,
        },
        context: {
          findings: allFindings,
          dualTrackMode: true,
          dastFindings: allFindings.filter((f) => f.metadata?.track === "dast"),
          sastFindings: allFindings.filter((f) => f.metadata?.track === "sast"),
          crossValidatedFindings: allFindings.filter((f) => f.metadata?.track === "cross-validated"),
          agentResults,
        },
      });

      agentResults.report = reportOutput;
      agentsRun.push("report");
      allFindings.push(...reportOutput.findings);
      if (!reportOutput.success) {
        errors.push(`Report: ${reportOutput.errors.join(", ")}`);
      }
    } catch (error) {
      errors.push(`Report generation error: ${String(error)}`);
    }

    // Cleanup
    await this.cleanupBrowserSession();

    const counts = this.countBySeverity(allFindings);

    return {
      success: errors.length === 0,
      agentResults,
      allFindings,
      totalFindings: allFindings.length,
      ...counts,
      executionTimeMs: Date.now() - startTime,
      agentsRun,
      errors,
    };
  }

  /**
   * Resume a previously checkpointed assessment
   */
  async resume(assessmentId: string): Promise<OrchestratorResult> {
    const checkpoint = this.checkpointManager.getLatestCheckpoint(assessmentId);
    if (!checkpoint) {
      return this.createErrorResult(`No checkpoint found for assessment ${assessmentId}`);
    }

    const config = checkpoint.orchestratorConfig;
    console.log(
      `[orchestrator] Resuming assessment ${assessmentId} from checkpoint after ${checkpoint.agentName} (${checkpoint.status})`
    );

    // Determine the original workflow
    const workflow = this.determineWorkflow(config);
    const completedSet = new Set(checkpoint.completedAgents);

    // Determine which agents to run
    let remainingAgents: AgentName[];
    if (checkpoint.status === "failed_during") {
      // Re-run the failed agent + everything after it
      remainingAgents = workflow.filter(
        (a) => a === (checkpoint.agentName as AgentName) || !completedSet.has(a)
      );
    } else {
      // Start from the next agent after the last completed
      remainingAgents = workflow.filter((a) => !completedSet.has(a));
    }

    if (remainingAgents.length === 0) {
      return this.createErrorResult("All agents already completed. Nothing to resume.");
    }

    console.log(`[orchestrator] Resuming with agents: ${remainingAgents.join(", ")}`);

    // Run remaining agents with restored state
    return this.runSequentialFromCheckpoint(
      config,
      remainingAgents,
      checkpoint.sharedContext,
      checkpoint.allFindings
    );
  }

  /**
   * Cancel/pause the current orchestration
   */
  cancel(): void {
    console.log("[orchestrator] Cancelling execution");
    this.cancelled = true;
    this.currentAgent?.cancel();
  }

  /**
   * Alias for cancel - pauses and saves checkpoint
   */
  pause(): void {
    this.cancel();
  }

  // ==================== Private Methods ====================

  /**
   * Run agents sequentially, passing context between them
   */
  private async runSequential(
    config: OrchestratorConfig,
    agentOrder: AgentName[]
  ): Promise<OrchestratorResult> {
    return this.runSequentialFromCheckpoint(config, agentOrder, {}, []);
  }

  /**
   * Run agents sequentially with optional restored state from checkpoint
   */
  private async runSequentialFromCheckpoint(
    config: OrchestratorConfig,
    agentOrder: AgentName[],
    initialContext: Record<string, any>,
    initialFindings: AgentFinding[]
  ): Promise<OrchestratorResult> {
    const startTime = Date.now();
    const results: Partial<Record<AgentName, AgentOutput>> = {};
    const allFindings: AgentFinding[] = [...initialFindings];
    const errors: string[] = [];
    const agentsRun: AgentName[] = [];
    let sharedContext: Record<string, any> = { ...initialContext };

    this.cancelled = false;

    for (const agentName of agentOrder) {
      // Check if cancelled
      if (this.cancelled) {
        console.log(`[orchestrator] Cancelled before ${agentName}`);
        errors.push(`Cancelled before ${agentName}`);

        // Save checkpoint on cancellation
        if (config.assessmentId) {
          this.checkpointManager.saveCheckpoint({
            assessmentId: config.assessmentId,
            agentName: agentsRun[agentsRun.length - 1] || agentName,
            phaseIndex: agentOrder.indexOf(agentName) - 1,
            sharedContext,
            allFindings,
            completedAgents: [...agentsRun],
            orchestratorConfig: config,
            status: "completed",
          });
        }
        break;
      }

      console.log(`[orchestrator] Starting ${agentName}`);

      const factory = this.agentFactories[agentName];
      if (!factory) {
        console.error(`[orchestrator] Unknown agent: ${agentName}`);
        errors.push(`Unknown agent: ${agentName}`);
        continue;
      }

      // Create agent with progress callback
      const agent = factory((state) => {
        if (this.onProgress) {
          this.onProgress(agentName, state);
        }
      });

      this.currentAgent = agent;

      // Build input for this agent
      const input = this.buildAgentInput(agentName, config, sharedContext, allFindings, results);

      try {
        const output = await agent.execute(input);
        results[agentName] = output;
        agentsRun.push(agentName);

        // Merge findings
        allFindings.push(...output.findings);

        // Merge context for next agent
        sharedContext = {
          ...sharedContext,
          ...output.context,
          vulnerabilities: allFindings,
        };

        console.log(
          `[orchestrator] ${agentName} completed: ${output.findings.length} findings, ${output.toolCallsCount} tool calls`
        );

        // Apply QA validation results
        if (agentName === "qa" && output.context) {
          this.applyQaResults(output, allFindings, sharedContext);
        }

        // If agent failed critically, log but continue
        if (!output.success) {
          console.warn(`[orchestrator] ${agentName} failed: ${output.errors.join(", ")}`);
          errors.push(`${agentName} failed: ${output.errors.join(", ")}`);
        }

        // Run code context enrichment before report agent
        const nextIdx = agentOrder.indexOf(agentName) + 1;
        if (
          nextIdx < agentOrder.length &&
          agentOrder[nextIdx] === "report" &&
          allFindings.some(
            (f) => f.metadata?.file || f.metadata?.file_path ||
              (f.target?.startsWith("/") && /\.\w+$/.test(f.target))
          )
        ) {
          console.log("[orchestrator] Enriching findings with source code context");
          try {
            const result = await enrichFindingsWithCodeContext(
              allFindings,
              (msg) => console.log(`[orchestrator] ${msg}`)
            );
            sharedContext.codeContextEnrichment = {
              codeContextCount: result.codeContextCount,
              remediationCount: result.remediationCount,
            };
          } catch (error) {
            console.warn("[orchestrator] Code context enrichment failed:", error);
            errors.push(`Code context enrichment failed: ${String(error)}`);
          }
        }

        // Save checkpoint after successful agent completion
        if (config.assessmentId) {
          this.checkpointManager.saveCheckpoint({
            assessmentId: config.assessmentId,
            agentName,
            phaseIndex: agentOrder.indexOf(agentName),
            sharedContext,
            allFindings,
            completedAgents: [...agentsRun],
            orchestratorConfig: config,
            status: "completed",
          });
        }
      } catch (error) {
        console.error(`[orchestrator] ${agentName} threw error:`, error);
        errors.push(`${agentName} error: ${String(error)}`);

        // Save checkpoint on error so we can resume
        if (config.assessmentId) {
          this.checkpointManager.saveCheckpoint({
            assessmentId: config.assessmentId,
            agentName,
            phaseIndex: agentOrder.indexOf(agentName),
            sharedContext,
            allFindings,
            completedAgents: [...agentsRun],
            orchestratorConfig: config,
            status: "failed_during",
            errorMessage: String(error),
          });
        }
      } finally {
        this.currentAgent = undefined;
      }
    }

    // Count findings by severity
    const counts = this.countBySeverity(allFindings);

    return {
      success: errors.length === 0,
      agentResults: results,
      allFindings,
      totalFindings: allFindings.length,
      ...counts,
      executionTimeMs: Date.now() - startTime,
      agentsRun,
      errors,
    };
  }

  /**
   * Run pipelined stages with parallel execution support
   */
  private async runPipelinedStages(
    config: OrchestratorConfig,
    stages: PipelineStage[]
  ): Promise<OrchestratorResult> {
    const startTime = Date.now();
    const results: Partial<Record<AgentName, AgentOutput>> = {};
    const allFindings: AgentFinding[] = [];
    const errors: string[] = [];
    const agentsRun: AgentName[] = [];
    let sharedContext: Record<string, any> = {};

    this.cancelled = false;

    for (const stage of stages) {
      if (this.cancelled) {
        errors.push(`Cancelled before stage: ${stage.name}`);
        break;
      }

      // Filter to agents that have factories
      const applicableAgents = stage.agents.filter((a) => this.agentFactories[a]);
      if (applicableAgents.length === 0) continue;

      console.log(
        `[orchestrator] Pipeline stage: ${stage.name} (${applicableAgents.join(", ")})`
      );

      if (applicableAgents.length === 1) {
        // Single agent - run normally
        const agentName = applicableAgents[0];
        const factory = this.agentFactories[agentName];
        const agent = factory((state) => {
          if (this.onProgress) {
            this.onProgress(agentName, state);
          }
        });

        this.currentAgent = agent;
        const input = this.buildAgentInput(agentName, config, sharedContext, allFindings, results);

        try {
          const output = await agent.execute(input);
          results[agentName] = output;
          agentsRun.push(agentName);
          allFindings.push(...output.findings);
          sharedContext = { ...sharedContext, ...output.context, vulnerabilities: allFindings };

          if (agentName === "qa" && output.context) {
            this.applyQaResults(output, allFindings, sharedContext);
          }

          if (!output.success) {
            errors.push(`${agentName} failed: ${output.errors.join(", ")}`);
          }
        } catch (error) {
          errors.push(`${agentName} error: ${String(error)}`);
        } finally {
          this.currentAgent = undefined;
        }
      } else {
        // Multiple agents - run in parallel
        const parallelProgress = new Map<AgentName, number>();

        const promises = applicableAgents.map((agentName) => {
          const factory = this.agentFactories[agentName];
          const agent = factory((state) => {
            parallelProgress.set(agentName, state.progress);
            if (this.onProgress) {
              this.onProgress(agentName, {
                ...state,
                currentStep: `[${stage.name}] ${agentName}: ${state.currentStep}`,
              });
            }
          });

          // Each parallel agent gets a copy of context (no race conditions)
          const input = this.buildAgentInput(
            agentName,
            config,
            { ...sharedContext },
            [...allFindings],
            results
          );

          return agent.execute(input).then((output) => ({ agentName, output }));
        });

        // Stagger starts by 2s to avoid API rate limit spikes
        const staggeredPromises = promises.map(
          (p, i) =>
            new Promise<{ agentName: AgentName; output: AgentOutput }>((resolve) =>
              setTimeout(() => p.then(resolve), i * 2000)
            )
        );

        const parallelResults = await Promise.allSettled(staggeredPromises);

        // Merge results from all parallel agents
        const contextUpdates: Record<string, any>[] = [];

        for (const result of parallelResults) {
          if (result.status === "fulfilled") {
            const { agentName, output } = result.value;
            results[agentName] = output;
            agentsRun.push(agentName);
            allFindings.push(...output.findings);
            contextUpdates.push(output.context);

            if (!output.success) {
              errors.push(`${agentName} failed: ${output.errors.join(", ")}`);
            }
          } else {
            errors.push(`Parallel agent failed: ${result.reason}`);
          }
        }

        // Merge all context updates
        sharedContext = this.mergeContexts(sharedContext, contextUpdates);
        sharedContext.vulnerabilities = allFindings;
      }

      // Deduplicate findings after each stage
      const deduped = this.deduplicateFindings(allFindings);
      allFindings.length = 0;
      allFindings.push(...deduped);

      // Run code context enrichment after QA and before report
      const stageIdx = stages.indexOf(stage);
      const nextStage = stageIdx + 1 < stages.length ? stages[stageIdx + 1] : null;
      if (
        nextStage?.agents.includes("report") &&
        allFindings.some(
          (f) => f.metadata?.file || f.metadata?.file_path ||
            (f.target?.startsWith("/") && /\.\w+$/.test(f.target))
        )
      ) {
        console.log("[orchestrator] Enriching findings with source code context (pipelined)");
        try {
          const enrichResult = await enrichFindingsWithCodeContext(
            allFindings,
            (msg) => console.log(`[orchestrator] ${msg}`)
          );
          sharedContext.codeContextEnrichment = {
            codeContextCount: enrichResult.codeContextCount,
            remediationCount: enrichResult.remediationCount,
          };
        } catch (enrichError) {
          console.warn("[orchestrator] Code context enrichment failed:", enrichError);
          errors.push(`Code context enrichment failed: ${String(enrichError)}`);
        }
      }

      // Save checkpoint after each stage
      if (config.assessmentId) {
        this.checkpointManager.saveCheckpoint({
          assessmentId: config.assessmentId,
          agentName: applicableAgents[applicableAgents.length - 1],
          phaseIndex: stages.indexOf(stage),
          sharedContext,
          allFindings,
          completedAgents: [...agentsRun],
          orchestratorConfig: config,
          status: "completed",
        });
      }
    }

    const counts = this.countBySeverity(allFindings);

    return {
      success: errors.length === 0,
      agentResults: results,
      allFindings,
      totalFindings: allFindings.length,
      ...counts,
      executionTimeMs: Date.now() - startTime,
      agentsRun,
      errors,
    };
  }

  /**
   * Build agent input with context from previous agents
   */
  private buildAgentInput(
    agentName: AgentName,
    config: OrchestratorConfig,
    sharedContext: Record<string, any>,
    allFindings: AgentFinding[],
    results: Partial<Record<AgentName, AgentOutput>>
  ): AgentInput {
    return {
      targets: config.targets,
      repoPaths: config.repoPaths,
      severity: config.severity,
      options: {
        ...config.options,
        jiraProject: config.jiraProject,
        emailRecipients: config.emailRecipients,
      },
      context: {
        ...sharedContext,
        // Thread assessment config to all agents
        assessmentConfig: config.assessmentConfig,
        // Pass all findings to QA, compliance, and report agents
        ...(agentName === "qa" || agentName === "report" || agentName === "compliance" ? { findings: allFindings } : {}),
        // Pass agent results summary to QA agent
        ...(agentName === "qa"
          ? {
              agentResults: Object.fromEntries(
                Object.entries(results).map(([name, result]) => [
                  name,
                  {
                    success: result?.success,
                    summary: result?.summary,
                    toolCallsCount: result?.toolCallsCount,
                    executionTimeMs: result?.executionTimeMs,
                    findingsCount: result?.findings?.length || 0,
                    errors: result?.errors,
                    findings: result?.findings,
                  },
                ])
              ),
              // Pass QA mode (sast/dast) if set via orchestrator options
              ...(config.options?._qaMode ? { qaMode: config.options._qaMode } : {}),
            }
          : {}),
        // Pass cross-validation context to web-app agent
        ...(agentName === "web-app" && sharedContext.crossValidationMode
          ? {
              crossValidationMode: true,
              crossValidationTargets: sharedContext.crossValidationTargets,
            }
          : {}),
      },
    };
  }

  /**
   * Apply QA agent validation results to findings
   */
  private applyQaResults(
    output: AgentOutput,
    allFindings: AgentFinding[],
    sharedContext: Record<string, any>
  ): void {
    const validatedFindings = output.context.validatedFindings || [];
    const falsePositives = output.context.falsePositives || [];
    const falsePositiveIds = new Set(falsePositives.map((fp: any) => fp.findingId));

    // Update findings with QA confidence scores
    for (const finding of allFindings) {
      const validation = validatedFindings.find((v: any) => v.findingId === finding.id);
      if (validation) {
        finding.metadata = finding.metadata || {};
        finding.metadata.qaConfidence = validation.confidence;
        finding.metadata.qaValidated = true;
        finding.metadata.qaStatus = validation.validationStatus;
        finding.metadata.qaNote = validation.notes;
      }
    }

    // Mark false positives
    for (const finding of allFindings) {
      if (falsePositiveIds.has(finding.id)) {
        finding.metadata = finding.metadata || {};
        finding.metadata.qaFalsePositive = true;
      }
    }

    // Store QA review summary for report agent
    sharedContext.qaReview = {
      validatedFindings,
      falsePositives,
      coverageGaps: output.context.coverageGaps || [],
      coverageScore: output.context.coverageScore || 0,
      overallConfidence:
        validatedFindings.length > 0
          ? validatedFindings.reduce((sum: number, v: any) => sum + (v.confidence || 0), 0) /
            validatedFindings.length
          : 0,
      stats: {
        totalReviewed: validatedFindings.length,
        confirmed: validatedFindings.filter((v: any) => v.validationStatus === "confirmed").length,
        falsePositives: falsePositives.length,
        inconclusive: validatedFindings.filter((v: any) => v.validationStatus === "inconclusive")
          .length,
      },
    };

    console.log(
      `[orchestrator] QA validated ${validatedFindings.length} findings, ${falsePositives.length} false positives identified`
    );
  }

  /**
   * Determine workflow from config (for resume)
   */
  private determineWorkflow(config: OrchestratorConfig): AgentName[] {
    // Dual-track mode: both targets + repoPaths → serialized view of both tracks
    if (config.targets?.length && config.repoPaths?.length) {
      const hasAuth = this.hasAuthConfig(config);
      // Return a flattened representation for resume purposes
      const dastAgents: AgentName[] = hasAuth
        ? ["recon", "auth", "vuln-scan", "web-app", "exploit", "qa"]
        : ["recon", "vuln-scan", "web-app", "exploit", "qa"];
      const sastAgents: AgentName[] = ["code-intel", "security-scan", "qa"];
      // Merge unique agents in order
      const merged: AgentName[] = [];
      for (const a of [...dastAgents, ...sastAgents, "report" as AgentName]) {
        if (!merged.includes(a)) merged.push(a);
      }
      return merged;
    }

    const hasCodeIntel = config.repoPaths?.length && this.agentFactories["code-intel"];
    const hasAuth = this.hasAuthConfig(config);

    if (hasCodeIntel && hasAuth) return FULL_WITH_CODE_INTEL_AND_AUTH;
    if (hasCodeIntel) return FULL_WITH_CODE_INTEL;
    if (hasAuth) return FULL_WORKFLOW_WITH_AUTH;
    return FULL_WORKFLOW;
  }

  /**
   * Merge context updates from parallel agents
   */
  private mergeContexts(
    base: Record<string, any>,
    updates: Record<string, any>[]
  ): Record<string, any> {
    const merged = { ...base };
    for (const update of updates) {
      for (const [key, value] of Object.entries(update)) {
        if (Array.isArray(merged[key]) && Array.isArray(value)) {
          merged[key] = [...merged[key], ...value];
        } else if (
          typeof merged[key] === "object" &&
          merged[key] !== null &&
          typeof value === "object" &&
          value !== null &&
          !Array.isArray(merged[key])
        ) {
          merged[key] = { ...merged[key], ...value };
        } else {
          merged[key] = value;
        }
      }
    }
    return merged;
  }

  /**
   * Deduplicate findings by fingerprint
   */
  private deduplicateFindings(findings: AgentFinding[]): AgentFinding[] {
    const seen = new Map<string, AgentFinding>();
    for (const finding of findings) {
      const fp = finding.metadata?.fingerprint;
      if (fp && seen.has(fp)) {
        // Keep the one with more evidence
        const existing = seen.get(fp)!;
        if ((finding.evidence?.length || 0) > (existing.evidence?.length || 0)) {
          seen.set(fp, finding);
        }
      } else {
        seen.set(fp || finding.id, finding);
      }
    }
    return Array.from(seen.values());
  }

  /**
   * Count findings by severity
   */
  private countBySeverity(findings: AgentFinding[]): {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  } {
    return {
      criticalCount: findings.filter((f) => f.severity === "critical").length,
      highCount: findings.filter((f) => f.severity === "high").length,
      mediumCount: findings.filter((f) => f.severity === "medium").length,
      lowCount: findings.filter((f) => f.severity === "low").length,
      infoCount: findings.filter((f) => f.severity === "info").length,
    };
  }

  /**
   * Check if assessment config has auth configured
   */
  private hasAuthConfig(config: OrchestratorConfig): boolean {
    const ac = config.assessmentConfig as AssessmentConfig | undefined;
    return !!(ac?.auth?.browser_login && ac.auth.browser_login.length > 0);
  }

  /**
   * Set up assessment-wide configuration: guidance mode, browser persistence
   */
  private setupAssessment(config: OrchestratorConfig): void {
    const ac = config.assessmentConfig as AssessmentConfig | undefined;

    // Set guidance mode (interactive vs autonomous)
    const mode = ac?.mode || "interactive";
    setGuidanceMode(mode);
    console.log(`[orchestrator] Guidance mode: ${mode}`);

    // Set up browser session persistence
    const persistSession = ac?.browser?.persist_session !== false && this.hasAuthConfig(config);
    if (persistSession) {
      this.enableBrowserSessionPersistence();
    }

    // Load assessment config from file if not provided
    if (!config.assessmentConfig) {
      const fileConfig = loadAssessmentConfig();
      if (fileConfig) {
        config.assessmentConfig = fileConfig;
        // Re-check auth after loading
        if (this.hasAuthConfig(config)) {
          this.enableBrowserSessionPersistence();
        }
      }
    }
  }

  /**
   * Override browser_close to be a no-op during multi-phase assessments
   * Prevents agents from accidentally destroying the shared browser session
   */
  private enableBrowserSessionPersistence(): void {
    if (this.persistBrowserSession) return; // Already enabled
    this.persistBrowserSession = true;

    // Save the original handler
    this.originalBrowserClose = browserHandlers.browser_close;

    // Replace with a no-op that returns a friendly message
    browserHandlers.browser_close = async () => {
      console.log("[orchestrator] browser_close intercepted (session persistence active)");
      return JSON.stringify({
        success: true,
        data: {
          message: "Browser close intercepted - session is being preserved for downstream agents",
          persisted: true,
        },
      });
    };

    console.log("[orchestrator] Browser session persistence enabled (browser_close → no-op)");
  }

  /**
   * Clean up browser session after all agents complete
   */
  private async cleanupBrowserSession(): Promise<void> {
    // Restore original browser_close handler
    if (this.originalBrowserClose) {
      browserHandlers.browser_close = this.originalBrowserClose as any;
      this.originalBrowserClose = null;
    }

    if (this.persistBrowserSession) {
      console.log("[orchestrator] Cleaning up browser session");
      try {
        // Save state before closing (in case of future resume)
        await browserHandlers.browser_save_state();
      } catch (e) {
        // Browser may not have been opened
      }

      try {
        await browserHandlers.browser_close();
      } catch (e) {
        // Browser may already be closed
      }

      this.persistBrowserSession = false;
      console.log("[orchestrator] Browser session cleaned up");
    }
  }

  /**
   * Apply phase overrides from assessment config
   */
  private applyPhaseOverrides(workflow: AgentName[], config: OrchestratorConfig): AgentName[] {
    const ac = config.assessmentConfig as AssessmentConfig | undefined;
    if (!ac?.phases) return workflow;

    let result = [...workflow];

    // Apply custom order if specified
    if (ac.phases.order?.length) {
      result = ac.phases.order.filter(
        (name) => this.agentFactories[name]
      ) as AgentName[];
    }

    // Apply skip list
    if (ac.phases.skip?.length) {
      const skipSet = new Set(ac.phases.skip);
      result = result.filter((name) => !skipSet.has(name));
    }

    return result;
  }

  /**
   * Create error result
   */
  private createErrorResult(error: string): OrchestratorResult {
    return {
      success: false,
      agentResults: {},
      allFindings: [],
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      executionTimeMs: 0,
      agentsRun: [],
      errors: [error],
    };
  }

  /**
   * Run a deterministic sequential assessment using the SequentialPipeline.
   *
   * Unlike other modes that use inner LLM agents (which can plan but not execute),
   * this mode calls tool handlers directly in a predetermined order matching
   * the test matrix. This guarantees:
   *
   * - Every test is executed (no toolCallsCount=0 failures)
   * - Results are consistent across runs
   * - Full evidence is captured for every test
   * - Clear coverage tracking against the 116-test matrix
   *
   * Phases run strictly in order:
   *   1. DAST (73 tests) - reconnaissance, SSL, auth, injection, API, etc.
   *   2. SAST (24 tests) - code analysis, data flows, defenses (requires repo_paths)
   *   3. Cross-Validation (11 tests) - correlate SAST findings with DAST results
   */
  async runDeterministic(
    config: OrchestratorConfig,
    handlers: Record<string, Function>
  ): Promise<OrchestratorResult> {
    const startTime = Date.now();
    console.log(`[orchestrator] Starting DETERMINISTIC sequential assessment`);
    console.log(`[orchestrator]   Targets: ${config.targets?.join(", ") || "none"}`);
    console.log(`[orchestrator]   Repo paths: ${config.repoPaths?.join(", ") || "none"}`);

    // Scan auth + scope come from the DAST page's scan_config, attached to the
    // run options (auth under web_app.auth, scope under scope). Thread them into
    // the deterministic pipeline so authed/scoped scans actually honor the config.
    const opts: any = config.options || {};
    const pipelineConfig: PipelineConfig = {
      targets: config.targets || [],
      repoPaths: config.repoPaths,
      severity: config.severity,
      assessmentId: config.assessmentId,
      auth: opts.web_app?.auth ?? opts.auth,
      scope: opts.scope,
      // Optional second user token for cross-user authorization tests (AUTHZ-02).
      secondUserToken: opts.harness?.second_user_jwt ?? opts.web_app?.second_user_jwt,
      // Scan-policy selection (migration 0039) — the pipeline runs only these.
      selectedTests: opts.selected_tests,
      selectedCategories: opts.selected_categories,
    };

    // Phase 3: create the scan row up-front (status 'running') so the Scans view
    // shows a LIVE run, then heartbeat progress as tests execute. null when
    // multi-target / no cloud session (same skip rule as before).
    const liveScan = await this.startDeterministicScan(config, startTime);
    let lastBeat = 0;

    const pipeline = new SequentialPipeline(
      handlers,
      pipelineConfig,
      (phase, testId, testName, progress) => {
        if (this.onProgress) {
          this.onProgress("recon" as AgentName, {
            id: config.assessmentId || "deterministic",
            agentName: "orchestrator",
            status: "running",
            startedAt: new Date(startTime).toISOString(),
            currentStep: `[${phase}] ${testId}: ${testName}`,
            progress,
            findings: [],
            errors: [],
            toolCallsCount: 0,
            iterations: 0,
            context: {},
          });
        }
        // Throttled live progress heartbeat to the scan row (≤1 / 3s).
        if (liveScan && Date.now() - lastBeat > 3000) {
          lastBeat = Date.now();
          cloudRequest(`/scans/${liveScan.scanId}`, {
            method: "PATCH",
            body: {
              progress_pct: Math.max(0, Math.min(100, Math.round(progress))),
              phase,
              current_activity: `${testId}: ${testName}`,
            },
          }).catch(() => {});
        }
      }
    );

    try {
      const pipelineOutput = await pipeline.run();

      // Convert PipelineOutput to OrchestratorResult
      const findings = pipelineOutput.findings;
      const result: OrchestratorResult = {
        success: pipelineOutput.success,
        agentResults: {}, // No inner agents used
        allFindings: findings,
        totalFindings: findings.length,
        criticalCount: findings.filter(f => f.severity === "critical").length,
        highCount: findings.filter(f => f.severity === "high").length,
        mediumCount: findings.filter(f => f.severity === "medium").length,
        lowCount: findings.filter(f => f.severity === "low").length,
        infoCount: findings.filter(f => f.severity === "info").length,
        executionTimeMs: pipelineOutput.executionTimeMs,
        agentsRun: ["recon"] as AgentName[], // Placeholder - all tests are run directly
        errors: [],
      };

      // Attach pipeline-specific data for reporting
      (result as any).pipelineOutput = pipelineOutput;
      (result as any).testResults = pipelineOutput.testResults;
      (result as any).coverage = pipelineOutput.coverage;

      console.log(`[orchestrator] Deterministic assessment complete:`);
      console.log(`[orchestrator]   Total tests: ${pipelineOutput.coverage.total}`);
      console.log(`[orchestrator]   Passed: ${pipelineOutput.coverage.passed}`);
      console.log(`[orchestrator]   Failed: ${pipelineOutput.coverage.failed}`);
      console.log(`[orchestrator]   Skipped: ${pipelineOutput.coverage.skipped}`);
      console.log(`[orchestrator]   N/A: ${pipelineOutput.coverage.notApplicable}`);
      console.log(`[orchestrator]   Errors: ${pipelineOutput.coverage.errors}`);
      console.log(`[orchestrator]   Findings: ${findings.length}`);
      console.log(`[orchestrator]   Duration: ${pipelineOutput.executionTimeMs}ms`);

      // Finalize the scan row (status completed + counts + coverage) and persist
      // the individual findings, stamped with the scan that produced them
      // (migration 0035). Findings stamping is what makes the Scheduled DAST →
      // Vulnerabilities view real. Best-effort + non-fatal.
      if (liveScan) {
        await this.finalizeDeterministicScan(liveScan.scanId, result, pipelineOutput);
        await this.promoteDeterministicFindings(liveScan.scanId, findings, config.assessmentId);
      }

      return result;
    } catch (error: any) {
      console.error(`[orchestrator] Deterministic pipeline error: ${error.message || error}`);
      // Mark the live scan failed so it doesn't hang at 'running' forever.
      if (liveScan) {
        await cloudRequest(`/scans/${liveScan.scanId}`, {
          method: "PATCH",
          body: { status: "failed", finished: true },
        }).catch(() => {});
      }
      return this.createErrorResult(`Pipeline error: ${error.message || error}`);
    }
  }

  /**
   * Create the `scans` row at the START of a deterministic run (status
   * 'running', counts 0) so the Scheduled DAST page shows a LIVE scan and the
   * findings promoted later can be stamped with its id (migration 0035).
   * Returns null when there's no cloud session or it's a multi-target run
   * (per-target counts would be dishonest — same skip rule as before).
   */
  private async startDeterministicScan(
    config: OrchestratorConfig,
    startTime: number
  ): Promise<{ scanId: string; targetId: string } | null> {
    try {
      if (!hasCloudSession()) return null;
      const targets = config.targets || [];
      if (targets.length !== 1) {
        if (targets.length > 1) {
          console.log(
            `[orchestrator] scan-history recording skipped (multi-target run; per-target counts unavailable)`
          );
        }
        return null;
      }
      const target = targets[0];
      const isWeb = /^https?:\/\//i.test(target);
      const resolved = await cloudRequest<{ id: string }>("/targets/resolve", {
        method: "POST",
        body: { raw_value: target, target_type: isWeb ? "web" : "host" },
      });
      const scan = await cloudRequest<{ id: string }>("/scans", {
        method: "POST",
        body: {
          target_id: resolved.id,
          assessment_id: config.assessmentId ?? null,
          scan_type: "deterministic",
          trigger_kind: (config as any).triggerKind ?? "manual",
          status: "running",
          scanner_set: [],
          started_at: new Date(startTime).toISOString(),
        },
      });
      console.log(`[orchestrator] started deterministic scan ${scan.id} for ${target}`);
      return { scanId: scan.id, targetId: resolved.id };
    } catch (e) {
      console.warn(
        `[orchestrator] scan start failed (non-fatal): ${e instanceof Error ? e.message : String(e)}`
      );
      return null;
    }
  }

  /** Finalize a live scan: status completed + severity counts + test coverage. */
  private async finalizeDeterministicScan(
    scanId: string,
    result: OrchestratorResult,
    pipelineOutput: PipelineOutput
  ): Promise<void> {
    try {
      const cov = pipelineOutput.coverage;
      const testsTotal = cov?.total ?? 0;
      // Executed = everything except the ones gated out (skipped/N-A).
      const testsDone = Math.max(0, testsTotal - (cov?.skipped ?? 0) - (cov?.notApplicable ?? 0));
      await cloudRequest(`/scans/${scanId}`, {
        method: "PATCH",
        body: {
          status: "completed",
          progress_pct: 100,
          critical_count: result.criticalCount,
          high_count: result.highCount,
          medium_count: result.mediumCount,
          low_count: result.lowCount,
          info_count: result.infoCount,
          total_count: result.totalFindings,
          tests_total: testsTotal,
          tests_done: testsDone,
          // Runtime attack volume (real requests fired) — the apples-to-apples
          // "attacks executed" figure, plus the per-tool breakdown for the chart.
          attacks_executed: pipelineOutput.attacksExecuted ?? 0,
          attacks_estimated: pipelineOutput.attacksEstimated ?? false,
          attacks_by_tool: pipelineOutput.attacksByTool ?? {},
          finished: true,
        },
      });
    } catch (e) {
      console.warn(
        `[orchestrator] scan finalize failed (non-fatal): ${e instanceof Error ? e.message : String(e)}`
      );
    }
  }

  /**
   * Persist a deterministic scan's findings to the cloud `/findings` table,
   * each stamped with `scan_id` (migration 0035). This is what gives the
   * Scheduled DAST → Vulnerabilities view its own substrate, separate from the
   * LLM-assessment findings (those carry `assessment_id` but no `scan_id`).
   *
   * The cloud POST upserts on fingerprint(title,target,source,cwe), so re-runs
   * of the same scheduled scan bump occurrence_count instead of duplicating,
   * and `scan_id` is sticky (COALESCE in the upsert) so a later LLM assessment
   * touching the same vuln doesn't strip its DAST attribution.
   *
   * Best-effort + non-fatal: a findings-promotion failure never breaks the scan.
   */
  private async promoteDeterministicFindings(
    scanId: string,
    findings: AgentFinding[],
    assessmentId?: string
  ): Promise<void> {
    if (!hasCloudSession() || findings.length === 0) return;
    // Phase 2 AI bridge + Phase 4 notifications: read the org policy once.
    // Auto-queue is cost-safe (only CREATEs not-started Prove runs).
    const escalate = await this.getEscalationConfig();
    let pushed = 0;
    let failed = 0;
    let queued = 0;
    for (const f of findings) {
      try {
        // Capture is_new + the cloud finding id so we can attribute a queued
        // Prove run to the exact finding it validates.
        const resp = await cloudRequest<{ id: string; is_new: boolean }>("/findings", {
          method: "POST",
          body: {
            title: f.title,
            severity: f.severity,
            description: f.description,
            target: f.target,
            evidence: f.evidence,
            remediation: f.remediation,
            source: f.source,
            cve: f.metadata?.cve,
            cwe: f.metadata?.cwe,
            scan_id: scanId,
            assessment_id: assessmentId ?? null,
          },
        });
        pushed++;
        const sev = String(f.severity).toLowerCase();
        if (escalate.enabled && resp.is_new && escalate.severities.has(sev)) {
          if (await this.queueProveRun(resp.id, f)) queued++;
        }
        // Phase 4: notify on a NEW Critical/High candidate (Slack-compatible).
        if (escalate.webhookUrl && resp.is_new && (sev === "critical" || sev === "high")) {
          this.fireWebhook(escalate.webhookUrl, f);
        }
      } catch {
        failed++;
      }
    }
    console.log(
      `[orchestrator] promoted ${pushed}/${findings.length} deterministic findings to scan ${scanId}` +
        (failed ? ` (${failed} failed, non-fatal)` : "") +
        (queued ? ` · auto-queued ${queued} Prove run(s)` : "")
    );
  }

  /** Read the org's DAST escalation + notification policy. Best-effort. */
  private async getEscalationConfig(): Promise<{
    enabled: boolean;
    severities: Set<string>;
    webhookUrl?: string;
  }> {
    try {
      const s = await cloudRequest<{
        dast_auto_escalate_enabled?: boolean;
        dast_auto_escalate_severities?: string;
        dast_webhook_url?: string | null;
      }>("/org-settings");
      const severities = new Set(
        (s.dast_auto_escalate_severities ?? "critical,high")
          .split(",")
          .map((x) => x.trim().toLowerCase())
          .filter(Boolean)
      );
      return {
        enabled: Boolean(s.dast_auto_escalate_enabled),
        severities,
        webhookUrl: s.dast_webhook_url ?? undefined,
      };
    } catch {
      return { enabled: false, severities: new Set() };
    }
  }

  /** Post a Slack-compatible {text} payload to the org's notification webhook.
   *  External URL (not the Maestro backend) → plain fetch. Fire-and-forget. */
  private fireWebhook(url: string, f: AgentFinding): void {
    const text = `:rotating_light: New ${String(f.severity).toUpperCase()} DAST finding: *${f.title}* on ${f.target}`;
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    }).catch(() => {});
  }

  /** Create a NOT-STARTED "Prove it" assessment for a new candidate finding.
   *  Mirrors the desktop's createProveRun shape so the user can one-click start
   *  it from the escalation queue. Best-effort + non-fatal. */
  private async queueProveRun(findingId: string, f: AgentFinding): Promise<boolean> {
    try {
      const pending_prompt = buildProvePrompt({
        findingId,
        title: f.title,
        severity: String(f.severity),
        cve: f.metadata?.cve ?? null,
        description: f.description,
        targetValue: f.target,
      });
      await cloudRequest("/assessments", {
        method: "POST",
        body: {
          type: "web_app",
          name: `Prove: ${f.title.slice(0, 60)}`,
          targets: [f.target],
          config: {
            brain: "claude",
            capabilities: ["web_app"],
            pending_prompt,
            prove_finding_id: findingId,
            // Marks the run as auto-queued by DAST escalation (vs a manual Prove).
            auto_escalated: true,
          },
        },
      });
      return true;
    } catch (e) {
      console.warn(
        `[orchestrator] auto-queue Prove run failed (non-fatal): ${e instanceof Error ? e.message : String(e)}`
      );
      return false;
    }
  }
}

// ==================== Dual-Track Helpers ====================

/**
 * Tag all findings in an array with a track identifier (dast/sast/cross-validated)
 */
function tagFindingsByTrack(findings: AgentFinding[], track: string): void {
  for (const finding of findings) {
    finding.metadata = finding.metadata || {};
    finding.metadata.track = track;
  }
}

/**
 * Infer the vulnerability type from a finding's title/description.
 * Returns a normalized type string used to select the right DAST tool.
 */
function inferVulnType(finding: AgentFinding): string {
  const text = `${finding.title} ${finding.description}`.toLowerCase();

  if (/sql.?inject|sqli|sql\s+query|parameterized/.test(text)) return "sqli";
  if (/xss|cross.?site.?script|reflected|stored.?script/.test(text)) return "xss";
  if (/ssrf|server.?side.?request/.test(text)) return "ssrf";
  if (/command.?inject|os.?command|exec\(|child_process|rce|remote.?code/.test(text)) return "rce";
  if (/path.?travers|directory.?travers|\.\.\/|lfi|local.?file/.test(text)) return "path_traversal";
  if (/open.?redirect|url.?redirect/.test(text)) return "open_redirect";
  if (/csrf|cross.?site.?request.?forg/.test(text)) return "csrf";
  if (/idor|insecure.?direct|broken.?access/.test(text)) return "idor";
  if (/auth|session|jwt|token|password|credential/.test(text)) return "auth";
  if (/header|cors|csp|x-frame|hsts/.test(text)) return "headers";

  return "unknown";
}

/**
 * Map a SAST finding's file path to a live endpoint using code-intel entry points.
 */
function mapFileToEndpoint(
  filePath: string,
  line: number | undefined,
  entryPoints: any[]
): { endpoint: string; method: string; parameters: string[] } | null {
  if (!entryPoints || entryPoints.length === 0) return null;

  // Normalize the file path for comparison (strip /mnt/host-home/ prefix)
  const normalizedPath = filePath
    .replace(/^\/mnt\/host-home\//, "")
    .replace(/^\//, "");

  // Find entry points whose handler file matches the finding file
  const matches = entryPoints.filter((ep: any) => {
    const handlerFile = (ep.handler?.file || ep.file || "")
      .replace(/^\/mnt\/host-home\//, "")
      .replace(/^\//, "");

    if (!handlerFile) return false;

    // Check if the file paths match (partial match for nested paths)
    if (handlerFile === normalizedPath) return true;
    if (normalizedPath.endsWith(handlerFile) || handlerFile.endsWith(normalizedPath)) return true;

    return false;
  });

  if (matches.length === 0) return null;

  // If we have a line number, try to find the closest entry point
  let bestMatch = matches[0];
  if (line && matches.length > 1) {
    let closestDistance = Infinity;
    for (const ep of matches) {
      const epLine = ep.handler?.line || ep.line || 0;
      const distance = Math.abs(epLine - line);
      if (distance < closestDistance) {
        closestDistance = distance;
        bestMatch = ep;
      }
    }
  }

  return {
    endpoint: bestMatch.route || bestMatch.path || bestMatch.endpoint || "/",
    method: bestMatch.method || "GET",
    parameters: bestMatch.parameters || bestMatch.params || [],
  };
}

/**
 * Build cross-validation targets by matching SAST findings to live endpoints.
 * Uses code-intel entry points to map file paths → API routes.
 */
function buildCrossValidationTargets(
  sastFindings: AgentFinding[],
  entryPoints: any[],
  config: OrchestratorConfig
): CrossValidationTarget[] {
  const targets: CrossValidationTarget[] = [];
  const baseUrl = config.targets?.[0] || "";

  for (const finding of sastFindings) {
    // Skip non-actionable findings
    if (finding.severity === "info" || finding.metadata?.qaFalsePositive) continue;

    const vulnType = inferVulnType(finding);
    if (vulnType === "unknown" || vulnType === "headers") continue;

    const filePath = finding.metadata?.file || finding.metadata?.file_path || finding.target;
    if (!filePath) continue;

    const line = finding.metadata?.line || finding.metadata?.line_start;

    // Try to map the file to a live endpoint
    const mapping = mapFileToEndpoint(filePath, line, entryPoints);
    if (!mapping) continue;

    // Build the live URL
    const liveUrl = baseUrl
      ? `${baseUrl.replace(/\/$/, "")}${mapping.endpoint}`
      : mapping.endpoint;

    targets.push({
      sastFindingId: finding.id,
      sastTitle: finding.title,
      vulnType,
      filePath: filePath as string,
      line,
      endpoint: mapping.endpoint,
      method: mapping.method,
      liveUrl,
      parameters: mapping.parameters,
    });
  }

  return targets;
}

/**
 * Helper function to create and run orchestrator
 */
export async function runFullAssessment(
  config: OrchestratorConfig,
  onProgress?: OrchestratorProgressCallback
): Promise<OrchestratorResult> {
  const orchestrator = new Orchestrator(onProgress);
  return orchestrator.runFull(config);
}

export async function runSelectiveAssessment(
  config: OrchestratorConfig & { agents: AgentName[] },
  onProgress?: OrchestratorProgressCallback
): Promise<OrchestratorResult> {
  const orchestrator = new Orchestrator(onProgress);
  return orchestrator.runSelective(config);
}

export async function runDualTrackAssessment(
  config: OrchestratorConfig,
  onProgress?: OrchestratorProgressCallback
): Promise<OrchestratorResult> {
  const orchestrator = new Orchestrator(onProgress);
  return orchestrator.runDualTrack(config);
}

export async function runSingleAgent(
  agentName: AgentName,
  input: AgentInput,
  onProgress?: OrchestratorProgressCallback
): Promise<AgentOutput> {
  const orchestrator = new Orchestrator(onProgress);
  return orchestrator.runSingle(agentName, input);
}
