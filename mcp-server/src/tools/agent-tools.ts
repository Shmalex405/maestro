/**
 * Agent Tools
 *
 * MCP tool definitions for invoking security agents.
 * These tools allow Claude Code to run specialized agents that
 * autonomously execute security assessment workflows.
 */

import { AgentOutput, AgentState, Severity } from "../agents/base-agent";

// Lazy import to avoid circular dependency (server.ts imports agent-tools.ts)
let _serverHandlers: Record<string, Function> | null = null;
async function getServerHandlers(): Promise<Record<string, Function>> {
  if (!_serverHandlers) {
    const server = await import("../server");
    _serverHandlers = server.allHandlers;
  }
  return _serverHandlers;
}

// Agent names type
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
  | "chain-analysis"
  | "cloud-recon"
  | "cloud-exploit";

// Running agents registry
const runningAgents = new Map<
  string,
  {
    state: AgentState;
    cancel: () => void;
  }
>();

// Tool definitions for MCP server
export const agentTools = [
  {
    name: "run_orchestrator",
    description: `Run the master orchestrator to execute a security assessment workflow.

Modes:
- "full": Run all agents sequentially (recon → vuln-scan → web-app → exploit → report)
- "selective": Run only the specified agents in order
- "pipelined": Run agents with parallel execution where possible (vuln-scan + web-app in parallel)
- "dual-track": Run DAST (Track A) and SAST (Track B) in parallel, then cross-validate and generate a unified report. Auto-activates when both targets and repo_paths are provided with "full" mode.
- "extreme": Run ALL agents with maximum parallelism (code-intel + recon parallel → infra + vuln parallel → web + api parallel → exploit → security-scan → qa → compliance → report)
- "sequential": RECOMMENDED. Deterministic pipeline that calls tools directly without inner LLM agents. Executes all 116 tests from the test matrix in order: DAST (73 tests) → SAST (24 tests, requires repo_paths) → Cross-Validation (11 tests) → Chain Analysis (8 tests). Most reliable and consistent mode — guaranteed tool execution with full evidence capture.

The orchestrator passes context between agents so findings flow through the pipeline.`,
    inputSchema: {
      type: "object",
      properties: {
        mode: {
          type: "string",
          enum: ["full", "selective", "pipelined", "dual-track", "extreme", "sequential"],
          description: "Execution mode - sequential (RECOMMENDED) runs deterministic tool-by-tool pipeline for consistent results, full runs inner LLM agents sequentially, selective runs specified agents, pipelined runs with parallel stages, dual-track runs DAST + SAST in parallel, extreme runs ALL agents with max parallelism",
        },
        agents: {
          type: "array",
          items: {
            type: "string",
            enum: ["code-intel", "recon", "auth", "vuln-scan", "web-app", "exploit", "security-scan", "qa", "report", "api-security", "infra-security", "compliance", "chain-analysis"],
          },
          description: "Agents to run (required for selective mode)",
        },
        assessment_config: {
          type: "object",
          description: "Assessment configuration (mode, auth, browser settings, focus). See config/assessment.yml for schema.",
        },
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Network targets (IPs, CIDRs, domains, URLs)",
        },
        repo_paths: {
          type: "array",
          items: { type: "string" },
          description: "Repository paths for code scanning",
        },
        severity: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Minimum severity threshold for reporting",
        },
        jira_project: {
          type: "string",
          description: "Jira project key for creating tickets",
        },
        email_recipients: {
          type: "array",
          items: { type: "string" },
          description: "Email addresses to send report to",
        },
      },
      required: ["mode"],
    },
  },
  {
    name: "run_recon_agent",
    description: `Run the reconnaissance agent for asset discovery and mapping.

This agent will:
1. Discover live hosts in CIDR ranges
2. Scan ports on discovered hosts
3. Enumerate subdomains for domains
4. Fingerprint services on open ports
5. Detect web technologies

Returns discovered assets and services for downstream scanning.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Targets to reconnoiter (IPs, CIDRs, domains)",
        },
        quick_scan: {
          type: "boolean",
          description: "Use quick scan mode (top 100 ports only)",
          default: false,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_vuln_scan_agent",
    description: `Run the vulnerability scanning agent.

This agent will:
1. Run Nuclei with appropriate templates
2. Run Nikto on web servers
3. Run WPScan on WordPress sites
4. Search for known exploits

Returns identified vulnerabilities with severity ratings.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs to scan for vulnerabilities",
        },
        severity: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Minimum severity to report",
          default: "medium",
        },
        context: {
          type: "object",
          description: "Optional context from recon agent (discovered services)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_web_app_agent",
    description: `Run the web application security testing agent (OWASP-style testing).

This agent will:
1. Crawl the application to discover endpoints
2. Test for SQL injection
3. Test for XSS vulnerabilities
4. Fuzz for hidden endpoints and files

Uses non-destructive testing methods only.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Web URLs to test",
        },
        context: {
          type: "object",
          description: "Optional context from previous agents",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_exploit_agent",
    description: `Run the exploit validation agent (NON-DESTRUCTIVE ONLY).

This agent will:
1. Validate that identified vulnerabilities are exploitable
2. Run Metasploit modules in check mode
3. Validate specific CVEs
4. Document exploitability evidence

NEVER executes destructive exploits. Reports them for manual review instead.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Targets to validate exploits against",
        },
        vulnerabilities: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              title: { type: "string" },
              cve: { type: "string" },
              target: { type: "string" },
            },
          },
          description: "Vulnerabilities to validate (from vuln-scan agent)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_security_scan_agent",
    description: `Run the code security scanning agent on local repositories.

This agent will:
1. Detect languages in the repository
2. Run Semgrep for SAST
3. Run language-specific scanners (Bandit for Python, njsscan for JS)
4. Scan for hardcoded secrets
5. Check dependencies for vulnerabilities
6. Scan IaC files for misconfigurations

Does NOT require scope validation (local files only).`,
    inputSchema: {
      type: "object",
      properties: {
        repo_paths: {
          type: "array",
          items: { type: "string" },
          description: "Repository paths to scan (use /mnt/host-home/ prefix for local paths)",
        },
        scan_types: {
          type: "array",
          items: {
            type: "string",
            enum: ["all", "sast", "secrets", "dependencies", "iac"],
          },
          description: "Types of scans to run",
          default: ["all"],
        },
        severity: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Minimum severity to report",
          default: "medium",
        },
      },
      required: ["repo_paths"],
    },
  },
  {
    name: "run_qa_agent",
    description: `Run the QA agent to validate findings from other agents.

This agent will:
1. Review all findings from prior agents
2. Validate critical and high severity findings by re-testing
3. Assign confidence scores (1-10) to each finding
4. Identify false positives and coverage gaps
5. Request follow-up scans if needed

Run this automatically before report generation, or manually to validate specific findings.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Targets that were tested (used for coverage analysis)",
        },
        findings: {
          type: "array",
          items: { type: "object" },
          description: "Findings to validate (from prior agents)",
        },
        agent_results: {
          type: "object",
          description: "Results from prior agents (for context)",
        },
      },
      required: [],
    },
  },
  {
    name: "run_report_agent",
    description: `Run the report generation agent.

This agent will:
1. Aggregate findings from all sources
2. Deduplicate findings
3. Generate formatted report
4. Create Jira tickets for high/critical findings
5. Upload report to SharePoint
6. Email report to recipients

Can be run standalone or as the final step in a workflow.`,
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["markdown", "html", "json"],
          description: "Report output format",
          default: "markdown",
        },
        findings: {
          type: "array",
          items: { type: "object" },
          description: "Findings to include (optional - will pull from context if not provided)",
        },
        jira_project: {
          type: "string",
          description: "Jira project key for creating tickets",
        },
        email_recipients: {
          type: "array",
          items: { type: "string" },
          description: "Email addresses to send report to",
        },
        upload_sharepoint: {
          type: "boolean",
          description: "Upload report to SharePoint",
          default: false,
        },
      },
      required: ["format"],
    },
  },
  {
    name: "run_code_intel_agent",
    description: `Run the code intelligence agent for pre-attack source code analysis.

This agent will:
1. Detect languages and framework in the repository
2. Map all HTTP routes, API endpoints, and entry points
3. Trace data flows from user input to sinks (DB, filesystem, commands, external HTTP)
4. Analyze existing security defenses (CSRF, auth middleware, input validation)
5. Generate a prioritized attack surface map

The attack surface map feeds into downstream agents (recon, vuln-scan, web-app) for targeted testing.
Does NOT require scope validation (local files only).`,
    inputSchema: {
      type: "object",
      properties: {
        repo_paths: {
          type: "array",
          items: { type: "string" },
          description: "Repository paths to analyze (use /mnt/host-home/ prefix for local paths)",
        },
        framework: {
          type: "string",
          description: "Optional framework hint (express, flask, django, spring, etc.)",
        },
      },
      required: ["repo_paths"],
    },
  },
  {
    name: "run_auth_agent",
    description: `Run the authentication setup agent to establish a browser-based authenticated session.

This agent will:
1. Read login instructions from assessment config
2. Navigate to login page and fill credentials
3. Handle redirects, consent screens
4. Pause for CAPTCHA/MFA and ask user for help
5. Capture cookies and auth headers after login
6. Save browser state for downstream agents

Run this before vuln-scan or web-app agents when the target requires authentication.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Target URLs (the login page or app URL)",
        },
        assessment_config: {
          type: "object",
          description: "Assessment config with auth.browser_login steps",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_api_security_agent",
    description: `Run the API security testing agent for deep REST, GraphQL, and WebSocket testing.

This agent will:
1. Discover API endpoints (crawl + OpenAPI/Swagger detection)
2. Classify API type (REST / GraphQL / WebSocket)
3. GraphQL: introspection, batching, depth limits, aliasing, field suggestions
4. REST: schema-based fuzzing if OpenAPI available
5. JWT analysis, token replay, unauthenticated access
6. IDOR testing across resources
7. Rate limiting and CORS on all API endpoints
8. Injection testing on all parameters
9. WebSocket security testing if WS detected

Uses non-destructive testing methods only.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "API URLs to test",
        },
        context: {
          type: "object",
          description: "Optional context from previous agents (discovered endpoints, auth tokens)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_infra_security_agent",
    description: `Run the infrastructure security testing agent.

This agent will:
1. SSL/TLS protocol and cipher analysis
2. Certificate chain validation
3. DNS security (zone transfer, DNSSEC, record enumeration)
4. Subdomain takeover detection
5. HTTP request smuggling tests
6. Cloud metadata endpoint probing
7. S3 bucket permission testing

Focuses on network/transport layer vulnerabilities.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Targets to test (domains, IPs, URLs)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "run_compliance_agent",
    description: `Run the compliance mapping agent.

This agent will:
1. Read all findings from the assessment
2. Map each finding to OWASP Top 10 2021, OWASP API Top 10, CWE
3. Map to NIST 800-53 controls and PCI-DSS requirements
4. Calculate CVSS v3.1 vector strings
5. Generate compliance coverage matrix
6. Flag untested controls as gaps

Does NOT perform any scanning — reads existing findings only.`,
    inputSchema: {
      type: "object",
      properties: {
        findings: {
          type: "array",
          items: { type: "object" },
          description: "Findings to map to compliance frameworks (optional — pulls from context if not provided)",
        },
      },
    },
  },
  {
    name: "run_chain_analysis_agent",
    description: `Run the attack chain analysis agent.

This agent will:
1. Read all findings from the assessment
2. Tag each finding with grants/requires capabilities
3. Match against known chain patterns (XSS→session hijack, SSRF→cloud metadata, etc.)
4. Discover emergent (novel) attack chains
5. Generate chain hypotheses with confidence scores
6. In validation mode: confirm/refute chains based on exploit results

Runs in two modes:
- "hypothesize": Analyze findings and generate chain hypotheses (default)
- "validate": Validate hypotheses against exploit results

Does NOT perform any scanning — reads existing findings only.`,
    inputSchema: {
      type: "object",
      properties: {
        findings: {
          type: "array",
          items: { type: "object" },
          description: "Findings to analyze for chains (optional — pulls from context if not provided)",
        },
        chain_mode: {
          type: "string",
          enum: ["hypothesize", "validate"],
          description: "Analysis mode: hypothesize (default) or validate",
        },
        chain_hypotheses: {
          type: "array",
          items: { type: "object" },
          description: "Chain hypotheses to validate (required for validate mode)",
        },
        exploit_results: {
          type: "array",
          items: { type: "object" },
          description: "Exploit results for validation (required for validate mode)",
        },
      },
    },
  },
  {
    name: "run_cloud_recon_agent",
    description: `Run the cloud reconnaissance agent.

This agent will autonomously:
1. Enumerate cloud resources using ScoutSuite (EC2, S3, Lambda, RDS, IAM, EKS)
2. Run Prowler security audit with CIS Benchmark mappings
3. Map cloud networking (VPCs, security groups, public IPs)
4. Discover public-facing cloud endpoints (API Gateway, CloudFront, ALB)
5. Analyze IAM policies for overpermissive access
6. Check credential exposure and key rotation
7. Enumerate K8s clusters if in scope
8. Verify security logging configuration

Outputs: cloud_inventory, iam_findings, network_map, k8s_inventory for cloud-exploit agent.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Cloud account IDs from scope.yml (e.g., ['aws-staging'])",
        },
        providers: {
          type: "array",
          items: { type: "string" },
          description: "Cloud providers to test: aws, azure, gcp (default: all in scope)",
        },
        kubernetes_clusters: {
          type: "array",
          items: { type: "string" },
          description: "K8s cluster IDs from scope.yml (default: all in scope)",
        },
      },
    },
  },
  {
    name: "run_cloud_exploit_agent",
    description: `Run the cloud exploitation agent.

This agent will autonomously:
1. Attempt IAM privilege escalation using PMapper and Pacu
2. Test cross-account trust abuse
3. Exploit storage misconfigurations and access sensitive data
4. Read secrets from cloud secrets management services
5. Test Lambda/serverless security (env vars, event injection)
6. Test API Gateway auth bypass
7. Test container registry security
8. Attempt K8s secrets extraction and container escape
9. Test log tampering capability

Requires cloud-recon output for targeting. Non-destructive exploitation only.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Cloud account IDs from scope.yml",
        },
        cloud_inventory: {
          type: "object",
          description: "Cloud inventory from cloud-recon agent (optional — pulls from context)",
        },
        iam_findings: {
          type: "array",
          items: { type: "object" },
          description: "IAM findings from cloud-recon (optional — pulls from context)",
        },
      },
    },
  },
  {
    name: "resume_assessment",
    description: "Resume a paused, failed, or cancelled assessment from its last checkpoint. The orchestrator will skip already-completed agents and continue from where it left off.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: {
          type: "string",
          description: "Assessment ID to resume",
        },
      },
      required: ["assessment_id"],
    },
  },
  {
    name: "pause_assessment",
    description: "Pause a running assessment. Saves a checkpoint so it can be resumed later with resume_assessment.",
    inputSchema: {
      type: "object",
      properties: {
        assessment_id: {
          type: "string",
          description: "Assessment ID to pause",
        },
      },
      required: ["assessment_id"],
    },
  },
  {
    name: "get_agent_status",
    description: "Get the current status of a running agent execution.",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "Agent execution ID (returned when agent is started)",
        },
      },
      required: ["agent_id"],
    },
  },
  {
    name: "cancel_agent",
    description: "Cancel a running agent execution.",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "Agent execution ID to cancel",
        },
      },
      required: ["agent_id"],
    },
  },
  {
    name: "list_running_agents",
    description: "List all currently running agent executions.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// ==================== Handler Imports ====================
// These will be populated as we implement each agent

// Placeholder for orchestrator - will be imported when created
let Orchestrator: any = null;

// Placeholder for agent implementations - will be imported when created
let ReconAgentImpl: any = null;
let VulnScanAgentImpl: any = null;
let WebAppAgentImpl: any = null;
let ExploitAgentImpl: any = null;
let SecurityScanAgentImpl: any = null;
let QaAgentImpl: any = null;
let ReportAgentImpl: any = null;
let CodeIntelAgentImpl: any = null;
let AuthAgentImpl: any = null;
let ApiSecurityAgentImpl: any = null;
let InfraSecurityAgentImpl: any = null;
let ComplianceAgentImpl: any = null;
let ChainAnalysisAgentImpl: any = null;

// Dynamic imports to avoid circular dependencies
async function loadAgentImplementations() {
  try {
    const orchestratorModule = await import("../agents/orchestrator");
    Orchestrator = orchestratorModule.Orchestrator;
  } catch (e) {
    console.warn("Orchestrator not yet implemented");
  }

  try {
    const reconModule = await import("../agents/impl/recon-agent-impl");
    ReconAgentImpl = reconModule.ReconAgentImpl;
  } catch (e) {
    console.warn("ReconAgentImpl not yet implemented");
  }

  try {
    const vulnModule = await import("../agents/impl/vuln-scan-agent-impl");
    VulnScanAgentImpl = vulnModule.VulnScanAgentImpl;
  } catch (e) {
    console.warn("VulnScanAgentImpl not yet implemented");
  }

  try {
    const webModule = await import("../agents/impl/web-app-agent-impl");
    WebAppAgentImpl = webModule.WebAppAgentImpl;
  } catch (e) {
    console.warn("WebAppAgentImpl not yet implemented");
  }

  try {
    const exploitModule = await import("../agents/impl/exploit-agent-impl");
    ExploitAgentImpl = exploitModule.ExploitAgentImpl;
  } catch (e) {
    console.warn("ExploitAgentImpl not yet implemented");
  }

  try {
    const securityModule = await import("../agents/impl/security-scan-agent-impl");
    SecurityScanAgentImpl = securityModule.SecurityScanAgentImpl;
  } catch (e) {
    console.warn("SecurityScanAgentImpl not yet implemented");
  }

  try {
    const qaModule = await import("../agents/impl/qa-agent-impl");
    QaAgentImpl = qaModule.QaAgentImpl;
  } catch (e) {
    console.warn("QaAgentImpl not yet implemented");
  }

  try {
    const reportModule = await import("../agents/impl/report-agent-impl");
    ReportAgentImpl = reportModule.ReportAgentImpl;
  } catch (e) {
    console.warn("ReportAgentImpl not yet implemented");
  }

  try {
    const codeIntelModule = await import("../agents/impl/code-intel-agent-impl");
    CodeIntelAgentImpl = codeIntelModule.CodeIntelAgentImpl;
  } catch (e) {
    console.warn("CodeIntelAgentImpl not yet implemented");
  }

  try {
    const authModule = await import("../agents/impl/auth-agent-impl");
    AuthAgentImpl = authModule.AuthAgentImpl;
  } catch (e) {
    console.warn("AuthAgentImpl not yet implemented");
  }

  try {
    const apiSecModule = await import("../agents/impl/api-security-agent-impl");
    ApiSecurityAgentImpl = apiSecModule.ApiSecurityAgentImpl;
  } catch (e) {
    console.warn("ApiSecurityAgentImpl not yet implemented");
  }

  try {
    const infraSecModule = await import("../agents/impl/infra-security-agent-impl");
    InfraSecurityAgentImpl = infraSecModule.InfraSecurityAgentImpl;
  } catch (e) {
    console.warn("InfraSecurityAgentImpl not yet implemented");
  }

  try {
    const complianceModule = await import("../agents/impl/compliance-agent-impl");
    ComplianceAgentImpl = complianceModule.ComplianceAgentImpl;
  } catch (e) {
    console.warn("ComplianceAgentImpl not yet implemented");
  }

  try {
    const chainModule = await import("../agents/impl/chain-analysis-agent-impl");
    ChainAnalysisAgentImpl = chainModule.ChainAnalysisAgentImpl;
  } catch (e) {
    console.warn("ChainAnalysisAgentImpl not yet implemented");
  }
}

// Load implementations on module load
loadAgentImplementations();

// ==================== Tool Handlers ====================

export const agentHandlers: Record<string, Function> = {
  run_orchestrator: async (args: {
    mode: "full" | "selective" | "pipelined" | "dual-track" | "extreme" | "sequential";
    agents?: AgentName[];
    targets?: string[];
    repo_paths?: string[];
    severity?: Severity;
    jira_project?: string;
    email_recipients?: string[];
    assessment_config?: Record<string, any>;
    /** Run options threaded into the deterministic pipeline — notably scan auth
     *  (options.auth = {type:"bearer", token}) and scope. The orchestrator reads
     *  config.options; without this the auth-gated tests silently skip. */
    options?: Record<string, any>;
    /** 'manual' (default) | 'scheduled' | 'ci' — stamped onto the recorded
     *  scans row. The schedule executor passes "scheduled". */
    trigger_kind?: "manual" | "scheduled" | "ci";
  }) => {
    // Ensure implementations are loaded
    await loadAgentImplementations();

    if (!Orchestrator) {
      return JSON.stringify({
        error: "Orchestrator not yet implemented",
        message: "The orchestrator agent has not been implemented yet.",
      });
    }

    // Auto-upgrade: when mode is "full" and both targets + repo_paths are provided,
    // upgrade to dual-track for better separation of DAST/SAST findings
    let effectiveMode = args.mode;
    if (
      args.mode === "full" &&
      args.targets?.length &&
      args.repo_paths?.length
    ) {
      effectiveMode = "dual-track";
      console.log("[agent-tools] Auto-upgrading from 'full' to 'dual-track' (both targets and repo_paths provided)");
    }

    const execId = `orchestrator-${Date.now()}`;
    console.log(`[agent-tools] Starting orchestrator: ${execId} (mode: ${effectiveMode})`);

    const orchestrator = new Orchestrator((agentName: string, state: AgentState) => {
      console.log(`[${agentName}] ${state.currentStep} - ${state.progress}%`);
      // Update running agent state
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state.currentStep = `[${agentName}] ${state.currentStep}`;
        existing.state.progress = state.progress;
      }
    });

    // Store for status checking
    runningAgents.set(execId, {
      state: {
        id: execId,
        agentName: "orchestrator",
        status: "running",
        startedAt: new Date().toISOString(),
        currentStep: "Starting",
        progress: 0,
        findings: [],
        errors: [],
        toolCallsCount: 0,
        iterations: 0,
        context: {},
      },
      cancel: () => orchestrator.cancel(),
    });

    const config = {
      assessmentId: execId,
      targets: args.targets,
      repoPaths: args.repo_paths,
      severity: args.severity,
      jiraProject: args.jira_project,
      emailRecipients: args.email_recipients,
      assessmentConfig: args.assessment_config,
      // Threaded into runDeterministic → pipelineConfig.auth/scope (scan auth, etc.)
      options: args.options ?? args.assessment_config,
      // 'manual' (default) | 'scheduled' | 'ci' — stamped onto the scans row so
      // scheduled-DAST runs are distinguishable from ad-hoc ones. The schedule
      // executor passes trigger_kind: "scheduled".
      triggerKind: args.trigger_kind,
    };

    try {
      let result;
      if (effectiveMode === "sequential") {
        // Deterministic pipeline — calls tools directly without inner LLM agents
        const allH = await getServerHandlers();
        // Filter out AGENT-level handlers to avoid recursive invocation — but keep
        // the scanner tools. The agent handlers are run_orchestrator + run_*_agent;
        // a blanket `run_` exclusion (the old bug) also stripped run_nuclei /
        // run_nikto / run_sqlmap, so the pipeline silently skipped the main
        // vuln scanners.
        const isAgentHandler = (name: string) =>
          name === "run_orchestrator" ||
          (name.startsWith("run_") && name.endsWith("_agent"));
        const toolHandlers = Object.fromEntries(
          Object.entries(allH).filter(([name]) =>
            !isAgentHandler(name) &&
            !name.startsWith("resume_") &&
            !name.startsWith("pause_") &&
            !name.startsWith("get_agent") &&
            !name.startsWith("cancel_") &&
            !name.startsWith("list_running")
          )
        );
        result = await orchestrator.runDeterministic(config, toolHandlers);
      } else if (effectiveMode === "extreme") {
        result = await orchestrator.runExtreme(config);
      } else if (effectiveMode === "dual-track") {
        result = await orchestrator.runDualTrack(config);
      } else if (effectiveMode === "pipelined") {
        result = await orchestrator.runPipelined(config);
      } else if (effectiveMode === "selective") {
        result = await orchestrator.runSelective({ ...config, agents: args.agents || [] });
      } else {
        result = await orchestrator.runFull(config);
      }

      return JSON.stringify(
        {
          execution_id: execId,
          ...result,
        },
        null,
        2
      );
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_recon_agent: async (args: { targets: string[]; quick_scan?: boolean }) => {
    await loadAgentImplementations();

    if (!ReconAgentImpl) {
      return JSON.stringify({
        error: "ReconAgentImpl not yet implemented",
        message: "The recon agent has not been implemented yet.",
      });
    }

    const execId = `recon-${Date.now()}`;
    console.log(`[agent-tools] Starting recon agent: ${execId}`);

    const agent = new ReconAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        options: { quickScan: args.quick_scan },
      });

      return JSON.stringify(
        {
          execution_id: execId,
          ...result,
        },
        null,
        2
      );
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_vuln_scan_agent: async (args: {
    targets: string[];
    severity?: Severity;
    context?: Record<string, any>;
  }) => {
    await loadAgentImplementations();

    if (!VulnScanAgentImpl) {
      return JSON.stringify({
        error: "VulnScanAgentImpl not yet implemented",
        message: "The vuln-scan agent has not been implemented yet.",
      });
    }

    const execId = `vuln-scan-${Date.now()}`;
    const agent = new VulnScanAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        severity: args.severity,
        context: args.context,
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_web_app_agent: async (args: { targets: string[]; context?: Record<string, any> }) => {
    await loadAgentImplementations();

    if (!WebAppAgentImpl) {
      return JSON.stringify({
        error: "WebAppAgentImpl not yet implemented",
        message: "The web-app agent has not been implemented yet.",
      });
    }

    const execId = `web-app-${Date.now()}`;
    const agent = new WebAppAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: args.context,
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_exploit_agent: async (args: {
    targets: string[];
    vulnerabilities?: Array<{ id: string; title: string; cve?: string; target: string }>;
  }) => {
    await loadAgentImplementations();

    if (!ExploitAgentImpl) {
      return JSON.stringify({
        error: "ExploitAgentImpl not yet implemented",
        message: "The exploit agent has not been implemented yet.",
      });
    }

    const execId = `exploit-${Date.now()}`;
    const agent = new ExploitAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: { vulnerabilities: args.vulnerabilities },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_security_scan_agent: async (args: {
    repo_paths: string[];
    scan_types?: string[];
    severity?: Severity;
  }) => {
    await loadAgentImplementations();

    if (!SecurityScanAgentImpl) {
      return JSON.stringify({
        error: "SecurityScanAgentImpl not yet implemented",
        message: "The security-scan agent has not been implemented yet.",
      });
    }

    const execId = `security-scan-${Date.now()}`;
    const agent = new SecurityScanAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        repoPaths: args.repo_paths,
        severity: args.severity,
        options: { scanTypes: args.scan_types },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_qa_agent: async (args: {
    targets?: string[];
    findings?: any[];
    agent_results?: Record<string, any>;
  }) => {
    await loadAgentImplementations();

    if (!QaAgentImpl) {
      return JSON.stringify({
        error: "QaAgentImpl not yet implemented",
        message: "The QA agent has not been implemented yet.",
      });
    }

    const execId = `qa-${Date.now()}`;
    console.log(`[agent-tools] Starting QA agent: ${execId}`);

    const agent = new QaAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: {
          findings: args.findings || [],
          agentResults: args.agent_results || {},
        },
      });

      return JSON.stringify(
        {
          execution_id: execId,
          ...result,
        },
        null,
        2
      );
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_report_agent: async (args: {
    format: "markdown" | "html" | "json";
    findings?: any[];
    jira_project?: string;
    email_recipients?: string[];
    upload_sharepoint?: boolean;
  }) => {
    await loadAgentImplementations();

    if (!ReportAgentImpl) {
      return JSON.stringify({
        error: "ReportAgentImpl not yet implemented",
        message: "The report agent has not been implemented yet.",
      });
    }

    const execId = `report-${Date.now()}`;
    const agent = new ReportAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        options: {
          format: args.format,
          jiraProject: args.jira_project,
          emailRecipients: args.email_recipients,
          uploadSharepoint: args.upload_sharepoint,
        },
        context: { findings: args.findings },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_code_intel_agent: async (args: {
    repo_paths: string[];
    framework?: string;
  }) => {
    await loadAgentImplementations();

    if (!CodeIntelAgentImpl) {
      return JSON.stringify({
        error: "CodeIntelAgentImpl not yet implemented",
        message: "The code-intel agent has not been implemented yet.",
      });
    }

    const execId = `code-intel-${Date.now()}`;
    console.log(`[agent-tools] Starting code-intel agent: ${execId}`);

    const agent = new CodeIntelAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        repoPaths: args.repo_paths,
        options: { framework: args.framework },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_auth_agent: async (args: {
    targets: string[];
    assessment_config?: Record<string, any>;
  }) => {
    await loadAgentImplementations();

    if (!AuthAgentImpl) {
      return JSON.stringify({
        error: "AuthAgentImpl not yet implemented",
        message: "The auth agent has not been implemented yet.",
      });
    }

    const execId = `auth-${Date.now()}`;
    console.log(`[agent-tools] Starting auth agent: ${execId}`);

    const agent = new AuthAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: {
          assessmentConfig: args.assessment_config,
        },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_api_security_agent: async (args: {
    targets: string[];
    context?: Record<string, any>;
  }) => {
    await loadAgentImplementations();

    if (!ApiSecurityAgentImpl) {
      return JSON.stringify({
        error: "ApiSecurityAgentImpl not yet implemented",
        message: "The API security agent has not been implemented yet.",
      });
    }

    const execId = `api-security-${Date.now()}`;
    console.log(`[agent-tools] Starting API security agent: ${execId}`);

    const agent = new ApiSecurityAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: args.context,
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_infra_security_agent: async (args: { targets: string[] }) => {
    await loadAgentImplementations();

    if (!InfraSecurityAgentImpl) {
      return JSON.stringify({
        error: "InfraSecurityAgentImpl not yet implemented",
        message: "The infrastructure security agent has not been implemented yet.",
      });
    }

    const execId = `infra-security-${Date.now()}`;
    console.log(`[agent-tools] Starting infrastructure security agent: ${execId}`);

    const agent = new InfraSecurityAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_compliance_agent: async (args: { findings?: any[] }) => {
    await loadAgentImplementations();

    if (!ComplianceAgentImpl) {
      return JSON.stringify({
        error: "ComplianceAgentImpl not yet implemented",
        message: "The compliance agent has not been implemented yet.",
      });
    }

    const execId = `compliance-${Date.now()}`;
    console.log(`[agent-tools] Starting compliance agent: ${execId}`);

    const agent = new ComplianceAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        context: {
          findings: args.findings || [],
        },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_chain_analysis_agent: async (args: {
    findings?: any[];
    chain_mode?: string;
    chain_hypotheses?: any[];
    exploit_results?: any[];
  }) => {
    await loadAgentImplementations();

    if (!ChainAnalysisAgentImpl) {
      return JSON.stringify({
        error: "ChainAnalysisAgentImpl not yet implemented",
        message: "The chain analysis agent has not been implemented yet.",
      });
    }

    const execId = `chain-analysis-${Date.now()}`;
    console.log(`[agent-tools] Starting chain analysis agent: ${execId} (mode: ${args.chain_mode || "hypothesize"})`);

    const agent = new ChainAnalysisAgentImpl((state: AgentState) => {
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state = state;
      }
    });

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        context: {
          findings: args.findings || [],
          chainMode: args.chain_mode || "hypothesize",
          chainHypotheses: args.chain_hypotheses || [],
          exploitResults: args.exploit_results || [],
        },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_cloud_recon_agent: async (args: {
    targets?: string[];
    providers?: string[];
    kubernetes_clusters?: string[];
  }) => {
    await loadAgentImplementations();

    const { CloudReconAgentImpl } = await import("../agents/impl/cloud-recon-agent-impl");

    const execId = `cloud-recon-${Date.now()}`;
    console.log(`[agent-tools] Starting cloud recon agent: ${execId}`);

    const agent = new CloudReconAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: {
          providers: args.providers || ["aws", "azure", "gcp"],
          kubernetes_clusters: args.kubernetes_clusters || [],
        },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  run_cloud_exploit_agent: async (args: {
    targets?: string[];
    cloud_inventory?: any;
    iam_findings?: any[];
  }) => {
    await loadAgentImplementations();

    const { CloudExploitAgentImpl } = await import("../agents/impl/cloud-exploit-agent-impl");

    const execId = `cloud-exploit-${Date.now()}`;
    console.log(`[agent-tools] Starting cloud exploit agent: ${execId}`);

    const agent = new CloudExploitAgentImpl();

    runningAgents.set(execId, {
      state: agent.getState(),
      cancel: () => agent.cancel(),
    });

    try {
      const result = await agent.execute({
        targets: args.targets,
        context: {
          cloud_inventory: args.cloud_inventory || {},
          iam_findings: args.iam_findings || [],
        },
      });

      return JSON.stringify({ execution_id: execId, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  resume_assessment: async (args: { assessment_id: string }) => {
    await loadAgentImplementations();

    if (!Orchestrator) {
      return JSON.stringify({
        error: "Orchestrator not yet implemented",
        message: "The orchestrator has not been implemented yet.",
      });
    }

    const execId = `resume-${args.assessment_id}-${Date.now()}`;
    console.log(`[agent-tools] Resuming assessment: ${args.assessment_id}`);

    const orchestrator = new Orchestrator((agentName: string, state: AgentState) => {
      console.log(`[${agentName}] ${state.currentStep} - ${state.progress}%`);
      const existing = runningAgents.get(execId);
      if (existing) {
        existing.state.currentStep = `[${agentName}] ${state.currentStep}`;
        existing.state.progress = state.progress;
      }
    });

    runningAgents.set(execId, {
      state: {
        id: execId,
        agentName: "orchestrator",
        status: "running",
        startedAt: new Date().toISOString(),
        currentStep: "Resuming from checkpoint",
        progress: 0,
        findings: [],
        errors: [],
        toolCallsCount: 0,
        iterations: 0,
        context: {},
      },
      cancel: () => orchestrator.cancel(),
    });

    try {
      const result = await orchestrator.resume(args.assessment_id);
      return JSON.stringify({ execution_id: execId, resumed_from: args.assessment_id, ...result }, null, 2);
    } finally {
      runningAgents.delete(execId);
    }
  },

  pause_assessment: async (args: { assessment_id: string }) => {
    // Find the running orchestrator for this assessment
    for (const [id, agent] of runningAgents.entries()) {
      if (
        id.includes(args.assessment_id) ||
        agent.state.agentName === "orchestrator"
      ) {
        agent.cancel();
        return JSON.stringify({
          success: true,
          message: `Assessment ${args.assessment_id} pause requested. A checkpoint will be saved.`,
          execution_id: id,
        });
      }
    }

    return JSON.stringify({
      error: "Assessment not found",
      message: `No running assessment with ID: ${args.assessment_id}`,
    });
  },

  get_agent_status: async (args: { agent_id: string }) => {
    const agent = runningAgents.get(args.agent_id);

    if (!agent) {
      return JSON.stringify({
        error: "Agent not found",
        message: `No running agent with ID: ${args.agent_id}`,
        hint: "The agent may have completed or the ID may be incorrect",
      });
    }

    return JSON.stringify(
      {
        id: args.agent_id,
        status: agent.state.status,
        currentStep: agent.state.currentStep,
        progress: agent.state.progress,
        findingsCount: agent.state.findings.length,
        toolCallsCount: agent.state.toolCallsCount,
        iterations: agent.state.iterations,
        errors: agent.state.errors,
      },
      null,
      2
    );
  },

  cancel_agent: async (args: { agent_id: string }) => {
    const agent = runningAgents.get(args.agent_id);

    if (!agent) {
      return JSON.stringify({
        error: "Agent not found",
        message: `No running agent with ID: ${args.agent_id}`,
      });
    }

    agent.cancel();

    return JSON.stringify({
      success: true,
      message: `Agent ${args.agent_id} cancellation requested`,
      status: "cancelled",
    });
  },

  list_running_agents: async () => {
    const agents = Array.from(runningAgents.entries()).map(([id, agent]) => ({
      id,
      agentName: agent.state.agentName,
      status: agent.state.status,
      progress: agent.state.progress,
      currentStep: agent.state.currentStep,
      startedAt: agent.state.startedAt,
    }));

    return JSON.stringify(
      {
        count: agents.length,
        agents,
      },
      null,
      2
    );
  },
};
