/**
 * Autonomous Security Assessment Runner
 *
 * This module enables fully automated security assessments triggered by:
 * - N8N workflows
 * - Scheduled cron jobs
 * - Webhook events (e.g., Cycode CSV upload)
 *
 * It uses the Anthropic API for intelligent decision-making.
 */

import Anthropic from "@anthropic-ai/sdk";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";

// LLM Configuration interface
interface LLMConfig {
  provider: "anthropic";
  anthropic?: {
    model: string;
    apiKey?: string;
  };
}

// Load LLM config from file or environment
function loadLLMConfig(): LLMConfig {
  const configPath = path.join(__dirname, "../../config/llm-config.yml");

  let config: LLMConfig = {
    provider: "anthropic",
    anthropic: { model: "claude-sonnet-4-20250514" },
  };

  try {
    const fileContent = fs.readFileSync(configPath, "utf-8");
    const parsed = yaml.load(fileContent) as any;
    config = {
      provider: process.env.LLM_PROVIDER as any || parsed.provider || "anthropic",
      anthropic: {
        model: process.env.ANTHROPIC_MODEL || parsed.anthropic?.model || "claude-sonnet-4-20250514",
        apiKey: process.env.ANTHROPIC_API_KEY || parsed.anthropic?.apiKey,
      },
    };
  } catch (e) {
    console.log("[LLM Config] Using defaults, config file not found");
  }

  return config;
}

// Import all tool handlers
import { reconHandlers } from "./tools/recon";
import { vulnScanHandlers } from "./tools/vuln-scan";
import { webAppHandlers } from "./tools/web-app";
import { exploitHandlers } from "./tools/exploit";
import { reportingHandlers } from "./tools/reporting";
import { codeScanHandlers } from "./tools/code-scan";
import { validateScope } from "./scope/validator";
import { validateToolScope } from "./scope/tool-scope";
import { logCommand } from "./logging/audit-logger";
import { runWithToolContext } from "./logging/tool-provenance";
import { emitProgress } from "./progress";
import { captureScopeDecision } from "./logging/test-results-store";
import { pulseAssessmentHeartbeat } from "./integrations/assessment-heartbeat";
import { runWithHandlerContext } from "./scope/handler-context";
import { initializeDatabase } from "./logging/log-store";
import { loadScopeConfig } from "./scope/scope-config";

// Full tool surface — used by the HTTP `/tools` + `/tools/call` endpoints
// the Tauri desktop hits. STDIO-MCP exposes the same set via `setupTools()`.
import {
  allTools as serverAllTools,
  allHandlers as serverAllHandlers,
  LOCAL_ONLY_TOOLS,
} from "./server";

// LLM-facing handler subset. The autonomous-runner's inner LLM loop only
// calls these — `toolDefinitions` below is the matching tool list passed
// to Claude in the inference call. This stays curated on purpose so the
// LLM's working set is small and predictable; widening it changes LLM
// behavior. The HTTP endpoints use the full `serverAllHandlers` instead.
const allHandlers: Record<string, Function> = {
  ...reconHandlers,
  ...vulnScanHandlers,
  ...webAppHandlers,
  ...exploitHandlers,
  ...reportingHandlers,
  ...codeScanHandlers,
};

// Tool definitions for Claude
const toolDefinitions = [
  {
    name: "scan_ports",
    description: "Scan ports on a target using nmap",
    input_schema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target IP or hostname" },
        ports: { type: "string", description: "Port specification" },
        scan_type: { type: "string", enum: ["quick", "full", "stealth"] },
      },
      required: ["target"],
    },
  },
  {
    name: "enumerate_subdomains",
    description: "Find subdomains for a domain",
    input_schema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain" },
        passive_only: { type: "boolean", default: true },
      },
      required: ["domain"],
    },
  },
  {
    name: "run_nuclei",
    description: "Run nuclei vulnerability scanner",
    input_schema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL" },
        templates: { type: "string", default: "cve,owasp-top-ten" },
        severity: { type: "string", default: "medium,high,critical" },
      },
      required: ["target"],
    },
  },
  {
    name: "run_sqlmap",
    description: "Test for SQL injection (non-destructive)",
    input_schema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL with parameters" },
        method: { type: "string", enum: ["GET", "POST"], default: "GET" },
        level: { type: "number", default: 2 },
        risk: { type: "number", default: 1 },
      },
      required: ["target"],
    },
  },
  {
    name: "scan_repository",
    description: "Scan local repository for vulnerabilities",
    input_schema: {
      type: "object",
      properties: {
        repo_path: { type: "string", description: "Path to repository" },
        scan_types: { type: "array", items: { type: "string" }, default: ["all"] },
        severity_threshold: { type: "string", default: "medium" },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "create_finding",
    description: "Create a security finding record",
    input_schema: {
      type: "object",
      properties: {
        title: { type: "string" },
        severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
        description: { type: "string" },
        target: { type: "string" },
        evidence: { type: "string" },
        remediation: { type: "string" },
      },
      required: ["title", "severity", "description", "target"],
    },
  },
  {
    name: "generate_report",
    description: "Generate security assessment report",
    input_schema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["markdown", "html", "json"], default: "markdown" },
        include_evidence: { type: "boolean", default: true },
      },
      required: ["format"],
    },
  },
  {
    name: "create_jira_ticket",
    description: "Create Jira ticket for a finding",
    input_schema: {
      type: "object",
      properties: {
        finding_id: { type: "string" },
        project_key: { type: "string" },
        priority: { type: "string", default: "Medium" },
      },
      required: ["finding_id", "project_key"],
    },
  },
  {
    name: "upload_report",
    description: "Upload report to SharePoint and email",
    input_schema: {
      type: "object",
      properties: {
        report_content: { type: "string" },
        filename: { type: "string" },
        email_recipients: { type: "array", items: { type: "string" } },
      },
      required: ["report_content", "filename"],
    },
  },
];

interface AssessmentConfig {
  type: "full" | "recon" | "vuln_scan" | "web_app" | "code_scan" | "cycode_validation";
  targets?: string[];
  repo_paths?: string[];
  cycode_csv?: string;
  jira_project?: string;
  email_recipients?: string[];
  severity_threshold?: string;
}

interface AssessmentResult {
  success: boolean;
  findings_count: number;
  critical_count: number;
  high_count: number;
  report_url?: string;
  jira_tickets?: string[];
  error?: string;
}

export class AutonomousRunner {
  private anthropicClient: Anthropic | null = null;
  private llmConfig: LLMConfig;
  private systemPrompt: string;

  constructor() {
    this.llmConfig = loadLLMConfig();

    if (this.llmConfig.provider === "anthropic") {
      this.anthropicClient = new Anthropic({
        apiKey: this.llmConfig.anthropic?.apiKey,
      });
    }

    console.log(`[Autonomous Runner] Using LLM provider: ${this.llmConfig.provider}`);

    this.systemPrompt = this.loadSystemPrompt();
  }


  private loadSystemPrompt(): string {
    // Load CLAUDE.md as system prompt
    const claudeMdPath = path.join(__dirname, "../../CLAUDE.md");
    let prompt = "";
    
    try {
      prompt = fs.readFileSync(claudeMdPath, "utf-8");
    } catch (e) {
      prompt = "You are a security assessment AI.";
    }
    
    // Add autonomous-specific instructions
    prompt += `

## Autonomous Mode Instructions

You are running in FULLY AUTONOMOUS mode. There is no human in the loop.

Your job is to:
1. Execute a complete security assessment based on the provided configuration
2. Make intelligent decisions about what to test and how
3. Adapt your approach based on findings
4. Document all findings properly
5. Generate reports and create Jira tickets for significant issues

Rules:
- ALWAYS validate scope before testing any target
- NEVER execute destructive exploits
- Create findings for all vulnerabilities discovered
- Prioritize critical and high severity issues
- Generate a final report when complete
- Create Jira tickets for HIGH and CRITICAL findings

You have access to security testing tools. Use them systematically.
`;

    return prompt;
  }

  private async executeTool(name: string, args: any): Promise<string> {
    // Scope validation for network tools
    const target = args?.target || args?.domain || args?.cidr;
    const localTools = ["scan_repository", "analyze_code_context", "detect_languages", "create_finding", "generate_report"];
    
    if (target && !localTools.includes(name)) {
      const scopeCheck = await validateScope(target);
      if (!scopeCheck.valid) {
        return JSON.stringify({
          error: "SCOPE_VIOLATION",
          message: `Target "${target}" is not in scope: ${scopeCheck.reason}`,
        });
      }
    }

    // Log the command
    await logCommand({
      tool: name,
      arguments: args,
      target: target || args?.repo_path,
      timestamp: new Date().toISOString(),
      user: "autonomous-runner",
    });

    // Execute the tool
    const handler = allHandlers[name];
    if (!handler) {
      return JSON.stringify({ error: `Unknown tool: ${name}` });
    }

    try {
      const result = await handler(args);
      return typeof result === "string" ? result : JSON.stringify(result);
    } catch (error) {
      return JSON.stringify({ error: String(error) });
    }
  }

  async runAssessment(config: AssessmentConfig): Promise<AssessmentResult> {
    console.log(`[Autonomous Runner] Starting ${config.type} assessment`);
    
    // Build the initial prompt based on assessment type
    let userPrompt = this.buildUserPrompt(config);
    
    const messages: any[] = [
      { role: "user", content: userPrompt },
    ];

    let continueLoop = true;
    let iterations = 0;
    const maxIterations = 50; // Safety limit

    while (continueLoop && iterations < maxIterations) {
      iterations++;
      console.log(`[Autonomous Runner] Iteration ${iterations}`);

      try {
        let response: { content: any[]; stop_reason: string };

        {
          // Anthropic is the only implemented provider.
          if (!this.anthropicClient) {
            throw new Error("Anthropic client not initialized. Set ANTHROPIC_API_KEY.");
          }
          const anthropicResponse = await this.anthropicClient.messages.create({
            model: this.llmConfig.anthropic?.model || "claude-sonnet-4-20250514",
            max_tokens: 4096,
            system: this.systemPrompt,
            tools: toolDefinitions as any,
            messages: messages,
          });
          response = {
            content: anthropicResponse.content as any[],
            stop_reason: anthropicResponse.stop_reason || "end_turn",
          };
        }

        // Process response
        const assistantContent: any[] = [];
        let hasToolUse = false;

        for (const block of response.content) {
          assistantContent.push(block);

          if (block.type === "tool_use") {
            hasToolUse = true;
            console.log(`[Autonomous Runner] Executing tool: ${block.name}`);
            
            const toolResult = await this.executeTool(block.name, block.input);
            
            // Add assistant message and tool result
            messages.push({ role: "assistant", content: assistantContent });
            messages.push({
              role: "user",
              content: [
                {
                  type: "tool_result",
                  tool_use_id: block.id,
                  content: toolResult,
                },
              ],
            });
            
            break; // Process one tool at a time
          }
        }

        // Check if we should continue
        if (response.stop_reason === "end_turn" && !hasToolUse) {
          continueLoop = false;
          messages.push({ role: "assistant", content: assistantContent });
        } else if (!hasToolUse) {
          // No tool use but not end_turn, add message and continue
          messages.push({ role: "assistant", content: assistantContent });
        }

      } catch (error) {
        console.error(`[Autonomous Runner] Error:`, error);
        return {
          success: false,
          findings_count: 0,
          critical_count: 0,
          high_count: 0,
          error: String(error),
        };
      }
    }

    // Extract results from the conversation
    return this.extractResults(messages);
  }

  private buildUserPrompt(config: AssessmentConfig): string {
    let prompt = "";

    switch (config.type) {
      case "full":
        prompt = `Run a FULL security assessment on the following targets:
${config.targets?.map(t => `- ${t}`).join("\n")}

Steps:
1. Run reconnaissance on each target
2. Perform vulnerability scanning
3. Test web applications for OWASP issues
4. Validate critical findings
5. Create findings for all vulnerabilities
6. Generate a comprehensive report
${config.jira_project ? `7. Create Jira tickets in project ${config.jira_project} for HIGH/CRITICAL issues` : ""}
${config.email_recipients?.length ? `8. Email the report to: ${config.email_recipients.join(", ")}` : ""}
`;
        break;

      case "recon":
        prompt = `Run reconnaissance ONLY on:
${config.targets?.map(t => `- ${t}`).join("\n")}

Discover hosts, scan ports, enumerate subdomains, fingerprint services.
Create a summary of all discovered assets.
`;
        break;

      case "vuln_scan":
        prompt = `Run vulnerability scanning on:
${config.targets?.map(t => `- ${t}`).join("\n")}

Use nuclei, nikto, and other scanners.
Minimum severity: ${config.severity_threshold || "medium"}
Create findings for all discovered vulnerabilities.
Generate a report.
`;
        break;

      case "web_app":
        prompt = `Run web application security testing on:
${config.targets?.map(t => `- ${t}`).join("\n")}

Test for SQL injection, XSS, and other OWASP vulnerabilities.
Use authenticated and unauthenticated testing where applicable.
Create findings and generate report.
`;
        break;

      case "code_scan":
        prompt = `Run static code analysis on these repositories:
${config.repo_paths?.map(p => `- ${p}`).join("\n")}

Scan for vulnerabilities, secrets, and dependency issues.
Severity threshold: ${config.severity_threshold || "medium"}
Generate a report of all findings.
`;
        break;

      case "cycode_validation":
        prompt = `Validate these Cycode findings:

${config.cycode_csv}

For each finding:
1. Analyze the vulnerability from the code context
2. Identify the live endpoint if applicable
3. Attempt to validate/exploit the vulnerability
4. Document evidence
5. Create confirmed findings

Generate a validation report.
${config.jira_project ? `Create Jira tickets in ${config.jira_project} for confirmed HIGH/CRITICAL vulnerabilities.` : ""}
`;
        break;
    }

    return prompt;
  }

  private extractResults(messages: any[]): AssessmentResult {
    // Parse conversation to extract results
    // This is a simplified extraction - you could make it more sophisticated
    
    let findings_count = 0;
    let critical_count = 0;
    let high_count = 0;
    let jira_tickets: string[] = [];
    let report_url: string | undefined;

    for (const msg of messages) {
      if (msg.role === "user" && Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === "tool_result") {
            try {
              const result = JSON.parse(block.content);
              
              // Count findings
              if (result.findings_count) {
                findings_count += result.findings_count;
              }
              if (result.summary) {
                critical_count += result.summary.critical || 0;
                high_count += result.summary.high || 0;
              }
              
              // Track Jira tickets
              if (result.ticket_key) {
                jira_tickets.push(result.ticket_key);
              }
              
              // Track report URL
              if (result.sharepoint_url) {
                report_url = result.sharepoint_url;
              }
            } catch (e) {
              // Not JSON, skip
            }
          }
        }
      }
    }

    return {
      success: true,
      findings_count,
      critical_count,
      high_count,
      report_url,
      jira_tickets: jira_tickets.length > 0 ? jira_tickets : undefined,
    };
  }
}

// HTTP endpoint for N8N to call
import express from "express";
import cors from "cors";
import { createApiRouter } from "./api";

export async function createAutonomousServer(port: number = 3001) {
  // Mark this process as the SSE-owning HTTP server so progress emission from
  // tool calls dispatched HERE emits directly onto the local bus (and skips the
  // cross-process forward). The separate STDIO MCP process leaves this unset and
  // forwards its events to us via the /progress ingest route. See progress/emitter.ts.
  process.env.MAESTRO_IS_AUTONOMOUS_RUNNER = "1";
  process.env.AUTONOMOUS_PORT = String(port);

  // Initialize database and config before starting server
  await initializeDatabase();
  await loadScopeConfig();

  const app = express();

  // Enable CORS for frontend
  // In cloud deployments, set CORS_ORIGINS env var (comma-separated)
  const allowedOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS === '*'
      ? '*'
      : process.env.CORS_ORIGINS.split(',').map(o => o.trim())
    : ["http://localhost:3000", "http://127.0.0.1:3000"];

  app.use(cors({
    origin: allowedOrigins,
    credentials: allowedOrigins !== '*',
  }));

  app.use(express.json());

  // Mount the REST API router
  app.use("/api", createApiRouter());

  const runner = new AutonomousRunner();

  // Health check. Still a bare 200 + {status:"ok"} — the desktop's startup gate
  // and any deploy verification only assert on the status code.
  app.get("/health", async (req, res) => {
    const health: Record<string, unknown> = { status: "ok" };
    res.json(health);
  });

  // =========================================================================
  // Tool API — used by Tauri frontend to call MCP tools directly
  // =========================================================================

  // Local-only set comes from server.ts so it stays in sync with the
  // canonical scope-validation rules. The previous hand-maintained list
  // here had drifted (e.g. missing browser_* and most agent tools).
  const localOnlyTools = new Set<string>(LOCAL_ONLY_TOOLS);

  // List all available tools — exposes the full MCP surface (162 tools),
  // not the curated 9-entry `toolDefinitions` (which is LLM-only). Maps
  // each tool's camelCase `inputSchema` to the snake_case `input_schema`
  // the wire format uses.
  app.get("/tools", (_req, res) => {
    const tools = (serverAllTools as Array<{ name: string; description: string; inputSchema: unknown }>).map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.inputSchema ?? {},
    }));
    res.json({ tools });
  });

  // Call a tool by name
  app.post("/tools/call", async (req, res) => {
    const { name, arguments: args } = req.body;

    if (!name) {
      return res.status(400).json({ error: "Missing tool name" });
    }

    // Scope validation (network + identity + cloud + k8s) via the shared
    // validator so this HTTP path can never drift from the STDIO MCP path again.
    const argObj = args as Record<string, unknown> | undefined;
    const target = (argObj?.target || argObj?.domain || argObj?.cidr) as string | undefined;

    const scopeCheck = await validateToolScope(name, argObj, (n) => localOnlyTools.has(n));
    // Capture the scope decision (Option B) for the end-of-run execution overview.
    // Best-effort and target-derived; never affects the validation outcome. Mirrors
    // the STDIO path in server.ts so the two never drift.
    captureScopeDecision(argObj, scopeCheck);
    if (!scopeCheck.valid) {
      return res.status(403).json({ error: scopeCheck.error });
    }

    // Log the command
    await logCommand({
      tool: name,
      arguments: args,
      target: target || (argObj?.repo_path as string) || (argObj?.file_path as string),
      timestamp: new Date().toISOString(),
    });

    // `/tools/call` resolves against the full server.ts handler set so the
    // Tauri frontend can reach every tool (162), not just the LLM-curated
    // subset of `allHandlers`.
    const handler = serverAllHandlers[name];
    if (!handler) {
      return res.status(404).json({ error: `Unknown tool: ${name}` });
    }

    // Live progress for the desktop Assessment View — emit "started" now and a
    // terminal "ok"/"error" below. Mirrors the STDIO path in server.ts.
    const progressTarget = target || (argObj?.repo_path as string) || (argObj?.file_path as string);
    const progressTestId = argObj?.test_id as string | undefined;
    emitProgress({ tool: name, status: "started", target: progressTarget, testId: progressTestId });
    const progressStartedAt = Date.now();

    try {
      // Keep the cloud assessment row alive during active work (throttled) so
      // the 3h stale-run reaper never false-fails a long but live run. Mirrors
      // the STDIO path in server.ts.
      pulseAssessmentHeartbeat();
      // Tag every shell call with the MCP tool / test it ran under (P1 provenance),
      // matching the STDIO path in server.ts so the two never drift.
      const result = await runWithToolContext(
        { tool_name: name, test_id: argObj?.test_id as string | undefined },
        () =>
          // Mirror server.ts: expose the validated in-scope identity_target /
          // ai_target to the handler so identity + AI tools can resolve named
          // credential refs and per-target fields without the LLM passing them.
          // The dimension picks the context slot. Nested inside provenance context.
          runWithHandlerContext(
            scopeCheck.dimension === "ai"
              ? { ai_target: scopeCheck.matched_target }
              : { identity_target: scopeCheck.matched_target },
            () => handler(args)
          )
      );
      emitProgress({ tool: name, status: "ok", target: progressTarget, testId: progressTestId, durationMs: Date.now() - progressStartedAt });
      // Handlers return stringified JSON — parse it back for a clean response
      try {
        const parsed = JSON.parse(result);
        res.json(parsed);
      } catch {
        // If not valid JSON, wrap it
        res.json({ result });
      }
    } catch (error: any) {
      emitProgress({ tool: name, status: "error", target: progressTarget, testId: progressTestId, durationMs: Date.now() - progressStartedAt });
      res.status(500).json({ error: error.message || String(error) });
    }
  });

  // Trigger full assessment
  app.post("/assess/full", async (req, res) => {
    const { targets, jira_project, email_recipients } = req.body;
    
    const result = await runner.runAssessment({
      type: "full",
      targets,
      jira_project,
      email_recipients,
    });
    
    res.json(result);
  });

  // Trigger recon only
  app.post("/assess/recon", async (req, res) => {
    const { targets } = req.body;
    
    const result = await runner.runAssessment({
      type: "recon",
      targets,
    });
    
    res.json(result);
  });

  // Trigger vuln scan
  app.post("/assess/vuln-scan", async (req, res) => {
    const { targets, severity_threshold } = req.body;
    
    const result = await runner.runAssessment({
      type: "vuln_scan",
      targets,
      severity_threshold,
    });
    
    res.json(result);
  });

  // Trigger code scan
  app.post("/assess/code-scan", async (req, res) => {
    const { repo_paths, severity_threshold } = req.body;
    
    const result = await runner.runAssessment({
      type: "code_scan",
      repo_paths,
      severity_threshold,
    });
    
    res.json(result);
  });

  // Trigger Cycode validation
  app.post("/assess/cycode-validate", async (req, res) => {
    const { cycode_csv, jira_project } = req.body;
    
    const result = await runner.runAssessment({
      type: "cycode_validation",
      cycode_csv,
      jira_project,
    });
    
    res.json(result);
  });

  app.listen(port, () => {
    console.log(`Autonomous Runner API listening on port ${port}`);
  });

  return app;
}

// CLI entry point
if (require.main === module) {
  const port = parseInt(process.env.AUTONOMOUS_PORT || "3001");
  createAutonomousServer(port).catch(console.error);
}
