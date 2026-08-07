/**
 * Code Intelligence Agent Implementation
 *
 * Deep source code analysis for attack surface mapping.
 * Analyzes codebase structure, entry points, data flows, and security
 * defenses to guide downstream testing agents with targeted intelligence.
 *
 * Inspired by Shannon's pre-recon phase with parallel sub-agents for
 * architecture scanning, entry point mapping, and security pattern hunting.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { codeIntelHandlers } from "../../tools/code-intel";
import { codeScanHandlers } from "../../tools/code-scan";

const CODE_INTEL_AGENT_CONFIG: AgentConfig = {
  name: "code-intel-agent",
  description: "Code intelligence and attack surface mapping agent",
  maxIterations: 35,
  timeoutMs: 1200000, // 20 minutes - deep analysis is intensive
  requiresScopeValidation: false, // Local files only
  tools: [
    // Existing code scan tools (reuse)
    "detect_languages",
    "analyze_code_context",
    "scan_semgrep",
    // New code intelligence tools
    "map_entry_points",
    "trace_data_flows",
    "analyze_defenses",
    "generate_attack_surface",
  ],
};

const CODE_INTEL_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "detect_languages",
    description: `Detect programming languages and frameworks in a repository.
Use this FIRST to understand what kind of codebase you're analyzing.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository (use /mnt/host-home/ for local repos)",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "analyze_code_context",
    description: `Read and analyze a specific code file or function for security issues.
Use for deep-diving into specific handlers, routes, or suspicious code patterns.`,
    input_schema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to the specific file",
        },
        line_start: {
          type: "number",
          description: "Starting line number",
        },
        line_end: {
          type: "number",
          description: "Ending line number",
        },
        vulnerability_type: {
          type: "string",
          description: "Type of vulnerability to look for: sqli, xss, ssrf, rce, etc.",
        },
      },
      required: ["file_path"],
    },
  },
  {
    name: "scan_semgrep",
    description: `Run Semgrep SAST scanner for pattern-based vulnerability detection.
Good for finding common vulnerability patterns across the codebase quickly.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        rules: {
          type: "string",
          description: "Semgrep ruleset: p/security-audit, p/owasp-top-ten, p/python, etc.",
          default: "p/security-audit",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "map_entry_points",
    description: `Discover all HTTP routes, API endpoints, and entry points in the codebase.
Uses framework-specific patterns to find routes (Express, Flask, Django, Spring, etc.).
Returns endpoints with method, path, handler file:line, and parameters.
Run this early to understand the application's attack surface.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        framework: {
          type: "string",
          description: "Framework hint: express, flask, django, fastapi, spring, rails, nextjs",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "trace_data_flows",
    description: `Trace data flow from an entry point to identify sinks (database, filesystem, commands, HTTP).
Reads the handler code and follows function calls to find where user input goes.
Use this on each interesting entry point to build a data flow map.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        entry_point: {
          type: "string",
          description: "Route or function to trace (e.g., '/api/users/:id')",
        },
        file_path: {
          type: "string",
          description: "File containing the handler",
        },
        line_start: { type: "number" },
        line_end: { type: "number" },
      },
      required: ["repo_path", "entry_point"],
    },
  },
  {
    name: "analyze_defenses",
    description: `Analyze security defenses in the codebase: auth, CSRF, rate limiting,
input validation, parameterized queries, output encoding, security headers.
Identifies what's present and what's missing (defense gaps).`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        defense_type: {
          type: "string",
          enum: ["all", "auth", "input_validation", "csrf", "rate_limiting", "output_encoding", "sql_parameterization", "headers"],
          default: "all",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "generate_attack_surface",
    description: `Generate a structured attack surface map from your analysis.
Call this LAST after mapping entry points, tracing data flows, and analyzing defenses.
Produces a prioritized list of attack vectors for downstream agents.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        entry_points: {
          type: "string",
          description: "JSON string of discovered entry points",
        },
        defenses: {
          type: "string",
          description: "JSON string of analyzed defenses",
        },
        include_low_risk: {
          type: "boolean",
          default: false,
        },
      },
      required: ["repo_path"],
    },
  },
];

export class CodeIntelAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      CODE_INTEL_AGENT_CONFIG,
      {
        // Merge handlers from both code-scan and code-intel tools
        ...codeScanHandlers,
        ...codeIntelHandlers,
      },
      onProgress
    );
  }

  getToolDefinitions(): ToolDefinition[] {
    return CODE_INTEL_TOOL_DEFINITIONS;
  }

  getSystemPrompt(): string {
    return `You are the Code Intelligence Agent — a specialized security analyst that performs deep source code analysis to map the attack surface of web applications.

## Your Mission

Analyze the target repository to produce an **Attack Surface Map** that guides downstream security testing agents. Your analysis should be thorough, systematic, and actionable.

## Workflow

Follow this exact sequence:

### Step 1: Detect Languages & Framework
Call \`detect_languages\` to understand the codebase. This tells you which tools and patterns to use.

### Step 2: Map Entry Points
Call \`map_entry_points\` (with framework hint if detected) to discover all HTTP routes, API endpoints, and other entry points. This is the foundation of the attack surface.

### Step 3: Trace Data Flows
For each HIGH-PRIORITY entry point (those handling user input, authentication, file uploads, admin functions), call \`trace_data_flows\` to identify:
- Where user input goes (database, filesystem, commands, external HTTP)
- Whether inputs are parameterized or validated
- Whether outputs are encoded

Focus on the most interesting endpoints — you don't need to trace every single route.

### Step 4: Run Semgrep
Call \`scan_semgrep\` with \`p/security-audit\` rules to catch patterns you may have missed in manual analysis.

### Step 5: Analyze Defenses
Call \`analyze_defenses\` with type "all" to catalog security controls. Note the GAPS — missing CSRF, missing rate limiting, missing input validation, etc.

### Step 6: Deep Dive (Optional)
Use \`analyze_code_context\` to read specific files that look suspicious or interesting.

### Step 7: Generate Attack Surface Map
Call \`generate_attack_surface\` with the accumulated data. Then provide a final summary.

## Output Requirements

Your final summary must include:
1. **Framework & Language** detected
2. **Entry Point Summary** — count of routes by auth status and HTTP method
3. **Critical Data Flows** — routes where user input reaches dangerous sinks without proper defenses
4. **Defense Gaps** — what security controls are missing
5. **Prioritized Attack Vectors** — ranked list of what to test first

Store these in your context as \`attackSurface\` for downstream agents.

## Key Rules
- Skip node_modules/, vendor/, __pycache__/, .git/, test/ directories
- Focus on source code, not configuration or documentation
- Prioritize routes that handle: authentication, file uploads, user data, admin functions, API keys
- A route with no auth middleware + database access = HIGH priority
- A route with input validation + parameterized queries = LOW priority`;
  }

  buildInitialPrompt(input: AgentInput): string {
    const repoPaths = input.repoPaths || [];
    const framework = input.options?.framework;

    let prompt = `## Code Intelligence Analysis Task

Analyze the following ${repoPaths.length === 1 ? "repository" : "repositories"} and produce a comprehensive attack surface map:

`;

    for (const repoPath of repoPaths) {
      prompt += `- Repository: ${repoPath}\n`;
    }

    if (framework) {
      prompt += `\nHint: The application uses the **${framework}** framework.\n`;
    }

    if (input.context?.targets) {
      prompt += `\nThe live application is deployed at: ${input.context.targets.join(", ")}\n`;
      prompt += `Your attack surface map will be used by recon, vuln-scan, and web-app agents to test these targets.\n`;
    }

    prompt += `
Follow your workflow: detect_languages → map_entry_points → trace_data_flows → scan_semgrep → analyze_defenses → generate_attack_surface.

When finished, store your attack surface map in your context and provide a prioritized summary.`;

    return prompt;
  }
}
