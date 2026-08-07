/**
 * Web Application Agent Implementation
 *
 * OWASP-style testing against web applications, focusing on injection
 * vulnerabilities, authentication issues, and access control problems.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { webAppHandlers } from "../../tools/web-app";
import { browserHandlers } from "../../tools/browser";
import { guidanceHandlers } from "../../tools/guidance";

const WEB_APP_AGENT_CONFIG: AgentConfig = {
  name: "web-app-agent",
  description: "Web application security testing agent (OWASP)",
  maxIterations: 35,
  timeoutMs: 1200000, // 20 minutes
  requiresScopeValidation: true,
  tools: [
    "run_sqlmap", "fuzz_endpoints", "test_xss", "crawl_site",
    // Browser tools for SPA testing, DOM XSS, and auth flows
    "browser_navigate", "browser_click", "browser_fill",
    "browser_screenshot", "browser_evaluate", "browser_get_cookies",
    "browser_set_cookies", "browser_get_content", "browser_wait_for",
    "browser_network_log", "browser_close",
    // Guidance tool for handling blockers
    "request_user_guidance",
  ],
};

const WEB_APP_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "crawl_site",
    description: `Crawl a website to discover all endpoints, forms, and parameters.
Use this FIRST to build a map of the application before testing.`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Base URL to crawl",
        },
        depth: {
          type: "number",
          description: "Crawl depth (default: 3)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "run_sqlmap",
    description: `Test for SQL injection vulnerabilities. NON-DESTRUCTIVE mode only.
Use on endpoints with parameters (query strings, form inputs).
IMPORTANT: Never use --risk > 2 or techniques that could damage data.`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL with parameters (e.g., /page?id=1)",
        },
        method: {
          type: "string",
          enum: ["GET", "POST"],
          description: "HTTP method",
        },
        data: {
          type: "string",
          description: "POST data if method is POST",
        },
        level: {
          type: "number",
          description: "Test level 1-5 (default: 2)",
        },
        risk: {
          type: "number",
          description: "Risk level 1-3 (default: 1, NEVER exceed 2)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_xss",
    description: `Test for Cross-Site Scripting (XSS) vulnerabilities.
Use on endpoints that reflect user input (search, comments, etc).`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL with parameter to test",
        },
        param: {
          type: "string",
          description: "Parameter name to test for XSS",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "fuzz_endpoints",
    description: `Discover hidden endpoints, directories, and files using wordlist fuzzing.
Use to find admin panels, backup files, config files, etc.`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Base URL to fuzz",
        },
        wordlist: {
          type: "string",
          description: "Wordlist: common, big, api, admin (default: common)",
        },
        extensions: {
          type: "string",
          description: "File extensions to try (e.g., 'php,html,js')",
        },
      },
      required: ["target"],
    },
  },
];

// Browser tool definitions available to the web-app agent
const BROWSER_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "browser_navigate",
    description: "Navigate the browser to a URL. Use for SPAs that require JavaScript.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to navigate to" },
        wait_for: { type: "string", description: "CSS selector to wait for after navigation" },
      },
      required: ["url"],
    },
  },
  {
    name: "browser_click",
    description: "Click an element on the current page.",
    input_schema: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector of element" },
        text: { type: "string", description: "Text content to match" },
      },
    },
  },
  {
    name: "browser_fill",
    description: "Fill a form field with text.",
    input_schema: {
      type: "object",
      properties: {
        selector: { type: "string", description: "CSS selector of input" },
        value: { type: "string", description: "Value to fill" },
      },
      required: ["selector", "value"],
    },
  },
  {
    name: "browser_screenshot",
    description: "Take a screenshot for evidence capture. Returns base64 PNG.",
    input_schema: {
      type: "object",
      properties: {
        full_page: { type: "boolean", description: "Capture full page", default: false },
        selector: { type: "string", description: "Screenshot specific element" },
      },
    },
  },
  {
    name: "browser_evaluate",
    description: "Execute JavaScript in the browser. Essential for DOM XSS validation.",
    input_schema: {
      type: "object",
      properties: {
        script: { type: "string", description: "JavaScript code to evaluate" },
      },
      required: ["script"],
    },
  },
  {
    name: "browser_get_cookies",
    description: "Get all cookies for session analysis and security auditing.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "browser_set_cookies",
    description: "Set cookies for authenticated testing or session manipulation.",
    input_schema: {
      type: "object",
      properties: {
        cookies: {
          type: "array",
          items: {
            type: "object",
            properties: { name: { type: "string" }, value: { type: "string" }, domain: { type: "string" } },
            required: ["name", "value"],
          },
        },
      },
      required: ["cookies"],
    },
  },
  {
    name: "browser_get_content",
    description: "Get page content as HTML or text. Check for reflected XSS in DOM.",
    input_schema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["html", "text"], default: "text" },
        selector: { type: "string", description: "Get content of specific element" },
      },
    },
  },
  {
    name: "browser_wait_for",
    description: "Wait for an element state. Use after form submissions.",
    input_schema: {
      type: "object",
      properties: {
        selector: { type: "string" },
        state: { type: "string", enum: ["visible", "hidden", "attached", "detached"], default: "visible" },
      },
    },
  },
  {
    name: "browser_network_log",
    description: "Get captured network requests. Reveals hidden API endpoints in SPAs.",
    input_schema: {
      type: "object",
      properties: {
        filter: { type: "string", description: "URL pattern regex to filter" },
      },
    },
  },
  {
    name: "browser_close",
    description: "Close browser session and clear all state. Do NOT call this during a multi-phase assessment.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "request_user_guidance",
    description:
      "Ask the user for help when blocked by a CAPTCHA, MFA challenge, login wall, or complex form you can't handle. " +
      "Takes a screenshot to show the user what you're seeing. The agent pauses until the user responds.",
    input_schema: {
      type: "object",
      properties: {
        situation: { type: "string", description: "What you're blocked on and what you need" },
        screenshot: { type: "boolean", description: "Take screenshot to show user", default: true },
        options: { type: "array", items: { type: "string" }, description: "Suggested actions" },
      },
      required: ["situation"],
    },
  },
];

export class WebAppAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      WEB_APP_AGENT_CONFIG,
      { ...webAppHandlers, ...browserHandlers, ...guidanceHandlers },
      onProgress
    );
  }

  getToolDefinitions(): ToolDefinition[] {
    return [...WEB_APP_TOOL_DEFINITIONS, ...BROWSER_TOOL_DEFINITIONS];
  }

  buildInitialPrompt(input: AgentInput): string {
    // Branch on cross-validation mode
    if (input.context?.crossValidationMode && input.context?.crossValidationTargets?.length) {
      return this.buildCrossValidationPrompt(input);
    }

    // Default: standard web app testing
    let prompt = `# Web Application Security Testing Task

You are the Web App Agent. Your mission is to test web applications for OWASP vulnerabilities.

## Targets to Test:
`;

    if (input.targets && input.targets.length > 0) {
      for (const target of input.targets) {
        prompt += `- ${target}\n`;
      }
    }

    // Include attack surface from code-intel agent if available
    if (input.context?.attackSurface) {
      const as = input.context.attackSurface;
      prompt += `\n## Attack Surface Intelligence (from Code Analysis):\n`;
      prompt += `Framework: ${as.framework || "unknown"}, Language: ${as.language || "unknown"}\n`;

      if (as.prioritizedAttackVectors?.length) {
        prompt += `\n### Prioritized Attack Vectors:\n`;
        for (const v of as.prioritizedAttackVectors.slice(0, 15)) {
          prompt += `- [${v.confidence?.toUpperCase() || "MEDIUM"}] ${v.type} → ${v.target} (${v.reason})\n`;
        }
      }

      if (as.entryPoints?.length) {
        prompt += `\n### Key Entry Points (${as.entryPoints.length} total):\n`;
        for (const ep of as.entryPoints.slice(0, 20)) {
          const auth = ep.auth === "none" ? " [NO AUTH]" : "";
          prompt += `- ${ep.method || "GET"} ${ep.route}${auth} → ${ep.handler?.file || "unknown"}:${ep.handler?.line || "?"}\n`;
        }
      }

      if (as.defenses) {
        const gaps = Object.entries(as.defenses)
          .filter(([, v]) => !v)
          .map(([k]) => k);
        if (gaps.length) {
          prompt += `\n### Defense Gaps: ${gaps.join(", ")}\n`;
        }
      }

      prompt += `\n**Use this intelligence to focus testing on the most vulnerable endpoints first.**\n`;
    }

    // Include context from previous agents
    if (input.context?.vulnerabilities) {
      prompt += `\n## Vulnerabilities from Previous Scans:\n`;
      for (const vuln of input.context.vulnerabilities.slice(0, 10)) {
        prompt += `- ${vuln.title} (${vuln.severity}): ${vuln.target}\n`;
      }
    }

    if (input.context?.webTechnologies) {
      prompt += `\n## Detected Web Technologies:\n`;
      for (const [host, techs] of Object.entries(input.context.webTechnologies)) {
        prompt += `- ${host}: ${JSON.stringify(techs)}\n`;
      }
    }

    prompt += `
## Your Workflow:

1. **Discovery Phase:**
   - crawl_site to discover all endpoints and parameters
   - fuzz_endpoints to find hidden paths
   - Note all forms and input parameters
   - For SPAs: use browser_navigate + browser_network_log to discover client-side API calls

2. **Injection Testing:**
   - For each parameter found: run_sqlmap (level 2, risk 1)
   - Focus on parameters like: id, user, search, query, page
   - Test both GET and POST parameters

3. **XSS Testing:**
   - test_xss on parameters that reflect user input
   - For DOM-based XSS: use browser_navigate → browser_fill → browser_evaluate to validate
   - Focus on search boxes, comment fields, profile fields

4. **Browser-Based Testing (for SPAs):**
   - browser_navigate to pages that require JavaScript
   - browser_fill + browser_click for form interactions
   - browser_evaluate to check for client-side vulnerabilities
   - browser_screenshot for evidence capture

5. **Directory Discovery:**
   - fuzz_endpoints with different wordlists
   - Look for: admin panels, backup files, config files

## CRITICAL SAFETY RULES:
- NEVER use sqlmap with risk > 2
- NEVER use techniques that could delete/modify data
- Stay non-destructive at all times
- If unsure about safety, err on the side of caution

## Output Requirements:

Provide a summary with:
- Endpoints discovered
- SQL injection vulnerabilities found
- XSS vulnerabilities found
- Hidden directories/files found
- Evidence for each finding

Begin web application testing now.`;

    return prompt;
  }

  /**
   * Build prompt for cross-validation mode — tests SAST findings against live endpoints
   */
  private buildCrossValidationPrompt(input: AgentInput): string {
    const targets = input.context?.crossValidationTargets || [];

    let prompt = `# Cross-Validation Testing Task

You are the Web App Agent running in **cross-validation mode**. Your mission is to test whether SAST (static code analysis) findings are exploitable against the live application.

## SAST Findings to Validate Against Live Endpoints:

`;

    for (let i = 0; i < targets.length; i++) {
      const t = targets[i];
      prompt += `### ${i + 1}. ${t.sastTitle}
- **SAST Finding ID**: ${t.sastFindingId}
- **Vulnerability Type**: ${t.vulnType}
- **Source File**: ${t.filePath}${t.line ? `:${t.line}` : ""}
- **Live Endpoint**: ${t.method} ${t.liveUrl}
- **Parameters**: ${t.parameters.length > 0 ? t.parameters.join(", ") : "none identified"}

`;
    }

    prompt += `## Your Workflow

For each SAST finding above:

1. **Select the right tool** based on vulnerability type:
   - \`sqli\` → use \`run_sqlmap\` on the endpoint with identified parameters
   - \`xss\` → use \`test_xss\` on the endpoint
   - \`ssrf\` / \`rce\` / \`path_traversal\` → use \`browser_navigate\` with crafted payloads
   - \`csrf\` → use \`browser_navigate\` + check for CSRF tokens
   - \`idor\` → use \`browser_navigate\` with modified IDs
   - \`auth\` → test authentication bypass on the endpoint

2. **Record the result** for each finding as one of:
   - **CONFIRMED**: The SAST finding is exploitable on the live endpoint
   - **NOT_EXPLOITABLE**: The vulnerability exists in code but is blocked by runtime defenses (WAF, framework sanitization, CORS, etc.)
   - **MITIGATED**: Partial defenses exist — finding is downgraded in severity
   - **INCONCLUSIVE**: Could not determine exploitability (e.g., endpoint requires auth, returns errors)

3. **Capture evidence**: Take screenshots or save responses for confirmed findings

## CRITICAL SAFETY RULES:
- Stay NON-DESTRUCTIVE at all times
- Never use sqlmap with risk > 2
- If unsure about safety, err on the side of caution

## Output Requirements

For each SAST finding, document:
- SAST Finding ID
- Live endpoint tested
- Tool used
- Result (CONFIRMED / NOT_EXPLOITABLE / MITIGATED / INCONCLUSIVE)
- Evidence or explanation

Begin cross-validation testing now.`;

    return prompt;
  }

  getSystemPrompt(): string {
    return `You are the Web App Agent, specialized in OWASP-style web application security testing.

## Your Capabilities:
- Site crawling and endpoint discovery
- SQL injection testing (non-destructive)
- XSS vulnerability testing (including DOM-based via browser)
- Directory/file fuzzing
- Browser automation for SPA testing, DOM XSS, and auth flows

## Decision Guidelines:

### When to use crawl_site:
- Always use FIRST on a new target
- Builds a map of the application
- Identifies parameters for injection testing

### When to use run_sqlmap:
- On URLs with query parameters (?id=1, ?user=admin)
- On forms with input fields
- ALWAYS use level <= 3 and risk <= 2
- NEVER use --os-shell or --os-cmd

### When to use test_xss:
- On parameters that reflect user input
- Search boxes, comment fields, profile inputs
- Any parameter where input is displayed back

### When to use browser tools:
- **browser_navigate**: For SPAs that require JavaScript to render content
- **browser_fill + browser_click**: To interact with forms, especially those with client-side validation
- **browser_evaluate**: To validate DOM-based XSS (inject payload, check execution)
- **browser_network_log**: To discover hidden API calls made by the SPA
- **browser_screenshot**: To capture visual evidence of vulnerabilities
- **browser_get_cookies**: To audit cookie security (HttpOnly, Secure, SameSite flags)
- Do NOT call browser_close during a multi-phase assessment (the session is shared)

### When to use request_user_guidance:
- You encounter a CAPTCHA you can't solve
- An MFA/2FA challenge appears that needs human input
- A login wall blocks your testing and you need credentials
- A complex form or workflow you can't navigate automatically
- ALWAYS include screenshot=true so the user can see what you're seeing

### When to use fuzz_endpoints:
- To find hidden admin panels
- To discover backup files (.bak, .old, .swp)
- To find configuration files
- Use different wordlists based on target type

### Using Attack Surface Intelligence:
- If context.attackSurface is available, prioritize testing endpoints with:
  - No auth middleware + database access (HIGH priority for SQLi)
  - Missing input validation (HIGH priority for injection)
  - Missing CSRF protection (test state-changing operations)
  - Command execution sinks (test for RCE)
- Skip endpoints that have parameterized queries + input validation (LOW priority)

## Safety Rules:
1. NON-DESTRUCTIVE TESTING ONLY
2. Never use sqlmap risk > 2
3. Don't attempt to modify/delete data
4. Stop testing if you detect data modification
5. Document everything for evidence`;
  }

  protected extractFindings(result: string, toolName: string, target?: string): void {
    super.extractFindings(result, toolName, target);

    try {
      const parsed = JSON.parse(result);

      // SQLMap-specific extraction
      if (toolName === "run_sqlmap") {
        if (parsed.vulnerable || parsed.injections) {
          // Capture ALL injection points, not just the first one
          const injections = parsed.injections || [parsed];
          const allPayloads = Array.isArray(injections)
            ? injections.map((inj: any) => `${inj.parameter || "unknown"}: ${inj.payload || inj.type || "detected"}`).join("\n")
            : JSON.stringify(injections);
          this.addFinding({
            title: `SQL Injection Vulnerability`,
            severity: "critical",
            target: target || parsed.target || "unknown",
            description: `SQL injection vulnerability confirmed. ${Array.isArray(injections) ? injections.length : 1} injection point(s) found. Type: ${parsed.type || parsed.technique || "unknown"}`,
            evidence: `Full sqlmap output:\n${allPayloads}\n\nBanner: ${parsed.banner || "N/A"}\nDBMS: ${parsed.dbms || "N/A"}`,
            remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            source: "sqlmap",
            metadata: {
              dbms: parsed.dbms,
              technique: parsed.technique,
              payload: parsed.payload,
              allInjections: injections,
            },
          });
        }
      }

      // XSS-specific extraction
      if (toolName === "test_xss") {
        if (parsed.vulnerable || parsed.xss_found) {
          for (const xss of parsed.vulnerabilities || [parsed]) {
            this.addFinding({
              title: `Cross-Site Scripting (XSS) Vulnerability`,
              severity: "high",
              target: target || xss.url || "unknown",
              description: `XSS vulnerability found. Type: ${xss.type || "reflected"}. Parameter: ${xss.param || "unknown"}`,
              evidence: xss.payload || xss.poc,
              remediation: "Encode all user input before outputting to HTML. Use Content-Security-Policy headers.",
              source: "xss-scanner",
            });
          }
        }
      }

      // Crawl results - store in context
      if (toolName === "crawl_site") {
        this.state.context.discoveredEndpoints = parsed.endpoints || parsed.urls || [];
        this.state.context.discoveredForms = parsed.forms || [];
        this.state.context.discoveredParameters = parsed.parameters || [];
      }

      // Fuzzing results
      if (toolName === "fuzz_endpoints") {
        for (const found of parsed.found || parsed.results || []) {
          const path = typeof found === "string" ? found : found.path || found.url;
          const status = typeof found === "object" ? found.status : 200;

          // Check for interesting findings
          const interesting = [
            "admin",
            "backup",
            ".bak",
            ".old",
            "config",
            ".env",
            "wp-admin",
            "phpmyadmin",
            ".git",
            ".svn",
          ];

          const isInteresting = interesting.some((i) => path.toLowerCase().includes(i));

          if (isInteresting || status === 200) {
            this.addFinding({
              title: `Hidden endpoint discovered: ${path}`,
              severity: isInteresting ? "medium" : "info",
              target: target || "unknown",
              description: `Discovered ${path} (HTTP ${status})`,
              source: "fuzzer",
            });
          }
        }
      }
    } catch {
      // Not JSON
    }
  }
}
