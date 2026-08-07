/**
 * QA Agent Implementation
 *
 * Validates findings from other agents before report generation.
 * Acts as a quality assurance layer that reduces false positives,
 * identifies coverage gaps, and assigns confidence scores.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  AgentFinding,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { qaHandlers, setQAContext } from "../../tools/qa-tools";
import { reconHandlers } from "../../tools/recon";
import { vulnScanHandlers } from "../../tools/vuln-scan";
import { webAppHandlers } from "../../tools/web-app";
import { browserHandlers } from "../../tools/browser";
import { guidanceHandlers } from "../../tools/guidance";
import { codeScanHandlers } from "../../tools/code-scan";

// QA agent configuration
const QA_AGENT_CONFIG: AgentConfig = {
  name: "qa-agent",
  description: "Validates findings from other agents, checks coverage, assigns confidence scores",
  maxIterations: 30, // May need more iterations for thorough validation
  timeoutMs: 600000, // 10 minutes
  requiresScopeValidation: true, // Still respects scope
  tools: [
    // QA-specific tools
    "validate_finding",
    "check_coverage",
    "score_confidence",
    "request_agent_followup",
    "get_agent_summary",
    "compare_findings",
    "list_findings",
    "get_finding_details",
    // Recon tools for re-validation
    "scan_ports",
    "fingerprint_services",
    "web_technology_scan",
    // Vuln scan tools for re-validation
    "run_nuclei",
    // Web app tools for re-validation
    "curl_request",
    "run_sqlmap",
    // Browser tools for re-validation
    "browser_navigate",
    "browser_screenshot",
    "browser_evaluate",
    "browser_get_cookies",
    "browser_get_content",
    // Guidance tool
    "request_user_guidance",
    // Code analysis tool (for SAST QA mode)
    "analyze_code_context",
  ],
};

// Tool definitions for Claude API
const QA_TOOL_DEFINITIONS: ToolDefinition[] = [
  // QA-specific tools
  {
    name: "validate_finding",
    description:
      "Re-test a specific finding to confirm it's real. Returns validation status (confirmed/not_reproduced/inconclusive) and updated confidence score.",
    input_schema: {
      type: "object",
      properties: {
        finding_id: {
          type: "string",
          description: "ID of the finding to validate",
        },
        retest_method: {
          type: "string",
          enum: ["quick", "thorough"],
          description: "How thoroughly to re-test (quick=fast check, thorough=full re-test)",
        },
        custom_payload: {
          type: "string",
          description: "Optional specific test payload to use",
        },
      },
      required: ["finding_id"],
    },
  },
  {
    name: "check_coverage",
    description:
      "Analyze what attack vectors were tested vs what could have been tested. Identifies gaps in testing coverage.",
    input_schema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Targets to analyze coverage for",
        },
        focus_areas: {
          type: "array",
          items: { type: "string" },
          description: "Specific areas to check (auth, injection, config, etc.)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "score_confidence",
    description:
      "Evaluate a finding's evidence quality and assign a confidence score (1-10). Higher scores indicate more reliable findings.",
    input_schema: {
      type: "object",
      properties: {
        finding_id: {
          type: "string",
          description: "ID of the finding to score",
        },
        criteria: {
          type: "object",
          description: "Optional specific criteria weights (evidenceQuality, reproducibility, impactClarity, falsePositiveLikelihood)",
        },
      },
      required: ["finding_id"],
    },
  },
  {
    name: "request_agent_followup",
    description:
      "Request a specific agent to run additional targeted tests. Use when you need more information to validate a finding.",
    input_schema: {
      type: "object",
      properties: {
        agent: {
          type: "string",
          enum: ["recon", "vuln-scan", "web-app", "exploit"],
          description: "Which agent to request follow-up from",
        },
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Specific targets to test",
        },
        focus: {
          type: "string",
          description: "What to look for specifically",
        },
        context: {
          type: "object",
          description: "Additional context for the agent",
        },
      },
      required: ["agent", "targets", "focus"],
    },
  },
  {
    name: "get_agent_summary",
    description:
      "Get detailed summary of what an agent did during its execution. Helps understand testing methodology.",
    input_schema: {
      type: "object",
      properties: {
        agent_name: {
          type: "string",
          description: "Name of the agent to summarize (e.g., 'recon-agent', 'vuln-scan-agent')",
        },
      },
      required: ["agent_name"],
    },
  },
  {
    name: "compare_findings",
    description:
      "Cross-reference findings from different sources to identify confirmations or discrepancies.",
    input_schema: {
      type: "object",
      properties: {
        finding_ids: {
          type: "array",
          items: { type: "string" },
          description: "Array of finding IDs to compare",
        },
      },
      required: ["finding_ids"],
    },
  },
  {
    name: "list_findings",
    description:
      "List all findings in context. Use this first to see what needs to be validated.",
    input_schema: {
      type: "object",
      properties: {
        severity: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Filter by minimum severity",
        },
        source: {
          type: "string",
          description: "Filter by source agent/tool",
        },
        limit: {
          type: "number",
          description: "Maximum number of findings to return (default: 50)",
        },
      },
    },
  },
  {
    name: "get_finding_details",
    description: "Get full details of a specific finding by ID, including evidence.",
    input_schema: {
      type: "object",
      properties: {
        finding_id: {
          type: "string",
          description: "ID of the finding to retrieve",
        },
      },
      required: ["finding_id"],
    },
  },
  // Re-validation tools from other agents
  {
    name: "scan_ports",
    description:
      "Re-verify open ports on a target. Use to confirm port-related findings.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP or hostname",
        },
        ports: {
          type: "string",
          description: "Specific ports to verify",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "fingerprint_services",
    description:
      "Re-verify service versions. Use to confirm version-related findings.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP or hostname",
        },
        ports: {
          type: "string",
          description: "Ports to fingerprint",
        },
      },
      required: ["target", "ports"],
    },
  },
  {
    name: "web_technology_scan",
    description:
      "Re-verify web technologies. Use to confirm technology-related findings.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "run_nuclei",
    description:
      "Re-run nuclei to verify CVE/vulnerability findings.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "URL to scan",
        },
        templates: {
          type: "string",
          description: "Specific template IDs or tags to run",
        },
        severity: {
          type: "string",
          description: "Severity filter",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "curl_request",
    description:
      "Make HTTP requests to verify web findings. Can test specific payloads.",
    input_schema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "URL to request",
        },
        method: {
          type: "string",
          enum: ["GET", "POST", "PUT", "DELETE", "PATCH"],
          description: "HTTP method",
        },
        headers: {
          type: "object",
          description: "Custom headers",
        },
        body: {
          type: "string",
          description: "Request body",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "run_sqlmap",
    description:
      "Re-verify SQL injection findings with sqlmap.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL with parameter",
        },
        level: {
          type: "number",
          description: "Test level (1-5)",
        },
        risk: {
          type: "number",
          description: "Risk level (1-3)",
        },
      },
      required: ["target"],
    },
  },
  // Browser tools for re-validation
  {
    name: "browser_navigate",
    description: "Navigate browser to re-test findings that require JavaScript rendering.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to navigate to" },
        wait_for: { type: "string", description: "CSS selector to wait for" },
      },
      required: ["url"],
    },
  },
  {
    name: "browser_screenshot",
    description: "Capture screenshot as re-validation evidence.",
    input_schema: {
      type: "object",
      properties: {
        full_page: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "browser_evaluate",
    description: "Execute JavaScript to re-validate DOM-based findings.",
    input_schema: {
      type: "object",
      properties: {
        script: { type: "string", description: "JavaScript to evaluate" },
      },
      required: ["script"],
    },
  },
  {
    name: "browser_get_cookies",
    description: "Get cookies to verify session-related findings.",
    input_schema: { type: "object", properties: {} },
  },
  {
    name: "browser_get_content",
    description: "Get page content to verify reflected content findings.",
    input_schema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["html", "text"], default: "text" },
        selector: { type: "string" },
      },
    },
  },
  {
    name: "request_user_guidance",
    description:
      "Ask the user for help when you need additional context to validate a finding, " +
      "or when re-validation requires manual steps.",
    input_schema: {
      type: "object",
      properties: {
        situation: { type: "string", description: "What you need help with" },
        screenshot: { type: "boolean", description: "Take screenshot", default: false },
        options: { type: "array", items: { type: "string" }, description: "Suggested options" },
      },
      required: ["situation"],
    },
  },
  // Code analysis tool (for SAST QA mode)
  {
    name: "analyze_code_context",
    description:
      "Read source code at a specific file:line to verify SAST findings. " +
      "Use to check if user input actually reaches the vulnerable sink, " +
      "whether mitigating defenses exist (parameterized queries, input validation), " +
      "and whether the code is in test files, dead code, or vendored dependencies.",
    input_schema: {
      type: "object",
      properties: {
        file_path: { type: "string", description: "Path to the source file" },
        line_start: { type: "number", description: "Starting line number" },
        line_end: { type: "number", description: "Ending line number" },
        vulnerability_type: {
          type: "string",
          description: "Type of vulnerability to look for (sqli, xss, ssrf, etc.)",
        },
      },
      required: ["file_path"],
    },
  },
];

/**
 * QA Agent Implementation
 */
export class QaAgentImpl extends BaseAgent {
  private followUpRequests: any[] = [];

  constructor(onProgress?: ProgressCallback) {
    // Combine all handlers
    const combinedHandlers = {
      ...qaHandlers,
      ...reconHandlers,
      ...vulnScanHandlers,
      ...webAppHandlers,
      ...browserHandlers,
      ...guidanceHandlers,
      ...codeScanHandlers,
    };

    super(QA_AGENT_CONFIG, combinedHandlers, onProgress);
  }

  /**
   * Get tool definitions for Claude
   */
  getToolDefinitions(): ToolDefinition[] {
    return QA_TOOL_DEFINITIONS;
  }

  /**
   * Build the initial prompt for Claude
   */
  buildInitialPrompt(input: AgentInput): string {
    // Set up the context for QA tools
    const findings = input.context?.findings || [];
    const agentResults = input.context?.agentResults || {};
    setQAContext(findings, agentResults);

    // Branch on QA mode (sast/dast)
    const qaMode = input.context?.qaMode;
    if (qaMode === "sast") {
      return this.buildSastQaPrompt(input, findings, agentResults);
    }

    // Default: DAST QA mode (original behavior)
    return this.buildDastQaPrompt(input, findings, agentResults);
  }

  /**
   * Build QA prompt for SAST mode — validates code-level findings
   */
  private buildSastQaPrompt(
    input: AgentInput,
    findings: AgentFinding[],
    agentResults: Record<string, any>
  ): string {
    const findingsBySeverity = {
      critical: findings.filter((f: AgentFinding) => f.severity === "critical"),
      high: findings.filter((f: AgentFinding) => f.severity === "high"),
      medium: findings.filter((f: AgentFinding) => f.severity === "medium"),
      low: findings.filter((f: AgentFinding) => f.severity === "low"),
      info: findings.filter((f: AgentFinding) => f.severity === "info"),
    };

    return `# SAST QA Validation Task

You are the QA Agent running in **SAST mode**. Your mission is to validate static code analysis findings by examining the source code itself.

## Findings to Review

Total findings: ${findings.length}
- Critical: ${findingsBySeverity.critical.length}
- High: ${findingsBySeverity.high.length}
- Medium: ${findingsBySeverity.medium.length}
- Low: ${findingsBySeverity.low.length}
- Info: ${findingsBySeverity.info.length}

## Agent Results Available
${Object.keys(agentResults).map((name) => `- ${name}`).join("\n") || "- No agent results in context"}

## Your Workflow (SAST-Specific)

1. **List and Triage Findings**
   - Use list_findings to see all SAST findings
   - Prioritize critical and high severity findings

2. **Validate by Reading Source Code**
   For each critical/high finding:
   - Use \`analyze_code_context\` to read the source code at the finding's file:line
   - **Check dataflow**: Does user input actually reach the vulnerable sink?
   - **Check defenses**: Are there mitigating controls? (parameterized queries, input validation, output encoding)
   - **Check context**: Is this in test code, dead code, or vendored/third-party code?
   - Use validate_finding to record your assessment

3. **SAST-Specific False Positive Detection**
   Flag as false positive if:
   - Finding is in test files (\`__tests__/\`, \`*.test.*\`, \`*.spec.*\`)
   - Finding is in vendored/node_modules code
   - User input is validated before reaching the sink
   - Parameterized queries are used (for SQLi findings)
   - Output is encoded (for XSS findings)
   - Dead code / unreachable path
   - Framework provides built-in protection (e.g., ORM sanitization)

4. **SAST Confidence Scoring**
   Score each finding 1-10 based on:
   - **9-10**: User input → vulnerable sink with no validation. Exploitable.
   - **7-8**: Likely vulnerable, minor mitigations present but bypassable.
   - **5-6**: Dataflow unclear, need runtime testing to confirm.
   - **3-4**: Defenses present but incomplete. Low exploitability.
   - **1-2**: Test code, dead code, or strong defenses. Likely FP.

5. **Check Coverage**
   - Were all languages scanned?
   - Were IaC files checked?
   - Were secrets scanned across git history?
   - Any files excluded from scanning?

6. **Produce Summary**
   - Summarize validation results
   - List confirmed findings with SAST confidence scores
   - List false positives with code-level reasoning
   - List coverage gaps

## IMPORTANT
- Use \`analyze_code_context\` liberally to read source code
- Focus on whether findings are **actually exploitable**, not just pattern matches
- SAST tools produce many false positives — your job is to separate signal from noise

${findings.length === 0 ? "\n**NOTE: No findings to validate. Focus on coverage analysis.**\n" : ""}

Begin SAST validation now.`;
  }

  /**
   * Build QA prompt for DAST mode (default) — validates dynamic testing findings
   */
  private buildDastQaPrompt(
    input: AgentInput,
    findings: AgentFinding[],
    agentResults: Record<string, any>
  ): string {
    const findingsBySeverity = {
      critical: findings.filter((f: AgentFinding) => f.severity === "critical"),
      high: findings.filter((f: AgentFinding) => f.severity === "high"),
      medium: findings.filter((f: AgentFinding) => f.severity === "medium"),
      low: findings.filter((f: AgentFinding) => f.severity === "low"),
      info: findings.filter((f: AgentFinding) => f.severity === "info"),
    };

    let prompt = `# QA Validation Task

You are the QA Agent. Your mission is to validate findings from prior agents before report generation.

## Findings to Review

Total findings: ${findings.length}
- Critical: ${findingsBySeverity.critical.length}
- High: ${findingsBySeverity.high.length}
- Medium: ${findingsBySeverity.medium.length}
- Low: ${findingsBySeverity.low.length}
- Info: ${findingsBySeverity.info.length}

## Agent Results Available
${Object.keys(agentResults).map((name) => `- ${name}`).join("\n") || "- No agent results in context"}

## Targets
${input.targets?.map((t) => `- ${t}`).join("\n") || "- No targets specified (use findings)"}

## Your Workflow

1. **List and Triage Findings**
   - Use list_findings to see all findings
   - Prioritize critical and high severity findings

2. **Validate Critical Findings (100%)**
   - For each critical finding, use validate_finding with retest_method="thorough"
   - If validation fails, investigate why

3. **Validate High Findings (50% sample)**
   - Select the most impactful high findings
   - Use validate_finding with retest_method="quick"

4. **Spot-check Medium/Low**
   - Validate any findings with weak evidence
   - Focus on findings that might be false positives

5. **Score Confidence**
   - Use score_confidence on all validated findings
   - Note findings with low confidence for report

6. **Check Coverage Against Test Matrix**
   - Use check_coverage to identify gaps
   - Verify that ALL test categories from the 116-test matrix were executed:
     - DAST: RECON (6), SSL (4), AUTH (8), AUTHZ (4), HDR (4), CORS (3), INJ (8), SSRF (3), GQL (8), API (6), CLI (6), VSCAN (3), UPLOAD (3), BIZ (3), PROTO (3), DESER (1)
     - SAST: SAST (10), SAST-DF (5), SAST-DEF (5), SAST-SC (4)
     - XVAL: Cross-validation (11)
     - CHAIN: Chain Analysis (8) — CHAIN-01 to CHAIN-08
   - For ANY test that was not executed, document it as SKIPPED with a specific reason
   - No test may be silently omitted — every test_id must appear in the coverage checklist

7. **Validate Finding Completeness**
   - For each finding, verify it includes:
     - Specific file paths with line numbers (not just "in the codebase")
     - Specific commit hashes (not "in git history" without a hash)
     - Reproduction steps with copy-pasteable commands
     - Exploitation scenario showing attacker impact
   - If a finding claims "N items found", verify all N are listed individually
   - Flag any finding that uses banned language: "various", "multiple", "several", "some", "others", "etc."

8. **Request Follow-ups (if needed)**
   - If you need more information to validate something
   - Use request_agent_followup to ask another agent

9. **Produce Summary**
   - Summarize validation results
   - List confirmed findings with confidence scores
   - List false positives with reasoning
   - List coverage gaps with specific missing test_ids
   - List any findings flagged for incomplete evidence

## Output Requirements

After completing QA, provide:
- Number of findings validated
- Number confirmed vs not reproduced vs inconclusive
- Overall confidence score (1-10)
- Coverage gaps identified (specific test_ids that were SKIPPED)
- Completeness flags (findings missing evidence, using vague language)
- Recommendations for the report

${findings.length === 0 ? "\n**NOTE: No findings to validate. Focus on coverage analysis.**\n" : ""}

Begin validation now.`;

    return prompt;
  }

  /**
   * Get the system prompt for this agent
   */
  getSystemPrompt(): string {
    return `You are the QA Agent, a quality assurance specialist for security assessments.

## Your Mission
Validate findings from other agents to ensure report accuracy. Reduce false positives, identify coverage gaps, and assign confidence scores.

## Validation Priorities
1. **Critical findings**: Validate ALL - these drive immediate remediation
2. **High findings**: Validate at least 50% - focus on most impactful
3. **Medium/Low**: Spot-check findings with weak evidence
4. **Info**: Generally no validation needed unless suspicious

## Decision Guidelines

### When to mark "confirmed":
- Re-test produces same or similar result
- Multiple tools/sources agree
- Clear evidence of vulnerability

### When to mark "not_reproduced":
- Re-test fails to produce vulnerability
- Original evidence was scanner-only
- Environment may have changed

### When to mark "inconclusive":
- Re-test produces different but related result
- Need more information to decide
- Environment factors unclear

## Confidence Scoring (1-10)
- **9-10**: Exploited, full PoC, easily repeatable
- **7-8**: Strong evidence, re-test confirmed
- **5-6**: Reasonable evidence, not fully validated
- **3-4**: Weak evidence, possible false positive
- **1-2**: Scanner-only, likely false positive

## Coverage Analysis
Check for gaps in:
- Authentication testing
- Authorization/IDOR testing
- Injection testing (SQLi, XSS, etc.)
- Configuration review
- API security testing

## Browser-Based Re-Validation
- Use browser_navigate + browser_evaluate for findings that require JavaScript
- Use browser_screenshot to capture evidence of re-validation
- Use browser_get_content to check DOM for reflected payloads
- The browser session may already be authenticated from prior agents

## When to use request_user_guidance
- You need manual context to understand a finding
- Re-validation requires credentials or access you don't have
- A finding seems ambiguous and you want human judgment

## Important Rules
1. Be conservative - don't inflate confidence
2. Document why findings were marked as false positives
3. Only request follow-ups if truly needed
4. Focus on actionable insights over completeness
5. Consider environment differences that affect reproducibility
6. Do NOT call browser_close during a multi-phase assessment`;
  }

  /**
   * Override extractFindings to handle QA-specific output
   */
  protected extractFindings(result: string, toolName: string, target?: string): void {
    // QA agent doesn't typically generate new findings
    // Instead, it validates existing ones

    try {
      const parsed = JSON.parse(result);

      // Track follow-up requests
      if (toolName === "request_agent_followup" && parsed.request) {
        this.followUpRequests.push(parsed.request);
        this.state.context.followUpRequests = this.followUpRequests;
      }

      // Track validation results
      if (toolName === "validate_finding") {
        if (!this.state.context.validatedFindings) {
          this.state.context.validatedFindings = [];
        }
        this.state.context.validatedFindings.push({
          findingId: parsed.findingId,
          confidence: parsed.confidence,
          validationStatus: parsed.validationStatus,
          retestEvidence: parsed.retestEvidence?.substring(0, 500),
          notes: parsed.notes,
        });

        // Track false positives separately
        if (parsed.validationStatus === "not_reproduced") {
          if (!this.state.context.falsePositives) {
            this.state.context.falsePositives = [];
          }
          this.state.context.falsePositives.push({
            findingId: parsed.findingId,
            reason: parsed.notes || "Could not reproduce",
            retestOutput: parsed.retestEvidence?.substring(0, 500),
          });
        }
      }

      // Track coverage analysis
      if (toolName === "check_coverage" && parsed.gaps) {
        this.state.context.coverageGaps = parsed.gaps;
        this.state.context.coverageScore = parsed.coverageScore;
      }

      // Track confidence scores
      if (toolName === "score_confidence") {
        if (!this.state.context.confidenceScores) {
          this.state.context.confidenceScores = {};
        }
        this.state.context.confidenceScores[parsed.findingId] = parsed.score;
      }
    } catch {
      // Not JSON, ignore
    }
  }

  /**
   * Generate summary specific to QA agent
   */
  protected generateSummary(): string {
    const validated = this.state.context.validatedFindings || [];
    const confirmed = validated.filter((v: any) => v.validationStatus === "confirmed").length;
    const notReproduced = validated.filter((v: any) => v.validationStatus === "not_reproduced").length;
    const inconclusive = validated.filter((v: any) => v.validationStatus === "inconclusive").length;
    const gaps = this.state.context.coverageGaps?.length || 0;

    if (validated.length === 0) {
      return `qa-agent completed. No findings were validated.`;
    }

    const avgConfidence =
      validated.reduce((sum: number, v: any) => sum + (v.confidence || 0), 0) /
      validated.length;

    return `qa-agent validated ${validated.length} findings: ${confirmed} confirmed, ${notReproduced} false positives, ${inconclusive} inconclusive. Average confidence: ${avgConfidence.toFixed(1)}/10. Coverage gaps: ${gaps}.`;
  }
}
