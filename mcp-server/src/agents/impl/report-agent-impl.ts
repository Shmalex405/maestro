/**
 * Report Agent Implementation
 *
 * Aggregates findings from all other agents, generates reports,
 * creates Jira tickets, and distributes results.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
  AgentFinding,
} from "../base-agent";
import { reportingHandlers } from "../../tools/reporting";

const REPORT_AGENT_CONFIG: AgentConfig = {
  name: "report-agent",
  description: "Report generation and distribution agent",
  maxIterations: 15,
  timeoutMs: 300000, // 5 minutes
  requiresScopeValidation: false, // Reporting only
  tools: [
    "create_finding",
    "generate_report",
    "generate_pdf_report",
    "create_jira_ticket",
    "upload_report",
    "import_cycode_findings",
  ],
};

const REPORT_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "create_finding",
    description: `Create a new finding record in the database.
Use to document vulnerabilities for reporting.`,
    input_schema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description: "Finding title",
        },
        severity: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Severity level",
        },
        description: {
          type: "string",
          description: "Detailed description",
        },
        target: {
          type: "string",
          description: "Affected target",
        },
        evidence: {
          type: "string",
          description: "Proof of vulnerability",
        },
        remediation: {
          type: "string",
          description: "Fix recommendation",
        },
      },
      required: ["title", "severity", "description", "target"],
    },
  },
  {
    name: "generate_report",
    description: `Generate a formatted security assessment report.
Compiles all findings into a professional document.`,
    input_schema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["markdown", "html", "json"],
          description: "Output format",
        },
        include_evidence: {
          type: "boolean",
          description: "Include evidence in report",
        },
        include_remediation: {
          type: "boolean",
          description: "Include remediation guidance",
        },
        executive_summary: {
          type: "boolean",
          description: "Include executive summary",
        },
      },
      required: ["format"],
    },
  },
  {
    name: "create_jira_ticket",
    description: `Create a Jira ticket for a finding.
Use for high and critical severity findings that need tracking.`,
    input_schema: {
      type: "object",
      properties: {
        finding_id: {
          type: "string",
          description: "Finding ID to create ticket for",
        },
        project_key: {
          type: "string",
          description: "Jira project key",
        },
        priority: {
          type: "string",
          enum: ["Lowest", "Low", "Medium", "High", "Highest"],
          description: "Ticket priority",
        },
        assignee: {
          type: "string",
          description: "Jira username to assign to",
        },
        labels: {
          type: "array",
          items: { type: "string" },
          description: "Labels to add",
        },
      },
      required: ["finding_id", "project_key"],
    },
  },
  {
    name: "upload_report",
    description: `Upload report to SharePoint and optionally email it.
Use for distributing final reports.`,
    input_schema: {
      type: "object",
      properties: {
        report_content: {
          type: "string",
          description: "Report content to upload",
        },
        filename: {
          type: "string",
          description: "Filename for the report",
        },
        email_recipients: {
          type: "array",
          items: { type: "string" },
          description: "Email addresses to send report to",
        },
        sharepoint_folder: {
          type: "string",
          description: "SharePoint folder path",
        },
      },
      required: ["report_content", "filename"],
    },
  },
  {
    name: "import_cycode_findings",
    description: `Import findings from Cycode CSV export.
Use to incorporate external scan results.`,
    input_schema: {
      type: "object",
      properties: {
        csv_path: {
          type: "string",
          description: "Path to Cycode CSV file",
        },
        csv_content: {
          type: "string",
          description: "CSV content directly",
        },
      },
      required: [],
    },
  },
  {
    name: "generate_pdf_report",
    description: `Generate a professional PDF report. ALWAYS call this as your final step.
Preferred: Pass the full markdown report content via markdown_content — this renders the complete
report as a styled PDF identical to the .md file. Alternative: omit markdown_content to build
a PDF from database findings using the HTML template.`,
    input_schema: {
      type: "object",
      properties: {
        markdown_content: {
          type: "string",
          description:
            "Full markdown report content. Pass the complete .md report text here for a 1:1 PDF rendering.",
        },
        output_filename: {
          type: "string",
          description: "Output PDF filename (default: report.pdf)",
        },
        title: {
          type: "string",
          description: "Report title (used only when building from DB findings)",
        },
        target: {
          type: "string",
          description: "Assessment target name (used only when building from DB findings)",
        },
      },
      required: [],
    },
  },
];

export class ReportAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(REPORT_AGENT_CONFIG, reportingHandlers, onProgress);
  }

  getToolDefinitions(): ToolDefinition[] {
    return REPORT_TOOL_DEFINITIONS;
  }

  buildInitialPrompt(input: AgentInput): string {
    // Branch on dual-track mode
    if (input.context?.dualTrackMode) {
      return this.buildDualTrackReportPrompt(input);
    }

    // Default: standard report
    const format = input.options?.format || "markdown";
    const jiraProject = input.options?.jiraProject;
    const emailRecipients = input.options?.emailRecipients || [];

    let prompt = `# Report Generation Task

You are the Report Agent. Your mission is to compile findings and generate a professional security assessment report.

## Configuration:
- Report Format: ${format}
- Jira Project: ${jiraProject || "Not configured"}
- Email Recipients: ${emailRecipients.length > 0 ? emailRecipients.join(", ") : "None"}
`;

    // Include findings from context (from previous agents)
    if (input.context?.findings && Array.isArray(input.context.findings)) {
      const findings = input.context.findings as AgentFinding[];
      const bySeverity = {
        critical: findings.filter((f) => f.severity === "critical"),
        high: findings.filter((f) => f.severity === "high"),
        medium: findings.filter((f) => f.severity === "medium"),
        low: findings.filter((f) => f.severity === "low"),
        info: findings.filter((f) => f.severity === "info"),
      };

      prompt += `
## Findings Summary:
- Critical: ${bySeverity.critical.length}
- High: ${bySeverity.high.length}
- Medium: ${bySeverity.medium.length}
- Low: ${bySeverity.low.length}
- Info: ${bySeverity.info.length}

## Critical Findings (ALL ${bySeverity.critical.length}):
`;
      for (const f of bySeverity.critical) {
        prompt += `- ${f.title} @ ${f.target}`;
        if (f.evidence) prompt += ` | Evidence: ${String(f.evidence).substring(0, 200)}`;
        if (f.metadata?.cwe) prompt += ` | ${f.metadata.cwe}`;
        prompt += `\n`;
      }

      prompt += `\n## High Findings (ALL ${bySeverity.high.length}):\n`;
      for (const f of bySeverity.high) {
        prompt += `- ${f.title} @ ${f.target}`;
        if (f.evidence) prompt += ` | Evidence: ${String(f.evidence).substring(0, 200)}`;
        if (f.metadata?.cwe) prompt += ` | ${f.metadata.cwe}`;
        prompt += `\n`;
      }

      prompt += `\n## Medium Findings (ALL ${bySeverity.medium.length}):\n`;
      for (const f of bySeverity.medium) {
        prompt += `- ${f.title} @ ${f.target}`;
        if (f.evidence) prompt += ` | Evidence: ${String(f.evidence).substring(0, 150)}`;
        prompt += `\n`;
      }

      prompt += `\n## Low/Info Findings (ALL ${bySeverity.low.length + bySeverity.info.length}):\n`;
      for (const f of [...bySeverity.low, ...bySeverity.info]) {
        prompt += `- ${f.title} @ ${f.target}\n`;
      }

      // Store findings in state for later use
      this.state.context.allFindings = findings;

      // Code Context section — findings with verified source code locations
      const withCodeContext = findings.filter((f) => f.metadata?.codeContextVerified);
      if (withCodeContext.length > 0) {
        prompt += `\n## Source Code References (${withCodeContext.length} findings)\n`;
        prompt += `These findings have verified source code locations. Include the code reference in each finding's detail section.\n`;
        for (const f of withCodeContext) {
          prompt += `- **${f.title}** → \`${f.metadata!.codeContextFile}\` (${f.metadata!.codeContextLanguage})\n`;
        }
      }

      // Code Remediation section — HIGH/CRITICAL findings with LLM-generated fixes
      const withRemediation = findings.filter((f) => f.metadata?.remediationVerified);
      if (withRemediation.length > 0) {
        prompt += `\n## Code Remediation Available (${withRemediation.length} findings)\n`;
        prompt += `For each finding below, include a "Code Remediation" subsection with before/after code blocks.\n\n`;
        for (const f of withRemediation) {
          prompt += `### ${f.title}\n`;
          prompt += `File: \`${f.metadata!.codeContextFile}\`\n`;
          prompt += `**Vulnerable:**\n\`\`\`${f.metadata!.codeContextLanguage}\n${f.metadata!.codeContext}\n\`\`\`\n`;
          prompt += `**Fixed:**\n\`\`\`${f.metadata!.codeContextLanguage}\n${f.metadata!.remediationCode}\n\`\`\`\n`;
          prompt += `**Why:** ${f.metadata!.remediationExplanation}\n\n`;
        }
      }
    }

    // Include validated exploits
    if (input.context?.validatedExploits) {
      prompt += `\n## Validated Exploits:\n`;
      for (const exploit of input.context.validatedExploits) {
        prompt += `- ${exploit.tool}: ${exploit.target} (${exploit.result?.status || "validated"})\n`;
      }
    }

    // Include chain validation data
    if (input.context?.chainValidation) {
      const cv = input.context.chainValidation;
      prompt += `\n## Attack Chain Analysis\n`;
      prompt += `The Chain Analysis Agent identified and validated multi-step attack chains.\n\n`;

      if (cv.confirmed && cv.confirmed.length > 0) {
        prompt += `### Confirmed Chains (${cv.confirmed.length}):\n`;
        for (const chain of cv.confirmed) {
          prompt += `- **${chain.name}** [${chain.severityCombined?.toUpperCase() || "UNKNOWN"}] (Confidence: ${chain.confidence || "?"})\n`;
          prompt += `  Steps: ${(chain.steps || []).map((s: any) => s.findingTitle).join(" → ")}\n`;
          if (chain.exploitEvidence) prompt += `  Evidence: ${String(chain.exploitEvidence).slice(0, 200)}\n`;
        }
      }

      if (cv.refuted && cv.refuted.length > 0) {
        prompt += `\n### Refuted Chains (${cv.refuted.length}):\n`;
        for (const chain of cv.refuted) {
          prompt += `- **${chain.name}** — Blocked by: ${chain.exploitEvidence || "defense mechanism"}\n`;
        }
      }

      if (cv.untested && cv.untested.length > 0) {
        prompt += `\n### Untested Chains (${cv.untested.length}) — Require Manual Follow-up:\n`;
        for (const chain of cv.untested) {
          prompt += `- **${chain.name}** [${chain.severityCombined?.toUpperCase() || "UNKNOWN"}] (Confidence: ${chain.confidence || "?"})\n`;
        }
      }

      if (cv.emergentChains && cv.emergentChains.length > 0) {
        prompt += `\n### Emergent Chains Discovered During Exploitation (${cv.emergentChains.length}):\n`;
        for (const chain of cv.emergentChains) {
          prompt += `- **${chain.name}** [${chain.severityCombined?.toUpperCase() || "UNKNOWN"}]\n`;
        }
      }

      prompt += `\n**Include an "Attack Chain Analysis" section in the report after the Exploitation Summary Matrix.**\n`;
      prompt += `**For each confirmed chain, show the full proof path with evidence from each step.**\n`;
      prompt += `**For defense-in-depth analysis, note which controls broke refuted chains.**\n\n`;
    }

    prompt += `
## Your Workflow:

1. **Finding Registration:**
   - Create findings in the database for each vulnerability
   - Ensure proper categorization and severity

2. **Report Generation:**
   - Generate ${format} report with:
     - Executive summary
     - Findings by severity
     - Evidence and remediation
     - Methodology section

3. **PDF Report Generation (ALWAYS):**
   - After the markdown report, ALWAYS call \`generate_pdf_report\` with the full markdown content
   - Pass the complete report text via \`markdown_content\` for a 1:1 PDF rendering
   - Use a descriptive output_filename like "assessment-report-YYYY-MM-DD.pdf"

4. **Jira Tickets (if configured):**
   ${jiraProject ? `- Create tickets in ${jiraProject} for HIGH and CRITICAL findings` : "- No Jira project configured"}

5. **Distribution:**
   ${emailRecipients.length > 0 ? `- Email report to: ${emailRecipients.join(", ")}` : "- No email recipients configured"}
   - Upload to SharePoint if configured

## Jira Priority Mapping:
- Critical → Highest
- High → High
- Medium → Medium
- Low → Low
- Info → Lowest

## Report Sections (ALL REQUIRED):
1. Table of Contents (clickable markdown anchors)
2. Executive Summary (severity counts + exploitability status)
3. Scope & Methodology (targets, tools, auth method)
4. Assessment Walkthrough (phase-by-phase tables)
5. Critical & High Findings (with reproduction steps, exploitation scenarios, full evidence)
6. Medium Findings (SAME detail level as Critical)
7. Low & Informational Findings (SAME detail level as Critical)
8. Exploitation Summary Matrix (ALL tests, successful AND failed)
9. Detailed Methodology (per-phase: objective, tools, rationale, techniques)
10. SAST Analysis Summary (if SAST data available)
11. Compliance Mapping (OWASP Top 10, CWE)
12. Test Coverage Checklist (PASS/FAIL/SKIPPED/N/A for every test)
13. Recommendations (immediate, short-term, medium-term)

CRITICAL: List ALL findings from ALL severity levels with identical detail. Never abbreviate lower-severity findings.

Begin report generation now.`;

    return prompt;
  }

  /**
   * Build report prompt for dual-track mode — separate DAST/SAST/Cross-Validated sections
   */
  private buildDualTrackReportPrompt(input: AgentInput): string {
    const format = input.options?.format || "markdown";
    const jiraProject = input.options?.jiraProject;
    const emailRecipients = input.options?.emailRecipients || [];

    const dastFindings = (input.context?.dastFindings || []) as AgentFinding[];
    const sastFindings = (input.context?.sastFindings || []) as AgentFinding[];
    const crossValidatedFindings = (input.context?.crossValidatedFindings || []) as AgentFinding[];
    const allFindings = (input.context?.findings || []) as AgentFinding[];

    // Store findings in state for later use
    this.state.context.allFindings = allFindings;

    const countBySeverity = (findings: AgentFinding[]) => ({
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    });

    const dastCounts = countBySeverity(dastFindings);
    const sastCounts = countBySeverity(sastFindings);
    const crossValCounts = countBySeverity(crossValidatedFindings);

    let prompt = `# Dual-Track Security Assessment Report

You are the Report Agent generating a **dual-track assessment report**. This assessment ran DAST and SAST in parallel, then cross-validated code findings against live endpoints.

## Configuration:
- Report Format: ${format}
- Jira Project: ${jiraProject || "Not configured"}
- Email Recipients: ${emailRecipients.length > 0 ? emailRecipients.join(", ") : "None"}

## Track Summary

### Track A — DAST/Pentest (${dastFindings.length} findings)
- Critical: ${dastCounts.critical}, High: ${dastCounts.high}, Medium: ${dastCounts.medium}, Low: ${dastCounts.low}, Info: ${dastCounts.info}

### Track B — SAST/Code Analysis (${sastFindings.length} findings)
- Critical: ${sastCounts.critical}, High: ${sastCounts.high}, Medium: ${sastCounts.medium}, Low: ${sastCounts.low}, Info: ${sastCounts.info}

### Cross-Validated (${crossValidatedFindings.length} findings)
- Critical: ${crossValCounts.critical}, High: ${crossValCounts.high}, Medium: ${crossValCounts.medium}, Low: ${crossValCounts.low}, Info: ${crossValCounts.info}

## REQUIRED Report Structure (Four Sections)

The report MUST be organized into these four distinct sections:

### Section 1: DAST/Pentest Findings
**Include findings where \`metadata.track === "dast"\`**
These are findings from live dynamic testing (port scanning, vulnerability scanning, web app testing, exploitation validation). Present them as a traditional pentest report:
- Vulnerability title + severity
- Affected endpoint/target
- Evidence (request/response, screenshots)
- Exploitability assessment
- Remediation steps

${dastFindings.length > 0 ? `ALL DAST findings (${dastFindings.length} total — list every single one):\n${dastFindings.map((f) => {
  let line = `- [${f.severity.toUpperCase()}] ${f.title} @ ${f.target}`;
  if (f.evidence) line += ` | Evidence: ${String(f.evidence).substring(0, 200)}`;
  if (f.metadata?.cwe) line += ` | ${f.metadata.cwe}`;
  return line;
}).join("\n")}` : "No DAST findings."}

### Section 2: SAST/Code Analysis Findings
**Include findings where \`metadata.track === "sast"\`**
These are findings from static code analysis (Semgrep, Bandit, secrets scanning, dependency checks). Present as code quality/security findings:
- Finding title + severity + CWE/rule ID
- Source file:line reference
- Code snippet (if available in metadata)
- Whether the finding was QA-validated (confidence score)
- Remediation with code examples

${sastFindings.length > 0 ? `ALL SAST findings (${sastFindings.length} total — list every single one):\n${sastFindings.map((f) => {
  let line = `- [${f.severity.toUpperCase()}] ${f.title} @ ${f.target}`;
  if (f.evidence) line += ` | Evidence: ${String(f.evidence).substring(0, 200)}`;
  if (f.metadata?.cwe) line += ` | ${f.metadata.cwe}`;
  return line;
}).join("\n")}` : "No SAST findings."}

### Section 3: Cross-Validated Findings
**Include findings where \`metadata.track === "cross-validated"\`**
These are the most valuable findings — SAST findings that were tested against the live application. Present as a comparison table:

| SAST Finding | Code Location | Live Endpoint | DAST Result | Status |
|---|---|---|---|---|
| Finding title | file:line | URL tested | CONFIRMED/NOT_EXPLOITABLE/MITIGATED | Verdict |

For CONFIRMED findings: include full SAST evidence + DAST evidence side-by-side.
For NOT_EXPLOITABLE findings: explain what runtime defense blocked exploitation.

${crossValidatedFindings.length > 0 ? `ALL cross-validated findings (${crossValidatedFindings.length} total — list every single one):\n${crossValidatedFindings.map((f) => {
  let line = `- [${f.severity?.toUpperCase() || "UNKNOWN"}] ${f.title} @ ${f.target}`;
  if (f.evidence) line += ` | Evidence: ${String(f.evidence).substring(0, 200)}`;
  return line;
}).join("\n")}` : "No cross-validated findings."}

### Section 4: Code Remediation Guide
For all findings with \`metadata.remediationCode\`, show before/after code fixes:
`;

    // Include remediation code blocks
    const withRemediation = allFindings.filter((f) => f.metadata?.remediationVerified);
    if (withRemediation.length > 0) {
      prompt += `\n**${withRemediation.length} findings have code remediation available:**\n\n`;
      for (const f of withRemediation) {
        prompt += `#### ${f.title}\n`;
        prompt += `File: \`${f.metadata!.codeContextFile}\`\n`;
        prompt += `**Vulnerable:**\n\`\`\`${f.metadata!.codeContextLanguage}\n${f.metadata!.codeContext}\n\`\`\`\n`;
        prompt += `**Fixed:**\n\`\`\`${f.metadata!.codeContextLanguage}\n${f.metadata!.remediationCode}\n\`\`\`\n`;
        prompt += `**Why:** ${f.metadata!.remediationExplanation}\n\n`;
      }
    } else {
      prompt += `No code remediation available (no source code references found).\n`;
    }

    prompt += `
## Additional Report Sections (Standard)

In addition to the four sections above, include:
1. **Table of Contents** — clickable navigation
2. **Executive Summary** — overall severity counts across ALL tracks
3. **Assessment Walkthrough** — phase-by-phase summary (note parallel Track A/B execution)
4. **Exploitation Summary Matrix** — from DAST + cross-validation results
5. **QA Review Summary** — if QA validation data is available
6. **Recommendations** — prioritized, drawing from both DAST and SAST findings
7. **Testing Methodology** — note the dual-track approach

## Your Workflow

1. **Register findings** using create_finding for each vulnerability
2. **Generate the markdown report** with the four-section structure
3. **Generate PDF report** using generate_pdf_report with the full markdown
4. ${jiraProject ? `**Create Jira tickets** in ${jiraProject} for HIGH and CRITICAL findings` : "No Jira project configured"}
5. ${emailRecipients.length > 0 ? `**Email report** to: ${emailRecipients.join(", ")}` : "No email recipients configured"}

Begin dual-track report generation now.`;

    return prompt;
  }

  getSystemPrompt(): string {
    return `You are the Report Agent, responsible for compiling security findings into professional reports.

## Your Capabilities:
- Finding documentation
- Report generation (markdown, HTML, JSON)
- Professional PDF report generation via Playwright
- Jira ticket creation
- SharePoint upload
- Email distribution

## Decision Guidelines:

### When to use create_finding:
- For each vulnerability that needs documentation
- Ensure all findings from previous agents are captured
- Deduplicate similar findings

### When to use generate_report:
- After all findings are documented
- Use appropriate format for audience
- Include evidence for technical report
- Executive summary for management

### When to use generate_pdf_report:
- ALWAYS as the final step of every report generation workflow
- Pass the full markdown report content via markdown_content for an identical PDF rendering
- Use a descriptive output_filename like "assessment-report-YYYY-MM-DD.pdf"
- The PDF renders the markdown with professional styling, tables, code blocks, and page numbers

### When to use create_jira_ticket:
- For HIGH and CRITICAL findings only
- Include all relevant details
- Link to original evidence
- Set appropriate priority

### When to use upload_report:
- After report is generated
- Include meaningful filename with date
- Send to appropriate recipients

## Report Quality Guidelines:
1. Clear executive summary (non-technical)
2. Severity-sorted findings
3. Actionable remediation steps
4. Evidence that proves the issue
5. CVSS/CWE references where applicable

## Code Context in Reports
- When a finding has metadata.codeContextVerified = true, show the source file:line reference
  and include the code snippet in the finding's evidence section.
- When a finding has metadata.remediationVerified = true, include a "Code Remediation"
  subsection with vulnerable code (before), fixed code (after), and explanation.
- For findings WITHOUT code context, document them normally — code reference is supplemental.

## CRITICAL: Complete Enumeration Rules (MANDATORY)

These rules are ABSOLUTE and override all other formatting preferences:

1. **ALL means ALL**: If a scan finds N items, ALL N must be listed individually in the report.
   - 65 AWS tokens → list ALL 65 in a table (key ID, file, commit, author, date)
   - 14 private keys → list ALL 14 with specific commit hashes
   - 11 injection points → list ALL 11 with file:line and expression
   - 31 vulnerable packages → list ALL 31 with package name, advisory link

2. **BANNED language — NEVER use these without immediate specifics:**
   - "various" → list every item (e.g., "commits f63354fc, 0130c007, edd36c0e")
   - "multiple" → state exact count and list them
   - "several", "some", "others", "etc.", "and more" → list every remaining item
   - "in git history" without commit hash → must include specific commit hash
   - "N instances found" without listing → must list all N in a table

3. **Evidence for every claim:**
   - "All 50 returned 200" → show a sample HTTP response (status + headers + body)
   - "No rate limiting" → show the absence of X-RateLimit headers in a sample response
   - "Key still in current code" → show ls -la or cat excerpt
   - "Schema reconstructed" → show the reconstructed schema

4. **Every finding gets IDENTICAL detail regardless of severity:**
   - Critical, High, Medium, Low, Informational → same reproduction steps, exploitation scenario, evidence
   - NO abbreviated findings for lower severities

5. **Internal reports show real data:**
   - Show actual secret values (AWS key IDs, PAT tokens, DB passwords)
   - Show actual PII from exploitation evidence (SSNs, emails)
   - Show actual file paths, commit hashes, IP addresses
   - NEVER redact or mask — the audience has full access to these systems

## Required Report Sections:
1. Table of Contents (clickable navigation)
2. Executive Summary (severity counts + exploitability status)
3. Scope & Methodology (targets, tools, auth method)
4. Assessment Walkthrough (phase-by-phase tables: Step | Action | Outcome)
5. Critical & High Findings (full detail)
6. Medium Findings (full detail — same level as Critical)
7. Low & Informational Findings (full detail — same level as Critical)
8. Exploitation Summary Matrix (table: Test | Target | Result | Exploitable)
9. Attack Chain Analysis (confirmed chains, refuted chains, defense-in-depth analysis)
10. Detailed Methodology (per-phase: objective, why it matters, tools + rationale, techniques, findings)
11. SAST Analysis Summary (Semgrep rules, secrets by type, defense analysis)
12. Compliance Mapping (OWASP Top 10, CWE, NIST, PCI-DSS)
13. 116-Test Coverage Checklist (PASS/FAIL/SKIPPED/N/A for every test_id)
14. Recommendations (prioritized: immediate, short-term, medium-term)`;
  }

  protected extractFindings(result: string, toolName: string, target?: string): void {
    try {
      const parsed = JSON.parse(result);

      // Track created findings
      if (toolName === "create_finding" && parsed.id) {
        if (!this.state.context.createdFindings) {
          this.state.context.createdFindings = [];
        }
        this.state.context.createdFindings.push(parsed.id);
      }

      // Track Jira tickets
      if (toolName === "create_jira_ticket" && parsed.ticket_key) {
        if (!this.state.context.jiraTickets) {
          this.state.context.jiraTickets = [];
        }
        this.state.context.jiraTickets.push({
          key: parsed.ticket_key,
          url: parsed.url,
          finding_id: parsed.finding_id,
        });

        // Add as a finding note
        this.addFinding({
          title: `Jira Ticket Created: ${parsed.ticket_key}`,
          severity: "info",
          target: parsed.finding_id || target || "unknown",
          description: `Jira ticket ${parsed.ticket_key} created for tracking.`,
          source: "report-agent",
          metadata: { ticketKey: parsed.ticket_key, url: parsed.url },
        });
      }

      // Track generated reports
      if (toolName === "generate_report") {
        this.state.context.generatedReport = {
          format: parsed.format,
          content: parsed.content,
          summary: parsed.summary,
        };
      }

      // Track PDF generation
      if (toolName === "generate_pdf_report" && parsed.status === "generated") {
        this.state.context.generatedPdf = {
          path: parsed.pdf_path,
          size_kb: parsed.size_kb,
          findings_count: parsed.findings_count,
        };
      }

      // Track uploads
      if (toolName === "upload_report" && parsed.sharepoint_url) {
        this.state.context.reportUrl = parsed.sharepoint_url;
        this.state.context.emailsSent = parsed.emails_sent;
      }

      // Import Cycode findings
      if (toolName === "import_cycode_findings" && parsed.findings) {
        for (const finding of parsed.findings) {
          this.addFinding({
            title: finding.title || finding.rule_name,
            severity: this.mapSeverity(finding.severity),
            target: finding.file || finding.path || "unknown",
            description: finding.description || finding.message,
            source: "cycode",
            metadata: {
              cycode_id: finding.id,
              file: finding.file,
              line: finding.line,
            },
          });
        }
      }
    } catch {
      // Not JSON
    }
  }

  /**
   * Override generateSummary for report-specific summary
   */
  protected generateSummary(): string {
    const parts = [];

    if (this.state.context.createdFindings?.length) {
      parts.push(`${this.state.context.createdFindings.length} findings documented`);
    }

    if (this.state.context.jiraTickets?.length) {
      parts.push(`${this.state.context.jiraTickets.length} Jira tickets created`);
    }

    if (this.state.context.generatedReport) {
      parts.push(`${this.state.context.generatedReport.format} report generated`);
    }

    if (this.state.context.generatedPdf) {
      parts.push(`PDF report generated (${this.state.context.generatedPdf.size_kb} KB)`);
    }

    if (this.state.context.reportUrl) {
      parts.push(`Report uploaded to SharePoint`);
    }

    if (this.state.context.emailsSent?.length) {
      parts.push(`Report emailed to ${this.state.context.emailsSent.length} recipients`);
    }

    if (parts.length === 0) {
      return "Report agent completed with no actions taken.";
    }

    return `Report agent completed: ${parts.join(", ")}.`;
  }
}
