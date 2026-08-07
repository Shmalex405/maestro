/**
 * QA Tools
 *
 * Tools for the QA Agent to validate findings, check coverage,
 * and coordinate with other agents.
 */

import { AgentFinding, Severity } from "../agents/base-agent";
import { executeInKali } from "../utils/docker-exec";

// QA-specific types
export interface ValidationResult {
  findingId: string;
  validationStatus: "confirmed" | "not_reproduced" | "inconclusive";
  confidence: number;
  retestEvidence?: string;
  notes?: string;
}

export interface CoverageGap {
  area: string;
  description: string;
  recommendation: string;
  priority: "high" | "medium" | "low";
}

export interface CoverageAnalysis {
  testedAreas: string[];
  gaps: CoverageGap[];
  coverageScore: number;
  recommendations: string[];
}

export interface ConfidenceScore {
  findingId: string;
  score: number;
  factors: {
    evidenceQuality: number;
    reproducibility: number;
    impactClarity: number;
    falsePositiveLikelihood: number;
  };
  notes: string;
}

export interface FollowUpRequest {
  agent: "recon" | "vuln-scan" | "web-app" | "exploit";
  targets: string[];
  focus: string;
  context?: Record<string, any>;
}

// Store for findings context (set by QA agent during execution)
let findingsContext: AgentFinding[] = [];
let agentResultsContext: Record<string, any> = {};

export function setQAContext(
  findings: AgentFinding[],
  agentResults: Record<string, any>
): void {
  findingsContext = findings;
  agentResultsContext = agentResults;
}

// Tool definitions for MCP/Claude
export const qaTools = [
  {
    name: "validate_finding",
    description:
      "Re-test a specific finding to confirm it's real. Returns validation status and updated confidence.",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: {
          type: "string",
          description: "ID of the finding to validate",
        },
        retest_method: {
          type: "string",
          enum: ["quick", "thorough"],
          description: "How thoroughly to re-test (default: quick)",
          default: "quick",
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
      "Analyze what attack vectors were tested vs what could have been tested. Identifies gaps.",
    inputSchema: {
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
          description:
            "Specific areas to check (auth, injection, config, etc.)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "score_confidence",
    description:
      "Evaluate a finding's evidence quality and assign a confidence score (1-10).",
    inputSchema: {
      type: "object",
      properties: {
        finding_id: {
          type: "string",
          description: "ID of the finding to score",
        },
        criteria: {
          type: "object",
          description: "Optional specific criteria weights to use",
        },
      },
      required: ["finding_id"],
    },
  },
  {
    name: "request_agent_followup",
    description:
      "Request a specific agent to run additional targeted tests. Returns request ID for tracking.",
    inputSchema: {
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
      "Get detailed summary of what an agent did during its execution.",
    inputSchema: {
      type: "object",
      properties: {
        agent_name: {
          type: "string",
          description: "Name of the agent to summarize",
        },
      },
      required: ["agent_name"],
    },
  },
  {
    name: "compare_findings",
    description:
      "Cross-reference findings from different sources to identify discrepancies or confirmations.",
    inputSchema: {
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
      "List all findings in context, optionally filtered by severity or source.",
    inputSchema: {
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
          description: "Maximum number of findings to return",
          default: 50,
        },
      },
    },
  },
  {
    name: "get_finding_details",
    description: "Get full details of a specific finding by ID.",
    inputSchema: {
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
];

// Tool handlers
export const qaHandlers: Record<string, Function> = {
  validate_finding: async (args: {
    finding_id: string;
    retest_method?: "quick" | "thorough";
    custom_payload?: string;
  }): Promise<string> => {
    const { finding_id, retest_method = "quick", custom_payload } = args;

    // Find the finding
    const finding = findingsContext.find((f) => f.id === finding_id);
    if (!finding) {
      return JSON.stringify({
        error: "Finding not found",
        finding_id,
        available_ids: findingsContext.slice(0, 10).map((f) => f.id),
      });
    }

    const result: ValidationResult = {
      findingId: finding_id,
      validationStatus: "inconclusive",
      confidence: 5,
      notes: "",
    };

    try {
      // Determine validation approach based on finding type
      const findingLower = finding.title.toLowerCase();
      const target = finding.target;

      if (findingLower.includes("sql") || findingLower.includes("injection")) {
        // SQL injection validation
        const payload = custom_payload || "' OR '1'='1";
        const cmd =
          retest_method === "thorough"
            ? `sqlmap -u "${target}" --batch --level=2 --risk=1 --technique=BEU`
            : `curl -s -o /dev/null -w "%{http_code}" "${target}${encodeURIComponent(payload)}"`;

        const output = await executeInKali(cmd);
        result.retestEvidence = output;

        if (
          output.includes("injectable") ||
          output.includes("vulnerability")
        ) {
          result.validationStatus = "confirmed";
          result.confidence = 9;
          result.notes = "SQL injection confirmed via re-test";
        } else if (output.includes("500") || output.includes("error")) {
          result.validationStatus = "confirmed";
          result.confidence = 7;
          result.notes = "Possible SQL injection - error response observed";
        } else {
          result.validationStatus = "not_reproduced";
          result.confidence = 3;
          result.notes = "Could not reproduce SQL injection";
        }
      } else if (findingLower.includes("xss") || findingLower.includes("cross-site")) {
        // XSS validation
        const payload = custom_payload || "<script>alert(1)</script>";
        const cmd = `curl -s "${target}" -d "test=${encodeURIComponent(payload)}"`;
        const output = await executeInKali(cmd);
        result.retestEvidence = output.substring(0, 2000);

        if (output.includes(payload) || output.includes("<script>")) {
          result.validationStatus = "confirmed";
          result.confidence = 8;
          result.notes = "XSS reflected in response";
        } else {
          result.validationStatus = "not_reproduced";
          result.confidence = 4;
          result.notes = "Payload not reflected - may be filtered";
        }
      } else if (findingLower.includes("open port") || findingLower.includes("service")) {
        // Port/service validation
        const portMatch = finding.description.match(/port\s*(\d+)/i);
        const port = portMatch ? portMatch[1] : "80";
        const cmd = `nmap -sV -p ${port} ${target} --open`;
        const output = await executeInKali(cmd);
        result.retestEvidence = output;

        if (output.includes("open")) {
          result.validationStatus = "confirmed";
          result.confidence = 9;
          result.notes = "Port confirmed open";
        } else {
          result.validationStatus = "not_reproduced";
          result.confidence = 2;
          result.notes = "Port appears closed or filtered";
        }
      } else if (findingLower.includes("cve") || finding.metadata?.cve) {
        // CVE validation via nuclei
        const cve = finding.metadata?.cve || finding.title.match(/CVE-\d{4}-\d+/)?.[0];
        if (cve) {
          const cmd = `nuclei -u ${target} -id ${cve.toLowerCase()} -silent`;
          const output = await executeInKali(cmd);
          result.retestEvidence = output;

          if (output.includes(cve) || output.includes("vulnerability")) {
            result.validationStatus = "confirmed";
            result.confidence = 9;
            result.notes = `${cve} confirmed via nuclei`;
          } else {
            result.validationStatus = "inconclusive";
            result.confidence = 5;
            result.notes = `Could not confirm ${cve} - may need manual verification`;
          }
        }
      } else {
        // Generic HTTP validation
        const cmd = `curl -s -o /dev/null -w "%{http_code}|%{time_total}" "${target}"`;
        const output = await executeInKali(cmd);
        result.retestEvidence = output;
        result.validationStatus = "inconclusive";
        result.confidence = 5;
        result.notes =
          "Generic validation - finding type not specifically handled. Manual review recommended.";
      }
    } catch (error) {
      result.validationStatus = "inconclusive";
      result.confidence = 3;
      result.notes = `Validation error: ${String(error)}`;
      result.retestEvidence = String(error);
    }

    return JSON.stringify(result, null, 2);
  },

  check_coverage: async (args: {
    targets: string[];
    focus_areas?: string[];
  }): Promise<string> => {
    const { targets, focus_areas } = args;

    // Define all possible testing areas
    const allAreas = [
      {
        category: "Authentication",
        checks: [
          "login_bypass",
          "session_management",
          "password_policy",
          "mfa_bypass",
          "oauth_misconfig",
        ],
      },
      {
        category: "Authorization",
        checks: ["idor", "privilege_escalation", "access_controls", "rbac"],
      },
      {
        category: "Injection",
        checks: ["sqli", "xss", "command_injection", "template_injection", "ldap_injection"],
      },
      {
        category: "Configuration",
        checks: ["headers", "cors", "error_handling", "debug_mode", "default_creds"],
      },
      {
        category: "Cryptography",
        checks: ["tls_config", "weak_algorithms", "key_management"],
      },
      {
        category: "Business Logic",
        checks: ["rate_limiting", "workflow_bypass", "race_conditions"],
      },
      {
        category: "API Security",
        checks: ["api_auth", "input_validation", "api_rate_limiting", "graphql"],
      },
    ];

    // Analyze what was tested based on findings and agent results
    const testedAreas: string[] = [];
    const gaps: CoverageGap[] = [];

    for (const area of allAreas) {
      // Check if focus_areas filter applies
      if (focus_areas && !focus_areas.some((f) => area.category.toLowerCase().includes(f.toLowerCase()))) {
        continue;
      }

      let areaWasTested = false;

      for (const check of area.checks) {
        // Look for findings related to this check
        const relatedFindings = findingsContext.filter(
          (f) =>
            f.title.toLowerCase().includes(check.replace("_", " ")) ||
            f.description.toLowerCase().includes(check.replace("_", " "))
        );

        if (relatedFindings.length > 0) {
          testedAreas.push(`${area.category}/${check}`);
          areaWasTested = true;
        }
      }

      if (!areaWasTested) {
        // Determine gap priority based on category
        let priority: "high" | "medium" | "low" = "medium";
        if (["Authentication", "Injection", "Authorization"].includes(area.category)) {
          priority = "high";
        } else if (["Cryptography", "Business Logic"].includes(area.category)) {
          priority = "low";
        }

        gaps.push({
          area: area.category,
          description: `No testing coverage for ${area.category} (checks: ${area.checks.join(", ")})`,
          recommendation: `Run targeted ${area.category.toLowerCase()} tests against ${targets.slice(0, 3).join(", ")}`,
          priority,
        });
      }
    }

    // Calculate coverage score
    const totalChecks = allAreas.reduce((sum, a) => sum + a.checks.length, 0);
    const coverageScore = Math.round((testedAreas.length / totalChecks) * 100);

    const analysis: CoverageAnalysis = {
      testedAreas,
      gaps: gaps.sort((a, b) => {
        const priorityOrder = { high: 0, medium: 1, low: 2 };
        return priorityOrder[a.priority] - priorityOrder[b.priority];
      }),
      coverageScore,
      recommendations: gaps.filter((g) => g.priority === "high").map((g) => g.recommendation),
    };

    return JSON.stringify(analysis, null, 2);
  },

  score_confidence: async (args: {
    finding_id: string;
    criteria?: Record<string, number>;
  }): Promise<string> => {
    const { finding_id, criteria } = args;

    const finding = findingsContext.find((f) => f.id === finding_id);
    if (!finding) {
      return JSON.stringify({
        error: "Finding not found",
        finding_id,
      });
    }

    // Default criteria weights
    const weights = {
      evidenceQuality: criteria?.evidenceQuality || 0.3,
      reproducibility: criteria?.reproducibility || 0.3,
      impactClarity: criteria?.impactClarity || 0.2,
      falsePositiveLikelihood: criteria?.falsePositiveLikelihood || 0.2,
    };

    // Score each factor (1-10)
    const factors = {
      evidenceQuality: 5,
      reproducibility: 5,
      impactClarity: 5,
      falsePositiveLikelihood: 5,
    };

    // Evidence quality
    if (finding.evidence) {
      const evidenceLen = finding.evidence.length;
      if (evidenceLen > 1000) factors.evidenceQuality = 9;
      else if (evidenceLen > 500) factors.evidenceQuality = 7;
      else if (evidenceLen > 100) factors.evidenceQuality = 5;
      else factors.evidenceQuality = 3;
    } else {
      factors.evidenceQuality = 2;
    }

    // Reproducibility (based on source)
    const automatedSources = ["nuclei", "nikto", "sqlmap", "nmap"];
    const isAutomated = automatedSources.some((s) =>
      finding.source.toLowerCase().includes(s)
    );
    if (isAutomated) {
      factors.reproducibility = 7; // Automated tools are generally reproducible
    } else {
      factors.reproducibility = 5; // Manual findings need verification
    }

    // Impact clarity
    if (finding.remediation && finding.remediation.length > 50) {
      factors.impactClarity = 8;
    } else if (finding.description.length > 200) {
      factors.impactClarity = 6;
    } else {
      factors.impactClarity = 4;
    }

    // False positive likelihood (inverse - lower is better for FP likelihood)
    const fpPatterns = [
      "informational",
      "potential",
      "possible",
      "may be",
      "could be",
    ];
    const hasFPPattern = fpPatterns.some((p) =>
      finding.description.toLowerCase().includes(p)
    );
    if (hasFPPattern) {
      factors.falsePositiveLikelihood = 4; // Higher FP likelihood = lower score
    } else if (finding.severity === "critical" || finding.severity === "high") {
      factors.falsePositiveLikelihood = 7;
    } else {
      factors.falsePositiveLikelihood = 5;
    }

    // Calculate weighted score
    const score = Math.round(
      factors.evidenceQuality * weights.evidenceQuality * 10 +
        factors.reproducibility * weights.reproducibility * 10 +
        factors.impactClarity * weights.impactClarity * 10 +
        factors.falsePositiveLikelihood * weights.falsePositiveLikelihood * 10
    ) / 10;

    const result: ConfidenceScore = {
      findingId: finding_id,
      score: Math.min(10, Math.max(1, score)),
      factors,
      notes: `Confidence based on: evidence length=${finding.evidence?.length || 0}, source=${finding.source}, severity=${finding.severity}`,
    };

    return JSON.stringify(result, null, 2);
  },

  request_agent_followup: async (args: FollowUpRequest): Promise<string> => {
    // This creates a follow-up request that the orchestrator will process
    const requestId = `followup-${Date.now()}`;

    const request = {
      requestId,
      agent: args.agent,
      targets: args.targets,
      focus: args.focus,
      context: args.context || {},
      status: "pending",
      createdAt: new Date().toISOString(),
    };

    // Follow-up requests are recorded for the QA agent's own tracking; there is
    // no background dispatcher that picks them up. Report that honestly so the QA
    // agent re-runs the relevant tool itself instead of waiting on a queue that
    // will never drain.
    return JSON.stringify(
      {
        success: true,
        message: `Follow-up request recorded for ${args.agent} agent`,
        request,
        note: "Not auto-dispatched — re-run the relevant tool directly to act on this follow-up.",
      },
      null,
      2
    );
  },

  get_agent_summary: async (args: { agent_name: string }): Promise<string> => {
    const { agent_name } = args;

    const agentResult = agentResultsContext[agent_name];
    if (!agentResult) {
      return JSON.stringify({
        error: "Agent results not found",
        agent_name,
        available_agents: Object.keys(agentResultsContext),
      });
    }

    const summary = {
      agentName: agent_name,
      success: agentResult.success,
      findingsCount: agentResult.findings?.length || 0,
      toolCallsCount: agentResult.toolCallsCount || 0,
      executionTimeMs: agentResult.executionTimeMs || 0,
      iterations: agentResult.iterations || 0,
      errors: agentResult.errors || [],
      summary: agentResult.summary || "No summary available",
      findingsBySeverity: {
        critical: agentResult.findings?.filter((f: AgentFinding) => f.severity === "critical").length || 0,
        high: agentResult.findings?.filter((f: AgentFinding) => f.severity === "high").length || 0,
        medium: agentResult.findings?.filter((f: AgentFinding) => f.severity === "medium").length || 0,
        low: agentResult.findings?.filter((f: AgentFinding) => f.severity === "low").length || 0,
        info: agentResult.findings?.filter((f: AgentFinding) => f.severity === "info").length || 0,
      },
    };

    return JSON.stringify(summary, null, 2);
  },

  compare_findings: async (args: { finding_ids: string[] }): Promise<string> => {
    const { finding_ids } = args;

    const findings = finding_ids
      .map((id) => findingsContext.find((f) => f.id === id))
      .filter(Boolean) as AgentFinding[];

    if (findings.length === 0) {
      return JSON.stringify({
        error: "No findings found",
        requested_ids: finding_ids,
      });
    }

    // Group by target
    const byTarget: Record<string, AgentFinding[]> = {};
    for (const f of findings) {
      if (!byTarget[f.target]) byTarget[f.target] = [];
      byTarget[f.target].push(f);
    }

    // Analyze similarities and differences
    const comparison = {
      totalCompared: findings.length,
      byTarget,
      commonalities: [] as string[],
      discrepancies: [] as string[],
      recommendations: [] as string[],
    };

    // Check for findings with same target but different severities
    for (const [target, targetFindings] of Object.entries(byTarget)) {
      if (targetFindings.length > 1) {
        const severities = [...new Set(targetFindings.map((f) => f.severity))];
        if (severities.length > 1) {
          comparison.discrepancies.push(
            `Target ${target} has findings with different severities: ${severities.join(", ")}`
          );
          comparison.recommendations.push(
            `Validate severity for ${target} - multiple assessments disagree`
          );
        } else {
          comparison.commonalities.push(
            `Multiple tools confirm issues on ${target} (severity: ${severities[0]})`
          );
        }
      }
    }

    // Check for similar titles across different sources
    const titleGroups: Record<string, AgentFinding[]> = {};
    for (const f of findings) {
      const normalizedTitle = f.title.toLowerCase().replace(/[^a-z0-9]/g, " ");
      if (!titleGroups[normalizedTitle]) titleGroups[normalizedTitle] = [];
      titleGroups[normalizedTitle].push(f);
    }

    for (const [title, group] of Object.entries(titleGroups)) {
      if (group.length > 1) {
        const sources = [...new Set(group.map((f) => f.source))];
        if (sources.length > 1) {
          comparison.commonalities.push(
            `"${group[0].title}" confirmed by multiple sources: ${sources.join(", ")}`
          );
        }
      }
    }

    return JSON.stringify(comparison, null, 2);
  },

  list_findings: async (args: {
    severity?: Severity;
    source?: string;
    limit?: number;
  }): Promise<string> => {
    let filtered = [...findingsContext];

    if (args.severity) {
      const severityOrder = ["info", "low", "medium", "high", "critical"];
      const minIndex = severityOrder.indexOf(args.severity);
      filtered = filtered.filter(
        (f) => severityOrder.indexOf(f.severity) >= minIndex
      );
    }

    if (args.source) {
      filtered = filtered.filter((f) =>
        f.source.toLowerCase().includes(args.source!.toLowerCase())
      );
    }

    const limit = args.limit || 50;
    filtered = filtered.slice(0, limit);

    // Return summary view
    const findings = filtered.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      target: f.target,
      source: f.source,
      hasEvidence: !!f.evidence,
    }));

    return JSON.stringify(
      {
        total: findingsContext.length,
        returned: findings.length,
        findings,
      },
      null,
      2
    );
  },

  get_finding_details: async (args: { finding_id: string }): Promise<string> => {
    const finding = findingsContext.find((f) => f.id === args.finding_id);

    if (!finding) {
      return JSON.stringify({
        error: "Finding not found",
        finding_id: args.finding_id,
      });
    }

    return JSON.stringify(finding, null, 2);
  },
};
