/**
 * Security Scan Agent Implementation
 *
 * Static application security testing (SAST) on local repositories.
 * Scans for vulnerabilities, secrets, dependencies, and IaC issues.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { codeScanHandlers } from "../../tools/code-scan";

const SECURITY_SCAN_AGENT_CONFIG: AgentConfig = {
  name: "security-scan-agent",
  description: "Code security scanning agent (SAST)",
  maxIterations: 25,
  timeoutMs: 900000, // 15 minutes
  requiresScopeValidation: false, // Local scanning only
  tools: [
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
  ],
};

const SECURITY_SCAN_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "detect_languages",
    description: `Detect programming languages used in a repository.
Use this FIRST to determine which scanners to run.`,
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
    name: "scan_repository",
    description: `Run comprehensive security scan on a repository.
Combines multiple scanners based on detected languages.
Use scan_types: ["all"] for complete assessment.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        scan_types: {
          type: "array",
          items: { type: "string" },
          description: "Scan types: all, sast, secrets, dependencies, iac",
        },
        severity_threshold: {
          type: "string",
          description: "Minimum severity to report: info, low, medium, high, critical",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_semgrep",
    description: `Run Semgrep SAST scanner with configurable rules.
Works on many languages. Good for finding security anti-patterns.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        config: {
          type: "string",
          description: "Semgrep config: auto, p/security-audit, p/owasp-top-ten",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_bandit",
    description: `Run Bandit Python security scanner.
Use when Python code is detected.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to Python code",
        },
        severity: {
          type: "string",
          description: "Minimum severity: low, medium, high",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_njsscan",
    description: `Run njsscan for JavaScript/Node.js security scanning.
Use when JavaScript or TypeScript is detected.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to JS/TS code",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_secrets",
    description: `Scan for hardcoded secrets and credentials.
Uses gitleaks and trufflehog. Run on ALL repositories.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
        include_git_history: {
          type: "boolean",
          description: "Scan git history for old secrets",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_dependencies",
    description: `Scan dependencies for known vulnerabilities.
Checks package.json, requirements.txt, Gemfile, etc.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to repository",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "scan_iac",
    description: `Scan Infrastructure as Code for misconfigurations.
Supports Terraform, CloudFormation, Kubernetes, Docker.`,
    input_schema: {
      type: "object",
      properties: {
        repo_path: {
          type: "string",
          description: "Path to IaC files",
        },
        framework: {
          type: "string",
          description: "IaC framework: terraform, cloudformation, kubernetes, docker",
        },
      },
      required: ["repo_path"],
    },
  },
  {
    name: "analyze_code_context",
    description: `Deep analysis of specific code sections.
Use for detailed review of suspicious findings.`,
    input_schema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to source file",
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
          description: "Type of vulnerability to analyze: sqli, xss, rce, etc.",
        },
      },
      required: ["file_path"],
    },
  },
  {
    name: "generate_scan_report",
    description: `Generate a formatted report from scan results.
Use at the end to compile all findings.`,
    input_schema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          description: "Output format: markdown, json, html",
        },
        include_remediation: {
          type: "boolean",
          description: "Include remediation guidance",
        },
      },
      required: ["format"],
    },
  },
];

export class SecurityScanAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(SECURITY_SCAN_AGENT_CONFIG, codeScanHandlers, onProgress);
  }

  getToolDefinitions(): ToolDefinition[] {
    return SECURITY_SCAN_TOOL_DEFINITIONS;
  }

  buildInitialPrompt(input: AgentInput): string {
    const severityThreshold = input.severity || "medium";
    const scanTypes = input.options?.scanTypes || ["all"];

    let prompt = `# Code Security Scanning Task

You are the Security Scan Agent. Your mission is to perform static security analysis on local repositories.

## Repositories to Scan:
`;

    if (input.repoPaths && input.repoPaths.length > 0) {
      for (const path of input.repoPaths) {
        prompt += `- ${path}\n`;
      }
    } else {
      prompt += "No repositories specified. Please request paths from the user.\n";
    }

    prompt += `
## Scan Configuration:
- Minimum Severity: ${severityThreshold}
- Scan Types: ${scanTypes.join(", ")}

## Your Workflow:

1. **Language Detection:**
   - Run detect_languages on each repository
   - Identify which scanners are applicable

2. **Comprehensive Scan (if scan_types includes "all"):**
   - Run scan_repository with scan_types: ["all"]
   - This combines all available scanners

3. **OR Targeted Scans:**
   - SAST: scan_semgrep for general SAST
   - Python: scan_bandit
   - JavaScript/Node: scan_njsscan
   - Secrets: scan_secrets (ALWAYS run this)
   - Dependencies: scan_dependencies
   - IaC: scan_iac if Terraform/K8s/Docker found

4. **Deep Analysis:**
   - For critical findings, use analyze_code_context
   - Understand the vulnerability in detail
   - Determine if it's exploitable

5. **Report Generation:**
   - generate_scan_report with findings summary

## Path Mapping:
- Local paths like ~/projects/app → /mnt/host-home/projects/app
- Paths starting with / are used as-is

## Output Requirements:

Provide:
- Languages detected
- Vulnerabilities by severity
- Secrets found (redacted)
- Vulnerable dependencies
- IaC misconfigurations
- Recommendations for remediation

Begin code security scanning now.`;

    return prompt;
  }

  getSystemPrompt(): string {
    return `You are the Security Scan Agent, specialized in static code analysis and security scanning.

## Your Capabilities:
- Language detection
- Semgrep SAST scanning
- Python-specific scanning (Bandit)
- JavaScript/Node scanning (njsscan)
- Secret detection (gitleaks, trufflehog)
- Dependency vulnerability scanning
- IaC security scanning (Checkov, KICS)

## Decision Guidelines:

### Language-specific scanners:
- Python detected → scan_bandit
- JavaScript/TypeScript → scan_njsscan
- Any language → scan_semgrep (universal)

### Always run:
- scan_secrets - Secrets can be in any file type
- scan_dependencies - If any package manager files exist

### IaC scanning:
- Terraform (.tf files) → scan_iac with framework: terraform
- Kubernetes (*.yaml with kind:) → scan_iac with framework: kubernetes
- Docker (Dockerfile) → scan_iac with framework: docker

### When to use analyze_code_context:
- For critical/high severity findings
- When you need to understand the code flow
- To determine if a finding is a false positive
- To identify the exploitable endpoint

## Important Notes:
1. No scope validation needed (local files only)
2. Be thorough - scan for all vulnerability types
3. Secrets are critical - always check git history too
4. Prioritize findings that could lead to RCE, SQLi, or data exposure
5. Note which findings map to OWASP Top 10`;
  }

  protected extractFindings(result: string, toolName: string, target?: string): void {
    super.extractFindings(result, toolName, target);

    try {
      const parsed = JSON.parse(result);

      // Secret detection results
      if (toolName === "scan_secrets") {
        for (const secret of parsed.secrets || parsed.findings || []) {
          this.addFinding({
            title: `Hardcoded Secret: ${secret.type || secret.rule || "credential"}`,
            severity: "critical",
            target: secret.file || target || "unknown",
            description: `Hardcoded ${secret.type || "secret"} found. File: ${secret.file}, Line: ${secret.line || "unknown"}`,
            evidence: secret.redacted || "[REDACTED]", // Never log actual secrets
            remediation: "Remove hardcoded secret and use environment variables or a secrets manager.",
            source: "secret-scanner",
            metadata: {
              file: secret.file,
              line: secret.line,
              rule: secret.rule,
            },
          });
        }
      }

      // Semgrep results
      if (toolName === "scan_semgrep" && parsed.results) {
        for (const result of parsed.results) {
          this.addFinding({
            title: result.check_id || result.rule_id || "Semgrep Finding",
            severity: this.mapSeverity(result.extra?.severity || result.severity),
            target: result.path || target || "unknown",
            description: result.extra?.message || result.message || "Security issue detected",
            evidence: result.extra?.lines || result.code,
            remediation: result.extra?.fix || result.fix,
            source: "semgrep",
            metadata: {
              file: result.path,
              line: result.start?.line,
              rule: result.check_id,
              cwe: result.extra?.metadata?.cwe,
            },
          });
        }
      }

      // Bandit results
      if (toolName === "scan_bandit" && parsed.results) {
        for (const result of parsed.results) {
          this.addFinding({
            title: `${result.test_name || result.test_id}: ${result.issue_text?.substring(0, 50) || "Security Issue"}`,
            severity: this.mapSeverity(result.issue_severity),
            target: result.filename || target || "unknown",
            description: result.issue_text,
            evidence: result.code,
            source: "bandit",
            metadata: {
              file: result.filename,
              line: result.line_number,
              test_id: result.test_id,
              cwe: result.issue_cwe?.id,
            },
          });
        }
      }

      // Dependency scan results
      if (toolName === "scan_dependencies") {
        for (const vuln of parsed.vulnerabilities || parsed.results || []) {
          this.addFinding({
            title: `Vulnerable Dependency: ${vuln.package || vuln.name}`,
            severity: this.mapSeverity(vuln.severity),
            target: vuln.file || target || "unknown",
            description: `${vuln.package || vuln.name}@${vuln.version} has known vulnerability: ${vuln.vulnerability || vuln.cve || vuln.title}`,
            remediation: vuln.fix_version ? `Upgrade to ${vuln.fix_version}` : "Update to latest secure version",
            source: "dependency-scan",
            metadata: {
              package: vuln.package,
              version: vuln.version,
              cve: vuln.cve,
              fixVersion: vuln.fix_version,
            },
          });
        }
      }

      // IaC scan results
      if (toolName === "scan_iac") {
        for (const check of parsed.results || parsed.checks || []) {
          if (check.status === "FAILED" || check.result === "FAILED") {
            this.addFinding({
              title: `IaC Misconfiguration: ${check.check_id || check.name}`,
              severity: this.mapSeverity(check.severity),
              target: check.file || check.resource || target || "unknown",
              description: check.description || check.message,
              remediation: check.guideline || check.fix,
              source: "iac-scan",
              metadata: {
                file: check.file,
                resource: check.resource,
                check_id: check.check_id,
              },
            });
          }
        }
      }

      // Store detected languages in context
      if (toolName === "detect_languages" && parsed.languages) {
        this.state.context.detectedLanguages = parsed.languages;
      }
    } catch {
      // Not JSON
    }
  }
}
