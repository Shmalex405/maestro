/**
 * Security Scan Agent
 * 
 * Performs static application security testing (SAST) on local repositories.
 * Complements Cycode by providing on-demand, independent code scanning.
 * 
 * Capabilities:
 * - Multi-language SAST (Semgrep, Bandit, njsscan)
 * - Secrets detection (gitleaks, trufflehog)
 * - Dependency vulnerability scanning (grype, safety, npm audit)
 * - Infrastructure as Code scanning (checkov, kics)
 * - Code context analysis for exploitation targeting
 * 
 * Usage: 
 * - Scan any local repository for vulnerabilities
 * - Generate findings in Cycode-compatible format
 * - Feed findings to exploit-agent for validation
 */

export interface ScanTarget {
  repo_path: string;
  name?: string;
  branch?: string;
}

export interface ScanOptions {
  scan_types: ("sast" | "secrets" | "dependencies" | "iac" | "all")[];
  severity_threshold: "info" | "low" | "medium" | "high" | "critical";
  languages?: string[];
  exclude_paths?: string[];
}

export interface CodeFinding {
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  file: string;
  line: number;
  line_end?: number;
  code_snippet?: string;
  description: string;
  scanner: string;
  cwe?: string;
  owasp?: string;
  remediation?: string;
  // For linking to exploitation
  exploitable?: boolean;
  exploit_validated?: boolean;
  exploit_evidence?: string;
}

export interface ScanResult {
  scan_id: string;
  repo_path: string;
  repo_name?: string;
  started_at: string;
  completed_at?: string;
  languages: string[];
  findings: CodeFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  scanners_used: string[];
}

export const securityScanAgentConfig = {
  name: "security-scan-agent",
  description: "Static application security testing agent for local repositories",
  
  defaults: {
    scan_types: ["all"],
    severity_threshold: "low",
    exclude_paths: [
      "node_modules",
      "vendor",
      "venv",
      ".git",
      "__pycache__",
      "dist",
      "build",
    ],
  },
  
  workflow: [
    "validate_repo_path",
    "detect_languages",
    "select_scanners",
    "run_sast_scans",
    "run_secrets_scans",
    "run_dependency_scans",
    "run_iac_scans",
    "deduplicate_findings",
    "prioritize_findings",
    "generate_report",
  ],
  
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
  
  // Scanner configurations
  scanners: {
    sast: {
      semgrep: {
        rules: ["p/security-audit", "p/owasp-top-ten", "p/secrets"],
        languages: "all",
      },
      bandit: {
        languages: ["python"],
        severity: "low",
        confidence: "medium",
      },
      njsscan: {
        languages: ["javascript", "typescript"],
      },
    },
    secrets: {
      gitleaks: { include_history: false },
      trufflehog: { include_history: false },
    },
    dependencies: {
      grype: { db_update: true },
      safety: { languages: ["python"] },
      npm_audit: { languages: ["javascript", "typescript"] },
    },
    iac: {
      checkov: { frameworks: ["all"] },
      kics: { frameworks: ["all"] },
    },
  },
  
  // Severity mapping for prioritization
  severity_weights: {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  },
};

export async function runSecurityScanWorkflow(
  target: ScanTarget,
  options?: Partial<ScanOptions>
): Promise<ScanResult> {
  const opts: ScanOptions = {
    scan_types: options?.scan_types || ["all"],
    severity_threshold: options?.severity_threshold || "low",
    languages: options?.languages,
    exclude_paths: options?.exclude_paths || securityScanAgentConfig.defaults.exclude_paths,
  };
  
  const result: ScanResult = {
    scan_id: `scan-${Date.now()}`,
    repo_path: target.repo_path,
    repo_name: target.name,
    started_at: new Date().toISOString(),
    languages: [],
    findings: [],
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0,
    },
    scanners_used: [],
  };
  
  // Workflow implementation would go here
  // This is orchestrated by Claude using the tools
  
  return result;
}

/**
 * Convert scan findings to Cycode-compatible format for consistency
 */
export function toCycodeFormat(findings: CodeFinding[]): string {
  const headers = [
    "id",
    "vulnerability_type",
    "severity",
    "file_path",
    "line_number",
    "code_snippet",
    "description",
    "remediation",
    "cwe",
  ];
  
  const rows = findings.map(f => [
    f.id,
    f.title,
    f.severity.toUpperCase(),
    f.file,
    f.line.toString(),
    (f.code_snippet || "").replace(/"/g, '""'),
    (f.description || "").replace(/"/g, '""'),
    (f.remediation || "").replace(/"/g, '""'),
    f.cwe || "",
  ].map(v => `"${v}"`).join(","));
  
  return [headers.join(","), ...rows].join("\n");
}

/**
 * Prioritize findings for exploitation validation
 */
export function prioritizeForExploitation(findings: CodeFinding[]): CodeFinding[] {
  // Vulnerability types that are more likely to be exploitable
  const exploitablePriority: Record<string, number> = {
    "sql-injection": 10,
    "command-injection": 10,
    "code-injection": 10,
    "ssrf": 9,
    "xxe": 9,
    "deserialization": 9,
    "path-traversal": 8,
    "xss": 7,
    "auth-bypass": 8,
    "hardcoded-secret": 6,
  };
  
  return findings
    .map(f => {
      let priority = securityScanAgentConfig.severity_weights[f.severity] || 0;
      
      // Boost priority for known exploitable types
      for (const [type, boost] of Object.entries(exploitablePriority)) {
        if (f.title.toLowerCase().includes(type) || f.id.toLowerCase().includes(type)) {
          priority += boost;
          break;
        }
      }
      
      return { ...f, _priority: priority };
    })
    .sort((a, b) => (b as any)._priority - (a as any)._priority)
    .map(({ _priority, ...f }) => f as CodeFinding);
}
