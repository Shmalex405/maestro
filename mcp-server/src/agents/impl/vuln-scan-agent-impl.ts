/**
 * Vulnerability Scanner Agent Implementation
 *
 * Automated vulnerability detection using multiple scanning engines
 * to identify known vulnerabilities and CVEs.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { vulnScanHandlers } from "../../tools/vuln-scan";

const VULN_SCAN_AGENT_CONFIG: AgentConfig = {
  name: "vuln-scan-agent",
  description: "Vulnerability scanning and CVE detection agent",
  maxIterations: 30,
  timeoutMs: 1800000, // 30 minutes
  requiresScopeValidation: true,
  tools: ["run_nuclei", "run_nikto", "run_wpscan", "search_exploits"],
};

const VULN_SCAN_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "run_nuclei",
    description: `Run Nuclei vulnerability scanner with specified templates.
This is the primary vulnerability scanner - use it on all web targets.
Supports multiple template categories: cve, owasp, misconfig, exposures, etc.`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to scan",
        },
        templates: {
          type: "string",
          description: "Template categories (comma-separated): cve, owasp-top-ten, misconfig, exposures, default-logins",
        },
        severity: {
          type: "string",
          description: "Minimum severity: info, low, medium, high, critical",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "run_nikto",
    description: `Run Nikto web server scanner. Good for finding server misconfigurations,
dangerous files, and outdated software. Use on web servers for comprehensive checks.`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to scan",
        },
        tuning: {
          type: "string",
          description: "Scan tuning options (0-9, x for reverse tuning)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "run_wpscan",
    description: `Scan WordPress installations for vulnerabilities.
Use this when WordPress is detected. Checks plugins, themes, and core for known issues.`,
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "WordPress site URL",
        },
        enumerate: {
          type: "string",
          description: "What to enumerate: vp (plugins), vt (themes), u (users), ap (all plugins)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "search_exploits",
    description: `Search exploit-db for known exploits for a service/product.
Use after identifying services to find available exploits.`,
    input_schema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search query (service name, version, CVE, etc.)",
        },
      },
      required: ["query"],
    },
  },
];

export class VulnScanAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(VULN_SCAN_AGENT_CONFIG, vulnScanHandlers, onProgress);
  }

  getToolDefinitions(): ToolDefinition[] {
    return VULN_SCAN_TOOL_DEFINITIONS;
  }

  buildInitialPrompt(input: AgentInput): string {
    const severityFilter = input.severity || "medium";

    let prompt = `# Vulnerability Scanning Task

You are the Vulnerability Scanner Agent. Your mission is to identify security vulnerabilities in the provided targets.

## Targets to Scan:
`;

    if (input.targets && input.targets.length > 0) {
      for (const target of input.targets) {
        prompt += `- ${target}\n`;
      }
    }

    // Include context from recon agent if available
    if (input.context?.discoveredHosts) {
      prompt += `\n## Discovered Hosts from Recon:\n`;
      for (const host of input.context.discoveredHosts) {
        prompt += `- ${host}\n`;
      }
    }

    if (input.context?.openPorts) {
      prompt += `\n## Open Ports from Recon:\n`;
      for (const [host, ports] of Object.entries(input.context.openPorts)) {
        prompt += `- ${host}: ${JSON.stringify(ports)}\n`;
      }
    }

    if (input.context?.webTechnologies) {
      prompt += `\n## Detected Web Technologies:\n`;
      for (const [host, techs] of Object.entries(input.context.webTechnologies)) {
        prompt += `- ${host}: ${JSON.stringify(techs)}\n`;
      }
    }

    // Include attack surface intelligence from code-intel agent
    if (input.context?.attackSurface) {
      const as = input.context.attackSurface;
      prompt += `\n## Attack Surface Intelligence (from Code Analysis):\n`;
      prompt += `Framework: ${as.framework || "unknown"}\n`;

      if (as.prioritizedAttackVectors?.length) {
        prompt += `\n### Prioritized Attack Vectors — use these to select targeted templates:\n`;
        for (const v of as.prioritizedAttackVectors.slice(0, 10)) {
          prompt += `- [${v.confidence?.toUpperCase() || "MEDIUM"}] ${v.type} → ${v.target} (${v.reason})\n`;
        }

        // Map attack types to nuclei template suggestions
        const vectorTypes = new Set(as.prioritizedAttackVectors.map((v: any) => v.type));
        const templateSuggestions: string[] = [];
        if (vectorTypes.has("sqli")) templateSuggestions.push("cve (SQL injection CVEs)");
        if (vectorTypes.has("xss")) templateSuggestions.push("xss, owasp-top-ten");
        if (vectorTypes.has("ssrf")) templateSuggestions.push("ssrf, owasp-top-ten");
        if (vectorTypes.has("rce")) templateSuggestions.push("cve (RCE CVEs), rce");
        if (vectorTypes.has("auth_bypass")) templateSuggestions.push("default-logins, exposures");
        if (templateSuggestions.length) {
          prompt += `\n**Suggested nuclei templates based on attack vectors:** ${templateSuggestions.join(", ")}\n`;
        }
      }

      if (as.defenses) {
        const gaps = Object.entries(as.defenses)
          .filter(([, v]) => !v)
          .map(([k]) => k);
        if (gaps.length) {
          prompt += `\n### Defense Gaps: ${gaps.join(", ")} — test these areas more thoroughly\n`;
        }
      }
    }

    prompt += `
## Minimum Severity: ${severityFilter}

## Your Workflow:

1. **For each web target:**
   - Run nuclei with high/critical severity templates first
   - If attack surface intelligence is available, use targeted templates for identified vectors
   - Run nuclei with OWASP top-10 templates
   - Run nikto for comprehensive web server checks
   - If WordPress detected: run wpscan

2. **For identified services:**
   - Search for exploits using service name and version
   - Note any exploits found for the exploit agent

3. **Prioritization:**
   - If attack surface data is available, prioritize endpoints flagged as HIGH confidence
   - Focus on high and critical severity first
   - Don't skip medium severity if time permits
   - Document all findings regardless of severity

## Output Requirements:

Provide a summary with:
- Total vulnerabilities by severity
- Critical/High findings that need immediate attention
- Exploits found for identified services
- Recommendations for exploit validation

Begin vulnerability scanning now.`;

    return prompt;
  }

  getSystemPrompt(): string {
    return `You are the Vulnerability Scanner Agent, specialized in identifying security weaknesses.

## Your Capabilities:
- Nuclei vulnerability scanning (CVEs, OWASP, misconfigs)
- Nikto web server scanning
- WordPress vulnerability scanning
- Exploit database searching

## Decision Guidelines:

### When to use run_nuclei:
- Always on web targets (HTTP/HTTPS)
- Use severity filter to focus on critical issues first
- Run multiple template categories for comprehensive coverage

### When to use run_nikto:
- On web servers for detailed checks
- Good for finding misconfigurations
- Use after nuclei for additional coverage

### When to use run_wpscan:
- ONLY when WordPress is detected
- Check context from recon agent for WP indicators
- Enumerate plugins and themes for vulnerabilities

### When to use search_exploits:
- After identifying specific services/versions
- Search for CVEs found by other tools
- Look for exploits for outdated software

## Using Attack Surface Intelligence:
- If context.attackSurface is available, use prioritizedAttackVectors to select targeted nuclei templates
- Focus on endpoints with defense gaps (missing CSRF, no input validation, no auth)
- Cross-reference code-level findings with runtime scan results

## Important Rules:
1. Always start with high/critical severity scans
2. Use context from recon agent to target specific services
3. Use context from code-intel agent to select targeted templates
4. Note exploit availability for each vulnerability
5. Distinguish between verified and potential vulnerabilities
6. Don't waste time on info-level findings unless specifically asked`;
  }

  protected extractFindings(result: string, toolName: string, target?: string): void {
    super.extractFindings(result, toolName, target);

    try {
      const parsed = JSON.parse(result);

      // Nuclei-specific extraction
      if (toolName === "run_nuclei" && parsed.matches) {
        for (const match of parsed.matches) {
          this.addFinding({
            title: match.info?.name || match.template || "Nuclei Finding",
            severity: this.mapSeverity(match.info?.severity),
            target: match.host || target || "unknown",
            description: match.info?.description || match.matcher_name || "Vulnerability detected",
            evidence: match.matched || match.curl_command,
            remediation: match.info?.remediation,
            source: "nuclei",
            metadata: {
              template: match.template,
              cve: match.info?.classification?.cve_id,
              reference: match.info?.reference,
            },
          });
        }
      }

      // Nikto-specific extraction
      if (toolName === "run_nikto" && parsed.vulnerabilities) {
        for (const vuln of parsed.vulnerabilities) {
          this.addFinding({
            title: vuln.msg || "Nikto Finding",
            severity: this.mapNiktoSeverity(vuln.OSVDB),
            target: target || "unknown",
            description: vuln.msg,
            evidence: vuln.url || vuln.uri,
            source: "nikto",
            metadata: { osvdb: vuln.OSVDB },
          });
        }
      }

      // WPScan-specific extraction
      if (toolName === "run_wpscan") {
        // Plugin vulnerabilities
        if (parsed.plugins) {
          for (const [name, plugin] of Object.entries(parsed.plugins as Record<string, any>)) {
            if (plugin.vulnerabilities) {
              for (const vuln of plugin.vulnerabilities) {
                this.addFinding({
                  title: `WordPress Plugin: ${vuln.title || name}`,
                  severity: this.mapSeverity(vuln.severity),
                  target: target || "unknown",
                  description: `Vulnerable plugin: ${name}. ${vuln.description || ""}`,
                  remediation: "Update the plugin to the latest version",
                  source: "wpscan",
                  metadata: { plugin: name, cve: vuln.cve },
                });
              }
            }
          }
        }

        // Theme vulnerabilities
        if (parsed.themes) {
          for (const [name, theme] of Object.entries(parsed.themes as Record<string, any>)) {
            if (theme.vulnerabilities) {
              for (const vuln of theme.vulnerabilities) {
                this.addFinding({
                  title: `WordPress Theme: ${vuln.title || name}`,
                  severity: this.mapSeverity(vuln.severity),
                  target: target || "unknown",
                  description: `Vulnerable theme: ${name}`,
                  source: "wpscan",
                });
              }
            }
          }
        }
      }

      // Exploit search extraction
      if (toolName === "search_exploits" && parsed.exploits) {
        this.state.context.availableExploits = [
          ...(this.state.context.availableExploits || []),
          ...parsed.exploits,
        ];
      }
    } catch {
      // Not JSON or parsing failed
    }
  }

  private mapNiktoSeverity(osvdb: string | undefined): "info" | "low" | "medium" | "high" | "critical" {
    // OSVDB-based severity mapping (simplified)
    if (!osvdb) return "info";
    return "medium"; // Nikto findings are generally medium
  }
}
