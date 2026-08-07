/**
 * Recon Agent Implementation
 *
 * Responsible for asset discovery, subdomain enumeration, port scanning,
 * and service fingerprinting. This agent builds the initial attack surface map.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { reconHandlers } from "../../tools/recon";
import { browserHandlers } from "../../tools/browser";

// Recon agent configuration
const RECON_AGENT_CONFIG: AgentConfig = {
  name: "recon-agent",
  description: "Asset discovery and reconnaissance agent",
  maxIterations: 25,
  timeoutMs: 600000, // 10 minutes
  requiresScopeValidation: true,
  tools: [
    "discover_hosts",
    "scan_ports",
    "enumerate_subdomains",
    "fingerprint_services",
    "web_technology_scan",
    // Light browser tools for SPA detection
    "browser_navigate",
    "browser_get_content",
  ],
};

// Tool definitions for Claude API
const RECON_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "discover_hosts",
    description:
      "Discover live hosts in a CIDR range using nmap ping scan. Use this first when given a network range.",
    input_schema: {
      type: "object",
      properties: {
        cidr: {
          type: "string",
          description: "CIDR range to scan (e.g., '192.168.1.0/24')",
        },
      },
      required: ["cidr"],
    },
  },
  {
    name: "scan_ports",
    description:
      "Scan ports on a target using nmap. Returns open ports and service information. Use 'quick' for initial scan, 'full' for comprehensive.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP or hostname",
        },
        ports: {
          type: "string",
          description: "Port specification (e.g., '22,80,443' or '1-1000')",
        },
        scan_type: {
          type: "string",
          enum: ["quick", "full", "stealth"],
          description: "Scan type: quick (top 1000), full (all ports), stealth (slow but quiet)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enumerate_subdomains",
    description:
      "Enumerate subdomains for a given domain using subfinder and amass. Essential for domain targets.",
    input_schema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain (e.g., 'example.com')",
        },
        passive_only: {
          type: "boolean",
          description: "Use only passive sources (recommended for stealth)",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "fingerprint_services",
    description:
      "Identify services and versions running on target ports. Use after port scan to get detailed service info.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP or hostname",
        },
        ports: {
          type: "string",
          description: "Ports to fingerprint (comma-separated)",
        },
      },
      required: ["target", "ports"],
    },
  },
  {
    name: "web_technology_scan",
    description:
      "Identify web technologies using whatweb and httpx. Use on web servers to detect frameworks, CMS, etc.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL (include http:// or https://)",
        },
      },
      required: ["target"],
    },
  },
];

// Light browser tool definitions for SPA detection
const RECON_BROWSER_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "browser_navigate",
    description: "Navigate a headless browser to a URL. Use to detect SPAs that render content via JavaScript (where web_technology_scan might miss frameworks).",
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
    name: "browser_get_content",
    description: "Get rendered page content. Use after browser_navigate to check for SPA frameworks, JavaScript-rendered content, or client-side routing.",
    input_schema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["html", "text"], default: "text" },
        selector: { type: "string", description: "Get content of specific element" },
      },
    },
  },
];

/**
 * Reconnaissance Agent Implementation
 */
export class ReconAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(RECON_AGENT_CONFIG, { ...reconHandlers, ...browserHandlers }, onProgress);
  }

  /**
   * Get tool definitions for Claude
   */
  getToolDefinitions(): ToolDefinition[] {
    return [...RECON_TOOL_DEFINITIONS, ...RECON_BROWSER_TOOL_DEFINITIONS];
  }

  /**
   * Build the initial prompt for Claude
   */
  buildInitialPrompt(input: AgentInput): string {
    let prompt = `# Reconnaissance Task

You are the Recon Agent. Your mission is to thoroughly map the attack surface of the provided targets.

## Targets to Reconnoiter:
`;

    if (input.targets && input.targets.length > 0) {
      for (const target of input.targets) {
        prompt += `- ${target}\n`;
      }
    } else {
      prompt += "No targets provided. Please indicate an error.\n";
    }

    prompt += `
## Your Workflow:

1. **Categorize each target** - Is it a CIDR range, domain, or single host?
   - CIDR (e.g., 192.168.1.0/24): Start with discover_hosts
   - Domain (e.g., example.com): Start with enumerate_subdomains
   - Single IP/hostname: Start with scan_ports

2. **For CIDRs:**
   - Run discover_hosts to find live hosts
   - For each live host: scan_ports (${input.options?.quickScan ? "quick mode" : "full mode"})
   - For interesting ports: fingerprint_services
   - For web ports (80, 443, 8080, 8443): web_technology_scan

3. **For Domains:**
   - Run enumerate_subdomains to discover subdomains
   - For each subdomain: scan_ports
   - For web services: web_technology_scan

4. **For Single Hosts:**
   - Run scan_ports first
   - fingerprint_services on open ports
   - web_technology_scan if web ports found

## Output Requirements:

After completing reconnaissance, provide a summary that includes:
- Total hosts discovered
- Open ports and services found
- Web technologies detected
- Subdomains discovered
- Notable findings (unusual ports, outdated services, etc.)
- Recommendations for next steps (vulnerability scanning targets)

${input.options?.quickScan ? "NOTE: Quick scan mode enabled - only scan top 100 ports." : ""}

Begin reconnaissance now.`;

    return prompt;
  }

  /**
   * Get the system prompt for this agent
   */
  getSystemPrompt(): string {
    return `You are the Recon Agent, a specialized reconnaissance AI for security assessments.

## Your Capabilities:
- Host discovery in network ranges
- Port scanning (quick, full, stealth modes)
- Subdomain enumeration
- Service fingerprinting
- Web technology detection

## Decision Guidelines:

### When to use discover_hosts:
- Target is a CIDR range (contains /)
- You need to find live hosts before scanning ports

### When to use scan_ports:
- After finding live hosts
- For domain/hostname targets
- Always run before fingerprinting

### When to use enumerate_subdomains:
- Target is a domain name (not IP)
- Early in the workflow for domain targets

### When to use fingerprint_services:
- After scan_ports finds open ports
- When you need version information
- Before passing to vuln scanner

### When to use web_technology_scan:
- When web ports are found (80, 443, 8080, 8443, 3000, etc.)
- After confirming web service is running

### When to use browser tools (SPA detection):
- **browser_navigate**: When web_technology_scan shows minimal results but the target might be a SPA
- **browser_get_content**: After browser_navigate to check for JavaScript-rendered content, detect React/Angular/Vue frameworks
- These are lightweight checks - only use on confirmed web targets

## Important Rules:
1. Be systematic - don't skip steps
2. Start with broad scans, then narrow down
3. Document everything you find
4. Identify targets for downstream vulnerability scanning
5. Note any unusual or potentially vulnerable services`;
  }

  /**
   * Override extractFindings to better handle recon-specific output
   */
  protected extractFindings(result: string, toolName: string, target?: string): void {
    // Call parent implementation first
    super.extractFindings(result, toolName, target);

    // Additional recon-specific extraction
    try {
      const parsed = JSON.parse(result);

      // Extract discovered hosts
      if (toolName === "discover_hosts" && parsed.hosts) {
        this.state.context.discoveredHosts = parsed.hosts;
      }

      // Extract open ports
      if (toolName === "scan_ports" && parsed.ports) {
        if (!this.state.context.openPorts) {
          this.state.context.openPorts = {};
        }
        this.state.context.openPorts[target || "unknown"] = parsed.ports;

        // Check for interesting/potentially vulnerable ports
        const interestingPorts = [21, 22, 23, 25, 53, 110, 139, 445, 3306, 3389, 5432, 6379, 27017];
        for (const port of parsed.ports || []) {
          const portNum = typeof port === "object" ? port.port : port;
          if (interestingPorts.includes(portNum)) {
            this.addFinding({
              title: `Interesting port found: ${portNum}`,
              severity: "info",
              target: target || "unknown",
              description: `Port ${portNum} is open. This port is commonly associated with services that may have security implications.`,
              source: toolName,
            });
          }
        }
      }

      // Extract subdomains
      if (toolName === "enumerate_subdomains" && parsed.subdomains) {
        this.state.context.subdomains = parsed.subdomains;
      }

      // Extract web technologies
      if (toolName === "web_technology_scan") {
        if (!this.state.context.webTechnologies) {
          this.state.context.webTechnologies = {};
        }
        this.state.context.webTechnologies[target || "unknown"] = parsed;

        // Check for outdated or vulnerable technologies
        const resultStr = JSON.stringify(parsed).toLowerCase();
        const riskyTechs = [
          "php/5",
          "php/4",
          "apache/2.2",
          "wordpress",
          "drupal",
          "joomla",
          "tomcat/6",
          "tomcat/7",
        ];

        for (const tech of riskyTechs) {
          if (resultStr.includes(tech)) {
            this.addFinding({
              title: `Potentially vulnerable technology: ${tech}`,
              severity: "low",
              target: target || "unknown",
              description: `Detected ${tech} which may have known vulnerabilities. Recommend vulnerability scanning.`,
              source: toolName,
            });
          }
        }
      }
    } catch {
      // Not JSON, try to parse plain text output
      if (toolName === "discover_hosts") {
        // Parse nmap grepable output for hosts
        const hostMatches = result.match(/Host:\s+(\d+\.\d+\.\d+\.\d+)/g);
        if (hostMatches) {
          this.state.context.discoveredHosts = hostMatches.map((m) =>
            m.replace("Host: ", "").trim()
          );
        }
      }
    }
  }
}
