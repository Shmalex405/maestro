/**
 * Infrastructure Security Agent Implementation
 *
 * Specialized agent for network and transport layer security testing.
 * Focuses on SSL/TLS configuration, DNS security, cloud metadata exposure,
 * HTTP protocol attacks, and subdomain takeover detection.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { sslTlsHandlers } from "../../tools/ssl-tls";
import { dnsSecurityHandlers } from "../../tools/dns-security";
import { cloudSecurityHandlers } from "../../tools/cloud-security";
import { advancedWebHandlers } from "../../tools/advanced-web";
import { reconHandlers } from "../../tools/recon";
import { browserHandlers } from "../../tools/browser";

// Infrastructure Security agent configuration
const INFRA_SECURITY_AGENT_CONFIG: AgentConfig = {
  name: "infra-security-agent",
  description: "Infrastructure and network layer security testing agent",
  maxIterations: 25,
  timeoutMs: 900000, // 15 minutes
  requiresScopeValidation: true,
  tools: [
    "scan_ssl_tls",
    "check_certificate",
    "scan_ssl_ciphers",
    "test_zone_transfer",
    "check_dnssec",
    "check_dns_records",
    "detect_subdomain_takeover",
    "test_cloud_metadata",
    "check_s3_bucket",
    "test_http_smuggling",
    "scan_ports",
    "fingerprint_services",
    "web_technology_scan",
  ],
};

// Tool definitions for Claude API
const INFRA_TOOL_DEFINITIONS: ToolDefinition[] = [
  // SSL/TLS Tools
  {
    name: "scan_ssl_tls",
    description:
      "Perform comprehensive SSL/TLS analysis using testssl.sh. Tests protocol versions " +
      "(SSLv2, SSLv3, TLS 1.0-1.3), cipher suites, and known vulnerabilities including " +
      "Heartbleed, ROBOT, POODLE, DROWN, BEAST, CRIME, BREACH, and LUCKY13.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target hostname:port (e.g., 'example.com:443')",
        },
        checks: {
          type: "string",
          description: "Specific checks: 'all', 'protocols', 'ciphers', 'vulnerabilities' (default: all)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "check_certificate",
    description:
      "Analyze the SSL certificate chain. Checks expiration, algorithm strength, " +
      "hostname match, Subject Alternative Names (SANs), issuer, serial number, " +
      "fingerprint, and certificate transparency logs.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target hostname:port (e.g., 'example.com:443')",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "scan_ssl_ciphers",
    description:
      "Enumerate and grade SSL/TLS cipher suites using nmap ssl-enum-ciphers script. " +
      "Identifies weak ciphers (RC4, DES, NULL), export-grade ciphers, and cipher " +
      "preference order issues.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target hostname",
        },
        port: {
          type: "number",
          description: "Port number (default: 443)",
        },
      },
      required: ["target"],
    },
  },
  // DNS Security Tools
  {
    name: "test_zone_transfer",
    description:
      "Attempt DNS zone transfer (AXFR) against all authoritative nameservers for a domain. " +
      "A successful zone transfer leaks the entire DNS zone, exposing internal hostnames, " +
      "IP addresses, and network topology.",
    input_schema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to test zone transfer against",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "check_dnssec",
    description:
      "Check DNSSEC deployment and validation. Verifies RRSIG, DNSKEY, DS, and " +
      "NSEC/NSEC3 records. Missing DNSSEC enables DNS spoofing and cache poisoning attacks.",
    input_schema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to check DNSSEC configuration",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "check_dns_records",
    description:
      "Retrieve and analyze all DNS record types for a domain. Checks A, AAAA, MX, TXT, " +
      "CNAME, NS, SOA, SRV, CAA records and parses SPF, DKIM, and DMARC from TXT records. " +
      "Identifies email security misconfigurations and information leakage.",
    input_schema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to query DNS records for",
        },
        record_types: {
          type: "string",
          description: "Comma-separated record types (default: all common types)",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "detect_subdomain_takeover",
    description:
      "Detect potential subdomain takeover vulnerabilities by checking for dangling CNAME " +
      "records pointing to deprovisioned cloud services (AWS S3, Azure, GitHub Pages, " +
      "Heroku, Fastly, Shopify, etc.).",
    input_schema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to check for subdomain takeover",
        },
        subdomains: {
          type: "array",
          items: { type: "string" },
          description: "List of subdomains to check. If not provided, will enumerate first.",
        },
      },
      required: ["domain"],
    },
  },
  // Cloud Security Tools
  {
    name: "test_cloud_metadata",
    description:
      "Probe for cloud metadata endpoint exposure (AWS IMDSv1/v2, GCP, Azure). Tests " +
      "whether the application or infrastructure exposes internal metadata services, which " +
      "can leak IAM credentials, instance identity, and user-data secrets.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description:
            "Target URL. Include SSRF-vulnerable parameter if applicable (e.g., 'https://app.com/fetch?url=FUZZ')",
        },
        providers: {
          type: "array",
          items: { type: "string" },
          description: "Cloud providers to test: 'aws', 'gcp', 'azure' (default: all)",
        },
        ssrf_parameter: {
          type: "string",
          description: "SSRF-vulnerable parameter name if known",
        },
      },
      required: [],
    },
  },
  {
    name: "check_s3_bucket",
    description:
      "Check AWS S3 bucket permissions and misconfigurations. Tests for public listing, " +
      "public read/write access, ACL disclosure, and bucket policy exposure.",
    input_schema: {
      type: "object",
      properties: {
        bucket_name: {
          type: "string",
          description: "S3 bucket name (e.g., 'company-assets')",
        },
        region: {
          type: "string",
          description: "AWS region (default: us-east-1)",
        },
      },
      required: ["bucket_name"],
    },
  },
  // Advanced Web Tools
  {
    name: "test_http_smuggling",
    description:
      "Test for HTTP request smuggling vulnerabilities (CL.TE, TE.CL, TE.TE). Detects " +
      "desync between front-end proxies and back-end servers that can lead to cache " +
      "poisoning, request hijacking, and access control bypass.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL to test for HTTP smuggling",
        },
        technique: {
          type: "string",
          description: "Smuggling technique: 'cl_te', 'te_cl', 'te_te', or 'all' (default: all)",
        },
      },
      required: ["target"],
    },
  },
  // Recon Tools
  {
    name: "scan_ports",
    description:
      "Scan ports on a target using nmap. Use to discover services that need infrastructure " +
      "security testing (HTTPS for SSL/TLS, DNS for zone transfer, etc.).",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP or hostname",
        },
        ports: {
          type: "string",
          description: "Port specification (e.g., '443,53,8443' or '1-1000')",
        },
        scan_type: {
          type: "string",
          enum: ["quick", "full", "stealth"],
          description: "Scan type: quick, full, or stealth",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "fingerprint_services",
    description:
      "Identify service versions on open ports. Use to determine SSL/TLS-enabled services " +
      "and specific server software versions for vulnerability matching.",
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
      "Identify web technologies, CDN providers, and hosting platforms. Use to determine " +
      "cloud provider (AWS, Azure, GCP) and identify infrastructure-level attack surface.",
    input_schema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL (include https://)",
        },
      },
      required: ["target"],
    },
  },
];

/**
 * Infrastructure Security Agent Implementation
 */
export class InfraSecurityAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      INFRA_SECURITY_AGENT_CONFIG,
      {
        ...sslTlsHandlers,
        ...dnsSecurityHandlers,
        ...cloudSecurityHandlers,
        ...advancedWebHandlers,
        ...reconHandlers,
        ...browserHandlers,
      },
      onProgress
    );
  }

  /**
   * Get tool definitions for Claude
   */
  getToolDefinitions(): ToolDefinition[] {
    return INFRA_TOOL_DEFINITIONS;
  }

  /**
   * Build the initial prompt for Claude
   */
  buildInitialPrompt(input: AgentInput): string {
    let prompt = `# Infrastructure Security Testing Task

You are the Infrastructure Security Agent. Your mission is to test the network and transport layer security of the provided targets.

## Targets to Test:
`;

    if (input.targets && input.targets.length > 0) {
      for (const target of input.targets) {
        prompt += `- ${target}\n`;
      }
    } else {
      prompt += "No targets provided. Please indicate an error.\n";
    }

    // Include context from previous agents
    if (input.context?.openPorts) {
      prompt += `\n## Open Ports (from recon):\n`;
      for (const [host, ports] of Object.entries(input.context.openPorts)) {
        prompt += `- ${host}: ${JSON.stringify(ports)}\n`;
      }
    }

    if (input.context?.subdomains) {
      prompt += `\n## Discovered Subdomains:\n`;
      for (const sub of input.context.subdomains.slice(0, 30)) {
        prompt += `- ${sub}\n`;
      }
    }

    if (input.context?.webTechnologies) {
      prompt += `\n## Detected Technologies:\n`;
      for (const [host, techs] of Object.entries(input.context.webTechnologies)) {
        prompt += `- ${host}: ${JSON.stringify(techs)}\n`;
      }
    }

    prompt += `
## Your Workflow:

### Phase 1: SSL/TLS Analysis (for HTTPS targets)
1. **Full SSL/TLS scan** with \`scan_ssl_tls\` to check protocols, cipher suites, and
   known vulnerabilities (Heartbleed, ROBOT, POODLE, etc.)
2. **Certificate analysis** with \`check_certificate\` to verify expiration, algorithm,
   hostname match, and certificate chain
3. **Cipher suite enumeration** with \`scan_ssl_ciphers\` to identify weak or deprecated ciphers

### Phase 2: DNS Security (for each domain)
4. **DNS record enumeration** with \`check_dns_records\` to discover all record types,
   check SPF/DKIM/DMARC email security
5. **Zone transfer attempt** with \`test_zone_transfer\` against all authoritative nameservers
6. **DNSSEC check** with \`check_dnssec\` to verify DNS response integrity

### Phase 3: Subdomain Takeover
7. **Subdomain takeover detection** with \`detect_subdomain_takeover\` on all discovered
   subdomains (check for dangling CNAME records to deprovisioned services)

### Phase 4: HTTP Protocol Attacks
8. **HTTP smuggling** with \`test_http_smuggling\` on web targets behind proxies/CDNs
   (test CL.TE, TE.CL, and TE.TE desync techniques)

### Phase 5: Cloud Infrastructure
9. **Cloud metadata probing** with \`test_cloud_metadata\` on targets hosted in cloud environments
   (check for AWS IMDS, GCP metadata, Azure IMDS exposure)
10. **S3 bucket testing** with \`check_s3_bucket\` for any S3 references found in
    HTML, JavaScript, DNS records, or HTTP headers

### Phase 6: Service Analysis
11. **Port scan** with \`scan_ports\` if not already done by recon agent
12. **Service fingerprinting** with \`fingerprint_services\` on interesting ports
13. **Technology detection** with \`web_technology_scan\` to identify CDN and hosting platform

## CRITICAL SAFETY RULES:
- NEVER attempt destructive operations
- Zone transfer tests are passive reconnaissance (read-only)
- HTTP smuggling detection uses timing-based techniques (non-destructive)
- S3 write tests only attempt to upload a harmless marker file and immediately clean up

## Output Requirements:

Provide a summary with:
- SSL/TLS configuration grade and issues
- Certificate validity and chain status
- DNS security posture (DNSSEC, zone transfer, email security)
- Subdomain takeover risks
- HTTP protocol vulnerabilities
- Cloud metadata exposure status
- Recommendations prioritized by severity

Begin infrastructure security testing now.`;

    return prompt;
  }

  /**
   * Get the system prompt for this agent
   */
  getSystemPrompt(): string {
    return `You are the Infrastructure Security Agent, specializing in network and transport layer security testing.

## Your Capabilities:
- SSL/TLS protocol and cipher analysis
- Certificate chain validation and expiry checks
- DNS security assessment (zone transfer, DNSSEC, records)
- Subdomain takeover detection
- Cloud metadata endpoint probing
- S3 bucket permission testing
- HTTP request smuggling detection
- Service fingerprinting and technology detection

## Decision Guidelines:

### When to use SSL/TLS tools:
- \`scan_ssl_tls\`: On any HTTPS target (port 443, 8443, etc.). Always run first for HTTPS targets.
- \`check_certificate\`: After scan_ssl_tls, to get detailed certificate info.
- \`scan_ssl_ciphers\`: When you need granular cipher suite grading per protocol version.

### When to use DNS tools:
- \`check_dns_records\`: On every domain target. Check for SPF/DKIM/DMARC misconfigurations.
- \`test_zone_transfer\`: On every domain. A successful transfer is a high-severity finding.
- \`check_dnssec\`: On every domain. Missing DNSSEC is a medium-severity finding.
- \`detect_subdomain_takeover\`: When subdomains are available from recon. Check for dangling CNAMEs.

### When to use cloud tools:
- \`test_cloud_metadata\`: When the target is hosted on AWS/GCP/Azure (check web_technology_scan results).
- \`check_s3_bucket\`: When S3 bucket names are found in HTML, JavaScript, DNS, or headers.

### When to use HTTP protocol tools:
- \`test_http_smuggling\`: When the target is behind a CDN, load balancer, or reverse proxy.
  Look for indicators: multiple server headers, CDN headers (cf-ray, x-amz-cf-id), etc.

### When to use recon tools:
- \`scan_ports\`: If not already done by recon agent, run to discover SSL/DNS/web ports.
- \`fingerprint_services\`: To identify specific versions for vulnerability matching.
- \`web_technology_scan\`: To detect CDN provider, cloud hosting, and server software.

## Severity Classification:
- **Critical**: Successful zone transfer, exposed cloud credentials, publicly writable S3 buckets
- **High**: SSLv2/SSLv3 enabled, Heartbleed/ROBOT vulnerable, subdomain takeover, cloud metadata exposure
- **Medium**: TLS 1.0/1.1 enabled, missing DNSSEC, weak cipher suites, missing HSTS
- **Low**: Certificate near expiry, missing CAA records, informational DNS records
- **Info**: DNSSEC configuration details, certificate chain info, cipher preference order

## Important Rules:
1. Always start with SSL/TLS for HTTPS targets
2. Always check DNS for domain targets
3. Check for cloud hosting before probing metadata
4. Document all findings with specific evidence
5. Include remediation recommendations for every finding`;
  }

  /**
   * Override extractFindings for infrastructure-specific finding extraction
   */
  protected extractFindings(result: string, toolName: string, target?: string): void {
    // Call parent implementation first
    super.extractFindings(result, toolName, target);

    const resultStr = typeof result === "string" ? result : JSON.stringify(result);

    try {
      // SSL/TLS finding extraction
      if (toolName === "scan_ssl_tls") {
        if (resultStr.includes("VULNERABLE") && resultStr.includes("Heartbleed")) {
          this.addFinding({
            title: "Heartbleed Vulnerability (CVE-2014-0160)",
            severity: "critical",
            target: target || "unknown",
            description:
              "The server is vulnerable to Heartbleed, allowing attackers to read server memory " +
              "including private keys, session tokens, and other sensitive data.",
            evidence: resultStr.slice(0, 1000),
            remediation: "Upgrade OpenSSL to a patched version. Reissue all SSL certificates and rotate all secrets.",
            source: toolName,
            metadata: { cve: "CVE-2014-0160" },
          });
        }

        if (resultStr.includes("SSLv2") && resultStr.includes("offered")) {
          this.addFinding({
            title: "SSLv2 Protocol Enabled",
            severity: "high",
            target: target || "unknown",
            description: "SSLv2 is enabled on the server. This protocol has critical vulnerabilities and must be disabled.",
            evidence: resultStr.slice(0, 500),
            remediation: "Disable SSLv2 in the server configuration. Only allow TLS 1.2 and TLS 1.3.",
            source: toolName,
          });
        }

        if (resultStr.includes("SSLv3") && resultStr.includes("offered")) {
          this.addFinding({
            title: "SSLv3 Protocol Enabled (POODLE)",
            severity: "high",
            target: target || "unknown",
            description: "SSLv3 is enabled, making the server vulnerable to the POODLE attack.",
            evidence: resultStr.slice(0, 500),
            remediation: "Disable SSLv3. Only allow TLS 1.2 and TLS 1.3.",
            source: toolName,
          });
        }

        if (resultStr.includes("TLSv1.0") && resultStr.includes("offered")) {
          this.addFinding({
            title: "TLS 1.0 Enabled (Deprecated)",
            severity: "medium",
            target: target || "unknown",
            description:
              "TLS 1.0 is deprecated and has known weaknesses (BEAST, etc.). " +
              "PCI-DSS requires disabling TLS 1.0.",
            source: toolName,
          });
        }
      }

      // Zone transfer extraction
      if (toolName === "test_zone_transfer") {
        if (
          resultStr.includes("Transfer failed") === false &&
          resultStr.includes("XFR size") &&
          !resultStr.includes("Transfer failed")
        ) {
          this.addFinding({
            title: "DNS Zone Transfer Successful (AXFR)",
            severity: "high",
            target: target || "unknown",
            description:
              "DNS zone transfer succeeded, exposing the entire DNS zone including internal " +
              "hostnames, IP addresses, and network topology.",
            evidence: resultStr.slice(0, 2000),
            remediation: "Restrict zone transfers to authorized secondary nameservers only.",
            source: toolName,
          });
        }
      }

      // DNSSEC extraction
      if (toolName === "check_dnssec") {
        if (resultStr.includes("No DNSSEC records found") || resultStr.includes("not signed")) {
          this.addFinding({
            title: "DNSSEC Not Deployed",
            severity: "medium",
            target: target || "unknown",
            description:
              "DNSSEC is not configured for this domain, making it vulnerable to DNS spoofing " +
              "and cache poisoning attacks.",
            remediation: "Enable DNSSEC with your DNS provider. Configure DS records at the registrar.",
            source: toolName,
          });
        }
      }

      // DNS records extraction (email security)
      if (toolName === "check_dns_records") {
        if (resultStr.includes("No SPF record found")) {
          this.addFinding({
            title: "Missing SPF Record",
            severity: "medium",
            target: target || "unknown",
            description: "No SPF record found, making the domain vulnerable to email spoofing.",
            remediation: "Add an SPF TXT record to specify authorized email senders.",
            source: toolName,
          });
        }

        if (resultStr.includes("No DMARC record found")) {
          this.addFinding({
            title: "Missing DMARC Record",
            severity: "medium",
            target: target || "unknown",
            description: "No DMARC record found, allowing email spoofing without reporting or enforcement.",
            remediation: "Add a _dmarc TXT record with at least p=none for monitoring, then upgrade to p=quarantine or p=reject.",
            source: toolName,
          });
        }
      }

      // Subdomain takeover extraction
      if (toolName === "detect_subdomain_takeover") {
        if (resultStr.includes("VULNERABLE") || resultStr.includes("takeover possible")) {
          this.addFinding({
            title: "Subdomain Takeover Vulnerability",
            severity: "high",
            target: target || "unknown",
            description:
              "A subdomain has a dangling CNAME record pointing to a deprovisioned cloud service. " +
              "An attacker could claim this service and serve malicious content under your domain.",
            evidence: resultStr.slice(0, 1000),
            remediation: "Remove the dangling CNAME record or re-provision the cloud service.",
            source: toolName,
          });
        }
      }

      // Cloud metadata extraction
      if (toolName === "test_cloud_metadata") {
        if (resultStr.includes("EXPOSED") || resultStr.includes("HTTP 200")) {
          this.addFinding({
            title: "Cloud Metadata Service Exposed",
            severity: "critical",
            target: target || "unknown",
            description:
              "Cloud metadata service is accessible, potentially exposing IAM credentials, " +
              "instance identity, user-data, and other sensitive configuration.",
            evidence: resultStr.slice(0, 1000),
            remediation:
              "Enforce IMDSv2 (AWS), restrict metadata access, and ensure applications cannot proxy requests to metadata endpoints.",
            source: toolName,
          });
        }
      }

      // S3 bucket extraction
      if (toolName === "check_s3_bucket") {
        if (resultStr.includes("Public listing enabled") || resultStr.includes("publicly accessible")) {
          this.addFinding({
            title: "S3 Bucket Publicly Accessible",
            severity: "high",
            target: target || "unknown",
            description: "S3 bucket contents are publicly listable, potentially exposing sensitive files.",
            evidence: resultStr.slice(0, 1000),
            remediation: "Apply a bucket policy that restricts public access. Enable S3 Block Public Access.",
            source: toolName,
          });
        }

        if (resultStr.includes("CRITICAL: Public write access")) {
          this.addFinding({
            title: "S3 Bucket Publicly Writable",
            severity: "critical",
            target: target || "unknown",
            description:
              "S3 bucket allows public write access, enabling attackers to upload malicious content " +
              "or overwrite existing files.",
            evidence: resultStr.slice(0, 1000),
            remediation: "Immediately restrict write access. Enable S3 Block Public Access and review bucket policies.",
            source: toolName,
          });
        }
      }

      // HTTP smuggling extraction
      if (toolName === "test_http_smuggling") {
        if (resultStr.includes("VULNERABLE") || resultStr.includes("desync detected")) {
          this.addFinding({
            title: "HTTP Request Smuggling Vulnerability",
            severity: "high",
            target: target || "unknown",
            description:
              "HTTP request smuggling is possible due to a desync between the front-end proxy " +
              "and back-end server. This can lead to cache poisoning, request hijacking, and access control bypass.",
            evidence: resultStr.slice(0, 1000),
            remediation:
              "Ensure consistent HTTP parsing between front-end and back-end. Disable HTTP/1.0, " +
              "normalize Transfer-Encoding handling, and use HTTP/2 end-to-end where possible.",
            source: toolName,
          });
        }
      }
    } catch {
      // Non-JSON results handled by text matching above
    }
  }
}
