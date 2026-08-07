/**
 * Compliance Agent Implementation
 *
 * Read-only agent that maps security findings to compliance frameworks
 * (OWASP Top 10 2021, OWASP API Top 10, CWE, NIST 800-53, PCI-DSS,
 * CIS Foundations Benchmarks for AWS / Azure / GCP / Kubernetes).
 * Calculates CVSS v3.1 vectors and generates compliance coverage matrices.
 *
 * This agent does NOT perform any scanning. It receives findings via
 * input.context.findings and produces compliance mappings as output.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { reportingHandlers } from "../../tools/reporting";

// Compliance agent configuration
const COMPLIANCE_AGENT_CONFIG: AgentConfig = {
  name: "compliance-agent",
  description: "Compliance mapping and CVSS scoring agent",
  maxIterations: 15,
  timeoutMs: 300000, // 5 minutes
  requiresScopeValidation: false,
  tools: [
    "create_finding",
    "generate_report",
  ],
};

// Tool definitions for Claude API
const COMPLIANCE_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "create_finding",
    description:
      "Create or update a security finding record with compliance mapping metadata. " +
      "Use this to persist compliance-enriched findings with CWE, CVSS vector, and " +
      "framework mappings added to the description and metadata fields.",
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
          description: "Finding severity",
        },
        description: {
          type: "string",
          description:
            "Detailed description including compliance mappings (OWASP, CWE, NIST, PCI-DSS, CVSS vector)",
        },
        target: {
          type: "string",
          description: "Affected target",
        },
        evidence: {
          type: "string",
          description: "Evidence of vulnerability",
        },
        remediation: {
          type: "string",
          description: "Recommended fix with compliance framework references",
        },
        cve: {
          type: "string",
          description: "Associated CVE identifier",
        },
        cwe: {
          type: "string",
          description: "CWE identifier (e.g., CWE-89)",
        },
        source: {
          type: "string",
          description: "Tool or source that found this",
        },
      },
      required: ["title", "severity", "description", "target"],
    },
  },
  {
    name: "generate_report",
    description:
      "Generate a compliance-focused report with framework mappings, CVSS scores, and " +
      "coverage matrices. Use after all findings have been enriched with compliance data.",
    input_schema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["markdown", "html", "json"],
          description: "Report format (default: markdown)",
        },
        include_evidence: {
          type: "boolean",
          description: "Include evidence in report (default: true)",
        },
        finding_ids: {
          type: "array",
          items: { type: "string" },
          description: "Specific finding IDs to include",
        },
      },
      required: ["format"],
    },
  },
];

/**
 * Compliance Agent Implementation
 */
export class ComplianceAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      COMPLIANCE_AGENT_CONFIG,
      { ...reportingHandlers },
      onProgress
    );
  }

  /**
   * Get tool definitions for Claude
   */
  getToolDefinitions(): ToolDefinition[] {
    return COMPLIANCE_TOOL_DEFINITIONS;
  }

  /**
   * Build the initial prompt for Claude
   */
  buildInitialPrompt(input: AgentInput): string {
    const findings = input.context?.findings || [];

    let prompt = `# Compliance Mapping Task

You are the Compliance Agent. Your mission is to map security findings to compliance frameworks and calculate CVSS v3.1 scores.

## Findings to Map:

`;

    if (findings.length === 0) {
      prompt += "No findings provided. Check context.findings for the findings array.\n";
      // Try to find findings in other context fields
      if (input.context) {
        const contextKeys = Object.keys(input.context);
        prompt += `\nAvailable context keys: ${contextKeys.join(", ")}\n`;
        prompt += "Look for findings in these context fields and process them.\n";
      }
    } else {
      for (let i = 0; i < findings.length; i++) {
        const f = findings[i];
        prompt += `### Finding ${i + 1}: ${f.title || f.name || "Untitled"}
- **Severity**: ${f.severity || "unknown"}
- **Target**: ${f.target || "unknown"}
- **Source**: ${f.source || "unknown"}
- **Description**: ${f.description || "No description"}
- **CWE**: ${f.cwe || f.metadata?.cwe || "Not assigned"}
- **CVE**: ${f.cve || f.metadata?.cve || "Not assigned"}
- **Evidence**: ${f.evidence ? f.evidence.slice(0, 300) + "..." : "None provided"}

`;
      }
    }

    prompt += `## Your Workflow:

For EACH finding above, perform the following mappings:

### 1. CWE Assignment
Assign the most specific CWE identifier:
- SQL Injection -> CWE-89
- XSS (Reflected) -> CWE-79
- XSS (Stored) -> CWE-79
- XSS (DOM) -> CWE-79
- Command Injection -> CWE-78
- Path Traversal -> CWE-22
- SSRF -> CWE-918
- CSRF -> CWE-352
- IDOR -> CWE-639
- Authentication Bypass -> CWE-287
- Broken Access Control -> CWE-284
- Sensitive Data Exposure -> CWE-200
- Security Misconfiguration -> CWE-16
- Insecure Deserialization -> CWE-502
- Missing Rate Limiting -> CWE-770
- Weak Cryptography -> CWE-327
- Hardcoded Credentials -> CWE-798
- Missing HSTS -> CWE-523
- Open Redirect -> CWE-601
- Information Disclosure -> CWE-200
- Weak Password Policy -> CWE-521

### 2. OWASP Top 10 2021 Mapping
Map to the correct category:
- **A01:2021 - Broken Access Control**: IDOR, privilege escalation, CORS misconfig, forced browsing
- **A02:2021 - Cryptographic Failures**: Weak TLS, missing encryption, weak algorithms, cleartext secrets
- **A03:2021 - Injection**: SQLi, XSS, command injection, SSTI, header injection
- **A04:2021 - Insecure Design**: Missing rate limiting, business logic flaws, missing auth checks
- **A05:2021 - Security Misconfiguration**: Default configs, verbose errors, unnecessary features, missing headers
- **A06:2021 - Vulnerable and Outdated Components**: Known CVEs in dependencies, outdated libraries
- **A07:2021 - Identification and Authentication Failures**: Weak passwords, session fixation, credential stuffing
- **A08:2021 - Software and Data Integrity Failures**: Insecure deserialization, unsigned updates, CI/CD insecurity
- **A09:2021 - Security Logging and Monitoring Failures**: Missing audit logs, unmonitored events
- **A10:2021 - Server-Side Request Forgery**: SSRF to internal services, cloud metadata access

### 3. OWASP API Top 10 Mapping (if applicable)
Only map if the finding relates to API security:
- **API1:2023 - Broken Object Level Authorization**: IDOR on API endpoints
- **API2:2023 - Broken Authentication**: Weak API auth, token issues
- **API3:2023 - Broken Object Property Level Authorization**: Mass assignment, excessive data exposure
- **API4:2023 - Unrestricted Resource Consumption**: Missing rate limiting, no pagination
- **API5:2023 - Broken Function Level Authorization**: Privilege escalation via API
- **API6:2023 - Unrestricted Access to Sensitive Business Flows**: Business logic abuse
- **API7:2023 - Server-Side Request Forgery**: SSRF via API parameters
- **API8:2023 - Security Misconfiguration**: Overly permissive CORS, verbose errors
- **API9:2023 - Improper Inventory Management**: Deprecated/shadow API endpoints
- **API10:2023 - Unsafe Consumption of APIs**: Trusting third-party API responses

### 4. NIST 800-53 Control Family
Map to the relevant control family:
- **AC (Access Control)**: IDOR, broken access control, privilege escalation
- **AU (Audit and Accountability)**: Logging failures, missing audit trail
- **CA (Assessment, Authorization, and Monitoring)**: Security assessment gaps
- **CM (Configuration Management)**: Misconfigurations, default settings
- **IA (Identification and Authentication)**: Auth bypass, weak passwords, session issues
- **IR (Incident Response)**: Missing monitoring, no alerting
- **RA (Risk Assessment)**: Unpatched vulnerabilities, outdated components
- **SC (System and Communications Protection)**: TLS issues, missing encryption, CORS
- **SI (System and Information Integrity)**: Injection flaws, input validation, deserialization

### 5. PCI-DSS Requirement Mapping
Map to PCI-DSS v4.0 requirements:
- **Req 1**: Network segmentation -> Cloud network exposure, public security groups, missing NACLs
- **Req 2**: Do not use vendor-supplied defaults -> Default credentials, default configs, default VPC use
- **Req 3**: Protect stored cardholder data -> Data exposure, weak encryption, unencrypted S3/EBS/RDS
- **Req 4**: Encrypt transmission of cardholder data -> Weak TLS, missing HSTS, plaintext storage transfer
- **Req 6**: Develop and maintain secure systems -> All code/app vulnerabilities (SQLi, XSS, etc.)
- **Req 7**: Restrict access to cardholder data -> Access control issues, IDOR, IAM least privilege violations
- **Req 8**: Identify users and authenticate access -> Auth failures, weak passwords, missing MFA on root/console
- **Req 10**: Log and monitor all access -> Missing logging and monitoring, CloudTrail disabled, audit log tampering
- **Req 11**: Test security of systems and networks regularly -> Assessment coverage gaps
- **Req 12**: Support information security with org policies -> Policy gaps

### 6. CIS Benchmark Mapping (Cloud Findings ONLY)

For findings sourced from cloud-recon or cloud-exploit agents, map to the relevant CIS Foundations Benchmark control. Pick the provider field that matches where the finding was discovered. Leave non-cloud findings' CIS fields as null.

**CIS AWS Foundations Benchmark v3.0** (\`cis_aws\`):
- Root account access keys / no MFA on root -> 1.4, 1.5
- IAM user without MFA -> 1.10, 1.11
- Stale access keys (>90 days) -> 1.14
- Wildcard \`*:*\` IAM policy or admin-equivalent -> 1.15, 1.16
- Public S3 bucket -> 2.1.5
- Unencrypted S3/EBS/RDS at rest -> 2.1.1, 2.2.1, 2.3.1
- Security group allows 0.0.0.0/0 to port 22/3389 -> 5.2, 5.3
- Default VPC not restricted -> 5.4
- CloudTrail disabled or not multi-region -> 3.1, 3.2
- KMS key rotation disabled -> 3.7
- IMDSv1 enabled (vs IMDSv2 required) -> 5.6

**CIS Azure Foundations Benchmark v2.1** (\`cis_azure\`):
- Custom subscription owner roles / stale guest accounts -> 1.21, 1.23
- MFA not enforced via Conditional Access -> 1.1.1, 1.2.x
- Storage account allows public blob access -> 3.6
- Storage account secure transfer disabled -> 3.1, 3.2
- NSG allows 0.0.0.0/0 to port 22/3389 -> 6.1, 6.2
- Diagnostic settings missing for activity logs -> 5.1.1
- Key Vault soft-delete or purge protection off -> 8.1

**CIS GCP Foundations Benchmark v3.0** (\`cis_gcp\`):
- User-managed service account keys -> 1.4
- Primitive Owner/Editor roles assigned -> 1.5
- Public Cloud Storage bucket -> 5.1
- KMS rotation period >90 days -> 1.10
- Firewall rule 0.0.0.0/0 to port 22/3389 -> 3.6, 3.7
- Default network in use -> 3.1
- Cloud Audit Logging gaps / sinks not exporting -> 2.1, 2.2

**CIS Kubernetes Benchmark v1.9** (\`cis_k8s\`):
- Anonymous auth enabled on kube-apiserver -> 1.2.1
- AlwaysAllow in --authorization-mode -> 1.2.7
- Cluster-admin binding outside system: namespaces -> 5.1.1
- Privileged containers (privileged: true) -> 5.2.5
- hostPath / hostPID / hostNetwork in pod spec -> 5.2.4, 5.2.2, 5.2.3
- RBAC wildcard verb on secrets -> 5.1.2, 5.1.6
- Namespace lacks default-deny NetworkPolicy -> 5.3.2
- etcd unencrypted at rest -> 1.2.34
- Kubelet anonymous auth enabled -> 4.2.1

### 7. CVSS v3.1 Vector Calculation
For each finding, calculate the CVSS v3.1 base score vector:

Format: \`CVSS:3.1/AV:{N|A|L|P}/AC:{L|H}/PR:{N|L|H}/UI:{N|R}/S:{U|C}/C:{N|L|H}/I:{N|L|H}/A:{N|L|H}\`

Components:
- **AV (Attack Vector)**: N=Network, A=Adjacent, L=Local, P=Physical
- **AC (Attack Complexity)**: L=Low, H=High
- **PR (Privileges Required)**: N=None, L=Low, H=High
- **UI (User Interaction)**: N=None, R=Required
- **S (Scope)**: U=Unchanged, C=Changed
- **C (Confidentiality)**: N=None, L=Low, H=High
- **I (Integrity)**: N=None, L=Low, H=High
- **A (Availability)**: N=None, L=Low, H=High

Common CVSS vectors:
- SQL Injection (unauthenticated): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)
- XSS Reflected: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)
- IDOR: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N (7.1)
- Missing Rate Limiting: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3)
- Weak TLS: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N (5.9)
- SSRF: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N (8.6)
- Public S3/blob bucket with PII: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- IAM privesc to admin: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.6)
- IMDS exposure / SSRF to metadata: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (10.0)
- K8s privileged container / container escape: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (8.8)
- K8s cluster-admin RBAC binding: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H (9.6)
- Cross-account trust without external ID: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (9.3)
- Public RDS/EBS snapshot: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)
- Stale active access key: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N (9.3)

### 7. Compliance Coverage Matrix
After mapping all findings, generate a coverage matrix showing:
- Which OWASP Top 10 categories were tested (and which were not)
- Which NIST 800-53 control families were assessed
- Which PCI-DSS requirements were evaluated
- Untested areas as gaps with recommendations

## Output Format:

After completing all mappings, use \`create_finding\` to persist each enriched finding with
compliance data in the description. Then summarize the results as your final output with:

1. Per-finding mapping table (Finding | OWASP | CWE | CVSS | NIST | PCI-DSS)
2. Compliance coverage matrix
3. Gaps and recommendations

Begin compliance mapping now.`;

    return prompt;
  }

  /**
   * Get the system prompt for this agent
   */
  getSystemPrompt(): string {
    return `You are the Compliance Agent, specializing in mapping security findings to compliance frameworks and calculating CVSS scores.

## Your Role:
You are a READ-ONLY analysis agent. You do NOT perform any scanning or testing. You receive
findings from other agents and enrich them with compliance framework mappings and CVSS scores.

## Your Capabilities:
- OWASP Top 10 2021 mapping (A01-A10)
- OWASP API Top 10 2023 mapping (API1-API10)
- CWE identifier assignment
- NIST 800-53 control family mapping (including cloud-relevant AC, SC, CM, AU, IA controls)
- PCI-DSS v4.0 requirement mapping (including cloud-relevant Req 1, 2, 3, 7, 8, 10)
- CIS Foundations Benchmark mapping for cloud findings (cis_aws v3.0, cis_azure v2.1, cis_gcp v3.0, cis_k8s v1.9)
- CVSS v3.1 base score vector calculation
- Compliance coverage matrix generation (web/API + cloud)
- Gap analysis and recommendations

## Compliance Mapping Rules:

### Severity vs. CVSS Consistency:
- Critical findings should have CVSS >= 9.0
- High findings should have CVSS 7.0-8.9
- Medium findings should have CVSS 4.0-6.9
- Low findings should have CVSS 0.1-3.9
- Info findings do not require CVSS
- If the CVSS score contradicts the severity, note the discrepancy

### Multiple Framework Mappings:
- A single finding can map to multiple OWASP categories (choose the primary one)
- A finding MUST have at least one CWE
- NIST and PCI-DSS mappings are optional but recommended for high/critical findings

### Coverage Gaps:
- Track which OWASP Top 10 categories were tested
- Track which categories had NO findings (could be positive or could be untested)
- Distinguish between "tested and clean" vs "not tested"

## Output Format:

Structure your compliance mapping as:

\`\`\`json
{
  "complianceMapping": {
    "findings": [
      {
        "findingId": "string",
        "title": "string",
        "severity": "string",
        "cwe": "CWE-89",
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvssScore": 9.1,
        "owaspTop10": "A03:2021 - Injection",
        "owaspApiTop10": "API8:2023 - Security Misconfiguration",
        "nist80053": "SI-10 (Information Input Validation)",
        "pciDss": "Req 6.2.4 - Software engineering techniques to prevent injection",
        "cisAws": null,
        "cisAzure": null,
        "cisGcp": null,
        "cisK8s": null
      },
      {
        "findingId": "string",
        "title": "Wildcard IAM policy on production role",
        "severity": "critical",
        "cwe": "CWE-732",
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "cvssScore": 9.6,
        "owaspTop10": "A05:2021 - Security Misconfiguration",
        "owaspApiTop10": null,
        "nist80053": "AC-6 (Least Privilege), CM-7 (Least Functionality)",
        "pciDss": "Req 7.1 (Limit access to system components by business need)",
        "cisAws": "1.16 (No \`*:*\` IAM policies)",
        "cisAzure": null,
        "cisGcp": null,
        "cisK8s": null
      }
    ],
    "coverageMatrix": {
      "owaspTop10": {
        "A01": { "status": "tested", "findingCount": 2 },
        "A02": { "status": "tested", "findingCount": 1 },
        "A03": { "status": "tested", "findingCount": 3 },
        "A04": { "status": "not_tested", "findingCount": 0 },
        "A05": { "status": "tested", "findingCount": 1 },
        "A06": { "status": "tested", "findingCount": 0 },
        "A07": { "status": "tested", "findingCount": 1 },
        "A08": { "status": "not_tested", "findingCount": 0 },
        "A09": { "status": "not_tested", "findingCount": 0 },
        "A10": { "status": "tested", "findingCount": 0 }
      },
      "cis": {
        "cisAws": { "status": "tested", "controlsEvaluated": 12, "controlsFailed": 4, "controlsPassed": 8 },
        "cisAzure": { "status": "not_tested", "reason": "no Azure accounts in scope" },
        "cisGcp": { "status": "not_tested", "reason": "no GCP accounts in scope" },
        "cisK8s": { "status": "tested", "controlsEvaluated": 6, "controlsFailed": 2, "controlsPassed": 4 }
      }
    },
    "gaps": [
      {
        "framework": "OWASP Top 10",
        "category": "A04:2021 - Insecure Design",
        "status": "not_tested",
        "recommendation": "Add business logic testing and rate limiting checks"
      }
    ],
    "summary": {
      "totalFindings": 8,
      "mappedToCWE": 8,
      "mappedToOWASP": 8,
      "mappedToNIST": 6,
      "mappedToPCIDSS": 5,
      "mappedToCIS": 3,
      "averageCVSS": 6.2,
      "complianceCoverage": "70%"
    }
  }
}
\`\`\`

## Important Rules:
1. Be precise with CWE assignments (use the most specific CWE, not generic parents)
2. Be accurate with CVSS calculations (justify each component choice)
3. Distinguish between "tested clean" and "not tested" in coverage
4. Include gaps as actionable recommendations
5. Do NOT change finding severity -- only add compliance metadata
6. If a finding already has a CWE, verify it is correct before keeping or updating
7. CIS Benchmark fields apply ONLY to cloud findings (source: cloud-recon, cloud-exploit, kubernetes-security tools). Set cisAws/cisAzure/cisGcp/cisK8s to null for web/API/SAST findings -- do not stretch CIS mappings beyond cloud
8. Pick the CIS provider field that matches where the finding was discovered. A finding on EKS that touches the AWS plane (node IAM role, security groups) gets cisAws; one that touches the K8s plane (RBAC, pod spec) gets cisK8s; one that touches both gets both`;
  }
}
