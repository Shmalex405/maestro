/**
 * Chain Analysis Agent Implementation
 *
 * Two-touch analysis agent that identifies multi-step attack chains:
 * - Touch 1 (hypothesize): Tags findings with grants/requires capabilities,
 *   matches against pattern catalog, generates chain hypotheses
 * - Touch 2 (validate): Receives exploit results, confirms/refutes hypotheses,
 *   discovers emergent chains, creates chain findings
 *
 * This agent does NOT perform any scanning. It receives findings via
 * input.context.findings and produces chain analysis as output.
 */

import {
  BaseAgent,
  AgentConfig,
  AgentInput,
  ToolDefinition,
  ProgressCallback,
} from "../base-agent";
import { reportingHandlers } from "../../tools/reporting";

const CHAIN_ANALYSIS_AGENT_CONFIG: AgentConfig = {
  name: "chain-analysis-agent",
  description: "Attack chain discovery and validation agent",
  maxIterations: 20,
  timeoutMs: 300000, // 5 minutes
  requiresScopeValidation: false,
  tools: [
    "create_finding",
    "generate_report",
  ],
};

const CHAIN_ANALYSIS_TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: "create_finding",
    description:
      "Create a chain finding that documents a multi-step attack path. " +
      "Title MUST be prefixed with 'CHAIN:'. Description should detail " +
      "the full attack path with steps, capabilities, and combined impact. " +
      "Evidence should contain the proof path showing how findings connect.",
    input_schema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description: "Finding title (MUST start with 'CHAIN:')",
        },
        severity: {
          type: "string",
          enum: ["info", "low", "medium", "high", "critical"],
          description: "Combined chain severity (highest step + chain bonus, capped at critical)",
        },
        description: {
          type: "string",
          description:
            "Full attack chain description: steps, capabilities granted/required at each step, combined impact",
        },
        target: {
          type: "string",
          description: "Primary target of the chain",
        },
        evidence: {
          type: "string",
          description:
            "Proof path: Step 1 (Finding X grants capability A) → Step 2 (Finding Y requires A, grants B) → Impact",
        },
        remediation: {
          type: "string",
          description: "Which link to break and why (defense-in-depth recommendations)",
        },
      },
      required: ["title", "severity", "description", "target"],
    },
  },
  {
    name: "generate_report",
    description:
      "Generate an attack chain analysis report section. Use after all chain " +
      "hypotheses have been generated or validated.",
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

export class ChainAnalysisAgentImpl extends BaseAgent {
  constructor(onProgress?: ProgressCallback) {
    super(
      CHAIN_ANALYSIS_AGENT_CONFIG,
      { ...reportingHandlers },
      onProgress
    );
  }

  getToolDefinitions(): ToolDefinition[] {
    return CHAIN_ANALYSIS_TOOL_DEFINITIONS;
  }

  buildInitialPrompt(input: AgentInput): string {
    const chainMode = input.context?.chainMode || "hypothesize";

    if (chainMode === "validate") {
      return this.buildValidationPrompt(input);
    }
    return this.buildHypothesisPrompt(input);
  }

  private buildHypothesisPrompt(input: AgentInput): string {
    const findings = input.context?.findings || [];

    let prompt = `# Attack Chain Hypothesis Generation

You are the Chain Analysis Agent in HYPOTHESIS mode. Your mission is to analyze individual security findings and identify multi-step attack chains.

## Capability Taxonomy

Each vulnerability GRANTS certain capabilities to an attacker and may REQUIRE certain preconditions:

| Capability | Description |
|---|---|
| unauthenticated_access | Can interact without credentials |
| authenticated_session | Has a valid user session |
| admin_session | Has admin-level access |
| javascript_execution | Can run JS in victim's browser |
| sql_execution | Can execute SQL queries |
| command_execution | Can execute OS commands |
| file_read | Can read arbitrary files |
| file_write | Can write arbitrary files |
| ssrf_request | Can make server-side requests |
| internal_network_access | Can reach internal services |
| cloud_metadata_access | Can access cloud metadata endpoint |
| credential_theft | Can steal credentials/tokens |
| session_hijack | Can take over user sessions |
| privilege_escalation | Can elevate access level |
| data_exfiltration | Can extract sensitive data |
| cache_control | Can manipulate cached responses |
| header_injection | Can inject HTTP headers |
| template_execution | Can execute server templates |
| deserialization_rce | Can achieve RCE via deserialization |
| dns_control | Can manipulate DNS records |
| token_forgery | Can create/modify auth tokens |
| api_abuse | Can abuse API without rate limits |
| upload_execution | Can upload and execute files |
| path_traversal | Can traverse file system paths |
| prototype_pollution | Can pollute JS prototypes |

## Vulnerability-to-Capability Mapping

| Vulnerability Type | Grants | Requires |
|---|---|---|
| xss (reflected/stored) | javascript_execution, credential_theft, session_hijack | unauthenticated_access or authenticated_session |
| sqli | sql_execution, data_exfiltration, credential_theft | unauthenticated_access or authenticated_session |
| ssrf | ssrf_request, internal_network_access, cloud_metadata_access | unauthenticated_access or authenticated_session |
| rce / command_injection | command_execution, file_read, file_write | unauthenticated_access or authenticated_session |
| idor | data_exfiltration, privilege_escalation | authenticated_session |
| path_traversal | file_read, path_traversal | unauthenticated_access or authenticated_session |
| ssti | template_execution, command_execution | unauthenticated_access or authenticated_session |
| jwt_weakness | token_forgery, privilege_escalation | unauthenticated_access |
| missing_httponly | credential_theft (via XSS) | javascript_execution |
| missing_rate_limit | api_abuse | unauthenticated_access |
| cors_misconfiguration | credential_theft (cross-origin) | javascript_execution |
| http_smuggling | cache_control, header_injection | unauthenticated_access |
| cache_poisoning | cache_control, javascript_execution | header_injection or cache_control |
| file_upload | upload_execution, file_write | authenticated_session |
| deserialization | deserialization_rce, command_execution | unauthenticated_access or authenticated_session |
| prototype_pollution | prototype_pollution, javascript_execution | unauthenticated_access |
| token_in_localstorage | credential_theft (via XSS) | javascript_execution |
| weak_password_policy | credential_theft (brute force) | unauthenticated_access |
| missing_csp | javascript_execution (enables XSS payloads) | (amplifier) |
| missing_hsts | credential_theft (network) | internal_network_access |
| exposed_secrets | credential_theft, authenticated_session, admin_session | file_read or unauthenticated_access |
| subdomain_takeover | dns_control, javascript_execution | unauthenticated_access |

## Findings to Analyze

`;

    if (findings.length === 0) {
      prompt += "No findings provided. Check context.findings.\n";
      if (input.context) {
        prompt += `Available context keys: ${Object.keys(input.context).join(", ")}\n`;
      }
    } else {
      for (let i = 0; i < findings.length; i++) {
        const f = findings[i];
        prompt += `### Finding ${i + 1}: ${f.title || f.name || "Untitled"}
- **ID**: ${f.id || `finding-${i}`}
- **Severity**: ${f.severity || "unknown"}
- **Target**: ${f.target || "unknown"}
- **Source**: ${f.source || "unknown"}
- **Description**: ${(f.description || "").slice(0, 300)}
- **Evidence**: ${f.evidence ? String(f.evidence).slice(0, 200) + "..." : "None"}

`;
      }
    }

    prompt += `## Your Workflow

### Step 1: Tag Each Finding
For every finding, determine what capabilities it GRANTS and what it REQUIRES. Store this analysis.

### Step 2: Match Chain Patterns
Look for these common patterns (and any others you identify):

1. **XSS → Session Hijack → Privilege Escalation**: XSS grants javascript_execution → steal admin token → access admin functions
2. **SSRF → Cloud Metadata → Key Theft**: SSRF grants internal_network_access → access 169.254.169.254 → steal AWS keys
3. **SQLi → Credential Dump → Admin Access**: SQLi grants data_exfiltration → dump user table → login as admin
4. **Token in localStorage + XSS → Session Theft**: Missing HttpOnly + XSS = trivial session hijack
5. **Missing CSP + XSS → Unrestricted Exploitation**: No CSP amplifies any XSS finding
6. **IDOR + Missing Rate Limit → Mass Data Extraction**: IDOR + no rate limit = automated enumeration
7. **HTTP Smuggling → Cache Poisoning → Stored XSS**: Smuggling enables cache poisoning enables persistent XSS
8. **File Upload + Path Traversal → RCE**: Upload shell + traverse to web root = code execution
9. **SAST Secrets + Active Credentials → Data Breach**: Hardcoded keys still active = direct access
10. **Weak JWT + IDOR → Full Account Takeover**: Forge tokens + access any user's data

### Step 3: Discover Emergent Chains
Beyond catalog patterns, look for novel combinations specific to THIS target. Consider:
- What does each finding enable that could be the precondition for another?
- Are there defense gaps (missing CSP, no rate limiting) that amplify other findings?
- Can SAST findings (code-level) connect to DAST findings (runtime)?

### Step 4: Generate Hypotheses
For each chain identified, create a finding with:
- Title: "CHAIN: [descriptive name]"
- Severity: Highest step severity + 1 level (capped at critical)
- Description: Full chain path with capabilities at each step
- Evidence: Proof path showing connection between findings
- Remediation: Which link is easiest to break

### Step 5: Output Chain Hypotheses
After creating all chain findings, output a JSON summary in your final message:

\`\`\`json
{
  "chainHypotheses": [
    {
      "id": "hyp-CHAIN-XX-timestamp",
      "patternId": "CHAIN-XX or null if emergent",
      "name": "Chain name",
      "description": "Full description",
      "steps": [
        { "findingId": "...", "findingTitle": "...", "grants": [...], "requires": [...], "order": 1 }
      ],
      "confidence": 0.0-1.0,
      "severityCombined": "critical|high|medium|low|info",
      "requiredTests": [
        { "description": "Test step", "steps": ["curl ..."], "findingIds": [...], "expectedOutcome": "..." }
      ],
      "emergent": false
    }
  ]
}
\`\`\`

## Confidence Scoring
- Base confidence from pattern match: 0.60
- +0.15 if both findings target same host
- +0.10 if findings from same scan session
- -0.20 if findings target different hosts
- -0.15 if chain requires authentication not yet proven
- Emergent chains start at 0.40 base

## Severity Calculation
- Take highest severity among chain steps
- Add one level for confirmed chains (medium → high)
- Cap at critical
- Example: Medium SSRF + Low missing metadata protection = High chain (medium + 1)

Begin hypothesis generation now.`;

    return prompt;
  }

  private buildValidationPrompt(input: AgentInput): string {
    const chainHypotheses = input.context?.chainHypotheses || [];
    const exploitResults = input.context?.exploitResults || input.context?.validatedExploits || [];
    const findings = input.context?.findings || [];

    let prompt = `# Attack Chain Validation

You are the Chain Analysis Agent in VALIDATION mode. You have chain hypotheses from your earlier analysis and exploit results from the Exploit Agent. Your job is to confirm, refute, or flag untested chains.

## Chain Hypotheses to Validate

`;

    if (chainHypotheses.length === 0) {
      prompt += "No chain hypotheses found in context. Check context.chainHypotheses.\n";
      if (input.context) {
        prompt += `Available context keys: ${Object.keys(input.context).join(", ")}\n`;
      }
    } else {
      for (let i = 0; i < chainHypotheses.length; i++) {
        const h = chainHypotheses[i];
        prompt += `### Hypothesis ${i + 1}: ${h.name || "Unnamed"}
- **ID**: ${h.id || `hyp-${i}`}
- **Pattern**: ${h.patternId || "emergent"}
- **Confidence**: ${h.confidence || "unknown"}
- **Severity**: ${h.severityCombined || "unknown"}
- **Steps**: ${JSON.stringify(h.steps || [], null, 2)}
- **Required Tests**: ${JSON.stringify(h.requiredTests || [], null, 2)}

`;
      }
    }

    prompt += `## Exploit Results

`;

    if (exploitResults.length === 0) {
      prompt += "No exploit results found. Chains that depended on exploitation are UNTESTED.\n";
    } else {
      for (const r of exploitResults) {
        prompt += `- **${r.tool || r.name || "unknown"}** on ${r.target || "unknown"}: ${JSON.stringify(r.result || r.status || "no result").slice(0, 300)}\n`;
      }
    }

    prompt += `
## Current Findings (${findings.length} total)

${findings.slice(0, 30).map((f: any, i: number) =>
  `${i + 1}. [${(f.severity || "?").toUpperCase()}] ${f.title} @ ${f.target}`
).join("\n")}

## Validation Rules

### Confirmed Chain
A chain is CONFIRMED if:
- All steps in the chain have corresponding findings
- Exploit results show the chain connection works (e.g., XSS payload successfully stole session cookie)
- Evidence proves capability transfer between steps

### Refuted Chain
A chain is REFUTED if:
- Exploit results show a step is blocked (e.g., CORS properly blocks cross-origin request despite reflected origin)
- A defense mechanism breaks the chain (e.g., CSP blocks XSS despite missing HttpOnly)
- The capability transfer was tested and failed

### Untested Chain
A chain is UNTESTED if:
- The exploit agent did not attempt the required tests
- Timeout or other issues prevented testing
- Mark as "requires manual follow-up"
- Do NOT mark untested as refuted

## Your Workflow

### Step 1: Match Exploit Results to Hypotheses
For each hypothesis, check if the exploit agent attempted the required tests. Map results to chain steps.

### Step 2: Evaluate Each Chain
Determine status: confirmed, refuted, or untested. Adjust confidence scores:
- +0.25 if exploit confirmed the chain
- -0.30 if exploit showed chain is blocked
- No change if untested

### Step 3: Discover Emergent Chains
With exploit results available, look for NEW chains that weren't hypothesized:
- Did the exploit agent discover unexpected connections?
- Did a failed exploit reveal a different viable path?
- Did defense-in-depth analysis reveal gaps?

### Step 4: Create Chain Findings
For CONFIRMED chains, create findings with:
- Title: "CHAIN: [name] (CONFIRMED)"
- Include full exploit evidence in the proof path

For REFUTED chains, create info findings:
- Title: "CHAIN: [name] (REFUTED - [reason])"
- Document what defense blocked the chain

### Step 5: Output Validation Summary
Output a JSON summary:

\`\`\`json
{
  "chainValidation": {
    "confirmed": [...],
    "refuted": [...],
    "untested": [...],
    "emergentChains": [...]
  }
}
\`\`\`

## Defense-in-Depth Analysis
For each refuted chain, document which security control broke it. This helps prioritize security controls:
- If CSP blocks XSS chains: CSP is a critical control
- If rate limiting prevents enumeration chains: rate limiting is critical
- If auth middleware blocks privilege escalation chains: auth middleware is critical

Begin chain validation now.`;

    return prompt;
  }

  getSystemPrompt(): string {
    return `You are the Chain Analysis Agent, specializing in identifying multi-step attack chains from individual security findings.

## Your Role
You are a READ-ONLY analysis agent. You do NOT perform scanning or testing. You receive findings from other agents and identify how they can be combined into multi-step attack paths.

## Core Concept: Grants and Requires
Every vulnerability GRANTS certain capabilities to an attacker and REQUIRES certain preconditions:
- XSS GRANTS javascript_execution, credential_theft. REQUIRES unauthenticated_access.
- Missing HttpOnly cookie GRANTS credential_theft (via XSS). REQUIRES javascript_execution.
- Therefore: XSS + Missing HttpOnly = Chain (XSS provides the javascript_execution that missing HttpOnly requires)

## Two Execution Modes

### Hypothesize Mode (Touch 1)
- Receives findings from scanning agents
- Tags each finding with grants/requires capabilities
- Matches against known chain patterns
- Discovers emergent (novel) chains
- Outputs chainHypotheses with requiredTests for the exploit agent

### Validate Mode (Touch 2)
- Receives chainHypotheses from Touch 1 and exploit results
- Confirms or refutes each hypothesis based on evidence
- Discovers new chains revealed by exploitation
- Creates chain findings for the report
- Outputs chainValidation summary

## Chain Finding Format
- Title MUST start with "CHAIN:" prefix
- Evidence MUST show the proof path: Step 1 → Step 2 → ... → Impact
- Remediation MUST recommend which link to break (defense-in-depth)
- Severity = highest step severity + chain bonus (capped at critical)

## Important Rules
1. Every chain hypothesis must have a clear proof path
2. Untested does NOT equal refuted — be honest about what was tested
3. Consider both same-host and cross-host chains (with lower confidence for cross-host)
4. SAST findings can chain with DAST findings (code weakness + runtime exploit)
5. Defense gaps (missing CSP, missing rate limiting) are AMPLIFIERS, not chains by themselves
6. Document which defensive controls would break each chain`;
  }
}
