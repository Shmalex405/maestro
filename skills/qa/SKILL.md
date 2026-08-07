# QA Agent Skill

## Purpose
The QA Agent validates findings from other agents before report generation. It acts as a quality assurance layer that reduces false positives, identifies coverage gaps, and assigns confidence scores to each finding.

## When to Use
- Automatically before report generation in full assessment workflow
- After any agent produces findings that need validation
- When you want to verify the quality of an assessment
- To identify what was missed during testing

## Input Format

The QA Agent receives context containing:
- `findings[]` - All findings from prior agents
- `agentResults` - Summary of what each agent did (tool calls, iterations, errors)
- `targets` - Original targets that were tested
- Standard shared context (credentials, scope info, etc.)

## Available Tools

### validate_finding
Re-test a specific finding to confirm it's real.
```
Arguments:
  - finding_id: ID of the finding to validate
  - retest_method: "quick" | "thorough" (default: quick)
  - custom_payload: Optional specific test payload
```

### check_coverage
Analyze what attack vectors were tested vs what could have been tested.
```
Arguments:
  - targets: Targets to analyze coverage for
  - agent_results: Results from agents that ran
```

### score_confidence
Evaluate a finding's evidence quality and assign a confidence score.
```
Arguments:
  - finding_id: ID of the finding to score
  - criteria: Optional specific criteria to evaluate
```

### request_agent_followup
Request a specific agent to run additional targeted tests.
```
Arguments:
  - agent: "recon" | "vuln-scan" | "web-app" | "exploit"
  - targets: Specific targets to test
  - focus: What to look for specifically
  - context: Additional context for the agent
```

### get_agent_summary
Get detailed summary of what an agent did during its execution.
```
Arguments:
  - agent_name: Name of the agent to summarize
```

### compare_findings
Cross-reference findings from different sources to identify discrepancies.
```
Arguments:
  - finding_ids: Array of finding IDs to compare
```

### Re-testing Tools
The QA agent also has access to tools from other agents for direct re-validation:
- `scan_ports` - Re-verify open ports
- `run_nuclei` - Re-run specific vulnerability checks
- `run_sqlmap` - Re-test SQL injection points
- `curl_request` - Make HTTP requests to verify web findings
- `run_metasploit_check` - Re-verify exploit conditions

## Workflow Pattern

1. **Receive Context**
   - Parse all findings from prior agents
   - Get agent execution summaries
   - Note original targets and scope

2. **Triage Findings**
   - Group by severity (critical > high > medium > low > info)
   - Group by source agent
   - Identify findings that need validation

3. **Validate Sample**
   - Re-test 100% of critical findings
   - Re-test ~50% of high findings (prioritize exploitable ones)
   - Spot-check medium/low findings as time permits
   - For each: Record confirmed | not_reproduced | inconclusive

4. **Coverage Analysis**
   - What attack vectors were tested?
   - What was NOT tested? (gaps)
   - Were all endpoints covered?
   - Were auth boundaries fully tested?
   - Were all severity levels of templates used?

5. **Confidence Scoring**
   For each finding, score 1-10 based on:
   - Evidence quality (PoC provided? Screenshots? Logs?)
   - Reproducibility (confirmed in re-test?)
   - Impact clarity (exploitation path documented?)
   - False positive likelihood (common FP pattern?)

6. **Request Follow-ups (if needed)**
   - Ask recon for more info on specific hosts
   - Ask vuln-scan to check specific CVEs
   - Ask web-app to test specific endpoints deeper
   - Wait for and incorporate follow-up results

7. **Produce QA Review**
   - Compile validated findings with confidence scores
   - Document false positives with reasoning
   - List coverage gaps with recommendations
   - Calculate overall confidence score
   - Generate summary for report agent

## Validation Decision Tree

```
For each finding:
├── Is severity critical?
│   └── YES → Validate thoroughly (use thorough retest)
├── Is severity high?
│   └── YES → Validate (use quick retest)
├── Is evidence weak or missing?
│   └── YES → Validate to strengthen or invalidate
├── Does finding match known FP pattern?
│   └── YES → Validate to confirm FP
├── Is finding from automated scanner only?
│   └── YES → Consider validation if high/critical
└── Otherwise → Assign confidence based on evidence quality
```

## Confidence Scoring Guide

| Score | Meaning | Criteria |
|-------|---------|----------|
| 10 | Certain | Exploited, full PoC, repeatable |
| 8-9 | High confidence | Strong evidence, re-test confirmed |
| 6-7 | Medium confidence | Reasonable evidence, not fully validated |
| 4-5 | Low confidence | Weak evidence, possible FP |
| 1-3 | Very low | Scanner-only, likely FP, needs investigation |

### Confidence Score Calibration Rubric

Agents MUST use this rubric when assigning confidence scores to ensure consistency across assessments:

| Score | Criteria | Example |
|-------|----------|---------|
| **9-10** | Confirmed exploit with real request/response proof. Attacker can reproduce with copy-paste commands. | SQL injection returned database contents; IDOR returned another user's PII |
| **7-8** | Tool confirmed vulnerability + manual re-test succeeded. Evidence includes actual HTTP responses. | Nuclei confirmed CVE with response body; curl verified missing security header |
| **5-6** | Tool reported finding but not manually verified against live target. Plausible but unproven. | Semgrep flagged SQL concatenation; dependency scanner found known CVE in library |
| **3-4** | SAST-only finding with no live endpoint to test, or finding in test/vendor code. | Hardcoded credential in test fixture; vulnerable pattern in vendored dependency |
| **1-2** | Likely false positive: test code, example files, commented-out code, or vendor boilerplate. | Secret pattern in `node_modules/`; SQL injection pattern in ORM-generated code |

**Anchoring Rules:**
- A successful curl/HTTP exploit with real response proof MUST score >= 8
- A tool-confirmed finding with response evidence MUST score >= 7
- A SAST-only finding with no live endpoint MUST score <= 5
- Any finding in test fixtures or vendor code MUST score <= 3
- If multiple tools confirm the same finding, add +1 to the base score (cap at 10)

## Test Matrix Compliance

**CRITICAL:** Before producing the QA review, the QA agent MUST read `config/test-matrix.yml` and verify that every required test was executed during the assessment. This is the primary mechanism for ensuring consistent, repeatable assessments.

### Compliance Check Workflow

1. Read `config/test-matrix.yml` to get the full list of required tests
2. Cross-reference each `test_id` against the assessment walkthrough and tool call history
3. For any test NOT executed:
   - Flag it as a **coverage gap** with priority "high"
   - If the test is feasible to run now, use `request_agent_followup` to execute it
   - If not feasible, document the reason (e.g., "tool unavailable", "target not applicable")
4. Include a **Test Matrix Compliance** table in the QA review output

### Test Matrix Compliance Output

```json
{
  "testMatrixCompliance": {
    "totalRequired": "<in-scope count — scope-derived from test-matrix applies_when, not a fixed number>",
    "executed": 95,
    "skipped": 8,
    "notApplicable": 5,
    "complianceRate": "87.9%",
    "missingTests": [
      {
        "test_id": "GQL-03",
        "name": "Schema enumeration via suggestions",
        "reason": "Not executed — should be run",
        "priority": "high"
      }
    ]
  }
}
```

## Coverage Gap Categories

- **Authentication**: Login bypass, session management, MFA bypass, session fixation, token replay
- **Authorization**: IDOR, horizontal/vertical privilege escalation, function-level access controls
- **Injection**: SQLi, XSS, Command injection, Template injection (SSTI), LDAP, XPath, NoSQL, CRLF
- **SSRF**: Internal IP access, cloud metadata, DNS rebinding
- **Business Logic**: Rate limiting, workflow bypass, race conditions, price manipulation
- **Cryptography**: Weak algorithms, key management, TLS config, cipher suites
- **Configuration**: Headers, CORS, error handling, debug modes, cookie flags
- **API Security**: GraphQL introspection, REST fuzzing, rate limiting, mass assignment, IDOR
- **File Upload**: Extension bypass, content-type manipulation, path traversal
- **Transport/Protocol**: HTTP smuggling, WebSocket security, cache poisoning
- **Deserialization**: Java/Python/PHP/dotNET unsafe deserialization
- **Supply Chain**: Dependency CVEs, license compliance, dependency confusion
- **Infrastructure**: SSL/TLS, DNS security, subdomain takeover, cloud metadata

## Best Practices

1. **Prioritize Validation**
   - Critical findings first, always
   - High findings with weak evidence
   - Findings that will drive remediation decisions

2. **Document Everything**
   - Why a finding was marked as FP
   - What evidence changed the confidence
   - What follow-up testing was requested

3. **Be Conservative**
   - When uncertain, don't inflate confidence
   - When finding can't be reproduced, investigate before marking FP
   - Consider environment differences that could affect reproducibility

4. **Coverage Over Completeness**
   - Better to validate a sample thoroughly than all findings superficially
   - Focus on actionable insights over comprehensive validation

5. **Coordinate Follow-ups**
   - Only request follow-ups if they will meaningfully improve the assessment
   - Provide specific, actionable requests to follow-up agents
   - Incorporate follow-up results before final scoring

## Output Format

The QA agent adds `qaReview` to context:

```json
{
  "qaReview": {
    "validatedFindings": [
      {
        "findingId": "string",
        "confidence": 8,
        "validationStatus": "confirmed",
        "retestEvidence": "string",
        "notes": "string"
      }
    ],
    "falsePositives": [
      {
        "findingId": "string",
        "reason": "string",
        "retestOutput": "string"
      }
    ],
    "coverageGaps": [
      {
        "area": "Authentication bypass",
        "description": "No testing of SSO/SAML integration",
        "recommendation": "Test SAML response manipulation",
        "priority": "high"
      }
    ],
    "followUpResults": [
      {
        "agent": "web-app",
        "request": "Test /api/admin endpoints",
        "result": { "...agent output..." }
      }
    ],
    "overallConfidence": 7.5,
    "summary": "Validated 15 findings. 2 false positives identified. 3 coverage gaps noted.",
    "stats": {
      "totalReviewed": 15,
      "confirmed": 12,
      "falsePositives": 2,
      "inconclusive": 1,
      "coverageScore": 75
    }
  }
}
```

The report agent should use this to:
- Only include validated findings (or note unvalidated ones)
- Show confidence scores in the report
- Include coverage gaps section
- Note overall assessment confidence

## SAST QA Mode

When the QA agent runs in dual-track mode, it operates in one of two specialized modes:

### When SAST Mode Activates
- `context.qaMode === "sast"` is set by the orchestrator when the QA agent is part of Track B (SAST pipeline)
- The agent receives findings from `security-scan` and `code-intel` agents (not DAST results)

### SAST-Specific Validation Approach

Instead of re-testing against live endpoints, SAST QA validates findings by:

1. **Reading source code** via `analyze_code_context` tool
2. **Checking dataflow**: Does user input actually reach the vulnerable sink?
3. **Checking defenses**: Are there mitigating controls? (parameterized queries, input validation, output encoding, ORM sanitization)
4. **Checking context**: Is the finding in test code, dead code, vendored dependencies, or example files?

### SAST False Positive Detection

Flag findings as false positives if:
- Located in test files (`__tests__/`, `*.test.*`, `*.spec.*`)
- In vendored/node_modules code
- User input is validated before reaching the sink
- Parameterized queries are used (for SQLi findings)
- Output is properly encoded (for XSS findings)
- Framework provides built-in protection
- Dead code / unreachable execution path

### SAST Confidence Scoring

| Score | Meaning | Criteria |
|-------|---------|----------|
| 9-10 | Exploitable | User input → vulnerable sink with no validation |
| 7-8 | Likely vulnerable | Minor mitigations present but bypassable |
| 5-6 | Uncertain | Dataflow unclear, needs runtime testing |
| 3-4 | Low risk | Defenses present but incomplete |
| 1-2 | Likely FP | Test code, dead code, or strong defenses |

### Additional Tool: analyze_code_context

Available only in SAST mode. Reads source code at a specific file:line to verify findings.

```
Arguments:
  - file_path: Path to the source file (required)
  - line_start: Starting line number
  - line_end: Ending line number
  - vulnerability_type: Type of vulnerability (sqli, xss, ssrf, etc.)
```

### DAST Mode (Default)

When `context.qaMode === "dast"` or `qaMode` is not set, the QA agent uses its standard behavior: re-testing findings against live endpoints using recon, vuln-scan, and browser tools.
