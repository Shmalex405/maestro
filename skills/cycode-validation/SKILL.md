# Cycode SCA Validation Skill

## When to Use This Skill

Use this skill whenever the user provides Cycode SCA (Software Composition Analysis) findings — either as a CSV export or a list of CVEs — and wants a validation report that confirms which findings are actually exploitable in the live application.

This skill produces a **Cycode Dependency Vulnerability Validation Report**: a full SCA validation with live exploitation testing, cross-validated by an independent Grype scan, with a definitive TRUE/FALSE verdict for every single CVE.

---

## Before Starting

1. Get the Cycode CSV export from the user (or confirm the number of raw findings to validate)
2. Confirm the target repo path (e.g., `/mnt/host-home/projects/<repo>`)
3. Confirm the live application URL, GraphQL/API endpoints, and auth method
4. Read `config/credentials.yml` for auth configuration
5. Tell the user the plan:
   - You will authenticate to the live app
   - Run an independent Grype scan against the repo
   - Analyze the live JavaScript bundle to confirm which packages are actually deployed
   - Validate every CVE to a definitive TRUE or FALSE verdict
   - Produce the full validation report + PDF

---

## Phase 1: Import and Deduplicate Cycode Findings

### 1.1 Import the CSV

```
Tool: import_cycode_findings
Args: { "csv_content": "<full CSV content>", "assessment_id": "<id>" }
```

### 1.2 Understand the finding structure

Cycode SCA produces **one finding per (CVE, package, lockfile) tuple**. A single CVE affecting the same package in 11 different `go.mod` files produces 11 findings. Always document:

- Total raw Cycode findings
- Unique CVEs (deduplicated)
- Unique vulnerable packages
- Number of affected lockfiles
- Breakdown by severity (Critical / High / Medium / Low)

---

## Phase 2: Authentication

Use the browser tools to authenticate to the live application. Handle OTP interactively with the user.

```
Tool: browser_navigate → browser_fill → browser_click → prompt_for_otp → browser_save_state
```

After login: extract the JWT token via `browser_evaluate` on `localStorage` or cookies. Record:
- JWT expiry (re-auth if > 15 min into assessment)
- Auth type (PingOne, Cognito, custom, etc.)
- The user email used for testing

---

## Phase 3: Live Application Fingerprinting

### 3.1 Fingerprint the backend

Send a batch JSON array to the GraphQL endpoint to identify Go/gqlgen:
```
POST /graph/query
Content-Type: application/json
[{"query":"{ __typename }"},{"query":"{ __typename }"}]
```

Expected Go/gqlgen response: `"json: cannot unmarshal array into Go value of type graphql.RawParams"`

Document: backend language, framework, GraphQL library, Apollo federation presence.

### 3.2 Analyze the live JavaScript bundle

Download and analyze the production bundle:
```
Tool: browser_navigate → target the JS bundle URL
Tool: browser_evaluate → search for package signatures in window/navigator globals
```

For each CVE-affected frontend package, confirm:
- Is it **present in the live bundle**? (TRUE/FALSE)
- What version string is extractable?
- Does the deployed version differ from the lockfile version? (build cache drift)

This is critical — packages in `yarn.lock` are NOT necessarily shipped to the browser. Always verify.

### 3.3 Infrastructure scan

```
Tool: web_technology_scan  →  target: <live app URL>
Tool: check_certificate    →  target: <host>:443
Tool: scan_ssl_tls         →  target: <host>:443, checks: "all"
```

Identify: CDN (CloudFront, Fastly, etc.), WAF, security headers, CORS headers.

---

## Phase 4: Independent Cross-Validation (Grype)

Run Grype against the repository as an independent cross-validator:

```
Tool: scan_dependencies
Args: {
  "repo_path": "/mnt/host-home/projects/<repo>",
  "scan_types": ["dependencies"],
  "severity_threshold": "low"
}
```

Always produce a scanner comparison table:

| Scanner | Total Findings | Unique CVEs | Critical | High | Medium | Low |
|---------|---------------|-------------|----------|------|--------|-----|
| Cycode SCA | N | N | N | N | N | N |
| Grype (live scan) | N | N | N | N | N | N |
| **Delta** | **+N** | **+N** | **+N** | **+N** | **+N** | **+N** |

Document any CVEs found by Grype but NOT in Cycode — these are **new findings** and must be included in the report.

---

## Phase 5: Per-CVE Validation

For every unique CVE, apply this 4-question validation framework:

1. **Version in affected range?** — If the installed version is outside the advisory's affected range, verdict is FALSE (false positive). State the installed version and the range.
2. **Deployed to production?** — If the package is dev-only, build-tool-only, or not in the active deployment, verdict is FALSE. Distinguish: CONFIRMED LIVE (live bundle/API evidence), LIKELY LIVE, LIKELY NOT DEPLOYED, NOT DEPLOYED.
3. **User input reaches the vulnerable code path?** — Search source code for direct `require()`/`import` statements AND calls to the specific vulnerable function. If the function is never called with user-controlled input, verdict is FALSE.
4. **Exploitable?** — TRUE / FALSE / EXPLOITED. ZERO CVEs may remain at POTENTIALLY. Resolve every ambiguity via source code analysis or live testing.

### Verdict Rules

| Verdict | When to Use |
|---------|-------------|
| **EXPLOITED** | Live exploitation was demonstrated with real HTTP evidence |
| **TRUE** | Source code analysis confirms the vulnerable code path is reachable with user-controlled input in production |
| **FALSE** | Not exploitable — via any of: version mismatch, dev-only, not imported, vulnerable function not called, no user input reach, or live test proved safe |

**BANNED: POTENTIALLY** — Every CVE must be TRUE or FALSE before the report is written.

### Common FALSE categories to check

- **Dev/build-only**: vitest, webpack, esbuild, rollup, babel, ESLint, ts-node — these NEVER run in production
- **Transitive dep of build tool**: e.g., `simple-git` is a dep of `serverless` framework, not the app
- **Not imported in source**: grep for `require('package-name')` and `import ... from 'package-name'` across ALL source files. Zero results = FALSE.
- **Browser-side only**: axios, fetch, etc. when used exclusively in `ui/` — SSRF/server-side CVEs don't apply
- **Version mismatch**: CVE affects 7.x, installed is 6.x — FALSE
- **Withdrawn advisory**: Check if advisory was later retracted

### Source Code Searches Required

For every "TRUE candidate" CVE:

```
Tool: analyze_code_context
Args: {
  "file_path": "/mnt/host-home/projects/<repo>/<suspect file>",
  "vulnerability_type": "<sqli|ssrf|rce|protopp|etc.>"
}
```

Search for:
- Direct `require('packagename')` or `import` statements
- The specific vulnerable function call (e.g., `jwt.Parse`, `tar.extract`, `yaml.load`)
- User-controlled input reaching that function

---

## Phase 6: Live Exploitation Testing

For every CVE with verdict TRUE or EXPLOITED:

### Required Evidence Format

Every exploitation attempt MUST include:

**Prerequisites / Attacker Setup:**
- Attack origin (external/internal/authenticated)
- Access level required
- Tools required
- Network position

**Steps to Reproduce with REAL evidence** (numbered):

Each step must show:
```
REQUEST:
[exact curl command or HTTP request with real token values — NO PLACEHOLDERS]

RESPONSE (HTTP NNN, Nms):
[actual raw response body received — NOT a description of the response]
```

**Impact Analysis:**
- What the attacker gains
- Blast radius
- Affected data/users
- Real-world exploitation scenario

**Affected Component:**
- Exact endpoint, parameter, file:line

### Exploitation Escalation Pattern (for DoS/amplification)

When testing rate limiting, query amplification, or DoS vectors, always escalate in tiers and record each step:

| Payload Size | Response Time | Processed | Blocked |
|--------------|---------------|-----------|---------|
| 10 units | Nms | YES | NO |
| 50 units | Nms | YES | NO |
| 200 units | Nms | YES | NO |
| 500 units | Nms | YES | NO |

This proves linear scaling and demonstrates real DoS potential.

### NOT EXPLOITABLE format

```
Verdict: NOT EXPLOITABLE — [specific technical reason]

Evidence:
REQUEST: [the actual test request sent]
RESPONSE: [the actual response that proved safety]

Why safe: [technical explanation — SPA mitigates, Go rejects batch queries, CloudFront blocks, etc.]
```

---

## Phase 7: Report Structure (MANDATORY)

Every Cycode validation report MUST contain these sections in this order:

### 1. Cover Page (before first `## ` heading)

```markdown
# [Short Title]
# [Repository Full Name]
# [Organization / Repo]

**CONFIDENTIAL**

**Date:** [date]
**Prepared for:** [team]
**Prepared by:** Automated Security Validation via Kali MCP Pentest
**Repository:** [full GitHub URL]
**Assessment Type:** Software Composition Analysis (SCA) — Dependency Vulnerability Validation with Live Exploitation
**Live Application:** [app URL] ([tech stack, version])
**GraphQL/API:** [API URL] ([framework])
**Auth Provider:** [PingOne/Cognito/etc.]
**Total Cycode SCA Findings:** [N]
**Unique CVEs:** [N]
**Unique Packages:** [N]
**Affected Lockfiles:** [N]
**CVEs Fully Validated:** [N] ([breakdown by severity])
```

### 2. "What We Found and How We Found It" (narrative — comes BEFORE Table of Contents)

This is the executive narrative that a non-technical stakeholder reads first. It must include:

**a. The Assessment Process** — 2–4 paragraphs explaining HOW validation was done (authentication, bundle analysis, source code search, live testing). Cite specific evidence: bundle filenames, file sizes, number of source files searched, Grype comparison.

**b. The N Exploitable Vulnerabilities** — One numbered plain-language paragraph per exploitable finding. Each paragraph must:
- Name the vulnerability in plain English
- State what it does and who is affected
- Cite the specific evidence (e.g., "We proved this by sending a single request with 500 aliased queries…")
- Cite the specific file:line for code findings
- Link to the detailed finding section and the remediation section

**c. The N That Don't Matter (and Why)** — Plain-language explanation of the dominant FALSE categories. Explain the reasoning non-technically. Give real examples by package name.

**d. Recommended Remediation — What to Do** — Numbered list of actions (one per exploitable group). Each action: what to run/change, how many CVEs it fixes, link to the step-by-step remediation section.

### 3. Table of Contents (after narrative, before Executive Summary)

Use clickable markdown anchors. Include all major sections and finding subsections.

### 4. Executive Summary

**Key Metrics table** — totals, severity breakdown, validation percentages.

**Complete Validation Results** subsection with two tables:
- Confirmed Exploitable (TRUE) — all exploitable CVEs with evidence summary
- Confirmed NOT Exploitable (FALSE) — categorized breakdown table (not individual rows)

**Critical Risk Summary** — prose + table for every TRUE/EXPLOITED finding.

**Live Testing Verdicts table** — every finding that received live testing with REQUEST/RESPONSE outcome.

**Deployment Impact Assessment table** — every component with: Deployment Status, Internet-Facing, Finding Count, Critical, High.

### 5. Methodology

Four subsections:
- Cycode SCA methodology (how Cycode works — lockfile parsing, CVE matching, finding generation)
- Live Exploitation Validation (what was tested live and how)
- Per-CVE Validation Methodology (the 4-question framework)
- Cross-Validation: Live Grype Scan (scanner comparison table)
- Why Findings > CVEs (explain deduplication)

### 6. Live Exploitation Evidence

One subsection per live test performed, labeled:

```markdown
### EXPLOITED: [Vulnerability Name — CVE]
### CONFIRMED: [Evidence type — what was confirmed]
### NOT EXPLOITABLE: [Vulnerability Name — CVE]
### Additional Security Tests
### NEW Findings Discovered by Grype (Not in Cycode CSV)
### Per-Component Grype Scan Details
```

Each EXPLOITED/CONFIRMED section must follow the evidence format from Phase 6.

### 7. Severity Distribution

Three tables: By Severity (Unique CVEs + Total Findings), By Ecosystem, Exploitability Summary (TRUE/FALSE breakdown by severity).

### 8. Deployment Analysis

**Lockfile-to-Deployment Mapping** — one row per lockfile covering ALL lockfiles in the repo:

| # | Lockfile Path | Component | Deployment Status | Evidence | Findings |
|---|--------------|-----------|-------------------|----------|----------|

Deployment Status options: CONFIRMED LIVE, LIKELY LIVE, LIKELY NOT DEPLOYED, NOT DEPLOYED, MIXED, LIVE (internal)

**Key Deployment Discovery** subsection — call out any surprises (e.g., the "active portal" is a different directory than expected).

**Deployment Tiers** table — Tier 1 (confirmed internet-facing) through Tier 5 (dev-only).

### 9. Complete CVE Validation Summary Table

All N unique CVEs in one table per severity level (Critical, High, Medium, Low). Every row must have:

| # | CVE / Advisory | Package | Installed Version | Fix Version | Deployed | Exploitable | Notes |

- **Deployed** column: YES / NO / NOT ACTIVE / LIKELY / PARTIAL
- **Exploitable** column: **TRUE** / FALSE / **EXPLOITED**
- **Notes** must explain the reason for the FALSE verdict specifically

**ZERO rows may have Exploitable = POTENTIALLY.**

### 10. Critical Findings (full detail cards)

Each critical CVE gets a `### FINDING N: Title — CVE` card with:

```markdown
| Field | Value |
|-------|-------|
| **Severity** | **CRITICAL** |
| **CVE** | [CVE ID] |
| **Package** | `package@version` |
| **Affected Versions** | [range] |
| **Fixed Version** | [version] |
| **Ecosystem** | Node.js / Go / Python |
| **Occurrences** | [N findings across N lockfiles] |
| **Exploitable** | TRUE / FALSE / EXPLOITED — [one-line reason] |
| **Deployment** | CONFIRMED LIVE / NOT DEPLOYED / etc. |
```

For FALSE findings: add "#### Affected Lockfiles" table listing every lockfile.
For TRUE/EXPLOITED findings: add full live evidence per Phase 6 format.

### 11. High Findings by Component

Group high-severity CVEs by deployment component:
- `### [Component Name] — High Findings (N CVEs)`
- Table per component with: CVE, Package, Installed Version, Fix Version, Deployed, Exploitable, Evidence

### 12. Medium Findings Inventory

Table with all medium CVEs using the same columns as the Complete CVE Validation Summary Table.

### 13. Low Findings Inventory

Same table format for low CVEs.

### 14. Risk Assessment by Component

Table with component-level risk summary: Component, Tier, Internet-Facing, Total CVEs, Exploitable, Recommended Priority.

### 15. Lockfile-to-Deployment Mapping (detailed)

Repeat from Deployment Analysis with added details — links to specific evidence for each CONFIRMED LIVE entry.

### 16. Prioritized Remediation Plan

Priority labels: P0 (Critical/High exploitable), P1 (High non-exploitable in internet-facing), P2 (High non-exploitable internal), P3 (Medium), P4 (Low + remainder).

Each priority item:
```markdown
#### P0-A: [Action Title]

**CVEs Resolved:** [list with finding count]
**Live Evidence:** [TRUE/EXPLOITED — one-line proof]
**Exploitable:** TRUE

**Step 1:** [exact command or code change]
```bash
[runnable command]
```

**Step 2:** [next action]

**Verification:**
```bash
[how to confirm the fix worked]
```
```

### 17. Full CVE Inventory Table

Complete table of ALL findings (all N rows from the Cycode CSV), grouped by lockfile. Columns: Lockfile, CVE, Package, Installed Version, Severity, Exploitable.

### 18. Appendix A: Lockfile Finding Counts

Table of all lockfiles sorted by finding count descending.

### 19. Appendix B: Infrastructure Fingerprinting Details

Raw output from: WhatWeb, security headers analysis, CDN fingerprinting, certificate details.

### 20. Appendix C: Individual CVE Validation Details — Critical and High

For every Critical and High CVE that is FALSE: a brief prose paragraph explaining the specific reason it's not exploitable (why the vulnerable code path is not reached). Reference exact source code evidence (file paths, function names, import grep results).

### 21. Appendix D: Individual CVE Validation Details — Medium and Low

Same format as Appendix C but for Medium and Low CVEs.

---

## Quality Gates (REPORT MUST PASS ALL BEFORE PDF)

Before generating the PDF:

- [ ] **Zero POTENTIALLY verdicts** — every CVE is TRUE or FALSE
- [ ] **Zero vague language** — no "various", "multiple", "several", "some", "etc.", "and more"
- [ ] **Every lockfile listed** — all N lockfiles appear in the Deployment Analysis table
- [ ] **Counts are verifiable** — if "9 exploitable", count the TRUE rows; if "394 findings", the inventory table has 394 rows
- [ ] **Real evidence on all TRUE/EXPLOITED findings** — real curl commands with real tokens, real HTTP response bodies
- [ ] **No placeholders** — `$TOKEN`, `<PASSWORD>`, `{BEARER}` banned; use real values
- [ ] **Grype cross-validation completed** — scanner comparison table present
- [ ] **Bundle analysis completed** — packages confirmed present or absent in live bundle
- [ ] **All remediation steps are runnable** — exact commands with real directory paths and version numbers
- [ ] **Narrative section present** — "What We Found and How We Found It" comes before ToC

---

## PDF Generation

After the markdown report is complete and passes quality gates:

```
Tool: generate_pdf_report
Args: {
  "markdown_path": "/mnt/host-home/Desktop/kali-mcp-pentest/reports/<filename>.md",
  "output_path": "/mnt/host-home/Desktop/kali-mcp-pentest/reports/<filename>.pdf"
}
```

If the MCP PDF tool fails, fall back to Playwright:
```
Tool: browser_navigate  →  file://... (the md-to-pdf script generates HTML first)
Tool: browser_evaluate  →  window.print() or call Playwright page.pdf()
```

---

## Key Lessons from a Dependency-Validation Engagement

- **Bundle drift**: The deployed JS bundle may contain different versions than the lockfile (build artifact caching). Always extract the version string from the live bundle — don't trust the lockfile alone.
- **Legacy portal disambiguation**: In monorepos with multiple frontend portals, confirm which one is actually live by downloading and analyzing the bundle, not by guessing from directory names.
- **Verdict reversal protocol**: When source code analysis overturns a preliminary verdict (e.g., golang-jwt looked TRUE until we confirmed only `NewWithClaims` is called, not `Parse`), document the reversal explicitly: "**Verdict changed: TRUE → FALSE**" with the exact code evidence.
- **Grype finds more**: Grype typically finds ~5–10% more CVEs than Cycode. Always run it and document the delta. Report Grype-only CVEs as "NEW Findings Discovered by Grype".
- **Apollo field suggestions leak schema**: Even with introspection disabled, Apollo returns field suggestions in error messages. Document this as an informational finding.
- **CDN CORS masking**: A CDN may override permissive backend CORS settings. The backend code is still misconfigured — document both the masking effect AND the underlying code risk.
- **Per-occurrence vs per-CVE reporting**: Keep both. Cycode counts per-occurrence (same CVE across 11 go.mod = 11 findings). Reports should show both the occurrence count AND the unique CVE count to avoid confusion.
