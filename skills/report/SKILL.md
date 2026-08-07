# Report Generation Agent Skill

## Purpose
The Report Agent aggregates findings from all other agents, generates reports in multiple formats, creates Jira tickets, and distributes results.

## When to Use
- End of assessment workflow
- On-demand report generation
- When findings need to be ticketed
- Periodic status reporting

## Available Tools

### create_finding
Creates a new finding record in the database.
```
Arguments:
  - title: Finding title
  - severity: info|low|medium|high|critical
  - description: Detailed description
  - target: Affected target
  - evidence: Proof of vulnerability
  - remediation: Recommended fix
  - exploitable: "true"|"false"|"not_tested" — whether exploitation succeeded
  - cve: Associated CVE (optional)
  - cwe: CWE identifier (optional, e.g., CWE-89)
  - cycode_ref: Cycode reference (optional)
  - source: Tool that found this (e.g., nuclei, sqlmap, semgrep)
  - file_path: Source file path for SAST findings (optional)
  - line_start: Starting line number (optional)
  - line_end: Ending line number (optional)
  - code_snippet: Relevant code snippet (optional)
  - file_locations: JSON array of affected locations for multi-file findings (optional)
    Format: [{"file": "path/to/file", "line": 42, "context": "description", "commit_hash": "abc123", "author": "name"}]
  - remediation_code: Fixed code snippet (optional)
  - remediation_explanation: Why the fix works (optional)
```

### generate_report
Generates a formatted report.
```
Arguments:
  - format: markdown|html|json
  - include_evidence: Boolean
  - finding_ids: Specific findings (optional, defaults to all)
```

### create_jira_ticket
Creates a Jira ticket for a finding.
```
Arguments:
  - finding_id: Finding to ticket
  - project_key: Jira project key
  - priority: Lowest|Low|Medium|High|Highest
```

### upload_report
Uploads report to SharePoint and optionally emails it.
```
Arguments:
  - report_content: Report content
  - filename: Report filename
  - email_recipients: Email addresses (optional)
```

### import_cycode_findings
Imports findings from Cycode CSV export.
```
Arguments:
  - csv_content: CSV content
```

### generate_pdf_report
Generates a professional PDF report. **ALWAYS called as the final step** after markdown report generation. Two modes:

**Mode 1 — Markdown (preferred):** Pass the full markdown report via `markdown_content`. This renders an identical PDF of the complete `.md` report with professional styling.
```
Arguments:
  - markdown_content: Full markdown report text (preferred)
  - output_filename: PDF filename (optional, default: "report.pdf")
```

**Mode 2 — Database findings:** Omit `markdown_content` to build a PDF from findings in the database using the HTML template.
```
Arguments:
  - title: Report title (optional)
  - target: Assessment target name (optional)
  - include_evidence: Include evidence blocks (optional, default: true)
  - output_filename: PDF filename (optional, default: "report.pdf")
  - finding_ids: Specific finding IDs (optional, default: all findings)
```

The PDF includes:
- Styled headings, tables with dark header rows and alternating stripes
- Code/evidence blocks with monospace font
- Header ("Security Assessment Report — Confidential") and footer (page numbers)
- Print-optimized CSS with page breaks
- All sections from the markdown: TOC, executive summary, walkthrough, findings, exploitation matrix, QA review, recommendations

## Report Sections (Required)

Every report MUST include these sections in order:

1. **Table of Contents**: Clickable navigation with markdown anchors
2. **Assessment Walkthrough**: High-level step-by-step summary of actions taken
3. **Executive Summary**: Finding counts by severity, exploitability status, and the **evidence split** (see below)
4. **Targets Assessed**: Endpoints, repositories, components tested
5. **Findings Summary**: Grouped by category (SAST, Infra, Vuln Scan, Web App)
6. **Exploitation Validation**: Detailed results of exploit attempts
7. **Exploitation Summary Matrix**: Table showing each attack and result
8. **QA Review Summary**: Validation results, confidence scores, coverage gaps (if QA agent ran)
9. **Recommendations**: Prioritized by severity with defense-in-depth guidance
10. **Testing Methodology**: Tools and techniques used
11. **Compliance Mapping** (if compliance agent ran): OWASP/NIST/PCI/CWE/CVSS mapping matrix
12. **Coverage Checklist**: in-scope test matrix compliance table (scope-derived count — see team-assessment SKILL.md)
13. **Conclusion**: Overall security posture assessment
14. **Appendix** (optional): Raw tool outputs

## Executive Summary — the evidence split (MANDATORY)

The executive summary must state, separately from the severity counts, how many findings were **re-proven by an oracle** versus merely detected. Pull the numbers from `list_verdicts` — never count them by hand from prose.

```markdown
**Evidence basis:** 23 findings. **11 VERIFIED** (re-proven in code by an oracle, each with a
replay capsule), 9 **CANDIDATE** (detected, not independently re-proven), 3 **REFUTED**
(tested and did not hold). 2 findings could not be verified because no out-of-band listener
is configured for this deployment — a coverage gap, not a clean result.
```

Rules:

1. **The headline count is the verified count.** If the report opens with "we found 23 vulnerabilities", the very next clause says how many were proven. A reader who takes only one number away should take the honest one.
2. **Never present a candidate as confirmed.** No "confirmed", "demonstrated", "proven", or "successfully exploited" about a finding whose verdict is `candidate`. The correct phrasing is "detected but not independently re-proven".
3. **Refuted findings still appear**, in their own subsection, with the reason. A finding we tested and could not reproduce is information the reader is entitled to — it is also what makes the verified count credible.
4. **Findings that were never live-testable** (SAST-only, no deployed endpoint) are neither verified nor refuted. Group them as "not live-testable" and say why. Do not let them dilute either number.
5. **State coverage gaps explicitly.** If `oast` was unavailable, or the verifier could not reach a target, say so. Silence reads as "everything was checked".

This section exists because severity alone has never told the reader how much to trust a finding. See `docs/oracle-verification-layer.md`.

## Table of Contents Format
```markdown
## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Assessment Walkthrough](#assessment-walkthrough)
3. [Targets Assessed](#targets-assessed)
4. [Findings Summary](#findings-summary)
5. [Exploitation Validation Results](#exploitation-validation-results)
6. [Exploitation Summary Matrix](#exploitation-summary-matrix)
7. [QA Review Summary](#qa-review-summary) *(if QA agent ran)*
8. [Recommendations by Priority](#recommendations-by-priority)
9. [Testing Methodology](#testing-methodology)
10. [Conclusion](#conclusion)
```

## Assessment Walkthrough Format
Document each phase with a table showing Step, Action, and Outcome:

```markdown
## Assessment Walkthrough

### Phase 1: Setup & Configuration
| Step | Action | Outcome |
|------|--------|---------|
| 1.1 | Added target to scope.yml | Domain authorized |
| 1.2 | Configured credentials | Auth ready |

### Phase 2: Static Code Analysis
| Step | Action | Outcome |
|------|--------|---------|
| 2.1 | Ran Semgrep | X findings |

### Phase 3: Reconnaissance
...

### Phase 4: Vulnerability Scanning
...

### Phase 5: Web Application Testing
...

### Phase 6: Exploitation Validation
| Step | Action | Outcome |
|------|--------|---------|
| 6.1 | CSRF attack attempt | Blocked by CORS |
| 6.2 | SQLi testing | Parameterized queries |
...

### Phase 7: Report Generation
...
```

## Exploitation Summary Matrix Format
Always include a matrix showing exploitability:

```markdown
## Exploitation Summary Matrix

| Vulnerability | Exploitable | Evidence |
|--------------|-------------|----------|
| CSRF | NO | CORS blocks requests |
| SQLi | NO | Parameterized queries |
| JWT attacks | NO | Strong secret |
| Redis FLUSHALL | YES — DESTRUCTIVE (withheld) | Auth bypass confirmed; the FLUSHALL proof-of-concept was withheld for safety |
```

A finding marked **EXPLOITED (DESTRUCTIVE — WITHHELD)** is a confirmed-exploitable finding (the target raised no defense — we self-limited), so it renders as `YES — DESTRUCTIVE (withheld)` in the Exploitable column, never `NO` and never `PARTIAL`. Its Evidence cell must name the exact destructive payload that was withheld and the non-destructive confirmation that proves the vuln is real. In a finding's metadata table, render it as `| **Exploitable** | TRUE — DESTRUCTIVE PoC withheld for safety |`.

## Finding Deduplication Summary

When multiple agents discover the same vulnerability, include a deduplication summary:

```markdown
## Finding Deduplication Summary

| # | Finding Title | Discovered By | Times Reported | Merged Evidence Sources |
|---|--------------|---------------|----------------|------------------------|
| 1 | [Title] | agent1, agent2 | 2 | [source1, source2] |

**Deduplication Stats:**
- Total raw findings: [N]
- After deduplication: [M]
- Duplicates merged: [N - M]
```

## QA Review Section Format
If the QA agent ran before report generation, include this section showing validation results:

```markdown
## QA Review Summary

### Validation Statistics
| Metric | Count |
|--------|-------|
| Findings Reviewed | 15 |
| Confirmed | 12 |
| False Positives | 2 |
| Inconclusive | 1 |
| Overall Confidence | 7.5/10 |

### Confidence Scores by Finding
| Finding | Severity | Confidence | Status |
|---------|----------|------------|--------|
| SQL Injection in /api/users | High | 9/10 | Confirmed |
| XSS in search form | Medium | 7/10 | Confirmed |
| Outdated jQuery | Low | 3/10 | False Positive |

### False Positives Identified
| Finding | Reason |
|---------|--------|
| Outdated jQuery | Version mismatch - CDN serves updated version |
| CSRF on login | Login form intentionally exempt from CSRF protection |

### Coverage Gaps
| Area | Priority | Recommendation |
|------|----------|----------------|
| Authentication bypass | High | Test SSO/SAML integration |
| Rate limiting | Medium | Test API rate limits |
| Business logic | Low | Review checkout workflow |

### Coverage Score: 75%
```

### When to Include QA Review
- **Include** if `context.qaReview` is present
- **Include** confidence scores in findings if `finding.metadata.qaConfidence` is set
- **Exclude false positives** marked with `finding.metadata.qaFalsePositive = true` from main findings list
- **Note** unvalidated findings (no `qaValidated` flag) as "Not QA validated"

### Confidence Score Interpretation
| Score | Interpretation |
|-------|----------------|
| 9-10 | High confidence - Exploit confirmed, strong evidence |
| 7-8 | Good confidence - Re-test confirmed the finding |
| 5-6 | Moderate confidence - Reasonable evidence |
| 3-4 | Low confidence - Weak evidence, possible FP |
| 1-2 | Very low - Likely false positive |

## Detailed Methodology Section (Required)

Every report MUST include a comprehensive methodology section documenting HOW and WHY each phase was conducted. This demonstrates thoroughness and provides audit trail.

### Structure for Each Phase

```markdown
### [Phase Name] Methodology

**Objective:** [What we aimed to achieve]

#### Why [Phase Name] Matters
[2-3 sentences explaining the importance of this phase]

#### Tools Selected & Rationale

| Tool | Purpose | Why Selected |
|------|---------|--------------|
| **toolname** | What it does | Why we chose it over alternatives |

#### Techniques Applied

1. **Technique Name**
   - What we did
   - Why we did it
   - What we found

#### [Phase] Findings Summary
[Quick summary of results from this phase]
```

### Required Methodology Sections

1. **Reconnaissance Methodology**
   - Tools: nmap, curl, DNS tools
   - Document: port scanning approach, service fingerprinting, header analysis
   - Explain: why mapping attack surface matters

2. **Static Code Analysis (SAST) Methodology**
   - Tools: Semgrep, Bandit, language-specific scanners
   - Document: which rules/rulesets used, what patterns checked
   - Explain: why catching issues in code before runtime matters

3. **Vulnerability Scanning Methodology**
   - Tools: Nuclei, Nikto, specialized scanners
   - Document: which templates/checks run, severity levels targeted
   - Explain: why automated scanning provides broad coverage

4. **Web Application Testing Methodology**
   - Tools: Manual testing, sqlmap, custom scripts
   - Document: injection tests, auth testing, authorization checks
   - Explain: why manual testing finds logic flaws scanners miss

5. **Exploitation Validation Methodology**
   - Document: each exploit attempt and result
   - Explain: difference between theoretical vs. practical exploitability
   - Note: browser vs. tool differences (CORS, etc.)

### Example Tool Rationale

| Tool | Good Rationale |
|------|----------------|
| nmap | "Industry standard for service detection; `-sV` provides version info needed for CVE matching" |
| Semgrep | "Pattern-based SAST with low false-positive rate; supports custom rules for org-specific patterns" |
| Nuclei | "Community-maintained templates covering latest CVEs; JSON output integrates with our pipeline" |
| Bandit | "Python-specific scanner understands language idioms; catches Python security anti-patterns" |

## Team Assessment Data Reception

When running as the `compliance-report` agent in a team-based assessment (see `skills/team-assessment/SKILL.md`), the report agent receives data through two channels:

### Channel 1: MCP Database (Findings)
All findings from all agents are stored in the shared SQLite DB via `create_finding`. Use `generate_report` to read all findings from the DB. This is the authoritative source for vulnerability data.

### Channel 2: Team Lead Message (Test Coverage + Metadata)
The team lead sends a structured message containing:
- **Complete test results** for every in-scope test (test_id, status, notes, agent that ran it) plus `{IN_SCOPE_TEST_IDS}` / `{IN_SCOPE_TEST_COUNT}`
- **QA validation results** (confidence scores, false positives, coverage gaps)
- **Assessment metadata** (target, date, assessor, repo paths)
- **Agent attribution map** (which agent ran which tests)

### Agent Attribution Requirement
Team-based assessment reports MUST include an **Agent Attribution Table** showing:

| Agent | Tests Assigned | Tests Completed | Findings Created | Status |
|-------|---------------|-----------------|-----------------|--------|
| team-lead | AUTH-01 to AUTH-08 | 8/8 | 2 | Completed |
| recon-infra | RECON-01 to TLS-04 | 10/10 | 3 | Completed |
| sast | SAST-01 to SAST-SC-04 | 24/24 | 12 | Completed |
| web-security | AUTHZ-01 to CLI-06 | 28/28 | 5 | Completed |
| api-graphql | GQL-01 to DESER-01 | 27/27 | 8 | Completed |
| crossval-qa | XVAL-01 to XVAL-11 | 11/11 | 2 | Completed |

This table appears in the Assessment Walkthrough section and provides traceability for every test.

## Workflow Pattern
1. Collect findings from all agents (MCP DB for team mode, or direct context)
2. Deduplicate (same vuln, different scanners)
3. Sort by severity (critical first)
4. **Read `config/test-matrix.yml`** and generate coverage checklist
5. Generate report in requested format (markdown/HTML/JSON)
6. **Generate PDF report** (ALWAYS — automatic final step)
7. Create Jira tickets for high/critical
8. Upload to SharePoint
9. Email to stakeholders

## Jira Integration
Severity to Priority mapping:
- Critical → Highest
- High → High
- Medium → Medium
- Low → Low
- Info → Lowest

## Best Practices

### Report Structure
- **Always include Table of Contents** for navigability
- **Always include Assessment Walkthrough** showing step-by-step actions
- Always deduplicate before reporting
- Include evidence for all exploited findings
- Link Jira tickets back to findings
- Use consistent naming conventions
- Archive reports with timestamps

### Finding Detail Standards — ALL SEVERITIES

**CRITICAL RULE:** Every single finding in the report — Critical, High, Medium, Low, and Informational — MUST have the same comprehensive level of detail. There are NO abbreviated findings. Treat a Low cookie flag finding with the same rigor as a Critical PII exfiltration finding.

**Every finding MUST include:**

1. **Metadata table** (see exact format below) — Severity, Exploitable, CWE, OWASP, Target, Source
2. **Description** — What it is, why it matters, what's affected
3. **Exact locations** — File paths with line numbers, commit hashes, URLs, endpoints
4. **Reproduction steps WITH REAL EVIDENCE** — Numbered steps showing the ACTUAL commands run and ACTUAL responses received during the assessment. Every step that involves an HTTP request must show both the real request and the real response body. No placeholders (`$TOKEN`, `<PASSWORD>`, `{BEARER}`). No comments like `# Returns HTTP 200`. Show the real data.
5. **Actual response data** — The real HTTP response body, status code, and relevant headers proving the vulnerability exists. This is the PROOF — without it the finding is an unsubstantiated claim.
6. **Exploitation scenario** — How an attacker uses this, what they gain, how it chains with other findings
7. **Remediation** — Specific, actionable fix with code examples where applicable

**REAL EVIDENCE RULE (NON-NEGOTIABLE):**

This is a confidential internal report. Every reproduction step must contain the actual attack as performed — real tokens, real passwords, real response bodies. The report is PROOF, not a tutorial.

- Show the actual bearer token used: `Authorization: Bearer eyJhbGciOiJIUzI1NiIs...`
- Show the actual response body: `{"id":1,"email":"admin@groovysec.com","role":"admin"}`
- Show actual secret values found: `AKIAIOSFODNN7EXAMPLE`
- Show actual PII from responses: real names, emails, SSNs if returned

**NEVER:**
- Use `$TOKEN`, `<TOKEN>`, `{AUTH}`, `$PASSWORD` or any variable/placeholder
- Write `# Returns HTTP 200 with user data` — show the actual response
- Write `# STILL returns full user data — token not invalidated` — show what was returned
- Describe what a response contains — paste it
- Write generic steps that read like documentation instead of evidence

**MANDATORY Finding Metadata Table Format** (use this exact layout — NEVER use "Status: OPEN"):

```markdown
| Attribute | Value |
|-----------|-------|
| **Severity** | **HIGH** |
| **Exploitable** | TRUE — API key accepted by AWS STS |
| **Verdict** | **VERIFIED** — `credential_use` oracle, 2/2 replays |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **OWASP** | A07:2021 — Identification and Authentication Failures |
| **Target** | `backend/.env` in ai-governance-platform repository |
| **Source** | gitleaks |
```

**Verdict field — exactly three values** (auto-styled in PDF, migration 0049):

- `**VERIFIED**` — an oracle re-proved this finding in code. Name the `oracle_kind` and the replay count. Only a VERIFIED finding may be described as proven, confirmed, or demonstrated.
- `**CANDIDATE**` — detected but never independently re-proven. Say so in the finding text: *"detected but not independently re-proven — reported as an unverified candidate."* Never write "confirmed" about a candidate.
- `**REFUTED**` — an oracle tested it and it did not hold. State the reason from the receipt.

The verdict is **not** the same axis as severity: severity is how bad it would be, the verdict is how sure we are. Render both. A CRITICAL CANDIDATE and a CRITICAL VERIFIED are very different things to the reader, and collapsing them is precisely what this column exists to prevent.

Pull all of it from `reports/verifier-results.json` and the finding's `verdict` / `oracle_kind` / `replay_successes` / `replay_n` fields. **Never infer a verdict** — if the field is absent the finding is a `CANDIDATE`.

### Replay Capsule (VERIFIED findings only)

Every VERIFIED finding carries a `capsule_json` — the exact recipe the oracle ran. Render it after the reproduction steps so the reader can re-run the proof themselves:

```markdown
**Replay capsule** — re-run this proof yourself:

    Oracle:   differential (2/2 replays)
    Verified: 2026-07-28T14:02:11Z

    # authorized context — the owner sees their own record
    curl -s -H "Authorization: Bearer eyJhbG...owner" https://staging.example.com/api/orders/8821

    # attacker context — a different user's token, same object
    curl -s -H "Authorization: Bearer eyJhbG...attacker" https://staging.example.com/api/orders/8821

    # control — no credentials at all (must NOT return the marker)
    curl -s https://staging.example.com/api/orders/8821

    Marker: "victim-4821@example.com"
```

This capsule is the human-attestation artifact. It is what the signer runs before putting their name on the report, and what CI replays to detect a finding that has been fixed or has gone flaky. Use the **real** commands and tokens from the receipt — the no-placeholders rule applies here more than anywhere else in the report.

**Exploitable field — exactly three values** (auto-styled in PDF):
- `TRUE` — We tested it and confirmed exploitation works. Include brief proof after the keyword.
- `FALSE` — We tested it and exploitation failed due to defenses. Include what blocked it.
- `POTENTIALLY` — Code/config finding (secrets, SAST, dependencies) that can't be live-tested. The vulnerability exists in code but runtime exploitability depends on deployment context.

**NEVER use "Status: OPEN"** — this is a penetration test report, not a bug tracker. Every finding must state whether it's exploitable.

**SAST findings additionally require:**
- Table of every affected file path (not just a count)
- Commit hash and author for git history findings
- Current code vs git history status (is it still in HEAD?)
- Actual secret values (this is an internal report — never redact)
- Git commands to retrieve the evidence: `git show <commit>:<file>`

**Dependency findings additionally require:**
- Table of every vulnerable package with severity and advisory links
- Dependency chain (which parent package pulls it in)
- At least one exploitation scenario specific to THIS codebase

**CI/CD findings additionally require:**
- Specific workflow files with line numbers and trigger events
- At least 2 concrete attack scenarios with exact payloads
- The actual vulnerable YAML code
- Any hardcoded tokens found in workflows (with values)
- Workflow permissions (write access, admin bypass, etc.)

**Complete Enumeration Rule (ALL Means ALL):**

If a scan produces N results, ALL N results must appear individually in the report. No partial listings.
- 65 AWS tokens → list ALL 65 in a table (key ID, file, commit, author, date)
- 14 private keys → list ALL 14 with specific commit hashes
- 11 injection points → list ALL 11 with file:line and vulnerable expression
- 50 rate-limit tests → show sample response body as evidence

**Banned Vague Language — NEVER use these without immediate specifics:**
- "various" → list every item explicitly
- "multiple" → state exact count and list them
- "several" → state exact count and list them
- "some" → state exact count and list them
- "others" / "etc." / "and more" → list every remaining item
- "in git history" without a commit hash → must include specific commit (e.g., "commit `6e833f51`")
- "N instances found" without listing → must list all N instances in a table

**Evidence Requirements for Claims:**
- "All 50 returned 200" → show a sample HTTP response (status + headers + body)
- "No rate limiting" → show absence of `X-RateLimit-*` headers in a response
- "Schema reconstructed" → show the reconstructed schema
- "Key is still in current code" → show `ls -la` or `cat` excerpt

**Anti-patterns — NEVER do these:**
- One-liner findings: `"_dd_s cookie lacks Secure and HttpOnly flags"` → MUST be a full finding with reproduction steps
- Vague counts: `"28 AWS tokens found"` → MUST list specific key IDs, files, and commits
- Missing locations: `"Private keys found in git history"` → MUST list every file path and commit
- No exploitation: `"Missing CSP header"` → MUST show an XSS attack scenario that CSP would block
- Partial listings: `"7 of 65 tokens shown"` → MUST show all 65
- Summarized commits: `"various commits"` → MUST list every commit hash

### Exploitation Validation
- **Test every finding** for real-world exploitability
- **Document both successful AND failed exploits** - shows thoroughness
- **Consider browser vs tool differences** (curl ignores CORS, browsers don't)
- **Downgrade findings** if exploitation is blocked by other controls
- Include proof-of-concept code for exploitable findings

### Walkthrough Best Practices
- Number steps hierarchically (1.1, 1.2, 2.1, etc.)
- Use tables with Step | Action | Outcome columns
- Group by assessment phase
- Highlight key outcomes (**bold** for important results)
- Include both positive and negative findings

### Internal Report Disclosure Policy
- Reports are internal-only — always show real data
- Show actual secret values (AWS key IDs, GitHub PAT prefixes, DB passwords)
- Show actual PII from exploitation evidence (SSNs, emails, names)
- Show actual file paths, commit hashes, and GitHub links
- Show actual IP addresses and infrastructure details
- Never redact or mask internal data — the audience has full access

### Defense-in-Depth Recommendations
- Note when findings are mitigated by other controls
- Recommend SSO/IdP for authentication concerns
- Distinguish between "exploitable now" vs "could become exploitable"
- Prioritize recommendations: Immediate > Short-term > Best Practice

### Distribution
- Send notifications for critical findings immediately
- Include executive summary for leadership
- Provide technical details for engineering teams

## Source Code Context & Remediation

When an assessment includes `repo_paths`, the orchestrator runs a **code context enricher** between QA and Report. This attaches source code references and generated fixes to findings.

### What Gets Enriched

**Tier 1 — Code Context (all findings with file_path):**
- Source code snippet at the vulnerability location
- File:line reference (e.g., `auth.ts:42`)
- Detected language
- Available as `finding.metadata.codeContext`, `.codeContextFile`, `.codeContextLanguage`

**Tier 2 — Code Remediation (ALL SAST findings, any severity):**
- Before/after code fix using the ACTUAL code from the repo (retrieved via `analyze_code_context`), not generic examples
- Fix MUST use the same frameworks/libraries already in the codebase (e.g., if the repo uses SQLAlchemy, show a SQLAlchemy fix — never suggest a different ORM)
- Explanation of why the fix works, referencing the specific mechanism
- Available as `finding.metadata.remediationCode`, `.remediationExplanation`
- **Every SAST finding gets the 5-part structure**: exact location, vulnerable code, why it's vulnerable, fixed code, fix explanation — regardless of severity

**CRITICAL:** Code remediation must be copy-pasteable. A developer should be able to take the "after" code block and drop it into the exact file:line referenced. Never show generic OWASP examples or suggest frameworks the codebase doesn't use.

### Rendering in Reports

When `metadata.codeContextVerified = true`:
- Show the source file:line reference in the finding header
- Include the code snippet in the evidence section

When `metadata.remediationVerified = true`:
- Include a "Code Remediation" subsection with:
  - **Vulnerable Code** block (before)
  - **Remediation Code** block (after, green-tinted)
  - **Why** explanation

### Example Report Section

```markdown
### SQL Injection in User API

**File:** `api/routes/users.ts:42`
**Severity:** HIGH

#### Vulnerable Code
\`\`\`typescript
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
\`\`\`

#### Remediation Code
\`\`\`typescript
const query = `SELECT * FROM users WHERE id = ?`;
const result = await db.query(query, [req.params.id]);
\`\`\`

**Why:** Parameterized queries prevent SQL injection by separating data from SQL logic.
```

### When Source Code Is Not Available

When `repo_paths` is not provided, the enricher is skipped entirely.
Findings are documented normally without code references — this is graceful degradation.

## SAST Companion Report

Full assessments that include static code analysis (SAST) produce **two reports**:

1. **Main Assessment Report** — the standard deliverable covering all phases (recon, DAST, SAST, chains, compliance, etc.). SAST findings that were cross-validated or relate to DAST findings appear as normal findings with a cross-reference: *"Full code analysis details in SAST Companion Report, Section X."*

2. **SAST Companion Report** — a **standalone comprehensive code security audit**. This contains ALL code-level findings from static analysis — not just the ones referenced in the main report. Every vulnerability the SAST tools found goes here, whether or not it was validated against a live endpoint.

### Why Two Reports

SAST output can be massive (286 secrets, 135 entry points, data flow maps, defense coverage matrices). Including every file path, commit hash, and code snippet inline in the main report buries the DAST/exploitation narrative. Splitting them:
- Keeps the main report readable and action-oriented for leadership
- Gives engineering teams a **complete code security audit** they can act on independently
- Captures findings that can't be live-validated (dead code paths, unused endpoints, internal-only functions) but still represent real risk
- Allows the SAST report to be updated independently (e.g., after remediation)

### SAST Report is a FULL Audit, Not Just Cross-References

**CRITICAL:** The SAST companion report is NOT limited to findings that appear in the main assessment report. It is a comprehensive code security audit that includes:

- **ALL findings from every SAST scanner** (Semgrep, gitleaks, Bandit, njsscan, dependency scanners, IaC scanners)
- **Findings that have no live endpoint** — code vulnerabilities in internal functions, dead routes, unused handlers
- **Findings that couldn't be cross-validated** — the code pattern exists but the endpoint wasn't reachable or wasn't deployed
- **Defense gap analysis** — routes missing auth middleware, unparameterized queries, missing output encoding — even if no exploit was attempted
- **Informational code quality issues** — deprecated patterns, unsafe defaults, missing security headers in code
- **Supply chain risks** — every vulnerable dependency, even transitive ones with no known exploit path in this codebase

The main report says "here's what we proved is exploitable." The SAST report says "here's everything we found in the code, exploitable or not." Together they give the full picture.

### Main Report — SAST Finding Format

SAST findings in the main report use the standard finding format but add a companion reference:

```markdown
### FINDING 5: Secrets Exposed in Git History

| Attribute | Value |
|-----------|-------|
| **Severity** | **CRITICAL** |
| **Exploitable** | POTENTIALLY |
| **CWE** | CWE-798 |
| **Source** | gitleaks |

**Description:** Gitleaks detected 286 secrets in git history including API keys for OpenAI, Anthropic, GCP, and AWS. 14 are in non-test files requiring immediate rotation.

**Summary:** 286 total secrets (203 generic-api-key, 19 github-pat, 17 jwt, 14 stripe, 12 private-key, 6 slack-bot, 3 gcp, 2 shopify, 2 square, 2 curl-auth, 1 aws, 1 k8s-secret, 1 slack-webhook, 1 gitlab-pat, 1 anthropic, 1 openai).

**Reproduction:** `cd /path/to/repo && gitleaks detect --report-format json`

**Remediation:** Rotate all exposed credentials immediately. Add `.gitleaks.toml` baseline. Enable pre-commit hooks.

> **Full Details:** Complete file-by-file listing of all 286 secrets with commit hashes, authors, dates, and current-vs-history status available in **SAST Companion Report, Finding SAST-02/SAST-10**.
```

### SAST Companion Report — Structure

The SAST companion report follows this structure:

```markdown
# SAST Companion Report — [Target Name]
# Comprehensive Code Security Audit
**Assessment Date:** YYYY-MM-DD
**Repository:** /path/to/repo
**Main Assessment Report:** groovysec-assessment-YYYY-MM-DD.pdf

## Table of Contents

### Part 1: Executive Summary
1. Code Security Posture Overview
2. Finding Severity Breakdown (with counts)
3. Scanner Coverage Summary (which tools ran, what they found)

### Part 2: Findings (ALL findings, grouped by category)
4. Secrets & Credentials (SAST-02, SAST-10)
5. OWASP Top 10 Code Patterns (SAST-01)
6. Injection Vulnerabilities (SQLi, XSS, RCE, SSRF, etc.)
7. Authentication & Authorization Code Gaps
8. Security Misconfigurations in Code
9. Dangerous Functions & Unsafe Patterns (SAST-09)
10. Language-Specific Issues (SAST-08)
11. IaC Security Issues (SAST-06)

### Part 3: Architecture Analysis
12. Entry Points & Attack Surface (SAST-04)
13. Data Flow Analysis (SAST-DF-01 to DF-05)
14. Defense Coverage Matrix (SAST-DEF-01 to DEF-05)

### Part 4: Supply Chain
15. Dependency Vulnerabilities (SAST-03, SC-01 to SC-04)
16. License Compliance (SC-03)
17. Dependency Confusion Risk (SC-04)

### Part 5: Cross-References
18. Findings Validated in Main Assessment (cross-ref table)
19. Findings NOT in Main Report (code-only issues)
20. Remediation Priority Matrix
```

### SAST Cross-References in Main Report

When the main report references SAST findings, use this format:

- **Reference format**: `**SAST Companion Report, Finding SAST-XX**` (always use the SAST finding number)
- **Main report scope**: Include a summary of the top 3-5 SAST findings with severity, affected component, and impact. Point to the companion for full file listings, commit hashes, and code remediation.
- **Division of responsibility**: The main report covers the vulnerability and its impact on the live application. The SAST companion report covers the code, every affected file path, every commit hash, and the concrete fix.
- **Cross-reference table**: Include in the appendix:

```markdown
| Main Report Finding | SAST Companion Finding | Relationship |
|--------------------|-----------------------|-------------|
| FINDING 3: Secrets in Git History | SAST-02, SAST-10 | Full secret listing in companion |
| FINDING 7: Missing CSRF Protection | SAST-05, SAST-DEF-03 | Defense gap analysis in companion |
```

### SAST Companion — Required Detail Level

This is where the "ALL means ALL" and "banned vague language" rules apply at full force:

- **Secrets:** Every single secret in a table with columns: #, Secret Type, File Path, Line, Commit Hash, Author, Date, Status (CURRENT / HISTORY ONLY)
- **Entry Points:** Full route table with HTTP method, path, auth required, parameters, handler file:line
- **Data Flows:** Source → sink traces for each flow type (SQLi, XSS, RCE, SSRF, path traversal) with file paths and line numbers
- **Defense Gaps:** Matrix showing which routes have/lack each defense (auth, input validation, CSRF, output encoding, SQL parameterization)
- **Dependencies:** Every vulnerable package with CVE, severity, advisory link, parent dependency chain
- **Code Snippets:** ACTUAL vulnerable code from the repo (retrieved via `analyze_code_context`), with concrete before/after remediation using the same frameworks the codebase already uses. Never show generic OWASP examples or suggest frameworks not in the project's dependency files.
- **Unvalidated Findings:** Findings that couldn't be confirmed against live endpoints still get full detail — file path, line number, code snippet, vulnerability explanation, remediation. Mark them as `Exploitable: POTENTIALLY` and include a **"Live Validation Attempted"** section documenting what was tried to find the issue in the running application, what the result was, and why it couldn't be confirmed (e.g., "Tested all error endpoints for config leakage — not exposed; internal config only")

### SAST Companion — Every Finding Gets Full Treatment

**Even findings NOT referenced in the main report** get the same detail level, PLUS a "Live Validation Attempted" section showing what was tried:

```markdown
### FINDING SAST-42: Hardcoded Database Connection String

| Attribute | Value |
|-----------|-------|
| **Severity** | **HIGH** |
| **Exploitable** | POTENTIALLY — internal config, not exposed via API |
| **CWE** | CWE-798 |
| **Scanner** | Semgrep |
| **File** | `backend/app/core/config.py:15` |
| **In Main Report** | No — could not be validated against the live application |

**Code:**
```python
# backend/app/core/config.py:15
DATABASE_URL = "postgresql://admin:Pr0dP@ss!@db.internal:5432/govplatform"
```

**Why This Matters:** Even though this string isn't exposed via the API, if an attacker gains read access to the repository (via the git history secrets in SAST-02), they obtain direct database credentials.

**Live Validation Attempted:**
We attempted to identify this finding in the running application:
1. Searched all API responses for database connection string leakage — not found in any endpoint response
2. Tested error handling by sending malformed requests to `/api/models`, `/api/assessments`, `/api/users` — application returns generic 422/500 errors without exposing connection details
3. Checked `/docs`, `/openapi.json`, and common debug endpoints — no database configuration exposed
4. **Result:** The hardcoded credential exists in source code but is not exposed through the live application's HTTP interface. However, it remains a risk if the repository is compromised or if a future code change introduces an error path that leaks configuration.

**Remediation:** Move to environment variable: `DATABASE_URL = os.environ["DATABASE_URL"]`
```

### SAST Companion — Cross-References

Section 18 links findings that were validated in the main assessment report:

```markdown
## Findings Validated in Main Assessment

| SAST Finding | Main Report Finding | Cross-Validation Result |
|-------------|-------------------|----------------------|
| SAST-02: 286 secrets in git | FINDING 1: API Keys in Git History | XVAL-11: No secrets exposed in live env |
| SAST-05: CSRF gap | FINDING 8: Missing CSRF | XVAL-04: Confirmed missing HSTS |
| SAST-07: Template XSS | FINDING 10: Template var-in-href | XVAL-01: Endpoints not deployed |
```

Section 19 lists findings that exist ONLY in code and were not validated live. For each one, document **what was tried** to find it in the running application:

```markdown
## Findings NOT in Main Report (Code-Only Issues)

These findings represent real code vulnerabilities that we attempted to validate against
the live application but could not confirm. For each finding, we document what validation
was attempted and why it could not be confirmed — showing that the work was done, not
that the finding was ignored.

| # | Finding | Severity | File | Validation Attempted | Why Not Confirmed |
|---|---------|----------|------|---------------------|-------------------|
| 1 | Hardcoded DB connection string | HIGH | config.py:15 | Tested all API error responses and debug endpoints for config leakage | Connection string not exposed in any HTTP response; internal config only |
| 2 | Unsafe deserialization in worker | CRITICAL | worker/task.py:89 | Attempted to reach task worker via API queue endpoints; sent crafted payloads to /api/tasks | Worker runs async, no direct HTTP path; queue input not controllable via API |
| 3 | Path traversal in file handler | HIGH | utils/files.py:34 | Searched all routes for file parameter handling; tested /api/files, /api/uploads with traversal payloads | Handler exists in code but is not mapped to any active route in the application |
```

### File Naming Convention

```
reports/
  groovysec-assessment-2026-03-06.md       # Main assessment report
  groovysec-assessment-2026-03-06.pdf      # Main assessment PDF
  groovysec-sast-2026-03-06.md             # SAST companion report
  groovysec-sast-2026-03-06.pdf            # SAST companion PDF
```

### When to Generate

- **Always** when the assessment includes `repo_paths` and the sast agent runs
- The sast agent generates the SAST companion report as its final step
- The compliance-report agent references the SAST companion report in the main report

## Cloud Companion Report

Assessments that include cloud scope (`cloud_accounts` defined in `config/scope.yml`) produce a **third report**, built in the same style as the SAST companion:

1. **Main Assessment Report** — cloud findings that were exploited or relate to the live attack narrative appear as normal findings with a cross-reference: *"Full cloud posture details in Cloud Companion Report, Section X."*

2. **SAST Companion Report** — the standalone code audit (above).

3. **Cloud Companion Report** — a **standalone comprehensive cloud security audit**. It contains ALL cloud findings from CLOUD-01 → CLOUD-29 — every IAM gap, every exposed bucket, every escalation path — whether or not it was exploited against the live account.

This report is written by the **cloud-analysis** agent (Phase 4.8), which is **analysis-only**: it synthesizes from the cloud-recon and cloud-exploit checkpoints and never re-touches the cloud.

### Why a Separate Cloud Report

A real cloud run produces as much output as a SAST run — ScoutSuite's full inventory, Prowler's 100+ checks, a complete IAM authorization-details dump, every security group rule, every escalation path. Folding all of it inline buries the main report's exploitation narrative. Splitting it:
- Keeps the main report readable and action-oriented
- Gives the cloud/platform team a **complete posture audit** they can act on independently
- Captures findings that were **detected but not exploited** — the key value when the assessment runs read-only by design (see the escalation graph below)

### Cloud Report is a FULL Audit, Not Just Cross-References

**CRITICAL:** The Cloud Companion Report is NOT limited to findings exploited in the main report. It includes:

- **ALL findings from cloud-recon and cloud-exploit** (every CLOUD-01 → CLOUD-29 result)
- **Detected-but-not-exploited findings** — escalation paths PMapper found from the IAM graph that were not walked because the run was read-only, plus actions gated behind user confirmation
- **Posture findings with no exploit** — missing encryption, missing CloudTrail coverage, missing alerting — even where no attack was attempted
- **Every misconfiguration** — every public bucket, every SG open to `0.0.0.0/0`, every over-permissive policy

The main report says "here's what we proved." The cloud report says "here's everything the cloud exposes, exploited or not."

### Cloud Companion Report — Structure

```markdown
# Cloud Infrastructure Security Companion Report — [Target Name]
# Comprehensive Cloud Posture & Exploitation Audit
**Assessment Date:** YYYY-MM-DD
**Cloud Accounts:** <account/subscription/project IDs assessed>
**Assessed Identity:** <the principal the run executed as, and its access level>
**Main Assessment Report:** groovysec-assessment-YYYY-MM-DD.pdf

## Table of Contents

### Part 1: Executive Summary
1. Cloud Posture Overview (providers, accounts, identity assessed)
2. Finding Severity Breakdown (original + calibrated counts)
3. Blast-Radius Summary (what the assessed identity could reach)
4. Tool Coverage (ScoutSuite, Prowler, PMapper, Pacu, kube-hunter, trivy, ...)

### Part 2: Findings (ALL findings, grouped by domain)
5. IAM & Identity (CLOUD-05, 08, 09, 10)
6. Privilege Escalation Paths (CLOUD-06, 07)  ← headline
7. Storage Exposure (CLOUD-11, 12, 15)
8. Secrets Exposure (CLOUD-14)
9. Network Exposure (CLOUD-03, 04, 20)
10. Compute & Serverless (CLOUD-16, 17, 18, 19)
11. Kubernetes (CLOUD-21, 22, 23, 24, 25, 26)
12. Encryption & Detection Posture (CLOUD-13, 27, 28, 29)

### Part 3: Identity & Escalation Graph (the read-only centerpiece)
13. Assessed Identity & Granted Permissions
14. Escalation Paths (EXPLOITED / DETECTED-ONLY / GATED)
15. Cross-Account Trust Map

### Part 4: Cloud Attack Chains
16. Validated Chains (CHAIN-31 → CHAIN-40, with real evidence per step)
17. Defense-in-Depth Analysis (what stopped a chain)

### Part 5: Cross-References
18. Cloud Findings Validated in Main Assessment (cross-ref table)
19. Findings Detected-Only / Not Executed (read-only posture or gated) — with why
20. Remediation Priority Matrix
```

### Identity & Escalation Graph — The Centerpiece

Part 3 is the reason this report exists. It answers: *"We ran this with read-only credentials — could a finding let it rewrite its own permissions into write or admin?"*

PMapper computes escalation paths **statically from the IAM graph** — it detects them without executing them. So a fully read-only run still surfaces every escalation route; read-only only prevents *proving* a route by assuming the role, never *finding* it. The Escalation Paths table uses three status values:

- **EXPLOITED** — the path was walked; show `aws sts get-caller-identity` before and after, plus the real commands.
- **DETECTED-ONLY (read-only posture)** — detected from the IAM graph but not walked because the run was non-mutating by design. **Just as important as EXPLOITED** — it means a read-only identity has a route to escalate. This is the cloud analog of the SAST "Live Validation Attempted" status.
- **GATED** — requires an action behind the `request_user_guidance` gate (snapshot copy, bucket write, container escape) that was declined or not attempted.

```markdown
| # | Starting Identity | Mechanism | Target Identity | Resulting Privilege | Status |
|---|-------------------|-----------|-----------------|---------------------|--------|
| 1 | maestro-audit (read-only) | iam:PassRole + lambda:CreateFunction | LambdaAdminRole | account admin | DETECTED-ONLY (read-only posture) |
| 2 | maestro-audit (read-only) | sts:AssumeRole (over-broad trust) | DeployRole | s3:* + secrets:* | DETECTED-ONLY (read-only posture) |
```

### Cloud Cross-References in Main Report

When the main report references cloud findings, use this format:

- **Reference format**: `**Cloud Companion Report, Section X**` (or the CLOUD-XX test id)
- **Main report scope**: Include the top 3-5 cloud findings (exploited or highest-severity) with severity, affected resource, and impact. Point to the companion for the full inventory, every SG rule, and every escalation path.
- **Cross-reference table** in the appendix:

```markdown
| Main Report Finding | Cloud Companion Section | Relationship |
|--------------------|------------------------|-------------|
| FINDING 4: IAM Privilege Escalation to Admin | Part 3, Escalation Path #1 | Full escalation graph in companion |
| FINDING 9: Public S3 Bucket with PII | Part 2, Storage Exposure | All 14 public buckets listed in companion |
```

### Cloud Companion — Required Detail Level

"ALL means ALL" and banned vague language apply at full force:
- **IAM:** every over-permissive policy, stale key, MFA gap, with the actual policy JSON
- **Escalation paths:** every PMapper-detected path with the exact enabling actions, even DETECTED-ONLY ones
- **Storage:** every public bucket/blob/object in a table (name, ACL, region, sensitive data found)
- **Network:** every SG/rule open to `0.0.0.0/0` (SG id, port, CIDR, attached resource)
- **Secrets:** every secret read (name, ARN, what it grants, value preview)
- **Detection posture:** which regions/services lack CloudTrail/GuardDuty, with evidence

### File Naming Convention

```
reports/
  groovysec-assessment-2026-03-06.md       # Main assessment report
  groovysec-assessment-2026-03-06.pdf      # Main assessment PDF
  groovysec-sast-2026-03-06.md             # SAST companion report
  groovysec-sast-2026-03-06.pdf            # SAST companion PDF
  groovysec-cloud-2026-03-06.md            # Cloud companion report
  groovysec-cloud-2026-03-06.pdf           # Cloud companion PDF
```

### When to Generate

- **Only** when `cloud_accounts` is defined in `config/scope.yml` (same condition as cloud-recon/cloud-exploit)
- The cloud-analysis agent generates it in Phase 4.8 as analysis-only synthesis — it never re-scans
- The report-writer references the Cloud Companion Report in the main report; the pdf-renderer renders it as a separate PDF bound to the same `assessment_id`

## Identity Companion Report

Assessments that include identity scope (`identity_targets` defined in `config/scope.yml`) produce a standalone identity report, built in the same style as the SAST and Cloud companions:

1. **Main Assessment Report** — identity findings that were exploited or relate to the live attack narrative appear as normal findings with a cross-reference: *"Full identity posture details in Identity Companion Report, Section X."*

2. **Identity Companion Report** — a **standalone comprehensive identity security audit**. It contains ALL identity findings from IDENTITY-01 → IDENTITY-60 — every Kerberoastable SPN, every ESC-vulnerable ADCS template, every illicit-consent grant, every reachable mailbox, every privilege-escalation path — whether or not it was exploited against the live directory/tenant. It covers all in-scope identity providers: **Active Directory (IDENTITY-01–15), Entra ID (16–28), Microsoft 365 (29–34), hybrid bridges (35–40), Okta (41–50), Google Workspace (51–56), and Ping (57–60)** — each provider's tests fire only when that target is in scope.

This report is written by the **identity-analysis** agent (Phase 4.85), which is **analysis-only**: it synthesizes from the identity-recon and identity-exploit checkpoints and **never re-scans, re-sprays, re-cracks, or makes any authentication attempt** against the customer's directory/tenant — re-touching identity during a write-up step would risk an account lockout (the Lockout Mandate).

### Why a Separate Identity Report

A real identity run produces as much output as a SAST or cloud run — the full AD/Entra/M365 inventory, every BloodHound-computed attack path, every roastable account, every ADCS template, every Conditional Access gap, every OAuth grant. Folding all of it inline buries the main report's exploitation narrative. Splitting it:
- Keeps the main report readable and action-oriented
- Gives the identity/directory team a **complete posture audit** they can act on independently
- Captures escalation paths that were **detected but not walked** — the key value when a run stays read-only or is gated by the Lockout Mandate (see the escalation graph below)

### Identity Report is a FULL Audit, Not Just Cross-References

**CRITICAL:** The Identity Companion Report is NOT limited to findings exploited in the main report. It includes:

- **ALL findings from identity-recon and identity-exploit** (every IDENTITY-01 → IDENTITY-60 result, across whichever providers are in scope)
- **Detected-but-not-walked escalation paths** — paths BloodHound/certipy/roadrecon found from the directory graph that were not walked because the run was read-only, candidate-only, or gated behind user confirmation
- **Posture findings with no exploit** — stale/over-privileged roles, MFA coverage gaps, legacy-auth exposure, Conditional Access gaps — even where no attack was attempted
- **Every misconfiguration** — every ESC-vulnerable ADCS template, every over-broad OAuth grant, every Kerberoastable/AS-REP-roastable account

The main report says "here's what we proved." The identity report says "here's everything the directory/tenant exposes, exploited or not."

### Identity Companion Report — Structure

```markdown
# Identity Security Companion Report — [Target Name]
# Comprehensive Identity Posture & Exploitation Audit
**Assessment Date:** YYYY-MM-DD
**Identity Targets:** <domains / tenant IDs / Okta orgs / Google Workspace / Ping assessed>
**Assessed Identity:** <the principal(s) the run executed as, and its access level>
**Main Assessment Report:** groovysec-assessment-YYYY-MM-DD.pdf

## Table of Contents

### Part 1: Executive Summary
1. Identity Posture Overview (providers, domains/tenants, identity assessed)
2. Finding Severity Breakdown (original + calibrated counts)
3. Blast-Radius Summary (what the assessed identity could reach — DA / GA)
4. Tool Coverage (BloodHound, certipy, roadrecon, AADInternals, Okta/GWS/Ping tooling, ...)

### Part 2: Findings (ALL findings, grouped by domain)
5. Active Directory Posture (IDENTITY-01–05)
6. Privilege-Escalation Graph (IDENTITY-06–15)  ← headline
7. Entra ID Posture (IDENTITY-16–20, 37)
8. Entra Exploitation (IDENTITY-21–28)
9. M365 Data Exposure (IDENTITY-29–34, 35–36)
10. Hybrid Identity Bridges (IDENTITY-38–40)
11. Okta / Google Workspace / Ping Posture & Exploitation (IDENTITY-41–60, provider-gated)

### Part 3: Identity & Escalation Graph (the read-only centerpiece)
12. Assessed Identity & Granted Rights
13. Escalation Paths (EXPLOITED / DETECTED-ONLY / GATED)
14. Tier-0 Exposure Map

### Part 4: Identity Attack Chains
15. Validated Chains (CHAIN-41 → CHAIN-50, with real evidence per step)
16. Defense-in-Depth Analysis (what stopped a chain; on-prem → cloud bridges)

### Part 5: Cross-References
17. Identity Findings Validated in Main Assessment (cross-ref table)
18. Findings Detected-Only / Gated (read-only posture, lockout-governed, or gated) — with why
19. Lockout-Governed Tests (where a spray was capped/aborted by the Lockout Mandate)
20. Remediation Priority Matrix
```

### Identity & Escalation Graph — The Centerpiece

Part 3 is the reason this report exists. It answers: *"Could a low-priv domain user / a single Entra (or Okta/Google/Ping) token reach Domain Admin or Global Admin, and was it proven?"*

BloodHound (and certipy/roadrecon) compute escalation paths **statically from the directory graph** — they detect them without executing them. So a fully read-only run still surfaces every escalation route; read-only only prevents *proving* a route by walking it, never *finding* it. The Escalation Paths table uses three status values:

- **EXPLOITED** — the path was walked; show the real cracked hash/password, forged ticket, or `whoami /groups`-equivalent proof and the real commands.
- **DETECTED-ONLY** — detected from the directory graph but not walked because the run was read-only, candidate-only, or had no foothold. **Just as important as EXPLOITED** — it means the path exists. This is the identity analog of the cloud "DETECTED-ONLY (read-only posture)" status.
- **GATED** — requires an action behind the `request_user_guidance` gate (ACL write, ESC8 relay, consent grant, PRT, persistence, Golden SAML) that was declined or not attempted.

```markdown
| # | Starting Identity | Mechanism | Target Identity | Resulting Privilege | Status |
|---|-------------------|-----------|-----------------|---------------------|--------|
| 1 | jdoe (domain user) | Kerberoast svc-sql → crack → GenericAll on Helpdesk → DCSync | krbtgt | Domain Admin | EXPLOITED (krbtgt hash pulled) |
| 2 | jdoe (domain user) | ADCS ESC1 on VulnTemplate → PKINIT → TGT | Administrator | Domain Admin | DETECTED-ONLY (template found, not enrolled) |
| 3 | app-sp (Entra token) | illicit consent → Mail.Read → mailbox exfil | n/a | tenant mailbox read | EXPLOITED |
| 4 | DA (on-prem) | Golden SAML via AD Connect | GA | Entra Global Admin | GATED (user declined the persistence op) |
```

### Identity Cross-References in Main Report

When the main report references identity findings, use this format:

- **Reference format**: `**Identity Companion Report, Section X**` (or the IDENTITY-XX test id)
- **Main report scope**: Include the top 3-5 identity findings (exploited or highest-severity) with severity, affected identity/principal, and impact. Point to the companion for the full inventory, every roastable account, every ADCS template, and every escalation path.
- **Cross-reference table** in the appendix:

```markdown
| Main Report Finding | Identity Companion Section | Relationship |
|--------------------|---------------------------|-------------|
| FINDING 4: Domain Admin via Kerberoast → DCSync | Part 3, Escalation Path #1 | Full escalation graph in companion |
| FINDING 9: Illicit-Consent Mailbox Exfiltration | Part 2, Entra Exploitation | All 80 reachable mailboxes listed in companion |
```

### Identity Companion — Required Detail Level

"ALL means ALL" and banned vague language apply at full force:
- **Active Directory:** every Kerberoastable/AS-REP-roastable account (SPN, account, encryption type, cracked?), every ESC-vulnerable ADCS template (exact ESC id, enrollee-supplies-subject / EKU detail)
- **Escalation paths:** every BloodHound/certipy-detected path with the exact enabling mechanism, even DETECTED-ONLY ones
- **Entra/M365:** every over-privileged role, stale grant, MFA gap, Conditional Access gap, with the actual policy/grant detail; every reachable mailbox/SharePoint/OneDrive/Teams scope in a table (UPN, scope granted, what was read)
- **Okta/Google Workspace/Ping:** every misconfiguration, over-broad grant, and proven access per provider
- **Lockout-governed tests:** every spray that was capped or aborted by the Lockout Mandate (with the threshold and where it stopped)

### File Naming Convention

```
reports/
  groovysec-assessment-2026-03-06.md       # Main assessment report
  groovysec-assessment-2026-03-06.pdf      # Main assessment PDF
  groovysec-sast-2026-03-06.md             # SAST companion report
  groovysec-sast-2026-03-06.pdf            # SAST companion PDF
  groovysec-cloud-2026-03-06.md            # Cloud companion report
  groovysec-cloud-2026-03-06.pdf           # Cloud companion PDF
  groovysec-identity-2026-03-06.md         # Identity companion report
  groovysec-identity-2026-03-06.pdf        # Identity companion PDF
  groovysec-ai-2026-03-06.md               # AI companion report
  groovysec-ai-2026-03-06.pdf              # AI companion PDF
```

### When to Generate

- **Only** when `identity_targets` is defined in `config/scope.yml` (same condition as identity-recon/identity-exploit)
- The identity-analysis agent generates it in Phase 4.85 as analysis-only synthesis — it never re-scans or re-sprays
- The report-writer references the Identity Companion Report in the main report; the pdf-renderer renders it as a separate PDF bound to the same `assessment_id`

## AI Companion Report

Assessments that include AI scope (`ai_targets` defined in `config/scope.yml`) produce a standalone AI report, built in the same style as the SAST, Cloud, and Identity companions. (For an AI-focused engagement run via `/assess-ai` this **is** the primary deliverable — see `docs/ai-surface-plan.md` and `skills/ai-assessment/SKILL.md`.)

1. **Main Assessment Report** — AI findings that were exploited or relate to the live attack narrative appear as normal findings with a cross-reference: *"Full AI posture details in AI Companion Report, Section X."* Each AI finding shows its **success-rate (k/N trials)**, not a bare pass/fail.

2. **AI Companion Report** — a **standalone comprehensive AI/LLM security audit**. It contains ALL AI findings from AI-RECON-01 → AI-MCP-02 — every successful injection, every system-prompt leak, every improper-output-handling sink, every excessive-agency captured tool call, every RAG-isolation/poisoning result — whether or not it composed into the main attack narrative. Mapped to the **OWASP Top 10 for LLM Applications (2025)** + **MITRE ATLAS**.

This report is written by the **ai-analysis** agent (Phase 4.9, or the standalone `/assess-ai` tail), which is **analysis-only**: it synthesizes from the ai-recon and ai-redteam checkpoints and **never re-attacks, re-probes, or re-sends any prompt** to the customer's AI system.

### Non-Determinism — render the success-rate, not a bare verdict

AI tests are probabilistic (N trials — see `docs/ai-surface-plan.md` §8). Every AI finding MUST show: the **success-rate (k/N)**, the trial count, the pinned `temperature`, the test's `fail_threshold`, and both the original and the success-rate-calibrated severity (the AI analog of the dual-severity columns). A finding that reached a sink 1/10 is materially different from 9/10 — the report must make that visible.

### AI Report is a FULL Audit, Not Just Cross-References

**CRITICAL:** The AI Companion Report is NOT limited to findings that fed the main narrative. It includes:
- **ALL findings from ai-recon and ai-redteam** (every AI-* result across the in-scope `kind`s)
- **DETECTED-ONLY excessive-agency paths** — a tool the agent *would* call (captured, capability-not-execution) but whose real execution was withheld per the AI Safety Mandate. Just as important as a walked path.
- **Posture findings with no successful exploit** — guardrails observed, the untrusted-input surface map, the exposed-tool inventory — even where every probe held (0/N)
- **The injection-surface map and the excessive-agency graph** in full

### AI Companion Report — Structure

```markdown
# AI / LLM Security Companion Report — [Target Name]
# Comprehensive AI Posture & Red-Team Audit
**Assessment Date:** YYYY-MM-DD
**AI Targets:** <ids / kinds / endpoints assessed>
**Models (claimed vs observed):** <fingerprint>
**Main Assessment Report:** groovysec-assessment-YYYY-MM-DD.pdf

## Table of Contents

### Part 1: Executive Summary + OWASP LLM Top 10 (2025) Coverage
1. AI Posture Overview (targets, kinds, models, frameworks, guardrails)
2. Finding Severity Breakdown (original + success-rate-calibrated)
3. OWASP LLM Top 10 coverage row per LLM01–LLM10 (tested? success-rate? status)

### Part 2: The Excessive-Agency Graph (the centerpiece)
4. Untrusted-input entry points → reachable tools → reached systems
5. Each path tagged EXPLOITED (captured tool call) / DETECTED-ONLY
6. Headline risk: highest-impact untrusted-input → high-side-effect-tool path

### Part 3: Injection-Surface Map
7. Each entry point × which injection class reached the model × success-rate

### Part 4: Findings (ALL AI findings, all severities)
8. Per finding: real probe prompt, real response, success-rate (k/N), guardrail behavior, OWASP LLM + ATLAS mapping, downstream-sink proof (AI-OH-*), captured tool call (AI-EA-*)

### Part 5: MITRE ATLAS Mapping + Cross-References
9. ATLAS TTP per finding
10. AI Findings Validated in Main Assessment (cross-ref table)
11. Remediation Priority Matrix
```

### AI Cross-References in Main Report

- **Reference format**: `**AI Companion Report, Section X**` (or the AI-XX test id)
- **Main report scope**: Include the top 3-5 AI findings (highest success-rate or highest-severity) with severity, success-rate (k/N), the OWASP LLM category, the real probe + response, and — for excessive agency — the captured tool call and its EXPLOITED / DETECTED-ONLY status. Point to the companion for the full OWASP LLM + ATLAS audit and the excessive-agency graph.
- **Cross-reference table** in the appendix:

```markdown
| Main Report Finding | AI Companion Section | Relationship |
|--------------------|----------------------|-------------|
| FINDING 5: Indirect Injection → Tool Exfil (CHAIN-51) | Part 2, Excessive-Agency Graph | Full path + captured call in companion |
| FINDING 8: Prompt Injection → Stored XSS (CHAIN-52) | Part 4, AI-OH-01 | Downstream sink proof in companion |
```

### AI Companion — Required Detail Level

"ALL means ALL" and banned vague language apply at full force:
- **Every AI-* test result** with its success-rate (k/N), trial count, temperature, and fail_threshold — never "injection worked sometimes"
- **Every captured tool call** (AI-EA-*) with the exact tool name + JSON arguments, marked captured-not-executed
- **Every untrusted-input entry point** from the surface map and **every exposed tool** with its real-world side-effect tag
- **Every guardrail** observed and whether it fired (AI-GB-* bypass evidence where it didn't)

### When to Generate

- **Only** when `ai_targets` is defined in `config/scope.yml` (same condition as ai-recon/ai-redteam)
- The ai-analysis agent generates it in Phase 4.9 (or the `/assess-ai` tail) as analysis-only synthesis — it never re-attacks
- The report-writer references the AI Companion Report in the main report; the pdf-renderer renders it as a separate PDF bound to the same `assessment_id`

## Changes Since Last Assessment — DISABLED

~~This section has been permanently disabled.~~ Each assessment is an independent point-in-time snapshot. **NEVER read, reference, or compare against previous assessment reports.** Do NOT use the `compare_assessments` MCP tool. Do NOT include a delta section.

**Why:** Reading old reports risks contaminating current findings with stale data, copying evidence from different test runs (different tokens, different responses), and creating confusion about which data belongs to which assessment. The team lead, agents, and report-writer must NEVER open previous report files.

## Dual-Track Report Format

When `context.dualTrackMode === true`, the report uses a four-section structure that separates DAST and SAST findings for clarity.

### When Dual-Track Activates
- The orchestrator sets `context.dualTrackMode = true` when running `mode: "dual-track"`
- Also auto-activates when `mode: "full"` is used with both `targets` and `repo_paths`
- Findings are tagged with `metadata.track`: `"dast"`, `"sast"`, or `"cross-validated"`

### Four-Section Report Structure

#### Section 1: DAST/Pentest Findings
Findings where `metadata.track === "dast"`. Traditional pentest findings from live testing:
- Port scanning, vulnerability scanning, web app testing, exploitation
- Present with: endpoint, evidence, exploitability, remediation

#### Section 2: SAST/Code Analysis Findings
Findings where `metadata.track === "sast"`. Static analysis findings:
- Semgrep, Bandit, secrets scanning, dependency vulnerabilities
- Present with: file:line reference, code snippet, CWE/rule ID, QA confidence score

#### Section 3: Cross-Validated Findings
Findings where `metadata.track === "cross-validated"`. The most valuable section — SAST findings tested against live endpoints:

```markdown
| SAST Finding | Code Location | Live Endpoint | DAST Result | Status |
|---|---|---|---|---|
| SQL Injection | api/users.ts:42 | POST /api/users | run_sqlmap: no injection | NOT_EXPLOITABLE |
| XSS in search | components/Search.tsx:15 | GET /search?q= | test_xss: reflected | CONFIRMED |
```

Status values:
- **CONFIRMED**: SAST finding is exploitable on the live endpoint
- **NOT_EXPLOITABLE**: Code vulnerability is blocked by runtime defenses
- **MITIGATED**: Partial defenses exist, severity downgraded
- **INCONCLUSIVE**: Could not determine exploitability

#### Section 4: Code Remediation Guide
For all findings with `metadata.remediationCode`, show before/after code:

```markdown
### SQL Injection in User API
File: `api/routes/users.ts:42`

**Vulnerable:**
\`\`\`typescript
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
\`\`\`

**Fixed:**
\`\`\`typescript
const query = `SELECT * FROM users WHERE id = ?`;
const result = await db.query(query, [req.params.id]);
\`\`\`

**Why:** Parameterized queries prevent SQL injection.
```

### Standard Sections Still Required
In addition to the four track-specific sections, include all standard sections:
- Table of Contents, Executive Summary, Assessment Walkthrough
- Exploitation Summary Matrix, QA Review Summary, Recommendations
- Testing Methodology (note the dual-track approach)

## Test Matrix Coverage Checklist (Required)

Every report MUST include a **Coverage Checklist** section that tracks execution of every test defined in `config/test-matrix.yml`. This ensures assessment consistency across runs.

### Format

```markdown
## Coverage Checklist

Tests defined in `config/test-matrix.yml` (the in-scope subset for this run — scope-derived count, not a fixed number). Every in-scope test must be accounted for.

### DAST Tests

| Test ID | Test Name | Status | Evidence/Notes |
|---------|-----------|--------|----------------|
| RECON-01 | Port scan primary target | PASS | Ports 80, 443 open on CloudFront |
| RECON-02 | Subdomain enumeration | PASS | 16 subdomains found |
| HDR-02 | CORS policy check | PASS | Access-Control-Allow-Origin: * on API |
| GQL-03 | Schema enumeration via suggestions | BLOCKED | Tool timeout after 120s — retry with manual curl also failed (DNS resolution error in container) |
| GQL-04 | Bulk data enumeration | BLOCKED | Depends on GQL-03 schema discovery — could not proceed without schema |

### SAST Tests

| Test ID | Test Name | Status | Evidence/Notes |
|---------|-----------|--------|----------------|
| SAST-01 | Semgrep OWASP Top 10 | PASS | 89 findings |
| SAST-02 | Secrets scanning | PASS | 50 secrets found |

### Cross-Validation Tests

| Test ID | Test Name | Status | Evidence/Notes |
|---------|-----------|--------|----------------|
| XVAL-01 | Validate SAST XSS against live | PASS | html2pdf NOT EXPLOITABLE |

### Compliance: 22/28 tests executed (78.6%)
```

### Status Values
- **PASS**: Test was executed and a result was obtained (finding or no finding)
- **FAIL**: Test was executed and a vulnerability was confirmed (finding created)
- **BLOCKED**: Test could not execute — MUST include root cause, what was tried, and recommended follow-up
- **N/A**: Test does not apply to this target — MUST include justification (e.g., "No file upload functionality exists")

**SKIPPED is not a valid status.** If a test was not run, it must be reported as BLOCKED with the specific reason it could not execute. This ensures every test gap is documented with enough detail for follow-up.

### Why This Matters
Without this checklist, assessments produce inconsistent results because the orchestrator may focus on different tests each time. The checklist ensures every required test is at least attempted, and any gaps are explicitly documented with root causes rather than silently omitted.

## Visual Styling Conventions

The PDF renderer (`md-to-pdf.js`) automatically applies color-coding and visual formatting to reports based on keyword detection. Reports must be **plain GFM markdown** — no raw HTML is allowed.

### Severity Keywords (Auto-Colored)

When these words appear as bold text (`**CRITICAL**`) or in table cells, they render as colored badges or tinted cells:

| Keyword | Color | Usage |
|---------|-------|-------|
| `**CRITICAL**` | White on red (#dc3545) | Severity badges, table cells |
| `**HIGH**` | White on orange (#fd7e14) | Severity badges, table cells |
| `**MEDIUM**` | Dark on yellow (#ffc107) | Severity badges, table cells |
| `**LOW**` | White on green (#28a745) | Severity badges, table cells |
| `**INFORMATIONAL**` / `**INFO**` | White on teal (#17a2b8) | Severity badges, table cells |

### Status Keywords (Auto-Colored in Tables)

Table cells containing these keywords get color treatment automatically:

| Keyword | Appearance | Usage |
|---------|------------|-------|
| TRUE | White on red | Exploitable field — confirmed exploitable |
| FALSE | Green bold | Exploitable field — not exploitable |
| POTENTIALLY | Orange bold | Exploitable field — code finding, not live-testable |
| PASS | Green text | Coverage checklist |
| FAIL | Red text, pink background | Coverage checklist |
| BLOCKED | Gray italic | Coverage checklist — test couldn't run |
| EXPOSED / CONFIRMED | White on red | Exploitation matrix |
| NOT EXPOSABLE / NOT_EXPLOITABLE | Green text | Exploitation matrix |
| MITIGATED | Orange text | Exploitation matrix |
| N/A | Light gray | Coverage checklist |
| YES / NO | Green / Gray | General tables |

### Finding Heading Format (Required)

Findings MUST use this heading format for automatic card styling:

```markdown
### FINDING 1: SQL Injection in User API
```

The renderer detects `### FINDING N:` and applies a colored left border + tinted background. The severity is auto-detected from the finding's metadata table or from keywords in the heading text.

### Section Heading Names (Accent Styling)

Use these exact section names (or close variants) for h2 headings to get colored bottom borders and accent markers:

- "Executive Summary"
- "Critical & High Findings" / "Critical and High Findings"
- "Medium Findings"
- "Low & Informational Findings"
- "Exploitation Summary Matrix" / "Exploitation Validation"
- "QA Review Summary"
- "Recommendations" / "Recommendations by Priority"
- "Testing Methodology" / "Detailed Methodology"
- "Compliance Mapping"
- "Coverage Checklist"
- "DAST Findings" / "SAST Findings" / "Cross-Validated Findings"

### Cover Page

The content before the first `## ` heading is automatically wrapped as a centered cover page with a page break after it. Include:
- The report title as `# Title`
- Metadata lines (date, assessor, target, classification)
- `**CONFIDENTIAL**` renders as a red classification banner

### Rules

1. Reports must be **plain GFM markdown** — never include raw HTML tags
2. Use exact keyword spelling for auto-coloring (e.g., `**CRITICAL**` not `**Crit**`)
3. Use `---` horizontal rules between findings for visual separation
4. Page breaks are inserted automatically before every `## ` heading

---

## Post-Exploitation Campaign Report

Produced by **post-exploit-analysis** (Phase 4.92) when `post_exploitation` is in scope and a foothold was established. It is the post-exploitation analog of the Cloud / Identity / AI companion reports — a **standalone, full-audit** account of everything the operator(s) did from their footholds: the "we got in, and here is everything we did from there" narrative + the replayable campaign graph.

Like the other companions, it is a **FULL audit, not just cross-references** — every foothold, every loot item, every walked AND available-but-not-walked path appears, not only the ones referenced in the main report. Internal: never redact foothold material, loot, or PII.

### Post-Exploitation Campaign Report — Structure

```
# Post-Exploitation Campaign Report — [Target Name]
**Assessment Date:** ... | **Footholds:** N | **Crown jewels reached:** M
[link back to the Main Assessment Report]

## Part 1: Executive Summary
- The headline campaign ("anonymous web visitor → full booking DB + account takeover in N steps")
- Footholds established, crown jewels reached, blast-radius
- Finding severity breakdown (original + calibrated; cite Rule 9 where an executed
  campaign anchored a finding at combined severity)

## Part 2: Foothold & Loot Inventory
- Every foothold: kind, target, how_acquired (provenance), grants
- Every loot item: what was obtained, from which step (never redacted)

## Part 3: The Campaign Graph (centerpiece)
- The post-ex analog of the Identity & Escalation Graph. Render every path tagged:
  - **WALKED-EXECUTED** — the operator actually traversed it (solid; real evidence)
  - **AVAILABLE-NOT-WALKED** — reachable from held capabilities, not traversed (budget) — as important as walked
  - **BLOCKED-BY-CONTROL** — attempted, a defense stopped it (name the control)

## Part 4: Campaign Timeline
- The step-by-step walk. Per step: the REAL command (with the injected $FOOTHOLD_*
  env, no placeholders) + the REAL response (status + body). Original + calibrated
  severity side-by-side. One row per step, in execution order.

## Part 5: Actions Withheld & Cross-References
- Every move NOT taken and WHY — out-of-boundary / never_touch / destructive-withheld
  / needs-infra-confirmation (the post-ex analog of the Identity report's
  "Lockout-Governed Tests" — the safety story as a first-class section)
- Cross-reference table into the main report (which footholds/loot map to which findings)
```

- **Reference format**: `**Post-Exploitation Campaign Report, Part X**`.
- Emit `**[CALIBRATION MISSING]**` if `reports/severity-calibration-results.json` is absent.
- Three-status discipline (Part 3) mirrors the cloud escalation graph: an AVAILABLE-NOT-WALKED path is reachable attack surface, not a non-finding — surface it.
