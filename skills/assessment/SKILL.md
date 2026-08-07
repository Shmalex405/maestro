# Full Assessment Skill (Single-Conversation Mode)

## When to Use This Skill

**For full assessments, use team mode instead: `skills/team-assessment/SKILL.md`.** Team mode distributes the scope-derived in-scope test set across specialized agents, each with their own context window, preventing context exhaustion that causes late-phase tests to be silently skipped.

**Use THIS skill for:**
- Quick scans (<30 tests)
- Single-phase testing (e.g., recon only, SAST only)
- Testing a specific vulnerability class
- Situations where team coordination overhead is unnecessary

## Purpose

Drive a security assessment interactively in a single conversation. You call every MCP tool directly, handle OTP/auth with the user, analyze results between steps, and produce one consolidated report.

**DO NOT use `run_orchestrator` or any `run_*_agent` tools.** Those delegate to inner LLM agents that are unreliable. Instead, call the individual MCP tools yourself following this workflow.

## Before Starting

1. Read `config/scope.yml` to verify targets are in scope
2. Read `config/test-matrix.yml` to load the in-scope checklist (the scope-derived subset — tests whose `applies_when` matches your scope)
3. Read `config/credentials.yml` for auth configuration
4. Tell the user the plan and ask them to watch for OTP prompts

## Phase 1: DAST (73 tests)

Execute every test below in order. For each test, call the listed MCP tool, analyze the result, and track the status (PASS/FAIL/BLOCKED/N_A). SKIPPED is not a valid status — use BLOCKED with a specific root cause if a test cannot execute.

### 1.1 Reconnaissance (6 tests)

| Test ID | Test | MCP Tool | Args |
|---------|------|----------|------|
| RECON-01 | Port scan | `scan_ports` | `target: <host>, scan_type: "quick"` |
| RECON-02 | Subdomain enumeration | `enumerate_subdomains` | `domain: <domain>` |
| RECON-03 | Service fingerprinting | `fingerprint_services` | `target: <host>, ports: <from RECON-01>` |
| RECON-04 | Web technology scan | `web_technology_scan` | `target: <url>` |
| RECON-05 | DNS records | `check_dns_records` | `domain: <domain>` |
| RECON-06 | Zone transfer | `test_zone_transfer` | `domain: <domain>` |

### 1.2 SSL/TLS (4 tests)

| Test ID | Test | MCP Tool | Args |
|---------|------|----------|------|
| TLS-01 | Protocol analysis | `scan_ssl_tls` | `target: <host>:443, checks: "protocols"` |
| TLS-02 | Certificate chain | `check_certificate` | `target: <host>:443` |
| TLS-03 | Cipher suites | `scan_ssl_ciphers` | `target: <host>` |
| TLS-04 | SSL vulnerabilities | `scan_ssl_tls` | `target: <host>:443, checks: "vulnerabilities"` |

### 1.3 Authentication (8 tests)

**INTERACTIVE — User provides OTP during this phase.**

| Test ID | Test | How |
|---------|------|-----|
| AUTH-01 | Complete auth flow | Use `browser_navigate` to go to login page, `browser_fill` + `browser_click` to submit email, use `prompt_for_otp` to get code from user, complete login, `browser_save_state` to persist session |
| AUTH-02 | JWT/token analysis | Use `browser_evaluate` to extract tokens from localStorage/cookies, then `analyze_jwt` on extracted token |
| AUTH-03 | Token storage security | Use `browser_evaluate` to check localStorage, sessionStorage, cookies for token locations |
| AUTH-04 | Unauthenticated API access | Call discovered API endpoints without auth headers, verify 401/403 |
| AUTH-05 | Session fixation | `test_session_fixation` with credentials |
| AUTH-06 | Session entropy | `test_session_management` |
| AUTH-07 | Token replay after logout | Save token, logout via browser, replay token with curl |
| AUTH-08 | Password policy | `test_password_policy` OR mark N/A if SSO-only |

**After AUTH-01**: Extract the Bearer token and GraphQL endpoint from browser network traffic. Use `browser_navigate` to a data page, then `browser_network_log` to capture API calls. This reveals the real API endpoint and auth header format.

### 1.4 Authorization (4 tests)

| Test ID | Test | How |
|---------|------|-----|
| AUTHZ-01 | IDOR on primary resources | `test_idor` on main API endpoints, or manual GraphQL queries with different IDs |
| AUTHZ-02 | Horizontal privilege escalation | Query other users' data using authenticated token |
| AUTHZ-03 | Vertical privilege escalation | Attempt admin-only operations with regular user token |
| AUTHZ-04 | Function-level access control | Test admin endpoints without admin privileges |

### 1.5 Security Headers (4 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| HDR-01 | CSP check | Check response headers from `web_technology_scan` or `browser_network_log` |
| HDR-02 | CORS policy | `test_cors` on both frontend and API |
| HDR-03 | Standard headers | Check HSTS, X-Frame-Options, etc. from web tech scan |
| HDR-04 | Cookie flags | `browser_get_cookies` to check HttpOnly, Secure, SameSite |

### 1.6 CORS (3 tests)

| Test ID | Test | MCP Tool | Args |
|---------|------|----------|------|
| CORS-01 | Origin reflection | `test_cors` | `origins: ["https://evil.com"]` |
| CORS-02 | Null origin | `test_cors` | `origins: ["null"]` |
| CORS-03 | Credentials + wildcard | `test_cors` | Check ACAO + ACAC headers together |

### 1.7 Injection (8 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| INJ-01 | SQL injection | `run_sqlmap` on parameterized endpoints |
| INJ-02 | XSS | `test_xss` on input-reflecting endpoints |
| INJ-03 | SSTI | `test_ssti` on server-rendered pages |
| INJ-04 | Command injection | Manual payloads via curl/browser |
| INJ-05 | LDAP injection | Only if LDAP detected |
| INJ-06 | XPath injection | Only if XML data sources |
| INJ-07 | CRLF injection | Manual header injection payloads |
| INJ-08 | NoSQL injection | Only if NoSQL detected |

### 1.8 SSRF (3 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| SSRF-01 | Internal IP access | `test_ssrf` |
| SSRF-02 | Cloud metadata | `test_cloud_metadata` |
| SSRF-03 | DNS rebinding | `test_ssrf` with rebinding payloads |

### 1.9 GraphQL (8 tests)

**Critical for GraphQL APIs.** If the app uses GraphQL, these tests often find the most impactful vulnerabilities.

| Test ID | Test | How |
|---------|------|-----|
| GQL-01 | Introspection | `test_graphql_security` with `tests: ["introspection"]` |
| GQL-02 | Batch query | `test_graphql_security` with `tests: ["batching"]` |
| GQL-03 | Schema via suggestions | `test_graphql_security` with `tests: ["field_suggestions"]` — probe 10+ field names |
| GQL-04 | Bulk data enumeration | Authenticated GraphQL query: `{ users { _id party_id user_roles } }` — check if ALL records return |
| GQL-05 | IDOR via lookup | Use IDs from GQL-04 in `{ user(id: "<other_id>") { ... } }` — check cross-user access |
| GQL-06 | Alias rate limit bypass | `test_graphql_security` with `tests: ["aliasing"]` |
| GQL-07 | API rate limiting | `test_api_rate_limiting` — send 50 rapid requests |
| GQL-08 | Mutation discovery | Probe for mutations via field suggestions |

**For GQL-04 and GQL-05**: Use `browser_evaluate` with the authenticated session to make GraphQL queries directly. This is how the critical IDOR was found — the `users` query returned ALL users' detokenized PII.

### 1.10 API Security (6 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| API-01 | OpenAPI/Swagger discovery | `fuzz_endpoints` for /swagger.json, /api-docs, etc. |
| API-02 | Schema-based fuzzing | `fuzz_api_schema` |
| API-03 | Rate limiting | `test_api_rate_limiting` |
| API-04 | API versioning bypass | Try /v1/, /v2/ versions of endpoints |
| API-05 | Mass assignment | POST/PUT with extra fields (role, isAdmin) |
| API-06 | Excessive data exposure | Compare API response fields vs UI display |

### 1.11 Client-Side (6 tests)

| Test ID | Test | How |
|---------|------|-----|
| CLI-01 | Source maps | Check for .js.map files via curl |
| CLI-02 | JS bundle analysis | `browser_evaluate` to inspect window/document for hardcoded values |
| CLI-03 | Config file exposure | Check /config.js, /env.js, /.env, /settings.json |
| CLI-04 | Error info leakage | Trigger errors and check for stack traces |
| CLI-05 | DOM-based XSS | `browser_evaluate` to check for innerHTML, postMessage sinks |
| CLI-06 | Prototype pollution | `browser_evaluate` to test __proto__ injection |

### 1.12 Vulnerability Scanning (3 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| VSCAN-01 | Nuclei CVE scan | `run_nuclei` with `severity: "medium,high,critical"` |
| VSCAN-02 | CSRF check | Analyze if Bearer token auth mitigates CSRF |
| VSCAN-03 | Nikto scan | `run_nikto` |

### 1.13 File Upload (3 tests) — only if upload functionality discovered

| Test ID | Test | MCP Tool |
|---------|------|----------|
| UPLOAD-01 | Extension bypass | `test_file_upload` |
| UPLOAD-02 | Content-Type manipulation | `test_file_upload` |
| UPLOAD-03 | Path traversal in filename | `test_file_upload` |

### 1.14 Business Logic (3 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| BIZ-01 | Race condition | `test_race_condition` |
| BIZ-02 | Price/quantity manipulation | Only if e-commerce functionality |
| BIZ-03 | Workflow bypass | Test skipping steps in multi-step flows |

### 1.15 Transport/Protocol (3 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| PROTO-01 | HTTP smuggling | `test_http_smuggling` |
| PROTO-02 | WebSocket security | `test_websocket` (only if WS detected) |
| PROTO-03 | Cache poisoning | `test_cache_poisoning` |

### 1.16 Deserialization (1 test)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| DESER-01 | Deserialization | `test_deserialization` (only if Java/Python/PHP/.NET) |

---

## Phase 2: SAST (24 tests) — Only if repo path provided

**Code-First Evidence Rule:** Every SAST finding MUST include: (1) exact file:line location, (2) actual vulnerable code from `analyze_code_context`, (3) why it's vulnerable, (4) fixed code using the same frameworks the codebase already uses, (5) fix explanation. Generic advice like "consider adding validation" or "use parameterized queries" is banned — show the actual code fix. See `skills/security-scan/SKILL.md` → "Code-First Evidence Standard" for the full anti-pattern list.

### 2.1 Code Analysis (10 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| SAST-01 | Semgrep OWASP Top 10 | `scan_semgrep` with `rules: "p/owasp-top-ten"` |
| SAST-02 | Secrets scanning | `scan_secrets` |
| SAST-03 | Dependency vulns | `scan_dependencies` |
| SAST-04 | Entry point mapping | `map_entry_points` |
| SAST-05 | Defense analysis | `analyze_defenses` |
| SAST-06 | IaC scanning | `scan_iac` |
| SAST-07 | Security audit | `scan_semgrep` with `rules: "p/security-audit"` |
| SAST-08 | Language-specific | `scan_bandit` (Python) or `scan_njsscan` (JS) |
| SAST-09 | Dangerous functions | `scan_semgrep` looking for eval/exec/system |
| SAST-10 | Git history secrets | `scan_secrets` with `include_git_history: true` |

### 2.2 Data Flow (5 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| SAST-DF-01 | SQL injection flows | `trace_data_flows` for DB sinks |
| SAST-DF-02 | XSS flows | `trace_data_flows` for template sinks |
| SAST-DF-03 | RCE flows | `trace_data_flows` for command sinks |
| SAST-DF-04 | SSRF flows | `trace_data_flows` for HTTP client sinks |
| SAST-DF-05 | File access flows | `trace_data_flows` for filesystem sinks |

### 2.3 Defense Verification (5 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| SAST-DEF-01 | Auth middleware | `analyze_defenses` with `defense_type: "auth"` |
| SAST-DEF-02 | Input validation | `analyze_defenses` with `defense_type: "input_validation"` |
| SAST-DEF-03 | CSRF protection | `analyze_defenses` with `defense_type: "csrf"` |
| SAST-DEF-04 | Output encoding | `analyze_defenses` with `defense_type: "output_encoding"` |
| SAST-DEF-05 | SQL parameterization | `analyze_defenses` with `defense_type: "sql_parameterization"` |

### 2.4 Supply Chain (4 tests)

| Test ID | Test | MCP Tool |
|---------|------|----------|
| SAST-SC-01 | Critical dep vulns | `scan_dependencies` — flag CRITICAL CVEs |
| SAST-SC-02 | High dep vulns | `scan_dependencies` — flag HIGH CVEs |
| SAST-SC-03 | License compliance | Check for GPL/AGPL licenses |
| SAST-SC-04 | Dependency confusion | Check private package scoping |

---

## Phase 3: Cross-Validation (11 tests) — Only if both DAST + SAST ran

For each SAST finding, test the corresponding live endpoint with the appropriate DAST tool. Document whether the code vulnerability is exploitable at runtime.

| Test ID | What | How |
|---------|------|-----|
| XVAL-01 | SAST XSS → DAST | Test live endpoints where SAST found XSS sinks |
| XVAL-02 | SAST injection → DAST | Test live endpoints where SAST found SQL injection |
| XVAL-03 | Token storage match | Compare SAST code vs DAST browser observation |
| XVAL-04 | Header gaps match | Compare SAST defense analysis vs DAST header check |
| XVAL-05 | SAST SSRF → DAST | Test live endpoints where SAST found HTTP client sinks |
| XVAL-06 | SAST RCE → DAST | Test live endpoints where SAST found command sinks |
| XVAL-07 | SAST auth bypass → DAST | Test unprotected routes found in SAST |
| XVAL-08 | SAST deserialization → DAST | Test endpoints with deserialization sinks |
| XVAL-09 | Rate limiting gaps | Test endpoints SAST identified as unprotected |
| XVAL-10 | Path traversal → DAST | Test endpoints with file access sinks |
| XVAL-11 | Secrets in deployed env | Verify if SAST-found secrets are active |

---

## Finding Creation — Evidence Standard

Follow the **Evidence Standard** defined in `CLAUDE.md`. Key rules:
- Use `create_finding` with `exploitable` field set for every vulnerability
- Every finding needs real evidence: actual curl commands (no `$TOKEN` placeholders), actual HTTP response bodies (no `# Returns 200`)
- SAST findings need code-first evidence: actual code from `analyze_code_context`, fixes using the codebase's own frameworks
- See CLAUDE.md sections "Evidence Standard" and "Finding Detail Standards" for the complete specification

### Evidence Requirements by Finding Type

| Finding Type | Must Include |
|-------------|-------------|
| **Injection (SQLi, XSS, SSTI)** | Exact payload used, request/response pair, proof of execution |
| **Authentication** | Full auth flow steps, token values, session behavior observed |
| **Authorization (IDOR)** | Two user contexts showing cross-access, exact IDs, full response bodies |
| **Configuration (CORS, headers, TLS)** | Exact headers sent/received, curl command, what's missing |
| **Information Disclosure** | What was exposed, where, exact content, risk |
| **SAST Code Finding** | File:line, ACTUAL code via `analyze_code_context`, data flow, concrete fix |
| **Cross-Validated (SAST→DAST)** | Both code vulnerability AND live exploitation proof |

---

## Report Generation

After all tests complete, generate the report using `generate_report` or write it directly. The report MUST include:

1. **Table of Contents** with clickable anchors
2. **Executive Summary** with severity counts
3. **Assessment Walkthrough** — phase-by-phase tables showing every step taken
4. **Detailed Methodology** — for each phase: objective, tool selection rationale, techniques, findings
5. **Exploitation Summary Matrix** — table of all attacks tested and results
6. **Detailed Findings** — each finding with full replicable evidence (see Evidence Standard above)
7. **Coverage Checklist** — every in-scope test ID with PASS/FAIL/BLOCKED/N_A status
8. **Recommendations** — prioritized remediation roadmap

Then generate PDF: `generate_pdf_report` with the markdown content.

## Key Principles

1. **YOU are the orchestrator** — call MCP tools directly, never delegate to inner agents
2. **Never skip auth** — the user will provide OTP when prompted
3. **Replicable evidence** — every finding must be reproducible by a third party using only the report
4. **No silent omissions** — every test ID must appear in the coverage checklist
5. **No SKIPPED status** — use PASS, FAIL, BLOCKED (with root cause), or N_A (with justification)
6. **Consistent severity** — same finding = same severity across assessments
7. **Consolidate everything** — one report with ALL findings from ALL tests
8. **Source code enrichment** — when repo is available, include file/line/code snippet and suggested fix for every applicable finding
9. **For full assessments, prefer team mode** — `skills/team-assessment/SKILL.md` prevents context exhaustion
