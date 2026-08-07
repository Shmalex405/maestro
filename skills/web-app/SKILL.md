# Web Application Testing Agent Skill

## Purpose
The Web App Agent performs OWASP-style testing against web applications, focusing on injection vulnerabilities, authentication issues, and access control problems.

## When to Use
- Testing web applications identified by recon
- Validating Cycode static analysis findings
- Deep-dive testing after vuln scanner identifies web issues
- Manual testing augmentation

## Available Tools

### run_sqlmap
Tests for SQL injection vulnerabilities.
```
Arguments:
  - target: URL with parameters
  - method: "GET" or "POST"
  - data: POST data (if POST method)
  - level: Test depth 1-5 (default: 2)
  - risk: Risk level 1-3 (default: 1, keep low!)
```

### fuzz_endpoints
Discovers hidden endpoints and directories.
```
Arguments:
  - target: URL with FUZZ placeholder
  - wordlist: Wordlist name (default: "common")
  - extensions: File extensions to check
```

### test_xss
Tests for cross-site scripting.
```
Arguments:
  - target: URL to test
  - params: Parameters to test
```

### crawl_site
Crawls website to discover endpoints.
```
Arguments:
  - target: Starting URL
  - depth: Crawl depth (default: 2)
```

## Workflow Pattern
1. Crawl application to discover endpoints
2. Identify parameters (query strings, form fields)
3. Test parameters for SQL injection
4. Test parameters for XSS
5. Fuzz for hidden directories/files
6. Document all findings with evidence

## Cycode Integration
When validating a Cycode finding:
1. Read the source code context
2. Identify the vulnerable function/endpoint
3. Determine the live URL for the vulnerable code
4. Craft targeted test based on code analysis
5. Execute test and capture evidence
6. Link finding to Cycode reference

## Best Practices
- Keep sqlmap risk level at 1-2 to avoid destructive tests
- Always crawl before fuzzing to understand app structure
- Use source code context to craft more effective payloads
- Capture full HTTP request/response as evidence
- Test authentication boundaries (can you access admin functions?)

## Safety Notes
- sqlmap is configured for NON-DESTRUCTIVE testing
- Time-based injection tests are allowed
- Data modification payloads are blocked
- Always validate scope before testing

## Output Format

Every test and finding MUST be individually documented with full evidence:

```json
{
  "tests": [
    {
      "test_id": "INJ-01",
      "test_name": "SQL injection on login endpoint",
      "target": "https://example.com/api/login",
      "method": "POST",
      "parameter": "username",
      "payloads_tested": ["' OR 1=1--", "admin'--", "1; DROP TABLE users--"],
      "result": "NOT_VULNERABLE",
      "evidence": {
        "request": "POST /api/login HTTP/1.1\n...",
        "response_status": 401,
        "response_body": "{\"error\":\"Invalid credentials\"}",
        "response_time_ms": 45
      }
    }
  ],
  "findings": [
    {
      "id": "WEBAPP-001",
      "title": "Reflected XSS in search parameter",
      "severity": "high",
      "endpoint": "https://example.com/search?q=PAYLOAD",
      "parameter": "q",
      "payload": "<script>alert(document.cookie)</script>",
      "evidence_request": "curl -s 'https://app.example.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E' -H 'Authorization: Bearer eyJhbG...'",
      "evidence_response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<div class=\"results\">Results for: <script>alert(document.cookie)</script></div>"
    }
  ]
}
```

## Completeness Rules (MANDATORY)

1. **Every endpoint tested must be documented** — both positive AND negative results
2. **Every payload sent must be listed** — not "10 payloads tested" but the actual 10 payloads
3. **Every response must include the HTTP status code and relevant body excerpt**
4. **Failed exploits are just as important as successful ones** — document what was tried and why it failed
5. **Never use "various", "multiple", "several"** — list every item explicitly
6. **Include response timing data** — this matters for blind injection detection
7. **If testing N parameters, all N must be documented** with their individual results
8. **GraphQL queries must include the full query text** — not "tested the users query" but the actual `{ users { _id ... } }` query
9. **REAL EVIDENCE, NOT TEMPLATES** — Every finding must contain the ACTUAL curl commands run (with real tokens, real URLs) and the ACTUAL HTTP response bodies received. NEVER use `$TOKEN`, `<PASSWORD>`, or any placeholder. NEVER write `# Returns HTTP 200` — paste the real response. This is a confidential internal report — show real data, real PII, real secrets.
