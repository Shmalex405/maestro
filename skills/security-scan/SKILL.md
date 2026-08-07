# Security Scan Agent Skill

## Purpose
The Security Scan Agent performs static application security testing (SAST) on local repositories. It provides independent vulnerability discovery that complements Cycode and feeds into the exploitation pipeline.

## When to Use
- Scanning repositories not covered by Cycode
- On-demand security assessment of new code
- Pre-commit/pre-merge security gates
- Deep-dive analysis of specific code areas
- Generating vulnerability lists for exploitation validation

## Available Tools

### scan_repository
Comprehensive multi-scanner security assessment.
```
Arguments:
  - repo_path: Absolute path to the repository
  - scan_types: ["sast", "secrets", "dependencies", "iac", "all"]
  - severity_threshold: Minimum severity to report
```

Example:
```json
{
  "repo_path": "/Users/you/projects/my-app",
  "scan_types": ["all"],
  "severity_threshold": "medium"
}
```

### scan_semgrep
Run Semgrep SAST scanner with configurable rules.
```
Arguments:
  - repo_path: Path to repository
  - rules: Ruleset (e.g., "p/security-audit", "p/owasp-top-ten")
  - languages: Specific languages to scan (optional)
```

### scan_bandit
Python-specific security scanning.
```
Arguments:
  - repo_path: Path to Python repository
  - severity: Minimum severity (low/medium/high)
  - confidence: Minimum confidence (low/medium/high)
```

### scan_njsscan
JavaScript/Node.js security scanning.
```
Arguments:
  - repo_path: Path to JS/TS repository
```

### scan_secrets
Detect hardcoded secrets and credentials.
```
Arguments:
  - repo_path: Path to repository
  - include_git_history: Scan git history (slower but thorough)
```

### scan_dependencies
Scan for vulnerable dependencies.
```
Arguments:
  - repo_path: Path to repository
  - package_manager: auto/pip/npm/yarn/maven/gradle/go
```

### scan_iac
Scan Infrastructure as Code for misconfigurations.
```
Arguments:
  - repo_path: Path to repository
  - frameworks: terraform/cloudformation/kubernetes/dockerfile/all
```

### analyze_code_context
Deep analysis of specific code sections.
```
Arguments:
  - file_path: Path to specific file
  - line_start: Starting line number
  - line_end: Ending line number
  - vulnerability_type: Type to look for (sqli, xss, ssrf, etc.)
```

### detect_languages
Identify languages in a repository.
```
Arguments:
  - repo_path: Path to repository
```

### generate_scan_report
Generate report from scan results.
```
Arguments:
  - scan_id: ID from scan_repository result
  - format: json/markdown/csv
```

## Workflow Pattern

### Full Repository Scan
1. `detect_languages` - Identify what's in the repo
2. `scan_repository` with `scan_types: ["all"]`
3. Review findings by severity
4. `analyze_code_context` on critical findings
5. `generate_scan_report` for documentation
6. Pass high-priority findings to exploit-agent

### Targeted Vulnerability Search
1. `scan_semgrep` with specific rules (e.g., "p/sql-injection")
2. For each finding: `analyze_code_context`
3. Identify exploitable endpoints
4. Pass to web-app-agent or exploit-agent

### Pre-Exploitation Analysis
1. Receive finding from Cycode or previous scan
2. `analyze_code_context` on the vulnerable code
3. Understand the vulnerability from source
4. Identify the live endpoint/function
5. Craft targeted exploit

## Scanner Coverage

| Language | SAST | Secrets | Dependencies |
|----------|------|---------|--------------|
| Python | Semgrep, Bandit | gitleaks, trufflehog | safety, grype |
| JavaScript/TS | Semgrep, njsscan | gitleaks, trufflehog | npm audit, grype |
| Java | Semgrep | gitleaks, trufflehog | grype |
| Go | Semgrep | gitleaks, trufflehog | grype |
| Ruby | Semgrep | gitleaks, trufflehog | grype |
| PHP | Semgrep | gitleaks, trufflehog | grype |
| IaC | checkov, kics | - | - |

## Output Format

Findings follow a consistent format:
```json
{
  "id": "rule-id",
  "title": "SQL Injection in User Query",
  "severity": "high",
  "file": "/src/api/users.py",
  "line": 42,
  "line_end": 45,
  "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
  "description": "User input directly concatenated into SQL query",
  "scanner": "semgrep",
  "cwe": "CWE-89",
  "owasp": "A03:2021"
}
```

## Integration with Exploit Pipeline

Findings can be passed to the exploitation pipeline:
1. Scan identifies vulnerability with file/line
2. `analyze_code_context` extracts the vulnerable code
3. Claude analyzes the code to understand the vulnerability
4. Claude identifies the corresponding live endpoint
5. Web-app-agent or exploit-agent tests the endpoint
6. Finding updated with exploitation evidence

## Best Practices

1. **Start broad, then narrow**: Use `scan_repository` first, then targeted scans
2. **Verify with context**: Always use `analyze_code_context` before exploitation
3. **Check dependencies**: Many vulns come from dependencies, not your code
4. **Don't skip secrets**: Leaked credentials are often the easiest attack vector
5. **Prioritize by exploitability**: Critical severity + injection type = validate first
6. **Generate reports**: Document everything for compliance and tracking

## Code-First Evidence Standard

Every SAST finding — whether in the main report or the SAST companion report — MUST include code-first evidence. Generic advice is banned.

### Required for Every Finding

1. **Exact location**: File path and line number (e.g., `backend/app/api/users.py:42`)
2. **Vulnerable code**: The ACTUAL code from the repo, retrieved via `analyze_code_context`. Not a generic example — the real code.
3. **Why it's vulnerable**: Explain the specific flaw in this code (e.g., "User input from `req.params.id` is concatenated directly into the SQL string without parameterization")
4. **Fixed code**: A concrete fix using the SAME frameworks and patterns the codebase already uses. If the codebase uses SQLAlchemy, show a SQLAlchemy fix. If it uses Prisma, show a Prisma fix.
5. **Fix explanation**: Why the fix works, referencing the specific mechanism (e.g., "SQLAlchemy's `text()` with `:param` syntax sends parameters separately from the query, preventing injection")

### Reading Source Code (Mandatory)

For every finding, you MUST:
- Call `analyze_code_context` on the vulnerable file/line range
- Read enough surrounding context to understand the function, its imports, and the frameworks in use
- Write remediation code that fits naturally into the existing codebase

### Anti-Patterns (BANNED)

These are **never acceptable** in SAST findings:

| Banned Pattern | Why It's Banned | Required Instead |
|---------------|-----------------|------------------|
| "Consider adding input validation" | Vague, not actionable | Show the exact validation code for this specific input, in this specific file |
| "Use parameterized queries" | Generic advice | Show the parameterized version of THIS query using the ORM/driver already in use |
| Generic OWASP code examples | Not from this codebase | Show a fix using the actual imports and patterns from the surrounding code |
| "Implement rate limiting" | Doesn't tell them how | Show the middleware/decorator code using their framework (Express, FastAPI, etc.) |
| "Sanitize user input" | Meaningless without specifics | Show which sanitizer function to call, on which variable, at which line |
| Suggesting frameworks the codebase doesn't use | Irrelevant to developers | Use only libraries already in package.json/requirements.txt/go.mod |

### Section Count Accuracy

When a section heading includes a count (e.g., "### 14 Private Keys Found"), the number in the heading MUST match the actual number of rows in the table below it. Verify counts before finalizing.

## Limitations

- Static analysis has false positives - always validate
- Cannot detect runtime/logic vulnerabilities
- Dependency scans depend on accurate manifest files
- IaC scans may miss custom configurations
- Secrets detection may flag test/example credentials

## Example Workflow
```
User: "Scan my API project at /Users/me/projects/api"

Claude:
1. detect_languages → Python, JavaScript
2. scan_repository with all scan types
3. Results show:
   - 2 Critical: SQL Injection, Command Injection
   - 5 High: XSS, Hardcoded secrets, etc.
4. analyze_code_context on SQL Injection finding
5. Identifies: /api/users.py:42, endpoint: POST /users
6. Passes to web-app-agent for validation
7. generate_scan_report for documentation
```
