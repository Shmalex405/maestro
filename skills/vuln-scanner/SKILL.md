# Vulnerability Scanner Agent Skill

## Purpose
The Vuln Scanner Agent performs automated vulnerability detection using multiple scanning engines. It identifies known vulnerabilities and CVEs.

## When to Use
- After recon-agent has identified targets
- Scheduled periodic scans
- When new CVEs are published affecting your stack
- Before deeper manual testing

## Available Tools

### run_nuclei
Runs nuclei with specified templates.
```
Arguments:
  - target: URL to scan
  - templates: Template tags (default: "cve,owasp-top-10")
  - severity: Severity filter (default: "medium,high,critical")
```

### run_nikto
Runs nikto web server scanner.
```
Arguments:
  - target: URL to scan
  - tuning: Scan tuning options (default: "x")
```

### run_wpscan
Scans WordPress installations.
```
Arguments:
  - target: WordPress URL
  - enumerate: Options like "vp,vt,u" (vulnerable plugins, themes, users)
```

### search_exploits
Searches exploit-db for known exploits.
```
Arguments:
  - query: Search term (service name, CVE, etc.)
```

## Workflow Pattern
1. Receive targets from recon-agent
2. Categorize services (web, database, mail, etc.)
3. Run nuclei against web targets
4. Run nikto for web servers
5. Run wpscan if WordPress detected
6. Search for exploits for each identified service
7. Deduplicate and prioritize findings
8. Pass to exploit-agent for validation

## Best Practices
- Use severity filters to focus on actionable findings
- Run nuclei with multiple template categories
- Cross-reference findings with exploit availability
- Update nuclei templates before each scan
- Group findings by target for easier remediation

## Output Format

Every finding MUST include ALL of the following fields — no optional fields:

```json
{
  "findings": [
    {
      "id": "VULN-001",
      "title": "Apache Struts RCE (CVE-2017-5638)",
      "severity": "critical",
      "cve": "CVE-2017-5638",
      "cvss": "10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
      "target": "https://example.com:8080",
      "endpoint": "/login.action",
      "scanner": "nuclei",
      "template": "CVE-2017-5638",
      "evidence": "HTTP 200 with command execution output in response body",
      "request": "GET /login.action HTTP/1.1\nHost: example.com\n...",
      "response_status": 200,
      "response_snippet": "uid=33(www-data) gid=33(www-data)..."
    }
  ]
}
```

## Completeness Rules (MANDATORY)

1. **Every finding must have a CVE** — if no CVE exists, document the CWE and a descriptive title
2. **Every finding must include the exact endpoint tested** — not just the host, but the full URL path with parameters
3. **Every finding must include the HTTP request sent and response received** (or relevant excerpts)
4. **If nuclei returns N findings, all N must be listed individually** — never summarize as "15 medium findings"
5. **Never use "various", "multiple", "several", "some"** — enumerate every item
6. **Service versions must be exact** — "Apache 2.4.49" not "Apache"
7. **Exploit availability must reference specific exploit-db IDs or Metasploit module paths**
8. **If a scan tool errors, document the exact error message** — never silently skip
