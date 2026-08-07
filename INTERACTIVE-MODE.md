# Interactive Mode Guide

This guide explains how to use the Kali MCP Pentest system interactively through Claude Code CLI, where you have a conversation with Claude and direct the security assessment in real-time.

---

## Overview
```
┌─────────────────────────────────────────────────────────────────┐
│                   HOW INTERACTIVE MODE WORKS                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────┐         ┌─────────────┐         ┌─────────────┐  │
│   │   YOU   │ ◀─────▶ │ Claude Code │ ──────▶ │ MCP Server  │  │
│   │         │  chat   │    CLI      │  tools  │             │  │
│   └─────────┘         └─────────────┘         └─────────────┘  │
│        │                     │                       │          │
│        │                     ▼                       ▼          │
│        │              Claude thinks:          Kali Container    │
│        │              - Plans approach        executes tools    │
│        │              - Selects tools                           │
│        │              - Analyzes results                        │
│        │                     │                                  │
│        │                     ▼                                  │
│        └──────────── Reports back to you                        │
│                      You ask follow-ups                         │
│                      Direct next steps                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## When to Use Interactive Mode

| Use Interactive Mode When... | Use Autonomous Mode Instead When... |
|------------------------------|-------------------------------------|
| Learning the system | Running scheduled scans |
| Exploring a new target | Validating large Cycode exports |
| Deep-diving on specific findings | Overnight/weekend assessments |
| Needing to make judgment calls | Routine weekly scans |
| Investigating complex vulnerabilities | Hands-off automation needed |
| Training team members | Consistent repeatable process |

---

## Setup Requirements

### Prerequisites

- [ ] Docker Desktop running
- [ ] Kali container built and running
- [ ] MCP server built
- [ ] Claude Code CLI installed
- [ ] Scope and credentials configured

### Start Services

**Terminal 1 - Start Kali Container:**
```bash
cd ~/Desktop/kali-mcp-pentest/docker
docker-compose up -d
```

**Terminal 2 - Start MCP Server:**
```bash
cd ~/Desktop/kali-mcp-pentest/mcp-server
npm start
```

**Terminal 3 - Open Claude Code:**
```bash
cd ~/Desktop/kali-mcp-pentest
claude
```

---

## Getting Started

### First Launch

When you run `claude` in the project directory, Claude automatically reads `CLAUDE.md` and understands:
- Available security tools
- Agent capabilities
- Safety rules
- Scope configuration

### Initial Conversation
```
You: Hi Claude, I want to run a security assessment on our staging environment.

Claude: I'd be happy to help with that. Before we start, let me verify a few things:

1. What targets would you like to assess? (domains, IPs, or application names)
2. What type of assessment? (full, recon only, web app focused, etc.)
3. Do you want authenticated or unauthenticated testing?

Also, I'll validate all targets against the scope configuration before any testing.
```

---

## Using Executable Agents

In addition to directing Claude tool-by-tool, you can run complete agents that autonomously execute their workflows.

### Running a Single Agent
```
You: Run the recon agent on 192.168.1.0/24

Claude: I'll run the recon agent on that network.

[Claude executes run_recon_agent]

The recon agent completed with the following results:
- 15 live hosts discovered
- 47 open ports across all hosts
- 3 web servers detected
- 2 database servers found

Key findings:
- MySQL exposed on 192.168.1.25 (potential security risk)
- Outdated Apache on 192.168.1.30

Would you like me to:
a) Run the vulnerability scanner agent on these targets
b) Deep-dive on a specific host
c) Generate a report of the recon findings
```

### Running the Full Orchestrator
```
You: Run a full security assessment on https://staging.example.com

Claude: I'll run the orchestrator in full mode. This will execute:
1. Recon Agent - discover assets
2. Vuln Scan Agent - scan for vulnerabilities
3. Web App Agent - test for OWASP issues
4. Exploit Agent - validate critical findings
5. Report Agent - generate report

[Claude executes run_orchestrator with mode: "full"]

Assessment complete! Here's the summary:
- Total findings: 12
- Critical: 1 (SQL Injection in /api/users)
- High: 3
- Medium: 5
- Low: 3

Jira tickets created: SEC-101, SEC-102, SEC-103, SEC-104
Report uploaded to SharePoint

Would you like to investigate any specific finding?
```

### Running Selective Agents
```
You: Just run recon and vuln scanning, skip the web app testing

Claude: I'll run the orchestrator with selective agents.

[Claude executes run_orchestrator with mode: "selective", agents: ["recon", "vuln-scan", "report"]]

Done! Ran recon → vuln-scan → report pipeline.
Found 8 vulnerabilities across the targets.
```

### Agent vs Direct Tool Usage

| Say This... | Claude Will... |
|-------------|----------------|
| "Run the recon agent" | Execute `run_recon_agent` - full autonomous recon |
| "Do a port scan on X" | Execute `scan_ports` - single specific tool |
| "Run a full assessment" | Execute `run_orchestrator` - all agents |
| "Check for SQL injection on /api/users" | Execute `run_sqlmap` - targeted test |

---

## Common Workflows

### Workflow 1: Full Assessment
```
You: Run a full security assessment on https://app.staging.company.com

Claude: I'll perform a comprehensive assessment. Let me start with reconnaissance.

[Claude executes scan_ports]

I found the following open ports:
- 80 (HTTP)
- 443 (HTTPS)
- 8080 (HTTP Proxy)

Let me now fingerprint these services and check for vulnerabilities...

[Claude executes run_nuclei]

I found 3 potential vulnerabilities:
1. HIGH: CVE-2023-1234 - Outdated Apache version
2. MEDIUM: Missing security headers
3. LOW: Information disclosure in error pages

Would you like me to:
a) Validate the HIGH severity finding
b) Continue with web application testing
c) Generate a report of current findings

You: Validate the HIGH severity finding first

Claude: I'll attempt to validate CVE-2023-1234...

[Claude executes targeted validation]

CONFIRMED: The Apache vulnerability is exploitable. I was able to...
[evidence details]

I've created a finding record. Should I create a Jira ticket for this?
```

### Workflow 2: Targeted Testing
```
You: Test the /api/users endpoint for SQL injection. It takes a user_id parameter.

Claude: I'll test that endpoint for SQL injection vulnerabilities.

First, let me verify the target is in scope...
✓ https://api.staging.company.com is in scope

[Claude executes run_sqlmap]

VULNERABLE: I confirmed SQL injection in the user_id parameter.

Details:
- Type: Boolean-based blind
- Parameter: user_id
- Payload: user_id=1' AND '1'='1

Evidence captured. Would you like me to:
a) Create a finding and Jira ticket
b) Test other parameters on this endpoint
c) Show the full sqlmap output

You: Create the finding and Jira ticket

Claude: Done! 
- Finding ID: f-2024-001
- Jira Ticket: SEC-456
- Severity: HIGH

What would you like to test next?
```

### Workflow 3: Code Scan + Exploitation
You: Scan my backend repo at ~/projects/api and then test any critical findings against staging
Claude: I'll scan the repository first.
[Claude executes scan_repository]
Scan complete. Found 8 issues:

1 CRITICAL: Hardcoded database password in config.py:23
2 HIGH: SQL injection patterns in routes/users.py:45, routes/orders.py:78
3 MEDIUM: XSS vulnerabilities
2 LOW: Information exposure

Let me analyze the SQL injection in routes/users.py:45...
[Claude executes analyze_code_context]
I can see the vulnerable code:
query = f"SELECT * FROM users WHERE id = {user_id}"
```

This corresponds to the /api/users endpoint. Let me validate against staging...

[Claude executes run_sqlmap against staging]

CONFIRMED: The SQL injection is exploitable in the live environment.

Should I create findings and tickets for all confirmed vulnerabilities?
```

### Workflow 4: Cycode Validation
```
You: Here's our Cycode export. Validate the HIGH severity findings.

[paste CSV]

Claude: I see 5 HIGH severity findings in the CSV:
1. SQL Injection - /api/users.py:42
2. Command Injection - /utils/backup.py:15
3. SSRF - /integrations/webhook.py:89
4. Path Traversal - /files/download.py:34
5. Hardcoded Secret - /config/settings.py:12

Let me validate each one. Starting with #1...

[Claude analyzes code, identifies endpoint, tests]

Finding #1 (SQL Injection): CONFIRMED ✓
- Endpoint: POST /api/users
- Parameter: user_id
- Evidence: [details]

Moving to #2 (Command Injection)...

[Claude continues through each finding]

Validation Summary:
- CONFIRMED: 3 of 5 (SQL Injection, SSRF, Hardcoded Secret)
- NOT EXPLOITABLE: 1 (Command Injection - input sanitized at runtime)
- COULD NOT TEST: 1 (Path Traversal - endpoint not accessible)

Should I create Jira tickets for the confirmed vulnerabilities?
```

### Workflow 5: Reconnaissance Only
```
You: Just do recon on 192.168.100.0/24, I want to know what's there

Claude: I'll discover and enumerate hosts on that network.

[Claude executes discover_hosts]

Found 12 live hosts:
- 192.168.100.1 (Gateway)
- 192.168.100.10 
- 192.168.100.11
- ...

Let me scan ports on each...

[Claude executes scan_ports on each host]

Network Map:
┌─────────────────┬───────────────────┬─────────────────────┐
│ IP              │ Open Ports        │ Services            │
├─────────────────┼───────────────────┼─────────────────────┤
│ 192.168.100.1   │ 22, 80            │ SSH, HTTP (router)  │
│ 192.168.100.10  │ 22, 80, 443, 3306 │ SSH, NGINX, MySQL   │
│ 192.168.100.11  │ 22, 8080          │ SSH, Tomcat         │
│ ...             │ ...               │ ...                 │
└─────────────────┴───────────────────┴─────────────────────┘

Interesting findings:
- MySQL exposed on .10 (should this be public?)
- Tomcat on .11 might have management interface

Want me to dig deeper on any of these?
```

---

## Useful Commands & Prompts

### Starting Assessments
```
"Run a full security assessment on [target]"

"Do reconnaissance on [CIDR range or domain]"

"Scan [target] for vulnerabilities, focus on OWASP Top 10"

"Test [application-name] using authenticated requests"
```

### Targeted Testing
```
"Test [URL] for SQL injection"

"Check if [target] is vulnerable to [CVE-XXXX-XXXX]"

"Fuzz the [endpoint] for hidden parameters"

"Scan [target] for exposed secrets or credentials"
```

### Code Analysis
```
"Scan my repo at [path] for security issues"

"Analyze [file:line] for [vulnerability type]"

"Find all SQL injection patterns in [repo path]"

"Check [repo] for hardcoded secrets"
```

### Reporting & Ticketing
```
"Create a finding for this vulnerability"

"Generate a report of all findings"

"Create Jira tickets for HIGH and CRITICAL findings"

"Show me all findings from today"
```

### Information & Status
```
"What applications are configured?"

"Show me the current scope"

"What findings have we discovered so far?"

"List all available tools"
```

---

## Interactive Tips

### 1. Be Specific About Targets
```
❌ "Test the API"
✅ "Test https://api.staging.company.com/v2/users endpoint"
```

### 2. Provide Context
```
❌ "Check for SQL injection"
✅ "Check the user_id parameter on /api/users for SQL injection. 
    It's a GET request and the parameter is an integer."
```

### 3. Ask for Explanations
```
"Explain what you found in simple terms"
"Why is this vulnerability critical?"
"What could an attacker do with this?"
```

### 4. Request Evidence
```
"Show me the proof for this finding"
"What payload confirmed the vulnerability?"
"Can you demonstrate the exploit?"
```

### 5. Guide the Assessment
```
"Focus on authentication bypass, skip the port scanning"
"Don't test that endpoint, it's known to be broken"
"Prioritize the payment API over the blog"
```

---

## Handling Findings

### When Claude Finds Something

Claude will typically:
1. Report what was found
2. Show evidence
3. Offer next steps

**Example:**
```
Claude: I found a potential XSS vulnerability.

Target: https://app.staging.company.com/search
Parameter: query
Payload: <script>alert(1)</script>

The response includes the unescaped payload in the HTML.

Options:
a) Create a finding record
b) Test for stored XSS
c) Check other parameters
d) Move to next target

You: Create the finding and test for stored XSS
```

### Creating Findings
```
You: Create a finding for this

Claude: I'll create a detailed finding record.

Finding Created:
- ID: f-2024-002
- Title: Reflected XSS in Search Function
- Severity: MEDIUM
- Target: https://app.staging.company.com/search
- Parameter: query
- Evidence: [payload and response captured]
- Remediation: Implement output encoding and CSP headers

Would you like me to create a Jira ticket as well?
```

### Generating Reports
```
You: Generate a report of everything we found today

Claude: Generating security assessment report...

Report Summary:
- Total Findings: 7
- Critical: 1
- High: 2
- Medium: 3
- Low: 1

Report saved to: data/reports/assessment-2024-01-15.md

Would you like me to:
a) Upload to SharePoint
b) Email to the security team
c) Show the full report here
```

---

## Session Management

### Continuing Work

Claude remembers context within a session:
```
You: Earlier you found SQL injection on the users endpoint. 
     Test the same thing on the orders endpoint.

Claude: I'll test /api/orders with similar techniques...
```

### Starting Fresh

To start a new assessment without prior context:
```
You: Let's start a fresh assessment. Forget what we tested before.
     New target: https://newapp.staging.company.com

Claude: Starting fresh assessment on https://newapp.staging.company.com...
```

### Saving Progress
```
You: Save our progress and generate a partial report

Claude: I'll save all findings discovered so far.

Saved:
- 4 findings recorded to database
- Partial report generated: data/reports/partial-2024-01-15.md
- Audit log contains all commands executed

You can continue this assessment later or generate the final report.
```

---

## Safety in Interactive Mode

### Scope Validation

Claude always validates before testing:
```
You: Test prod.company.com for vulnerabilities

Claude: I cannot test prod.company.com as it is not within the defined scope.

Current scope allows:
- *.staging.company.com
- *.dev.company.com
- 192.168.100.0/24

If you have authorization to test this target, please add it to 
config/scope.yml first.
```

### Destructive Operations
```
You: Run a DoS test against the staging server

Claude: I cannot execute denial-of-service attacks, even in staging.

However, I can:
- Check for DoS vulnerabilities without exploiting them
- Report potential DoS vectors based on configuration
- Document that the target MAY be vulnerable to DoS

Would you like me to assess DoS risk without active exploitation?
```

### Confirmation for Sensitive Actions
```
Claude: I found credentials in a config file. Should I:
a) Test these credentials against the database (might trigger alerts)
b) Document the finding without testing
c) Report as information disclosure only

You: Just document it, don't test the credentials
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Cancel current operation |
| `Ctrl+D` | Exit Claude Code |
| Up Arrow | Previous command/message |
| Tab | Autocomplete |

---

## Troubleshooting Interactive Mode

### Claude Doesn't Have Tools
```
You: Scan the target

Claude: I don't seem to have access to security tools. 
        Please ensure the MCP server is running.
```

**Fix:** Start the MCP server in another terminal:
```bash
cd mcp-server && npm start
```

### Target Out of Scope

**Fix:** Add target to `config/scope.yml`:
```yaml
domains:
  - pattern: "your-target.com"
    environment: "staging"
```

### Tool Execution Fails
```
You: Run nmap on the target

Claude: The tool execution failed with error: [error message]
```

**Fix:** Check Kali container is running:
```bash
docker ps | grep kali-pentest
docker logs kali-pentest
```

### Slow Responses

Long-running tools (full port scan, nuclei) take time:
```
Claude: Running full port scan, this may take several minutes...
[progress indicators if available]
```

Be patient or ask for quicker alternatives:
```
You: That's taking too long, do a quick scan instead
```

---

## Best Practices

### 1. Plan Before Testing
```
You: Before we start, what's your recommended approach for testing 
     a REST API with authentication?

Claude: For a REST API assessment, I recommend:
1. Recon - identify all endpoints
2. Auth testing - check for bypass, weak tokens
3. Input validation - test each parameter
4. Business logic - check authorization between roles
...
```

### 2. Document As You Go
```
You: Create findings for everything important, even if it's LOW severity
```

### 3. Review Before Ticketing
```
You: Show me all findings before creating Jira tickets

Claude: [lists all findings]

You: Don't create a ticket for finding #3, that's a known issue.
     Create tickets for the rest.
```

### 4. Ask for Recommendations
```
You: What should we test next based on what you've found?

Claude: Based on the SQL injection in the users API, I recommend:
1. Test other parameters on the same endpoint
2. Check related endpoints (orders, products)
3. Test for privilege escalation using the injection
...
```

---

## Example Full Session
```
$ cd ~/Desktop/kali-mcp-pentest
$ claude

Claude: Hello! I'm ready to help with security assessments. I have access 
        to the Kali MCP Pentest tools and have loaded your scope configuration.
        
        What would you like to test today?

You: Let's assess the staging API at https://api.staging.company.com

Claude: I'll start the assessment. First, let me verify scope...
        ✓ api.staging.company.com is in scope
        
        Beginning reconnaissance...
        
        [Executes port scan]
        
        Found: Port 443 open, running nginx/1.18.0
        
        Let me enumerate the API endpoints...
        
        [Executes directory fuzzing]
        
        Discovered endpoints:
        - /api/v1/users
        - /api/v1/orders
        - /api/v1/products
        - /api/v1/auth
        - /api/internal/admin (interesting!)
        
        The /api/internal/admin endpoint might be sensitive. 
        Should I investigate that first?

You: Yes, check what's exposed on the admin endpoint

Claude: Testing /api/internal/admin...
        
        [Executes requests]
        
        FINDING: Admin endpoint accessible without authentication!
        
        I was able to access:
        - GET /api/internal/admin/users - lists all users
        - GET /api/internal/admin/config - shows system configuration
        
        This is HIGH severity - the admin API should require authentication.
        
        Evidence captured. Should I:
        a) Create finding and Jira ticket
        b) Test what actions are possible (POST, DELETE)
        c) Continue to other endpoints

You: Create the finding and ticket, then test what actions are possible

Claude: Finding created: f-2024-001
        Jira ticket created: SEC-789
        
        Now testing dangerous operations...
        
        [Executes POST/DELETE tests - read-only, non-destructive]
        
        CRITICAL: Full admin access confirmed!
        - POST /api/internal/admin/users - Can create admin users
        - DELETE /api/internal/admin/users/{id} - Can delete users
        
        I did NOT execute these (non-destructive mode), but confirmed 
        the endpoints accept these methods.
        
        This should be escalated immediately. Creating CRITICAL finding...

You: Yes, create it. Then generate a report and send to the security team

Claude: Done:
        - Finding f-2024-002 created (CRITICAL)
        - Jira ticket SEC-790 created (Priority: Highest)
        - Report generated: assessment-2024-01-15.md
        - Uploaded to SharePoint: [link]
        - Emailed to security-team@company.com
        
        Summary:
        - 2 findings discovered
        - 1 CRITICAL (Unauthenticated admin access)
        - 1 HIGH (Admin API exposed)
        
        Recommend immediate action on the critical finding.
        
        Would you like to continue testing other endpoints?

You: No, that's enough for now. Thanks Claude!

Claude: Assessment complete. All findings are documented and stakeholders 
        have been notified. Stay secure! 🔒
```

---

*Last Updated: January 2025*
