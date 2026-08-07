# Kali MCP Pentest - Setup and Usage Guide

This guide walks you through setting up and using the automated ethical hacking system.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Configuration](#configuration)
4. [LLM Provider Setup](#llm-provider-setup)
5. [Running the System](#running-the-system)
6. [Using Claude Code](#using-claude-code)
7. [Running Assessments](#running-assessments)
8. [Working with Cycode](#working-with-cycode)
9. [Security Scanning Local Repositories](#security-scanning-local-repositories)
10. [Generating Reports](#generating-reports)
11. [N8N Workflows](#n8n-workflows)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before starting, ensure you have:

- [ ] macOS (Intel or Apple Silicon)
- [ ] Docker Desktop installed and running
- [ ] Node.js 18+ installed (`brew install node`)
- [ ] Claude Code CLI installed (`npm install -g @anthropic-ai/claude-code`)
- [ ] Git installed
- [ ] Access to your target test environments
- [ ] Jira API credentials (optional)
- [ ] SharePoint access (optional)
- [ ] SMTP credentials for email (optional)

---

## Initial Setup

### Step 1: Navigate to Project
```bash
cd ~/Desktop/kali-mcp-pentest
```

### Step 2: Create Environment File
```bash
cp .env.example .env
```

### Step 3: Edit Environment Variables

Open `.env` in your editor and fill in your credentials:
```bash
# Required
JIRA_BASE_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=your-email@company.com
JIRA_API_TOKEN=your-jira-api-token

# Optional but recommended
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Application credentials for authenticated testing
WEBAPP_USERNAME=test@yourcompany.com
WEBAPP_PASSWORD=your-test-password
API_BEARER_TOKEN=your-api-token
```

### Step 4: Build Kali Docker Container
```bash
cd docker
docker-compose up -d --build
```

This will:
- Download the Kali Linux base image
- Install all security tools (nmap, nuclei, sqlmap, semgrep, etc.)
- Install code scanning tools (bandit, gitleaks, grype, checkov, etc.)
- Start the container in the background

**Note:** The first build may take 10-15 minutes due to tool installation.

**Verify it's running:**
```bash
docker ps | grep kali-pentest
```

### Step 5: Install MCP Server Dependencies
```bash
cd ../mcp-server
npm install
```

### Step 6: Build MCP Server
```bash
npm run build
```

### Step 7: Initialize Database

The database initializes automatically on first run, but you can verify:
```bash
npm run dev
# Press Ctrl+C after you see "Server running"
```

---

## Configuration

### Configure Scope (REQUIRED)

Edit `config/scope.yml` to define your allowed targets:
```yaml
networks:
  - cidr: "10.0.0.0/8"
    environment: "internal-dev"
    notes: "Your dev network"

domains:
  - pattern: "*.staging.yourcompany.com"
    environment: "staging"

exclusions:
  - "*.prod.yourcompany.com"  # Never test production!
```

**⚠️ IMPORTANT:** Only targets in this file can be tested. Everything else is blocked.

### Configure Authentication (For Authenticated Testing)

Edit `config/credentials.yml` with your test application credentials:
```yaml
applications:
  - name: "my-webapp"
    base_url: "https://app.staging.yourcompany.com"
    auth_type: "bearer"
    credentials:
      token: "${API_BEARER_TOKEN}"
```

Supported auth types:
- `session` - Cookie-based login
- `basic` - HTTP Basic Auth
- `bearer` - Bearer token
- `api_key` - API key in header
- `oauth2` - OAuth2 client credentials
- `otp_email` - Interactive OTP via email (prompts for code)

### Configure Tool Settings (Optional)

Edit `config/tools.yml` to adjust tool behavior:
```yaml
nuclei:
  severity: "medium,high,critical"  # What to report
  rate_limit: 150                    # Requests per second

sqlmap:
  level: 2    # Test depth (1-5)
  risk: 1     # Keep at 1 for non-destructive
```

---

## LLM Provider Setup

Maestro is driven by an LLM, and each user brings their own credentials. There
are two brains, selected per-assessment in the desktop app:

| Brain | CLI | Credential modes |
|---|---|---|
| **Claude** (default) | Claude Code | Sign in with Claude (OAuth), or `ANTHROPIC_API_KEY` |
| **Codex** | OpenAI Codex CLI | Sign in with ChatGPT (device code), or `OPENAI_API_KEY` |

For the API-key path:

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
# or
export OPENAI_API_KEY=sk-...
```

No further configuration is needed. The desktop app's config screens handle
OAuth and store credentials in the container.

### Self-hosted local models are not supported

Earlier versions shipped an Ollama provider for air-gapped use. It was removed:
local models could not reliably sustain the multi-step tool use an assessment
requires, and a provider that silently produces weaker findings is worse than
not offering the choice. If data residency is the concern, note that the
scanners and the Kali container already run entirely on your own machine — only
the orchestration prompts leave it.

---

## Running the System

### Start All Services

**Terminal 1 - Kali Container:**
```bash
cd ~/Desktop/kali-mcp-pentest/docker
docker-compose up -d
```

**Terminal 2 - MCP Server:**
```bash
cd ~/Desktop/kali-mcp-pentest/mcp-server
npm start
```

### Verify Services

Check Kali is running:
```bash
docker exec kali-pentest nmap --version
```

Check scanning tools:
```bash
docker exec kali-pentest semgrep --version
docker exec kali-pentest bandit --version
docker exec kali-pentest gitleaks version
```

Check MCP server is responding:
```bash
# Should see server output in Terminal 2
```

---

## Using Claude Code

### Step 1: Open Project in Claude Code
```bash
cd ~/Desktop/kali-mcp-pentest
claude
```

This opens Claude Code with the project context.

### Step 2: Claude Code Will Read CLAUDE.md

Claude automatically reads the `CLAUDE.md` file which contains:
- Project structure
- Available tools
- Agent capabilities
- Safety rules

### Step 3: Start Interacting

Example prompts:

**Run reconnaissance:**
```
"Run a full reconnaissance scan on the staging environment. 
Target: 192.168.100.0/24"
```

**Validate a Cycode finding:**
```
"I have a SQL injection finding from Cycode in /api/users.py at line 42. 
The endpoint is https://api.staging.company.com/api/users. 
Validate if this is exploitable."
```

**Scan local code:**
```
"Scan my repository at ~/projects/backend-api for security vulnerabilities"
```

**Generate a report:**
```
"Generate a security report for all findings from today's assessment. 
Create Jira tickets for critical and high findings."
```

---

## Running Assessments

### Unauthenticated Assessment
```
"Perform an unauthenticated security assessment of https://app.staging.company.com.
Start with reconnaissance, then vulnerability scanning, then web app testing."
```

### Authenticated Assessment
```
"Perform an authenticated assessment of the 'main-webapp' application.
Use the configured credentials to test authenticated endpoints.
Focus on authorization bypass and privilege escalation."
```

### Targeted Cycode Validation
```
"Import the attached Cycode CSV and validate all HIGH severity findings.
For each finding:
1. Read the source code context
2. Identify the vulnerable endpoint
3. Attempt to exploit it
4. Document evidence"
```

---

## Working with Cycode

### Import Cycode Findings

1. Export findings from Cycode as CSV
2. In Claude Code:
```
"Import this Cycode CSV and start validation:
[paste CSV content or upload file]"
```

### Automated Validation Flow

Claude will:
1. Parse the CSV to extract findings
2. For each finding:
   - Read the source code (via repo access)
   - Analyze the vulnerability
   - Craft targeted exploit
   - Execute against test environment
   - Capture evidence
3. Create findings for confirmed vulnerabilities
4. Generate report linking back to Cycode IDs

### Example Cycode CSV Format
```csv
id,vulnerability_type,severity,file_path,line_number,description
CYC-001,SQL Injection,HIGH,/api/users.py,42,"Unsanitized input in query"
CYC-002,XSS,MEDIUM,/templates/profile.html,15,"Unescaped user input"
```

---

## Security Scanning Local Repositories

### Overview

The Security Scan Agent lets you scan any local repository for vulnerabilities. This works alongside Cycode to give you comprehensive static analysis.

### Repo Path Mapping

Your home directory is mounted in the container:
- Mac path: `~/projects/my-app`
- Container path: `/mnt/host-home/projects/my-app`

Claude automatically translates paths when you use `~` or reference your home directory.

### Running a Scan

In Claude Code:
```
"Scan my repository at ~/projects/backend-api for security vulnerabilities"
```

Claude will:
1. Detect languages in the repo
2. Run appropriate scanners (Semgrep, Bandit, etc.)
3. Check for hardcoded secrets
4. Scan dependencies for known CVEs
5. Report findings by severity

### Scan Types

| Type | What It Checks |
|------|----------------|
| sast | Source code vulnerabilities (SQL injection, XSS, etc.) |
| secrets | Hardcoded credentials, API keys, tokens |
| dependencies | Vulnerable packages and libraries |
| iac | Terraform, Kubernetes, Docker misconfigurations |
| all | Everything above |

### Example Workflows

**Full security audit:**
```
"Run a complete security scan on ~/projects/my-app and generate a report"
```

**Check for secrets before committing:**
```
"Scan ~/projects/my-app for any hardcoded secrets or credentials"
```

**Analyze specific vulnerability:**
```
"Analyze the code at ~/projects/api/routes/users.py lines 40-60 for SQL injection"
```

**Feed findings to exploitation:**
```
"Scan ~/projects/webapp, then validate any critical findings against the staging environment at https://webapp.staging.company.com"
```

**Compare with Cycode:**
```
"Scan ~/projects/api for vulnerabilities and compare with the attached Cycode CSV. Identify any findings Cycode missed."
```

### Supported Languages

| Language | SAST Scanners | Dependency Scanners |
|----------|---------------|---------------------|
| Python | Semgrep, Bandit | safety, grype |
| JavaScript/TS | Semgrep, njsscan | npm audit, grype |
| Java | Semgrep | grype |
| Go | Semgrep | grype |
| Ruby | Semgrep | grype |
| PHP | Semgrep | grype |
| Terraform | checkov, kics | - |
| Kubernetes | checkov, kics | - |
| Dockerfile | checkov, kics | - |

### Secrets Detection

The following secret types are detected:
- AWS credentials
- API keys (generic and service-specific)
- Private keys (RSA, SSH, etc.)
- Database connection strings
- OAuth tokens
- JWT secrets
- Password in configuration files

### Output Formats

Scan results can be exported as:
- **JSON** - Full structured data
- **Markdown** - Human-readable report
- **CSV** - Cycode-compatible format for import

### Integration with Exploit Pipeline

1. Scan identifies vulnerability with file/line
2. `analyze_code_context` extracts the vulnerable code
3. Claude analyzes the code to understand the vulnerability
4. Claude identifies the corresponding live endpoint
5. Web-app-agent or exploit-agent tests the endpoint
6. Finding updated with exploitation evidence

---

## Generating Reports

### On-Demand Report
```
"Generate a Markdown security report with all findings.
Include evidence. Upload to SharePoint and email security-team@company.com"
```

### Filtered Report
```
"Generate a report with only CRITICAL and HIGH findings.
Create Jira tickets in project SEC for each."
```

### Code Scan Report
```
"Generate a scan report for scan ID [scan-id] in CSV format"
```

### Report Outputs

Reports are:
1. Generated in Markdown/HTML/JSON/CSV format
2. Saved locally in `data/reports/`
3. Uploaded to SharePoint (if configured)
4. Emailed to recipients (if configured)

---

## N8N Workflows

### Available Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `scheduled-recon.json` | Cron (weekly) | Regular reconnaissance |
| `cycode-import.json` | Webhook | Automated Cycode validation |
| `report-generation.json` | Manual | Generate and distribute reports |

### Import Workflows to N8N

1. Open N8N (http://localhost:5678)
2. Go to Workflows → Import
3. Import JSON files from `n8n/workflows/`
4. Configure credentials in N8N

### Trigger Cycode Workflow via Webhook
```bash
curl -X POST http://localhost:5678/webhook/cycode-import \
  -H "Content-Type: text/csv" \
  --data-binary @cycode-export.csv
```

---

## Troubleshooting

### Kali Container Won't Start
```bash
# Check Docker is running
docker info

# Check logs
docker logs kali-pentest

# Rebuild if needed
docker-compose down
docker-compose up -d --build
```

### MCP Server Connection Issues
```bash
# Check if running
ps aux | grep node

# Check Docker socket permissions
ls -la /var/run/docker.sock

# Restart server
cd mcp-server
npm start
```

### Scope Validation Errors

If you see "SCOPE VIOLATION" errors:
1. Check `config/scope.yml` includes your target
2. Verify CIDR ranges are correct
3. Check domain patterns match

### Authentication Failures

1. Verify credentials in `.env`
2. Check `config/credentials.yml` syntax
3. Test credentials manually first
4. Check token expiration

### Code Scanning Issues
```bash
# Verify scanners are installed
docker exec kali-pentest semgrep --version
docker exec kali-pentest bandit --version
docker exec kali-pentest gitleaks version
docker exec kali-pentest grype version

# Check repo is mounted
docker exec kali-pentest ls /mnt/host-home

# Rebuild container if tools missing
cd docker
docker-compose down
docker-compose up -d --build
```

### Tools Not Found in Kali
```bash
# Rebuild container
cd docker
docker-compose down
docker-compose up -d --build

# Or install manually
docker exec kali-pentest apt-get update
docker exec kali-pentest apt-get install -y <tool-name>

# For Python tools
docker exec kali-pentest pip3 install --break-system-packages <tool-name>
```

### Slow Scans

If scans are running slowly:
1. Use `severity_threshold: "high"` to reduce output
2. Limit scan types: `scan_types: ["sast"]` instead of `["all"]`
3. Exclude large directories in scan options
4. For dependency scans, ensure lock files exist

### LLM Provider Issues

**Anthropic API key errors:**
```bash
# Verify key is set
echo $ANTHROPIC_API_KEY

# Check it's valid (first few chars)
echo $ANTHROPIC_API_KEY | cut -c1-10
```

---

## Quick Reference

### Key Directories

| Path | Purpose |
|------|---------|
| `config/scope.yml` | Allowed network targets |
| `config/credentials.yml` | Authentication for apps |
| `config/tools.yml` | Tool settings |
| `config/llm-config.yml` | LLM provider configuration |
| `data/` | SQLite database, reports |
| `logs/` | Audit logs |
| `skills/` | Agent skill documentation |
| `/mnt/host-home/` | Your home directory (in container) |

### Key Commands
```bash
# Start Kali
cd docker && docker-compose up -d

# Start MCP Server
cd mcp-server && npm start

# Open Claude Code
cd ~/Desktop/kali-mcp-pentest && claude

# Check Kali tools
docker exec kali-pentest <tool> --version

# View audit logs
sqlite3 data/pentest.db "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10"

# View findings
sqlite3 data/pentest.db "SELECT * FROM findings ORDER BY severity DESC"

# Check mounted repos
docker exec kali-pentest ls -la /mnt/host-home
```

### Safety Reminders

1. ✅ Only test systems you have authorization for
2. ✅ Keep scope.yml updated and restrictive
3. ✅ Review destructive exploit reports before manual testing
4. ✅ Rotate credentials regularly
5. ✅ Local repos are mounted read-only for safety
6. ❌ Never add production systems to scope
7. ❌ Never commit `.env` or `credentials.yml` to git
8. ❌ Never store real credentials in code scan test files
