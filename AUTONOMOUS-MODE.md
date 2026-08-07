# Autonomous Mode Guide

This guide explains how to run fully automated security assessments where Claude makes all decisions autonomously.

---

## Overview
```
┌─────────────────────────────────────────────────────────────────┐
│                  HOW AUTONOMOUS MODE WORKS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. TRIGGER                                                    │
│      │                                                          │
│      ├── N8N Schedule (cron)                                    │
│      ├── N8N Webhook (Cycode CSV, release event)                │
│      └── Manual API call                                        │
│                                                                 │
│   2. AUTONOMOUS RUNNER receives request                         │
│      │                                                          │
│      ▼                                                          │
│   3. CLAUDE API is called with:                                 │
│      - System prompt (from CLAUDE.md)                           │
│      - Assessment instructions                                  │
│      - Available security tools                                 │
│                                                                 │
│   4. CLAUDE THINKS and ACTS                                     │
│      │                                                          │
│      ├── "What should I scan first?"                            │
│      ├── "Let me run nmap on this target"                       │
│      ├── [Executes nmap via MCP tools]                          │
│      ├── "I found open ports, let me check for vulns"           │
│      ├── [Executes nuclei]                                      │
│      ├── "Found SQL injection, let me validate"                 │
│      ├── [Executes sqlmap]                                      │
│      ├── "Confirmed! Creating finding and Jira ticket"          │
│      └── [Creates finding, ticket, report]                      │
│                                                                 │
│   5. RESULTS returned to N8N                                    │
│      │                                                          │
│      ▼                                                          │
│   6. N8N handles notifications (Slack, email)                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Setup Requirements

### 1. Anthropic API Key

You need an Anthropic API key for Claude to think autonomously.

1. Get your API key from: https://console.anthropic.com/
2. Add to `.env`:
```bash
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

### 2. Install Dependencies
```bash
cd mcp-server
npm install
npm run build
```

### 3. Start Both Servers

**Terminal 1 - MCP Server (for tools):**
```bash
cd mcp-server
npm start
```

**Terminal 2 - Autonomous Runner (for N8N):**
```bash
cd mcp-server
npm run start:autonomous
```

### 4. Verify Autonomous Runner
```bash
curl http://localhost:3001/health
# Should return: {"status":"ok"}
```

---

## Available Endpoints

The Autonomous Runner exposes these HTTP endpoints for N8N:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/assess/full` | POST | Full security assessment |
| `/assess/recon` | POST | Reconnaissance only |
| `/assess/vuln-scan` | POST | Vulnerability scanning only |
| `/assess/code-scan` | POST | Static code analysis |
| `/assess/cycode-validate` | POST | Validate Cycode findings |

---

## Request/Response Examples

### Full Assessment

**Request:**
```bash
curl -X POST http://localhost:3001/assess/full \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [
      "https://app.staging.company.com",
      "https://api.staging.company.com"
    ],
    "jira_project": "SEC",
    "email_recipients": ["security@company.com"]
  }'
```

**Response:**
```json
{
  "success": true,
  "findings_count": 12,
  "critical_count": 1,
  "high_count": 3,
  "report_url": "https://sharepoint.com/reports/2024-01-15.md",
  "jira_tickets": ["SEC-123", "SEC-124", "SEC-125", "SEC-126"]
}
```

### Cycode Validation

**Request:**
```bash
curl -X POST http://localhost:3001/assess/cycode-validate \
  -H "Content-Type: application/json" \
  -d '{
    "cycode_csv": "id,vulnerability_type,severity,file_path,line_number\nCYC-001,SQL Injection,HIGH,/api/users.py,42",
    "jira_project": "SEC"
  }'
```

### Code Scan

**Request:**
```bash
curl -X POST http://localhost:3001/assess/code-scan \
  -H "Content-Type: application/json" \
  -d '{
    "repo_paths": [
      "/mnt/host-home/projects/backend-api",
      "/mnt/host-home/projects/frontend"
    ],
    "severity_threshold": "medium"
  }'
```

---

## N8N Integration

### Import Workflows

1. Open N8N (http://localhost:5678)
2. Go to Workflows → Import
3. Import from `n8n/workflows/`:
   - `autonomous-full-assessment.json`
   - `autonomous-cycode-validation.json`

### Configure Workflows

**Full Assessment Workflow:**
1. Open the workflow
2. Edit "Define Targets" node
3. Update targets list with your applications
4. Update jira_project and email_recipients
5. Activate the workflow

**Cycode Validation Workflow:**
1. Import the workflow
2. Note the webhook URL
3. Configure Cycode to POST CSV exports to this URL
4. Activate the workflow

### Trigger Methods

| Method | How |
|--------|-----|
| Schedule | Cron expression in Schedule Trigger node |
| Webhook | POST to N8N webhook URL |
| Manual | Click "Execute Workflow" in N8N |
| API | `curl -X POST http://n8n:5678/webhook/...` |

---

## What Claude Does Autonomously

When triggered, Claude will:

### For Full Assessment:
1. ✅ Validate all targets are in scope
2. ✅ Run port scans on network targets
3. ✅ Enumerate subdomains for domain targets
4. ✅ Fingerprint discovered services
5. ✅ Run vulnerability scanners (nuclei, nikto)
6. ✅ Test web apps for injection vulnerabilities
7. ✅ Validate critical findings with targeted tests
8. ✅ Create finding records for all vulnerabilities
9. ✅ Generate comprehensive report
10. ✅ Create Jira tickets for HIGH/CRITICAL
11. ✅ Upload report to SharePoint
12. ✅ Send email notifications

### For Cycode Validation:
1. ✅ Parse CSV findings
2. ✅ Read source code context for each finding
3. ✅ Analyze vulnerability from code
4. ✅ Identify live endpoint
5. ✅ Craft targeted exploit
6. ✅ Execute validation test
7. ✅ Capture evidence
8. ✅ Create confirmed findings
9. ✅ Create Jira tickets
10. ✅ Generate validation report

---

## Configuration Summary

### What You Configure Once:

| File | What | Required |
|------|------|----------|
| `.env` | API keys, credentials | ✅ Yes |
| `config/scope.yml` | Allowed targets | ✅ Yes |
| `config/credentials.yml` | App authentication | For authenticated tests |
| N8N Workflows | Targets, schedules | ✅ Yes |

### OTP Authentication in Autonomous Mode

Applications using OTP (one-time password) authentication require user interaction and cannot run fully autonomously. For these apps:

**Option 1: Pre-authenticate via API**
Before starting the autonomous run, authenticate manually:
```bash
# Step 1: Initiate OTP (sends email)
curl -X POST http://localhost:3001/api/config/credentials/otp/initiate \
  -H "Content-Type: application/json" \
  -d '{"app_name": "secure-app"}'

# Step 2: Enter OTP code you received
curl -X POST http://localhost:3001/api/config/credentials/otp/verify \
  -H "Content-Type: application/json" \
  -d '{"app_name": "secure-app", "otp_code": "123456"}'

# Step 3: Now start autonomous assessment (session is cached for 1 hour)
curl -X POST http://localhost:3001/assess/full -d '{"targets": [...]}'
```

**Option 2: Use pending prompts API**
The autonomous runner will create a pending prompt when OTP is needed:
```bash
# Check for pending prompts
curl http://localhost:3001/api/config/prompts
# Returns: {"prompts": [{"id": "prompt_xxx", "type": "otp", "message": "..."}]}

# Submit OTP response
curl -X POST http://localhost:3001/api/config/prompts/prompt_xxx/respond \
  -H "Content-Type: application/json" \
  -d '{"value": "123456"}'
```

**Option 3: Exclude OTP apps from autonomous runs**
For fully hands-off automation, exclude OTP-authenticated apps and test them separately in interactive mode.

### What Runs Automatically:

| Component | Purpose | Port |
|-----------|---------|------|
| Kali Container | Executes security tools | - |
| MCP Server | Tool interface | 3000 |
| Autonomous Runner | Claude orchestration | 3001 |
| N8N | Workflow triggers | 5678 |

---

## Monitoring & Logs

### View Audit Logs
```bash
sqlite3 data/pentest.db "SELECT * FROM audit_logs WHERE user='autonomous-runner' ORDER BY timestamp DESC LIMIT 50"
```

### View Findings
```bash
sqlite3 data/pentest.db "SELECT * FROM findings ORDER BY created_at DESC"
```

### Docker Logs
```bash
docker logs kali-pentest -f
```

### Autonomous Runner Logs

The runner prints to stdout:
```
[Autonomous Runner] Starting full assessment
[Autonomous Runner] Iteration 1
[Autonomous Runner] Executing tool: scan_ports
[Autonomous Runner] Iteration 2
[Autonomous Runner] Executing tool: run_nuclei
...
```

---

## Safety Features

Even in autonomous mode, safety is enforced:

| Safety Feature | How It Works |
|----------------|--------------|
| Scope validation | Every target checked against scope.yml |
| Non-destructive only | Destructive exploits reported but not run |
| Iteration limit | Max 50 tool calls per assessment |
| Timeout | Configurable per N8N node |
| Audit logging | Every action logged to SQLite |

---

## Cost Considerations

Autonomous mode uses Claude API calls:

| Assessment Type | Estimated API Calls | Estimated Cost* |
|-----------------|---------------------|-----------------|
| Full (5 targets) | 20-40 | $0.50-1.00 |
| Recon only | 5-10 | $0.10-0.25 |
| Vuln scan | 10-20 | $0.25-0.50 |
| Code scan | 5-15 | $0.15-0.40 |
| Cycode validation (10 findings) | 15-30 | $0.40-0.80 |

*Estimates based on Claude Sonnet pricing. Actual costs vary.

---

## Troubleshooting

### "ANTHROPIC_API_KEY not set"
```bash
# Check .env has the key
grep ANTHROPIC_API_KEY .env

# Verify it's loaded
cd mcp-server && npm run start:autonomous
# Should NOT show the error
```

### "Connection refused on 3001"
```bash
# Make sure autonomous runner is running
npm run start:autonomous

# Check port
lsof -i :3001
```

### "Assessment timeout"

Increase timeout in N8N node:
- Full assessment: 3600000 (1 hour)
- Cycode validation: 1800000 (30 min)
- Others: 900000 (15 min)

### "Scope violation"

Target not in scope.yml. Add it:
```yaml
domains:
  - pattern: "your-target.com"
    environment: "staging"
```

---

## Quick Start Checklist

| Step | Action | Done |
|------|--------|------|
| 1 | Add `ANTHROPIC_API_KEY` to `.env` | ☐ |
| 2 | Configure `config/scope.yml` | ☐ |
| 3 | Configure `config/credentials.yml` | ☐ |
| 4 | `cd docker && docker-compose up -d` | ☐ |
| 5 | `cd mcp-server && npm install` | ☐ |
| 6 | `npm run build` | ☐ |
| 7 | Terminal 1: `npm start` | ☐ |
| 8 | Terminal 2: `npm run start:autonomous` | ☐ |
| 9 | Verify: `curl http://localhost:3001/health` | ☐ |
| 10 | Import N8N workflows | ☐ |
| 11 | Configure workflow targets | ☐ |
| 12 | Activate workflows | ☐ |
| 13 | 🎉 Fully automated! | ☐ |
