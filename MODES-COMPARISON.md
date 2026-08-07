# Kali MCP Pentest - Modes Comparison

This document compares the four operational modes available in the system.

---

## Quick Comparison

| Feature | Interactive | Agent Tools | N8N Direct | Autonomous |
|---------|-------------|-------------|------------|------------|
| Human in loop | ✅ Yes | ✅ Partial | ❌ No | ❌ No |
| AI reasoning | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| Adaptive | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| Scheduled | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| API costs | ❌ None | 💰 Yes | ❌ None | 💰 Yes |
| Complexity | Medium | Low | Low | High |
| Setup time | Quick | Quick | Medium | Longer |
| Invocation | CLI chat | MCP tools | N8N UI | HTTP API |

---

## Decision Tree
```
Do you need automation?
│
├── NO → Do you want AI to handle entire workflows?
│        │
│        ├── YES → Use AGENT TOOLS (via Interactive)
│        │         (run_recon_agent, run_orchestrator, etc.)
│        │
│        └── NO → Use INTERACTIVE MODE
│                 (You direct Claude tool-by-tool)
│
└── YES → Do you need AI decision-making?
          │
          ├── NO → Use N8N DIRECT MODE
          │        (Fixed workflows, no AI)
          │
          └── YES → Use AUTONOMOUS MODE
                    (Claude makes decisions via HTTP API)
```

---

## Mode Details

### Interactive Mode
```
┌──────────────────────────────────────┐
│         INTERACTIVE MODE             │
├──────────────────────────────────────┤
│ You ◀──▶ Claude Code CLI ──▶ Tools   │
│      conversation                    │
└──────────────────────────────────────┘
```

**Best for:**
- Learning the system
- Exploratory testing
- Complex investigations
- Training team members

**Start command:**
```bash
cd ~/Desktop/kali-mcp-pentest && claude
```

**Guide:** [INTERACTIVE-MODE.md](INTERACTIVE-MODE.md)

---

### Agent Tools Mode (NEW)
```
┌──────────────────────────────────────┐
│          AGENT TOOLS MODE            │
├──────────────────────────────────────┤
│ You ──▶ Claude Code ──▶ Agent Tool   │
│              │                       │
│              ▼                       │
│         Claude API                   │
│         (AI reasoning)               │
│              │                       │
│              ▼                       │
│         MCP Tools ──▶ Kali           │
└──────────────────────────────────────┘
```

**Best for:**
- Running complete workflows with one command
- Delegating decisions to AI within interactive session
- Combining AI autonomy with human oversight
- Quick full assessments

**Usage:**
```
You: Run the recon agent on 192.168.1.0/24
Claude: [executes run_recon_agent - AI handles the workflow]

You: Run a full assessment on staging.example.com
Claude: [executes run_orchestrator - all agents run sequentially]
```

**Available agent tools:**
- `run_orchestrator` - Full or selective multi-agent workflow
- `run_recon_agent` - Reconnaissance
- `run_vuln_scan_agent` - Vulnerability scanning
- `run_web_app_agent` - Web app testing
- `run_exploit_agent` - Exploit validation
- `run_security_scan_agent` - Code scanning
- `run_report_agent` - Report generation

**Requires:** `ANTHROPIC_API_KEY` in `.env`

---

### N8N Direct Mode
```
┌──────────────────────────────────────┐
│          N8N DIRECT MODE             │
├──────────────────────────────────────┤
│ N8N Workflow ──▶ MCP Server ──▶ Kali │
│ (fixed steps, no AI)                 │
└──────────────────────────────────────┘
```

**Best for:**
- Simple scheduled scans
- Compliance checks
- Fixed security gates
- Cost-conscious automation

**Start command:**
```bash
# Terminal 1
cd mcp-server && npm start

# Terminal 2
n8n start
```

**Guide:** [N8N-DIRECT-MODE.md](N8N-DIRECT-MODE.md)

---

### Autonomous Mode
```
┌──────────────────────────────────────┐
│         AUTONOMOUS MODE              │
├──────────────────────────────────────┤
│ N8N ──▶ Claude API ──▶ MCP ──▶ Kali  │
│         (AI reasoning)               │
└──────────────────────────────────────┘
```

**Best for:**
- Full security assessments
- Cycode validation
- Complex vulnerability testing
- Hands-off automation

**Start command:**
```bash
# Terminal 1
cd mcp-server && npm start

# Terminal 2
cd mcp-server && npm run start:autonomous

# Terminal 3
n8n start
```

**Guide:** [AUTONOMOUS-MODE.md](AUTONOMOUS-MODE.md)

---

## Cost Comparison

| Mode | Infrastructure | API Costs | Total (Monthly) |
|------|----------------|-----------|-----------------|
| Interactive | Docker, compute | $0 | ~$0 |
| N8N Direct | Docker, compute, N8N | $0 | ~$0 |
| Autonomous | Docker, compute, N8N | ~$20-100* | ~$20-100 |

*Autonomous API costs depend on usage frequency and assessment complexity.

---

## Setup Requirements by Mode

### Interactive Mode
- [ ] Docker + Kali container
- [ ] MCP server
- [ ] Claude Code CLI
- [ ] Scope/credentials configured

### N8N Direct Mode
- [ ] Docker + Kali container
- [ ] MCP server
- [ ] N8N installed
- [ ] Workflows configured
- [ ] Scope/credentials configured

### Autonomous Mode
- [ ] Docker + Kali container
- [ ] MCP server
- [ ] Autonomous runner
- [ ] N8N installed
- [ ] Anthropic API key
- [ ] Workflows configured
- [ ] Scope/credentials configured

---

## Recommended Usage

| Scenario | Recommended Mode |
|----------|------------------|
| First time using the system | Interactive |
| Quick full assessment with oversight | Agent Tools |
| Weekly scheduled scans | N8N Direct |
| Full penetration test (unattended) | Autonomous |
| Investigating a specific bug | Interactive |
| CI/CD security gate | N8N Direct |
| Validating Cycode findings | Autonomous |
| Training new team members | Interactive |
| Run complete recon workflow | Agent Tools |
| Compliance audit scans | N8N Direct |
| Pre-release security check | Agent Tools or Autonomous |
| Exploring new target | Interactive |
| Code scan with AI analysis | Agent Tools |

---

## Switching Between Modes

You can use multiple modes depending on the task:
```
Monday:    Autonomous full scan (scheduled)
Tuesday:   Interactive investigation of findings
Wednesday: N8N Direct quick compliance check
Thursday:  Autonomous Cycode validation
Friday:    Interactive deep-dive on critical bug
```

All modes share:
- Same Kali container
- Same MCP server
- Same scope configuration
- Same credentials
- Same findings database

---

## Quick Start by Mode

### Interactive (5 minutes)
```bash
cd docker && docker-compose up -d
cd ../mcp-server && npm start &
cd .. && claude
```

### N8N Direct (10 minutes)
```bash
cd docker && docker-compose up -d
cd ../mcp-server && npm start &
n8n start &
# Import workflows in N8N UI
```

### Autonomous (15 minutes)
```bash
cd docker && docker-compose up -d
cd ../mcp-server && npm start &
npm run start:autonomous &
n8n start &
# Add ANTHROPIC_API_KEY to .env
# Import workflows in N8N UI
```

---

*See individual mode guides for detailed instructions.*
