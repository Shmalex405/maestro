# Kali MCP Pentest - Frontend Dashboard Guide

This guide covers setting up and using the Next.js dashboard for the Kali MCP Pentest system.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Setup Guide](#setup-guide)
5. [Running the System](#running-the-system)
6. [Dashboard Usage Guide](#dashboard-usage-guide)
7. [API Reference](#api-reference)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The frontend dashboard provides a web interface for:
- **Launching security assessments** - Start scans with visual configuration
- **Real-time monitoring** - Watch assessment progress via Server-Sent Events
- **Findings management** - View, filter, and manage discovered vulnerabilities
- **Configuration** - Edit scope, credentials, and tool settings
- **Audit logs** - Review all tool executions

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Frontend      │────▶│   Backend API   │────▶│  Kali Docker    │
│   (Next.js)     │     │   (Express)     │     │   Container     │
│   Port 3000     │     │   Port 3001     │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌─────────────────┐
                        │   SQLite DB     │
                        │   (findings,    │
                        │    audit logs)  │
                        └─────────────────┘
```

---

## Prerequisites

Before setting up the frontend, ensure you have:

- [ ] Node.js 18+ installed (`node --version`)
- [ ] npm or yarn installed
- [ ] The MCP server set up (see [STEPS.md](./STEPS.md))
- [ ] Docker Desktop running (for Kali container)

---

## Quick Start

If you just want to get running quickly:

```bash
# Terminal 1: Start the backend API
cd mcp-server
npm install
npm run build
npm run start:autonomous

# Terminal 2: Start the frontend
cd frontend
npm install
npm run dev
```

Then open http://localhost:3000 in your browser.

---

## Setup Guide

### Step 1: Install Backend Dependencies

```bash
cd mcp-server
npm install
```

This installs:
- Express.js (API server)
- better-sqlite3 (database)
- Anthropic SDK (for autonomous mode)
- CORS support

### Step 2: Build the Backend

```bash
npm run build
```

This compiles TypeScript to JavaScript in the `dist/` folder.

### Step 3: Install Frontend Dependencies

```bash
cd ../frontend
npm install
```

This installs:
- Next.js 14 (React framework)
- TanStack Query (server state management)
- shadcn/ui components
- Tailwind CSS

### Step 4: Verify Setup

Check both directories have `node_modules`:

```bash
ls -la mcp-server/node_modules | head -5
ls -la frontend/node_modules | head -5
```

---

## Running the System

### Option A: Run Both Servers (Recommended)

**Terminal 1 - Backend API:**
```bash
cd mcp-server
npm run start:autonomous
```

Expected output:
```
Autonomous Runner API listening on port 3001
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

Expected output:
```
▲ Next.js 16.x.x
- Local: http://localhost:3000
✓ Ready in Xms
```

### Option B: Production Build

For production deployment:

```bash
# Build frontend
cd frontend
npm run build

# Start in production mode
npm run start
```

### Verify Everything is Running

Test the API:
```bash
curl http://localhost:3001/api/health
# Expected: {"status":"ok","timestamp":"..."}
```

Test the frontend:
```bash
curl -s http://localhost:3000 | head -20
# Expected: HTML content
```

---

## Dashboard Usage Guide

### Home Dashboard (`/`)

The dashboard overview shows:

| Section | Description |
|---------|-------------|
| **System Status** | Health of backend API and Kali container |
| **Quick Stats** | Total findings by severity |
| **Recent Assessments** | Last 5 assessments with status |
| **Critical Findings** | High-priority items needing attention |

**Actions:**
- Click "New Assessment" to start a scan
- Click any assessment to view details
- Click any finding to see full information

---

### Assessments (`/assessments`)

#### Viewing Assessments

The assessments list shows:
- **Status**: pending, running, completed, failed, cancelled
- **Type**: full, recon, vuln_scan, web_app, code_scan
- **Progress**: Percentage complete (for running assessments)
- **Findings**: Count of discovered vulnerabilities
- **Duration**: Time taken or elapsed

#### Launching a New Assessment (`/assessments/new`)

1. **Select Assessment Type:**

   | Type | Description |
   |------|-------------|
   | **Full Assessment** | Complete security audit (recon → vuln scan → web app → exploit validation) |
   | **Reconnaissance** | Network discovery, port scanning, subdomain enumeration |
   | **Vulnerability Scan** | Nuclei, Nikto, and exploit database searches |
   | **Web Application** | SQL injection, XSS, directory fuzzing |
   | **Code Scan** | SAST, secrets detection, dependency vulnerabilities |

2. **Enter Targets:**
   - For network scans: IP addresses, CIDR ranges, or hostnames
   - For code scans: Repository paths (e.g., `/mnt/host-home/projects/my-app`)

   > Targets are validated against your scope configuration

3. **Optional Settings:**
   - **Credentials**: Select app credentials for authenticated testing
   - **Jira Project**: Auto-create tickets for findings
   - **Severity Threshold**: Minimum severity to report (low/medium/high/critical)

4. **Click "Launch Assessment"**

#### Monitoring a Running Assessment (`/assessments/[id]`)

The real-time monitoring page shows:
- **Progress bar** with percentage
- **Current step** being executed
- **Timeline** of completed steps
- **Live findings** as they're discovered
- **Logs** from tool execution

The page uses Server-Sent Events (SSE) for live updates without refreshing.

---

### Findings (`/findings`)

#### Filtering Findings

Use the filter controls to narrow results:

| Filter | Options |
|--------|---------|
| **Severity** | Critical, High, Medium, Low, Info |
| **Status** | Open, In Progress, Remediated, Accepted |
| **Search** | Free text search in title/description |

Click severity cards at the top to quick-filter by severity.

#### Managing Findings

**Change Status:**
- Use the dropdown in the table row to update status
- Status changes are saved immediately

**Export Findings:**
- Click "Export" button
- Choose format: JSON, CSV, or Markdown
- File downloads automatically

#### Finding Details (`/findings/[id]`)

The detail page shows:
- **Severity badge** and title
- **Description** of the vulnerability
- **Evidence** (code snippets, tool output)
- **Remediation** guidance
- **Metadata**: CVE, target, dates, IDs

**Actions:**
- **Create Jira Ticket**: Opens dialog to select project
- **Update Status**: Change remediation status
- **Copy Evidence**: Copy raw evidence to clipboard
- **Delete**: Remove finding (with confirmation)

---

### Configuration (`/config`)

#### Scope Configuration (`/config/scope`)

Manage what targets are allowed for testing:

**Networks:**
```yaml
- cidr: 10.0.0.0/8
  environment: internal
  notes: Internal network
```

**Domains:**
```yaml
- pattern: "*.staging.company.com"
  environment: staging
```

**Exclusions:**
```yaml
- pattern: "prod.company.com"
  reason: Production environment
```

> Changes require editing `config/scope.yml` directly

#### Credentials (`/config/credentials`)

View configured application credentials:
- Application name
- Environment (staging/production)
- Auth type (session, basic, bearer, oauth2, api_key)
- Base URL

> Credentials are stored in `config/credentials.yml` with sensitive values

#### Tools & Agents (`/config/tools`)

**Tools Tab:**
Shows all 27 available security tools grouped by category:
- Recon (nmap, subdomain enum, etc.)
- Vuln Scanner (nuclei, nikto, wpscan)
- Web App (sqlmap, xss testing, fuzzing)
- Exploit (metasploit, CVE validation)
- Code Scan (semgrep, bandit, secrets)
- Reporting (findings, reports, Jira)

**Agents Tab:**
Shows agent configuration:
- Enabled/disabled status
- Auto-start setting
- Approval requirements
- Timeout settings

---

### Audit Logs (`/audit-logs`)

View all tool executions:

| Column | Description |
|--------|-------------|
| **Timestamp** | When the tool was executed |
| **Tool** | Which tool was run |
| **Target** | What was scanned |
| **Status** | Success/failure |
| **Duration** | Execution time |

Use filters to search by:
- Tool name
- Target
- Date range

---

## API Reference

The backend exposes these REST endpoints:

### Health & System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/system/status` | Container & DB status |
| GET | `/api/system/tools` | List available tools |

### Assessments
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/assessments` | List assessments |
| GET | `/api/assessments/:id` | Get assessment details |
| POST | `/api/assessments` | Create new assessment |
| DELETE | `/api/assessments/:id` | Cancel assessment |
| GET | `/api/assessments/:id/events` | SSE event stream |

### Findings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/findings` | List findings (with filters) |
| GET | `/api/findings/:id` | Get finding details |
| PATCH | `/api/findings/:id` | Update finding |
| DELETE | `/api/findings/:id` | Delete finding |
| POST | `/api/findings/:id/jira` | Create Jira ticket |
| GET | `/api/findings/stats` | Severity/status counts |
| GET | `/api/findings/export` | Export findings |

### Configuration
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config/scope` | Get scope config |
| PUT | `/api/config/scope` | Update scope config |
| POST | `/api/config/scope/validate` | Validate target |
| GET | `/api/config/credentials` | Get credentials (masked) |
| GET | `/api/config/tools` | Get tool settings |
| GET | `/api/config/agents` | Get agent settings |

### Audit Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit-logs` | Query audit logs |

---

## Troubleshooting

### Frontend won't start

**Error: `Module not found`**
```bash
cd frontend
rm -rf node_modules
npm install
```

**Error: Port 3000 in use**
```bash
# Find and kill process on port 3000
lsof -i :3000
kill -9 <PID>
```

### Backend won't start

**Error: `Cannot find module 'dist/...'`**
```bash
cd mcp-server
npm run build
```

**Error: `better-sqlite3` compilation failed**
```bash
# Ensure you have Xcode CLI tools
xcode-select --install

# Try reinstalling
rm -rf node_modules
npm install
```

**Error: Port 3001 in use**
```bash
lsof -i :3001
kill -9 <PID>
```

### API Connection Failed

**Frontend shows "Failed to fetch"**

1. Verify backend is running:
   ```bash
   curl http://localhost:3001/api/health
   ```

2. Check CORS settings in `mcp-server/src/autonomous-runner.ts`

3. Verify frontend is using correct API URL:
   ```bash
   # Should be http://localhost:3001
   grep NEXT_PUBLIC_API_URL frontend/.env*
   ```

### Database Issues

**Error: `SQLITE_CANTOPEN`**
```bash
# Ensure data directory exists
mkdir -p mcp-server/data

# Check permissions
ls -la mcp-server/data
```

**Reset database:**
```bash
rm mcp-server/data/pentest.db
# Database will be recreated on next start
```

### Assessment Not Starting

1. Check Kali container is running:
   ```bash
   docker ps | grep kali
   ```

2. Start container if needed:
   ```bash
   docker-compose up -d
   ```

3. Verify MCP connection in backend logs

---

## Related Documentation

- [STEPS.md](./STEPS.md) - Core system setup
- [AUTONOMOUS-MODE.md](./AUTONOMOUS-MODE.md) - Autonomous assessment mode
- [CLAUDE.md](./CLAUDE.md) - Claude Code integration guide
- [MODES-COMPARISON.md](./MODES-COMPARISON.md) - Comparison of operating modes
