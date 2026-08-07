# Architecture — what runs where

A short tour of how the pieces fit together, so you know what's local, what's cloud, and where to look when something breaks.

> [!NOTE] At a glance
> - **Scans run on your machine** — the Kali container executes every tool locally. Traffic never detours through the cloud just to run a port scan.
> - **Data lives in your org's cloud** — assessments, findings, reports, and projects are stored per-org and shared with teammates.
> - **The bridge** — the desktop app writes your live login token to a file the container reads, so the in-container tools can save findings to the cloud.

## The big picture

```
  Your Mac                                  Your org's cloud
  ┌──────────────────────────┐              ┌──────────────────────┐
  │ Maestro desktop app      │              │  FastAPI/axum backend│
  │  ├── Next.js UI          │   HTTPS      │  └── Postgres        │
  │  └── Tauri Rust shell    │ ───────────▶ │     (assessments,    │
  │                          │   JWT auth   │      findings,       │
  │ Kali Docker container    │              │      reports, etc.)  │
  │  ├── MCP HTTP :3001      │              │                      │
  │  ├── Tools (nmap, nuclei │              └──────────────────────┘
  │  │         sqlmap, etc.) │
  │  └── tmux + claude       │
  │                          │
  │ ~/.kali-mcp-pentest/     │
  │  ├── cloud-session.json  │ (your live JWT, refreshed by the
  │  ├── mcp-server/         │  desktop app every 15 min)
  │  └── reports/            │
  └──────────────────────────┘
```

## What runs locally

| Piece | What it does | Why local |
| --- | --- | --- |
| **Kali Docker container** | Runs every security tool: nmap, nuclei, sqlmap, semgrep, bandit, gitleaks, Metasploit. | So you can test internal IPs, localhost, or air-gapped targets without exposing them to the internet. |
| **Tmux sessions** | Back the in-app terminal pane. | Live terminal state is yours alone — teammates see only the findings you persist. |
| **MCP HTTP server (:3001)** | The chat panel calls it when you ask claude to "run a scan". Runs inside the container. | Bundled with the app (~5 MB JS + a one-time `npm install`, ~3 min on first launch). |
| **Cognito tokens** | Your identity. Stored in browser localStorage + `cloud-session.json`. | Your refresh token never leaves your machine. |

## What lives in the cloud

- **All persisted data** — assessments, findings, reports, projects, imports, audit logs, scan snapshots, repository metadata.
- **Per-org backend** — each org has its own deployment (e.g. `groovy.maestro.groovysec.com`).
- **Discovery** — first launch maps your email domain → backend URL → Cognito pool via `/api/discover`. No hardcoded URL list ships in the app.

> [!IMPORTANT] Tenancy is enforced at the token level
> Every request carries a JWT with an `org_id` claim. The backend checks it against its own `ALLOWED_ORG_ID` on every call — so a user signed into Org A physically cannot read Org B's data, even with a stolen token.

## What's hybrid

**Repositories** are split: the *metadata* (`name`, `description`, `languages`, `created_by_user_id`) is cloud, but the *path* is per-machine. Alice's Mac has `/Users/alice/work/foo`; Bob's has `/Users/bob/dev/foo`. Both see the same repo entry; each maps it to their own local clone.

**Cycode / CSV imports** — the raw CSV is uploaded to cloud, parsed into structured findings, and both the parsed findings and the original CSV are kept on the import record.

## Where each action writes

| Action | Writes to |
| --- | --- |
| Click "Create Assessment" in the UI | Cloud DB (`POST /api/v1/assessments`) |
| Update a finding's status | Cloud DB (`PATCH /api/v1/findings/:id`) |
| `create_finding` MCP tool during a scan | Cloud DB, via the bridge file |
| Generate a PDF report | Local file in `~/.kali-mcp-pentest/reports/`; metadata to cloud |
| Run a scanner (nmap, etc.) | Local execution; structured output flows back to MCP → cloud as findings |

> [!TIP] How the container reaches the cloud
> The **bridge file** at `~/.kali-mcp-pentest/cloud-session.json` holds your live JWT. The desktop app rewrites it every 15 minutes; the MCP server (inside the container) reads it on each cloud write. No keys are ever baked into the container image.

## What is NOT shared across your org

- Your terminal pane and tmux sessions
- Your Kali container state (each user has their own)
- Your local repo paths
- Your personal integration tokens (Jira, GitHub — org-shared config is cloud-routed, but personal credentials stay local)
- Your Cognito refresh token

## Troubleshooting

> [!WARNING] Login fails on first launch
> Check that the discovery endpoint is reachable from your network. The error names the step that failed — DNS resolution, Cognito challenge, or token storage.

**Dashboard shows old data after sign-in.** Likely a token issue. Open DevTools (`Cmd+Opt+I`) → Console:
```js
JSON.parse(localStorage.getItem('maestro-bootstrap'))
```
If `backendUrl` is missing or wrong, discovery didn't complete. Sign out and back in to re-run it.

**"MCP Server: Offline" on the dashboard.** The in-container HTTP server isn't responding. Open the System Status popover (bottom-left) and click **Stop + Start** on the Kali Container. First launch can take 3–4 min for the in-container `npm install`.

**Assessment writes fail with 401 / "Cloud session expired".** Your JWT aged out and refresh failed. Sign back in — your refresh token may have been revoked from the Cognito side (e.g. an admin password reset).

## For developers — where the source lives

| Component | Path |
| --- | --- |
| Desktop UI | `frontend/` (Next.js + React) |
| Desktop Rust shell | `frontend/src-tauri/` (Tauri 2) |
| Cloud backend | `backend-rs/` (Rust; `backend-legacy/` is the deprecated Python original) |
| MCP server | `mcp-server/` (TypeScript; runs locally + inside the container) |
| Kali Docker image | `docker/Dockerfile.kali` |
| Slash commands & agents | `.claude/commands/` and `.claude/agents/` |
| Per-org cloud infra | `kali-mcp-pentest-infra/` (separate repo — Terraform + ECS) |
