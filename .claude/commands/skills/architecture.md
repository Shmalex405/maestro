Display the full system architecture reference for the Kali MCP Pentest project. Use this skill when you need to understand how components connect, data flows, or where to put new code.

Read project structure and key files, then present the architecture overview.

## Files to Scan
- `frontend/src-tauri/src/main.rs` — Tauri app entry, all command registrations
- `frontend/src-tauri/Cargo.toml` — Rust dependencies
- `frontend/package.json` — Frontend dependencies
- `mcp-server/package.json` — MCP server dependencies
- `docker-compose.yml` — Container orchestration
- `Dockerfile` — Kali image definition

## Present This Architecture

### System Layers

```
┌──────────────────────────────────────────────────┐
│  Frontend (Next.js + React)                       │
│  Port 3000 | shadcn/ui | React Query | Sonner    │
├──────────────────────────────────────────────────┤
│  API Bridge (tauri-api.ts)                        │
│  Tauri invoke() ←→ HTTP fallback                  │
├──────────────────────────────────────────────────┤
│  Tauri Backend (Rust)                             │
│  Commands | Database (SQLite) | MCP Client        │
├──────────────────────────────────────────────────┤
│  MCP Server (TypeScript, inside Kali container)   │
│  Port 3001 | Tools | Agents | Orchestrator        │
├──────────────────────────────────────────────────┤
│  Kali Linux Docker Container                      │
│  nmap | nuclei | sqlmap | metasploit | semgrep    │
└──────────────────────────────────────────────────┘
```

### Data Flow: User Action → Result

```
User clicks button
  → React component calls api.section.method()
    → tauri-api.ts checks isTauri()
      → If Tauri: invoke('command_name', { params })
        → Rust command in commands/<module>.rs
          → Database::new()? for DB ops
          → McpClient::new()? for MCP ops
            → HTTP POST to localhost:3001
              → MCP server dispatches to handler
                → executeInKali() runs tool in container
              → Returns JSON result
            → Rust parses JSON
          → Returns Result<T> to frontend
      → If Web: httpRequest('/api/endpoint')
        → Direct to MCP server HTTP API
```

### File Organization

```
kali-mcp-pentest/
├── frontend/
│   ├── app/                    # Next.js pages (file-based routing)
│   │   ├── page.tsx            # Dashboard
│   │   ├── assessments/        # Assessment pages
│   │   ├── findings/           # Findings pages
│   │   ├── repositories/       # Repo management
│   │   ├── reports/            # Report viewing
│   │   ├── config/             # Settings pages
│   │   ├── import/             # CSV import
│   │   └── audit-logs/         # Audit trail
│   ├── components/
│   │   ├── layout/             # Sidebar, startup-gate, system-status
│   │   └── ui/                 # shadcn/ui primitives
│   ├── lib/
│   │   ├── tauri-api.ts        # API bridge (THE central API file)
│   │   ├── types.ts            # ALL TypeScript types
│   │   └── utils.ts            # cn() helper
│   └── src-tauri/
│       └── src/
│           ├── main.rs          # App entry + all command registration
│           ├── commands/         # Tauri command modules
│           │   ├── mod.rs       # Module declarations
│           │   ├── system.rs    # Docker/system status
│           │   ├── assessments.rs
│           │   ├── findings.rs
│           │   ├── reports.rs
│           │   ├── repos.rs
│           │   ├── chat.rs
│           │   ├── config.rs
│           │   ├── agents.rs
│           │   ├── tools.rs     # MCP tool proxies
│           │   ├── terminal.rs
│           │   ├── imports.rs
│           │   ├── projects.rs
│           │   ├── cloud.rs
│           │   └── audit.rs
│           ├── database.rs      # SQLite schema + all CRUD
│           ├── docker.rs        # Docker management (bollard)
│           ├── error.rs         # AppError enum
│           ├── mcp.rs           # MCP HTTP client
│           ├── llm.rs           # LLM provider abstraction
│           └── state.rs         # Tauri app state
├── mcp-server/
│   └── src/
│       ├── server.ts            # MCP tool registration + dispatch
│       ├── tools/               # Tool definitions + handlers
│       ├── agents/              # AI agent implementations
│       │   ├── base-agent.ts
│       │   ├── orchestrator.ts
│       │   └── impl/           # Concrete agent classes
│       ├── utils/               # docker-exec, parsers
│       ├── scope/               # Scope validation
│       └── logging/             # Audit logger
├── config/                      # YAML configuration
│   ├── scope.yml
│   ├── credentials.yml
│   ├── tools.yml
│   └── llm-config.yml
├── skills/                      # Agent SKILL.md documentation
└── docker-compose.yml           # Container orchestration
```

### Key Dependencies

**Frontend**: Next.js 14, React 18, @tanstack/react-query, @tauri-apps/api, shadcn/ui, lucide-react, sonner
**Tauri**: bollard (Docker), rusqlite (SQLite), reqwest (HTTP), serde (JSON), uuid, tracing
**MCP Server**: @modelcontextprotocol/sdk, Playwright (browser), LLM providers

### Adding New Features — Where Code Goes

| What | Where |
|------|-------|
| New page | `frontend/app/<route>/page.tsx` |
| New UI component | `frontend/components/<feature>/` |
| New type | `frontend/lib/types.ts` |
| New API method | `frontend/lib/tauri-api.ts` |
| New Tauri command | `frontend/src-tauri/src/commands/<module>.rs` |
| New DB table | `frontend/src-tauri/src/database.rs` |
| New MCP tool | `mcp-server/src/tools/<category>.ts` |
| New agent | `mcp-server/src/agents/<name>-agent.ts` |
| New config | `config/<name>.yml` |
