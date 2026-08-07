Display the MCP server codebase patterns reference for the Kali MCP Pentest project. Use this skill when you need to recall how tools, agents, and the orchestrator are structured.

Read and summarize patterns from these files, then present as quick-reference:

## Files to Read
- `mcp-server/src/server.ts` — Tool registration, scope validation, handler dispatch
- `mcp-server/src/tools/recon.ts` — Reference tool pattern
- `mcp-server/src/tools/agent-tools.ts` — Agent tool registration
- `mcp-server/src/agents/base-agent.ts` — BaseAgent class
- `mcp-server/src/agents/orchestrator.ts` — Multi-agent orchestration
- `mcp-server/src/utils/docker-exec.ts` — Kali container execution

## Present These Patterns

### 1. Tool Definition
```typescript
export const categoryTools = [
  {
    name: "tool_name",
    description: "What this tool does.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target IP or hostname" },
        option: { type: "string", description: "Option", default: "value" },
      },
      required: ["target"],
    },
  },
];
```

### 2. Tool Handler
```typescript
export const categoryHandlers: Record<string, Function> = {
  tool_name: async (args: { target: string; option?: string }) => {
    const { target, option = "default" } = args;
    const command = `kali-tool ${target}`;
    const output = await executeInKali(command);
    return JSON.stringify(parsedResult, null, 2);
  },
};
```

### 3. Server Registration (`server.ts`)
```typescript
import { categoryTools, categoryHandlers } from "./tools/category";

export const allTools = [...existingTools, ...categoryTools];
export const allHandlers = { ...existingHandlers, ...categoryHandlers };

// Scope-exempt tools
export const LOCAL_ONLY_TOOLS = ["scan_repository", /* ... */];
```

### 4. BaseAgent Pattern
```typescript
class MyAgent extends BaseAgent {
  constructor(toolHandlers, onProgress?) {
    super(config, toolHandlers, onProgress);
  }
  abstract getToolDefinitions(): ToolDefinition[];
  abstract buildInitialPrompt(input: AgentInput): string;
  abstract getSystemPrompt(): string;
}
```

### 5. Agent Config
```typescript
const AGENT_CONFIG: AgentConfig = {
  name: "agent-name",
  description: "What this agent does",
  maxIterations: 15,
  timeoutMs: 10 * 60 * 1000,
  requiresScopeValidation: true,
  tools: ["tool1", "tool2"],
};
```

### 6. Orchestrator Workflows
- `FULL_WORKFLOW`: recon → vuln-scan → web-app → exploit → qa → report
- `CODE_WORKFLOW`: security-scan → qa → report
- `PIPELINED_STAGES`: recon → [vuln-scan + web-app parallel] → exploit → qa → report

### 7. Docker Execution
```typescript
import { executeInKali } from "../utils/docker-exec";
const output = await executeInKali("nmap -sV target");
```

### 8. Scope Validation Flow
- `server.ts` extracts target from args
- Checks if tool is in `LOCAL_ONLY_TOOLS` — skip validation if so
- Calls `validateScope(target)` from `scope/validator.ts`
- Returns `SCOPE VIOLATION` error if out of scope

### 9. Agent Tool Pattern
```typescript
// In agent-tools.ts
run_my_agent: async (args) => {
  const agent = new MyAgent(allHandlers);
  const result = await agent.execute({ targets: args.targets });
  return JSON.stringify(result, null, 2);
},
```

### 10. File Organization
```
mcp-server/src/
├── server.ts          # Tool registration + dispatch
├── tools/             # Tool definitions + handlers
│   ├── recon.ts
│   ├── vuln-scan.ts
│   ├── web-app.ts
│   ├── exploit.ts
│   ├── code-scan.ts
│   ├── reporting.ts
│   ├── browser.ts
│   ├── code-intel.ts
│   ├── interactive.ts
│   └── agent-tools.ts
├── agents/            # AI-driven agents
│   ├── base-agent.ts
│   ├── orchestrator.ts
│   ├── checkpoint-manager.ts
│   └── impl/          # Agent implementations
├── utils/             # Shared utilities
│   ├── docker-exec.ts
│   └── parser.ts
├── scope/             # Scope validation
│   └── validator.ts
└── logging/           # Audit logging
    └── audit-logger.ts
```
