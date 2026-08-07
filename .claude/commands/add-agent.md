Scaffold a new MCP security agent. The user describes the agent via $ARGUMENTS.

Parse the description to determine:
1. **Agent name** (kebab-case for files, camelCase for class)
2. **Purpose** - what this agent does autonomously
3. **Tools** - which MCP tools this agent should have access to
4. **Workflow** - the autonomous decision-making steps

## Step 1: Agent implementation in `mcp-server/src/agents/<name>-agent.ts`

Follow the `base-agent.ts` pattern:

```typescript
/**
 * <Name> Agent
 *
 * <Description of what this agent does>
 */

import { BaseAgent, AgentConfig, AgentInput, AgentState, AgentFinding } from "./base-agent";

const <NAME>_CONFIG: AgentConfig = {
  name: "<name>",
  description: "<Description>",
  maxIterations: 15,
  timeoutMs: 10 * 60 * 1000, // 10 minutes
  requiresScopeValidation: true, // false for code-only agents
  tools: [
    // List the MCP tool names this agent can use
    "<tool_name>",
  ],
};

export class <Name>Agent extends BaseAgent {
  constructor() {
    super(<NAME>_CONFIG);
  }

  protected getSystemPrompt(input: AgentInput): string {
    return `You are a specialized <name> security agent. Your role is to <description>.

## Available Tools
${this.getToolDescriptions()}

## Instructions
1. <Step 1>
2. <Step 2>
3. <Step 3>

## Rules
- Always validate targets against scope
- Use non-destructive testing only
- Report findings with evidence

## Targets
${input.targets?.join("\n") || "No targets specified"}
`;
  }
}
```

Key patterns:
- Extend `BaseAgent` from `"./base-agent"`
- Define `AgentConfig` with name, tools, limits
- Override `getSystemPrompt()` for the agent's personality and instructions
- The base class handles: tool execution, state management, finding extraction, LLM calls

## Step 2: Agent tool in `mcp-server/src/tools/agent-tools.ts`

Add the tool definition to the `agentTools` array:

```typescript
{
  name: "run_<name>_agent",
  description: "Run the <name> agent. <What it does>.",
  inputSchema: {
    type: "object",
    properties: {
      targets: {
        description: "Targets to test",
        type: "array",
        items: { type: "string" },
      },
      // Add agent-specific params
    },
    required: ["targets"],
  },
},
```

Add the handler to `agentHandlers`:

```typescript
run_<name>_agent: async (args: { targets?: string[]; /* ... */ }) => {
  const agent = new <Name>Agent();
  const result = await agent.run({
    targets: args.targets,
    // map other args
  });
  return JSON.stringify(result, null, 2);
},
```

Import the agent at the top of `agent-tools.ts`:
```typescript
import { <Name>Agent } from "../agents/<name>-agent";
```

## Step 3: Create SKILL.md documentation

Create `skills/<name>/SKILL.md`:

```markdown
# <Name> Agent

## Purpose
<What this agent does>

## Capabilities
- <Capability 1>
- <Capability 2>

## Tools Used
| Tool | Purpose |
|------|---------|
| <tool> | <why> |

## Workflow
1. <Step 1>
2. <Step 2>
3. <Step 3>

## Configuration
- Max iterations: 15
- Timeout: 10 minutes
- Scope validation: required/not required

## Example Usage
```
Tool: run_<name>_agent
Arguments: { "targets": ["example.com"] }
```
```

## Step 4: Register in orchestrator

Edit `mcp-server/src/agents/orchestrator.ts` to include the new agent in the pipeline if appropriate. Add it to the agent registry and define where it fits in the workflow stages.

## Step 5: Update LOCAL_ONLY_TOOLS in `mcp-server/src/server.ts`

Add `"run_<name>_agent"` to the `LOCAL_ONLY_TOOLS` array (agents handle their own scope validation internally).

## After scaffolding

1. List all created/modified files
2. Note that MCP server needs rebuild: `cd mcp-server && npm run build`
3. Suggest testing with a simple target first

---

User request: $ARGUMENTS
