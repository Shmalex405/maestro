Scaffold a new MCP server tool. The user describes the tool via $ARGUMENTS.

Parse the description to determine:
1. **Tool name** (snake_case)
2. **Category** - which `tools/<category>.ts` file (recon, vuln-scan, web-app, exploit, code-scan, reporting, browser, code-intel, interactive) or create new
3. **Parameters** - inputSchema properties
4. **What it does** - handler implementation outline
5. **Scope-exempt?** - Does it operate on local files only?

## Step 1: Tool definition + handler in `mcp-server/src/tools/<category>.ts`

Follow the exact pattern from `recon.ts`:

### Tool definition (add to the tools array):

```typescript
{
  name: "<tool_name>",
  description: "<Description of what this tool does.>",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "Target description" },
      option: { type: "string", description: "Option description", default: "default_value" },
    },
    required: ["target"],
  },
},
```

### Handler (add to the handlers object):

```typescript
<tool_name>: async (args: { target: string; option?: string }) => {
  const { target, option = "default_value" } = args;

  const command = `<kali-tool> ${target}`;
  const output = await executeInKali(command);

  return JSON.stringify({
    target,
    // parsed results
  }, null, 2);
},
```

Key patterns:
- Import `executeInKali` from `"../utils/docker-exec"` for commands that run in the Kali container
- Handler must return a string (JSON.stringify for structured data)
- Use existing parsers from `"../utils/parser"` if applicable
- Tool arrays are exported as `<category>Tools`
- Handler objects are exported as `<category>Handlers`

## Step 2: Register in `mcp-server/src/server.ts`

If creating a NEW category file, add imports and spread into allTools/allHandlers:

```typescript
import { <category>Tools, <category>Handlers } from "./tools/<category>";

export const allTools = [
  // ... existing
  ...<category>Tools,
];

export const allHandlers: Record<string, Function> = {
  // ... existing
  ...<category>Handlers,
};
```

If adding to an EXISTING category, just add to its tools array and handlers object — no server.ts changes needed.

## Step 3: Update LOCAL_ONLY_TOOLS (if scope-exempt)

If this tool operates only on local files (no network targets), add it to the `LOCAL_ONLY_TOOLS` array in `mcp-server/src/server.ts`:

```typescript
export const LOCAL_ONLY_TOOLS = [
  // ... existing
  "<tool_name>",
];
```

## Conventions

- Tool names are snake_case
- Descriptions should be one clear sentence
- inputSchema follows JSON Schema
- `required` array lists mandatory parameters
- Handlers destructure args with defaults for optional params
- Always handle errors gracefully (try/catch in handler)
- Return structured JSON strings from handlers

## After scaffolding

1. List all created/modified files
2. Note if MCP server needs rebuild (`cd mcp-server && npm run build`)
3. If the tool needs a Kali package, note that the Dockerfile may need updating

---

User request: $ARGUMENTS
