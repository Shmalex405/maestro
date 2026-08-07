You are an API scaffolding agent. Your job is to scaffold a complete API layer — a Tauri backend command paired with its MCP tool counterpart. The user describes the endpoint via $ARGUMENTS.

This is for features where data flows: **Frontend → Tauri command → MCP server tool → Kali container**.

## Analysis Phase

Determine:
1. **Operation name** (snake_case)
2. **Input parameters** — what the caller sends
3. **Output type** — what gets returned
4. **Execution context** — Does this run in Kali container (MCP tool) or Rust only?
5. **Scope requirement** — Does the MCP tool need scope validation?

## Layer 1: MCP Tool (if runs in Kali)

In `mcp-server/src/tools/<category>.ts`:

1. Add tool definition to the tools array:
```typescript
{
  name: "<tool_name>",
  description: "<description>",
  inputSchema: {
    type: "object",
    properties: { /* ... */ },
    required: ["<required_fields>"],
  },
},
```

2. Add handler to the handlers object:
```typescript
<tool_name>: async (args: { /* typed args */ }) => {
  const command = `<kali-command>`;
  const output = await executeInKali(command);
  return JSON.stringify(/* parsed result */, null, 2);
},
```

3. If scope-exempt, add to `LOCAL_ONLY_TOOLS` in `mcp-server/src/server.ts`

## Layer 2: Tauri Command

In `frontend/src-tauri/src/commands/<module>.rs`:

1. Add param struct (if needed):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct <Name>Params { /* fields */ }
```

2. Add command function:
```rust
#[tauri::command]
pub async fn <command_name>(params: <Name>Params) -> Result<ReturnType> {
    info!("Running <command_name>");
    // For MCP-backed commands:
    let mcp = McpClient::new()?;
    if !mcp.health_check().await.unwrap_or(false) {
        return Err(AppError::ContainerNotRunning);
    }
    let result = mcp.call_tool("<tool_name>", &params).await?;
    Ok(result)
}
```

3. Register in `mod.rs` (if new module) and `main.rs` invoke_handler

## Layer 3: TypeScript Types

In `frontend/lib/types.ts`:
- Add `<Name>Params` interface
- Add `<Name>Result` interface

## Layer 4: API Bridge

In `frontend/lib/tauri-api.ts`:
- Import types
- Add method to appropriate `api.*` section:
```typescript
<methodName>: (params: <Name>Params): Promise<<Name>Result> =>
  isTauri()
    ? invoke('<command_name>', { params })
    : httpRequest('/api/<endpoint>', {
        method: 'POST',
        body: JSON.stringify(params),
      }),
```

## Verification

- [ ] MCP tool name matches what Tauri command calls via `mcp.call_tool()`
- [ ] Parameter names match across all layers (Rust snake_case ↔ TS camelCase via serde)
- [ ] Return types are compatible across MCP JSON → Rust → TypeScript
- [ ] Command registered in main.rs
- [ ] Types exported from types.ts and imported in tauri-api.ts

---

API endpoint request: $ARGUMENTS
