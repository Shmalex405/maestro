Scaffold a new Tauri command end-to-end. The user describes what the command should do via $ARGUMENTS.

Parse the description to determine:
1. **Command name** (snake_case)
2. **Module** - which `commands/*.rs` file it belongs to (or create new module)
3. **Parameters** - input struct fields (if any)
4. **Return type** - what the command returns
5. **Description** - what it does

Then scaffold across ALL 5 files:

## Step 1: Rust Command (`frontend/src-tauri/src/commands/<module>.rs`)

Follow the exact pattern from `repos.rs`:

```rust
// If params needed, add a struct:
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct <Name>Params {
    pub field: Type,
}

// The command function:
#[tauri::command]
pub async fn <command_name>(/* params */) -> Result<ReturnType> {
    info!("Description: {:?}", params);

    let db = Database::new()?;
    // Implementation
}
```

Key patterns:
- Use `crate::database::Database` for DB access
- Use `crate::error::{AppError, Result}` for error handling
- Use `crate::mcp::McpClient` if MCP interaction needed
- Use `tracing::{info, debug, warn}` for logging
- All commands are `pub async fn` returning `Result<T>`

## Step 2: Register in `frontend/src-tauri/src/commands/mod.rs`

Add `pub mod <module>;` in **alphabetical order** among existing modules.
Only needed if creating a NEW module file.

## Step 3: Register in `frontend/src-tauri/src/main.rs`

Add to the `invoke_handler` macro inside the appropriate section comment block.
The sections are organized by domain:
- `// System status`
- `// Assessments`
- `// Findings`
- `// Reports`
- `// Config`
- `// Repositories`
- `// Projects`
- `// Tools (MCP)`
- `// Chat (LLM)`
- `// Conversations`
- `// Agents`
- `// Audit logs`
- `// Cloud sync`
- `// Terminal`
- `// Imports`

Format: `commands::<module>::<command_name>,`

## Step 4: TypeScript types in `frontend/lib/types.ts`

Add interfaces in the appropriate section (matching the `// === SECTION ===` comments):

```typescript
export interface <Name>Params {
  field: type;
}

export interface <Name>Result {
  field: type;
}
```

## Step 5: API bridge in `frontend/lib/tauri-api.ts`

Add to the appropriate section of the `api` object. Follow the dual-mode pattern:

```typescript
/** Description of what this does */
methodName: (params: ParamsType): Promise<ReturnType> =>
  isTauri()
    ? invoke('command_name', { params })
    : httpRequest('/api/endpoint', {
        method: 'POST',
        body: JSON.stringify(params),
      }),
```

Also add the type import at the top of the file in the appropriate import group.

## After scaffolding

1. Show a summary of all files modified
2. Remind the user to implement the actual logic in the Rust command body
3. Note if they need to add DB schema changes (point them to `/project:add-db-table`)

---

User request: $ARGUMENTS
