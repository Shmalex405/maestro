Display the Rust codebase patterns reference for the Kali MCP Pentest project. Use this skill when you need to recall exact Rust conventions before writing backend code.

Read and summarize the key patterns from these files, then present them as a quick-reference:

## Files to Read
- `frontend/src-tauri/src/commands/repos.rs` — Reference Tauri command pattern
- `frontend/src-tauri/src/commands/mod.rs` — Module registration
- `frontend/src-tauri/src/main.rs` — invoke_handler registration
- `frontend/src-tauri/src/database.rs` — DB struct + CRUD pattern
- `frontend/src-tauri/src/error.rs` — Error types
- `frontend/src-tauri/src/mcp.rs` — MCP client usage

## Present These Patterns

### 1. Tauri Command Signature
```rust
#[tauri::command]
pub async fn command_name(params: ParamsStruct) -> Result<ReturnType> {
    info!("Doing thing: {:?}", params);
    let db = Database::new()?;
    // ... implementation
    Ok(result)
}
```

### 2. Param/Result Structs
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameParams {
    pub field: Type,
    pub optional_field: Option<Type>,
}
```

### 3. Database CRUD Pattern
- `list_*()` — `prepare()` + `query_map()` + `collect()`
- `get_*()` — `query_row()` with `NotFound` error mapping
- `create_*()` — `Uuid::new_v4()` + `execute()` + re-fetch
- `update_*()` — `execute()` + check rows affected
- `delete_*()` — `execute()` + check rows affected

### 4. Error Handling
- `AppError::NotFound` for missing records
- `AppError::Validation` for bad input
- `AppError::ContainerNotRunning` for MCP issues
- `AppError::Mcp` for MCP call failures
- Use `?` operator everywhere, never `.unwrap()`

### 5. Registration Checklist
1. Function in `commands/<module>.rs`
2. `pub mod <module>;` in `commands/mod.rs` (alphabetical)
3. `commands::<module>::<fn_name>,` in `main.rs` invoke_handler (correct section)

### 6. Imports Template
```rust
use crate::database::Database;
use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, debug, warn};
```

### 7. MCP Client Pattern (for container-backed commands)
```rust
let mcp = McpClient::new()?;
if !mcp.health_check().await.unwrap_or(false) {
    return Err(AppError::ContainerNotRunning);
}
let result = mcp.call_tool("tool_name", &params).await?;
```
