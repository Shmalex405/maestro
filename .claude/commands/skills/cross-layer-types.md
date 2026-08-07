Display the cross-layer type mapping reference. Use this skill when you need to ensure types are consistent across Rust, TypeScript, and MCP tool schemas.

Read `types.ts`, `database.rs`, and key command files, then present the mapping.

## Files to Read
- `frontend/lib/types.ts` — TypeScript interfaces
- `frontend/src-tauri/src/database.rs` — Rust structs
- `frontend/src-tauri/src/commands/repos.rs` — Command param structs
- `mcp-server/src/tools/recon.ts` — MCP inputSchema

## Present These Mappings

### Rust ↔ TypeScript Type Mapping

| Rust | TypeScript | SQLite | Notes |
|------|-----------|--------|-------|
| `String` | `string` | `TEXT` | |
| `Option<String>` | `string?` or `string \| undefined` | `TEXT NULL` | |
| `i32` | `number` | `INTEGER` | |
| `Option<i32>` | `number?` | `INTEGER NULL` | |
| `f64` | `number` | `REAL` | |
| `bool` | `boolean` | `INTEGER` | 0/1 in SQLite |
| `Vec<String>` | `string[]` | `TEXT` | JSON-serialized |
| `serde_json::Value` | `Record<string, unknown>` | `TEXT` | JSON string |
| `Option<Vec<String>>` | `string[]?` | `TEXT NULL` | |

### Serde Naming Convention

Rust uses `snake_case`, TypeScript uses `camelCase`. Serde handles this automatically for Tauri commands, but be aware:

```rust
// Rust struct
pub struct Assessment {
    pub assessment_type: String,  // Serialized as "assessment_type"
    pub created_at: String,       // Serialized as "created_at"
}
```

```typescript
// TypeScript — field names match the serialized JSON (snake_case)
interface Assessment {
  assessment_type: string;  // NOT assessmentType
  created_at: string;       // NOT createdAt
}
```

**Important**: This project uses snake_case in TypeScript to match Rust serialization. Do NOT convert to camelCase unless using `#[serde(rename_all = "camelCase")]`.

Exception: Some types use `#[serde(rename)]` for specific fields:
```rust
#[serde(rename = "type")]
pub assessment_type: String,  // Serialized as "type" in JSON
```

### Core Entity Type Map

**Assessment**
- Rust: `database::Assessment`
- TS: `types.ts → Assessment`
- Table: `assessments`

**Finding**
- Rust: `database::Finding`
- TS: `types.ts → Finding`
- Table: `findings`

**Repository**
- Rust: `database::Repository`
- TS: `types.ts → Repository`
- Table: `repositories`

**Report**
- Rust: `database::Report`
- TS: `types.ts → Report`
- Table: `reports`

**Project**
- Rust: `database::Project`
- TS: `types.ts → Project`
- Table: `projects`

**Conversation**
- Rust: `database::Conversation`
- TS: `types.ts → Conversation`
- Table: `conversations`

### MCP Tool Schema → TypeScript → Rust

MCP tools use JSON Schema for input:
```typescript
// MCP inputSchema (JSON Schema)
{
  type: "object",
  properties: {
    target: { type: "string" },
    ports: { type: "string", default: "1-1000" },
  },
  required: ["target"],
}

// Corresponding TypeScript params
interface ScanPortsParams {
  target: string;
  ports?: string;  // Optional because not in required[]
}

// Corresponding Rust params (in commands/tools.rs)
#[derive(Deserialize)]
pub struct ScanPortsParams {
    pub target: String,
    pub ports: Option<String>,
}
```

### Common Gotchas

1. **`Option<T>` fields in Rust** — Must be `?` or `| undefined` in TypeScript
2. **`Vec<String>` in Rust** — Stored as comma-separated TEXT in SQLite, parsed on read
3. **`#[serde(rename = "type")]`** — `assessment_type` field serializes as `type` in JSON
4. **Enum types** — Rust uses String, TypeScript uses union types (`'open' | 'closed'`)
5. **Timestamps** — Always RFC3339 strings, never Date objects
6. **IDs** — Always UUID v4 strings, generated in Rust via `Uuid::new_v4().to_string()`
