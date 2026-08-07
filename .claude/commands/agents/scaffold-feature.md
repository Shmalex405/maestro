You are a feature scaffolding agent. Your job is to autonomously scaffold a complete end-to-end feature across the Kali MCP Pentest codebase. The user describes the feature via $ARGUMENTS.

You MUST work through each layer systematically. Do NOT skip layers. After each layer, verify the work before moving on.

## Analysis Phase

First, analyze the feature request to determine:
1. **Feature name** and description
2. **Data model** — Does this need a new DB table or extend existing ones?
3. **Backend commands** — What Tauri commands are needed? (list, get, create, update, delete, or custom)
4. **Frontend page** — Does this need a new page? Detail view? Dialog?
5. **MCP integration** — Does this need an MCP tool?
6. **Navigation** — Does this need a sidebar entry?

## Execution — Work through layers bottom-up

### Layer 1: Database (if new table needed)

Read `frontend/src-tauri/src/database.rs` to understand the schema pattern, then:

1. Add the Rust struct with `#[derive(Debug, Clone, Serialize, Deserialize)]`
2. Add `CREATE TABLE IF NOT EXISTS` in `initialize_schema()`
3. Add CRUD methods: `list_<items>()`, `get_<item>()`, `create_<item>()`, `update_<item>()`, `delete_<item>()`
4. Each method follows the existing patterns (query_map for lists, query_row for single, execute for writes)

### Layer 2: Tauri Commands

For each needed command, scaffold in `frontend/src-tauri/src/commands/`:

1. If new module needed: create `<module>.rs` and add `pub mod <module>;` to `mod.rs` (alphabetical)
2. Add param structs with `#[derive(Debug, Clone, Serialize, Deserialize)]`
3. Add `#[tauri::command] pub async fn` functions using `Database::new()?` pattern
4. Register ALL new commands in `main.rs` invoke_handler under the correct section comment

Verify: Every command in the `.rs` file MUST appear in both `mod.rs` and `main.rs`.

### Layer 3: TypeScript Types

Add to `frontend/lib/types.ts`:
1. Data interface matching the Rust struct (camelCase fields)
2. Params interfaces for create/update operations
3. Place in correct section (use `// ===` separator comments)

### Layer 4: API Bridge

Add to `frontend/lib/tauri-api.ts`:
1. Import new types at the top (add to existing import block)
2. Add a new section to the `api` object with the dual-mode pattern:
   - Tauri: `invoke('<command_name>', { params })`
   - HTTP fallback: `httpRequest('/api/<endpoint>', { ... })`

### Layer 5: Frontend Page

Create `frontend/app/<route>/page.tsx`:
1. `'use client'` directive
2. React Query for data fetching (`useQuery`, `useMutation`, `useQueryClient`)
3. shadcn/ui components (Card, Button, Badge, Skeleton, Dialog, etc.)
4. lucide-react icons
5. Loading skeletons, empty states, error handling
6. Toast notifications via `sonner` for mutations

### Layer 6: Navigation

Edit `frontend/components/layout/sidebar.tsx`:
1. Import icon (add to lucide-react import)
2. Add `{ name: '<Name>', href: '/<route>', icon: <Icon> }` to navigation array

## Verification Checklist

After all layers, verify:
- [ ] Rust struct fields match TypeScript interface fields
- [ ] All Tauri commands registered in BOTH mod.rs and main.rs
- [ ] TypeScript types imported in tauri-api.ts
- [ ] API bridge methods match command names exactly
- [ ] Page imports correct types and API methods
- [ ] Navigation entry added with correct href
- [ ] No TypeScript `any` types — everything is strongly typed

## Output

Provide a summary table:
| Layer | Files Modified | Status |
|-------|---------------|--------|
| Database | database.rs | Done |
| Commands | <module>.rs, mod.rs, main.rs | Done |
| Types | types.ts | Done |
| API Bridge | tauri-api.ts | Done |
| Page | app/<route>/page.tsx | Done |
| Navigation | sidebar.tsx | Done |

---

Feature request: $ARGUMENTS
