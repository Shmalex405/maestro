Display the database patterns reference for the Kali MCP Pentest project. Use this skill when you need to recall the SQLite schema and CRUD conventions.

Read and summarize patterns from `frontend/src-tauri/src/database.rs`, then present as quick-reference.

## File to Read
- `frontend/src-tauri/src/database.rs` — Full schema, structs, and CRUD methods

## Present These Patterns

### 1. Current Schema (Tables)

Read `initialize_schema()` and list all tables with their columns:
- `assessments` — Security assessment records
- `findings` — Vulnerability findings
- `reports` — Generated reports
- `audit_logs` — Tool execution audit trail
- `repositories` — Code repositories for scanning
- `imports` — Import batch records
- `imported_findings` — Findings from external sources
- `conversations` — Chat conversations
- `chat_messages` — Individual chat messages
- `projects` — Project groupings
- `templates` — Assessment prompt templates
- `assessment_chat_messages` — Assessment-specific chat persistence
- `terminal_sessions` — Terminal session records

### 2. Struct → Table Mapping

Show how each Rust struct maps to a database table:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,              // TEXT PRIMARY KEY
    pub assessment_id: Option<String>,  // TEXT (nullable FK)
    pub title: String,           // TEXT NOT NULL
    pub severity: String,        // TEXT NOT NULL
    // ...
}
```

### 3. Database::new() Pattern
```rust
pub fn new() -> Result<Self> {
    let db_path = Self::get_db_path()?;
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(&db_path)?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    let db = Self { conn };
    db.initialize_schema()?;
    Ok(db)
}
```

### 4. List Pattern (query_map)
```rust
pub fn list_items(&self) -> Result<Vec<Item>> {
    let mut stmt = self.conn.prepare(
        "SELECT col1, col2, ... FROM table ORDER BY created_at DESC"
    )?;
    let items = stmt.query_map([], |row| {
        Ok(Item {
            field1: row.get(0)?,
            field2: row.get(1)?,
        })
    })?.collect::<SqliteResult<Vec<_>>>()?;
    Ok(items)
}
```

### 5. Get Pattern (query_row)
```rust
pub fn get_item(&self, id: &str) -> Result<Item> {
    self.conn.query_row(
        "SELECT ... FROM table WHERE id = ?1",
        params![id],
        |row| Ok(Item { /* ... */ }),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows =>
            AppError::NotFound(format!("Item not found: {}", id)),
        _ => AppError::Database(e),
    })
}
```

### 6. Create Pattern
```rust
pub fn create_item(&self, name: &str) -> Result<Item> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    self.conn.execute(
        "INSERT INTO table (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, name, now, now],
    )?;
    self.get_item(&id)
}
```

### 7. Update Pattern
```rust
pub fn update_item(&self, id: &str, name: &str) -> Result<Item> {
    let now = Utc::now().to_rfc3339();
    let rows = self.conn.execute(
        "UPDATE table SET name = ?1, updated_at = ?2 WHERE id = ?3",
        params![name, now, id],
    )?;
    if rows == 0 {
        return Err(AppError::NotFound(format!("Item not found: {}", id)));
    }
    self.get_item(id)
}
```

### 8. Delete Pattern
```rust
pub fn delete_item(&self, id: &str) -> Result<()> {
    let rows = self.conn.execute("DELETE FROM table WHERE id = ?1", params![id])?;
    if rows == 0 {
        return Err(AppError::NotFound(format!("Item not found: {}", id)));
    }
    Ok(())
}
```

### 9. JSON Column Pattern
For array/object columns stored as TEXT:
```rust
// Writing: serialize to JSON string
let languages_json = serde_json::to_string(&languages)?;
// Reading: deserialize from JSON string
let languages: Vec<String> = row.get::<_, String>(N)?
    .split(',').map(String::from).collect();
// Or for proper JSON:
let value: serde_json::Value = serde_json::from_str(&row.get::<_, String>(N)?)?;
```

### 10. Migration Pattern (ALTER TABLE)
```rust
// In initialize_schema(), after CREATE TABLE:
let _ = self.conn.execute(
    "ALTER TABLE table ADD COLUMN new_col TEXT DEFAULT ''",
    [],
);
// Ignore error = column already exists in existing databases
```

### 11. DB Path Resolution
Priority: `DB_PATH` env → `config/database.yml` → `~/.pentest/data/pentest.db`
