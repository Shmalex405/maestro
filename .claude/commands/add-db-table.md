Scaffold a new database table with full CRUD. The user describes the table via $ARGUMENTS.

Parse the description to determine:
1. **Table name** (snake_case, plural)
2. **Columns** - name, type, nullable, default
3. **Relationships** - foreign keys to existing tables

## Step 1: Rust struct in `frontend/src-tauri/src/database.rs`

Add the struct near the other model structs (before the `Database` impl block):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct <ModelName> {
    pub id: String,
    pub name: String,
    // ... other fields
    pub created_at: String,
    pub updated_at: String,
}
```

Type mapping:
- `TEXT` → `String`
- `TEXT NULL` → `Option<String>`
- `INTEGER` → `i32`
- `INTEGER NULL` → `Option<i32>`
- `REAL` → `f64`
- `REAL NULL` → `Option<f64>`
- `BOOLEAN` → `bool` (stored as INTEGER 0/1 in SQLite)
- `JSON` → `Option<serde_json::Value>` or `Vec<String>` (stored as TEXT)

## Step 2: CREATE TABLE in `initialize_schema()`

Add to the `initialize_schema` method in the `Database` impl:

```rust
self.conn.execute_batch("
    CREATE TABLE IF NOT EXISTS <table_name> (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        -- other columns
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
")?;
```

Conventions:
- `id TEXT PRIMARY KEY` — always use UUID string IDs
- `created_at` and `updated_at` with datetime defaults
- Foreign keys: `<ref>_id TEXT REFERENCES <table>(id)`
- Add indexes for frequently queried columns

## Step 3: CRUD methods on `Database` impl

Add these methods inside `impl Database { ... }`:

```rust
// List all
pub fn list_<table_name>(&self) -> Result<Vec<<ModelName>>> {
    let mut stmt = self.conn.prepare(
        "SELECT id, name, /* ... */ created_at, updated_at FROM <table_name> ORDER BY created_at DESC"
    )?;

    let items = stmt.query_map([], |row| {
        Ok(<ModelName> {
            id: row.get(0)?,
            name: row.get(1)?,
            // ... map columns
            created_at: row.get(N)?,
            updated_at: row.get(N+1)?,
        })
    })?.collect::<SqliteResult<Vec<_>>>()?;

    Ok(items)
}

// Get by ID
pub fn get_<singular>(&self, id: &str) -> Result<<ModelName>> {
    let item = self.conn.query_row(
        "SELECT id, name, /* ... */ created_at, updated_at FROM <table_name> WHERE id = ?1",
        params![id],
        |row| {
            Ok(<ModelName> {
                id: row.get(0)?,
                name: row.get(1)?,
                // ...
                created_at: row.get(N)?,
                updated_at: row.get(N+1)?,
            })
        },
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => AppError::NotFound(format!("<ModelName> not found: {}", id)),
        _ => AppError::Database(e),
    })?;

    Ok(item)
}

// Create
pub fn create_<singular>(&self, name: &str /* other params */) -> Result<<ModelName>> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    self.conn.execute(
        "INSERT INTO <table_name> (id, name, /* ... */ created_at, updated_at) VALUES (?1, ?2, /* ... */ ?N, ?N+1)",
        params![id, name, /* ... */ now, now],
    )?;

    self.get_<singular>(&id)
}

// Update
pub fn update_<singular>(&self, id: &str, name: &str /* other params */) -> Result<<ModelName>> {
    let now = Utc::now().to_rfc3339();

    let rows = self.conn.execute(
        "UPDATE <table_name> SET name = ?1, /* ... */ updated_at = ?N WHERE id = ?N+1",
        params![name, /* ... */ now, id],
    )?;

    if rows == 0 {
        return Err(AppError::NotFound(format!("<ModelName> not found: {}", id)));
    }

    self.get_<singular>(id)
}

// Delete
pub fn delete_<singular>(&self, id: &str) -> Result<()> {
    let rows = self.conn.execute(
        "DELETE FROM <table_name> WHERE id = ?1",
        params![id],
    )?;

    if rows == 0 {
        return Err(AppError::NotFound(format!("<ModelName> not found: {}", id)));
    }

    Ok(())
}
```

## Step 4: TypeScript interface in `frontend/lib/types.ts`

Add in an appropriate section:

```typescript
// =============================================================================
// <SECTION NAME> TYPES
// =============================================================================

export interface <ModelName> {
  id: string;
  name: string;
  // ... fields matching Rust struct
  created_at: string;
  updated_at: string;
}

export interface Create<ModelName>Params {
  name: string;
  // ... required creation fields (no id, no timestamps)
}

export interface Update<ModelName>Params {
  name?: string;
  // ... optional update fields
}
```

## After scaffolding

1. List all modified files
2. Remind user to create Tauri commands for the CRUD operations (point to `/project:add-command`)
3. Note that the DB schema auto-migrates on app start via `CREATE TABLE IF NOT EXISTS`

---

User request: $ARGUMENTS
