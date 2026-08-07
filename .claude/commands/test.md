Run tests for the Kali MCP Pentest project.

$ARGUMENTS specifies what to test. If empty, run all tests.

Valid scopes:
- `frontend` — Run frontend tests (Vitest)
- `mcp` — Run MCP server tests (Jest)
- `rust` — Run Rust backend tests (cargo test)
- `coverage` — Run all tests with coverage reports
- `<file-path>` — Run tests for a specific file
- `all` or empty — Run everything

## Frontend Tests (Vitest)

```bash
cd ${CLAUDE_PROJECT_DIR}/frontend
npx vitest run
```

For a specific file:
```bash
npx vitest run <file-path>
```

For coverage:
```bash
npx vitest run --coverage
```

## MCP Server Tests (Jest)

```bash
cd ${CLAUDE_PROJECT_DIR}/mcp-server
npm test
```

For a specific file:
```bash
npm test -- <file-path>
```

For coverage:
```bash
npm test -- --coverage
```

## Rust Tests

```bash
cd ${CLAUDE_PROJECT_DIR}/frontend/src-tauri
cargo test
```

## After running

1. Report pass/fail counts per test suite
2. Highlight any failing tests with error messages
3. For coverage mode, report coverage percentages
4. Suggest fixes for any failures if the cause is obvious
