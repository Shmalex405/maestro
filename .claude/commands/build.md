Build production artifacts for Kali MCP Pentest.

$ARGUMENTS specifies which component(s) to build. If empty, build all.

Valid component targets:
- `mcp` — Build the MCP server TypeScript
- `frontend` — Build the Next.js frontend only
- `tauri` — Full Tauri production build (includes Next.js)
- `docker` — Build/rebuild the Kali Docker image
- `all` or empty — Build everything

## MCP Server Build

```bash
cd ${CLAUDE_PROJECT_DIR}/mcp-server
npm run build
```

Check for TypeScript errors. Report any compilation failures.

## Frontend Build (Next.js only)

```bash
cd ${CLAUDE_PROJECT_DIR}/frontend
npm run build
```

Report any build warnings or errors.

## Tauri Build (full production app)

```bash
cd ${CLAUDE_PROJECT_DIR}/frontend
npm run tauri:build
```

This produces:
- macOS: `.dmg` and `.app` in `frontend/src-tauri/target/release/bundle/`
- Linux: `.deb` and `.AppImage`
- Windows: `.msi` and `.exe`

Report the artifact paths and sizes.

## Docker Build

```bash
cd ${CLAUDE_PROJECT_DIR}
docker build -t kali-mcp-pentest:latest .
```

Report image size and build duration.

## After building

1. Report success/failure for each component
2. List artifact locations and sizes
3. Note any warnings that should be addressed
