Run a comprehensive health check of the Kali MCP Pentest development environment.

Check each component and report status with pass/fail indicators.

## 1. Docker Status

```bash
# Docker daemon running?
docker info > /dev/null 2>&1 && echo "Docker: OK" || echo "Docker: NOT RUNNING"

# Kali container status
docker compose -f ${CLAUDE_PROJECT_DIR}/docker-compose.yml ps

# Kali image exists?
docker images kali-mcp-pentest --format "{{.Repository}}:{{.Tag}} ({{.Size}}, created {{.CreatedSince}})"
```

## 2. MCP Server

```bash
# Health check
curl -s http://localhost:3001/health 2>/dev/null || echo "MCP: NOT RESPONDING"

# Container MCP process
docker exec kali-mcp-pentest ps aux | grep -i node 2>/dev/null || echo "MCP process not found in container"
```

## 3. Dependencies

```bash
# Frontend deps
cd ${CLAUDE_PROJECT_DIR}/frontend && npm ls --depth=0 2>&1 | tail -5

# MCP server deps
cd ${CLAUDE_PROJECT_DIR}/mcp-server && npm ls --depth=0 2>&1 | tail -5

# Rust deps
cd ${CLAUDE_PROJECT_DIR}/frontend/src-tauri && cargo check 2>&1 | tail -3
```

## 4. Git Status

```bash
cd ${CLAUDE_PROJECT_DIR}
git status --short
git log --oneline -5
```

## 5. Database

```bash
# DB file exists and size
ls -lh ~/.pentest/data/pentest.db 2>/dev/null || echo "Database file not found"

# Table count
sqlite3 ~/.pentest/data/pentest.db "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;" 2>/dev/null || echo "Could not query database"
```

## 6. Configuration Files

Check these exist:
- `config/scope.yml`
- `config/credentials.yml`
- `config/tools.yml`
- `config/llm-config.yml`

```bash
cd ${CLAUDE_PROJECT_DIR}
for f in config/scope.yml config/credentials.yml config/tools.yml config/llm-config.yml; do
  [ -f "$f" ] && echo "  $f: OK" || echo "  $f: MISSING"
done
```

## Report Format

Present results as a status dashboard:

```
=== Kali MCP Pentest Status ===

Docker:        [OK/FAIL] <details>
Kali Container:[OK/FAIL] <status, uptime>
MCP Server:    [OK/FAIL] <health endpoint response>
Frontend Deps: [OK/WARN] <any issues>
MCP Deps:      [OK/WARN] <any issues>
Rust Build:    [OK/FAIL] <cargo check result>
Database:      [OK/FAIL] <size, table count>
Config Files:  [OK/WARN] <missing files>
Git:           <branch, clean/dirty, uncommitted count>
```

Suggest fixes for any failures.
