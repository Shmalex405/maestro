Rebuild the Kali Docker image and restart the container.

$ARGUMENTS can include:
- `--no-cache` — Force full rebuild without Docker cache
- `--mcp-only` — Only rebuild MCP server inside existing container
- (empty) — Normal cached rebuild

## Step 1: Stop existing container

```bash
cd ${CLAUDE_PROJECT_DIR}
docker compose down
```

## Step 2: Rebuild the image

Normal build:
```bash
docker compose build kali
```

No-cache build (if `--no-cache` specified):
```bash
docker compose build --no-cache kali
```

MCP-only rebuild (if `--mcp-only` specified):
```bash
# Copy updated MCP server into running container
docker compose up -d kali
docker cp mcp-server/. kali-mcp-pentest:/opt/mcp-server/
docker exec kali-mcp-pentest bash -c "cd /opt/mcp-server && npm install && npm run build"
docker exec kali-mcp-pentest bash -c "supervisorctl restart mcp-server 2>/dev/null || true"
```

## Step 3: Start the container

```bash
docker compose up -d kali
```

## Step 4: Wait for health

```bash
# Wait up to 60 seconds for container to be healthy
for i in $(seq 1 12); do
  if curl -s http://localhost:3001/health > /dev/null 2>&1; then
    echo "MCP server healthy"
    break
  fi
  echo "Waiting for MCP server... ($i/12)"
  sleep 5
done
```

## Step 5: Verify MCP tools

```bash
# Quick check that MCP server responds
curl -s http://localhost:3001/health
```

## Report

- Build duration
- Image size (before/after if rebuilding)
- Container status
- MCP health check result
- Any build warnings or errors
