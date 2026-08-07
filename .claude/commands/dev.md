Start the full development environment for Kali MCP Pentest.

Run these steps in order, checking each before proceeding:

## Step 1: Check Docker

```bash
docker info > /dev/null 2>&1
```

If Docker is not running:
- On macOS: `open -a Docker`
- Wait up to 30 seconds for Docker daemon to become available
- Re-check with `docker info`
- If still not running, tell the user to start Docker Desktop manually

## Step 2: Start Kali Container

```bash
cd ${CLAUDE_PROJECT_DIR}
docker compose up -d kali
```

Wait for container to be healthy:
```bash
docker compose ps kali
```

If the Kali image doesn't exist, tell the user to run `/project:docker-rebuild` first.

## Step 3: Build & Start MCP Server

```bash
cd ${CLAUDE_PROJECT_DIR}/mcp-server
npm run build
```

The MCP server runs inside the Kali container. Verify it's accessible:
```bash
curl -s http://localhost:3001/health || echo "MCP server not responding"
```

If MCP isn't responding, check container logs:
```bash
docker compose logs kali --tail 20
```

## Step 4: Start Tauri Dev (includes Next.js)

```bash
cd ${CLAUDE_PROJECT_DIR}/frontend
npm run tauri:dev
```

This starts both:
- Next.js dev server (port 3000)
- Tauri native window

## Summary

Report the status of each component:
- Docker: running/not running
- Kali container: healthy/unhealthy/missing
- MCP server: connected/disconnected
- Tauri dev: started/failed

If any step fails, provide the error and suggest fixes.
