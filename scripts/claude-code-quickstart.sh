#!/usr/bin/env bash
#
# Drive Maestro from Claude Code (or any MCP client) — no desktop app required.
#
# This gets everything the `.mcp.json` server needs running:
#   1. the Kali toolkit container (named `kali-pentest`, where tools execute)
#   2. the host-side MCP server built (`mcp-server/dist`)
# then prints the two commands that start a Claude Code session wired to it.
#
# Usage, from the repo root:
#   ./scripts/claude-code-quickstart.sh            # pull the prebuilt image (fast)
#   ./scripts/claude-code-quickstart.sh --build    # build the image from source
#
# See QUICKSTART-CLAUDE-CODE.md for the full walkthrough and caveats.

set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
BUILD=0
[[ "${1:-}" == "--build" ]] && BUILD=1

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── Prerequisites ────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Desktop and retry."
docker info >/dev/null 2>&1       || die "Docker is installed but not running. Start it and retry."
command -v node >/dev/null 2>&1   || die "Node.js is not installed. Install Node 20+ and retry."
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[[ "$NODE_MAJOR" -ge 20 ]] || die "Node 20+ required (found $(node --version))."
ok "Docker running, Node $(node --version)"

# ── 1. Kali toolkit container ────────────────────────────────────────────────
if docker ps --filter "name=^kali-pentest$" --format '{{.Names}}' | grep -q kali-pentest; then
  ok "kali-pentest container already running"
elif [[ "$BUILD" == "1" ]]; then
  say "Building the Kali toolkit image from source (30–60 min, ~29 GB)…"
  docker compose -f docker/docker-compose.yml up -d --build
  ok "kali-pentest container up (built from source)"
else
  say "Starting the Kali toolkit container (pulling the prebuilt image on first run; ~29 GB)…"
  docker compose -f docker/docker-compose.prebuilt.yml up -d
  ok "kali-pentest container up (prebuilt image)"
fi

# ── 2. MCP server ────────────────────────────────────────────────────────────
say "Building the MCP server…"
( cd mcp-server && npm ci --silent && npm run build --silent )
[[ -f mcp-server/dist/index.js ]] || die "MCP build did not produce mcp-server/dist/index.js"
ok "MCP server built (mcp-server/dist/index.js)"

# ── Done ─────────────────────────────────────────────────────────────────────
cat <<EOF

$(printf '\033[1;32mReady.\033[0m') Two commands to start driving Maestro from Claude Code:

  export CLAUDE_PROJECT_DIR="$REPO_ROOT"
  claude

The exported path is required — .mcp.json references \${CLAUDE_PROJECT_DIR}, and
without it the kali-pentest MCP server fails to connect.

Then, inside Claude Code:
  • It auto-loads .mcp.json → the kali-pentest tools (scan_ports, run_nuclei, …).
  • Approve the MCP server when prompted (or add it to your allowlist).
  • Edit config/scope.yml to the targets you are authorized to test, then ask it
    to run an assessment.

First time with Claude Code? Install it and sign in with your own Anthropic
account first:  npm i -g @anthropic-ai/claude-code  &&  claude

Heads-up: sustained exploitation on an account not enrolled in Anthropic's Cyber
Verification Program may be refused mid-run — recon, SAST, secret/dependency
scanning, compliance and reporting are unaffected. See QUICKSTART-CLAUDE-CODE.md.
EOF
