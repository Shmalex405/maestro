#!/usr/bin/env bash
# SKELETON — the Maestro (LLM-orchestrated) proving run.
#
# Same targets, same scope, same SCORER (assert.mjs) as the deterministic harness
# (run.sh) — but the DRIVER is the real product: Claude Code orchestrating the agent
# team, instead of run_orchestrator sequential. This is what actually grades Maestro.
#
# Status: the environment setup below is reused verbatim from run.sh (proven). The
# parts marked >>> SPIKE <<< are NOT yet proven and are the work to do before this is
# a trusted gate. Do not wire the weekly cron until the spike passes once.
#
# Usage: ANTHROPIC_API_KEY=... ./tests-e2e-assessment/run-llm.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
COMPOSE="docker compose -f $HERE/docker-compose.yml"
WORK="$(mktemp -d)"
KALI="${KALI_CONTAINER:-kali-pentest-e2e}"; export KALI_CONTAINER="$KALI"
MCP="http://localhost:${MCP_PORT:-3001}"
JUICE_URL_HOST="http://localhost:${JUICE_PORT:-3000}"
JUICE_URL_NET="http://juice-shop:3000"
NODEGOAT_COMMIT="${NODEGOAT_COMMIT:-master}"
# Pin the SAME model the desktop product uses (credentials.rs DEFAULT_CLAUDE_MODEL)
# so the proving run is faithful — not whatever `claude`'s default happens to be.
export ANTHROPIC_MODEL="${ANTHROPIC_MODEL:-claude-opus-4-8}"
DEBUG_DIR=/tmp/llm-assessment-debug

log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }
cleanup() {
  local code=$?
  # Persist the trace on SUCCESS AND FAILURE. Previously this only copied *.json
  # and only on a non-zero exit — so claude.log (the stream-json trace) and the
  # rich on-disk transcripts, the single most useful artifacts, were discarded the
  # moment the run worked. Now: the stream log, the on-disk transcripts (incl.
  # subagents/), the per-agent checkpoints, and the scored JSON always survive.
  mkdir -p "$DEBUG_DIR"
  cp "$WORK"/claude.log "$DEBUG_DIR/claude.log" 2>/dev/null || true
  cp "$WORK"/*.json "$DEBUG_DIR/" 2>/dev/null || true
  docker exec "$KALI" sh -c 'cat /tmp/mcp-server.log 2>/dev/null' > "$DEBUG_DIR/mcp-server.log" 2>/dev/null || true
  docker cp "$KALI:/root/.claude/projects" "$DEBUG_DIR/projects" 2>/dev/null || true
  docker cp "$KALI:/harness/project/reports" "$DEBUG_DIR/reports" 2>/dev/null || true
  # Belt-and-suspenders: if the main flow aborted before producing one, analyze
  # whatever transcripts we recovered so there is ALWAYS a trace-report.json.
  if [ ! -f "$DEBUG_DIR/trace-report.json" ] && [ -d "$DEBUG_DIR/projects" ]; then
    local m=""
    while IFS= read -r f; do
      if [ -z "$m" ] || [ "$f" -nt "$m" ]; then m="$f"; fi
    done < <(find "$DEBUG_DIR/projects" -mindepth 2 -maxdepth 2 -name '*.jsonl' 2>/dev/null)
    if [ -n "$m" ]; then
      node "$HERE/analyze-trace.mjs" --transcript "$m" --checkpoints "$DEBUG_DIR/reports" --out "$DEBUG_DIR/trace-report.json" >/dev/null 2>&1 || true
    fi
  fi
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"; exit $code
}
trap cleanup EXIT

# --- 1–5. Setup (identical to run.sh — proven) -------------------------------
log "Build mcp-server + stand up targets + provision creds + start MCP server"
( cd "$ROOT/mcp-server" && (test -d node_modules || npm ci) && npm run build >/dev/null )
rm -rf "$HERE/.nodegoat"
git clone --depth 1 --branch "$NODEGOAT_COMMIT" https://github.com/OWASP/NodeGoat.git "$HERE/.nodegoat" 2>/dev/null \
  || git clone --depth 1 https://github.com/OWASP/NodeGoat.git "$HERE/.nodegoat"
$COMPOSE up -d
for i in $(seq 1 150); do curl -sf "$JUICE_URL_HOST/rest/admin/application-version" >/dev/null && break || sleep 2; done
node "$HERE/provision-creds.mjs" "$JUICE_URL_HOST" "$WORK/creds.json"
USER_A="$(node -e "console.log(require('$WORK/creds.json').userA.jwt)")"
docker exec "$KALI" mkdir -p /opt/pentest/mcp-server /opt/pentest/config
docker cp "$ROOT/mcp-server/dist" "$KALI:/opt/pentest/mcp-server/dist"
docker cp "$ROOT/mcp-server/package.json" "$KALI:/opt/pentest/mcp-server/package.json"
docker cp "$ROOT/mcp-server/package-lock.json" "$KALI:/opt/pentest/mcp-server/package-lock.json"
docker cp "$ROOT/config/test-matrix.yml" "$KALI:/opt/pentest/config/test-matrix.yml"
docker exec "$KALI" bash -lc 'cd /opt/pentest/mcp-server && (test -d node_modules || npm ci --omit=dev)'
docker exec -d -e TEST_MATRIX_PATH=/opt/pentest/config/test-matrix.yml "$KALI" \
  bash -lc 'cd /opt/pentest/mcp-server && nohup node dist/autonomous-runner.js > /tmp/mcp-server.log 2>&1 &'
for i in $(seq 1 60); do curl -sf "$MCP/health" >/dev/null && break || sleep 2; done

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY is required for the LLM proving run (real cost). Set it and re-run."
  exit 2
fi

# --- 6a. Make the project (agents + CLAUDE.md + config + skills) available -----
# The kali image bakes the claude CLI + /opt/pentest/mcp-server, but NOT the project
# tree. claude discovers .claude/agents + .claude/commands from its cwd, so we place
# a project root and `cd` into it (exactly like the desktop app cds into the mounted
# project dir).
log "Stage the project tree + MCP config for headless claude"
docker exec "$KALI" mkdir -p /harness/project/reports /harness/project/logs /harness/project/data
docker cp "$ROOT/.claude"   "$KALI:/harness/project/.claude"
docker cp "$ROOT/CLAUDE.md" "$KALI:/harness/project/CLAUDE.md"
docker cp "$ROOT/config"    "$KALI:/harness/project/config"
docker cp "$ROOT/skills"    "$KALI:/harness/project/skills"

# claude reaches the MCP tools via its own stdio server (same DB_PATH as the running
# autonomous-runner, so findings land in one place). Mirrors the desktop's
# /root/.claude/maestro-mcp.json (ensure_claude_mcp_config in terminal.rs).
docker exec "$KALI" bash -lc 'mkdir -p /root/.claude && cat > /root/.claude/maestro-mcp.json <<JSON
{
  "mcpServers": {
    "kali-pentest": {
      "command": "node",
      "args": ["/opt/pentest/mcp-server/dist/index.js"],
      "env": {
        "DB_PATH": "/tmp/assess.db",
        "SCOPE_CONFIG_PATH": "/harness/scope.yml",
        "TEST_MATRIX_PATH": "/opt/pentest/config/test-matrix.yml"
      }
    }
  }
}
JSON'

# --- 6b. Kickoff prompt (mirrors the desktop new-assessment wizard) -----------
# Written to a file + copied in, so there are no host/container shell-quoting
# hazards. Injects the provisioned bearer token inline + says NOT to prompt for auth.
cat > "$WORK/prompt.txt" <<EOF
/assess

Run a full web + API security assessment, then a SAST scan of the repo.

In-scope target: ${JUICE_URL_NET}
Authenticate using this bearer token DIRECTLY — do NOT prompt for credentials, there is no interactive user: ${USER_A}
Repository to scan (SAST + IaC): /harness/nodegoat

Orchestrate per .claude/commands/assess.md (the default Workflow path). Validate scope
first, then run the assessment to completion. Record every finding via create_finding.
Do not wait for human input at any point; if a step needs interactive auth/approval that
cannot be satisfied headlessly, mark it BLOCKED/PARTIAL and continue.
EOF
docker cp "$WORK/prompt.txt" "$KALI:/harness/prompt.txt"

# --- 6c. Drive Maestro headless (real LLM, same model as the product) ---------
log "Run Maestro assessment headless (claude -p, model=$ANTHROPIC_MODEL) — this is the real cost step"
timeout "${LLM_TIMEOUT_SECONDS:-5400}" docker exec \
  -e ANTHROPIC_API_KEY -e ANTHROPIC_MODEL \
  -e MAESTRO_ASSESSMENT_ID=e2e-llm \
  -e CLAUDE_PROJECT_DIR=/harness/project \
  "$KALI" bash -lc 'unset CLAUDECODE; cd /harness/project && \
    claude -p "$(cat /harness/prompt.txt)" \
      --model "$ANTHROPIC_MODEL" \
      --mcp-config /root/.claude/maestro-mcp.json --strict-mcp-config \
      --dangerously-skip-permissions \
      --max-turns '"${LLM_MAX_TURNS:-400}"' \
      --output-format stream-json --verbose' \
  > "$WORK/claude.log" 2>&1 || echo "claude exited non-zero (timeout or max-turns) — scoring whatever it produced"

# --- 7. Read what Maestro produced + score with the SAME assertions -----------
# IMPORTANT: create_finding writes the SQLite findings table (DB_PATH=/tmp/assess.db);
# the list_findings tool reads only an in-memory array (empty for an LLM-driven run),
# so we query the DB directly via the mcp-server's bundled better-sqlite3.
log "Read findings + score"
docker exec "$KALI" node -e "
  const db = require('/opt/pentest/mcp-server/node_modules/better-sqlite3')('/tmp/assess.db');
  const rows = db.prepare('SELECT title, description, severity, source FROM findings').all();
  process.stdout.write(JSON.stringify(rows));
" > "$WORK/findings.json" 2>/dev/null || echo "[]" > "$WORK/findings.json"

# testResults come from the per-agent checkpoints the assessment writes
# (reports/{agent}-results.json under the project dir). Flatten them.
docker exec "$KALI" bash -lc '
  node -e "
    const fs=require(\"fs\"); const dir=\"/harness/project/reports\";
    const out=[];
    try { for (const f of fs.readdirSync(dir).filter(f=>f.endsWith(\"-results.json\"))) {
      try { const j=JSON.parse(fs.readFileSync(dir+\"/\"+f,\"utf8\"));
        for (const t of (j.test_results||[])) out.push({testId:t.test_id, status:t.status});
      } catch {}
    } } catch {}
    process.stdout.write(JSON.stringify(out));
  "' > "$WORK/testresults.json" 2>/dev/null || echo "[]" > "$WORK/testresults.json"

node -e "
  const fs=require('fs');
  const allFindings=JSON.parse(fs.readFileSync('$WORK/findings.json','utf8'));
  const testResults=JSON.parse(fs.readFileSync('$WORK/testresults.json','utf8'));
  fs.writeFileSync('$WORK/result.json', JSON.stringify({ execution_id:'e2e-llm', allFindings, testResults }));
  console.error('[llm] findings='+allFindings.length+' testResults='+testResults.length);
"

# Read the gate, then score. First spike: full assert.mjs run. Coverage depends on
# the LLM writing checkpoints; if it is sparse this surfaces as a real signal to
# calibrate (e.g. an expectations-llm.json / relaxed coverage for the LLM path).
node -e "
  const r=require('$WORK/result.json');
  const tr=(r.testResults||[]).map(t=>({test_id:t.testId,status:t.status}));
  process.stdout.write(JSON.stringify({name:'check_tool_provenance',arguments:{test_results:tr}}));
" > "$WORK/prov-req.json"
curl -sf -X POST "$MCP/tools/call" -H 'Content-Type: application/json' --data-binary "@$WORK/prov-req.json" > "$WORK/provenance.json" || echo '{}' > "$WORK/provenance.json"

# --- 8. Recover the rich transcripts + analyze what the LLM ACTUALLY did ------
# claude.log is the stdout stream; the on-disk /root/.claude/projects/*.jsonl is
# richer (includes the subagents/ tree), so prefer it as the analyzer's input.
log "Recover transcripts + analyze trace (what the orchestrated run actually did)"
mkdir -p "$DEBUG_DIR"
cp "$WORK"/*.json "$DEBUG_DIR/" 2>/dev/null || true
docker cp "$KALI:/root/.claude/projects" "$DEBUG_DIR/projects" 2>/dev/null || true
docker cp "$KALI:/harness/project/reports" "$DEBUG_DIR/reports" 2>/dev/null || true
MAIN_JSONL=""
while IFS= read -r f; do
  if [ -z "$MAIN_JSONL" ] || [ "$f" -nt "$MAIN_JSONL" ]; then MAIN_JSONL="$f"; fi
done < <(find "$DEBUG_DIR/projects" -mindepth 2 -maxdepth 2 -name '*.jsonl' 2>/dev/null)
if [ -n "$MAIN_JSONL" ]; then
  node "$HERE/analyze-trace.mjs" --transcript "$MAIN_JSONL" --checkpoints "$DEBUG_DIR/reports" \
    --provenance "$WORK/provenance.json" --out "$DEBUG_DIR/trace-report.json" || echo "analyzer non-fatal error — trace preserved"
else
  echo "WARN: no main transcript recovered from the container — trace analysis skipped"
fi

# --- 9. Score with the SAME assertions, LLM mode (adds trace-integrity gates) --
log "Score (assert.mjs llm) — Maestro proving run"
if [ -f "$DEBUG_DIR/trace-report.json" ]; then
  node "$HERE/assert.mjs" llm "$WORK/result.json" "$WORK/provenance.json" "$DEBUG_DIR/trace-report.json"
else
  echo "no trace-report.json — falling back to deterministic-style scoring (run mode)"
  node "$HERE/assert.mjs" run "$WORK/result.json" "$WORK/provenance.json" "$WORK/creds.json"
fi
log "MAESTRO PROVING RUN PASSED — the LLM-orchestrated assessment ran and did its job."
