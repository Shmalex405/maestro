#!/usr/bin/env bash
# End-to-end assessment harness driver.
#
# Runs a complete deterministic assessment (no LLM, no frontend, $0 tokens)
# against OWASP Juice Shop (web) + OWASP NodeGoat (repo), authenticated, then
# asserts the matrix ran, the auth path worked, real vulns were found, the
# verdict gate both earns and refuses verdicts, and the provenance gate blocks a
# removed tool.
#
# Usage:  ./tests-e2e-assessment/run.sh
# Exit 0 = proven; non-zero = a stage or assertion failed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
COMPOSE="docker compose -f $HERE/docker-compose.yml"
WORK="$(mktemp -d)"
# Container name + ports are parameterized so the harness coexists with a running
# desktop app (kali-pentest on :3001) instead of colliding. Defaults are distinct.
KALI="${KALI_CONTAINER:-kali-pentest-e2e}"
export KALI_CONTAINER="$KALI"
MCP="http://localhost:${MCP_PORT:-3001}"
JUICE_URL_HOST="http://localhost:${JUICE_PORT:-3000}"  # reachable from the host (provisioning)
JUICE_URL_NET="http://juice-shop:3000"                 # reachable from inside the kali container
NODEGOAT_COMMIT="${NODEGOAT_COMMIT:-master}"            # pin a commit/tag for full determinism

log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }

DEBUG_DIR=/tmp/e2e-assessment-debug
cleanup() {
  local code=$?
  if [ $code -ne 0 ]; then
    log "FAILED (exit $code) — preserving debug output to $DEBUG_DIR"
    mkdir -p "$DEBUG_DIR"
    docker exec "$KALI" sh -c 'cat /tmp/mcp-server.log 2>/dev/null' > "$DEBUG_DIR/mcp-server.log" 2>/dev/null || true
    cp "$WORK"/*.json "$DEBUG_DIR/" 2>/dev/null || true  # includes oracles.json
    tail -n 60 "$DEBUG_DIR/mcp-server.log" 2>/dev/null || true
  fi
  log "Teardown"
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
  exit $code
}
trap cleanup EXIT

# --- 1. Build the working tree (test THIS version's MCP code) ----------------
log "Build mcp-server (working tree)"
( cd "$ROOT/mcp-server" && (test -d node_modules || npm ci) && npm run build >/dev/null )

# --- 2. Fetch the SAST target ------------------------------------------------
log "Fetch NodeGoat ($NODEGOAT_COMMIT)"
rm -rf "$HERE/.nodegoat"
git clone --depth 1 --branch "$NODEGOAT_COMMIT" https://github.com/OWASP/NodeGoat.git "$HERE/.nodegoat" 2>/dev/null \
  || git clone --depth 1 https://github.com/OWASP/NodeGoat.git "$HERE/.nodegoat"

# --- 3. Stand up Juice Shop + Kali -------------------------------------------
log "Compose up (juice-shop + kali)"
$COMPOSE up -d
log "Wait for Juice Shop (up to ~5 min — first boot can be slow under emulation)"
for i in $(seq 1 150); do curl -sf "$JUICE_URL_HOST/rest/admin/application-version" >/dev/null && break || sleep 2; done
curl -sf "$JUICE_URL_HOST/rest/admin/application-version" >/dev/null || { echo "Juice Shop never became ready"; exit 1; }

# --- 4. Provision two test users (authenticated scanning) --------------------
log "Provision credentials"
node "$HERE/provision-creds.mjs" "$JUICE_URL_HOST" "$WORK/creds.json"
USER_A="$(node -e "console.log(require('$WORK/creds.json').userA.jwt)")"
USER_B="$(node -e "console.log(require('$WORK/creds.json').userB.jwt)")"

# --- 5. Materialize the MCP server in the container + start it ---------------
# The published Kali image does NOT ship /opt/pentest/mcp-server — the desktop
# app populates it at runtime. So the harness copies the working-tree server
# (dist + package manifests) and installs prod deps in-container (better-sqlite3
# resolves a linux-x64 prebuild, so this is a download, not a compile).
log "Materialize MCP server in container + start autonomous-runner"
docker exec "$KALI" mkdir -p /opt/pentest/mcp-server /opt/pentest/config
docker cp "$ROOT/mcp-server/dist" "$KALI:/opt/pentest/mcp-server/dist"
docker cp "$ROOT/mcp-server/package.json" "$KALI:/opt/pentest/mcp-server/package.json"
docker cp "$ROOT/mcp-server/package-lock.json" "$KALI:/opt/pentest/mcp-server/package-lock.json"
# Place the test matrix where the gate's default search finds it (so the
# test→tool→binary map resolves regardless of env-var inheritance via docker exec).
docker cp "$ROOT/config/test-matrix.yml" "$KALI:/opt/pentest/config/test-matrix.yml"
docker exec "$KALI" bash -lc 'cd /opt/pentest/mcp-server && npm ci --omit=dev'
docker exec -d -e TEST_MATRIX_PATH=/opt/pentest/config/test-matrix.yml "$KALI" \
  bash -lc 'cd /opt/pentest/mcp-server && nohup node dist/autonomous-runner.js > /tmp/mcp-server.log 2>&1 &'
log "Wait for MCP server /health"
for i in $(seq 1 60); do curl -sf "$MCP/health" >/dev/null && break || sleep 2; done
curl -sf "$MCP/health" >/dev/null || { echo "MCP server never became healthy"; docker exec "$KALI" tail -n 40 /tmp/mcp-server.log 2>/dev/null; exit 1; }

run_assessment() { # $1 = out file
  # Build the request with node (env-passed values → no shell-quoting hazards).
  UA="$USER_A" UB="$USER_B" TGT="$JUICE_URL_NET" node -e '
    const a = { name: "run_orchestrator", arguments: {
      mode: "sequential",
      targets: [process.env.TGT],
      repo_paths: ["/harness/nodegoat"],
      severity: "medium",
      options: {
        auth: { type: "bearer", token: process.env.UA },
        harness: { second_user_jwt: process.env.UB },
      },
    }};
    process.stdout.write(JSON.stringify(a));' > "$WORK/req.json"
  curl -sf -X POST "$MCP/tools/call" -H 'Content-Type: application/json' --data-binary "@$WORK/req.json" > "$1"
}

read_provenance() { # $1 = result file, $2 = out file
  node -e "
    const r=require('$1');
    const tr=(r.testResults||[]).map(t=>({test_id:t.testId,status:t.status}));
    process.stdout.write(JSON.stringify({name:'check_tool_provenance',arguments:{test_results:tr}}));
  " > "$WORK/prov-req.json"
  curl -sf -X POST "$MCP/tools/call" -H 'Content-Type: application/json' --data-binary "@$WORK/prov-req.json" > "$2"
}

# --- 6. Baseline authenticated run + gate read + assert ----------------------
log "Run assessment (authenticated)"
run_assessment "$WORK/result.json"
read_provenance "$WORK/result.json" "$WORK/provenance.json"
log "Assert: coverage + auth path + ground truth + provenance"
node "$HERE/assert.mjs" run "$WORK/result.json" "$WORK/provenance.json" "$WORK/creds.json"

# --- 7. Verdict gate: oracles must earn verdicts AND refuse bad recipes ------
# Runs before the nuclei-removal stage because it needs a fully-armed container.
log "Verdict gate: run the oracles through the real MCP path"
node "$HERE/oracles.mjs" "$MCP" "$WORK/creds.json" "$JUICE_URL_NET" "$WORK/oracles.json"
node "$HERE/assert.mjs" oracles "$WORK/oracles.json"

# --- 8. Negative gate proof: remove nuclei → its tests must go BLOCKED -------
log "Negative gate: remove nuclei, re-run, assert BLOCKED"
docker exec "$KALI" bash -lc 'NB="$(command -v nuclei)"; [ -n "$NB" ] && mv "$NB" /tmp/nuclei.bak || true'
run_assessment "$WORK/result-neg.json"
read_provenance "$WORK/result-neg.json" "$WORK/provenance-neg.json"
node "$HERE/assert.mjs" negative "$WORK/provenance-neg.json"
docker exec "$KALI" bash -lc '[ -f /tmp/nuclei.bak ] && mv /tmp/nuclei.bak "$(dirname "$(command -v nuclei || echo /usr/local/bin/nuclei)")/nuclei" || true' || true

log "ALL ASSERTIONS PASSED — the assessment matrix ran end-to-end and did its job."
