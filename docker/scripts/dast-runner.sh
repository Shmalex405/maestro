#!/usr/bin/env bash
# =============================================================================
# Headless DAST runner (Scheduled DAST launch). Runs in a Fargate task with NO
# user logged in. Two modes:
#
#   POLL   (default): GET /scan-schedules/due → run every due scan, advance each.
#                     Launched on a cadence by EventBridge Scheduler → ECS RunTask.
#   SINGLE (MAESTRO_SCHEDULE_ID set): run exactly that schedule (CI / ad-hoc).
#
# Env:
#   MAESTRO_BACKEND_URL   bare backend host (no /api/v1; cloudRequest appends it; script adds it to REST calls)
#   MAESTRO_API_KEY       org `dast_*` key (bearer; org-scoped, service_caller=ci)
#   MAESTRO_SCHEDULE_ID   (single mode only) the schedule to run
#   MAESTRO_TARGET_ID     (single mode only; optional — derived from schedule otherwise)
#
# Boots the MCP server ONCE, then runs the deterministic pipeline per schedule
# (auto-records scan + scan_id findings), advancing each via /scan-schedules/:id/fired.
# =============================================================================
set -uo pipefail

log() { echo "[dast-runner] $*"; }
fail() { echo "[dast-runner][ERROR] $*" >&2; exit 1; }

: "${MAESTRO_BACKEND_URL:?MAESTRO_BACKEND_URL required}"
: "${MAESTRO_API_KEY:?MAESTRO_API_KEY required}"

BACKEND="${MAESTRO_BACKEND_URL%/}"
MCP="http://localhost:${AUTONOMOUS_PORT:-3001}"
SESSION_DIR="/opt/pentest/config"
SESSION_FILE="$SESSION_DIR/cloud-session.json"
MCP_DIR="/opt/pentest/mcp-server"

# MAESTRO_BACKEND_URL is the bare host; cloudRequest appends /api/v1 (so the
# cloud-session carries the host). This script adds /api/v1 to its own REST calls.
API="${BACKEND}/api/v1"
api() { curl -sS -H "Authorization: Bearer ${MAESTRO_API_KEY}" "$@"; }

# --- 1. Cloud session (the MCP server's cloudRequest reads this) ---
mkdir -p "$SESSION_DIR"
cat > "$SESSION_FILE" <<JSON
{ "backendUrl": "${BACKEND}", "idToken": "${MAESTRO_API_KEY}", "tokenExpiry": 4102444800000 }
JSON
export MAESTRO_CLOUD_SESSION_PATH="$SESSION_FILE"
export TEST_MATRIX_PATH="/opt/pentest/config/test-matrix.yml"

# --- 2. Boot the MCP HTTP server once ---
log "Starting MCP server…"
( cd "$MCP_DIR" && nohup node dist/autonomous-runner.js > /tmp/mcp-server.log 2>&1 & )
for _ in $(seq 1 60); do curl -sf "$MCP/health" >/dev/null 2>&1 && break || sleep 2; done
curl -sf "$MCP/health" >/dev/null 2>&1 || { tail -n 40 /tmp/mcp-server.log >&2 || true; fail "MCP server never became healthy"; }
log "MCP server healthy."

# --- run one schedule: resolve target+config+policy, scan, advance ---
# Run the deterministic pipeline against ONE target. auth_mode 'unauthed' sends
# NO credentials (anonymous scan); 'authed' applies the target's scan-config auth.
# Does NOT advance the schedule — the caller does that once per schedule.
run_one() {
  local schedule_id="$1" target_id="$2" auth_mode="${3:-authed}"
  log "── schedule=$schedule_id target=$target_id auth=$auth_mode"

  local target_json target_value
  target_json="$(api "${API}/targets/${target_id}")" || { log "WARN target fetch failed"; return 1; }
  target_value="$(echo "$target_json" | jq -r '.canonical_value // empty')"
  [ -n "$target_value" ] || { log "WARN could not resolve target $target_id"; return 1; }

  local cfg auth_json scope_json
  cfg="$(api "${API}/scan-configs?target_id=${target_id}")" || cfg='{}'
  scope_json="$(echo "$cfg" | jq -c '.scope // {}')"
  if [ "$auth_mode" = "unauthed" ]; then
    auth_json='{}'   # anonymous — what an unauthenticated attacker sees
  else
    auth_json="$(echo "$cfg" | jq -c '.auth // {}')"
  fi

  # policy_id pinned to the schedule → selected categories/tests (empty = full).
  local policy_id sel_cats sel_tests
  policy_id="$(api "${API}/scan-schedules" | jq -r --arg id "$schedule_id" '.[] | select(.id==$id) | .policy_id // empty')"
  sel_cats='[]'; sel_tests='[]'
  if [ -n "$policy_id" ]; then
    local pol; pol="$(api "${API}/scan-policies" | jq -c --arg id "$policy_id" '.[] | select(.id==$id)')"
    [ -n "$pol" ] && { sel_cats="$(echo "$pol" | jq -c '.categories // []')"; sel_tests="$(echo "$pol" | jq -c '.test_ids // []')"; }
  fi

  local options body resp
  options="$(jq -nc --argjson auth "$auth_json" --argjson scope "$scope_json" --argjson cats "$sel_cats" --argjson tests "$sel_tests" \
    '{ web_app: { auth: $auth }, scope: $scope }
     | (if ($cats|length)  > 0 then .selected_categories = $cats  else . end)
     | (if ($tests|length) > 0 then .selected_tests      = $tests else . end)')"
  body="$(jq -nc --arg t "$target_value" --argjson opts "$options" \
    '{ name:"run_orchestrator", arguments:{ mode:"sequential", targets:[$t], options:$opts, trigger_kind:"scheduled" } }')"

  log "scanning $target_value…"
  resp="$(curl -sS -X POST "$MCP/tools/call" -H 'Content-Type: application/json' -d "$body")" || { log "WARN scan call failed"; return 1; }
  log "result: $(echo "$resp" | jq -rc '{success,totalFindings,criticalCount,highCount} // .' 2>/dev/null || echo ok)"
}

# Process one due schedule row (JSON): a solo target OR an application (fan out to
# all its CURRENT targets — dynamic), then advance the schedule once via /fired.
process_schedule() {
  local s="$1" sid tid aid mode
  sid="$(echo "$s" | jq -r '.id')"
  tid="$(echo "$s" | jq -r '.target_id // empty')"
  aid="$(echo "$s" | jq -r '.application_id // empty')"
  mode="$(echo "$s" | jq -r '.auth_mode // "authed"')"

  if [ -n "$aid" ]; then
    log "schedule $sid → application $aid (fan-out, auth=$mode)"
    local ids
    ids="$(api "${API}/targets?application_id=${aid}&source=dast" | jq -r '.[].id')"
    [ -n "$ids" ] || log "WARN application $aid has no targets"
    while IFS= read -r t; do [ -n "$t" ] && { run_one "$sid" "$t" "$mode" || true; }; done <<< "$ids"
  elif [ -n "$tid" ]; then
    run_one "$sid" "$tid" "$mode" || true
  else
    log "WARN schedule $sid has neither target_id nor application_id"; return 1
  fi
  api -X POST "${API}/scan-schedules/${sid}/fired" >/dev/null && log "advanced $sid." || log "WARN /fired failed for $sid"
}

# --- 3a. SINGLE mode ---
if [ -n "${MAESTRO_SCHEDULE_ID:-}" ]; then
  sched="$(api "${API}/scan-schedules" | jq -c --arg id "$MAESTRO_SCHEDULE_ID" '.[] | select(.id==$id)')"
  [ -n "$sched" ] || fail "schedule $MAESTRO_SCHEDULE_ID not found"
  process_schedule "$sched"
  log "Done (single)."; exit 0
fi

# --- 3b. POLL mode (default): every due schedule ---
due="$(api "${API}/scan-schedules/due")" || fail "/scan-schedules/due failed"
count="$(echo "$due" | jq 'length' 2>/dev/null || echo 0)"
log "due schedules: $count"
[ "$count" -eq 0 ] && { log "nothing due."; exit 0; }
echo "$due" | jq -c '.[]' | while read -r s; do process_schedule "$s" || true; done
log "Done (poll)."
exit 0
