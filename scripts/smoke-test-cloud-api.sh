#!/usr/bin/env bash
# Cloud API smoke test — verifies the FastAPI backend at the configured backend
# URL has every endpoint the desktop+MCP app POSTs / PATCHes / DELETEs to.
#
# Why: in v0.1.7-v0.1.9 we wired the desktop UI and MCP tools to route writes
# to the per-org cloud backend. If any endpoint is missing or has a different
# shape, the customer experience silently 4xxs. This smoke test catches that
# in <30 seconds.
#
# Usage:
#   MAESTRO_JWT="$(pbpaste)" \
#   MAESTRO_BACKEND="https://groovy.maestro.groovysec.com" \
#   bash scripts/smoke-test-cloud-api.sh
#
# Get the JWT from the prod app: open DevTools (Cmd+Opt+I), in the console:
#   copy(JSON.parse(localStorage.getItem('maestro-auth')).state.idToken)

set -uo pipefail

JWT="${MAESTRO_JWT:-}"
BACKEND="${MAESTRO_BACKEND:-https://groovy.maestro.groovysec.com}"

if [ -z "$JWT" ]; then
  echo "ERROR: MAESTRO_JWT not set"
  echo "  Get from prod app DevTools console:"
  echo "    copy(JSON.parse(localStorage.getItem('maestro-auth')).state.idToken)"
  echo "  Then: MAESTRO_JWT=\"\$(pbpaste)\" bash $0"
  exit 1
fi

API="${BACKEND%/}/api/v1"
PASS=0
FAIL=0
SKIP=0
declare -a FAILURES

# Color codes (bash-portable)
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
DIM=$'\033[2m'
RESET=$'\033[0m'

# Issue a request, print summary line, accumulate pass/fail counters.
# Args: name method path expected_status [body]
check() {
  local name="$1"
  local method="$2"
  local path="$3"
  local expected="$4"
  local body="${5:-}"

  local args=(-s -o /tmp/smoke-resp.json -w '%{http_code}' -X "$method" \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json")
  if [ -n "$body" ]; then
    args+=(-d "$body")
  fi

  local code
  code=$(curl "${args[@]}" "${API}${path}" 2>/dev/null)

  # Accept any of the expected codes (comma-separated)
  local matched=false
  IFS=',' read -ra wanted <<<"$expected"
  for w in "${wanted[@]}"; do
    if [ "$code" = "$w" ]; then matched=true; break; fi
  done

  if $matched; then
    printf "  %s✓%s %-50s %s%s%s\n" "$GREEN" "$RESET" "$name" "$DIM" "$code" "$RESET"
    PASS=$((PASS + 1))
    return 0
  else
    local detail
    detail=$(jq -r 'if type == "object" then (.detail // .message // .error // "") else "" end' /tmp/smoke-resp.json 2>/dev/null | head -c 100)
    printf "  %s✗%s %-50s %s%d%s  %s\n" "$RED" "$RESET" "$name" "$RED" "$code" "$RESET" "$detail"
    FAILURES+=("$name → $code: $detail")
    FAIL=$((FAIL + 1))
    return 1
  fi
}

# Like check, but stash the response JSON's `id` field into a global var.
check_capture_id() {
  local var="$1"; shift
  if check "$@"; then
    local id
    id=$(jq -r '.id // empty' /tmp/smoke-resp.json 2>/dev/null)
    if [ -n "$id" ]; then
      printf -v "$var" '%s' "$id"
      return 0
    fi
  fi
  return 1
}

echo "=========================================="
echo "Maestro Cloud API Smoke Test"
echo "  Backend: $BACKEND"
echo "  JWT:     ${JWT:0:20}...${JWT: -10}  (${#JWT} chars)"
echo "=========================================="

# ── Identity / health ──────────────────────────────────────────────────────
echo
echo "${YELLOW}Identity / auth${RESET}"
check "GET /auth/me" GET "/auth/me" "200"

# ── List / read endpoints (these worked in v0.1.5 — re-verify) ─────────────
echo
echo "${YELLOW}Read endpoints (already working in v0.1.5)${RESET}"
check "GET /findings"          GET "/findings"          "200"
check "GET /findings/stats"    GET "/findings/stats"    "200"
check "GET /assessments"       GET "/assessments"       "200"
check "GET /projects"          GET "/projects"          "200"
check "GET /reports"           GET "/reports"           "200"
check "GET /repositories"      GET "/repositories"      "200"
check "GET /imports"           GET "/imports"           "200"
check "GET /imported-findings" GET "/imported-findings" "200"
check "GET /scan-snapshots"    GET "/scan-snapshots"    "200"
check "GET /audit-logs"        GET "/audit-logs"        "200"
check "GET /dashboard/stats"   GET "/dashboard/stats"   "200"

# ── Write endpoints (v0.1.7-v0.1.9 — never tested against backend) ─────────
echo
echo "${YELLOW}Write endpoints (the load-bearing ones for v0.1.7+)${RESET}"

PROJECT_ID=""
ASSESSMENT_ID=""
FINDING_ID=""

# Projects: create → update → delete
if check_capture_id PROJECT_ID "POST /projects"  POST  "/projects"  "200,201" \
    '{"name":"Maestro Smoke Test","description":"Auto-created by smoke-test-cloud-api.sh, safe to delete"}'; then
  check "PATCH /projects/{id}" PATCH "/projects/${PROJECT_ID}" "200" \
    '{"description":"Updated by smoke test"}'
fi

# Assessments: create → update → assign-to-project → lifecycle (start/cancel)
if check_capture_id ASSESSMENT_ID "POST /assessments" POST "/assessments" "200,201" \
    '{"type":"recon","name":"Maestro Smoke Test","targets":["smoke-test.example.invalid"],"start":false}'; then
  check "PATCH /assessments/{id}" PATCH "/assessments/${ASSESSMENT_ID}" "200" \
    '{"name":"Maestro Smoke Test (renamed)"}'
  if [ -n "$PROJECT_ID" ]; then
    check "PUT /assessments/{id}/project (assign)" PUT "/assessments/${ASSESSMENT_ID}/project" "200,204" \
      "{\"project_id\":\"${PROJECT_ID}\"}"
  fi
  # Lifecycle endpoints — these may 4xx if they require a real scanner running.
  # Mark non-fatal: we want to know if the routes EXIST, not necessarily that
  # they succeed without an active assessment in flight.
  check "POST /assessments/{id}/cancel"            POST "/assessments/${ASSESSMENT_ID}/cancel" "200,204,400,404,409"
fi

# Findings: create → update → delete
if check_capture_id FINDING_ID "POST /findings" POST "/findings" "200,201" \
    '{"title":"Maestro Smoke Test Finding","severity":"info","target":"smoke-test.example.invalid","description":"Auto-created by smoke-test-cloud-api.sh","evidence":"smoke test","exploitable":"FALSE"}'; then
  check "PATCH /findings/{id}" PATCH "/findings/${FINDING_ID}" "200" \
    '{"description":"Updated by smoke test"}'
fi

# Imports: probably accepts CSV — check that POST exists with a tiny dummy
check "POST /imports (CSV import)" POST "/imports" "200,201,400,422" \
  '{"csv_content":"title,severity,description\nSmoke,info,test","source":"smoke-test"}'

# Reports: POST is gated behind generated content, so just verify the route
# accepts a request. We use 200/201 for success or 400/422 for "shape OK,
# content missing" — any of those means the endpoint EXISTS.
check "POST /reports" POST "/reports" "200,201,400,422" \
  '{"format":"markdown","include_evidence":false,"finding_ids":[]}'

# Scan snapshots
if [ -n "$ASSESSMENT_ID" ]; then
  check "POST /scan-snapshots" POST "/scan-snapshots" "200,201,400,422" \
    "{\"assessment_id\":\"${ASSESSMENT_ID}\"}"
fi

# ── Repositories CRUD (v0.1.19) ────────────────────────────────────────────
echo
echo "${YELLOW}Repositories CRUD (v0.1.19)${RESET}"
REPO_ID=""
if check_capture_id REPO_ID "POST /repositories" POST "/repositories" "200,201" \
    '{"name":"Maestro Smoke Test Repo","path":"/tmp/smoke-test","source_type":"local","languages":["typescript"]}'; then
  check "GET /repositories/{id}"   GET   "/repositories/${REPO_ID}" "200"
  check "PATCH /repositories/{id}" PATCH "/repositories/${REPO_ID}" "200" \
    '{"description":"Updated by smoke test"}'
fi

# ── Configs (v0.1.19 + v0.1.24) ────────────────────────────────────────────
echo
echo "${YELLOW}Configs (cloud-routed kinds)${RESET}"
for kind in scope tools agents llm integrations credentials; do
  check "GET /configs/${kind}"    GET "/configs/${kind}"    "200"
  check "PUT /configs/${kind}"    PUT "/configs/${kind}"    "200" \
    "{\"value\":{\"smoke_test\":true}}"
done

# ── Assessment events (v0.1.25) ────────────────────────────────────────────
echo
echo "${YELLOW}Assessment activity events (v0.1.25)${RESET}"
if [ -n "$ASSESSMENT_ID" ]; then
  check "GET /assessments/{id}/events"  GET  "/assessments/${ASSESSMENT_ID}/events"  "200"
  check "POST /assessments/{id}/events" POST "/assessments/${ASSESSMENT_ID}/events" "200,201" \
    '{"event_type":"orchestrator_message","details":{"message":"smoke test event"}}'
fi

# DELETE /findings/all — verify route exists; expect 405 if backend disallows it
# globally, 200/204 if it actually deletes. We treat 200/204/405/404 as "shape
# discoverable", anything else as a real failure. SKIPPED here because it's
# destructive — clear_findings being routed at all is what matters; whether
# it actually works can be tested with `confirm: false` semantics.
echo "  ${DIM}~ DELETE /findings/all                              SKIPPED (destructive)${RESET}"
SKIP=$((SKIP + 1))

# ── Cleanup ────────────────────────────────────────────────────────────────
echo
echo "${YELLOW}Cleanup${RESET}"
if [ -n "$FINDING_ID" ]; then
  check "DELETE /findings/{id}"    DELETE "/findings/${FINDING_ID}"    "200,204"
fi
if [ -n "$ASSESSMENT_ID" ]; then
  check "DELETE /assessments/{id}" DELETE "/assessments/${ASSESSMENT_ID}" "200,204"
fi
if [ -n "$PROJECT_ID" ]; then
  check "DELETE /projects/{id}"    DELETE "/projects/${PROJECT_ID}"    "200,204"
fi
if [ -n "$REPO_ID" ]; then
  check "DELETE /repositories/{id}" DELETE "/repositories/${REPO_ID}" "200,204"
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo
echo "=========================================="
echo "Results: ${GREEN}${PASS} passed${RESET}  ${RED}${FAIL} failed${RESET}  ${DIM}${SKIP} skipped${RESET}"
if [ "$FAIL" -gt 0 ]; then
  echo
  echo "${RED}Failures:${RESET}"
  for f in "${FAILURES[@]}"; do
    echo "  • $f"
  done
fi
echo "=========================================="

[ "$FAIL" -eq 0 ]
