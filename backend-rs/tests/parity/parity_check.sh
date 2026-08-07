#!/usr/bin/env bash
# Parity harness driver. Hits the Python backend (:8000) and the Rust
# backend (:8001) with identical traffic and diffs the responses.
#
# Usage:
#   cd backend-rs/tests/parity
#   docker compose up --build -d
#   ./parity_check.sh
#
# Exits non-zero on the first diff. Prints which endpoint failed and the
# full diff so a reader can see exactly what drifted.

set -euo pipefail

PY_URL="${PY_URL:-http://localhost:8100}"
RS_URL="${RS_URL:-http://localhost:8101}"

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()  { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=$((fail+1)); }

# Fetch both and compare. Normalizes with jq when both responses are JSON
# so field-order differences don't trigger false failures.
compare() {
    local label="$1" method="$2" path="$3"
    shift 3
    # Any trailing args are passed to both curls (e.g. -H "Auth: ...").
    local py_body="$tmp/py.json"
    local rs_body="$tmp/rs.json"
    curl -sS -X "$method" "$PY_URL$path" "$@" -o "$py_body" || { bad "$label [curl py failed]"; return; }
    curl -sS -X "$method" "$RS_URL$path" "$@" -o "$rs_body" || { bad "$label [curl rs failed]"; return; }

    if jq empty < "$py_body" >/dev/null 2>&1 && jq empty < "$rs_body" >/dev/null 2>&1; then
        # Normalize JSON: strip id/tokens/timestamps that are inherently
        # different between runs.
        local py_n="$tmp/py.norm.json"
        local rs_n="$tmp/rs.norm.json"
        jq -S 'walk(if type == "object" then with_entries(select(.key | test("^(access_token|id|sub|created_at|updated_at|started_at|completed_at|last_login_at|sync_at|exp|iat|client_id)$") | not)) else . end)' < "$py_body" > "$py_n"
        jq -S 'walk(if type == "object" then with_entries(select(.key | test("^(access_token|id|sub|created_at|updated_at|started_at|completed_at|last_login_at|sync_at|exp|iat|client_id)$") | not)) else . end)' < "$rs_body" > "$rs_n"
        if diff -u "$py_n" "$rs_n" >/dev/null; then
            ok "$label"
        else
            bad "$label"
            diff -u "$py_n" "$rs_n" || true
        fi
    else
        if diff "$py_body" "$rs_body" >/dev/null; then
            ok "$label (raw)"
        else
            bad "$label (raw)"
            diff "$py_body" "$rs_body" || true
        fi
    fi
}

say "Public endpoints"
compare "GET /health"          GET "/health"
compare "GET /health/ready"    GET "/health/ready"
compare "GET /health/live"     GET "/health/live"
compare "GET /api/v1/version"  GET "/api/v1/version"
compare "GET /auth/providers"  GET "/api/v1/auth/providers"

say "Local auth flow"
EMAIL="parity-$(date +%s)@example.com"
PW="hunter2"
PAYLOAD="{\"email\":\"$EMAIL\",\"password\":\"$PW\",\"name\":\"Parity\"}"
LOGIN_PAYLOAD="{\"email\":\"$EMAIL\",\"password\":\"$PW\"}"

# Heads-up: the currently shipping `backend/` has a passlib 1.7.4 +
# bcrypt 5.0 incompatibility that makes `/auth/register` and `/auth/login`
# 500 for every request. See the "Blocker" section of the soak report.
# When the Python side is broken we can't diff against it, so we run both
# paths separately and just assert the Rust side is healthy.

py_register_status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$PY_URL/api/v1/auth/register" \
    -H "Content-Type: application/json" -d "$PAYLOAD")
rs_register_status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$RS_URL/api/v1/auth/register" \
    -H "Content-Type: application/json" -d "$PAYLOAD")
printf '  Python /auth/register → HTTP %s\n' "$py_register_status"
printf '  Rust   /auth/register → HTTP %s\n' "$rs_register_status"
if [ "$rs_register_status" = "201" ]; then
    ok "Rust /auth/register returns 201"
else
    bad "Rust /auth/register (got $rs_register_status)"
fi

rs_token=$(curl -sS -X POST "$RS_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" -d "$LOGIN_PAYLOAD" | jq -r .access_token)
if [ -n "$rs_token" ] && [ "$rs_token" != "null" ]; then ok "Rust login issued token"; else bad "Rust login"; fi

# Check that `/auth/me` parity works against both when we supply a valid
# token. Token is Rust-issued (HS256 shared secret — either backend can
# verify it since they share JWT_SECRET).
compare "GET /auth/me (HS256 shared secret)" GET "/api/v1/auth/me" \
    -H "Authorization: Bearer $rs_token"

say "Assessments"
compare "GET /assessments (empty)" GET "/api/v1/assessments" \
    -H "Authorization: Bearer $rs_token"

say "Findings"
compare "GET /findings/stats" GET "/api/v1/findings/stats" \
    -H "Authorization: Bearer $rs_token"

say "Sync status"
compare "GET /sync/status" GET "/api/v1/sync/status" \
    -H "Authorization: Bearer $rs_token"

say "Projects"
compare "GET /projects (empty)" GET "/api/v1/projects" \
    -H "Authorization: Bearer $rs_token"

say "Conversations"
compare "GET /conversations (empty)" GET "/api/v1/conversations" \
    -H "Authorization: Bearer $rs_token"

if [ "$fail" -eq 0 ]; then
    printf '\n\033[1;32mAll parity checks green.\033[0m\n'
    exit 0
else
    printf '\n\033[1;31m%d parity check(s) failed.\033[0m\n' "$fail"
    exit 1
fi
