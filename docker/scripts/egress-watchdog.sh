#!/bin/bash
#
# Tier 3 egress watchdog. Runs as a backgrounded loop from entrypoint.sh.
#
# Purpose: if Tier 3 enforcement accidentally blocks the LLM endpoints
# (e.g. allowlist generator drifted, DNS resolution flapped during init,
# scope.yml briefly missing), the agent loses its brain and the assessment
# wedges. Without a watchdog the user has to manually flush rules.
#
# Behaviour: every 30s, attempt a connect to api.anthropic.com:443 and
# api.openai.com:443. If both fail for >=60s consecutively, flush the
# OUTPUT chain (back to ACCEPT all) and exit. The loud log line is the
# signal — the desktop's tail-on-container-logs path picks it up and the
# audit log records the event.
#
# Trade-off: a watchdog that flushes is strictly less safe than one that
# leaves rules in place and pages a human. For v0.1.77 we pick "keep the
# product working" over "fail closed" because Tier 3 is opt-in and the
# alternative is wedged assessments that customers can't unstick. Revisit
# in v0.1.78 once we have a UI signal for "Tier 3 self-disabled, please
# investigate scope.yml".

set -e

if [ "${MAESTRO_TIER3_EGRESS:-0}" != "1" ]; then
    exit 0
fi

UNREACHABLE_SECONDS=0
THRESHOLD_SECONDS=60

while true; do
    sleep 30
    if curl -sS -o /dev/null --max-time 5 -w '%{http_code}' https://api.anthropic.com/v1/messages 2>/dev/null | grep -qE '^[0-9]'; then
        UNREACHABLE_SECONDS=0
    elif curl -sS -o /dev/null --max-time 5 -w '%{http_code}' https://api.openai.com/v1/models 2>/dev/null | grep -qE '^[0-9]'; then
        UNREACHABLE_SECONDS=0
    else
        UNREACHABLE_SECONDS=$((UNREACHABLE_SECONDS + 30))
        echo "[egress-watchdog] LLM endpoints unreachable for ${UNREACHABLE_SECONDS}s" >&2
        if [ "$UNREACHABLE_SECONDS" -ge "$THRESHOLD_SECONDS" ]; then
            echo "[egress-watchdog] AUTO-DISABLING Tier 3: LLM unreachable >${THRESHOLD_SECONDS}s — flushing OUTPUT chain" >&2
            iptables -F OUTPUT
            iptables -P OUTPUT ACCEPT
            echo "[egress-watchdog] OUTPUT chain flushed; assessment can proceed (audit log will reflect this)" >&2
            exit 0
        fi
    fi
done
