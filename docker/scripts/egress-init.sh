#!/bin/bash
#
# Tier 3 outbound network egress enforcement (v0.1.77+).
#
# Applies a default-deny iptables OUTPUT policy when MAESTRO_TIER3_EGRESS=1.
# No-op otherwise so the Tauri side can ship the script unconditionally and
# flip the flag per-org. Pairs with the NET_ADMIN cap re-add in docker.rs;
# without that cap iptables refuses and we fail loudly so the host knows
# enforcement isn't actually in place.
#
# Inputs (env):
#   MAESTRO_TIER3_EGRESS         "1" enables enforcement, anything else = no-op
#   MAESTRO_TIER3_ALLOWLIST      Comma-separated <ip-or-cidr>[:port] entries
#                                from scope.yml. Without :port, ports 80+443
#                                are opened (covers HTTP and HTTPS scans).
#   MAESTRO_BACKEND_HOST         Per-org backend hostname (resolved + opened
#                                on 443/tcp). The desktop reads scope/creds
#                                from this — must be reachable.
#
# Always-allow regardless of scope: DNS, loopback, established/related,
# and the system endpoints required for the agent runtime to function
# (LLM APIs, Cognito, GHCR for image fetches, Google Fonts for the PDF
# renderer). Without these the agent can't reach its own brain.
#
# Logs blocked packets via iptables LOG target; rate-limited so a chatty
# tool that retries forever doesn't fill /var/log.

set -e

if [ "${MAESTRO_TIER3_EGRESS:-0}" != "1" ]; then
    echo "[egress-init] Tier 3 disabled (MAESTRO_TIER3_EGRESS=${MAESTRO_TIER3_EGRESS:-unset}) — no-op"
    exit 0
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "[egress-init] FATAL: iptables not installed — Tier 3 cannot enforce" >&2
    exit 1
fi

if ! iptables -L >/dev/null 2>&1; then
    echo "[egress-init] FATAL: iptables refused (NET_ADMIN cap missing?) — Tier 3 cannot enforce" >&2
    exit 1
fi

echo "[egress-init] Applying Tier 3 outbound egress allowlist"

iptables -F OUTPUT
iptables -P OUTPUT DROP

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

resolve_and_allow() {
    local host="$1"
    local port="${2:-443}"
    local ip
    for ip in $(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
        iptables -A OUTPUT -d "$ip" -p tcp --dport "$port" -j ACCEPT
    done
}

for HOST in \
    api.anthropic.com \
    api.openai.com \
    cognito-idp.us-west-2.amazonaws.com \
    cognito-identity.us-west-2.amazonaws.com \
    ghcr.io \
    pkg-containers.githubusercontent.com \
    fonts.googleapis.com \
    fonts.gstatic.com; do
    resolve_and_allow "$HOST" 443
done

if [ -n "${MAESTRO_BACKEND_HOST:-}" ]; then
    echo "[egress-init] opening per-org backend: $MAESTRO_BACKEND_HOST:443"
    resolve_and_allow "$MAESTRO_BACKEND_HOST" 443
fi

if [ -n "${MAESTRO_TIER3_ALLOWLIST:-}" ]; then
    IFS=',' read -ra ENTRIES <<< "$MAESTRO_TIER3_ALLOWLIST"
    for ENTRY in "${ENTRIES[@]}"; do
        ENTRY=$(echo "$ENTRY" | xargs)
        if [ -z "$ENTRY" ]; then continue; fi
        if [[ "$ENTRY" == *:* ]]; then
            DEST="${ENTRY%:*}"
            PORT="${ENTRY##*:}"
            iptables -A OUTPUT -d "$DEST" -p tcp --dport "$PORT" -j ACCEPT
        else
            iptables -A OUTPUT -d "$ENTRY" -p tcp --dport 80 -j ACCEPT
            iptables -A OUTPUT -d "$ENTRY" -p tcp --dport 443 -j ACCEPT
        fi
    done
fi

iptables -A OUTPUT -m limit --limit 10/min -j LOG --log-prefix "MAESTRO_BLOCKED_EGRESS: " --log-level 4

RULE_COUNT=$(iptables -L OUTPUT --line-numbers 2>/dev/null | grep -c '^[0-9]')
echo "[egress-init] Tier 3 active — ${RULE_COUNT} rules loaded"
