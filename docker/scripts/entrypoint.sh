#!/bin/bash
set -e

# Initialize Metasploit database if needed
if [ ! -f /var/lib/postgresql/.msf_db_initialized ]; then
    service postgresql start
    msfdb init || true
    touch /var/lib/postgresql/.msf_db_initialized
fi

# Update nuclei templates in background (non-blocking)
nuclei -update-templates -silent &

# Tier 3 outbound egress filter (v0.1.77+). No-op when MAESTRO_TIER3_EGRESS
# is unset or 0 — exits cleanly so this `set -e` script doesn't abort.
# When enabled, must run BEFORE the watchdog so the rules are in place
# before any health-check probes go out.
if [ -x /opt/pentest/scripts/egress-init.sh ]; then
    /opt/pentest/scripts/egress-init.sh || echo "[entrypoint] egress-init exited non-zero — Tier 3 may not be enforced" >&2
fi

# Watchdog runs in background. Exits silently when Tier 3 is off, so the
# unconditional invocation here is safe.
if [ -x /opt/pentest/scripts/egress-watchdog.sh ]; then
    /opt/pentest/scripts/egress-watchdog.sh &
fi

exec "$@"
