#!/usr/bin/env bash
#
# Boot tauri-driver under Xvfb, wait for it to listen, then exec the test
# command passed as args. Used by the Linux test-runner image.

set -euo pipefail

# Start dbus — webkit2gtk needs it.
mkdir -p /run/dbus
dbus-daemon --system --fork || true

# Headless display.
export DISPLAY=:99
Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp &
XVFB_PID=$!

# tauri-driver listens on :4444 by default.
tauri-driver --port "${TAURI_DRIVER_PORT:-4444}" &
DRIVER_PID=$!

cleanup() {
  kill "$DRIVER_PID" 2>/dev/null || true
  kill "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for tauri-driver to accept connections.
for i in $(seq 1 30); do
  if curl -fsSo /dev/null "http://127.0.0.1:${TAURI_DRIVER_PORT:-4444}/status"; then
    break
  fi
  sleep 1
  if [ "$i" = 30 ]; then
    echo "tauri-driver did not come up within 30s" >&2
    exit 1
  fi
done

# Sanity-check the binary the tests are about to drive.
if [ ! -x "${MAESTRO_BINARY_PATH:-/app/bin/Maestro}" ]; then
  echo "binary missing or not executable: ${MAESTRO_BINARY_PATH:-/app/bin/Maestro}" >&2
  echo "mount the built Tauri binary at /app/bin/Maestro (or set MAESTRO_BINARY_PATH)" >&2
  exit 1
fi

exec "$@"
