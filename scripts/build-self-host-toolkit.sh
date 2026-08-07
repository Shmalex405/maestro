#!/usr/bin/env bash
#
# Build the Maestro Kali toolkit image from source.
#
# The managed product pulls a prebuilt image from Groovy's private GHCR. A
# self-hosted deployment has no access to that registry, so it builds the same
# image from docker/Dockerfile.kali — which is Apache-2.0 and complete. This is
# not a stripped-down variant: it is the identical definition CI publishes.
#
# Usage:
#   ./scripts/build-self-host-toolkit.sh [TAG]
#
#   TAG   Image tag to produce. Default: maestro-toolkit:local
#
# Then build the desktop app pointing at it:
#   KALI_IMAGE=maestro-toolkit:local MAESTRO_DISTRIBUTION=self-host \
#     npm run tauri:build -- --config src-tauri/tauri.self-host.conf.json
#
# The desktop checks for the image locally before attempting a registry pull, so
# a locally-built tag is used as-is and never fetched.
#
# Expect 30-60 minutes and ~15 GB of disk on a first build. The image installs
# kali-linux-headless plus pinned tooling; there is no way to make that small.

set -euo pipefail

cd "$(dirname "$0")/.."

TAG="${1:-maestro-toolkit:local}"

# ── Preflight ────────────────────────────────────────────────────────────────

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found on PATH." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "error: the Docker daemon is not responding. Start Docker and retry." >&2
  exit 1
fi

if [[ ! -f docker/Dockerfile.kali ]]; then
  echo "error: docker/Dockerfile.kali not found — run this from the repo root." >&2
  exit 1
fi

# amd64 only, and deliberately so. kali-rolling's systemd segfaults under
# qemu-aarch64 emulation, so an arm64 build fails partway through the systemd
# postinst with a QEMU internal SIGSEGV. Apple Silicon runs the amd64 image
# fine under Docker Desktop's emulation — slower, but it works. Forcing the
# platform here means an M-series Mac produces a working image instead of
# failing 40 minutes into a build.
PLATFORM="linux/amd64"

host_arch="$(uname -m)"
if [[ "$host_arch" == "arm64" || "$host_arch" == "aarch64" ]]; then
  echo "note: building linux/amd64 on $host_arch under emulation."
  echo "      This is the supported arrangement — a native arm64 build of this"
  echo "      image does not work (kali systemd segfaults under QEMU). Expect"
  echo "      the build and subsequent scans to run slower than on amd64."
  echo
fi

# ── Build ────────────────────────────────────────────────────────────────────

echo "Building $TAG for $PLATFORM from docker/Dockerfile.kali..."
echo "Build context: docker/"
echo

# `docker/` is the build context — the Dockerfile COPYs scripts/ from there.
docker build \
  --platform "$PLATFORM" \
  -f docker/Dockerfile.kali \
  -t "$TAG" \
  docker

echo
echo "Built $TAG"
echo

# ── Report what actually landed ──────────────────────────────────────────────
#
# A toolkit image that built successfully but is missing scanners produces
# assessments where tests report PASS because nothing ran. The provenance gate
# (check_tool_provenance) catches that at report time and forces those to
# BLOCKED, but it is much better to know now.

echo "Verifying core tooling is present..."
missing=()
for tool in nmap nuclei sqlmap semgrep nikto gitleaks trivy grype; do
  if docker run --rm --entrypoint sh "$TAG" -c "command -v $tool >/dev/null 2>&1"; then
    printf '  ok       %s\n' "$tool"
  else
    printf '  MISSING  %s\n' "$tool"
    missing+=("$tool")
  fi
done

echo
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "warning: ${#missing[@]} tool(s) missing: ${missing[*]}"
  echo
  echo "The image is usable, but every test backed by a missing tool will be"
  echo "reported BLOCKED rather than PASS — the provenance gate refuses to let"
  echo "an absent scanner masquerade as clean coverage. Re-run the build, or"
  echo "install the missing tools and commit a Dockerfile change."
  exit 1
fi

echo "All core tooling present."
echo
echo "Next — build the desktop app from frontend/:"
echo
echo "  KALI_IMAGE=$TAG \\"
echo "  MAESTRO_DISTRIBUTION=self-host \\"
echo "    npm run tauri:build -- --config src-tauri/tauri.self-host.conf.json"
echo
echo "MAESTRO_DISTRIBUTION=self-host makes the app default to LOCAL mode: all"
echo "data in the local SQLite DB, no AWS and no sign-in. Omit it only if you"
echo "are building against a managed deployment."
echo
echo "See SELF-HOSTING.md for the full sequence."
