#!/bin/bash
# Build a static tmux binary for Tauri sidecar bundling.
# Outputs: src-tauri/binaries/tmux-{target_triple}
#
# Usage: cd frontend/src-tauri/scripts && ./build-tmux.sh

set -euo pipefail

TMUX_VERSION="3.5a"
LIBEVENT_VERSION="2.1.12-stable"
TARGET_TRIPLE=$(rustc -vV | sed -n 's/host: //p')
BUILD_DIR="$(mktemp -d)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../binaries"

echo "Building tmux ${TMUX_VERSION} for ${TARGET_TRIPLE}"
echo "Build directory: ${BUILD_DIR}"

cd "${BUILD_DIR}"

# Download and build libevent (static)
echo "==> Downloading libevent ${LIBEVENT_VERSION}..."
curl -LO "https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/libevent-${LIBEVENT_VERSION}.tar.gz"
tar xzf "libevent-${LIBEVENT_VERSION}.tar.gz"
cd "libevent-${LIBEVENT_VERSION}"
echo "==> Building libevent (static)..."
./configure --disable-shared --enable-static --prefix="${BUILD_DIR}/libevent-install" --disable-openssl
make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" && make install
cd "${BUILD_DIR}"

# Download and build tmux (statically linked against libevent)
echo "==> Downloading tmux ${TMUX_VERSION}..."
curl -LO "https://github.com/tmux/tmux/releases/download/${TMUX_VERSION}/tmux-${TMUX_VERSION}.tar.gz"
tar xzf "tmux-${TMUX_VERSION}.tar.gz"
cd "tmux-${TMUX_VERSION}"
echo "==> Building tmux..."
PKG_CONFIG_PATH="${BUILD_DIR}/libevent-install/lib/pkgconfig" \
  ./configure --disable-utf8proc LDFLAGS="-L${BUILD_DIR}/libevent-install/lib"
make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
cd "${BUILD_DIR}"

# Copy to sidecar location
mkdir -p "${OUTPUT_DIR}"
cp "tmux-${TMUX_VERSION}/tmux" "${OUTPUT_DIR}/tmux-${TARGET_TRIPLE}"
chmod +x "${OUTPUT_DIR}/tmux-${TARGET_TRIPLE}"

echo "==> Built successfully: ${OUTPUT_DIR}/tmux-${TARGET_TRIPLE}"

# Cleanup
rm -rf "${BUILD_DIR}"
echo "==> Done."
