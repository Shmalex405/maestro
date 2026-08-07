# Linux test-runner image for the desktop e2e suite.
#
# Brings up tauri-driver under xvfb, runs the WebdriverIO suite against a
# pre-built Tauri binary mounted in at /app/bin/Maestro.
#
# Build:
#   docker build -f tests-e2e-desktop/Dockerfile -t maestro-e2e .
# Run (binary must exist on the host first):
#   docker run --rm -v $PWD/frontend/src-tauri/target/debug:/app/bin maestro-e2e

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Base system + webkit2gtk for Tauri's WebView + xvfb for the virtual
# display. `webkit2gtk-driver` ships WebKitWebDriver which tauri-driver
# proxies on Linux.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        libgtk-3-0 \
        libwebkit2gtk-4.1-0 \
        webkit2gtk-driver \
        libayatana-appindicator3-1 \
        librsvg2-2 \
        libsoup-3.0-0 \
        xvfb \
        xauth \
        dbus \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# Node 20 for WebdriverIO
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g pnpm@9

# Rust toolchain (only needed to install tauri-driver). Removed at the
# end of the layer to keep the image small — we don't need cargo at runtime.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable \
    && . "$HOME/.cargo/env" \
    && cargo install tauri-driver --locked \
    && cp "$HOME/.cargo/bin/tauri-driver" /usr/local/bin/tauri-driver \
    && rustup self uninstall -y

WORKDIR /app/tests

# Install JS deps as a separate layer so changes to specs don't bust the cache.
COPY tests-e2e-desktop/package.json /app/tests/package.json
RUN pnpm install --frozen-lockfile=false

# Copy the rest of the suite.
COPY tests-e2e-desktop /app/tests

# Default binary location — override with MAESTRO_BINARY_PATH at run time.
ENV MAESTRO_BINARY_PATH=/app/bin/Maestro
ENV MAESTRO_TEST_BYPASS_AUTH=1
ENV TAURI_DRIVER_HOST=127.0.0.1
ENV TAURI_DRIVER_PORT=4444

# Entrypoint: start dbus + tauri-driver under xvfb, then run wdio.
COPY tests-e2e-desktop/scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["pnpm", "test"]
