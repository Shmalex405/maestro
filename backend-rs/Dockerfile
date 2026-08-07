# =============================================================================
# Maestro Backend (Rust port) — Production Image
# =============================================================================
# This image is published to Groovy's private ECR (repo: maestro-backend-rs)
# and pulled by every customer's ECS cluster. The Python `maestro-backend`
# image continues to be published in parallel during the soak window; cutover
# is a separate change outside this Dockerfile's concern.
#
# Design goals:
#   - Keep build context minimal (root `.dockerignore` constrains what ships).
#   - Compile in a rust:1.80 builder so the runtime stage has no toolchain.
#   - debian:bookworm-slim runtime: needs Chromium + fonts for report PDF
#     rendering (headless_chrome, see src/pdf.rs). We considered distroless
#     but Chromium requires a shell/runtime libs that distroless omits.
#   - Non-root user in runtime.
#   - Multi-arch (amd64 + arm64) handled by the GHA workflow via buildx.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------------
FROM rust:1.92-bookworm AS builder

WORKDIR /app

# Build deps for rustls / openssl / pkg-config users. `pkg-config` + openssl
# aren't needed (we use rustls throughout), but `libssl-dev` stays cheap and
# covers native deps if a crate pulls it in.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the workspace members this crate depends on.
COPY backend-rs ./backend-rs
COPY crates ./crates

# The PDF stylesheet is `include_str!`'d from src/pdf.rs at compile time.
# It lives alongside the MCP server's md-to-pdf.js so both PDF pipelines
# share one source of truth.
COPY docker/scripts/report-style.css ./docker/scripts/report-style.css

# Build the release binary. `--locked` guards against Cargo.lock drift.
WORKDIR /app/backend-rs
RUN cargo build --release --bin maestro-backend --locked

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Chromium for PDF rendering + fonts + CA certs for outbound TLS (JWKS
# fetch, OIDC discovery, S3 when enabled).
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_PATH=/usr/bin/chromium

# Non-root.
RUN groupadd --gid 1000 app \
 && useradd --uid 1000 --gid app --shell /bin/bash --create-home app

WORKDIR /app
COPY --from=builder /app/backend-rs/target/release/maestro-backend /usr/local/bin/maestro-backend
COPY --chown=app:app backend-rs/migrations /app/migrations

USER app
EXPOSE 8000

# No container-level HEALTHCHECK: in ECS the ALB target group health check
# on `/health` is authoritative. Keeping a separate container check would
# only be meaningful if this image ran outside ECS, and the previous
# `wget` variant was silently always-passing because wget isn't installed
# in debian-slim.

CMD ["/usr/local/bin/maestro-backend"]
