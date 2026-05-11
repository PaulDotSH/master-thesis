# Multi-stage build for smaller final image
FROM rustlang/rust:nightly-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates_downloader/Cargo.toml ./crates_downloader/
COPY webpanel/Cargo.toml ./webpanel/

# Create dummy source files to cache dependencies
RUN mkdir -p crates_downloader/src webpanel/src && \
    echo "fn main() {}" > crates_downloader/src/main.rs && \
    echo "fn main() {}" > webpanel/src/main.rs

# Build dependencies (cached layer)
ENV RUSTFLAGS="-C target-cpu=native"
RUN cargo build --bin crates_downloader --profile production --manifest-path crates_downloader/Cargo.toml

# Remove dummy sources
RUN rm -rf crates_downloader/src

# Copy actual source code
COPY crates_downloader/src ./crates_downloader/src
COPY crates_downloader/migrations ./crates_downloader/migrations

# Build the actual application with production profile (LTO + native CPU)
RUN touch crates_downloader/src/main.rs && cargo build --profile production --manifest-path crates_downloader/Cargo.toml

# Install cargo-audit in builder (has nightly rust)
RUN cargo install cargo-audit

# Pre-fetch the advisory database and pre-seed the crates.io registry index.
# The registry index is copied to /cargo-seed in the runtime image and then
# copied into the tmpfs-mounted /usr/local/cargo at container startup by the
# entrypoint script. This avoids each worker downloading the registry from the
# network on first `cargo update --workspace`.
RUN cd /tmp && \
    cargo init --lib audit-init && \
    cd audit-init && \
    cargo fetch && \
    cargo audit 2>/dev/null || true && \
    cd / && rm -rf /tmp/audit-init

# Runtime stage - use same base as builder to avoid glibc issues
FROM rustlang/rust:nightly-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy cargo-audit, cargo, rustc, and advisory database from builder
# All binaries go to /usr/local/bin/ so they survive the tmpfs mount over /usr/local/cargo.
# cargo + rustc are needed by cargo-audit to run `cargo update --workspace` when a crate
# has no committed Cargo.lock.
COPY --from=builder /usr/local/cargo/bin/cargo-audit /usr/local/bin/cargo-audit
COPY --from=builder /usr/local/cargo/bin/cargo /usr/local/bin/cargo
COPY --from=builder /usr/local/cargo/bin/rustc /usr/local/bin/rustc
COPY --from=builder /usr/local/cargo/advisory-db /advisory-db

# Pre-seed the cargo registry so workers don't download the index from the network.
# At startup the entrypoint copies this into the tmpfs /usr/local/cargo (RAM),
# so all `cargo update --workspace` calls hit RAM instead of the network.
# Only registry/ is copied - git/ only exists for git-sourced deps (none here).
COPY --from=builder /usr/local/cargo/registry /cargo-seed/registry

# Install gitleaks (Go binary, not Rust)
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.21.2_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm gitleaks_8.21.2_linux_x64.tar.gz

WORKDIR /app

# Copy the built binary from builder (production profile outputs to target/production/)
COPY --from=builder /build/target/production/crates_downloader /app/crates_downloader

# Copy config
COPY crates_downloader/config.toml /app/config.toml

# Advisory-db is at /advisory-db, pre-seeded registry at /cargo-seed
# CARGO_NET_OFFLINE prevents cargo update from doing a git fetch on the index
# for every analyzed crate - the index is already fully pre-seeded in RAM.
ENV RUST_LOG=info
# ENV RUST_LOG=info \
    # CARGO_NET_OFFLINE=true

# Create temp directory for crate downloads
RUN mkdir -p /tmp/crates

# Entrypoint script: copy the pre-seeded registry into the tmpfs-mounted
# /usr/local/cargo before starting the worker. The copy is RAM-to-RAM (overlay2
# read → tmpfs write) and only happens once per container startup.
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["worker"]

