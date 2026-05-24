FROM rustlang/rust:nightly-slim as builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates_downloader/Cargo.toml ./crates_downloader/
COPY webpanel/Cargo.toml ./webpanel/

# Create dummy source files to cache dependencies
RUN mkdir -p crates_downloader/src webpanel/src && \
    echo "fn main() {}" > crates_downloader/src/main.rs && \
    echo "fn main() {}" > webpanel/src/main.rs

ENV RUSTFLAGS="-C target-cpu=native"
RUN cargo build --bin crates_downloader --profile production --manifest-path crates_downloader/Cargo.toml

RUN rm -rf crates_downloader/src

COPY crates_downloader/src ./crates_downloader/src
COPY crates_downloader/migrations ./crates_downloader/migrations

RUN touch crates_downloader/src/main.rs && cargo build --profile production --manifest-path crates_downloader/Cargo.toml

RUN cargo install cargo-audit

# Pre-fetch the advisory database and pre-seed the crates.io registry index.
RUN cd /tmp && \
    cargo init --lib audit-init && \
    cd audit-init && \
    cargo fetch && \
    cargo audit 2>/dev/null || true && \
    cd / && rm -rf /tmp/audit-init

FROM rustlang/rust:nightly-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libpq5 \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/cargo-audit /usr/local/bin/cargo-audit
COPY --from=builder /usr/local/cargo/bin/cargo /usr/local/bin/cargo
COPY --from=builder /usr/local/cargo/bin/rustc /usr/local/bin/rustc
COPY --from=builder /usr/local/cargo/advisory-db /advisory-db

COPY --from=builder /usr/local/cargo/registry /cargo-seed/registry

RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz && \
    tar -xzf gitleaks_8.21.2_linux_x64.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm gitleaks_8.21.2_linux_x64.tar.gz

WORKDIR /app

COPY --from=builder /build/target/production/crates_downloader /app/crates_downloader

COPY crates_downloader/config.toml /app/config.toml

# CARGO_NET_OFFLINE prevents cargo update from doing a git fetch on the index
ENV RUST_LOG=info
# ENV RUST_LOG=info \
    # CARGO_NET_OFFLINE=true

RUN mkdir -p /tmp/crates

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["worker"]

