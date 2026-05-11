#!/bin/sh
# The cargo registry is pre-seeded into the cargo-registry named volume by the
# registry-seeder service at startup. Workers mount it read-only at
# /usr/local/cargo/registry. No per-container copy needed.
# Ensure git/ dir exists (cargo expects it even when empty).
mkdir -p /usr/local/cargo/git

exec /app/crates_downloader "$@"
