#!/bin/bash
# Start Docker workers for distributed crate analysis
#
# Usage:
#   1. Queue work first (either full analysis or single crate):
#      cargo run --release -- run-analysis          # Queue all crates
#      cargo run --release -- queue-crate --name serde  # Queue single crate + deps
#
#   2. Start workers:
#      ./start-workers.sh           # Default: 24 workers
#      ./start-workers.sh 10        # Custom: 10 workers
#
#   3. Check progress:
#      cargo run --release -- queue-status

NUM_WORKERS=${1:-24}
sudo docker-compose -f docker-compose.workers.yml up -d --scale worker=$NUM_WORKERS