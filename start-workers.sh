#!/bin/bash
# Start Docker workers for distributed crate analysis
#
#      cargo run --release -- run-analysis          # Queue all crates
#      ./start-workers.sh           # Default: 24 workers
#      ./start-workers.sh 10
#      cargo run --release -- queue-status

NUM_WORKERS=${1:-24}
sudo docker-compose -f docker-compose.workers.yml up -d --scale worker=$NUM_WORKERS