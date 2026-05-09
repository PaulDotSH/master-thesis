#!/bin/bash
# Start workers for a limited time, then shut them down gracefully.
#
# Usage:
#   ./start-timed.sh              # Default: 24 workers, 8 hours
#   ./start-timed.sh 10           # 10 workers, 8 hours
#   ./start-timed.sh 10 4         # 10 workers, 4 hours

NUM_WORKERS=${1:-24}
HOURS=${2:-8}
SECONDS_TO_RUN=$(( HOURS * 3600 ))

echo "Starting $NUM_WORKERS workers for $HOURS hour(s)..."
sudo docker-compose -f docker-compose.workers.yml up -d --scale worker=$NUM_WORKERS

echo "Workers running. Will stop in $HOURS hour(s) (at $(date -d "+${SECONDS_TO_RUN} seconds" '+%H:%M:%S'))."
sleep $SECONDS_TO_RUN

echo "Time's up. Shutting down workers..."
sudo docker-compose -f docker-compose.workers.yml down
echo "Done."
