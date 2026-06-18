#!/bin/bash
set -euo pipefail

# - Stops workers
# - Removes unused containers/images/networks
# docker-cleanup.sh --all # also remove cache volumes

REMOVE_VOLUMES=false
if [[ "${1:-}" == "--all" ]]; then
  REMOVE_VOLUMES=true
fi

echo "[1/4] Stopping worker stack"
sudo docker-compose -f docker-compose.workers.yml down || true

echo "[2/4] Removing stopped containers"
sudo docker container prune -f

echo "[3/4] Removing dangling/unused images"
sudo docker image prune -af

echo "[4/4] Removing unused build cache"
sudo docker builder prune -af

if [[ "$REMOVE_VOLUMES" == "true" ]]; then
  echo "Removing project cache volumes"
  sudo docker volume rm \
    master-thesis_worker_tmp 2>/dev/null || true
fi

