#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
SQL_DIR="${SCRIPT_DIR}/sql"

DB="${PGDATABASE:-postgres://postgres:postgres@localhost:5432/crates}"

mkdir -p "${OUTPUT_DIR}/plots"
mkdir -p "${OUTPUT_DIR}/data"

python3 "${SCRIPT_DIR}/analyze.py" --db "${DB}" --out-dir "${OUTPUT_DIR}" "$@"
