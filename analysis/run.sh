#!/usr/bin/env bash
# =============================================================================
# Master Thesis - Crate Security Analysis Runner
# =============================================================================
# Runs all SQL queries and the Python analysis/visualization script.
#
# Usage:
#   ./run.sh                          # Run everything (plots + data output)
#   ./run.sh --skip-plots             # Only run queries, skip visualizations
#   ./run.sh --only-sql 03            # Only run typosquatting analysis
#   ./run.sh --db "postgres://..."    # Custom DB connection string
#
# Prerequisites:
#   - PostgreSQL running with the crates database
#   - psql available on PATH
#   - Python 3 with matplotlib (for plots)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
SQL_DIR="${SCRIPT_DIR}/sql"

# Default DB connection (override with --db or PGDATABASE env)
DB="${PGDATABASE:-postgres://postgres:postgres@localhost:5432/crates}"

echo "========================================"
echo "  CRATE ECOSYSTEM SECURITY ANALYSIS"
echo "========================================"
echo "  DB:     ${DB}"
echo "  Output: ${OUTPUT_DIR}"
echo "========================================"
echo ""

mkdir -p "${OUTPUT_DIR}/plots"
mkdir -p "${OUTPUT_DIR}/data"

# Run Python analysis script (which handles both SQL execution and plotting)
python3 "${SCRIPT_DIR}/analyze.py" --db "${DB}" --out-dir "${OUTPUT_DIR}" "$@"

echo ""
echo "Done."
