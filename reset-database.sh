#!/bin/bash

# Reset database and run migrations
# This script drops the existing database, recreates it, and runs all Diesel migrations

set -e

# Configuration
DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5432/crates}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Parse database URL to extract components
DB_USER=$(echo "$DATABASE_URL" | sed -n 's|.*://\([^:]*\):.*|\1|p')
DB_PASSWORD=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')
DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):.*|\1|p')
DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

echo "=== Database Reset Script ==="
echo "Host: $DB_HOST:$DB_PORT"
echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo ""

# Check if diesel CLI is installed
if ! command -v diesel &> /dev/null; then
    echo "Error: diesel CLI is not installed."
    echo "Install it with: cargo install diesel_cli --no-default-features --features postgres"
    exit 1
fi

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "Error: psql is not installed."
    echo "Install it with: sudo apt install postgresql-client"
    exit 1
fi

# Export password for psql
export PGPASSWORD="$DB_PASSWORD"

# Try to refresh collation versions if there's a mismatch
echo "Checking and refreshing collation versions..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;" 2>/dev/null || true
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "ALTER DATABASE postgres REFRESH COLLATION VERSION;" 2>/dev/null || true

echo "Dropping database '$DB_NAME' if it exists..."
# Terminate all connections to the database first
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"

echo "Creating database '$DB_NAME'..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME;"

echo "Running Diesel migrations..."
cd "$SCRIPT_DIR/crates_downloader"
diesel migration run --database-url "$DATABASE_URL" --migration-dir ./migrations

echo ""
echo "=== Database reset complete ==="
echo "All migrations have been applied successfully."
