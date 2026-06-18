#!/bin/bash
set -e

# Configuration
DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5432/crates}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DB_USER=$(echo "$DATABASE_URL" | sed -n 's|.*://\([^:]*\):.*|\1|p')
DB_PASSWORD=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')
DB_HOST=$(echo "$DATABASE_URL" | sed -n 's|.*@\([^:]*\):.*|\1|p')
DB_PORT=$(echo "$DATABASE_URL" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
DB_NAME=$(echo "$DATABASE_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

echo "Host: $DB_HOST:$DB_PORT"
echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "" 

if ! command -v diesel &> /dev/null; then
    echo "Error: diesel CLI is not installed."
    exit 1
fi

if ! command -v psql &> /dev/null; then
    echo "Error: psql is not installed."
    exit 1
fi

export PGPASSWORD="$DB_PASSWORD"

# Try to refresh collation versions if there's a mismatch
echo "Checking and refreshing collation versions..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;" 2>/dev/null || true
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "ALTER DATABASE postgres REFRESH COLLATION VERSION;" 2>/dev/null || true

echo "Dropping database '$DB_NAME' if it exists..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME;"

echo "Creating database '$DB_NAME'..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME;"

echo "Running Diesel migrations..."
cd "$SCRIPT_DIR/crates_downloader"
diesel migration run --database-url "$DATABASE_URL" --migration-dir ./migrations
