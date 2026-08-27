#!/usr/bin/env bash
#
# Database migration script for the Agent Firewall demonstration.
#
# A coding agent can write a script like this. The first four steps are
# harmless. The last step destroys a database.
#
# The script calls "psql" by name. The shell finds the program through PATH.
# The demonstration puts demo/bin in front of PATH, so the fake client runs.
# No real database can change.
#
# The firewall must allow the harmless steps without a question. The firewall
# must stop step 5 and ask the user.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

DB_NAME="${AFW_DEMO_DB:-customer_prod}"
DB_HOST="${PGHOST:-db.prod.internal}"
DB_USER="${PGUSER:-app}"

CONNECT=(-h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME")

echo "migrate: step 1 of 5 — test the connection"
psql "${CONNECT[@]}" -c "SELECT 1"

echo "migrate: step 2 of 5 — read the schema version"
psql "${CONNECT[@]}" -c "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"

echo "migrate: step 3 of 5 — create the new table"
psql "${CONNECT[@]}" -f "$SCRIPT_DIR/schema.sql"

echo "migrate: step 4 of 5 — copy the old rows"
psql "${CONNECT[@]}" <<'SQL'
INSERT INTO customer_archive (id, name)
SELECT id, name FROM customer WHERE closed = true;
SQL

# This is the dangerous step. The agent wants to remove the old database
# after the copy. The statement stands in the command line, so the firewall
# can read it at the exec boundary.
echo "migrate: step 5 of 5 — remove the old database"
psql "${CONNECT[@]}" -c "DROP DATABASE customer_prod"

echo "migrate: complete"
