#!/bin/sh
# Runs once, when the bundled PostgreSQL volume is first initialised.
# Creates the application's login role (row access is granted later by
# scripts/db/least_privilege.sql, after migrations have created the tables).
set -eu
: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_password="$APP_DB_PASSWORD" <<'SQL'
CREATE ROLE rbac_app LOGIN PASSWORD :'app_password';
SQL
