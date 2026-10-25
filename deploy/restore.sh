#!/usr/bin/env sh
# Restores a dump produced by backup.sh into the bundled PostgreSQL, then
# re-applies least-privilege grants (pg_restore --no-owner drops them).
# Usage: ./deploy/restore.sh backups/rbac-20261019T021500Z.dump
set -eu

file=${1:?usage: restore.sh <dump-file>}

docker compose stop app
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' < "$file"
docker compose run --rm grants
docker compose start app
echo "restored from $file"
