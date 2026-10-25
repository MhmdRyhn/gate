#!/usr/bin/env sh
# Dumps the bundled PostgreSQL database to ./backups and keeps 14 days.
# Run from the project directory, e.g. via cron:
#   15 2 * * * cd /opt/rbac-service && ./deploy/backup.sh >> /var/log/rbac-backup.log 2>&1
set -eu

BACKUP_DIR=${BACKUP_DIR:-./backups}
RETENTION_DAYS=${RETENTION_DAYS:-14}
mkdir -p "$BACKUP_DIR"

file="$BACKUP_DIR/rbac-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' > "$file.tmp"
mv "$file.tmp" "$file"
echo "backup written: $file"

find "$BACKUP_DIR" -name 'rbac-*.dump' -mtime +"$RETENTION_DAYS" -delete

# Off-site copy to any S3-compatible / SFTP / other storage (configure rclone first):
# rclone copy "$BACKUP_DIR" offsite:rbac-backups --max-age 25h
