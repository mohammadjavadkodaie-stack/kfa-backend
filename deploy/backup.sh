#!/bin/sh
set -eu

BACKUP_DIR=${BACKUP_DIR:-./backups}
KEEP=${KEEP:-14}
COMPOSE_FILE=${COMPOSE_FILE:-deploy/docker-compose.prod.yml}
ENV_FILE=${ENV_FILE:-deploy/.env.production}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FILE="$BACKUP_DIR/kfa-$STAMP.sql.gz"
mkdir -p "$BACKUP_DIR"
umask 077

if ! docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec -T postgres \
  pg_dump --no-owner --no-privileges --clean --if-exists "${POSTGRES_DB:-kfa}" | gzip -c > "$FILE"; then
  rm -f "$FILE"
  echo "backup failed" >&2
  exit 1
fi
chmod 600 "$FILE"
find "$BACKUP_DIR" -type f -name 'kfa-*.sql.gz' -printf '%T@ %p\n' | sort -nr | awk "NR > $KEEP {print \$2}" | xargs -r rm -f
printf '%s\n' "$FILE"
# Documents live in S3-compatible object storage and are not backed up here.
