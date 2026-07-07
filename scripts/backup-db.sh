#!/usr/bin/env bash
# Backup do Postgres do PAM (pg_dump comprimido + retencao). Lab/dev; produção
# usaria snapshot gerenciado ou WAL archiving. docs/phase4-operation.md.
#
# Uso:  BACKUP_DIR=/var/backups/pam RETENTION_DAYS=14 ./scripts/backup-db.sh
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../infra" && pwd)"
[ -f .env ] && set -a && . ./.env && set +a

BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/pam-$STAMP.sql.gz"

docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-pam}" "${POSTGRES_DB:-pam}" | gzip > "$OUT"
echo "backup gravado em $OUT"

find "$BACKUP_DIR" -name 'pam-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete
echo "retencao aplicada: backups com mais de $RETENTION_DAYS dias removidos"
