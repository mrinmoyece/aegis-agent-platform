#!/bin/sh
set -eu

POSTGRES_IMAGE='pgvector/pgvector:pg16@sha256:ccc6e83d6e35e931dc7c5def2022729d5a6c370318d099181995567ff1fb4d6b'
REDIS_IMAGE='redis:7.4-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2'
POSTGRES_CONTAINER="aegis-restore-postgres-$$"
REDIS_CONTAINER="aegis-restore-redis-$$"
REPORT_PATH="${AEGIS_RESTORE_REPORT:-.aegis-evidence/restore-drill.json}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-restore.XXXXXX")"
PASSWORD='local-restore-drill-only'
PYTHON="${PYTHON:-python3}"

cleanup() {
  docker rm --force "${POSTGRES_CONTAINER}" "${REDIS_CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$(dirname "${REPORT_PATH}")"
docker run --detach --rm \
  --name "${POSTGRES_CONTAINER}" \
  --env POSTGRES_DB=aegis_source \
  --env POSTGRES_PASSWORD="${PASSWORD}" \
  --env POSTGRES_USER=postgres \
  --publish 127.0.0.1::5432 \
  --mount "type=bind,source=${WORK_DIR},target=/evidence" \
  "${POSTGRES_IMAGE}" >/dev/null
docker run --detach --rm \
  --name "${REDIS_CONTAINER}" \
  --publish 127.0.0.1::6379 \
  "${REDIS_IMAGE}" >/dev/null

ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if docker exec "${POSTGRES_CONTAINER}" pg_isready -U postgres -d aegis_source >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [ "${ready}" != "true" ]; then
  echo "restore drill PostgreSQL did not become ready" >&2
  exit 1
fi

POSTGRES_PORT="$(
  docker port "${POSTGRES_CONTAINER}" 5432/tcp | sed 's/.*://'
)"
AEGIS_MIGRATION_DATABASE_URL="postgresql://postgres:${PASSWORD}@127.0.0.1:${POSTGRES_PORT}/aegis_source" \
  "${PYTHON}" scripts/migrate.py --applied-by restore-drill >/dev/null

docker exec --interactive \
  --env PGPASSWORD="${PASSWORD}" \
  "${POSTGRES_CONTAINER}" \
  psql --set=ON_ERROR_STOP=1 --username postgres --dbname aegis_source \
  >/dev/null <<'SQL'
INSERT INTO tenants (tenant_id, display_name, created_at)
VALUES ('restore-tenant', 'Restore drill tenant', '2026-08-14T00:00:00Z');
UPDATE tenant_writer_fences
SET home_region = 'restore-region',
    state = 'active',
    enforcement_enabled = true,
    approved_change_reference = 'change-ref://restore-drill',
    updated_at = transaction_timestamp()
WHERE tenant_id = 'restore-tenant';
SELECT set_config('aegis.writer_region', 'restore-region', false);
SELECT set_config('aegis.writer_generation', '1', false);
INSERT INTO event_stream_heads (tenant_id, aggregate_id, current_version)
VALUES ('restore-tenant', 'restore-run', 2);
INSERT INTO tenant_event_commit_locks (tenant_id)
VALUES ('restore-tenant');
INSERT INTO events (
  event_id, tenant_id, aggregate_id, aggregate_sequence, event_type,
  schema_version, occurred_at, payload, metadata, actor_id, actor_kind
) VALUES
  (
    '11111111-1111-4111-8111-111111111111',
    'restore-tenant', 'restore-run', 1, 'restore.drill.started.v1',
    1, '2026-08-14T00:00:00Z', '{"step":"start"}', '{}',
    'restore-drill', 'system'
  ),
  (
    '22222222-2222-4222-8222-222222222222',
    'restore-tenant', 'restore-run', 2, 'restore.drill.completed.v1',
    1, '2026-08-14T00:00:01Z', '{"step":"complete"}', '{}',
    'restore-drill', 'system'
  );
INSERT INTO outbox_messages (
  tenant_id, message_id, event_id, destination, payload, headers,
  available_at, max_attempts
) VALUES (
  'restore-tenant',
  '33333333-3333-4333-8333-333333333333',
  '22222222-2222-4222-8222-222222222222',
  'aegis:work:v1',
  '{
    "work_id":"44444444-4444-4444-8444-444444444444",
    "correlation_id":"55555555-5555-4555-8555-555555555555",
    "operation":"restore-redrive"
  }',
  '{"tenant_id":"restore-tenant"}',
  '2026-08-14T00:00:01Z',
  8
);
INSERT INTO run_status_projection (
  tenant_id, run_id, status, aggregate_sequence, last_global_position, updated_at
)
SELECT
  tenant_id, aggregate_id, 'completed', max(aggregate_sequence),
  max(global_position), '2026-08-14T00:00:02Z'
FROM events
WHERE tenant_id = 'restore-tenant'
GROUP BY tenant_id, aggregate_id;
SQL

docker exec "${REDIS_CONTAINER}" redis-cli SET restore-drill ephemeral >/dev/null
docker exec \
  --env PGPASSWORD="${PASSWORD}" \
  "${POSTGRES_CONTAINER}" \
  pg_dump --format=custom --no-owner --no-privileges \
  --username postgres --dbname aegis_source --file /evidence/ledger.dump
docker exec \
  --env PGPASSWORD="${PASSWORD}" \
  "${POSTGRES_CONTAINER}" \
  createdb --username postgres aegis_restored
docker exec \
  --env PGPASSWORD="${PASSWORD}" \
  "${POSTGRES_CONTAINER}" \
  pg_restore --exit-on-error --no-owner --no-privileges \
  --username postgres --dbname aegis_restored /evidence/ledger.dump >/dev/null

docker exec \
  --env PGPASSWORD="${PASSWORD}" \
  "${POSTGRES_CONTAINER}" \
  psql --no-align --tuples-only --username postgres --dbname aegis_source \
  --command "SELECT to_jsonb(events)::text FROM events ORDER BY global_position" \
  > "${WORK_DIR}/source-events.txt"
docker exec \
  --env PGPASSWORD="${PASSWORD}" \
  "${POSTGRES_CONTAINER}" \
  psql --no-align --tuples-only --username postgres --dbname aegis_restored \
  --command "SELECT to_jsonb(events)::text FROM events ORDER BY global_position" \
  > "${WORK_DIR}/restored-events.txt"

source_checksum="$(shasum -a 256 "${WORK_DIR}/source-events.txt" | awk '{print $1}')"
restored_checksum="$(shasum -a 256 "${WORK_DIR}/restored-events.txt" | awk '{print $1}')"
source_count="$(wc -l < "${WORK_DIR}/source-events.txt" | tr -d ' ')"
restored_count="$(wc -l < "${WORK_DIR}/restored-events.txt" | tr -d ' ')"
source_max="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_source --command "SELECT coalesce(max(global_position), 0) FROM events")"
restored_max="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_restored --command "SELECT coalesce(max(global_position), 0) FROM events")"
source_history="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_source --command "SELECT count(*) || '|' || min(version) || '|' || max(version) FROM aegis_schema_migrations")"
restored_history="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_restored --command "SELECT count(*) || '|' || min(version) || '|' || max(version) FROM aegis_schema_migrations")"
source_history_checksum="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_source --command "SELECT version, migration_name, content_sha256, applied_at, applied_by FROM aegis_schema_migrations ORDER BY version" | shasum -a 256 | awk '{print $1}')"
restored_history_checksum="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_restored --command "SELECT version, migration_name, content_sha256, applied_at, applied_by FROM aegis_schema_migrations ORDER BY version" | shasum -a 256 | awk '{print $1}')"

docker exec "${POSTGRES_CONTAINER}" psql --username postgres --dbname aegis_restored \
  --command "DELETE FROM run_status_projection" >/dev/null
docker exec "${POSTGRES_CONTAINER}" psql --username postgres --dbname aegis_restored \
  --command "INSERT INTO run_status_projection (tenant_id, run_id, status, aggregate_sequence, last_global_position, updated_at) SELECT tenant_id, aggregate_id, 'completed', max(aggregate_sequence), max(global_position), '2026-08-14T00:00:02Z' FROM events GROUP BY tenant_id, aggregate_id" >/dev/null
projection_count="$(docker exec "${POSTGRES_CONTAINER}" psql --no-align --tuples-only --username postgres --dbname aegis_restored --command "SELECT count(*) FROM run_status_projection")"

docker exec "${REDIS_CONTAINER}" redis-cli FLUSHALL >/dev/null
redis_keys="$(docker exec "${REDIS_CONTAINER}" redis-cli DBSIZE | tr -d '\r')"
REDIS_PORT="$(
  docker port "${REDIS_CONTAINER}" 6379/tcp | sed 's/.*://'
)"
"${PYTHON}" scripts/restore_redrive.py \
  --database-url "postgresql://postgres:${PASSWORD}@127.0.0.1:${POSTGRES_PORT}/aegis_restored" \
  --redis-url "redis://127.0.0.1:${REDIS_PORT}/0" \
  --output "${WORK_DIR}/redrive.json"
redrive_published="$(
  "${PYTHON}" -c 'import json,sys; print(json.load(open(sys.argv[1]))["published"])' \
    "${WORK_DIR}/redrive.json"
)"
redis_keys_after_redrive="$(
  docker exec "${REDIS_CONTAINER}" redis-cli DBSIZE | tr -d '\r'
)"

if [ "${source_count}" != "${restored_count}" ] \
  || [ "${source_max}" != "${restored_max}" ] \
  || [ "${source_checksum}" != "${restored_checksum}" ] \
  || [ "${source_history}" != "11|1|11" ] \
  || [ "${source_history}" != "${restored_history}" ] \
  || [ "${source_history_checksum}" != "${restored_history_checksum}" ] \
  || [ "${projection_count}" != "1" ] \
  || [ "${redis_keys}" != "0" ] \
  || [ "${redrive_published}" != "1" ] \
  || [ "${redis_keys_after_redrive}" -lt "1" ]; then
  echo "restore integrity gate failed" >&2
  exit 1
fi

cat > "${REPORT_PATH}" <<EOF
{
  "backup_contents_logged": false,
  "backup_sha256": "$(shasum -a 256 "${WORK_DIR}/ledger.dump" | awk '{print $1}')",
  "drill_kind": "isolated-container-logical-restore",
  "migration_history": "${restored_history}",
  "migration_history_sha256": "${restored_history_checksum}",
  "projection_rows_rebuilt": ${projection_count},
  "redis_authoritative": false,
  "redis_keys_after_loss": ${redis_keys},
  "redis_keys_after_redrive": ${redis_keys_after_redrive},
  "restored_outbox_messages_redriven": ${redrive_published},
  "restored_event_count": ${restored_count},
  "restored_event_sha256": "${restored_checksum}",
  "restored_max_global_position": ${restored_max},
  "schema_version": 11,
  "source_event_count": ${source_count},
  "source_event_sha256": "${source_checksum}",
  "source_max_global_position": ${source_max},
  "status": "passed"
}
EOF
