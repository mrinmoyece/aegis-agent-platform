#!/bin/sh
set -eu

psql \
  --set=ON_ERROR_STOP=1 \
  --set=app_password="$AEGIS_POSTGRES_APP_PASSWORD" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
SELECT format(
    'CREATE ROLE aegis_runtime LOGIN INHERIT NOBYPASSRLS PASSWORD %L',
    :'app_password'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'aegis_runtime'
)
\gexec
GRANT aegis_app TO aegis_runtime;
SQL
