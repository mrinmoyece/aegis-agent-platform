#!/bin/sh
set -eu

psql \
  --set=ON_ERROR_STOP=1 \
  --set=app_password="$AEGIS_POSTGRES_APP_PASSWORD" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_runtime') THEN
    EXECUTE format(
      'CREATE ROLE aegis_runtime LOGIN INHERIT NOBYPASSRLS PASSWORD %L',
      :'app_password'
    );
  ELSE
    EXECUTE format(
      'ALTER ROLE aegis_runtime PASSWORD %L',
      :'app_password'
    );
  END IF;
END $$;
GRANT aegis_app TO aegis_runtime;
SQL
