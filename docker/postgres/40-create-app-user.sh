#!/bin/sh
set -eu

psql \
  --set=ON_ERROR_STOP=1 \
  --set=app_password="$AEGIS_POSTGRES_APP_PASSWORD" \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --file=- <<'SQL'
SELECT CASE
    WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_runtime')
        THEN 'true'
    ELSE 'false'
END AS aegis_runtime_exists \gset

\if :aegis_runtime_exists
ALTER ROLE aegis_runtime WITH PASSWORD :'app_password';
\else
CREATE ROLE aegis_runtime
    LOGIN INHERIT NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    PASSWORD :'app_password';
\endif

GRANT aegis_app TO aegis_runtime;
SQL
