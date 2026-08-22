#!/bin/sh
set -eu

# Pass the password as a session-level GUC so PL/pgSQL can read it with
# current_setting().  psql \set variable interpolation does not occur inside
# dollar-quoted DO blocks (the text is sent verbatim to the server), so
# :'app_password' would arrive as invalid PL/pgSQL syntax and abort init.
psql \
  --set=ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -c "SET app.app_password = '$AEGIS_POSTGRES_APP_PASSWORD'" \
  --file=- <<'SQL'
DO $$
DECLARE pw text := current_setting('app.app_password');
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_runtime') THEN
        EXECUTE format(
            'ALTER ROLE aegis_runtime WITH LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
            pw
        );
    ELSE
        EXECUTE format(
            'CREATE ROLE aegis_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
            pw
        );
    END IF;
END;
$$;
GRANT aegis_app TO aegis_runtime;
SQL
