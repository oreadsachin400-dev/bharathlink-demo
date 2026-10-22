#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 validate_target.py
command -v psql >/dev/null || { echo 'BLOCKED: psql not installed' >&2; exit 3; }
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGSERVICE PGSERVICEFILE PGOPTIONS PGSSLMODE PGCONNECT_TIMEOUT
{
cat <<'SQL'
BEGIN;
DO $guard$
BEGIN
 IF current_database() <> 'bharathlink_disposable_v30' OR inet_server_addr() IS DISTINCT FROM inet '127.0.0.1' AND inet_server_addr() IS DISTINCT FROM inet '::1' THEN
  RAISE EXCEPTION 'REFUSED: database identity or server address mismatch';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema' AND nspname <> 'public' AND nspname <> 'auth') THEN
  RAISE EXCEPTION 'REFUSED: preexisting custom schema';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='auth') THEN
  RAISE EXCEPTION 'REFUSED: preexisting auth schema';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
              AND c.relkind IN ('r','p','v','m','S','f')) THEN
  RAISE EXCEPTION 'REFUSED: database has existing user relations';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_extension WHERE extname <> 'plpgsql') THEN
  RAISE EXCEPTION 'REFUSED: database has additional extensions';
 END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('anon','authenticated','service_role')) THEN
  RAISE EXCEPTION 'REFUSED: test roles already exist';
 END IF;
END $guard$;
SQL
cat bootstrap_local.sql
sed "/^BEGIN;$/d; /^COMMIT;$/d" schema_NOT_FOR_LIVE.sql
cat assertions_local.sql
printf '\nCOMMIT;\n'
} | psql "$LOCAL_TEST_DATABASE_URL" -X -v ON_ERROR_STOP=1 -f -
echo 'PASS: PostgreSQL transaction committed successfully'
