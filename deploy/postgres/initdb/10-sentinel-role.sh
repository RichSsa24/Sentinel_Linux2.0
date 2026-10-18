#!/bin/sh
# Runs once, when the PostgreSQL data volume is first initialised (the
# official image executes /docker-entrypoint-initdb.d as the bootstrap
# superuser). Sentinel gets its own role: it owns its database, so it can run
# its migrations there, and nothing else — no superuser (no COPY ... PROGRAM,
# no other databases), no role or database creation, no replication.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v app_password="$POSTGRES_APP_PASSWORD" <<'SQL'
CREATE ROLE sentinel LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
    PASSWORD :'app_password';
CREATE DATABASE sentinel OWNER sentinel;
REVOKE ALL ON DATABASE sentinel FROM PUBLIC;
-- Every role may connect to the maintenance databases by default.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
SQL
