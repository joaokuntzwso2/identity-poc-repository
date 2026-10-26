#!/usr/bin/env bash
# Initialize only the two empty PostgreSQL databases of the isolated WSO2 CIAM v10 project.
# Never operates on the existing H2-backed WSO2 container.
set -euo pipefail

PROJECT='wso2-ciam-v10'
IMAGE='wso2/wso2is:7.3.0'
WSO2_IMAGE_USER=wso2carbon
IS_HOME="/home/${WSO2_IMAGE_USER}/wso2is-7.3.0"
cd "${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}"

if docker inspect wso2-identity-server-1 >/dev/null 2>&1; then
  if [ "$(docker inspect -f '{{.State.Running}}' wso2-identity-server-1)" != true ]; then
    echo 'STOP: EXISTING_ORIGINAL_WSO2_NOT_RUNNING' >&2; exit 1
  fi
fi
if [ ! -f compose.yaml ]; then
  echo 'STOP: V10_COMPOSE_NOT_FOUND' >&2
  exit 1
fi
docker compose -p "$PROJECT" config --quiet

pg() {
  local db="$1"
  shift
  docker compose -p "$PROJECT" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U ciamadmin -d "$db" "$@"
}
table_count() {
  pg "$1" -Atc "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public';"
}

if [ "$(table_count ciam_identity)" != '0' ] || [ "$(table_count ciam_shared)" != '0' ]; then
  echo 'STOP: SCHEMA_NOT_EMPTY; never apply these scripts twice' >&2
  echo "IDENTITY_TABLES=$(table_count ciam_identity)"
  echo "SHARED_TABLES=$(table_count ciam_shared)"
  exit 1
fi

if [ -L sql ]; then
  echo 'STOP: SQL_DIRECTORY_IS_SYMLINK' >&2
  exit 1
fi
mkdir -p sql
umask 077
for f in identity.postgresql.sql consent.postgresql.sql shared.postgresql.sql; do
  if [ -e "sql/$f" ] || [ -L "sql/$f" ]; then
    echo "STOP: SQL_FILE_ALREADY_EXISTS: $f" >&2
    exit 1
  fi
done

extract_dir="$(mktemp -d "$PWD/.wso2-schema-extract.XXXXXX")"
temp_container=''
cleanup() {
  if [ -n "$temp_container" ]; then
    docker rm "$temp_container" >/dev/null 2>&1 || true
  fi
  if [ -n "$extract_dir" ] && [ -d "$extract_dir" ]; then
    rm -rf -- "$extract_dir"
  fi
}
trap cleanup EXIT

temp_container="$(docker create --entrypoint /bin/true "$IMAGE")"
docker cp "$temp_container:$IS_HOME/dbscripts/identity/postgresql.sql" "$extract_dir/identity.postgresql.sql"
docker cp "$temp_container:$IS_HOME/dbscripts/consent/postgresql.sql" "$extract_dir/consent.postgresql.sql"
docker cp "$temp_container:$IS_HOME/dbscripts/postgresql.sql" "$extract_dir/shared.postgresql.sql"

for f in identity.postgresql.sql consent.postgresql.sql shared.postgresql.sql; do
  if [ ! -f "$extract_dir/$f" ] || [ -L "$extract_dir/$f" ] || [ ! -s "$extract_dir/$f" ]; then
    echo "STOP: UNEXPECTED_OR_EMPTY_WSO2_SQL: $f" >&2
    exit 1
  fi
done

for f in identity.postgresql.sql consent.postgresql.sql shared.postgresql.sql; do
  mv "$extract_dir/$f" "sql/$f"
done
echo 'OFFICIAL_WSO2_730_SCHEMAS_EXTRACTED'

# Run each database's SQL in a single transaction; fail on the first SQL error.
{
  cat sql/identity.postgresql.sql
  printf '\n'
  cat sql/consent.postgresql.sql
} | pg ciam_identity --single-transaction -f - >/dev/null

pg ciam_shared --single-transaction -f - < sql/shared.postgresql.sql >/dev/null

identity_tables="$(table_count ciam_identity)"
shared_tables="$(table_count ciam_shared)"
echo "IDENTITY_TABLES=$identity_tables"
echo "SHARED_TABLES=$shared_tables"
if ! [[ "$identity_tables" =~ ^[1-9][0-9]*$ && "$shared_tables" =~ ^[1-9][0-9]*$ ]]; then
  echo 'STOP: UNEXPECTED_SCHEMA_TABLE_COUNTS' >&2
  exit 1
fi
echo 'WSO2_POSTGRESQL_SCHEMAS_INITIALIZED'
