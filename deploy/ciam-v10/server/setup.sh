#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}"
PROJECT=wso2-ciam-v10
OLD=wso2-identity-server-1
IMAGE=wso2/wso2is:7.3.0
WSO2_IMAGE_USER=wso2carbon
IS_HOME="/home/${WSO2_IMAGE_USER}/wso2is-7.3.0"
JDBC_VERSION=42.7.14
DRIVER="postgresql-$JDBC_VERSION.jar"
VOLUME=wso2-ciam-v10_isconf
SELF="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

fail() { printf 'V10_SETUP_STOP: %s\n' "$1" >&2; exit 1; }

[ -f "$ROOT/compose.yaml" ] || fail 'EXPECTED_ISOLATED_COMPOSE_NOT_FOUND'
[ -f "$ROOT/.env" ] || fail 'EXPECTED_PRIVATE_POSTGRES_ENV_NOT_FOUND'
[ -z "$(docker ps -q --filter name='^/wso2-ciam-v10-is-1$')" ] || fail 'NEW_IS_ALREADY_RUNNING'
[ ! -e "$ROOT/compose.identity.yaml" ] || fail 'IDENTITY_COMPOSE_ALREADY_EXISTS_REFUSE_OVERWRITE'
[ ! -e "$ROOT/private/deployment.toml" ] || fail 'PRIVATE_CONFIG_EXISTS_REFUSE_OVERWRITE'
[ ! -e "$ROOT/private/admin.private.json" ] || fail 'ADMIN_CREDENTIALS_EXIST_REFUSE_OVERWRITE'
[ ! -e "$ROOT/driver/$DRIVER" ] || fail 'JDBC_DRIVER_EXISTS_REFUSE_OVERWRITE'
if docker volume inspect "$VOLUME" >/dev/null 2>&1; then fail 'IS_CONFIG_VOLUME_ALREADY_EXISTS_REFUSE_OVERWRITE'; fi
if docker inspect "$OLD" >/dev/null 2>&1; then
  [ "$(docker inspect -f '{{.State.Running}}' "$OLD")" = true ] || fail 'EXISTING_OLD_WSO2_NOT_RUNNING';
fi

cd "$ROOT"
[ "$(docker compose -p "$PROJECT" exec -T postgres pg_isready -U ciamadmin -d postgres 2>/dev/null | grep -c 'accepting connections' || true)" -ge 1 ] || fail 'POSTGRES_NOT_READY'

table_count() {
  docker compose -p "$PROJECT" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U ciamadmin -d "$1" -Atc \
    "select count(*) from pg_catalog.pg_tables where schemaname='public';"
}
IDENTITY=$(table_count ciam_identity)
SHARED=$(table_count ciam_shared)
[ "$IDENTITY" -ge 150 ] && [ "$SHARED" -ge 50 ] || fail 'IDENTITY_SHARED_SCHEMA_NOT_INITIALIZED'

WORK="$(mktemp -d "$ROOT/.is-v10-setup.XXXXXX")"
chmod 700 "$WORK"
TMP_CONTAINER=''
cleanup() {
  if [ -n "$TMP_CONTAINER" ]; then docker rm "$TMP_CONTAINER" >/dev/null 2>&1 || true; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT

TMP_CONTAINER="$(docker create --entrypoint /bin/true "$IMAGE")"
docker cp "$TMP_CONTAINER:$IS_HOME/repository/conf/deployment.toml" "$WORK/stock.toml" >/dev/null
docker cp "$TMP_CONTAINER:$IS_HOME/dbscripts/identity/agent/postgresql.sql" "$WORK/agent.sql" >/dev/null
[ -s "$WORK/stock.toml" ] && [ -s "$WORK/agent.sql" ] || fail 'IMAGE_FILES_MISSING'
docker rm "$TMP_CONTAINER" >/dev/null
TMP_CONTAINER=''
echo 'OFFICIAL_WSO2_730_CONFIG_AND_AGENT_SCHEMA_FOUND'

mkdir -p driver private
chmod 700 private
curl --fail --location --silent --show-error --retry 2 \
  "https://repo.maven.apache.org/maven2/org/postgresql/postgresql/$JDBC_VERSION/$DRIVER" \
  -o "$WORK/$DRIVER"
python3 - "$WORK/$DRIVER" <<'PY'
import pathlib, sys, zipfile
p=pathlib.Path(sys.argv[1]);
if p.stat().st_size < 500000 or p.stat().st_size > 4000000: raise SystemExit('JDBC_JAR_SIZE_UNEXPECTED')
with zipfile.ZipFile(p) as z:
    if z.testzip() is not None or 'org/postgresql/Driver.class' not in z.namelist():
        raise SystemExit('JDBC_DRIVER_NOT_VALID')
print('POSTGRES_JDBC_JAR_VALIDATED')
PY
AGENT_PRESENT="$(docker compose -p "$PROJECT" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U ciamadmin -d postgres -Atc "select count(*) from pg_database where datname='ciam_agent';")"
if [ "$AGENT_PRESENT" = 0 ]; then
  docker compose -p "$PROJECT" exec -T postgres \
    psql -X -v ON_ERROR_STOP=1 -U ciamadmin -d postgres -c 'CREATE DATABASE ciam_agent;' >/dev/null
elif [ "$AGENT_PRESENT" != 1 ]; then
  fail 'AGENT_DATABASE_CATALOG_UNEXPECTED'
fi
AGENT_TABLES="$(table_count ciam_agent)"
[ "$AGENT_TABLES" = 0 ] || fail 'AGENT_DATABASE_NOT_EMPTY_STOP_FOR_REVIEW'
docker compose -p "$PROJECT" exec -T postgres \
  psql -X -v ON_ERROR_STOP=1 --single-transaction -U ciamadmin -d ciam_agent \
  < "$WORK/agent.sql" >/dev/null
AGENT_TABLES="$(table_count ciam_agent)"
[ "$AGENT_TABLES" -gt 0 ] || fail 'AGENT_SCHEMA_NO_TABLES'
echo "AGENT_IDENTITY_POSTGRES_SCHEMA_INITIALIZED tables=$AGENT_TABLES"


install -m 0644 "$WORK/$DRIVER" "driver/$DRIVER"
python3 "$SELF/render.py" "$WORK/stock.toml" .env private/deployment.toml private/admin.private.json

cat > compose.identity.yaml <<EOF
services:
  is:
    image: $IMAGE
    restart: "no"
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "127.0.0.1:9444:9444"
    volumes:
      - isconf:$IS_HOME/repository/conf
      - ./driver/$DRIVER:$IS_HOME/repository/components/lib/$DRIVER:ro
volumes:
  isconf:
EOF
chmod 600 compose.identity.yaml

docker compose -p "$PROJECT" -f compose.yaml -f compose.identity.yaml config --quiet

docker volume create "$VOLUME" >/dev/null
# A newly mounted named volume receives the stock image conf directory before replacement.
# In-container filesystem holds the password with UID/GID 802 and mode 0600.
docker run --rm --interactive --user 0:0 --entrypoint /bin/sh \
  --mount "type=volume,source=$VOLUME,target=$IS_HOME/repository/conf" \
  "$IMAGE" -c '
  set -eu
  p="'$IS_HOME'/repository/conf"
  [ ! -e "$p/.ciam-v10-managed" ] || exit 33
  [ -f "$p/deployment.toml" ] || exit 34
  umask 077
  cat > "$p/deployment.toml"
  chown 802:802 "$p/deployment.toml"
  chmod 600 "$p/deployment.toml"
  printf "wso2-ciam-v10\n" > "$p/.ciam-v10-managed"
  chown 802:802 "$p/.ciam-v10-managed"
  chmod 600 "$p/.ciam-v10-managed"
  ' < private/deployment.toml

echo 'ISOLATED_CONFIG_VOLUME_READY'
docker compose -p "$PROJECT" -f compose.yaml -f compose.identity.yaml up -d --no-deps is

docker compose -p "$PROJECT" -f compose.yaml -f compose.identity.yaml ps
if docker inspect "$OLD" >/dev/null 2>&1; then
  [ "$(docker inspect -f '{{.State.Running}}' "$OLD")" = true ] || fail 'ORIGINAL_WSO2_STATE_CHANGED'
  echo 'ORIGINAL_WSO2_PRESERVED_RUNNING'
else
  echo 'NO_LEGACY_WSO2_CONTAINER'
fi
echo 'V10_WSO2_START_REQUESTED https://localhost:9444/console'
echo 'CHECK_JAVA_LOGS: docker compose -p wso2-ciam-v10 -f compose.yaml -f compose.identity.yaml logs --tail 100 is'
echo 'BOOTSTRAP_CIAM_USERS_APPS: NOT_YET_IMPLEMENTED'
