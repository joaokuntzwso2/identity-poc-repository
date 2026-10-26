#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/wso2-ciam-v10"
echo 'CIAM_V10_ISOLATED_RUNTIME_STATUS'
for name in wso2-identity-server-1 wso2-ciam-v10-postgres-1 wso2-ciam-v10-is-1; do
  if docker inspect "$name" >/dev/null 2>&1; then
    docker inspect -f 'name={{.Name}} running={{.State.Running}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}NOT_CONFIGURED{{end}} restarts={{.RestartCount}}' "$name" | sed 's/name=\///'
  else
    echo "name=$name status=NOT_CREATED"
  fi
done
for db in ciam_identity ciam_shared ciam_agent; do
  if docker compose -p wso2-ciam-v10 exec -T postgres psql -X -v ON_ERROR_STOP=1 -U ciamadmin -d "$db" -Atc 'select 1' >/dev/null 2>&1; then
    n=$(docker compose -p wso2-ciam-v10 exec -T postgres psql -X -v ON_ERROR_STOP=1 -U ciamadmin -d "$db" -Atc "select count(*) from pg_catalog.pg_tables where schemaname='public';")
    echo "database=$db table_count=$n"
  else
    echo "database=$db state=UNAVAILABLE"
  fi
done
code=$(curl -k -sS --connect-timeout 2 --max-time 12 -o /dev/null -w '%{http_code}' 'https://localhost:9444/console' 2>/dev/null) || code=000
echo "new_console_http=$code"
if [ "$code" = 200 ] || [ "$code" = 302 ] || [ "$code" = 303 ]; then
  echo 'NEW_WSO2_HTTPS_REACHABLE'
else
  echo 'NEW_WSO2_HTTPS_NOT_YET_READY_OR_FAILED'
fi
echo 'CIAM_PROVISIONING=NOT_YET_IMPLEMENTED'
