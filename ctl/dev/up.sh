#!/usr/bin/env bash
# ctl-pg: the control plane's own PostgreSQL 16 (DOC-03 §0), never agent-pg (db-1).
set -euo pipefail
DEV="$(cd "$(dirname "$0")" && pwd)"
[ -f "$DEV/.env" ] || { echo "CTL_PG_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" > "$DEV/.env"; chmod 600 "$DEV/.env"; }
. "$DEV/.env"
if ! docker container inspect ctl-pg >/dev/null 2>&1; then
    docker run -d --name ctl-pg -e POSTGRES_PASSWORD="$CTL_PG_PASSWORD" -p 127.0.0.1:55433:5432 postgres:16 >/dev/null
fi
docker start ctl-pg >/dev/null      # stopped by a Docker restart: created, not running
until docker exec ctl-pg pg_isready -q -U postgres; do sleep 0.5; done
echo "up: ctl-pg 127.0.0.1:55433"
