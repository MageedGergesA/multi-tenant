#!/usr/bin/env bash
# Local stand-ins on Docker Desktop:
#   agent-pg        db-1 (PostgreSQL 16, pg_hba include_dir on volume agent-dev-hba)
#   agent-exec-dev  agent-exec as root on an app host; socket on volume agent-dev-sock
# Docker Desktop runs containers in a VM: host folders ignore chown and Unix
# sockets don't cross into the host, so tenant files, the socket and pg_hba
# fragments live in named volumes, and agentd runs in the VM too (dev/test.sh).
set -euo pipefail
DEV="$(cd "$(dirname "$0")" && pwd)"
AGENT_UID=1000
[ -f "$DEV/.env" ] || { echo "PG_SUPER_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" > "$DEV/.env"; chmod 600 "$DEV/.env"; }
. "$DEV/.env"

for v in agent-dev-root agent-dev-sock agent-dev-hba; do docker volume create "$v" >/dev/null; done
# agentd (uid 1000) owns the socket directory; the db-agent stand-in writes hba fragments;
# agentd reaches archives under srv/backup-tmp.
docker run --rm -v agent-dev-sock:/s -v agent-dev-hba:/h -v agent-dev-root:/r postgres:16 \
    sh -c "chown $AGENT_UID:$AGENT_UID /s /h && chmod 0750 /s && chmod 0755 /h && mkdir -p /r/srv/backup-tmp && chmod 0711 /r/srv/backup-tmp && mkdir -p /r/etc/traefik/dynamic" >/dev/null

# agent-s3: LocalStack S3 standing in for Backblaze B2 (Object Lock, compliance mode).
if ! docker container inspect agent-s3 >/dev/null 2>&1; then
    docker run -d --name agent-s3 -p 127.0.0.1:4566:4566 -e SERVICES=s3 localstack/localstack:4.4 >/dev/null
fi
docker start agent-s3 >/dev/null      # stopped by a Docker restart: created, not running
until curl -sf http://127.0.0.1:4566/_localstack/health >/dev/null; do sleep 1; done

if ! docker container inspect agent-pg >/dev/null 2>&1; then
    docker run -d --name agent-pg -e POSTGRES_PASSWORD="$PG_SUPER_PASSWORD" -p 127.0.0.1:55432:5432 \
        -v "$DEV/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" -v agent-dev-hba:/etc/postgresql/hba.d:ro \
        postgres:16 -c hba_file=/etc/postgresql/pg_hba.conf >/dev/null
fi
docker start agent-pg >/dev/null

cat > "$DEV/exec.toml" <<TOML
role = "app"
socket = "/sock/agent-exec.sock"
owner_uid = $AGENT_UID
audit_log = "/devroot/agent-exec-audit.log"

[app]
root = "/devroot"
root_volume = "agent-dev-root"
image_source = "local"
# Tenants reach db-1 through the host, as in production (their bridge has ICC off).
db_host = "host.docker.internal"
db_port = 55432
db_sslmode = "disable"
nft_mode = "dryrun"
cert_resolver = ""
TOML

docker build -q -t hostagent-exec:dev -f "$DEV/Dockerfile.exec" "$DEV/.." >/dev/null
docker rm -f agent-exec-dev >/dev/null 2>&1 || true
docker run -d --name agent-exec-dev --network none \
    -v /var/run/docker.sock:/var/run/docker.sock -v "$DEV/exec.toml:/etc/agent-exec.toml:ro" \
    -v agent-dev-root:/devroot -v agent-dev-sock:/sock \
    hostagent-exec:dev --config /etc/agent-exec.toml >/dev/null
until docker exec agent-pg pg_isready -q; do sleep 0.5; done
for _ in $(seq 30); do docker exec agent-exec-dev test -S /sock/agent-exec.sock && break; sleep 0.5; done
docker exec agent-exec-dev test -S /sock/agent-exec.sock || { docker logs agent-exec-dev | tail; exit 1; }
# agent-traefik: the ingress, on the Docker VM's network like tenants' loopback ports,
# with a default certificate from a dev CA (no ACME locally).
CERTS="$DEV/traefik/certs"
if [ ! -f "$CERTS/wildcard.pem" ]; then
    mkdir -p "$CERTS"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 -subj /CN=agent-dev-ca \
        -keyout "$CERTS/ca.key" -out "$CERTS/ca.pem" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=*.cloud.test" \
        -keyout "$CERTS/wildcard.key" -out "$CERTS/wildcard.csr" 2>/dev/null
    printf 'subjectAltName=DNS:*.cloud.test\nextendedKeyUsage=serverAuth\n' > "$CERTS/wildcard.ext"
    openssl x509 -req -in "$CERTS/wildcard.csr" -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca.key" -CAcreateserial \
        -days 365 -extfile "$CERTS/wildcard.ext" -out "$CERTS/wildcard.pem" 2>/dev/null
    chmod 644 "$CERTS"/*.pem "$CERTS"/*.key
fi
docker run --rm -v agent-dev-root:/r -v "$DEV/traefik:/t:ro" alpine cp /t/zz-dev-tls.yml /r/etc/traefik/dynamic/
if ! docker container inspect agent-traefik >/dev/null 2>&1; then
    docker run -d --name agent-traefik --network host -v "$DEV/traefik/traefik.yml:/etc/traefik/traefik.yml:ro" \
        -v "$CERTS:/certs:ro" --mount type=volume,src=agent-dev-root,dst=/dynamic,volume-subpath=etc/traefik/dynamic \
        traefik:v3.1.6 >/dev/null
fi
docker start agent-traefik >/dev/null

echo "up: agent-traefik :18443, agent-pg 127.0.0.1:55432, agent-s3 127.0.0.1:4566, agent-exec /sock/agent-exec.sock (volume agent-dev-sock)"
