#!/usr/bin/env bash
# Run tests inside the Docker VM as agentd would run on a host (uid 1000, host
# network for loopback health probes, the executor socket from agent-dev-sock).
#   dev/test.sh                       # the Tenant.Create end-to-end test
#   dev/test.sh tests/                # everything
set -euo pipefail
DEV="$(cd "$(dirname "$0")" && pwd)"
. "$DEV/.env"
DIGEST=$(docker image inspect --format '{{.Id}}' bench/odoo:19.0-faee5d865473)
docker build -q -t hostagent-agentd:dev -f "$DEV/Dockerfile.agentd" "$DEV" >/dev/null
docker run --rm --network host -v "$DEV/..:/src:ro" -v agent-dev-sock:/sock -v agent-dev-hba:/hba \
    -e AGENT_EXEC_SOCKET=/sock/agent-exec.sock -e AGENT_HBA_DIR=/hba -e AGENT_PG_PASSWORD="$PG_SUPER_PASSWORD" \
    --mount type=volume,src=agent-dev-root,dst=/backup-tmp,volume-subpath=srv/backup-tmp \
    -e AGENT_BACKUP_TMP=/backup-tmp -e AGENT_S3_ENDPOINT=http://127.0.0.1:4566 \
    -e AGENT_IMAGE_DIGEST="$DIGEST" -e AGENT_KEEP="${AGENT_KEEP:-}" \
    -e AGENT_INGRESS_URL=https://127.0.0.1:18443 -e AGENT_INGRESS_CA=/src/dev/traefik/certs/ca.pem \
    hostagent-agentd:dev python -m pytest -p no:cacheprovider -q "${@:-tests/test_create_e2e.py}"
