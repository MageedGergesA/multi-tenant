#!/usr/bin/env bash
docker rm -f agent-exec-dev agent-pg agent-s3 >/dev/null 2>&1 || true
# Volumes kept; to wipe every dev tenant file and hba fragment:
#   docker volume rm agent-dev-root agent-dev-sock agent-dev-hba
echo "stopped"
