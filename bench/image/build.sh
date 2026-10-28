#!/usr/bin/env bash
# Build the benchmark image from a pinned Odoo 19.0 commit and record its
# provenance in evidence/image.json (DOC-06 §10).
set -euo pipefail
cd "$(dirname "$0")"

ODOO_COMMIT="${ODOO_COMMIT:-$(git ls-remote https://github.com/odoo/odoo refs/heads/19.0 | cut -f1)}"
WKHTMLTOX_SHA256="${WKHTMLTOX_SHA256:-}"
TAG="bench/odoo:19.0-${ODOO_COMMIT:0:12}"

docker build --pull \
    --build-arg ODOO_COMMIT="$ODOO_COMMIT" \
    --build-arg WKHTMLTOX_SHA256="$WKHTMLTOX_SHA256" \
    -t "$TAG" .

IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$TAG")
WKHTML=$(docker run --rm --entrypoint wkhtmltopdf "$TAG" --version)
PY=$(docker run --rm --entrypoint python3 "$TAG" --version)

mkdir -p ../evidence
cat > ../evidence/image.json <<EOF
{
  "tag": "$TAG",
  "image_id": "$IMAGE_ID",
  "odoo_commit": "$ODOO_COMMIT",
  "wkhtmltopdf": "$WKHTML",
  "python": "$PY",
  "built_at": "$(date -u +%FT%TZ)"
}
EOF
echo "$TAG"
