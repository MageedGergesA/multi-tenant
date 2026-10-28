#!/usr/bin/env bash
# Build one benchmark dataset (DOC-06 §3) and snapshot it with SHA-256.
#   BAND=S [LOC=eg|sa] ./make_dataset.sh
# Needs: the image from image/build.sh and a reachable PostgreSQL 16
# (PGHOST/PGPORT/PGUSER/PGPASSWORD; defaults to the local bench-pg container).
set -euo pipefail
cd "$(dirname "$0")"
BENCH=$(cd .. && pwd)

BAND="${BAND:?BAND=XS|S|M|L}"
LOC="${LOC:-eg}"
IMAGE="${IMAGE:-$(python3 -c 'import json;print(json.load(open("'"$BENCH"'/evidence/image.json"))["tag"])')}"
DB="bench_${BAND,,}_${LOC}"
OUT="$BENCH/evidence/datasets/$DB"
NET="${NET:-bench}"
PGHOST="${PGHOST:-bench-pg}" PGPORT="${PGPORT:-5432}" PGUSER="${PGUSER:-odoo}" PGPASSWORD="${PGPASSWORD:-bench}"
mkdir -p "$OUT/filestore"
chmod 777 "$OUT/filestore"

MODULES=$(python3 -c 'import json;b=json.load(open("bands.json"));print(b["modules"]+","+b["localisation"]["'"$LOC"'"])')

odoo() {
    docker run --rm -i --network "$NET" \
        -v "$OUT/filestore:/var/lib/odoo" -v "$PWD:/bench/dataset:ro" -v "$OUT:/bench/out" \
        -e BANDS_FILE=/bench/dataset/bands.json -e BAND="$BAND" -e PHASE="${PHASE:-base}" -e USERS_FILE=/bench/out/users.csv \
        -e PGPASSWORD="$PGPASSWORD" \
        --entrypoint odoo "$IMAGE" "$@" \
        --db_host="$PGHOST" --db_port="$PGPORT" --db_user="$PGUSER" --data-dir=/var/lib/odoo
}

echo "== $DB: install $MODULES with demo seed"
odoo -d "$DB" -i "$MODULES" --with-demo --stop-after-init --no-http --log-level=warn

echo "== $DB: platform_defaults(create) (DOC-04 §6.1 step 6a)"
# The tenant admin password comes from a file (DOC-04 §5.4); the benchmark
# never logs in as admin, so a random one is generated and discarded.
ADMIN_PW=$(mktemp); chmod 644 "$ADMIN_PW"; head -c 24 /dev/urandom | base64 > "$ADMIN_PW"
docker run --rm --network "$NET" -e PGPASSWORD="$PGPASSWORD" -v "$ADMIN_PW:/run/tenant/tenant_admin_password:ro" \
    --entrypoint /opt/platform/platform-defaults "$IMAGE" \
    create en_US "$(echo "$LOC" | tr a-z A-Z)" -d "$DB" --db_host="$PGHOST" --db_port="$PGPORT" --db_user="$PGUSER"
rm -f "$ADMIN_PW"

echo "== $DB: populate"
ARGS=$(odoo shell -d "$DB" --no-http --log-level=warn < factors.py | sed -n 's/^POPULATE_ARGS=//p')
echo "   $ARGS"
# shellcheck disable=SC2086
[ -n "$ARGS" ] && odoo populate -d "$DB" $ARGS --log-level=warn

echo "== $DB: populate stock moves"
ARGS=$(PHASE=moves odoo shell -d "$DB" --no-http --log-level=warn < factors.py | sed -n 's/^POPULATE_ARGS=//p')
echo "   $ARGS"
# shellcheck disable=SC2086
[ -n "$ARGS" ] && odoo populate -d "$DB" $ARGS --log-level=warn

echo "== $DB: users and attachments"
odoo shell -d "$DB" --no-http --log-level=warn < finish.py

echo "== $DB: counts"
docker run --rm --network "$NET" -e PGPASSWORD="$PGPASSWORD" postgres:16 \
    psql -h "$PGHOST" -U "$PGUSER" -d "$DB" -At -F' ' -c "
    select 'partners', count(*) from res_partner union all
    select 'products', count(*) from product_template union all
    select 'sale_orders', count(*) from sale_order union all
    select 'invoices', count(*) from account_move union all
    select 'pickings', count(*) from stock_picking union all
    select 'stock_moves', count(*) from stock_move union all
    select 'stock_move_lines', count(*) from stock_move_line union all
    select 'moves_per_picking', round(count(*)::numeric / nullif((select count(*) from stock_picking), 0), 2) from stock_move where picking_id is not null union all
    select 'attachments', count(*) from ir_attachment union all
    select 'db_bytes', pg_database_size(current_database())" | tee "$OUT/counts.txt"

echo "== $DB: snapshot"
docker run --rm --network "$NET" -e PGPASSWORD="$PGPASSWORD" -v "$OUT:/out" postgres:16 \
    pg_dump -h "$PGHOST" -U "$PGUSER" -Fc -f /out/dump.pgc "$DB"
tar -C "$OUT" -cf "$OUT/filestore.tar" filestore
(cd "$OUT" && sha256sum dump.pgc filestore.tar > SHA256SUMS)
cat > "$OUT/manifest.json" <<EOF
{"db": "$DB", "band": "$BAND", "localisation": "$LOC", "image": "$IMAGE",
 "modules": "$MODULES", "created_at": "$(date -u +%FT%TZ)",
 "sha256": "$(sha256sum "$OUT/SHA256SUMS" | cut -d' ' -f1)"}
EOF
cat "$OUT/manifest.json"
