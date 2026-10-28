#!/usr/bin/env bash
# infra/ansible against throwaway Ubuntu 24.04 containers with systemd: ctl-1
# (the bootstrap's two runs, checks inside the host, runs that must change
# nothing or recover), then db-1 enrolled with ctl-1 through the operator API,
# then app-1 (privileged, for Docker inside: userns-remap, Traefik) enrolled the
# same way and driven through its executor
# and polling it. Needs Docker, ctl's dev venv (for keys and LocalStack) and
# LocalStack (agent/dev/up.sh). No WireGuard module in a container: the hosts
# share a Docker network on 10.8.0.0/24 whose interface is renamed wg0 (so
# nftables' iifname rules apply), and one on 10.0.0.0/24 as the private
# network. sops is a stand-in that decrypts with the host's age key.
#
# The container gets CAP_SYS_ADMIN and no AppArmor profile so systemd can
# remount its own cgroup namespace read-write; nothing is shared with the host.
set -euo pipefail
trap 'FAILED=1' ERR
HERE="$(cd "$(dirname "$0")" && pwd)"
INFRA="$(dirname "$HERE")"
CTL="$(dirname "$INFRA")/ctl"
PY="$CTL/.venv/bin/python"
export PATH="$INFRA/.venv/bin:$PATH" ANSIBLE_CONFIG="$INFRA/ansible/ansible.cfg"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ctl1-test.XXXXXX")"
NAME="ctl1-test-$$"
DB="db1-test-$$"
APP="app1-test-$$"
WGNET="ctl1-wg-$$"
PRIVNET="ctl1-priv-$$"
FAILED=0
cleanup() {
    if [ "$FAILED" != 0 ]; then
        docker exec "$NAME" journalctl --no-pager -u ctl-secrets -u ctl-migrate -u ctl > "$WORK/journal.log" 2>&1 || true
    fi
    if [ "$FAILED" != 0 ]; then
        docker exec "$DB" journalctl --no-pager -u agent-exec -u agentd -u postgresql > "$WORK/journal-db.log" 2>&1 || true
    fi
    if [ "$FAILED" != 0 ]; then
        docker exec "$APP" journalctl --no-pager -u agent-exec -u agentd -u docker -u traefik -u srv-tenants.mount \
            > "$WORK/journal-app.log" 2>&1 || true
    fi
    if [ -n "${KEEP_CONTAINER:-}" ]; then echo "containers kept: $NAME $DB $APP"; else
        docker rm -f -v "$NAME" "$DB" "$APP" >/dev/null 2>&1 || true
        docker network rm "$WGNET" "$PRIVNET" >/dev/null 2>&1 || true
    fi
    if [ "$FAILED" = 0 ]; then rm -rf "$WORK"; else echo "logs kept in $WORK"; fi
}
trap cleanup EXIT
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAILED=1; }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
in_host() { docker exec "$NAME" "$@"; }

docker build -q -t ctl1-test:24.04 "$HERE" >/dev/null
docker network create --subnet 10.8.0.0/24 --gateway 10.8.0.254 "$WGNET" >/dev/null
docker network create --subnet 10.0.0.0/24 --gateway 10.0.0.254 "$PRIVNET" >/dev/null
# A host: systemd up, SSH on a loopback port (with Docker Desktop the bridge is inside its VM, not
# routable from here), then the WireGuard and private networks, the former's interface named wg0.
start_host() {
    local name="$1" hostname="$2" wg_ip="$3" priv_ip="$4"
    shift 4
    docker run -d --name "$name" --hostname "$hostname" -p 127.0.0.1::22 --cgroupns=private --cap-add SYS_ADMIN \
        --cap-add NET_ADMIN --security-opt apparmor=unconfined --tmpfs /run --tmpfs /run/lock "$@" ctl1-test:24.04 \
        sh -c 'mount -o remount,rw /sys/fs/cgroup && exec /sbin/init' >/dev/null
    until docker exec "$name" systemctl is-system-running --wait >/dev/null 2>&1; do sleep 1; done
    # Keep the bridge's resolver: on a user-defined network Docker switches to its embedded DNS
    # (127.0.0.11, NAT rules in the container), which the base role's nftables flush removes.
    docker exec "$name" cp /etc/resolv.conf /etc/resolv.conf.bridge
    docker network connect --ip "$wg_ip" "$WGNET" "$name"
    docker network connect --ip "$priv_ip" "$PRIVNET" "$name"
    docker exec "$name" sh -c 'cat /etc/resolv.conf.bridge > /etc/resolv.conf'
    docker exec "$name" sh -c "i=\$(ip -o -4 addr show | awk '\$4 ~ /^$wg_ip\\// {print \$2}') && ip link set \$i down \
        && ip link set \$i name wg0 && ip link set wg0 up"
    ssh-keygen -q -t ed25519 -N '' -f "$WORK/id-$hostname" -C "$hostname-test"
    docker cp "$WORK/id-$hostname.pub" "$name:/root/.ssh/authorized_keys"
    docker exec "$name" sh -c 'chown root:root /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys'
    docker cp "$HERE/sops-standin" "$name:/usr/local/bin/sops"
}
# The gateway first: once on more networks, the template lists every network's.
GATEWAY="$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
start_host "$NAME" ctl-1 10.8.0.1 10.0.0.2
SSH_PORT="$(docker port "$NAME" 22 | head -1 | cut -d: -f2)"
S3_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' agent-s3)"
cp "$WORK/id-ctl-1" "$WORK/id"

# Operator side: PKI, IdP keys, the release key, the secrets, a bucket C.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
    -subj /CN=agents-ca -days 1 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/ctl.key" -out "$WORK/ctl.csr" \
    -subj /CN=ctl-1 2>/dev/null
printf 'subjectAltName=IP:10.8.0.1\n' > "$WORK/ext"
openssl x509 -req -in "$WORK/ctl.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -out "$WORK/ctl.pem" \
    -days 1 -extfile "$WORK/ext" 2>/dev/null
"$PY" - "$WORK" "$S3_IP" <<'PY'
import base64, json, secrets, sys, boto3, pyrage, jwt
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey
work, s3_ip = sys.argv[1:]
idp = ec.generate_private_key(ec.SECP256R1())
from cryptography.hazmat.primitives import serialization
open(work + '/idp.pem', 'wb').write(idp.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
release = SigningKey.generate()
open(work + '/release.seed', 'w').write(base64.b64encode(release.encode()).decode())
jwk = dict(jwt.algorithms.ECAlgorithm.to_jwk(idp.public_key(), as_dict=True), kid='k1', alg='ES256')
open(work + '/jwks.json', 'w').write(json.dumps({'keys': [jwk]}))
recovery = pyrage.x25519.Identity.generate()
bucket = 'ctl1-test-' + secrets.token_hex(4)
boto3.client('s3', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test',
             aws_secret_access_key='test').create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
key = {'key_id': 'test', 'secret': 'test'}
plain = {'database_url': 'postgresql://ctl_owner:%s@127.0.0.1:5432/ctl' % secrets.token_urlsafe(24),
         'dispatch_seed': base64.b64encode(SigningKey.generate().encode()).decode(),
         'vault_identity': str(pyrage.x25519.Identity.generate()),
         'agent_tls_key': open(work + '/ctl.key').read(), 'agents_ca_key': open(work + '/ca.key').read(),
         'bucket_c_write.json': key, 'bucket_c_retention.json': key,
         'dump_signing_seed': base64.b64encode(SigningKey.generate().encode()).decode()}
open(work + '/secrets.json', 'w').write(json.dumps(plain))
# The first run's file: encrypted to the operators only, not yet to this new host.
other = pyrage.x25519.Identity.generate().to_public()
open(work + '/ctl.sops.yaml', 'wb').write(pyrage.encrypt(json.dumps(plain).encode(), [other]))
json.dump({'bucket': bucket, 'recovery': str(recovery.to_public()),
           'release': base64.b64encode(bytes(release.verify_key)).decode()}, open(work + '/vars.json', 'w'))
PY
BUCKET="$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['bucket'])" "$WORK/vars.json")"
RECOVERY="$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['recovery'])" "$WORK/vars.json")"
RELEASE="$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['release'])" "$WORK/vars.json")"
cat > "$WORK/inventory.yml" <<YAML
ctl:
  hosts:
    ctl-1:
      ansible_host: 127.0.0.1
      ansible_port: $SSH_PORT
      ansible_user: root
      ansible_ssh_private_key_file: $WORK/id
      ansible_ssh_common_args: "-o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
  vars:
    base_admin_cidrs: ["$GATEWAY/32"]
    wireguard_start: false
    wireguard_peers: [{name: founder, public_key: "$(head -c 32 /dev/urandom | base64)", address: 10.8.0.10}]
    ctl_sops_install: false
    ctl_sops_file: $WORK/ctl.sops.yaml
    ctl_tls_cert_file: $WORK/ctl.pem
    ctl_agents_ca_cert_file: $WORK/ca.pem
    ctl_jwks_file: $WORK/jwks.json
    ctl_oidc_issuer: https://id.example.test
    ctl_oidc_audience: ctl-1
    monitoring_scrape_interval: 5s
    monitoring_evaluation_interval: 5s
    monitoring_group_wait: 5s
    ctl_s3_endpoint: http://$S3_IP:4566
    ctl_s3_region: us-east-1
    ctl_bucket_c: $BUCKET
    ctl_recovery_recipient: $RECOVERY
    ctl_trust: {release_public_key: "$RELEASE"}
    ctl_regions: [{code: test, backup_recipient: "$RECOVERY", backup_bucket: "$BUCKET"}]
YAML
# A short TMPDIR: Ansible puts a Unix socket there (108-byte path limit).
play() { TMPDIR=/tmp ansible-playbook -i "$WORK/inventory.yml" "$INFRA/ansible/ctl.yml" > "$WORK/play$1.log" 2>&1; }

echo "run 1: a new host, its key not in the SOPS file yet"
if play 1; then bad "run 1 should stop at ctl-secrets"; fi
check "run 1 stopped at ctl-secrets" grep -q "ctl-secrets failed" "$WORK/play1.log"
RECIPIENT="$(in_host age-keygen -y /etc/ctl/host.agekey)"
check "it named the host's recipient" grep -q "$RECIPIENT" "$WORK/play1.log"
check "the host key is root's, 0400" test "$(in_host stat -c '%U %a' /etc/ctl/host.agekey)" = "root 400"
check "ctl isn't running" sh -c "! docker exec $NAME systemctl is-active -q ctl"

echo "run 2: the SOPS file now encrypted to the host too"
"$PY" -c "
import json, sys, pyrage
plain = open(sys.argv[1], 'rb').read()
open(sys.argv[2], 'wb').write(pyrage.encrypt(plain, [pyrage.x25519.Recipient.from_str(sys.argv[3])]))
" "$WORK/secrets.json" "$WORK/ctl.sops.yaml" "$RECIPIENT"
if play 2; then ok "run 2 completed"; else bad "run 2 failed"; tail -40 "$WORK/play2.log"; fi
for unit in ctl ctl-secrets postgresql nftables; do check "$unit active" in_host systemctl is-active -q "$unit"; done
check "/run/ctl is ctl's, 0700, on tmpfs" test "$(in_host stat -f -c %T /run/ctl) $(in_host stat -c '%U %a' /run/ctl)" = "tmpfs ctl 700"
check "every secret is ctl's, 0400" test "$(in_host sh -c 'stat -c "%U %a" /run/ctl/* | sort -u')" = "ctl 400"
check "the schema is at head" in_host runuser -u ctl -- env CTL_CONFIG=/etc/ctl/ctl.toml /opt/ctl/venv/bin/python -m ctlplane check
check "the workers run (ctl_workers_leader 1)" sh -c "docker exec $NAME python3 -c \"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9464/metrics').read().decode())\" | grep -qx 'ctl_workers_leader 1'"
PID="$(in_host systemctl show -p MainPID --value ctl)"
# From ctl's mountinfo (docker exec can't enter its namespace: no CAP_SYS_PTRACE).
for f in /etc/ctl/host.agekey /etc/ctl/secrets.sops.yaml; do
    check "in ctl's namespace $f is systemd's inaccessible node (InaccessiblePaths)" \
        in_host grep -q " /systemd/inaccessible/reg $f " "/proc/$PID/mountinfo"
done
check "in ctl's namespace / is read-only (ProtectSystem=strict), outside read-write" test \
    "$(in_host awk '$5=="/" {print substr($6, 1, 2)}' "/proc/$PID/mountinfo") $(in_host awk '$5=="/" {print substr($6, 1, 2)}' /proc/1/mountinfo)" = "ro rw"
check "ctl runs with no capabilities" test "$(in_host sh -c "grep CapEff /proc/$PID/status | awk '{print \$2}'")" = 0000000000000000
check "PostgreSQL listens on loopback only" sh -c "docker exec $NAME ss -ltnH 'sport = :5432' | awk '{print \$4}' | grep -v -E '^(127\.0\.0\.1|\[::1\]):5432$' | wc -l | grep -qx 0"
check "the agent API listens on wg0's address only" sh -c "docker exec $NAME ss -ltnH 'sport = :8443' | awk '{print \$4}' | grep -qx 10.8.0.1:8443"
check "the operator API and monitoring on loopback" sh -c "docker exec $NAME ss -ltnH | awk '{print \$4}' | grep -E ':(8080|9464)$' | grep -v '^127.0.0.1:' | wc -l | grep -qx 0"
check "nftables drops by default" sh -c "docker exec $NAME nft list chain inet filter input | grep -q 'policy drop'"
check "ctl_owner has no superuser" test "$(in_host runuser -u postgres -- psql -tAc "SELECT rolsuper FROM pg_roles WHERE rolname='ctl_owner'")" = f
check "ctl_owner may become ctl_dispatcher" test "$(in_host runuser -u postgres -- psql -d ctl -tAc "SELECT pg_has_role('ctl_owner', 'ctl_dispatcher', 'SET')")" = t
check "the owner's password is stored as SCRAM" test "$(in_host runuser -u postgres -- psql -tAc "SELECT left(rolpassword, 14) FROM pg_authid WHERE rolname='ctl_owner'")" = 'SCRAM-SHA-256$'

echo "monitoring: Prometheus and Alertmanager on loopback, an alert all the way to a ctl incident"
for unit in prometheus prometheus-alertmanager; do check "$unit active" in_host systemctl is-active -q "$unit"; done
check "Prometheus, Alertmanager on loopback only, no cluster port" sh -c "docker exec $NAME ss -ltnH | awk '{print \$4}' | grep -E ':(9090|9093|9094)$' | sort | tr '\n' ' ' | grep -qx '127.0.0.1:9090 127.0.0.1:9093 '"
api() { in_host python3 -c "import urllib.request, sys; print(urllib.request.urlopen(sys.argv[1]).read().decode())" "$1"; }
check "ctl's rules and the Watchdog are loaded" sh -c "docker exec $NAME python3 -c \"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/rules').read().decode())\" | grep -q CtlWorkerFailing"
deadline=$((SECONDS + 120))
until api http://127.0.0.1:9090/api/v1/targets | grep -q '"health":"up"' || [ $SECONDS -gt $deadline ]; do sleep 2; done
check "Prometheus scrapes ctl (job ctl up)" sh -c "docker exec $NAME python3 -c \"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9090/api/v1/targets').read().decode())\" | grep -q '\"health\":\"up\"'"
# Prometheus to Alertmanager: the always-firing Watchdog arrives there.
until api http://127.0.0.1:9093/api/v2/alerts | grep -q Watchdog || [ $SECONDS -gt $((deadline + 120)) ]; do sleep 3; done
check "Prometheus sends its alerts to Alertmanager (the Watchdog is there)" sh -c "docker exec $NAME python3 -c \"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:9093/api/v2/alerts').read().decode())\" | grep -q Watchdog"
# Alertmanager to ctl: an alert posted to it becomes an incident through the webhook and its token.
in_host python3 -c "import json, urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9093/api/v2/alerts', json.dumps([{'labels': {'alertname': 'HarnessProbe', 'severity': 'sev3', 'runbook': 'RB-25'}, 'annotations': {'summary': 'harness probe alert'}}]).encode(), {'Content-Type': 'application/json'}))"
incident() { in_host runuser -u postgres -- psql -d ctl -tAc "SELECT severity || ' ' || coalesce(runbook_ref, '') FROM incident WHERE summary = 'harness probe alert'"; }
until [ -n "$(incident)" ] || [ $SECONDS -gt $((deadline + 180)) ]; do sleep 3; done
check "an alert reached ctl as an incident (Alertmanager, the webhook, its token)" test "$(incident)" = "sev3 RB-25"
check "the Watchdog didn't become an incident" test "$(in_host runuser -u postgres -- psql -d ctl -tAc "SELECT count(*) FROM incident WHERE summary LIKE 'Always firing%'")" = 0

echo "a control-plane dump from inside ctl.service's sandbox (pg_dump, age, bucket C)"
check "bootstrap registered the release key and region test" test "$(in_host runuser -u postgres -- psql -d ctl -tAc \
    "SELECT (SELECT count(*) FROM signing_key WHERE purpose = 'release')::text || (SELECT count(*) FROM region WHERE code = 'test')::text")" = 11
cat > "$WORK/dump-probe.py" <<'PY'
from nacl.signing import SigningKey
from ctlplane.main import Config, build_cpbackup, secret
from ctlplane.store import Store
dsn = secret('/run/ctl/database_url')
print(build_cpbackup(Config.load('/etc/ctl/ctl.toml'), Store(dsn, SigningKey.generate(), role=None), dsn).dump('manual'))
PY
docker cp "$WORK/dump-probe.py" "$NAME:/usr/local/lib/ctl/dump-probe.py"
in_host sh -c "sed -e '/^ExecStart/d' -e '/^Restart/d' -e '/^\[Install\]/,\$d' -e 's/^Type=exec/Type=oneshot/' \
    -e '/^Type=oneshot/a ExecStart=/opt/ctl/venv/bin/python /usr/local/lib/ctl/dump-probe.py' \
    /etc/systemd/system/ctl.service > /etc/systemd/system/ctl-dump-probe.service && systemctl daemon-reload"
check "the dump ran under ctl.service's sandbox" in_host systemctl start ctl-dump-probe
# (ctl's own worker dumps too, once its region exists: the probe's is the 'manual' one.)
PROBE_KEY="$(in_host runuser -u postgres -- psql -d ctl -tAc "SELECT object_key FROM ctl_dump WHERE reason = 'manual'")"
check "it is in bucket C" "$PY" -c "
import boto3, sys
s3 = boto3.client('s3', endpoint_url='http://127.0.0.1:4566', region_name='us-east-1', aws_access_key_id='test',
                  aws_secret_access_key='test')
sys.exit(0 if sys.argv[2] and s3.head_object(Bucket=sys.argv[1], Key=sys.argv[2]) else 1)" "$BUCKET" "$PROBE_KEY"

echo "run 3: nothing to change"
if play 3; then ok "run 3 completed"; else bad "run 3 failed"; tail -40 "$WORK/play3.log"; fi
check "run 3 changed nothing" grep -qE 'ctl-1 +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' "$WORK/play3.log"
grep -E 'changed:' "$WORK/play3.log" | head -5 || true
check "ctl kept running through it" test "$(in_host systemctl show -p MainPID --value ctl)" = "$PID"

echo "run 4: after an install that died midway (same bundle, venv there, package gone)"
in_host sh -c '/opt/ctl/venv/bin/pip uninstall -q -y ctlplane && rm -f /opt/ctl/installed-bundle'
if play 4; then ok "run 4 completed"; else bad "run 4 failed"; tail -40 "$WORK/play4.log"; fi
check "run 4 installed ctl again" grep -q 'changed: \[ctl-1\]' <(grep -A1 'TASK \[ctl : Install ctl\]' "$WORK/play4.log")
check "ctl is serving again" in_host runuser -u ctl -- env CTL_CONFIG=/etc/ctl/ctl.toml /opt/ctl/venv/bin/python -m ctlplane check

echo "run 5: after a deploy interrupted between install and restart (old code still running)"
PID="$(in_host systemctl show -p MainPID --value ctl)"
in_host sh -c 'echo interrupted > /opt/ctl/active-bundle'
if play 5; then ok "run 5 completed"; else bad "run 5 failed"; tail -40 "$WORK/play5.log"; fi
check "run 5 restarted ctl onto the installed bundle" test "$(in_host systemctl show -p MainPID --value ctl)" != "$PID"
check "migrate is ordered after ctl's stop" sh -c "docker exec $NAME systemctl show -p After ctl-migrate | grep -qw ctl.service"

echo "db-1: enrolled with ctl-1 through the operator API, then polling it"
start_host "$DB" db-1 10.8.0.3 10.0.0.3
DB_PORT="$(docker port "$DB" 22 | head -1 | cut -d: -f2)"
# An operator, as the IdP's subject (MFA is in the token), and the founder's release key.
in_host runuser -u postgres -- psql -q -d ctl -c "INSERT INTO operator (id, oidc_subject, status) VALUES
    ('00000000-0000-0000-0000-00000000000a', 'sub-founder', 'active'),
    ('00000000-0000-0000-0000-00000000000b', 'sub-custodian', 'active');
    INSERT INTO operator_role_grant (id, operator_id, role, valid_from, granted_by) VALUES
    (gen_random_uuid(), '00000000-0000-0000-0000-00000000000a', 'platform_operator', now() - interval '1 day',
     '00000000-0000-0000-0000-00000000000b')"
ENROLLED="$(cd "$CTL" && "$PY" "$HERE/enroll_host.py" "$NAME" "$WORK" db test 10.0.0.3)"
DB_HOST_ID="$("$PY" -c "import json,sys; print(json.loads(sys.argv[1])['host_id'])" "$ENROLLED")"
DB_TOKEN="$("$PY" -c "import json,sys; print(json.loads(sys.argv[1])['token_file'])" "$ENROLLED")"
cp "$WORK/ca.pem" "$WORK/ctl-ca.pem"
cat >> "$WORK/inventory.yml" <<YAML
db:
  hosts:
    db-1:
      ansible_host: 127.0.0.1
      ansible_port: $DB_PORT
      ansible_user: root
      ansible_ssh_private_key_file: $WORK/id-db-1
      ansible_ssh_common_args: "-o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
  vars:
    base_admin_cidrs: ["$GATEWAY/32"]
    base_wg_tcp_ports: []
    base_private_allow: [{port: 5432, cidr: 10.0.0.16/28}]
    wireguard_start: false
    wireguard_address: 10.8.0.3/24
    db_host_private_ip: 10.0.0.3
    agent_role: db
    agent_host_id: "$DB_HOST_ID"
    agent_trust_root: "$RELEASE"
    agent_ctl_ca_file: $WORK/ctl-ca.pem
YAML
dbplay() { TMPDIR=/tmp ansible-playbook -i "$WORK/inventory.yml" "$INFRA/ansible/db.yml" "${@:2}" > "$WORK/db$1.log" 2>&1; }
if dbplay 1; then bad "without a token the play should stop"; fi
check "without a token it stops and says how to enroll" grep -q "isn't enrolled. Open its enrollment" "$WORK/db1.log"
if dbplay 2 -e "agent_enroll_token_file=$DB_TOKEN"; then ok "db-1 configured and enrolled"; else bad "db-1 play failed"; tail -40 "$WORK/db2.log"; fi
in_db() { docker exec "$DB" "$@"; }
for unit in postgresql agent-exec agentd nftables; do check "db-1 $unit active" in_db systemctl is-active -q "$unit"; done
unit_user() { in_db sh -c "ps -o user= -p \$(systemctl show -p MainPID --value $1)"; }
check "the executor runs as postgres, agentd as agent" test "$(unit_user agent-exec) $(unit_user agentd)" = "postgres agent"
check "the executor's socket: postgres:agent-exec 0660" test "$(in_db stat -c '%U:%G %a' /run/agent-exec/agent-exec.sock)" = "postgres:agent-exec 660"
check "the token is gone from db-1" sh -c "! docker exec $DB test -e /var/lib/agent/enroll.token"
check "the agent's keys are its own, 0600" test "$(in_db stat -c '%U %a' /var/lib/agent/agent.key /var/lib/agent/age.key /var/lib/agent/tls.key | sort -u)" = "agent 600"
host_row() { in_host runuser -u postgres -- psql -d ctl -tAc "SELECT state || ' ' || (client_cert_sha256 IS NOT NULL) || ' ' || (last_seen_at > now() - interval '2 minutes') FROM host WHERE id = '$DB_HOST_ID'"; }
deadline=$((SECONDS + 90))
until [ "$(host_row)" = "active true true" ] || [ $SECONDS -gt $deadline ]; do sleep 3; done
check "ctl-1 has db-1 active, its certificate pinned, polling now (mutual TLS over wg0)" test "$(host_row)" = "active true true"
check "PostgreSQL on the private address with TLS" sh -c "docker exec $DB runuser -u postgres -- psql -tAc 'SHOW ssl' | grep -qx on && docker exec $DB ss -ltnH 'sport = :5432' | grep -q '10.0.0.3:5432'"
check "port 5432 closed to a private address outside the app range (ctl-1, 10.0.0.2)" \
    sh -c "! docker exec $NAME timeout 3 bash -c 'echo > /dev/tcp/10.0.0.3/5432'"
if dbplay 3; then ok "db-1 run again"; else bad "db-1 run again failed"; tail -30 "$WORK/db3.log"; fi
check "the second db-1 run changed nothing" grep -qE 'db-1 +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' "$WORK/db3.log"
grep -E 'changed:' "$WORK/db3.log" | head -5 || true

echo "app-1: Docker with userns-remap, Traefik, the filestore Volume, enrolled and driven through its executor"
# Privileged: Docker inside needs it (cgroups, namespaces, iptables); its storage on a volume, not overlayfs.
start_host "$APP" app-1 10.8.0.21 10.0.0.16 --privileged -v /var/lib/docker
APP_PORT="$(docker port "$APP" 22 | head -1 | cut -d: -f2)"
in_app() { docker exec "$APP" "$@"; }
ENROLLED="$(cd "$CTL" && "$PY" "$HERE/enroll_host.py" "$NAME" "$WORK" app test 10.0.0.16)"
APP_HOST_ID="$("$PY" -c "import json,sys; print(json.loads(sys.argv[1])['host_id'])" "$ENROLLED")"
APP_TOKEN="$("$PY" -c "import json,sys; print(json.loads(sys.argv[1])['token_file'])" "$ENROLLED")"
cat >> "$WORK/inventory.yml" <<YAML
app:
  hosts:
    app-1:
      ansible_host: 127.0.0.1
      ansible_port: $APP_PORT
      ansible_user: root
      ansible_ssh_private_key_file: $WORK/id-app-1
      ansible_ssh_common_args: "-o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
  vars:
    base_admin_cidrs: ["$GATEWAY/32"]
    base_wg_tcp_ports: []
    base_public_tcp_ports: [80, 443]
    base_forward_docker: true
    wireguard_start: false
    wireguard_address: 10.8.0.21/24
    app_filestore_on_root_disk: true
    app_db_ca_file: $INFRA/ansible/.build/db-1.crt
    app_cert_resolver: ""
    agent_role: app
    agent_app_db_host: 10.0.0.3
    agent_registry_host: registry.example.test
    agent_app_repository: tenants/odoo
    agent_host_id: "$APP_HOST_ID"
    agent_trust_root: "$RELEASE"
    agent_ctl_ca_file: $WORK/ctl-ca.pem
YAML
appplay() { TMPDIR=/tmp ansible-playbook -i "$WORK/inventory.yml" "$INFRA/ansible/app.yml" "${@:2}" > "$WORK/app$1.log" 2>&1; }
# No udev in a container, so no device unit for a mount to wait on: the Volume's mount is
# checked only for its refusal of a device without ext4; then /srv/tenants on the root disk.
if appplay 0 -e app_filestore_on_root_disk=false -e app_filestore_device=/dev/null; then bad "a device without ext4 should stop the play"; fi
check "a device without ext4 is refused, not formatted" grep -q "has no ext4 filesystem" "$WORK/app0.log"
if appplay 1 -e "agent_enroll_token_file=$APP_TOKEN"; then ok "app-1 configured and enrolled"; else bad "app-1 play failed"; tail -40 "$WORK/app1.log"; fi
for unit in nftables docker traefik agent-exec agentd; do check "app-1 $unit active" in_app systemctl is-active -q "$unit"; done
check "Docker remaps (root dir under the remap base)" test "$(in_app docker info -f '{{.DockerRootDir}}')" = "/var/lib/docker/100000.100000"
unit_user_app() { in_app sh -c "ps -o user= -p \$(systemctl show -p MainPID --value $1)"; }
check "the executor runs as root, agentd as agent" test "$(unit_user_app agent-exec) $(unit_user_app agentd)" = "root agent"
check "the executor's socket: agent's, 0600" test "$(in_app stat -c '%U %a' /run/agent-exec/agent-exec.sock)" = "agent 600"
# Finding 13: the base role's firewall replaces its own table; Docker's (iptables-nft) stay.
in_app systemctl reload nftables && in_app systemctl restart nftables
check "Docker's NAT table survives nftables reload and restart" sh -c "docker exec $APP nft list table ip nat | grep -q DOCKER"
check "the base table is back after the restart" in_app nft list table inet filter
VENV=/opt/agent/venv/bin/python
https_status() {  # host path -> Traefik's status for it on :443 (its default certificate: unverified)
    in_app $VENV -c "import ssl, sys, http.client
c = http.client.HTTPSConnection('127.0.0.1', 443, context=ssl._create_unverified_context())
c.request('GET', sys.argv[2], headers={'Host': sys.argv[1]}); print(c.getresponse().status)" "$1" "$2"
}
check "Traefik answers its ping, and 404 for a hostname nobody routes" test "$(https_status nobody.example.test /)" = "404"
# agentd's side of the socket, as agentd: a tenant's volume, network, firewall and router.
in_app runuser -u agent -- $VENV -c "from pathlib import Path
from hostagent.execd import ExecClient
c = ExecClient(Path('/run/agent-exec/agent-exec.sock'), 'app')
c.call('volume.create', sid='feedfacecafe', host_uid=110001)
c.call('net.create', sid='feedfacecafe')
c.call('nft.apply_tenant', sid='feedfacecafe', profile='production')
c.call('traefik.write', sid='feedfacecafe', hostnames=['t1.example.test'], http_port=20000, gevent_port=20001, generation=1)" \
    > "$WORK/exec-app.log" 2>&1 && ok "agentd drove the executor" || { bad "agentd drove the executor"; cat "$WORK/exec-app.log"; }
check "the tenant's filestore: remapped uid 110001, 0700" \
    test "$(in_app stat -c '%u %a' /srv/tenants/feedfacecafe/data)" = "110001 700"
check "the tenant's network: its own bridge, no inter-container traffic" \
    test "$(in_app docker network inspect -f '{{index .Options "com.docker.network.bridge.enable_icc"}} {{index .Options "com.docker.network.bridge.name"}}' net-feedfacecafe)" = "false br-feedfacecafe"
check "the tenant's egress table is loaded" in_app nft list table inet tenant_feedfacecafe
exec_call() {  # verb json-args -> the executor's result, as agentd calls it
    in_app runuser -u agent -- $VENV -c "import json, sys
from pathlib import Path
from hostagent.execd import ExecClient
print(json.dumps(ExecClient(Path('/run/agent-exec/agent-exec.sock'), 'app').call(sys.argv[1], **json.loads(sys.argv[2]))))" "$1" "$2"
}
nft_applied() { exec_call nft.inspect '{"sid": "feedfacecafe"}' | $PY -c "import json,sys; print(json.load(sys.stdin)['applied'])"; }
check "nft.inspect: applied" test "$(nft_applied)" = "True"
in_app nft delete table inet tenant_feedfacecafe
check "nft.inspect reads the kernel: table deleted, file still there, not applied" test "$(nft_applied)" = "False"
# A reboot's firewall load, as nftables.service does it: the tenant's table comes back from its file.
in_app systemctl restart nftables
check "after the firewall's (boot) load the tenant's table is back, Docker's NAT intact" \
    sh -c "docker exec $APP nft list table inet tenant_feedfacecafe >/dev/null && docker exec $APP nft list table ip nat | grep -q DOCKER"
check "nft.inspect: applied again" test "$(nft_applied)" = "True"
check "agentd reads the remap base (tenant uid N is host uid 100000 + N)" \
    test "$(in_app runuser -u agent -- $VENV -c "from pathlib import Path; from hostagent import config; print(config.load(Path('/etc/agent/agent.toml')).subuid_base)")" = "100000"
check "the executor knows the image repository (a registry digest is looked up, not a KeyError)" \
    sh -c "docker exec $APP runuser -u agent -- $VENV -c \"import json
from pathlib import Path
from hostagent.execd import ExecClient
r = ExecClient(Path('/run/agent-exec/agent-exec.sock'), 'app').call('image.inspect', digest='sha256:' + 'ab' * 32)
assert r == {'present': False}, r\""
deadline=$((SECONDS + 20))
until [ "$(https_status t1.example.test /)" = "502" ] || [ $SECONDS -gt $deadline ]; do sleep 1; done
check "Traefik routes the tenant's hostname (502: nothing on its port yet)" test "$(https_status t1.example.test /)" = "502"
check "and refuses its database manager at the edge" test "$(https_status t1.example.test /web/database/manager)" = "403"
# Tenants connect to db-1 with verify-full against its certificate: TLS succeeds, then pg_hba says no.
check "app-1 → db-1: TLS verified against db-1's certificate (verify-full), then pg_hba refuses" \
    sh -c "docker exec $APP $VENV -c \"import psycopg
try: psycopg.connect('host=10.0.0.3 dbname=x user=x sslmode=verify-full sslrootcert=/etc/platform/db-ca.pem connect_timeout=5')
except psycopg.OperationalError as e: print(e)\" | tee $WORK/app-db-tls.log | grep -q 'pg_hba.conf.*SSL encryption'"
host_row_app() { in_host runuser -u postgres -- psql -d ctl -tAc "SELECT state || ' ' || (client_cert_sha256 IS NOT NULL) || ' ' || (last_seen_at > now() - interval '2 minutes') FROM host WHERE id = '$APP_HOST_ID'"; }
deadline=$((SECONDS + 90))
until [ "$(host_row_app)" = "active true true" ] || [ $SECONDS -gt $deadline ]; do sleep 3; done
check "ctl-1 has app-1 active, polling" test "$(host_row_app)" = "active true true"
if appplay 2; then ok "app-1 run again"; else bad "app-1 run again failed"; tail -30 "$WORK/app2.log"; fi
check "the second app-1 run changed nothing" grep -qE 'app-1 +: ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' "$WORK/app2.log"
grep -E 'changed:' "$WORK/app2.log" | head -5 || true
check "the tenant's files, network and table survive the run" \
    sh -c "docker exec $APP test -d /srv/tenants/feedfacecafe/data && docker exec $APP nft list table inet tenant_feedfacecafe >/dev/null"

[ "$FAILED" = 0 ] && echo PASS || { echo FAIL; exit 1; }
