"""Tenant.Create end to end on the development topology (dev/up.sh):
db-agent → agent-pg, app-agent → agent-exec-dev (root, Docker) over the 0600
socket, bench Odoo image. Skipped unless the topology is up.

    dev/up.sh && dev/test.sh
"""
import json
import os
import secrets
import socket
import urllib.request
import uuid
from pathlib import Path

import pyrage
import pytest

from hostagent.agentd import Agent
from hostagent.config import AgentConfig, Trust
from hostagent.devtools import odoo_master_hash, scram_verifier
from hostagent.execd import ExecClient, Executor, LocalExecClient
from hostagent.logs import AuditLog
from hostagent.naming import sid as derive_sid
from hostagent.pg_backend import DbHostConfig, PgBackend
from hostagent.secrets import seal
from hostagent.state import State

from .conftest import CELL, Clock, Keys, iso

SOCKET = Path(os.environ.get('AGENT_EXEC_SOCKET', '/nonexistent'))
APP_HOST = '11111111-1111-4111-8111-111111111111'
DB_HOST = '22222222-2222-4222-8222-222222222222'
STEPS = ('db.provision', 'app.network', 'app.image', 'app.config', 'app.init_db', 'app.platform_defaults',
         'app.container', 'app.route', 'app.health')


def _up():
    if not SOCKET.exists() or 'AGENT_PG_PASSWORD' not in os.environ:
        return False
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(str(SOCKET))
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason='run through dev/test.sh after dev/up.sh')


def _free_port_pair():
    for _ in range(100):
        p = secrets.randbelow(4000) * 2 + 21000
        ok = True
        for port in (p, p + 1):
            with socket.socket() as s:
                ok &= s.connect_ex(('127.0.0.1', port)) != 0
        if ok:
            return p
    raise RuntimeError('no free ports')


class World:
    def __init__(self, tmp_path):
        self.keys = Keys()
        self.clock = Clock()
        self.age = pyrage.x25519.Identity.generate()
        trust = Trust(dispatch=(self.keys.dispatch.verify_key,), release=self.keys.release.verify_key,
                      custodian=(self.keys.custodian.verify_key,))
        self.app_log, self.db_log = AuditLog(None), AuditLog(None)
        ingress = {'ingress_url': os.environ['AGENT_INGRESS_URL'],
                   'ingress_ca': Path(os.environ['AGENT_INGRESS_CA'])} if os.environ.get('AGENT_INGRESS_URL') else {}
        self.app = Agent(AgentConfig(host_id=APP_HOST, role='app', trust=trust, state_dir=tmp_path / 'app',
                                     registry_host='', age_identity=self.age, **ingress),
                         State(tmp_path / 'app.db'), ExecClient(SOCKET, 'app'), self.keys.agent, self.app_log)
        self.pg = PgBackend(DbHostConfig(
            dsn='host=127.0.0.1 port=55432 user=postgres dbname=postgres password=%s' % os.environ['AGENT_PG_PASSWORD'],
            hba_dir=Path(os.environ['AGENT_HBA_DIR']), hba_method='host',
            # Docker Desktop: tenant traffic reaches agent-pg from the bridge gateway.
            hba_cidr_override='172.17.0.1/32'))
        self.db_exec = Executor('db', self.pg, AuditLog(None))
        self.db = Agent(AgentConfig(host_id=DB_HOST, role='db', trust=trust, state_dir=tmp_path / 'db',
                                    registry_host='', age_identity=self.age),
                        State(tmp_path / 'db.db'), LocalExecClient(self.db_exec), self.keys.agent, self.db_log)
        self.digest = os.environ['AGENT_IMAGE_DIGEST']
        self.environment_id = str(uuid.uuid4())
        self.tenant_id = str(uuid.uuid4())
        self.op_id = str(uuid.uuid4())
        self.sid = derive_sid(self.environment_id)
        port = _free_port_pair()
        self.slot = {'container_uid': 10001 + secrets.randbelow(40000), 'http_port': port, 'gevent_port': port + 1,
                     'workers': 2, 'max_cron_threads': 1, 'db_maxconn': 8,
                     'limit_memory_soft': 640 << 20, 'limit_memory_hard': 768 << 20,
                     'limit_time_cpu': 600, 'limit_time_real': 1200,
                     'mem_limit_bytes': 2 << 30, 'cpu_millis': 2000}
        self.db_password = secrets.token_urlsafe(24)
        self.admin_password = secrets.token_urlsafe(24)
        from hostagent.canonical import sign
        m = {'cell': CELL, 'repository': 'tenants/odoo', 'image_digest': self.digest, 'change_class': 'major',
             'addon_manifest_sha256': 'cd' * 32,
             'module_versions': {'base': '19.0', 'web': '19.0', 'mail': '19.0'}}
        m['release_signature'] = sign(m, self.keys.release)
        self.manifest = m
        self.params = {'runtime_slot': self.slot, 'domains': [{'hostname': 't%s.cloud.test' % self.sid,
                                                                'kind': 'platform'}],
                       'modules': ['mail'], 'lang': 'en_US', 'country': 'EG', 'app_host_ip': '10.0.0.11'}

    def envelope(self, step, token=1):
        from hostagent.canonical import sign
        host = DB_HOST if step.startswith('db.') else APP_HOST
        secrets_map = None
        if step == 'db.provision':
            secrets_map = {'db_password_scram': scram_verifier(self.db_password)}
        elif step == 'app.config':
            secrets_map = {'db_password': self.db_password, 'admin_passwd_hash': odoo_master_hash(secrets.token_urlsafe(24)),
                           'smtp_password': secrets.token_urlsafe(24), 'tenant_salt': secrets.token_hex(16),
                           'tenant_admin_password': self.admin_password}
        now = self.clock()
        env = {'v': 1, 'op_id': self.op_id, 'op_type': 'Tenant.Create', 'step': step, 'host_id': host,
               'tenant_id': self.tenant_id, 'environment_id': self.environment_id, 'tenant_state': 'PROVISIONING',
               'fencing_token': token, 'issued_at': iso(now), 'expires_at': iso(now + 600),
               'nonce': secrets.token_hex(16), 'params': self.params,
               'secrets': seal(secrets_map, self.age.to_public()) if secrets_map else None,
               'release_manifest': self.manifest, 'approval': None}
        env['dispatch_signature'] = sign(env, self.keys.dispatch)
        return env

    def send(self, step, **kw):
        agent = self.db if step.startswith('db.') else self.app
        self.clock.t = __import__('time').time()
        return agent.handle(self.envelope(step, **kw))

    def teardown(self):
        x = self.app.exec
        for verb in ('container.remove', 'traefik.remove', 'nft.remove_tenant', 'net.remove', 'volume.remove'):
            try:
                x.call(verb, sid=self.sid)
            except Exception:
                pass
        for verb in ('pg.drop_db', 'pg.drop_role', 'pg.hba_remove'):
            self.db_exec.handle({'verb': verb, 'args': {'sid': self.sid}})
        self.db_exec.handle({'verb': 'pg.reload', 'args': {}})


@pytest.fixture(scope='module')
def world(tmp_path_factory):
    w = World(tmp_path_factory.mktemp('e2e'))
    w.results = {}
    yield w
    if not os.environ.get('AGENT_KEEP'):
        w.teardown()


def _login(world, password):
    body = json.dumps({'jsonrpc': '2.0', 'method': 'call', 'id': 1,
                       'params': {'db': 't_' + world.sid, 'login': 'admin', 'password': password}}).encode()
    req = urllib.request.Request('http://127.0.0.1:%d/web/session/authenticate' % world.slot['http_port'], body,
                                 {'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


@pytest.mark.parametrize('step', STEPS)
def test_step(world, step):
    resp = world.send(step)
    world.results[step] = resp
    assert (resp['status'], resp['code']) == ('done', 'OK'), json.dumps(resp['observed'], indent=1)


def test_evidence(world):
    r = world.results
    assert r['db.provision']['observed']['role'] == {'super': False, 'createdb': False, 'createrole': False,
                                                     'replication': False, 'bypassrls': False, 'login': True}
    assert r['db.provision']['observed']['public_connect'] is False
    pd = r['app.platform_defaults']['observed']
    assert pd['admin.default_password_rejected'] and pd['company.country'] == 'EG' and pd['ok']
    c = r['app.container']['observed']
    assert c['read_only'] and c['cap_drop'] == ['ALL'] and c['user'] == '%d:%d' % ((world.slot['container_uid'],) * 2)
    h = r['app.health']['observed']
    assert h['login'] == 200 and h['websocket'] == 101
    if os.environ.get('AGENT_INGRESS_URL'):          # through Traefik, by the public hostname (DOC-04 §6.1 8–9)
        assert r['app.route']['observed']['certificate'] == 'issued'
        assert (h['https_login'], h['https_websocket'], h['public_db_manager']) == (200, 101, 403)
        hostname = world.params['domains'][0]['hostname']
        assert h['public'] == {hostname: {'login': 200, 'websocket': 101, 'db_manager': 403}}


def test_admin_password_is_the_secret_not_the_default(world):
    assert _login(world, world.admin_password)['result']['uid'] == 2
    assert 'error' in _login(world, 'admin')


def test_admin_password_file_removed(world):
    files = world.app.exec.call('file.inspect', sid=world.sid)
    assert 'tenant_admin_password' not in files
    assert files['odoo.conf']['mode'] == '0o400' and files['pgpass']['mode'] == '0o400'


def test_steps_are_idempotent(world):
    for step in ('db.provision', 'app.network', 'app.image', 'app.config', 'app.init_db', 'app.platform_defaults',
                 'app.container', 'app.route'):
        resp = world.send(step)
        assert resp['code'] == 'OK', (step, resp['observed'])


def test_other_tenant_cannot_use_this_environment(world):
    env = world.envelope('app.container')
    from hostagent.canonical import sign, without
    env = without(env, 'dispatch_signature')
    env.update(tenant_id=str(uuid.uuid4()), nonce=secrets.token_hex(16))
    env['dispatch_signature'] = sign(env, world.keys.dispatch)
    assert world.app.handle(env)['code'] == 'NOT_OWNER'
