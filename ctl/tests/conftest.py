"""ctl-pg (dev/up.sh), a throwaway database per test, a real PKI from openssl,
the agent API served by uvicorn over mutual TLS, and the real hostagent."""
import base64
import json
import os
import secrets
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path

import psycopg
import pytest
from alembic import command
from alembic.config import Config
from nacl.signing import SigningKey

from ctlplane.agent_api import create_app
from ctlplane.canonical import b64_public, sha256_hex, sign
from ctlplane.store import Store
from ctlplane.vault import Vault, encrypt
import pyrage
from ctlplane.tls import server

ROOT = Path(__file__).resolve().parent.parent
APP_HOST, DB_HOST, OTHER_HOST, MAIL_HOST = (str(uuid.uuid4()) for _ in range(4))
IPS = {APP_HOST: '10.0.0.11', DB_HOST: '10.0.0.21', OTHER_HOST: '10.0.0.12', MAIL_HOST: '10.0.0.31'}
TENANT, ENV = str(uuid.uuid4()), str(uuid.uuid4())


def _password():
    env = ROOT / 'dev' / '.env'
    if not env.exists():
        return None
    return dict(line.split('=', 1) for line in env.read_text().split()).get('CTL_PG_PASSWORD')


def _pg_up(password):
    try:
        psycopg.connect('postgresql://postgres:%s@127.0.0.1:55433/postgres' % password, connect_timeout=2).close()
        return True
    except psycopg.OperationalError:
        return False


PASSWORD = _password()
PG_UP = bool(PASSWORD) and _pg_up(PASSWORD)


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


@pytest.fixture
def dsn():
    if not PG_UP:
        pytest.skip('needs ctl-pg (dev/up.sh)')
    name = 'ctl_test_' + secrets.token_hex(4)
    admin = 'postgresql://postgres:%s@127.0.0.1:55433/postgres' % PASSWORD
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute('CREATE DATABASE ' + name)
    url = 'postgresql://postgres:%s@127.0.0.1:55433/%s' % (PASSWORD, name)
    cfg = Config(str(ROOT / 'alembic.ini'))
    cfg.set_main_option('script_location', str(ROOT / 'migrations'))
    cfg.attributes['url'] = url
    command.upgrade(cfg, 'head')
    yield url
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute('DROP DATABASE %s WITH (FORCE)' % name)


class World:
    """Hosts, keys, one tenant with one production environment."""

    def __init__(self, dsn, clock=None):
        self.dsn = dsn
        self.dispatch = SigningKey.generate()
        self.agent_keys = {h: SigningKey.generate() for h in IPS}
        self.ages = {h: pyrage.x25519.Identity.generate() for h in IPS}
        self.vault = Vault(pyrage.x25519.Identity.generate())
        self.region_backup = pyrage.x25519.Identity.generate()      # the region's backup key pair
        self.region_restore = str(self.region_backup)               # what restores need: its identity
        self.b2 = {'key_id': 'K' + secrets.token_hex(6), 'secret': secrets.token_urlsafe(24)}
        self.clock = clock or time.time
        self.store = Store(dsn, self.dispatch, vault=self.vault, clock=self.clock)
        with psycopg.connect(dsn) as c:
            b2_ref, restore_ref, self.region = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            for ref, kind, value in ((b2_ref, 'b2_write_key', json.dumps(self.b2)),
                                     (restore_ref, 'region_restore_key', self.region_restore)):
                c.execute('INSERT INTO secret_ref (id, kind, ciphertext, created_at) VALUES (%s, %s, %s, now())',
                          (ref, kind, encrypt(value, self.vault.recipient)))
            c.execute("INSERT INTO region (id, code, backup_recipient, b2_write_key_ref, restore_key_ref) "
                      "VALUES (%s, 'eu-de-fsn1', %s, %s, %s)",
                      (self.region, str(self.region_backup.to_public()), b2_ref, restore_ref))
            for host, role in ((APP_HOST, 'app'), (DB_HOST, 'db'), (OTHER_HOST, 'app'), (MAIL_HOST, 'mail')):
                key_id = uuid.uuid4()
                c.execute("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'agent', %s)",
                          (key_id, b64_public(self.agent_keys[host])))
                c.execute("INSERT INTO host (id, role, state, agent_key_id, region_id, age_recipient, private_ip) "
                          "VALUES (%s, %s, 'active', %s, %s, %s, %s)",
                          (host, role, key_id, self.region, str(self.ages[host].to_public()), IPS[host]))
            c.execute("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ACTIVE')", (TENANT,))
            c.execute("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'production')", (ENV, TENANT))

    def sql(self, query, args=()):
        with psycopg.connect(self.dsn, row_factory=psycopg.rows.dict_row) as c:
            cur = c.execute(query, args)
            return cur.fetchall() if cur.description else None

    def op(self, op_id):
        return self.sql('SELECT * FROM operation WHERE id = %s', (op_id,))[0]

    def steps(self, op_id):
        return self.sql('SELECT * FROM operation_step WHERE operation_id = %s ORDER BY seq', (op_id,))

    def start(self, key='k1', environment_id=ENV):
        return self.store.dispatch('Tenant.Stop', tenant_id=TENANT, environment_id=environment_id,
                                   params={'reason': 'operator'}, hosts={'app': APP_HOST}, idempotency_key=key)

    def expire(self, copy=None):
        return self.store.dispatch('RestoreCopy.Expire', tenant_id=TENANT, environment_id=ENV,
                                   params={'environment_id': copy or str(uuid.uuid4())},
                                   hosts={'app': APP_HOST, 'db': DB_HOST}, idempotency_key=str(uuid.uuid4()))

    def response(self, env, status='done', code='OK', observed=None, host=None, key=None, **over):
        """What the agent would send for `env` (agentd._respond)."""
        host = host or env['host_id']
        observed = {} if observed is None else observed
        r = {'v': 1, 'op_id': env['op_id'], 'step': env['step'], 'host_id': host,
             'fencing_token': env['fencing_token'], 'status': status, 'code': code, 'observed': observed,
             'evidence_sha256': sha256_hex(observed), 'agent_high_water': env['fencing_token'],
             'at': '2026-10-26T00:00:00+00:00', **over}
        r['agent_signature'] = sign(r, key or self.agent_keys[host])
        return r


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def w(dsn, clock):
    return World(dsn, clock)


# -- PKI and the TLS server ----------------------------------------------------

def _openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


def _issue(d, ca, name, subject, san=None):
    _openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', name + '.key',
             '-out', name + '.csr', '-subj', subject, cwd=d)
    (d / (name + '.ext')).write_text('subjectAltName=%s\n' % san if san else 'basicConstraints=CA:FALSE\n')
    _openssl('x509', '-req', '-in', name + '.csr', '-CA', ca + '.pem', '-CAkey', ca + '.key', '-CAcreateserial',
             '-out', name + '.pem', '-days', '1', '-extfile', name + '.ext', cwd=d)


@pytest.fixture(scope='session')
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp('pki')
    for ca in ('ca', 'rogue_ca'):
        _openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                 '-keyout', ca + '.key', '-out', ca + '.pem', '-subj', '/CN=' + ca, '-days', '1',
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign', cwd=d)
    _issue(d, 'ca', 'server', '/CN=ctl-1', 'DNS:localhost,IP:127.0.0.1')
    for name, host in (('app', APP_HOST), ('db', DB_HOST), ('other', OTHER_HOST)):
        _issue(d, 'ca', name, '/CN=' + host)
    _issue(d, 'rogue_ca', 'rogue', '/CN=' + APP_HOST)
    _issue(d, 'ca', 'with_org', '/O=evil/CN=' + APP_HOST)
    return d


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def api(w, pki):
    """The agent API on https://127.0.0.1:<port>, real clock (agents check envelope times)."""
    w.store.clock = time.time
    from ctlplane.tls import fingerprint
    for host, cert in ((APP_HOST, 'app'), (DB_HOST, 'db'), (OTHER_HOST, 'other')):     # as if enrolled
        w.sql('UPDATE host SET client_cert_sha256 = %s WHERE id = %s',
              (fingerprint((pki / (cert + '.pem')).read_bytes()), host))
    port = _free_port()
    srv = server(create_app(w.store, poll_interval=0.05), '127.0.0.1', port,
                 cert=pki / 'server.pem', key=pki / 'server.key', ca=pki / 'ca.pem')
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    while not srv.started:
        time.sleep(0.01)
    yield 'https://127.0.0.1:%d' % port
    srv.should_exit = True
    t.join(5)
