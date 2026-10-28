"""Tenant.Backup and Tenant.RestoreToIsolated end to end (DOC-04 §6.8, §6.9) on
the development topology, with LocalStack S3 standing in for B2.

    dev/up.sh && dev/test.sh tests/test_backup_e2e.py
"""
import base64
import http.cookiejar
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import botocore
import pyrage
import pytest

from hostagent import s3
from hostagent.canonical import sign
from hostagent.devtools import odoo_master_hash, scram_verifier
from hostagent.naming import sid as derive_sid
from hostagent.secrets import seal

from .conftest import iso
from .test_create_e2e import APP_HOST, DB_HOST, STEPS, World, _free_port_pair, _up

pytestmark = pytest.mark.skipif(not _up() or 'AGENT_S3_ENDPOINT' not in os.environ,
                                reason='run through dev/test.sh after dev/up.sh')

BUCKET = 'tenant-backups'
KEY_ID, KEY_SECRET = 'test', 'test'   # LocalStack accepts any credentials


class BackupWorld(World):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.region = pyrage.x25519.Identity.generate()
        for agent in (self.app, self.db):
            object.__setattr__(agent.config, 's3_endpoint', os.environ['AGENT_S3_ENDPOINT'])
            object.__setattr__(agent.config, 's3_region', 'us-east-1')
            object.__setattr__(agent.config, 's3_bucket', BUCKET)
            object.__setattr__(agent.config, 'backup_tmp', Path(os.environ['AGENT_BACKUP_TMP']))
        self.s3 = s3.client(os.environ['AGENT_S3_ENDPOINT'], 'us-east-1', KEY_ID, KEY_SECRET)
        try:
            self.s3.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        except self.s3.exceptions.BucketAlreadyOwnedByYou:
            pass
        self.copies = []
        self.token = 1

    def op(self, op_type, step, params, secrets_map=None, *, op_id=None, tenant_id=None, state='ACTIVE',
           release=False, approval=None):
        self.token += 1
        now = __import__('time').time()
        self.clock.t = now
        env = {'v': 1, 'op_id': op_id or str(uuid.uuid4()), 'op_type': op_type, 'step': step,
               'host_id': DB_HOST if step.startswith('db.') else APP_HOST, 'tenant_id': tenant_id or self.tenant_id,
               'environment_id': self.environment_id, 'tenant_state': state, 'fencing_token': self.token,
               'issued_at': iso(now), 'expires_at': iso(now + 600), 'nonce': secrets.token_hex(16),
               'params': params, 'secrets': seal(secrets_map, self.age.to_public()) if secrets_map else None,
               'release_manifest': self.manifest if release else None, 'approval': approval}
        env['dispatch_signature'] = sign(env, self.keys.dispatch)
        return (self.db if step.startswith('db.') else self.app).handle(env)

    def backup(self, backup_id):
        return self.op('Tenant.Backup', 'app.backup',
                       {'backup_id': backup_id, 'retention_tier': 'daily', 'lock_days': 2},
                       {'s3_key_id': KEY_ID, 's3_secret': KEY_SECRET, 'region_recipient': str(self.region.to_public())})

    def restore(self, backup_id, tenant_id=None, deep=False):
        target = str(uuid.uuid4())
        self.copies.append(target)
        port = _free_port_pair()
        slot = dict(self.slot, container_uid=10001 + secrets.randbelow(40000), http_port=port, gevent_port=port + 1)
        params = {'backup_id': backup_id, 'target_environment_id': target, 'purpose': 'drill', 'deep': deep,
                  'runtime_slot': slot, 'app_host_ip': '10.0.0.11'}
        password = secrets.token_urlsafe(24)
        op_id = str(uuid.uuid4())
        first = self.op('Tenant.RestoreToIsolated', 'db.provision_copy', params,
                        {'db_password_scram': scram_verifier(password)}, op_id=op_id, tenant_id=tenant_id,
                        release=True)
        if first['code'] != 'OK':
            return target, slot, first
        second = self.op('Tenant.RestoreToIsolated', 'app.restore_copy', params,
                         {'db_password': password, 'admin_passwd_hash': odoo_master_hash(secrets.token_urlsafe(24)),
                          's3_key_id': KEY_ID, 's3_secret': KEY_SECRET, 'region_identity': str(self.region)},
                         op_id=op_id, tenant_id=tenant_id, release=True)
        return target, slot, second

    def teardown(self):
        super().teardown()
        for target in self.copies:
            t = derive_sid(target)
            for verb in ('container.remove', 'nft.remove_tenant', 'net.remove', 'volume.remove'):
                try:
                    self.app.exec.call(verb, sid=t)
                except Exception:
                    pass
            for verb in ('pg.drop_db', 'pg.drop_role', 'pg.hba_remove'):
                self.db_exec.handle({'verb': verb, 'args': {'sid': t}})
        self.db_exec.handle({'verb': 'pg.reload', 'args': {}})


class Odoo:
    """Minimal JSON-RPC client with a session cookie."""

    def __init__(self, port, db, password):
        self.base = 'http://127.0.0.1:%d' % port
        self.opener = __import__('urllib.request').request.build_opener(
            __import__('urllib.request').request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.call_json('/web/session/authenticate', {'db': db, 'login': 'admin', 'password': password})

    def call_json(self, path, params):
        import urllib.request
        body = json.dumps({'jsonrpc': '2.0', 'method': 'call', 'id': 1, 'params': params}).encode()
        req = urllib.request.Request(self.base + path, body, {'Content-Type': 'application/json'})
        with self.opener.open(req, timeout=60) as r:
            reply = json.loads(r.read())
        if 'error' in reply:
            raise RuntimeError(reply['error']['data']['message'])
        return reply['result']

    def kw(self, model, method, *args, **kwargs):
        return self.call_json('/web/dataset/call_kw', {'model': model, 'method': method, 'args': list(args),
                                                        'kwargs': kwargs})


@pytest.fixture(scope='module')
def w(tmp_path_factory):
    world = BackupWorld(tmp_path_factory.mktemp('backup'))
    for step in STEPS:
        resp = world.send(step)
        assert resp['code'] == 'OK', (step, resp['observed'])
    world.odoo = Odoo(world.slot['http_port'], 't_' + world.sid, world.admin_password)
    world.payloads = {}
    for i in range(3):
        data = secrets.token_bytes(2048 + i)
        att = world.odoo.kw('ir.attachment', 'create', {'name': 'probe-%d.bin' % i,
                                                        'datas': base64.b64encode(data).decode()})
        world.payloads[att] = data
    world.backup_id = str(uuid.uuid4())
    world.results = {}
    yield world
    if not os.environ.get('AGENT_KEEP'):
        world.teardown()


def test_backup(w):
    resp = w.backup(w.backup_id)
    w.results['backup'] = resp
    assert resp['code'] == 'OK', resp['observed']
    o = resp['observed']
    assert o['gc_guard_held'] and o['missing_files'] == 0 and o['referenced_files'] >= 3
    assert o['lock_mode'] == 'COMPLIANCE'
    assert datetime.fromisoformat(o['lock_until']) > datetime.now(timezone.utc) + timedelta(days=1)


def test_backup_rerun_verifies_and_changes_nothing(w):
    resp = w.backup(w.backup_id)
    assert resp['code'] == 'OK' and resp['observed']['already_stored']
    assert resp['observed']['object_version_id'] == w.results['backup']['observed']['object_version_id']


def test_stolen_key_cannot_delete_or_shorten(w):
    key = s3.object_key(w.tenant_id, w.environment_id, w.backup_id)
    version = w.results['backup']['observed']['object_version_id']
    for attempt in (lambda: w.s3.delete_object(Bucket=BUCKET, Key=key, VersionId=version),
                    lambda: w.s3.put_object_retention(
                        Bucket=BUCKET, Key=key, VersionId=version,
                        Retention={'Mode': 'COMPLIANCE',
                               'RetainUntilDate': datetime.now(timezone.utc) + timedelta(hours=1)})):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            attempt()
        assert e.value.response['Error']['Code'] == 'AccessDenied'


def test_archive_is_encrypted(w):
    key = s3.object_key(w.tenant_id, w.environment_id, w.backup_id)
    head = w.s3.get_object(Bucket=BUCKET, Key=key, Range='bytes=0-63')['Body'].read()
    assert head.startswith(b'age-encryption.org/v1')


def test_restore_to_isolated_copy(w):
    target, slot, resp = w.restore(w.backup_id)
    w.results['restore'] = (target, slot, resp)
    assert resp['code'] == 'OK', resp['observed']
    checks = resp['observed']['checks']
    assert checks['signature'] and checks['tenant'] and checks['modules_match'] and checks['files_verified']
    assert checks['zero_egress'] == 'not_measured'     # dry-run nftables in development
    assert 'row_counts_match' not in checks and resp['observed']['pdf'] is None     # not a deep drill


def test_deep_drill_compares_row_counts_and_prints_a_pdf(w):
    target, slot, resp = w.restore(w.backup_id, deep=True)
    assert resp['code'] == 'OK', resp['observed']
    seen = resp['observed']
    assert seen['checks']['row_counts_match'] is True and seen['checks']['pdf_printed'] is True
    counts = seen['row_counts']
    assert counts == seen['expected_row_counts'] and len(counts) == 10
    assert counts['res_users'] >= 1 and counts['ir_attachment'] >= 3 and counts['ir_module_module'] > 10
    assert seen['pdf']['kind'] == 'pdf' and seen['pdf']['pages'] >= 1 and seen['pdf']['bytes'] > 1000


@pytest.mark.parametrize('broken', ['row_counts', 'pdf'])
def test_deep_drill_fails_on_a_count_mismatch_or_no_pdf(w, monkeypatch, broken):
    client = w.app.exec.client
    real = client.call

    def call(verb, **args):
        out = real(verb, **args)
        if broken == 'row_counts' and verb == 'restore.load' and out.get('result'):
            out['result']['row_counts'] = dict(out['result']['row_counts'], res_partner=-1)
        if broken == 'pdf' and verb == 'container.run_oneshot' and args['command']['name'] == 'print_report':
            out = dict(out, result=dict(out['result'] or {}, ok=False))
        return out

    monkeypatch.setattr(client, 'call', call)
    _, _, resp = w.restore(w.backup_id, deep=True)
    assert resp['code'] == 'EXEC_ERROR'
    checks = resp['observed']['checks']
    assert checks['row_counts_match'] is (broken != 'row_counts') and checks['pdf_printed'] is (broken != 'pdf')


def test_restored_copy_has_the_same_attachments(w):
    target, slot, _ = w.results['restore']
    copy = Odoo(slot['http_port'], 't_' + derive_sid(target), w.admin_password)
    for att_id, data in w.payloads.items():
        rec = copy.kw('ir.attachment', 'read', [att_id], ['datas'])[0]
        assert base64.b64decode(rec['datas']) == data


def test_restored_copy_is_neutralized(w):
    target, slot, _ = w.results['restore']
    copy = Odoo(slot['http_port'], 't_' + derive_sid(target), w.admin_password)
    assert copy.kw('ir.config_parameter', 'get_param', 'database.is_neutralized') == 'true'
    assert copy.kw('ir.config_parameter', 'get_param', 'report.url') == 'http://127.0.0.1:8072'


def test_other_tenant_cannot_restore_this_backup(w):
    foreign = str(uuid.uuid4())
    target, _, resp = w.restore(w.backup_id, tenant_id=foreign)
    w.results['foreign'] = (target, foreign)
    # The object key is derived from the envelope's tenant: nothing to find.
    assert resp['code'] in ('EXEC_ERROR', 'NOT_OWNER')
    assert resp['observed'].get('backup') == 'not found' or resp['code'] == 'NOT_OWNER'


def test_backup_fails_when_a_referenced_file_is_missing(w):
    # DOC-04 §11: a referenced file that isn't in the filestore fails the backup
    # (missing_files > 0) and nothing is uploaded. Odoo's ir.attachment.write drops
    # store_fname, so the row is pointed at a missing file as the DB superuser.
    import psycopg
    att_id = next(iter(w.payloads))
    with psycopg.connect(w.pg.c.dsn, dbname='t_' + w.sid, autocommit=True) as conn:
        original = conn.execute('SELECT store_fname FROM ir_attachment WHERE id = %s', [att_id]).fetchone()[0]
        conn.execute('UPDATE ir_attachment SET store_fname = %s WHERE id = %s', ['ff/' + 'f' * 40, att_id])
        try:
            backup_id = str(uuid.uuid4())
            resp = w.backup(backup_id)
            assert (resp['status'], resp['code']) == ('failed', 'EXEC_ERROR')
            assert resp['observed']['missing_files'] == 1
            assert s3.head(w.s3, BUCKET, s3.object_key(w.tenant_id, w.environment_id, backup_id)) is None
        finally:
            conn.execute('UPDATE ir_attachment SET store_fname = %s WHERE id = %s', [original, att_id])


# -- RestoreCopy.Expire (DOC-04 §6.15) ---------------------------------------------

def expire(w, copy, tenant_id=None):
    op_id = str(uuid.uuid4())
    return [w.op('RestoreCopy.Expire', step, {'environment_id': copy}, op_id=op_id, tenant_id=tenant_id, state=None)
            for step in ('app.expire', 'db.expire')]


def test_expire_removes_the_copy(w):
    target, slot, _ = w.results['restore']
    app, db = expire(w, target)
    assert (app['code'], db['code']) == ('OK', 'OK'), (app['observed'], db['observed'])
    o = app['observed']
    assert not o['container']['exists'] and not o['volume']['exists'] and not o['nft']['applied'] and o['secrets'] == []
    assert db['observed']['db'] is None and db['observed']['role'] is None and db['observed']['hba_rules'] == 0
    assert w.app.state.environment(target)['deleted_at'] and w.db.state.environment(target)['deleted_at']


def test_expire_leaves_production_running(w):
    assert w.app.exec.call('container.inspect', sid=w.sid)['running']
    assert w.odoo.kw('res.users', 'search_count', [])


def test_expire_cleans_up_a_failed_restore(w):
    # The other tenant's restore created a database on the db host, then failed on the app host.
    target, foreign = w.results['foreign']
    assert w.db_exec.handle({'verb': 'pg.inspect', 'args': {'sid': derive_sid(target)}})['result']['db']
    app, db = expire(w, target, tenant_id=foreign)
    assert (app['code'], db['code']) == ('OK', 'OK'), (app['observed'], db['observed'])
    assert db['observed']['db'] is None


def test_expire_refuses_production(w):
    app, _ = expire(w, w.environment_id)
    assert app['code'] == 'POLICY_KIND'
