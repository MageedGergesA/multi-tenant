"""Tenant.Delete end to end (DOC-04 §6.13, DOC-07 RB-20) on the development
topology: stop, final backup, then app.remove and db.drop under one custodian
approval. The locked backup outlives the tenant.

    dev/up.sh && dev/test.sh tests/test_delete_e2e.py
"""
import os
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

from hostagent import s3
from hostagent.canonical import sign

from .conftest import iso
from .test_backup_e2e import BUCKET, KEY_ID, KEY_SECRET, BackupWorld
from .test_create_e2e import STEPS, _up

pytestmark = pytest.mark.skipif(not _up() or 'AGENT_S3_ENDPOINT' not in os.environ,
                                reason='run through dev/test.sh after dev/up.sh')

STATE = 'DELETION_ELIGIBLE'


@pytest.fixture(scope='module')
def w(tmp_path_factory):
    world = BackupWorld(tmp_path_factory.mktemp('delete'))
    for step in STEPS:
        resp = world.send(step)
        assert resp['code'] == 'OK', (step, resp['observed'])
    world.case = str(uuid.uuid4())
    world.delete_op = str(uuid.uuid4())
    world.backup_id = str(uuid.uuid4())
    world.results = {}
    yield world
    if not os.environ.get('AGENT_KEEP'):
        world.teardown()


def delete(w, step, op_id=None):
    op_id = op_id or w.delete_op
    a = {'op_id': op_id, 'tenant_id': w.tenant_id, 'action': 'Tenant.Delete',
         'expires_at': iso(__import__('time').time() + 600), 'deletion_case_id': w.case}
    a['custodian_signature'] = sign(a, w.keys.custodian)
    return w.op('Tenant.Delete', step, {'deletion_case_id': w.case}, op_id=op_id, state=STATE, approval=a)


def tenant_db_exists(w):
    with psycopg.connect(w.pg.c.dsn, autocommit=True) as conn:
        role = conn.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', ['r_' + w.sid]).fetchone()
        db = conn.execute('SELECT 1 FROM pg_database WHERE datname = %s', ['t_' + w.sid]).fetchone()
    return bool(role or db)


def test_refused_while_running(w):
    resp = delete(w, 'app.remove', op_id=str(uuid.uuid4()))
    assert (resp['code'], resp['observed']['detail']) == ('POLICY_STATE', 'runtime not stopped')


def test_refused_without_final_backup(w):
    assert w.op('Tenant.Stop', 'app.stop', {'reason': 'operator'}, state=STATE)['code'] == 'OK'
    resp = delete(w, 'app.remove', op_id=str(uuid.uuid4()))
    assert (resp['code'], resp['observed']['detail']) == ('POLICY_STATE', 'no backup in the last hour')


def test_final_backup(w):
    resp = w.op('Tenant.Backup', 'app.backup', {'backup_id': w.backup_id, 'retention_tier': 'final', 'lock_days': 2},
                {'s3_key_id': KEY_ID, 's3_secret': KEY_SECRET, 'region_recipient': str(w.region.to_public())},
                state=STATE)
    assert resp['code'] == 'OK', resp['observed']
    w.results['backup'] = resp['observed']


def test_app_remove(w):
    resp = delete(w, 'app.remove')
    assert resp['code'] == 'OK', resp['observed']
    o = resp['observed']
    assert not o['container']['exists'] and not o['network']['exists'] and not o['volume']['exists']
    assert not o['route']['present'] and not o['nft']['applied'] and o['secrets'] == []


def test_db_drop(w):
    resp = delete(w, 'db.drop')
    assert resp['code'] == 'OK', resp['observed']
    assert resp['observed']['role'] is None and resp['observed']['db'] is None
    assert resp['observed']['hba_rules'] == 0
    assert not tenant_db_exists(w)
    assert not (w.pg.c.hba_dir / ('%s.conf' % w.sid)).exists()


def test_nothing_left_in_backup_tmp(w):
    assert not (w.app.config.backup_tmp / w.sid).exists()


def test_steps_retry_cleanly(w):
    for step in ('app.remove', 'db.drop'):
        assert delete(w, step)['code'] == 'OK', step


def test_final_backup_outlives_the_tenant(w):
    stored = s3.head(w.s3, BUCKET, s3.object_key(w.tenant_id, w.environment_id, w.backup_id))
    assert stored['lock_mode'] == 'COMPLIANCE'
    assert datetime.fromisoformat(stored['lock_until']) > datetime.now(timezone.utc)
    assert stored['version_id'] == w.results['backup']['object_version_id']


def test_environment_never_comes_back(w):
    for step in ('app.network', 'db.provision'):
        resp = w.send(step, token=10 ** 6)
        assert (resp['code'], resp['observed']['detail']) == ('POLICY_STATE', 'deleted'), step
    assert w.app.state.environment(w.environment_id)['deleted_at']
    assert w.op('Tenant.Start', 'app.start', {'reason': 'operator'})['observed']['detail'] == 'deleted'
