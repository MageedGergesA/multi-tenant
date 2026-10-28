"""Runtime slots and capacity: Create and RestoreToIsolated through the operator
API (DOC-03 §2.3, §2.4, §5; INV-8, INV-10, INV-13, INV-17)."""
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from ctlplane import capacity
from hostagent.secrets import open_secrets

from .conftest import APP_HOST, DB_HOST, ENV, MAIL_HOST, OTHER_HOST, TENANT
from .test_operator_api import Api
from .test_secrets_releases import Releases, _binding, _odoo_ok, _scram_ok, agent_verifier

BUNDLE = dict(workers=2, max_cron_threads=1, db_maxconn=8, limit_memory_soft=640 << 20, limit_memory_hard=768 << 20,
              limit_time_cpu=600, limit_time_real=1200, mem_limit_bytes=2 << 30, cpu_millis=2000, disk_gb=10,
              db_disk_gb=5)
PG_CONN = (2 + 1 + 1) * 8 + 1      # 33
CREATE = {'domains': [{'hostname': 'acme.cloud.test', 'kind': 'platform'}], 'modules': ['sale'], 'lang': 'en_US',
          'country': 'EG'}


class World:
    def __init__(self, w):
        self.w = w
        self.api = Api(w)
        self.rel = Releases(w, self.api)
        self.release = self.rel.manifest(change_class='major')
        assert self.rel.upload(self.release).json()['status'] == 'approved'
        self.bundle = str(uuid.uuid4())
        w.sql('INSERT INTO resource_bundle (id, code, %s) VALUES (%%s, %%s, %s)'
              % (', '.join(BUNDLE), ', '.join(['%s'] * len(BUNDLE))), (self.bundle, 'S', *BUNDLE.values()))
        # Room for six on the app hosts by memory, four on the DB host by connections.
        w.sql('UPDATE host SET total_vcpu_milli = 16000, total_ram_mb = 16384, total_disk_gb = 400, reserve_pct = 20 '
              "WHERE role = 'app'")
        w.sql("UPDATE host SET total_disk_gb = 1000, pg_max_connections = 200, reserve_pct = 20 WHERE role = 'db'")
        w.sql("UPDATE host SET state = 'maintenance' WHERE id = %s", (OTHER_HOST,))     # one app host unless asked

    def tenant(self):
        t = str(uuid.uuid4())
        self.w.sql("INSERT INTO tenant (id, lifecycle_state, release_cell_id, resource_bundle_id) "
                   "VALUES (%s, 'ELIGIBLE', %s, %s)", (t, self.rel.cell, self.bundle))
        return t

    def create(self, tenant=None, params=None):
        return self.api.request('Tenant.Create', CREATE if params is None else params, tenant_id=tenant or self.tenant())

    def run(self, op_id, fail_at=None):
        """Every step answered by its host, in order."""
        while True:
            [step] = self.w.sql("SELECT * FROM operation_step WHERE operation_id = %s AND state = 'dispatched'",
                                (op_id,)) or [None]
            if step is None:
                return self.w.op(op_id)
            [env] = self.w.store.claim(str(step['host_id']), 8)
            if step['name'] == fail_at:
                self.w.store.apply(env['host_id'], self.w.response(env, 'failed', 'EXEC_ERROR'))
            else:
                self.w.store.apply(env['host_id'], self.w.response(env))

    def reservations(self, env):
        return self.w.sql('SELECT host_id, vcpu_milli, ram_mb, disk_gb, pg_conn, state FROM capacity_reservation '
                          'WHERE environment_id = %s ORDER BY pg_conn', (env,))


@pytest.fixture
def cw(w):
    return World(w)


# -- Create ---------------------------------------------------------------------------

def test_create_places_reserves_and_dispatches(cw, w, tmp_path):
    op = cw.create()
    assert (op['state'], op['result_code']) == ('DISPATCHED', None)
    o = w.op(op['id'])
    [tenant] = w.sql('SELECT lifecycle_state FROM tenant WHERE id = %s', (o['tenant_id'],))
    assert tenant['lifecycle_state'] == 'PROVISIONING'
    [env] = w.sql('SELECT * FROM environment WHERE id = %s', (o['environment_id'],))
    assert (env['kind'], str(env['app_host_id']), str(env['db_host_id']), str(env['mail_host_id'])) == \
        ('production', APP_HOST, DB_HOST, MAIL_HOST)
    [slot] = w.sql('SELECT * FROM runtime_slot WHERE environment_id = %s', (env['id'],))
    assert (slot['http_port'], slot['gevent_port'], str(slot['host_id'])) == (20000, 20001, APP_HOST)
    assert o['params']['runtime_slot']['container_uid'] == slot['container_uid'] >= 10001
    assert o['params']['app_host_ip'] == '10.0.0.11' and o['params']['domains'] == CREATE['domains']
    res = cw.reservations(env['id'])
    assert [(str(r['host_id']), r['vcpu_milli'], r['ram_mb'], r['disk_gb'], r['pg_conn'], r['state']) for r in res] == \
        [(APP_HOST, 2000, 2048, 10, 0, 'held'), (DB_HOST, 0, 0, 5, PG_CONN, 'held')]
    [db_env] = w.store.claim(DB_HOST, 4)
    agent_verifier(w, cw.rel, DB_HOST, 'db', tmp_path).verify(db_env, time.time())
    assert db_env['tenant_state'] == 'PROVISIONING' and db_env['release_manifest'] == cw.release
    assert _scram_ok(open_secrets(db_env, w.ages[DB_HOST])['db_password_scram'],
                     _binding(w, env['id'], 'db_password'))
    assert [a['action'] for a in w.sql('SELECT action FROM audit_event ORDER BY seq')][-3:] == \
        ['operation.requested', 'tenant.reserved', 'operation.dispatched']


def test_create_app_steps_get_the_slot_and_secrets(cw, w, tmp_path):
    op = cw.create()
    env = w.op(op['id'])['environment_id']
    for host in (DB_HOST, MAIL_HOST, APP_HOST, APP_HOST):
        [e] = w.store.claim(host, 4)
        w.store.apply(host, w.response(e))
    [cfg] = w.store.claim(APP_HOST, 4)
    assert cfg['step'] == 'app.config'
    agent_verifier(w, cw.rel, APP_HOST, 'app', tmp_path).verify(cfg, time.time())    # slot, ports, capacity
    got = open_secrets(cfg, w.ages[APP_HOST])
    assert got['db_password'] == _binding(w, env, 'db_password')
    assert _odoo_ok(got['admin_passwd_hash'], _binding(w, env, 'admin_passwd'))


def test_completed_create_commits_and_awaits_validation(cw, w):
    op = cw.create()
    assert cw.run(op['id'])['state'] == 'COMPLETED'
    o = w.op(op['id'])
    assert w.sql('SELECT lifecycle_state FROM tenant WHERE id = %s', (o['tenant_id'],))[0]['lifecycle_state'] == \
        'VALIDATING'
    assert {r['state'] for r in cw.reservations(o['environment_id'])} == {'committed'}


def test_failed_create_keeps_everything(cw, w):
    op = cw.create()
    assert cw.run(op['id'], fail_at='app.init_db')['state'] == 'FAILED'
    o = w.op(op['id'])
    assert w.sql('SELECT lifecycle_state FROM tenant WHERE id = %s', (o['tenant_id'],))[0]['lifecycle_state'] == 'ERROR'
    assert {r['state'] for r in cw.reservations(o['environment_id'])} == {'committed'}
    assert w.sql('SELECT released_at FROM runtime_slot WHERE environment_id = %s',
                 (o['environment_id'],))[0]['released_at'] is None


def test_create_needs_an_eligible_tenant_with_no_production(cw, w):
    t = cw.tenant()
    assert cw.create(t)['state'] == 'DISPATCHED'
    again = cw.create(t)
    assert (again['result_code'], again['result_detail']) == ('POLICY_STATE', {'tenant_state': 'PROVISIONING'})
    w.sql("UPDATE tenant SET lifecycle_state = 'ELIGIBLE' WHERE id = %s", (t,))
    assert cw.create(t)['result_detail'] == {'detail': 'production environment exists'}
    with pytest.raises(psycopg.errors.UniqueViolation):     # INV-10, even for the owner
        w.sql("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'production')", (uuid.uuid4(), t))


@pytest.mark.parametrize('case, code', [('no_bundle', 'NO_BUNDLE'), ('no_release', 'POLICY_RELEASE'),
                                        ('environment', 'SCHEMA'), ('slot', 'SCHEMA')])
def test_create_refused(cw, w, case, code):
    t = cw.tenant()
    if case == 'no_bundle':
        w.sql('UPDATE tenant SET resource_bundle_id = NULL WHERE id = %s', (t,))
    if case == 'no_release':
        w.sql("UPDATE image_release SET status = 'revoked'")
    if case == 'environment':
        op = cw.api.request('Tenant.Create', CREATE, tenant_id=t, environment_id=str(uuid.uuid4()))
    elif case == 'slot':                    # the slot is ctl-1's to choose
        op = cw.create(t, dict(CREATE, runtime_slot={'container_uid': 10001}))
    else:
        op = cw.create(t)
    assert (op['state'], op['result_code']) == ('REJECTED', code)


# -- INV-8 ------------------------------------------------------------------------------

def _nothing_left(w, tenant):
    assert w.sql('SELECT lifecycle_state FROM tenant WHERE id = %s', (tenant,))[0]['lifecycle_state'] == 'ELIGIBLE'
    assert w.sql('SELECT * FROM environment WHERE tenant_id = %s', (tenant,)) == []
    assert w.sql('SELECT * FROM secret_ref WHERE scope_tenant_id = %s', (tenant,)) == []


def test_db_connection_budget_limits_placement(cw, w):
    for _ in range(4):
        assert cw.create()['state'] == 'DISPATCHED'
    t = cw.tenant()
    op = cw.create(t)
    assert (op['state'], op['result_code']) == ('REJECTED', 'CAPACITY')
    _nothing_left(w, t)
    [used] = w.sql("SELECT SUM(pg_conn) AS n FROM capacity_reservation WHERE host_id = %s AND state = 'held'",
                   (DB_HOST,))
    assert used['n'] == 4 * PG_CONN <= 200 * 80 // 100


def test_app_memory_limits_placement_and_reserve_is_kept(cw, w):
    w.sql('UPDATE host SET pg_max_connections = 10000 WHERE id = %s', (DB_HOST,))
    results = [cw.create()['result_code'] for _ in range(7)]
    assert results == [None] * 6 + ['CAPACITY']           # 6 × 2048 MB ≤ 80% of 16384 < 7 × 2048


def test_spreads_to_the_host_with_most_free_memory(cw, w):
    w.sql('UPDATE host SET pg_max_connections = 10000 WHERE id = %s', (DB_HOST,))
    w.sql("UPDATE host SET state = 'active' WHERE id = %s", (OTHER_HOST,))
    hosts = [str(w.op(cw.create()['id'])['host_id']) for _ in range(4)]
    envs = w.sql("SELECT app_host_id FROM environment WHERE kind = 'production' AND tenant_id <> %s", (TENANT,))
    assert sorted(str(e['app_host_id']) for e in envs).count(APP_HOST) == 2
    assert hosts[0] == DB_HOST     # Create's first step is the DB's


def test_expired_hold_frees_capacity(cw, w):
    for _ in range(4):
        cw.create()
    w.sql("UPDATE capacity_reservation SET expires_at = now() - interval '1 second' WHERE state = 'held'")
    assert cw.create()['state'] == 'DISPATCHED'


def test_concurrent_creates_never_overbook(cw, w):
    tenants = [cw.tenant() for _ in range(8)]
    out, lock = [], threading.Lock()

    def go(t):
        op = cw.api.admission.request(cw.api.ops['founder'], op_type='Tenant.Create', tenant_id=t,
                                      params=CREATE, idempotency_key=t)
        with lock:
            out.append(op['state'])
    threads = [threading.Thread(target=go, args=(t,)) for t in tenants]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(out) == ['DISPATCHED'] * 4 + ['REJECTED'] * 4
    with w.store.connect() as c:
        [host] = c.execute('SELECT * FROM host WHERE id = %s', (DB_HOST,)).fetchall()
        assert capacity.free(c, host, time.time())['pg_conn'] == 160 - 4 * PG_CONN


# -- slots ----------------------------------------------------------------------------

def test_ports_are_the_lowest_free_pair_and_uids_never_repeat(cw, w):
    ops = [cw.create() for _ in range(3)]
    slots = [w.op(o['id'])['params']['runtime_slot'] for o in ops]
    assert [s['http_port'] for s in slots] == [20000, 20002, 20004]
    uids = [s['container_uid'] for s in slots]
    assert uids == sorted(set(uids))
    middle = w.op(ops[1]['id'])['environment_id']
    with w.store.connect() as c:
        capacity.release_environment(c, middle, time.time())
    nxt = w.op(cw.create()['id'])['params']['runtime_slot']
    assert nxt['http_port'] == 20002 and nxt['container_uid'] > max(uids)


def test_ports_respect_the_host_range(cw, w):
    w.sql('UPDATE host SET port_low = 20100, port_high = 20103 WHERE id = %s', (APP_HOST,))
    assert [w.op(cw.create()['id'])['params']['runtime_slot']['http_port'] for _ in range(2)] == [20100, 20102]
    assert cw.create()['result_code'] == 'CAPACITY'


# -- RestoreToIsolated and removal ------------------------------------------------------

@pytest.fixture
def prod(cw, w):
    """The fixture tenant's production, placed and sized, with a recoverable backup."""
    w.sql('UPDATE tenant SET release_cell_id = %s, resource_bundle_id = %s', (cw.rel.cell, cw.bundle))
    w.sql('UPDATE environment SET resource_bundle_id = %s, app_host_id = %s, db_host_id = %s, '
          'image_release_id = (SELECT id FROM image_release) WHERE id = %s', (cw.bundle, APP_HOST, DB_HOST, ENV))
    with w.store.connect() as c:
        from ctlplane import vault
        vault.provision(c, ENV, TENANT, w.vault.recipient, datetime.now(timezone.utc))
        [host] = c.execute('SELECT * FROM host WHERE id = %s', (APP_HOST,)).fetchall()
        bundle = c.execute('SELECT * FROM resource_bundle WHERE id = %s', (cw.bundle,)).fetchone()
        capacity.allocate_slot(c, ENV, host, bundle, time.time())
    return cw.api.backup()


def test_restore_copy_gets_its_own_slot_secrets_and_expiry(cw, w, prod, tmp_path):
    op = cw.api.request('Tenant.RestoreToIsolated', {'backup_id': prod, 'purpose': 'drill'})
    assert op['state'] == 'DISPATCHED', op
    p = w.op(op['id'])['params']
    [copy] = w.sql('SELECT * FROM environment WHERE id = %s', (p['target_environment_id'],))
    assert (copy['kind'], str(copy['tenant_id']), str(copy['source_backup_id'])) == ('restore_copy', TENANT, prod)
    assert timedelta(days=6, hours=23) < copy['expires_at'] - datetime.now(timezone.utc) <= timedelta(days=7)
    assert (str(copy['app_host_id']), str(copy['db_host_id'])) == (APP_HOST, DB_HOST)
    assert p['runtime_slot']['http_port'] == 20002            # production has 20000
    assert {r['state'] for r in cw.reservations(copy['id'])} == {'held'}
    [db_env] = w.store.claim(DB_HOST, 4)
    agent_verifier(w, cw.rel, DB_HOST, 'db', tmp_path).verify(db_env, time.time())
    assert _scram_ok(open_secrets(db_env, w.ages[DB_HOST])['db_password_scram'],
                     _binding(w, copy['id'], 'db_password'))
    assert _binding(w, copy['id'], 'db_password') != _binding(w, ENV, 'db_password')


@pytest.mark.parametrize('case, code', [('other_tenant', 'NOT_OWNER'), ('failed', 'POLICY_BACKUP'),
                                        ('unknown', 'NOT_FOUND'), ('target', 'SCHEMA')])
def test_restore_refused(cw, w, prod, case, code):
    backup = prod
    if case == 'other_tenant':
        other, oenv = str(uuid.uuid4()), str(uuid.uuid4())
        w.sql("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ACTIVE')", (other,))
        w.sql("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'production')", (oenv, other))
        w.sql('UPDATE backup_point SET environment_id = %s', (oenv,))
    if case == 'failed':
        w.sql("UPDATE backup_point SET state = 'failed'")
    if case == 'unknown':
        backup = str(uuid.uuid4())
    params = {'backup_id': backup, 'purpose': 'drill'}
    if case == 'target':                     # the copy's identity is ctl-1's to choose
        params['target_environment_id'] = ENV
    op = cw.api.request('Tenant.RestoreToIsolated', params)
    assert (op['state'], op['result_code']) == ('REJECTED', code)
    assert w.sql("SELECT * FROM environment WHERE kind = 'restore_copy'") == []


def test_expiring_the_copy_frees_its_host(cw, w, prod):
    op = cw.api.request('Tenant.RestoreToIsolated', {'backup_id': prod, 'purpose': 'drill'})
    copy = w.op(op['id'])['params']['target_environment_id']
    cw.run(op['id'])
    assert {r['state'] for r in cw.reservations(copy)} == {'committed'}
    exp = cw.api.request('RestoreCopy.Expire', {'environment_id': copy})
    assert cw.run(exp['id'])['state'] == 'COMPLETED'
    assert {r['state'] for r in cw.reservations(copy)} == {'released'}
    [slot] = w.sql('SELECT released_at FROM runtime_slot WHERE environment_id = %s', (copy,))
    assert slot['released_at'] is not None
    assert w.sql('SELECT observed_state FROM environment WHERE id = %s', (copy,))[0]['observed_state'] == 'absent'
    again = cw.api.request('Tenant.RestoreToIsolated', {'backup_id': prod, 'purpose': 'drill'})
    assert w.op(again['id'])['params']['runtime_slot']['http_port'] == 20002    # the port came back


def test_delete_frees_the_host_and_ends_the_tenant(cw, w):
    op = cw.create()
    cw.run(op['id'])
    o = w.op(op['id'])
    w.sql("UPDATE tenant SET lifecycle_state = 'DELETION_ELIGIBLE' WHERE id = %s", (o['tenant_id'],))
    case = str(uuid.uuid4())
    d = cw.api.request('Tenant.Delete', {'deletion_case_id': case}, tenant_id=str(o['tenant_id']),
                       environment_id=str(o['environment_id']))
    bid = str(uuid.uuid4())
    w.sql("INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, "
          "gc_guard_held, missing_files, state, created_at) VALUES (%s, %s, %s, 'manual', 'final', now(), true, 0, "
          "'recoverable', now())", (bid, o['environment_id'], op['id']))
    a = cw.api.approval(d, deletion_case_id=case, tenant_id=str(o['tenant_id']))
    r = cw.api.post('/v1/operations/%s/approval' % d['id'], {'approval': a}, who='custodian')
    assert r.json()['state'] == 'DISPATCHED'
    w.sql('UPDATE environment SET mail_host_id = %s WHERE id = %s', (MAIL_HOST, o['environment_id']))
    assert cw.run(d['id'])['state'] == 'COMPLETED'
    assert w.sql('SELECT lifecycle_state FROM tenant WHERE id = %s', (o['tenant_id'],))[0]['lifecycle_state'] == \
        'DELETED'
    assert {r['state'] for r in cw.reservations(o['environment_id'])} == {'released'}


def test_refusal_after_allocation_leaves_nothing(cw, w):
    w.sql('UPDATE host SET private_ip = NULL WHERE id = %s', (APP_HOST,))     # found only once params are filled
    t = cw.tenant()
    op = cw.create(t)
    assert (op['state'], op['result_code']) == ('REJECTED', 'NO_PLACEMENT')
    _nothing_left(w, t)
    assert w.sql('SELECT * FROM runtime_slot') == [] and w.sql('SELECT * FROM capacity_reservation') == []


def test_host_lock_alone_prevents_overbooking(cw, w):
    """Without admission's audit lock in the way: concurrent place + hold on one DB host."""
    bundle = w.sql('SELECT * FROM resource_bundle')[0]
    _, db_need = capacity.needs(bundle)
    envs = [str(uuid.uuid4()) for _ in range(6)]
    op_id = w.store.dispatch('Tenant.Stop', tenant_id=TENANT, environment_id=ENV, params={'reason': 'operator'},
                             hosts={'app': APP_HOST}, idempotency_key='x')
    for e in envs:
        w.sql("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ELIGIBLE')", (e,))
        w.sql("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'production')", (e, e))
    held, start = [], threading.Barrier(6)

    def go(env):
        with w.store.connect() as c:
            start.wait()
            try:
                app, db = capacity.place(c, bundle, time.time())
            except capacity.NoCapacity:
                return
            time.sleep(0.3)                  # widen the gap between reading usage and holding
            capacity.hold(c, op_id, env, db, db_need, time.time())
            held.append(env)
    threads = [threading.Thread(target=go, args=(e,)) for e in envs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(held) == 4
