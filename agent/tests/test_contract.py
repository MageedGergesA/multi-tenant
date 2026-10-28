"""DOC-04 §11 negative tests, plus the positive paths they guard."""
import json
import os
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from hostagent.canonical import verify, without
from hostagent.execd import ExecServer
from hostagent.naming import sid

from .conftest import DIGEST, ENV_A, ENV_B, HOST_ID, TENANT_A, TENANT_B, Harness


def codes(resp):
    return resp['status'], resp['code']


def test_start_runs_and_response_is_signed(h):
    h.register()
    resp = h.agent.handle(h.envelope())
    assert codes(resp) == ('done', 'OK')
    assert h.backend.containers[sid(ENV_A)]['running']
    body = without(resp, 'agent_signature')
    assert verify(body, resp['agent_signature'], [h.keys.agent.verify_key])


def test_completed_step_is_idempotent(h):
    h.register(running=True)
    resp = h.agent.handle(h.envelope())
    assert codes(resp) == ('done', 'OK')
    assert h.backend.calls == []  # read-back found it running; nothing was done


def test_older_fencing_token_is_stale(h):
    h.register()
    assert h.agent.handle(h.envelope(token=10))['code'] == 'OK'
    resp = h.agent.handle(h.envelope(op_type='Tenant.Stop', step='app.stop', token=9))
    assert codes(resp) == ('rejected', 'STALE_FENCE')
    assert [c for c in h.backend.calls if c[0] != 'secret' and c[0] != 'conf'] == [('start', sid(ENV_A))]


def test_equal_token_only_for_the_same_operation(h):
    h.register()
    op = str(uuid.uuid4())
    assert h.agent.handle(h.envelope(token=5, op_id=op))['code'] == 'OK'
    assert h.agent.handle(h.envelope(token=5, op_id=op))['code'] == 'OK'          # same op, next envelope
    assert h.agent.handle(h.envelope(token=5))['code'] == 'STALE_FENCE'           # another op, same token


def test_replay_is_rejected(h):
    h.register()
    env = h.envelope()
    assert h.agent.handle(env)['code'] == 'OK'
    assert codes(h.agent.handle(env)) == ('rejected', 'REPLAY')


@pytest.mark.parametrize('signer', ['stranger', 'custodian', 'release'])
def test_wrong_signing_key(h, signer):
    h.register()
    resp = h.agent.handle(h.envelope(key=getattr(h.keys, signer)))
    assert codes(resp) == ('rejected', 'SIG_INVALID')


def test_tampered_envelope(h):
    h.register()
    env = h.envelope()
    env['environment_id'] = ENV_B
    assert h.agent.handle(env)['code'] == 'SIG_INVALID'


@pytest.mark.parametrize('extra', [{'cmd': 'rm -rf /'}, {'path': '/etc/shadow'}])
def test_extra_param_field(h, extra):
    h.register()
    resp = h.agent.handle(h.envelope(params={'reason': 'operator', **extra}))
    assert codes(resp) == ('rejected', 'SCHEMA')


def test_extra_envelope_field(h):
    h.register()
    assert h.agent.handle(h.envelope(extra={'image': 'evil:latest'}))['code'] == 'SCHEMA'


def test_unknown_version_and_step(h):
    h.register()
    assert h.agent.handle(h.resign({**h.envelope(), 'v': 2}))['code'] == 'SCHEMA'
    assert h.agent.handle(h.envelope(step='app.stop'))['code'] == 'SCHEMA'
    assert h.agent.handle('not an envelope')['code'] == 'SCHEMA'


def test_other_host(h):
    h.register()
    env = h.resign({**h.envelope(), 'host_id': '22222222-2222-4222-8222-222222222222'})
    assert h.agent.handle(env)['code'] == 'POLICY_HOST'


def test_clock_skew_and_expiry(h):
    h.register()
    assert h.agent.handle(h.envelope(issued=h.clock() + 300))['code'] == 'EXPIRED'   # 5 min in the future
    assert h.agent.handle(h.envelope(issued=h.clock() - 700, life=600))['code'] == 'EXPIRED'
    assert h.agent.handle(h.envelope(life=3600))['code'] == 'EXPIRED'                 # lifetime > 10 min


def test_tenant_b_environment_with_tenant_a_id(h):
    h.register(ENV_B, TENANT_B)
    resp = h.agent.handle(h.envelope(environment_id=ENV_B, tenant_id=TENANT_A))
    assert codes(resp) == ('rejected', 'NOT_OWNER')
    assert h.backend.calls == []


def test_unregistered_environment(h):
    assert h.agent.handle(h.envelope())['code'] == 'NOT_OWNER'


def test_wrong_tenant_state(h):
    h.register()
    assert h.agent.handle(h.envelope(tenant_state='SUSPENDED'))['code'] == 'POLICY_STATE'


def test_step_for_another_role(h):
    h.register()
    env = h.envelope('Tenant.Delete', 'db.drop', {'deletion_case_id': str(uuid.uuid4())},
                     tenant_state='DELETION_ELIGIBLE')
    assert h.agent.handle(env)['code'] in ('POLICY_APPROVAL', 'POLICY_ROLE')


# -- release manifest (SEC-07) ------------------------------------------------

def patch_env(h, manifest, digest=DIGEST):
    return h.envelope('Tenant.ApplyPatch', 'app.check_versions', {'target_digest': digest},
                      release_manifest=manifest)


def test_digest_not_in_signed_manifest(h):
    h.register()
    assert h.agent.handle(patch_env(h, h.manifest(), 'sha256:' + 'ef' * 32))['code'] == 'POLICY_RELEASE'


def test_manifest_signed_by_dispatch_key(h):
    h.register()
    assert h.agent.handle(patch_env(h, h.manifest(key=h.keys.dispatch)))['code'] == 'POLICY_RELEASE'


def test_manifest_missing(h):
    h.register()
    assert h.agent.handle(patch_env(h, None))['code'] == 'POLICY_RELEASE'


def test_manifest_other_cell(h):
    h.register()
    m = h.manifest()
    m = {**without(m, 'release_signature'), 'cell': 'enterprise/19.0/ubuntu-24.04/py3.12/pg16'}
    from hostagent.canonical import sign
    m['release_signature'] = sign(m, h.keys.release)
    assert h.agent.handle(patch_env(h, m))['code'] == 'POLICY_CELL'


def test_patch_requires_patch_class(h):
    h.register()
    assert h.agent.handle(patch_env(h, h.manifest(change_class='module_update')))['code'] == 'POLICY_RELEASE'


def test_valid_manifest_passes_to_the_step(h):
    h.register()
    resp = h.agent.handle(patch_env(h, h.manifest()))
    # Verification passed; the step itself isn't built yet and fails closed.
    assert codes(resp) == ('failed', 'EXEC_ERROR')
    assert resp['observed'] == {'reason': 'step not implemented'}


# -- custodian approval (SEC-11, DR-16) ---------------------------------------

def delete_env(h, approval_for=None, key=None, case=None, tenant=TENANT_A):
    op_id = str(uuid.uuid4())
    case = case or str(uuid.uuid4())
    approval = None
    if approval_for != 'none':
        approval = h.approval(op_id, approval_for or tenant, 'Tenant.Delete', key=key, deletion_case_id=case)
    return h.envelope('Tenant.Delete', 'app.remove', {'deletion_case_id': case}, op_id=op_id, tenant_id=tenant,
                      tenant_state='DELETION_ELIGIBLE', approval=approval)


def journal(h, op_type, step, finished=None, environment_id=ENV_A):
    row = h.state.journal_start(op_id=str(uuid.uuid4()), op_type=op_type, step=step, environment_id=environment_id,
                                token=0, now=h.clock())
    h.state.journal_finish(row, status='done', code='OK', evidence_sha256='0' * 64,
                           now=h.clock() if finished is None else finished)


def ready_for_delete(h):
    journal(h, 'Tenant.Stop', 'app.stop')
    journal(h, 'Tenant.Backup', 'app.backup')


def test_delete_without_custodian(h):
    h.register()
    assert h.agent.handle(delete_env(h, approval_for='none'))['code'] == 'POLICY_APPROVAL'


def test_delete_with_approval_for_other_tenant(h):
    h.register()
    assert h.agent.handle(delete_env(h, approval_for=TENANT_B))['code'] == 'POLICY_APPROVAL'


def test_delete_with_approval_signed_by_dispatch(h):
    h.register()
    assert h.agent.handle(delete_env(h, key=h.keys.dispatch))['code'] == 'POLICY_APPROVAL'


def test_delete_with_approval_for_other_case(h):
    h.register()
    op_id = str(uuid.uuid4())
    approval = h.approval(op_id, TENANT_A, 'Tenant.Delete', deletion_case_id=str(uuid.uuid4()))
    env = h.envelope('Tenant.Delete', 'app.remove', {'deletion_case_id': str(uuid.uuid4())}, op_id=op_id,
                     tenant_state='DELETION_ELIGIBLE', approval=approval)
    assert h.agent.handle(env)['code'] == 'POLICY_APPROVAL'


def test_delete_only_when_deletion_eligible(h):
    h.register()
    op_id = str(uuid.uuid4())
    case = str(uuid.uuid4())
    env = h.envelope('Tenant.Delete', 'app.remove', {'deletion_case_id': case}, op_id=op_id, tenant_state='ACTIVE',
                     approval=h.approval(op_id, TENANT_A, 'Tenant.Delete', deletion_case_id=case))
    assert h.agent.handle(env)['code'] == 'POLICY_STATE'


def test_breakglass_only_when_enabled(tmp_path):
    for enabled, expected in ((False, 'POLICY_APPROVAL'), (True, 'OK')):
        hh = Harness(tmp_path / str(enabled), breakglass_enabled=enabled)
        hh.register()
        ready_for_delete(hh)
        resp = hh.agent.handle(delete_env(hh, key=hh.keys.breakglass))
        assert resp['code'] == expected
        if enabled:
            assert resp['observed']['breakglass_used'] is True


# -- concurrency, rate, capacity, drain ---------------------------------------

def test_parallel_start_stop_one_proceeds(h):
    h.register()
    h.backend.delay = 0.3
    envs = [h.envelope('Tenant.Start' if i % 2 else 'Tenant.Stop', 'app.start' if i % 2 else 'app.stop')
            for i in range(100)]
    with ThreadPoolExecutor(32) as pool:
        results = list(pool.map(h.agent.handle, envs))
    # Never two at once (INV-21). Once a step finishes, later requests may be
    # admitted, bounded by the 5/min per-environment rate limit.
    assert h.backend.max_active <= 1
    done = [r for r in results if r['code'] == 'OK']
    assert 1 <= len(done) <= 5
    others = {r['code'] for r in results if r['code'] != 'OK'}
    assert 'BUSY' in others and others <= {'BUSY', 'STALE_FENCE', 'RATE_LIMITED'}
    assert all(r['status'] == 'busy' for r in results if r['code'] == 'BUSY')
    # Final state matches the last step that ran.
    last = max(done, key=lambda r: r['fencing_token'])
    assert h.backend.containers[sid(ENV_A)]['running'] == (last['step'] == 'app.start')


def test_rate_limit_per_environment(h):
    h.register()
    results = [h.agent.handle(h.envelope())['code'] for _ in range(7)]
    assert results[:5] == ['OK'] * 5
    assert results[5:] == ['RATE_LIMITED'] * 2


def test_steps_of_one_operation_count_once(h):
    # A multi-step operation stays admitted between its steps; only its first
    # admission is a rate event (DOC-04 §4 counts requests, not envelopes).
    op, token = str(uuid.uuid4()), h.next_token()
    for _ in range(8):
        h.state.admit(scope_id=ENV_A, op_id=op, step='app.network', token=token, fenced=True, exclusive=True,
                      mutating=True, host_scope=HOST_ID, rate_host=30, rate_env=5, now=h.clock())
    assert h.state._one('SELECT count(*) FROM rate_event WHERE scope_id = ?', (ENV_A,))[0] == 1


def test_drain_blocks_create_and_needs_custodian_to_evacuate(h):
    host_env = dict(environment_id=None, tenant_id=None, tenant_state=None)
    assert h.agent.handle(h.envelope('Host.Drain', 'any.drain', {'evacuate': True}, **host_env))['code'] \
        == 'POLICY_APPROVAL'
    assert h.agent.handle(h.envelope('Host.Drain', 'any.drain', {'evacuate': False}, **host_env))['code'] == 'OK'
    assert h.state.flag('draining') == '1'


# -- reconciliation read-back --------------------------------------------------

def test_query_returns_journal_and_observed_state(h):
    h.register()
    op = str(uuid.uuid4())
    h.agent.handle(h.envelope(op_id=op))
    resp = h.agent.handle(h.envelope('Agent.Query', 'any.query', {'op_id': op}, tenant_state=None))
    assert resp['code'] == 'OK'
    assert [r['status'] for r in resp['observed']['journal']] == ['done']
    assert resp['observed']['container']['running'] is True


def test_query_does_not_leak_other_tenants(h):
    h.register(ENV_B, TENANT_B)
    resp = h.agent.handle(h.envelope('Agent.Query', 'any.query', {'op_id': None}, environment_id=ENV_B,
                                     tenant_id=TENANT_A, tenant_state=None))
    assert resp['observed'] == {'registry': None}


# -- executor ------------------------------------------------------------------

@pytest.mark.parametrize('request_', [
    {'verb': 'shell.run', 'args': {'cmd': 'id'}},
    {'verb': 'container.create', 'args': {'sid': 'a' * 12, 'digest': DIGEST, 'uid': 10001,
                                          'limits': {'mem_limit_bytes': 1 << 30, 'cpu_millis': 1000, 'pids': 256},
                                          'ports': {'http': 8069, 'gevent': 20001}}},
    {'verb': 'container.start', 'args': {'sid': '../../etc'}},
    {'verb': 'container.stop', 'args': {'sid': 'a' * 12, 'timeout': 60, 'signal': 'KILL'}},
    {'verb': 'pg.drop_db', 'args': {'sid': 'a' * 12}},          # a db verb on the app executor
    'garbage',
])
def test_executor_refuses_and_logs(h, request_):
    reply = h.executor.handle(request_)
    assert reply == {'ok': False, 'error': 'REFUSED', 'reason': reply['reason']}
    assert json.loads(h.exec_log.lines[-1])['result'] == 'refused'
    assert h.backend.calls == []


def test_executor_socket_is_private_and_refuses(h, tmp_path):
    path = tmp_path / 'exec.sock'
    server = ExecServer(path, h.executor)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert oct(path.stat().st_mode & 0o777) == '0o600'
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(str(path))
            s.sendall(b'{"verb": "container.start", "args": {"sid": "x; reboot"}}\n')
            assert json.loads(s.makefile().readline())['error'] == 'REFUSED'
    finally:
        server.shutdown()
        server.server_close()


def test_executor_socket_can_be_shared_through_a_group(h, tmp_path):
    """The db executor runs as postgres: it can't give the socket to agentd's uid, only to a group both
    are in (0660)."""
    path = tmp_path / 'exec.sock'
    server = ExecServer(path, h.executor, owner_gid=os.getgid())
    try:
        st = path.stat()
        assert oct(st.st_mode & 0o777) == '0o660' and st.st_gid == os.getgid()
    finally:
        server.server_close()


def test_logs_are_redacted(h):
    h.executor.handle({'verb': 'file.write_secret', 'args': {'sid': 'a' * 12, 'name': 'pgpass',
                                                              'data_b64': 'c2VjcmV0'}})
    assert 'c2VjcmV0' not in '\n'.join(h.exec_log.lines)


# -- Tenant.Delete preconditions and tombstone (DOC-04 §6.13, DOC-03 §9) ----------

def test_delete_refused_while_runtime_not_stopped(h):
    h.register(running=True)
    journal(h, 'Tenant.Stop', 'app.stop')
    journal(h, 'Tenant.Start', 'app.start')
    journal(h, 'Tenant.Backup', 'app.backup')
    resp = h.agent.handle(delete_env(h))
    assert codes(resp) == ('rejected', 'POLICY_STATE') and resp['observed']['detail'] == 'runtime not stopped'
    assert h.backend.containers[sid(ENV_A)]['running']


def test_delete_refused_without_a_recent_backup(h):
    h.register()
    journal(h, 'Tenant.Stop', 'app.stop')
    journal(h, 'Tenant.Backup', 'app.backup', finished=h.clock() - 3601)
    resp = h.agent.handle(delete_env(h))
    assert codes(resp) == ('rejected', 'POLICY_STATE') and resp['observed']['detail'] == 'no backup in the last hour'


def test_delete_refused_while_a_restore_copy_lives(h):
    h.register()
    ready_for_delete(h)
    h.state.register(environment_id=ENV_B, tenant_id=TENANT_A, sid=sid(ENV_B), container_uid=10002,
                     http_port=20010, gevent_port=20011, kind='restore_copy', egress_profile='deny_all', now=h.clock())
    resp = h.agent.handle(delete_env(h))
    assert resp['observed']['detail'] == 'restore copies outstanding'
    h.state.tombstone(ENV_B, h.clock())
    assert codes(h.agent.handle(delete_env(h))) == ('done', 'OK')


def test_delete_refused_on_a_restore_copy(h):
    h.state.register(environment_id=ENV_A, tenant_id=TENANT_A, sid=sid(ENV_A), container_uid=10001,
                     http_port=20000, gevent_port=20001, kind='restore_copy', egress_profile='deny_all', now=h.clock())
    ready_for_delete(h)
    assert h.agent.handle(delete_env(h))['code'] == 'POLICY_KIND'


def test_deleted_environment_is_a_tombstone(h):
    h.register()
    ready_for_delete(h)
    resp = h.agent.handle(delete_env(h))
    assert codes(resp) == ('done', 'OK') and resp['observed']['registry'] == 'tombstoned'
    assert ('remove', sid(ENV_A)) in h.backend.calls
    reg = h.state.environment(ENV_A)
    assert reg['deleted_at'] and reg['container_uid'] == 10001 and reg['http_port'] is None
    # Nothing else runs on it again, and its container_uid is never reused; its ports are.
    h.backend.containers[sid(ENV_A)] = {'running': False}
    resp = h.agent.handle(h.envelope())
    assert codes(resp) == ('rejected', 'POLICY_STATE') and resp['observed']['detail'] == 'deleted'
    assert h.state.slot_conflict(ENV_B, 10001, (20100, 20101))
    assert not h.state.slot_conflict(ENV_B, 10003, (20000, 20001))
    # A retry of the delete itself passes (a lost response); it skips the journal checks.
    assert codes(h.agent.handle(delete_env(h))) == ('done', 'OK')


def test_final_backup_allowed_while_deletion_eligible(h):
    h.register()
    env = h.envelope('Tenant.Backup', 'app.backup', {'backup_id': str(uuid.uuid4()), 'retention_tier': 'final',
                                                     'lock_days': 93}, tenant_state='DELETION_ELIGIBLE')
    resp = h.agent.handle(env)
    # Admitted; it then fails only because this envelope carries no S3 secrets.
    assert codes(resp) == ('failed', 'SCHEMA') and resp['observed'] == {'secrets': 'missing'}


# -- RestoreCopy.Expire (DOC-04 §6.15) ---------------------------------------------

def register_copy(h, environment_id=ENV_B, tenant_id=TENANT_A):
    h.state.register(environment_id=environment_id, tenant_id=tenant_id, sid=sid(environment_id),
                     container_uid=10002, http_port=20010, gevent_port=20011, kind='restore_copy',
                     egress_profile='deny_all', now=h.clock())
    h.backend.containers[sid(environment_id)] = {'running': True}


def expire_env(h, copy=ENV_B, tenant=TENANT_A, **kw):
    return h.envelope('RestoreCopy.Expire', 'app.expire', {'environment_id': copy}, tenant_id=tenant,
                      tenant_state=None, **kw)


def test_expire_removes_the_copy_only(h):
    h.register(running=True)
    register_copy(h)
    resp = h.agent.handle(expire_env(h))
    assert codes(resp) == ('done', 'OK') and resp['observed']['registry'] == 'tombstoned'
    assert h.state.environment(ENV_B)['deleted_at'] and h.state.environment(ENV_A)['deleted_at'] is None
    assert sid(ENV_B) not in h.backend.containers and h.backend.containers[sid(ENV_A)]['running']
    assert h.state.live_copies(TENANT_A) == []
    assert codes(h.agent.handle(expire_env(h))) == ('done', 'OK')       # retry


def test_expire_refuses_production(h):
    h.register()
    assert h.agent.handle(expire_env(h, copy=ENV_A))['code'] == 'POLICY_KIND'
    assert sid(ENV_A) in h.backend.containers


def test_expire_refuses_another_tenants_copy(h):
    register_copy(h, tenant_id=TENANT_B)
    assert h.agent.handle(expire_env(h))['code'] == 'NOT_OWNER'
    assert sid(ENV_B) in h.backend.containers


def test_expire_of_an_unknown_copy_touches_nothing(h):
    resp = h.agent.handle(expire_env(h))
    assert codes(resp) == ('done', 'OK') and resp['observed'] == {'registry': 'absent'}
    assert h.backend.calls == []


def test_expire_waits_for_a_restore_in_progress(h):
    register_copy(h)
    h.state.admit(scope_id=ENV_B, op_id=str(uuid.uuid4()), step='app.restore_copy', token=h.next_token(),
                  fenced=True, exclusive=True, mutating=False, host_scope=HOST_ID, rate_host=30, rate_env=5,
                  now=h.clock())
    assert codes(h.agent.handle(expire_env(h))) == ('busy', 'BUSY')


def test_expire_is_fenced_on_the_copy(h):
    # A high-token Expire doesn't make production's next (lower-token) Start stale.
    h.register()
    register_copy(h)
    start = h.envelope(token=5)
    assert codes(h.agent.handle(expire_env(h, token=50))) == ('done', 'OK')
    assert codes(h.agent.handle(start)) == ('done', 'OK')


# -- agent-exec: one changing verb per sid (README gap 30) -------------------------

def _orphan(h, verb, environment_id=ENV_A):
    # A verb agentd asked for before it restarted: still running in agent-exec.
    args = {'sid': sid(environment_id)}
    if verb == 'container.stop':
        args['timeout'] = 60
    t = threading.Thread(target=h.executor.handle, args=({'verb': verb, 'args': args},))
    t.start()
    deadline = time.time() + 2
    while h.backend.active == 0 and time.time() < deadline:
        time.sleep(0.01)
    return t


def test_executor_runs_one_changing_verb_per_sid(h):
    h.register(running=True)
    h.register(ENV_B, uid=10002, port=20010)
    h.backend.delay = 0.5
    t = _orphan(h, 'container.stop')
    busy = h.executor.handle({'verb': 'container.start', 'args': {'sid': sid(ENV_A)}})
    assert busy == {'ok': False, 'error': 'BUSY', 'reason': 'sid busy'}
    assert h.executor.handle({'verb': 'container.inspect', 'args': {'sid': sid(ENV_A)}})['ok']
    assert h.executor.handle({'verb': 'container.start', 'args': {'sid': sid(ENV_B)}})['ok']
    t.join()
    assert h.executor.handle({'verb': 'container.start', 'args': {'sid': sid(ENV_A)}})['ok']


def test_redispatched_step_does_not_overlap_an_orphaned_verb(h):
    h.register()
    h.backend.delay = 0.5
    t = _orphan(h, 'container.start')
    resp = h.agent.handle(h.envelope())
    assert codes(resp) == ('busy', 'BUSY') and resp['observed'] == {'executor': 'sid busy'}
    assert h.backend.calls == [('start', sid(ENV_A))]
    t.join()
    # The environment wasn't left claimed: the retry is admitted and finds the container running.
    resp = h.agent.handle(h.envelope())
    assert codes(resp) == ('done', 'OK') and resp['observed']['container']['running']
    assert h.backend.calls == [('start', sid(ENV_A))]


def test_start_renders_the_run_files_first(h):
    """/run/tenants is tmpfs, empty after a reboot: Start writes the secrets and odoo.conf, then starts."""
    h.register()
    assert codes(h.agent.handle(h.envelope())) == ('done', 'OK')
    s = sid(ENV_A)
    assert h.backend.calls == [('secret', s, 'db_password'), ('secret', s, 'smtp_password'),
                               ('secret', s, 'tenant_salt'), ('secret', s, 'tenant_admin_password'),
                               ('conf', s, 'relay'), ('start', s)]


def test_a_restore_copy_starts_with_smtp_to_the_sink(h):
    from .conftest import START_PARAMS
    h.register()
    assert codes(h.agent.handle(h.envelope(params=dict(START_PARAMS, smtp='sink')))) == ('done', 'OK')
    s = sid(ENV_A)
    assert h.backend.calls == [('secret', s, 'db_password'), ('conf', s, 'sink'), ('start', s)]


def test_a_running_tenant_is_not_rendered_again(h):
    h.register(running=True)
    assert codes(h.agent.handle(h.envelope())) == ('done', 'OK')
    assert h.backend.calls == []


def test_start_applies_a_missing_egress_table_first(h):
    """A firewall load that failed at boot: the tenant's table is applied again before it starts."""
    h.register()
    h.backend.nft_missing.add(sid(ENV_A))
    assert codes(h.agent.handle(h.envelope())) == ('done', 'OK')
    assert h.backend.calls[0] == ('nft', sid(ENV_A), 'production') and h.backend.calls[-1] == ('start', sid(ENV_A))
