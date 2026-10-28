"""Operation state from agent responses, leases, the outbox claim, append-only
tables (DOC-03 §2.5, §6), with a controlled clock."""
import threading
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

from ctlplane import catalog
from ctlplane.store import MAX_RETRIES, Conflict

from .conftest import APP_HOST, DB_HOST, ENV, TENANT


def _at(ts):
    return datetime.fromtimestamp(ts, timezone.utc)


def _one(w):
    op_id = w.start()
    [env] = w.store.claim(APP_HOST, 4)
    return op_id, env


def test_claim_hands_each_event_out_once(w):
    _one(w)
    assert w.store.claim(APP_HOST, 4) == []
    assert w.store.claim(DB_HOST, 4) == []


def test_envelope_is_signed_and_short_lived(w):
    from hostagent.canonical import verify, without
    _, env = _one(w)
    assert verify(without(env, 'dispatch_signature'), env['dispatch_signature'], [w.dispatch.verify_key])
    assert env['tenant_state'] == 'ACTIVE' and env['host_id'] == APP_HOST
    assert (datetime.fromisoformat(env['expires_at']) - datetime.fromisoformat(env['issued_at'])).seconds == 300


def test_concurrent_polls_never_share_an_event(w):
    envs = [str(uuid.uuid4()) for _ in range(20)]
    for e in envs:
        w.sql("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ACTIVE')", (e,))
        w.sql("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'production')", (e, e))
        w.store.dispatch('Tenant.Stop', tenant_id=e, environment_id=e, params={'reason': 'operator'},
                         hosts={'app': APP_HOST}, idempotency_key=e)
    got, errors, lock = [], [], threading.Lock()
    start = threading.Barrier(8)

    def poll():
        start.wait()
        for _ in range(10):
            try:
                batch = w.store.claim(APP_HOST, 20)
            except Exception as e:
                errors.append(e)
                continue
            with lock:
                got.extend(batch)
    threads = [threading.Thread(target=poll) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert sorted(e['environment_id'] for e in got) == sorted(envs)


def test_idempotency_key_and_one_exclusive_operation_per_environment(w):
    a = w.start(key='same')
    assert w.start(key='same') == a
    assert len(w.sql('SELECT * FROM operation_event')) == 1
    with pytest.raises(Conflict):
        w.start(key='other')


def test_heartbeat_extends_the_lease_up_to_deadline_plus_margin(w, clock):
    op_id, env = _one(w)
    deadline = clock.t + 120
    beat = {'heartbeat': 1, 'elapsed_s': 1, 'deadline_at': _at(deadline).isoformat()}
    clock.t += 100
    assert w.store.apply(APP_HOST, w.response(env, 'in_progress', observed=beat)) == 'heartbeat'
    op = w.op(op_id)
    assert op['state'] == 'APPLYING' and op['lease_expires_at'] == _at(clock.t + w.store.liveness)
    w.store.liveness = 1000                        # a beat may not push the lease past deadline + margin
    beat['heartbeat'] = 2
    assert w.store.apply(APP_HOST, w.response(env, 'in_progress', observed=beat)) == 'heartbeat'
    assert w.op(op_id)['lease_expires_at'] == _at(deadline + catalog.margin('app.stop'))


def test_expired_lease_reconciles_and_only_a_result_settles_it(w, clock):
    op_id, env = _one(w)
    clock.t += w.store.liveness - 1
    assert w.store.expire_leases() == []
    clock.t += 2
    assert w.store.expire_leases() == [op_id]
    assert (w.op(op_id)['state'], w.op(op_id)['result_code']) == ('RECONCILING', 'LEASE_EXPIRED')
    beat = {'heartbeat': 1, 'elapsed_s': 1, 'deadline_at': _at(clock.t).isoformat()}
    assert w.store.apply(APP_HOST, w.response(env, 'in_progress', observed=beat)) == 'ignored'
    assert w.store.apply(APP_HOST, w.response(env)) == 'completed'


@pytest.mark.parametrize('code, state', [('TIMEOUT', 'RECONCILING'), ('EXEC_ERROR', 'FAILED'),
                                         ('HEALTH_FAILED', 'FAILED')])
def test_failed_step(w, code, state):
    op_id, env = _one(w)
    assert w.store.apply(APP_HOST, w.response(env, 'failed', code, {'reason': 'x'})) in ('reconciling', 'failed')
    op = w.op(op_id)
    assert (op['state'], op['result_code'], op['result_detail']) == (state, code, {'reason': 'x'})
    assert w.steps(op_id)[0]['state'] == 'failed'
    assert (op['finished_at'] is not None) == (state == 'FAILED')


def test_failed_first_step_never_dispatches_the_next(w):
    op_id = w.expire()
    [env] = w.store.claim(APP_HOST, 1)
    w.store.apply(APP_HOST, w.response(env, 'failed', 'EXEC_ERROR'))
    assert w.store.claim(DB_HOST, 4) == [] and w.steps(op_id)[1]['state'] == 'pending'


def test_busy_is_retried_later_with_the_same_token_then_fails(w, clock):
    op_id, env = _one(w)
    for attempt in range(1, MAX_RETRIES):
        busy = w.response(env, 'busy', 'BUSY', {'executor': 'sid busy'}, at='2026-10-26T00:00:%02d+00:00' % attempt)
        assert w.store.apply(APP_HOST, busy) == 'retry'
        assert w.store.claim(APP_HOST, 4) == []            # not before the backoff
        clock.t += 60
        [again] = w.store.claim(APP_HOST, 4)
        assert again['fencing_token'] == env['fencing_token'] and again['nonce'] != env['nonce']
        env = again
    assert w.store.apply(APP_HOST, w.response(env, 'busy', 'BUSY')) == 'failed'
    assert (w.op(op_id)['state'], w.op(op_id)['result_code']) == ('FAILED', 'BUSY')


def test_rejected_envelope_fails_but_expired_is_resent(w, clock):
    op_id, env = _one(w)
    assert w.store.apply(APP_HOST, w.response(env, 'rejected', 'EXPIRED', {'detail': None})) == 'retry'
    clock.t += 60
    [env] = w.store.claim(APP_HOST, 1)
    assert w.store.apply(APP_HOST, w.response(env, 'rejected', 'REPLAY')) == 'replay'
    assert w.store.apply(APP_HOST, w.response(env, 'rejected', 'NOT_OWNER')) == 'failed'


def test_duplicate_and_stale_responses_change_nothing(w):
    op_id = w.expire()
    [env] = w.store.claim(APP_HOST, 1)
    done = w.response(env, observed={'registry': 'absent'})
    assert w.store.apply(APP_HOST, done) == 'next_step'
    assert w.store.apply(APP_HOST, done) == 'duplicate'
    assert w.store.apply(APP_HOST, w.response(env, at='2026-10-26T00:00:01+00:00')) == 'stale'   # step moved on
    [db_env] = w.store.claim(DB_HOST, 1)
    assert w.store.apply(DB_HOST, w.response(db_env, fencing_token=env['fencing_token'] - 1)) == 'stale'
    assert w.store.apply(DB_HOST, w.response(db_env, evidence_sha256='0' * 64)) == 'bad_evidence'
    assert w.store.apply(DB_HOST, w.response(db_env)) == 'completed'
    assert len(w.sql('SELECT * FROM operation_event')) == 2


def test_host_cannot_misstate_its_own_id(w):
    from .conftest import OTHER_HOST
    _, env = _one(w)
    lie = w.response(env, host=OTHER_HOST, key=w.agent_keys[APP_HOST])
    assert w.store.apply(APP_HOST, lie) == 'wrong_host'


def test_unknown_operation_and_malformed(w):
    _, env = _one(w)
    assert w.store.apply(APP_HOST, w.response(env, op_id=str(uuid.uuid4()))) == 'unknown_op'
    assert w.store.apply(APP_HOST, {'no': 'signature'}) == 'malformed'
    assert w.store.apply(APP_HOST, 'x') == 'malformed'


def test_outbox_and_responses_are_append_only(w):
    _one(w)
    app = w.store.connect()
    for sql in ('UPDATE operation_event SET not_before = now()', 'DELETE FROM agent_response',
                # DOC-03 §2.5 reads the outbox FOR UPDATE SKIP LOCKED: that needs UPDATE.
                'SELECT * FROM operation_event FOR UPDATE SKIP LOCKED'):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(sql)
        app.rollback()
    app.close()
    for sql in ('UPDATE operation_event SET not_before = now()', 'TRUNCATE agent_response'):
        with pytest.raises(psycopg.errors.RaiseException):    # even the owner
            w.sql(sql)


# -- backup points from Tenant.Backup evidence (DOC-03 §7) -------------------------

def _backup(w, clock, seen, lock_days=2):
    bid = str(uuid.uuid4())
    w.store.dispatch('Tenant.Backup', tenant_id=TENANT, environment_id=ENV,
                     params={'backup_id': bid, 'retention_tier': 'daily', 'lock_days': lock_days},
                     hosts={'app': APP_HOST}, idempotency_key=bid)
    [env] = w.store.claim(APP_HOST, 1)
    assert w.store.apply(APP_HOST, w.response(env, observed=seen)) == 'completed'
    return w.sql('SELECT * FROM backup_point WHERE id = %s', (bid,))


def _seen(clock, **over):
    return {'snapshot_time': _at(clock.t - 30).isoformat(), 'gc_guard_held': True, 'referenced_files': 12,
            'missing_files': 0, 'dump_sha256': 'aa' * 32, 'archive_sha256': 'bb' * 32, 'size': 1,
            'object_version_id': 'v1', 'lock_mode': 'COMPLIANCE',
            'lock_until': _at(clock.t + 2 * 86400 + 5).isoformat(), 'image_id': 'sha256:' + 'c' * 64, **over}


def test_backup_evidence_makes_a_recoverable_point(w, clock):
    [p] = _backup(w, clock, _seen(clock))
    assert p['state'] == 'recoverable' and p['snapshot_at'] == _at(clock.t - 30) and p['archive_sha256'] == 'bb' * 32


@pytest.mark.parametrize('over', [dict(missing_files=1), dict(gc_guard_held=False), dict(lock_until=None),
                                  dict(snapshot_time=None)])
def test_incomplete_backup_evidence_is_not_recoverable(w, clock, over):
    [p] = _backup(w, clock, _seen(clock, **over))
    assert p['state'] == 'failed'


def test_lock_shorter_than_planned_is_not_recoverable(w, clock):
    [p] = _backup(w, clock, _seen(clock), lock_days=30)
    assert p['state'] == 'failed'


def test_rerun_that_found_the_archive_records_nothing(w, clock):
    assert _backup(w, clock, {'already_stored': True, 'object_version_id': 'v1',
                              'lock_until': _at(clock.t).isoformat(), 'sha256_b64': 'x'}) == []
