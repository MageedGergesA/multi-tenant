"""RECONCILING read-back and decisions (DOC-03 §6), with a controlled clock and
hand-signed agent answers."""
import pytest

from ctlplane.reconciler import Reconciler, decide

from .conftest import APP_HOST, DB_HOST


@pytest.fixture
def r(w):
    return Reconciler(w.store)


def _lapse(w, clock):
    clock.t += w.store.liveness + 1
    return w.store.expire_leases()


def _row(env, status='done', code='OK', step=None, token=None):
    return {'op_id': env['op_id'], 'op_type': env['op_type'], 'step': step or env['step'],
            'environment_id': env['environment_id'],
            'fencing_token': env['fencing_token'] if token is None else token,
            'status': status, 'code': code, 'started_at': 1.0, 'finished_at': 2.0, 'evidence_sha256': 'ab' * 32}


def _answer(w, host, journal):
    """The host picks up its probe and answers with `journal`."""
    [probe] = w.store.claim(host, 4)
    assert probe['op_type'] == 'Agent.Query' and probe['step'] == 'any.query'
    assert w.store.apply(host, w.response(probe, observed={'journal': journal})) == 'completed'
    return probe


def _lost(w):
    """Dispatched and handed out; nothing ever comes back."""
    op_id = w.start()
    [env] = w.store.claim(APP_HOST, 4)
    return op_id, env


def test_probe_goes_to_the_steps_host_once(w, clock, r):
    op_id, env = _lost(w)
    assert _lapse(w, clock) == [op_id]
    assert r.run_once() == {op_id: 'probing'}
    assert r.run_once() == {op_id: 'probing'}          # no second probe while one is out
    [probe] = w.store.claim(APP_HOST, 4)
    assert probe['params'] == {'op_id': op_id} and w.store.claim(DB_HOST, 4) == []


def test_done_at_the_agent_completes(w, clock, r):
    op_id, env = _lost(w)
    _lapse(w, clock)
    r.run_once()
    _answer(w, APP_HOST, [_row(env)])
    assert r.run_once() == {op_id: 'completed'}
    op = w.op(op_id)
    assert (op['state'], op['result_code'], op['reconciling_since']) == ('COMPLETED', 'OK', None)
    assert w.steps(op_id)[0]['evidence_sha256'] == 'ab' * 32


def test_still_running_goes_back_to_applying_with_the_same_token(w, clock, r):
    op_id, env = _lost(w)
    _lapse(w, clock)
    r.run_once()
    _answer(w, APP_HOST, [_row(env, 'in_progress', None)])
    assert r.run_once() == {op_id: 'applying'}
    op = w.op(op_id)
    assert op['state'] == 'APPLYING' and op['fencing_token'] == env['fencing_token']
    assert w.store.apply(APP_HOST, w.response(env)) == 'completed'      # its result still counts


@pytest.mark.parametrize('journal', ['none', 'busy', 'timeout', 'old_token'])
def test_not_run_or_cut_short_is_redispatched_with_a_new_token(w, clock, r, journal):
    op_id, env = _lost(w)
    rows = {'busy': [_row(env, 'busy', 'BUSY')], 'timeout': [_row(env, 'failed', 'TIMEOUT')],
            'old_token': [_row(env, token=env['fencing_token'] - 1)]}.get(journal, [])
    _lapse(w, clock)
    r.run_once()
    _answer(w, APP_HOST, rows)
    assert r.run_once() == {op_id: 'resume'}
    op = w.op(op_id)
    assert op['state'] == 'DISPATCHED' and op['attempt'] == 2 and op['fencing_token'] > env['fencing_token']
    [again] = w.store.claim(APP_HOST, 4)
    assert (again['step'], again['fencing_token']) == ('app.stop', op['fencing_token'])
    assert w.store.apply(APP_HOST, w.response(env, at='late')) == 'stale'     # the old token is dead
    assert w.store.apply(APP_HOST, w.response(again)) == 'completed'


def test_known_failure_fails(w, clock, r):
    op_id, env = _lost(w)
    _lapse(w, clock)
    r.run_once()
    _answer(w, APP_HOST, [_row(env, 'failed', 'HEALTH_FAILED')])
    assert r.run_once() == {op_id: 'failed'}
    assert (w.op(op_id)['state'], w.op(op_id)['result_code']) == ('FAILED', 'HEALTH_FAILED')


def test_partial_two_host_operation_resumes_at_the_next_host(w, clock, r):
    op_id = w.expire()
    [app_env] = w.store.claim(APP_HOST, 1)
    _lapse(w, clock)                                   # app.expire ran, its response was lost
    r.run_once()
    _answer(w, APP_HOST, [_row(app_env)])
    assert w.store.claim(DB_HOST, 4) == []             # only hosts with an unknown step are asked
    assert r.run_once() == {op_id: 'resume'}
    assert [s['state'] for s in w.steps(op_id)] == ['done', 'dispatched']
    [db_env] = w.store.claim(DB_HOST, 4)
    assert db_env['step'] == 'db.expire' and db_env['fencing_token'] > app_env['fencing_token']
    assert w.store.apply(DB_HOST, w.response(db_env)) == 'completed'


def test_timeout_response_is_reconciled(w, clock, r):
    op_id, env = _lost(w)
    w.store.apply(APP_HOST, w.response(env, 'failed', 'TIMEOUT', {'cancelled': True}))
    assert w.op(op_id)['state'] == 'RECONCILING'
    r.run_once()
    _answer(w, APP_HOST, [_row(env, 'failed', 'TIMEOUT')])
    assert r.run_once() == {op_id: 'resume'}


def test_a_step_that_keeps_timing_out_stops_with_an_incident(w, clock, r):
    op_id, env = _lost(w)
    for attempt in range(1, 4):
        w.store.apply(APP_HOST, w.response(env, 'failed', 'TIMEOUT', at=str(attempt)))
        r.run_once()
        _answer(w, APP_HOST, [_row(env, 'failed', 'TIMEOUT')])
        verdict = r.run_once()[op_id]
        if attempt < 3:
            assert verdict == 'resume'
            [env] = w.store.claim(APP_HOST, 4)
    assert verdict == 'limit'
    assert (w.op(op_id)['state'], w.op(op_id)['result_code']) == ('FAILED', 'RECONCILE_LIMIT')
    [incident] = w.sql('SELECT * FROM incident')
    assert incident['severity'] == 'sev3' and str(incident['operation_id']) == op_id


def test_unanswered_probe_is_resent_then_fails_after_30_minutes(w, clock, r):
    op_id, env = _lost(w)
    _lapse(w, clock)
    r.run_once()
    w.store.claim(APP_HOST, 4)                          # the probe is lost as well
    _lapse(w, clock)
    probes = w.sql("SELECT state, result_code FROM operation WHERE type = 'Agent.Query'")
    assert probes == [{'state': 'FAILED', 'result_code': 'LEASE_EXPIRED'}]   # not reconciled itself
    assert r.run_once() == {op_id: 'probing'}
    assert len(w.store.claim(APP_HOST, 4)) == 1         # a fresh probe
    clock.t += 1800
    assert r.run_once() == {op_id: 'unreachable'}
    assert (w.op(op_id)['state'], w.op(op_id)['result_code']) == ('FAILED', 'UNREACHABLE')
    [incident] = w.sql('SELECT * FROM incident')
    assert incident['severity'] == 'sev2' and incident['scope_tenant_ids'] == [w.op(op_id)['tenant_id']]


def test_probe_answer_from_an_earlier_episode_is_not_used(w, clock, r):
    op_id, env = _lost(w)
    _lapse(w, clock)
    r.run_once()
    _answer(w, APP_HOST, [])
    r.run_once()                                        # resumed with a new token
    [env] = w.store.claim(APP_HOST, 4)
    _lapse(w, clock)                                    # lost again: a new episode
    assert r.run_once() == {op_id: 'probing'}


def test_decide_is_ordered():
    steps = [{'seq': 0, 'name': 'app.expire', 'host_id': 'a', 'state': 'dispatched'},
             {'seq': 1, 'name': 'db.expire', 'host_id': 'b', 'state': 'pending'}]
    row = {'step': 'app.expire', 'fencing_token': 7, 'status': 'done'}
    assert decide(steps, 7, {'a': [row]})[:2] == ('resume', 1)
    assert decide(steps, 8, {'a': [row]})[:2] == ('resume', 0)
    assert decide(steps, 7, {'a': [row, dict(row, status='in_progress')]})[:2] == ('applying', 0)


def test_probe_that_times_out_fails_and_is_resent(w, clock, r):
    op_id, env = _lost(w)
    _lapse(w, clock)
    r.run_once()
    [probe] = w.store.claim(APP_HOST, 4)
    assert w.store.apply(APP_HOST, w.response(probe, 'failed', 'TIMEOUT')) == 'failed'
    assert w.op(probe['op_id'])['state'] == 'FAILED'
    assert r.run_once() == {op_id: 'probing'} and len(w.store.claim(APP_HOST, 4)) == 1
