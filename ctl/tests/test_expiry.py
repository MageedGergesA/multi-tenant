"""The restore-copy expiry sweep (DOC-03 §9.5, DOC-07)."""
import pytest

from ctlplane.expiry import MAX_FAILURES, Expiry

from .conftest import APP_HOST, ENV
from .test_capacity import World, prod  # noqa: F401  (fixture)


@pytest.fixture
def cw(w):
    return World(w)


@pytest.fixture
def x(cw):
    return Expiry(cw.api.admission)


def _copy(cw, prod, fail_at=None):  # noqa: F811
    op = cw.api.request('Tenant.RestoreToIsolated', {'backup_id': prod, 'purpose': 'drill'})
    copy = cw.w.op(op['id'])['params']['target_environment_id']
    cw.run(op['id'], fail_at=fail_at)
    return copy


def _expire_now(w, copy):
    w.sql("UPDATE environment SET expires_at = now() - interval '1 second' WHERE id = %s", (copy,))


def test_expires_at_expires_at_and_frees_the_host(cw, w, x, prod):  # noqa: F811
    copy = _copy(cw, prod)
    assert x.run_once() == {}                                           # 7 days to go
    _expire_now(w, copy)
    assert x.run_once() == {copy: 'DISPATCHED'}
    assert x.run_once() == {copy: 'in_flight'}
    [op] = w.sql("SELECT * FROM operation WHERE type = 'RestoreCopy.Expire'")
    assert op['requested_by'] is None and op['params'] == {'environment_id': copy}
    assert str(op['environment_id']) == ENV
    assert cw.run(op['id'])['state'] == 'COMPLETED'
    assert w.sql('SELECT observed_state FROM environment WHERE id = %s', (copy,))[0]['observed_state'] == 'absent'
    assert {r['state'] for r in cw.reservations(copy)} == {'released'}
    assert x.run_once() == {}
    actors = {r['actor_kind'] for r in w.sql("SELECT actor_kind FROM audit_event WHERE correlation_id = %s",
                                             (op['id'],))}
    assert actors == {'system'}


def test_a_failed_restore_is_expired_at_once(cw, w, x, prod):  # noqa: F811
    copy = _copy(cw, prod, fail_at='app.restore_copy')
    assert x.run_once() == {copy: 'DISPATCHED'}


def test_waits_while_production_is_busy(cw, w, x, prod):  # noqa: F811
    copy = _copy(cw, prod)
    _expire_now(w, copy)
    cw.api.request('Tenant.Stop')                                       # exclusive on production
    assert x.run_once() == {copy: 'production_busy'}
    assert w.sql("SELECT * FROM operation WHERE type = 'RestoreCopy.Expire'") == []


@pytest.mark.parametrize('how', ['failed', 'rejected'])
def test_gives_up_after_repeated_failures_with_one_incident(cw, w, x, prod, how):  # noqa: F811
    copy = _copy(cw, prod)
    _expire_now(w, copy)
    if how == 'rejected':
        w.sql('UPDATE environment SET app_host_id = NULL WHERE id = %s', (ENV,))     # NO_PLACEMENT
    for _ in range(MAX_FAILURES):
        out = x.run_once()[copy]
        if how == 'failed':
            assert out == 'DISPATCHED'
            [op] = w.sql("SELECT id FROM operation WHERE type = 'RestoreCopy.Expire' AND state = 'DISPATCHED'")
            cw.run(op['id'], fail_at='app.expire')
        else:
            assert out == 'rejected:NO_PLACEMENT'
    keys = [r['idempotency_key'] for r in w.sql("SELECT idempotency_key FROM operation "
                                                "WHERE type = 'RestoreCopy.Expire' ORDER BY created_at")]
    assert keys == ['expire:%s:%d' % (copy, n) for n in range(MAX_FAILURES)]
    assert x.run_once() == {copy: 'given_up'}
    assert x.run_once() == {copy: 'given_up'}
    # (The restore reported no checks: its failed-drill incident is RB-04's.)
    [incident] = w.sql("SELECT * FROM incident WHERE runbook_ref = 'DOC-07'")
    assert incident['severity'] == 'sev3' and copy in incident['summary']


def test_production_is_never_expired(cw, w, x, prod):  # noqa: F811
    w.sql("UPDATE environment SET expires_at = now() - interval '1 day' WHERE id = %s", (ENV,))
    assert x.run_once() == {}
