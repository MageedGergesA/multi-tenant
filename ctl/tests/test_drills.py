"""L1 restore drills (DOC-05 §5): selection, restore attempts, the DRILL_VERIFIED
mark, immediate expiry, and failures (RB-04)."""
import random
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from ctlplane import capacity, drills
from ctlplane.drills import Drills
from ctlplane.expiry import Expiry

from .conftest import APP_HOST, DB_HOST, ENV, TENANT
from .test_capacity import World, prod  # noqa: F401  (fixture)

UTC = timezone.utc
CHECKS = {'signature': True, 'tenant': True, 'environment': True, 'backup_id': True, 'login': True,
          'modules_match': True, 'files_verified': True, 'zero_egress': 'not_measured'}


class Clock:
    def __init__(self, at):
        self.at = at

    def __call__(self):
        return self.at.timestamp()


class D:
    def __init__(self, w, cw):
        self.w = w
        self.cw = cw
        self.clock = Clock(datetime(2026, 11, 3, 7, 0, tzinfo=UTC))       # a Tuesday, in the window
        self.cw.api.admission.store.clock = self.clock
        w.store.clock = self.clock
        self.d = Drills(self.cw.api.admission, rng=random.Random(7))

    def tier(self, backup, tier):
        self.w.sql('UPDATE backup_point SET retention_tier = %s WHERE id = %s', (tier, backup))

    def other(self):
        """A second tenant's production, placed beside the first, with a backup."""
        t = str(uuid.uuid4())
        self.w.sql("INSERT INTO tenant (id, lifecycle_state, release_cell_id, resource_bundle_id) "
                   "VALUES (%s, 'ACTIVE', %s, %s)", (t, self.cw.rel.cell, self.cw.bundle))
        self.w.sql("INSERT INTO environment (id, tenant_id, kind, resource_bundle_id, app_host_id, db_host_id, "
                   "image_release_id) VALUES (%s, %s, 'production', %s, %s, %s, (SELECT id FROM image_release))",
                   (t, t, self.cw.bundle, APP_HOST, DB_HOST))
        with self.w.store.connect() as c:
            from ctlplane import vault
            vault.provision(c, t, t, self.w.vault.recipient, datetime.now(UTC))
            host = c.execute('SELECT * FROM host WHERE id = %s', (APP_HOST,)).fetchone()
            bundle = c.execute('SELECT * FROM resource_bundle WHERE id = %s', (self.cw.bundle,)).fetchone()
            capacity.allocate_slot(c, t, host, bundle, self.clock())
        op = self.w.sql('SELECT operation_id FROM backup_point LIMIT 1')[0]['operation_id']
        b = str(uuid.uuid4())
        self.w.sql("INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, "
                   "gc_guard_held, missing_files, state, created_at) VALUES (%s, %s, %s, 'scheduled', 'daily', "
                   "now() - interval '1 hour', true, 0, 'recoverable', now())", (b, t, op))
        return t, b

    def finish(self, op_id, checks=None, fail=False):
        """Answer each step; the restore step reports `checks` (default: all
        passing, the deep ones too for a deep drill)."""
        if checks is None:
            deep = self.w.op(op_id)['params'].get('deep')
            checks = dict(CHECKS, row_counts_match=True, pdf_printed=True) if deep else CHECKS
        while True:
            [step] = self.w.sql("SELECT * FROM operation_step WHERE operation_id = %s AND state = 'dispatched'",
                                (op_id,)) or [None]
            if step is None:
                return self.w.op(op_id)
            [env] = self.w.store.claim(str(step['host_id']), 8)
            if step['name'] == 'app.restore_copy':
                observed = {'checks': checks, 'duration_s': 42.0}
                resp = self.w.response(env, 'failed', 'EXEC_ERROR', observed) if fail else \
                    self.w.response(env, observed=observed)
            else:
                resp = self.w.response(env)
            self.w.store.apply(env['host_id'], resp)

    def drilled(self):
        """Finish the latest drill, then expire its copy as the sweep would."""
        self.finish(self.drill_ops()[-1]['id'])
        Expiry(self.cw.api.admission).run_once()
        for op in self.w.sql("SELECT id FROM operation WHERE type = 'RestoreCopy.Expire' AND state = 'DISPATCHED'"):
            assert self.finish(op['id'])['state'] == 'COMPLETED'

    def attempts(self):
        return self.w.sql('SELECT * FROM restore_attempt ORDER BY created_at, id')

    def drill_ops(self):
        return self.w.sql("SELECT * FROM operation WHERE type = 'Tenant.RestoreToIsolated' "
                          'ORDER BY created_at, idempotency_key')


@pytest.fixture
def cw(w):
    return World(w)


@pytest.fixture
def d(w, cw, prod):  # noqa: F811
    x = D(w, cw)
    x.prod = prod
    x.tier(prod, 'daily')
    return x


def test_only_in_the_morning_window(d):
    for hour in (5, 10, 22):
        d.clock.at = d.clock.at.replace(hour=hour)
        assert d.d.run_once() == {'state': 'outside_window'}
    assert d.drill_ops() == []


def test_a_passing_drill_is_recorded_marked_and_expired_at_once(d, w):
    out = d.d.run_once()
    assert out == {'state': 'DISPATCHED', 'kind': 'oldest', 'environment_id': ENV, 'backup_id': d.prod,
                   'result_code': None}
    assert d.d.run_once() == {'state': 'in_flight'}
    [op] = d.drill_ops()
    assert op['requested_by'] is None and op['params']['purpose'] == 'drill'
    assert op['idempotency_key'] == 'drill:2026-11-03:oldest:0'
    d.clock.at += timedelta(minutes=20)
    assert d.finish(op['id'])['state'] == 'COMPLETED'
    [a] = d.attempts()
    copy = op['params']['target_environment_id']
    assert (a['result'], a['purpose'], a['drill_kind'], str(a['backup_point_id']), str(a['target_environment_id']),
            a['measured_rto_seconds'], a['checks']) == ('pass', 'drill', 'oldest', d.prod, copy, 1200, CHECKS)
    assert a['evidence_sha256']
    assert w.sql('SELECT drill_verified_at FROM backup_point WHERE id = %s', (d.prod,))[0]['drill_verified_at'] \
        == d.clock.at
    assert w.sql('SELECT expires_at FROM environment WHERE id = %s', (copy,))[0]['expires_at'] == d.clock.at
    assert Expiry(d.cw.api.admission).run_once() == {copy: 'DISPATCHED'}
    assert w.sql('SELECT * FROM incident') == []
    assert {r['action'] for r in w.sql('SELECT action FROM audit_event WHERE correlation_id = %s', (op['id'],))} \
        >= {'restore.drill_passed'}


def test_restore_attempts_are_append_only(d, w):
    d.d.run_once()
    d.finish(d.drill_ops()[0]['id'])
    with pytest.raises(psycopg.errors.RaiseException, match='append-only'):
        w.sql("UPDATE restore_attempt SET result = 'fail'")


@pytest.mark.parametrize('checks', [
    {**CHECKS, 'modules_match': False},
    {k: v for k, v in CHECKS.items() if k != 'login'},
    {**CHECKS, 'login': 'not_measured'},             # only egress may be unmeasured (dry-run nftables)
    {**CHECKS, 'tenant': 1},
    'nope',
])
def test_ctl_checks_what_the_agent_reports(d, w, checks):
    d.d.run_once()
    assert d.finish(d.drill_ops()[0]['id'], checks=checks)['state'] == 'COMPLETED'
    assert d.attempts()[0]['result'] == 'fail'
    assert w.sql('SELECT drill_verified_at FROM backup_point WHERE id = %s', (d.prod,))[0]['drill_verified_at'] is None
    assert len(w.sql("SELECT * FROM incident WHERE runbook_ref = 'RB-04'")) == 1


def test_failure_redrill_then_manual_investigation(d, w):
    d.d.run_once()
    d.finish(d.drill_ops()[0]['id'], fail=True)
    [a] = d.attempts()
    assert (a['result'], a['result_code'], a['checks']) == ('fail', 'EXEC_ERROR', CHECKS)
    [i] = w.sql('SELECT * FROM incident')
    assert (i['severity'], i['runbook_ref'], i['scope_tenant_ids']) == ('sev2', 'RB-04', [uuid.UUID(TENANT)])
    assert i['summary'].startswith('restore drill failed')
    # Re-drilled within the day, outside the daily quota (already used by the failed drill).
    assert d.d.run_once()['kind'] == 'redrill'
    d.finish(d.drill_ops()[-1]['id'], fail=True)
    assert sum('manual investigation' in r['summary'] for r in w.sql('SELECT summary FROM incident')) == 1
    assert d.d.run_once() == {'state': 'nothing_due'}           # out of the rotation
    d.clock.at += timedelta(days=1)
    assert d.d.run_once() == {'state': 'nothing_due'}
    # An operator's drill that passes puts it back.
    # (Its key looks like the scheduler's; it's still an operator's.)
    op = d.cw.api.request('Tenant.RestoreToIsolated', {'backup_id': d.prod, 'purpose': 'drill'},
                          key='drill:2026-11-04:oldest:9')
    d.finish(op['id'])
    assert d.attempts()[-1]['drill_kind'] == 'manual' and d.attempts()[-1]['result'] == 'pass'
    assert d.d.run_once()['kind'] == 'oldest'


def test_oldest_first_quota_and_weekly_random(d, w, monkeypatch):
    other, other_backup = d.other()
    first = min(ENV, other)
    out = d.d.run_once()
    assert (out['kind'], out['environment_id']) == ('oldest', first)              # never drilled; then by id
    d.drilled()
    # per_day 1: the other waits for tomorrow; the weekly random drill goes now.
    out = d.d.run_once()
    assert out['kind'] == 'weekly_random' and out['backup_id'] in (d.prod, other_backup)
    d.drilled()
    assert d.d.run_once() == {'state': 'nothing_due'}
    d.clock.at += timedelta(days=1)
    out = d.d.run_once()
    assert out['kind'] == 'oldest'
    never = {ENV, other} - {str(a['source_environment_id']) for a in d.attempts()}
    assert out['environment_id'] == (never.pop() if never else first)
    d.drilled()
    assert d.d.run_once() == {'state': 'nothing_due'}                             # weekly done this week
    # Enough a day that every environment comes round within CYCLE_DAYS.
    monkeypatch.setattr(drills, 'CYCLE_DAYS', 1)
    d.clock.at += timedelta(days=1)
    assert d.d.run_once()['kind'] == 'oldest'
    d.drilled()
    assert d.d.run_once()['kind'] == 'oldest'
    d.drilled()
    assert d.d.run_once() == {'state': 'nothing_due'}
    # A new week: another random drill.
    d.clock.at = datetime(2026, 11, 9, 8, tzinfo=UTC)
    for _ in range(2):
        assert d.d.run_once()['kind'] == 'oldest'
        d.drilled()
    assert d.d.run_once()['kind'] == 'weekly_random'


def test_weekly_random_picks_a_tier_then_a_backup(d, w):
    weekly, monthly = d.cw.api.backup(), d.cw.api.backup()
    d.tier(weekly, 'weekly')
    d.tier(monthly, 'monthly')
    d.cw.api.backup()                                         # 'final': not a drill tier
    seen = set()
    for seed in range(30):
        envs = [{'id': ENV, 'tenant_id': TENANT, 'streak': 0}]
        with w.store.connect() as c:
            kind, _, backup = Drills(d.cw.api.admission, rng=random.Random(seed))._pick(c, envs, ['oldest'], 1, False)
        assert kind == 'weekly_random'
        seen.add(str(backup))
    assert seen == {d.prod, weekly, monthly}


def test_skips_a_busy_environment_and_other_states(d, w):
    d.cw.api.request('Tenant.Stop')                             # exclusive on production
    assert d.d.run_once() == {'state': 'nothing_due'}
    w.sql("UPDATE operation SET state = 'COMPLETED' WHERE type = 'Tenant.Stop'")
    for state in ('VALIDATING', 'ERROR', 'DELETED'):
        w.sql('UPDATE tenant SET lifecycle_state = %s', (state,))
        assert d.d.run_once() == {'state': 'nothing_due'}, state
    w.sql("UPDATE tenant SET lifecycle_state = 'ACTIVE'")
    w.sql("UPDATE backup_point SET state = 'failed'")
    assert d.d.run_once() == {'state': 'nothing_due'}          # nothing recoverable to drill


def test_refused_requests_retry_then_give_up(d, w):
    w.sql('UPDATE environment SET app_host_id = NULL WHERE id = %s', (ENV,))       # NO_PLACEMENT
    for n in range(drills.MAX_REJECTED):
        out = d.d.run_once()
        assert (out['state'], out['result_code']) == ('REJECTED', 'NO_PLACEMENT')
    assert d.d.run_once() == {'state': 'gave_up'}
    assert [o['idempotency_key'] for o in d.drill_ops()] == \
        ['drill:2026-11-03:oldest:%d' % n for n in range(drills.MAX_REJECTED)]
    assert d.attempts() == []


def test_other_restores_are_recorded_without_drill_effects(d, w):
    op = d.cw.api.request('Tenant.RestoreToIsolated', {'backup_id': d.prod, 'purpose': 'restore_to_stage'})
    copy = op['params']['target_environment_id'] if 'params' in op else d.w.op(op['id'])['params'][
        'target_environment_id']
    before = w.sql('SELECT expires_at FROM environment WHERE id = %s', (copy,))[0]['expires_at']
    d.finish(op['id'])
    [a] = d.attempts()
    assert (a['purpose'], a['drill_kind'], a['result']) == ('restore_to_stage', None, 'pass')
    assert w.sql('SELECT expires_at FROM environment WHERE id = %s', (copy,))[0]['expires_at'] == before
    assert w.sql('SELECT drill_verified_at FROM backup_point WHERE id = %s', (d.prod,))[0]['drill_verified_at'] is None
    # It isn't a drill: the environment is still due one.
    assert d.d.run_once()['kind'] == 'oldest'


def test_a_refused_weekly_drill_is_still_due(d, w):
    d.d.run_once()
    d.drilled()
    w.sql('UPDATE environment SET app_host_id = NULL WHERE id = %s', (ENV,))       # NO_PLACEMENT
    out = d.d.run_once()
    assert (out['kind'], out['state']) == ('weekly_random', 'REJECTED')
    w.sql('UPDATE environment SET app_host_id = %s WHERE id = %s', (APP_HOST, ENV))
    out = d.d.run_once()
    assert (out['kind'], out['state']) == ('weekly_random', 'DISPATCHED')


def test_the_weekly_random_drill_is_deep(d, w):
    d.d.run_once()
    assert d.drill_ops()[-1]['params']['deep'] is False                  # the daily one
    d.drilled()
    d.clock.at += timedelta(minutes=1)          # its attempt and the next must not tie on created_at
    assert d.d.run_once()['kind'] == 'weekly_random'
    op = d.drill_ops()[-1]
    assert op['params']['deep'] is True
    d.finish(op['id'], checks=CHECKS)                                   # the plain checks only: not enough
    assert d.attempts()[-1]['result'] == 'fail'
    d.clock.at += timedelta(minutes=1)
    op = d.cw.api.request('Tenant.RestoreToIsolated', {'backup_id': d.prod, 'purpose': 'drill', 'deep': True})
    d.finish(op['id'], checks={**CHECKS, 'row_counts_match': True, 'pdf_printed': True})
    assert d.attempts()[-1]['result'] == 'pass'
    d.clock.at += timedelta(minutes=1)
    op = d.cw.api.request('Tenant.RestoreToIsolated', {'backup_id': d.prod, 'purpose': 'drill', 'deep': True})
    d.finish(op['id'], checks={**CHECKS, 'row_counts_match': True, 'pdf_printed': 'not_measured'})
    assert d.attempts()[-1]['result'] == 'fail'
