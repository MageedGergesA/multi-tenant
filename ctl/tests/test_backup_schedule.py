"""The daily backup schedule (DOC-05 §2, §3)."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from ctlplane import backup_schedule as bs
from ctlplane.backup_schedule import BackupSchedule

from .conftest import APP_HOST, DB_HOST, ENV, TENANT
from .test_operator_api import Api

UTC = timezone.utc


class Clock:
    def __init__(self, at: datetime):
        self.at = at

    def __call__(self):
        return self.at.timestamp()


class Sched:
    def __init__(self, w):
        self.w = w
        self.api = Api(w)
        self.clock = Clock(datetime(2026, 11, 2, 12, 0, tzinfo=UTC))   # a Monday
        self.api.admission.store.clock = self.clock
        w.store.clock = self.clock                      # the dispatcher too: events are due by this clock
        self.s = BackupSchedule(self.api.admission, max_per_host=2)
        w.sql('UPDATE environment SET app_host_id = %s, db_host_id = %s', (APP_HOST, DB_HOST))

    def at_slot(self, day: datetime, tenant=TENANT, minutes=1):
        """The clock just after `tenant`'s slot in the window opening on `day`."""
        self.clock.at = bs.slot(tenant, day.replace(hour=22, tzinfo=UTC)) + timedelta(minutes=minutes)
        return self.clock.at

    def op(self, env=ENV):
        rows = self.w.sql("SELECT * FROM operation WHERE type = 'Tenant.Backup' AND environment_id = %s "
                          'ORDER BY created_at DESC', (env,))
        return rows[0] if rows else None

    def finish(self, ok=True):
        [e] = self.w.store.claim(APP_HOST, 1)
        p = e['params']
        if not ok:
            return self.w.store.apply(APP_HOST, self.w.response(e, 'failed', 'EXEC_ERROR'))
        snap = self.clock.at
        return self.w.store.apply(APP_HOST, self.w.response(e, observed={
            'snapshot_time': snap.isoformat(), 'gc_guard_held': True, 'referenced_files': 1, 'missing_files': 0,
            'dump_sha256': 'aa' * 32, 'archive_sha256': 'bb' * 32, 'object_version_id': 'v',
            'lock_until': (snap + timedelta(days=p['lock_days'], minutes=5)).isoformat()}))

    def tenant(self, state='ACTIVE', host=APP_HOST):
        t = str(uuid.uuid4())
        self.w.sql('INSERT INTO tenant (id, lifecycle_state) VALUES (%s, %s)', (t, state))
        self.w.sql("INSERT INTO environment (id, tenant_id, kind, app_host_id, db_host_id) "
                   "VALUES (%s, %s, 'production', %s, %s)", (t, t, host, DB_HOST))
        return t


@pytest.fixture
def s(w):
    return Sched(w)


def test_start_minutes_spread_over_the_window():
    offsets = [bs.offset_minutes(uuid.uuid4()) for _ in range(300)]
    assert all(0 <= o < 360 for o in offsets) and len(set(offsets)) > 150
    assert bs.window(datetime(2026, 11, 3, 21, 59, tzinfo=UTC)) == datetime(2026, 11, 2, 22, tzinfo=UTC)
    assert bs.window(datetime(2026, 11, 3, 22, 0, tzinfo=UTC)) == datetime(2026, 11, 3, 22, tzinfo=UTC)
    t = str(uuid.uuid4())
    start = bs.slot(t, datetime(2026, 11, 3, 23, tzinfo=UTC))
    assert datetime(2026, 11, 3, 22, tzinfo=UTC) <= start < datetime(2026, 11, 4, 4, tzinfo=UTC)


def test_one_backup_per_window_from_the_slot(s, w):
    s.at_slot(datetime(2026, 11, 3), minutes=-1)
    assert s.s.run_once() == {ENV: 'not_yet'}
    s.at_slot(datetime(2026, 11, 3))
    assert s.s.run_once() == {ENV: 'DISPATCHED'}
    assert s.s.run_once() == {ENV: 'in_flight'}
    assert s.finish() == 'completed'
    assert s.s.run_once() == {ENV: 'done'}
    s.clock.at += timedelta(hours=10)                   # still the same window (until 22:00)
    assert s.s.run_once() == {ENV: 'done'}
    [p] = w.sql('SELECT trigger, state FROM backup_point')
    assert (p['trigger'], p['state']) == ('scheduled', 'recoverable')
    op = s.op()
    assert op['requested_by'] is None
    actors = {r['actor_kind'] for r in w.sql('SELECT actor_kind FROM audit_event WHERE correlation_id = %s',
                                             (op['id'],))}
    assert actors == {'system'}


def test_a_missed_window_still_runs_later_that_day(s, w):
    s.clock.at = bs.window(datetime(2026, 11, 4, 15, tzinfo=UTC)) + timedelta(hours=17)    # 15:00, ctl-1 was down
    assert s.s.run_once() == {ENV: 'DISPATCHED'}


def _tier_of_next(s, day):
    s.at_slot(day)
    assert s.s.run_once() == {ENV: 'DISPATCHED'}, day
    p = s.op()['params']
    assert s.finish() == 'completed'
    return p['retention_tier'], p['lock_days']


def test_tiers_monthly_then_daily_then_monthly(s, w):
    assert _tier_of_next(s, datetime(2026, 11, 3)) == ('monthly', 93)      # first of the month for this env
    assert _tier_of_next(s, datetime(2026, 11, 4)) == ('daily', 8)          # a Wednesday (or Thursday) slot
    assert _tier_of_next(s, datetime(2026, 12, 1)) == ('monthly', 93)       # a new month


def test_slot_on_sunday_is_weekly(s, w):
    # A tenant whose slot falls after midnight: the window opening Saturday 22:00 runs on Sunday.
    t = next(t for t in (str(uuid.uuid4()) for _ in range(500)) if bs.offset_minutes(t) >= 120)
    w.sql("UPDATE tenant SET lifecycle_state = 'DRAFT' WHERE id = %s", (TENANT,))     # only `t` this time
    w.sql("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ACTIVE')", (t,))
    w.sql("INSERT INTO environment (id, tenant_id, kind, app_host_id, db_host_id) VALUES (%s, %s, 'production', %s, %s)",
          (t, t, APP_HOST, DB_HOST))
    s.at_slot(datetime(2026, 11, 3), tenant=t)            # this month's monthly, out of the way
    assert s.s.run_once() == {t: 'DISPATCHED'}
    assert s.op(t)['params']['retention_tier'] == 'monthly'
    s.finish()
    s.at_slot(datetime(2026, 11, 7), tenant=t)            # Saturday's window, Sunday's slot
    assert s.clock.at.weekday() == 6
    assert s.s.run_once() == {t: 'DISPATCHED'}
    assert s.op(t)['params'] == {'backup_id': str(s.op(t)['id']), 'retention_tier': 'weekly', 'lock_days': 29}


def test_failed_monthly_passes_the_tier_on(s, w):
    s.at_slot(datetime(2026, 11, 3))
    s.s.run_once()
    s.finish(ok=False)
    assert _tier_of_next(s, datetime(2026, 11, 4))[0] == 'monthly'


def test_unrecoverable_monthly_passes_the_tier_on(s, w):
    # It completed, but its evidence makes the point `failed` (a missing file): not this month's monthly.
    s.at_slot(datetime(2026, 11, 3))
    s.s.run_once()
    [e] = w.store.claim(APP_HOST, 1)
    w.store.apply(APP_HOST, w.response(e, observed={'snapshot_time': s.clock.at.isoformat(), 'gc_guard_held': True,
                                                    'missing_files': 1, 'archive_sha256': 'bb' * 32}))
    assert w.sql('SELECT retention_tier, state FROM backup_point')[0] == {'retention_tier': 'monthly',
                                                                         'state': 'failed'}
    assert _tier_of_next(s, datetime(2026, 11, 4))[0] == 'monthly'


def test_retries_within_the_window_then_gives_up(s, w):
    s.at_slot(datetime(2026, 11, 3))
    for n in range(bs.MAX_ATTEMPTS):
        assert s.s.run_once() == {ENV: 'DISPATCHED'}
        s.finish(ok=False)
    assert s.s.run_once() == {ENV: 'gave_up'}
    keys = [r['idempotency_key'] for r in w.sql("SELECT idempotency_key FROM operation WHERE type = 'Tenant.Backup' "
                                                'ORDER BY created_at')]
    assert keys == ['scheduled-backup:%s:2026-11-03:%d' % (ENV, n) for n in range(bs.MAX_ATTEMPTS)]
    s.at_slot(datetime(2026, 11, 4))
    assert s.s.run_once() == {ENV: 'DISPATCHED'}                           # a new window starts afresh


def test_waits_for_an_exclusive_operation_and_the_host_limit(s, w):
    s.at_slot(datetime(2026, 11, 3))
    s.api.request('Tenant.Stop')                                           # exclusive on ENV
    assert s.s.run_once() == {ENV: 'environment_busy'}
    assert s.op() is None
    w.sql("UPDATE operation SET state = 'COMPLETED' WHERE type = 'Tenant.Stop'")
    others = [s.tenant() for _ in range(3)]
    s.clock.at = bs.window(s.clock.at) + timedelta(hours=7)                # past every slot
    out = s.s.run_once()
    assert sorted(out.values()) == ['DISPATCHED', 'DISPATCHED', 'host_busy', 'host_busy']
    assert set(out) == {ENV, *others}


@pytest.mark.parametrize('state, scheduled', [('VALIDATING', True), ('SUSPENDED', True), ('DRAFT', False),
                                              ('ERROR', False), ('DELETED', False)])
def test_which_tenants(s, w, state, scheduled):
    w.sql('UPDATE tenant SET lifecycle_state = %s', (state,))
    s.at_slot(datetime(2026, 11, 3))
    assert (ENV in s.s.run_once()) == scheduled


def test_a_scheduled_backup_feeds_the_alert_metric(s, w):
    from ctlplane.monitoring import backup_ages
    s.at_slot(datetime(2026, 11, 3))
    s.s.run_once()
    s.finish()
    with w.store.connect() as c:
        [row] = backup_ages(c)
    assert int(row['ts']) == int(s.clock.at.timestamp())
