"""The L2 worker (ctlplane/l2.py) against pgBackRest 2.50's own output, and its metrics."""
import json
import subprocess
from datetime import datetime, timezone

import pytest

from ctlplane import monitoring
from ctlplane.l2 import L2, L2Error, summarize

# Captured from pgBackRest 2.50 (full + diff on a fresh cluster), trimmed to what is read.
INFO = {'archive': [{'database': {'id': 1, 'repo-key': 1}, 'id': '16-1', 'max': '000000010000000000000005',
                     'min': '000000010000000000000001'}],
        'backup': [{'error': False, 'label': '20261028-123318F', 'type': 'full', 'database': {'id': 1, 'repo-key': 1},
                    'timestamp': {'start': 1793190798, 'stop': 1793190803}},
                   {'error': False, 'label': '20261028-123318F_20261028-123324D', 'type': 'diff',
                    'database': {'id': 1, 'repo-key': 1}, 'timestamp': {'start': 1793190804, 'stop': 1793190807}}],
        'db': [{'id': 1, 'repo-key': 1, 'system-id': 7701695801374384370, 'version': '16'}],
        'name': 'main', 'status': {'code': 0, 'message': 'ok'}}
LISTING = {'.': {'type': 'path'},
           '000000010000000000000004-5882e0f0194e22e6898e516135dcc1669e1692aa.gz':
               {'type': 'file', 'size': 16526, 'time': 1793190805},
           '000000010000000000000004.00000028.backup': {'type': 'file', 'size': 371, 'time': 1793190807},
           '000000010000000000000005-37dcddeaf4f56052e51931dbc2bf4b075f91c318.gz':
               {'type': 'file', 'size': 16385, 'time': 1793190808}}


NOON = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc).timestamp()      # inside the expire hours
BACKUPS = {'.': {'type': 'path'}, 'backup.history': {'type': 'path'}, '20261028-123318F': {'type': 'path'},
           '20261028-123318F_20261028-123324D': {'type': 'path'}}


class FakeBackrest:
    """pgBackRest's commands as the worker calls them; repo-ls by path."""

    def __init__(self, info=INFO, listing=LISTING):
        self.info, self.listing = info, listing
        self.backups = dict(BACKUPS)
        self.inside = {}            # label -> repo-ls of backup/main/<label>
        self.calls = []
        self.fail = set()

    def __call__(self, args, **kw):
        command = args[-1] if args[-1] in ('info', 'expire') else 'repo-ls'
        self.calls.append(args[1:])
        if command in self.fail:
            return subprocess.CompletedProcess(args, 56, '', 'ERROR: [056]: unable to reach bucket')
        if command == 'repo-ls':
            path = args[-1]
            if path == 'backup/main':
                out = self.backups
            elif path.startswith('backup/main/'):
                out = self.inside.get(path.split('/')[-1], {})
            else:
                out = self.listing
            return subprocess.CompletedProcess(args, 0, json.dumps(out), '')
        out = {'info': json.dumps([self.info]), 'expire': ''}[command]
        return subprocess.CompletedProcess(args, 0, out, '')


def _l2(w, run):
    """An L2 worker whose db-1 hold is granted (its own tests are below)."""
    l2 = L2(w.store, run=run, clock=w.clock)
    l2.hold = lambda now: (None, now + 900)
    return l2


def _row(w):
    [r] = w.sql('SELECT * FROM l2_status')
    return r


def test_summary_from_pgbackrest_output():
    assert summarize(INFO, LISTING) == {'full_at': 1793190803, 'backup_at': 1793190807, 'wal_at': 1793190808,
                                        'wal_segment': '000000010000000000000005'}


def test_a_failed_backup_counts_for_nothing():
    info = dict(INFO, backup=[dict(INFO['backup'][0]), dict(INFO['backup'][1], error=True)])
    assert summarize(info, LISTING)['backup_at'] == 1793190803


def test_after_a_stanza_upgrade_only_the_new_generation_counts():
    """Fresh backups of the old cluster, WAL of the new one, no backup of it yet: no backup time."""
    info = dict(INFO, db=INFO['db'] + [{'id': 2, 'repo-key': 1, 'system-id': 7701695801374384999, 'version': '17'}],
                archive=INFO['archive'] + [{'database': {'id': 2, 'repo-key': 1}, 'id': '17-2',
                                            'max': '000000010000000000000009', 'min': '000000010000000000000008'}])
    listing = {'000000010000000000000009-' + 'ab' * 20 + '.zst': {'type': 'file', 'time': 1793191000}}
    seen = summarize(info, listing)
    assert (seen['full_at'], seen['backup_at']) == (None, None)
    assert (seen['wal_segment'], seen['wal_at']) == ('000000010000000000000009', 1793191000)


def test_a_stanza_in_error_is_an_error():
    with pytest.raises(L2Error, match='missing stanza path'):
        summarize(dict(INFO, status={'code': 1, 'message': 'missing stanza path'}), None)


def test_run_records_reads_and_expires_once_a_day(w):
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = _l2(w, run)
    l2.run_once()
    r = _row(w)
    assert (r['full_at'].timestamp(), r['backup_at'].timestamp(), r['wal_at'].timestamp()) == \
        (1793190803, 1793190807, 1793190808)
    assert r['wal_segment'] == '000000010000000000000005' and r['error'] is None and r['expired_at']
    # The newest segment's directory, through pgBackRest (same repository, same keys).
    assert ['--stanza=main', 'repo-ls', '--output=json', 'archive/main/16-1/0000000100000000'] in run.calls
    assert sum(c[-1] == 'expire' for c in run.calls) == 1
    w.clock.t += 3600
    l2.run_once()
    assert sum(c[-1] == 'expire' for c in run.calls) == 1             # not again within a day
    w.clock.t += 24 * 3600
    l2.run_once()
    assert sum(c[-1] == 'expire' for c in run.calls) == 2


def test_a_failed_read_keeps_what_was_read_and_says_why(w):
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = _l2(w, run)
    l2.run_once()
    before = _row(w)
    run.fail.add('info')
    w.clock.t += 600
    with pytest.raises(L2Error, match='unable to reach bucket'):
        l2.run_once()
    after = _row(w)
    assert after['checked_at'] == before['checked_at'] and after['wal_at'] == before['wal_at']
    assert 'unable to reach bucket' in after['error']


def test_a_failed_expire_is_retried_and_the_read_still_counts(w):
    w.clock.t = NOON
    run = FakeBackrest()
    run.fail.add('expire')
    l2 = _l2(w, run)
    with pytest.raises(L2Error, match='expire'):
        l2.run_once()
    r = _row(w)
    assert r['expired_at'] is None and r['wal_at'] and 'expire' in r['error']
    run.fail.clear()
    w.clock.t += 120
    l2.run_once()                                                      # due again at once
    assert _row(w)['expired_at'] and _row(w)['error'] is None


def test_metrics_for_a_configured_stanza_never_read_are_zero(w):
    with w.store.connect() as c:
        text = monitoring.metrics(c, w.clock(), l2_stanzas=['main'])
    assert 'ctl_l2_checked_timestamp_seconds{stanza="main"} 0' in text
    assert 'ctl_l2_wal_last_timestamp_seconds{stanza="main"} 0' in text


def test_metrics_are_bounded_by_now(w):
    w.clock.t = 1793190900
    _l2(w, FakeBackrest()).run_once()
    with w.store.connect() as c:
        text = monitoring.metrics(c, w.clock(), l2_stanzas=['main'])
    assert 'ctl_l2_wal_last_timestamp_seconds{stanza="main"} 1793190808' in text
    # A repository time in the future (clock skew) reads as never, so the alerts don't go quiet.
    w.clock.t = 1793190805
    with w.store.connect() as c:
        text = monitoring.metrics(c, w.clock(), l2_stanzas=['main'])
    assert 'ctl_l2_wal_last_timestamp_seconds{stanza="main"} 0' in text


def test_the_key_and_cipher_pass_go_by_environment_only():
    seen = {}

    def run(args, **kw):
        seen.update(args=args, env=kw['env'])
        return subprocess.CompletedProcess(args, 0, json.dumps([INFO]), '')
    L2(None, run=run, key={'key_id': 'K1', 'secret': 'S1'}, cipher_pass='P1')._cmd('--output=json', 'info')
    assert seen['env']['PGBACKREST_REPO1_S3_KEY'] == 'K1' and seen['env']['PGBACKREST_REPO1_S3_KEY_SECRET'] == 'S1'
    assert seen['env']['PGBACKREST_REPO1_CIPHER_PASS'] == 'P1'
    assert not any(v in a for a in seen['args'] for v in ('K1', 'S1', 'P1'))


def _expires(run):
    return sum(c[-1] == 'expire' for c in run.calls)


def test_expire_waits_for_a_backup_in_progress_on_db_1(w):
    """Codex P1: locks are per host. A backup directory not yet in backup.info, written to an hour
    ago, is a backup running on db-1: expire waits (it could drop it), then runs once it's listed."""
    w.clock.t = NOON
    run = FakeBackrest()
    run.backups['20261028-113000F_20261028-110000D'] = {'type': 'path'}
    run.inside['20261028-113000F_20261028-110000D'] = {'backup.manifest.copy': {'type': 'file', 'time': NOON - 3600}}
    l2 = _l2(w, run)
    l2.run_once()
    assert _expires(run) == 0 and _row(w)['expired_at'] is None and _row(w)['error'] is None
    run.info = dict(INFO, backup=INFO['backup'] + [dict(INFO['backup'][1], label='20261028-113000F_20261028-110000D')])
    w.clock.t += 120
    l2.run_once()
    assert _expires(run) == 1


def test_an_abandoned_backup_directory_doesnt_block_expire(w):
    w.clock.t = NOON
    run = FakeBackrest()
    run.backups['20261020-010000F'] = {'type': 'path'}
    run.inside['20261020-010000F'] = {'backup.manifest.copy': {'type': 'file', 'time': NOON - 8 * 86400}}
    _l2(w, run).run_once()
    assert _expires(run) == 1


def test_expire_waits_outside_its_hours(w):
    """db-1's backups start at 01:00 UTC: no expire then."""
    w.clock.t = datetime(2026, 10, 28, 1, 30, tzinfo=timezone.utc).timestamp()
    run = FakeBackrest()
    l2 = _l2(w, run)
    l2.run_once()
    assert _expires(run) == 0 and _row(w)['wal_at']            # still read
    w.clock.t = NOON
    l2.run_once()
    assert _expires(run) == 1


# -- db-1's archiver (Codex: the queue itself, and hosts that never reported) ------------------

def _report(**over):
    return dict({'current_wal': '00000001000000020000003C', 'last_archived_wal': '00000001000000020000003B',
                 'last_archived_at': NOON - 30, 'failed_count': 0, 'last_failed_at': None, 'at': NOON,
                 'pending': 0, 'oldest_pending_age': None}, **over)


def _metrics(w):
    with w.store.connect() as c:
        return monitoring.metrics(c, w.clock())


def test_archiver_up_to_date(w):
    from .conftest import DB_HOST
    w.clock.t = NOON
    w.store.record_archiver(DB_HOST, _report())
    text = _metrics(w)
    assert 'ctl_l2_archive_pending_segments{host_id="%s"} 0' % DB_HOST in text
    assert 'ctl_l2_archive_oldest_pending_seconds{host_id="%s"} 0' % DB_HOST in text
    assert 'ctl_l2_archived_age_seconds{host_id="%s"} 30' % DB_HOST in text


def test_a_small_queue_that_never_drains_shows_its_age(w):
    """Codex: four waiting, the oldest eight minutes old, one archived 30 s ago."""
    from .conftest import DB_HOST
    w.clock.t = NOON
    w.store.record_archiver(DB_HOST, _report(pending=4, oldest_pending_age=480.4))
    text = _metrics(w)
    assert 'ctl_l2_archive_pending_segments{host_id="%s"} 4' % DB_HOST in text
    assert 'ctl_l2_archive_oldest_pending_seconds{host_id="%s"} 480' % DB_HOST in text


def test_a_db_host_that_never_reported_reads_0(w):
    """Codex: no row, no series, no silence alert. Every active db host has a report time."""
    from .conftest import DB_HOST
    text = _metrics(w)
    assert 'ctl_l2_archiver_report_timestamp_seconds{host_id="%s"} 0' % DB_HOST in text
    assert 'ctl_l2_archive_pending_segments{host_id="%s"}' % DB_HOST not in text


def test_a_report_without_the_queue_has_no_queue_series(w):
    from .conftest import DB_HOST
    w.clock.t = NOON
    w.store.record_archiver(DB_HOST, _report(pending=None))
    text = _metrics(w)
    assert 'ctl_l2_archiver_report_timestamp_seconds{host_id="%s"} %d' % (DB_HOST, NOON) in text
    assert 'ctl_l2_archive_pending_segments{host_id="%s"}' % DB_HOST not in text


def test_never_archived_and_app_hosts_are_ignored(w):
    from .conftest import APP_HOST, DB_HOST
    w.clock.t = NOON
    w.store.record_archiver(DB_HOST, _report(last_archived_wal=None, last_archived_at=None))
    w.store.record_archiver(APP_HOST, _report())
    text = _metrics(w)
    assert 'ctl_l2_archived_age_seconds{host_id="%s"} -1' % DB_HOST in text
    assert APP_HOST not in text.split('ctl_l2_archiver_report')[1]


# -- L2.Hold: db-1's backup lock around expire (Codex P1: real exclusion) -----------------------

def _hold_op(w):
    return w.sql("SELECT o.id, o.state, o.params, s.host_id FROM operation o JOIN operation_step s "
                 "ON s.operation_id = o.id WHERE o.type = 'L2.Hold' ORDER BY o.created_at")


def _answer(w, op_id, observed):
    w.sql("UPDATE operation SET state = 'COMPLETED' WHERE id = %s", (op_id,))
    w.sql("UPDATE operation_step SET state = 'done', observed = %s WHERE operation_id = %s",
          (json.dumps(observed), op_id))


def test_expire_runs_only_inside_a_hold_db_1_granted(w):
    from .conftest import DB_HOST
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
    l2.run_once()                                                   # asks db-1, doesn't expire
    [op] = _hold_op(w)
    assert (str(op['host_id']), op['params'], op['state'], _expires(run)) == (DB_HOST, {'seconds': 900}, 'DISPATCHED', 0)
    w.clock.t += 60
    l2.run_once()                                                   # still pending: no second hold
    assert len(_hold_op(w)) == 1 and _expires(run) == 0
    _answer(w, op['id'], {'held': True, 'seconds': 900, 'until': w.clock.t + 890})
    w.clock.t += 5
    timeouts = []
    real = run.__call__

    def spy(args, **kw):
        if args[-1] == 'expire':
            timeouts.append(kw['timeout'])
        return real(args, **kw)
    l2.run = spy
    l2.run_once()
    assert _expires(run) == 1 and timeouts == [300]                # killed before the hold ends


def test_a_hold_refused_while_a_backup_runs_means_no_expire(w):
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
    l2.run_once()
    [op] = _hold_op(w)
    _answer(w, op['id'], {'held': False})
    w.clock.t += 120
    l2.run_once()
    assert _expires(run) == 0 and len(_hold_op(w)) == 1            # not asked again at once
    w.clock.t += 600
    l2.run_once()
    assert len(_hold_op(w)) == 2                                    # asked again later


def test_a_hold_too_close_to_its_end_isnt_used(w):
    """The end is db-1's clock less the skew allowed; expire needs 5 min plus a margin inside it."""
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
    l2.run_once()
    [op] = _hold_op(w)
    _answer(w, op['id'], {'held': True, 'seconds': 900, 'until': w.clock.t + 400})
    w.clock.t += 700
    l2.run_once()
    assert _expires(run) == 0 and len(_hold_op(w)) == 2


def test_no_db_host_no_expire(w):
    w.clock.t = NOON
    w.sql("UPDATE host SET state = 'retired' WHERE role = 'db'")
    run = FakeBackrest()
    L2(w.store, run=run, clock=w.clock).run_once()
    assert _expires(run) == 0 and _hold_op(w) == []


def test_a_slow_read_doesnt_stretch_the_lease(w):
    """Codex: `now` taken before minutes of repository reads. The clock is read again before expire."""
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
    l2.run_once()
    [op] = _hold_op(w)
    _answer(w, op['id'], {'held': True, 'seconds': 900})
    w.clock.t = NOON + 300                                       # 600 s of lease left at the start
    real = run.__call__

    def slow(args, **kw):
        if args[-1] == 'info':
            w.clock.t += 500                                     # a slow bucket
        return real(args, **kw)
    l2.run = slow
    l2.run_once()
    assert _expires(run) == 0                                    # 40 s left when it would start


def test_db_1s_clock_doesnt_set_the_lease(w):
    """Codex: a db clock ahead (accepted within the envelope's life) overstated `until`. Only
    ctl-1's dispatch time and the lease's length count."""
    w.clock.t = NOON
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
    l2.run_once()
    [op] = _hold_op(w)
    _answer(w, op['id'], {'held': True, 'seconds': 900, 'until': NOON + 900 + 300})
    w.clock.t = NOON + 650                                       # 250 s left by ctl-1's clock
    l2.run_once()
    assert _expires(run) == 0
