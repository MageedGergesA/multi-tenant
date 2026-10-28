"""The L2 worker (ctlplane/l2.py) against pgBackRest 2.50's own output, and its metrics."""
import json
import subprocess

import pytest

from ctlplane import monitoring
from ctlplane.l2 import L2, L2Error, summarize

# Captured from pgBackRest 2.50 (full + diff on a fresh cluster), trimmed to what is read.
INFO = {'archive': [{'database': {'id': 1, 'repo-key': 1}, 'id': '16-1', 'max': '000000010000000000000005',
                     'min': '000000010000000000000001'}],
        'backup': [{'error': False, 'label': '20261028-123318F', 'type': 'full',
                    'timestamp': {'start': 1793190798, 'stop': 1793190803}},
                   {'error': False, 'label': '20261028-123318F_20261028-123324D', 'type': 'diff',
                    'timestamp': {'start': 1793190804, 'stop': 1793190807}}],
        'name': 'main', 'status': {'code': 0, 'message': 'ok'}}
LISTING = {'.': {'type': 'path'},
           '000000010000000000000004-5882e0f0194e22e6898e516135dcc1669e1692aa.gz':
               {'type': 'file', 'size': 16526, 'time': 1793190805},
           '000000010000000000000004.00000028.backup': {'type': 'file', 'size': 371, 'time': 1793190807},
           '000000010000000000000005-37dcddeaf4f56052e51931dbc2bf4b075f91c318.gz':
               {'type': 'file', 'size': 16385, 'time': 1793190808}}


class FakeBackrest:
    def __init__(self, info=INFO, listing=LISTING):
        self.info, self.listing = info, listing
        self.calls = []
        self.fail = set()

    def __call__(self, args, **kw):
        command = args[-1] if args[-1] in ('info', 'expire') else 'repo-ls'
        self.calls.append(args[1:])
        if command in self.fail:
            return subprocess.CompletedProcess(args, 56, '', 'ERROR: [056]: unable to reach bucket')
        out = {'info': json.dumps([self.info]), 'repo-ls': json.dumps(self.listing), 'expire': ''}[command]
        return subprocess.CompletedProcess(args, 0, out, '')


def _row(w):
    [r] = w.sql('SELECT * FROM l2_status')
    return r


def test_summary_from_pgbackrest_output():
    assert summarize(INFO, LISTING) == {'full_at': 1793190803, 'backup_at': 1793190807, 'wal_at': 1793190808,
                                        'wal_segment': '000000010000000000000005'}


def test_a_failed_backup_counts_for_nothing():
    info = dict(INFO, backup=[dict(INFO['backup'][0]), dict(INFO['backup'][1], error=True)])
    assert summarize(info, LISTING)['backup_at'] == 1793190803


def test_a_stanza_in_error_is_an_error():
    with pytest.raises(L2Error, match='missing stanza path'):
        summarize(dict(INFO, status={'code': 1, 'message': 'missing stanza path'}), None)


def test_run_records_reads_and_expires_once_a_day(w):
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
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
    run = FakeBackrest()
    l2 = L2(w.store, run=run, clock=w.clock)
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
    run = FakeBackrest()
    run.fail.add('expire')
    l2 = L2(w.store, run=run, clock=w.clock)
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
    L2(w.store, run=FakeBackrest(), clock=w.clock).run_once()
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
