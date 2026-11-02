"""infra/ansible/roles/pgbackrest/files/pgbackrest-scheduled: which backup the daily run takes.
Run with any pytest: `python -m pytest infra/test/test_pgbackrest_scheduled.py`."""
import importlib.machinery
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / 'ansible/roles/pgbackrest/files/pgbackrest-scheduled'
_loader = importlib.machinery.SourceFileLoader('pgbackrest_scheduled', str(SCRIPT))
_spec = importlib.util.spec_from_loader('pgbackrest_scheduled', _loader)
sched = importlib.util.module_from_spec(_spec)
_loader.exec_module(sched)

SUNDAY = datetime(2026, 11, 1, 1, 0, tzinfo=timezone.utc).timestamp()
DAY = 86400


def info(*fulls, db=1, code=0):
    return {'status': {'code': code}, 'db': [{'id': d} for d in range(1, db + 1)],
            'backup': [{'type': 'full', 'error': False, 'database': {'id': g}, 'timestamp': {'stop': t}}
                       for t, g in fulls]}


def test_sunday_is_full():
    assert sched.choose(info((SUNDAY - DAY, 1)), SUNDAY, 6) == 'full'


def test_a_weekday_after_a_recent_full_is_differential():
    assert sched.choose(info((SUNDAY, 1)), SUNDAY + 2 * DAY, 6) == 'diff'


def test_after_missing_sunday_the_next_run_is_full():
    """Codex P2: db-1 down over Sunday and Monday. One timer, one run on start: the overdue full."""
    last_full = SUNDAY - 7 * DAY
    assert sched.choose(info((last_full, 1)), SUNDAY + DAY + 3600, 6) == 'full'


def test_no_full_of_the_current_cluster_is_full():
    """After a stanza-upgrade the old cluster's full doesn't count."""
    assert sched.choose(info((SUNDAY, 1), db=2), SUNDAY + DAY, 6) == 'full'


def test_unreadable_repository_tries_a_full():
    assert sched.choose(None, SUNDAY + DAY, 6) == 'full'
    assert sched.choose(info((SUNDAY, 1), code=1), SUNDAY + DAY, 6) == 'full'
