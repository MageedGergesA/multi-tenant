"""L2.Hold on db-1 (DOC-05 §3.1): the backup lock pgbackrest-scheduled takes, held for ctl-1's
expire. pgBackRest's own locks are per host; this one keeps backup and expire apart."""
import fcntl
import os
import time

import pytest

from hostagent.pg_backend import DbHostConfig, PgBackend


def _backend(tmp_path):
    return PgBackend(DbHostConfig(dsn='', hba_dir=tmp_path, l2_lock=tmp_path / 'backup.lock'))


def _free(path) -> bool:
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


def _lease(tmp_path) -> float:
    return float((tmp_path / 'backup.lock.hold').read_text())


def test_a_hold_is_a_lease_on_disk_written_under_the_lock(tmp_path):
    pg = _backend(tmp_path)
    got = pg.pg_l2_hold(60)
    assert (got['held'], got['seconds']) == (True, 60) and abs(got['until'] - time.time() - 60) < 2
    assert _lease(tmp_path) == pytest.approx(got['until'], abs=0.01)
    assert _free(tmp_path / 'backup.lock')            # the lock itself only while writing


def test_the_lease_outlives_the_executor(tmp_path):
    """Codex: a restart released a lock held by the process. The lease is a file."""
    _backend(tmp_path).pg_l2_hold(60)
    restarted = _backend(tmp_path)                    # a new agent-exec: nothing in memory
    assert _lease(tmp_path) > time.time() + 50
    assert restarted.pg_l2_hold(120)['held']          # and it can grant (extend) again
    assert _lease(tmp_path) > time.time() + 110


def test_the_rename_is_on_disk_before_the_grant_under_the_lock(tmp_path, monkeypatch):
    """Codex: fsync of the file alone left the rename itself to a crash. The directory too, while
    the lock is still held, before the hold is acknowledged."""
    from hostagent import pg_backend
    seen = []

    def spy(path):
        seen.append((path, (tmp_path / 'backup.lock.hold').exists(), _free(tmp_path / 'backup.lock')))
    monkeypatch.setattr(pg_backend, 'fsync_dir', spy)
    assert _backend(tmp_path).pg_l2_hold(60)['held']
    assert seen == [(tmp_path, True, False)]


def test_a_running_backup_means_no_hold(tmp_path):
    pg = _backend(tmp_path)
    backup = os.open(tmp_path / 'backup.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(backup, fcntl.LOCK_EX)
    assert pg.pg_l2_hold(60) == {'held': False}
    assert not (tmp_path / 'backup.lock.hold').exists()
    os.close(backup)
    assert pg.pg_l2_hold(60)['held'] is True


def test_l2_hold_envelope_runs_on_db_1(tmp_path):
    """A signed, host-scoped internal operation from ctl-1: no tenant, no environment."""
    import dataclasses
    from hostagent.agentd import Agent
    from hostagent.execd import Executor, LocalExecClient
    from hostagent.logs import AuditLog
    from .conftest import Harness

    h = Harness(tmp_path)
    pg = _backend(tmp_path)
    h.config = dataclasses.replace(h.config, role='db')
    h.agent = Agent(h.config, h.state, LocalExecClient(Executor('db', pg, AuditLog(None))), h.keys.agent, h.log,
                    clock_fn=h.clock)
    resp = h.agent.handle(h.envelope('L2.Hold', 'db.l2_hold', {'seconds': 120}, environment_id=None, tenant_id=None,
                                     tenant_state=None))
    assert (resp['status'], resp['code']) == ('done', 'OK') and resp['observed']['held'] is True
    assert _lease(tmp_path) > time.time() + 100


def test_an_app_host_refuses_l2_hold(h):
    resp = h.agent.handle(h.envelope('L2.Hold', 'db.l2_hold', {'seconds': 120}, environment_id=None, tenant_id=None,
                                     tenant_state=None))
    assert resp['status'] == 'rejected'
