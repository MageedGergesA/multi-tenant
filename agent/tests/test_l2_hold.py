"""L2.Hold on db-1 (DOC-05 §3.1): the backup lock pgbackrest-scheduled takes, held for ctl-1's
expire. pgBackRest's own locks are per host; this one keeps backup and expire apart."""
import fcntl
import os
import time

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


def test_a_hold_keeps_a_backup_from_starting_until_it_ends(tmp_path):
    pg = _backend(tmp_path)
    got = pg.pg_l2_hold(60)
    assert (got['held'], got['seconds']) == (True, 60) and abs(got['until'] - time.time() - 60) < 2
    assert not _free(tmp_path / 'backup.lock')                 # the backup's flock: blocked
    pg._hold[1].cancel()
    pg._release_hold()                                         # the lease ends
    assert _free(tmp_path / 'backup.lock')


def test_a_running_backup_means_no_hold(tmp_path):
    pg = _backend(tmp_path)
    backup = os.open(tmp_path / 'backup.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(backup, fcntl.LOCK_EX)
    assert pg.pg_l2_hold(60) == {'held': False}
    os.close(backup)
    assert pg.pg_l2_hold(60)['held'] is True
    pg._release_hold()


def test_the_lease_runs_out_by_itself(tmp_path, monkeypatch):
    import threading
    real = threading.Timer
    monkeypatch.setattr(threading, 'Timer', lambda s, f: real(0.05, f))
    pg = _backend(tmp_path)
    assert pg.pg_l2_hold(60)['held']
    time.sleep(0.3)
    assert _free(tmp_path / 'backup.lock') and pg._hold is None


def test_asked_again_while_holding_it_renews_the_lease(tmp_path):
    pg = _backend(tmp_path)
    pg.pg_l2_hold(60)
    first = pg._hold[1]
    assert pg.pg_l2_hold(120)['seconds'] == 120
    assert not first.is_alive() or first.finished.is_set()
    pg._release_hold()


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
    assert not _free(tmp_path / 'backup.lock')
    pg._release_hold()


def test_an_app_host_refuses_l2_hold(h):
    resp = h.agent.handle(h.envelope('L2.Hold', 'db.l2_hold', {'seconds': 120}, environment_id=None, tenant_id=None,
                                     tenant_state=None))
    assert resp['status'] == 'rejected'
