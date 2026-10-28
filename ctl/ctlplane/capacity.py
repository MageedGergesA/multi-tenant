"""Placement, runtime slots and capacity reservations (DOC-03 §2.3, §2.4).

INV-8: on every host, held (unexpired) + committed reservations stay within
total × (100 − reserve_pct)% in every dimension, and on a DB host the
connection budget within pg_max_connections likewise. DOC-03 asks for a
SERIALIZABLE transaction; here each host is locked (a transaction-scoped
advisory lock, in a fixed order) before its usage is summed, which gives the
same guarantee without retry loops, and works inside the longer admission
transaction.

A reservation is `held` from admission, `committed` once its operation has
run (COMPLETED or FAILED: either way something now exists on the host and
"nothing is dropped", DOC-03 §5), and `released` when the environment is
removed (Delete, RestoreCopy.Expire) or the operation never dispatched.
"""
import uuid
from dataclasses import dataclass

from .store import _ts

HOLD_TTL = 24 * 3600        # beyond the longest lease (3 h) plus reconciling (30 min)
MIB = 1 << 20
DIMS = ('vcpu_milli', 'ram_mb', 'disk_gb', 'pg_conn')


class NoCapacity(Exception):
    pass


@dataclass(frozen=True)
class Need:
    vcpu_milli: int = 0
    ram_mb: int = 0
    disk_gb: int = 0
    pg_conn: int = 0


def needs(bundle) -> tuple[Need, Need]:
    """(app host, DB host) for one environment of this bundle."""
    app = Need(vcpu_milli=bundle['cpu_millis'], ram_mb=-(-bundle['mem_limit_bytes'] // MIB), disk_gb=bundle['disk_gb'])
    # ADR-004 (amended): (workers + max_cron_threads + 1) × db_maxconn + 1.
    db = Need(disk_gb=bundle['db_disk_gb'],
              pg_conn=(bundle['workers'] + bundle['max_cron_threads'] + 1) * bundle['db_maxconn'] + 1)
    return app, db


def _lock(c, host_id):
    c.execute("SELECT pg_advisory_xact_lock(hashtextextended('capacity:' || %s, 0))", (str(host_id),))


def free(c, host, now) -> dict:
    """What can still be reserved on `host` (a host row), by dimension."""
    used = c.execute(
        'SELECT COALESCE(SUM(vcpu_milli), 0) AS vcpu_milli, COALESCE(SUM(ram_mb), 0) AS ram_mb, '
        'COALESCE(SUM(disk_gb), 0) AS disk_gb, COALESCE(SUM(pg_conn), 0) AS pg_conn FROM capacity_reservation '
        "WHERE host_id = %s AND (state = 'committed' OR (state = 'held' AND expires_at > %s))",
        (host['id'], _ts(now))).fetchone()
    usable = lambda total: (total or 0) * (100 - host['reserve_pct']) // 100   # noqa: E731
    return {'vcpu_milli': usable(host['total_vcpu_milli']) - used['vcpu_milli'],
            'ram_mb': usable(host['total_ram_mb']) - used['ram_mb'],
            'disk_gb': usable(host['total_disk_gb']) - used['disk_gb'],
            'pg_conn': usable(host['pg_max_connections']) - used['pg_conn']}


def _fits(c, host, need: Need, now) -> bool:
    room = free(c, host, now)
    return all(getattr(need, d) <= room[d] for d in DIMS if getattr(need, d))


def place(c, bundle, now, *, app_host=None, db_host=None) -> tuple[dict, dict]:
    """An (app host, DB host) pair in one region where the bundle fits, locked
    until the transaction ends. Pinned hosts are only checked."""
    app_need, db_need = needs(bundle)
    apps = _candidates(c, 'app', app_host)
    dbs = _candidates(c, 'db', db_host)
    for host in sorted(apps + dbs, key=lambda h: str(h['id'])):      # one lock order everywhere
        _lock(c, host['id'])
    fitting_db = [h for h in dbs if _fits(c, h, db_need, now)]
    for app in sorted(apps, key=lambda h: -free(c, h, now)['ram_mb']):  # spread: most free memory first
        if not _fits(c, app, app_need, now):
            continue
        for db in fitting_db:
            if db['region_id'] == app['region_id']:
                return app, db
    raise NoCapacity()


def _candidates(c, role, pinned):
    if pinned is not None:
        return c.execute("SELECT * FROM host WHERE id = %s AND role = %s AND state = 'active'",
                         (pinned, role)).fetchall()
    return c.execute("SELECT * FROM host WHERE role = %s AND state = 'active' ORDER BY id", (role,)).fetchall()


def hold(c, op_id, environment_id, host, need: Need, now):
    c.execute('INSERT INTO capacity_reservation (id, host_id, environment_id, operation_id, vcpu_milli, ram_mb, '
              "disk_gb, pg_conn, state, expires_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'held', %s, %s)",
              (uuid.uuid4(), host['id'], environment_id, op_id, need.vcpu_milli, need.ram_mb, need.disk_gb,
               need.pg_conn, _ts(now + HOLD_TTL), _ts(now)))


def allocate_slot(c, environment_id, host, bundle, now) -> dict:
    """A container UID (never reused, INV-13) and the lowest free port pair on
    the host. The host is already locked by `place`."""
    used = {r['http_port'] for r in c.execute('SELECT http_port FROM runtime_slot WHERE host_id = %s '
                                              'AND released_at IS NULL', (host['id'],)).fetchall()}
    low = host['port_low'] + host['port_low'] % 2
    port = next((p for p in range(low, host['port_high'], 2) if p not in used), None)
    if port is None:
        raise NoCapacity()
    uid = c.execute("SELECT nextval('container_uid_seq') AS u").fetchone()['u']
    slot = {'container_uid': uid, 'http_port': port, 'gevent_port': port + 1,
            **{k: bundle[k] for k in ('workers', 'max_cron_threads', 'db_maxconn', 'limit_memory_soft',
                                      'limit_memory_hard', 'limit_time_cpu', 'limit_time_real', 'mem_limit_bytes',
                                      'cpu_millis')}}
    c.execute('INSERT INTO runtime_slot (environment_id, host_id, container_uid, http_port, gevent_port, workers, '
              'max_cron_threads, db_maxconn, limit_memory_soft, limit_memory_hard, limit_time_cpu, limit_time_real, '
              'mem_limit_bytes, cpu_millis, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, '
              '%s, %s)', (environment_id, host['id'], uid, port, port + 1, slot['workers'], slot['max_cron_threads'],
                          slot['db_maxconn'], slot['limit_memory_soft'], slot['limit_memory_hard'],
                          slot['limit_time_cpu'], slot['limit_time_real'], slot['mem_limit_bytes'],
                          slot['cpu_millis'], _ts(now)))
    return slot


def commit(c, op_id):
    c.execute("UPDATE capacity_reservation SET state = 'committed', expires_at = NULL "
              "WHERE operation_id = %s AND state = 'held'", (op_id,))


def release_operation(c, op_id):
    """The operation never ran: what it held goes back."""
    c.execute("UPDATE capacity_reservation SET state = 'released', expires_at = NULL "
              "WHERE operation_id = %s AND state = 'held'", (op_id,))


def release_environment(c, environment_id, now):
    """The environment is gone from its hosts: its reservations and its ports
    go back; its container UID doesn't."""
    c.execute("UPDATE capacity_reservation SET state = 'released', expires_at = NULL "
              "WHERE environment_id = %s AND state IN ('held', 'committed')", (environment_id,))
    c.execute('UPDATE runtime_slot SET released_at = %s WHERE environment_id = %s AND released_at IS NULL',
              (_ts(now), environment_id))
