"""The daily L1 tenant backup (DOC-05 §2, §3).

Window 22:00–04:00 UTC; each tenant's start minute is a hash of its
`tenant_id`, so starts are spread over the six hours. A window is named by
the date it opens (22:00 on that day). From its slot until the next window
opens, a production environment that should be backed up gets one
Tenant.Backup requested, as the system, through the same admission as an
operator's: a backup missed because ctl-1 was down still runs late that day.

Tier, fixed when the backup is created (lock periods can't be extended):
monthly if the environment has no recoverable monthly backup yet this
calendar month (so a failed first-of-month run passes the tier to the next
night), else weekly on Sundays, else daily; Object Lock 93, 29 or 8 days.

Skipped this round: an environment with an exclusive operation in flight
(INV-21, e.g. a module update), and an app host already running
`max_per_host` backups (DOC-05 §2; N from DOC-06). A refused or failed
attempt is retried within the window under a new idempotency key, up to
MAX_ATTEMPTS; after that the 26-hour alert is the backstop.
"""
import hashlib
from datetime import datetime, timedelta, timezone

from .admission import Admission

WINDOW_START_HOUR = 22
WINDOW_MINUTES = 6 * 60
LOCK_DAYS = {'daily': 8, 'weekly': 29, 'monthly': 93}
MAX_ATTEMPTS = 3
# VALIDATING too: its first recoverable backup is an activation check (DOC-03 §3.6).
STATES = ('VALIDATING', 'ACTIVE', 'MAINTENANCE', 'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY',
          'DELETION_ELIGIBLE')
IN_FLIGHT = ('REQUESTED', 'VALIDATED', 'RESERVED', 'DISPATCHED', 'APPLYING', 'VERIFIED', 'RECONCILING',
             'RECOVERING')
KEY_PREFIX = 'scheduled-backup'


def offset_minutes(tenant_id: str) -> int:
    """The tenant's start minute within the window."""
    return int.from_bytes(hashlib.sha256(str(tenant_id).encode()).digest()[:4], 'big') % WINDOW_MINUTES


def window(now: datetime) -> datetime:
    """Start of the window `now` belongs to (it lasts until the next one opens)."""
    start = now.replace(hour=WINDOW_START_HOUR, minute=0, second=0, microsecond=0)
    return start if now >= start else start - timedelta(days=1)


def slot(tenant_id: str, now: datetime) -> datetime:
    return window(now) + timedelta(minutes=offset_minutes(tenant_id))


def tier(c, environment_id, at: datetime) -> str:
    month = at.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if not c.execute("SELECT 1 FROM backup_point WHERE environment_id = %s AND state = 'recoverable' "
                     "AND retention_tier = 'monthly' AND snapshot_at >= %s", (environment_id, month)).fetchone():
        return 'monthly'
    return 'weekly' if at.weekday() == 6 else 'daily'


class BackupSchedule:
    def __init__(self, admission: Admission, *, max_per_host: int = 2):
        self.admission = admission
        self.store = admission.store
        self.max_per_host = max_per_host

    def run_once(self) -> dict[str, str]:
        """→ {environment id: what happened this round}."""
        now = datetime.fromtimestamp(self.store.clock(), timezone.utc)
        with self.store.connect() as c:
            envs = c.execute(
                'SELECT e.id, e.tenant_id, e.app_host_id FROM environment e JOIN tenant t ON t.id = e.tenant_id '
                "WHERE e.kind = 'production' AND e.observed_state <> 'absent' AND t.lifecycle_state = ANY(%s) "
                'ORDER BY e.id', (list(STATES),)).fetchall()
        return {str(e['id']): self._one(e, now) for e in envs}

    def _one(self, env, now) -> str:
        at = slot(env['tenant_id'], now)
        if now < at:
            return 'not_yet'
        prefix = '%s:%s:%s:' % (KEY_PREFIX, env['id'], window(now).date().isoformat())
        with self.store.connect() as c:
            attempts = c.execute("SELECT state FROM operation WHERE type = 'Tenant.Backup' AND idempotency_key LIKE %s",
                                 (prefix + '%',)).fetchall()
            if any(a['state'] == 'COMPLETED' for a in attempts):
                return 'done'
            if any(a['state'] in IN_FLIGHT for a in attempts):
                return 'in_flight'
            if len(attempts) >= MAX_ATTEMPTS:
                return 'gave_up'
            if c.execute('SELECT 1 FROM operation WHERE environment_id = %s AND exclusive AND state = ANY(%s)',
                         (env['id'], list(IN_FLIGHT))).fetchone():
                return 'environment_busy'
            running = c.execute("SELECT count(*) AS n FROM operation WHERE type = 'Tenant.Backup' AND host_id = %s "
                                'AND state = ANY(%s)', (env['app_host_id'], list(IN_FLIGHT))).fetchone()['n']
            if running >= self.max_per_host:
                return 'host_busy'
            t = tier(c, env['id'], at)
        op = self.admission.request(None, op_type='Tenant.Backup', tenant_id=str(env['tenant_id']),
                                    environment_id=str(env['id']),
                                    params={'retention_tier': t, 'lock_days': LOCK_DAYS[t]},
                                    idempotency_key=prefix + str(len(attempts)))
        return op['state'] if op['state'] != 'REJECTED' else 'rejected:' + (op['result_code'] or '')
