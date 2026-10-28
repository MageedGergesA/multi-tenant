"""L1 restore drills (DOC-05 §5, DR-07, DR-13; DOC-07 RB-04).

Between 06:00 and 10:00 UTC (off the backup window), one drill at a time is
requested, as the system, through the same admission as an operator's
`Tenant.RestoreToIsolated {purpose: drill}`; its copy holds capacity like any
restore (INV-8). In order:

    redrill        a production environment whose last drill failed: its
                   latest recoverable backup, again (within 24 h)
    oldest         the environment drilled longest ago (never: first), its
                   latest recoverable backup; `per_day` a day, and at least
                   enough that every environment comes round within
                   CYCLE_DAYS
    weekly_random  once a week, a random environment and a random tier, and a
                   random recoverable backup of that tier; a deep drill (the
                   key tables' row counts and a printed PDF too)

After two failed drills in a row the environment isn't drilled automatically
again: it is for manual investigation and a customer notice (an operator's
drill that passes puts it back in the rotation). A refused request is retried
next round under a new idempotency key, at most MAX_REJECTED a day.

`record` is called by the store when a RestoreToIsolated finishes: it writes
the `restore_attempt`, and for a drill marks the backup DRILL_VERIFIED and
expires the copy at once, or opens a sev2 incident.
"""
import math
import random
import uuid
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from . import audit
from .admission import Admission
from .store import _ts

WINDOW_HOURS = (6, 10)
PER_DAY = 1
CYCLE_DAYS = 28                 # inside DOC-05's 30, so a refused day or two doesn't breach it
MAX_REJECTED = 3
TIERS = ('daily', 'weekly', 'monthly')
KEY_PREFIX = 'drill'
# Tenant states whose production environment is backed up daily (monitoring.BACKED_UP).
DRILLED = ('ACTIVE', 'MAINTENANCE', 'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY',
           'DELETION_ELIGIBLE')
IN_FLIGHT = ('REQUESTED', 'VALIDATED', 'RESERVED', 'DISPATCHED', 'APPLYING', 'VERIFIED', 'RECONCILING',
             'RECOVERING')
# DOC-04 §6.9 checks a drill must pass, as the agent reports them.
CHECKS = ('signature', 'tenant', 'environment', 'backup_id', 'login', 'modules_match', 'files_verified',
          'zero_egress')
# And for a deep drill (the weekly random one): key-table row counts equal the
# backup's, and one PDF printed by the copy.
DEEP_CHECKS = ('row_counts_match', 'pdf_printed')
# Dry-run nftables has no packet counters; on a real host the agent fails the check closed.
UNMEASURED_OK = ('zero_egress',)


# -- results -------------------------------------------------------------------------

def passed(checks, deep=False) -> bool:
    if not isinstance(checks, dict):
        return False
    return all(checks.get(k) is True or (k in UNMEASURED_OK and checks.get(k) == 'not_measured')
               for k in CHECKS + (DEEP_CHECKS if deep else ()))


def record(c, op_id, state, now):
    op = c.execute('SELECT * FROM operation WHERE id = %s', (op_id,)).fetchone()
    p = op['params']
    step = c.execute("SELECT observed, evidence_sha256 FROM operation_step WHERE operation_id = %s "
                     "AND name = 'app.restore_copy'", (op_id,)).fetchone()
    observed = (step and step['observed']) or op['result_detail'] or {}
    checks = observed.get('checks') if isinstance(observed, dict) and 'checks' in observed else observed
    ok = state == 'COMPLETED' and passed(checks, deep=p.get('deep') is True)
    kind = None
    if p.get('purpose') == 'drill':
        parts = (op['idempotency_key'] or '').split(':')
        kind = parts[2] if op['requested_by'] is None and parts[0] == KEY_PREFIX and len(parts) == 4 else 'manual'
    c.execute('INSERT INTO restore_attempt (id, operation_id, backup_point_id, source_environment_id, '
              'target_environment_id, purpose, drill_kind, checks, evidence_sha256, result, result_code, '
              'measured_rto_seconds, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
              (uuid.uuid4(), op_id, p['backup_id'], op['environment_id'], p.get('target_environment_id'),
               p['purpose'], kind, Jsonb(checks), step and step['evidence_sha256'], 'pass' if ok else 'fail',
               op['result_code'] if not ok else None, int(now - op['created_at'].timestamp()), _ts(now)))
    if p.get('purpose') != 'drill':
        return
    audit.append(c, _ts(now), 'restore.drill_passed' if ok else 'restore.drill_failed', tenant_id=op['tenant_id'],
                 resource_type='backup_point', resource_id=p['backup_id'], correlation_id=op_id,
                 after={'drill_kind': kind, 'result_code': op['result_code']})
    if ok:
        c.execute('UPDATE backup_point SET drill_verified_at = %s WHERE id = %s', (_ts(now), p['backup_id']))
        # DOC-05 §5: a drill's copy expires immediately (the expiry sweep removes it).
        c.execute('UPDATE environment SET expires_at = %s, row_version = row_version + 1 WHERE id = %s',
                  (_ts(now), p['target_environment_id']))
        return
    streak = failed_streak(c, op['environment_id'])
    summary = ('restore drill failed: tenant %s, backup %s' % (op['tenant_id'], p['backup_id']) if streak < 2 else
               'second restore drill in a row failed: tenant %s needs manual investigation and a customer notice'
               % op['tenant_id'])
    c.execute("INSERT INTO incident (id, severity, scope_tenant_ids, operation_id, summary, runbook_ref, opened_at) "
              "VALUES (%s, 'sev2', %s, %s, %s, 'RB-04', %s)",
              (uuid.uuid4(), [op['tenant_id']], op_id, summary, _ts(now)))


def failed_streak(c, environment_id) -> int:
    """Failed drills in a row, newest first."""
    n = 0
    for r in c.execute("SELECT result FROM restore_attempt WHERE source_environment_id = %s AND purpose = 'drill' "
                       'ORDER BY created_at DESC, id LIMIT 3', (environment_id,)).fetchall():
        if r['result'] != 'fail':
            break
        n += 1
    return n


# -- scheduling ----------------------------------------------------------------------

class Drills:
    def __init__(self, admission: Admission, *, per_day: int = PER_DAY, rng: random.Random | None = None):
        self.admission = admission
        self.store = admission.store
        self.per_day = per_day
        self.rng = rng or random.SystemRandom()

    def eligible(self, c) -> list[dict]:
        rows = c.execute(
            'SELECT e.id, e.tenant_id, '
            "  (SELECT MAX(r.created_at) FROM restore_attempt r WHERE r.source_environment_id = e.id "
            "   AND r.purpose = 'drill') AS last_drill "
            'FROM environment e JOIN tenant t ON t.id = e.tenant_id '
            "WHERE e.kind = 'production' AND e.observed_state <> 'absent' AND t.lifecycle_state = ANY(%s) "
            "AND EXISTS (SELECT 1 FROM backup_point b WHERE b.environment_id = e.id AND b.state = 'recoverable') "
            'ORDER BY e.id', (list(DRILLED),)).fetchall()
        for r in rows:
            r['streak'] = failed_streak(c, r['id'])
            r['busy'] = bool(c.execute('SELECT 1 FROM operation WHERE environment_id = %s AND exclusive '
                                       'AND state = ANY(%s)', (r['id'], list(IN_FLIGHT))).fetchone())
        return rows

    def run_once(self) -> dict:
        now = datetime.fromtimestamp(self.store.clock(), timezone.utc)
        if not WINDOW_HOURS[0] <= now.hour < WINDOW_HOURS[1]:
            return {'state': 'outside_window'}
        day = now.date().isoformat()
        week = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        with self.store.connect() as c:
            today = c.execute("SELECT state, idempotency_key FROM operation WHERE type = 'Tenant.RestoreToIsolated' "
                              'AND requested_by IS NULL AND idempotency_key LIKE %s',
                              ('%s:%s:%%' % (KEY_PREFIX, day),)).fetchall()
            if any(o['state'] in IN_FLIGHT for o in today):
                return {'state': 'in_flight'}
            if sum(o['state'] == 'REJECTED' for o in today) >= MAX_REJECTED:
                return {'state': 'gave_up'}
            ran = [o['idempotency_key'].split(':')[2] for o in today if o['state'] != 'REJECTED']
            weekly_done = c.execute(
                "SELECT 1 FROM operation WHERE type = 'Tenant.RestoreToIsolated' AND requested_by IS NULL "
                "AND idempotency_key LIKE %s AND state <> 'REJECTED' AND created_at >= %s",
                ('%s:%%:weekly_random:%%' % KEY_PREFIX, week)).fetchone()
            envs = [e for e in self.eligible(c) if e['streak'] < 2 and not e['busy']]
            quota = max(self.per_day, math.ceil(len(envs) / CYCLE_DAYS))
            pick = self._pick(c, envs, ran, quota, weekly_done)
        if pick is None:
            return {'state': 'nothing_due'}
        kind, env, backup = pick
        op = self.admission.request(None, op_type='Tenant.RestoreToIsolated', tenant_id=str(env['tenant_id']),
                                    environment_id=str(env['id']),
                                    params={'backup_id': str(backup), 'purpose': 'drill',
                                            'deep': kind == 'weekly_random'},
                                    idempotency_key='%s:%s:%s:%d' % (KEY_PREFIX, day, kind, len(today)))
        return {'state': op['state'], 'kind': kind, 'environment_id': str(env['id']), 'backup_id': str(backup),
                'result_code': op['result_code']}

    def _pick(self, c, envs, ran, quota, weekly_done):
        latest = lambda e: c.execute(  # noqa: E731
            "SELECT id FROM backup_point WHERE environment_id = %s AND state = 'recoverable' "
            'ORDER BY snapshot_at DESC NULLS LAST, id LIMIT 1', (e['id'],)).fetchone()['id']
        redrill = [e for e in envs if e['streak'] == 1]
        if redrill:
            return 'redrill', redrill[0], latest(redrill[0])
        if ran.count('oldest') < quota and envs:
            e = min(envs, key=lambda e: (e['last_drill'] is not None, e['last_drill'] or 0, str(e['id'])))
            return 'oldest', e, latest(e)
        if not weekly_done and envs:
            e = self.rng.choice(envs)
            tiers = [r['retention_tier'] for r in c.execute(
                "SELECT DISTINCT retention_tier FROM backup_point WHERE environment_id = %s AND state = 'recoverable' "
                'AND retention_tier = ANY(%s) ORDER BY retention_tier', (e['id'], list(TIERS))).fetchall()]
            if tiers:
                tier = self.rng.choice(tiers)
                points = [r['id'] for r in c.execute(
                    "SELECT id FROM backup_point WHERE environment_id = %s AND state = 'recoverable' "
                    'AND retention_tier = %s ORDER BY id', (e['id'], tier)).fetchall()]
                return 'weekly_random', e, self.rng.choice(points)
        return None
