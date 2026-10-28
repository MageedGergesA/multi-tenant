"""ctl-1's side of ADR-008 monitoring, served on loopback for the Prometheus and
Alertmanager on the same host:

    GET  /metrics            Prometheus text format
    POST /v1/alertmanager    Alertmanager webhook (bearer token) → incidents

`ctl_backup_last_recoverable_timestamp_seconds{tenant_id, environment_id}`
is the snapshot time of the newest `recoverable` backup point of each
production environment that should be backed up (0: none yet). Any tier
counts: "daily backup" in DOC-03 §7 is the daily schedule, whose Sunday run
is `weekly` and first of the month `monthly` (DOC-05 §3); counting only the
`daily` tier would page every Monday. The rule
`NoRecoverableDailyBackup` (monitoring/rules/backups.yml) fires when it is
older than 26 h (DOC-05 §8, sev2, RB-01).

`ctl_drill_last_pass_timestamp_seconds{tenant_id, environment_id}` is when
the environment last passed a restore drill or, never drilled, the snapshot
time of its first recoverable backup (the 30 days start when there is
something to drill); environments with no recoverable backup are left to the
backup alert. `TenantNotDrilled` (monitoring/rules/drills.yml) fires past 30
days (DOC-05 §8, sev3, RB-04). A failed drill opens its sev2 incident
directly (drills.record).

`ctl_controlplane_dump_last_timestamp_seconds` and
`ctl_audit_anchor_last_timestamp_seconds` (0: none yet) are the newest
control-plane dump and audit anchor in bucket C (cpbackup).
`monitoring/rules/controlplane.yml`: `ControlPlaneDumpMissing` (sev2) and
`AuditAnchorMissing` (sev1, RB-09) past 26 h (DOC-05 §8). A broken chain
opens its sev1 incident directly. `ctl_controlplane_drill_last_pass_timestamp_seconds`
is the last passed control-plane drill, or the first dump if none passed;
`ControlPlaneNotDrilled` (sev3, RB-10) past 92 days.

`ctl_workers_leader` is 1 while this process holds the workers lock
(main.Workers), not from the database: it is per process.
`monitoring/rules/workers.yml`: `CtlWorkersNotRunning` (sev2, RB-16) when no
scraped instance has held it for 10 min, `CtlWorkersTwice` (sev2) when two
have for 5 min.

`ctl_worker_last_success_timestamp_seconds{worker}` and
`ctl_worker_interval_seconds{worker}`, only from the process holding the lock;
`ctl_worker_failures_total{worker}` from every process. `CtlWorkerFailing`
(sev2, RB-16) when a worker's last success is older than three intervals,
at least 15 min.
"""
import hashlib
import hmac
import time
import uuid

from fastapi import FastAPI, HTTPException, Request, Response

from . import audit
from .store import Store, _ts

# Tenant states in which a production environment is backed up daily: the
# states Tenant.Backup is allowed in, less VALIDATING (its first backup is
# part of activation, DOC-03 §3.6).
BACKED_UP = ('ACTIVE', 'MAINTENANCE', 'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY',
             'DELETION_ELIGIBLE')
SEVERITIES = ('sev1', 'sev2', 'sev3', 'sev4')


def backup_ages(c) -> list[dict]:
    return c.execute(
        'SELECT e.tenant_id, e.id AS environment_id, '
        "  COALESCE(EXTRACT(EPOCH FROM MAX(b.snapshot_at) FILTER (WHERE b.state = 'recoverable')), 0) AS ts "
        'FROM environment e JOIN tenant t ON t.id = e.tenant_id '
        'LEFT JOIN backup_point b ON b.environment_id = e.id '
        "WHERE e.kind = 'production' AND e.observed_state <> 'absent' AND t.lifecycle_state = ANY(%s) "
        'GROUP BY e.tenant_id, e.id ORDER BY e.tenant_id', (list(BACKED_UP),)).fetchall()


def drill_ages(c) -> list[dict]:
    return c.execute(
        'SELECT e.tenant_id, e.id AS environment_id, EXTRACT(EPOCH FROM COALESCE('
        "  (SELECT MAX(r.created_at) FROM restore_attempt r WHERE r.source_environment_id = e.id "
        "   AND r.purpose = 'drill' AND r.result = 'pass'), MIN(b.snapshot_at))) AS ts "
        "FROM environment e JOIN tenant t ON t.id = e.tenant_id "
        "JOIN backup_point b ON b.environment_id = e.id AND b.state = 'recoverable' "
        "WHERE e.kind = 'production' AND e.observed_state <> 'absent' AND t.lifecycle_state = ANY(%s) "
        'GROUP BY e.tenant_id, e.id ORDER BY e.tenant_id', (list(BACKED_UP),)).fetchall()


def metrics(c, now=None) -> str:
    """`now`: the store's clock (bounds the dump, anchor and drill times read)."""
    now = _ts(time.time() if now is None else now)
    rows = backup_ages(c)
    out = ['# HELP ctl_backup_last_recoverable_timestamp_seconds Snapshot time of the newest recoverable '
           'backup of a production environment, any tier (0: none).',
           '# TYPE ctl_backup_last_recoverable_timestamp_seconds gauge']
    out += ['ctl_backup_last_recoverable_timestamp_seconds{tenant_id="%s",environment_id="%s"} %s'
            % (r['tenant_id'], r['environment_id'], int(r['ts'])) for r in rows]
    out += ['# HELP ctl_backup_environments Production environments expected to have daily backups.',
            '# TYPE ctl_backup_environments gauge', 'ctl_backup_environments %d' % len(rows)]
    out += ['# HELP ctl_drill_last_pass_timestamp_seconds Last passed restore drill of a production environment '
            '(never drilled: its first recoverable backup).',
            '# TYPE ctl_drill_last_pass_timestamp_seconds gauge']
    out += ['ctl_drill_last_pass_timestamp_seconds{tenant_id="%s",environment_id="%s"} %s'
            % (r['tenant_id'], r['environment_id'], int(r['ts'])) for r in drill_ages(c)]
    # Bounded by now: a row dated in the future mustn't keep the alerts quiet.
    last = c.execute("SELECT COALESCE(EXTRACT(EPOCH FROM (SELECT MAX(created_at) FROM ctl_dump "
                     "WHERE created_at <= %(now)s)), 0) AS dump, "
                     "COALESCE(EXTRACT(EPOCH FROM (SELECT MAX(anchored_at) FROM audit_anchor "
                     "WHERE anchored_at <= %(now)s)), 0) AS anchor, "
                     "COALESCE(EXTRACT(EPOCH FROM COALESCE("
                     "(SELECT MAX(created_at) FROM ctl_drill WHERE result = 'pass' AND created_at <= %(now)s), "
                     "(SELECT MIN(created_at) FROM ctl_dump WHERE created_at <= %(now)s))), 0) AS drill",
                     {'now': now}).fetchone()
    out += ['# HELP ctl_controlplane_dump_last_timestamp_seconds Newest control-plane dump uploaded to bucket C '
            'and read back (0: none).', '# TYPE ctl_controlplane_dump_last_timestamp_seconds gauge',
            'ctl_controlplane_dump_last_timestamp_seconds %d' % int(last['dump']),
            '# HELP ctl_audit_anchor_last_timestamp_seconds Newest audit hash anchor written to bucket C (0: none).',
            '# TYPE ctl_audit_anchor_last_timestamp_seconds gauge',
            'ctl_audit_anchor_last_timestamp_seconds %d' % int(last['anchor']),
            '# HELP ctl_controlplane_drill_last_pass_timestamp_seconds Last passed control-plane drill (never: the '
            'first dump; 0: no dump yet).', '# TYPE ctl_controlplane_drill_last_pass_timestamp_seconds gauge',
            'ctl_controlplane_drill_last_pass_timestamp_seconds %d' % int(last['drill'])]
    return '\n'.join(out) + '\n'


def _uuid(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def alertmanager(store: Store, payload: dict) -> dict:
    """Open an incident per firing alert (once per fingerprint), resolve it when resolved."""
    now = store.clock()
    opened = resolved = 0
    alerts = payload.get('alerts') if isinstance(payload, dict) else None
    if not isinstance(alerts, list):
        raise ValueError('alerts')
    with store.connect() as c:
        for a in alerts[:500]:
            if not isinstance(a, dict) or not isinstance(a.get('fingerprint'), str):
                continue
            fp = a['fingerprint'][:64]
            labels = a.get('labels') if isinstance(a.get('labels'), dict) else {}
            notes = a.get('annotations') if isinstance(a.get('annotations'), dict) else {}
            if a.get('status') == 'resolved':
                row = c.execute('UPDATE incident SET resolved_at = %s WHERE alert_fingerprint = %s '
                                'AND resolved_at IS NULL RETURNING id', (_ts(now), fp)).fetchone()
                resolved += bool(row)
                continue
            if c.execute('SELECT 1 FROM incident WHERE alert_fingerprint = %s AND resolved_at IS NULL',
                         (fp,)).fetchone():
                continue
            severity = labels.get('severity') if labels.get('severity') in SEVERITIES else 'sev3'
            tenant = _uuid(labels.get('tenant_id'))
            summary = str(notes.get('summary') or labels.get('alertname') or 'alert')[:500]
            incident = uuid.uuid4()
            c.execute('INSERT INTO incident (id, severity, scope_tenant_ids, summary, runbook_ref, opened_at, '
                      'alert_fingerprint) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                      (incident, severity, [tenant] if tenant else [], summary,
                       str(labels.get('runbook') or '')[:64] or None, _ts(now), fp))
            audit.append(c, _ts(now), 'incident.opened', tenant_id=tenant, resource_type='incident',
                         resource_id=incident, after={'alertname': labels.get('alertname'), 'severity': severity})
            opened += 1
    return {'opened': opened, 'resolved': resolved}


def workers_metric(workers) -> str:
    out = ['# HELP ctl_workers_leader 1 while this process holds the workers lock and runs the workers.',
           '# TYPE ctl_workers_leader gauge', 'ctl_workers_leader %d' % workers.leading.is_set(),
           '# HELP ctl_worker_failures_total Runs of a worker that raised, since this process started.',
           '# TYPE ctl_worker_failures_total counter']
    out += ['ctl_worker_failures_total{worker="%s"} %d' % (n, v) for n, v in sorted(workers.failures.items())]
    last = dict(workers.last_success)          # empty unless this process holds the lock
    out += ['# HELP ctl_worker_last_success_timestamp_seconds Last run of a worker that didn\'t raise '
            '(the start of this lock term if none has yet).',
            '# TYPE ctl_worker_last_success_timestamp_seconds gauge']
    out += ['ctl_worker_last_success_timestamp_seconds{worker="%s"} %.3f' % (n, v) for n, v in sorted(last.items())]
    out += ['# HELP ctl_worker_interval_seconds How often a worker runs.', '# TYPE ctl_worker_interval_seconds gauge']
    out += ['ctl_worker_interval_seconds{worker="%s"} %g' % (n, workers.intervals[n]) for n in sorted(last)]
    return '\n'.join(out) + '\n'


def create_app(store: Store, *, webhook_token_sha256: str, workers=None) -> FastAPI:
    """`webhook_token_sha256`: SHA-256 (hex) of the bearer token in Alertmanager's
    webhook `http_config`; the token itself isn't kept here. `workers`: this
    process's `main.Workers`, for `ctl_workers_leader`."""
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get('/metrics')
    def get_metrics():
        with store.connect() as c:
            text = metrics(c, store.clock())
        if workers is not None:
            text += workers_metric(workers)
        return Response(text, media_type='text/plain; version=0.0.4')

    @app.post('/v1/alertmanager')
    async def webhook(request: Request):
        header = request.headers.get('authorization', '')
        given = hashlib.sha256(header[7:].encode()).hexdigest() if header.startswith('Bearer ') else ''
        if not hmac.compare_digest(given, webhook_token_sha256):
            raise HTTPException(401)
        try:
            return alertmanager(store, await request.json())
        except ValueError:
            raise HTTPException(422) from None

    return app
