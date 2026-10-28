"""Restore-copy expiry (DOC-03 §9.5): a restore copy "expires at `expires_at`
through `RestoreCopy.Expire`". This sweep requests it, as the system, through
the same admission as an operator's request.

Due: a live copy past `expires_at`, and at once a copy whose
RestoreToIsolated failed (DOC-07: make sure Expire has removed the failed
copy). Skipped this round: a copy whose production environment has an
exclusive operation in flight (INV-21 would refuse it), and one with an
Expire already in flight. A refused or failed attempt is retried next round
under a new idempotency key; after MAX_FAILURES refused or failed attempts the
copy is left to an operator with a sev3 incident, opened once.
"""
import uuid

from . import audit
from .admission import Admission
from .store import _ts

MAX_FAILURES = 3
IN_FLIGHT = ('REQUESTED', 'VALIDATED', 'RESERVED', 'DISPATCHED', 'APPLYING', 'VERIFIED', 'RECONCILING',
             'RECOVERING')


class Expiry:
    def __init__(self, admission: Admission):
        self.admission = admission
        self.store = admission.store

    def due(self, c, now) -> list[dict]:
        return c.execute(
            "SELECT copy.id, copy.tenant_id, prod.id AS production_id FROM environment copy "
            "JOIN environment prod ON prod.tenant_id = copy.tenant_id AND prod.kind = 'production' "
            "WHERE copy.kind = 'restore_copy' AND copy.observed_state <> 'absent' AND (copy.expires_at <= %s "
            "  OR EXISTS (SELECT 1 FROM operation o WHERE o.type = 'Tenant.RestoreToIsolated' AND o.state = 'FAILED' "
            "             AND o.params->>'target_environment_id' = copy.id::text)) "
            'ORDER BY copy.expires_at', (_ts(now),)).fetchall()

    def run_once(self) -> dict[str, str]:
        """→ {copy id: what happened this round}."""
        now = self.store.clock()
        out = {}
        with self.store.connect() as c:
            copies = self.due(c, now)
        for copy in copies:
            out[str(copy['id'])] = self._one(copy, now)
        return out

    def _one(self, copy, now) -> str:
        copy_id = str(copy['id'])
        with self.store.connect() as c:
            attempts = c.execute("SELECT state FROM operation WHERE type = 'RestoreCopy.Expire' "
                                 "AND params->>'environment_id' = %s", (copy_id,)).fetchall()
            if any(a['state'] in IN_FLIGHT for a in attempts):
                return 'in_flight'
            failures = sum(a['state'] in ('FAILED', 'REJECTED') for a in attempts)
            if failures >= MAX_FAILURES:
                self._incident_once(c, copy, failures, now)
                return 'given_up'
            if c.execute('SELECT 1 FROM operation WHERE environment_id = %s AND exclusive AND state = ANY(%s)',
                         (copy['production_id'], list(IN_FLIGHT))).fetchone():
                return 'production_busy'
        op = self.admission.request(None, op_type='RestoreCopy.Expire', tenant_id=str(copy['tenant_id']),
                                    environment_id=str(copy['production_id']), params={'environment_id': copy_id},
                                    idempotency_key='expire:%s:%d' % (copy_id, len(attempts)))
        return op['state'] if op['state'] != 'REJECTED' else 'rejected:' + (op['result_code'] or '')

    def _incident_once(self, c, copy, failures, now):
        if c.execute("SELECT 1 FROM incident WHERE summary = %s AND resolved_at IS NULL",
                     (_summary(copy),)).fetchone():
            return
        c.execute("INSERT INTO incident (id, severity, scope_tenant_ids, summary, runbook_ref, opened_at) "
                  "VALUES (%s, 'sev3', %s, %s, 'DOC-07', %s)", (uuid.uuid4(), [copy['tenant_id']], _summary(copy), _ts(now)))
        audit.append(c, _ts(now), 'restore_copy.expiry_given_up', tenant_id=copy['tenant_id'],
                     resource_type='environment', resource_id=copy['id'], after={'failed_attempts': failures})


def _summary(copy) -> str:
    return 'restore copy %s could not be expired' % copy['id']
