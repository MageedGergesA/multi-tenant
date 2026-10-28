"""RECONCILING (DOC-03 §6): an unknown outcome is never retried blindly.

For each reconciling operation, every host whose step has an unknown outcome
is asked for its step journal (`Agent.Query`, DOC-04 §7). The probe goes
through the same outbox and response checks as any step. From the journal rows
of the operation's current fencing token:

    every step done                    → VERIFIED → COMPLETED
    the step is still running there    → APPLYING, same token, lease renewed
    not started, busy, or cut short    → re-dispatched from that step with a NEW token
    (TIMEOUT)
    failed with any other code         → FAILED with that code
    no answer for 30 min               → FAILED + incident (sev2)

Re-dispatch also needs a new token when it resumes a step the agent has
already finished as failed: the agent answers a repeated (op, token, step)
from its store and would never run it again. After `max_attempts`
dispatches the operation fails with an incident (sev3) instead of looping on a
step that keeps timing out.
"""
import uuid

from psycopg.types.json import Jsonb

from .store import Store, _ts

RESUME_CODES = ('TIMEOUT',)


def decide(steps: list[dict], token: int, journals: dict[str, list[dict]]):
    """→ (verdict, seq, code, newly_done). `steps` in order, as stored on ctl-1;
    `journals` maps a host to its rows for this operation."""
    newly_done = []
    for s in steps:
        if s['state'] == 'done':
            continue
        if s['state'] == 'pending':     # its predecessor turned out done
            return 'resume', s['seq'], None, newly_done
        rows = [r for r in journals.get(str(s['host_id']), ())
                if r.get('step') == s['name'] and r.get('fencing_token') == token]
        last = rows[-1] if rows else None
        if last is None or last['status'] == 'busy':
            return 'resume', s['seq'], None, newly_done
        if last['status'] == 'in_progress':
            return 'applying', s['seq'], None, newly_done
        if last['status'] == 'done':
            newly_done.append((s, last))
            continue
        if last.get('code') in RESUME_CODES:
            return 'resume', s['seq'], last['code'], newly_done
        return 'failed', s['seq'], last.get('code') or 'EXEC_ERROR', newly_done
    return 'completed', None, None, newly_done


class Reconciler:
    def __init__(self, store: Store, *, max_attempts: int = 3, unreachable_after: float = 1800):
        self.store = store
        self.max_attempts = max_attempts
        self.unreachable_after = unreachable_after

    def run_once(self) -> dict[str, str]:
        self.store.expire_leases()
        with self.store.connect() as c:
            ids = [str(r['id']) for r in c.execute(
                "SELECT id FROM operation WHERE state = 'RECONCILING' AND type <> 'Agent.Query' "
                'ORDER BY reconciling_since').fetchall()]
        return {op_id: self._reconcile(op_id) for op_id in ids}

    def _reconcile(self, op_id) -> str:
        now = self.store.clock()
        with self.store.connect() as c:
            # NO KEY UPDATE: probes inserted below reference this row.
            op = c.execute("SELECT * FROM operation WHERE id = %s AND state = 'RECONCILING' "
                           'FOR NO KEY UPDATE SKIP LOCKED', (op_id,)).fetchone()
            if op is None:
                return 'busy'
            steps = c.execute('SELECT * FROM operation_step WHERE operation_id = %s ORDER BY seq',
                              (op_id,)).fetchall()
            if now - op['reconciling_since'].timestamp() > self.unreachable_after:
                self._fail(c, op, 'UNREACHABLE', {'reconciling_s': round(now - op['reconciling_since'].timestamp())},
                           now, 'sev2', 'agent unreachable while reconciling %s' % op['type'])
                return 'unreachable'

            unknown = [s for s in steps if s['state'] in ('dispatched', 'applying', 'failed')]
            hosts = list(dict.fromkeys(str(s['host_id']) for s in unknown))
            probes = {}
            for p in c.execute(
                    'SELECT o.id, o.state, s.host_id, s.observed FROM operation o '
                    'JOIN operation_step s ON s.operation_id = o.id '
                    'WHERE o.reconciles_operation_id = %s AND o.reconcile_epoch = %s ORDER BY o.created_at, o.id',
                    (op_id, op['reconcile_epoch'])).fetchall():
                probes[str(p['host_id'])] = p          # the latest per host
            asked = False
            for host in hosts:
                p = probes.get(host)
                if p is None or p['state'] == 'FAILED':
                    self.store._dispatch(c, 'Agent.Query', tenant_id=op['tenant_id'],
                                         environment_id=op['environment_id'], params={'op_id': op_id},
                                         hosts={'any': host}, idempotency_key='probe:%s' % uuid.uuid4(),
                                         reconciles=op_id, epoch=op['reconcile_epoch'])
                    asked = True
            if asked or any(probes[h]['state'] != 'COMPLETED' for h in hosts):
                return 'probing'

            journals = {h: (probes[h]['observed'] or {}).get('journal') or [] for h in hosts}
            verdict, seq, code, newly_done = decide(steps, op['fencing_token'], journals)
            for s, row in newly_done:
                c.execute("UPDATE operation_step SET state = 'done', evidence_sha256 = %s, observed = %s, "
                          'updated_at = %s WHERE operation_id = %s AND seq = %s',
                          (row.get('evidence_sha256'), Jsonb({'reconciled': row}), _ts(now), op_id, s['seq']))
            if verdict == 'completed':
                self.store._set_op(c, op, 'VERIFIED', now)
                self.store._set_op(c, op, 'COMPLETED', now, code='OK', finished=True)
            elif verdict == 'applying':
                c.execute("UPDATE operation_step SET state = 'applying', updated_at = %s "
                          'WHERE operation_id = %s AND seq = %s', (_ts(now), op_id, seq))
                self.store._set_op(c, op, 'APPLYING', now, lease=now + self.store.liveness)
            elif verdict == 'failed':
                c.execute("UPDATE operation_step SET state = 'failed', updated_at = %s "
                          'WHERE operation_id = %s AND seq = %s', (_ts(now), op_id, seq))
                self.store._set_op(c, op, 'FAILED', now, code=code, detail={'reconciled': True}, finished=True)
            elif op['attempt'] >= self.max_attempts:
                self._fail(c, op, 'RECONCILE_LIMIT', {'attempts': op['attempt'], 'step': seq}, now, 'sev3',
                           '%s did not finish after %d dispatches' % (op['type'], op['attempt']))
                return 'limit'
            else:
                self._redispatch(c, op, steps[seq], now)
            return verdict

    def _redispatch(self, c, op, step, now):
        token = c.execute("SELECT nextval('fencing_token_seq') AS t").fetchone()['t']
        c.execute("UPDATE operation_step SET state = 'dispatched', attempt = 1, updated_at = %s "
                  'WHERE operation_id = %s AND seq = %s', (_ts(now), op['id'], step['seq']))
        c.execute("UPDATE operation_step SET state = 'pending', attempt = 0 "
                  'WHERE operation_id = %s AND seq > %s', (op['id'], step['seq']))
        c.execute('UPDATE operation SET fencing_token = %s, attempt = attempt + 1 WHERE id = %s', (token, op['id']))
        self.store._event(c, op['id'], step['seq'], step['host_id'], token, now)
        self.store._set_op(c, op, 'DISPATCHED', now, lease=now + self.store.liveness)

    def _fail(self, c, op, code, detail, now, severity, summary):
        self.store._set_op(c, op, 'FAILED', now, code=code, detail=detail, finished=True)
        c.execute('INSERT INTO incident (id, severity, scope_tenant_ids, operation_id, summary, runbook_ref, '
                  'opened_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                  (uuid.uuid4(), severity, [op['tenant_id']] if op['tenant_id'] else [], op['id'], summary,
                   'DOC-07', _ts(now)))
