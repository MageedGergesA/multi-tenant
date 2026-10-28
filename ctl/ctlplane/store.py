"""Operations, the outbox and agent responses in ctl-1's PostgreSQL (DOC-03 §2.5, §6).

`dispatch` writes an operation, its steps and the first step's event in one
transaction. `claim` hands a host its pending events as signed envelopes.
`apply` takes one signed agent response and moves the operation on: next step,
COMPLETED, FAILED, RECONCILING, or a retry of the same step.
"""
import base64
import secrets
import time
import uuid
from datetime import datetime, timezone

import psycopg
from nacl.signing import SigningKey, VerifyKey
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import catalog
from .canonical import sha256_hex, sign, verify, without
from .vault import SOURCES, Unavailable

POLLING_HOST_STATES = ('provisioning', 'active', 'draining', 'maintenance')
IN_FLIGHT = ('DISPATCHED', 'APPLYING')
RETRY_CODES = ('BUSY', 'RATE_LIMITED', 'EXPIRED')   # the agent didn't run the step: send it again
RECONCILE_CODES = ('TIMEOUT', 'STALE_FENCE')        # outcome unknown: read back before anything else
MAX_RETRIES = 5


class _Undeliverable(Exception):
    def __init__(self, code, detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


class Conflict(Exception):
    """INV-21: another exclusive operation is in flight on this environment."""


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _ts(value) -> datetime:
    return datetime.fromtimestamp(value, timezone.utc)


class Store:
    def __init__(self, dsn: str, dispatch_key: SigningKey, *, role: str | None = 'ctl_dispatcher', vault=None,
                 liveness: float = 150, envelope_life: int = 300, clock=time.time):
        self.dsn = dsn
        self.role = role        # ctl_dispatcher hands out envelopes; the operator API runs as ctl_app
        self.key = dispatch_key
        self.vault = vault      # the dispatcher's age identity (vault.Vault); None: no step with secrets
        self.liveness = liveness            # lease before the first heartbeat, and per heartbeat
        self.envelope_life = envelope_life  # the agent accepts at most 600 s
        self.clock = clock

    def connect(self):
        conn = psycopg.connect(self.dsn, row_factory=dict_row)
        if self.role:
            conn.execute('SET ROLE %s' % self.role)   # constant, not input
            conn.commit()
        return conn

    # -- hosts --------------------------------------------------------------
    def host_may_poll(self, host_id: str, cert_sha256: str | None) -> bool:
        if not cert_sha256:
            return False
        with self.connect() as c:
            row = c.execute('UPDATE host SET last_seen_at = %s WHERE id = %s AND state = ANY(%s) '
                            'AND client_cert_sha256 = %s RETURNING id',
                            (_ts(self.clock()), host_id, list(POLLING_HOST_STATES), cert_sha256)).fetchone()
        return row is not None

    def _agent_key(self, c, host_id) -> VerifyKey | None:
        row = c.execute('SELECT k.public_key FROM host h JOIN signing_key k ON k.id = h.agent_key_id '
                        "WHERE h.id = %s AND k.purpose = 'agent' AND k.retired_at IS NULL", (host_id,)).fetchone()
        return VerifyKey(base64.b64decode(row['public_key'])) if row else None

    # -- dispatch -------------------------------------------------------------
    def dispatch(self, op_type: str, **kw) -> str:
        """REQUESTED → DISPATCHED for an operation that has passed schema, authz,
        precondition and capacity checks (the API layer; not built yet).
        `hosts` maps a step role (`app`, `db`, `mail`, `any`) to its host."""
        with self.connect() as c:
            return self._dispatch(c, op_type, **kw)

    def _dispatch(self, c, op_type: str, *, tenant_id, environment_id, params: dict, hosts: dict,
                  idempotency_key: str, op_id: str | None = None, reconciles: str | None = None,
                  epoch: int = 0) -> str:
        steps = catalog.STEPS[op_type]
        op_id = op_id or str(uuid.uuid4())
        now = _ts(self.clock())
        try:
            with c.transaction():
                row = c.execute(
                    'INSERT INTO operation (id, type, tenant_id, environment_id, host_id, idempotency_key, params, '
                    'params_sha256, state, exclusive, fencing_token, lease_expires_at, created_at, updated_at, '
                    "reconciles_operation_id, reconcile_epoch) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'DISPATCHED', "
                    "%s, nextval('fencing_token_seq'), %s, %s, %s, %s, %s) "
                    'ON CONFLICT (tenant_id, type, idempotency_key) DO NOTHING RETURNING id, fencing_token',
                    (op_id, op_type, tenant_id, environment_id, hosts[catalog.step_role(steps[0])], idempotency_key,
                     Jsonb(params), bytes.fromhex(sha256_hex(params)), op_type not in catalog.NOT_EXCLUSIVE,
                     _ts(self.clock() + self.liveness), now, now, reconciles, epoch)).fetchone()
        except psycopg.errors.UniqueViolation:
            raise Conflict(environment_id) from None
        if row is None:     # idempotency key seen: the existing operation, nothing new
            return str(c.execute('SELECT id FROM operation WHERE tenant_id IS NOT DISTINCT FROM %s AND type = %s '
                                 'AND idempotency_key = %s', (tenant_id, op_type, idempotency_key)).fetchone()['id'])
        self._steps(c, op_id, steps, hosts, row['fencing_token'])
        return op_id

    def _steps(self, c, op_id, steps, hosts, token):
        now = _ts(self.clock())
        for seq, step in enumerate(steps):
            c.execute('INSERT INTO operation_step (operation_id, seq, name, host_id, state, attempt, updated_at) '
                      'VALUES (%s, %s, %s, %s, %s, %s, %s)',
                      (op_id, seq, step, hosts[catalog.step_role(step)],
                       'dispatched' if seq == 0 else 'pending', 1 if seq == 0 else 0, now))
        self._event(c, op_id, 0, hosts[catalog.step_role(steps[0])], token, self.clock())

    def launch(self, c, op_id: str, op_type: str, hosts: dict):
        """RESERVED → DISPATCHED for an operation admitted through the API
        (admission.py): token, steps, the first event, the lease."""
        now = self.clock()
        steps = catalog.STEPS[op_type]
        token = c.execute("UPDATE operation SET state = 'DISPATCHED', fencing_token = nextval('fencing_token_seq'), "
                          'host_id = %s, lease_expires_at = %s, updated_at = %s, row_version = row_version + 1 '
                          "WHERE id = %s AND state = 'RESERVED' RETURNING fencing_token",
                          (hosts[catalog.step_role(steps[0])], _ts(now + self.liveness), _ts(now), op_id)
                          ).fetchone()['fencing_token']
        self._steps(c, op_id, steps, hosts, token)

    def _event(self, c, op_id, seq, host_id, token, not_before):
        c.execute('INSERT INTO operation_event (operation_id, seq, host_id, fencing_token, not_before) '
                  'VALUES (%s, %s, %s, %s, %s)', (op_id, seq, host_id, token, _ts(not_before)))

    # -- polling ------------------------------------------------------------
    def claim(self, host_id: str, capacity: int) -> list[dict]:
        """Hand out up to `capacity` due events for this host, each once, as
        envelopes signed now. Claiming is inserting the delivery row, so two
        concurrent polls never get the same event."""
        now = self.clock()
        out = []
        with self.connect() as c:
            rows = c.execute(
                'SELECT e.id, e.operation_id, s.name AS step, s.seq, e.fencing_token, o.type, o.tenant_id, '
                'o.environment_id, o.params, o.approval, t.lifecycle_state, r.manifest AS release_manifest, '
                'r.status AS release_status '
                'FROM operation_event e '
                'JOIN operation o ON o.id = e.operation_id '
                'JOIN operation_step s ON s.operation_id = e.operation_id AND s.seq = e.seq '
                'LEFT JOIN tenant t ON t.id = o.tenant_id '
                'LEFT JOIN image_release r ON r.id = o.image_release_id '
                'WHERE e.host_id = %s AND e.not_before <= %s AND o.state = ANY(%s) '
                "AND e.fencing_token = o.fencing_token AND s.state = 'dispatched' "
                'AND NOT EXISTS (SELECT 1 FROM operation_event_delivery d WHERE d.event_id = e.id) '
                'ORDER BY e.id LIMIT %s', (host_id, _ts(now), list(IN_FLIGHT), capacity)).fetchall()
            host = c.execute('SELECT age_recipient, region_id FROM host WHERE id = %s', (host_id,)).fetchone() \
                if rows else None
            for r in rows:
                nonce = secrets.token_hex(16)
                if c.execute('INSERT INTO operation_event_delivery (event_id, delivered_at, nonce) '
                             'VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING event_id',
                             (r['id'], _ts(now), nonce)).fetchone() is None:
                    continue
                op = {'id': r['operation_id'], 'type': r['type'], 'environment_id': r['environment_id'],
                      'params': r['params']}
                try:
                    if r['release_manifest'] is not None and r['release_status'] != 'approved':
                        raise _Undeliverable('RELEASE_REVOKED', {'status': r['release_status']})
                    try:
                        sealed = self._seal(c, op, r['step'], host)
                    except Unavailable as u:
                        raise _Undeliverable('SECRET_UNAVAILABLE', {'secret': str(u)}) from None
                except _Undeliverable as x:
                    # Nothing the agent could run: a known outcome, not a retry.
                    c.execute("UPDATE operation_step SET state = 'failed', updated_at = %s "
                              'WHERE operation_id = %s AND seq = %s', (_ts(now), r['operation_id'], r['seq']))
                    self._set_op(c, op, 'FAILED', now, code=x.code, detail=x.detail, finished=True)
                    continue
                # The lease runs from hand-out, not from dispatch.
                c.execute('UPDATE operation SET lease_expires_at = %s, updated_at = %s, '
                          'row_version = row_version + 1 WHERE id = %s',
                          (_ts(now + self.liveness), _ts(now), r['operation_id']))
                env = {
                    'v': 1, 'op_id': str(r['operation_id']), 'op_type': r['type'], 'step': r['step'],
                    'host_id': host_id,
                    'tenant_id': str(r['tenant_id']) if r['tenant_id'] else None,
                    'environment_id': str(r['environment_id']) if r['environment_id'] else None,
                    'tenant_state': r['lifecycle_state'], 'fencing_token': r['fencing_token'],
                    'issued_at': _iso(now), 'expires_at': _iso(now + self.envelope_life), 'nonce': nonce,
                    'params': r['params'], 'secrets': sealed, 'release_manifest': r['release_manifest'],
                    'approval': r['approval'],
                }
                env['dispatch_signature'] = sign(env, self.key)
                out.append(env)
        return out

    def _seal(self, c, op, step, host):
        if (op['type'], step) not in SOURCES:
            return None
        if self.vault is None:
            raise Unavailable('dispatcher identity')
        return self.vault.envelope_secrets(c, op, step, host)

    # -- responses ------------------------------------------------------------
    def apply(self, host_id: str, resp) -> str:
        """Record one response from `host_id` and act on it. Returns the outcome,
        which is also stored with the response."""
        if not isinstance(resp, dict) or not isinstance(resp.get('agent_signature'), str):
            return 'malformed'
        try:
            digest = sha256_hex(resp)
        except Exception:      # not canonicalisable (floats out of range, huge ints)
            return 'malformed'
        try:
            with self.connect() as c:
                outcome = self._apply(c, host_id, resp)
                c.execute('INSERT INTO agent_response (host_id, response_sha256, op_id, step, fencing_token, '
                          'status, code, body, outcome, received_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                          (host_id, digest, _uuid_or_none(resp.get('op_id')) if outcome != 'bad_signature' else None,
                           _short(resp.get('step')), _int_or_none(resp.get('fencing_token')),
                           _short(resp.get('status')), _short(resp.get('code')), Jsonb(resp), outcome,
                           _ts(self.clock())))
            return outcome
        except psycopg.errors.UniqueViolation:
            return 'duplicate'      # delivered before: rolled back, nothing applied twice

    def _apply(self, c, host_id, resp) -> str:
        key = self._agent_key(c, host_id)
        if key is None or not verify(without(resp, 'agent_signature'), resp['agent_signature'], key):
            return 'bad_signature'
        if resp.get('host_id') != host_id:
            return 'wrong_host'
        if resp.get('evidence_sha256') != sha256_hex(resp.get('observed')):
            return 'bad_evidence'
        c.execute('UPDATE host SET agent_high_water_fence = GREATEST(agent_high_water_fence, %s) WHERE id = %s',
                  (_int_or_none(resp.get('agent_high_water')) or 0, host_id))
        op_id = _uuid_or_none(resp.get('op_id'))
        op = op_id and c.execute('SELECT * FROM operation WHERE id = %s FOR UPDATE', (op_id,)).fetchone()
        if not op:
            return 'unknown_op'
        step = c.execute("SELECT * FROM operation_step WHERE operation_id = %s AND state IN ('dispatched', 'applying') "
                         'ORDER BY seq LIMIT 1', (op_id,)).fetchone()
        if step is None or str(step['host_id']) != host_id:
            # Signed by this host, about a step it doesn't own: never acted on.
            return 'wrong_host' if step is not None and resp.get('step') == step['name'] else 'stale'
        if resp.get('fencing_token') != op['fencing_token'] or resp.get('step') != step['name']:
            return 'stale'
        status, code = resp.get('status'), resp.get('code')
        now = self.clock()
        if op['state'] == 'RECONCILING' and status != 'done':
            return 'ignored'    # only a result settles a reconciling operation
        if op['state'] not in IN_FLIGHT + ('RECONCILING',):
            return 'stale'

        if status == 'in_progress':
            return self._heartbeat(c, op, step, resp, now)
        if status == 'done' and code == 'OK':
            return self._done(c, op, step, resp, now)
        if code in RETRY_CODES:
            return self._retry(c, op, step, code, now)
        if code == 'REPLAY':
            return 'replay'     # the agent re-queues the original response as well
        self._set_step(c, op, step, 'failed', resp)
        if code in RECONCILE_CODES and op['type'] != 'Agent.Query':   # a probe is never itself reconciled
            self._set_op(c, op, 'RECONCILING', now, code=code, detail=resp.get('observed'))
            return 'reconciling'
        self._set_op(c, op, 'FAILED', now, code=code, detail=resp.get('observed'), finished=True)
        return 'failed'

    def _heartbeat(self, c, op, step, resp, now) -> str:
        deadline = _parse_iso((resp.get('observed') or {}).get('deadline_at'))
        cap = deadline + catalog.margin(step['name']) if deadline else now + self.liveness
        lease = min(now + self.liveness, cap)
        c.execute("UPDATE operation_step SET state = 'applying', deadline_at = %s, updated_at = %s "
                  'WHERE operation_id = %s AND seq = %s',
                  (_ts(deadline) if deadline else None, _ts(now), op['id'], step['seq']))
        # Never shortened, never past the agent's deadline plus the §8 margin.
        c.execute("UPDATE operation SET state = 'APPLYING', lease_expires_at = GREATEST(lease_expires_at, %s), "
                  'updated_at = %s, row_version = row_version + 1 WHERE id = %s',
                  (_ts(lease), _ts(now), op['id']))
        return 'heartbeat'

    def _done(self, c, op, step, resp, now) -> str:
        self._set_step(c, op, step, 'done', resp)
        nxt = c.execute('SELECT * FROM operation_step WHERE operation_id = %s AND seq = %s',
                        (op['id'], step['seq'] + 1)).fetchone()
        if nxt is None:
            # VERIFIED → COMPLETED: the control-plane checks of DOC-03 §6 go here.
            if op['type'] == 'Tenant.Backup':
                self._backup_point(c, op, resp.get('observed') or {}, now)
            if op['type'] in ('Tenant.ApplyPatch', 'Tenant.ModuleUpdate') and op['image_release_id']:
                c.execute('UPDATE environment SET image_release_id = %s, row_version = row_version + 1 '
                          'WHERE id = %s', (op['image_release_id'], op['environment_id']))
            self._set_op(c, op, 'VERIFIED', now)
            self._set_op(c, op, 'COMPLETED', now, code='OK', finished=True)
            return 'completed'
        c.execute("UPDATE operation_step SET state = 'dispatched', attempt = 1, updated_at = %s "
                  'WHERE operation_id = %s AND seq = %s', (_ts(now), op['id'], nxt['seq']))
        self._event(c, op['id'], nxt['seq'], nxt['host_id'], op['fencing_token'], now)
        self._set_op(c, op, 'DISPATCHED', now, lease=now + self.liveness)
        return 'next_step'

    def _backup_point(self, c, op, seen, now):
        """DOC-03 §7 from the agent's evidence. RECOVERABLE needs zero missing
        files, the guard held, and the lock read back covering the planned
        retention (INV-16). A re-run that found the archive already stored
        reports no snapshot; the point from the first run stands."""
        p = op['params']
        if seen.get('already_stored'):
            return
        lock_until = _parse_iso(seen.get('lock_until'))
        planned = op['created_at'].timestamp() + p['lock_days'] * 86400
        ok = (seen.get('missing_files') == 0 and seen.get('gc_guard_held') is True and seen.get('archive_sha256')
              and lock_until is not None and lock_until >= planned - 60 and _parse_iso(seen.get('snapshot_time')))
        snapshot = _parse_iso(seen.get('snapshot_time'))
        c.execute('INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, '
                  'gc_guard_held, referenced_files, missing_files, db_dump_sha256, archive_sha256, '
                  'object_version_id, lock_until, state, created_at) '
                  "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                  (p['backup_id'], op['environment_id'], op['id'],
                   'scheduled' if op['requested_by'] is None and op['idempotency_key'].startswith('scheduled-backup:')
                   else 'manual', p['retention_tier'],
                   _ts(snapshot) if snapshot else None, seen.get('gc_guard_held') is True,
                   _int_or_none(seen.get('referenced_files')), _int_or_none(seen.get('missing_files')),
                   _short(seen.get('dump_sha256')), _short(seen.get('archive_sha256')),
                   _short(seen.get('object_version_id')), _ts(lock_until) if lock_until else None,
                   'recoverable' if ok else 'failed', _ts(now)))

    def _retry(self, c, op, step, code, now) -> str:
        if step['attempt'] >= MAX_RETRIES:
            self._set_step(c, op, step, 'failed', None)
            self._set_op(c, op, 'FAILED', now, code=code, detail={'attempts': step['attempt']}, finished=True)
            return 'failed'
        delay = min(60, 5 * 2 ** (step['attempt'] - 1))
        c.execute("UPDATE operation_step SET state = 'dispatched', attempt = attempt + 1, updated_at = %s "
                  'WHERE operation_id = %s AND seq = %s', (_ts(now), op['id'], step['seq']))
        # Same token: the agent never accepted the step, and accepts the token again for this op.
        self._event(c, op['id'], step['seq'], step['host_id'], op['fencing_token'], now + delay)
        self._set_op(c, op, 'DISPATCHED', now, lease=now + delay + self.liveness)
        return 'retry'

    def _set_step(self, c, op, step, state, resp):
        c.execute('UPDATE operation_step SET state = %s, evidence_sha256 = %s, observed = %s, updated_at = %s '
                  'WHERE operation_id = %s AND seq = %s',
                  (state, resp and resp.get('evidence_sha256'), Jsonb(resp.get('observed')) if resp else None,
                   _ts(self.clock()), op['id'], step['seq']))

    def _set_op(self, c, op, state, now, *, code=None, detail=None, finished=False, lease=None):
        c.execute('UPDATE operation SET state = %s, result_code = COALESCE(%s, result_code), '
                  'result_detail = COALESCE(%s, result_detail), lease_expires_at = %s, '
                  'finished_at = CASE WHEN %s THEN %s ELSE finished_at END, updated_at = %s, '
                  "reconciling_since = CASE WHEN %s = 'RECONCILING' THEN COALESCE(reconciling_since, %s) END, "
                  "reconcile_epoch = reconcile_epoch + (%s = 'RECONCILING' AND state <> 'RECONCILING')::int, "
                  'row_version = row_version + 1 WHERE id = %s',
                  (state, code, Jsonb(detail) if detail is not None else None,
                   _ts(lease) if lease else None, finished, _ts(now), _ts(now), state, _ts(now), state, op['id']))
        if state in ('COMPLETED', 'FAILED'):
            self._finished(c, op['id'], state, now)

    def _finished(self, c, op_id, state, now):
        """What an operation's end means for capacity and the tenant (DOC-03 §2.3, §5)."""
        from . import capacity
        op = c.execute('SELECT type, tenant_id, environment_id, params FROM operation WHERE id = %s',
                       (op_id,)).fetchone()
        capacity.commit(c, op_id)          # it ran: whatever it made now occupies the host
        gone = None
        if state == 'COMPLETED' and op['type'] == 'Tenant.Delete':
            gone = op['environment_id']
            self._tenant(c, op['tenant_id'], ('DELETION_ELIGIBLE',), 'DELETED', op_id, now)
        elif state == 'COMPLETED' and op['type'] == 'RestoreCopy.Expire':
            gone = op['params']['environment_id']
        elif state == 'COMPLETED' and op['type'] == 'Host.RotateTrust':
            c.execute('UPDATE host SET trust_version = GREATEST(trust_version, %s) '
                      'WHERE id = (SELECT host_id FROM operation WHERE id = %s)',
                      (op['params']['trust_document']['trust_version'], op_id))
        elif op['type'] == 'Tenant.RestoreToIsolated':
            from . import drills
            drills.record(c, op_id, state, now)
        elif op['type'] == 'Tenant.Create':
            # VALIDATING → ACTIVE needs the §3.6 checks; ERROR keeps everything for the operator.
            self._tenant(c, op['tenant_id'], ('PROVISIONING',), 'VALIDATING' if state == 'COMPLETED' else 'ERROR',
                         op_id, now)
        if gone:
            capacity.release_environment(c, gone, now)
            c.execute("UPDATE environment SET observed_state = 'absent', observed_at = %s, "
                      'row_version = row_version + 1 WHERE id = %s', (_ts(now), gone))

    def _tenant(self, c, tenant_id, from_states, to_state, op_id, now):
        from . import audit
        row = c.execute('UPDATE tenant SET lifecycle_state = %s, row_version = row_version + 1 '
                        'WHERE id = %s AND lifecycle_state = ANY(%s) RETURNING id', (to_state, tenant_id,
                                                                                   list(from_states))).fetchone()
        if row:
            audit.append(c, _ts(now), 'tenant.' + to_state.lower(), tenant_id=tenant_id, resource_type='tenant',
                         resource_id=tenant_id, correlation_id=op_id, after={'lifecycle_state': to_state})

    # -- leases -------------------------------------------------------------
    def expire_leases(self) -> list[str]:
        """DISPATCHED/APPLYING past its lease → RECONCILING (DOC-03 §6). A
        read-back probe past its lease just fails; the reconciler sends another."""
        now = _ts(self.clock())
        with self.connect() as c:
            c.execute("UPDATE operation SET state = 'FAILED', result_code = 'LEASE_EXPIRED', lease_expires_at = NULL, "
                      'finished_at = %s, updated_at = %s, row_version = row_version + 1 '
                      "WHERE type = 'Agent.Query' AND state = ANY(%s) AND lease_expires_at < %s",
                      (now, now, list(IN_FLIGHT), now))
            rows = c.execute("UPDATE operation SET state = 'RECONCILING', result_code = 'LEASE_EXPIRED', "
                             'lease_expires_at = NULL, reconciling_since = COALESCE(reconciling_since, %s), '
                             'reconcile_epoch = reconcile_epoch + 1, '
                             'updated_at = %s, row_version = row_version + 1 '
                             'WHERE state = ANY(%s) AND lease_expires_at < %s RETURNING id',
                             (now, now, list(IN_FLIGHT), now)).fetchall()
        return [str(r['id']) for r in rows]


def _uuid_or_none(value):
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _int_or_none(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2 ** 63 else None


def _short(value):
    return value if isinstance(value, str) and len(value) <= 64 else None


def _parse_iso(value):
    try:
        return datetime.fromisoformat(value).timestamp() if isinstance(value, str) else None
    except ValueError:
        return None
