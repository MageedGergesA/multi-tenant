"""REQUESTED → VALIDATED → RESERVED → DISPATCHED (DOC-03 §6, §6.3).

    REQUESTED   stored as asked, with the operator who asked
    VALIDATED   known type ctl-1 can build; params match DOC-04's schema; the
                tenant and environment exist and belong together; INV-21
    (approval)  RestoreProduction and Delete wait in VALIDATED for an approval
                signed by a backup_custodian key (or break-glass, while allowed)
    RESERVED    tenant-state gate and DR-06 recovery point, checked again when
                the approval arrives; capacity reservations come with
                Tenant.Create (not dispatchable yet)
    DISPATCHED  token, steps and first event (store.launch)

Anything that fails ends REJECTED with a code, all in the audit chain.
"""
import base64
import uuid

import jsonschema
import psycopg
from nacl.signing import VerifyKey
from psycopg.types.json import Jsonb

from . import audit, capacity, catalog, vault
from .canonical import sha256_hex, verify, without
from .store import Store, _parse_iso, _ts

APPROVAL_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['op_id', 'tenant_id', 'action', 'expires_at', 'custodian_signature'],
    'properties': {'op_id': {'type': 'string'}, 'tenant_id': {'type': 'string'}, 'action': {'type': 'string'},
                   'expires_at': {'type': 'string', 'maxLength': 40},
                   'deletion_case_id': {'type': ['string', 'null']},
                   'custodian_signature': {'type': 'string', 'maxLength': 128}},
}


def _actor(operator_id) -> str:
    """Requests come from an operator, or from ctl-1 itself (`None`: the expiry scheduler)."""
    return 'operator' if operator_id else 'system'


def _check_schema(schema, params):
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(params), key=lambda e: list(e.path))
    if errors:
        raise Refused('SCHEMA', {'params': '/'.join(map(str, errors[0].path)) or '(root)'})


class Refused(Exception):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


def _uuid(value) -> str | None:
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


class Admission:
    def __init__(self, store: Store, *, recipient: str | None = None, breakglass_enabled: bool = False,
                 placement: dict | None = None):
        self.store = store
        # The rest of the data placement manifest (DOC-03 §2.4): where logs, mail and
        # finance data live; configuration, not per tenant.
        self.placement = placement or {}
        self.recipient = recipient      # the dispatcher's age recipient, for secrets generated here
        self.breakglass_enabled = breakglass_enabled   # only until a backup operator is named (DOC-03 §12.4)

    def _now(self):
        return self.store.clock()

    # -- request ------------------------------------------------------------
    def request(self, operator_id: str, *, op_type, tenant_id=None, environment_id=None, host_id=None,
                params=None, idempotency_key) -> dict:
        now = self._now()
        with self.store.connect() as c:
            existing = c.execute('SELECT * FROM operation WHERE tenant_id IS NOT DISTINCT FROM %s AND type = %s '
                                 'AND idempotency_key = %s', (_uuid(tenant_id), op_type, idempotency_key)).fetchone()
            if existing:
                return existing
            op_id = str(uuid.uuid4())
            params = dict(params) if isinstance(params, dict) else {}
            if op_type == 'Tenant.Backup':
                params['backup_id'] = op_id     # generated here; a caller's value is replaced
            if op_type == 'Host.RotateTrust':      # always the active, release-signed document
                from .trust import active
                doc = active(c)
                params = {'trust_document': doc} if doc else {}
            # Known tenant: stored now, so the idempotency key holds even if this is rejected.
            tenant = _uuid(tenant_id)
            if tenant and not c.execute('SELECT 1 FROM tenant WHERE id = %s', (tenant,)).fetchone():
                tenant = None
            c.execute('INSERT INTO operation (id, type, tenant_id, environment_id, host_id, idempotency_key, params, '
                      "params_sha256, state, exclusive, requested_by, created_at, updated_at) "
                      "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'REQUESTED', %s, %s, %s, %s)",
                      (op_id, op_type, tenant, None, None, idempotency_key, Jsonb(params),
                       bytes.fromhex(sha256_hex(params)), op_type not in catalog.NOT_EXCLUSIVE, operator_id,
                       _ts(now), _ts(now)))
            audit.append(c, _ts(now), 'operation.requested', actor_kind=_actor(operator_id), actor_id=operator_id,
                         resource_type='operation', resource_id=op_id, correlation_id=op_id,
                         after={'type': op_type, 'tenant_id': tenant_id, 'environment_id': environment_id,
                                'host_id': host_id, 'params_sha256': sha256_hex(params)})
            try:
                with c.transaction():
                    self._validate(c, op_id, op_type, tenant_id, environment_id, host_id, params)
                if op_type in catalog.CUSTODIAN:
                    self._set(c, op_id, 'VALIDATED', 'AWAITING_APPROVAL', operator_id)
                else:
                    self._reserve_and_launch(c, op_id, operator_id)
            except Refused as r:
                self._set(c, op_id, 'REJECTED', r.code, operator_id, r.detail, finished=True)
            return self._op(c, op_id)

    def _validate(self, c, op_id, op_type, tenant_id, environment_id, host_id, params):
        if op_type not in catalog.STEPS or op_type in catalog.INTERNAL:
            raise Refused('SCHEMA', {'type': 'unknown'})
        if op_type == 'Host.RotateTrust' and not params:
            raise Refused('NO_TRUST_DOCUMENT')
        missing = catalog.not_supported(op_type)
        if missing:
            raise Refused('NOT_SUPPORTED', {'needs': missing})
        _check_schema(catalog.REQUEST_PARAMS.get(op_type) or catalog.PARAMS[op_type], params)
        if op_type == 'Tenant.Create':
            return self._validate_create(c, op_id, tenant_id, environment_id, host_id)
        if op_type in catalog.HOST_SCOPED:
            if tenant_id is not None or environment_id is not None or _uuid(host_id) is None:
                raise Refused('SCHEMA', {'scope': 'host'})
            host = c.execute('SELECT * FROM host WHERE id = %s', (_uuid(host_id),)).fetchone()
            if host is None:
                raise Refused('NOT_FOUND', {'host_id': host_id})
            if op_type == 'Host.RotateTrust':
                if host['client_cert_sha256'] is None:
                    raise Refused('POLICY_STATE', {'detail': 'not enrolled'})
                if host['trust_version'] >= params['trust_document']['trust_version']:
                    raise Refused('POLICY_STATE', {'detail': 'already on version %d' % host['trust_version']})
            c.execute("UPDATE operation SET host_id = %s, state = 'VALIDATED' WHERE id = %s", (_uuid(host_id), op_id))
            return
        tenant, env = _uuid(tenant_id), _uuid(environment_id)
        if tenant is None or env is None or host_id is not None:
            raise Refused('SCHEMA', {'scope': 'environment'})
        row = c.execute('SELECT e.kind FROM environment e WHERE e.id = %s AND e.tenant_id = %s',
                        (env, tenant)).fetchone()
        if row is None:
            raise Refused('NOT_FOUND', {'environment_id': env})
        if op_type == 'RestoreCopy.Expire':
            copy = c.execute('SELECT kind, tenant_id FROM environment WHERE id = %s',
                             (params['environment_id'],)).fetchone()
            # Unknown here is allowed (cleanup of a copy never registered); another tenant's or production isn't.
            if copy is not None and (str(copy['tenant_id']) != tenant or copy['kind'] != 'restore_copy'):
                raise Refused('POLICY_KIND', {'environment_id': params['environment_id']})
        if op_type == 'Tenant.RestoreToIsolated':
            # FOR SHARE: retention locks the row FOR UPDATE before deleting it (retention.execute).
            backup = c.execute('SELECT b.state, b.environment_id, e.tenant_id FROM backup_point b '
                               'JOIN environment e ON e.id = b.environment_id WHERE b.id = %s FOR SHARE OF b',
                               (params['backup_id'],)).fetchone()
            if backup is None:
                raise Refused('NOT_FOUND', {'backup_id': params['backup_id']})
            if str(backup['tenant_id']) != tenant or str(backup['environment_id']) != env:
                raise Refused('NOT_OWNER', {'backup_id': params['backup_id']})        # INV-17
            if backup['state'] != 'recoverable':
                raise Refused('POLICY_BACKUP', {'state': backup['state']})
        release = self._release(c, op_type, env, params) if op_type in catalog.NEEDS_RELEASE else None
        try:
            with c.transaction():
                c.execute("UPDATE operation SET tenant_id = %s, environment_id = %s, image_release_id = %s, "
                          "state = 'VALIDATED' WHERE id = %s", (tenant, env, release, op_id))
        except psycopg.errors.UniqueViolation:
            raise Refused('BUSY', {'detail': 'another exclusive operation is in flight'}) from None

    def _validate_create(self, c, op_id, tenant_id, environment_id, host_id):
        tenant = _uuid(tenant_id)
        if tenant is None or environment_id is not None or host_id is not None:
            raise Refused('SCHEMA', {'scope': 'tenant'})      # ctl-1 creates the environment
        row = c.execute('SELECT * FROM tenant WHERE id = %s', (tenant,)).fetchone()
        if row is None:
            raise Refused('NOT_FOUND', {'tenant_id': tenant})
        if row['lifecycle_state'] != 'ELIGIBLE':
            raise Refused('POLICY_STATE', {'tenant_state': row['lifecycle_state']})
        if c.execute("SELECT 1 FROM environment WHERE tenant_id = %s AND kind = 'production'", (tenant,)).fetchone():
            raise Refused('POLICY_STATE', {'detail': 'production environment exists'})        # INV-10
        if row['resource_bundle_id'] is None:
            raise Refused('NO_BUNDLE')
        release = c.execute("SELECT r.id FROM image_release r JOIN release_cell l ON l.id = r.release_cell_id "
                            "WHERE r.release_cell_id = %s AND r.status = 'approved' AND l.status = 'available' "
                            'ORDER BY r.created_at DESC LIMIT 1', (row['release_cell_id'],)).fetchone()
        if release is None:
            raise Refused('POLICY_RELEASE', {'detail': 'no approved release in the tenant cell'})
        c.execute("UPDATE operation SET tenant_id = %s, image_release_id = %s, state = 'VALIDATED' WHERE id = %s",
                  (tenant, release['id'], op_id))

    # -- placement (Create, RestoreToIsolated) ------------------------------
    def _allocate(self, c, op, now):
        """Place the new environment, give it a slot, hold capacity on its hosts,
        generate its secrets, and fill in the params DOC-04 wants. Runs inside
        the caller's savepoint: a refusal leaves nothing behind."""
        if self.recipient is None:
            raise Refused('SECRET_UNAVAILABLE', {'secret': 'dispatcher recipient'})
        p = dict(op['params'])
        if op['type'] == 'Tenant.Create':
            bundle = c.execute('SELECT b.* FROM tenant t JOIN resource_bundle b ON b.id = t.resource_bundle_id '
                               'WHERE t.id = %s', (op['tenant_id'],)).fetchone()
            pinned = {}
        else:
            source = c.execute('SELECT * FROM environment WHERE id = %s', (op['environment_id'],)).fetchone()
            bundle = c.execute('SELECT * FROM resource_bundle WHERE id = %s', (source['resource_bundle_id'],)
                               ).fetchone()
            if bundle is None or source['app_host_id'] is None or source['db_host_id'] is None:
                raise Refused('NO_PLACEMENT', {'detail': 'source environment'})
            # The copy runs beside the source: the backup and the region keys are there.
            pinned = {'app_host': source['app_host_id'], 'db_host': source['db_host_id']}
        try:
            app, db = capacity.place(c, bundle, now, **pinned)
        except capacity.NoCapacity:
            raise Refused('CAPACITY') from None
        mail = None
        if op['type'] == 'Tenant.Create':
            mail = c.execute("SELECT id FROM host WHERE role = 'mail' AND state = 'active' AND region_id = %s "
                             'ORDER BY id LIMIT 1', (app['region_id'],)).fetchone()
            if mail is None:
                raise Refused('NO_PLACEMENT', {'roles': ['mail']})
        env = str(uuid.uuid4())
        if op['type'] == 'Tenant.Create':
            c.execute("INSERT INTO environment (id, tenant_id, kind, image_release_id, resource_bundle_id, "
                      "app_host_id, db_host_id, mail_host_id) VALUES (%s, %s, 'production', %s, %s, %s, %s, %s)",
                      (env, op['tenant_id'], op['image_release_id'], bundle['id'], app['id'], db['id'], mail['id']))
            c.execute('UPDATE operation SET environment_id = %s WHERE id = %s', (env, op['id']))
        else:
            c.execute("INSERT INTO environment (id, tenant_id, kind, image_release_id, resource_bundle_id, "
                      "app_host_id, db_host_id, source_backup_id, expires_at) "
                      "VALUES (%s, %s, 'restore_copy', %s, %s, %s, %s, %s, %s)",
                      (env, op['tenant_id'], source['image_release_id'], bundle['id'], app['id'], db['id'],
                       p['backup_id'], _ts(now + catalog.RESTORE_COPY_DAYS * 86400)))
            p['target_environment_id'] = env
            p.setdefault('deep', False)
        try:
            slot = capacity.allocate_slot(c, env, app, bundle, now)
        except capacity.NoCapacity:
            raise Refused('CAPACITY', {'detail': 'no free port pair'}) from None
        app_need, db_need = capacity.needs(bundle)
        capacity.hold(c, op['id'], env, app, app_need, now)
        capacity.hold(c, op['id'], env, db, db_need, now)
        vault.provision(c, env, op['tenant_id'], self.recipient, _ts(now))
        p['runtime_slot'] = slot
        p['app_host_ip'] = str(app['private_ip']) if app['private_ip'] else None
        try:
            _check_schema(catalog.PARAMS[op['type']], p)
        except Refused as r:
            raise Refused('NO_PLACEMENT', r.detail) from None        # e.g. no private IP on the app host
        c.execute('UPDATE operation SET params = %s, params_sha256 = %s WHERE id = %s',
                  (Jsonb(p), bytes.fromhex(sha256_hex(p)), op['id']))
        if op['type'] == 'Tenant.Create':
            c.execute("UPDATE tenant SET lifecycle_state = 'RESERVED', row_version = row_version + 1 WHERE id = %s",
                      (op['tenant_id'],))
            version = c.execute('SELECT COALESCE(MAX(version), 0) + 1 AS v FROM data_placement_manifest '
                                'WHERE tenant_id = %s', (op['tenant_id'],)).fetchone()['v']
            region = c.execute('SELECT backup_bucket FROM region WHERE id = %s', (app['region_id'],)).fetchone()
            c.execute('INSERT INTO data_placement_manifest (id, tenant_id, version, region_id, db_host_id, app_host_id, '
                      'backup_bucket, log_sink, mail_provider, finance_system_location, created_at) '
                      'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                      (uuid.uuid4(), op['tenant_id'], version, app['region_id'], db['id'], app['id'],
                       region['backup_bucket'], self.placement.get('log_sink'), self.placement.get('mail_provider'),
                       self.placement.get('finance_system_location'), _ts(now)))
            audit.append(c, _ts(now), 'tenant.reserved', tenant_id=op['tenant_id'], resource_type='tenant',
                         resource_id=op['tenant_id'], correlation_id=op['id'],
                         after={'app_host_id': str(app['id']), 'db_host_id': str(db['id']),
                                'container_uid': slot['container_uid'], 'http_port': slot['http_port']})

    def _release(self, c, op_type, env, params) -> str:
        """The image release this operation starts (DOC-03 §2.2, DOC-04 §4)."""
        current = c.execute('SELECT r.id, r.release_cell_id, r.status FROM environment e '
                            'JOIN image_release r ON r.id = e.image_release_id WHERE e.id = %s', (env,)).fetchone()
        if current is None:
            raise Refused('POLICY_RELEASE', {'detail': 'environment has no release'})
        if op_type not in catalog.TARGET_RELEASE:
            target = current
        else:
            target = c.execute('SELECT id, release_cell_id, status, change_class, module_versions FROM image_release '
                               'WHERE image_digest = %s', (params['target_digest'],)).fetchone()
            if target is None:
                raise Refused('POLICY_RELEASE', {'detail': 'unknown digest'})
            if target['release_cell_id'] != current['release_cell_id']:
                raise Refused('POLICY_RELEASE', {'detail': 'other cell'})      # a major change isn't a patch
            if target['change_class'] not in catalog.TARGET_RELEASE[op_type]:
                raise Refused('POLICY_RELEASE', {'detail': 'change class %s' % target['change_class']})
            if not set(params.get('modules', ())) <= set(target['module_versions']):
                raise Refused('POLICY_MODULES')
        if target['status'] != 'approved':
            raise Refused('POLICY_RELEASE', {'detail': 'release %s' % target['status']})
        cell = c.execute('SELECT status FROM release_cell WHERE id = %s', (target['release_cell_id'],)).fetchone()
        if cell['status'] != 'available' and op_type in catalog.TARGET_RELEASE:
            raise Refused('POLICY_RELEASE', {'detail': 'cell %s' % cell['status']})
        return target['id']

    def _fill_slot(self, c, op):
        row = c.execute('SELECT s.container_uid, s.http_port, s.gevent_port, s.workers, s.max_cron_threads, '
                        's.db_maxconn, s.limit_memory_soft, s.limit_memory_hard, s.limit_time_cpu, s.limit_time_real, '
                        's.mem_limit_bytes, s.cpu_millis, e.kind FROM runtime_slot s '
                        'JOIN environment e ON e.id = s.environment_id '
                        'WHERE s.environment_id = %s AND s.released_at IS NULL', (op['environment_id'],)).fetchone()
        if row is None:
            raise Refused('NOT_FOUND', {'runtime_slot': str(op['environment_id'])})
        kind = row.pop('kind')
        p = dict(op['params'], runtime_slot=dict(row), smtp='relay' if kind == 'production' else 'sink')
        _check_schema(catalog.PARAMS[op['type']], p)
        c.execute('UPDATE operation SET params = %s, params_sha256 = %s WHERE id = %s',
                  (Jsonb(p), bytes.fromhex(sha256_hex(p)), op['id']))

    def _secrets_ready(self, c, op, hosts):
        """Every secret the steps will need exists: fail now, not at hand-out."""
        from .vault import SOURCES
        for step in catalog.STEPS[op['type']]:
            sources = SOURCES.get((op['type'], step))
            if not sources:
                continue
            host = c.execute('SELECT h.age_recipient, g.b2_write_key_ref, g.restore_key_ref FROM host h '
                             'LEFT JOIN region g ON g.id = h.region_id WHERE h.id = %s',
                             (hosts[catalog.step_role(step)],)).fetchone()
            if not host['age_recipient']:
                raise Refused('SECRET_UNAVAILABLE', {'secret': 'host recipient', 'step': step})
            for name, (scope, kind, _) in sources.items():
                if scope == 'region':
                    ok = kind == 'backup_recipient' or host['b2_write_key_ref' if kind == 'b2_write_key'
                                                            else 'restore_key_ref']
                else:
                    ok = c.execute('SELECT 1 FROM secret_binding WHERE environment_id = %s AND purpose = %s',
                                   (op['environment_id'] if scope == 'env'
                                    else op['params'].get('target_environment_id'), kind)).fetchone()
                if not ok:
                    raise Refused('SECRET_UNAVAILABLE', {'secret': name, 'step': step})

    # -- approval -----------------------------------------------------------
    def approve(self, operator_id: str, op_id: str, approval) -> dict:
        now = self._now()
        with self.store.connect() as c:
            op = c.execute('SELECT * FROM operation WHERE id = %s FOR UPDATE', (_uuid(op_id),)).fetchone()
            if op is None:
                raise Refused('NOT_FOUND')
            if op['state'] != 'VALIDATED' or op['result_code'] != 'AWAITING_APPROVAL':
                raise Refused('STATE', {'state': op['state']})
            try:
                breakglass = self._check_approval(c, op, approval, now)
            except Refused as r:      # kept: a refused approval may be a forgery attempt
                audit.append(c, _ts(now), 'operation.approval_refused', actor_kind='operator', actor_id=operator_id,
                             tenant_id=op['tenant_id'], resource_type='operation', resource_id=op['id'],
                             correlation_id=op['id'], after={'code': r.code, 'detail': r.detail})
                c.commit()
                raise
            c.execute('UPDATE operation SET approval = %s, breakglass_used = %s WHERE id = %s',
                      (Jsonb(approval), breakglass, op['id']))
            audit.append(c, _ts(now), 'operation.breakglass' if breakglass else 'operation.approved',
                         actor_kind='operator', actor_id=operator_id, tenant_id=op['tenant_id'],
                         resource_type='operation', resource_id=op['id'], correlation_id=op['id'],
                         after={'approval_sha256': sha256_hex(approval)})
            if breakglass:      # DOC-04 §2: every use raises a sev2 incident
                c.execute("INSERT INTO incident (id, severity, scope_tenant_ids, operation_id, summary, runbook_ref, "
                          "opened_at) VALUES (%s, 'sev2', %s, %s, %s, 'DOC-07', %s)",
                          (uuid.uuid4(), [op['tenant_id']], op['id'],
                           'break-glass approval for %s' % op['type'], _ts(now)))
            try:
                self._reserve_and_launch(c, str(op['id']), operator_id)
            except Refused as r:
                self._set(c, str(op['id']), 'REJECTED', r.code, operator_id, r.detail, finished=True)
            return self._op(c, str(op['id']))

    def _check_approval(self, c, op, approval, now) -> bool:
        """True if it was signed with the break-glass key."""
        try:
            jsonschema.validate(approval, APPROVAL_SCHEMA)
        except jsonschema.ValidationError:
            raise Refused('POLICY_APPROVAL', {'detail': 'schema'}) from None
        expires = _parse_iso(approval['expires_at'])
        if (approval['op_id'] != str(op['id']) or approval['tenant_id'] != str(op['tenant_id'])
                or approval['action'] != op['type'] or expires is None or expires < now):
            raise Refused('POLICY_APPROVAL', {'detail': 'mismatch'})
        if op['type'] == 'Tenant.Delete' and approval.get('deletion_case_id') != op['params']['deletion_case_id']:
            raise Refused('POLICY_APPROVAL', {'detail': 'deletion case'})
        body = without(approval, 'custodian_signature')
        keys = c.execute("SELECT purpose, public_key FROM signing_key WHERE purpose IN ('custodian', 'breakglass') "
                         'AND retired_at IS NULL').fetchall()
        for k in keys:
            if k['purpose'] == 'custodian' and verify(body, approval['custodian_signature'],
                                                      VerifyKey(base64.b64decode(k['public_key']))):
                return False
        if self.breakglass_enabled:
            for k in keys:
                if k['purpose'] == 'breakglass' and verify(body, approval['custodian_signature'],
                                                           VerifyKey(base64.b64decode(k['public_key']))):
                    return True
        raise Refused('POLICY_APPROVAL', {'detail': 'signature'})

    # -- preconditions, reservation, dispatch -------------------------------
    def _reserve_and_launch(self, c, op_id, operator_id):
        with c.transaction():       # a refusal anywhere below leaves nothing allocated
            self._reserve_and_launch_tx(c, op_id, operator_id)

    def _reserve_and_launch_tx(self, c, op_id, operator_id):
        now = self._now()
        op = self._op(c, op_id)
        if op['type'] in catalog.ALLOCATING:
            self._allocate(c, op, now)
            op = self._op(c, op_id)
        elif op['type'] in catalog.SLOT_FILLED:
            self._fill_slot(c, op)
            op = self._op(c, op_id)
        hosts = self._hosts(c, op)
        self._secrets_ready(c, op, hosts)
        if op['type'] in catalog.TENANT_STATES:
            state = c.execute('SELECT lifecycle_state FROM tenant WHERE id = %s', (op['tenant_id'],)
                              ).fetchone()['lifecycle_state']
            if state not in catalog.TENANT_STATES[op['type']]:
                raise Refused('POLICY_STATE', {'tenant_state': state})
        backup = None
        if op['type'] in catalog.RECOVERY_POINT:
            backup = c.execute("SELECT id FROM backup_point WHERE environment_id = %s AND state = 'recoverable' "
                               'AND snapshot_at >= %s ORDER BY snapshot_at DESC LIMIT 1 FOR SHARE',
                               (op['environment_id'], _ts(now - catalog.RECOVERY_WINDOW))).fetchone()
            if backup is None:
                raise Refused('NO_RECOVERY_POINT', {'window_s': catalog.RECOVERY_WINDOW})
        c.execute("UPDATE operation SET state = 'RESERVED', precondition_backup_id = %s, result_code = NULL, "
                  'updated_at = %s WHERE id = %s', (backup and backup['id'], _ts(now), op_id))
        self.store.launch(c, op_id, op['type'], hosts)
        if op['type'] == 'Tenant.Create':
            c.execute("UPDATE tenant SET lifecycle_state = 'PROVISIONING', row_version = row_version + 1 "
                      'WHERE id = %s', (op['tenant_id'],))
        audit.append(c, _ts(now), 'operation.dispatched', actor_kind=_actor(operator_id), actor_id=operator_id,
                     tenant_id=op['tenant_id'], resource_type='operation', resource_id=op_id, correlation_id=op_id,
                     after={'precondition_backup_id': str(backup['id']) if backup else None})

    def _hosts(self, c, op) -> dict:
        if op['type'] in catalog.HOST_SCOPED:
            return {'any': str(op['host_id'])}
        env = c.execute('SELECT app_host_id, db_host_id, mail_host_id FROM environment WHERE id = %s',
                        (op['environment_id'],)).fetchone()
        hosts = {role: str(env[role + '_host_id']) for role in ('app', 'db', 'mail') if env[role + '_host_id']}
        need = {catalog.step_role(s) for s in catalog.STEPS[op['type']]}
        if not need <= set(hosts):
            raise Refused('NO_PLACEMENT', {'roles': sorted(need - set(hosts))})
        return hosts

    def _set(self, c, op_id, state, code, operator_id, detail=None, finished=False):
        now = _ts(self._now())
        c.execute('UPDATE operation SET state = %s, result_code = %s, result_detail = %s, updated_at = %s, '
                  'finished_at = CASE WHEN %s THEN %s END WHERE id = %s',
                  (state, code, Jsonb(detail) if detail is not None else None, now, finished, now, op_id))
        audit.append(c, now, 'operation.rejected' if state == 'REJECTED' else 'operation.validated',
                     actor_kind=_actor(operator_id), actor_id=operator_id, resource_type='operation', resource_id=op_id,
                     correlation_id=op_id, after={'state': state, 'code': code, 'detail': detail})

    @staticmethod
    def _op(c, op_id):
        return c.execute('SELECT * FROM operation WHERE id = %s', (op_id,)).fetchone()
