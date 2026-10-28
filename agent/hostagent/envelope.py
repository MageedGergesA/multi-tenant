"""Request verification (DOC-04 §3 verification order, §4 local policy).

schema version → host_id → time → dispatch signature → nonce → fencing token →
parameter schema → release and approval signatures → local policy.
The first failure raises `Rejected`; nothing has been decrypted at that point.
"""
import base64
from dataclasses import dataclass
from datetime import datetime

import jsonschema

from . import ops
from .canonical import sha256_hex, verify, without
from .config import AgentConfig
from .naming import sid as derive_sid
from .state import Rejected, State

FINAL_BACKUP_MAX_AGE = 3600     # DOC-03 DR-06: a recoverable backup less than 1 hour old


class Duplicate(Exception):
    """A signed envelope for a step that already finished: at-least-once delivery
    from ctl-1 (DOC-03 §2.5). Carries the stored response."""

    def __init__(self, response: dict):
        super().__init__('duplicate')
        self.response = response


@dataclass
class Verified:
    env: dict
    spec: ops.OpSpec
    scope_id: str
    breakglass_used: bool = False


def request_sha256(env) -> str:
    """What a redelivery repeats: everything but nonce, times, secrets (re-sealed
    each time) and the signature. Same op, token and step with other content
    (another tenant, other params) is a different request."""
    return sha256_hex({k: v for k, v in env.items()
                       if k not in ('nonce', 'issued_at', 'expires_at', 'secrets', 'dispatch_signature')})


def _valid(schema, value) -> bool:
    try:
        jsonschema.validate(value, schema)
        return True
    except jsonschema.ValidationError:
        return False


def _ts(text: str) -> float:
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise Rejected('SCHEMA', 'bad timestamp')
    if parsed.tzinfo is None:
        raise Rejected('SCHEMA', 'timestamp without zone')
    return parsed.timestamp()


class Verifier:
    def __init__(self, config: AgentConfig, state: State, capacity=None):
        self.config = config
        self.state = state
        # capacity(params) -> bool: True if the request fits above reserve_pct.
        self.capacity = capacity

    def verify(self, env, now: float) -> Verified:
        c = self.config
        # 1. schema version (and envelope shape)
        if not isinstance(env, dict) or env.get('v') not in ops.ENVELOPE_VERSIONS:
            raise Rejected('SCHEMA', 'envelope version')
        if not _valid(ops.ENVELOPE, env):
            raise Rejected('SCHEMA', 'envelope')
        spec = ops.CATALOG.get(env['op_type'])
        if spec is None or env['step'] not in spec.steps:
            raise Rejected('SCHEMA', 'op_type/step')
        # 2. host
        if env['host_id'] != c.host_id:
            raise Rejected('POLICY_HOST')
        # 3. time
        issued, expires = _ts(env['issued_at']), _ts(env['expires_at'])
        if expires <= issued or expires - issued > c.max_envelope_life:
            raise Rejected('EXPIRED', 'lifetime')
        if issued > now + c.max_clock_skew or now > expires + c.max_clock_skew:
            raise Rejected('EXPIRED')
        # 4. dispatch signature
        if verify(without(env, 'dispatch_signature'), env['dispatch_signature'], list(c.trust.dispatch)) is None:
            raise Rejected('SIG_INVALID')
        # 5. nonce. Either way a finished step never runs twice; ctl-1's
        # at-least-once redelivery (DOC-03 §2.5) gets the stored response queued
        # again: alongside REPLAY for the same envelope (DOC-04 §11), or as the
        # reply to a re-signed one with the same (op_id, fencing_token, step).
        stored = None if env['op_type'] == 'Agent.Query' else \
            self.state.finished_response(env['op_id'], env['fencing_token'], env['step'], request_sha256(env))
        if not self.state.record_nonce(env['nonce'], c.nonce_ttl, now):
            if stored is not None:
                self.state.store_response(stored, now, request_sha256(env))
            raise Rejected('REPLAY')
        if stored is not None:
            raise Duplicate(stored)
        # 6. fencing token (re-checked atomically at admission)
        scope_id = c.host_id if spec.host_scoped else env['environment_id']
        if env['op_type'] in ('Tenant.RestoreToIsolated', 'RestoreCopy.Expire'):
            # Fenced on the copy, so a drill never blocks the production environment.
            key = 'target_environment_id' if env['op_type'] == 'Tenant.RestoreToIsolated' else 'environment_id'
            target = env['params'].get(key)
            if not isinstance(target, str) or not _valid(ops.UUID, target):
                raise Rejected('SCHEMA', key)
            scope_id = target
        fenced = env['op_type'] != 'Agent.Query'
        if fenced and scope_id is None:
            raise Rejected('SCHEMA', 'environment_id required')
        if fenced and not State.fence_ok(env['fencing_token'], env['op_id'], self.state.high_water(scope_id)):
            raise Rejected('STALE_FENCE')
        # 7. parameter schema
        if not _valid(ops.PARAMS[env['op_type']], env['params']):
            raise Rejected('SCHEMA', 'params')
        # 8. release manifest and approval
        if spec.release:
            self._check_release(env)
        breakglass = False
        if spec.custodian or (env['op_type'] == 'Host.Drain' and env['params']['evacuate']):
            breakglass = self._check_approval(env, now)
        # 9. local policy
        self._policy(env, spec, now)
        return Verified(env=env, spec=spec, scope_id=scope_id, breakglass_used=breakglass)

    def _check_release(self, env):
        manifest = env['release_manifest']
        if manifest is None or not _valid(ops.RELEASE_MANIFEST, manifest):
            raise Rejected('POLICY_RELEASE', 'manifest missing or malformed')
        if verify(without(manifest, 'release_signature'), manifest['release_signature'],
                  [self.config.trust.release]) is None:
            raise Rejected('POLICY_RELEASE', 'signature')
        if manifest['cell'] not in self.config.allowed_cells:
            raise Rejected('POLICY_CELL')
        params = env['params']
        target = params.get('target_digest')
        if target is not None and target != manifest['image_digest']:
            raise Rejected('POLICY_RELEASE', 'digest not in manifest')
        modules = params.get('modules') or []
        if not set(modules) <= set(manifest['module_versions']):
            raise Rejected('POLICY_MODULES')
        if env['op_type'] == 'Tenant.ApplyPatch' and manifest['change_class'] != 'patch':
            raise Rejected('POLICY_RELEASE', 'not a patch')

    def _check_approval(self, env, now) -> bool:
        approval = env['approval']
        if approval is None or not _valid(ops.APPROVAL, approval):
            raise Rejected('POLICY_APPROVAL', 'missing')
        if (approval['op_id'] != env['op_id'] or approval['tenant_id'] != env['tenant_id']
                or approval['action'] != env['op_type'] or _ts(approval['expires_at']) < now):
            raise Rejected('POLICY_APPROVAL', 'mismatch')
        if env['op_type'] == 'Tenant.Delete' and approval.get('deletion_case_id') != env['params']['deletion_case_id']:
            raise Rejected('POLICY_APPROVAL', 'deletion case')
        trust = self.config.trust
        body = without(approval, 'custodian_signature')
        if verify(body, approval['custodian_signature'], list(trust.custodian)):
            return False
        if trust.breakglass_enabled and trust.breakglass and verify(body, approval['custodian_signature'],
                                                                     [trust.breakglass]):
            return True
        raise Rejected('POLICY_APPROVAL', 'signature')

    def _policy(self, env, spec, now):
        c = self.config
        role = ops.step_role(env['step'])
        if role not in (c.role, 'any'):
            raise Rejected('POLICY_ROLE')
        if spec.states is not None:
            if env['tenant_id'] is None or env['tenant_state'] not in spec.states:
                raise Rejected('POLICY_STATE')
        op_type = env['op_type']
        if op_type in ('Tenant.Create', 'Tenant.Relocate', 'Tenant.RestoreToIsolated') \
                and self.state.flag('draining') == '1':
            raise Rejected('POLICY_DRAINING')
        if op_type == 'Tenant.Create':
            self._policy_create(env)
        elif op_type == 'Tenant.RestoreToIsolated':
            # The source may live on another host; the step checks the backup
            # manifest's tenant instead (DOC-04 §6.9). The copy must not belong to
            # anyone else, and production can't be a restore target.
            if env['params']['target_environment_id'] == env['environment_id']:
                raise Rejected('POLICY_KIND')
            target = self.state.environment(env['params']['target_environment_id'])
            if target and (target['kind'] != 'restore_copy' or target['deleted_at'] is not None):
                raise Rejected('POLICY_KIND')
            if target and target['tenant_id'] != env['tenant_id']:
                raise Rejected('NOT_OWNER')
        elif op_type == 'RestoreCopy.Expire':
            # No row: this agent never created anything for it (the steps register
            # first), so the step has nothing to remove. A retry passes the tombstone.
            copy = self.state.environment(env['params']['environment_id'])
            if copy is not None:
                if copy['tenant_id'] != env['tenant_id']:
                    raise Rejected('NOT_OWNER')
                if copy['kind'] != 'restore_copy':
                    raise Rejected('POLICY_KIND')
        elif op_type == 'Tenant.Delete':
            self._policy_delete(env, now)
        elif op_type == 'Host.RotateTrust':
            self._policy_trust(env)
        elif env['environment_id'] is not None and op_type not in ('Agent.Query', 'Host.Drain'):
            self._owned(env['environment_id'], env['tenant_id'])
        if op_type in ('Tenant.Create', 'Tenant.RestoreToIsolated', 'Tenant.Relocate') and role == 'app' \
                and self.capacity is not None and not self.capacity(env['params']):
            raise Rejected('CAPACITY')

    def _policy_trust(self, env):
        """DOC-04 §2: new pinned keys need the release key's signature as well as
        the dispatch key's on this envelope. Never older, and never without the
        dispatch key that signs this very request, or the host is locked out."""
        new = self.new_trust(env)
        if new.version <= self.config.trust.version:
            raise Rejected('POLICY_TRUST', 'not newer')
        signer = verify(without(env, 'dispatch_signature'), env['dispatch_signature'], list(self.config.trust.dispatch))
        if bytes(signer) not in {bytes(k) for k in new.dispatch}:
            raise Rejected('POLICY_TRUST', 'drops the signing dispatch key')

    def new_trust(self, env):
        from .enroll import EnrollError, trust_from
        c = self.config
        try:
            return trust_from(env['params']['trust_document'], base64.b64encode(bytes(c.trust.release)).decode(),
                              c.host_id, c.role)
        except EnrollError as e:
            raise Rejected('POLICY_TRUST', str(e)) from None

    def _owned(self, environment_id, tenant_id, deleted_ok=False) -> dict:
        reg = self.state.environment(environment_id)
        if reg is None or reg['tenant_id'] != tenant_id:
            raise Rejected('NOT_OWNER')
        if reg['deleted_at'] is not None and not deleted_ok:
            raise Rejected('POLICY_STATE', 'deleted')
        return reg

    def _policy_delete(self, env, now):
        reg = self._owned(env['environment_id'], env['tenant_id'], deleted_ok=True)
        if reg['kind'] != 'production':
            raise Rejected('POLICY_KIND')      # copies go through RestoreCopy.Expire
        if reg['deleted_at'] is not None:
            return                             # a retry: the step re-checks that everything is gone
        # Copies hold the tenant's data too: they are expired first.
        if self.state.live_copies(env['tenant_id']):
            raise Rejected('POLICY_STATE', 'restore copies outstanding')
        if self.config.role != 'app':
            return
        # DOC-04 §6.13: the journal must hold the Stop or Suspend; DOC-03 DR-06: the final backup.
        if self.state.last_lifecycle_step(env['environment_id']) not in ('app.stop', 'app.suspend'):
            raise Rejected('POLICY_STATE', 'runtime not stopped')
        if not self.state.backup_since(env['environment_id'], now - FINAL_BACKUP_MAX_AGE):
            raise Rejected('POLICY_STATE', 'no backup in the last hour')

    def _policy_create(self, env):
        reg = self.state.environment(env['environment_id'])
        if reg is not None and reg['tenant_id'] != env['tenant_id']:
            raise Rejected('NOT_OWNER')
        if reg is not None and reg['deleted_at'] is not None:
            raise Rejected('POLICY_STATE', 'deleted')
        if self.config.role != 'app':
            return
        slot = env['params']['runtime_slot']
        low, high = self.config.port_range
        ports = (slot['http_port'], slot['gevent_port'])
        if ports[0] == ports[1] or not all(low <= p <= high for p in ports):
            raise Rejected('POLICY_PORT')
        if self.state.slot_conflict(env['environment_id'], slot['container_uid'], ports):
            raise Rejected('POLICY_SLOT')
        if slot['limit_memory_soft'] > slot['limit_memory_hard']:
            raise Rejected('SCHEMA', 'memory limits')
        # The sid must be unique on the host too (12 hex chars of the uuid).
        clash = self.state.sid_owner(derive_sid(env['environment_id']))
        if clash and clash != env['environment_id']:
            raise Rejected('POLICY_SLOT', 'sid collision')
