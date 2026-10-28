"""Operation catalog (DOC-04 §6) and the JSON Schemas for envelopes and params.

Every step name is `<role>.<name>`; an agent accepts only steps for its own role.
"""
from dataclasses import dataclass

ENVELOPE_VERSIONS = (1,)

UUID = {'type': 'string', 'pattern': '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'}
DIGEST = {'type': 'string', 'pattern': '^sha256:[0-9a-f]{64}$'}
MODULE = {'type': 'string', 'pattern': '^[a-z0-9_]{1,64}$'}
HOSTNAME = {'type': 'string', 'maxLength': 253,
            'pattern': r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$'}
RFC3339 = {'type': 'string', 'maxLength': 40}

TENANT_STATES = ('DRAFT', 'ELIGIBLE', 'RESERVED', 'PROVISIONING', 'VALIDATING', 'ACTIVE', 'MAINTENANCE',
                 'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY', 'DELETION_ELIGIBLE',
                 'DELETED')   # CANCELLING, EXPORT_READY: DOC-03 §9.2, missing from DOC-04
LIVE = ('ACTIVE', 'MAINTENANCE', 'SUSPENSION_NOTICE', 'SUSPENDED')


def obj(props, required=None):
    return {'type': 'object', 'properties': props, 'required': list(required if required is not None else props),
            'additionalProperties': False}


ENVELOPE = obj({
    'v': {'type': 'integer'},
    'op_id': UUID,
    'op_type': {'type': 'string', 'maxLength': 64},
    'step': {'type': 'string', 'maxLength': 64},
    'host_id': UUID,
    'tenant_id': {'anyOf': [UUID, {'type': 'null'}]},
    'environment_id': {'anyOf': [UUID, {'type': 'null'}]},
    # Not in DOC-04 §3's table, but §6.13 needs it ("the control plane sends the state").
    'tenant_state': {'anyOf': [{'enum': list(TENANT_STATES)}, {'type': 'null'}]},
    'fencing_token': {'type': 'integer', 'minimum': 1, 'maximum': 2 ** 53 - 1},
    'issued_at': RFC3339,
    'expires_at': RFC3339,
    'nonce': {'type': 'string', 'pattern': '^[0-9a-f]{32}$'},
    'params': {'type': 'object'},
    'secrets': {'anyOf': [{'type': 'string', 'maxLength': 65536}, {'type': 'null'}]},
    'release_manifest': {'anyOf': [{'type': 'object'}, {'type': 'null'}]},
    'approval': {'anyOf': [{'type': 'object'}, {'type': 'null'}]},
    'dispatch_signature': {'type': 'string', 'maxLength': 128},
})

RELEASE_MANIFEST = obj({
    'cell': {'type': 'string', 'maxLength': 128},
    'repository': {'type': 'string', 'pattern': '^[a-z0-9][a-z0-9._/-]{0,127}$'},
    'image_digest': DIGEST,
    'change_class': {'enum': ['patch', 'module_update', 'major']},
    'addon_manifest_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    'module_versions': {'type': 'object', 'maxProperties': 2000,
                        'propertyNames': MODULE, 'additionalProperties': {'type': 'string', 'maxLength': 32}},
    'release_signature': {'type': 'string', 'maxLength': 128},
})

APPROVAL = obj({
    'op_id': UUID,
    'tenant_id': UUID,
    'action': {'type': 'string', 'maxLength': 64},
    'expires_at': RFC3339,
    'deletion_case_id': {'anyOf': [UUID, {'type': 'null'}]},
    'custodian_signature': {'type': 'string', 'maxLength': 128},
}, required=['op_id', 'tenant_id', 'action', 'expires_at', 'custodian_signature'])

PORT = {'type': 'integer', 'minimum': 1, 'maximum': 65535}  # the host range is a local policy check
RUNTIME_SLOT = obj({
    'container_uid': {'type': 'integer', 'minimum': 10001, 'maximum': 59999},
    'http_port': PORT,
    'gevent_port': PORT,
    'workers': {'type': 'integer', 'minimum': 0, 'maximum': 32},
    'max_cron_threads': {'type': 'integer', 'minimum': 0, 'maximum': 4},
    'db_maxconn': {'type': 'integer', 'minimum': 2, 'maximum': 64},
    'limit_memory_soft': {'type': 'integer', 'minimum': 256 << 20, 'maximum': 16 << 30},
    'limit_memory_hard': {'type': 'integer', 'minimum': 256 << 20, 'maximum': 16 << 30},
    'limit_time_cpu': {'type': 'integer', 'minimum': 10, 'maximum': 3600},
    'limit_time_real': {'type': 'integer', 'minimum': 10, 'maximum': 7200},
    # Container limits (ADR-011 "derived from the plan band"); not named in DOC-04 §6.1.
    'mem_limit_bytes': {'type': 'integer', 'minimum': 512 << 20, 'maximum': 64 << 30},
    'cpu_millis': {'type': 'integer', 'minimum': 250, 'maximum': 16000},
})
REASON = {'enum': ['operator', 'maintenance', 'suspension', 'customer_request', 'incident', 'nonpayment', 'security']}

KEY = {'type': 'string', 'pattern': '^[A-Za-z0-9+/]{43}=$'}     # Ed25519 public key, base64
# Host.RotateTrust (DOC-04 §2): the fleet's pinned keys, signed with the release key.
TRUST_DOCUMENT = obj({
    'v': {'type': 'integer'},
    'kind': {'const': 'trust'},
    'trust_version': {'type': 'integer', 'minimum': 1, 'maximum': 2 ** 31},
    'issued_at': RFC3339,
    'trust': obj({
        'dispatch': {'type': 'array', 'minItems': 1, 'maxItems': 4, 'items': KEY},
        'custodian': {'type': 'array', 'maxItems': 8, 'items': KEY},
        'breakglass': {'anyOf': [KEY, {'type': 'null'}]},
        'breakglass_enabled': {'type': 'boolean'},
        'agents': {'type': 'array', 'maxItems': 512, 'items': KEY},
    }),
    'release_signature': {'type': 'string', 'maxLength': 128},
})

PARAMS = {
    'Tenant.Create': obj({
        'runtime_slot': RUNTIME_SLOT,
        'domains': {'type': 'array', 'minItems': 1, 'maxItems': 10,
                    'items': obj({'hostname': HOSTNAME, 'kind': {'enum': ['platform', 'custom']}})},
        'modules': {'type': 'array', 'maxItems': 200, 'uniqueItems': True, 'items': MODULE},
        'lang': {'enum': ['en_US', 'ar_001']},
        'country': {'type': 'string', 'pattern': '^[A-Z]{2}$'},
        # The db-agent needs the app host for pg_hba; not in DOC-04 §6.1's list.
        'app_host_ip': {'type': 'string', 'pattern': r'^(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}$'},
    }),
    # ctl-1 fills runtime_slot and smtp: the agent re-renders the tenant's /run files (tmpfs) at every start.
    'Tenant.Start': obj({'reason': REASON, 'runtime_slot': RUNTIME_SLOT, 'smtp': {'enum': ['relay', 'sink']}}),
    'Tenant.Stop': obj({'reason': REASON}),
    'Tenant.SetDomain': obj({
        'add': {'type': 'array', 'maxItems': 10, 'items': HOSTNAME},
        'remove': {'type': 'array', 'maxItems': 10, 'items': HOSTNAME},
        'verification_evidence_id': UUID,
    }),
    'Tenant.ApplyPatch': obj({'target_digest': DIGEST}),
    'Tenant.ModuleUpdate': obj({'target_digest': DIGEST,
                                'modules': {'type': 'array', 'minItems': 1, 'maxItems': 200,
                                            'uniqueItems': True, 'items': MODULE}}),
    'Tenant.Suspend': obj({'reason': REASON}),
    'Tenant.Reactivate': obj({'reason': REASON}),
    'Tenant.RotateSecret': obj({'which': {'enum': ['db_password', 'admin_passwd', 'smtp']}}),
    'Tenant.Backup': obj({'backup_id': UUID,
                          'retention_tier': {'enum': ['daily', 'weekly', 'monthly', 'pre_update',
                                                      'pre_restore', 'final']},
                          'lock_days': {'type': 'integer', 'minimum': 1, 'maximum': 3650}}),
    'Tenant.RestoreToIsolated': obj({'backup_id': UUID, 'target_environment_id': UUID,
                                     'purpose': {'enum': ['drill', 'restore_to_stage', 'export_verify']},
                                     # DOC-05 §5 weekly deep drill: row counts and a printed PDF.
                                     'deep': {'type': 'boolean'},
                                     # The copy needs its own slot; not in DOC-04 §6.9's list.
                                     'runtime_slot': RUNTIME_SLOT,
                                     'app_host_ip': {'type': 'string',
                                                     'pattern': r'^(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}$'}}),
    'Tenant.RestoreProduction': obj({'backup_id': UUID}),
    'Tenant.Export': obj({'backup_id': UUID, 'ttl_hours': {'type': 'integer', 'minimum': 1, 'maximum': 72}}),
    'Tenant.Relocate': obj({'target_host_id': UUID}),
    'Tenant.Delete': obj({'deletion_case_id': UUID}),
    'Tenant.MeterSeats': obj({'role_map_version': {'type': 'integer', 'minimum': 1}}),
    'RestoreCopy.Expire': obj({'environment_id': UUID}),
    'Host.Drain': obj({'evacuate': {'type': 'boolean'}}),
    'Host.RotateTrust': obj({'trust_document': TRUST_DOCUMENT}),
    'Agent.Query': obj({'op_id': {'anyOf': [UUID, {'type': 'null'}]}}),
}


@dataclass(frozen=True)
class OpSpec:
    steps: tuple[str, ...]
    states: tuple[str, ...] | None = None     # allowed tenant_state; None = not tenant-scoped
    release: bool = False                     # R: release manifest required
    custodian: bool = False                   # C: custodian approval required
    exclusive: bool = True                    # INV-21: one exclusive op per environment
    mutating: bool = True                     # counts against the rate limit
    host_scoped: bool = False                 # fenced per host, not per environment


CATALOG = {
    'Tenant.Create': OpSpec(
        ('db.provision', 'mail.user', 'app.network', 'app.image', 'app.config', 'app.init_db',
         'app.platform_defaults', 'app.container', 'app.route', 'app.health'),
        states=('RESERVED', 'PROVISIONING'), release=True),
    'Tenant.Start': OpSpec(('app.start',), states=('ACTIVE', 'MAINTENANCE')),
    'Tenant.Stop': OpSpec(('app.stop',), states=tuple(s for s in TENANT_STATES if s != 'DELETED')),
    'Tenant.SetDomain': OpSpec(('app.route', 'app.health'), states=('ACTIVE', 'MAINTENANCE')),
    'Tenant.ApplyPatch': OpSpec(('app.check_versions', 'app.image', 'app.swap', 'app.health'),
                                states=('ACTIVE', 'MAINTENANCE'), release=True),
    'Tenant.ModuleUpdate': OpSpec(('app.image', 'app.stop', 'app.update_modules', 'app.swap', 'app.health'),
                                  states=('ACTIVE', 'MAINTENANCE'), release=True),
    'Tenant.Suspend': OpSpec(('app.suspend', 'mail.disable'), states=('ACTIVE', 'SUSPENSION_NOTICE')),
    'Tenant.Reactivate': OpSpec(('mail.enable', 'app.reactivate'), states=('SUSPENDED',)),
    'Tenant.RotateSecret': OpSpec(('db.rotate', 'app.rotate', 'db.terminate_old', 'mail.rotate'), states=LIVE),
    # DELETION_ELIGIBLE: the final backup before Tenant.Delete (DOC-07 RB-20 step 4).
    # VALIDATING: DOC-03 §3.6 wants a recoverable first backup before ACTIVE; DOC-04 §6.8 omits it.
    'Tenant.Backup': OpSpec(('app.backup',), states=('VALIDATING', 'ACTIVE', 'MAINTENANCE', 'SUSPENDED',
                                                          'CANCELLING', 'EXPORT_READY', 'DELETION_ELIGIBLE')),
    'Tenant.RestoreToIsolated': OpSpec(('db.provision_copy', 'app.restore_copy'),
                                       states=tuple(s for s in TENANT_STATES if s != 'DELETED'), release=True),
    'Tenant.RestoreProduction': OpSpec(('db.provision_copy', 'app.restore_copy', 'app.stop',
                                        'db.terminate_sessions', 'db.switch', 'app.switch', 'app.health'),
                                       states=('MAINTENANCE',), release=True, custodian=True),
    'Tenant.Export': OpSpec(('app.export',), states=tuple(s for s in TENANT_STATES if s != 'DELETED')),
    'Tenant.Relocate': OpSpec(('app.stop', 'app.backup', 'app.restore_slot', 'db.hba_move', 'app.route',
                               'app.health', 'app.retire_source'), states=('MAINTENANCE',), release=True),
    'Tenant.Delete': OpSpec(('app.remove', 'mail.remove', 'db.drop'), states=('DELETION_ELIGIBLE',),
                            custodian=True),
    'Tenant.MeterSeats': OpSpec(('app.meter',), states=LIVE, exclusive=False, mutating=False),
    'RestoreCopy.Expire': OpSpec(('app.expire', 'db.expire'), states=None),
    'Host.Drain': OpSpec(('any.drain',), host_scoped=True),
    'Host.RotateTrust': OpSpec(('any.rotate_trust',), host_scoped=True),
    'Agent.Query': OpSpec(('any.query',), exclusive=False, mutating=False),
}


# DOC-04 §8 agent timeouts, in seconds. Heartbeats stop at the deadline, so
# ctl-1's lease lapses into RECONCILING instead of being extended forever.
STEP_TIMEOUTS = {
    **dict.fromkeys(('app.start', 'app.stop', 'app.suspend', 'app.reactivate', 'app.container', 'app.swap',
                     'app.switch'), 120),
    **dict.fromkeys(('app.init_db', 'app.platform_defaults'), 1200),
    'app.update_modules': 3600,
    **dict.fromkeys(('app.backup', 'app.restore_copy', 'app.export'), 7200),
    'app.health': 180,
}
DEFAULT_STEP_TIMEOUT = 600


def step_timeout(step: str) -> int:
    return STEP_TIMEOUTS.get(step, DEFAULT_STEP_TIMEOUT)


def step_role(step: str) -> str:
    return step.split('.', 1)[0]
