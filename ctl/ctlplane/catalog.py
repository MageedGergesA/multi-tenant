"""The operation catalog as ctl-1 dispatches it (DOC-04 §6, §8). The agent has
its own copy (hostagent.ops); tests/test_contract.py checks they agree."""
import json
from pathlib import Path

STEPS = {
    'Tenant.Create': ('db.provision', 'mail.user', 'app.network', 'app.image', 'app.config', 'app.init_db',
                      'app.platform_defaults', 'app.container', 'app.route', 'app.health'),
    'Tenant.Start': ('app.start',),
    'Tenant.Stop': ('app.stop',),
    'Tenant.SetDomain': ('app.route', 'app.health'),
    'Tenant.ApplyPatch': ('app.check_versions', 'app.image', 'app.swap', 'app.health'),
    'Tenant.ModuleUpdate': ('app.image', 'app.stop', 'app.update_modules', 'app.swap', 'app.health'),
    'Tenant.Suspend': ('app.suspend', 'mail.disable'),
    'Tenant.Reactivate': ('mail.enable', 'app.reactivate'),
    'Tenant.RotateSecret': ('db.rotate', 'app.rotate', 'db.terminate_old', 'mail.rotate'),
    'Tenant.Backup': ('app.backup',),
    'Tenant.RestoreToIsolated': ('db.provision_copy', 'app.restore_copy'),
    'Tenant.RestoreProduction': ('db.provision_copy', 'app.restore_copy', 'app.stop', 'db.terminate_sessions',
                                  'db.switch', 'app.switch', 'app.health'),
    'Tenant.Export': ('app.export',),
    'Tenant.Relocate': ('app.stop', 'app.backup', 'app.restore_slot', 'db.hba_move', 'app.route', 'app.health',
                        'app.retire_source'),
    'Tenant.Delete': ('app.remove', 'mail.remove', 'db.drop'),
    'Tenant.MeterSeats': ('app.meter',),
    'RestoreCopy.Expire': ('app.expire', 'db.expire'),
    'Host.Drain': ('any.drain',),
    'Host.RotateTrust': ('any.rotate_trust',),
    'Agent.Query': ('any.query',),      # read-back probes (reconciler.py)
}
NOT_EXCLUSIVE = ('Tenant.MeterSeats', 'Agent.Query')
PARAMS = {k: v for k, v in json.loads((Path(__file__).parent / 'params.schema.json').read_text()).items()
          if not k.startswith('_')}
RELEASE_MANIFEST = {k: v for k, v in json.loads((Path(__file__).parent / 'release_manifest.schema.json').read_text()
                                                ).items() if not k.startswith('_')}

# DOC-04 §8: the agent's timeout and the control-plane lease, per step class.
AGENT_TIMEOUT = {
    **dict.fromkeys(('app.start', 'app.stop', 'app.suspend', 'app.reactivate', 'app.container', 'app.swap',
                     'app.switch'), 120),
    **dict.fromkeys(('app.init_db', 'app.platform_defaults'), 1200),
    'app.update_modules': 3600,
    **dict.fromkeys(('app.backup', 'app.restore_copy', 'app.export'), 7200),
    'app.health': 180,
}
LEASE = {
    **dict.fromkeys(('app.start', 'app.stop', 'app.suspend', 'app.reactivate', 'app.container', 'app.swap',
                     'app.switch'), 300),
    **dict.fromkeys(('app.init_db', 'app.platform_defaults'), 1800),
    'app.update_modules': 5400,
    **dict.fromkeys(('app.backup', 'app.restore_copy', 'app.export'), 10800),
    'app.health': 300,
}
DEFAULT_AGENT_TIMEOUT, DEFAULT_LEASE = 600, 900   # §8 names no default; the agent's is 600 s


def margin(step: str) -> int:
    """How long past the agent's deadline ctl-1 still waits for the result."""
    return LEASE.get(step, DEFAULT_LEASE) - AGENT_TIMEOUT.get(step, DEFAULT_AGENT_TIMEOUT)


def step_role(step: str) -> str:
    return step.split('.', 1)[0]


# -- admission (DOC-03 §6.3, DOC-04 §6) ----------------------------------------------
_NOT_DELETED = ('DRAFT', 'ELIGIBLE', 'RESERVED', 'PROVISIONING', 'VALIDATING', 'ACTIVE', 'MAINTENANCE',
                'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY', 'DELETION_ELIGIBLE')
_LIVE = ('ACTIVE', 'MAINTENANCE', 'SUSPENSION_NOTICE', 'SUSPENDED')
TENANT_STATES = {           # the tenant-state gate; types not listed aren't tenant-gated
    'Tenant.Create': ('RESERVED', 'PROVISIONING'),
    'Tenant.Start': ('ACTIVE', 'MAINTENANCE'),
    'Tenant.Stop': _NOT_DELETED,
    'Tenant.SetDomain': ('ACTIVE', 'MAINTENANCE'),
    'Tenant.ApplyPatch': ('ACTIVE', 'MAINTENANCE'),
    'Tenant.ModuleUpdate': ('ACTIVE', 'MAINTENANCE'),
    'Tenant.Suspend': ('ACTIVE', 'SUSPENSION_NOTICE'),
    'Tenant.Reactivate': ('SUSPENDED',),
    'Tenant.RotateSecret': _LIVE,
    'Tenant.Backup': ('VALIDATING', 'ACTIVE', 'MAINTENANCE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY',
                      'DELETION_ELIGIBLE'),
    'Tenant.RestoreToIsolated': _NOT_DELETED,
    'Tenant.RestoreProduction': ('MAINTENANCE',),
    'Tenant.Export': _NOT_DELETED,
    'Tenant.Relocate': ('MAINTENANCE',),
    'Tenant.Delete': ('DELETION_ELIGIBLE',),
    'Tenant.MeterSeats': _LIVE,
}
CUSTODIAN = ('Tenant.RestoreProduction', 'Tenant.Delete')          # approval by a second role
RECOVERY_POINT = ('Tenant.ModuleUpdate', 'Tenant.RestoreProduction', 'Tenant.Relocate', 'Tenant.Delete')  # DR-06
RECOVERY_WINDOW = 3600
NEEDS_RELEASE = ('Tenant.Create', 'Tenant.ApplyPatch', 'Tenant.ModuleUpdate', 'Tenant.RestoreToIsolated',
                 'Tenant.RestoreProduction', 'Tenant.Relocate')
# Steps that open envelope secrets at the agent (S3 keys, passwords, recipients).
# mail.user would take the relay password, but the mail agent defines neither the step nor its secrets yet.
SECRET_STEPS = ('db.provision', 'app.config', 'app.start', 'app.backup', 'db.provision_copy', 'app.restore_copy',
                'db.rotate', 'app.rotate', 'mail.rotate')
HOST_SCOPED = ('Host.Drain', 'Host.RotateTrust')
INTERNAL = ('Agent.Query',)     # the reconciler's probes, never requested
# They need a runtime slot (container_uid, ports) and capacity allocated by ctl-1 (INV-8, INV-13).
SLOT_ALLOCATION = ('Tenant.Relocate',)
ALLOCATING = ('Tenant.Create', 'Tenant.RestoreToIsolated')     # ctl-1 places them and fills in the slot
# ctl-1 fills in the environment's slot and SMTP mode: the agent re-renders /run/tenants/<sid> (tmpfs, gone
# after a reboot) before every start (DOC-04 §5.2).
SLOT_FILLED = ('Tenant.Start',)
# What operators send for those; the rest of DOC-04's params is ctl-1's to fill.
REQUEST_PARAMS = {
    'Tenant.Create': {**PARAMS['Tenant.Create'],
                      'properties': {k: v for k, v in PARAMS['Tenant.Create']['properties'].items()
                                     if k not in ('runtime_slot', 'app_host_ip')},
                      'required': [k for k in PARAMS['Tenant.Create']['required']
                                   if k not in ('runtime_slot', 'app_host_ip')]},
    'Tenant.Start': {**PARAMS['Tenant.Start'],
                     'properties': {'reason': PARAMS['Tenant.Start']['properties']['reason']},
                     'required': ['reason']},
    'Tenant.RestoreToIsolated': {**PARAMS['Tenant.RestoreToIsolated'],
                                 'properties': {k: PARAMS['Tenant.RestoreToIsolated']['properties'][k]
                                                for k in ('backup_id', 'purpose', 'deep')},
                                 'required': ['backup_id', 'purpose']},
}
RESTORE_COPY_DAYS = 7      # DOC-03 §2.4 default
TARGET_RELEASE = {'Tenant.ApplyPatch': ('patch',), 'Tenant.ModuleUpdate': ('patch', 'module_update')}


def not_supported(op_type: str) -> str | None:
    """Why ctl-1 can't build this type's envelope yet, or None."""
    from .vault import SOURCES
    if op_type in SLOT_ALLOCATION:
        return 'runtime slot allocation'
    if any(step in SECRET_STEPS and (op_type, step) not in SOURCES for step in STEPS[op_type]):
        return 'envelope secrets'
    return None
