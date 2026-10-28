"""Envelope secrets (DOC-04 §3): age ciphertext, base64, encrypted to this
agent's X25519 key. Opened only after the envelope has passed every check, and
only the names the step expects are accepted."""
import base64
import json

import pyrage

ALLOWED = {
    ('Tenant.Create', 'db.provision'): {'db_password_scram'},
    ('Tenant.Create', 'app.config'): {'db_password', 'admin_passwd_hash', 'smtp_password', 'tenant_salt',
                                      'tenant_admin_password'},
    ('Tenant.Start', 'app.start'): {'db_password', 'admin_passwd_hash', 'smtp_password', 'tenant_salt',
                                    'tenant_admin_password'},
    ('Tenant.Backup', 'app.backup'): {'s3_key_id', 's3_secret', 'region_recipient'},
    ('Tenant.RestoreToIsolated', 'db.provision_copy'): {'db_password_scram'},
    ('Tenant.RestoreToIsolated', 'app.restore_copy'): {'db_password', 'admin_passwd_hash', 's3_key_id', 's3_secret',
                                                       'region_identity'},
}


class SecretError(Exception):
    pass


def seal(values: dict, recipient) -> str:
    """Control-plane side, used by tests and dev tools."""
    return base64.b64encode(pyrage.encrypt(json.dumps(values).encode(), [recipient])).decode()


def open_secrets(env, identity) -> dict:
    expected = ALLOWED.get((env['op_type'], env['step']), set())
    if env['secrets'] is None:
        if expected:
            raise SecretError('missing')
        return {}
    if identity is None:
        raise SecretError('no identity')
    try:
        values = json.loads(pyrage.decrypt(base64.b64decode(env['secrets'], validate=True), [identity]))
    except Exception:
        raise SecretError('undecryptable')
    if not isinstance(values, dict) or set(values) != expected \
            or not all(isinstance(v, str) and 0 < len(v) <= 4096 for v in values.values()):
        raise SecretError('unexpected names')
    return values
