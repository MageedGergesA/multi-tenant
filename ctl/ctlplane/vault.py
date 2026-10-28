"""Secrets (ADR-006, DOC-03 §2.7). Values are age-encrypted to the dispatcher's
key the moment they exist; the operator API holds only the public recipient.
The dispatcher alone holds the identity: at hand-out it opens what a step
needs, derives what the agent stores (a SCRAM verifier, Odoo's admin_passwd
hash), and seals the set to that host's X25519 key. Plaintext never touches
the database or a log.
"""
import base64
import hashlib
import hmac
import json
import secrets
import uuid

import pyrage

TENANT_KINDS = ('db_password', 'admin_passwd', 'smtp', 'tenant_salt', 'tenant_admin_password')

# What the agent expects per step (hostagent.secrets.ALLOWED; checked in
# tests/test_contract.py), and where each value comes from:
#   (scope, kind, derivation). scope: env (the operation's environment),
#   target (params.target_environment_id), region (the step host's region).
SOURCES = {
    ('Tenant.Create', 'db.provision'): {'db_password_scram': ('env', 'db_password', 'scram')},
    ('Tenant.Create', 'app.config'): {
        'db_password': ('env', 'db_password', None), 'admin_passwd_hash': ('env', 'admin_passwd', 'odoo_hash'),
        'smtp_password': ('env', 'smtp', None), 'tenant_salt': ('env', 'tenant_salt', None),
        'tenant_admin_password': ('env', 'tenant_admin_password', None)},
    # The /run files again, for a start after a reboot; a restore copy's SMTP goes to the sink.
    ('Tenant.Start', 'app.start'): {
        'db_password': ('env', 'db_password', None), 'admin_passwd_hash': ('env', 'admin_passwd', 'odoo_hash'),
        'smtp_password': ('env', 'smtp', None), 'tenant_salt': ('env', 'tenant_salt', None),
        'tenant_admin_password': ('env', 'tenant_admin_password', None)},
    ('Tenant.Backup', 'app.backup'): {
        's3_key_id': ('region', 'b2_write_key', 'key_id'), 's3_secret': ('region', 'b2_write_key', 'secret'),
        'region_recipient': ('region', 'backup_recipient', None)},
    ('Tenant.RestoreToIsolated', 'db.provision_copy'): {'db_password_scram': ('target', 'db_password', 'scram')},
    ('Tenant.RestoreToIsolated', 'app.restore_copy'): {
        'db_password': ('target', 'db_password', None), 'admin_passwd_hash': ('target', 'admin_passwd', 'odoo_hash'),
        's3_key_id': ('region', 'b2_write_key', 'key_id'), 's3_secret': ('region', 'b2_write_key', 'secret'),
        'region_identity': ('region', 'region_restore_key', None)},
}


class Unavailable(Exception):
    """A secret the step needs can't be produced; the name is safe to report."""


def generate(kind: str) -> str:
    return secrets.token_hex(16) if kind == 'tenant_salt' else secrets.token_urlsafe(32)


def encrypt(value: str, recipient: str) -> bytes:
    return pyrage.encrypt(value.encode(), [pyrage.x25519.Recipient.from_str(recipient)])


def provision(c, environment_id, tenant_id, recipient: str, now):
    """Fresh tenant secrets for an environment, bound by purpose."""
    for kind in TENANT_KINDS:
        ref = uuid.uuid4()
        c.execute('INSERT INTO secret_ref (id, kind, scope_tenant_id, ciphertext, created_at) '
                  'VALUES (%s, %s, %s, %s, %s)', (ref, kind, tenant_id, encrypt(generate(kind), recipient), now))
        c.execute('INSERT INTO secret_binding (environment_id, purpose, secret_ref_id) VALUES (%s, %s, %s)',
                  (environment_id, kind, ref))


def scram_verifier(password: str, iterations: int = 4096) -> str:
    """PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677), as stored in pg_authid."""
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return 'SCRAM-SHA-256$%d:%s$%s:%s' % (iterations, b64(salt), b64(hashlib.sha256(client_key).digest()),
                                          b64(server_key))


def odoo_hash(password: str, rounds: int = 600_000) -> str:
    """passlib `pbkdf2_sha512` format, which Odoo accepts for admin_passwd."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, rounds)
    ab64 = lambda b: base64.b64encode(b).decode().rstrip('=').replace('+', '.')  # noqa: E731
    return '$pbkdf2-sha512$%d$%s$%s' % (rounds, ab64(salt), ab64(digest))


class Vault:
    """The dispatcher's side."""

    def __init__(self, identity: pyrage.x25519.Identity):
        self.identity = identity

    @property
    def recipient(self) -> str:
        return str(self.identity.to_public())

    def _open(self, c, ref, name) -> str:
        row = ref and c.execute("SELECT ciphertext FROM secret_ref WHERE id = %s AND state = 'active'",
                                (ref,)).fetchone()
        if not row:
            raise Unavailable(name)
        try:
            return pyrage.decrypt(bytes(row['ciphertext']), [self.identity]).decode()
        except Exception:
            raise Unavailable(name) from None

    def envelope_secrets(self, c, op, step, host) -> str | None:
        """The sealed `secrets` field for this step, or None if it takes none."""
        sources = SOURCES.get((op['type'], step))
        if not sources:
            return None
        if not host['age_recipient']:
            raise Unavailable('host recipient')
        region = host['region_id'] and c.execute('SELECT * FROM region WHERE id = %s',
                                                 (host['region_id'],)).fetchone()
        values, opened = {}, {}
        for name, (scope, kind, derive) in sources.items():
            if scope == 'region':
                if not region:
                    raise Unavailable(name)
                if kind == 'backup_recipient':
                    value = region['backup_recipient']
                else:
                    ref = region['b2_write_key_ref' if kind == 'b2_write_key' else 'restore_key_ref']
                    value = opened.get(ref) or self._open(c, ref, name)
                    opened[ref] = value
            else:
                env = op['environment_id'] if scope == 'env' else (op['params'] or {}).get('target_environment_id')
                row = env and c.execute('SELECT secret_ref_id FROM secret_binding WHERE environment_id = %s '
                                        'AND purpose = %s', (env, kind)).fetchone()
                value = self._open(c, row and row['secret_ref_id'], name)
            if derive == 'scram':
                value = scram_verifier(value)
            elif derive == 'odoo_hash':
                value = odoo_hash(value)
            elif derive in ('key_id', 'secret'):
                try:
                    value = json.loads(value)[derive]
                except (ValueError, KeyError, TypeError):
                    raise Unavailable(name) from None
            values[name] = value
        sealed = pyrage.encrypt(json.dumps(values).encode(), [pyrage.x25519.Recipient.from_str(host['age_recipient'])])
        return base64.b64encode(sealed).decode()
