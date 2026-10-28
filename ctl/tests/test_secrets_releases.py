"""Envelope secrets and release manifests: what ctl-1 builds, checked by the
real agent's own verifier and `open_secrets` (DOC-04 §3, ADR-006, INV-6)."""
import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pyrage
import pytest
from nacl.signing import SigningKey

from ctlplane import vault
from ctlplane.canonical import b64_public, sign
from hostagent.config import AgentConfig, Trust
from hostagent.envelope import Verifier
from hostagent.secrets import ALLOWED, SecretError, open_secrets
from hostagent.state import State

from .conftest import APP_HOST, DB_HOST, ENV, OTHER_HOST, TENANT
from .test_operator_api import Api

CELL = 'community/19.0/ubuntu-24.04/py3.12/pg16'
SLOT = {'container_uid': 10123, 'http_port': 20010, 'gevent_port': 20011, 'workers': 2, 'max_cron_threads': 1,
        'db_maxconn': 8, 'limit_memory_soft': 640 << 20, 'limit_memory_hard': 768 << 20, 'limit_time_cpu': 600,
        'limit_time_real': 1200, 'mem_limit_bytes': 2 << 30, 'cpu_millis': 2000}


def _digest():
    return 'sha256:' + uuid.uuid4().hex * 2


class Releases:
    def __init__(self, w, api):
        self.w, self.api = w, api
        self.key = SigningKey.generate()
        w.sql("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'release', %s)",
              (uuid.uuid4(), b64_public(self.key)))
        self.cell = uuid.uuid4()
        w.sql("INSERT INTO release_cell (id, cell, edition, odoo_major, status) "
              "VALUES (%s, %s, 'community', '19.0', 'available')", (self.cell, CELL))

    def manifest(self, digest=None, change_class='patch', key=None, cell=CELL, modules=None):
        m = {'cell': cell, 'repository': 'tenants/odoo', 'image_digest': digest or _digest(),
             'change_class': change_class, 'addon_manifest_sha256': 'cd' * 32,
             'module_versions': modules or {'base': '19.0.1.3', 'sale': '19.0.1.2'}}
        m['release_signature'] = sign(m, key or self.key)
        return m

    def upload(self, manifest, evidence=True):
        ev = {'uri': 's3://evidence/%s.json' % manifest['image_digest'][7:19], 'sha256': 'ee' * 32} \
            if evidence else None
        return self.api.post('/v1/releases', {'manifest': manifest, 'evidence': ev})

    def current(self, **kw):
        """An approved release as the environment's current image."""
        m = self.manifest(**kw)
        assert self.upload(m).json()['status'] == 'approved'
        self.w.sql('UPDATE environment SET image_release_id = (SELECT id FROM image_release WHERE image_digest = %s)',
                   (m['image_digest'],))
        return m


@pytest.fixture
def api(w):
    return Api(w)


@pytest.fixture
def rel(w, api):
    return Releases(w, api)


def agent_verifier(w, rel, host, role, tmp_path):
    nobody = SigningKey.generate().verify_key
    config = AgentConfig(host_id=host, role=role, state_dir=tmp_path, registry_host='registry.internal',
                         trust=Trust(dispatch=(w.dispatch.verify_key,), release=rel.key.verify_key,
                                     custodian=(nobody,), breakglass=nobody, breakglass_enabled=False))
    return Verifier(config, State(tmp_path / ('%s.db' % role)), lambda params: True)


def _open(w, host, env):
    return open_secrets(env, w.ages[host])


def _scram_ok(verifier, password):
    head, keys = verifier.split('$', 1)[1].split('$')
    iterations, salt = head.split(':')
    stored, server = keys.split(':')
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(salt), int(iterations))
    client = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    return (base64.b64decode(stored) == hashlib.sha256(client).digest()
            and base64.b64decode(server) == hmac.new(salted, b'Server Key', hashlib.sha256).digest())


def _odoo_ok(h, password):
    _, scheme, rounds, salt, digest = h.split('$')
    unab64 = lambda s: base64.b64decode(s.replace('.', '+') + '=' * (-len(s) % 4))  # noqa: E731
    return scheme == 'pbkdf2-sha512' and hashlib.pbkdf2_hmac('sha512', password.encode(), unab64(salt),
                                                              int(rounds)) == unab64(digest)


def _binding(w, env, purpose):
    [row] = w.sql('SELECT r.ciphertext FROM secret_binding b JOIN secret_ref r ON r.id = b.secret_ref_id '
                  'WHERE b.environment_id = %s AND b.purpose = %s', (env, purpose))
    return pyrage.decrypt(bytes(row['ciphertext']), [w.vault.identity]).decode()


def _done(w, env):
    assert w.store.apply(env['host_id'], w.response(env)) in ('next_step', 'completed')


# -- contract --------------------------------------------------------------------

def test_ctl_supplies_exactly_what_the_agent_expects():
    assert {k: set(v) for k, v in vault.SOURCES.items()} == ALLOWED


def test_derived_values_verify():
    assert _scram_ok(vault.scram_verifier('pw-1'), 'pw-1') and not _scram_ok(vault.scram_verifier('pw-1'), 'pw-2')
    assert _odoo_ok(vault.odoo_hash('pw-1', rounds=1000), 'pw-1')
    from hostagent.devtools import odoo_master_hash, scram_verifier       # the formats the agent e2e proved
    assert _scram_ok(scram_verifier('x'), 'x') and _odoo_ok(odoo_master_hash('x', rounds=1000), 'x')


def test_release_schema_matches_the_agent():
    from ctlplane import catalog
    from hostagent import ops
    assert catalog.RELEASE_MANIFEST == ops.RELEASE_MANIFEST


# -- Backup through the API -------------------------------------------------------

def test_backup_envelope_carries_the_region_secrets_for_that_host_only(w, api, tmp_path):
    op = api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7})
    assert op['state'] == 'DISPATCHED'
    assert w.op(op['id'])['params']['backup_id'] == op['id']        # generated by ctl-1
    [env] = w.store.claim(APP_HOST, 4)
    verifier = agent_verifier(w, Releases(w, api), APP_HOST, 'app', tmp_path)
    verifier.state.register(environment_id=ENV, tenant_id=TENANT, sid=ENV.replace('-', '')[:12], container_uid=10001,
                            http_port=20000, gevent_port=20001, kind='production', egress_profile='production',
                            now=time.time())
    verifier.verify(env, time.time())
    assert _open(w, APP_HOST, env) == {'s3_key_id': w.b2['key_id'], 's3_secret': w.b2['secret'],
                                       'region_recipient': str(w.region_backup.to_public())}
    with pytest.raises(SecretError):
        open_secrets(env, w.ages[OTHER_HOST])


def test_no_plaintext_secret_at_rest(w, api):
    api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7})
    [env] = w.store.claim(APP_HOST, 4)
    w.store.apply(APP_HOST, w.response(env, observed={'already_stored': True}))
    with psycopg.connect(w.dsn) as c:
        tables = [r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")]
        for t in tables:
            dump = ''.join(str(r) for r in c.execute('SELECT * FROM %s' % t).fetchall())
            assert w.b2['secret'] not in dump and w.region_restore not in dump, t


def test_operator_api_role_cannot_read_ciphertext(w, api):
    app = api.admission.store.connect()
    assert app.execute('SELECT id, kind FROM secret_ref').fetchall()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        app.execute('SELECT ciphertext FROM secret_ref')
    app.close()


@pytest.mark.parametrize('broken, secret', [
    ("UPDATE host SET age_recipient = NULL WHERE id = '%s'" % APP_HOST, 'host recipient'),
    ('UPDATE region SET b2_write_key_ref = NULL', 's3_key_id')])
def test_backup_refused_when_a_secret_is_missing(w, api, broken, secret):
    w.sql(broken)
    op = api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7})
    assert (op['state'], op['result_code'], op['result_detail']['secret']) == ('REJECTED', 'SECRET_UNAVAILABLE',
                                                                             secret)


def test_undecryptable_secret_fails_at_hand_out(w, api):
    api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7})
    stranger = pyrage.x25519.Identity.generate().to_public()
    w.sql('UPDATE secret_ref SET ciphertext = %s WHERE kind = %s',
          (vault.encrypt('{}', str(stranger)), 'b2_write_key'))
    assert w.store.claim(APP_HOST, 4) == []
    [op] = w.sql("SELECT state, result_code, result_detail FROM operation WHERE type = 'Tenant.Backup'")
    assert (op['state'], op['result_code'], op['result_detail']) == ('FAILED', 'SECRET_UNAVAILABLE',
                                                                     {'secret': 's3_key_id'})


def test_no_dispatcher_identity_no_secrets(w, api):
    api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7})
    w.store.vault = None
    assert w.store.claim(APP_HOST, 4) == []
    assert w.sql("SELECT result_code FROM operation WHERE type = 'Tenant.Backup'")[0]['result_code'] == \
        'SECRET_UNAVAILABLE'


def test_region_secret_upload_takes_only_ciphertext(w, api):
    new = {'key_id': 'K2', 'secret': 's2'}
    ct = base64.b64encode(vault.encrypt(json.dumps(new), w.vault.recipient)).decode()
    from .test_operator_api import token
    r = api.client.put('/v1/regions/eu-de-fsn1/secrets/b2_write_key', json={'ciphertext_b64': ct},
                       headers={'Authorization': 'Bearer ' + token('sub-founder')})
    assert r.status_code == 200
    states = {x['state'] for x in w.sql("SELECT state FROM secret_ref WHERE kind = 'b2_write_key'")}
    assert states == {'active', 'revoked'}
    plain = base64.b64encode(json.dumps(new).encode()).decode()
    r = api.client.put('/v1/regions/eu-de-fsn1/secrets/b2_write_key', json={'ciphertext_b64': plain},
                       headers={'Authorization': 'Bearer ' + token('sub-founder')})
    assert r.status_code == 422 and r.json()['detail']['detail'] == {'ciphertext': 'not age'}
    assert api.get('/v1/dispatcher/recipient', who='auditor').json() == {'recipient': w.vault.recipient}
    api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7})
    [env] = w.store.claim(APP_HOST, 4)
    assert _open(w, APP_HOST, env)['s3_key_id'] == 'K2'


# -- Create and RestoreToIsolated envelopes (dispatched internally) ------------------

def _provision(w, env):
    with w.store.connect() as c:
        vault.provision(c, env, TENANT, w.vault.recipient, datetime.now(timezone.utc))


def test_create_envelopes_open_at_the_agent(w, api, rel, tmp_path):
    w.store.clock = time.time
    m = rel.current(change_class='major')
    _provision(w, ENV)
    params = {'runtime_slot': SLOT, 'domains': [{'hostname': 'acme.cloud.test', 'kind': 'platform'}],
              'modules': ['sale'], 'lang': 'en_US', 'country': 'EG', 'app_host_ip': '10.0.0.11'}
    w.sql("UPDATE tenant SET lifecycle_state = 'PROVISIONING'")
    op_id = w.store.dispatch('Tenant.Create', tenant_id=TENANT, environment_id=ENV, params=params,
                             hosts={'app': APP_HOST, 'db': DB_HOST, 'mail': OTHER_HOST}, idempotency_key='c')
    w.sql('UPDATE operation SET image_release_id = (SELECT id FROM image_release) WHERE id = %s', (op_id,))
    [db_env] = w.store.claim(DB_HOST, 4)
    agent_verifier(w, rel, DB_HOST, 'db', tmp_path).verify(db_env, time.time())
    db_password = _binding(w, ENV, 'db_password')
    assert _scram_ok(_open(w, DB_HOST, db_env)['db_password_scram'], db_password)
    assert db_env['release_manifest'] == m
    _done(w, db_env)
    [mail_env] = w.store.claim(OTHER_HOST, 4)
    assert mail_env['secrets'] is None
    _done(w, mail_env)
    for step in ('app.network', 'app.image'):
        [e] = w.store.claim(APP_HOST, 4)
        assert e['step'] == step and e['secrets'] is None
        _done(w, e)
    [cfg] = w.store.claim(APP_HOST, 4)
    agent_verifier(w, rel, APP_HOST, 'app', tmp_path).verify(cfg, time.time())
    got = _open(w, APP_HOST, cfg)
    assert set(got) == ALLOWED[('Tenant.Create', 'app.config')]
    assert got['db_password'] == db_password and _odoo_ok(got['admin_passwd_hash'], _binding(w, ENV, 'admin_passwd'))
    for name, purpose in (('smtp_password', 'smtp'), ('tenant_salt', 'tenant_salt'),
                          ('tenant_admin_password', 'tenant_admin_password')):
        assert got[name] == _binding(w, ENV, purpose)


def test_restore_copy_gets_its_own_passwords_and_the_region_restore_key(w, api, rel, tmp_path):
    rel.current()
    _provision(w, ENV)
    copy = str(uuid.uuid4())
    w.sql("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'restore_copy')", (copy, TENANT))
    _provision(w, copy)
    params = {'backup_id': str(uuid.uuid4()), 'target_environment_id': copy, 'purpose': 'drill',
              'runtime_slot': SLOT, 'app_host_ip': '10.0.0.11'}
    op_id = w.store.dispatch('Tenant.RestoreToIsolated', tenant_id=TENANT, environment_id=ENV, params=params,
                             hosts={'app': APP_HOST, 'db': DB_HOST}, idempotency_key='r')
    w.sql('UPDATE operation SET image_release_id = (SELECT id FROM image_release) WHERE id = %s', (op_id,))
    [db_env] = w.store.claim(DB_HOST, 4)
    assert _scram_ok(_open(w, DB_HOST, db_env)['db_password_scram'], _binding(w, copy, 'db_password'))
    _done(w, db_env)
    [app_env] = w.store.claim(APP_HOST, 4)
    got = _open(w, APP_HOST, app_env)
    assert set(got) == ALLOWED[('Tenant.RestoreToIsolated', 'app.restore_copy')]
    assert got['db_password'] == _binding(w, copy, 'db_password') != _binding(w, ENV, 'db_password')
    assert got['region_identity'] == w.region_restore
    assert pyrage.decrypt(pyrage.encrypt(b'x', [w.region_backup.to_public()]),
                          [pyrage.x25519.Identity.from_str(got['region_identity'])]) == b'x'


def test_missing_binding_fails_at_hand_out(w, api, rel):
    rel.current()
    w.sql("UPDATE tenant SET lifecycle_state = 'PROVISIONING'")
    w.store.dispatch('Tenant.Create', tenant_id=TENANT, environment_id=ENV, params={},
                     hosts={'app': APP_HOST, 'db': DB_HOST, 'mail': OTHER_HOST}, idempotency_key='c')
    assert w.store.claim(DB_HOST, 4) == []
    assert w.sql("SELECT result_detail FROM operation WHERE type = 'Tenant.Create'")[0]['result_detail'] == \
        {'secret': 'db_password_scram'}


# -- releases -------------------------------------------------------------------------

def test_release_needs_evidence_to_be_approved(w, api, rel):
    m = rel.manifest()
    assert rel.upload(m, evidence=False).json()['status'] == 'evidence_pending'
    assert rel.upload(m).json()['status'] == 'approved'
    [ev] = w.sql('SELECT * FROM evidence_artifact')
    assert (ev['kind'], ev['subject_digest']) == ('release_approval', m['image_digest'])
    assert rel.upload(m).json()['status'] == 'approved' and len(w.sql('SELECT * FROM evidence_artifact')) == 1
    with pytest.raises(psycopg.errors.CheckViolation):     # INV-6, even for the owner
        w.sql("INSERT INTO image_release (id, release_cell_id, image_digest, change_class, addon_manifest_sha256, "
              "module_versions, manifest, status, created_at) VALUES (%s, %s, 'x', 'patch', 'y', '{}', '{}', "
              "'approved', now())", (uuid.uuid4(), rel.cell))


@pytest.mark.parametrize('bad, status, code', [
    (dict(key='forged'), 422, 'SIG_INVALID'), (dict(cell='community/18.0/x'), 422, 'POLICY_CELL'),
    (dict(change_class='hotfix'), 422, 'SCHEMA')])
def test_bad_release_is_refused(w, api, rel, bad, status, code):
    if bad.get('key') == 'forged':
        bad['key'] = SigningKey.generate()
    r = rel.upload(rel.manifest(**bad))
    assert (r.status_code, r.json()['detail']['code']) == (status, code)
    assert w.sql('SELECT * FROM image_release') == []


def test_release_digest_is_immutable(w, api, rel):
    m = rel.manifest()
    rel.upload(m)
    other = rel.manifest(digest=m['image_digest'], modules={'base': '19.0.9'})
    assert rel.upload(other).status_code == 409


def test_unavailable_cell_refuses_uploads(w, api, rel):
    w.sql("UPDATE release_cell SET status = 'withdrawn'")
    assert rel.upload(rel.manifest()).json()['detail']['code'] == 'POLICY_CELL'


# -- ApplyPatch and ModuleUpdate -------------------------------------------------------

def test_apply_patch_sends_the_signed_manifest_and_moves_the_environment(w, api, rel, tmp_path):
    rel.current()
    target = rel.manifest()
    rel.upload(target)
    op = api.request('Tenant.ApplyPatch', {'target_digest': target['image_digest']})
    assert op['state'] == 'DISPATCHED'
    [env] = w.store.claim(APP_HOST, 4)
    assert env['release_manifest'] == target and env['secrets'] is None
    agent_verifier(w, rel, APP_HOST, 'app', tmp_path)._check_release(env)
    for _ in range(3):
        _done(w, env)
        [env] = w.store.claim(APP_HOST, 4) or [None]
    _done(w, env)
    [e] = w.sql('SELECT r.image_digest FROM environment e JOIN image_release r ON r.id = e.image_release_id '
                'WHERE e.id = %s', (ENV,))
    assert e['image_digest'] == target['image_digest']


@pytest.mark.parametrize('case, code', [('module_update', 'POLICY_RELEASE'), ('pending', 'POLICY_RELEASE'),
                                        ('unknown', 'POLICY_RELEASE'), ('revoked', 'POLICY_RELEASE'),
                                        ('no_current', 'POLICY_RELEASE')])
def test_apply_patch_refused(w, api, rel, case, code):
    if case != 'no_current':
        rel.current()
    target = rel.manifest(change_class='module_update' if case == 'module_update' else 'patch')
    if case != 'unknown':
        rel.upload(target, evidence=case != 'pending')
    if case == 'revoked':
        api.post('/v1/releases/revoke', {'image_digest': target['image_digest']})
    op = api.request('Tenant.ApplyPatch', {'target_digest': target['image_digest']})
    assert (op['state'], op['result_code']) == ('REJECTED', code)


def test_module_update_checks_modules_and_needs_a_recovery_point(w, api, rel):
    rel.current()
    target = rel.manifest(change_class='module_update')
    rel.upload(target)
    w.sql("UPDATE tenant SET lifecycle_state = 'MAINTENANCE'")
    op = api.request('Tenant.ModuleUpdate', {'target_digest': target['image_digest'], 'modules': ['stock']})
    assert op['result_code'] == 'POLICY_MODULES'
    op = api.request('Tenant.ModuleUpdate', {'target_digest': target['image_digest'], 'modules': ['sale']})
    assert op['result_code'] == 'NO_RECOVERY_POINT'
    api.backup()
    op = api.request('Tenant.ModuleUpdate', {'target_digest': target['image_digest'], 'modules': ['sale']})
    assert op['state'] == 'DISPATCHED'


def test_revoked_after_dispatch_is_never_handed_out(w, api, rel):
    rel.current()
    target = rel.manifest()
    rel.upload(target)
    op = api.request('Tenant.ApplyPatch', {'target_digest': target['image_digest']})
    api.post('/v1/releases/revoke', {'image_digest': target['image_digest']})
    assert w.store.claim(APP_HOST, 4) == []
    assert (w.op(op['id'])['state'], w.op(op['id'])['result_code']) == ('FAILED', 'RELEASE_REVOKED')


def test_patch_never_crosses_cells(w, api, rel):
    rel.current()
    other = 'community/19.0/ubuntu-26.04/py3.13/pg17'
    w.sql("INSERT INTO release_cell (id, cell, edition, odoo_major, status) VALUES (%s, %s, 'community', '19.0', "
          "'available')", (uuid.uuid4(), other))
    target = rel.manifest(cell=other)
    assert rel.upload(target).json()['status'] == 'approved'
    op = api.request('Tenant.ApplyPatch', {'target_digest': target['image_digest']})
    assert (op['result_code'], op['result_detail']) == ('POLICY_RELEASE', {'detail': 'other cell'})


def test_backup_id_is_never_the_callers(w, api):
    mine = str(uuid.uuid4())
    op = api.request('Tenant.Backup', {'backup_id': mine, 'retention_tier': 'daily', 'lock_days': 7})
    assert w.op(op['id'])['params']['backup_id'] == op['id'] != mine
