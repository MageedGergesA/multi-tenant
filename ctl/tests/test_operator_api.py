"""The operator API and admission before dispatch (DOC-03 §2.1, §6, §6.3)."""
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from ctlplane import audit
from ctlplane.admission import Admission
from ctlplane.auth import OidcVerifier
from ctlplane.canonical import b64_public, sign
from ctlplane.operator_api import create_app
from ctlplane.store import Store

from .conftest import APP_HOST, DB_HOST, ENV, OTHER_HOST, TENANT

ISSUER, AUDIENCE = 'https://id.example.test', 'ctl-1'
IDP = ec.generate_private_key(ec.SECP256R1())
JWKS = {'keys': [dict(jwt.algorithms.ECAlgorithm.to_jwk(IDP.public_key(), as_dict=True), kid='k1', alg='ES256')]}
ROGUE = ec.generate_private_key(ec.SECP256R1())


def token(sub, *, key=IDP, amr=('pwd', 'hwk', 'mfa'), auth_age=60, aud=AUDIENCE, iss=ISSUER, life=300):
    now = int(time.time())
    claims = {'iss': iss, 'aud': aud, 'sub': sub, 'iat': now, 'exp': now + life, 'auth_time': now - auth_age,
              'amr': list(amr)}
    return jwt.encode(claims, key, algorithm='ES256', headers={'kid': 'k1'})


class Api:
    def __init__(self, w, breakglass=False, enrollment=None, trust=None, retention=None):
        self.w = w
        w.store.clock = time.time
        self.custodian = SigningKey.generate()
        self.breakglass = SigningKey.generate()
        self.ops = {}
        w.sql("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'custodian', %s), (%s, 'breakglass', %s)",
              (uuid.uuid4(), b64_public(self.custodian), uuid.uuid4(), b64_public(self.breakglass)))
        w.sql('UPDATE environment SET app_host_id = %s, db_host_id = %s, mail_host_id = %s',
              (APP_HOST, DB_HOST, OTHER_HOST))
        now = datetime.now(timezone.utc)
        for name, status in (('founder', 'active'), ('custodian', 'active'), ('auditor', 'active'),
                             ('gone', 'suspended'), ('lapsed', 'active')):
            self.ops[name] = str(uuid.uuid4())
            w.sql("INSERT INTO operator (id, oidc_subject, status) VALUES (%s, %s, %s)",
                  (self.ops[name], 'sub-' + name, status))
        for name, role, valid_to in (('founder', 'platform_operator', None), ('custodian', 'backup_custodian', None),
                                     ('auditor', 'auditor', None), ('gone', 'platform_operator', None),
                                     ('lapsed', 'platform_operator', now - timedelta(seconds=1))):
            granter = self.ops['custodian' if name == 'founder' else 'founder']
            w.sql('INSERT INTO operator_role_grant (id, operator_id, role, valid_from, valid_to, granted_by) '
                  'VALUES (%s, %s, %s, %s, %s, %s)',
                  (uuid.uuid4(), self.ops[name], role, now - timedelta(days=1), valid_to, granter))
        # The operator API runs as ctl_app: it can't read secret_ref.
        self.admission = Admission(Store(w.dsn, w.dispatch, role='ctl_app'), recipient=w.vault.recipient,
                                   breakglass_enabled=breakglass)
        self.client = TestClient(create_app(self.admission, OidcVerifier(ISSUER, AUDIENCE, JWKS),
                                            dispatcher_recipient=w.vault.recipient, enrollment=enrollment,
                                            trust=trust, retention=retention))

    def post(self, path, body, who='founder', **tok):
        return self.client.post(path, json=body, headers={'Authorization': 'Bearer ' + token('sub-' + who, **tok)})

    def get(self, path, who='founder'):
        return self.client.get(path, headers={'Authorization': 'Bearer ' + token('sub-' + who)})

    def request(self, op_type='Tenant.Stop', params=None, key=None, **scope):
        scope = scope or {'tenant_id': TENANT, 'environment_id': ENV}
        r = self.post('/v1/operations', {'type': op_type, 'params': {'reason': 'operator'} if params is None else params,
                                         'idempotency_key': key or str(uuid.uuid4()), **scope})
        assert r.status_code == 201, r.text
        return r.json()

    def approval(self, op, key=None, **over):
        a = {'op_id': op['id'], 'tenant_id': TENANT, 'action': op['type'],
             'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
             'deletion_case_id': DELETION_CASE, **over}
        a['custodian_signature'] = sign(a, key or self.custodian)
        return a

    def backup(self, age=600, state='recoverable'):
        op_id = self.w.store.dispatch('Tenant.Backup', tenant_id=TENANT, environment_id=None, params={},
                                      hosts={'app': APP_HOST}, idempotency_key=str(uuid.uuid4()))
        self.w.sql("UPDATE operation SET state = 'COMPLETED' WHERE id = %s", (op_id,))
        bid = str(uuid.uuid4())
        self.w.sql("INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, "
                   "gc_guard_held, missing_files, state, created_at) VALUES (%s, %s, %s, 'manual', 'final', %s, true, "
                   '0, %s, now())', (bid, ENV, op_id, datetime.now(timezone.utc) - timedelta(seconds=age), state))
        return bid


DELETION_CASE = str(uuid.uuid4())


@pytest.fixture
def api(w):
    return Api(w)


def _codes(w, action):
    return [r['after'] for r in w.sql('SELECT after FROM audit_event WHERE action = %s ORDER BY seq', (action,))]


# -- authentication and roles ------------------------------------------------------

@pytest.mark.parametrize('tok, status', [
    (None, 401), ('not-a-jwt', 401), (dict(key=ROGUE), 401), (dict(aud='other'), 401),
    (dict(iss='https://evil.test'), 401), (dict(life=-120), 401)])
def test_bad_tokens(api, tok, status):
    headers = {} if tok is None else {'Authorization': 'Bearer ' + (tok if isinstance(tok, str)
                                                                    else token('sub-founder', **tok))}
    assert api.client.get('/v1/operations/%s' % uuid.uuid4(), headers=headers).status_code == status


@pytest.mark.parametrize('who', ['nobody', 'gone', 'lapsed'])
def test_unknown_suspended_or_lapsed_operator_is_refused(api, who):
    assert api.post('/v1/operations', {'type': 'Tenant.Start', 'idempotency_key': 'x'}, who=who).status_code == 403


def test_auditor_reads_but_cannot_request(api):
    op = api.request()
    assert api.get('/v1/operations/%s' % op['id'], who='auditor').json()['state'] == 'DISPATCHED'
    assert api.post('/v1/operations', {'type': 'Tenant.Start', 'idempotency_key': 'y',
                                       'tenant_id': TENANT, 'environment_id': ENV}, who='auditor').status_code == 403


@pytest.mark.parametrize('tok', [dict(amr=('pwd',)), dict(auth_age=12 * 3600 + 60)])
def test_privileged_actions_need_fresh_mfa(api, w, tok):
    r = api.post('/v1/operations', {'type': 'Tenant.Start', 'idempotency_key': 'z', 'tenant_id': TENANT,
                                    'environment_id': ENV, 'params': {'reason': 'operator'}}, **tok)
    assert r.status_code == 403 and w.sql('SELECT * FROM operation') == []


def test_mfa_time_is_recorded(api, w):
    api.request()
    [row] = w.sql('SELECT mfa_verified_at FROM operator WHERE id = %s', (api.ops['founder'],))
    assert time.time() - row['mfa_verified_at'].timestamp() < 120


def test_no_self_grant(api, w):
    import psycopg
    with pytest.raises(psycopg.errors.CheckViolation):
        w.sql("INSERT INTO operator_role_grant (id, operator_id, role, valid_from, granted_by) "
              "VALUES (%s, %s, 'auditor', now(), %s)", (uuid.uuid4(), api.ops['auditor'], api.ops['auditor']))


# -- validation and preconditions -----------------------------------------------------

def _slot(w, environment_id=ENV, kind='production'):
    from ctlplane import vault
    w.sql("UPDATE environment SET kind = %s WHERE id = %s", (kind, environment_id))
    w.sql("INSERT INTO runtime_slot (environment_id, host_id, container_uid, http_port, gevent_port, workers, "
          "max_cron_threads, db_maxconn, limit_memory_soft, limit_memory_hard, limit_time_cpu, limit_time_real, "
          "mem_limit_bytes, cpu_millis, created_at) VALUES (%s, %s, 10042, 20010, 20011, 2, 1, 8, 671088640, "
          "805306368, 600, 1200, 1073741824, 1000, now())", (environment_id, APP_HOST))
    with psycopg.connect(w.dsn) as c:
        vault.provision(c, environment_id, TENANT, w.vault.recipient, datetime.now(timezone.utc))


@pytest.mark.parametrize('kind,smtp', [('production', 'relay'), ('restore_copy', 'sink')])
def test_start_carries_the_slot_and_the_run_files_secrets(api, w, kind, smtp):
    """/run/tenants is tmpfs: every start renders it again (DOC-04 §5.2), so ctl-1 sends what it needs."""
    import base64
    import json
    import pyrage
    _slot(w, kind=kind)
    op = api.request('Tenant.Start')
    assert (op['state'], op['result_code']) == ('DISPATCHED', None)
    [env] = w.store.claim(APP_HOST, 4)
    assert env['step'] == 'app.start' and env['params']['smtp'] == smtp
    assert (env['params']['runtime_slot']['container_uid'], env['params']['runtime_slot']['http_port']) == (10042, 20010)
    sealed = json.loads(pyrage.decrypt(base64.b64decode(env['secrets']), [w.ages[APP_HOST]]))
    assert set(sealed) == {'db_password', 'admin_passwd_hash', 'smtp_password', 'tenant_salt',
                           'tenant_admin_password'}


def test_start_without_a_slot_is_refused(api, w):
    op = api.request('Tenant.Start')
    assert (op['state'], op['result_code']) == ('REJECTED', 'NOT_FOUND')


def test_stop_is_dispatched_to_the_app_host(api, w):
    op = api.request()
    assert (op['state'], op['result_code']) == ('DISPATCHED', None) and op['fencing_token']
    [env] = w.store.claim(APP_HOST, 4)
    assert (env['op_id'], env['step'], env['tenant_state']) == (op['id'], 'app.stop', 'ACTIVE')
    assert [r['action'] for r in w.sql('SELECT action FROM audit_event ORDER BY seq')] == \
        ['operation.requested', 'operation.dispatched']
    assert str(w.op(op['id'])['requested_by']) == api.ops['founder']


@pytest.mark.parametrize('op_type, params, code, detail', [
    ('Tenant.Start', {'reason': 'whim'}, 'SCHEMA', {'params': 'reason'}),
    ('Tenant.Start', {}, 'SCHEMA', {'params': '(root)'}),
    ('Tenant.Nope', {}, 'SCHEMA', {'type': 'unknown'}),
    ('Agent.Query', {'op_id': None}, 'SCHEMA', {'type': 'unknown'}),
    ('Tenant.Relocate', {'target_host_id': str(uuid.uuid4())}, 'NOT_SUPPORTED', {'needs': 'runtime slot allocation'}),
    ('Tenant.RestoreToIsolated', {}, 'SCHEMA', {'params': '(root)'}),
    ('Tenant.RotateSecret', {'which': 'db_password'}, 'NOT_SUPPORTED', {'needs': 'envelope secrets'}),
    ('Tenant.RestoreProduction', {'backup_id': str(uuid.uuid4())}, 'NOT_SUPPORTED', {'needs': 'envelope secrets'}),
])
def test_rejected_before_dispatch(api, w, op_type, params, code, detail):
    op = api.request(op_type, params)
    assert (op['state'], op['result_code'], op['result_detail']) == ('REJECTED', code, detail)
    assert w.sql('SELECT * FROM operation_event') == []


def test_environment_must_belong_to_the_tenant(api, w):
    other = str(uuid.uuid4())
    w.sql("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ACTIVE')", (other,))
    assert api.request(tenant_id=other, environment_id=ENV)['result_code'] == 'NOT_FOUND'


def test_idempotency_key_returns_the_same_operation(api, w):
    a = api.request(key='once')
    assert api.request(key='once')['id'] == a['id']
    bad = api.request(params={'reason': 'whim'}, key='bad')
    assert api.request(key='bad')['id'] == bad['id']     # a rejected key stays used
    assert len(w.sql("SELECT * FROM operation")) == 2


def test_one_exclusive_operation_per_environment(api):
    api.request()
    op = api.request('Tenant.Stop')
    assert (op['state'], op['result_code']) == ('REJECTED', 'BUSY')


def test_tenant_state_gate(api, w):
    w.sql("UPDATE tenant SET lifecycle_state = 'SUSPENDED'")
    _slot(w)
    op = api.request('Tenant.Start')
    assert (op['result_code'], op['result_detail']) == ('POLICY_STATE', {'tenant_state': 'SUSPENDED'})
    assert api.request('Tenant.Stop')['state'] == 'DISPATCHED'


def test_missing_placement(api, w):
    w.sql('UPDATE environment SET app_host_id = NULL')
    assert api.request()['result_code'] == 'NO_PLACEMENT'


def test_host_drain_is_host_scoped(api, w):
    op = api.request('Host.Drain', {'evacuate': False}, host_id=DB_HOST)
    assert op['state'] == 'DISPATCHED'
    [env] = w.store.claim(DB_HOST, 4)
    assert env['step'] == 'any.drain' and env['environment_id'] is None
    bad = api.request('Host.Drain', {'evacuate': False}, host_id=DB_HOST, tenant_id=TENANT)
    assert (bad['result_code'], bad['result_detail']) == ('SCHEMA', {'scope': 'host'})


def test_expire_refuses_production(api):
    op = api.request('RestoreCopy.Expire', {'environment_id': ENV})
    assert op['result_code'] == 'POLICY_KIND'
    assert api.request('RestoreCopy.Expire', {'environment_id': str(uuid.uuid4())})['state'] == 'DISPATCHED'


# -- approval and DR-06 -------------------------------------------------------------

@pytest.fixture
def deletion(api, w):
    w.sql("UPDATE tenant SET lifecycle_state = 'DELETION_ELIGIBLE'")
    op = api.request('Tenant.Delete', {'deletion_case_id': DELETION_CASE})
    assert (op['state'], op['result_code']) == ('VALIDATED', 'AWAITING_APPROVAL')
    assert w.sql('SELECT * FROM operation_event') == []
    return op


def _approve(api, op, approval, who='custodian'):
    return api.post('/v1/operations/%s/approval' % op['id'], {'approval': approval}, who=who)


def test_delete_with_approval_and_a_recent_backup_is_dispatched(api, w, deletion):
    bid = api.backup(age=1800)
    approval = api.approval(deletion)
    r = _approve(api, deletion, approval)
    assert r.status_code == 200 and r.json()['state'] == 'DISPATCHED'
    assert r.json()['precondition_backup_id'] == bid
    [env] = w.store.claim(APP_HOST, 4)
    assert env['step'] == 'app.remove' and env['approval'] == approval
    from hostagent.canonical import verify, without
    assert verify(without(env['approval'], 'custodian_signature'), env['approval']['custodian_signature'],
                  [api.custodian.verify_key])


@pytest.mark.parametrize('backup', [None, dict(age=3700), dict(state='failed')])
def test_delete_without_a_recoverable_backup_in_the_last_hour(api, deletion, backup):
    if backup is not None:
        api.backup(**backup)
    r = _approve(api, deletion, api.approval(deletion))
    assert (r.json()['state'], r.json()['result_code']) == ('REJECTED', 'NO_RECOVERY_POINT')


@pytest.mark.parametrize('bad', [
    dict(op_id=str(uuid.uuid4())), dict(action='Tenant.Stop'), dict(tenant_id=str(uuid.uuid4())),
    dict(deletion_case_id=str(uuid.uuid4())),
    dict(expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()),
    dict(key='forged'), dict(key='breakglass'), dict(extra='x')])
def test_bad_approval_is_refused_and_audited(api, w, deletion, bad):
    api.backup()
    key = {'forged': SigningKey.generate(), 'breakglass': api.breakglass}.get(bad.pop('key', None))
    r = _approve(api, deletion, api.approval(deletion, key=key, **bad))
    assert r.status_code == 422 and r.json()['detail']['code'] == 'POLICY_APPROVAL'
    assert w.op(deletion['id'])['state'] == 'VALIDATED'
    assert [a['code'] for a in _codes(w, 'operation.approval_refused')] == ['POLICY_APPROVAL']


def test_approval_only_while_awaiting(api, deletion):
    api.backup()
    assert _approve(api, deletion, api.approval(deletion)).status_code == 200
    assert _approve(api, deletion, api.approval(deletion)).status_code == 409
    start = api.request('Tenant.Stop', key='s')     # BUSY: rejected
    assert _approve(api, start, api.approval(start)).status_code == 409


def test_breakglass_while_enabled_raises_sev2(w):
    api = Api(w, breakglass=True)
    w.sql("UPDATE tenant SET lifecycle_state = 'DELETION_ELIGIBLE'")
    op = api.request('Tenant.Delete', {'deletion_case_id': DELETION_CASE})
    api.backup()
    r = _approve(api, op, api.approval(op, key=api.breakglass), who='founder')
    assert r.json()['state'] == 'DISPATCHED' and r.json()['breakglass_used'] is True
    [incident] = w.sql('SELECT * FROM incident')
    assert incident['severity'] == 'sev2' and str(incident['operation_id']) == op['id']
    assert len(_codes(w, 'operation.breakglass')) == 1


def test_state_is_checked_again_at_approval(api, w, deletion):
    api.backup()
    w.sql("UPDATE tenant SET lifecycle_state = 'ACTIVE'")       # the customer withdrew meanwhile
    r = _approve(api, deletion, api.approval(deletion))
    assert (r.json()['state'], r.json()['result_code']) == ('REJECTED', 'POLICY_STATE')


# -- audit chain ------------------------------------------------------------------

def test_audit_chain_verifies_and_detects_a_forged_row(api, w):
    api.request()
    api.request(params={'reason': 'whim'})
    with w.store.connect() as c:
        assert audit.verify_chain(c) is None
    rows = w.sql('SELECT * FROM audit_event ORDER BY seq')
    w.sql("INSERT INTO audit_event (at, actor_kind, action, prev_hash, hash) VALUES (now(), 'system', 'forged', %s, %s)",
          (rows[-1]['hash'], b'\x01' * 32))
    with w.store.connect() as c:
        assert audit.verify_chain(c) == rows[-1]['seq'] + 1
    import psycopg
    with pytest.raises(psycopg.errors.RaiseException):
        w.sql("UPDATE audit_event SET action = 'x'")


def test_concurrent_requests_keep_one_chain(api, w):
    import threading
    envs = [str(uuid.uuid4()) for _ in range(8)]
    for e in envs:
        w.sql("INSERT INTO tenant (id, lifecycle_state) VALUES (%s, 'ACTIVE')", (e,))
        w.sql("INSERT INTO environment (id, tenant_id, kind, app_host_id) VALUES (%s, %s, 'production', %s)",
              (e, e, APP_HOST))
    threads = [threading.Thread(target=api.admission.request, args=(api.ops['founder'],),
                                kwargs=dict(op_type='Tenant.Stop', tenant_id=e, environment_id=e,
                                            params={'reason': 'operator'}, idempotency_key=e)) for e in envs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with w.store.connect() as c:
        assert audit.verify_chain(c) is None
    assert len(w.sql('SELECT * FROM audit_event')) == 16
