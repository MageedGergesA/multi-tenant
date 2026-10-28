"""VALIDATING → ACTIVE (DOC-03 §3.6, §5; INV-4, INV-15), from a Create run with
the evidence each step reports."""
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import APP_HOST, DB_HOST
from .test_capacity import World

TERMS = {'terms_version': 'H0-PILOT-1.0', 'document_sha256': 'ab' * 32, 'accepted_by_name': 'A. Customer',
         'accepted_at': '2026-10-20T10:00:00+00:00',
         'covers': ['region', 'retention', 'no_ha', 'no_pitr', 'nonpayment', 'exit', 'backup_expiry'],
         'region': 'eu-de-fsn1'}
TODAY = {'app.health': {'login': 200, 'websocket': 101, 'db_service_refused': True},
         'app.route': {'present': True, 'certificate': 'not_checked'}}
PUBLIC = {'app.health': {'login': 200, 'websocket': 101, 'db_service_refused': True, 'https_login': 200,
                         'https_websocket': 101, 'public_db_manager': 403},
          'app.route': {'present': True, 'certificate': 'issued'}}


class Act:
    def __init__(self, w):
        self.w = w
        self.cw = World(w)
        self.api = self.cw.api
        w.sql("UPDATE region SET backup_bucket = 'tenant-backups-eu'")

    def created(self, evidence, **image):
        """A tenant through Create, its steps answering with `evidence`."""
        op = self.cw.create()
        o = self.w.op(op['id'])
        digest = self.cw.release['image_digest']
        seen = {'app.image': {'present': True, 'image_id': 'sha256:' + 'f' * 64,
                              'repo_digests': ['registry.internal/tenants/odoo@' + digest]},
                'app.container': {'running': True, 'image_id': image.get('running', 'sha256:' + 'f' * 64)},
                **evidence}
        while True:
            [step] = self.w.sql("SELECT * FROM operation_step WHERE operation_id = %s AND state = 'dispatched'",
                                (op['id'],)) or [None]
            if step is None:
                break
            [env] = self.w.store.claim(str(step['host_id']), 8)
            self.w.store.apply(env['host_id'], self.w.response(env, observed=seen.get(step['name'], {})))
        assert self.state(o['tenant_id']) == 'VALIDATING'
        return str(o['tenant_id']), str(o['environment_id'])

    def state(self, tenant):
        return self.w.sql('SELECT lifecycle_state FROM tenant WHERE id = %s', (tenant,))[0]['lifecycle_state']

    def backup(self, tenant, env):
        op = self.api.request('Tenant.Backup', {'retention_tier': 'daily', 'lock_days': 7}, tenant_id=tenant,
                              environment_id=env)
        assert op['state'] == 'DISPATCHED', op                  # allowed in VALIDATING
        [e] = self.w.store.claim(APP_HOST, 4)
        now = datetime.now(timezone.utc)
        self.w.store.apply(APP_HOST, self.w.response(e, observed={
            'snapshot_time': (now - timedelta(seconds=30)).isoformat(), 'gc_guard_held': True,
            'referenced_files': 3, 'missing_files': 0, 'dump_sha256': 'aa' * 32, 'archive_sha256': 'bb' * 32,
            'object_version_id': 'v1', 'lock_until': (now + timedelta(days=7, minutes=5)).isoformat()}))
        return op

    def terms(self, tenant, **over):
        return self.api.post('/v1/tenants/%s/terms' % tenant, dict(TERMS, **over), who='founder')

    def check(self, tenant):
        r = self.api.post('/v1/tenants/%s/activation/check' % tenant, {})
        assert r.status_code == 200, r.text
        return r.json()

    def activate(self, tenant, check_id):
        return self.api.post('/v1/tenants/%s/activation' % tenant, {'check_id': check_id})


@pytest.fixture
def a(w):
    return Act(w)


def _statuses(check):
    return {k: v['status'] for k, v in check['results'].items()}


def test_with_todays_agent_evidence_activation_waits(a, w):
    tenant, env = a.created(TODAY)
    c = a.check(tenant)
    assert c['verdict'] == 'incomplete'
    assert _statuses(c) == {'health': 'pass', 'image_digest': 'pass', 'https': 'missing',
                            'db_manager_403': 'missing', 'first_backup': 'missing', 'placement_terms': 'missing'}
    r = a.activate(tenant, c['id'])
    assert r.status_code == 409 and a.state(tenant) == 'VALIDATING'


def test_all_evidence_then_operator_confirms(a, w):
    tenant, env = a.created(PUBLIC)
    a.backup(tenant, env)
    assert a.terms(tenant).status_code == 201
    c = a.check(tenant)
    assert c['verdict'] == 'pass', c
    r = a.activate(tenant, c['id'])
    assert r.status_code == 200 and a.state(tenant) == 'ACTIVE'
    [t] = w.sql('SELECT activation_check_id, activated_by FROM tenant WHERE id = %s', (tenant,))
    assert str(t['activation_check_id']) == c['id'] and str(t['activated_by']) == a.api.ops['founder']
    assert [x['action'] for x in w.sql('SELECT action FROM audit_event ORDER BY seq')][-1] == 'tenant.activated'
    [m] = w.sql('SELECT * FROM data_placement_manifest WHERE tenant_id = %s', (tenant,))
    assert (m['version'], str(m['app_host_id']), str(m['db_host_id']), m['backup_bucket']) == \
        (1, APP_HOST, DB_HOST, 'tenant-backups-eu')


@pytest.mark.parametrize('case, failed', [
    ('login', 'health'), ('websocket', 'health'), ('https', 'https'), ('wss', 'https'), ('cert', 'https'), ('public_db', 'db_manager_403'), ('db_service', 'db_manager_403'),
    ('image', 'image_digest'), ('region', 'placement_terms')])
def test_a_failed_check_sends_the_tenant_to_error(a, w, case, failed):
    health = dict(PUBLIC['app.health'])
    route = dict(PUBLIC['app.route'])
    image = {}
    if case == 'login':
        health['login'] = 500
    if case == 'websocket':
        health['websocket'] = 400
    if case == 'https':
        health['https_login'] = 502
    if case == 'wss':
        health['https_websocket'] = 404
    if case == 'cert':
        route['certificate'] = 'pending'
    if case == 'public_db':
        health['public_db_manager'] = 200
    if case == 'db_service':
        health['db_service_refused'] = False
    if case == 'image':
        image['running'] = 'sha256:' + 'e' * 64
    tenant, env = a.created({'app.health': health, 'app.route': route}, **image)
    a.backup(tenant, env)
    w.sql("INSERT INTO region (id, code, backup_recipient) VALUES (%s, 'eu-fi-hel1', 'age1x')", (uuid.uuid4(),))
    a.terms(tenant, region='eu-fi-hel1' if case == 'region' else 'eu-de-fsn1')
    c = a.check(tenant)
    assert c['verdict'] == 'fail' and [k for k, v in _statuses(c).items() if v == 'fail'] == [failed]
    assert a.state(tenant) == 'ERROR'


def test_loopback_database_service_answering_is_a_failure_even_unprobed_publicly(a, w):
    # Today's evidence (no public path), but the database service answered on loopback.
    tenant, _ = a.created({'app.health': dict(TODAY['app.health'], db_service_refused=False),
                           'app.route': TODAY['app.route']})
    c = a.check(tenant)
    assert c['results']['db_manager_403']['status'] == 'fail' and a.state(tenant) == 'ERROR'


def test_terms_must_cover_everything(a, w):
    tenant, _ = a.created(TODAY)
    r = a.terms(tenant, covers=TERMS['covers'][:-1])
    assert r.status_code == 422
    assert a.terms(tenant, region='nowhere').status_code == 404
    assert a.api.post('/v1/tenants/%s/terms' % tenant, TERMS, who='auditor').status_code == 403


def test_activation_needs_the_latest_fresh_passing_check(a, w):
    tenant, env = a.created(PUBLIC)
    a.backup(tenant, env)
    a.terms(tenant)
    first = a.check(tenant)
    second = a.check(tenant)
    assert a.activate(tenant, first['id']).status_code == 409                # not the latest
    a.api.admission.store.clock = lambda: time.time() + 3700
    r = a.activate(tenant, second['id'])
    assert r.status_code == 409 and 'older' in str(r.json())
    a.api.admission.store.clock = time.time
    w.sql("UPDATE backup_point SET state = 'expired'")                      # evidence gone since the check
    r = a.activate(tenant, second['id'])
    assert r.status_code == 409 and r.json()['detail']['detail']['detail'] == 'evidence changed'
    assert a.state(tenant) == 'VALIDATING'


def test_only_a_validating_tenant_and_only_an_operator(a, w):
    tenant, env = a.created(PUBLIC)
    a.backup(tenant, env)
    a.terms(tenant)
    c = a.check(tenant)
    assert a.api.post('/v1/tenants/%s/activation' % tenant, {'check_id': c['id']}, who='auditor').status_code == 403
    assert a.activate(tenant, c['id']).status_code == 200
    again = a.check(tenant)
    r = a.activate(tenant, again['id'])
    assert r.status_code == 409 and r.json()['detail']['detail'] == {'tenant_state': 'ACTIVE'}


def test_checks_are_append_only(a, w):
    import psycopg
    tenant, _ = a.created(TODAY)
    a.check(tenant)
    with pytest.raises(psycopg.errors.RaiseException):
        w.sql("UPDATE activation_check SET verdict = 'pass'")
