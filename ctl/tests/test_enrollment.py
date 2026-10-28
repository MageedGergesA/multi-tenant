"""Host.Enroll end to end: operator opens, the release key authorizes, the real
agent enrolls over TLS, then polls and answers with what it was given."""
import hashlib
import json
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid

import pyrage
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from nacl.signing import SigningKey

from ctlplane import enroll_api
from ctlplane.canonical import b64_public, sign
from ctlplane.enrollment import MAX_ATTEMPTS, Enrollment
from ctlplane.tls import server
from ctlplane.trust import Trust
from hostagent import config as agent_config
from hostagent.agentd import Agent
from hostagent.enroll import EnrollError, enroll
from hostagent.execd import Executor, LocalExecClient
from hostagent.logs import AuditLog
from hostagent.poller import ControlPlane, Poller, TransportError, tls_context
from hostagent.state import State

from .conftest import _free_port
from .test_operator_api import Api


class Enroll:
    def __init__(self, w, pki, api_url, tmp_path):
        self.w, self.pki, self.api_url, self.tmp = w, pki, api_url, tmp_path
        self.release = SigningKey.generate()
        w.sql("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'release', %s), (%s, 'dispatch', %s)",
              (uuid.uuid4(), b64_public(self.release), uuid.uuid4(), b64_public(w.dispatch)))
        self.enrollment = Enrollment(w.store, ca_cert_pem=(pki / 'ca.pem').read_bytes(),
                                     ca_key_pem=(pki / 'ca.key').read_bytes())
        self.trust = Trust(w.store)
        self.api = Api(w, enrollment=self.enrollment, trust=self.trust)
        port = _free_port()
        self.srv = server(enroll_api.create_app(self.enrollment), '127.0.0.1', port, cert=pki / 'server.pem',
                          key=pki / 'server.key', client_certs=False)
        threading.Thread(target=self.srv.run, daemon=True).start()
        while not self.srv.started:
            time.sleep(0.01)
        self.url = 'https://127.0.0.1:%d' % port

    def open(self, **kw):
        if 'host_id' in kw:
            r = self.api.post('/v1/hosts/%s/enrollment' % kw['host_id'], {})
        else:
            r = self.api.post('/v1/hosts', {'role': 'app', 'region': 'eu-de-fsn1', 'private_ip': '10.0.0.41',
                                            'totals': {'vcpu_milli': 8000, 'ram_mb': 16384, 'disk_gb': 200}})
        assert r.status_code == 201, r.text
        return r.json()

    def authorize(self, opened, key=None, **over):
        signed = dict(opened['authorization'], **over)
        signed['release_signature'] = sign({k: v for k, v in signed.items() if k != 'release_signature'},
                                           key or self.release)
        return self.api.post('/v1/hosts/%s/enrollment/authorize' % opened['host_id'], {'authorization': signed})

    def config(self, host_id, name='agent', role='app'):
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        toml = d / 'agent.toml'
        toml.write_text('\n'.join('%s = %s' % (k, json.dumps(v)) for k, v in {
            'host_id': host_id, 'role': role, 'state_dir': str(d / 'state'), 'registry_host': 'registry.internal',
            'ctl_url': self.api_url, 'ctl_ca': str(self.pki / 'ca.pem'), 'enroll_url': self.url,
            'trust_root': b64_public(self.release), 'tls_cert': str(d / 'tls.crt'),
            'tls_key': str(d / 'tls.key')}.items()))
        return toml

    def enrolled(self, name='agent'):
        opened = self.open()
        assert self.authorize(opened).status_code == 200
        toml = self.config(opened['host_id'], name)
        enroll(toml, opened['bootstrap_token'])
        return opened, toml

    def stop(self):
        self.srv.should_exit = True


@pytest.fixture
def e(w, pki, api, tmp_path):
    x = Enroll(w, pki, api, tmp_path)
    yield x
    x.stop()


def _agent(w, toml):
    config = agent_config.load(toml)
    key = SigningKey((config.state_dir / 'agent.key').read_bytes())
    agent = Agent(config, State(config.state_dir / 'agent.db'), LocalExecClient(Executor('app', object(),
                                                                                         AuditLog(None))),
                  key, AuditLog(None))
    cp = ControlPlane(config.ctl_url, config.host_id, tls_context(config.ctl_ca, config.tls_cert, config.tls_key))
    return agent, cp


# -- the whole path -----------------------------------------------------------------

def test_enrolled_agent_polls_and_its_answers_verify(w, e):
    opened, toml = e.enrolled()
    host_id = opened['host_id']
    [host] = w.sql('SELECT * FROM host WHERE id = %s', (host_id,))
    assert host['state'] == 'active' and host['enrolled_at'] and host['age_recipient'].startswith('age1')
    state = toml.parent / 'state'
    for f, mode in (('agent.key', 0o600), ('age.key', 0o600), ('trust.json', 0o644)):
        assert (state / f).stat().st_mode & 0o777 == mode
    assert (toml.parent / 'tls.key').stat().st_mode & 0o777 == 0o600
    config = agent_config.load(toml)                         # trust pinned from the signed authorization
    assert [bytes(k) for k in config.trust.dispatch] == [bytes(w.dispatch.verify_key)]
    assert bytes(config.trust.release) == bytes(e.release.verify_key)
    assert len(config.trust.custodian) == 1
    op_id = w.store.dispatch('Host.Drain', tenant_id=None, environment_id=None, params={'evacuate': False},
                             hosts={'any': host_id}, idempotency_key='d')
    agent, cp = _agent(w, toml)
    p = Poller(agent, cp, workers=1, wait=0, sleep=lambda s: None)
    assert p.run_once() == 1
    p.pool.shutdown(wait=True)
    assert w.op(op_id)['state'] == 'COMPLETED'
    assert [a['action'] for a in w.sql('SELECT action FROM audit_event ORDER BY seq')][-3:] == \
        ['host.enrollment_opened', 'host.enrollment_authorized', 'host.enrolled']


def test_reenrolling_retires_the_old_certificate_and_key(w, e):
    opened, toml = e.enrolled()
    host_id = opened['host_id']
    old_agent, old_cp = _agent(w, toml)
    again = e.open(host_id=host_id)
    assert e.authorize(again).status_code == 200
    new_toml = e.config(host_id, 'rebuilt')
    enroll(new_toml, again['bootstrap_token'])
    with pytest.raises(TransportError, match='403'):
        old_cp.poll(0, 1)                                    # same CN, other certificate
    _, new_cp = _agent(w, new_toml)
    assert new_cp.poll(0, 1) == []
    op_id = w.store.dispatch('Host.Drain', tenant_id=None, environment_id=None, params={'evacuate': False},
                             hosts={'any': host_id}, idempotency_key='d')
    [env] = w.store.claim(host_id, 1)
    old = old_agent._respond(env, 'done', 'OK', {'draining': True}, time.time())
    assert w.store.apply(host_id, old) == 'bad_signature'    # the old key is retired
    assert w.op(op_id)['state'] == 'DISPATCHED'
    assert len(w.sql("SELECT * FROM signing_key WHERE purpose = 'agent' AND retired_at IS NOT NULL")) == 1


# -- refusals ---------------------------------------------------------------------

def test_token_is_useless_until_the_release_key_signs(w, e):
    opened = e.open()
    with pytest.raises(EnrollError, match='403'):
        enroll(e.config(opened['host_id']), opened['bootstrap_token'])
    assert not (e.tmp / 'agent' / 'state' / 'agent.key').exists()


@pytest.mark.parametrize('bad, status', [(dict(key='other'), 422), (dict(role='db'), 409)])
def test_authorization_must_be_the_release_keys_signature_over_the_open_body(w, e, bad, status):
    opened = e.open()
    key = SigningKey.generate() if bad.pop('key', None) else None
    assert e.authorize(opened, key=key, **bad).status_code == status
    assert w.sql('SELECT state FROM host_enrollment')[0]['state'] == 'pending'


def test_wrong_token_counts_and_revokes(w, e):
    opened = e.open()
    e.authorize(opened)
    toml = e.config(opened['host_id'])
    for _ in range(MAX_ATTEMPTS):
        with pytest.raises(EnrollError, match='403'):
            enroll(toml, 'guess-' + uuid.uuid4().hex)
    with pytest.raises(EnrollError, match='403'):
        enroll(toml, opened['bootstrap_token'])             # too late: revoked
    assert w.sql('SELECT state, failed_attempts FROM host_enrollment')[0] == {'state': 'revoked',
                                                                              'failed_attempts': MAX_ATTEMPTS}


def test_token_is_one_time(w, e):
    opened, _ = e.enrolled()
    with pytest.raises(EnrollError, match='403'):
        enroll(e.config(opened['host_id'], 'twice'), opened['bootstrap_token'])


def test_expired_enrollment(w, e):
    opened = e.open()
    e.authorize(opened)
    w.sql("UPDATE host_enrollment SET expires_at = now() - interval '1 second'")
    with pytest.raises(EnrollError, match='403'):
        enroll(e.config(opened['host_id']), opened['bootstrap_token'])


def test_compromised_ctl_cannot_swap_the_dispatch_key(w, e):
    opened = e.open()
    e.authorize(opened)
    rogue = b64_public(SigningKey.generate())
    w.sql("UPDATE host_enrollment SET signed_body = jsonb_set(signed_body, '{trust,dispatch}', %s::jsonb)",
          (json.dumps([rogue]),))
    toml = e.config(opened['host_id'])
    with pytest.raises(EnrollError, match='not signed by the release key'):
        enroll(toml, opened['bootstrap_token'])
    assert not (toml.parent / 'state').exists() or not any((toml.parent / 'state').iterdir())


def test_tampered_trust_is_refused_at_start(w, e):
    _, toml = e.enrolled()
    path = toml.parent / 'state' / 'trust.json'
    signed = json.loads(path.read_text())
    signed['trust']['dispatch'] = [b64_public(SigningKey.generate())]
    path.write_text(json.dumps(signed))
    with pytest.raises(EnrollError, match='release key'):
        agent_config.load(toml)


def test_agent_will_not_overwrite_an_enrolled_state(w, e):
    opened, toml = e.enrolled()
    again = e.open(host_id=opened['host_id'])
    e.authorize(again)
    with pytest.raises(EnrollError, match='already enrolled'):
        enroll(toml, again['bootstrap_token'])


def _raw(e, opened, **over):
    """A hand-made enrollment request, as a broken or hostile agent might send."""
    signing = SigningKey.generate()
    tls_key = ec.generate_private_key(ec.SECP256R1())
    cn = over.pop('cn', opened['host_id'])
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(tls_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    age = str(pyrage.x25519.Identity.generate().to_public())
    claim = {'host_id': opened['host_id'], 'token_sha256': hashlib.sha256(opened['bootstrap_token'].encode()).hexdigest(),
             'age_recipient': age, 'csr_sha256': hashlib.sha256(csr.encode()).hexdigest()}
    body = {'host_id': opened['host_id'], 'token': opened['bootstrap_token'], 'agent_key': b64_public(signing),
            'age_recipient': age, 'csr_pem': csr, 'proof': sign(claim, over.pop('proof_key', signing)), **over}
    ctx = ssl.create_default_context(cafile=str(e.pki / 'ca.pem'))
    req = urllib.request.Request(e.url + '/v1/enroll', json.dumps(body).encode(), {'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b'null')


@pytest.mark.parametrize('over, code', [(dict(cn='someone-else'), 'SCHEMA'),
                                        (dict(proof_key=SigningKey.generate()), 'SIG_INVALID'),
                                        (dict(age_recipient='age1nope'), 'SCHEMA')])
def test_bad_keys_are_refused_and_the_token_survives(w, e, over, code):
    opened = e.open()
    e.authorize(opened)
    status, body = _raw(e, opened, **over)
    assert (status, body['detail']['code']) == (422, code)
    assert w.sql('SELECT state FROM host_enrollment')[0]['state'] == 'authorized'
    assert _raw(e, opened)[0] == 200


def test_unknown_host_and_garbage_get_the_same_answer(w, e):
    opened = e.open()
    e.authorize(opened)
    assert _raw(e, dict(opened, host_id=str(uuid.uuid4())))[0] == 403
    assert _raw(e, dict(opened, host_id='not-a-uuid'))[0] == 403


def test_new_host_needs_a_private_address_and_a_known_region(w, e):
    for body in ({'role': 'app', 'region': 'eu-de-fsn1', 'private_ip': '8.8.8.8'},
                 {'role': 'app', 'region': 'nowhere', 'private_ip': '10.0.0.9'},
                 {'role': 'ctl', 'region': 'eu-de-fsn1', 'private_ip': '10.0.0.9'}):
        assert e.api.post('/v1/hosts', body).status_code in (404, 422)
    assert e.api.post('/v1/hosts', {'role': 'app', 'region': 'eu-de-fsn1', 'private_ip': '10.0.0.9'},
                      who='auditor').status_code == 403


def test_agent_refuses_another_hosts_authorization(w, e):
    # A compromised ctl-1 answers with a genuine, release-signed authorization for another host.
    mine, theirs = e.open(), e.open()
    e.authorize(mine)
    e.authorize(theirs)
    w.sql('UPDATE host_enrollment SET signed_body = (SELECT signed_body FROM host_enrollment WHERE host_id = %s) '
          'WHERE host_id = %s', (theirs['host_id'], mine['host_id']))
    toml = e.config(mine['host_id'])
    with pytest.raises(EnrollError, match='another host'):
        enroll(toml, mine['bootstrap_token'])
    assert not (toml.parent / 'state' / 'agent.key').exists()
