"""Host.RotateTrust (DOC-04 §2): a dispatch-key rotation end to end with an
enrolled real agent, and every way a trust document is refused."""
import base64
import json
import uuid

import pytest
from nacl.signing import SigningKey

from ctlplane.canonical import b64_public, sign
from hostagent import config as agent_config
from hostagent.poller import Poller

from .test_enrollment import _agent, e  # noqa: F401  (fixture)


class Fleet:
    def __init__(self, w, e):
        self.w, self.e = w, e
        self.opened, self.toml = e.enrolled()
        self.host = self.opened['host_id']
        self.agent, self.cp = _agent(w, self.toml)
        # The shared fixture marks its hosts enrolled; here only real agents are.
        w.sql('UPDATE host SET client_cert_sha256 = NULL WHERE id <> %s', (self.host,))

    def run(self):
        """One poll by the enrolled agent, steps finished and answered."""
        p = Poller(self.agent, self.cp, workers=1, wait=0, sleep=lambda s: None)
        n = p.run_once()
        p.pool.shutdown(wait=True)
        return n

    def add_dispatch(self):
        key = SigningKey.generate()
        self.w.sql("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'dispatch', %s)",
                   (uuid.uuid4(), b64_public(key)))
        return key

    def retire(self, key):
        self.w.sql('UPDATE signing_key SET retired_at = now() WHERE public_key = %s', (b64_public(key),))

    def publish(self, key=None, **over):
        """Draft, sign with the release key, authorize. → the signed document."""
        r = self.e.api.post('/v1/trust', {})
        assert r.status_code == 201, r.text
        doc = dict(r.json()['document'], **over)
        doc['release_signature'] = sign({k: v for k, v in doc.items() if k != 'release_signature'},
                                        key or self.e.release)
        r = self.e.api.post('/v1/trust/%d/authorize' % doc['trust_version'], {'document': doc})
        return doc, r

    def rollout(self):
        r = self.e.api.post('/v1/trust/rollout', {})
        assert r.status_code == 200, r.text
        return r.json()

    def drain(self):
        return self.w.store.dispatch('Host.Drain', tenant_id=None, environment_id=None,
                                     params={'evacuate': False}, hosts={'any': self.host},
                                     idempotency_key=str(uuid.uuid4()))

    def version(self):
        return self.w.sql('SELECT trust_version FROM host WHERE id = %s', (self.host,))[0]['trust_version']


@pytest.fixture
def f(w, e):  # noqa: F811
    return Fleet(w, e)


def _dispatch_keys(toml):
    return {base64.b64encode(bytes(k)).decode() for k in agent_config.load(toml).trust.dispatch}


def test_dispatch_key_rotation_end_to_end(w, f):
    old = w.dispatch
    new = f.add_dispatch()
    doc, r = f.publish()
    assert r.status_code == 200 and doc['trust']['dispatch'] == [b64_public(old), b64_public(new)]
    [agent_key] = w.sql('SELECT k.public_key FROM host h JOIN signing_key k ON k.id = h.agent_key_id '
                        'WHERE h.id = %s', (f.host,))
    assert doc['trust']['agents'] == [agent_key['public_key']]
    out = f.rollout()
    assert [o['state'] for o in out['operations']] == ['DISPATCHED']
    assert f.run() == 1
    assert f.version() == 1
    assert _dispatch_keys(f.toml) == {b64_public(old), b64_public(new)}           # on disk, re-checked
    assert len(agent_config.load(f.toml).trust.agents) == 1
    w.store.key = new                                                               # ctl-1 switches
    op = f.drain()
    assert f.run() == 1 and w.op(op)['state'] == 'COMPLETED'                       # in memory too
    f.retire(old)
    doc2, r = f.publish()
    assert doc2['trust']['dispatch'] == [b64_public(new)]
    f.rollout()
    assert f.run() == 1 and f.version() == 2
    w.store.key = old                                                               # a stolen old key
    op = f.drain()
    f.run()
    assert (w.op(op)['state'], w.op(op)['result_code']) == ('FAILED', 'SIG_INVALID')
    statuses = f.e.api.get('/v1/trust', who='auditor').json()
    assert statuses['active_version'] == 2 and statuses['hosts'][0]['trust_version'] == 2


def test_agent_refuses_a_document_without_the_key_signing_it(w, f):
    f.add_dispatch()
    f.retire(w.dispatch)                     # but ctl-1 still signs with it
    f.publish()
    f.rollout()
    f.run()
    [op] = w.sql("SELECT state, result_code, result_detail FROM operation WHERE type = 'Host.RotateTrust'")
    assert (op['state'], op['result_code']) == ('FAILED', 'POLICY_TRUST')
    assert f.agent.config.trust.version == 0 and f.version() == 0
    assert _dispatch_keys(f.toml) == {b64_public(w.dispatch)}


@pytest.mark.parametrize('case', ['tampered', 'older'])
def test_agent_refuses_unsigned_or_older_documents(w, f, case):
    f.publish()
    f.rollout()
    f.run()                                  # now on version 1
    doc = json.loads(json.dumps(w.sql("SELECT signed_body FROM trust_document WHERE state = 'active'")[0]
                                ['signed_body']))
    if case == 'tampered':
        doc['trust_version'] = 2
        doc['trust']['agents'].append(b64_public(SigningKey.generate()))
    # Straight to the outbox, past admission (which would refuse it first).
    op = w.store.dispatch('Host.RotateTrust', tenant_id=None, environment_id=None, params={'trust_document': doc},
                          hosts={'any': f.host}, idempotency_key=case)
    f.run()
    assert (w.op(op)['state'], w.op(op)['result_code']) == ('FAILED', 'POLICY_TRUST')
    assert f.agent.config.trust.version == 1


def test_ctl_refusals(w, f):
    assert f.rollout()['operations'] == []                                  # nobody behind version 0
    r = f.e.api.post('/v1/operations', {'type': 'Host.RotateTrust', 'host_id': f.host, 'idempotency_key': 'k'})
    assert r.json()['result_code'] == 'NO_TRUST_DOCUMENT'
    _, r = f.publish(key=SigningKey.generate())
    assert r.status_code == 422 and r.json()['detail']['code'] == 'SIG_INVALID'
    _, r = f.publish(trust_version=99)
    assert r.status_code == 404                                             # not the pending draft
    doc, r = f.publish(issued_at='2020-01-01T00:00:00+00:00')
    assert r.status_code == 409
    doc, _ = f.publish()
    f.rollout()
    f.run()
    r = f.e.api.post('/v1/operations', {'type': 'Host.RotateTrust', 'host_id': f.host, 'idempotency_key': 'k2'})
    assert (r.json()['result_code'], r.json()['result_detail']) == (
        'POLICY_STATE', {'detail': 'already on version %d' % doc['trust_version']})
    w.sql("UPDATE signing_key SET retired_at = now() WHERE purpose = 'dispatch'")
    r = f.e.api.post('/v1/trust', {})
    assert r.json()['detail']['code'] == 'NO_DISPATCH_KEY'


def test_host_enrolled_later_starts_on_the_active_version(w, f):
    f.publish()
    f.rollout()
    f.run()
    later, toml = f.e.enrolled('later')
    assert later['authorization']['trust_version'] == 1
    assert agent_config.load(toml).trust.version == 1
    assert f.e.trust.behind() == []
