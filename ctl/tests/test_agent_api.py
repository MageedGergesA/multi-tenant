"""The real agent (hostagent Agent + Poller) against the real agent API over
mutual TLS: dispatch on ctl-1, poll, run, respond, operation state."""
import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import psycopg
import pytest
from nacl.signing import SigningKey

from hostagent.agentd import Agent
from hostagent.config import AgentConfig, Trust
from hostagent.execd import Executor, LocalExecClient
from hostagent.logs import AuditLog
from hostagent.naming import sid
from hostagent.poller import ControlPlane, Poller, TransportError, tls_context
from hostagent.state import State

from .conftest import APP_HOST, DB_HOST, ENV, OTHER_HOST, TENANT


class FakeApp:
    def __init__(self):
        self.running = {}
        self.delay = 0

    def container_inspect(self, sid):
        return {'exists': sid in self.running, 'running': self.running.get(sid, False)}

    def container_start(self, sid):
        time.sleep(self.delay)
        self.running[sid] = True
        return {}

    def file_write_secret(self, sid, name, data_b64):
        return {}

    def nft_inspect(self, sid):
        return {'applied': True}

    def file_write_conf(self, sid, conf):
        return {}


class Host:
    """One host's agentd, polling the API with its own client certificate."""

    def __init__(self, w, pki, url, host_id, role, cert, tmp_path, heartbeat_s=0):
        self.w = w
        self.backend = FakeApp()
        nobody = SigningKey.generate().verify_key
        config = AgentConfig(host_id=host_id, role=role, state_dir=tmp_path, registry_host='registry.internal',
                             heartbeat_s=heartbeat_s, age_identity=w.ages[host_id],
                             trust=Trust(dispatch=(w.dispatch.verify_key,), release=nobody, custodian=(nobody,),
                                         breakglass=nobody, breakglass_enabled=False))
        self.state = State(tmp_path / ('%s.db' % role))
        executor = Executor(role, self.backend if role == 'app' else object(), AuditLog(None))
        self.agent = Agent(config, self.state, LocalExecClient(executor), w.agent_keys[host_id], AuditLog(None),
                           capacity=lambda params: True)
        self.cp = ControlPlane(url, host_id, tls_context(pki / 'ca.pem', pki / (cert + '.pem'), pki / (cert + '.key')))
        self.poller = Poller(self.agent, self.cp, workers=2, wait=0, sleep=lambda s: None)

    def register(self):
        self.state.register(environment_id=ENV, tenant_id=TENANT, sid=sid(ENV), container_uid=10001,
                            http_port=20000, gevent_port=20001, kind='production', egress_profile='production',
                            now=time.time())
        self.backend.running[sid(ENV)] = False

    def run(self):
        """One poll, then wait for the steps it started and their delivery."""
        n = self.poller.run_once()
        self.poller.pool.shutdown(wait=True)
        self.poller.pool = type(self.poller.pool)(2)
        return n


_SLOT = {'container_uid': 10001, 'http_port': 20000, 'gevent_port': 20001, 'workers': 2, 'max_cron_threads': 1,
         'db_maxconn': 8, 'limit_memory_soft': 671088640, 'limit_memory_hard': 805306368, 'limit_time_cpu': 600,
         'limit_time_real': 1200, 'mem_limit_bytes': 1073741824, 'cpu_millis': 1000}


def start(w, key='k1'):
    """Tenant.Start as admission fills it in: the slot, SMTP mode, and the environment's secrets bound."""
    from ctlplane import vault
    if not w.sql('SELECT 1 FROM secret_binding WHERE environment_id = %s', (ENV,)):
        with psycopg.connect(w.dsn) as c:
            vault.provision(c, ENV, TENANT, w.vault.recipient, datetime.now(timezone.utc))
    return w.store.dispatch('Tenant.Start', tenant_id=TENANT, environment_id=ENV,
                            params={'reason': 'operator', 'runtime_slot': _SLOT, 'smtp': 'relay'},
                            hosts={'app': APP_HOST}, idempotency_key=key)


@pytest.fixture
def app(w, pki, api, tmp_path):
    (tmp_path / 'app').mkdir()
    h = Host(w, pki, api, APP_HOST, 'app', 'app', tmp_path / 'app')
    h.register()
    return h


@pytest.fixture
def db(w, pki, api, tmp_path):
    (tmp_path / 'db').mkdir()
    return Host(w, pki, api, DB_HOST, 'db', 'db', tmp_path / 'db')


def post(url, path, body, pki, cert):
    ctx = tls_context(pki / 'ca.pem', pki / (cert + '.pem'), pki / (cert + '.key'))
    req = urllib.request.Request(url + path, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.status, json.loads(r.read() or b'null')
    except urllib.error.HTTPError as e:
        return e.code, None


def test_start_runs_end_to_end(w, app):
    op_id = start(w)
    assert app.run() == 1
    op = w.op(op_id)
    assert (op['state'], op['result_code']) == ('COMPLETED', 'OK') and op['finished_at']
    [step] = w.steps(op_id)
    assert step['state'] == 'done' and step['observed'] == {'container': {'exists': True, 'running': True}}
    [resp] = w.sql('SELECT * FROM agent_response')
    assert resp['outcome'] == 'completed' and resp['body']['evidence_sha256'] == step['evidence_sha256']
    assert app.backend.running[sid(ENV)]
    [host] = w.sql('SELECT agent_high_water_fence FROM host WHERE id = %s', (APP_HOST,))
    assert host['agent_high_water_fence'] == op['fencing_token']


def test_two_host_operation_goes_step_by_step(w, app, db):
    op_id = w.expire()
    assert db.run() == 0                   # db.expire isn't due before app.expire is done
    assert app.run() == 1
    assert w.op(op_id)['state'] == 'DISPATCHED' and [s['state'] for s in w.steps(op_id)] == ['done', 'dispatched']
    assert db.run() == 1
    assert w.op(op_id)['state'] == 'COMPLETED'
    assert [s['observed'] for s in w.steps(op_id)] == [{'registry': 'absent'}] * 2


def test_heartbeats_reach_ctl_and_hold_the_lease(w, pki, api, tmp_path):
    (tmp_path / 'hb').mkdir()
    h = Host(w, pki, api, APP_HOST, 'app', 'app', tmp_path / 'hb', heartbeat_s=0.1)
    h.register()
    h.backend.delay = 0.45
    op_id = start(w)
    h.run()
    outcomes = [r['outcome'] for r in w.sql('SELECT outcome FROM agent_response ORDER BY id')]
    assert outcomes[-1] == 'completed' and set(outcomes[:-1]) == {'heartbeat'} and len(outcomes) >= 3
    assert w.steps(op_id)[0]['deadline_at'] is not None


def test_another_hosts_certificate_is_refused(w, pki, api, app):
    op_id = start(w)
    assert post(api, '/v1/agents/%s/poll' % APP_HOST, {'wait': 0, 'capacity': 4}, pki, 'other')[0] == 403
    assert post(api, '/v1/agents/%s/poll' % APP_HOST, {'wait': 0, 'capacity': 4}, pki, 'with_org')[0] == 403
    assert w.sql('SELECT * FROM operation_event_delivery') == []
    assert app.run() == 1 and w.op(op_id)['state'] == 'COMPLETED'


def test_client_from_another_ca_is_refused(w, pki, api):
    cp = ControlPlane(api, APP_HOST, tls_context(pki / 'ca.pem', pki / 'rogue.pem', pki / 'rogue.key'))
    with pytest.raises(TransportError):
        cp.poll(0, 1)


def test_client_without_certificate_is_refused(w, pki, api):
    ctx = ssl.create_default_context(cafile=str(pki / 'ca.pem'))
    req = urllib.request.Request(api + '/v1/agents/%s/poll' % APP_HOST, b'{"wait":0,"capacity":1}',
                                 {'Content-Type': 'application/json'})
    with pytest.raises((urllib.error.URLError, ssl.SSLError, ConnectionError)):
        urllib.request.urlopen(req, context=ctx, timeout=5).read()


def test_retired_host_is_refused(w, pki, api, app):
    start(w)
    w.sql("UPDATE host SET state = 'retired' WHERE id = %s", (APP_HOST,))
    with pytest.raises(TransportError, match='403'):
        app.cp.poll(0, 1)


def test_forged_and_misattributed_responses_change_nothing(w, pki, api, app):
    op_id = start(w)
    [env] = w.store.claim(APP_HOST, 1)
    forged = w.response(env, key=SigningKey.generate())
    # The other host signs with its own key: as itself, then claiming to be the app host.
    as_other = w.response(env, host=OTHER_HOST)
    claiming = w.response(env, key=w.agent_keys[OTHER_HOST])
    status, body = post(api, '/v1/agents/%s/responses' % APP_HOST, {'responses': [forged]}, pki, 'app')
    assert (status, body['outcomes']) == (200, ['bad_signature'])
    status, body = post(api, '/v1/agents/%s/responses' % OTHER_HOST, {'responses': [as_other, claiming]}, pki,
                        'other')
    assert body['outcomes'] == ['wrong_host', 'wrong_host']
    assert w.op(op_id)['state'] == 'DISPATCHED'
    status, body = post(api, '/v1/agents/%s/responses' % APP_HOST, {'responses': [w.response(env)]}, pki, 'app')
    assert body['outcomes'] == ['completed']


def test_oversized_request_is_refused(w, pki, api):
    status, _ = post(api, '/v1/agents/%s/responses' % APP_HOST, {'responses': [{'x': 'a' * (5 << 20)}]}, pki, 'app')
    assert 400 <= status < 500


# -- reconciling with the real agent ---------------------------------------------

def _wait(cond, timeout=10):
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end
        time.sleep(0.05)


def test_lost_poll_reply_is_read_back_and_redispatched(w, app):
    from ctlplane.reconciler import Reconciler
    r = Reconciler(w.store)
    w.store.liveness = 0.3
    op_id = start(w)
    [lost] = w.store.claim(APP_HOST, 4)                 # handed out; the reply never arrives
    time.sleep(0.4)
    assert r.run_once() == {op_id: 'probing'}
    w.store.liveness = 150
    assert app.run() == 1                               # the agent answers the probe: no journal row
    assert r.run_once() == {op_id: 'resume'}
    assert app.run() == 1
    op = w.op(op_id)
    assert op['state'] == 'COMPLETED' and op['attempt'] == 2 and op['fencing_token'] > lost['fencing_token']
    assert app.backend.running[sid(ENV)]


def test_agent_crash_mid_step_is_recovered(w, pki, api, app, tmp_path):
    from ctlplane.reconciler import Reconciler
    r = Reconciler(w.store)
    app.backend.delay = 3
    op_id = start(w)
    app.poller.run_once()                               # the step starts, then agentd "dies"
    _wait(app.state.interrupted_steps)
    first = w.op(op_id)['fencing_token']

    restarted = Host(w, pki, api, APP_HOST, 'app', 'app', tmp_path / 'app')
    restarted.backend.running[sid(ENV)] = False
    restarted.poller.start()                            # recover(): failed/TIMEOUT, delivered
    assert w.op(op_id)['state'] == 'RECONCILING'
    assert r.run_once() == {op_id: 'probing'}
    assert restarted.run() == 1
    assert r.run_once() == {op_id: 'resume'}
    assert restarted.run() == 1
    op = w.op(op_id)
    assert op['state'] == 'COMPLETED' and op['fencing_token'] > first
    # The old process's step finishes later; its result carries the old token.
    app.poller.pool.shutdown(wait=True)
    outcomes = [x['outcome'] for x in w.sql('SELECT outcome FROM agent_response WHERE fencing_token = %s',
                                            (first,))]
    assert outcomes == ['reconciling', 'stale']


def test_operator_request_runs_on_the_agent(w, app):
    from .test_operator_api import Api
    api = Api(w)
    op = api.request()
    assert op['state'] == 'DISPATCHED'
    assert app.run() == 1
    assert api.get('/v1/operations/%s' % op['id'], who='auditor').json()['state'] == 'COMPLETED'
