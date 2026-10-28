"""Polling ctl-1 (poller.py) against a fake ctl-1 over mutual TLS 1.3."""
import json
import ssl
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hostagent.agentd import Agent
from hostagent.canonical import verify, without
from hostagent.envelope import request_sha256
from hostagent.execd import LocalExecClient
from hostagent.poller import ControlPlane, Poller, TransportError, tls_context
from hostagent.state import State

from .conftest import ENV_A, ENV_B, HOST_ID


def _openssl(*args, cwd):
    subprocess.run(['openssl', *args], cwd=cwd, check=True, capture_output=True)


def _issue(d, ca, name, cn, san=None):
    _openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', name + '.key',
             '-out', name + '.csr', '-subj', '/CN=' + cn, cwd=d)
    ext = d / (name + '.ext')
    ext.write_text('subjectAltName=%s\n' % san if san else 'basicConstraints=CA:FALSE\n')
    _openssl('x509', '-req', '-in', name + '.csr', '-CA', ca + '.pem', '-CAkey', ca + '.key', '-CAcreateserial',
             '-out', name + '.pem', '-days', '1', '-extfile', ext.name, cwd=d)


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp('pki')
    for ca in ('ca', 'rogue_ca'):
        _openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                 '-keyout', ca + '.key', '-out', ca + '.pem', '-subj', '/CN=' + ca, '-days', '1',
                 '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign', cwd=d)
    _issue(d, 'ca', 'server', 'ctl-1', 'DNS:localhost,IP:127.0.0.1')
    _issue(d, 'ca', 'client', HOST_ID)
    _issue(d, 'rogue_ca', 'rogue_server', 'ctl-1', 'DNS:localhost,IP:127.0.0.1')
    _issue(d, 'rogue_ca', 'rogue_client', HOST_ID)
    return d


class FakeCtl:
    """Queues envelopes per host; records delivered responses. Requires a client
    certificate from `ca` whose CN is the host in the URL."""

    def __init__(self, pki, server='server', ca='ca'):
        self.queue, self.responses, self.polls = [], [], []
        self.fail_responses = False
        self.garbage = False
        ctl = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                cn = dict(x[0] for x in self.connection.getpeercert()['subject'])['commonName']
                host, _, action = self.path.removeprefix('/v1/agents/').partition('/')
                if cn != host:
                    return self._reply(403, b'')
                if action == 'poll':
                    ctl.polls.append(body)
                    if ctl.garbage:
                        return self._reply(200, b'{not json')
                    batch, ctl.queue[:] = ctl.queue[:body['capacity']], ctl.queue[body['capacity']:]
                    return self._reply(200, json.dumps({'envelopes': batch}).encode()) if batch \
                        else self._reply(204, b'')
                if ctl.fail_responses:
                    return self._reply(503, b'')
                ctl.responses.extend(body['responses'])
                return self._reply(200, b'{}')

            def _reply(self, code, data):
                self.send_response(code)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(pki / (server + '.pem'), pki / (server + '.key'))
        ctx.load_verify_locations(pki / (ca + '.pem'))
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = 'https://localhost:%d' % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def ctl(pki):
    c = FakeCtl(pki)
    yield c
    c.close()


def control_plane(pki, ctl, client='client', ca='ca'):
    return ControlPlane(ctl.url, HOST_ID, tls_context(pki / (ca + '.pem'), pki / (client + '.pem'),
                                                      pki / (client + '.key')), timeout=5)


def poller(h, pki, ctl, **kw):
    sleeps = []
    p = Poller(h.agent, control_plane(pki, ctl), wait=0, sleep=sleeps.append, **kw)
    p.sleeps = sleeps
    return p


def drain(p):
    p.pool.shutdown(wait=True)


def test_polls_runs_and_delivers_a_signed_response(h, pki, ctl):
    h.register()
    env = h.envelope()
    ctl.queue.append(env)
    p = poller(h, pki, ctl)
    assert p.run_once() == 1
    drain(p)
    [resp] = ctl.responses
    assert (resp['op_id'], resp['status'], resp['code']) == (env['op_id'], 'done', 'OK')
    assert verify(without(resp, 'agent_signature'), resp['agent_signature'], [h.keys.agent.verify_key])
    assert h.state.undelivered(10) == []


def test_capacity_is_the_number_of_free_workers(h, pki, ctl):
    p = poller(h, pki, ctl, workers=3)
    p.run_once()
    assert ctl.polls[-1]['capacity'] == 3


def test_refuses_plain_http(h):
    with pytest.raises(ValueError):
        ControlPlane('http://ctl-1', HOST_ID, ssl.create_default_context())


def test_server_from_another_ca_is_refused(h, pki):
    rogue = FakeCtl(pki, server='rogue_server', ca='ca')
    try:
        h.register()
        rogue.queue.append(h.envelope())
        p = Poller(h.agent, control_plane(pki, rogue), wait=0, sleep=lambda s: None)
        assert p.run_once() == 0
        assert len(rogue.queue) == 1 and rogue.polls == []
    finally:
        rogue.close()


def test_client_without_a_trusted_certificate_is_refused(h, pki, ctl):
    cp = control_plane(pki, ctl, client='rogue_client')
    with pytest.raises(TransportError):
        cp.poll(0, 1)
    assert ctl.polls == []


def test_response_survives_an_outage_and_a_restart(h, pki, ctl, tmp_path):
    h.register()
    ctl.queue.append(h.envelope())
    ctl.fail_responses = True
    p = poller(h, pki, ctl)
    p.run_once()
    drain(p)
    assert ctl.responses == [] and len(h.state.undelivered(10)) == 1
    # Restart: a new agent on the same state file delivers it.
    ctl.fail_responses = False
    again = Agent(h.config, State(tmp_path / 'agent.db'), LocalExecClient(h.executor), h.keys.agent, h.log,
                  clock_fn=h.clock)
    Poller(again, control_plane(pki, ctl), wait=0).start()
    assert [r['code'] for r in ctl.responses] == ['OK']


def test_redelivery_never_reruns_a_finished_step(h, pki, ctl):
    h.register()
    env = h.envelope()
    p = poller(h, pki, ctl)
    ctl.queue.append(env)
    p.run_once()
    time.sleep(0.2)
    # Same bytes again (at-least-once delivery): REPLAY, and the original result is queued again.
    ctl.queue.append(env)
    p.run_once()
    time.sleep(0.2)
    # Re-signed with a fresh nonce, same (op_id, token, step): the stored result is the reply.
    resigned = h.resign(dict(env, nonce=uuid.uuid4().hex))
    ctl.queue.append(resigned)
    p.run_once()
    drain(p)
    # Start is idempotent, so the journal (not the backend) shows whether it ran again.
    assert len(h.state.journal(env['op_id'])) == 1
    assert [r['code'] for r in ctl.responses] == ['OK', 'OK', 'REPLAY', 'OK']
    assert ctl.responses[0] == ctl.responses[1] == ctl.responses[3]


def test_step_interrupted_by_a_crash_is_failed_and_released(h, pki, ctl):
    h.register()
    op_id = str(uuid.uuid4())
    token = h.next_token()
    h.state.admit(scope_id=ENV_A, op_id=op_id, step='app.start', token=token, fenced=True, exclusive=True,
                  mutating=True, host_scope=HOST_ID, rate_host=30, rate_env=5, now=h.clock())
    h.state.journal_start(op_id=op_id, op_type='Tenant.Start', step='app.start', environment_id=ENV_A,
                          token=token, now=h.clock())
    p = poller(h, pki, ctl)
    p.start()
    [resp] = ctl.responses
    assert (resp['op_id'], resp['status'], resp['code'], resp['observed']) == \
        (op_id, 'failed', 'TIMEOUT', {'interrupted': True})
    assert h.state.journal(op_id)[0]['status'] == 'failed'
    # The environment is free again: the control plane re-dispatches with a new token.
    ctl.queue.append(h.envelope())
    p.run_once()
    drain(p)
    assert ctl.responses[-1]['code'] == 'OK'


def test_a_slow_step_does_not_hold_up_other_environments(h, pki, ctl):
    h.register(ENV_A, running=True)
    h.register(ENV_B, uid=10002, port=20010)
    h.backend.delay = 0.5
    ctl.queue += [h.envelope('Tenant.Stop', 'app.stop'), h.envelope(environment_id=ENV_B)]
    p = poller(h, pki, ctl, workers=2)
    assert p.run_once() == 2
    drain(p)
    assert h.backend.max_active == 2
    assert sorted(r['code'] for r in ctl.responses) == ['OK', 'OK']


def test_malformed_reply_backs_off(h, pki, ctl):
    ctl.garbage = True
    p = poller(h, pki, ctl)
    assert p.run_once() == 0 and p.run_once() == 0
    assert p.sleeps == [2, 4]
    ctl.garbage = False
    p.run_once()
    assert p.failures == 0


def test_same_key_with_other_content_is_not_a_redelivery(h, pki, ctl):
    # Same (op_id, token, step), other tenant: verified afresh, not answered from the store.
    from .conftest import TENANT_B
    h.register()
    env = h.envelope()
    assert h.agent.handle(env)['code'] == 'OK'
    other = h.resign(dict(env, nonce=uuid.uuid4().hex, tenant_id=TENANT_B))
    assert h.agent.handle(other)['code'] == 'NOT_OWNER'


# -- progress heartbeats (README gap 31) --------------------------------------------

def _beats(h, pki, ctl, delay, interval=0.1):
    h.register()
    h.backend.delay = delay
    object.__setattr__(h.config, 'heartbeat_s', interval)
    env = h.envelope()
    ctl.queue.append(env)
    p = poller(h, pki, ctl)
    p.run_once()
    drain(p)
    return env


def test_a_long_step_sends_signed_heartbeats_then_its_result(h, pki, ctl):
    env = _beats(h, pki, ctl, delay=0.45)
    statuses = [r['status'] for r in ctl.responses]
    assert statuses[-1] == 'done' and set(statuses[:-1]) == {'in_progress'} and len(statuses) >= 3
    beats = [r for r in ctl.responses if r['status'] == 'in_progress']
    assert [b['observed']['heartbeat'] for b in beats] == list(range(1, len(beats) + 1))
    for b in beats:
        assert (b['op_id'], b['step'], b['fencing_token']) == (env['op_id'], 'app.start', env['fencing_token'])
        assert verify(without(b, 'agent_signature'), b['agent_signature'], [h.keys.agent.verify_key])
        assert b['observed']['deadline_at']


def test_a_quick_step_sends_no_heartbeat(h, pki, ctl):
    _beats(h, pki, ctl, delay=0)
    assert [r['status'] for r in ctl.responses] == ['done']


def test_heartbeats_stop_at_the_step_deadline(h, pki, ctl, monkeypatch):
    from hostagent import ops
    monkeypatch.setitem(ops.STEP_TIMEOUTS, 'app.start', 0.25)
    _beats(h, pki, ctl, delay=0.8)
    beats = [r for r in ctl.responses if r['status'] == 'in_progress']
    assert 1 <= len(beats) <= 2 and ctl.responses[-1]['code'] == 'TIMEOUT'


def test_no_heartbeat_after_the_result(h, pki, ctl):
    _beats(h, pki, ctl, delay=0.35, interval=0.05)
    time.sleep(0.2)
    assert ctl.responses[-1]['status'] == 'done'
    assert h.state.undelivered(10) == []


def test_heartbeats_are_not_a_finished_result(h, pki, ctl):
    # A redelivery while the step still runs must not be answered from a heartbeat.
    env = _beats(h, pki, ctl, delay=0.3)
    stored = h.state.finished_response(env['op_id'], env['fencing_token'], env['step'],
                                       request_sha256(env))
    assert stored['status'] == 'done'
