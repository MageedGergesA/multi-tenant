"""A step past its DOC-04 §8 deadline is cancelled: the sid's one-shot is killed in
agent-exec, no further verb is sent, and the step is recorded as failed with
TIMEOUT (README gap 31)."""
import json
import threading
import time

import pytest

from hostagent import ops
from hostagent.agentd import StepFailed, _Guarded, _Ticket
from hostagent.envelope import request_sha256
from hostagent.naming import sid

from .conftest import ENV_A

SID = sid(ENV_A)


@pytest.fixture
def slow(h, monkeypatch):
    h.register()
    h.backend.delay = 5
    monkeypatch.setitem(ops.STEP_TIMEOUTS, 'app.start', 0.3)
    return h


def _events(log, name):
    return [json.loads(line) for line in log.lines if json.loads(line).get('event') == name]


@pytest.mark.parametrize('interval', [0.1, 0])
def test_overdue_step_is_cancelled_and_fails_with_timeout(slow, interval):
    object.__setattr__(slow.config, 'heartbeat_s', interval)
    t = time.monotonic()
    r = slow.agent.handle(slow.envelope())
    assert time.monotonic() - t < 2              # the 5 s verb was cut short
    assert (r['status'], r['code'], r['observed']) == ('failed', 'TIMEOUT', {'cancelled': True})
    assert ('cancel', SID) in slow.backend.calls
    [cancelled] = _events(slow.log, 'step_cancelled')
    assert cancelled['sid'] == SID and cancelled['result'] == {'killed': [SID]}


def test_timeout_releases_the_environment_and_is_kept_for_redelivery(slow):
    env = slow.envelope()
    assert slow.agent.handle(env)['code'] == 'TIMEOUT'
    stored = slow.state.finished_response(env['op_id'], env['fencing_token'], env['step'], request_sha256(env))
    assert stored['code'] == 'TIMEOUT'
    slow.backend.delay = 0
    assert slow.agent.handle(slow.envelope())['code'] == 'OK'   # re-dispatch with a new token runs


def test_no_verb_after_the_deadline(slow):
    slow.agent.handle(slow.envelope())
    assert [c for c in slow.backend.calls if c[0] in ('start', 'cancel')] == [('start', SID), ('cancel', SID)]


def test_step_within_its_deadline_is_not_cancelled(slow):
    slow.backend.delay = 0.05
    assert slow.agent.handle(slow.envelope())['code'] == 'OK'
    time.sleep(0.4)
    assert ('cancel', SID) not in slow.backend.calls and not _events(slow.log, 'step_cancelled')


def test_cancelled_ticket_sends_nothing():
    class Client:
        role = 'app'
        calls = []

        def call(self, verb, **args):
            self.calls.append(verb)

    local = threading.local()
    local.ticket = _Ticket()
    local.ticket.cancelled.set()
    guarded = _Guarded(Client(), local)
    with pytest.raises(StepFailed) as e:
        guarded.call('container.start', sid=SID)
    assert e.value.code == 'TIMEOUT' and Client.calls == []


def test_cancel_is_not_held_up_by_the_sid_claim(h):
    # exec.cancel must reach a sid whose verb is still running.
    h.register()
    h.backend.delay = 5
    t = threading.Thread(target=h.executor.handle, args=({'verb': 'container.start', 'args': {'sid': SID}},))
    t.start()
    while not h.backend.active:
        time.sleep(0.01)
    assert h.executor.handle({'verb': 'container.stop', 'args': {'sid': SID, 'timeout': 10}})['error'] == 'BUSY'
    reply = h.executor.handle({'verb': 'exec.cancel', 'args': {'sid': SID}})
    assert reply == {'ok': True, 'result': {'killed': [SID]}}
    t.join(2)
    assert not t.is_alive()
