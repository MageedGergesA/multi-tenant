"""agentd: the unprivileged half (DOC-04 §1, §7).

`Agent.handle(envelope)` verifies, admits, journals and runs one step, and
returns a signed response. Polling ctl-1 is a thin loop around it (poller.py).
"""
import threading
import time
from datetime import datetime, timezone

from nacl.signing import SigningKey

from . import ops, steps, verbs
from .canonical import sha256_hex, sign
from .config import AgentConfig
from .envelope import Duplicate, Verifier, request_sha256
from .execd import ExecError
from .logs import AuditLog
from .secrets import SecretError
from .state import Rejected, State, now as clock

CODES = ('OK', 'SIG_INVALID', 'EXPIRED', 'REPLAY', 'STALE_FENCE', 'SCHEMA', 'NOT_OWNER', 'BUSY', 'CAPACITY',
         'REQUIRES_MODULE_UPDATE', 'HEALTH_FAILED', 'EXEC_ERROR', 'TIMEOUT', 'RATE_LIMITED')
STATUS_FOR = {'BUSY': 'busy', 'RATE_LIMITED': 'rate_limited'}
ECHO = ('op_id', 'step', 'fencing_token', 'environment_id', 'tenant_id')


def _echoable(value) -> bool:
    # Rejected envelopes are untrusted: echo only short scalars back.
    return isinstance(value, int) and not isinstance(value, bool) or isinstance(value, str) and len(value) <= 64


class StepFailed(Exception):
    def __init__(self, code: str, observed: dict | None = None):
        super().__init__(code)
        self.code = code
        self.observed = observed or {}


class _Ticket:
    """One running step: the sid its last verb was for, and whether its
    deadline has passed."""

    def __init__(self):
        self.sid = None
        self.cancelled = threading.Event()

    def check(self):
        if self.cancelled.is_set():
            raise StepFailed('TIMEOUT', {'cancelled': True})


class _Guarded:
    """The exec client as steps see it. Once the step is cancelled, no further
    verb is sent and the one in flight is answered with TIMEOUT, whatever it
    returned, so a step past its deadline stops at its next verb."""

    def __init__(self, client, local):
        self.client = client
        self.local = local

    def __getattr__(self, name):
        return getattr(self.client, name)

    def call(self, verb, **args):
        ticket = getattr(self.local, 'ticket', None)
        if ticket is None:
            return self.client.call(verb, **args)
        ticket.check()
        ticket.sid = args.get('sid', ticket.sid)
        try:
            return self.client.call(verb, **args)
        finally:
            ticket.check()


class Agent:
    def __init__(self, config: AgentConfig, state: State, exec_client, signing_key: SigningKey,
                 log: AuditLog, capacity=None, clock_fn=clock):
        self.config = config
        self.state = state
        self._local = threading.local()
        self.raw_exec = exec_client
        self.exec = _Guarded(exec_client, self._local)
        self.key = signing_key
        self.log = log
        self.verifier = Verifier(config, state, capacity)
        self.clock = clock_fn
        self.on_response = None    # set by the poller: deliver the outbox now

    def handle(self, env) -> dict:
        t0 = self.clock()
        try:
            v = self.verifier.verify(env, t0)
        except Duplicate as d:
            # Queued again: ctl-1 redelivers when it hasn't seen the response.
            self.state.store_response(d.response, t0, request_sha256(env))
            return d.response
        except Rejected as r:
            return self._respond(env, 'rejected', r.code, {'detail': r.detail}, t0)
        e = v.env
        spec = v.spec
        if e['op_type'] == 'Agent.Query':
            return self._respond(e, 'done', 'OK', steps.query(self, e), t0)
        try:
            self.state.admit(scope_id=v.scope_id, op_id=e['op_id'], step=e['step'], token=e['fencing_token'],
                             fenced=True, exclusive=spec.exclusive, mutating=spec.mutating,
                             host_scope=self.config.host_id, rate_host=self.config.rate_host_per_min,
                             rate_env=self.config.rate_env_per_min, now=t0)
        except Rejected as r:
            return self._respond(e, STATUS_FOR.get(r.code, 'rejected'), r.code, {'detail': r.detail}, t0)

        row = self.state.journal_start(op_id=e['op_id'], op_type=e['op_type'], step=e['step'],
                                       environment_id=e['environment_id'], token=e['fencing_token'], now=t0)
        status, code, observed = 'done', 'OK', {}
        ticket = self._local.ticket = _Ticket()
        stop_watch = self._watch(e, t0, ticket)
        try:
            observed = steps.run(self, e)
        except StepFailed as f:
            status, code, observed = 'failed', f.code, f.observed
        except ExecError as x:
            if x.args[0] == 'BUSY':     # a verb from before an agentd restart still runs on this sid
                status, code, observed = 'busy', 'BUSY', {'executor': 'sid busy'}
            else:
                status, code, observed = 'failed', 'EXEC_ERROR', {'executor': x.args[0], 'reason': x.args[1]}
        except SecretError as x:
            status, code, observed = 'failed', 'SCHEMA', {'secrets': x.args[0]}
        except NotImplementedError:
            status, code, observed = 'failed', 'EXEC_ERROR', {'reason': 'step not implemented'}
        finally:
            stop_watch()
            self._local.ticket = None
        if v.breakglass_used:
            observed = {**observed, 'breakglass_used': True}  # control plane raises sev2
        evidence = sha256_hex(observed)
        self.state.journal_finish(row, status=status, code=code, evidence_sha256=evidence, now=self.clock())
        if spec.exclusive and (status in ('failed', 'busy') or e['step'] == spec.steps[-1]
                               or not self._more_here(e, spec)):
            self.state.release(v.scope_id, e['op_id'])
        return self._respond(e, status, code, observed, t0, evidence)

    def _watch(self, env, t0, ticket):
        """Signed `in_progress` responses every `heartbeat_s` while the step runs,
        until its DOC-04 §8 deadline; at the deadline the step is cancelled.
        Returns the function that stops the watch."""
        interval = self.config.heartbeat_s
        stop = threading.Event()
        started = time.monotonic()
        timeout = ops.step_timeout(env['step'])
        deadline_at = datetime.fromtimestamp(t0 + timeout, timezone.utc).isoformat()

        # The lock orders beats before the final response; delivery happens outside
        # it, so a slow ctl-1 never holds up the end of the step.
        lock = threading.Lock()

        def watch():
            n = 0
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    break
                if stop.wait(min(interval, remaining) if interval else remaining):
                    return
                elapsed = time.monotonic() - started
                if elapsed >= timeout:
                    break
                with lock:
                    if stop.is_set():
                        return
                    n += 1
                    self._respond(env, 'in_progress', 'OK', {'heartbeat': n, 'elapsed_s': round(elapsed, 1),
                                                            'deadline_at': deadline_at}, t0)
                if self.on_response:
                    self.on_response()
            with lock:
                if stop.is_set():
                    return
                ticket.cancelled.set()
            self._cancel(env, ticket)

        threading.Thread(target=watch, name='watch', daemon=True).start()

        def stop_watch():
            with lock:
                stop.set()
        return stop_watch

    def _cancel(self, env, ticket):
        """Past the deadline: the step stops at its next verb (_Guarded), and the
        verb running now is cut short in agent-exec, which kills the sid's
        one-shot. Other verbs are short API calls and are let finish."""
        result = None
        sid = ticket.sid
        if sid and 'exec.cancel' in verbs.BY_ROLE.get(self.config.role, {}):
            try:
                result = self.raw_exec.call('exec.cancel', sid=sid)
            except (ExecError, OSError) as x:
                result = {'error': type(x).__name__}
        self.log.write(event='step_cancelled', op_id=env['op_id'], step=env['step'],
                       tenant_id=env.get('tenant_id'), sid=sid, result=result)

    def recover(self) -> list[dict]:
        """At startup: a step left `in_progress` by a crash is recorded as failed
        with TIMEOUT and its operation released (DOC-04 §8). The control plane's
        RECONCILING reads the journal and re-dispatches with a new token."""
        out = []
        for row in self.state.interrupted_steps():
            observed = {'interrupted': True}
            evidence = sha256_hex(observed)
            self.state.abort_step(row['id'], row['op_id'], evidence, self.clock())
            out.append(self._respond(row, 'failed', 'TIMEOUT', observed, self.clock(), evidence))
        return out

    def _more_here(self, env, spec) -> bool:
        """True if a later step of this op is for this agent's role."""
        later = spec.steps[spec.steps.index(env['step']) + 1:]
        return any(s.split('.', 1)[0] in (self.config.role, 'any') for s in later)

    def _respond(self, env, status, code, observed, t0, evidence=None) -> dict:
        try:
            request = request_sha256(env) if isinstance(env, dict) else None
        except Exception:      # a malformed envelope may not even canonicalise
            request = None
        env = {k: v for k, v in env.items() if k in ECHO and _echoable(v)} if isinstance(env, dict) else {}
        scope = env.get('environment_id') or self.config.host_id
        hw_token, _ = self.state.high_water(scope)
        evidence = evidence or sha256_hex(observed)
        resp = {
            'v': 1, 'op_id': env.get('op_id'), 'step': env.get('step'), 'host_id': self.config.host_id,
            'fencing_token': env.get('fencing_token'), 'status': status, 'code': code, 'observed': observed,
            'evidence_sha256': evidence, 'agent_high_water': hw_token,
            'at': datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
        }
        resp['agent_signature'] = sign(resp, self.key)
        self.state.store_response(resp, self.clock(), request)
        self.log.write(event='step', op_id=resp['op_id'], step=resp['step'], tenant_id=env.get('tenant_id'),
                       code=code, status=status, duration=round(self.clock() - t0, 3), evidence_sha256=evidence)
        return resp
