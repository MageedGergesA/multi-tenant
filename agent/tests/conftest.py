import secrets
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pyrage
import pytest
from nacl.signing import SigningKey

from hostagent.agentd import Agent
from hostagent.canonical import sign, without
from hostagent.config import AgentConfig, Trust
from hostagent.execd import Executor, LocalExecClient
from hostagent.logs import AuditLog
from hostagent.naming import sid
from hostagent.secrets import seal
from hostagent.state import State

HOST_ID = '11111111-1111-4111-8111-111111111111'
TENANT_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
TENANT_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
ENV_A = 'a0000000-0000-4000-8000-00000000000a'
ENV_B = 'b0000000-0000-4000-8000-00000000000b'
CELL = 'community/19.0/ubuntu-24.04/py3.12/pg16'
DIGEST = 'sha256:' + 'ab' * 32
SLOT = {'container_uid': 10001, 'http_port': 20000, 'gevent_port': 20001, 'workers': 2, 'max_cron_threads': 1,
        'db_maxconn': 8, 'limit_memory_soft': 640 << 20, 'limit_memory_hard': 768 << 20, 'limit_time_cpu': 600,
        'limit_time_real': 1200, 'mem_limit_bytes': 1 << 30, 'cpu_millis': 1000}
# What ctl-1 sends with Tenant.Start (the /run files are rendered again at every start).
START_PARAMS = {'reason': 'operator', 'runtime_slot': SLOT, 'smtp': 'relay'}
START_SECRETS = {'db_password': 'p' * 32, 'admin_passwd_hash': '$pbkdf2-sha512$600000$c2FsdA$aGFzaA',
                 'smtp_password': 's' * 32, 'tenant_salt': 'ab' * 16, 'tenant_admin_password': 'a' * 32}


class FakeApp:
    """Records verbs; containers are dicts. `delay` makes start/stop slow."""

    def __init__(self):
        self.containers = {}
        self.calls = []
        self.nft_missing = set()        # sids whose egress table the kernel doesn't have
        self.delay = 0.0
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()
        self._kill = threading.Event()

    def _slow(self):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        killed = self._kill.wait(self.delay)
        with self._lock:
            self.active -= 1
        if killed:
            self._kill.clear()
            raise RuntimeError('one-shot killed')

    def exec_cancel(self, sid):
        self.calls.append(('cancel', sid))
        killed = bool(self.active)
        if killed:
            self._kill.set()
        return {'killed': [sid] if killed else []}

    def container_inspect(self, sid):
        c = self.containers.get(sid)
        return {'exists': c is not None, 'running': bool(c and c['running'])}

    def container_start(self, sid):
        self.calls.append(('start', sid))
        self._slow()
        self.containers[sid]['running'] = True
        return {}

    def container_stop(self, sid, timeout):
        self.calls.append(('stop', sid))
        self._slow()
        self.containers[sid]['running'] = False
        return {}

    # Tenant.Delete: everything but the container is reported absent after removal.
    def container_remove(self, sid):
        self.calls.append(('remove', sid))
        self.containers.pop(sid, None)
        return {}

    def traefik_inspect(self, sid):
        return {'present': sid in self.containers}

    def nft_inspect(self, sid):
        return {'applied': sid in self.containers and sid not in self.nft_missing}

    def nft_apply_tenant(self, sid, profile):
        self.calls.append(('nft', sid, profile))
        self.nft_missing.discard(sid)
        return self.nft_inspect(sid)

    def net_inspect(self, sid):
        return {'exists': sid in self.containers}

    def volume_inspect(self, sid):
        return {'exists': sid in self.containers}

    def file_inspect(self, sid):
        return {}

    def file_write_secret(self, sid, name, data_b64):
        self.calls.append(('secret', sid, name))
        return {}

    def file_write_conf(self, sid, conf):
        self.calls.append(('conf', sid, conf['smtp']))
        return {}

    traefik_remove = nft_remove_tenant = net_remove = volume_remove = lambda self, sid: {}


class Keys:
    def __init__(self):
        self.dispatch = SigningKey.generate()
        self.release = SigningKey.generate()
        self.custodian = SigningKey.generate()
        self.breakglass = SigningKey.generate()
        self.agent = SigningKey.generate()
        self.stranger = SigningKey.generate()


class Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class Harness:
    def __init__(self, tmp_path, breakglass_enabled=False):
        self.keys = Keys()
        self.clock = Clock()
        self.age = pyrage.x25519.Identity.generate()
        self.config = AgentConfig(
            host_id=HOST_ID, role='app',
            trust=Trust(dispatch=(self.keys.dispatch.verify_key,), release=self.keys.release.verify_key,
                        custodian=(self.keys.custodian.verify_key,), breakglass=self.keys.breakglass.verify_key,
                        breakglass_enabled=breakglass_enabled),
            state_dir=tmp_path, registry_host='registry.internal', age_identity=self.age)
        self.state = State(tmp_path / 'agent.db')
        self.backend = FakeApp()
        self.exec_log = AuditLog(None)
        self.executor = Executor('app', self.backend, self.exec_log)
        self.log = AuditLog(None)
        self.capacity_ok = True
        self.agent = Agent(self.config, self.state, LocalExecClient(self.executor), self.keys.agent, self.log,
                           capacity=lambda params: self.capacity_ok, clock_fn=self.clock)
        self._token = 0
        self._lock = threading.Lock()

    def register(self, environment_id=ENV_A, tenant_id=TENANT_A, running=False, uid=10001, port=20000):
        self.state.register(environment_id=environment_id, tenant_id=tenant_id, sid=sid(environment_id),
                            container_uid=uid, http_port=port, gevent_port=port + 1, kind='production',
                            egress_profile='production', now=self.clock())
        self.backend.containers[sid(environment_id)] = {'running': running}

    def next_token(self):
        with self._lock:
            self._token += 1
            return self._token

    def envelope(self, op_type='Tenant.Start', step='app.start', params=None, *, environment_id=ENV_A,
                 tenant_id=TENANT_A, tenant_state='ACTIVE', token=None, op_id=None, issued=None, life=300,
                 release_manifest=None, approval=None, key=None, extra=None):
        issued = self.clock() if issued is None else issued
        env = {
            'v': 1, 'op_id': op_id or str(uuid.uuid4()), 'op_type': op_type, 'step': step, 'host_id': HOST_ID,
            'tenant_id': tenant_id, 'environment_id': environment_id, 'tenant_state': tenant_state,
            'fencing_token': token if token is not None else self.next_token(),
            'issued_at': iso(issued), 'expires_at': iso(issued + life), 'nonce': secrets.token_hex(16),
            'params': params if params is not None else (START_PARAMS if op_type == 'Tenant.Start'
                                                          else {'reason': 'operator'}),
            'secrets': seal(START_SECRETS, self.age.to_public()) if op_type == 'Tenant.Start' else None,
            'release_manifest': release_manifest, 'approval': approval,
        }
        env.update(extra or {})
        env['dispatch_signature'] = sign(env, key or self.keys.dispatch)
        return env

    def resign(self, env, key=None):
        env = without(env, 'dispatch_signature')
        env['dispatch_signature'] = sign(env, key or self.keys.dispatch)
        return env

    def manifest(self, key=None, digest=DIGEST, change_class='patch', modules=None):
        m = {'cell': CELL, 'repository': 'tenants/odoo', 'image_digest': digest, 'change_class': change_class,
             'addon_manifest_sha256': 'cd' * 32,
             'module_versions': modules if modules is not None else {'base': '19.0.1.3', 'sale': '19.0.1.2'}}
        m['release_signature'] = sign(m, key or self.keys.release)
        return m

    def approval(self, op_id, tenant_id, action, key=None, deletion_case_id=None, expires_in=600):
        a = {'op_id': op_id, 'tenant_id': tenant_id, 'action': action, 'expires_at': iso(self.clock() + expires_in),
             'deletion_case_id': deletion_case_id}
        a['custodian_signature'] = sign(a, key or self.keys.custodian)
        return a


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)
