"""Start/Stop against the real local Docker Engine (skipped if Docker isn't reachable)."""
import pytest

from hostagent.agentd import Agent
from hostagent.execd import Executor, LocalExecClient
from hostagent.logs import AuditLog
from hostagent.naming import container, sid

from .conftest import ENV_A

docker = pytest.importorskip('docker')


@pytest.fixture
def real(h):
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        pytest.skip('Docker not reachable')
    from hostagent.backends import DockerApp
    name = container(sid(ENV_A))
    c = client.containers.create('postgres:16', command=['sh', '-c', 'trap "exit 0" TERM; sleep 600 & wait'], name=name, entrypoint=[])
    app = DockerApp(client)
    # This is about Docker's start and stop; the /run files (tenant-owned, root's to write) and the
    # egress table (root's nft) are other tests'.
    app.file_write_secret = app.file_write_conf = lambda *a, **k: {}
    app.nft_inspect = lambda sid: {'applied': True}
    h.agent = Agent(h.config, h.state, LocalExecClient(Executor('app', app, AuditLog(None))),
                    h.keys.agent, h.log, clock_fn=h.clock)
    h.register()
    yield h
    c.remove(force=True)


def test_start_then_stop_real_container(real):
    h = real
    assert h.agent.handle(h.envelope())['observed']['container']['running'] is True
    assert h.agent.handle(h.envelope('Tenant.Stop', 'app.stop'))['observed']['container']['running'] is False
    again = h.agent.handle(h.envelope('Tenant.Stop', 'app.stop'))
    assert again['code'] == 'OK' and again['observed']['container']['status'] == 'exited'
