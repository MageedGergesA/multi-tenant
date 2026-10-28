"""agent-exec restart: orphaned one-shot containers and plaintext leftovers are
reaped before it serves (README gap 30)."""
import base64
import json
import subprocess
import time

import pytest

from hostagent.backends import ONESHOT_LABEL, AppHostConfig, DockerApp

SID = 'feedfacecafe'


class _FakeContainer:
    def __init__(self, kwargs):
        self.kwargs = kwargs
        self.attrs = {'Config': {'User': kwargs.get('user')}}
        self.name = kwargs.get('name')

    def start(self):
        pass

    def wait(self, timeout):
        return {'StatusCode': 0}

    def logs(self, **kw):
        return b''

    def remove(self, force):
        pass


class _FakeDocker:
    class errors:
        pass

    def __init__(self):
        self.created = []
        outer = self

        class Containers:
            def get(self, name):
                from docker.errors import NotFound
                raise NotFound(name)

            def create(self, image, **kwargs):
                outer.created.append(kwargs)
                return _FakeContainer(kwargs)
        self.containers = Containers()


def test_oneshot_containers_carry_the_reap_label(tmp_path, monkeypatch):
    fake = _FakeDocker()
    app = DockerApp(AppHostConfig(root=tmp_path), client=fake)
    monkeypatch.setattr(app, '_tenant_uid', lambda sid: 10001)
    app._oneshot(SID, 'sha256:' + 'ab' * 32, 'module_versions', ['/opt/platform/module-versions'], [])
    assert fake.created[0]['labels'] == {'platform.sid': SID, ONESHOT_LABEL: 'module_versions'}


def test_tenants_get_db_1s_certificate(tmp_path, monkeypatch):
    """verify-full needs a root certificate: db-1's is copied into the run dir and named by PGSSLROOTCERT."""
    ca = tmp_path / 'db-ca.pem'
    ca.write_text('-----BEGIN CERTIFICATE-----\n')
    fake = _FakeDocker()
    app = DockerApp(AppHostConfig(root=tmp_path, db_host='10.0.0.3', db_ca=str(ca)), client=fake)
    monkeypatch.setattr(app, '_tenant_uid', lambda sid: 10001)
    monkeypatch.setattr('os.chown', lambda *a: None)
    app._run(SID).mkdir(parents=True)
    monkeypatch.setattr(app, 'render_conf', lambda sid, conf, pw='': '[options]\n')
    app.file_write_conf(SID, {})
    assert (app._run(SID) / 'db-ca.pem').read_text() == ca.read_text()
    app._oneshot(SID, 'sha256:' + 'ab' * 32, 'module_versions', ['/opt/platform/module-versions'], [])
    assert fake.created[0]['environment']['PGSSLROOTCERT'] == '/run/tenant/db-ca.pem'


def test_package_refuses_a_missing_dump(tmp_path):
    import pyrage
    app = DockerApp(AppHostConfig(root=tmp_path), client=_FakeDocker())
    work = app._tmp(SID, 'b1')
    work.mkdir()
    (work / 'files.json').write_text('{}')
    with pytest.raises(FileNotFoundError):
        app.backup_package(SID, 'b1', base64.b64encode(b'{}').decode(),
                           str(pyrage.x25519.Identity.generate().to_public()))
    assert not app._tmp(SID, 'b1.tar.age').exists()


# -- the real thing: restart agent-exec-dev (dev/up.sh) ---------------------------------

def _docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check)


def _exec_dev_up():
    try:
        return _docker('inspect', '-f', '{{.State.Running}}', 'agent-exec-dev', check=False).stdout.strip() == 'true'
    except FileNotFoundError:
        return False


SETUP = """set -e
d=/r/srv/backup-tmp/%s
mkdir -p $d/b1 $d/b2.in/x
echo dump > $d/b1/dump.pgc
echo tar > $d/b1.tar
echo age > $d/b1.tar.age
echo age > $d/b2.in/archive.tar.age
echo tar > $d/b2.in/archive.tar
echo dump > $d/b2.in/x/dump.pgc
""" % SID


def _startups():
    out = _docker('exec', 'agent-exec-dev', 'cat', '/devroot/agent-exec-audit.log', check=False).stdout
    return out.count('"exec_startup"')


@pytest.mark.skipif(not _exec_dev_up(), reason='needs agent-exec-dev (dev/up.sh)')
def test_restart_reaps_orphans_and_plaintext():
    oneshot, tenant = 'odoo-%s-backup-dump' % SID, 'odoo-%s' % SID
    for name in (oneshot, tenant):
        _docker('rm', '-f', name, check=False)
    try:
        _docker('run', '-d', '--name', oneshot, '--label', '%s=backup_dump' % ONESHOT_LABEL,
                '--label', 'platform.sid=' + SID, 'alpine', 'sleep', '300')
        # The tenant's own container has the sid label but isn't a one-shot: it stays.
        _docker('run', '-d', '--name', tenant, '--label', 'platform.sid=' + SID, 'alpine', 'sleep', '300')
        _docker('run', '--rm', '-v', 'agent-dev-root:/r', 'alpine', 'sh', '-c', SETUP)

        before = _startups()
        _docker('restart', 'agent-exec-dev')
        # The socket file survives the restart, so wait for the new startup line instead.
        for _ in range(60):
            if _startups() > before:
                break
            time.sleep(0.5)
        assert _startups() > before, _docker('logs', '--tail', '20', 'agent-exec-dev').stderr

        names = _docker('ps', '-a', '--format', '{{.Names}}').stdout.split()
        assert oneshot not in names and tenant in names
        left = _docker('run', '--rm', '-v', 'agent-dev-root:/r', 'alpine', 'sh', '-c',
                       'cd /r/srv/backup-tmp/%s && find . | sort' % SID).stdout.split()
        assert left == ['.', './b1.tar.age', './b2.in', './b2.in/archive.tar.age']
        audit = _docker('exec', 'agent-exec-dev', 'cat', '/devroot/agent-exec-audit.log').stdout
        startup = [line for line in audit.splitlines() if '"exec_startup"' in line][-1]
        assert oneshot in startup and '"plaintext_removed": 4' in startup
    finally:
        for name in (oneshot, tenant):
            _docker('rm', '-f', name, check=False)
        _docker('run', '--rm', '-v', 'agent-dev-root:/r', 'alpine', 'rm', '-rf', '/r/srv/backup-tmp/' + SID,
                check=False)


CANCEL = """import json
from hostagent.execd import ExecClient
print(json.dumps(ExecClient('/sock/agent-exec.sock', 'app').call('exec.cancel', sid=%r)))"""


@pytest.mark.skipif(not _exec_dev_up(), reason='needs agent-exec-dev (dev/up.sh)')
def test_cancel_kills_only_that_sids_oneshot():
    other = 'f00dfacecafe'
    oneshot, tenant, foreign = ('odoo-%s-backup-dump' % SID, 'odoo-%s' % SID, 'odoo-%s-backup-dump' % other)
    for name in (oneshot, tenant, foreign):
        _docker('rm', '-f', name, check=False)
    try:
        _docker('run', '-d', '--name', oneshot, '--label', '%s=backup_dump' % ONESHOT_LABEL,
                '--label', 'platform.sid=' + SID, 'alpine', 'sleep', '300')
        _docker('run', '-d', '--name', tenant, '--label', 'platform.sid=' + SID, 'alpine', 'sleep', '300')
        _docker('run', '-d', '--name', foreign, '--label', '%s=backup_dump' % ONESHOT_LABEL,
                '--label', 'platform.sid=' + other, 'alpine', 'sleep', '300')
        out = _docker('exec', 'agent-exec-dev', 'python', '-c', CANCEL % SID).stdout
        assert json.loads(out) == {'killed': [oneshot]}
        running = _docker('ps', '--format', '{{.Names}}').stdout.split()
        assert oneshot not in running and tenant in running and foreign in running
        assert _docker('inspect', '-f', '{{.State.ExitCode}}', oneshot).stdout.strip() == '137'
        out = _docker('exec', 'agent-exec-dev', 'python', '-c', CANCEL % SID).stdout
        assert json.loads(out) == {'killed': []}
    finally:
        for name in (oneshot, tenant, foreign):
            _docker('rm', '-f', name, check=False)
