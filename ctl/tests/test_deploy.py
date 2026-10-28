"""deploy/: write_secrets.py (SOPS onto tmpfs) and the systemd units, run for
real under the units' own sandbox through the user's systemd manager.

User mode can't drop capabilities, so the properties that do
(CapabilityBoundingSet, AmbientCapabilities, PrivateDevices, ProtectClock,
ProtectKernelModules, ProtectKernelLogs, ProtectHostname) are left out here;
ProtectHome too, since this venv is under /home (on ctl-1 it is /opt/ctl).
The rest is passed, but a user manager may not set up mount namespaces (this
machine's systemd 249 doesn't, silently): then ProtectSystem, PrivateTmp,
InaccessiblePaths and ReadWritePaths aren't exercised, and the test that
needs them skips. What always applies is seccomp: the syscall filters,
NoNewPrivileges, RestrictAddressFamilies, MemoryDenyWriteExecute,
LockPersonality, RestrictNamespaces, RestrictRealtime, SystemCallArchitectures
(and the syscall filter test proves it is enforced).
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from .conftest import ROOT
from .test_main import Setup, needs_s3

DEPLOY = ROOT / 'deploy'
sys.path.insert(0, str(DEPLOY))
import write_secrets as ws  # noqa: E402

USER = os.environ.get('USER') or __import__('pwd').getpwuid(os.getuid()).pw_name
NOT_IN_USER_MODE = {'CapabilityBoundingSet', 'AmbientCapabilities', 'PrivateDevices', 'ProtectClock',
                    'ProtectKernelModules', 'ProtectKernelLogs', 'ProtectHostname', 'ProtectHome'}
NOT_PROPERTIES = {'ExecStart', 'ExecStartPre', 'User', 'Group', 'Type', 'RemainAfterExit', 'Restart', 'RestartSec',
                  'RestartPreventExitStatus', 'KillSignal', 'TimeoutStopSec', 'Environment'}
FAKE_SOPS = '''import json, os, sys
if os.environ.get('FAKE_SOPS_FAIL'):
    sys.stderr.write('Failed to get the data key required to decrypt the SOPS file.\\n')
    sys.exit(128)
sys.stdout.write(open(os.environ['FAKE_SOPS_JSON']).read())
'''


def _user_manager():
    try:
        return subprocess.run(['systemd-run', '--user', '--wait', '--quiet', 'true'], capture_output=True,
                              timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


needs_systemd = pytest.mark.skipif(not _user_manager(), reason="needs the user's systemd manager")


def _mount_namespacing():
    probe = Path.home() / ('.ctl-ns-probe-' + uuid.uuid4().hex[:6])
    subprocess.run(['systemd-run', '--user', '--wait', '--quiet', '-p', 'ProtectSystem=strict', 'touch', str(probe)],
                   capture_output=True, timeout=20)
    written = probe.exists()
    probe.unlink(missing_ok=True)
    return not written


def properties(unit, replace=()) -> list[str]:
    out, section = [], None
    for line in (DEPLOY / unit).read_text().splitlines():
        line = line.strip()
        if line.startswith('['):
            section = line
        elif section == '[Service]' and line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            if key not in NOT_PROPERTIES | NOT_IN_USER_MODE:
                for old, new in replace:
                    value = value.replace(old, new)
                out += ['-p', '%s=%s' % (key, value)]
    return out


def sandboxed(unit, argv, env=None, replace=(), extra=()):
    cmd = ['systemd-run', '--user', '--wait', '--pipe', '--quiet', '-p', 'WorkingDirectory=%s' % ROOT,
           *properties(unit, replace), *extra]
    for k, v in (env or {}).items():
        cmd += ['--setenv', '%s=%s' % (k, v)]
    return subprocess.run(cmd + list(argv), capture_output=True, text=True, timeout=120)


@pytest.fixture
def shm():
    """A directory on tmpfs."""
    d = Path('/dev/shm') / ('ctl-test-' + uuid.uuid4().hex[:8])
    d.mkdir(mode=0o700)
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def sops(tmp_path):
    """A stand-in for `sops --decrypt --output-type json`: prints $FAKE_SOPS_JSON."""
    script = tmp_path / 'fake_sops.py'
    script.write_text(FAKE_SOPS)

    def given(values, fail=False):
        plain = tmp_path / 'plain.json'
        plain.write_text(json.dumps(values))
        os.environ['FAKE_SOPS_JSON'] = str(plain)
        os.environ.pop('FAKE_SOPS_FAIL', None)
        if fail:
            os.environ['FAKE_SOPS_FAIL'] = '1'
        return '%s %s' % (sys.executable, script)
    yield given
    os.environ.pop('FAKE_SOPS_JSON', None)
    os.environ.pop('FAKE_SOPS_FAIL', None)


def _run(sops_cmd, d):
    return ws.main(['--sops-file', 'secrets.sops.yaml', '--dir', str(d), '--user', USER, '--sops', sops_cmd])


# -- write_secrets ----------------------------------------------------------------------

def test_writes_each_key_private_and_removes_stale_ones(sops, shm):
    (shm / 'old_secret').write_text('gone')
    (shm / '.database_url.tmp').write_text('half-written')
    (shm / 'Not-Ours').write_text('kept')                  # not a name this writes
    assert _run(sops({'database_url': 'postgresql://ctl:pw@127.0.0.1/ctl',
                      'bucket_c_write.json': {'secret': 's', 'key_id': 'k'}, 'sops': {'mac': 'x'}}), shm) == 0
    assert sorted(os.listdir(shm)) == ['Not-Ours', 'bucket_c_write.json', 'database_url']
    assert (shm / 'database_url').read_text() == 'postgresql://ctl:pw@127.0.0.1/ctl\n'
    assert json.loads((shm / 'bucket_c_write.json').read_text()) == {'key_id': 'k', 'secret': 's'}
    for name in ('database_url', 'bucket_c_write.json'):
        st = os.stat(shm / name)
        assert stat.S_IMODE(st.st_mode) == 0o400 and st.st_uid == os.getuid()
    assert stat.S_IMODE(os.stat(shm).st_mode) == 0o700
    from ctlplane.main import secret
    assert secret(shm / 'database_url') == 'postgresql://ctl:pw@127.0.0.1/ctl'      # main accepts them


@pytest.mark.parametrize('values, says', [
    ({'database_url': 'x', '../escape': 'y'}, 'is not a file name'),
    ({'database_url': 'x', 'Upper': 'y'}, 'is not a file name'),
    ({'database_url': ['a', 'b']}, 'a string or a map'),
    ({'n': 1}, 'a string or a map'),
])
def test_nothing_is_written_unless_every_key_is_valid(sops, shm, capsys, values, says):
    (shm / 'database_url').write_text('before')
    assert _run(sops(values), shm) == 1
    assert says in capsys.readouterr().err
    assert os.listdir(shm) == ['database_url'] and (shm / 'database_url').read_text() == 'before'


def test_a_sops_failure_writes_nothing_and_says_why(sops, shm, capsys):
    assert _run(sops({'database_url': 'postgresql://ctl:secret-pw@h/ctl'}, fail=True), shm) == 1
    err = capsys.readouterr().err
    assert 'sops failed (128)' in err and 'data key' in err and 'secret-pw' not in err
    assert os.listdir(shm) == []


def test_values_are_never_printed(sops, shm, capsys):
    assert _run(sops({'database_url': 'postgresql://ctl:secret-pw@h/ctl'}), shm) == 0
    out = capsys.readouterr()
    assert 'secret-pw' not in out.out + out.err and '1 files' in out.out


def test_refuses_a_directory_not_on_tmpfs_a_symlink_and_an_unknown_user(sops, shm, tmp_path, capsys):
    given = sops({'database_url': 'x'})
    if ws.fstype(tmp_path) != 'tmpfs':
        assert _run(given, tmp_path) == 1 and 'not on tmpfs' in capsys.readouterr().err
    link = shm.parent / (shm.name + '-link')
    link.symlink_to(shm)
    try:
        assert _run(given, link) == 1 and 'not a directory' in capsys.readouterr().err
    finally:
        link.unlink()
    assert ws.main(['--sops-file', 'f', '--dir', str(shm), '--user', 'no-such-user-' + uuid.uuid4().hex[:6],
                    '--sops', given]) == 1
    assert 'no user' in capsys.readouterr().err and os.listdir(shm) == []


def test_fstype():
    assert ws.fstype('/dev/shm') == 'tmpfs' and ws.fstype('/proc/self') == 'proc'


# -- the units ------------------------------------------------------------------------------

def test_units_verify(tmp_path):
    """systemd-analyze verify, with this machine's paths and user for ctl-1's."""
    py = os.path.realpath(sys.executable)
    for unit in ('ctl-secrets.service', 'ctl.service', 'ctl-migrate.service'):
        text = ((DEPLOY / unit).read_text().replace('/opt/ctl/venv/bin/python', py)
                .replace('/usr/local/lib/ctl/write-secrets', str(DEPLOY / 'write_secrets.py'))
                .replace('User=ctl', 'User=' + USER).replace('--user ctl', '--user ' + USER)
                .replace('Group=ctl', 'Group=' + USER))
        (tmp_path / unit).write_text(text)
    run = subprocess.run(['systemd-analyze', 'verify', '--man=no', *(str(tmp_path / u) for u in
                          ('ctl-secrets.service', 'ctl.service', 'ctl-migrate.service'))],
                         capture_output=True, text=True)
    ours = [line for line in run.stderr.splitlines() if 'ctl' in line.split(':', 1)[0]]
    assert run.returncode == 0 and not ours, run.stderr


def test_ctl_secrets_unit_flags():
    text = (DEPLOY / 'ctl-secrets.service').read_text()
    assert 'RuntimeDirectory=ctl\n' in text and 'RuntimeDirectoryMode=0700' in text
    assert 'CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER\n' in text and 'PrivateNetwork=yes' in text
    assert '~@privileged' not in text.split('[Service]')[1].replace('# Not ~@privileged', '')   # it needs @chown
    assert 'SystemCallFilter=setrlimit\n' in text                  # sops is Go (infra/test/run.sh found it)
    for unit in ('ctl.service', 'ctl-migrate.service'):
        t = (DEPLOY / unit).read_text()
        assert 'User=ctl\n' in t and 'CapabilityBoundingSet=\n' in t
        assert 'InaccessiblePaths=-/etc/ctl/host.agekey -/etc/ctl/secrets.sops.yaml' in t
    ctl = (DEPLOY / 'ctl.service').read_text()
    assert 'BindsTo=ctl-secrets.service' in ctl and 'RestartPreventExitStatus=2' in ctl
    assert 'ExecStartPre=/opt/ctl/venv/bin/python -m ctlplane check' in ctl
    migrate = (DEPLOY / 'ctl-migrate.service').read_text()
    assert 'Conflicts=ctl.service' in migrate
    after = [line for line in migrate.splitlines() if line.startswith('After=')][0]
    assert 'ctl.service' in after.split('=', 1)[1].split()          # the stop is ordered before the start


@needs_systemd
def test_ctl_secrets_runs_under_its_sandbox(tmp_path, sops):
    runtime = Path(os.environ.get('XDG_RUNTIME_DIR', '/run/user/%d' % os.getuid())) / 'ctl'
    shutil.rmtree(runtime, ignore_errors=True)
    given = sops({'database_url': 'postgresql://x', 'bucket_c_write.json': {'key_id': 'k', 'secret': 's'}})
    try:
        run = sandboxed('ctl-secrets.service',
                        [sys.executable, '-I', str(DEPLOY / 'write_secrets.py'), '--sops-file', 'f',
                         '--dir', str(runtime), '--user', USER, '--sops', given],
                        env={'FAKE_SOPS_JSON': os.environ['FAKE_SOPS_JSON']},
                        replace=(('/run/ctl', str(runtime)),), extra=['-p', 'RuntimeDirectoryPreserve=yes'])
        assert run.returncode == 0, run.stderr
        assert sorted(os.listdir(runtime)) == ['bucket_c_write.json', 'database_url']
        assert stat.S_IMODE(os.stat(runtime / 'database_url').st_mode) == 0o400
    finally:
        shutil.rmtree(runtime, ignore_errors=True)


@needs_systemd
def test_the_syscall_filter_is_enforced(shm):
    """chown is in @system-service, which ctl.service allows, and in @privileged, which it then denies: the
    process is killed (SIGSYS), not refused. ctl-secrets.service, which exists to chown, may."""
    f = shm / 'f'
    f.write_text('')
    probe = 'import os; os.chown(%r, os.getuid(), os.getgid()); print("chowned")' % str(f)
    run = sandboxed('ctl.service', [sys.executable, '-c', probe])
    assert run.returncode != 0 and 'chowned' not in run.stdout and 'PermissionError' not in run.stderr, run
    assert 'chowned' in sandboxed('ctl-secrets.service', [sys.executable, '-c', probe]).stdout


@needs_systemd
def test_ctl_secrets_maps_no_writable_executable_memory():
    probe = ('import mmap\ntry:\n    mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n'
             '    print("wx mapped")\nexcept OSError:\n    print("refused")\n')
    assert sandboxed('ctl-secrets.service', [sys.executable, '-c', probe]).stdout.strip() == 'refused'


@needs_systemd
def test_ctl_unit_cant_read_the_sops_file_or_the_host_key(tmp_path):
    if not _mount_namespacing():
        pytest.skip('this user manager sets up no mount namespaces: InaccessiblePaths is checked on ctl-1')
    sops_file = tmp_path / 'secrets.sops.yaml'
    sops_file.write_text('encrypted')
    key = tmp_path / 'host.agekey'
    key.write_text('AGE-SECRET-KEY-1')
    probe = 'import sys\nfor p in sys.argv[1:]:\n    try:\n        open(p).read(); print("read", p)\n' \
            '    except OSError as e:\n        print("denied", p, e.errno)\n'
    run = sandboxed('ctl.service', [sys.executable, '-c', probe, str(sops_file), str(key)],
                    replace=(('/etc/ctl/secrets.sops.yaml', str(sops_file)), ('/etc/ctl/host.agekey', str(key))),
                    extra=['-p', 'PrivateTmp=no'])
    assert run.returncode == 0, run.stderr
    assert run.stdout.count('denied') == 2 and 'read' not in run.stdout, run.stdout


@needs_systemd
@needs_s3
def test_check_runs_under_the_ctl_unit_with_secrets_from_write_secrets(dsn, pki, tmp_path, sops, shm):
    """The secrets as write_secrets leaves them, the configuration as on ctl-1, `check` in ctl.service's sandbox
    (PrivateTmp hides /tmp, so what it reads is on /dev/shm)."""
    s = Setup(tmp_path, dsn, pki)
    secrets_dir, etc = shm / 'run', shm / 'etc'
    secrets_dir.mkdir(mode=0o700)
    etc.mkdir()
    names = {('database', 'url_file'): 'database_url', ('dispatcher', 'signing_key_file'): 'dispatch_seed',
             ('dispatcher', 'vault_identity_file'): 'vault_identity', ('enrollment', 'ca_key_file'): 'agents_ca_key',
             ('bucket_c', 'write_key_file'): 'bucket_c_write.json',
             ('bucket_c', 'retention_key_file'): 'bucket_c_retention.json'}
    plain = {}
    for (section, key), name in names.items():
        value = Path(s.data[section][key]).read_text()
        plain[name] = json.loads(value) if name.endswith('.json') else value
        s.data[section][key] = str(secrets_dir / name)
    assert _run(sops(plain), secrets_dir) == 0
    for name in ('server.pem', 'server.key', 'ca.pem'):
        shutil.copy(pki / name, etc / name)
    shutil.copy(s.data['operator_api']['jwks_file'], etc / 'jwks.json')
    s.data['operator_api']['jwks_file'] = str(etc / 'jwks.json')
    s.data['enrollment']['ca_cert_file'] = str(etc / 'ca.pem')
    for section in ('agent_api', 'enroll_api'):
        s.data[section].update(cert_file=str(etc / 'server.pem'), key_file=str(etc / 'server.key'))
    s.data['agent_api']['ca_file'] = str(etc / 'ca.pem')
    config = etc / 'ctl.toml'
    shutil.copy(s.config(), config)
    run = sandboxed('ctl.service', [sys.executable, '-m', 'ctlplane', '--config', str(config),
                                    'check'])
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)['ok'] is True
