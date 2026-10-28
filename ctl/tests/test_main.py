"""`python -m ctlplane`: configuration, the workers lock, serve, and the
operator commands (migrate, drill, rebuild)."""
import base64
import json
import os
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import psycopg
import pytest
from alembic import command

from ctlplane import main
from ctlplane.main import Workers

from .conftest import ROOT, World, _free_port
from .test_cpbackup import ADMIN, HEAD, PG16, TEMP_ADMIN, _alembic, _database, _drop, new_cluster  # noqa: F401
from .test_operator_api import AUDIENCE, ISSUER, JWKS, token
from .test_retention import S3, _s3_up

UTC = timezone.utc
needs_s3 = pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')


def _write(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)
    return str(path)


class Setup:
    """A complete configuration for the world in `dsn`, on free loopback ports."""

    def __init__(self, tmp_path, dsn, pki, bucket=None):
        import pyrage
        self.d = tmp_path
        self.w = World(dsn)
        self.recovery = pyrage.x25519.Identity.generate()
        from nacl.signing import SigningKey
        self.dump_signing = SigningKey.generate()
        self.ports = {k: _free_port() for k in ('agent_api', 'enroll_api', 'operator_api', 'monitoring')}
        self.bucket = bucket or 'ctl-c-' + uuid.uuid4().hex[:12]
        s3 = boto3.client('s3', endpoint_url=S3, region_name='us-east-1', aws_access_key_id='test',
                          aws_secret_access_key='test')
        if _s3_up():
            s3.create_bucket(Bucket=self.bucket, ObjectLockEnabledForBucket=True)
        key = json.dumps({'key_id': 'test', 'secret': 'test'})
        q = lambda v: json.dumps(str(v))  # noqa: E731
        self.data = {
            'database': {'url_file': _write(tmp_path / 'db_url', dsn)},
            'dispatcher': {'signing_key_file': _write(tmp_path / 'dispatch', base64.b64encode(
                self.w.dispatch.encode()).decode()),
                'vault_identity_file': _write(tmp_path / 'vault', str(self.w.vault.identity))},
            'agent_api': {'listen': '127.0.0.1:%d' % self.ports['agent_api'], 'cert_file': str(pki / 'server.pem'),
                          'key_file': str(pki / 'server.key'), 'ca_file': str(pki / 'ca.pem')},
            'enroll_api': {'listen': '127.0.0.1:%d' % self.ports['enroll_api'], 'cert_file': str(pki / 'server.pem'),
                           'key_file': str(pki / 'server.key')},
            'enrollment': {'ca_cert_file': str(pki / 'ca.pem'),
                           'ca_key_file': _write(tmp_path / 'ca.key', (pki / 'ca.key').read_text())},
            'operator_api': {'listen': '127.0.0.1:%d' % self.ports['operator_api'], 'oidc_issuer': ISSUER,
                             'oidc_audience': AUDIENCE, 'jwks_file': _write(tmp_path / 'jwks', json.dumps(JWKS))},
            'monitoring': {'listen': '127.0.0.1:%d' % self.ports['monitoring'], 'webhook_token_sha256': '0' * 64},
            's3': {'endpoint': S3, 'region': 'us-east-1'},
            'bucket_c': {'bucket': self.bucket, 'write_key_file': _write(tmp_path / 'c_write', key),
                         'retention_key_file': _write(tmp_path / 'c_retention', key),
                         'recovery_recipient': str(self.recovery.to_public()),
                         'signing_key_file': _write(tmp_path / 'dump_signing', base64.b64encode(
                             self.dump_signing.encode()).decode()),
                         'pg_dump': PG16 + ['pg_dump'], 'pg_restore': PG16 + ['pg_restore']},
            'policy': {'breakglass_enabled': False},
        }
        self.q = q

    def config(self, **override):
        data = json.loads(json.dumps(self.data))
        for section, values in override.items():
            if values is None:
                data.pop(section, None)
            else:
                data[section] = {**data.get(section, {}), **values}
        lines = []
        for section, values in data.items():
            lines.append('[%s]' % section)
            lines += ['%s = %s' % (k, json.dumps(v)) for k, v in values.items()]
        return _write(self.d / 'ctl.toml', '\n'.join(lines) + '\n', 0o644)       # not a secret

    def run(self, *args, **override):
        return main.main(['--config', self.config(**override), *args])


@pytest.fixture
def setup(tmp_path, dsn, pki):
    return Setup(tmp_path, dsn, pki)


# -- configuration -------------------------------------------------------------------

@needs_s3
def test_check_builds_everything(setup, capsys):
    assert setup.run('check') == 0
    out = json.loads(capsys.readouterr().out)
    assert out['servers'] == ['agent_api', 'enroll_api', 'monitoring', 'operator_api']
    assert out['workers'] == ['reconciler', 'expiry', 'backup_schedule', 'retention', 'drills', 'controlplane_backup']
    assert out['schema_revision'] == out['head'] == HEAD


def test_optional_sections(setup, capsys):
    assert setup.run('check', enrollment=None, enroll_api=None, bucket_c=None) == 0
    out = json.loads(capsys.readouterr().out)
    assert 'enroll_api' not in out['servers'] and 'controlplane_backup' not in out['workers']


@pytest.mark.parametrize('mode', [0o644, 0o640])
def test_secret_files_must_be_private(setup, capsys, mode):
    os.chmod(setup.data['database']['url_file'], mode)
    assert setup.run('check') == 2
    err = capsys.readouterr().err
    assert 'db_url' in err and '0600' in err and 'postgresql://' not in err


@pytest.mark.parametrize('override, says', [
    ({'operator_api': {'oidc_issuer': ...}}, '[operator_api] oidc_issuer is required'),
    ({'bucket_c': {'signing_key_file': ...}}, 'signing_key_file is required: ctl-1 signs its dumps'),
    ({'monitoring': {'listen': '0.0.0.0:9464'}}, 'listen on loopback'),
    ({'operator_api': {'listen': '10.8.0.1:8080'}}, 'without TLS'),
    ({'agent_api': {'listen': 'nowhere'}}, 'host:port'),
    ({'dispatcher': {'signing_key_file': 'MISSING'}}, 'No such file'),
])
def test_bad_configuration_is_refused(setup, capsys, override, says):
    section, values = next(iter(override.items()))
    key, value = next(iter(values.items()))
    if value is ...:
        del setup.data[section][key]
        override = {}
    elif value == 'MISSING':
        override = {section: {key: str(setup.d / 'missing')}}
    assert setup.run('check', **override) == 2
    assert says in capsys.readouterr().err


def test_bad_secret_content_is_refused(setup, capsys):
    _write(setup.d / 'vault', 'not-an-identity')
    assert setup.run('check') == 2
    assert 'not an age identity' in capsys.readouterr().err


# -- the workers lock ----------------------------------------------------------------

def test_one_instance_runs_the_workers_and_another_takes_over(dsn):
    runs = {'a': 0, 'b': 0}

    def job(name, fail=False):
        def run():
            runs[name] += 1
            if fail:
                raise RuntimeError('boom')        # logged; runs again next round
        return run
    a = Workers(dsn, [('job', job('a', fail=True), 0.05)], retry=0.1, ping=0.1)
    b = Workers(dsn, [('job', job('b'), 0.05)], retry=0.1, ping=0.1)
    stop_a, stop_b = threading.Event(), threading.Event()
    ta = threading.Thread(target=a.run, args=(stop_a,))
    tb = threading.Thread(target=b.run, args=(stop_b,))
    try:
        ta.start()
        assert a.leading.wait(5)
        tb.start()
        time.sleep(0.6)
        assert not b.leading.is_set() and runs['b'] == 0 and runs['a'] > 3
        stop_a.set()
        ta.join(5)
        assert b.leading.wait(5)
        time.sleep(0.3)
        assert runs['b'] > 0
    finally:
        stop_a.set()
        stop_b.set()
        ta.join(5)
        tb.join(5)


def test_a_lost_lock_connection_ends_that_term(dsn):
    """Its workers stop; the lock, free again, is taken in a new term."""
    threads = []
    w = Workers(dsn, [('job', lambda: threads.append(threading.current_thread()), 0.05)], retry=0.1, ping=0.1)
    stop = threading.Event()
    t = threading.Thread(target=w.run, args=(stop,))
    try:
        t.start()
        assert w.leading.wait(5)
        time.sleep(0.2)
        first = set(threads)
        with psycopg.connect(ADMIN, autocommit=True) as c:
            killed = c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' "
                               'AND objid = %s', (main.WORKERS_LOCK & 0xffffffff,)).fetchone()[0]
        assert killed == 1
        deadline = time.time() + 5
        while not set(threads) - first and time.time() < deadline:
            time.sleep(0.05)
        assert set(threads) - first                                     # a new term
        assert not any(x.is_alive() for x in first)                     # the old one's workers ended
    finally:
        stop.set()
        t.join(5)


def test_the_workers_metric_follows_the_lock(dsn):
    from fastapi.testclient import TestClient
    from nacl.signing import SigningKey

    from ctlplane import monitoring
    from ctlplane.store import Store
    store = Store(dsn, SigningKey.generate())
    a = Workers(dsn, [('job', lambda: None, 0.05)], retry=0.1, ping=0.1)
    b = Workers(dsn, [('job', lambda: None, 0.05)], retry=0.1, ping=0.1)
    leader = lambda w: [line for line in TestClient(monitoring.create_app(  # noqa: E731
        store, webhook_token_sha256='0' * 64, workers=w)).get('/metrics').text.splitlines()
        if line.startswith('ctl_workers_leader ')]
    stop_a, stop_b = threading.Event(), threading.Event()
    ta = threading.Thread(target=a.run, args=(stop_a,))
    tb = threading.Thread(target=b.run, args=(stop_b,))
    try:
        assert leader(a) == ['ctl_workers_leader 0']                    # not started
        ta.start()
        assert a.leading.wait(5)
        tb.start()
        time.sleep(0.3)
        assert (leader(a), leader(b)) == (['ctl_workers_leader 1'], ['ctl_workers_leader 0'])
        stop_a.set()
        ta.join(5)
        assert b.leading.wait(5)
        assert (leader(a), leader(b)) == (['ctl_workers_leader 0'], ['ctl_workers_leader 1'])
        assert leader(None) == []                                       # monitoring without workers
    finally:
        stop_a.set()
        stop_b.set()
        ta.join(5)
        tb.join(5)


def _metrics(w):
    from ctlplane.monitoring import workers_metric
    return dict(line.rsplit(' ', 1) for line in workers_metric(w).splitlines() if not line.startswith('#'))


def test_per_worker_metrics(dsn):
    def bad():
        raise RuntimeError('boom')
    w = Workers(dsn, [('good', lambda: None, 0.05), ('bad', bad, 0.05)], retry=0.1, ping=0.1)
    m = _metrics(w)
    assert m == {'ctl_workers_leader': '0', 'ctl_worker_failures_total{worker="bad"}': '0',
                 'ctl_worker_failures_total{worker="good"}': '0'}                       # no term: no ages
    stop = threading.Event()
    t = threading.Thread(target=w.run, args=(stop,))
    try:
        before = time.time()
        t.start()
        assert w.leading.wait(5)
        time.sleep(0.4)
        m = _metrics(w)
        good = float(m['ctl_worker_last_success_timestamp_seconds{worker="good"}'])
        bad_at = float(m['ctl_worker_last_success_timestamp_seconds{worker="bad"}'])
        assert before <= bad_at < good <= time.time()                   # bad: still the term's start
        assert int(m['ctl_worker_failures_total{worker="bad"}']) >= 3
        assert m['ctl_worker_failures_total{worker="good"}'] == '0'
        assert m['ctl_worker_interval_seconds{worker="good"}'] == '0.05'
    finally:
        stop.set()
        t.join(5)
    m = _metrics(w)
    assert not [k for k in m if 'last_success' in k or 'interval' in k]   # the term ended
    assert int(m['ctl_worker_failures_total{worker="bad"}']) >= 3       # a counter: kept


def test_a_database_error_on_the_lock_query_is_retried(dsn, monkeypatch):
    """The connection succeeds and the server goes away before the lock query: the supervisor tries again."""
    real, calls = psycopg.connect, []

    class Gone:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, *a):
            raise psycopg.OperationalError('server closed the connection unexpectedly')

    def connect(*a, **k):
        calls.append(1)
        return Gone() if len(calls) == 1 else real(*a, **k)
    monkeypatch.setattr(main.psycopg, 'connect', connect)
    w = Workers(dsn, [('job', lambda: None, 0.05)], retry=0.1, ping=0.1)
    stop = threading.Event()
    t = threading.Thread(target=w.run, args=(stop,))
    try:
        t.start()
        assert w.leading.wait(5) and len(calls) >= 2
    finally:
        stop.set()
        t.join(5)
    assert not t.is_alive()


# -- serve ---------------------------------------------------------------------------

def _get(url, headers=None, context=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=5,
                                    context=context) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@needs_s3
def test_serve_runs_the_apis_and_the_workers_and_stops_on_sigterm(setup, pki):
    _operator(setup.w, 'auditor', 'sub-auditor')
    proc = subprocess.Popen([sys.executable, '-m', 'ctlplane', '--config', setup.config(), 'serve'], cwd=ROOT,
                            stderr=subprocess.PIPE, text=True)
    try:
        mon = 'http://127.0.0.1:%d/metrics' % setup.ports['monitoring']
        deadline = time.time() + 30
        while True:
            try:
                status, body = _get(mon)
                break
            except (urllib.error.URLError, ConnectionError):
                assert proc.poll() is None and time.time() < deadline, proc.stderr.read() if proc.poll() else ''
                time.sleep(0.2)
        assert status == 200 and b'ctl_controlplane_dump_last_timestamp_seconds' in body
        while b'\nctl_workers_leader 1\n' not in _get(mon)[1]:                # once the workers start
            assert time.time() < deadline
            time.sleep(0.2)
        body = _get(mon)[1].decode()
        for worker in ('reconciler', 'expiry', 'backup_schedule', 'retention', 'drills', 'controlplane_backup'):
            assert 'ctl_worker_last_success_timestamp_seconds{worker="%s"}' % worker in body
        op = 'http://127.0.0.1:%d/v1/retention' % setup.ports['operator_api']
        assert _get(op)[0] == 401
        assert _get(op, {'Authorization': 'Bearer ' + token('sub-auditor')})[0] == 200
        agent = 'https://127.0.0.1:%d/v1/hosts/%s/poll' % (setup.ports['agent_api'], uuid.uuid4())
        with pytest.raises((urllib.error.URLError, ConnectionError, ssl.SSLError)):
            _get(agent, context=ssl.create_default_context(cafile=str(pki / 'ca.pem')))     # no client cert
        assert _get('https://127.0.0.1:%d/v1/enroll' % setup.ports['enroll_api'],
                    context=ssl.create_default_context(cafile=str(pki / 'ca.pem')))[0] == 405
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        log = proc.stderr.read()
    assert code == 0, log
    assert 'workers: started reconciler, expiry, backup_schedule, retention, drills, controlplane_backup' in log
    assert 'Traceback' not in log, log


# -- operator commands ----------------------------------------------------------------

@needs_s3
def test_migrate_dumps_then_upgrades(tmp_path, pki, capsys):
    name, url = _database()
    try:
        command.upgrade(_alembic(url), '0011')
        s = Setup(tmp_path, url, pki)
        assert s.run('check') == 1                                       # behind: not served
        out = json.loads(capsys.readouterr().out)
        assert (out['ok'], out['schema_revision'], out['head']) == (False, '0011', HEAD)
        assert s.run('migrate') == 0
        out = json.loads(capsys.readouterr().out)
        assert out['dump']['reason'] == 'pre_migration' and out['dump']['schema_revision'] == '0011'
        assert s.w.sql('SELECT version_num FROM alembic_version')[0]['version_num'] == HEAD
        assert s.run('check') == 0 and json.loads(capsys.readouterr().out)['ok']
        assert s.run('migrate') == 0 and json.loads(capsys.readouterr().out)['dump'] is None
        assert s.run('migrate', bucket_c=None) == 2
    finally:
        _drop(name)


def _operator(w, role, sub=None):
    op, granter = uuid.uuid4(), uuid.uuid4()        # nobody grants themselves a role
    for i, s in ((op, sub or 'sub-' + op.hex[:8]), (granter, 'sub-' + granter.hex[:8])):
        w.sql("INSERT INTO operator (id, oidc_subject, status) VALUES (%s, %s, 'active')", (i, s))
    w.sql("INSERT INTO operator_role_grant (id, operator_id, role, valid_from, granted_by) "
          "VALUES (%s, %s, %s, now() - interval '1 day', %s)", (uuid.uuid4(), op, role, granter))
    return str(op)


@needs_s3
def test_drill_command(setup, capsys):
    if TEMP_ADMIN is None:
        pytest.skip('needs agent-pg (agent dev/up.sh) as the temporary server')
    setup.w.store.clock = lambda: datetime.now(UTC).timestamp()
    main.build_cpbackup(main.Config(setup.data), setup.w.store, main.secret(setup.data['database']['url_file'])).dump()
    name = 'ctl_drill_' + uuid.uuid4().hex[:8]
    with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
        c.execute('CREATE DATABASE ' + name)
    try:
        target = _write(setup.d / 'target', TEMP_ADMIN.rsplit('/', 1)[0] + '/' + name)
        auditor = _operator(setup.w, 'auditor')
        assert setup.run('drill', '--operator', auditor, '--target-file', target) == 2
        assert 'not an active' in capsys.readouterr().err
        os.chmod(target, 0o644)
        assert setup.run('drill', '--operator', _operator(setup.w, 'backup_custodian'), '--target-file', target) == 2
        assert 'mode 0600' in capsys.readouterr().err
        os.chmod(target, 0o600)
        assert setup.run('drill', '--operator', _operator(setup.w, 'backup_custodian'), '--target-file', target) == 0
        out = json.loads(capsys.readouterr().out)
        assert out['ok'] and out['key_kind'] == 'operational' and 'postgres:' not in json.dumps(out)
        import pyrage
        wrong = _write(setup.d / 'wrong', str(pyrage.x25519.Identity.generate()))
        with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
            c.execute('DROP DATABASE %s WITH (FORCE)' % name)
            c.execute('CREATE DATABASE ' + name)
        assert setup.run('drill', '--operator', _operator(setup.w, 'platform_operator'), '--target-file', target,
                         '--recovery-identity-file', wrong) == 1
        assert json.loads(capsys.readouterr().out)['reason'] == 'cannot_decrypt'
    finally:
        with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
            c.execute('DROP DATABASE %s WITH (FORCE)' % name)


@needs_s3
def test_rebuild_command_needs_no_database(setup, new_cluster, capsys):  # noqa: F811
    admin, login = new_cluster
    setup.w.store.clock = lambda: datetime.now(UTC).timestamp()
    main.build_cpbackup(main.Config(setup.data), setup.w.store, main.secret(setup.data['database']['url_file'])).dump()
    admin_file = _write(setup.d / 'admin', admin)
    identity = _write(setup.d / 'recovery', str(setup.recovery))
    # A new ctl-1 trusts the old one's public key from its configuration; it has no signing key yet.
    del setup.data['bucket_c']['signing_key_file']
    setup.data['bucket_c']['signing_public_keys'] = [base64.b64encode(bytes(setup.dump_signing.verify_key)).decode()]
    # A new ctl-1: no [database], [dispatcher] or APIs yet.
    bare = {k: None for k in ('database', 'dispatcher', 'agent_api', 'enroll_api', 'enrollment', 'operator_api',
                              'monitoring')}
    assert setup.run('rebuild', '--admin-file', admin_file, '--identity-file', identity, **bare) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['ok'] and out['privileges_match'] and login in out['login_roles'], out
    assert setup.run('rebuild', '--admin-file', admin_file, '--identity-file', identity, **bare) == 1
    assert json.loads(capsys.readouterr().out)['reason'] == 'database_exists'


# -- bootstrap -----------------------------------------------------------------------

def test_bootstrap_registers_root_keys_and_regions_once(setup, capsys):
    import pyrage
    from nacl.signing import SigningKey
    b64 = lambda k: base64.b64encode(bytes(k.verify_key)).decode()  # noqa: E731
    release, custodian, glass = SigningKey.generate(), SigningKey.generate(), SigningKey.generate()
    recipient = str(pyrage.x25519.Identity.generate().to_public())
    trust = {'release_public_key': b64(release), 'custodian_public_keys': [b64(custodian)],
             'breakglass_public_key': b64(glass)}
    setup.data['trust'] = trust
    config = setup.config()
    with open(config, 'a') as f:                                   # an array of tables
        f.write('\n[[regions]]\ncode = "eu-de-hel1"\nbackup_recipient = "%s"\nbackup_bucket = "tenants-hel1"\n'
                % recipient)
    run = lambda: main.main(['--config', config, 'bootstrap'])  # noqa: E731
    assert run() == 0
    out = json.loads(capsys.readouterr().out)
    assert sorted(out['keys_registered']) == ['breakglass', 'custodian', 'dispatch', 'release']
    assert out['regions_registered'] == ['eu-de-hel1']
    keys = {r['purpose']: r['public_key'] for r in setup.w.sql(
        "SELECT purpose, public_key FROM signing_key WHERE purpose <> 'agent' AND public_key IN (%s, %s, %s, %s)",
        (b64(release), b64(custodian), b64(glass), b64(setup.w.dispatch)))}
    assert keys == {'release': b64(release), 'custodian': b64(custodian), 'breakglass': b64(glass),
                    'dispatch': b64(setup.w.dispatch)}
    assert run() == 0 and json.loads(capsys.readouterr().out) == {
        'keys_registered': [], 'regions_registered': [], 'regions_differing': []}
    setup.w.sql("UPDATE region SET backup_bucket = 'other' WHERE code = 'eu-de-hel1'")
    assert run() == 0 and json.loads(capsys.readouterr().out)['regions_differing'] == ['eu-de-hel1']
    assert setup.w.sql("SELECT backup_bucket FROM region WHERE code = 'eu-de-hel1'")[0]['backup_bucket'] == 'other'


@pytest.mark.parametrize('bad', ['release', 'recipient'])
def test_bootstrap_refuses_bad_keys(setup, capsys, bad):
    setup.data['trust'] = {'release_public_key': 'not-a-key' if bad == 'release' else
                           base64.b64encode(b'x' * 32).decode()}
    config = setup.config()
    if bad == 'recipient':
        with open(config, 'a') as f:
            f.write('\n[[regions]]\ncode = "x"\nbackup_recipient = "age1nope"\nbackup_bucket = "b"\n')
    assert main.main(['--config', config, 'bootstrap']) == 2
    assert 'configuration' in capsys.readouterr().err
