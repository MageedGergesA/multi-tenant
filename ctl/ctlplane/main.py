"""ctl-1's process (ADR-009): `python -m ctlplane [--config PATH] <command>`.

    serve     the agent API (mutual TLS), enrollment (server TLS), the operator
              API and monitoring, plus the workers on the instance that holds
              the workers lock
    check     build everything from the configuration, then exit
    migrate   dump to bucket C, then upgrade the schema (DOC-05 §2)
    bootstrap register the root public keys ([trust]: release, custodian,
              break-glass; dispatch from the dispatcher's seed) and regions
              ([[regions]]); idempotent, never changes or retires one
    drill     the quarterly control-plane drill onto a temporary server
              (DOC-05 §5); prints the report, exit 1 if it failed
    rebuild   RB-09/RB-10: restore the newest (or a given) dump onto this
              cluster with the recovery key; works without a database

The configuration is TOML (`--config`, else $CTL_CONFIG) and holds no secret:
each `*_file` names a file (SOPS-decrypted onto tmpfs by the host's unit) that
must belong to this user and not be readable by group or others. `drill` and
`rebuild` read their DSNs from such files too, so no password is on a
command line or goes through the operator API.

Workers: Reconciler, Expiry, BackupSchedule, Retention, Drills and the
control-plane backup, each in its own thread; one that raises is logged,
counted, and runs again next round (`ctl_worker_*` in /metrics). They run only while this process holds a PostgreSQL
session advisory lock, so a second instance (a restart overlapping the old
one, or a mistake) serves the APIs but not the workers. A lost lock
connection stops them; until the next ping (LOCK_PING s) both may run,
which the jobs' idempotency keys and row locks tolerate. Proper leader
election is E1's.
"""
import argparse
import asyncio
import base64
import contextlib
import ipaddress
import json
import logging
import os
import signal
import stat
import sys
import threading
import time
import tomllib
from pathlib import Path

import psycopg
import pyrage
import uvicorn
from nacl.signing import SigningKey

log = logging.getLogger('ctlplane')

WORKERS_LOCK = 0x63746c776f726b      # "ctlwork"
LOCK_RETRY = 30.0
LOCK_PING = 10.0
DRILL_ROLES = ('platform_operator', 'backup_custodian')


class ConfigError(Exception):
    pass


# -- configuration ----------------------------------------------------------------------

def secret(path) -> str:
    """A secret file's content, refused unless it is this user's and private."""
    p = Path(path)
    try:
        st = p.stat()
    except OSError as e:
        raise ConfigError('%s: %s' % (path, e.strerror)) from None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ConfigError('%s: must be a regular file of this user, mode 0600 or 0400' % path)
    return p.read_text().strip()


class Config:
    def __init__(self, data: dict, path='config'):
        self.data = data
        self.path = path

    @classmethod
    def load(cls, path) -> 'Config':
        try:
            with open(path, 'rb') as f:
                return cls(tomllib.load(f), str(path))
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise ConfigError('%s: %s' % (path, e)) from None

    def has(self, section) -> bool:
        return isinstance(self.data.get(section), dict)

    def get(self, section, key, default=...):
        value = self.data.get(section, {}).get(key, default) if self.has(section) else default
        if value is ...:
            raise ConfigError('%s: [%s] %s is required' % (self.path, section, key))
        return value

    def secret(self, section, key) -> str:
        return secret(self.get(section, key))

    def json_secret(self, section, key) -> dict:
        try:
            value = json.loads(self.secret(section, key))
        except ValueError:
            raise ConfigError('[%s] %s: not JSON' % (section, key)) from None
        if not isinstance(value, dict) or not {'key_id', 'secret'} <= set(value):
            raise ConfigError('[%s] %s: needs key_id and secret' % (section, key))
        return value

    def listen(self, section) -> tuple[str, int]:
        value = self.get(section, 'listen')
        host, _, port = str(value).rpartition(':')
        try:
            return host.strip('[]'), int(port)
        except ValueError:
            raise ConfigError('[%s] listen: host:port, not %r' % (section, value)) from None


def _loopback(host) -> bool:
    try:
        return host == 'localhost' or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# -- building ------------------------------------------------------------------------

class Ctl:
    """Everything `serve` runs, built from the configuration; nothing is started."""

    def __init__(self, cfg: Config):
        from .admission import Admission
        from .store import Store
        from .vault import Vault

        self.cfg = cfg
        self.dsn = cfg.secret('database', 'url_file')
        try:
            seed = base64.b64decode(cfg.secret('dispatcher', 'signing_key_file'), validate=True)
            self.dispatch = SigningKey(seed)
        except (ValueError, TypeError):
            raise ConfigError('[dispatcher] signing_key_file: base64 of a 32-byte Ed25519 seed') from None
        try:
            self.vault = Vault(pyrage.x25519.Identity.from_str(cfg.secret('dispatcher', 'vault_identity_file')))
        except pyrage.IdentityError:
            raise ConfigError('[dispatcher] vault_identity_file: not an age identity') from None
        policy = lambda key, default: cfg.get('policy', key, default)  # noqa: E731
        self.breakglass = bool(policy('breakglass_enabled', False))
        # The dispatcher's role hands out envelopes and runs the workers; the operator API runs as ctl_app.
        self.store = Store(self.dsn, self.dispatch, vault=self.vault)
        self.app_store = Store(self.dsn, self.dispatch, role='ctl_app')
        self.admission = Admission(self.store, recipient=self.vault.recipient, breakglass_enabled=self.breakglass)
        self.s3_endpoint = cfg.get('s3', 'endpoint', '')
        self.s3_region = cfg.get('s3', 'region', 'eu-central-003')
        self.cpbackup = build_cpbackup(cfg, self.store, self.dsn) if cfg.has('bucket_c') else None
        if self.cpbackup is not None and self.cpbackup.signing_key is None:
            raise ConfigError('[bucket_c] signing_key_file is required: ctl-1 signs its dumps')
        self.jobs = self._jobs()
        self.workers = Workers(self.dsn, self.jobs)
        self.servers = self._servers()

    def _servers(self) -> dict[str, uvicorn.Server]:
        from . import agent_api, enroll_api, monitoring, operator_api
        from .admission import Admission
        from .auth import OidcVerifier
        from .enrollment import Enrollment
        from .retention import Retention
        from .tls import server
        from .trust import Trust

        c = self.cfg
        out = {}
        host, port = c.listen('agent_api')
        out['agent_api'] = server(agent_api.create_app(self.store), host, port, cert=c.get('agent_api', 'cert_file'),
                                  key=c.get('agent_api', 'key_file'), ca=c.get('agent_api', 'ca_file'))
        enrollment = None
        if c.has('enrollment'):
            enrollment = Enrollment(self.store, ca_cert_pem=Path(c.get('enrollment', 'ca_cert_file')).read_bytes(),
                                    ca_key_pem=c.secret('enrollment', 'ca_key_file').encode(),
                                    breakglass_enabled=self.breakglass)
            host, port = c.listen('enroll_api')
            out['enroll_api'] = server(enroll_api.create_app(enrollment), host, port,
                                       cert=c.get('enroll_api', 'cert_file'), key=c.get('enroll_api', 'key_file'),
                                       client_certs=False)
        try:
            jwks = json.loads(Path(c.get('operator_api', 'jwks_file')).read_text())
            verifier = OidcVerifier(c.get('operator_api', 'oidc_issuer'), c.get('operator_api', 'oidc_audience'), jwks)
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise ConfigError('[operator_api] jwks_file: %s' % e) from None
        app = operator_api.create_app(
            Admission(self.app_store, recipient=self.vault.recipient, breakglass_enabled=self.breakglass), verifier,
            dispatcher_recipient=self.vault.recipient, enrollment=enrollment,
            trust=Trust(self.store, breakglass_enabled=self.breakglass),
            retention=Retention(self.app_store, breakglass_enabled=self.breakglass))
        host, port = c.listen('operator_api')
        cert = c.get('operator_api', 'cert_file', None)
        if not _loopback(host) and not cert:
            raise ConfigError('[operator_api] listens on %s without TLS: give cert_file and key_file' % host)
        out['operator_api'] = _plain(app, host, port, cert=cert, key=cert and c.get('operator_api', 'key_file'))
        host, port = c.listen('monitoring')
        if not _loopback(host):
            raise ConfigError('[monitoring] serves the local Prometheus and Alertmanager: listen on loopback')
        out['monitoring'] = _plain(monitoring.create_app(
            self.store, webhook_token_sha256=c.get('monitoring', 'webhook_token_sha256'), workers=self.workers),
            host, port)
        return out

    def _jobs(self) -> list[tuple]:
        from .backup_schedule import BackupSchedule
        from .drills import Drills
        from .expiry import Expiry
        from .reconciler import Reconciler
        from .retention import Retention

        c = self.cfg
        ctl_key = (c.json_secret('bucket_c', 'retention_key_file')
                   if self.cpbackup and c.get('bucket_c', 'retention_key_file', None) else None)
        jobs = [('reconciler', Reconciler(self.store).run_once, 5),
                ('expiry', Expiry(self.admission).run_once, 300),
                ('backup_schedule', BackupSchedule(self.admission, max_per_host=c.get('policy', 'backups_per_host', 2))
                 .run_once, 60),
                ('retention', Retention(self.store, s3_endpoint=self.s3_endpoint, s3_region=self.s3_region,
                                        breakglass_enabled=self.breakglass, ctl_retention_key=ctl_key).run_once, 3600),
                ('drills', Drills(self.admission, per_day=c.get('policy', 'drills_per_day', 1)).run_once, 300)]
        if self.cpbackup:
            jobs.append(('controlplane_backup', self.cpbackup.run_once, 300))
        return jobs


def build_cpbackup(cfg: Config, store, owner_dsn):
    """`store`/`owner_dsn` None: a new ctl-1 that only rebuilds."""
    from nacl.signing import VerifyKey

    from .cpbackup import ControlPlaneBackup
    signing = None
    if cfg.get('bucket_c', 'signing_key_file', None):
        try:
            signing = SigningKey(base64.b64decode(cfg.secret('bucket_c', 'signing_key_file'), validate=True))
        except (ValueError, TypeError):
            raise ConfigError('[bucket_c] signing_key_file: base64 of a 32-byte Ed25519 seed') from None
    # The keys a dump must be signed by: configured (the IaC repo), plus this ctl-1's own.
    try:
        trusted = [VerifyKey(base64.b64decode(k, validate=True))
                   for k in cfg.get('bucket_c', 'signing_public_keys', [])]
    except (ValueError, TypeError):
        raise ConfigError('[bucket_c] signing_public_keys: base64 Ed25519 public keys') from None
    if signing is not None:
        trusted.append(signing.verify_key)
    try:
        return ControlPlaneBackup(
            store, owner_dsn=owner_dsn, bucket=cfg.get('bucket_c', 'bucket'),
            s3_key=cfg.json_secret('bucket_c', 'write_key_file'),
            recovery_recipient=cfg.get('bucket_c', 'recovery_recipient'), s3_endpoint=cfg.get('s3', 'endpoint', ''),
            s3_region=cfg.get('s3', 'region', 'eu-central-003'), pg_dump=cfg.get('bucket_c', 'pg_dump', ['pg_dump']),
            pg_restore=cfg.get('bucket_c', 'pg_restore', ['pg_restore']), signing_key=signing, trusted_keys=trusted)
    except pyrage.RecipientError:
        raise ConfigError('[bucket_c] recovery_recipient: not an age recipient') from None


def _plain(app, host, port, *, cert=None, key=None) -> uvicorn.Server:
    config = uvicorn.Config(app, host=host, port=port, ssl_certfile=cert, ssl_keyfile=key, ws='none',
                            lifespan='off', log_level='warning', access_log=False)
    config.load()
    return uvicorn.Server(config)


# -- workers -------------------------------------------------------------------------

class Workers:
    def __init__(self, dsn, jobs, *, retry=LOCK_RETRY, ping=LOCK_PING):
        self.dsn = dsn
        self.jobs = jobs
        self.retry = retry
        self.ping = ping
        self.leading = threading.Event()        # ctl_workers_leader
        self.intervals = {name: interval for name, _, interval in jobs}
        self.last_success = {}                  # while leading: name -> time of the last run that didn't raise
        self.failures = dict.fromkeys(self.intervals, 0)    # this process's lifetime

    def run(self, stop: threading.Event):
        while not stop.is_set():
            try:
                conn = psycopg.connect(self.dsn, autocommit=True)
            except psycopg.Error as e:
                log.warning('workers: no database (%s); again in %ss', type(e).__name__, self.retry)
                stop.wait(self.retry)
                continue
            try:
                with conn:
                    if not conn.execute('SELECT pg_try_advisory_lock(%s)', (WORKERS_LOCK,)).fetchone()[0]:
                        log.info('workers: another instance holds the lock')
                        stop.wait(self.retry)
                        continue
                    self._lead(conn, stop)
            except psycopg.Error as e:       # the server went away mid-acquisition: try again, never die
                log.warning('workers: database error (%s); again in %ss', type(e).__name__, self.retry)
                stop.wait(self.retry)

    def _lead(self, conn, stop):
        halt = threading.Event()
        # A term starts with nothing overdue: a job that fails from the start ages from here.
        self.last_success = dict.fromkeys(self.intervals, time.time())
        threads = [threading.Thread(target=self._loop, args=(name, job, interval, halt), name='worker-' + name,
                                    daemon=True) for name, job, interval in self.jobs]
        for t in threads:
            t.start()
        self.leading.set()
        log.info('workers: started %s', ', '.join(name for name, _, _ in self.jobs))
        try:
            while not stop.wait(self.ping):
                conn.execute('SELECT 1')
        except psycopg.Error:
            log.error('workers: lost the lock connection; stopping them')
        finally:
            halt.set()
            self.leading.clear()
            for t in threads:
                t.join()
            self.last_success = {}

    def _loop(self, name, job, interval, halt: threading.Event):
        while not halt.is_set():
            try:
                job()
                self.last_success[name] = time.time()
            except Exception:
                self.failures[name] += 1
                log.exception('worker %s failed; again in %ss', name, interval)
            halt.wait(interval)


# -- commands ------------------------------------------------------------------------

async def _serve_all(servers, stop: threading.Event):
    loop = asyncio.get_running_loop()

    def shutdown():
        stop.set()
        for s in servers:
            s.should_exit = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown)
    for s in servers:
        s.capture_signals = contextlib.nullcontext      # one handler for all, above
    await asyncio.gather(*(s.serve() for s in servers))
    stop.set()


def serve(cfg: Config):
    ctl = Ctl(cfg)
    stop = threading.Event()
    t = threading.Thread(target=ctl.workers.run, args=(stop,), name='workers')
    t.start()
    try:
        asyncio.run(_serve_all(list(ctl.servers.values()), stop))
    finally:
        stop.set()
        t.join()
    return 0


def _alembic(cfg: Config, dsn):
    from alembic.config import Config as AlembicConfig
    alembic = AlembicConfig()
    # An installed package doesn't carry them: ctl-1 has them beside the venv (infra/ansible).
    alembic.set_main_option('script_location', cfg.get('database', 'migrations_dir',
                                                       str(Path(__file__).resolve().parent.parent / 'migrations')))
    alembic.attributes['url'] = dsn
    return alembic


def check(cfg: Config):
    """Exit 0 only with the schema at the migrations' head: ctl.service doesn't serve an
    old schema, and infra/ansible runs ctl-migrate when it isn't."""
    from alembic.script import ScriptDirectory
    ctl = Ctl(cfg)
    with psycopg.connect(ctl.dsn) as c:
        revision = (c.execute('SELECT version_num FROM alembic_version').fetchone()[0]
                    if c.execute("SELECT to_regclass('alembic_version')").fetchone()[0] else None)
    head = ScriptDirectory.from_config(_alembic(cfg, ctl.dsn)).get_current_head()
    ok = revision is not None and revision == head
    print(json.dumps({'ok': ok, 'servers': sorted(ctl.servers), 'workers': [n for n, _, _ in ctl.jobs],
                      'schema_revision': revision, 'head': head}))
    return 0 if ok else 1


def migrate(cfg: Config):
    dsn = cfg.secret('database', 'url_file')
    if not cfg.has('bucket_c'):
        raise ConfigError('migrate dumps to bucket C first: [bucket_c] is required')
    from .store import Store
    # As the owner, not yet through roles a migration may be about to create; a signing key isn't needed.
    cp = build_cpbackup(cfg, Store(dsn, SigningKey.generate(), role=None), dsn)
    record = cp.migrate(_alembic(cfg, dsn))
    print(json.dumps({'ok': True, 'dump': record}, default=str))
    return 0


def bootstrap(cfg: Config):
    """What a new ctl-1 needs before the first host enrolls (enrollment pins dispatch, custodian and
    break-glass; the founder signs it with the release key). Keys and regions are added, never changed
    or retired here: that is rotation (Host.RotateTrust) and its own flow."""
    import uuid

    from . import audit
    from .store import _ts
    dsn = cfg.secret('database', 'url_file')
    try:
        dispatch = base64.b64encode(bytes(
            SigningKey(base64.b64decode(cfg.secret('dispatcher', 'signing_key_file'), validate=True)).verify_key
        )).decode()
    except (ValueError, TypeError):
        raise ConfigError('[dispatcher] signing_key_file: base64 of a 32-byte Ed25519 seed') from None
    keys = [('dispatch', dispatch), ('release', cfg.get('trust', 'release_public_key'))]
    keys += [('custodian', k) for k in cfg.get('trust', 'custodian_public_keys', [])]
    if cfg.get('trust', 'breakglass_public_key', None):
        keys.append(('breakglass', cfg.get('trust', 'breakglass_public_key')))
    for purpose, key in keys:
        try:
            if len(base64.b64decode(key, validate=True)) != 32:
                raise ValueError
        except (ValueError, TypeError):
            raise ConfigError('[trust] %s key: base64 of a 32-byte Ed25519 public key' % purpose) from None
    regions = cfg.data.get('regions', [])
    for r in regions:
        try:
            pyrage.x25519.Recipient.from_str(r['backup_recipient'])
            str(r['code']), str(r['backup_bucket'])
        except (KeyError, TypeError, pyrage.RecipientError):
            raise ConfigError('[[regions]]: code, backup_bucket and an age backup_recipient each') from None
    out = {'keys_registered': [], 'regions_registered': [], 'regions_differing': []}
    now = _ts(time.time())
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row) as c:
        for purpose, key in keys:
            if not c.execute('SELECT 1 FROM signing_key WHERE purpose = %s AND public_key = %s AND retired_at IS NULL',
                             (purpose, key)).fetchone():
                key_id = uuid.uuid4()
                c.execute('INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, %s, %s)',
                          (key_id, purpose, key))
                audit.append(c, now, 'key.registered', resource_type='signing_key', resource_id=key_id,
                             after={'purpose': purpose, 'public_key': key})
                out['keys_registered'].append(purpose)
        for r in regions:
            have = c.execute('SELECT backup_recipient, backup_bucket FROM region WHERE code = %s',
                             (r['code'],)).fetchone()
            if have is None:
                region_id = uuid.uuid4()
                c.execute('INSERT INTO region (id, code, backup_recipient, backup_bucket) VALUES (%s, %s, %s, %s)',
                          (region_id, r['code'], r['backup_recipient'], r['backup_bucket']))
                audit.append(c, now, 'region.registered', resource_type='region', resource_id=region_id,
                             after={'code': r['code'], 'backup_bucket': r['backup_bucket']})
                out['regions_registered'].append(r['code'])
            elif (have['backup_recipient'], have['backup_bucket']) != (r['backup_recipient'], r['backup_bucket']):
                out['regions_differing'].append(r['code'])       # left as it is: changing one isn't this
    print(json.dumps(out))
    return 0


def drill(cfg: Config, operator_id, target_file, recovery_identity_file=None, key=None):
    dsn = cfg.secret('database', 'url_file')
    with psycopg.connect(dsn) as c:
        ok = c.execute("SELECT 1 FROM operator o JOIN operator_role_grant g ON g.operator_id = o.id "
                       "WHERE o.id = %s AND o.status = 'active' AND g.role = ANY(%s) AND g.valid_from <= now() "
                       'AND (g.valid_to IS NULL OR g.valid_to > now())', (operator_id, list(DRILL_ROLES))).fetchone()
    if not ok:
        raise ConfigError('operator %s: not an active platform_operator or backup_custodian' % operator_id)
    ctl = Ctl(cfg)
    if ctl.cpbackup is None:
        raise ConfigError('[bucket_c] is required')
    identity = _identity(recovery_identity_file) if recovery_identity_file else None
    report = ctl.cpbackup.drill(operator_id, secret(target_file), recovery_identity=identity, key=key)
    print(json.dumps(report, default=str))
    return 0 if report['ok'] else 1


def rebuild(cfg: Config, admin_file, identity_file, key=None):
    """On a new ctl-1: [database] needn't exist yet, only [bucket_c] and [s3]."""
    report = build_cpbackup(cfg, None, None).rebuild(secret(admin_file), [_identity(identity_file)], key=key)
    print(json.dumps(report, default=str))
    return 0 if report['ok'] else 1


def _identity(path):
    try:
        return pyrage.x25519.Identity.from_str(secret(path))
    except pyrage.IdentityError:
        raise ConfigError('%s: not an age identity' % path) from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='python -m ctlplane')
    parser.add_argument('--config', default=os.environ.get('CTL_CONFIG'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('serve')
    sub.add_parser('check')
    sub.add_parser('migrate')
    sub.add_parser('bootstrap')
    p = sub.add_parser('drill')
    p.add_argument('--operator', required=True)
    p.add_argument('--target-file', required=True, help='a file holding the temporary server\'s DSN')
    p.add_argument('--recovery-identity-file')
    p.add_argument('--key')
    p = sub.add_parser('rebuild')
    p.add_argument('--admin-file', required=True, help='a file holding a superuser DSN on this cluster')
    p.add_argument('--identity-file', required=True, help='the reconstructed recovery key')
    p.add_argument('--key')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(threadName)s %(message)s')
    if not args.config:
        parser.error('--config or CTL_CONFIG is required')
    try:
        cfg = Config.load(args.config)
        if args.command == 'serve':
            return serve(cfg)
        if args.command == 'check':
            return check(cfg)
        if args.command == 'migrate':
            return migrate(cfg)
        if args.command == 'bootstrap':
            return bootstrap(cfg)
        if args.command == 'drill':
            return drill(cfg, args.operator, args.target_file, args.recovery_identity_file, args.key)
        return rebuild(cfg, args.admin_file, args.identity_file, args.key)
    except ConfigError as e:
        print('configuration: %s' % e, file=sys.stderr)
        return 2
