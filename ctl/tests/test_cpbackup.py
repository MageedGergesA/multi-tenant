"""Control-plane dump and audit anchors in bucket C (DOC-05 §2, §4, §8; SEC-13;
RB-09), against ctl-pg and LocalStack S3 with compliance-mode Object Lock."""
import base64
import hashlib
import json
import secrets
import subprocess
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import psycopg
import pyrage
import pytest
from nacl.signing import SigningKey
from psycopg.conninfo import make_conninfo
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from ctlplane import audit, cpbackup, monitoring
from ctlplane.canonical import canonical, sign
from ctlplane.cpbackup import (ANCHORS, ControlPlaneBackup, JobFailed, ReadBackMismatch, privileges_sha256,
                               roles_manifest)

from .conftest import PASSWORD, PG_UP, ROOT, World
from .test_retention import S3, _s3_up

UTC = timezone.utc
ADMIN = 'postgresql://postgres:%s@127.0.0.1:55433/postgres' % PASSWORD
PG16 = ['docker', 'run', '--rm', '-i', '--network', 'host', '-e', 'PGHOST', '-e', 'PGPORT', '-e', 'PGUSER',
        '-e', 'PGPASSWORD', '-e', 'PGDATABASE', 'postgres:16']

pytestmark = pytest.mark.skipif(not (PG_UP and _s3_up()), reason='needs ctl-pg and LocalStack (dev/up.sh)')


class Clock:
    def __init__(self, at):
        self.at = at

    def __call__(self):
        return self.at.timestamp()


def _database():
    name = 'ctl_test_' + secrets.token_hex(4)
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute('CREATE DATABASE ' + name)
    return name, 'postgresql://postgres:%s@127.0.0.1:55433/%s' % (PASSWORD, name)


def _drop(name):
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute('DROP DATABASE %s WITH (FORCE)' % name)


def _alembic(url):
    cfg = Config(str(ROOT / 'alembic.ini'))
    cfg.set_main_option('script_location', str(ROOT / 'migrations'))
    cfg.attributes['url'] = url
    return cfg


HEAD = ScriptDirectory.from_config(_alembic('')).get_current_head()


@pytest.fixture
def scratch():
    """Empty databases for restores."""
    made = []

    def new():
        name, url = _database()
        made.append(name)
        return url
    yield new
    for name in made:
        _drop(name)


def put_dump(b, key, body, revision=HEAD, snapshot_at=None, sign_as=None, metadata=None):
    """An object under ctl/dumps/: signed for `sign_as` (default: this key) by b's key, or with
    `metadata` as given (e.g. copied from another dump)."""
    sha = hashlib.sha256(body).hexdigest()
    if metadata is None:
        snapshot_at = (snapshot_at or datetime.now(UTC)).isoformat()
        claim = cpbackup._dump_claim(sign_as or key, sha, snapshot_at, revision)
        metadata = {'schema-revision': revision, 'snapshot-at': snapshot_at, 'signature': sign(claim, b.signing)}
    b.s3.put_object(Bucket=b.bucket, Key=key, Body=body, ObjectLockMode='COMPLIANCE', Metadata=metadata,
                    ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode(),
                    ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=1))


class B:
    def __init__(self, dsn, at=datetime(2026, 11, 1, 3, 31, tzinfo=UTC), bucket=None):
        self.clock = Clock(at)
        self.w = World(dsn, clock=self.clock)
        self.recovery = pyrage.x25519.Identity.generate()
        self.s3 = boto3.client('s3', endpoint_url=S3, region_name='us-east-1', aws_access_key_id='test',
                               aws_secret_access_key='test')
        self.bucket = bucket or 'ctl-c-' + uuid.uuid4().hex[:12]
        if bucket is None:
            self.s3.create_bucket(Bucket=self.bucket, ObjectLockEnabledForBucket=True)
        self.signing = SigningKey.generate()
        self.cp = ControlPlaneBackup(self.w.store, owner_dsn=dsn, bucket=self.bucket, signing_key=self.signing,
                                     trusted_keys=[self.signing.verify_key],
                                     s3_key={'key_id': 'test', 'secret': 'test'},
                                     recovery_recipient=str(self.recovery.to_public()), s3_endpoint=S3,
                                     s3_region='us-east-1', pg_dump=PG16 + ['pg_dump'],
                                     pg_restore=PG16 + ['pg_restore'])

    def event(self, action='tenant.test'):
        with self.w.store.connect() as c:
            audit.append(c, datetime.fromtimestamp(self.clock(), UTC), action)

    def incidents(self):
        return self.w.sql("SELECT * FROM incident WHERE runbook_ref = 'RB-09' ORDER BY opened_at")

    def anchors_in_bucket(self):
        return [o['Key'] for o in self.s3.list_objects_v2(Bucket=self.bucket, Prefix=ANCHORS).get('Contents', [])]

    def tamper(self, seq, rechain=False):
        """Rewrite an audit row as the owner could (triggers off); with `rechain`, recompute every later hash
        so the chain verifies again."""
        with psycopg.connect(self.w.dsn, row_factory=psycopg.rows.dict_row) as c:
            c.execute('ALTER TABLE audit_event DISABLE TRIGGER audit_event_ao')
            c.execute("UPDATE audit_event SET action = 'tampered' WHERE seq = %s", (seq,))
            if rechain:
                prev = audit.GENESIS
                for r in c.execute('SELECT * FROM audit_event ORDER BY seq').fetchall():
                    row = audit._row(r['at'], r['actor_kind'], r['actor_id'], r['action'], r['tenant_id'],
                                     r['resource_type'], r['resource_id'], r['before'], r['after'],
                                     r['correlation_id'])
                    h = hashlib.sha256(prev + canonical(row)).digest()
                    c.execute('UPDATE audit_event SET prev_hash = %s, hash = %s WHERE seq = %s', (prev, h, r['seq']))
                    prev = h
            c.execute('ALTER TABLE audit_event ENABLE TRIGGER audit_event_ao')


# -- dump -------------------------------------------------------------------------------

def test_dump_is_locked_read_back_and_restores_with_either_key(dsn, scratch):
    b = B(dsn)
    b.event()
    rec = b.cp.dump()
    assert rec['tier'] == 'monthly' and rec['reason'] == 'scheduled' and rec['schema_revision'] == HEAD
    h = b.s3.head_object(Bucket=b.bucket, Key=rec['object_key'], VersionId=rec['object_version_id'])
    assert h['ObjectLockMode'] == 'COMPLIANCE'
    assert h['ObjectLockRetainUntilDate'] >= datetime(2026, 11, 1, 3, 31, tzinfo=UTC) + timedelta(days=366, seconds=-60)
    row = b.w.sql('SELECT * FROM ctl_dump')[0]
    assert (row['sha256'], row['tier']) == (rec['sha256'], 'monthly')
    assert b.w.sql("SELECT 1 FROM audit_event WHERE action = 'ctl.dumped'")
    # The recovery key alone (ctl-1 and its keys lost), and a region's operational key (the drill).
    for identity in (b.recovery, b.w.region_backup):
        out = b.cp.verify(scratch(), [identity])
        assert out['ok'] and out['schema_revision'] == HEAD and out['first_bad_seq'] is None, out
        assert out['last_seq'] >= 1
    assert b.cp.verify(scratch(), [pyrage.x25519.Identity.generate()])['reason'] == 'cannot_decrypt'


def test_tiers(dsn):
    b = B(dsn)
    assert b.cp.dump('pre_migration')['tier'] == 'daily'
    assert b.cp.dump()['tier'] == 'monthly'
    b.clock.at += timedelta(days=1)
    second = b.cp.dump()
    assert second['tier'] == 'daily'
    h = b.s3.head_object(Bucket=b.bucket, Key=second['object_key'], VersionId=second['object_version_id'])
    assert h['ObjectLockRetainUntilDate'] < b.clock.at + timedelta(days=32)
    b.clock.at = datetime(2026, 12, 1, 3, 31, tzinfo=UTC)
    assert b.cp.dump()['tier'] == 'monthly'


def test_a_dump_needs_an_operational_and_a_recovery_recipient(dsn):
    b = B(dsn)
    b.w.sql("UPDATE region SET status = 'retired'")
    with pytest.raises(RuntimeError):
        b.cp.dump()
    with pytest.raises(Exception):
        ControlPlaneBackup(b.w.store, owner_dsn=dsn, bucket=b.bucket, s3_key={}, recovery_recipient='')


@pytest.mark.parametrize('seen', [{'ObjectLockRetainUntilDate': datetime.now(UTC)},
                                  {'ChecksumSHA256': base64.b64encode(b'x' * 32).decode()}])
def test_a_read_back_mismatch_raises_and_opens_a_sev1(dsn, monkeypatch, seen):
    b = B(dsn)
    real = b.cp._s3

    def other():
        s3 = real()
        head = s3.head_object
        s3.head_object = lambda **k: {**head(**k), **seen}
        return s3
    monkeypatch.setattr(b.cp, '_s3', other)
    with pytest.raises(ReadBackMismatch):
        b.cp.dump()
    assert not b.w.sql('SELECT 1 FROM ctl_dump')
    assert [i['severity'] for i in b.incidents()] == ['sev1']


def test_dump_before_migration(dsn, scratch):
    name, url = _database()
    try:
        command.upgrade(_alembic(url), '0011')
        b = B(url)
        b.event()
        bad = ControlPlaneBackup(b.w.store, owner_dsn=url, bucket='no-such-bucket-' + uuid.uuid4().hex[:8],
                                 signing_key=b.signing,
                                 s3_key={'key_id': 'test', 'secret': 'test'},
                                 recovery_recipient=str(b.recovery.to_public()), s3_endpoint=S3,
                                 s3_region='us-east-1', pg_dump=PG16 + ['pg_dump'])
        with pytest.raises(Exception):
            bad.migrate(_alembic(url))
        assert b.w.sql('SELECT version_num FROM alembic_version')[0]['version_num'] == '0011'
        rec = b.cp.migrate(_alembic(url))
        assert rec['reason'] == 'pre_migration' and rec['schema_revision'] == '0011'
        assert b.w.sql('SELECT version_num FROM alembic_version')[0]['version_num'] == HEAD
        assert b.cp.migrate(_alembic(url)) is None
        out = b.cp.verify(scratch(), [b.recovery], key=rec['object_key'])
        assert out['ok'] and out['schema_revision'] == '0011', out
    finally:
        _drop(name)


# -- anchor -----------------------------------------------------------------------------

def test_anchor_writes_the_last_hash_locked(dsn):
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    b.event()
    last = b.w.sql('SELECT seq, hash FROM audit_event ORDER BY seq DESC LIMIT 1')[0]
    out = b.cp.anchor()
    assert out['state'] == 'anchored' and out['seq'] == last['seq']
    obj = b.s3.get_object(Bucket=b.bucket, Key=out['object_key'])
    assert obj['ObjectLockMode'] == 'COMPLIANCE'
    assert obj['ObjectLockRetainUntilDate'] >= b.clock.at + timedelta(days=366, seconds=-60)
    body = json.loads(obj['Body'].read())
    assert (body['seq'], body['hash']) == (last['seq'], bytes(last['hash']).hex())
    assert b.w.sql('SELECT seq FROM audit_anchor')[0]['seq'] == last['seq']
    assert b.w.sql("SELECT 1 FROM audit_event WHERE action = 'audit.anchored'")
    b.event()
    assert b.cp.anchor()['matched'] == 1


@pytest.mark.parametrize('rechain', [False, True])
def test_a_rewritten_row_stops_anchoring_and_opens_one_sev1(dsn, rechain):
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    for _ in range(3):
        b.event()
    assert b.cp.anchor()['state'] == 'anchored'
    b.tamper(2, rechain=rechain)
    assert (audit.verify_chain(psycopg.connect(dsn, row_factory=psycopg.rows.dict_row)) is None) is rechain
    for _ in range(2):
        out = b.cp.anchor()
        assert out['state'] == 'chain_broken'
        assert (out['first_bad_seq'] is None) is rechain and bool(out['mismatched']) is rechain
    assert len(b.anchors_in_bucket()) == 1
    assert [i['severity'] for i in b.incidents()] == ['sev1']


def test_a_rolled_back_database_is_caught(dsn):
    """Anchors past the last row: the database lost anchored events."""
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    b.event()
    assert b.cp.anchor()['state'] == 'anchored'
    b.w.sql('ALTER TABLE audit_event DISABLE TRIGGER audit_event_ao')
    b.w.sql('DELETE FROM audit_event WHERE seq > 1')
    b.w.sql('ALTER TABLE audit_event ENABLE TRIGGER audit_event_ao')
    out = b.cp.anchor()
    assert out['state'] == 'chain_broken' and out['beyond'] == 1 and out['first_bad_seq'] is None


def test_a_newer_version_of_an_anchor_doesnt_hide_the_locked_one(dsn):
    """ctl-1's write key can't delete a locked version, but can put a newer one: here one that matches the
    database after it was rewritten and rechained."""
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    key = b.cp.anchor()['object_key']
    anchored = json.loads(b.s3.get_object(Bucket=b.bucket, Key=key)['Body'].read())
    b.tamper(1, rechain=True)
    forged = {**anchored, 'hash': bytes(b.w.sql('SELECT hash FROM audit_event WHERE seq = %s',
                                                (anchored['seq'],))[0]['hash']).hex()}
    b.s3.put_object(Bucket=b.bucket, Key=key, Body=json.dumps(forged).encode(), ObjectLockMode='COMPLIANCE',
                    ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=1))
    out = b.cp.anchor()
    assert out['state'] == 'chain_broken' and out['first_bad_seq'] is None and out['mismatched'] == [key], out


def test_a_delete_marker_on_an_anchor_is_a_mismatch(dsn):
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    key = b.cp.anchor()['object_key']
    b.s3.delete_object(Bucket=b.bucket, Key=key)          # no version: a marker, which the lock allows
    out = b.cp.anchor()
    assert out['state'] == 'chain_broken' and out['mismatched'] == [key], out


# -- verify (the control-plane drill, RB-09 step 4) --------------------------------------

def test_verify_against_anchors(dsn, scratch):
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    older = b.cp.dump()['object_key']
    b.event()
    b.cp.anchor()
    b.event()
    b.clock.at += timedelta(seconds=1)
    newer = b.cp.dump()['object_key']
    out = b.cp.verify(scratch(), [b.recovery], key=older)
    # Its own pre-dump anchor matches; the explicit one is later (the newer dump wrote none: within the hour).
    assert out['ok'] and (out['matched'], out['beyond'], out['stale']) == (1, 1, []), out
    out = b.cp.verify(scratch(), [b.recovery])                                # the newest
    assert out['object_key'] == newer and out['ok'] and out['matched'] == 2, out
    # A dump of a database rewritten consistently (chain recomputed) verifies only until the anchors are checked.
    b.tamper(1, rechain=True)
    b.clock.at += timedelta(seconds=1)
    rewritten = b.cp.dump()['object_key']
    out = b.cp.verify(scratch(), [b.recovery], key=rewritten)
    assert out['first_bad_seq'] is None and out['mismatched'] and not out['ok'], out


def test_an_anchored_row_missing_below_the_last_is_a_mismatch(dsn, scratch):
    """Rows deleted and the chain recomputed: the anchored seq is gone, later rows remain."""
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    for _ in range(3):
        b.event()
    anchored = b.cp.anchor()['seq']                    # 3; then audit.anchored is 4
    b.event()                                          # 5
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as c:
        c.execute('ALTER TABLE audit_event DISABLE TRIGGER audit_event_ao')
        c.execute('DELETE FROM audit_event WHERE seq = %s', (anchored,))
        prev = audit.GENESIS
        for r in c.execute('SELECT * FROM audit_event ORDER BY seq').fetchall():
            h = hashlib.sha256(prev + canonical(audit._row(
                r['at'], r['actor_kind'], r['actor_id'], r['action'], r['tenant_id'], r['resource_type'],
                r['resource_id'], r['before'], r['after'], r['correlation_id']))).digest()
            c.execute('UPDATE audit_event SET prev_hash = %s, hash = %s WHERE seq = %s', (prev, h, r['seq']))
            prev = h
        c.execute('ALTER TABLE audit_event ENABLE TRIGGER audit_event_ao')
        assert audit.verify_chain(c) is None                            # the chain alone can't tell
    b.clock.at += timedelta(seconds=1)
    out = b.cp.verify(scratch(), [b.recovery], key=b.cp.dump()['object_key'])
    assert out['mismatched'] and out['beyond'] == 0 and not out['ok'], out


def test_every_connection_parameter_reaches_pg_dump():
    from ctlplane.cpbackup import _libpq_env
    env = _libpq_env('postgresql://u:p%40ss@db.example:6543/ctl?sslmode=verify-full&sslrootcert=/etc/ca.pem'
                     '&sslcert=/etc/c.pem&sslkey=/etc/c.key&connect_timeout=5&application_name=drill')
    assert {k: env[k] for k in ('PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE', 'PGSSLMODE',
                                'PGSSLROOTCERT', 'PGSSLCERT', 'PGSSLKEY', 'PGCONNECT_TIMEOUT', 'PGAPPNAME')} == {
        'PGHOST': 'db.example', 'PGPORT': '6543', 'PGUSER': 'u', 'PGPASSWORD': 'p@ss', 'PGDATABASE': 'ctl',
        'PGSSLMODE': 'verify-full', 'PGSSLROOTCERT': '/etc/ca.pem', 'PGSSLCERT': '/etc/c.pem',
        'PGSSLKEY': '/etc/c.key', 'PGCONNECT_TIMEOUT': '5', 'PGAPPNAME': 'drill'}
    with pytest.raises(ValueError, match='keepalives, sslpassword'):
        _libpq_env('postgresql://u@h/ctl?keepalives=1&sslpassword=x')


def test_verify_doesnt_depend_on_the_session_time_zone(dsn, scratch):
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    b.cp.anchor()
    b.cp.dump()
    target = scratch()
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute("ALTER DATABASE %s SET timezone TO 'Africa/Cairo'" % target.rsplit('/', 1)[1])
    out = b.cp.verify(target, [b.recovery])
    assert out['ok'] and out['matched'] == 1, out          # the explicit one (the dump wrote none: within the hour)


def test_verify_refuses_a_corrupted_dump(dsn, scratch):
    b = B(dsn)
    rec = b.cp.dump()
    sealed = b.s3.get_object(Bucket=b.bucket, Key=rec['object_key'])['Body'].read()
    corrupted = sealed[:-1] + bytes([sealed[-1] ^ 1])
    name = lambda tag: rec['object_key'].replace('.dump.age', '-%s.dump.age' % tag)  # noqa: E731
    # Signed and checksummed, but the bytes are wrong: age's authentication refuses them.
    put_dump(b, name('x'), corrupted)
    assert b.cp.verify(scratch(), [b.recovery], key=name('x'))['reason'] == 'cannot_decrypt'
    # Not uploaded by a dump (no SHA-256 checksum): refused before anything else.
    b.s3.put_object(Bucket=b.bucket, Key=name('y'), Body=sealed, ObjectLockMode='COMPLIANCE',
                    ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=1))
    assert b.cp.verify(scratch(), [b.recovery], key=name('y'))['reason'] == 'sha256_mismatch'


@pytest.mark.parametrize('shadow', ['version', 'delete_marker', 'delete_marker_newest'])
def test_a_shadowed_dump_is_refused_not_read(dsn, scratch, shadow):
    """The write key can't remove a locked version but can put another over it, or a delete marker."""
    b = B(dsn)
    rec = b.cp.dump()
    if shadow == 'delete_marker_newest':
        pass
    elif shadow == 'version':
        older = b.cp.dump()                     # a valid ciphertext of the same database, put on rec's key
        body = b.s3.get_object(Bucket=b.bucket, Key=older['object_key'])['Body'].read()
        b.s3.put_object(Bucket=b.bucket, Key=rec['object_key'], Body=body, ObjectLockMode='COMPLIANCE',
                        ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode(),
                        ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(days=1))
    else:
        b.s3.delete_object(Bucket=b.bucket, Key=rec['object_key'])
    if shadow == 'delete_marker_newest':                # hidden from a plain listing: no silent fallback
        b.clock.at += timedelta(seconds=1)
        newest = b.cp.dump()
        b.s3.delete_object(Bucket=b.bucket, Key=newest['object_key'])
        out = b.cp.verify(scratch(), [b.recovery])
        assert out['object_key'] == newest['object_key'], out
    else:
        out = b.cp.verify(scratch(), [b.recovery], key=rec['object_key'])
    assert out['reason'] == 'not_one_version' and not out['ok'], out


# -- schedule and metrics ---------------------------------------------------------------

def test_schedule(dsn):
    b = B(dsn, at=datetime(2026, 11, 2, 3, 0, tzinfo=UTC))
    b.event()                                          # something to anchor
    assert b.cp.run_once() == {}
    b.clock.at = datetime(2026, 11, 2, 3, 30, tzinfo=UTC)
    assert set(b.cp.run_once()) == {'dump'}
    b.clock.at = datetime(2026, 11, 2, 4, 0, tzinfo=UTC)
    assert b.cp.run_once() == {}                       # the dump anchored first: the day has its anchor
    # ctl-1 was down at 03:30: the dump catches up later in the day; a pre-migration one doesn't count
    # for the dump (it does for the anchor, written before it).
    b.clock.at = datetime(2026, 11, 3, 1, 0, tzinfo=UTC)
    b.cp.dump('pre_migration')
    b.clock.at = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)
    assert set(b.cp.run_once()) == {'dump'}
    # A day whose dump is done but whose anchor isn't (it failed before the dump): the 04:00 job anchors.
    b.clock.at = datetime(2026, 11, 4, 3, 31, tzinfo=UTC)
    b.w.sql("INSERT INTO ctl_dump (id, reason, tier, schema_revision, bucket, object_key, object_version_id, "
            "sha256, size_bytes, lock_until, created_at) VALUES (gen_random_uuid(), 'scheduled', 'daily', 'x', "
            "'b', 'k', 'v', 's', 1, now(), %s)", (b.clock.at,))
    assert b.cp.run_once() == {}
    b.clock.at = datetime(2026, 11, 4, 4, 0, tzinfo=UTC)
    assert b.cp.run_once()['anchor']['state'] == 'anchored'


def test_a_failure_is_retried_next_round(dsn):
    b = B(dsn, at=datetime(2026, 11, 2, 4, 0, tzinfo=UTC))
    b.event()
    good = b.cp.bucket
    b.cp.bucket = 'no-such-bucket-' + uuid.uuid4().hex[:8]
    with pytest.raises(JobFailed) as failed:
        b.cp.run_once()
    out = failed.value.result                                         # both were tried
    assert out['dump']['state'] == 'error' and out['anchor']['state'] == 'error'
    assert str(failed.value) == 'dump: NoSuchBucket, anchor: NoSuchBucket'
    b.cp.bucket = good
    out = b.cp.run_once()
    assert out['dump']['reason'] == 'scheduled' and out['anchor']['state'] == 'anchored'


def test_metrics(dsn):
    b = B(dsn, at=datetime(2026, 11, 2, 4, 0, tzinfo=UTC))
    with b.w.store.connect() as c:
        text = monitoring.metrics(c, b.clock())
    assert 'ctl_controlplane_dump_last_timestamp_seconds 0\n' in text
    assert 'ctl_audit_anchor_last_timestamp_seconds 0\n' in text
    b.event()
    b.cp.run_once()
    with b.w.store.connect() as c:
        text = monitoring.metrics(c, b.clock())
    ts = int(b.clock())
    assert 'ctl_controlplane_dump_last_timestamp_seconds %d\n' % ts in text
    assert 'ctl_audit_anchor_last_timestamp_seconds %d\n' % ts in text


def test_verify_compares_the_schema_revision(dsn, scratch):
    b = B(dsn)
    rec = b.cp.dump()
    other = rec['object_key'].replace('.dump.age', '-relabelled.dump.age')
    body = b.s3.get_object(Bucket=b.bucket, Key=rec['object_key'])['Body'].read()
    put_dump(b, other, body, revision='0011')          # signed, but claiming another schema than it holds
    out = b.cp.verify(scratch(), [b.recovery], key=other)
    assert out['schema_revision'] == HEAD and out['expected_revision'] == '0011' and not out['ok'], out


# -- the quarterly control-plane drill ------------------------------------------------------

def _agent_pg():
    """agent-pg (the agent's dev/up.sh) plays the temporary server: another cluster."""
    env = ROOT.parent / 'agent' / 'dev' / '.env'
    if not env.exists():
        return None
    pw = dict(line.split('=', 1) for line in env.read_text().split()).get('PG_SUPER_PASSWORD')
    url = 'postgresql://postgres:%s@127.0.0.1:55432/postgres' % pw
    try:
        psycopg.connect(url, connect_timeout=2).close()
        return url
    except psycopg.OperationalError:
        return None


TEMP_ADMIN = _agent_pg()


@pytest.fixture
def temp_server():
    if TEMP_ADMIN is None:
        pytest.skip('needs agent-pg (agent dev/up.sh) as the temporary server')
    made = []

    def new():
        name = 'ctl_drill_' + secrets.token_hex(4)
        with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
            c.execute('CREATE DATABASE ' + name)
        made.append(name)
        return TEMP_ADMIN.rsplit('/', 1)[0] + '/' + name
    yield new
    with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
        for name in made:
            c.execute('DROP DATABASE %s WITH (FORCE)' % name)


def _operator(w):
    op = uuid.uuid4()
    w.sql("INSERT INTO operator (id, oidc_subject, status) VALUES (%s, %s, 'active')", (op, 'op-' + op.hex[:8]))
    return op


def _drill_metric(b):
    with b.w.store.connect() as c:
        line = [x for x in monitoring.metrics(c, b.clock()).splitlines()
                if x.startswith('ctl_controlplane_drill_last_pass_timestamp_seconds ')]
    return int(line[0].split()[1])


def test_drill_with_the_operational_key_on_a_temporary_server(dsn, temp_server):
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    who = _operator(b.w)
    assert _drill_metric(b) == 0                                       # nothing to drill yet
    b.event()
    b.cp.anchor()
    b.cp.dump()
    first = int(b.clock())
    b.clock.at += timedelta(hours=1)
    rec = b.cp.dump()                                                  # the newest is drilled
    assert _drill_metric(b) == first                                   # the clock starts at the first dump
    b.clock.at += timedelta(days=1)
    out = b.cp.drill(who, temp_server())
    assert out['ok'] and out['key_kind'] == 'operational' and out['object_key'] == rec['object_key'], out
    row = b.w.sql('SELECT * FROM ctl_drill')[0]
    assert (row['result'], row['schema_revision'], row['anchors_matched'], row['run_by']) == ('pass', HEAD, 1, who)
    assert row['target'].startswith('127.0.0.1:55432/ctl_drill_') and 'postgres:' not in row['target']
    ev = b.w.sql('SELECT * FROM evidence_artifact WHERE id = %s', (row['evidence_id'],))[0]
    assert ev['kind'] == 'restore_drill' and ev['produced_by'] == who
    key, version = ev['uri'].split('/', 3)[3].split('?versionId=')
    obj = b.s3.get_object(Bucket=b.bucket, Key=key, VersionId=version)
    assert obj['ObjectLockMode'] == 'COMPLIANCE' and hashlib.sha256(obj['Body'].read()).hexdigest() == ev['sha256']
    assert obj['ObjectLockRetainUntilDate'] >= b.clock.at + timedelta(days=366, seconds=-60)
    assert b.w.sql("SELECT 1 FROM audit_event WHERE action = 'ctl.drill_passed'")
    assert not b.w.sql('SELECT 1 FROM incident')
    passed = int(b.clock())
    assert _drill_metric(b) == passed
    b.clock.at += timedelta(days=1)
    assert not b.cp.drill(who, temp_server(), recovery_identity=pyrage.x25519.Identity.generate())['ok']
    assert _drill_metric(b) == passed                                  # a fail doesn't reset the clock


def test_drill_with_the_recovery_key(dsn, temp_server):
    b = B(dsn)
    b.cp.dump()
    out = b.cp.drill(_operator(b.w), temp_server(), recovery_identity=b.recovery)
    assert out['ok'] and b.w.sql('SELECT key_kind FROM ctl_drill')[0]['key_kind'] == 'recovery'


def test_the_drill_refuses_ctl_1s_own_cluster(dsn, scratch):
    b = B(dsn)
    b.cp.dump()
    with pytest.raises(ValueError):
        b.cp.drill(_operator(b.w), scratch())
    assert not b.w.sql('SELECT 1 FROM ctl_drill')


@pytest.mark.parametrize('case', ['wrong_key', 'no_dump', 'no_evidence', 'evidence_rejected'])
def test_a_failed_drill_is_recorded_with_a_sev2(dsn, temp_server, monkeypatch, case):
    b = B(dsn)
    if case != 'no_dump':
        b.cp.dump()
    kw = {'recovery_identity': pyrage.x25519.Identity.generate()} if case == 'wrong_key' else {}
    if case == 'no_evidence':
        real = b.cp._put_locked
        monkeypatch.setattr(b.cp, '_put_locked', lambda s3, key, *a, **k:
                            (_ for _ in ()).throw(ReadBackMismatch(key)) if key.startswith('ctl/drills/')
                            else real(s3, key, *a, **k))
    if case == 'evidence_rejected':     # stored, but the database refuses the row (its sha256 CHECK)
        real = b.cp._put_locked
        monkeypatch.setattr(b.cp, '_put_locked', lambda s3, key, *a, **k:
                            {**real(s3, key, *a, **k), 'sha256': 'not-hex'} if key.startswith('ctl/drills/')
                            else real(s3, key, *a, **k))
    out = b.cp.drill(_operator(b.w), temp_server(), **kw)
    reason = {'wrong_key': 'cannot_decrypt', 'no_dump': 'no_dump', 'no_evidence': 'evidence_not_stored',
              'evidence_rejected': 'evidence_not_stored'}[case]
    assert not out['ok'] and out['reason'] == reason, out
    row = b.w.sql('SELECT * FROM ctl_drill')[0]
    assert row['result'] == 'fail' and row['reason'] == reason
    assert (row['evidence_id'] is None) is (case in ('no_evidence', 'evidence_rejected'))
    assert [(i['severity'], i['runbook_ref']) for i in b.w.sql('SELECT * FROM incident')] == [('sev2', 'RB-10')]
    assert b.w.sql("SELECT 1 FROM audit_event WHERE action = 'ctl.drill_failed'")
    assert _drill_metric(b) in (0, int(b.clock()))                     # a fail doesn't reset the clock


# -- rebuilding ctl-1 (RB-09 step 4, RB-10): roles, owners, grants -------------------------

@pytest.fixture
def new_cluster(dsn):
    """agent-pg as the rebuilt ctl-1's cluster; the database and roles a rebuild creates are removed after."""
    if TEMP_ADMIN is None:
        pytest.skip('needs agent-pg (agent dev/up.sh) as the new cluster')
    login = 'ctl_api_' + secrets.token_hex(3)
    with psycopg.connect(ADMIN, autocommit=True) as c:          # a login role that becomes ctl_app, as ctl-1's would
        c.execute('CREATE ROLE %s LOGIN NOINHERIT CREATEDB IN ROLE ctl_app' % login)
    yield TEMP_ADMIN, login
    name = dsn.rsplit('/', 1)[1]
    with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
        c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % name)
        for role in (login, 'ctl_dispatcher', 'ctl_app'):
            c.execute('DROP ROLE IF EXISTS %s' % role)
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute('DROP ROLE %s' % login)


def _on(admin, dbname, query, args=()):
    with psycopg.connect(make_conninfo(admin, dbname=dbname)) as c:
        return c.execute(query, args).fetchone()[0]


def test_the_manifest_has_the_roles_and_no_passwords(dsn, new_cluster):
    _, login = new_cluster
    b = B(dsn)
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as c:
        m = roles_manifest(c)
    roles = {r['name']: r for r in m['roles']}
    assert {'postgres', 'ctl_app', 'ctl_dispatcher', login} <= set(roles)
    assert roles[login]['login'] and not roles['ctl_app']['login'] and 'rolsuper' in roles['postgres']['privileged']
    # [role, member, admin, inherit, set]: the login role is NOINHERIT, so its grant doesn't inherit (PG 16).
    assert ['ctl_app', 'ctl_dispatcher', False, True, True] in m['memberships']
    assert ['ctl_app', login, False, False, True] in m['memberships']
    assert m['database'] == dsn.rsplit('/', 1)[1] and 'password' not in json.dumps(m).lower()
    assert b


def test_rebuild_restores_roles_owners_and_grants(dsn, new_cluster):
    admin, login = new_cluster
    b = B(dsn, at=datetime(2026, 11, 1, 4, 1, tzinfo=UTC))
    b.event()
    b.cp.anchor()
    b.clock.at += timedelta(seconds=1)
    b.cp.dump()
    out = b.cp.rebuild(admin, [b.recovery])
    assert out['ok'] and out['privileges_match'] and out['matched'] == 1, out
    assert set(out['roles_created']) == {'ctl_app', 'ctl_dispatcher', login} and 'postgres' in out['roles_existing']
    assert out['login_roles'] == [login]
    assert out['privileged_not_restored'] == [{'role': login, 'attributes': ['rolcreatedb']}]
    for role in out['roles_created']:
        expected = _on(ADMIN, 'postgres', 'SELECT row(rolcanlogin, rolinherit) FROM pg_roles WHERE rolname = %s',
                       (role,))
        assert _on(admin, 'postgres', 'SELECT row(rolcanlogin, rolinherit) FROM pg_roles WHERE rolname = %s',
                   (role,)) == expected
    assert _on(admin, 'postgres', 'SELECT rolcreatedb FROM pg_roles WHERE rolname = %s', (login,)) is False
    name = out['database']
    has = lambda role, obj, priv: _on(admin, name, 'SELECT has_table_privilege(%s, %s, %s)',  # noqa: E731
                                      (role, obj, priv))
    assert has('ctl_app', 'audit_event', 'INSERT') and not has('ctl_app', 'audit_event', 'UPDATE')
    assert has('ctl_dispatcher', 'secret_ref', 'SELECT') and not has('ctl_app', 'secret_ref', 'SELECT')
    assert _on(admin, name, "SELECT has_column_privilege('ctl_app', 'region', 'retention_key_ref', 'UPDATE')")
    assert _on(admin, name, "SELECT pg_has_role(%s, 'ctl_app', 'MEMBER')", (login,))      # SET ROLE ctl_app
    assert not _on(admin, name, "SELECT pg_has_role(%s, 'ctl_app', 'USAGE')", (login,))   # NOINHERIT, as on ctl-1
    assert _on(admin, name, "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = %s", (login,))
    assert _on(admin, name, "SELECT tableowner FROM pg_tables WHERE tablename = 'audit_event'") == 'postgres'
    # Rebuilding again onto the same cluster: the database is there.
    assert b.cp.rebuild(admin, [b.recovery])['reason'] == 'database_exists'


def test_rebuild_keeps_per_membership_options_and_checks_existing_roles(dsn, new_cluster):
    admin, login = new_cluster
    narrow = 'ctl_ro_' + secrets.token_hex(3)          # may neither inherit ctl_app's rights nor SET ROLE to it
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute('CREATE ROLE %s LOGIN INHERIT' % narrow)
        c.execute('GRANT ctl_app TO %s WITH INHERIT FALSE, SET FALSE' % narrow)
    try:
        b = B(dsn)
        b.cp.dump()
        out = b.cp.rebuild(admin, [b.recovery])
        assert out['ok'] and out['memberships_match'] and out['roles_differing'] == [], out
        q = "SELECT pg_has_role(%s, 'ctl_app', 'USAGE'), pg_has_role(%s, 'ctl_app', 'SET')"
        with psycopg.connect(admin) as c:
            assert c.execute(q, (narrow, narrow)).fetchone() == (False, False)
        # Again, onto a cluster where the login role already exists with other attributes.
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % out['database'])
            c.execute('DROP ROLE %s' % login)
            c.execute('CREATE ROLE %s LOGIN INHERIT' % login)      # NOINHERIT on ctl-1
        out = b.cp.rebuild(admin, [b.recovery])
        assert out['roles_differing'] == [login] and not out['ok'], out
        # And where the roles are right but a membership was granted with more than ctl-1 gave it.
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % out['database'])
            c.execute('DROP ROLE %s' % login)
            c.execute('CREATE ROLE %s LOGIN NOINHERIT' % login)
            c.execute('DROP ROLE IF EXISTS %s' % narrow)
            c.execute('CREATE ROLE %s LOGIN INHERIT' % narrow)
            c.execute('GRANT ctl_app TO %s' % narrow)                   # INHERIT TRUE, SET TRUE
        out = b.cp.rebuild(admin, [b.recovery])
        assert out['roles_differing'] == [] and out['privileges_match'], out
        assert out['memberships_match'] is False and not out['ok'], out
    finally:
        with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
            c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % dsn.rsplit('/', 1)[1])
            c.execute('DROP ROLE IF EXISTS %s' % narrow)
        with psycopg.connect(ADMIN, autocommit=True) as c:
            c.execute('DROP ROLE %s' % narrow)


def test_rebuild_checks_the_grants_it_restored(dsn, new_cluster):
    admin, _ = new_cluster
    b = B(dsn)
    b.cp.dump()
    b.cp.pg_restore = PG16 + ['pg_restore', '--no-privileges']        # a restore that drops the grants
    out = b.cp.rebuild(admin, [b.recovery])
    assert out['schema_revision'] == HEAD and out['privileges_match'] is False and not out['ok'], out


def test_rebuild_refuses_ctl_1s_own_cluster_and_a_wrong_key(dsn, new_cluster):
    admin, _ = new_cluster
    b = B(dsn)
    b.cp.dump()
    with pytest.raises(ValueError):
        b.cp.rebuild(ADMIN, [b.recovery])
    out = b.cp.rebuild(admin, [pyrage.x25519.Identity.generate()])
    assert out['reason'] == 'cannot_decrypt'
    assert not _on(admin, 'postgres', "SELECT count(*) FROM pg_roles WHERE rolname = 'ctl_app'")   # nothing made


@pytest.mark.parametrize('change', [
    'GRANT SELECT (retention_key_ref) ON region TO ctl_dispatcher',             # a column grant
    'REVOKE INSERT ON audit_event FROM ctl_app',                                # a table grant
    'ALTER TABLE ctl_drill OWNER TO ctl_app',                                   # an owner
    'REVOKE EXECUTE ON FUNCTION reject_change() FROM PUBLIC',                   # a function ACL
    'ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO ctl_app',               # default privileges
    'GRANT CONNECT ON DATABASE {db} TO ctl_app',                                # the database ACL
])
def test_the_acl_fingerprint_sees_every_kind_of_grant(dsn, change):
    with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as c:
        before = privileges_sha256(c)
        c.execute(change.format(db=dsn.rsplit('/', 1)[1]))
        assert privileges_sha256(c) != before


# -- second Codex review --------------------------------------------------------------------

@pytest.mark.parametrize('pick', ['by_key', 'newest'])
def test_an_older_dump_copied_under_a_newer_name_is_refused(dsn, scratch, pick):
    """Its signature, copied along, names the original key."""
    b = B(dsn)
    first = b.cp.dump()
    obj = b.s3.get_object(Bucket=b.bucket, Key=first['object_key'])
    copy = 'ctl/dumps/2099-01-01/20990101T000000Z-%s.dump.age' % uuid.uuid4()     # sorts last
    put_dump(b, copy, obj['Body'].read(), metadata=obj['Metadata'])
    out = b.cp.verify(scratch(), [b.recovery], key=copy if pick == 'by_key' else None)
    if pick == 'by_key':
        assert out['object_key'] == copy and out['reason'] == 'signature_invalid' and not out['ok'], out
    else:                                               # skipped and reported: it can't block the default
        assert out['object_key'] == first['object_key'] and out['ok'] and out['skipped_unsigned'] == [copy], out


@pytest.mark.parametrize('case', ['unsigned', 'other_key', 'no_trusted_key'])
def test_an_unauthenticated_archive_never_reaches_pg_restore(dsn, new_cluster, monkeypatch, case):
    """Bucket C's write key can put an archive encrypted to the (public) recovery recipient; its SQL would
    run as the new cluster's superuser. The signature is checked before decrypting, let alone restoring."""
    admin, _ = new_cluster
    b = B(dsn)
    rec = b.cp.dump()
    body = b.s3.get_object(Bucket=b.bucket, Key=rec['object_key'])['Body'].read()
    forged = 'ctl/dumps/2099-01-01/20990101T000000Z-%s.dump.age' % uuid.uuid4()
    if case == 'unsigned':
        put_dump(b, forged, body, metadata={'schema-revision': HEAD})
    elif case == 'other_key':
        real, b.signing = b.signing, SigningKey.generate()                     # the attacker's own key
        put_dump(b, forged, body)
        b.signing = real
    else:
        b.cp.trusted_keys = []
    ran = []
    monkeypatch.setattr(cpbackup.subprocess, 'run', lambda *a, **k: ran.append(a) or (_ for _ in ()).throw(
        AssertionError('pg_restore must not run')))
    out = b.cp.rebuild(admin, [b.recovery], key=forged if case != 'no_trusted_key' else rec['object_key'])
    assert out['reason'] == ('no_trusted_key' if case == 'no_trusted_key' else 'signature_invalid'), out
    assert ran == [] and not _on(admin, 'postgres', "SELECT count(*) FROM pg_roles WHERE rolname = 'ctl_app'")


def test_a_dump_whose_content_is_older_than_its_signed_snapshot_is_stale(dsn, scratch):
    """Anchors written before the signed snapshot time must be in the dump."""
    b = B(dsn)
    b.event()
    rec = b.cp.dump()
    b.event()
    b.cp.anchor()                                      # after rec's snapshot: rec lacks it
    body = b.s3.get_object(Bucket=b.bucket, Key=rec['object_key'])['Body'].read()
    later = 'ctl/dumps/2099-01-01/20990101T000000Z-%s.dump.age' % uuid.uuid4()
    put_dump(b, later, body, snapshot_at=datetime.fromtimestamp(b.clock(), UTC) + timedelta(seconds=1))
    out = b.cp.verify(scratch(), [b.recovery], key=later)
    assert out['stale'] and not out['ok'], out
    assert b.cp.verify(scratch(), [b.recovery], key=rec['object_key'])['stale'] == []     # as signed: fine


def test_an_anchor_written_while_a_dump_is_made_is_not_expected_in_it(dsn, scratch, monkeypatch):
    """A slow dump: another anchor lands after its snapshot, before its upload."""
    b = B(dsn)
    b.event()
    real = b.cp._put_locked

    def slow(s3, key, *a, **k):
        if key.startswith('ctl/dumps/'):
            b.clock.at += timedelta(minutes=20)
            b.event()
            b.cp.anchor()
        return real(s3, key, *a, **k)
    monkeypatch.setattr(b.cp, '_put_locked', slow)
    rec = b.cp.dump()
    out = b.cp.verify(scratch(), [b.recovery], key=rec['object_key'])
    assert out['ok'] and out['stale'] == [] and out['beyond'] >= 1, out


def test_rebuild_refuses_an_unknown_manifest_version_before_touching_the_target(dsn, new_cluster, monkeypatch):
    admin, _ = new_cluster
    b = B(dsn)
    real = cpbackup.roles_manifest
    monkeypatch.setattr(cpbackup, 'roles_manifest', lambda c: {**real(c), 'v': 1})
    b.cp.dump()
    out = b.cp.rebuild(admin, [b.recovery])
    assert (out['reason'], out['manifest_version']) == ('manifest_version', 1) and not out['ok'], out
    assert not _on(admin, 'postgres', "SELECT count(*) FROM pg_roles WHERE rolname IN ('ctl_app', 'ctl_dispatcher')")


def test_memberships_across_the_manifest_boundary(dsn, new_cluster):
    """Captured: ctl_app's membership in a built-in role. Compared: an outside login given ctl_app."""
    admin, _ = new_cluster
    outsider = 'ctl_out_' + secrets.token_hex(3)
    with psycopg.connect(ADMIN, autocommit=True) as c:
        c.execute('GRANT pg_read_all_stats TO ctl_app')
    try:
        b = B(dsn)
        b.cp.dump()
        with psycopg.connect(dsn, row_factory=psycopg.rows.dict_row) as c:
            assert ['pg_read_all_stats', 'ctl_app', False, True, True] in roles_manifest(c)['memberships']
        out = b.cp.rebuild(admin, [b.recovery])
        assert out['ok'] and out['memberships_match'], out
        assert _on(admin, 'postgres', "SELECT pg_has_role('ctl_app', 'pg_read_all_stats', 'MEMBER')")
        with psycopg.connect(admin, autocommit=True) as c:
            c.execute('DROP DATABASE %s WITH (FORCE)' % out['database'])
            c.execute('CREATE ROLE %s LOGIN' % outsider)
            c.execute('GRANT ctl_app TO %s' % outsider)                  # not on ctl-1
        out = b.cp.rebuild(admin, [b.recovery])
        assert out['memberships_match'] is False and out['roles_differing'] == [] and not out['ok'], out
    finally:
        with psycopg.connect(ADMIN, autocommit=True) as c:
            c.execute('REVOKE pg_read_all_stats FROM ctl_app')
        with psycopg.connect(TEMP_ADMIN, autocommit=True) as c:
            c.execute('DROP DATABASE IF EXISTS %s WITH (FORCE)' % dsn.rsplit('/', 1)[1])
            c.execute('DROP ROLE IF EXISTS %s' % outsider)
            if c.execute("SELECT 1 FROM pg_roles WHERE rolname = 'ctl_app'").fetchone():
                c.execute('REVOKE pg_read_all_stats FROM ctl_app')


def test_an_anchor_started_before_a_dump_but_choosing_its_row_after_is_not_required(dsn, scratch, monkeypatch):
    """anchor() begins (lists and checks anchors), a dump snapshots meanwhile, a row is committed, then
    anchor() picks that row: the anchor's time is after the dump's snapshot, so the dump needn't have it."""
    b = B(dsn)
    b.event()
    real, made = cpbackup.bucket_anchors, {}

    def meanwhile(s3, bucket):
        out = real(s3, bucket)
        if not made:
            made['dump'] = True
            b.clock.at += timedelta(minutes=1)
            made['rec'] = b.cp.dump()                      # its own pre-dump anchor recurses here: guarded
            b.clock.at += timedelta(minutes=1)
            b.event()                                      # committed after the dump's snapshot
        return out
    monkeypatch.setattr(cpbackup, 'bucket_anchors', meanwhile)
    assert b.cp.anchor()['state'] == 'anchored'
    monkeypatch.setattr(cpbackup, 'bucket_anchors', real)
    out = b.cp.verify(scratch(), [b.recovery], key=made['rec']['object_key'])
    assert out['ok'] and out['stale'] == [], out


@pytest.mark.parametrize('extra', ['BYPASSRLS', 'CREATEROLE', 'SUPERUSER'])
def test_an_existing_role_with_more_privilege_fails_the_rebuild(dsn, new_cluster, extra):
    admin, _ = new_cluster
    b = B(dsn)
    b.cp.dump()
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute('CREATE ROLE ctl_app NOLOGIN INHERIT %s' % extra)   # as on ctl-1, plus one attribute
    out = b.cp.rebuild(admin, [b.recovery])
    assert 'ctl_app' in out['roles_differing'] and not out['ok'], out


def test_an_unreachable_drill_target_is_a_recorded_failed_drill(dsn):
    b = B(dsn)
    b.cp.dump()
    who = _operator(b.w)
    out = b.cp.drill(who, 'postgresql://nobody:x@127.0.0.1:1/none?connect_timeout=2')
    assert out['reason'] == 'target_unreachable' and not out['ok'], out
    assert b.w.sql('SELECT result, reason FROM ctl_drill')[0] == {'result': 'fail', 'reason': 'target_unreachable'}
    assert [i['severity'] for i in b.w.sql('SELECT severity FROM incident')] == ['sev2']


def test_a_failing_dump_writes_at_most_one_anchor_an_hour(dsn, monkeypatch):
    b = B(dsn)
    b.event()
    b.cp.pg_dump = ['false']                            # pg_dump fails every round
    for _ in range(4):
        with pytest.raises(subprocess.CalledProcessError):
            b.cp.dump()
        b.clock.at += timedelta(minutes=5)
    assert len(b.anchors_in_bucket()) == 1
    b.clock.at += timedelta(hours=1)
    with pytest.raises(subprocess.CalledProcessError):
        b.cp.dump()
    assert len(b.anchors_in_bucket()) == 2


def test_rows_dated_in_the_future_dont_count_as_done(dsn):
    """Whoever can insert one mustn't stop the schedule or quiet the alerts."""
    b = B(dsn, at=datetime(2026, 11, 2, 4, 0, tzinfo=UTC))
    b.event()
    future = datetime(2100, 1, 1, tzinfo=UTC)
    b.w.sql("INSERT INTO ctl_dump (id, reason, tier, schema_revision, bucket, object_key, object_version_id, sha256, "
            "size_bytes, lock_until, created_at) VALUES (gen_random_uuid(), 'scheduled', 'daily', 'x', 'b', 'k', "
            "'v', 's', 1, now(), %s)", (future,))
    b.w.sql("INSERT INTO audit_anchor (id, seq, hash, bucket, object_key, object_version_id, lock_until, anchored_at) "
            "VALUES (gen_random_uuid(), 1, '\\x00', 'b', 'k', 'v', now(), %s)", (future,))
    with b.w.store.connect() as c:
        text = monitoring.metrics(c, b.clock())
    assert 'ctl_controlplane_dump_last_timestamp_seconds 0\n' in text
    assert 'ctl_audit_anchor_last_timestamp_seconds 0\n' in text
    assert 'ctl_controlplane_drill_last_pass_timestamp_seconds 0\n' in text       # no real dump yet
    out = b.cp.run_once()
    assert out['dump']['reason'] == 'scheduled' and out['anchor']['state'] == 'anchored', out
    # The dump anchored first too (the future anchor row didn't count as recent).
    assert b.w.sql('SELECT count(*) AS n FROM audit_anchor WHERE anchored_at <= %s', (b.clock.at,))[0]['n'] == 2


def test_junk_put_twice_under_a_new_key_doesnt_block_the_default(dsn, scratch):
    b = B(dsn)
    rec = b.cp.dump()
    junk = 'ctl/dumps/2099-01-01/20990101T000000Z-%s.dump.age' % uuid.uuid4()
    for _ in range(2):
        put_dump(b, junk, b'junk', metadata={'schema-revision': HEAD})
    out = b.cp.verify(scratch(), [b.recovery])
    assert out['object_key'] == rec['object_key'] and out['ok'] and out['skipped_unsigned'] == [junk], out


def test_the_drill_doesnt_blame_the_target_when_ctl_1s_database_is_down(dsn):
    b = B(dsn)
    b.cp.dump()
    who = _operator(b.w)
    b.cp.owner_dsn = 'postgresql://nobody:x@127.0.0.1:1/none?connect_timeout=2'
    with pytest.raises(psycopg.OperationalError):
        b.cp.drill(who, 'postgresql://nobody:x@127.0.0.1:1/other?connect_timeout=2')
    assert not b.w.sql('SELECT 1 FROM ctl_drill')


def test_a_future_dated_monthly_row_doesnt_make_this_months_dump_daily(dsn):
    b = B(dsn)                                          # 2026-11-01: the first scheduled dump of the month
    b.w.sql("INSERT INTO ctl_dump (id, reason, tier, schema_revision, bucket, object_key, object_version_id, sha256, "
            "size_bytes, lock_until, created_at) VALUES (gen_random_uuid(), 'scheduled', 'monthly', 'x', 'b', 'k', "
            "'v', 's', 1, now(), '2026-11-20T00:00:00Z')")
    assert b.cp.dump()['tier'] == 'monthly'


@pytest.mark.parametrize('hidden', [False, True])
def test_an_unreadable_newest_dump_fails_the_pick_rather_than_falling_back(dsn, scratch, monkeypatch, hidden):
    from botocore.exceptions import ClientError
    b = B(dsn)
    b.cp.dump()
    b.clock.at += timedelta(seconds=1)
    newest = b.cp.dump()['object_key']
    if hidden:
        b.s3.delete_object(Bucket=b.bucket, Key=newest)
    real = b.cp._s3

    def flaky():
        s3 = real()
        head = s3.head_object

        def failing(**k):
            if k['Key'] == newest:
                raise ClientError({'Error': {'Code': '503', 'Message': 'Slow Down'}}, 'HeadObject')
            return head(**k)
        s3.head_object = failing
        return s3
    monkeypatch.setattr(b.cp, '_s3', flaky)
    out = b.cp.verify(scratch(), [b.recovery])
    assert (out['reason'], out['object_key']) == ('candidate_unreadable', newest) and not out['ok'], out
