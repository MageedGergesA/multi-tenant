"""Backup retention (DOC-05 §3): what may be deleted, custodian approval, and
deletion against LocalStack S3 with compliance-mode Object Lock."""
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from nacl.signing import SigningKey

from ctlplane import retention as ret
from ctlplane.canonical import b64_public, sign
from ctlplane.retention import Retention
from ctlplane.store import Store
from ctlplane.vault import encrypt

from .conftest import APP_HOST, ENV, TENANT
from .test_operator_api import Api

S3 = 'http://127.0.0.1:4566'
UTC = timezone.utc


def _s3_up():
    try:
        boto3.client('s3', endpoint_url=S3, region_name='us-east-1', aws_access_key_id='test',
                     aws_secret_access_key='test').list_buckets()
        return True
    except Exception:
        return False


class R:
    def __init__(self, w, breakglass=False):
        self.w = w
        w.sql('UPDATE environment SET app_host_id = %s', (APP_HOST,))
        self.bucket = 'retention-' + uuid.uuid4().hex[:12]
        w.sql('UPDATE region SET backup_bucket = %s', (self.bucket,))
        ref = uuid.uuid4()
        w.sql("INSERT INTO secret_ref (id, kind, ciphertext, created_at) VALUES (%s, 'b2_retention_key', %s, now())",
              (ref, encrypt(json.dumps({'key_id': 'test', 'secret': 'test'}), w.vault.recipient)))
        w.sql('UPDATE region SET retention_key_ref = %s', (ref,))
        self.api = Api(w, retention=Retention(Store(w.dsn, w.dispatch, role='ctl_app'), breakglass_enabled=breakglass))
        self.offset = 0.0
        w.store.clock = lambda: time.time() + self.offset          # after Api(), which resets it
        self.r = Retention(w.store, s3_endpoint=S3, s3_region='us-east-1', breakglass_enabled=breakglass)
        self.op = w.store.dispatch('Tenant.Stop', tenant_id=TENANT, environment_id=None, params={'reason': 'operator'},
                                   hosts={'app': APP_HOST}, idempotency_key='for-backup-points')
        w.sql("UPDATE operation SET state = 'COMPLETED' WHERE id = %s", (self.op,))
        self.s3 = None

    def point(self, age_days, tier='daily', state='recoverable', lock_passed=True, version='v', env=ENV):
        pid = str(uuid.uuid4())
        snap = datetime.now(UTC) - timedelta(days=age_days)
        lock = datetime.now(UTC) - timedelta(hours=2) if lock_passed else datetime.now(UTC) + timedelta(days=3)
        self.w.sql("INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, "
                   "gc_guard_held, missing_files, object_version_id, lock_until, state, created_at) "
                   "VALUES (%s, %s, %s, 'scheduled', %s, %s, true, 0, %s, %s, %s, now())",
                   (pid, env, self.op, tier, snap, version, lock, state))
        return pid

    def candidates(self):
        with self.w.store.connect() as c:
            return {i['backup_point_id'] for i in ret.candidates(c, time.time())}

    def bucket_up(self):
        self.s3 = boto3.client('s3', endpoint_url=S3, region_name='us-east-1', aws_access_key_id='test',
                               aws_secret_access_key='test')
        self.s3.create_bucket(Bucket=self.bucket, ObjectLockEnabledForBucket=True)

    def stored(self, lock_seconds, age_days=30, tier='daily'):
        """A real locked object and its backup point."""
        pid = str(uuid.uuid4())
        key = ret.object_key(TENANT, ENV, pid)
        until = datetime.now(UTC) + timedelta(seconds=lock_seconds)
        v = self.s3.put_object(Bucket=self.bucket, Key=key, Body=b'archive', ObjectLockMode='COMPLIANCE',
                               ObjectLockRetainUntilDate=until)['VersionId']
        self.w.sql("INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, "
                   "gc_guard_held, missing_files, object_version_id, lock_until, state, created_at) "
                   "VALUES (%s, %s, %s, 'scheduled', %s, %s, true, 0, %s, %s, 'recoverable', now())",
                   (pid, ENV, self.op, tier, datetime.now(UTC) - timedelta(days=age_days), v, until))
        return pid, key, v

    def approve(self, draft, key):
        a = dict(draft['body'])
        a['custodian_signature'] = sign(draft['body'], key)
        return a


@pytest.fixture
def r(w):
    return R(w)


@pytest.fixture
def custodian(w):
    key = SigningKey.generate()
    w.sql("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'custodian', %s)", (uuid.uuid4(), b64_public(key)))
    return key


def test_object_key_is_the_agents():
    from hostagent.s3 import object_key
    assert ret.object_key('t', 'e', 'b') == object_key('t', 'e', 'b')


# -- what may be deleted ------------------------------------------------------------

def test_keeps_the_newest_of_each_tier(r):
    daily = [r.point(d) for d in range(1, 10)]                    # 9 dailies: keep 7
    weekly = [r.point(7 * w + 1, 'weekly') for w in range(5)]     # keep 4
    monthly = [r.point(31 * m + 1, 'monthly') for m in range(4)]  # keep 3
    pre = r.point(2, 'pre_update')                                # no keep count
    assert r.candidates() == {*daily[7:], weekly[4], monthly[3], pre}


def test_lock_references_and_objects(r, w):
    for d in range(1, 8):
        r.point(d)
    locked = r.point(20, lock_passed=False)
    failed_stored = r.point(5, state='failed')
    failed_nothing = r.point(5, state='failed', version=None)
    restoring = r.point(30)
    w.store.dispatch('Tenant.RestoreToIsolated', tenant_id=TENANT, environment_id=ENV,
                     params={'backup_id': restoring}, hosts={'app': APP_HOST, 'db': APP_HOST},
                     idempotency_key='restore')
    assert r.candidates() == {failed_stored}                       # not locked, not referenced, not empty
    assert locked and failed_nothing


@pytest.mark.parametrize('gone', ['absent', 'deleted'])
def test_nothing_is_kept_for_a_removed_environment(r, w, gone):
    points = {r.point(d) for d in range(1, 4)} | {r.point(40, 'monthly')}
    if gone == 'absent':
        w.sql("UPDATE environment SET observed_state = 'absent'")
    else:
        w.sql("UPDATE tenant SET lifecycle_state = 'DELETED'")
    assert r.candidates() == points


# -- approval -----------------------------------------------------------------------

def test_draft_and_custodian_approval_through_the_api(r, w, custodian):
    old = r.point(40, 'pre_update')
    d = r.api.post('/v1/retention/draft', {}, who='custodian').json()['batch']
    assert [i['backup_point_id'] for i in d['items']] == [old] and d['body']['count'] == 1
    assert r.api.get('/v1/retention', who='auditor').json()['batch']['state'] == 'drafted'
    bad = r.approve(d, SigningKey.generate())
    resp = r.api.post('/v1/retention/%s/approve' % d['body']['batch_id'], {'approval': bad}, who='custodian')
    assert resp.status_code == 422 and resp.json()['detail']['code'] == 'SIG_INVALID'
    other = dict(r.approve(d, custodian), count=99)
    assert r.api.post('/v1/retention/%s/approve' % d['body']['batch_id'], {'approval': other},
                      who='custodian').status_code == 409
    ok = r.api.post('/v1/retention/%s/approve' % d['body']['batch_id'], {'approval': r.approve(d, custodian)},
                    who='custodian')
    assert ok.json() == {'batch_id': d['body']['batch_id'], 'state': 'approved'}
    assert r.api.post('/v1/retention/draft', {}, who='custodian').json()['batch'] is None     # executes first
    assert r.api.post('/v1/retention/draft', {}, who='auditor').status_code == 403


def test_expired_batch_and_breakglass(w, custodian):
    rr = R(w, breakglass=True)
    rr.point(40, 'pre_update')
    d = rr.r.draft()
    rr.offset = ret.APPROVAL_TTL + 60
    with pytest.raises(Exception, match='EXPIRED'):
        rr.r.approve(None, d['body']['batch_id'], rr.approve(d, custodian))
    rr.offset = 0
    d = rr.r.draft()
    bg = SigningKey.generate()
    w.sql("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'breakglass', %s)", (uuid.uuid4(), b64_public(bg)))
    rr.r.approve(None, d['body']['batch_id'], rr.approve(d, bg))
    assert w.sql('SELECT severity FROM incident')[0]['severity'] == 'sev2'


# -- deletion against S3 Object Lock --------------------------------------------------

pytestmark_s3 = pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')


@pytestmark_s3
def test_deletes_the_object_version_once_approved(r, w, custodian):
    r.bucket_up()
    pid, key, v = r.stored(lock_seconds=2)
    for d in range(1, 8):
        r.point(d)                                                  # 7 newer dailies: this one isn't kept
    time.sleep(3)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    assert [i['backup_point_id'] for i in d['items']] == [pid]
    assert r.r.execute() is None                                    # nothing approved yet
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    assert r.r.execute() == {pid: 'deleted'}
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expired'
    versions = r.s3.list_object_versions(Bucket=r.bucket, Prefix=key).get('Versions', [])
    assert [x['VersionId'] for x in versions] == []


@pytestmark_s3
def test_object_lock_refuses_an_early_delete_whatever_ctl_thinks(r, w, custodian):
    r.bucket_up()
    pid, key, v = r.stored(lock_seconds=600)
    for d in range(1, 8):
        r.point(d)
    # A wrong clock (or bad lock data) on ctl-1 makes it a candidate; B2/LocalStack still says no.
    w.sql("UPDATE backup_point SET lock_until = now() - interval '2 hours' WHERE id = %s", (pid,))
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    assert r.r.execute() == {pid: 'AccessDenied'}                    # compliance mode: no key can
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'recoverable'
    assert [x['VersionId'] for x in r.s3.list_object_versions(Bucket=r.bucket, Prefix=key)['Versions']] == [v]


@pytestmark_s3
def test_checked_again_at_execution_and_frozen(r, w, custodian):
    r.bucket_up()
    pid, key, v = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    r.api.post('/v1/retention/freeze', {'frozen': True}, who='custodian')
    assert r.r.execute() == {'frozen': True}
    r.api.post('/v1/retention/freeze', {'frozen': False}, who='custodian')
    # Meanwhile a restore of it started: it is no longer deletable.
    w.store.dispatch('Tenant.RestoreToIsolated', tenant_id=TENANT, environment_id=ENV, params={'backup_id': pid},
                     hosts={'app': APP_HOST, 'db': APP_HOST}, idempotency_key='restore-it')
    assert r.r.execute() == {pid: 'no_longer_deletable'}
    assert len(r.s3.list_object_versions(Bucket=r.bucket, Prefix=key)['Versions']) == 1


def test_items_changed_after_approval_are_refused(r, w, custodian):
    r.point(40, 'pre_update')
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    w.sql("UPDATE retention_batch SET items = jsonb_set(items, '{0,version_id}', '\"other\"')")
    with pytest.raises(RuntimeError, match='changed after approval'):
        r.r.execute()


@pytest.mark.parametrize('forgery', ['state_only', 'body_and_items'])
def test_an_approval_that_does_not_verify_is_not_executed(r, w, custodian, forgery):
    """Whoever can write retention_batch can't make ctl-1 delete: the signature is checked again."""
    r.point(40, 'pre_update')
    gone = r.point(41, 'pre_update')
    d = r.r.draft()
    if forgery == 'state_only':         # never approved: the row is just set so
        w.sql("UPDATE retention_batch SET state = 'approved', approval = body || "
              "jsonb_build_object('custodian_signature', 'AAAA')")
    else:                               # approved for one item, then body, items and hash rewritten together
        r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
        batch = w.sql('SELECT * FROM retention_batch')[0]
        items = [i for i in batch['items'] if i['backup_point_id'] == gone]
        body = dict(batch['body'], items_sha256=ret.sha256_hex(items), count=1)
        w.sql('UPDATE retention_batch SET items = %s, body = %s', (json.dumps(items), json.dumps(body)))
    with pytest.raises(RuntimeError, match='does not verify'):
        r.r.execute()
    assert [i['severity'] for i in w.sql("SELECT severity FROM incident WHERE runbook_ref = 'RB-09'")] == ['sev1']
    assert w.sql("SELECT count(*) AS n FROM backup_point WHERE state = 'expired'")[0]['n'] == 0


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_restore_admitted_while_retention_waits_keeps_its_backup(r, w, custodian):
    """Admission holds the backup row FOR SHARE until its operation is in; retention waits for it,
    then sees the reference and leaves the backup."""
    import threading

    import psycopg
    r.bucket_up()
    pid, key, v = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    admitting = psycopg.connect(w.dsn)
    admitting.execute('SELECT 1 FROM backup_point WHERE id = %s FOR SHARE', (pid,))
    out = {}
    t = threading.Thread(target=lambda: out.update(r.r.execute()))
    t.start()
    time.sleep(1)
    assert t.is_alive()                                         # waiting on the row
    w.store.dispatch('Tenant.RestoreToIsolated', tenant_id=TENANT, environment_id=ENV, params={'backup_id': pid},
                     hosts={'app': APP_HOST, 'db': APP_HOST}, idempotency_key='restore-while-retention')
    admitting.commit()
    admitting.close()
    t.join(10)
    assert out == {pid: 'no_longer_deletable'}
    assert len(r.s3.list_object_versions(Bucket=r.bucket, Prefix=key)['Versions']) == 1


def test_admission_waits_for_retention_and_refuses_the_expired_backup(r, w):
    """The other side of the race: retention holds the row FOR UPDATE and expires it; a restore requested
    meanwhile waits for that (FOR SHARE) and sees the backup expired."""
    import threading

    import psycopg
    pid = r.point(30)
    retaining = psycopg.connect(w.dsn)
    retaining.execute('SELECT 1 FROM backup_point WHERE id = %s FOR UPDATE', (pid,))
    out = {}
    t = threading.Thread(target=lambda: out.update(r.api.admission.request(
        None, op_type='Tenant.RestoreToIsolated', tenant_id=TENANT, environment_id=ENV,
        params={'backup_id': pid, 'purpose': 'drill'}, idempotency_key='restore-vs-retention')))
    t.start()
    time.sleep(1)
    assert t.is_alive()                                         # waiting on the row
    retaining.execute("UPDATE backup_point SET state = 'expired', expired_at = now() WHERE id = %s", (pid,))
    retaining.commit()
    retaining.close()
    t.join(10)
    assert (out['state'], out['result_code']) == ('REJECTED', 'POLICY_BACKUP'), out


# -- bucket C: control-plane dumps ----------------------------------------------------

def _dump(w, age_days, tier='daily', lock_passed=True, key=None, version='v', bucket='ctl-c'):
    did = str(uuid.uuid4())
    lock = datetime.now(UTC) + (timedelta(hours=-2) if lock_passed else timedelta(days=3))
    w.sql("INSERT INTO ctl_dump (id, reason, tier, schema_revision, bucket, object_key, object_version_id, sha256, "
          "size_bytes, lock_until, created_at) VALUES (%s, 'scheduled', %s, '0013', %s, %s, %s, 'x', 1, %s, %s)",
          (did, tier, bucket, key or 'ctl/dumps/%s' % did, version, lock,
           datetime.now(UTC) - timedelta(days=age_days)))
    return did


def _ctl_candidates(w, now=None):
    with w.store.connect() as c:
        return {i['ctl_dump_id'] for i in ret.ctl_candidates(c, now or time.time())}


def test_keeps_the_newest_ctl_dumps(r, w):
    daily = [_dump(w, d) for d in range(1, 33)]                       # keep 30
    monthly = [_dump(w, 31 * m + 1, 'monthly') for m in range(13)]   # keep 12
    locked = _dump(w, 40, lock_passed=False)
    assert _ctl_candidates(w) == {*daily[30:], monthly[12]}
    assert locked


@pytestmark_s3
def test_deletes_an_expired_dump_in_the_same_batch(r, w, custodian):
    r.bucket_up()
    pid, _, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    key = 'ctl/dumps/old.dump.age'
    v = r.s3.put_object(Bucket=r.bucket, Key=key, Body=b'dump', ObjectLockMode='COMPLIANCE',
                        ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(seconds=1))['VersionId']
    old = _dump(w, 40, key=key, version=v, bucket=r.bucket)
    for d in range(1, 31):
        _dump(w, d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    assert [i.get('backup_point_id') or i['ctl_dump_id'] for i in d['items']] == [pid, old]
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    assert r.r.execute() == {pid: 'deleted', old: 'SECRET_UNAVAILABLE'}           # no bucket C key given
    assert not w.sql('SELECT 1 FROM ctl_dump_expired')
    d = r.r.draft()
    assert [i['ctl_dump_id'] for i in d['items']] == [old]
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    with_key = Retention(w.store, s3_endpoint=S3, s3_region='us-east-1',
                         ctl_retention_key={'key_id': 'test', 'secret': 'test'})
    assert with_key.execute() == {old: 'deleted'}
    assert w.sql('SELECT batch_id FROM ctl_dump_expired WHERE ctl_dump_id = %s', (old,))[0]['batch_id'] \
        == uuid.UUID(d['body']['batch_id'])
    assert r.s3.list_object_versions(Bucket=r.bucket, Prefix=key).get('Versions', []) == []
    assert old not in _ctl_candidates(w, time.time() + r.offset)


@pytestmark_s3
def test_object_lock_refuses_an_early_dump_delete(r, w, custodian):
    r.bucket_up()
    key = 'ctl/dumps/locked.dump.age'
    v = r.s3.put_object(Bucket=r.bucket, Key=key, Body=b'dump', ObjectLockMode='COMPLIANCE',
                        ObjectLockRetainUntilDate=datetime.now(UTC) + timedelta(seconds=600))['VersionId']
    early = _dump(w, 40, key=key, version=v, bucket=r.bucket)        # ctl-1 believes the lock passed
    for d in range(1, 31):
        _dump(w, d)
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    r.r.ctl_retention_key = {'key_id': 'test', 'secret': 'test'}
    assert r.r.execute() == {early: 'AccessDenied'}
    assert not w.sql('SELECT 1 FROM ctl_dump_expired')


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_an_approval_past_its_expiry_is_abandoned_not_executed(r, w, custodian):
    r.bucket_up()
    pid, key, v = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    r.offset += ret.APPROVAL_TTL                        # e.g. frozen, or workers stopped, past the deadline
    assert r.r.execute()['expired'] is True
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'abandoned'
    assert len(r.s3.list_object_versions(Bucket=r.bucket, Prefix=key)['Versions']) == 1
    assert r.r.draft()['items'][0]['backup_point_id'] == pid     # drafted afresh, for a new approval


class Crash(BaseException):
    pass


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_batch_resumed_after_a_crash_keeps_what_it_did(r, w, custodian, monkeypatch):
    r.bucket_up()
    first, key1, _ = r.stored(lock_seconds=1, age_days=31)
    second, key2, _ = r.stored(lock_seconds=1, age_days=30)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real, deleted = Retention._client, []

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def once(**k):
            if deleted:
                raise Crash()                           # the process dies before the second item commits
            deleted.append(k['Key'])
            return delete(**k)
        s3.delete_object = once
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(Crash):
        r.r.execute()
    batch = w.sql('SELECT * FROM retention_batch')[0]
    assert batch['state'] == 'approved' and list(batch['results'].values()) == ['deleted']
    monkeypatch.setattr(Retention, '_client', real)
    assert r.r.execute() == {first: 'deleted', second: 'deleted'}
    rows = {str(x['id']): x for x in w.sql('SELECT id, state, retention_batch_id FROM backup_point WHERE id IN '
                                          '(%s, %s)', (first, second))}
    assert {x['state'] for x in rows.values()} == {'expired'}
    assert {str(x['retention_batch_id']) for x in rows.values()} == {d['body']['batch_id']}
    after = w.sql("SELECT after FROM audit_event WHERE action = 'retention.executed'")[0]['after']
    assert after['results'] == {first: 'deleted', second: 'deleted'}


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_an_approval_that_expires_during_execution_stops_it(r, w, custodian, monkeypatch):
    r.bucket_up()
    first, key1, _ = r.stored(lock_seconds=1, age_days=31)
    second, key2, _ = r.stored(lock_seconds=1, age_days=30)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def then_expire(**k):
            out = delete(**k)
            r.offset += ret.APPROVAL_TTL                 # the first delete took past the deadline
            return out
        s3.delete_object = then_expire
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    out = r.r.execute()
    assert out['expired'] is True and list(out['results'].values()) == ['deleted'], out
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'abandoned'
    left = [k for k in (key1, key2) if r.s3.list_object_versions(Bucket=r.bucket, Prefix=k).get('Versions')]
    assert len(left) == 1


def test_one_executor_at_a_time_and_a_deletion_stays_recorded(r, w, custodian):
    import psycopg
    r.point(40, 'pre_update')
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    other = psycopg.connect(w.dsn, autocommit=True)                 # another executor, mid-batch
    other.execute('SELECT pg_advisory_lock(%s)', (ret._EXECUTE_LOCK,))
    try:
        assert r.r.execute() == {'busy': True}
        assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'approved'
    finally:
        other.close()
    batch = d['body']['batch_id']
    with w.store.connect() as c:
        Retention._record(c, batch, 'x', 'deleted')
        Retention._record(c, batch, 'x', 'no_longer_deletable')     # a stale executor's view
        Retention._record(c, batch, 'y', 'AccessDenied')
        Retention._record(c, batch, 'y', 'deleted')
    assert w.sql('SELECT results FROM retention_batch')[0]['results'] == {'x': 'deleted', 'y': 'deleted'}


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_crash_right_after_the_s3_delete_leaves_it_expiring_not_recoverable(r, w, custodian, monkeypatch):
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def then_die(**k):
            delete(**k)
            raise Crash()                               # deleted in S3, nothing recorded yet
        s3.delete_object = then_die
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(Crash):
        r.r.execute()
    assert r.s3.list_object_versions(Bucket=r.bucket, Prefix=key).get('Versions', []) == []
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expiring'
    op = r.api.admission.request(None, op_type='Tenant.RestoreToIsolated', tenant_id=TENANT, environment_id=ENV,
                                 params={'backup_id': pid, 'purpose': 'drill'}, idempotency_key='after-crash')
    assert (op['state'], op['result_code']) == ('REJECTED', 'POLICY_BACKUP')
    monkeypatch.setattr(Retention, '_client', real)
    assert r.r.execute() == {pid: 'deleted'}                     # resumed: finished, not skipped
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expired'


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_freeze_during_a_batch_stops_it_before_the_next_delete(r, w, custodian, monkeypatch):
    import threading
    r.bucket_up()
    first, key1, _ = r.stored(lock_seconds=1, age_days=31)
    second, key2, _ = r.stored(lock_seconds=1, age_days=30)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real, froze = Retention._client, []

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def then_freeze(**k):
            out = delete(**k)
            if not froze:                               # the custodian freezes while the first item is in hand
                t = threading.Thread(target=lambda: froze.append(r.r.set_frozen(None, True)))
                t.start()
                time.sleep(0.5)
                assert t.is_alive()                     # waits for this item's commit
                froze.append(t)
            return out
        s3.delete_object = then_freeze
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    out = r.r.execute()
    froze[0].join(5)
    assert out['frozen'] is True and len(out['results']) == 1 and list(out['results'].values()) == ['deleted'], out
    left = [k for k in (key1, key2) if r.s3.list_object_versions(Bucket=r.bucket, Prefix=k).get('Versions')]
    assert len(left) == 1
    assert {x['state'] for x in w.sql('SELECT state FROM backup_point WHERE id IN (%s, %s)', (first, second))} == {
        'expired', 'recoverable'}
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'approved'      # resumes once unfrozen


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_freeze_after_marking_but_before_the_delete_puts_the_backup_back(r, w, custodian, monkeypatch):
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real, calls = Retention._frozen, []

    def frozen(c):
        calls.append(1)
        if len(calls) == 2:                     # the check after `expiring` was committed: freeze lands now
            r.r.set_frozen(None, True)
        return real(c)
    monkeypatch.setattr(Retention, '_frozen', staticmethod(frozen))
    assert r.r.execute()['frozen'] is True
    assert w.sql('SELECT state, retention_batch_id FROM backup_point WHERE id = %s', (pid,))[0] == {
        'state': 'recoverable', 'retention_batch_id': None}
    assert len(r.s3.list_object_versions(Bucket=r.bucket, Prefix=key)['Versions']) == 1


def test_a_draft_survives_the_next_rounds_until_it_expires(r, w):
    """The custodian signs offline; the hourly worker mustn't replace the batch meanwhile."""
    r.point(40, 'pre_update')
    first = r.r.draft()
    r.point(41, 'pre_update')                           # deletable since: waits for the next batch
    r.offset = 3600
    assert r.r.run_once()['body']['batch_id'] == first['body']['batch_id']
    assert r.r.draft() == first
    assert [x['state'] for x in w.sql('SELECT state FROM retention_batch')] == ['drafted']
    r.offset = ret.APPROVAL_TTL + 60
    later = r.r.draft()
    assert later['body']['batch_id'] != first['body']['batch_id'] and later['body']['count'] == 2


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
@pytest.mark.parametrize('gone', [True, False])
def test_an_expiring_backup_is_settled_when_the_approval_lapses(r, w, custodian, monkeypatch, gone):
    """Its delete timed out (still 'expiring'); the approval then expired: back to recoverable if the
    version is still there, expired if not; never left 'expiring'."""
    from botocore.exceptions import ReadTimeoutError
    r.bucket_up()
    pid, key, v = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def timeout(**k):
            if gone:
                delete(**k)                             # it went through; the answer didn't
            raise ReadTimeoutError(endpoint_url='s3')
        s3.delete_object = timeout
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(ReadTimeoutError):
        r.r.execute()
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expiring'
    monkeypatch.setattr(Retention, '_client', real)
    r.offset += ret.APPROVAL_TTL
    out = r.r.execute()
    assert out['expired'] is True and out['results'] == {pid: 'deleted' if gone else 'approval_expired'}, out
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == (
        'expired' if gone else 'recoverable')
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'abandoned'


def test_future_dated_dumps_take_no_keep_slot(r, w):
    old = _dump(w, 40)
    for d in range(1, 30):
        _dump(w, d)                                     # 29 newer: old is the 30th, kept
    for d in range(1, 6):
        _dump(w, -d)                                    # dated in the future: ignored
    assert old not in _ctl_candidates(w)


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_freeze_settles_what_a_failed_delete_left_expiring(r, w, custodian, monkeypatch):
    """Frozen before the next round, and kept frozen: the backup is settled anyway (nothing deleted)."""
    from botocore.exceptions import ReadTimeoutError
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)

        def timeout(**k):
            raise ReadTimeoutError(endpoint_url='s3')   # never reached S3
        s3.delete_object = timeout
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(ReadTimeoutError):
        r.r.execute()
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expiring'
    monkeypatch.setattr(Retention, '_client', real)
    r.r.set_frozen(None, True)
    assert r.r.execute() == {'frozen': True}
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'recoverable'
    assert len(r.s3.list_object_versions(Bucket=r.bucket, Prefix=key)['Versions']) == 1
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'approved'


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_refused_retry_of_a_resumed_delete_doesnt_resurrect_it(r, w, custodian, monkeypatch):
    """S3 deleted it, the process died; the retry is refused: still `expiring` (not `recoverable`),
    then settled as expired once the approval lapses."""
    from botocore.exceptions import ClientError
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region, then=None):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def die(**k):
            delete(**k)
            raise Crash()
        s3.delete_object = die
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(Crash):
        r.r.execute()

    def refusing(self, c, region):
        s3 = real(self, c, region)

        def denied(**k):
            raise ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'no'}}, 'DeleteObject')
        s3.delete_object = denied
        return s3
    monkeypatch.setattr(Retention, '_client', refusing)
    unmarked = []
    monkeypatch.setattr(Retention, '_unmark', staticmethod(lambda *a: unmarked.append(a)))
    # Refused, so not put back; settled before the batch closes: its version is gone, so expired.
    assert r.r.execute() == {pid: 'deleted'}
    assert unmarked == []
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expired'
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'executed'


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_settle_s3_cannot_answer_keeps_the_batch_and_opens_one_sev2(r, w, custodian, monkeypatch):
    from botocore.exceptions import ClientError, ReadTimeoutError
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)

        def timeout(**k):
            raise ReadTimeoutError(endpoint_url='s3')

        def forbidden(**k):                             # a delete-only key: no readFiles
            raise ClientError({'Error': {'Code': '403', 'Message': 'Forbidden'}}, 'HeadObject')
        s3.delete_object, s3.head_object = timeout, forbidden
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(ReadTimeoutError):
        r.r.execute()
    r.offset += ret.APPROVAL_TTL
    for _ in range(2):
        assert r.r.execute() == {'expired': True, 'unresolved': 1}
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'approved'
    assert [i['severity'] for i in w.sql("SELECT severity FROM incident WHERE runbook_ref = 'RB-04'")] == ['sev2']


def test_a_point_another_batch_left_expiring_is_not_resumed(r, w, custodian):
    """Resume needs this batch's id on the point, not just the state."""
    pid = r.point(40, 'pre_update')
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    other = str(uuid.uuid4())
    w.sql("INSERT INTO retention_batch (id, body, items, state, drafted_at) VALUES (%s, '{}', '[]', 'executed', now())",
          (other,))
    w.sql("UPDATE backup_point SET state = 'expiring', retention_batch_id = %s WHERE id = %s", (other, pid))
    assert r.r.execute() == {pid: 'no_longer_deletable'}
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expiring'


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
def test_a_resumed_delete_without_its_key_stays_expiring(r, w, custodian, monkeypatch):
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def die(**k):
            delete(**k)
            raise Crash()
        s3.delete_object = die
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    with pytest.raises(Crash):
        r.r.execute()

    def no_key(self, c, region):
        raise ret.Refused('SECRET_UNAVAILABLE')
    monkeypatch.setattr(Retention, '_client', no_key)
    assert r.r.execute() == {'expired': False, 'unresolved': 1}
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == 'expiring'
    assert w.sql('SELECT state FROM retention_batch')[0]['state'] == 'approved'


@pytest.mark.skipif(not _s3_up(), reason='needs LocalStack (agent dev/up.sh)')
@pytest.mark.parametrize('deleted', [True, False])
def test_an_error_from_the_first_delete_call_is_settled_not_trusted(r, w, custodian, monkeypatch, deleted):
    """boto3 retries inside one call: the first request may delete the version, the last one fail.
    The point stays `expiring` and is settled from the bucket: expired if gone, back if not."""
    from botocore.exceptions import ClientError
    r.bucket_up()
    pid, key, _ = r.stored(lock_seconds=1)
    for d in range(1, 8):
        r.point(d)
    time.sleep(2)
    r.offset = ret.LOCK_MARGIN + 60
    d = r.r.draft()
    r.r.approve(None, d['body']['batch_id'], r.approve(d, custodian))
    real = Retention._client

    def client(self, c, region):
        s3 = real(self, c, region)
        delete = s3.delete_object

        def lost_answer(**k):
            if deleted:
                delete(**k)
            raise ClientError({'Error': {'Code': 'InternalError', 'Message': 'retries exhausted'}}, 'DeleteObject')
        s3.delete_object = lost_answer
        return s3
    monkeypatch.setattr(Retention, '_client', client)
    out = r.r.execute()
    assert out == {pid: 'deleted' if deleted else 'InternalError'}, out
    assert w.sql('SELECT state FROM backup_point WHERE id = %s', (pid,))[0]['state'] == (
        'expired' if deleted else 'recoverable')
