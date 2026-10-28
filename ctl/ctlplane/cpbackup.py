"""Control-plane backup to bucket C (DOC-05 §1, §2, §4, §5, §8; DOC-03 §2.9
SEC-13; DOC-07 RB-09).

    dump     03:30 UTC daily, and before every schema migration: `pg_dump -Fc`
             of ctl-1's database, age-encrypted to every active region's
             operational key and the offline recovery key, uploaded under
             compliance Object Lock (31 days; the first scheduled dump of a
             month 366) and read back: the version's SHA-256 and lock date
             must be what was sent.
    anchor   04:00 UTC daily: the hash chain is verified and checked against
             every anchor already in the bucket, then the latest audit_event
             (seq, hash) is written, locked 366 days (as long as any dump it
             vouches for). A broken chain or an anchor that doesn't match opens
             a sev1 incident (RB-09) and nothing is anchored.
    verify   the control-plane drill and RB-09 step 4: download a dump, check
             its SHA-256 and ctl-1's signature over it (key, bytes, snapshot
             time, schema) with a configured key, decrypt, pg_restore into an empty database, compare
             its schema revision with the dump's, verify the chain, and check
             it against every anchor in the bucket it covers.
    rebuild  RB-09/RB-10: the same checks, restored onto a new cluster as it
             was: the roles the database needs are created from the dump's
             roles manifest (no passwords: login roles get new ones, RB-09
             step 5), then the database with its owners and privileges, which
             must match the manifest's ACL fingerprint.
    drill    quarterly, run by an operator: `verify` of the newest dump into
             a database on a temporary server the operator created (never
             ctl-1's own cluster), with a region's operational key from the
             vault, or the recovery key at its annual reconstruction. The
             report is put in bucket C (locked) as `restore_drill` evidence;
             a fail opens a sev2 incident (DOC-05 §8). ctl-1 orders no
             servers: `ControlPlaneNotDrilled` says when one is due.

A dump is an age-encrypted tar: `ctl.dump` (`pg_dump -Fc`) and `roles.json`,
the cluster roles that own or are granted something, and their members, with their
LOGIN/INHERIT and memberships, plus the SHA-256 of every ACL and owner in
the database: `pg_dump` of one database carries the grants, not the roles.

The bucket's anchors are what is trusted, never `audit_anchor`: whoever can
rewrite the database can rewrite that table too. Every version of an anchor
key is read, since a newer version would hide a locked one.
"""
import base64
import hashlib
import io
import json
import os
import subprocess
import tarfile
import time
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import psycopg
import pyrage
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg import pq, sql
from psycopg.rows import dict_row
from nacl.signing import SigningKey

from . import audit
from .canonical import sign, verify
from .store import Store, _ts

DUMP_AT = (3, 30)
ANCHOR_AT = (4, 0)
LOCK_DAYS = {'daily': 31, 'monthly': 366}
ANCHOR_LOCK_DAYS = 366
PRE_DUMP_ANCHOR_EVERY = 3600
MANIFEST_VERSION = 2       # 1 kept only ADMIN of a membership; never shipped
DUMPS = 'ctl/dumps/'
ANCHORS = 'ctl/audit-anchors/'
DRILLS = 'ctl/drills/'
DRILL_LOCK_DAYS = 366


class JobFailed(Exception):
    """run_once tried what was due and some of it failed; `result` has each outcome."""

    def __init__(self, result):
        super().__init__(', '.join('%s: %s' % (k, v.get('error')) for k, v in result.items()
                                   if v.get('state') == 'error'))
        self.result = result


class Unreadable(Exception):
    """S3 wouldn't return a dump's metadata: neither signed nor unsigned is established."""


class ReadBackMismatch(Exception):
    """The stored version isn't what was sent (DOC-05 §8: sev1)."""


def _libpq_env(dsn) -> dict:
    """The connection as libpq environment variables, so no password is on a command line.
    Every parameter goes (sslmode, sslrootcert, sslcert, ...): pg_dump and pg_restore
    must connect exactly as the check before them did. One with no environment
    variable (keepalives, sslpassword, ...) is refused rather than dropped."""
    envvars = {o.keyword.decode(): (o.envvar or b'').decode() for o in pq.Conninfo.get_defaults()}
    params = {k: v for k, v in conninfo_to_dict(dsn).items() if v is not None}
    missing = sorted(k for k in params if not envvars.get(k))
    if missing:
        raise ValueError('connection parameters pg_dump/pg_restore would not get: %s' % ', '.join(missing))
    return {**os.environ, **{envvars[k]: str(v) for k, v in params.items()}}


def _cluster(dsn) -> int:
    with psycopg.connect(dsn) as c:
        return c.execute('SELECT system_identifier FROM pg_control_system()').fetchone()[0]


def _b64(hexdigest) -> str:
    return base64.b64encode(bytes.fromhex(hexdigest)).decode()


def schema_revision(c) -> str | None:
    if not c.execute("SELECT to_regclass('alembic_version') AS t").fetchone()['t']:
        return None
    row = c.execute('SELECT version_num FROM alembic_version').fetchone()
    return row and row['version_num']


# Everything in the database that has an owner or an ACL; compared after a rebuild.
_PRIVILEGES = """
SELECT 'database' AS kind, datname AS name, datdba::regrole::text AS owner, datacl::text AS acl
  FROM pg_database WHERE datname = current_database()
UNION ALL SELECT 'schema', nspname, nspowner::regrole::text, nspacl::text FROM pg_namespace WHERE nspname = 'public'
UNION ALL SELECT 'relation', c.relname, c.relowner::regrole::text, c.relacl::text
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
UNION ALL SELECT 'column', c.relname || '.' || a.attname, NULL, a.attacl::text
  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND a.attacl IS NOT NULL
UNION ALL SELECT 'function', p.oid::regprocedure::text, p.proowner::regrole::text, p.proacl::text
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
UNION ALL SELECT 'default_acl', d.defaclobjtype::text, d.defaclrole::regrole::text, d.defaclacl::text
  FROM pg_default_acl d
ORDER BY 1, 2
"""

_ROLE_OIDS = """
SELECT datdba AS oid FROM pg_database WHERE datname = current_database()
UNION SELECT (aclexplode(datacl)).grantee FROM pg_database WHERE datname = current_database() AND datacl IS NOT NULL
UNION SELECT nspowner FROM pg_namespace WHERE nspname = 'public'
UNION SELECT (aclexplode(nspacl)).grantee FROM pg_namespace WHERE nspname = 'public' AND nspacl IS NOT NULL
UNION SELECT c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'
UNION SELECT (aclexplode(c.relacl)).grantee FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relacl IS NOT NULL
UNION SELECT (aclexplode(a.attacl)).grantee FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND a.attacl IS NOT NULL
UNION SELECT p.proowner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'
UNION SELECT (aclexplode(p.proacl)).grantee FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'public' AND p.proacl IS NOT NULL
UNION SELECT defaclrole FROM pg_default_acl
UNION SELECT (aclexplode(defaclacl)).grantee FROM pg_default_acl
"""


def privileges_sha256(c) -> str:
    rows = [[r['kind'], r['name'], r['owner'], r['acl']] for r in c.execute(_PRIVILEGES).fetchall()]
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()


_PRIVILEGED = ('rolsuper', 'rolcreatedb', 'rolcreaterole', 'rolreplication', 'rolbypassrls')


def _memberships(c, names=None) -> list[dict]:
    """PG 16 memberships with all three options, one row per (role, member): grants by
    different grantors are merged (an option any of them gives is given). With
    `names`, those touching any of them on either side: an outside login made a
    member of ctl_app, or ctl_app made a member of an outside (or built-in) role,
    changes who can do what in this database as much as one between them."""
    rows = c.execute('SELECT m.roleid, m.member, r.rolname AS role, u.rolname AS member_name, '
                     'bool_or(m.admin_option) AS admin, bool_or(m.inherit_option) AS inherit, '
                     'bool_or(m.set_option) AS set FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid '
                     'JOIN pg_roles u ON u.oid = m.member GROUP BY 1, 2, 3, 4').fetchall()
    return [r for r in rows if names is None or r['role'] in names or r['member_name'] in names]


def roles_manifest(c) -> dict:
    """The roles this database needs: owners and grantees, and their members
    (a login role that becomes ctl_app), transitively. A role they are members
    of adds nothing here unless it is a grantee itself."""
    oids = {r['oid'] for r in c.execute(_ROLE_OIDS).fetchall() if r['oid']}      # 0: PUBLIC
    edges = _memberships(c)
    while True:
        more = {e['member'] for e in edges if e['roleid'] in oids}
        if more <= oids:
            break
        oids |= more
    rows = c.execute("SELECT oid, rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, "
                     "rolreplication, rolbypassrls FROM pg_roles WHERE oid = ANY(%s) AND rolname !~ '^pg_' "
                     'ORDER BY rolname', (list(oids),)).fetchall()
    names = {r['oid']: r['rolname'] for r in rows}
    return {'v': MANIFEST_VERSION, 'database': c.execute('SELECT current_database() AS d').fetchone()['d'],
            'roles': [{'name': r['rolname'], 'login': r['rolcanlogin'], 'inherit': r['rolinherit'],
                       'privileged': [a for a in _PRIVILEGED if r[a]]} for r in rows],
            'memberships': sorted([e['role'], e['member_name'], e['admin'], e['inherit'], e['set']]
                                  for e in _memberships(c, set(names.values()))),
            'privileges_sha256': privileges_sha256(c)}


def _dump_claim(key, sha256, snapshot_at, schema_revision) -> dict:
    """What a dump's signature covers: which object, which bytes, as of when, which schema."""
    return {'v': 1, 'type': 'ctl.dump', 'object_key': key, 'sha256': sha256, 'snapshot_at': snapshot_at,
            'schema_revision': schema_revision}


def _pack(dump: bytes, manifest: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        for name, data in (('roles.json', json.dumps(manifest, sort_keys=True).encode()), ('ctl.dump', dump)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _unpack(payload: bytes) -> tuple[bytes, dict]:
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r') as tar:
        return tar.extractfile('ctl.dump').read(), json.loads(tar.extractfile('roles.json').read())


def bucket_anchors(s3, bucket) -> list[dict]:
    """Every version of every anchor object; a version that isn't a valid anchor is {'key', 'invalid': True}."""
    out = []
    for page in s3.get_paginator('list_object_versions').paginate(Bucket=bucket, Prefix=ANCHORS):
        for v in page.get('Versions', []):
            body = s3.get_object(Bucket=bucket, Key=v['Key'], VersionId=v['VersionId'])['Body'].read()
            try:
                a = json.loads(body)
                out.append({'key': v['Key'], 'seq': int(a['seq']), 'hash': bytes.fromhex(a['hash']),
                            'anchored_at': datetime.fromisoformat(a['anchored_at'])})
            except (ValueError, KeyError, TypeError):
                out.append({'key': v['Key'], 'invalid': True})
        out += [{'key': m['Key'], 'invalid': True} for m in page.get('DeleteMarkers', [])]
    return out


def check_anchors(c, anchors, snapshot_at=None) -> dict:
    """→ matched, mismatched (keys), beyond (anchors past the database's last row).
    An anchored row missing below the last one is a mismatch: anchors reference
    committed rows, and a row's hash doesn't cover its seq, so deleting rows and
    renumbering the rest would keep the chain whole.

    With `snapshot_at` (a dump's signed snapshot time), an anchor written
    before it that the dump lacks makes it `stale`: its content is older than
    it claims. Anchors written while a dump was being made, after its
    snapshot, aren't expected in it."""
    matched, mismatched, beyond, stale = 0, [], 0, []
    last = c.execute('SELECT max(seq) AS m FROM audit_event').fetchone()['m'] or 0
    for a in anchors:
        if a.get('invalid'):
            mismatched.append(a['key'])
            continue
        row = c.execute('SELECT hash FROM audit_event WHERE seq = %s', (a['seq'],)).fetchone()
        if row is None and a['seq'] <= last:
            mismatched.append(a['key'])
        elif row is None:
            beyond += 1
            if snapshot_at is not None and a['anchored_at'] < snapshot_at:
                stale.append(a['key'])
        elif bytes(row['hash']) == a['hash']:
            matched += 1
        else:
            mismatched.append(a['key'])
    return {'matched': matched, 'mismatched': mismatched, 'beyond': beyond, 'stale': stale}


class ControlPlaneBackup:
    def __init__(self, store: Store | None, *, owner_dsn: str | None, bucket: str, s3_key: dict,
                 recovery_recipient: str,
                 s3_endpoint: str = '', s3_region: str = 'eu-central-003', pg_dump=('pg_dump',),
                 pg_restore=('pg_restore',), signing_key: SigningKey | None = None, trusted_keys=()):
        """`owner_dsn`: a role that can dump every table (the migrations' owner);
        `store` and `owner_dsn` are None on a new ctl-1 that only rebuilds.
        `s3_key`: {key_id, secret}, bucket C's write key (no delete capability).
        `recovery_recipient`: the region-independent recovery key's age public
        key, whose identity exists only as offline shares (DOC-05 §4).
        `pg_dump`/`pg_restore`: the command, version 16 like the server.
        `signing_key`: signs each dump (needed to dump). `trusted_keys`: the
        VerifyKeys a dump must be signed by to be decrypted or restored at all;
        from configuration (the IaC repo), never from the bucket, whose write
        key could otherwise put an archive whose SQL pg_restore would run."""
        pyrage.x25519.Recipient.from_str(recovery_recipient)
        self.store = store
        self.owner_dsn = owner_dsn
        self.bucket = bucket
        self.s3_key = s3_key
        self.recovery_recipient = recovery_recipient
        self.s3_endpoint = s3_endpoint
        self.s3_region = s3_region
        self.pg_dump = list(pg_dump)
        self.pg_restore = list(pg_restore)
        self.signing_key = signing_key
        self.trusted_keys = list(trusted_keys)

    def _s3(self):
        return boto3.client('s3', endpoint_url=self.s3_endpoint or None, region_name=self.s3_region,
                            aws_access_key_id=self.s3_key['key_id'], aws_secret_access_key=self.s3_key['secret'],
                            config=Config(retries={'max_attempts': 5}))

    def _put_locked(self, s3, key, body: bytes, until: datetime, metadata=None) -> dict:
        sha = hashlib.sha256(body).hexdigest()
        version = s3.put_object(Bucket=self.bucket, Key=key, Body=body, ChecksumSHA256=_b64(sha),
                                ObjectLockMode='COMPLIANCE', ObjectLockRetainUntilDate=until,
                                Metadata=metadata or {})['VersionId']
        h = s3.head_object(Bucket=self.bucket, Key=key, VersionId=version, ChecksumMode='ENABLED')
        seen = h.get('ObjectLockRetainUntilDate')
        if (h.get('ObjectLockMode') != 'COMPLIANCE' or h.get('ChecksumSHA256') != _b64(sha)
                or seen is None or seen < until - timedelta(seconds=60)):
            raise ReadBackMismatch(key)
        return {'version_id': version, 'sha256': sha, 'size': len(body), 'lock_until': seen}

    def _sev1(self, c, now, summary):
        """Once while open: a broken chain is found again every round until it is dealt with."""
        if c.execute("SELECT 1 FROM incident WHERE summary = %s AND resolved_at IS NULL", (summary,)).fetchone():
            return
        c.execute("INSERT INTO incident (id, severity, summary, runbook_ref, opened_at) "
                  "VALUES (%s, 'sev1', %s, 'RB-09', %s)", (uuid.uuid4(), summary, _ts(now)))

    # -- dump ----------------------------------------------------------------------------
    def dump(self, reason='scheduled') -> dict | None:
        """→ the dump's record; None if there is no schema yet (nothing to dump)."""
        now = self.store.clock()
        with psycopg.connect(self.owner_dsn, row_factory=dict_row) as c:
            revision = schema_revision(c)
            if revision is None:
                return None
            recipients = [r['backup_recipient'] for r in c.execute(
                "SELECT backup_recipient FROM region WHERE status = 'active' ORDER BY code").fetchall()]
            if not recipients:
                raise RuntimeError('no active region: a dump needs an operational recipient besides the recovery key')
            manifest = roles_manifest(c)
        # An anchor just before the dump: this dump must contain it (check_anchors' `stale`). Not
        # again within the hour: a dump failing every round mustn't add a 366-day anchor each time.
        # A failure here doesn't stop the dump.
        if not self._anchored_since(self.store.clock() - PRE_DUMP_ANCHOR_EVERY):
            self._attempt(self.anchor)
        if self.signing_key is None:
            raise RuntimeError('a dump must be signed: no signing key')
        snapshot_at = _ts(self.store.clock())      # every anchor before this is in the dump
        plain = _pack(subprocess.run([*self.pg_dump, '-Fc'], env=_libpq_env(self.owner_dsn), capture_output=True,
                                     check=True).stdout, manifest)
        sealed = pyrage.encrypt(plain, [pyrage.x25519.Recipient.from_str(r)
                                        for r in recipients + [self.recovery_recipient]])
        at = _ts(now)
        with self.store.connect() as c:
            recorded = c.execute("SELECT to_regclass('ctl_dump') AS t").fetchone()['t']
            monthly = reason == 'scheduled' and recorded and not c.execute(
                "SELECT 1 FROM ctl_dump WHERE reason = 'scheduled' AND tier = 'monthly' AND created_at >= %s "
                'AND created_at <= %s', (at.replace(day=1, hour=0, minute=0, second=0, microsecond=0), at)).fetchone()
            tier = 'monthly' if monthly else 'daily'
            dump_id = uuid.uuid4()
            key = '%s%s/%s-%s.dump.age' % (DUMPS, at.date().isoformat(), at.strftime('%Y%m%dT%H%M%SZ'), dump_id)
            s3 = self._s3()
            claim = _dump_claim(key, hashlib.sha256(sealed).hexdigest(), snapshot_at.isoformat(), revision)
            try:
                stored = self._put_locked(s3, key, sealed, at + timedelta(days=LOCK_DAYS[tier]),
                                          {'schema-revision': revision, 'reason': reason,
                                           'snapshot-at': snapshot_at.isoformat(),
                                           'signature': sign(claim, self.signing_key)})
            except ReadBackMismatch:
                self._sev1(c, now, 'control-plane dump read back differently from what was sent: %s' % key)
                c.commit()          # the incident stays
                raise
            record = {'id': str(dump_id), 'reason': reason, 'tier': tier, 'schema_revision': revision,
                      'object_key': key, 'object_version_id': stored['version_id'], 'sha256': stored['sha256'],
                      'size_bytes': stored['size'], 'lock_until': stored['lock_until'].isoformat()}
            if recorded:        # before migration 0012, a pre-migration dump has nowhere to be recorded
                c.execute('INSERT INTO ctl_dump (id, reason, tier, schema_revision, bucket, object_key, '
                          'object_version_id, sha256, size_bytes, lock_until, created_at) '
                          'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                          (dump_id, reason, tier, revision, self.bucket, key, stored['version_id'], stored['sha256'],
                           stored['size'], stored['lock_until'], at))
                audit.append(c, at, 'ctl.dumped', resource_type='ctl_dump', resource_id=dump_id,
                             after={'reason': reason, 'tier': tier, 'schema_revision': revision,
                                    'sha256': stored['sha256']})
            return record

    def _anchored_since(self, since) -> bool:
        with self.store.connect() as c:
            if not c.execute("SELECT to_regclass('audit_anchor') AS t").fetchone()['t']:
                return False            # before migration 0012
            return bool(c.execute('SELECT 1 FROM audit_anchor WHERE anchored_at >= %s AND anchored_at <= %s',
                                  (_ts(since), _ts(self.store.clock()))).fetchone())

    def migrate(self, alembic_cfg, revision='head'):
        """DOC-05 §2: dump, then upgrade. A failed dump leaves the schema as it is."""
        from alembic import command
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
        from sqlalchemy import create_engine

        engine = create_engine(self.owner_dsn.replace('postgresql://', 'postgresql+psycopg://', 1))
        with engine.connect() as conn:
            current = MigrationContext.configure(conn).get_current_revision()
        engine.dispose()
        target = ScriptDirectory.from_config(alembic_cfg).get_revision(revision).revision
        if current == target:
            return None
        record = self.dump('pre_migration') if current is not None else None
        command.upgrade(alembic_cfg, revision)
        return record

    # -- anchor --------------------------------------------------------------------------
    def anchor(self) -> dict:
        now = self.store.clock()
        s3 = self._s3()
        anchors = bucket_anchors(s3, self.bucket)
        with self.store.connect() as c:
            broken = audit.verify_chain(c)
            seen = check_anchors(c, anchors)
            if broken is not None or seen['mismatched'] or seen['beyond']:
                self._sev1(c, now, 'audit chain verification failed (first bad seq %s, anchors not matching: %d, '
                                   'anchors past the last row: %d): investigate as a compromise'
                           % (broken, len(seen['mismatched']), seen['beyond']))
                return {'state': 'chain_broken', 'first_bad_seq': broken, **seen}
            last = c.execute('SELECT seq, hash, at FROM audit_event ORDER BY seq DESC LIMIT 1').fetchone()
            if last is None:
                return {'state': 'empty'}
            # Timed after the row is chosen, not on entry: a dump whose snapshot falls between the two
            # needn't contain a row committed after it (check_anchors' `stale` compares these times).
            at = _ts(self.store.clock())
            body = json.dumps({'v': 1, 'seq': last['seq'], 'hash': bytes(last['hash']).hex(),
                               'at': last['at'].astimezone(timezone.utc).isoformat(),
                               'anchored_at': at.isoformat()}, sort_keys=True).encode()
            key = '%s%s-%d.json' % (ANCHORS, at.strftime('%Y%m%dT%H%M%SZ'), last['seq'])
            try:
                stored = self._put_locked(s3, key, body, at + timedelta(days=ANCHOR_LOCK_DAYS))
            except ReadBackMismatch:
                self._sev1(c, now, 'audit anchor read back differently from what was sent: %s' % key)
                c.commit()          # the incident stays
                raise
            anchor_id = uuid.uuid4()
            c.execute('INSERT INTO audit_anchor (id, seq, hash, bucket, object_key, object_version_id, lock_until, '
                      'anchored_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                      (anchor_id, last['seq'], last['hash'], self.bucket, key, stored['version_id'],
                       stored['lock_until'], at))
            audit.append(c, at, 'audit.anchored', resource_type='audit_anchor', resource_id=anchor_id,
                         after={'seq': last['seq'], 'hash': bytes(last['hash']).hex()})
            return {'state': 'anchored', 'seq': last['seq'], 'object_key': key, 'matched': seen['matched']}

    # -- verify --------------------------------------------------------------------------
    def verify(self, target_dsn, identities, key=None) -> dict:
        """Restore a dump (the newest if `key` is None) into the empty database
        `target_dsn` and check it. `identities`: age identities, a region's
        operational key or the reconstructed recovery key."""
        s3 = self._s3()
        out, dump, _ = self._fetch(s3, identities, key)
        if dump is None:
            return out
        restore = subprocess.run([*self.pg_restore, '--no-owner', '--no-privileges', '--exit-on-error', '-d',
                                  conninfo_to_dict(target_dsn)['dbname']],
                                 input=dump, env=_libpq_env(target_dsn), capture_output=True)
        if restore.returncode != 0:
            return {**out, 'ok': False, 'reason': 'restore_failed',
                    'detail': restore.stderr.decode(errors='replace')[-500:]}
        with psycopg.connect(target_dsn, row_factory=dict_row) as c:
            self._check(c, s3, out)
        return out

    def rebuild(self, admin_dsn, identities, key=None) -> dict:
        """Restore a dump onto a new cluster as it was (`admin_dsn`: a superuser
        there): the manifest's roles, then the database under its own name with
        owners and privileges, then the checks of `verify` and the ACL
        fingerprint. Roles already there are left as they are; roles created
        get LOGIN/INHERIT and memberships, never a password or a privileged
        attribute (SUPERUSER, CREATEROLE, ...): set new passwords for
        `login_roles` before ctl-1 connects (RB-09 step 5)."""
        if self.owner_dsn and _cluster(admin_dsn) == _cluster(self.owner_dsn):
            raise ValueError('the rebuild target is the running ctl-1\'s own cluster')
        s3 = self._s3()
        out, dump, manifest = self._fetch(s3, identities, key)
        if dump is None:
            return out
        if manifest.get('v') != MANIFEST_VERSION:
            return {**out, 'ok': False, 'reason': 'manifest_version', 'manifest_version': manifest.get('v')}
        name = manifest['database']
        out.update(database=name, roles_created=[], roles_existing=[], login_roles=[], privileged_not_restored=[])
        with psycopg.connect(admin_dsn, autocommit=True) as c:
            if c.execute('SELECT 1 FROM pg_database WHERE datname = %s', (name,)).fetchone():
                return {**out, 'ok': False, 'reason': 'database_exists'}
            for r in manifest['roles']:
                if c.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (r['name'],)).fetchone():
                    out['roles_existing'].append(r['name'])
                    continue
                c.execute(sql.SQL('CREATE ROLE {} {} {}').format(
                    sql.Identifier(r['name']), sql.SQL('LOGIN' if r['login'] else 'NOLOGIN'),
                    sql.SQL('INHERIT' if r['inherit'] else 'NOINHERIT')))
                out['roles_created'].append(r['name'])
                if r['login']:
                    out['login_roles'].append(r['name'])
                if r['privileged']:
                    out['privileged_not_restored'].append({'role': r['name'], 'attributes': r['privileged']})
            out['memberships_unrestorable'] = []
            for role, member, admin, inherit, set_ in manifest['memberships']:
                if c.execute('SELECT count(*) FROM pg_roles WHERE rolname IN (%s, %s)',
                             (role, member)).fetchone()[0] != len({role, member}):
                    out['memberships_unrestorable'].append([role, member])     # an outside role not here
                    continue
                if not c.execute('SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid '
                                 'JOIN pg_roles u ON u.oid = m.member WHERE r.rolname = %s AND u.rolname = %s',
                                 (role, member)).fetchone():
                    c.execute(sql.SQL('GRANT {} TO {} WITH ADMIN {}, INHERIT {}, SET {}').format(
                        sql.Identifier(role), sql.Identifier(member), *(sql.SQL('TRUE' if v else 'FALSE')
                                                                         for v in (admin, inherit, set_))))
        restore = subprocess.run([*self.pg_restore, '--create', '--exit-on-error', '-d',
                                  conninfo_to_dict(admin_dsn)['dbname']],
                                 input=dump, env=_libpq_env(admin_dsn), capture_output=True)
        if restore.returncode != 0:
            return {**out, 'ok': False, 'reason': 'restore_failed',
                    'detail': restore.stderr.decode(errors='replace')[-500:]}
        with psycopg.connect(make_conninfo(admin_dsn, dbname=name), row_factory=dict_row) as c:
            self._check(c, s3, out)
            out['privileges_match'] = privileges_sha256(c) == manifest['privileges_sha256']
            # Roles that were already there, and memberships, as the manifest has them: a role or
            # membership left with more (or less) than it had would pass the ACL fingerprint.
            names = {r['name'] for r in manifest['roles']}
            have = {r['rolname']: r for r in c.execute(
                'SELECT rolname, rolcanlogin, rolinherit, rolsuper, rolcreatedb, rolcreaterole, rolreplication, '
                'rolbypassrls FROM pg_roles WHERE rolname = ANY(%s)', (list(names),)).fetchall()}
            created = set(out['roles_created'])

            def differs(r):
                h = have.get(r['name'])
                if h is None or (h['rolcanlogin'], h['rolinherit']) != (r['login'], r['inherit']):
                    return True
                # No role may hold more (SUPERUSER, BYPASSRLS, ...) than on ctl-1, and one made here holds
                # none; what one lacks is listed in privileged_not_restored, as for a role made here.
                privileged = {a for a in _PRIVILEGED if h[a]}
                expected = set() if r['name'] in created else set(r['privileged'])
                lacking = set(r['privileged']) - privileged
                if lacking and r['name'] not in created:
                    out['privileged_not_restored'].append({'role': r['name'], 'attributes': sorted(lacking)})
                return bool(privileged - expected)
            out['roles_differing'] = sorted(r['name'] for r in manifest['roles'] if differs(r))
            out['memberships_match'] = sorted([m['role'], m['member_name'], m['admin'], m['inherit'], m['set']]
                                              for m in _memberships(c, names)) == manifest['memberships']
        out['ok'] = (out['ok'] and out['privileges_match'] and out['memberships_match']
                     and not out['roles_differing'])
        return out

    def _signed_alone(self, s3, key):
        """For picking the newest dump: False if `key` is one version whose signature doesn't verify
        (from its metadata and S3's checksum; _fetch checks the bytes); None if it has more than one
        version or a delete marker (picked, then refused); True otherwise."""
        versions, markers = [], []
        for page in s3.get_paginator('list_object_versions').paginate(Bucket=self.bucket, Prefix=key):
            versions += [v for v in page.get('Versions', []) if v['Key'] == key]
            markers += [m for m in page.get('DeleteMarkers', []) if m['Key'] == key]
        signed = any([self._version_signed(s3, key, v['VersionId']) for v in versions])     # each read
        if len(versions) == 1 and not markers:
            return signed
        # Shadowed or hidden: chosen (and refused) only if a genuine dump is under it; junk put twice
        # under a new key is skipped like junk put once.
        return None if signed else False

    def _version_signed(self, s3, key, version) -> bool:
        """True or False from metadata actually read; Unreadable if S3 wouldn't say (an error is
        not a bad signature: skipping on one would fall back to an older dump)."""
        try:
            h = s3.head_object(Bucket=self.bucket, Key=key, VersionId=version, ChecksumMode='ENABLED')
        except (ClientError, BotoCoreError) as e:
            raise Unreadable(key) from e
        try:
            sha = base64.b64decode(h['ChecksumSHA256']).hex()
        except (KeyError, ValueError, TypeError):
            return False
        meta = h.get('Metadata', {})
        claim = _dump_claim(key, sha, meta.get('snapshot-at'), meta.get('schema-revision'))
        return any(verify(claim, meta.get('signature'), k) for k in self.trusted_keys)

    def _fetch(self, s3, identities, key):
        """→ (report so far, the pg_dump archive or None if refused, the roles manifest)."""
        key_was_chosen, skipped = key is None, []
        if key is None:
            # From the version listing, delete markers included: a marker hiding the newest dump
            # would otherwise make this fall back to an older one without a word. Picked, the hidden
            # one is then refused below (not_one_version).
            keys = {o['Key'] for page in s3.get_paginator('list_object_versions').paginate(
                Bucket=self.bucket, Prefix=DUMPS) for o in page.get('Versions', []) + page.get('DeleteMarkers', [])}
            # Dated keys: the newest sorts last. One whose signature doesn't verify (anyone with the
            # write key can put one) is skipped and reported, so it can't block every default drill or
            # rebuild; one shadowed or hidden by a delete marker is chosen, and refused below.
            skipped, key = [], None
            for k in sorted(keys, reverse=True):
                try:
                    if self._signed_alone(s3, k) is False:
                        skipped.append(k)
                        continue
                except Unreadable:
                    return {'ok': False, 'reason': 'candidate_unreadable', 'object_key': k,
                            'skipped_unsigned': skipped}, None, None
                key = k
                break
            if key is None:
                return {'ok': False, 'reason': 'no_dump', 'skipped_unsigned': skipped}, None, None
        # A dump is written once. Another version (or a delete marker) on its key is someone with the
        # write key shadowing the locked one; refuse rather than pick. The version read is pinned.
        versions, markers = [], []
        for page in s3.get_paginator('list_object_versions').paginate(Bucket=self.bucket, Prefix=key):
            versions += [v for v in page.get('Versions', []) if v['Key'] == key]
            markers += [m for m in page.get('DeleteMarkers', []) if m['Key'] == key]
        if len(versions) != 1 or markers:
            return {'ok': False, 'reason': 'not_one_version', 'object_key': key, 'versions': len(versions),
                    'delete_markers': len(markers)}, None, None
        obj = s3.get_object(Bucket=self.bucket, Key=key, VersionId=versions[0]['VersionId'], ChecksumMode='ENABLED')
        sealed = obj['Body'].read()
        sha = hashlib.sha256(sealed).hexdigest()
        meta = obj['Metadata']
        out = {'object_key': key, 'sha256': sha, 'expected_revision': meta.get('schema-revision')}
        if key_was_chosen and skipped:
            out['skipped_unsigned'] = skipped
        if obj.get('ChecksumSHA256') != _b64(sha):
            return {**out, 'ok': False, 'reason': 'sha256_mismatch'}, None, None
        # Before anything is decrypted or restored: signed by ctl-1, for this key, these bytes.
        claim = _dump_claim(key, sha, meta.get('snapshot-at'), meta.get('schema-revision'))
        if not self.trusted_keys:
            return {**out, 'ok': False, 'reason': 'no_trusted_key'}, None, None
        if not any(verify(claim, meta.get('signature'), k) for k in self.trusted_keys):
            return {**out, 'ok': False, 'reason': 'signature_invalid'}, None, None
        out['snapshot_at'] = datetime.fromisoformat(meta['snapshot-at'])
        try:
            dump, manifest = _unpack(pyrage.decrypt(sealed, list(identities)))
        except pyrage.DecryptError:
            return {**out, 'ok': False, 'reason': 'cannot_decrypt'}, None, None
        except (tarfile.TarError, KeyError, AttributeError, ValueError):
            return {**out, 'ok': False, 'reason': 'not_a_dump'}, None, None
        return out, dump, manifest

    def _check(self, c, s3, out):
        """Schema revision, hash chain and anchors of a restored database; sets out['ok']."""
        out['schema_revision'] = schema_revision(c)
        out['first_bad_seq'] = audit.verify_chain(c)
        out['last_seq'] = c.execute('SELECT max(seq) AS m FROM audit_event').fetchone()['m']
        out.update(check_anchors(c, bucket_anchors(s3, self.bucket), out.get('snapshot_at')))
        out['ok'] = (out['schema_revision'] is not None and out['schema_revision'] == out['expected_revision']
                     and out['first_bad_seq'] is None and not out['mismatched'] and not out['stale'])

    # -- drill ---------------------------------------------------------------------------
    def operational_identities(self) -> list:
        """Every active region's operational restore key, opened by the vault."""
        if self.store.vault is None:
            raise RuntimeError('the drill needs the dispatcher\'s vault')
        with self.store.connect() as c:
            refs = c.execute("SELECT restore_key_ref FROM region WHERE status = 'active' "
                             'AND restore_key_ref IS NOT NULL ORDER BY code').fetchall()
            return [pyrage.x25519.Identity.from_str(self.store.vault._open(c, r['restore_key_ref'], 'restore key'))
                    for r in refs]

    def drill(self, operator_id, target_dsn, recovery_identity=None, key=None) -> dict:
        """The control-plane drill into `target_dsn`, an empty database on a
        temporary server. `recovery_identity`: the reconstructed recovery key;
        otherwise the operational keys."""
        params = conninfo_to_dict(target_dsn)
        target = '%s:%s/%s' % (params.get('host'), params.get('port') or 5432, params.get('dbname'))
        started = time.monotonic()
        own = _cluster(self.owner_dsn)          # ctl-1's own database down: an error, not the target's
        try:
            same = _cluster(target_dsn) == own
            out = None
        except psycopg.Error as e:              # unreachable: a failed drill, recorded like any other
            same, out = False, {'ok': False, 'reason': 'target_unreachable', 'detail': type(e).__name__}
        if same:
            raise ValueError('the drill target is ctl-1\'s own cluster: use a temporary server')
        if out is None:
            try:
                identities = [recovery_identity] if recovery_identity else self.operational_identities()
                out = self.verify(target_dsn, identities, key=key) if identities else {'ok': False, 'reason': 'no_key'}
            except Exception as e:
                out = {'ok': False, 'reason': 'error', 'detail': type(e).__name__}
        seconds = int(time.monotonic() - started)
        now = self.store.clock()
        at = _ts(now)
        drill_id = uuid.uuid4()
        report = {'v': 1, 'drill_id': str(drill_id), 'target': target, 'measured_seconds': seconds,
                  'key_kind': 'recovery' if recovery_identity else 'operational', 'at': at.isoformat(),
                  **{k: v for k, v in out.items() if k != 'detail'}}
        with self.store.connect() as c:
            evidence = None
            try:
                body = json.dumps(report, sort_keys=True, default=str).encode()
                rkey = '%s%s-%s.json' % (DRILLS, at.strftime('%Y%m%dT%H%M%SZ'), drill_id)
                stored = self._put_locked(self._s3(), rkey, body, at + timedelta(days=DRILL_LOCK_DAYS))
                evidence = uuid.uuid4()
                with c.transaction():       # a savepoint: a failed insert mustn't abort the drill's record
                    c.execute("INSERT INTO evidence_artifact (id, kind, uri, sha256, produced_by, produced_at) "
                              "VALUES (%s, 'restore_drill', %s, %s, %s, %s)",
                              (evidence, 's3://%s/%s?versionId=%s' % (self.bucket, rkey, stored['version_id']),
                               stored['sha256'], operator_id, at))
            except Exception as e:      # the drill is recorded either way; without evidence it can't pass
                evidence = None
                report['ok'], report['reason'] = False, report.get('reason') or 'evidence_not_stored'
                report['evidence_error'] = type(e).__name__
            c.execute('INSERT INTO ctl_drill (id, dump_object_key, dump_sha256, key_kind, target, expected_revision, '
                      'schema_revision, first_bad_seq, anchors_matched, anchors_mismatched, anchors_beyond, result, '
                      'reason, measured_seconds, evidence_id, run_by, created_at) '
                      'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                      (drill_id, report.get('object_key'), report.get('sha256'), report['key_kind'], target,
                       report.get('expected_revision'), report.get('schema_revision'), report.get('first_bad_seq'),
                       report.get('matched'), len(report['mismatched']) if 'mismatched' in report else None,
                       report.get('beyond'), 'pass' if report['ok'] else 'fail', report.get('reason'), seconds,
                       evidence, operator_id, at))
            audit.append(c, at, 'ctl.drill_passed' if report['ok'] else 'ctl.drill_failed', actor_kind='operator',
                         actor_id=operator_id, resource_type='ctl_drill', resource_id=drill_id,
                         after={'reason': report.get('reason'), 'object_key': report.get('object_key')})
            if not report['ok']:
                c.execute("INSERT INTO incident (id, severity, summary, runbook_ref, opened_at) "
                          "VALUES (%s, 'sev2', %s, 'RB-10', %s)",
                          (uuid.uuid4(), 'control-plane drill failed: %s' % report.get('reason', 'checks'), at))
        return report

    # -- schedule ------------------------------------------------------------------------
    def run_once(self) -> dict:
        now = datetime.fromtimestamp(self.store.clock(), timezone.utc)
        day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        out = {}
        with self.store.connect() as c:
            # Bounded by now: a row dated in the future (whoever can insert one) mustn't count as done.
            dumped = c.execute("SELECT 1 FROM ctl_dump WHERE reason = 'scheduled' AND created_at >= %s "
                               'AND created_at <= %s', (day, now)).fetchone()
            anchored = c.execute('SELECT 1 FROM audit_anchor WHERE anchored_at >= %s AND anchored_at <= %s',
                                 (day, now)).fetchone()
        if not dumped and (now.hour, now.minute) >= DUMP_AT:
            out['dump'] = self._attempt(self.dump)
        if not anchored and (now.hour, now.minute) >= ANCHOR_AT:
            out['anchor'] = self._attempt(self.anchor)
        if any(v.get('state') == 'error' for v in out.values()):
            raise JobFailed(out)        # both were tried; the worker counts the failure (main.Workers)
        return out

    @staticmethod
    def _attempt(job):
        """A failure is retried next round; the 26-hour alerts catch one that keeps failing."""
        try:
            return job()
        except Exception as e:
            return {'state': 'error', 'error': type(e).__name__}
