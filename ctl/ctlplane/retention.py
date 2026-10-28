"""Backup retention (DOC-05 §3): delete tenant backups past their Object Lock,
in batches the backup custodian approves (DOC-03 §7, DOC-04 §2).

Per environment, the newest recoverable backups of each tier are kept: 7
daily, 4 weekly, 3 monthly; other tiers (pre_update, final, …) aren't kept
past their lock. Nothing is kept for an environment that has been removed
(Delete, RestoreCopy.Expire): its data is gone at its last `lock_until`
(DOC-03 §5). A candidate's lock has passed by at least LOCK_MARGIN, and no
operation in flight refers to it (a restore, a DR-06 precondition).
Completed backups whose evidence failed are cleaned up the same way, if an
object was stored.

    draft      ctl-1 lists the candidates; the batch body (action, batch id,
               SHA-256 of the items, expiry) is what the custodian signs
    approve    the custodian's signature (or break-glass while enabled: sev2)
    execute    every item is checked again, then that object version is
               deleted with the region's retention key; the point becomes
               `expired`. Nothing runs while `retention_frozen` is set
               (DOC-07 RB-04).

Control-plane dumps in bucket C (cpbackup) go in the same batches: the newest
30 daily-tier and 12 monthly dumps are kept, others once their lock has passed
by LOCK_MARGIN; they are deleted with bucket C's retention key and recorded
in `ctl_dump_expired`.

The region's retention key (and bucket C's) needs listFiles, readFiles and
deleteFiles on its bucket: readFiles because a backup left `expiring` (a
delete that never answered) is settled by reading its version (`_settle`);
without it the batch waits, with a sev2 incident.

Compliance-mode Object Lock refuses a delete before `lock_until` whatever
key is used; the approval guards the last backups once their locks lapse.
"""
import base64
import json
import uuid
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from nacl.signing import VerifyKey
from psycopg.types.json import Jsonb

from . import audit
from .admission import Refused
from .canonical import sha256_hex, verify, without
from .store import Store, _ts

KEEP = {'daily': 7, 'weekly': 4, 'monthly': 3}
CTL_KEEP = {'daily': 30, 'monthly': 12}
LOCK_MARGIN = 3600
APPROVAL_TTL = 48 * 3600
ACTION = 'Backup.Retention'
_EXECUTE_LOCK = 0x726574656e74     # "retent": one execution at a time, across its per-item commits
IN_FLIGHT = ('REQUESTED', 'VALIDATED', 'RESERVED', 'DISPATCHED', 'APPLYING', 'VERIFIED', 'RECONCILING',
             'RECOVERING')


def object_key(tenant_id, environment_id, backup_id) -> str:
    """As the agent uploads it (hostagent.s3.object_key; tests/test_contract.py)."""
    return 'tenants/%s/%s/%s.tar.age' % (tenant_id, environment_id, backup_id)


def candidates(c, now: float, environment_id=None) -> list[dict]:
    """`environment_id`: only that environment's (its keep counts are per environment)."""
    referenced = {str(r['b']) for r in c.execute(
        "SELECT precondition_backup_id AS b FROM operation WHERE precondition_backup_id IS NOT NULL "
        'AND state = ANY(%s) UNION SELECT (params->>%s)::uuid FROM operation '
        "WHERE type IN ('Tenant.RestoreToIsolated', 'Tenant.RestoreProduction', 'Tenant.Export') AND state = ANY(%s)",
        (list(IN_FLIGHT), 'backup_id', list(IN_FLIGHT))).fetchall() if r['b']}
    rows = c.execute(
        'SELECT b.*, e.tenant_id, e.observed_state, t.lifecycle_state, g.backup_bucket, g.id AS region_id '
        'FROM backup_point b JOIN environment e ON e.id = b.environment_id JOIN tenant t ON t.id = e.tenant_id '
        'LEFT JOIN host h ON h.id = e.app_host_id LEFT JOIN region g ON g.id = h.region_id '
        "WHERE b.state IN ('recoverable', 'failed') AND (%s::uuid IS NULL OR b.environment_id = %s::uuid) "
        'ORDER BY b.environment_id, b.snapshot_at DESC NULLS LAST', (environment_id, environment_id)).fetchall()
    kept, seen = set(), {}
    for r in rows:
        live = r['observed_state'] != 'absent' and r['lifecycle_state'] != 'DELETED'
        if r['state'] == 'recoverable' and live:
            n = seen.setdefault((r['environment_id'], r['retention_tier']), 0)
            if n < KEEP.get(r['retention_tier'], 0):
                kept.add(r['id'])
            seen[(r['environment_id'], r['retention_tier'])] = n + 1
    out = []
    for r in rows:
        if (r['id'] in kept or str(r['id']) in referenced or not r['object_version_id'] or r['lock_until'] is None
                or r['lock_until'].timestamp() > now - LOCK_MARGIN or not r['backup_bucket']):
            continue
        out.append({'backup_point_id': str(r['id']), 'region_id': str(r['region_id']), 'bucket': r['backup_bucket'],
                    'key': object_key(r['tenant_id'], r['environment_id'], r['id']),
                    'version_id': r['object_version_id'], 'lock_until': r['lock_until'].isoformat(),
                    'tier': r['retention_tier'], 'state': r['state']})
    return out


def ctl_candidates(c, now: float) -> list[dict]:
    # Rows dated after now (forged) neither take the newest slots nor become candidates.
    rows = c.execute('SELECT * FROM ctl_dump d WHERE NOT EXISTS '
                     '(SELECT 1 FROM ctl_dump_expired x WHERE x.ctl_dump_id = d.id) AND d.created_at <= %s '
                     'ORDER BY d.created_at DESC, d.id', (_ts(now),)).fetchall()
    seen, out = {}, []
    for r in rows:
        n = seen[r['tier']] = seen.get(r['tier'], 0) + 1
        if n <= CTL_KEEP[r['tier']] or r['lock_until'].timestamp() > now - LOCK_MARGIN:
            continue
        out.append({'ctl_dump_id': str(r['id']), 'bucket': r['bucket'], 'key': r['object_key'],
                    'version_id': r['object_version_id'], 'lock_until': r['lock_until'].isoformat(),
                    'tier': r['tier']})
    return out


def _item_id(item) -> str:
    return item.get('backup_point_id') or item['ctl_dump_id']


def _flag(c, name) -> str | None:
    row = c.execute('SELECT value FROM ctl_flag WHERE name = %s', (name,)).fetchone()
    return row and row['value']


class Retention:
    def __init__(self, store: Store, *, s3_endpoint: str = '', s3_region: str = 'eu-central-003',
                 breakglass_enabled: bool = False, ctl_retention_key: dict | None = None):
        """`store` must be able to open secrets (the dispatcher's role and vault):
        executing needs the region's retention key. `ctl_retention_key`:
        {key_id, secret}, bucket C's delete-capable key, configuration like
        cpbackup's write key."""
        self.store = store
        self.ctl_retention_key = ctl_retention_key
        self.s3_endpoint = s3_endpoint
        self.s3_region = s3_region
        self.breakglass_enabled = breakglass_enabled

    def draft(self) -> dict | None:
        """The batch awaiting the custodian: the one drafted until it expires (a signature takes
        time; replacing it every round would leave nothing to approve), then a new one of
        everything deletable now. Backups that became deletable meanwhile wait for the next."""
        now = self.store.clock()
        with self.store.connect() as c:
            if c.execute("SELECT 1 FROM retention_batch WHERE state = 'approved'").fetchone():
                return None                     # executes first
            pending = c.execute("SELECT body, items FROM retention_batch WHERE state = 'drafted'").fetchone()
            if pending and datetime.fromisoformat(pending['body']['expires_at']).timestamp() >= now:
                return {'body': pending['body'], 'items': pending['items']}
            c.execute("UPDATE retention_batch SET state = 'abandoned' WHERE state = 'drafted'")
            items = candidates(c, now) + ctl_candidates(c, now)
            if not items:
                return None
            batch = str(uuid.uuid4())
            body = {'v': 1, 'action': ACTION, 'batch_id': batch, 'count': len(items),
                    'items_sha256': sha256_hex(items),
                    'expires_at': datetime.fromtimestamp(now + APPROVAL_TTL, timezone.utc).isoformat()}
            c.execute("INSERT INTO retention_batch (id, body, items, state, drafted_at) VALUES (%s, %s, %s, 'drafted', %s)",
                      (batch, Jsonb(body), Jsonb(items), _ts(now)))
            audit.append(c, _ts(now), 'retention.drafted', resource_type='retention_batch', resource_id=batch,
                         after={'count': len(items), 'items_sha256': body['items_sha256']})
            return {'body': body, 'items': items}

    def approve(self, operator_id, batch_id, approval) -> dict:
        now = self.store.clock()
        with self.store.connect() as c:
            row = c.execute("SELECT * FROM retention_batch WHERE id = %s AND state = 'drafted' FOR UPDATE",
                            (batch_id,)).fetchone()
            if row is None:
                raise Refused('NOT_FOUND')
            if not isinstance(approval, dict) or without(approval, 'custodian_signature') != row['body']:
                raise Refused('CONFLICT', {'detail': 'not this batch'})
            if datetime.fromisoformat(row['body']['expires_at']).timestamp() < now:
                raise Refused('EXPIRED')
            signer = self._signer(c, row['body'], approval)
            if signer is None:
                raise Refused('SIG_INVALID')
            breakglass = signer == 'breakglass'
            c.execute("UPDATE retention_batch SET state = 'approved', approval = %s, approved_by = %s, "
                      'breakglass_used = %s WHERE id = %s', (Jsonb(approval), operator_id, breakglass, batch_id))
            if breakglass:
                c.execute("INSERT INTO incident (id, severity, summary, runbook_ref, opened_at) "
                          "VALUES (%s, 'sev2', 'break-glass approval of a backup retention batch', 'DOC-07', %s)",
                          (uuid.uuid4(), _ts(now)))
            audit.append(c, _ts(now), 'retention.approved', actor_kind='operator', actor_id=operator_id,
                         resource_type='retention_batch', resource_id=batch_id,
                         after={'breakglass': breakglass, 'count': row['body']['count']})
            return {'batch_id': batch_id, 'state': 'approved'}

    def _signer(self, c, body, approval) -> str | None:
        """'custodian' or 'breakglass' (while enabled) if `approval` is `body` signed by an
        active key of that purpose; None otherwise."""
        if not isinstance(approval, dict) or without(approval, 'custodian_signature') != body:
            return None
        keys = c.execute("SELECT purpose, public_key FROM signing_key WHERE purpose IN ('custodian', 'breakglass') "
                         'AND retired_at IS NULL').fetchall()
        sig = approval.get('custodian_signature')
        ok = lambda purpose: any(k['purpose'] == purpose and verify(body, sig,  # noqa: E731
                                                                    VerifyKey(base64.b64decode(k['public_key'])))
                                 for k in keys)
        if ok('custodian'):
            return 'custodian'
        return 'breakglass' if self.breakglass_enabled and ok('breakglass') else None

    def set_frozen(self, operator_id, frozen: bool):
        now = self.store.clock()
        with self.store.connect() as c:
            c.execute('INSERT INTO ctl_flag (name, value, set_by, set_at) VALUES (%s, %s, %s, %s) '
                      'ON CONFLICT (name) DO UPDATE SET value = excluded.value, set_by = excluded.set_by, '
                      'set_at = excluded.set_at', ('retention_frozen', 'true' if frozen else 'false', operator_id,
                                                   _ts(now)))
            audit.append(c, _ts(now), 'retention.frozen' if frozen else 'retention.unfrozen', actor_kind='operator',
                         actor_id=operator_id)

    def execute(self) -> dict | None:
        """Run the approved batch, if any. → its results."""
        now = self.store.clock()
        with self.store.connect() as c:
            frozen = _flag(c, 'retention_frozen') == 'true'
            c.commit()
            # Session-level, so it outlives the per-item commits: two executors (a worker overlap
            # after a lost leadership connection) never interleave on a batch.
            if not c.execute('SELECT pg_try_advisory_lock(%s) AS ok', (_EXECUTE_LOCK,)).fetchone()['ok']:
                return {'busy': True}
            try:
                if frozen:
                    # Nothing is deleted while frozen, but a backup a failed delete left `expiring`
                    # is settled from the bucket: it mustn't stay unrestorable through the freeze.
                    batch = c.execute("SELECT * FROM retention_batch WHERE state = 'approved'").fetchone()
                    if batch is not None:
                        unresolved = self._settle(c, batch, {})
                        if unresolved:
                            self._unresolved_incident(c, batch['id'], unresolved, now)
                    return {'frozen': True}
                return self._execute(c, now)
            finally:
                c.rollback()
                c.execute('SELECT pg_advisory_unlock(%s)', (_EXECUTE_LOCK,))
                c.commit()

    def _execute(self, c, now):
        """Commits as it goes; the caller rolls back what is left and releases the lock."""
        batch = c.execute("SELECT * FROM retention_batch WHERE state = 'approved'").fetchone()
        if batch is None:
            return None
        if sha256_hex(batch['items']) != batch['body']['items_sha256']:
            raise RuntimeError('retention batch items changed after approval')
        # The row's state isn't proof: whoever can write the table could set it. The custodian's
        # signature over this very body (batch, action, items hash) is checked again here.
        signer = self._signer(c, batch['body'], batch['approval'])
        if (signer is None or (signer == 'breakglass') != batch['breakglass_used']
                or batch['body'].get('batch_id') != str(batch['id']) or batch['body'].get('action') != ACTION):
            c.execute("INSERT INTO incident (id, severity, summary, runbook_ref, opened_at) VALUES "
                      "(%s, 'sev1', %s, 'RB-09', %s)", (uuid.uuid4(), 'retention batch %s is approved but its '
                                                        'approval does not verify' % batch['id'], _ts(now)))
            c.commit()
            raise RuntimeError('retention batch %s: approval does not verify' % batch['id'])
        # The custodian approved deleting these until expires_at: not whenever execution gets there (a
        # freeze, workers stopped, a long batch). Checked again before each delete; abandoned, the next
        # round drafts afresh.
        expires = datetime.fromisoformat(batch['body']['expires_at']).timestamp()
        # Outcomes committed by an earlier run of this batch (it stopped midway): kept, not redone.
        done = batch['results'] or {}
        clients, expired, frozen = {}, False, False
        for item in batch['items']:
            ident, region = _item_id(item), item.get('region_id')
            if done.get(ident) == 'deleted':
                continue
            try:
                resuming = False
                if region:
                    # Under this lock (held until the commit below), a restore admitted meanwhile shows
                    # as a reference; one admitted after waits for it and sees the backup expiring.
                    row = c.execute('SELECT state, retention_batch_id FROM backup_point WHERE id = %s FOR UPDATE',
                                    (ident,)).fetchone()
                    # This batch marked it and stopped (a crash) before recording the outcome.
                    resuming = (row is not None and row['state'] == 'expiring'
                                and str(row['retention_batch_id']) == str(batch['id']))
                if self._frozen(c):
                    frozen = True
                    break
                now = self.store.clock()
                if now > expires:
                    expired = True
                    break
                if not resuming:
                    # This item's environment only: not the whole fleet per item, under the locks.
                    still = candidates(c, now, item['key'].split('/')[2]) if region else ctl_candidates(c, now)
                    if ident not in {_item_id(i) for i in still}:
                        self._record(c, batch['id'], ident, 'no_longer_deletable')
                        continue
                if region and not resuming:
                    # Committed before S3 is touched: a crash after the delete leaves an `expiring` point
                    # (admission takes only `recoverable`) that the next run finishes, never a
                    # `recoverable` one with no object.
                    c.execute("UPDATE backup_point SET state = 'expiring', retention_batch_id = %s WHERE id = %s",
                              (batch['id'], ident))
                    c.commit()
                    if self._frozen(c):         # frozen meanwhile: put it back
                        self._unmark(c, ident, item)
                        frozen = True
                        break
                try:
                    s3 = clients.get(region) or (self._client(c, region) if region else self._ctl_client())
                    clients[region] = s3
                    s3.delete_object(Bucket=item['bucket'], Key=item['key'], VersionId=item['version_id'])
                except ClientError as e:
                    code = e.response['Error'].get('Code', 'error')
                    if not (code in ('NoSuchVersion', 'NoSuchKey') and (resuming or not region)):
                        # An error from S3 doesn't say the version is still there: boto3 retries
                        # inside one call, and the first request may have deleted it. It stays
                        # `expiring`; _settle reads the bucket before the batch closes.
                        self._record(c, batch['id'], ident, code)
                        continue
                    # Already gone: the run that stopped had deleted it.
                except Refused as r:          # raised before any request: nothing was sent
                    if region and not resuming:
                        self._unmark(c, ident, item)
                    self._record(c, batch['id'], ident, r.code)
                    continue
                if region:
                    c.execute("UPDATE backup_point SET state = 'expired', expired_at = %s, retention_batch_id = %s "
                              'WHERE id = %s', (_ts(now), batch['id'], ident))
                else:
                    c.execute('INSERT INTO ctl_dump_expired (ctl_dump_id, batch_id, expired_at) '
                              'VALUES (%s, %s, %s) ON CONFLICT DO NOTHING', (ident, batch['id'], _ts(now)))
                self._record(c, batch['id'], ident, 'deleted')        # in the same commit as the expiry
            finally:
                c.commit()              # one item at a time: the lock is short, progress survives a crash
        now = self.store.clock()
        # Before the batch is closed, frozen or left: a point it left `expiring` (a delete that failed,
        # was refused on resume, or never answered) is settled from what the bucket holds, so none
        # stays unrestorable and undeletable.
        unresolved = self._settle(c, batch, clients, 'approval_expired' if expired else None)
        if unresolved:
            self._unresolved_incident(c, batch['id'], unresolved, now)
            if not frozen:              # S3 couldn't say: stays approved, settled next round
                return {'expired': expired, 'unresolved': unresolved}
        if frozen:                      # stays approved: it resumes once unfrozen
            results = c.execute('SELECT results FROM retention_batch WHERE id = %s',
                                (batch['id'],)).fetchone()['results'] or {}
            c.commit()
            return {'frozen': True, 'results': results}
        state, action = ('abandoned', 'retention.approval_expired') if expired else ('executed', 'retention.executed')
        # The results as stored, not this run's view: they include an earlier run's.
        results = c.execute('UPDATE retention_batch SET state = %s, executed_at = CASE WHEN %s THEN %s END '
                            'WHERE id = %s RETURNING results', (state, not expired, _ts(now), batch['id'])
                            ).fetchone()['results'] or {}
        audit.append(c, _ts(now), action, resource_type='retention_batch', resource_id=batch['id'],
                     after={'results': results})
        c.commit()
        return {'expired': True, 'results': results} if expired else results

    def _settle(self, c, batch, clients, outcome=None) -> int:
        """Points of this batch still `expiring` (their delete failed, was refused on resume, or the
        process stopped): each goes back to what it was if its version is still in the bucket, or
        to `expired` if it isn't (`outcome` recorded for one put back; None keeps what the delete
        recorded, e.g. AccessDenied). → how many S3 couldn't answer for."""
        unresolved = 0
        for item in batch['items']:
            region = item.get('region_id')
            if not region:
                continue
            ident = item['backup_point_id']
            try:
                row = c.execute('SELECT state, retention_batch_id FROM backup_point WHERE id = %s FOR UPDATE',
                                (ident,)).fetchone()
                if not (row and row['state'] == 'expiring' and str(row['retention_batch_id']) == str(batch['id'])):
                    continue
                try:
                    s3 = clients.get(region) or self._client(c, region)
                    clients[region] = s3
                    s3.head_object(Bucket=item['bucket'], Key=item['key'], VersionId=item['version_id'])
                except ClientError as e:
                    if e.response['Error'].get('Code') not in ('404', 'NoSuchKey', 'NoSuchVersion', 'NotFound'):
                        unresolved += 1
                        continue
                    c.execute("UPDATE backup_point SET state = 'expired', expired_at = %s WHERE id = %s",
                              (_ts(self.store.clock()), ident))
                    self._record(c, batch['id'], ident, 'deleted')
                    continue
                except (BotoCoreError, Refused):
                    unresolved += 1
                    continue
                self._unmark(c, ident, item)
                if outcome:
                    self._record(c, batch['id'], ident, outcome)
            finally:
                c.commit()
        return unresolved

    @staticmethod
    def _unresolved_incident(c, batch_id, n, now):
        """Once while open: the retention key can't read the bucket (HeadObject needs B2's readFiles),
        or S3 is down; retention waits on this batch until it can settle it."""
        summary = 'retention batch %s: %d backup(s) left expiring, S3 cannot say whether deleted' % (batch_id, n)
        if not c.execute('SELECT 1 FROM incident WHERE summary = %s AND resolved_at IS NULL', (summary,)).fetchone():
            c.execute("INSERT INTO incident (id, severity, summary, runbook_ref, opened_at) VALUES "
                      "(%s, 'sev2', %s, 'RB-04', %s)", (uuid.uuid4(), summary, _ts(now)))
        c.commit()

    @staticmethod
    def _frozen(c) -> bool:
        """FOR SHARE until the item's commit: a freeze (set_frozen updates this row) waits for the
        item in hand, and no delete starts once it is committed."""
        row = c.execute("SELECT value FROM ctl_flag WHERE name = 'retention_frozen' FOR SHARE").fetchone()
        return bool(row) and row['value'] == 'true'

    @staticmethod
    def _unmark(c, ident, item):
        """Back to what it was (recoverable, or failed) when its object wasn't deleted."""
        c.execute("UPDATE backup_point SET state = %s, retention_batch_id = NULL WHERE id = %s AND state = 'expiring'",
                  (item['state'], ident))

    @staticmethod
    def _record(c, batch_id, ident, outcome):
        """An item's outcome, durably; a 'deleted' is final and never overwritten."""
        c.execute("UPDATE retention_batch SET results = COALESCE(results, '{}'::jsonb) "
                  '|| jsonb_build_object(%s::text, %s::text) '
                  "WHERE id = %s AND COALESCE(results->>%s, '') <> 'deleted'", (ident, outcome, batch_id, ident))

    def _client(self, c, region_id):
        region = c.execute('SELECT retention_key_ref FROM region WHERE id = %s', (region_id,)).fetchone()
        if self.store.vault is None or region is None or region['retention_key_ref'] is None:
            raise Refused('SECRET_UNAVAILABLE')
        try:
            key = json.loads(self.store.vault._open(c, region['retention_key_ref'], 'b2_retention_key'))
        except Exception:
            raise Refused('SECRET_UNAVAILABLE') from None
        return boto3.client('s3', endpoint_url=self.s3_endpoint or None, region_name=self.s3_region,
                            aws_access_key_id=key['key_id'], aws_secret_access_key=key['secret'],
                            config=Config(retries={'max_attempts': 3}))

    def _ctl_client(self):
        if not self.ctl_retention_key:
            raise Refused('SECRET_UNAVAILABLE')
        return boto3.client('s3', endpoint_url=self.s3_endpoint or None, region_name=self.s3_region,
                            aws_access_key_id=self.ctl_retention_key['key_id'],
                            aws_secret_access_key=self.ctl_retention_key['secret'],
                            config=Config(retries={'max_attempts': 3}))

    def run_once(self):
        """Execute an approved batch; otherwise draft one for the custodian."""
        return self.execute() or self.draft()
