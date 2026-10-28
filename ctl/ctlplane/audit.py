"""audit_event [AO] with its hash chain (DOC-03 §2.9, SEC-13):
hash = SHA-256(prev_hash ‖ canonical(row)). Appends are serialised by a
transaction-scoped advisory lock, so the chain never forks."""
import hashlib
from datetime import datetime, timezone

from psycopg.types.json import Jsonb

from .canonical import canonical

GENESIS = b'\0' * 32
_LOCK = 0x617564697400   # "audit"


def _row(at: datetime, actor_kind, actor_id, action, tenant_id, resource_type, resource_id, before, after,
         correlation_id) -> dict:
    s = lambda v: str(v) if v is not None else None
    # In UTC whatever the session's TimeZone, or a restored copy read elsewhere wouldn't verify.
    return {'at': at.astimezone(timezone.utc).isoformat(), 'actor_kind': actor_kind, 'actor_id': s(actor_id),
            'action': action, 'tenant_id': s(tenant_id), 'resource_type': resource_type, 'resource_id': s(resource_id),
            'before': before, 'after': after, 'correlation_id': s(correlation_id)}


def append(c, at: datetime, action: str, *, actor_kind='system', actor_id=None, tenant_id=None,
           resource_type=None, resource_id=None, before=None, after=None, correlation_id=None):
    c.execute('SELECT pg_advisory_xact_lock(%s)', (_LOCK,))
    last = c.execute('SELECT hash FROM audit_event ORDER BY seq DESC LIMIT 1').fetchone()
    prev = bytes(last['hash']) if last else GENESIS
    row = _row(at, actor_kind, actor_id, action, tenant_id, resource_type, resource_id, before, after,
               correlation_id)
    digest = hashlib.sha256(prev + canonical(row)).digest()
    c.execute('INSERT INTO audit_event (at, actor_kind, actor_id, action, tenant_id, resource_type, resource_id, '
              'before, after, correlation_id, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
              (at, actor_kind, actor_id, action, tenant_id, resource_type, resource_id,
               Jsonb(before) if before is not None else None, Jsonb(after) if after is not None else None,
               correlation_id, prev, digest))


def verify_chain(c) -> int | None:
    """The seq of the first row that doesn't chain, or None."""
    prev = GENESIS
    for r in c.execute('SELECT * FROM audit_event ORDER BY seq').fetchall():
        row = _row(r['at'], r['actor_kind'], r['actor_id'], r['action'], r['tenant_id'], r['resource_type'],
                   r['resource_id'], r['before'], r['after'], r['correlation_id'])
        if bytes(r['prev_hash']) != prev or bytes(r['hash']) != hashlib.sha256(prev + canonical(row)).digest():
            return r['seq']
        prev = bytes(r['hash'])
    return None
