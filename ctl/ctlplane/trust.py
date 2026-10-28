"""Fleet trust documents for Host.RotateTrust (DOC-04 §2).

A document lists the keys every agent pins: dispatch (two during the 7-day
overlap of a rotation), custodian, break-glass, and every enrolled agent's
key (to verify backup manifests signed on another host). ctl-1 drafts it
from `signing_key`; the founder signs it offline with the release key; ctl-1
then sends it to each host in a Host.RotateTrust envelope signed with the
current dispatch key. Versions only go up, and agents refuse a document that
drops the dispatch key signing the request.

Rotating the dispatch key:
  1. register the new key in `signing_key` (purpose dispatch);
  2. draft, sign and roll out a document with both keys;
  3. when every host reports that version, switch ctl-1 to the new key;
  4. retire the old key, then draft, sign and roll out a document without it.
"""
import base64
from datetime import datetime, timezone

from nacl.signing import VerifyKey
from psycopg.types.json import Jsonb

from . import audit
from .admission import Refused
from .canonical import sha256_hex, verify, without
from .store import Store, _ts

ENROLLED = "client_cert_sha256 IS NOT NULL AND state IN ('active', 'draining', 'maintenance')"
ENROLLED_H = "h.client_cert_sha256 IS NOT NULL AND h.state IN ('active', 'draining', 'maintenance')"


def keys(c, breakglass_enabled: bool) -> dict:
    """The trust section, from the keys registered now."""
    rows = lambda purpose: [r['public_key'] for r in c.execute(  # noqa: E731
        'SELECT public_key FROM signing_key WHERE purpose = %s AND retired_at IS NULL ORDER BY created_at, id',
        (purpose,)).fetchall()]
    breakglass = rows('breakglass')
    agents = [r['public_key'] for r in c.execute(
        'SELECT k.public_key FROM host h JOIN signing_key k ON k.id = h.agent_key_id '
        'WHERE %s AND k.retired_at IS NULL ORDER BY h.id' % ENROLLED_H
    ).fetchall()]
    return {'dispatch': rows('dispatch'), 'custodian': rows('custodian'),
            'breakglass': breakglass[0] if breakglass else None, 'breakglass_enabled': breakglass_enabled,
            'agents': agents}


def active(c) -> dict | None:
    row = c.execute("SELECT signed_body FROM trust_document WHERE state = 'active'").fetchone()
    return row and row['signed_body']


def active_version(c) -> int:
    doc = active(c)
    return doc['trust_version'] if doc else 0


class Trust:
    def __init__(self, store: Store, *, breakglass_enabled: bool = False):
        self.store = store
        self.breakglass_enabled = breakglass_enabled

    def draft(self, operator_id) -> dict:
        """The next version, to be signed with the release key. A pending draft is replaced."""
        now = self.store.clock()
        with self.store.connect() as c:
            c.execute("UPDATE trust_document SET state = 'abandoned' WHERE state = 'pending'")
            version = c.execute('SELECT COALESCE(MAX(version), 0) + 1 AS v FROM trust_document').fetchone()['v']
            body = {'v': 1, 'kind': 'trust', 'trust_version': version,
                    'issued_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
                    'trust': keys(c, self.breakglass_enabled)}
            if not body['trust']['dispatch']:
                raise Refused('NO_DISPATCH_KEY')
            c.execute("INSERT INTO trust_document (version, body, state, created_by, created_at) "
                      "VALUES (%s, %s, 'pending', %s, %s)", (version, Jsonb(body), operator_id, _ts(now)))
            audit.append(c, _ts(now), 'trust.drafted', actor_kind='operator', actor_id=operator_id,
                         after={'trust_version': version, 'body_sha256': sha256_hex(body)})
        return body

    def authorize(self, operator_id, version: int, signed) -> dict:
        now = self.store.clock()
        with self.store.connect() as c:
            row = c.execute("SELECT * FROM trust_document WHERE version = %s AND state = 'pending' FOR UPDATE",
                            (version,)).fetchone()
            if row is None:
                raise Refused('NOT_FOUND')
            if not isinstance(signed, dict) or without(signed, 'release_signature') != row['body']:
                raise Refused('CONFLICT', {'detail': 'not the pending draft'})
            release = c.execute("SELECT public_key FROM signing_key WHERE purpose = 'release' AND retired_at IS NULL"
                                ).fetchall()
            if not any(verify(row['body'], signed.get('release_signature'), VerifyKey(base64.b64decode(k['public_key'])))
                       for k in release):
                raise Refused('SIG_INVALID')
            c.execute("UPDATE trust_document SET state = 'superseded' WHERE state = 'active'")
            c.execute("UPDATE trust_document SET state = 'active', signed_body = %s, authorized_at = %s "
                      'WHERE version = %s', (Jsonb(signed), _ts(now), version))
            audit.append(c, _ts(now), 'trust.authorized', actor_kind='operator', actor_id=operator_id,
                         after={'trust_version': version})
        return signed

    def status(self) -> dict:
        with self.store.connect() as c:
            hosts = c.execute('SELECT id, role, state, trust_version FROM host WHERE %s ORDER BY id' % ENROLLED
                              ).fetchall()
            return {'active_version': active_version(c),
                    'hosts': [{'host_id': str(h['id']), 'role': h['role'], 'state': h['state'],
                               'trust_version': h['trust_version']} for h in hosts]}

    def behind(self) -> list[str]:
        """Enrolled hosts not yet on the active version."""
        with self.store.connect() as c:
            v = active_version(c)
            return [str(r['id']) for r in c.execute(
                'SELECT id FROM host WHERE %s AND trust_version < %%s ORDER BY id' % ENROLLED, (v,)).fetchall()]
