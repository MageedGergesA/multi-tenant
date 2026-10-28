"""Release manifests and region secrets, as operators hand them to ctl-1.

A release manifest is signed offline with the founder's release key
(DOC-04 §2); ctl-1 only checks and stores it, and sends it verbatim in every
envelope that starts that image. It becomes `approved` only with evidence for
its own digest (INV-6); `evidence_pending` without.

Region secrets (B2 write key, operational restore key) arrive already
age-encrypted to the dispatcher's recipient: ctl-1's API never sees them in
the clear.
"""
import base64
import uuid

import jsonschema
from nacl.signing import VerifyKey
from psycopg.types.json import Jsonb

from . import audit, catalog
from .admission import Refused
from .canonical import sha256_hex, verify, without
from .store import Store, _ts

AGE_HEADER = b'age-encryption.org/v1\n'
REGION_SECRETS = {'b2_write_key': 'b2_write_key_ref', 'region_restore_key': 'restore_key_ref',
                  'b2_retention_key': 'retention_key_ref'}


def upload(store: Store, operator_id: str, manifest, evidence) -> dict:
    now = store.clock()
    try:
        jsonschema.validate(manifest, catalog.RELEASE_MANIFEST)
        if evidence is not None:
            jsonschema.validate(evidence, {'type': 'object', 'additionalProperties': False,
                                           'required': ['uri', 'sha256'],
                                           'properties': {'uri': {'type': 'string', 'maxLength': 1024},
                                                          'sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}}})
    except jsonschema.ValidationError as e:
        raise Refused('SCHEMA', {'at': '/'.join(map(str, e.path)) or '(root)'}) from None
    with store.connect() as c:
        keys = c.execute("SELECT public_key FROM signing_key WHERE purpose = 'release' AND retired_at IS NULL"
                         ).fetchall()
        body = without(manifest, 'release_signature')
        if not any(verify(body, manifest['release_signature'], VerifyKey(base64.b64decode(k['public_key'])))
                   for k in keys):
            raise Refused('SIG_INVALID')
        cell = c.execute('SELECT id, status FROM release_cell WHERE cell = %s', (manifest['cell'],)).fetchone()
        if cell is None or cell['status'] != 'available':
            raise Refused('POLICY_CELL', {'cell': manifest['cell'], 'status': cell and cell['status']})
        existing = c.execute('SELECT * FROM image_release WHERE image_digest = %s',
                             (manifest['image_digest'],)).fetchone()
        if existing is not None and existing['manifest'] != manifest:
            raise Refused('CONFLICT', {'detail': 'another manifest for this digest'})   # releases are immutable
        if existing is not None and (existing['status'] != 'evidence_pending' or evidence is None):
            return existing
        evidence_id = None
        if evidence is not None:
            evidence_id = uuid.uuid4()
            c.execute("INSERT INTO evidence_artifact (id, kind, subject_digest, uri, sha256, produced_by, produced_at) "
                      "VALUES (%s, 'release_approval', %s, %s, %s, %s, %s)",
                      (evidence_id, manifest['image_digest'], evidence['uri'], evidence['sha256'], operator_id,
                       _ts(now)))
        status = 'approved' if evidence_id else 'evidence_pending'
        if existing is None:
            release_id = uuid.uuid4()
            c.execute('INSERT INTO image_release (id, release_cell_id, image_digest, change_class, '
                      'addon_manifest_sha256, module_versions, manifest, status, approval_evidence_id, created_at) '
                      'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                      (release_id, cell['id'], manifest['image_digest'], manifest['change_class'],
                       manifest['addon_manifest_sha256'], Jsonb(manifest['module_versions']), Jsonb(manifest),
                       status, evidence_id, _ts(now)))
        else:
            release_id = existing['id']
            c.execute('UPDATE image_release SET status = %s, approval_evidence_id = %s WHERE id = %s',
                      (status, evidence_id, release_id))
        audit.append(c, _ts(now), 'release.' + status, actor_kind='operator', actor_id=operator_id,
                     resource_type='image_release', resource_id=release_id,
                     after={'image_digest': manifest['image_digest'], 'manifest_sha256': sha256_hex(manifest),
                            'evidence_sha256': evidence and evidence['sha256']})
        return c.execute('SELECT * FROM image_release WHERE id = %s', (release_id,)).fetchone()


def revoke(store: Store, operator_id: str, image_digest: str) -> dict:
    now = store.clock()
    with store.connect() as c:
        row = c.execute("UPDATE image_release SET status = 'revoked' WHERE image_digest = %s RETURNING *",
                        (image_digest,)).fetchone()
        if row is None:
            raise Refused('NOT_FOUND')
        audit.append(c, _ts(now), 'release.revoked', actor_kind='operator', actor_id=operator_id,
                     resource_type='image_release', resource_id=row['id'], after={'image_digest': image_digest})
        return row


def put_region_secret(store: Store, operator_id: str, region_code: str, kind: str, ciphertext_b64: str) -> str:
    if kind not in REGION_SECRETS:
        raise Refused('SCHEMA', {'kind': kind})
    try:
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (ValueError, TypeError):
        raise Refused('SCHEMA', {'ciphertext': 'base64'}) from None
    if not ciphertext.startswith(AGE_HEADER) or len(ciphertext) > 65536:
        raise Refused('SCHEMA', {'ciphertext': 'not age'})      # plaintext is never accepted
    now = _ts(store.clock())
    with store.connect() as c:
        region = c.execute('SELECT * FROM region WHERE code = %s FOR UPDATE', (region_code,)).fetchone()
        if region is None:
            raise Refused('NOT_FOUND')
        ref = uuid.uuid4()
        c.execute('INSERT INTO secret_ref (id, kind, ciphertext, created_at) VALUES (%s, %s, %s, %s)',
                  (ref, kind, ciphertext, now))
        old = region[REGION_SECRETS[kind]]
        c.execute('UPDATE region SET %s = %%s WHERE id = %%s' % REGION_SECRETS[kind], (ref, region['id']))
        if old:
            c.execute("UPDATE secret_ref SET state = 'revoked', rotated_at = %s WHERE id = %s", (now, old))
        audit.append(c, now, 'secret.region_' + kind, actor_kind='operator', actor_id=operator_id,
                     resource_type='secret_ref', resource_id=ref,
                     after={'region': region_code, 'replaces': str(old) if old else None})
    return str(ref)
