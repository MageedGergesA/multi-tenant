"""Host.Enroll (DOC-04 §2, §6.16).

1. `open`: an operator opens an enrollment for a new host (or re-enrolls one).
   ctl-1 makes a one-time bootstrap token (shown once, only its hash kept)
   and the authorization body: the host's identity, the token's hash, an
   expiry, and the trust keys the agent is to pin (dispatch, custodian,
   break-glass).
2. `authorize`: the founder signs that body offline with the release key
   ("Enroll: R"). Unsigned, the token is useless.
3. `enroll` (no client certificate yet; server TLS only): the agent sends the
   token, its new Ed25519 and X25519 public keys, a CSR for CN=<host_id>, and
   a proof signed by the new key that binds them together. ctl-1 issues the
   client certificate, registers the keys (retiring the old ones), pins the
   certificate by fingerprint, and returns the signed authorization, which
   the agent checks against the release key in its image before pinning
   anything. A compromised ctl-1 can't make an agent trust another dispatch
   key, and a compromised operator account can't enroll a host.
"""
import base64
import hashlib
import hmac
import ipaddress
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pyrage
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from nacl.signing import VerifyKey
from psycopg.types.json import Jsonb

from . import audit, trust
from .admission import Refused
from .canonical import sha256_hex, verify, without
from .store import Store, _ts
from .tls import fingerprint

TOKEN_TTL = 24 * 3600
MAX_ATTEMPTS = 5
CERT_DAYS = 365          # until the next enrollment; renewal isn't built
ROLES = ('app', 'db', 'mail')


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class Enrollment:
    def __init__(self, store: Store, *, ca_cert_pem: bytes, ca_key_pem: bytes, breakglass_enabled: bool = False):
        self.store = store
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        self.ca_key = serialization.load_pem_private_key(ca_key_pem, None)
        self.breakglass_enabled = breakglass_enabled

    # -- operator side --------------------------------------------------------
    def open(self, operator_id, *, host_id=None, role=None, region=None, private_ip=None, totals=None):
        """→ (host_id, token, body). A new host when `host_id` is None."""
        now = self.store.clock()
        token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(token.encode()).hexdigest()
        with self.store.connect() as c:
            if host_id is None:
                if role not in ROLES:
                    raise Refused('SCHEMA', {'role': role})
                reg = c.execute("SELECT id FROM region WHERE code = %s AND status = 'active'", (region,)).fetchone()
                if reg is None:
                    raise Refused('NOT_FOUND', {'region': region})
                try:
                    if private_ip is None or not ipaddress.ip_address(private_ip).is_private:
                        raise ValueError
                except ValueError:
                    raise Refused('SCHEMA', {'private_ip': private_ip}) from None
                totals = totals or {}
                host_id = str(uuid.uuid4())
                c.execute("INSERT INTO host (id, role, state, region_id, private_ip, total_vcpu_milli, total_ram_mb, "
                          "total_disk_gb, pg_max_connections) VALUES (%s, %s, 'provisioning', %s, %s, %s, %s, %s, %s)",
                          (host_id, role, reg['id'], private_ip, totals.get('vcpu_milli', 0),
                           totals.get('ram_mb', 0), totals.get('disk_gb', 0), totals.get('pg_max_connections')))
            host = c.execute('SELECT h.*, r.code AS region_code FROM host h LEFT JOIN region r ON r.id = h.region_id '
                             'WHERE h.id = %s', (host_id,)).fetchone()
            if host is None:
                raise Refused('NOT_FOUND', {'host_id': host_id})
            if host['state'] in ('failed', 'retired'):
                raise Refused('POLICY_STATE', {'state': host['state']})
            # One open enrollment per host: a new one replaces it.
            c.execute("UPDATE host_enrollment SET state = 'revoked' WHERE host_id = %s AND state IN "
                      "('pending', 'authorized')", (host_id,))
            body = {'v': 1, 'host_id': str(host_id), 'role': host['role'], 'region': host['region_code'],
                    'private_ip': str(host['private_ip']) if host['private_ip'] else None,
                    'token_sha256': token_sha256, 'expires_at': _iso(now + TOKEN_TTL),
                    # Built like the active trust document and carrying its version, so the
                    # new host isn't sent a rotation it already has.
                    'trust_version': trust.active_version(c), 'trust': trust.keys(c, self.breakglass_enabled)}
            c.execute("INSERT INTO host_enrollment (id, host_id, token_sha256, body, state, created_by, created_at, "
                      "expires_at) VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s)",
                      (uuid.uuid4(), host_id, token_sha256, Jsonb(body), operator_id, _ts(now),
                       _ts(now + TOKEN_TTL)))
            audit.append(c, _ts(now), 'host.enrollment_opened', actor_kind='operator', actor_id=operator_id,
                         resource_type='host', resource_id=host_id, after={'body_sha256': sha256_hex(body)})
        return str(host_id), token, body

    def authorize(self, operator_id, host_id, signed) -> dict:
        now = self.store.clock()
        with self.store.connect() as c:
            row = c.execute("SELECT * FROM host_enrollment WHERE host_id = %s AND state = 'pending' FOR UPDATE",
                            (host_id,)).fetchone()
            if row is None:
                raise Refused('NOT_FOUND')
            if not isinstance(signed, dict) or without(signed, 'release_signature') != row['body']:
                raise Refused('CONFLICT', {'detail': 'not the open enrollment'})
            keys = c.execute("SELECT public_key FROM signing_key WHERE purpose = 'release' AND retired_at IS NULL"
                             ).fetchall()
            if not any(verify(row['body'], signed.get('release_signature'),
                              VerifyKey(base64.b64decode(k['public_key']))) for k in keys):
                raise Refused('SIG_INVALID')
            if row['expires_at'].timestamp() < now:
                raise Refused('EXPIRED')
            c.execute("UPDATE host_enrollment SET state = 'authorized', signed_body = %s WHERE id = %s",
                      (Jsonb(signed), row['id']))
            audit.append(c, _ts(now), 'host.enrollment_authorized', actor_kind='operator', actor_id=operator_id,
                         resource_type='host', resource_id=host_id, after={'body_sha256': sha256_hex(row['body'])})
        return signed

    # -- the agent's request -------------------------------------------------
    def enroll(self, req: dict) -> dict:
        """Refusals before the token is proven are all the same 403 (`Refused('DENIED')`)."""
        now = self.store.clock()
        host_id, token = req.get('host_id'), req.get('token')
        if not isinstance(host_id, str) or not isinstance(token, str) or len(token) > 256:
            raise Refused('DENIED')
        try:
            host_id = str(uuid.UUID(host_id))
        except ValueError:
            raise Refused('DENIED') from None
        with self.store.connect() as c:
            row = c.execute("SELECT * FROM host_enrollment WHERE host_id = %s AND state IN ('pending', 'authorized') "
                            'FOR UPDATE', (host_id,)).fetchone()
            if row is None:
                raise Refused('DENIED')
            if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), row['token_sha256']):
                attempts = row['failed_attempts'] + 1
                c.execute("UPDATE host_enrollment SET failed_attempts = %s, "
                          "state = CASE WHEN %s >= %s THEN 'revoked' ELSE state END WHERE id = %s",
                          (attempts, attempts, MAX_ATTEMPTS, row['id']))
                audit.append(c, _ts(now), 'host.enroll_refused', actor_kind='system', resource_type='host',
                             resource_id=host_id, after={'reason': 'token', 'attempts': attempts})
                c.commit()
                raise Refused('DENIED')
            if row['state'] != 'authorized' or row['expires_at'].timestamp() < now:
                raise Refused('DENIED')
            # The token is good: from here, say what's wrong.
            agent_key, csr_pem, age_recipient = self._check_keys(req, host_id, row['token_sha256'])
            cert_pem = self._issue(host_id, csr_pem, now)
            key_id = uuid.uuid4()
            c.execute("UPDATE signing_key SET retired_at = %s WHERE id = (SELECT agent_key_id FROM host WHERE id = %s) "
                      'AND retired_at IS NULL', (_ts(now), host_id))
            c.execute("INSERT INTO signing_key (id, purpose, public_key) VALUES (%s, 'agent', %s)",
                      (key_id, agent_key))
            c.execute("UPDATE host SET agent_key_id = %s, age_recipient = %s, client_cert_sha256 = %s, enrolled_at = %s, "
                      'trust_version = %s, '
                      "state = CASE WHEN state = 'provisioning' THEN 'active' ELSE state END, "
                      'row_version = row_version + 1 WHERE id = %s',
                      (key_id, age_recipient, fingerprint(cert_pem), _ts(now), row['body'].get('trust_version', 0),
                       host_id))
            c.execute("UPDATE host_enrollment SET state = 'used', used_at = %s WHERE id = %s", (_ts(now), row['id']))
            audit.append(c, _ts(now), 'host.enrolled', actor_kind='system', resource_type='host', resource_id=host_id,
                         after={'agent_key': agent_key, 'age_recipient': age_recipient,
                                'client_cert_sha256': fingerprint(cert_pem)})
            return {'certificate_pem': cert_pem.decode(), 'authorization': row['signed_body']}

    def _check_keys(self, req, host_id, token_sha256):
        agent_key, csr_pem, age_recipient, proof = (req.get(k) for k in ('agent_key', 'csr_pem', 'age_recipient',
                                                                         'proof'))
        if not all(isinstance(v, str) for v in (agent_key, csr_pem, age_recipient, proof)) or len(csr_pem) > 8192:
            raise Refused('SCHEMA')
        try:
            vk = VerifyKey(base64.b64decode(agent_key, validate=True))
            pyrage.x25519.Recipient.from_str(age_recipient)
        except Exception:
            raise Refused('SCHEMA', {'keys': 'malformed'}) from None
        # Possession: the new signing key signs over everything it brings.
        claim = {'host_id': host_id, 'token_sha256': token_sha256, 'age_recipient': age_recipient,
                 'csr_sha256': hashlib.sha256(csr_pem.encode()).hexdigest()}
        if not verify(claim, proof, vk):
            raise Refused('SIG_INVALID', {'proof': 'agent key'})
        return agent_key, csr_pem.encode(), age_recipient

    def _issue(self, host_id, csr_pem: bytes, now) -> bytes:
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError:
            raise Refused('SCHEMA', {'csr': 'malformed'}) from None
        if not csr.is_signature_valid:
            raise Refused('SCHEMA', {'csr': 'signature'})
        if [(a.oid, a.value) for a in csr.subject] != [(NameOID.COMMON_NAME, host_id)]:
            raise Refused('SCHEMA', {'csr': 'subject must be exactly CN=<host_id>'})
        key = csr.public_key()
        if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != 'secp256r1':
            raise Refused('SCHEMA', {'csr': 'key must be EC P-256'})
        start = datetime.fromtimestamp(now, timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host_id)]))
                .issuer_name(self.ca_cert.subject)
                .public_key(key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(start - timedelta(minutes=5))
                .not_valid_after(start + timedelta(days=CERT_DAYS))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                             crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                               critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM)
