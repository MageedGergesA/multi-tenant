"""Host.Enroll, the agent's side (DOC-04 §2, §6.16):

    python -m hostagent.enroll --config agent.toml --token-file /run/bootstrap-token

The host image carries only two roots of trust: ctl-1's CA (`ctl_ca`) and the
release public key (`trust_root`). Enrollment generates this host's keys
(Ed25519 to sign responses, X25519 for envelope secrets, EC P-256 for TLS),
sends their public halves with the one-time token, and gets back a client
certificate and the enrollment authorization signed with the release key.
Only after that signature, the host ID, the role and the token hash all
check out is anything written; the authorization is then the pinned trust
(`trust.json`), checked again at every start (config.load).
"""
import argparse
import hashlib
import json
import os
import ssl
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

import pyrage
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from nacl.signing import SigningKey

from .canonical import b64_public, load_verify_key, sign, verify, without
from .config import ROLES, Trust


class EnrollError(Exception):
    pass


def trust_from(signed, trust_root: str, host_id: str, role: str) -> Trust:
    """The pinned keys, from a document the release key signed: this host's
    enrollment authorization, or a fleet trust document (`kind: trust`) from
    Host.RotateTrust."""
    if not isinstance(signed, dict) or not isinstance(signed.get('trust'), dict):
        raise EnrollError('authorization malformed')
    root = load_verify_key(trust_root)
    if verify(without(signed, 'release_signature'), signed.get('release_signature', ''), [root]) is None:
        raise EnrollError('authorization not signed by the release key')
    fleet = signed.get('kind') == 'trust'
    if not fleet and (signed.get('host_id') != host_id or signed.get('role') != role):
        raise EnrollError('authorization is for another host')
    version = signed.get('trust_version', 0)
    if not isinstance(version, int) or isinstance(version, bool) or version < (1 if fleet else 0):
        raise EnrollError('trust version malformed')
    t = signed['trust']
    if not t.get('dispatch'):
        raise EnrollError('no dispatch key')
    return Trust(dispatch=tuple(load_verify_key(k) for k in t['dispatch']), release=root,
                 custodian=tuple(load_verify_key(k) for k in t.get('custodian') or ()),
                 breakglass=load_verify_key(t['breakglass']) if t.get('breakglass') else None,
                 breakglass_enabled=bool(t.get('breakglass_enabled')),
                 agents=tuple(load_verify_key(k) for k in t.get('agents') or ()), version=version)


def _write(path: Path, data: bytes, mode: int):
    tmp = path.with_name(path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def enroll(config_path: Path, token: str, *, timeout: float = 30) -> dict:
    raw = tomllib.loads(config_path.read_text())
    host_id, role = raw['host_id'], raw['role']
    if role not in ROLES:
        raise EnrollError('unknown role')
    state = Path(raw['state_dir'])
    if (state / 'agent.key').exists():
        # Re-enrolling a used host would reset its fences, nonces and registry
        # (DOC-05 §1); that is a rebuild, done on a wiped state directory.
        raise EnrollError('already enrolled: %s exists' % (state / 'agent.key'))
    if not raw['enroll_url'].startswith('https://'):
        raise EnrollError('ctl-1 is reached over https only')

    signing = SigningKey.generate()
    age = pyrage.x25519.Identity.generate()
    tls_key = ec.generate_private_key(ec.SECP256R1())
    csr_pem = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host_id)]))
               .sign(tls_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
    token_sha256 = hashlib.sha256(token.encode()).hexdigest()
    claim = {'host_id': host_id, 'token_sha256': token_sha256, 'age_recipient': str(age.to_public()),
             'csr_sha256': hashlib.sha256(csr_pem.encode()).hexdigest()}
    body = {'host_id': host_id, 'token': token, 'agent_key': b64_public(signing),
            'age_recipient': str(age.to_public()), 'csr_pem': csr_pem, 'proof': sign(claim, signing)}

    ctx = ssl.create_default_context(cafile=raw['ctl_ca'])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    req = urllib.request.Request(raw['enroll_url'].rstrip('/') + '/v1/enroll', json.dumps(body).encode(),
                                 {'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            reply = json.loads(r.read(1 << 20))
    except urllib.error.HTTPError as e:
        raise EnrollError('refused: http %d' % e.code) from None
    except (urllib.error.URLError, OSError) as e:
        raise EnrollError('unreachable: %s' % type(e).__name__) from None

    signed = reply.get('authorization')
    trust_from(signed, raw['trust_root'], host_id, role)
    if signed.get('token_sha256') != token_sha256:
        raise EnrollError('authorization is for another token')
    cert = x509.load_pem_x509_certificate(reply['certificate_pem'].encode())
    if [(a.oid, a.value) for a in cert.subject] != [(NameOID.COMMON_NAME, host_id)] or \
            cert.public_key().public_numbers() != tls_key.public_key().public_numbers():
        raise EnrollError('certificate is not for this host and key')

    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write(Path(raw['tls_key']), tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()), 0o600)
    _write(Path(raw['tls_cert']), reply['certificate_pem'].encode(), 0o644)
    _write(state / 'age.key', str(age).encode(), 0o600)
    _write(state / 'trust.json', json.dumps(signed, sort_keys=True).encode(), 0o644)
    _write(state / 'agent.key', bytes(signing), 0o600)       # last: its presence means enrolled
    return {'host_id': host_id, 'agent_key': b64_public(signing), 'age_recipient': str(age.to_public()),
            'cert_sha256': hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', required=True, type=Path)
    ap.add_argument('--token-file', required=True, type=Path)
    a = ap.parse_args()
    result = enroll(a.config, a.token_file.read_text().strip())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
