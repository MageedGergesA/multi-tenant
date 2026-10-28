"""Canonical JSON (RFC 8785 JCS) and Ed25519 over it: the same encoding as the
agent's (DOC-04 §3). tests/test_contract.py checks they agree."""
import base64
import hashlib

import rfc8785
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def canonical(obj) -> bytes:
    return rfc8785.dumps(obj)


def sha256_hex(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def without(obj: dict, field: str) -> dict:
    return {k: v for k, v in obj.items() if k != field}


def sign(obj: dict, key: SigningKey) -> str:
    return base64.b64encode(key.sign(canonical(obj)).signature).decode()


def verify(obj: dict, signature_b64, key: VerifyKey) -> bool:
    try:
        key.verify(canonical(obj), base64.b64decode(signature_b64, validate=True))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def b64_public(key: SigningKey) -> str:
    return base64.b64encode(bytes(key.verify_key)).decode()
