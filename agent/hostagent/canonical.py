"""Canonical JSON (RFC 8785 JCS) and Ed25519 signatures over it (DOC-04 §3)."""
import base64
import hashlib

import rfc8785
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def canonical(obj) -> bytes:
    # JCS only admits integers up to 2**53; fencing tokens must stay below that.
    return rfc8785.dumps(obj)


def sha256_hex(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def without(obj: dict, field: str) -> dict:
    return {k: v for k, v in obj.items() if k != field}


def sign(obj: dict, key: SigningKey) -> str:
    return base64.b64encode(key.sign(canonical(obj)).signature).decode()


def verify(obj: dict, signature_b64: str, keys: list[VerifyKey]) -> VerifyKey | None:
    """Return the key that verifies `signature_b64` over `obj`, or None."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return None
    message = canonical(obj)
    for key in keys:
        try:
            key.verify(message, signature)
            return key
        except BadSignatureError:
            continue
    return None


def load_verify_key(b64: str) -> VerifyKey:
    return VerifyKey(base64.b64decode(b64))


def b64_public(key: SigningKey) -> str:
    return base64.b64encode(bytes(key.verify_key)).decode()
