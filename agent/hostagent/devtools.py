"""Control-plane-side helpers for tests and local tooling. The agent itself
never computes these: it receives only the verifier and the hash."""
import base64
import hashlib
import hmac
import secrets


def scram_verifier(password: str, iterations: int = 4096) -> str:
    """PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677), as stored in pg_authid."""
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    client_key = hmac.new(salted, b'Client Key', hashlib.sha256).digest()
    server_key = hmac.new(salted, b'Server Key', hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return 'SCRAM-SHA-256$%d:%s$%s:%s' % (iterations, b64(salt), b64(hashlib.sha256(client_key).digest()),
                                          b64(server_key))


def odoo_master_hash(password: str, rounds: int = 600_000) -> str:
    """passlib `pbkdf2_sha512` format, which Odoo accepts for admin_passwd."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, rounds)
    ab64 = lambda b: base64.b64encode(b).decode().rstrip('=').replace('+', '.')  # noqa: E731
    return '$pbkdf2-sha512$%d$%s$%s' % (rounds, ab64(salt), ab64(digest))
