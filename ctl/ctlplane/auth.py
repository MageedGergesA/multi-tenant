"""Operator identity: OIDC ID tokens from the platform's IdP (DOC-03 §2.1: no
local passwords). Vendor-neutral: the issuer, audience and signing keys (a
JWKS) are pinned in configuration, not fetched at request time."""
import time
from dataclasses import dataclass

import jwt

MFA_METHODS = ('mfa', 'hwk', 'swk')     # RFC 8176; WebAuthn reports hwk/swk with mfa
MFA_MAX_AGE = 12 * 3600                  # SEC-01: privileged actions need MFA newer than 12 h


class Unauthorized(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    subject: str
    auth_time: float | None
    mfa: bool


class OidcVerifier:
    def __init__(self, issuer: str, audience: str, jwks: dict, *, leeway: int = 30, clock=time.time):
        self.issuer = issuer
        self.audience = audience
        self.keys = {k['kid']: jwt.PyJWK(k) for k in jwks['keys']}
        self.leeway = leeway
        self.clock = clock

    def verify(self, token: str) -> Identity:
        try:
            kid = jwt.get_unverified_header(token).get('kid')
            key = self.keys[kid]
            claims = jwt.decode(token, key.key, algorithms=[key.algorithm_name], audience=self.audience,
                                issuer=self.issuer, leeway=self.leeway,
                                options={'require': ['exp', 'iat', 'iss', 'aud', 'sub']})
        except (jwt.PyJWTError, KeyError, TypeError):
            raise Unauthorized('token') from None
        if claims['iat'] > self.clock() + self.leeway:
            raise Unauthorized('token')
        amr = claims.get('amr') if isinstance(claims.get('amr'), list) else []
        auth_time = claims.get('auth_time') if isinstance(claims.get('auth_time'), (int, float)) else None
        return Identity(claims['sub'], auth_time, any(m in MFA_METHODS for m in amr))

    def mfa_fresh(self, identity: Identity) -> bool:
        return identity.mfa and identity.auth_time is not None and self.clock() - identity.auth_time <= MFA_MAX_AGE
