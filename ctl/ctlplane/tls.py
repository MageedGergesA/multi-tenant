"""Mutual TLS for the agent API, served by uvicorn.

uvicorn verifies the client certificate (CERT_REQUIRED against the pinned CA)
but doesn't pass it to the application. This protocol class does, as the ASGI
TLS extension's `client_cert_name`. If a uvicorn upgrade bypasses it, the
extension is missing and every agent request is refused: it fails closed.
"""
import hashlib
import ssl

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

MAX_BODY = 4 << 20


def _subject_name(cert: dict | None) -> str | None:
    if not cert:
        return None
    rdns = [f'{_SHORT.get(k, k)}={v}' for rdn in cert.get('subject', ()) for k, v in rdn]
    return ','.join(reversed(rdns))    # RFC 4514 order: most specific first


_SHORT = {'commonName': 'CN', 'organizationName': 'O', 'organizationalUnitName': 'OU', 'countryName': 'C'}


class _Peer:
    def __init__(self, app, name, fingerprint):
        self.app = app
        self.name = name
        self.fingerprint = fingerprint

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            # `client_cert_sha256` isn't in the ASGI extension: the agent API pins each
            # host's certificate by it, which revokes a replaced one without a CRL.
            tls = {'client_cert_name': self.name, 'client_cert_sha256': self.fingerprint}
            scope = dict(scope, extensions={**scope.get('extensions', {}), 'tls': tls})
            receive = _limited(receive)
        await self.app(scope, receive, send)


def _limited(receive):
    seen = 0

    async def wrapped():
        nonlocal seen
        message = await receive()
        seen += len(message.get('body', b''))
        if seen > MAX_BODY:
            raise ValueError('request body too large')
        return message
    return wrapped


class MutualTlsH11(H11Protocol):
    def connection_made(self, transport):
        super().connection_made(transport)
        tls = transport.get_extra_info('ssl_object')
        der = tls.getpeercert(binary_form=True) if tls else None
        self.app = _Peer(self.app, _subject_name(transport.get_extra_info('peercert')),
                         hashlib.sha256(der).hexdigest() if der else None)


def fingerprint(pem: bytes) -> str:
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode())).hexdigest()


def server(app, host: str, port: int, *, cert, key, ca=None, client_certs: bool = True) -> uvicorn.Server:
    """Mutual TLS by default. `client_certs=False` serves enrollment, where the
    agent has no certificate yet: server authentication only."""
    config = uvicorn.Config(app, host=host, port=port, ssl_certfile=str(cert), ssl_keyfile=str(key),
                            ssl_ca_certs=str(ca) if client_certs else None,
                            ssl_cert_reqs=ssl.CERT_REQUIRED if client_certs else ssl.CERT_NONE,
                            http=MutualTlsH11, ws='none', lifespan='off', log_level='warning', access_log=False)
    config.load()
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    return uvicorn.Server(config)
