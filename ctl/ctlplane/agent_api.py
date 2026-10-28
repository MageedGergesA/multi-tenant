"""The agent-facing API on ctl-1 (README gap 28 in the agent):

    POST /v1/agents/<host_id>/poll       {"wait": s, "capacity": n}
         -> 200 {"envelopes": [...]} | 204
    POST /v1/agents/<host_id>/responses  {"responses": [...]}
         -> 200 {"outcomes": [...]}

Served only over mutual TLS (tls.py). The client certificate's subject must be
exactly CN=<host_id> and the certificate the one issued at the host's last
enrollment (by fingerprint), the host must be in a polling state, and every
response must carry that host's agent signature.
"""
import time
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .store import Store


class Poll(BaseModel):
    wait: int = Field(ge=0, le=60)
    capacity: int = Field(ge=1, le=32)


class Responses(BaseModel):
    responses: list[dict] = Field(max_length=200)


def create_app(store: Store, *, poll_interval: float = 0.5) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def authenticate(request: Request, host_id: uuid.UUID) -> str:
        host = str(host_id)
        tls = request.scope.get('extensions', {}).get('tls') or {}
        if tls.get('client_cert_name') != 'CN=' + host \
                or not store.host_may_poll(host, tls.get('client_cert_sha256')):
            raise HTTPException(403)
        return host

    # Plain `def`: FastAPI runs these in its thread pool, so a long poll holds a
    # thread, not the event loop. Fine for a handful of hosts.
    @app.post('/v1/agents/{host_id}/poll')
    def poll(host_id: uuid.UUID, body: Poll, request: Request):
        host = authenticate(request, host_id)
        until = time.monotonic() + body.wait
        while True:
            envelopes = store.claim(host, body.capacity)
            if envelopes:
                return {'envelopes': envelopes}
            if time.monotonic() >= until:
                return Response(status_code=204)
            time.sleep(min(poll_interval, max(0.0, until - time.monotonic())))

    @app.post('/v1/agents/{host_id}/responses')
    def responses(host_id: uuid.UUID, body: Responses, request: Request):
        host = authenticate(request, host_id)
        return {'outcomes': [store.apply(host, r) for r in body.responses]}

    return app
