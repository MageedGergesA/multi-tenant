"""The enrollment listener: `POST /v1/enroll`, served with server TLS only
(the agent has no client certificate yet). Everything before the bootstrap
token is proven gets the same 403."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .admission import Refused
from .enrollment import Enrollment


class EnrollRequest(BaseModel):
    host_id: str = Field(max_length=36)
    token: str = Field(max_length=256)
    agent_key: str = Field(max_length=64)
    age_recipient: str = Field(max_length=128)
    csr_pem: str = Field(max_length=8192)
    proof: str = Field(max_length=128)


def create_app(enrollment: Enrollment) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post('/v1/enroll')
    def enroll(body: EnrollRequest):
        try:
            return enrollment.enroll(body.model_dump())
        except Refused as r:
            if r.code == 'DENIED':
                raise HTTPException(403) from None
            raise HTTPException(422, detail={'code': r.code, 'detail': r.detail}) from None

    return app
