"""The operator API (the console's backend, over WireGuard):

    POST /v1/operations                   request an operation
    POST /v1/operations/<id>/approval     submit a custodian-signed approval
    GET  /v1/operations/<id>              its state
    POST /v1/releases                     a release manifest signed with the release key, plus evidence
    POST /v1/releases/revoke              {image_digest}
    PUT  /v1/regions/<code>/secrets/<kind>  age ciphertext to the dispatcher's recipient
    GET  /v1/dispatcher/recipient         that recipient
    POST /v1/hosts                        a new host and its enrollment (token shown once)
    POST /v1/hosts/<id>/enrollment        re-enroll a host
    POST /v1/hosts/<id>/enrollment/authorize   the body signed with the release key
    GET  /v1/trust                        active trust version, and each host's
    POST /v1/trust                        draft the next trust document (to sign with the release key)
    POST /v1/trust/<version>/authorize    the signed document; it becomes active
    POST /v1/trust/rollout                Host.RotateTrust to every enrolled host behind it
    POST /v1/tenants/<id>/terms           record the signed terms acceptance (billing)
    POST /v1/tenants/<id>/activation/check   evaluate DOC-03 §3.6; a failure sends the tenant to ERROR
    POST /v1/tenants/<id>/activation      {check_id}: confirm a passing check, VALIDATING → ACTIVE
    GET  /v1/retention                    the open retention batch and whether retention is frozen
    POST /v1/retention/draft              list what may be deleted now (a batch for the custodian)
    POST /v1/retention/<id>/approve       {approval}: the batch body signed with a custodian key
    POST /v1/retention/freeze             {frozen}: stop or resume deletions (RB-04)

Bearer OIDC ID token; the operator must be active with a current role grant.
Requests and approvals are privileged: MFA newer than 12 hours (SEC-01).
"""
import uuid
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from . import releases
from .admission import Admission, Refused
from .auth import OidcVerifier, Unauthorized
from .store import _ts

READ_ROLES = ('platform_operator', 'backup_custodian', 'auditor', 'billing_admin')


class OperationRequest(BaseModel):
    type: str = Field(max_length=64)
    tenant_id: str | None = Field(default=None, max_length=36)
    environment_id: str | None = Field(default=None, max_length=36)
    host_id: str | None = Field(default=None, max_length=36)
    params: dict = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1, max_length=128)


class ApprovalBody(BaseModel):
    approval: dict


class ReleaseBody(BaseModel):
    manifest: dict
    evidence: dict | None = None


class RevokeBody(BaseModel):
    image_digest: str = Field(max_length=80)


class HostBody(BaseModel):
    role: str = Field(max_length=8)
    region: str = Field(max_length=64)
    private_ip: str = Field(max_length=45)
    totals: dict = Field(default_factory=dict)


class AuthorizeBody(BaseModel):
    authorization: dict


class TrustBody(BaseModel):
    document: dict


class TermsBody(BaseModel):
    terms_version: str = Field(max_length=64)
    document_sha256: str = Field(max_length=64)
    accepted_by_name: str = Field(max_length=200)
    accepted_at: datetime
    covers: list[str] = Field(max_length=32)
    region: str = Field(max_length=64)


class ActivateBody(BaseModel):
    check_id: str = Field(max_length=36)


class FreezeBody(BaseModel):
    frozen: bool


class SecretBody(BaseModel):
    ciphertext_b64: str = Field(max_length=90000)


def _refused(r: Refused):
    status = {'NOT_FOUND': 404, 'STATE': 409, 'CONFLICT': 409, 'EXPIRED': 409}.get(r.code, 422)
    return HTTPException(status, detail={'code': r.code, 'detail': r.detail})


def _public(op) -> dict:
    keep = ('id', 'type', 'tenant_id', 'environment_id', 'host_id', 'state', 'result_code', 'result_detail',
            'attempt', 'fencing_token', 'precondition_backup_id', 'breakglass_used', 'created_at', 'updated_at',
            'finished_at')
    return {k: (str(op[k]) if isinstance(op[k], (uuid.UUID, datetime)) else op[k]) for k in keep}


def create_app(admission: Admission, verifier: OidcVerifier, *, dispatcher_recipient: str = '',
               enrollment=None, trust=None, retention=None) -> FastAPI:
    from .activation import Activation, record_terms
    activation = Activation(admission.store)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    store = admission.store

    def operator(request: Request) -> dict:
        header = request.headers.get('authorization', '')
        if not header.startswith('Bearer '):
            raise HTTPException(401, headers={'WWW-Authenticate': 'Bearer'})
        try:
            ident = verifier.verify(header[7:])
        except Unauthorized:
            raise HTTPException(401, headers={'WWW-Authenticate': 'Bearer'}) from None
        now = _ts(store.clock())
        with store.connect() as c:
            row = c.execute("SELECT id FROM operator WHERE oidc_subject = %s AND status = 'active'",
                            (ident.subject,)).fetchone()
            if row is None:
                raise HTTPException(403)
            roles = {r['role'] for r in c.execute(
                'SELECT role FROM operator_role_grant WHERE operator_id = %s AND valid_from <= %s '
                'AND (valid_to IS NULL OR valid_to > %s)', (row['id'], now, now)).fetchall()}
            fresh = verifier.mfa_fresh(ident)
            if fresh:
                c.execute('UPDATE operator SET mfa_verified_at = %s WHERE id = %s',
                          (_ts(ident.auth_time), row['id']))
        return {'id': str(row['id']), 'roles': roles, 'mfa_fresh': fresh}

    def privileged(op: dict, *roles):
        if not op['roles'] & set(roles):
            raise HTTPException(403)
        if not op['mfa_fresh']:
            raise HTTPException(403, detail='mfa required')

    @app.post('/v1/operations', status_code=201)
    def request_operation(body: OperationRequest, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        return _public(admission.request(op['id'], op_type=body.type, tenant_id=body.tenant_id,
                                         environment_id=body.environment_id, host_id=body.host_id,
                                         params=body.params, idempotency_key=body.idempotency_key))

    @app.post('/v1/operations/{op_id}/approval')
    def approve(op_id: uuid.UUID, body: ApprovalBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator', 'backup_custodian')
        try:
            return _public(admission.approve(op['id'], str(op_id), body.approval))
        except Refused as r:
            raise _refused(r) from None

    @app.get('/v1/operations/{op_id}')
    def get_operation(op_id: uuid.UUID, op: dict = Depends(operator)):
        if not op['roles'] & set(READ_ROLES):
            raise HTTPException(403)
        with store.connect() as c:
            row = c.execute('SELECT * FROM operation WHERE id = %s', (op_id,)).fetchone()
        if row is None:
            raise HTTPException(404)
        return _public(row)

    @app.post('/v1/releases')
    def upload_release(body: ReleaseBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            row = releases.upload(store, op['id'], body.manifest, body.evidence)
        except Refused as r:
            raise _refused(r) from None
        return {'id': str(row['id']), 'image_digest': row['image_digest'], 'status': row['status']}

    @app.post('/v1/releases/revoke')
    def revoke_release(body: RevokeBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            row = releases.revoke(store, op['id'], body.image_digest)
        except Refused as r:
            raise _refused(r) from None
        return {'id': str(row['id']), 'status': row['status']}

    @app.put('/v1/regions/{code}/secrets/{kind}')
    def put_region_secret(code: str, kind: str, body: SecretBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            return {'secret_ref_id': releases.put_region_secret(store, op['id'], code, kind, body.ciphertext_b64)}
        except Refused as r:
            raise _refused(r) from None

    def _enrollment():
        if enrollment is None:
            raise HTTPException(404)
        return enrollment

    @app.post('/v1/hosts', status_code=201)
    def new_host(body: HostBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            host_id, token, unsigned = _enrollment().open(op['id'], role=body.role, region=body.region,
                                                          private_ip=body.private_ip, totals=body.totals)
        except Refused as r:
            raise _refused(r) from None
        return {'host_id': host_id, 'bootstrap_token': token, 'authorization': unsigned}

    @app.post('/v1/hosts/{host_id}/enrollment', status_code=201)
    def reenroll(host_id: uuid.UUID, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            _, token, unsigned = _enrollment().open(op['id'], host_id=str(host_id))
        except Refused as r:
            raise _refused(r) from None
        return {'host_id': str(host_id), 'bootstrap_token': token, 'authorization': unsigned}

    @app.post('/v1/hosts/{host_id}/enrollment/authorize')
    def authorize(host_id: uuid.UUID, body: AuthorizeBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            _enrollment().authorize(op['id'], str(host_id), body.authorization)
        except Refused as r:
            raise _refused(r) from None
        return {'host_id': str(host_id), 'state': 'authorized'}

    def _trust():
        if trust is None:
            raise HTTPException(404)
        return trust

    @app.get('/v1/trust')
    def trust_status(op: dict = Depends(operator)):
        if not op['roles'] & set(READ_ROLES):
            raise HTTPException(403)
        return _trust().status()

    @app.post('/v1/trust', status_code=201)
    def trust_draft(op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            return {'document': _trust().draft(op['id'])}
        except Refused as r:
            raise _refused(r) from None

    @app.post('/v1/trust/{version}/authorize')
    def trust_authorize(version: int, body: TrustBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            _trust().authorize(op['id'], version, body.document)
        except Refused as r:
            raise _refused(r) from None
        return {'active_version': version}

    @app.post('/v1/trust/rollout')
    def trust_rollout(op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        t = _trust()
        version = t.status()['active_version']
        out = []
        for host in t.behind():
            row = admission.request(op['id'], op_type='Host.RotateTrust', host_id=host, params={},
                                    idempotency_key='rotate-trust:%d:%s' % (version, host))
            out.append({'host_id': host, 'operation_id': str(row['id']), 'state': row['state'],
                        'result_code': row['result_code']})
        return {'active_version': version, 'operations': out}

    @app.post('/v1/tenants/{tenant_id}/terms', status_code=201)
    def terms(tenant_id: uuid.UUID, body: TermsBody, op: dict = Depends(operator)):
        privileged(op, 'billing_admin', 'platform_operator')
        try:
            return {'id': record_terms(store, op['id'], str(tenant_id), body.model_dump())}
        except Refused as r:
            raise _refused(r) from None

    @app.post('/v1/tenants/{tenant_id}/activation/check')
    def activation_check(tenant_id: uuid.UUID, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            return activation.check(op['id'], str(tenant_id))
        except Refused as r:
            raise _refused(r) from None

    @app.post('/v1/tenants/{tenant_id}/activation')
    def activate(tenant_id: uuid.UUID, body: ActivateBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator')
        try:
            return activation.activate(op['id'], str(tenant_id), body.check_id)
        except Refused as r:
            raise _refused(r) from None

    def _retention():
        if retention is None:
            raise HTTPException(404)
        return retention

    @app.get('/v1/retention')
    def retention_status(op: dict = Depends(operator)):
        if not op['roles'] & set(READ_ROLES):
            raise HTTPException(403)
        with store.connect() as c:
            batch = c.execute("SELECT id, body, items, state FROM retention_batch WHERE state IN ('drafted', 'approved')"
                              ).fetchone()
            frozen = c.execute("SELECT value FROM ctl_flag WHERE name = 'retention_frozen'").fetchone()
        return {'frozen': bool(frozen and frozen['value'] == 'true'),
                'batch': batch and {'id': str(batch['id']), 'state': batch['state'], 'body': batch['body'],
                                    'items': batch['items']}}

    @app.post('/v1/retention/draft')
    def retention_draft(op: dict = Depends(operator)):
        privileged(op, 'platform_operator', 'backup_custodian')
        return {'batch': _retention().draft()}

    @app.post('/v1/retention/{batch_id}/approve')
    def retention_approve(batch_id: uuid.UUID, body: ApprovalBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator', 'backup_custodian')
        try:
            return _retention().approve(op['id'], str(batch_id), body.approval)
        except Refused as r:
            raise _refused(r) from None

    @app.post('/v1/retention/freeze')
    def retention_freeze(body: FreezeBody, op: dict = Depends(operator)):
        privileged(op, 'platform_operator', 'backup_custodian')
        _retention().set_frozen(op['id'], body.frozen)
        return {'frozen': body.frozen}

    @app.get('/v1/dispatcher/recipient')
    def recipient(op: dict = Depends(operator)):
        return {'recipient': dispatcher_recipient}

    return app
