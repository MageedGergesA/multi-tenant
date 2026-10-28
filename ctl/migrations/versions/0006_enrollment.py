"""Host.Enroll (DOC-04 §2, §6.16; DOC-05 §1).

An operator opens an enrollment: a one-time bootstrap token (only its hash is
kept) and an authorization naming the host and the trust keys it is to pin.
The founder signs the authorization offline with the release key ("Enroll:
R"); only then can the token be used. The agent's client certificate is
pinned by fingerprint, so re-enrolling a host retires the old one.
"""
from alembic import op

revision = '0006'
down_revision = '0005'

SQL = """
ALTER TABLE host
    ADD COLUMN client_cert_sha256 text,         -- the one certificate the agent API accepts for this host
    ADD COLUMN enrolled_at timestamptz;

CREATE TABLE host_enrollment (
    id uuid PRIMARY KEY,
    host_id uuid NOT NULL REFERENCES host(id),
    token_sha256 text NOT NULL CHECK (token_sha256 ~ '^[0-9a-f]{64}$'),
    body jsonb NOT NULL,                       -- the authorization the release key signs
    signed_body jsonb,                         -- with release_signature, once authorized
    state text NOT NULL CHECK (state IN ('pending', 'authorized', 'used', 'revoked')),
    failed_attempts int NOT NULL DEFAULT 0,
    created_by uuid REFERENCES operator(id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE UNIQUE INDEX host_enrollment_open ON host_enrollment (host_id) WHERE state IN ('pending', 'authorized');

GRANT SELECT, INSERT, UPDATE ON host_enrollment TO ctl_app;
GRANT UPDATE (retired_at) ON signing_key TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
