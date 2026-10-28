"""Host.RotateTrust (DOC-04 §2): versioned fleet trust documents, signed with
the release key, and the version each host has pinned."""
from alembic import op

revision = '0007'
down_revision = '0006'

SQL = """
CREATE TABLE trust_document (
    version int PRIMARY KEY CHECK (version >= 1),
    body jsonb NOT NULL,                       -- what the release key signs
    signed_body jsonb,                         -- with release_signature, once authorized
    state text NOT NULL CHECK (state IN ('pending', 'active', 'superseded', 'abandoned')),
    created_by uuid REFERENCES operator(id),
    created_at timestamptz NOT NULL,
    authorized_at timestamptz
);
CREATE UNIQUE INDEX trust_document_one_active ON trust_document ((true)) WHERE state = 'active';
CREATE UNIQUE INDEX trust_document_one_pending ON trust_document ((true)) WHERE state = 'pending';

ALTER TABLE host ADD COLUMN trust_version int NOT NULL DEFAULT 0;   -- what the agent has pinned

GRANT SELECT, INSERT, UPDATE ON trust_document TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
