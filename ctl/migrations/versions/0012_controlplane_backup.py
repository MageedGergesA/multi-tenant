"""Control-plane dumps and audit anchors in bucket C (DOC-05 §1, §2; DOC-03
§2.9 SEC-13)."""
from alembic import op

revision = '0012'
down_revision = '0011'

SQL = """
-- [AO] one row per dump uploaded and read back.
CREATE TABLE ctl_dump (
    id uuid PRIMARY KEY,
    reason text NOT NULL CHECK (reason IN ('scheduled', 'pre_migration', 'manual')),
    tier text NOT NULL CHECK (tier IN ('daily', 'monthly')),
    schema_revision text NOT NULL,
    bucket text NOT NULL,
    object_key text NOT NULL,
    object_version_id text NOT NULL,
    sha256 text NOT NULL,                      -- of the age ciphertext, as read back
    size_bytes bigint NOT NULL,
    lock_until timestamptz NOT NULL,           -- as read back
    created_at timestamptz NOT NULL
);
CREATE TRIGGER ctl_dump_ao BEFORE UPDATE OR DELETE ON ctl_dump
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- [AO] one row per anchor written. The bucket's copy is what verification trusts.
CREATE TABLE audit_anchor (
    id uuid PRIMARY KEY,
    seq bigint NOT NULL,
    hash bytea NOT NULL,
    bucket text NOT NULL,
    object_key text NOT NULL,
    object_version_id text NOT NULL,
    lock_until timestamptz NOT NULL,
    anchored_at timestamptz NOT NULL
);
CREATE TRIGGER audit_anchor_ao BEFORE UPDATE OR DELETE ON audit_anchor
    FOR EACH ROW EXECUTE FUNCTION reject_change();

GRANT SELECT, INSERT ON ctl_dump, audit_anchor TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
