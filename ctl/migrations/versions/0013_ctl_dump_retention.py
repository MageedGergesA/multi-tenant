"""Bucket C retention: control-plane dumps past their lock (DOC-05 §3), in the
custodian-approved retention batches."""
from alembic import op

revision = '0013'
down_revision = '0012'

SQL = """
-- [AO] ctl_dump is append-only, so a deleted dump is recorded here.
CREATE TABLE ctl_dump_expired (
    ctl_dump_id uuid PRIMARY KEY REFERENCES ctl_dump(id),
    batch_id uuid NOT NULL REFERENCES retention_batch(id),
    expired_at timestamptz NOT NULL
);
CREATE TRIGGER ctl_dump_expired_ao BEFORE UPDATE OR DELETE ON ctl_dump_expired
    FOR EACH ROW EXECUTE FUNCTION reject_change();

GRANT SELECT, INSERT ON ctl_dump_expired TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
