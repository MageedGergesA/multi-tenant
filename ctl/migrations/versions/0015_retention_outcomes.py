"""Which retention batch expired a backup point: each item's outcome is
committed with its expiry, so a batch that resumes after a crash keeps what
it already did (retention.execute)."""
from alembic import op

revision = '0015'
down_revision = '0014'

SQL = """
ALTER TABLE backup_point ADD COLUMN retention_batch_id uuid REFERENCES retention_batch(id);
GRANT UPDATE (retention_batch_id) ON backup_point TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
