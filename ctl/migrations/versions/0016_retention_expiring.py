"""Retention marks a backup point `expiring` (committed) before deleting its
object, so a crash between the S3 delete and the database update can't leave
a `recoverable` point with no object; and the freeze flag always exists, so
a freeze waits for the item being deleted (retention.execute)."""
from alembic import op

revision = '0016'
down_revision = '0015'

SQL = """
ALTER TABLE backup_point DROP CONSTRAINT backup_point_state_check;
ALTER TABLE backup_point ADD CONSTRAINT backup_point_state_check CHECK (state IN (
    'planned', 'guarded', 'dumped', 'copied', 'verified_local', 'recoverable', 'failed', 'expiring', 'expired'));
INSERT INTO ctl_flag (name, value, set_at) VALUES ('retention_frozen', 'false', now()) ON CONFLICT (name) DO NOTHING;
"""


def upgrade():
    op.execute(SQL)
