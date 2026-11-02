"""The archive queue itself in db-1's report (Codex, L2 re-review): the `.ready` files
waiting in pg_wal/archive_status and the oldest one's age. A segment count derived
from last_archived_wal assumed an archived prefix with no gaps and missed a small
backlog that never drains."""
from alembic import op

revision = '0019'
down_revision = '0018'

SQL = """
ALTER TABLE db_archiver ADD COLUMN pending bigint NOT NULL DEFAULT 0;
ALTER TABLE db_archiver ADD COLUMN oldest_pending_age double precision;   -- seconds, at the report; NULL: none
"""


def upgrade():
    op.execute(SQL)
