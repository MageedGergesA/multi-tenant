"""db-1's WAL archiver as its agent reports it with each poll (pg_stat_archiver,
DOC-05 §8): the real archive lag, which the repository's newest object can't
show (old segments uploaded late look fresh). One row per db host."""
from alembic import op

revision = '0018'
down_revision = '0017'

SQL = """
CREATE TABLE db_archiver (
    host_id uuid PRIMARY KEY REFERENCES host(id),
    reported_at timestamptz NOT NULL,          -- ctl-1's clock, when the poll arrived
    db_at timestamptz NOT NULL,                -- the database server's clock at the report
    current_wal text NOT NULL,                 -- the segment being written
    last_archived_wal text,
    last_archived_at timestamptz,
    failed_count bigint NOT NULL,
    last_failed_at timestamptz
);
GRANT SELECT, INSERT, UPDATE ON db_archiver TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
