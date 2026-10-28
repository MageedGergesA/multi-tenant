"""The L2 layer's state as ctl-1 reads it from bucket B (DOC-05 §2, §3.1, §8): one
row per pgBackRest stanza, written by the `l2` worker (ctlplane/l2.py)."""
from alembic import op

revision = '0017'
down_revision = '0016'

SQL = """
CREATE TABLE l2_status (
    stanza text PRIMARY KEY,
    checked_at timestamptz NOT NULL,           -- the last read of the repository that succeeded
    full_at timestamptz,                       -- the newest full backup's stop time
    backup_at timestamptz,                     -- the newest full or differential backup's stop time
    wal_at timestamptz,                        -- when the newest archived WAL segment was stored
    wal_segment text,
    expired_at timestamptz,                    -- the last `expire` that succeeded
    error text                                 -- the last failure, cleared by a success
);
GRANT SELECT, INSERT, UPDATE ON l2_status TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
