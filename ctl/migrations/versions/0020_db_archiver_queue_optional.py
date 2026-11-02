"""An agent from before 0019 reports no queue (Codex: its whole poll was refused): the queue
columns are NULL then, "unknown", not 0."""
from alembic import op

revision = '0020'
down_revision = '0019'

SQL = """
ALTER TABLE db_archiver ALTER COLUMN pending DROP NOT NULL, ALTER COLUMN pending DROP DEFAULT;
"""


def upgrade():
    op.execute(SQL)
