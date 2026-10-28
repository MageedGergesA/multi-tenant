"""Alertmanager → incident (DOC-03 §2.9): one open incident per alert fingerprint."""
from alembic import op

revision = '0009'
down_revision = '0008'

SQL = """
ALTER TABLE incident ADD COLUMN alert_fingerprint text;
CREATE UNIQUE INDEX incident_open_alert ON incident (alert_fingerprint)
    WHERE alert_fingerprint IS NOT NULL AND resolved_at IS NULL;
"""


def upgrade():
    op.execute(SQL)
