"""The quarterly control-plane drill (DOC-05 §5): one row per drill an operator
runs against a temporary server."""
from alembic import op

revision = '0014'
down_revision = '0013'

SQL = """
-- [AO]
CREATE TABLE ctl_drill (
    id uuid PRIMARY KEY,
    dump_object_key text,
    dump_sha256 text,
    key_kind text NOT NULL CHECK (key_kind IN ('operational', 'recovery')),
    target text NOT NULL,                      -- host:port/dbname, no credentials
    expected_revision text,
    schema_revision text,
    first_bad_seq bigint,
    anchors_matched int,
    anchors_mismatched int,
    anchors_beyond int,
    result text NOT NULL CHECK (result IN ('pass', 'fail')),
    reason text,
    measured_seconds int NOT NULL,
    evidence_id uuid REFERENCES evidence_artifact(id),
    run_by uuid NOT NULL REFERENCES operator(id),
    created_at timestamptz NOT NULL
);
CREATE TRIGGER ctl_drill_ao BEFORE UPDATE OR DELETE ON ctl_drill
    FOR EACH ROW EXECUTE FUNCTION reject_change();

GRANT SELECT, INSERT ON ctl_drill TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
