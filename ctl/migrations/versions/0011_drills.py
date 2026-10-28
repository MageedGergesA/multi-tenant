"""Restore drills (DOC-05 §5, DR-07, DR-13): restore attempts and the
DRILL_VERIFIED mark (DOC-03 §2.6, §7)."""
from alembic import op

revision = '0011'
down_revision = '0010'

SQL = """
-- [AO] one row per finished Tenant.RestoreToIsolated.
CREATE TABLE restore_attempt (
    id uuid PRIMARY KEY,
    operation_id uuid NOT NULL UNIQUE REFERENCES operation(id),
    backup_point_id uuid NOT NULL REFERENCES backup_point(id),
    source_environment_id uuid NOT NULL REFERENCES environment(id),
    target_environment_id uuid,
    purpose text NOT NULL CHECK (purpose IN ('drill', 'restore_to_stage', 'export_verify')),
    drill_kind text CHECK (drill_kind IN ('oldest', 'redrill', 'weekly_random', 'manual')),
    checks jsonb,
    evidence_sha256 text,                      -- the agent's signed evidence of the restore step
    result text NOT NULL CHECK (result IN ('pass', 'fail')),
    result_code text,
    measured_rto_seconds int,
    created_at timestamptz NOT NULL
);
CREATE INDEX restore_attempt_drills ON restore_attempt (source_environment_id, created_at DESC) WHERE purpose = 'drill';
CREATE TRIGGER restore_attempt_ao BEFORE UPDATE OR DELETE ON restore_attempt
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- RECOVERABLE ─(restore drill pass)─> DRILL_VERIFIED: a mark; the state stays recoverable.
ALTER TABLE backup_point ADD COLUMN drill_verified_at timestamptz;

GRANT SELECT, INSERT ON restore_attempt TO ctl_app;
GRANT UPDATE (drill_verified_at) ON backup_point TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
