"""Backup retention (DOC-05 §3; DOC-03 §7 RECOVERABLE → EXPIRED; DOC-04 §2
custodian approval of backup-retention deletion)."""
from alembic import op

revision = '0010'
down_revision = '0009'

SQL = """
ALTER TABLE secret_ref DROP CONSTRAINT secret_ref_kind_check;
ALTER TABLE secret_ref ADD CONSTRAINT secret_ref_kind_check CHECK (kind IN (
    'db_password', 'admin_passwd', 'smtp', 'tenant_salt', 'tenant_admin_password', 'b2_write_key',
    'region_restore_key', 'b2_retention_key'));
ALTER TABLE region ADD COLUMN retention_key_ref uuid REFERENCES secret_ref(id);
ALTER TABLE backup_point ADD COLUMN expired_at timestamptz;

CREATE TABLE retention_batch (
    id uuid PRIMARY KEY,
    body jsonb NOT NULL,                       -- what the custodian signs: action, batch, items hash, expiry
    items jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('drafted', 'approved', 'executed', 'abandoned')),
    drafted_at timestamptz NOT NULL,
    approval jsonb,
    approved_by uuid REFERENCES operator(id),
    breakglass_used bool NOT NULL DEFAULT false,
    executed_at timestamptz,
    results jsonb
);
CREATE UNIQUE INDEX retention_batch_one_open ON retention_batch ((true)) WHERE state IN ('drafted', 'approved');

-- Operational switches (DOC-07 RB-04: freeze retention deletions).
CREATE TABLE ctl_flag (
    name text PRIMARY KEY,
    value text NOT NULL,
    set_by uuid REFERENCES operator(id),
    set_at timestamptz NOT NULL
);

GRANT SELECT, INSERT, UPDATE ON retention_batch, ctl_flag TO ctl_app;
GRANT UPDATE (retention_key_ref) ON region TO ctl_app;
GRANT UPDATE (state, expired_at) ON backup_point TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
