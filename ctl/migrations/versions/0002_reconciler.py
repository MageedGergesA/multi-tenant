"""Reconciler (DOC-03 §6): read-back probes, the RECONCILING clock, incidents (§2.9 subset)."""
from alembic import op

revision = '0002'
down_revision = '0001'

SQL = """
ALTER TABLE operation
    ADD COLUMN reconciles_operation_id uuid REFERENCES operation(id),   -- set on Agent.Query probes
    ADD COLUMN reconciling_since timestamptz,                           -- start of the current episode
    -- +1 on each entry to RECONCILING; a probe carries its target's epoch, so an
    -- answer from an earlier episode is never used.
    ADD COLUMN reconcile_epoch int NOT NULL DEFAULT 0;
CREATE INDEX operation_probe ON operation (reconciles_operation_id) WHERE reconciles_operation_id IS NOT NULL;
CREATE INDEX operation_reconciling ON operation (reconciling_since) WHERE state = 'RECONCILING';

CREATE TABLE incident (
    id uuid PRIMARY KEY,
    severity text NOT NULL CHECK (severity IN ('sev1', 'sev2', 'sev3', 'sev4')),
    scope_tenant_ids uuid[] NOT NULL DEFAULT '{}',
    operation_id uuid REFERENCES operation(id),
    summary text NOT NULL,
    runbook_ref text,
    opened_at timestamptz NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamptz,
    resolved_at timestamptz
);
GRANT SELECT, INSERT, UPDATE ON incident TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
