"""Admission before dispatch (DOC-03 §2.1, §2.6, §2.9, §6.3): operators and
their roles, placement, backup points for DR-06, approvals, the audit chain."""
from alembic import op

revision = '0003'
down_revision = '0002'

SQL = """
CREATE TABLE operator (
    id uuid PRIMARY KEY,
    oidc_subject text UNIQUE NOT NULL,
    display_name text,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'retired')),
    mfa_verified_at timestamptz
);

CREATE TABLE operator_role_grant (
    id uuid PRIMARY KEY,
    operator_id uuid NOT NULL REFERENCES operator(id),
    role text NOT NULL CHECK (role IN ('platform_operator', 'billing_admin', 'backup_custodian', 'auditor')),
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    granted_by uuid NOT NULL REFERENCES operator(id),
    CHECK (granted_by <> operator_id)                                  -- INV-1
);

-- Placement (DOC-03 keeps it in runtime_slot, db_binding and mail_identity,
-- which Tenant.Create will write; until then, the hosts directly).
ALTER TABLE environment
    ADD COLUMN app_host_id uuid REFERENCES host(id),
    ADD COLUMN db_host_id uuid REFERENCES host(id),
    ADD COLUMN mail_host_id uuid REFERENCES host(id);

ALTER TABLE operation
    ADD COLUMN requested_by uuid REFERENCES operator(id),
    ADD COLUMN precondition_backup_id uuid,
    ADD COLUMN approval jsonb,              -- the custodian-signed object, sent in the envelope
    ADD COLUMN breakglass_used bool NOT NULL DEFAULT false;

CREATE TABLE backup_point (
    id uuid PRIMARY KEY,                    -- the Tenant.Backup backup_id
    environment_id uuid NOT NULL REFERENCES environment(id),
    operation_id uuid NOT NULL REFERENCES operation(id),
    trigger text NOT NULL CHECK (trigger IN ('scheduled', 'pre_operation', 'manual')),
    retention_tier text NOT NULL,
    snapshot_at timestamptz,
    gc_guard_held bool NOT NULL,
    referenced_files int,
    missing_files int,
    db_dump_sha256 text,
    archive_sha256 text,
    object_version_id text,
    lock_until timestamptz,                 -- as read back from the bucket
    state text NOT NULL CHECK (state IN ('planned', 'guarded', 'dumped', 'copied', 'verified_local',
                                         'recoverable', 'failed', 'expired')),
    created_at timestamptz NOT NULL
);
CREATE INDEX backup_point_recent ON backup_point (environment_id, snapshot_at DESC) WHERE state = 'recoverable';
ALTER TABLE operation ADD FOREIGN KEY (precondition_backup_id) REFERENCES backup_point(id);

-- [AO] SEC-13: hash = SHA-256(prev_hash || canonical(row)).
CREATE TABLE audit_event (
    seq bigserial PRIMARY KEY,
    at timestamptz NOT NULL,
    actor_kind text NOT NULL CHECK (actor_kind IN ('operator', 'agent', 'system')),
    actor_id uuid,
    action text NOT NULL,
    tenant_id uuid,
    resource_type text,
    resource_id uuid,
    before jsonb,
    after jsonb,
    correlation_id uuid,
    prev_hash bytea NOT NULL,
    hash bytea NOT NULL UNIQUE
);
CREATE TRIGGER audit_event_ao BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER audit_event_ao_truncate BEFORE TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION reject_change();

GRANT SELECT ON operator, operator_role_grant TO ctl_app;
GRANT UPDATE (mfa_verified_at) ON operator TO ctl_app;
GRANT SELECT, INSERT, UPDATE ON backup_point TO ctl_app;
GRANT SELECT, INSERT ON audit_event TO ctl_app;
GRANT USAGE ON SEQUENCE audit_event_seq_seq TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
