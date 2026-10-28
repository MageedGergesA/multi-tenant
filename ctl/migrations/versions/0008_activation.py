"""VALIDATING → ACTIVE (DOC-03 §3.6, §5; INV-4, INV-15).

The data placement manifest is written when a tenant is placed; terms
acceptance is recorded by billing; every activation check is kept with its
results, and activation names the check it rests on.
"""
from alembic import op

revision = '0008'
down_revision = '0007'

SQL = """
ALTER TABLE region ADD COLUMN backup_bucket text;

-- [AO, versioned] DOC-03 §2.4 (DAT-01, RUN-12)
CREATE TABLE data_placement_manifest (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    version int NOT NULL,
    region_id uuid NOT NULL REFERENCES region(id),
    db_host_id uuid NOT NULL REFERENCES host(id),
    app_host_id uuid NOT NULL REFERENCES host(id),
    backup_bucket text,
    log_sink text,
    mail_provider text,
    finance_system_location text,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, version)
);

-- [AO] DOC-03 §2.1 keeps this per organization (not built) and without the
-- region accepted; here per tenant, with the region (INV-15 needs it).
CREATE TABLE terms_acceptance (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    terms_version text NOT NULL,
    document_sha256 text NOT NULL CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    accepted_by_name text NOT NULL,
    accepted_at timestamptz NOT NULL,
    covers text[] NOT NULL CHECK (covers @> ARRAY['region', 'retention', 'no_ha', 'no_pitr', 'nonpayment', 'exit',
                                                  'backup_expiry']),            -- INV-4
    region_code text NOT NULL,
    recorded_by uuid REFERENCES operator(id),
    recorded_at timestamptz NOT NULL
);

-- [AO] each evaluation of §3.6, kept; activation points at one.
CREATE TABLE activation_check (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    environment_id uuid REFERENCES environment(id),
    results jsonb NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('pass', 'fail', 'incomplete')),
    evaluated_by uuid REFERENCES operator(id),
    evaluated_at timestamptz NOT NULL
);
ALTER TABLE tenant
    ADD COLUMN activation_check_id uuid REFERENCES activation_check(id),
    ADD COLUMN activated_by uuid REFERENCES operator(id),
    ADD COLUMN activated_at timestamptz;

DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['data_placement_manifest', 'terms_acceptance', 'activation_check'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION reject_change()',
                       t || '_ao', t);
    END LOOP;
END $$;

GRANT SELECT, INSERT ON data_placement_manifest, terms_acceptance, activation_check TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
