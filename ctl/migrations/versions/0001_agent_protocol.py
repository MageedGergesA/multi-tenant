"""The tables the agent protocol touches (DOC-03 §2.3–2.5, §2.7, §2.9 subset).

Columns follow DOC-03; only what dispatch, polling and responses need is here.
"""
from alembic import op

revision = '0001'
down_revision = None

SQL = """
CREATE TABLE signing_key (
    id uuid PRIMARY KEY,
    purpose text NOT NULL CHECK (purpose IN ('agent', 'dispatch', 'release', 'custodian', 'breakglass')),
    public_key text NOT NULL,                       -- Ed25519, base64
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);

CREATE TABLE host (
    id uuid PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('app', 'db', 'ctl', 'mail')),
    private_ip inet,
    state text NOT NULL CHECK (state IN ('provisioning', 'active', 'draining', 'maintenance', 'failed', 'retired')),
    agent_key_id uuid REFERENCES signing_key(id),
    agent_high_water_fence bigint NOT NULL DEFAULT 0,
    last_seen_at timestamptz,                      -- not in DOC-03: last authenticated poll
    row_version int NOT NULL DEFAULT 1
);

CREATE TABLE tenant (
    id uuid PRIMARY KEY,
    lifecycle_state text NOT NULL CHECK (lifecycle_state IN (
        'DRAFT', 'ELIGIBLE', 'RESERVED', 'PROVISIONING', 'VALIDATING', 'ACTIVE', 'MAINTENANCE',
        'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY', 'DELETION_ELIGIBLE', 'DELETED')),
    row_version int NOT NULL DEFAULT 1
);

CREATE TABLE environment (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    kind text NOT NULL CHECK (kind IN ('production', 'restore_copy')),
    observed_state text NOT NULL DEFAULT 'unknown'
        CHECK (observed_state IN ('unknown', 'starting', 'running', 'unhealthy', 'stopped', 'absent')),
    observed_at timestamptz,
    row_version int NOT NULL DEFAULT 1
);

CREATE SEQUENCE fencing_token_seq;                  -- global, strictly increasing (DOC-03 §6.2)

CREATE TABLE operation (
    id uuid PRIMARY KEY,
    type text NOT NULL,
    tenant_id uuid REFERENCES tenant(id),
    environment_id uuid REFERENCES environment(id),
    host_id uuid REFERENCES host(id),              -- the first step's agent; each step names its own
    idempotency_key text NOT NULL,
    params jsonb NOT NULL,
    params_sha256 bytea NOT NULL,
    state text NOT NULL CHECK (state IN ('REQUESTED', 'VALIDATED', 'RESERVED', 'DISPATCHED', 'APPLYING',
        'VERIFIED', 'COMPLETED', 'FAILED', 'RECOVERING', 'RECONCILING', 'REJECTED')),
    exclusive bool NOT NULL,
    fencing_token bigint,
    lease_owner text,
    lease_expires_at timestamptz,
    attempt int NOT NULL DEFAULT 1,
    result_code text,
    result_detail jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    row_version int NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, type, idempotency_key)
);
-- INV-21: one exclusive operation in flight per environment.
CREATE UNIQUE INDEX operation_one_exclusive ON operation (environment_id)
    WHERE exclusive AND state IN ('VALIDATED', 'RESERVED', 'DISPATCHED', 'APPLYING', 'VERIFIED',
                                  'RECONCILING', 'RECOVERING');
CREATE INDEX operation_lease ON operation (lease_expires_at) WHERE state IN ('DISPATCHED', 'APPLYING');

CREATE TABLE operation_step (
    operation_id uuid NOT NULL REFERENCES operation(id),
    seq int NOT NULL,
    name text NOT NULL,
    host_id uuid NOT NULL REFERENCES host(id),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'dispatched', 'applying', 'done', 'failed')),
    attempt int NOT NULL DEFAULT 0,
    deadline_at timestamptz,                        -- from the agent's heartbeats
    evidence_sha256 text,
    observed jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (operation_id, seq)
);

-- [AO] the transactional outbox: one row per envelope to hand out.
CREATE TABLE operation_event (
    id bigserial PRIMARY KEY,
    operation_id uuid NOT NULL REFERENCES operation(id),
    seq int NOT NULL,
    host_id uuid NOT NULL REFERENCES host(id),
    fencing_token bigint NOT NULL,
    not_before timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (operation_id, seq) REFERENCES operation_step(operation_id, seq)
);
CREATE INDEX operation_event_host ON operation_event (host_id, id);

-- Handing an event out is inserting its delivery row: the claim needs no lock
-- on the append-only outbox (see README).
CREATE TABLE operation_event_delivery (
    event_id bigint PRIMARY KEY REFERENCES operation_event(id),
    delivered_at timestamptz NOT NULL DEFAULT now(),
    nonce text NOT NULL
);

-- [AO] every response an agent sent, as received, with what was done with it.
CREATE TABLE agent_response (
    id bigserial PRIMARY KEY,
    host_id uuid NOT NULL REFERENCES host(id),
    response_sha256 text NOT NULL UNIQUE,
    op_id uuid,
    step text,
    fencing_token bigint,
    status text,
    code text,
    body jsonb NOT NULL,
    outcome text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_response_op ON agent_response (op_id);

CREATE FUNCTION reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
CREATE TRIGGER operation_event_ao BEFORE UPDATE OR DELETE ON operation_event
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER operation_event_ao_truncate BEFORE TRUNCATE ON operation_event
    FOR EACH STATEMENT EXECUTE FUNCTION reject_change();
CREATE TRIGGER agent_response_ao BEFORE UPDATE OR DELETE ON agent_response
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER agent_response_ao_truncate BEFORE TRUNCATE ON agent_response
    FOR EACH STATEMENT EXECUTE FUNCTION reject_change();
"""

# The application role (DOC-03 §0): INSERT and SELECT only on append-only tables.
GRANTS = """
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ctl_app') THEN
        CREATE ROLE ctl_app NOLOGIN;
    END IF;
END $$;
GRANT SELECT, INSERT, UPDATE ON signing_key, host, tenant, environment, operation, operation_step TO ctl_app;
GRANT SELECT, INSERT ON operation_event, operation_event_delivery, agent_response TO ctl_app;
GRANT USAGE ON SEQUENCE fencing_token_seq, operation_event_id_seq, agent_response_id_seq TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
    op.execute(GRANTS)
