"""Runtime slots and capacity (DOC-03 §2.3, §2.4, §5; INV-8, INV-10, INV-13).

A slot is where an environment runs: its host, a container UID never reused
platform-wide, and a loopback port pair unique on that host while live.
Reservations are held at admission and committed once the operation has run;
they free the host only when the environment is removed.
"""
from alembic import op

revision = '0005'
down_revision = '0004'

SQL = """
-- The contracted size (ADR-011 "derived from the plan band").
CREATE TABLE resource_bundle (
    id uuid PRIMARY KEY,
    code text UNIQUE NOT NULL,
    workers int NOT NULL, max_cron_threads int NOT NULL, db_maxconn int NOT NULL,
    limit_memory_soft bigint NOT NULL, limit_memory_hard bigint NOT NULL,
    limit_time_cpu int NOT NULL, limit_time_real int NOT NULL,
    mem_limit_bytes bigint NOT NULL, cpu_millis int NOT NULL,
    disk_gb int NOT NULL,                      -- filestore, on the app host
    db_disk_gb int NOT NULL                    -- database, on the DB host
);

ALTER TABLE host
    ADD COLUMN total_vcpu_milli int NOT NULL DEFAULT 0,
    ADD COLUMN total_ram_mb int NOT NULL DEFAULT 0,
    ADD COLUMN total_disk_gb int NOT NULL DEFAULT 0,
    ADD COLUMN pg_max_connections int,
    ADD COLUMN reserve_pct int NOT NULL DEFAULT 20 CHECK (reserve_pct BETWEEN 0 AND 90),
    ADD COLUMN port_low int NOT NULL DEFAULT 20000,
    ADD COLUMN port_high int NOT NULL DEFAULT 29999;

ALTER TABLE tenant ADD COLUMN resource_bundle_id uuid REFERENCES resource_bundle(id);
ALTER TABLE tenant DROP CONSTRAINT tenant_lifecycle_state_check;
ALTER TABLE tenant ADD CONSTRAINT tenant_lifecycle_state_check CHECK (lifecycle_state IN (
    'DRAFT', 'ELIGIBLE', 'RESERVED', 'PROVISIONING', 'VALIDATING', 'ACTIVE', 'MAINTENANCE', 'ERROR',
    'SUSPENSION_NOTICE', 'SUSPENDED', 'CANCELLING', 'EXPORT_READY', 'DELETION_ELIGIBLE', 'DELETED'));
ALTER TABLE environment ADD COLUMN resource_bundle_id uuid REFERENCES resource_bundle(id);
CREATE UNIQUE INDEX environment_one_production ON environment (tenant_id) WHERE kind = 'production';   -- INV-10

-- INV-13: the agent's schema takes 10001..59999; a sequence that never cycles never reuses one.
CREATE SEQUENCE container_uid_seq MINVALUE 10001 MAXVALUE 59999 NO CYCLE;

CREATE TABLE runtime_slot (
    environment_id uuid PRIMARY KEY REFERENCES environment(id),
    host_id uuid NOT NULL REFERENCES host(id),
    container_uid int NOT NULL UNIQUE,
    http_port int NOT NULL,
    gevent_port int NOT NULL,
    workers int NOT NULL, max_cron_threads int NOT NULL, db_maxconn int NOT NULL,
    limit_memory_soft bigint NOT NULL, limit_memory_hard bigint NOT NULL,
    limit_time_cpu int NOT NULL, limit_time_real int NOT NULL,
    mem_limit_bytes bigint NOT NULL, cpu_millis int NOT NULL,
    created_at timestamptz NOT NULL,
    released_at timestamptz,                   -- the row stays: the UID is never handed out again
    CHECK (http_port % 2 = 0 AND gevent_port = http_port + 1)     -- pairs never overlap
);
CREATE UNIQUE INDEX runtime_slot_port ON runtime_slot (host_id, http_port) WHERE released_at IS NULL;

CREATE TABLE capacity_reservation (
    id uuid PRIMARY KEY,
    host_id uuid NOT NULL REFERENCES host(id),
    environment_id uuid NOT NULL REFERENCES environment(id),
    operation_id uuid NOT NULL REFERENCES operation(id),
    vcpu_milli int NOT NULL, ram_mb int NOT NULL, disk_gb int NOT NULL, pg_conn int NOT NULL,
    state text NOT NULL CHECK (state IN ('held', 'committed', 'released')),
    expires_at timestamptz,                    -- held only
    created_at timestamptz NOT NULL,
    CHECK (state <> 'held' OR expires_at IS NOT NULL)
);
CREATE INDEX capacity_reservation_live ON capacity_reservation (host_id) WHERE state IN ('held', 'committed');

GRANT SELECT ON resource_bundle TO ctl_app;
GRANT SELECT, INSERT, UPDATE ON runtime_slot, capacity_reservation TO ctl_app;
GRANT INSERT ON environment TO ctl_app;
GRANT USAGE ON SEQUENCE container_uid_seq TO ctl_app;
"""


def upgrade():
    op.execute(SQL)
