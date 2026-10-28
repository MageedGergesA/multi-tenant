# ctl-1: control plane (ADR-009, DOC-03)

FastAPI with its own PostgreSQL 16; plain-SQL migrations under Alembic. So far,
the agent side of the protocol (dispatch, polling, responses, leases), the
reconciler, the operator API with admission before dispatch, envelope secrets
and release manifests, runtime slots and capacity, host enrollment, trust
rotation, the VALIDATING → ACTIVE checks, restore-copy expiry, the daily
backup schedule, backup retention and the 26-hour backup alert.

    python3.12 -m venv .venv && .venv/bin/pip install -e '.[test]'   # and hostagent: see "Dev"
    dev/up.sh                       # ctl-pg on 127.0.0.1:55433 (password in dev/.env, mode 600)
    .venv/bin/python -m pytest -q   # a throwaway database per test

## What is built

- `migrations/versions/0001_agent_protocol.py`: `signing_key`, `host`,
  `tenant`, `environment`, `operation`, `operation_step`, `operation_event`
  [AO], `operation_event_delivery`, `agent_response` [AO], the global
  `fencing_token_seq`, INV-21 as a partial unique index, and the `ctl_app`
  role: INSERT/SELECT only on the append-only tables, plus a trigger that
  refuses UPDATE/DELETE/TRUNCATE even for the owner. The store runs as
  `ctl_app`.
- `store.py`:
  - `dispatch`: operation, steps and the first step's event in one
    transaction; idempotency key returns the existing operation; INV-21 →
    `Conflict`. It enters at DISPATCHED: schema, authz, preconditions and
    capacity (REQUESTED → RESERVED) are the API layer, not built.
  - `claim(host, capacity)`: that host's due events, each handed out once, as
    envelopes signed with the dispatch key at hand-out (life 300 s).
  - `apply(host, response)`: verifies the host's agent signature, that the
    body's `host_id` is the poster, the evidence hash, and that the response is
    for this host's current step and the operation's current token. Then:
    `in_progress` → APPLYING and lease extension; `done` → next step (to its
    own host) or VERIFIED → COMPLETED; `TIMEOUT`/`STALE_FENCE` → RECONCILING;
    `BUSY`/`RATE_LIMITED`/`EXPIRED` → the same step again after a backoff,
    FAILED after 5 tries; `REPLAY` → nothing; anything else → FAILED with the
    code and the agent's `observed`. Every response is stored as received with
    its outcome; a second delivery is `duplicate`.
  - `expire_leases`: DISPATCHED/APPLYING past the lease → RECONCILING.
- `agent_api.py`: `POST /v1/agents/<host_id>/poll` (long poll, `wait` ≤ 60,
  `capacity` ≤ 32) and `/responses` (≤ 200 per request, returns the
  outcomes). The client certificate subject must be exactly `CN=<host_id>`
  and the host in `provisioning|active|draining|maintenance`; otherwise 403.
- `tls.py`: uvicorn with `CERT_REQUIRED` against the pinned CA, TLS 1.3 only,
  request bodies capped at 4 MiB (400).
- `catalog.py`: DOC-04 §6 steps and §8 timeouts/leases.
- `reconciler.py` (migration 0002): for each RECONCILING operation, an
  `Agent.Query` probe to every host whose step has an unknown outcome, through
  the same outbox and response checks. From the journal rows of the current
  token: all done → VERIFIED → COMPLETED; still running → APPLYING, same
  token; not started, `busy` or cut short (`TIMEOUT`) → re-dispatched from
  that step with a new token; another failure code → FAILED with it. No
  answer for 30 min → FAILED `UNREACHABLE` + sev2 incident. A probe past its
  lease, or answered with a failure, just fails and the next round sends
  another. `run_once` also expires leases; `main` loops it every 5 s.

- `operator_api.py` + `auth.py` + `admission.py` (migration 0003): the
  operator API. `POST /v1/operations`, `POST /v1/operations/<id>/approval`,
  `GET /v1/operations/<id>`. Bearer OIDC ID token checked against a pinned
  issuer, audience and JWKS; the operator must be `active` with a current
  role grant (INV-1: no self-grant). Requests and approvals need
  `platform_operator` (approvals also `backup_custodian`) and MFA newer than
  12 h (`amr` with mfa/hwk/swk, `auth_time`), recorded in `mfa_verified_at`;
  any role may read. Admission: REQUESTED → VALIDATED (known type ctl-1 can
  build, DOC-04 params schema, scope: tenant+environment or host, the
  environment belongs to the tenant, RestoreCopy.Expire never on production
  or another tenant's environment, INV-21) → RESERVED (tenant-state gate,
  DR-06: a `recoverable` backup point < 1 h old becomes
  `precondition_backup_id`, placement for every step's role) → DISPATCHED.
  RestoreProduction and Delete wait in VALIDATED (`AWAITING_APPROVAL`) for an
  approval signed by a `custodian` key, or the `breakglass` key while
  enabled (sev2 incident); the gate and DR-06 are checked again then, and the
  approval travels in the envelope. A refused approval is audited. Every
  step is in `audit_event`.
- `audit.py`: `audit_event` [AO], `hash = SHA-256(prev_hash ‖ canonical(row))`,
  appends serialised by an advisory lock; `verify_chain` finds the first
  broken row.
- `store.py` records a `backup_point` from Tenant.Backup evidence:
  `recoverable` only with zero missing files, the guard held, a snapshot
  time and the read-back lock covering the planned retention (INV-16),
  otherwise `failed`.

- `vault.py` + `releases.py` (migration 0004): envelope secrets and release
  manifests.
  - Per-tenant secrets (`db_password`, `admin_passwd`, `smtp`, `tenant_salt`,
    `tenant_admin_password`) are generated by ctl-1 (`vault.provision`) and
    stored only as age ciphertext to the dispatcher's recipient, bound to the
    environment by purpose. Region secrets (B2 write key, operational
    restore key, DOC-05 §4) arrive already encrypted:
    `PUT /v1/regions/<code>/secrets/<kind>` refuses anything that isn't age
    ciphertext, and the old one is revoked; `GET /v1/dispatcher/recipient`
    gives operators the key to encrypt to.
  - Two DB roles: the operator API runs as `ctl_app`, which can add secrets
    and see their metadata but has no SELECT on `ciphertext`; only
    `ctl_dispatcher` (the agent API) reads it, and only the dispatcher holds
    the age identity.
  - At hand-out the dispatcher opens what the step needs (`vault.SOURCES`,
    equal to the agent's `secrets.ALLOWED`), derives the SCRAM verifier and
    Odoo's `pbkdf2_sha512` hash, takes the region's B2 key and recipient or
    restore key from the step host's region, and seals the set to that
    host's X25519 key. Envelopes are never stored. A secret that can't be
    produced fails the operation `SECRET_UNAVAILABLE` (a known outcome, not a
    retry); admission checks the same things first.
  - `POST /v1/releases` takes a manifest signed with the release key: schema
    (DOC-04), signature against `release` keys, cell `available`, the digest
    immutable; `approved` only with evidence for that digest
    (`evidence_artifact`, INV-6 also as a CHECK), otherwise
    `evidence_pending` until re-sent with it. `POST /v1/releases/revoke`.
  - The release an operation starts: ApplyPatch / ModuleUpdate the target
    digest (approved, same cell as the environment's current release,
    change class `patch` / `patch|module_update`, modules within the
    manifest); everything else the environment's current release. The
    signed manifest goes in the envelope verbatim; completion moves
    `environment.image_release_id`. A release revoked after dispatch is
    never handed out (`RELEASE_REVOKED`).
  - Now dispatchable: Backup (ctl-1 generates `backup_id`), ApplyPatch,
    ModuleUpdate.
- `capacity.py` (migration 0005): runtime slots and capacity (INV-8,
  INV-10, INV-13), which make Create and RestoreToIsolated requestable.
  - Operators send only their part: Create `{domains, modules, lang,
    country}` for an ELIGIBLE tenant; RestoreToIsolated `{backup_id,
    purpose}` on the production environment. ctl-1 fills in the rest of
    DOC-04's params (`runtime_slot`, `app_host_ip`, `target_environment_id`)
    and checks the result against the agent's schema; a caller can't choose
    a slot or a target.
  - Size comes from the tenant's `resource_bundle` (workers, limits, memory,
    CPU, filestore and DB disk). Per environment it holds the bundle's CPU,
    memory and filestore disk on the app host, and its DB disk plus
    `(workers + max_cron_threads + 1) × db_maxconn + 1` connections on the
    DB host (ADR-004).
  - Placement: active app and DB hosts in one region, each locked before its
    usage is summed; the app host with the most free memory that fits wins.
    INV-8 per host: held (unexpired) + committed ≤ total × (100 −
    reserve_pct)% in every dimension. A restore copy goes beside its source
    (same app and DB hosts). Create also needs an active mail host in the
    region.
  - Slot: a container UID from a sequence that never cycles (10001–59999,
    the agent's range: never reused, INV-13) and the lowest free even/odd
    port pair in the host's range; the slot row stays when released, so
    ports come back and UIDs don't.
  - Create: new production environment (INV-10 also a unique index) with the
    newest approved release of the tenant's cell, fresh secrets, tenant
    ELIGIBLE → RESERVED → PROVISIONING. RestoreToIsolated: the backup must be
    `recoverable` and this environment's (INV-17); a new `restore_copy`
    environment with its own slot and secrets, expiring in 7 days.
  - Everything allocated runs in one savepoint: a refusal (`CAPACITY`,
    `NO_PLACEMENT`, …) leaves no environment, slot, reservation or secret.
  - When an operation ends (COMPLETED or FAILED) its reservations are
    committed. Delete and RestoreCopy.Expire, once completed, release the
    environment's reservations and ports and mark it `absent`; Delete also
    moves the tenant to DELETED. Create completed → tenant VALIDATING
    (ACTIVE needs the §3.6 checks), failed → ERROR.
- `enrollment.py` + `enroll_api.py` (migration 0006): `Host.Enroll`.
  - `POST /v1/hosts` (role, region, private IP, totals) makes a
    `provisioning` host and opens its enrollment; `POST
    /v1/hosts/<id>/enrollment` re-enrolls one. Either returns the bootstrap
    token once (only its hash is kept; it belongs in the SOPS repo, DOC-07)
    and the authorization body: host, role, region, IP, token hash, expiry
    (24 h), and the trust to pin (the dispatch, custodian and break-glass
    keys registered in `signing_key`, and whether break-glass is on).
  - `POST /v1/hosts/<id>/enrollment/authorize` takes that body signed with
    the release key ("Enroll: R"), offline by the founder; it must be the
    open body exactly. Until then the token opens nothing.
  - `POST /v1/enroll` on its own listener (server TLS only: the agent has no
    certificate yet): token, the agent's Ed25519 and X25519 public keys, a
    CSR, and a proof signed by the new Ed25519 key over host, token hash,
    X25519 key and CSR. Unknown host, wrong token, not yet authorized or
    expired all get the same 403; 5 wrong tokens revoke the enrollment.
    After the token, bad keys or CSR say what's wrong and leave the token
    usable. The CSR must be exactly CN=<host_id> on EC P-256. ctl-1 issues a
    365-day client certificate (clientAuth), retires the host's previous
    agent key, registers the new keys, pins the certificate's fingerprint,
    and the host goes `provisioning → active`.
  - The agent API now accepts only that certificate per host (fingerprint,
    as well as the CN): re-enrolling revokes the old one without a CRL.
- `trust.py` (migration 0007): `Host.RotateTrust`.
  - `POST /v1/trust` drafts the next fleet trust document from
    `signing_key`: dispatch keys, custodian keys, break-glass and whether
    it's on, and every enrolled agent's key. `POST
    /v1/trust/<version>/authorize` takes it signed with the release key (the
    pending draft exactly) and makes it active. `POST /v1/trust/rollout`
    requests Host.RotateTrust for every enrolled host below that version;
    admission always fills in the active document and refuses a host that
    already has it. `GET /v1/trust` shows each host's version, which moves
    when its rotation completes.
  - The envelope is signed with the current dispatch key and carries the
    release-signed document: the two signatures DOC-04 §2 asks for.
  - Enrollment builds its trust the same way and carries the active
    version, so a new host isn't sent a rotation it already has.
  - Rotating the dispatch key (runbook in `trust.py`): register the new key,
    publish and roll out a document with both, switch ctl-1 once every host
    reports that version, retire the old key, publish and roll out again.
- `activation.py` (migration 0008): VALIDATING → ACTIVE (DOC-03 §3.6, §5).
  - `POST /v1/tenants/<id>/activation/check` evaluates six checks from what
    ctl-1 holds, each `pass`, `fail` or `missing`: health (login 200,
    websocket 101, from Create's `app.health`), HTTPS on the public hostname
    (`https_login` 200, `https_websocket` 101 and `certificate: issued`), the
  database manager
    (database service refused on loopback and 403 on the public path), the
    image digest (the release digest resolved by `app.image` and run by
    `app.container`), a first `recoverable` backup point, and the placement
    manifest's region equal to the accepted terms' region (INV-15). Every
    evaluation is kept (`activation_check`, append-only); a `fail` sends a
    VALIDATING tenant to ERROR, `missing` leaves it waiting.
  - `POST /v1/tenants/<id>/activation {check_id}` is the operator's
    confirmation: the latest check, `pass`, under an hour old, the tenant
    still VALIDATING; the evidence is evaluated again before the state
    moves. The tenant records the check and who activated it.
  - Create writes `data_placement_manifest` (region, hosts, the region's
    backup bucket, and the log, mail and finance locations from
    configuration). `POST /v1/tenants/<id>/terms` records a terms
    acceptance (billing_admin or platform_operator); INV-4 is a CHECK.
  - Tenant.Backup is now allowed in VALIDATING (finding 44).
- `expiry.py`: the restore-copy expiry sweep (DOC-03 §9.5). `run_once`
  requests RestoreCopy.Expire, as the system (`requested_by` empty, audit
  actor `system`), through the same admission as an operator, for every
  live copy past `expires_at`, and at once for a copy whose
  RestoreToIsolated failed (DOC-07). It skips a copy with an Expire already
  in flight and one whose production environment is busy (INV-21); a refused
  or failed attempt is retried next round under a new idempotency key, and
  after 3 the copy is left to an operator with one sev3 incident.
  `main` loops it (5 min).
- `backup_schedule.py`: the daily L1 backup (DOC-05 §2, §3). Window
  22:00–04:00 UTC, each tenant's start minute a hash of its `tenant_id`.
  From that slot until the next window opens, every production
  environment of a tenant in VALIDATING through DELETION_ELIGIBLE gets one
  Tenant.Backup requested by the system (backup point `trigger:
  scheduled`); a window missed while ctl-1 was down still runs later that
  day. Tier fixed at creation: monthly while the environment has no
  recoverable monthly backup this month, else weekly when the run falls on
  a Sunday, else daily; locks 93/29/8 days. It waits while the environment
  has an exclusive operation in flight and while the app host already runs
  `max_per_host` backups (2 by default; DOC-06 sets N); retries a refused or
  failed run within the window under a new key, 3 times, after which the
  26-hour alert is the backstop. `main` loops it every minute.
- `retention.py` (migration 0010): backup retention (DOC-05 §3), in
  batches the backup custodian approves.
  - Kept per environment: the newest recoverable 7 daily, 4 weekly and 3
    monthly; other tiers aren't kept past their lock, and nothing is kept
    for a removed environment (Delete, RestoreCopy.Expire), so a deleted
    tenant's data is gone at its last `lock_until`. A candidate's lock has
    passed by an hour and no operation in flight refers to it; completed
    backups whose evidence failed are cleaned up the same way if an object
    was stored.
  - `POST /v1/retention/draft` lists them in a batch whose body (action,
    batch id, SHA-256 of the items, 48 h expiry) the custodian signs;
    `POST /v1/retention/<id>/approve` checks the signature (break-glass
    while enabled: sev2). Execution (`run_once`, in the worker that holds
    the dispatcher identity) refuses items changed since approval, checks
    each again, deletes that exact object version with the region's
    retention key (`b2_retention_key`, uploaded as ciphertext like the
    other region secrets), and marks the point `expired`.
    `POST /v1/retention/freeze` stops it (RB-04).
- `drills.py` (migration 0011): L1 restore drills (DOC-05 §5, DR-07,
  DR-13; RB-04).
  - Between 06:00 and 10:00 UTC, one at a time, the system requests
    `Tenant.RestoreToIsolated {purpose: drill}` through the operator
    admission (so the copy is placed and holds capacity, INV-8). Order: a
    re-drill of an environment whose last drill failed (outside the daily
    quota); then the environment drilled longest ago (never drilled first),
    its latest recoverable backup, `per_day` a day (default 1) but at least
    ceil(N / 28) so every environment comes round within 30 days; then, once
    a week, a random environment, random tier (daily, weekly, monthly) and
    random backup of it, as a deep drill. Idempotency key `drill:<date>:<kind>:<n>`; a
    refused request is retried next round, at most 3 a day. Busy
    environments (an exclusive operation in flight) wait.
  - Every finished RestoreToIsolated writes an append-only `restore_attempt`
    (backup, source and copy, purpose, drill kind, the agent's checks and
    evidence hash, pass/fail, measured RTO). ctl-1 checks the DOC-04 §6.9
    set itself: signature, tenant, environment, backup id, login, module
    list, files, zero egress (`not_measured` accepted only there: dry-run
    nftables). A pass marks the backup `drill_verified_at`
    (DRILL_VERIFIED) and expires the copy at once (the expiry sweep removes
    it). A fail opens a sev2 incident (RB-04); a second in a row says
    "manual investigation and a customer notice" and takes the environment
    out of the rotation until an operator's drill passes.
- `monitoring.py` + `monitoring/rules/` (migration 0009): the 26-hour backup
  alert (DOC-05 §8, ADR-008, RB-01), served on loopback for the Prometheus
  and Alertmanager on ctl-1.
  - `GET /metrics`: `ctl_backup_last_recoverable_timestamp_seconds`
    per production environment of a tenant that should be backed up
    (ACTIVE through DELETION_ELIGIBLE; not VALIDATING, whose first backup is
    part of activation): the snapshot time of its newest `recoverable`
    backup point of any tier, 0 if none.
  - `monitoring/rules/backups.yml`: `NoRecoverableDailyBackup` (sev2,
    RB-01) when that is older than 26 h, and `CtlMetricsDown` (sev2) when
    ctl-1 isn't scraped for 10 min, since without series the first alert
    can't fire. `backups_test.yml` is the promtool test.
  - `ctl_drill_last_pass_timestamp_seconds`: the last passed drill, or for
    an environment never drilled the snapshot time of its first recoverable
    backup. `monitoring/rules/drills.yml`: `TenantNotDrilled` (sev3, RB-04)
    past 30 days; `drills_test.yml` is its promtool test.
  - `POST /v1/alertmanager`: Alertmanager's webhook, with a bearer token
    (only its SHA-256 is configured). A firing alert opens one incident per
    fingerprint (severity from its label, sev3 if not sev1–4; tenant scope
    from `tenant_id` if it is one); resolved closes it.
  - Prometheus scrapes it as `job="ctl"`; Alertmanager's receiver for
    incidents is a `webhook_configs` entry pointing at it with
    `http_config.authorization.credentials` set to the token, beside the
    Telegram and email receivers ADR-008 names.
- `cpbackup.py` (migration 0012): the control plane's own backup to bucket C
  (DOC-05 §1, §2, §4; SEC-13; RB-09).
  - `dump`, 03:30 UTC daily and through `migrate` before every schema
    migration: `pg_dump -Fc` as the owner (the password reaches libpq
    through the environment, never the command line), age-encrypted to
    every active region's operational key and to the recovery key, put with
    a SHA-256 checksum under compliance Object Lock (31 days; the first
    scheduled dump of a month 366) and read back by version: checksum and
    lock date as sent, otherwise `ReadBackMismatch` and a sev1 incident.
    Recorded in `ctl_dump` [AO] and the audit log.
  - `anchor`, 04:00 UTC daily: verifies the hash chain, checks it against
    every version of every anchor in the bucket (a newer version or a delete
    marker can't hide a locked one), then writes the last `audit_event`
    (seq, hash) locked 366 days and records it in `audit_anchor` [AO]. A
    broken chain, an anchor that doesn't match, or one past the last row (a
    rolled-back database) opens one sev1 incident (RB-09) and nothing is
    anchored.
  - `verify(target_dsn, identities, key=None)`: the control-plane drill and
    RB-09 step 4. Downloads a dump (the newest by default), checks its
    SHA-256, decrypts it with the given identity, `pg_restore`s it into an
    empty database, and passes if its schema revision equals the one the dump
    was labelled with, the chain verifies, and no anchor it covers differs.
    Anchors newer than the dump are counted as `beyond`, as expected.
  - `run_once`: each job once a day after its time, catching up later in the
    day if ctl-1 was down; a failure is retried next round.
  - Metrics `ctl_controlplane_dump_last_timestamp_seconds` and
    `ctl_audit_anchor_last_timestamp_seconds`; `monitoring/rules/controlplane.yml`:
    `ControlPlaneDumpMissing` (sev2, RB-10) and `AuditAnchorMissing` (sev1,
    RB-09) past 26 h (DOC-05 §8); `controlplane_test.yml` is the promtool test.
  - Retention of dumps (migration 0013): in `retention.py`'s batches, so one
    custodian approval covers tenant backups and bucket C. The newest 30
    daily-tier and 12 monthly dumps are kept; older ones become items once
    their lock has passed by `LOCK_MARGIN`, are checked again at execution,
    deleted by version with bucket C's retention key (`ctl_retention_key`,
    configuration; none given: `SECRET_UNAVAILABLE` for those items) and
    recorded in `ctl_dump_expired` [AO], since `ctl_dump` is append-only.
  - A dump is an age-encrypted tar of `ctl.dump` (`pg_dump -Fc`) and
    `roles.json`: the roles that own or are granted anything in the
    database, and their members, transitively (a login role that becomes
    `ctl_app`), with LOGIN/INHERIT, privileged attributes and memberships,
    no passwords; plus the SHA-256 of every owner and ACL (database, schema,
    relations, columns, functions, default privileges).
  - `rebuild(admin_dsn, identities, key=None)`: RB-09 step 4 / RB-10 onto a
    new cluster. Refuses ctl-1's own cluster and a database already there;
    creates the manifest's missing roles (LOGIN/INHERIT as they were, never
    a password or SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS, which
    are reported), grants the memberships, restores with `--create` and
    owners and privileges, then runs `verify`'s checks plus the ACL
    fingerprint. Reports `roles_created`, `roles_existing`, `login_roles`
    (set new passwords before ctl-1 connects, RB-09 step 5) and
    `privileged_not_restored`.
  - `drill(operator_id, target_dsn, recovery_identity=None, key=None)`
    (migration 0014): the quarterly control-plane drill, run by an operator
    against an empty database on a temporary server they created; ctl-1
    orders no servers and holds no Hetzner token (decided 2026-10-27). It
    refuses a target on ctl-1's own cluster (same `system_identifier`), runs
    `verify` on the newest dump with every region's operational key from
    the vault, or with the recovery key at its annual reconstruction, and
    times it. The report is put in bucket C (locked 366 days) and recorded
    as `restore_drill` evidence; the drill goes in `ctl_drill` [AO] and the
    audit log. A fail, including a report that couldn't be stored, opens a
    sev2 incident (RB-10).
  - `ctl_controlplane_drill_last_pass_timestamp_seconds`: the last passed
    drill, else the first dump (0: no dump yet, left to the dump alert).
    `ControlPlaneNotDrilled` (sev3, RB-10) past 92 days.

## Running ctl-1

`python -m ctlplane [--config PATH] <command>` (`ctlplane/main.py`; the
configuration path defaults to `$CTL_CONFIG`):

| Command | Does |
|---|---|
| `serve` | agent API (mutual TLS), enrollment (server TLS, if configured), operator API, monitoring (loopback only); the workers on the instance holding the workers lock |
| `check` | builds everything from the configuration and prints what would run; exit 1 unless the schema is at the migrations' head (`[database] migrations_dir`, default beside the source) |
| `migrate` | dump to bucket C, then upgrade the schema; refused without `[bucket_c]` |
| `drill --operator ID --target-file F [--recovery-identity-file F]` | the quarterly control-plane drill; the operator must be an active `platform_operator` or `backup_custodian`; prints the report, exit 1 if it failed |
| `bootstrap` | registers the root public keys (`[trust]`: release, custodian, break-glass; dispatch from the dispatcher's seed) and regions (`[[regions]]`: code, backup recipient, bucket A); idempotent, never changes or retires one, reports a region that differs |
| `rebuild --admin-file F --identity-file F` | RB-09/RB-10 onto this cluster; needs only `[bucket_c]` and `[s3]` |

Exit 2 is a configuration error. The configuration holds no secret: each
`*_file` is a file (SOPS-decrypted onto tmpfs) that must belong to this user
with mode 0600 or 0400, and the DSNs `drill` and `rebuild` take are such
files too, so no password is on a command line or in the operator API.

```toml
[database]
url_file = "/run/ctl/database_url"            # the owner's DSN; the process SETs ROLE per component
[dispatcher]
signing_key_file = "/run/ctl/dispatch_seed"   # base64 of the Ed25519 seed
vault_identity_file = "/run/ctl/vault_identity"   # AGE-SECRET-KEY-1...
[agent_api]
listen = "10.8.0.1:8443"
cert_file = "/etc/ctl/tls/server.pem"
key_file = "/run/ctl/agent_tls_key"
ca_file = "/etc/ctl/tls/agents-ca.pem"
[enroll_api]                                  # optional, with [enrollment]
listen = "10.8.0.1:8444"
cert_file = "/etc/ctl/tls/server.pem"
key_file = "/run/ctl/agent_tls_key"
[enrollment]
ca_cert_file = "/etc/ctl/tls/agents-ca.pem"
ca_key_file = "/run/ctl/agents_ca_key"
[operator_api]
listen = "127.0.0.1:8080"                     # off loopback it needs cert_file and key_file
oidc_issuer = "https://id.example"
oidc_audience = "ctl-1"
jwks_file = "/etc/ctl/jwks.json"
[monitoring]
listen = "127.0.0.1:9464"                     # loopback only
webhook_token_sha256 = "<hex>"
[s3]
endpoint = "https://s3.eu-central-003.backblazeb2.com"
region = "eu-central-003"
[bucket_c]                                    # optional for serve: no control-plane backup worker without it
bucket = "teklines-ctl-c"
write_key_file = "/run/ctl/bucket_c_write.json"           # {"key_id", "secret"}
retention_key_file = "/run/ctl/bucket_c_retention.json"   # optional
recovery_recipient = "age1..."
[policy]
breakglass_enabled = false
backups_per_host = 2
drills_per_day = 1
```

Workers (each its own thread; one that raises is logged and runs again next
round): reconciler 5 s, backup schedule 60 s, expiry, drills and the
control-plane backup 5 min, retention 1 h. They run only while the process
holds the PostgreSQL advisory lock `WORKERS_LOCK`; another instance tries
every `LOCK_RETRY` s, and a lost lock connection ends that term (its workers
stop) at the next `LOCK_PING`. SIGTERM/SIGINT stop the servers and the
workers, then the process exits 0.

`/metrics` adds `ctl_workers_leader` (1 while this process holds the lock;
per process, not from the database). `monitoring/rules/workers.yml`:
`CtlWorkersNotRunning` (sev2, RB-16) when the sum over job `ctl` is 0 for 10
min, `CtlWorkersTwice` (sev2) when it is above 1 for 5 min; a restart that
overlaps the old process (a minute or two without a leader) fires neither.
`CtlMetricsDown` already covers ctl-1 not being scraped.

Per worker: `ctl_worker_failures_total{worker}` (runs that raised, this
process's lifetime), and from the process holding the lock only,
`ctl_worker_last_success_timestamp_seconds{worker}` (a term starts as a
success, so a worker failing from the start still ages) and
`ctl_worker_interval_seconds{worker}`. `CtlWorkerFailing` (sev2, RB-16) when
a worker's last success is older than three intervals, at least 15 min: 15
min for all but retention (3 h). The traceback is in the ctl log.

### On ctl-1: systemd and SOPS (`deploy/`)

| Unit | Runs | As |
|---|---|---|
| `ctl-secrets.service` | `write-secrets` (`deploy/write_secrets.py`, stdlib only, `python3 -I`): `sops --decrypt` of `/etc/ctl/secrets.sops.yaml` with the host's age key (`/etc/ctl/host.agekey`, root 0400), one file per top-level key in `/run/ctl` (tmpfs, its `RuntimeDirectory`), 0400, owned by `ctl`; the directory 0700 | root, bounded to CAP_CHOWN and CAP_FOWNER, no network |
| `ctl.service` | `check`, then `serve`; restarts on failure except exit 2 (configuration); `BindsTo=ctl-secrets.service` | `ctl`, no capabilities; the SOPS file and host key inaccessible |
| `ctl-migrate.service` | `migrate`; `Conflicts=ctl.service`, so a deploy is `systemctl start ctl-migrate && systemctl start ctl` | `ctl` |

The plaintext goes from `sops` through a pipe to tmpfs only. A key is a file
name (`[a-z0-9_]+`, optionally `.json`); a map is written as JSON. Nothing is
written unless every key is valid, files no longer in the SOPS file are
removed, and no value is printed. Stopping `ctl-secrets` removes `/run/ctl`
and stops `ctl`.

`/etc/ctl/secrets.sops.yaml` (in the infrastructure repo, encrypted to the
host's age recipient and to the operators', `.sops.yaml` `creation_rules`):

```yaml
database_url: postgresql://ctl_owner:...@127.0.0.1:5432/ctl
dispatch_seed: <base64 Ed25519 seed>
vault_identity: AGE-SECRET-KEY-1...
agent_tls_key: |
  -----BEGIN PRIVATE KEY-----
agents_ca_key: |
  -----BEGIN PRIVATE KEY-----
bucket_c_write.json: {key_id: ..., secret: ...}
bucket_c_retention.json: {key_id: ..., secret: ...}
```

with `/etc/ctl/ctl.toml` (root:ctl 0640) naming `/run/ctl/<key>` for each
`*_file`. The venv is `/opt/ctl/venv` (`pip install` of this package), the
helper `/usr/local/lib/ctl/write-secrets` (root 0755). For `drill` and
`rebuild` the operator puts the DSN or identity in `/run/ctl` as `ctl`
(`sudo -u ctl sh -c 'umask 077; cat > /run/ctl/drill_target'`) and runs
`sudo -u ctl env CTL_CONFIG=/etc/ctl/ctl.toml /opt/ctl/venv/bin/python -m
ctlplane drill ...`; the file goes when `ctl-secrets` next restarts or stops.

## Findings

1. **The outbox can't be read `FOR UPDATE`** as DOC-03 §2.5 says: row locks
   need UPDATE privilege, which the append-only rule revokes (a test shows the
   `permission denied`). Claiming is inserting the event's
   `operation_event_delivery` row `ON CONFLICT DO NOTHING`, so concurrent
   polls never share an event (8 threads racing, and the test fails without
   the `ON CONFLICT`).
2. **uvicorn doesn't pass the client certificate to the app.** `tls.py` adds it
   per connection as the ASGI TLS extension's `client_cert_name`. If an
   upgrade bypasses that, the name is missing and every agent request gets
   403 (fails closed).
3. **One fencing token per dispatch of the operation, not per step.** DOC-03
   §6.2 says "assigned at each dispatch"; the agent accepts an equal token
   only for the operation that set it, so every step of one dispatch carries
   the same token, and so does a resend of a step the agent never ran (BUSY,
   RATE_LIMITED, EXPIRED). A new token comes only from RECONCILING's
   re-dispatch.
4. **`operation.host_id` is one host, but operations span hosts** (Create:
   db, mail, app). Each `operation_step` names its host; a step's event goes
   only to that host, and only once the step before it is done.
5. **Leases:** hand-out + 150 s; each heartbeat extends to
   `min(now + 150 s, deadline_at + §8 margin)` (margin = lease − agent
   timeout, e.g. 180 s for start/stop), never shortening it. A lost poll reply
   is not resent blindly (a second copy could run beside the first); the lease
   lapses into RECONCILING, where only a result (not a heartbeat) settles it.
6. **Catalog drift:** the contract test against `hostagent.ops` caught three
   step lists typed wrong here (Create, RestoreProduction, Relocate). The two
   copies stay only with that test.
7. **Resuming needs a new token too.** DOC-03 gives a new token only to
   "not started"; but the agent answers a repeated (op, token, step) from its
   store, so a step it finished as failed (TIMEOUT) would never run again
   under the old token. Every re-dispatch gets a new token; a late result
   under the old one is `stale` (the crash test shows it).
8. **DOC-03 can loop forever** on a step that always times out (TIMEOUT →
   RECONCILING → re-dispatch → …). After 3 dispatches the operation fails
   with `RECONCILE_LIMIT` and a sev3 incident.
9. **Probes belong to one reconciling episode** by a counter
   (`reconcile_epoch`, +1 on each entry), not by time: with equal timestamps
   an answer from the previous episode was reused (a test caught it).
10. **`Agent.Query` isn't an operation type in DOC-03 §6.1.** Probes are
    stored as operations of that type, linked to the operation they
    reconcile, never themselves reconciled.
11. After an agentd crash, agent-exec (its own process) may still be running
    the old verb, so the re-dispatched step can get `BUSY`; that is the
    ordinary retry path. Journal rows are matched by step name, which is
    unique within every operation in the catalog.

12. **No identity provider is named** (only "SSO with WebAuthn"). Tokens are
    checked against configured issuer, audience and keys, so any OIDC IdP
    fits; MFA comes from the RFC 8176 `amr` claim and `auth_time`.
13. **An approval names the op_id, so it can only come after the request.**
    DOC-03 doesn't say when it enters; here the operation waits in VALIDATED,
    and the tenant-state gate and the DR-06 hour are checked when the
    approval arrives, not when it was asked for.
14. **DOC-03 keeps an `approval_id` → `evidence_artifact`;** the envelope needs
    the signed object itself, so it is stored on the operation.
    `evidence_artifact` and `deletion_case` aren't built; the approval's
    `deletion_case_id` must equal the params'.
15. **Not dispatchable yet** (`NOT_SUPPORTED`): every type needing a release
    manifest or envelope secrets (Create, ApplyPatch, ModuleUpdate, Backup,
    RestoreToIsolated, RestoreProduction, Relocate, RotateSecret). A contract
    test checks the secret-opening steps against the agent's handlers.
    SetDomain, Suspend, Reactivate, Export and MeterSeats pass admission but
    the agent has no handlers for their steps yet (they fail
    `EXEC_ERROR`, "step not implemented"); Delete's `mail.remove` likewise.
16. **Placement** lives in `runtime_slot`, `db_binding` and `mail_identity`,
    which Tenant.Create writes; until then `environment.app/db/mail_host_id`.
17. **Capacity reservations (INV-8) wait for Tenant.Create:** none of the
    dispatchable types takes capacity, so the code would be unreachable.
18. **A backup whose response was lost has no backup point:** the reconciler
    sees the journal (an evidence hash), not the evidence, and a re-run finds
    the archive stored and reports no snapshot. It needs a read-back of the
    stored manifest. Until then such a backup doesn't count for DR-06.
19. A rejected request keeps its idempotency key; retrying needs a new key.

20. **DOC-03's `secret_ref.kind` lacks three kinds** the agent needs:
    `tenant_salt`, `tenant_admin_password` and the region's operational
    restore key (DOC-05 §4). Added; `agent_key` isn't used (agents keep
    their own keys).
21. **"Read access is limited to the dispatcher role"** (§2.7) needs two
    logins in production: the operator API as a member of `ctl_app`, the
    agent API as a member of `ctl_dispatcher`. Column grants keep
    `ciphertext` out of `ctl_app`'s reach.
22. **Derived values are fresh per envelope:** each hand-out has a new SCRAM
    salt and Odoo hash salt for the same password. `app.config` costs
    600,000 PBKDF2-SHA512 rounds (~0.5 s) inside the poll request.
23. **Backups don't record their release.** The agent reports a local image
    ID, not the release digest, so a restore uses the environment's
    current release, which may be newer than the backup's.
    `backup_point.image_digest` (DOC-03 §2.6) should be filled from the
    environment's release at backup time.
24. **The agent defines no secrets for RestoreProduction, Relocate's backup
    step or RotateSecret,** though they need them; ctl-1 refuses them
    (`NOT_SUPPORTED`) until it does. The contract test ties ctl-1's list to
    the agent's exactly.
25. Regions, host age recipients and release cells are inserted directly:
    `Host.Enroll` and cell management aren't built.
26. **INV-8 by host locks, not SERIALIZABLE.** DOC-03 asks for a
    SERIALIZABLE transaction; each host is locked (transaction advisory lock,
    one order) before its usage is summed. Same guarantee, no retry loop, and
    it works inside the admission transaction. Concurrent place + hold on a
    host with room for 4 holds exactly 4; without the lock it overbooks.
27. **`ERROR` isn't a tenant state the agent knows.** DOC-03 §5 has it, DOC-04's
    list doesn't, so any envelope for a tenant in ERROR is rejected `SCHEMA`
    by the agent. Added on ctl-1's side; the agent's list needs it too.
28. **Create can't complete yet:** its second step, `mail.user`, has no handler
    or secrets in the agent (the mail agent isn't built). Create admits and
    dispatches; it will fail at that step on a real mail host.
29. **A failed operation keeps its capacity.** DOC-03 says ERROR keeps
    everything ("nothing is dropped"), and a failed step can leave things on
    the host, so reservations are committed on FAILED too and released only
    when the environment is removed. A hold lives 24 h, past the longest
    lease plus reconciling.
30. **`resource_bundle` isn't specified in DOC-03** beyond the tenant's
    `resource_bundle_id`; its fields here are DOC-04's runtime slot plus
    disk sizes.
31. **Where a restore copy runs isn't specified;** here beside its source,
    where the backup tmp area and the region keys already are.
32. Running out of ports raised past the refusal handling (a 500) until a
    test hit it.
33. **Every admission is serialised today** by the audit chain's lock, taken
    at the request's first audit line and held to commit. Correct, and fine
    for H0 volumes, but it also hides the capacity lock (a mutation test
    showed it): the capacity test calls placement directly. Moving the
    audit append to the end of the transaction would shorten that window.

34. **`Host.Enroll` isn't an envelope** although DOC-04 §6.16 lists it with
    them: the host has nothing yet to verify one with. Built as its own
    exchange whose root of trust is the release key in the host image, so
    neither a compromised ctl-1 (it can't re-sign the pinned trust) nor an
    operator account (it can't authorize) can enroll a host or plant a
    dispatch key.
35. **`Host.RotateTrust` was needed within 90 days of go-live** (the dispatch
    key rotates every 90 days and agents pin the keys of their enrollment).
    Built: see findings 40–43.
36. **Client certificates live 365 days with no renewal;** re-enrolling is the
    renewal, and the agent re-enrolls only onto a wiped state directory
    (DOC-05 §1: agent state is rebuilt), so a host's tenants are restored or
    relocated first. A key rotation that keeps the agent's state would be a
    separate operation.
37. **Other hosts' agent keys** (`Trust.agents`, which a restore on another
    host needs to verify the backup manifest's signer) now come with every
    trust document; a host enrolled since the last one is known to the
    others only after the next rollout.
38. The dispatch key wasn't in `signing_key` until now (it lived only in
    configuration); enrollment reads it from there.
39. The enrollment listener is unauthenticated by design; it should listen
    on the WireGuard address only.
40. **`Host.RotateTrust` isn't in DOC-04 §6's catalog** (only named in §2).
    Added as a host-scoped type with one step, `any.rotate_trust`. One
    document per version for the whole fleet, so the founder signs once per
    rotation, not once per host.
41. **Two guards the spec doesn't name:** an agent refuses a document that
    isn't newer than its own (no rollback to a set that still holds a
    retired key), and one that drops the dispatch key signing the request
    carrying it (that would lock the host out until re-enrolled).
42. **The release key can't be rotated this way:** it is the root of trust
    in the host image, checked at every start. Replacing it means new images
    and re-enrolling every host; DOC-04 §2 rotates it only on compromise.
43. Development agents with a `[trust]` table in their TOML still get
    `trust.json` written by a rotation, but read the TOML again on restart.
44. **A tenant could never become ACTIVE:** §3.6 needs a recoverable first
    backup before ACTIVE, but DOC-04 §6.8 doesn't allow Tenant.Backup in
    VALIDATING. Added on both sides (the contract test keeps them equal).
45. **Public evidence needs an ingress on the host:** agents with
    `ingress_url` set report `certificate: issued` (`app.route`) and
    `https_login`, `https_websocket`, `public_db_manager` (`app.health`)
    through Traefik by each public hostname; without it those checks stay
    `missing` and activation `incomplete`, as the spec requires. The HTTPS
    check needs login 200, websocket 101 and the certificate.
46. **`terms_acceptance` has no region in DOC-03,** but INV-15 compares the
    placement region with "the region accepted": added `region_code`. It is
    kept per tenant, as there is no `organization` table yet.
47. Missing evidence never sends a tenant to ERROR; only evidence that says
    no does. An operator can re-check at any time; each check is kept.
48. **A failed restore's copy is expired at once,** not after 7 days: DOC-07
    asks that Expire removes it, and it holds capacity and the tenant's data.
49. **"Daily backup" is the schedule, not the tier.** DOC-05 §3 makes
    Sunday's scheduled backup `weekly` and the month's first `monthly`;
    counting only the `daily` tier (as first built) would have paged every
    Monday. Any recoverable backup clears the alert.
50. **The monthly tier rolls over:** DOC-05 says "the first scheduled
    backup of a calendar month is monthly"; here it's the first one that
    becomes recoverable, so a failed first-of-month run doesn't leave the
    month without a 93-day backup.
51. **"Sunday's backup" is the run that falls on Sunday (UTC).** The window
    opens Saturday 22:00, so tenants whose slot is before midnight get their
    weekly from the window opening on Sunday instead.
52. **Who may delete expired backups was contradictory:** DOC-05 §3 has a
    ctl-1 job with a retention key kept on ctl-1; DOC-03 §7 and DOC-04 §2 a
    custodian; ADR-005/006 a key split 2-of-2. Decided (2026-10-26): ctl-1
    drafts, the custodian approves each batch, ctl-1 deletes with the key it
    holds; the split-custody copy is the break-glass copy. ADR-005/006 need
    that amendment.
53. **Compliance mode is the real guard** against early deletion: LocalStack
    answers `AccessDenied` to a delete before `lock_until` even when ctl-1
    has been made to think the lock passed. The approval protects the last
    backups once their locks lapse (when backups have been failing).
54. **A re-drill runs on the same host.** RB-04 says re-drill "on a
    different host", but a restore copy is placed beside its source (the
    backup's region keys and the source's DB host are there), so a re-drill
    can't tell a host problem from a backup problem yet.
55. **The 30-day drill clock starts at the first recoverable backup**, not
    at activation: before that there is nothing to drill, and the backup
    alert covers it.
56. **The weekly random drill is the deep drill** (`deep: true`): besides
    the §6.9 checks, `row_counts_match` (10 key tables, the backup's own
    counts from its signed manifest against the copy as loaded) and
    `pdf_printed` must be `true` (agent README findings 38–39). Zero egress
    is `not_measured` in dry-run and fails closed on a real host until the
    agent reads the nftables counters.
57. **ctl-1 doesn't trust a completed restore:** a RestoreToIsolated that
    completes without the full DOC-04 §6.9 check set (or any check not
    exactly `true`) is a failed drill with its sev2 incident.
58. **Operators choose their own idempotency keys**, so one shaped like the
    scheduler's (`drill:<date>:oldest:9`) was counted against the daily
    quota. The scheduler now only counts its own (system) requests, and a
    drill an operator requests is recorded as `manual` whatever its key.
59. **Chain verification depended on the session's TimeZone:** a row's
    hash covered `at.isoformat()` as read back, so a copy restored on a
    server whose TimeZone isn't UTC failed to verify. `audit._row` now
    normalises to UTC; existing hashes are unchanged because every row was
    written in UTC.
60. **Only the bucket's anchors can be trusted.** `audit_anchor` is in the
    database being checked, so whoever rewrites the database and recomputes
    the chain can rewrite it too. ctl-1's bucket C key can't delete a
    locked version but can put a newer one with the same key, so every
    version is read. What anchors can't catch: rows rewritten after the last
    anchor, or forged anchors added for a database rewritten after them; the
    older, honest anchors still disagree.
61. **The control-plane dump isn't per region**, while DOC-05 §4 keys are
    "one per region": it is encrypted to every active region's operational
    key (any of them can run the drill) and to one recovery key given to
    ctl-1 as configuration. With no active region it refuses to dump. Bucket
    C's write key is configuration too, not a vault secret: it lives where
    the dispatch key does.
62. **Pre-migration dumps count among the 30 dailies**, as pre-operation
    tenant backups count among the 7 (DOC-05 §3 makes both `daily`), so a
    burst of migrations shortens the daily history. Anchors aren't deleted:
    they are small, and the oldest ones still vouch for the start of the
    chain.
63. **A drill test was flaky** (the intermittent failure seen before): two
    restore attempts written at the same fake-clock instant tie on
    `created_at`, and the test read the wrong one as the newest. The test
    now moves the clock; the 16 drill tests passed 8 runs in a row.
64. **A drill without stored evidence fails**, even when the restore
    verified: a PASS must point to an `evidence_artifact` (SEC-07), and the
    report in bucket C is that evidence. The target is recorded as
    `host:port/dbname` only, never the DSN.
65. **`pg_dump` of one database carries its grants but not the roles** they
    name, so the drill restored without owners or privileges and a rebuild
    couldn't. The roles go in the dump as a manifest; their passwords don't
    (RB-09 rotates every credential anyway), nor do privileged attributes:
    whoever needs SUPERUSER on the new cluster is given it by its installer.
    Only roles a needed role is a member *of* are left out: they add nothing
    to this database unless they are grantees themselves, and then they are
    in.
66. **The workers' `run_forever` loops stopped for good on the first
    exception**: one database error and the reconciler, or the backup
    schedule, was gone with no sign but the 26-hour alert. They are removed;
    `main` runs every job in a loop that logs and continues.
67. **`drill` and `rebuild` are commands on ctl-1, not operator API
    endpoints**: they take DSNs with passwords, which would otherwise cross
    the API. Shell access to ctl-1 (WireGuard and SSH) is the
    authentication; `--operator` is checked for an active role and recorded,
    not authenticated.
68. **A migration's dump runs as the owner**, without `SET ROLE`: the roles
    may be what the migration is about to create.
69. **`~@privileged` includes `@chown`**: denying it in `ctl-secrets.service`,
    as in the other units, would have killed `write-secrets` at its first
    `fchown` (SIGSYS). It denies the other dangerous sets instead; the test
    with the unit's own filter fails if `~@privileged` comes back.
70. **The host's age key is on ctl-1's disk**, root-only: an unattended
    restart needs it, and Hetzner Cloud servers have no TPM for
    `systemd-creds`. Root on ctl-1 can read every secret; the `ctl` user
    can't read the key or the SOPS file, only its own files in `/run/ctl`.
71. **The control-plane backup worker never failed**: its `run_once`
    turned every error into a result, so a dump or anchor that kept failing
    looked healthy to the worker loop. It still tries both, then raises
    `JobFailed` with both outcomes.
72. **Review by Codex (2026-10-27), five rounds until approved**, each fix
    with a test that fails without it. Round 1:
    - an anchor whose row is missing *below* the last row was counted as
      "newer than the dump" and accepted; a row's hash doesn't cover its
      `seq`, so deleting rows and rechaining kept the chain whole. It is a
      mismatch now;
    - verify/drill/rebuild read whatever version of a dump key was newest:
      the write key can put a version (or a delete marker) over a locked
      dump. A key with more than one version is refused (`not_one_version`)
      and the one read is pinned;
    - `pg_dump`/`pg_restore` got only host, port, user, password and
      database: `sslmode`, `sslrootcert`, client certificates were dropped.
      Every parameter goes through libpq's own environment variables; one
      that has none is refused;
    - the roles manifest kept only ADMIN of a membership, not PG 16's
      INHERIT and SET, and a rebuild trusted roles already on the target.
      Memberships carry all three options and are compared after the
      restore, as are existing roles' LOGIN/INHERIT (`memberships_match`,
      `roles_differing`);
    - retention executed any batch whose row said `approved`: the
      custodian's signature over its body is checked again at execution
      (sev1 RB-09 if it doesn't verify);
    - a restore admitted between retention's candidate check and its delete
      lost its backup: retention locks each row FOR UPDATE and checks it
      again under the lock, one item per transaction; admission reads the
      backup FOR SHARE;
    - a failed evidence insert aborted the drill's transaction, losing the
      drill and its incident: it runs in a savepoint;
    - a database error on the workers lock query (after connecting) killed
      the supervisor thread for good while the APIs stayed up: retried;
    - (infra) a pip install that failed left the next run skipping it.
    Codex's claim that `pg_control_system()` needs privileges was wrong
    (PUBLIC may execute it; checked on PG 16) and it withdrew it.
    Rounds 2–4:
    - **dumps are signed**: an Ed25519 key on ctl-1 (`[bucket_c]
      signing_key_file`, SOPS `dump_signing_seed`) signs object key,
      ciphertext SHA-256, snapshot time and schema revision into the
      version's metadata; verify, drill and rebuild check it against
      configured keys (`signing_public_keys`, plus the host's own) before
      decrypting, so an archive put by whoever holds the bucket's write key
      (encrypted to the public recovery key) never reaches `pg_restore`, and
      a dump copied under another name is refused;
    - each dump anchors just before its snapshot; an anchor written before
      the signed snapshot time that the dump lacks makes it `stale`. An
      anchor is timed after it picks its row, so one that started before a
      dump's snapshot but anchored a later row isn't required;
    - memberships touching a manifest role on either side (outside and
      built-in roles) are captured and compared; the manifest's version is
      checked before the target is touched (`MANIFEST_VERSION` 2);
    - retention: the approval's expiry is checked again before each delete
      (the batch is abandoned, outcomes kept); one executor at a time
      (session advisory lock across the per-item commits); each outcome is
      committed with its expiry and a `deleted` is never overwritten;
      `backup_point.retention_batch_id` (migration 0015).
    A fresh review afterwards (same day) found more, fixed with tests:
    - retention commits `expiring` before the S3 delete (migration 0016),
      so a crash between the two can't leave a `recoverable` point with no
      object; a resumed run finishes it, a refused delete puts it back;
    - a freeze stops a running batch: the flag is read FOR SHARE per item,
      so `set_frozen` waits for the item in hand and no delete starts after
      it commits; checked again after `expiring` is committed;
    - the newest dump is picked from the version listing, delete markers
      included, so a hidden newest dump is refused, not skipped;
    - no role may hold more SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/
      BYPASSRLS after a rebuild than on ctl-1 (an existing one included);
    - an unreachable drill target is a recorded failed drill;
    - `ctl-migrate` is ordered after ctl's stop; Ansible restarts ctl until
      the running bundle is the installed one (`active-bundle`).
    Its `pg_control_system()` claim, raised again, is still wrong.
    While Codex was out of quota, two independent reviews (Claude subagents)
    found, fixed with tests:
    - the hourly worker replaced the custodian's draft every round, so an
      approval could never land: a draft is kept until it expires;
    - a point left `expiring` by a delete that never answered, whose batch
      then expired or froze, stayed unrestorable and undeletable: it is
      settled from the bucket (version there: back to what it was; gone:
      expired); if S3 can't say, the batch waits with a sev2 (the retention
      key needs readFiles);
    - a dump failing every round wrote a 366-day anchor every 5 minutes:
      at most one pre-dump anchor an hour;
    - rows dated in the future (in `ctl_dump`, `audit_anchor`) counted as
      done, quieted the alerts, took bucket C keep slots and made a month's
      dump daily: every such read is bounded by now;
    - junk put once or twice under a newer dump key blocked every default
      drill and rebuild: skipped (and reported) unless a signed dump is
      under it;
    - an unreachable ctl-1 database was recorded as an unreachable target;
      retention re-checked the whole fleet per item (now its environment).
    Codex again, after its quota reset, until approved (2026-10-27):
    - a refused retry, or an error from the first delete call (boto3
      retries inside one call; an earlier request may have deleted the
      version), put a deleted backup back to `recoverable`: no S3 error
      unmarks a point now; it stays `expiring` and is settled from the
      bucket before its batch closes, freezes or is left; only a `Refused`
      raised before any request (no key) unmarks a first attempt;
    - an error reading the newest dump's metadata was taken for a bad
      signature and the pick fell back to an older dump: it fails
      (`candidate_unreadable`) instead;
    - a batch frozen before the next round never settled its `expiring`
      points: a frozen run takes the executor lock and settles them, deleting
      nothing.
73. **A tenant didn't come back after its app host rebooted** (Codex, app-host
    round): its `/run/tenants` files (odoo.conf, pgpass) are on tmpfs and
    nothing rendered them again, while Docker restarted the container. Now
    containers aren't restarted by Docker, and `Tenant.Start` is admitted with
    the environment's runtime slot and SMTP mode filled in by ctl-1
    (`catalog.SLOT_FILLED`; `relay`, or `sink` for a restore copy) and the
    `app.config` secrets sealed for `app.start`: the agent renders the files,
    then starts. Without a slot it is refused (`NOT_FOUND`). Tests that used
    Tenant.Start as a generic one-step operation use Tenant.Stop.
74. **L2 had no supervisor** (DOC-05 §3.1, §8): `ctlplane/l2.py`, the `l2`
    worker (`[l2]`, every 2 minutes), runs pgBackRest on ctl-1 against bucket
    B with the delete-capable key and the cipher pass from SOPS, passed as
    `PGBACKREST_REPO1_*` environment (never in a config file or argument):
    `expire` once a day (db-1's key can't delete, `expire-auto=n` there),
    `info` for the newest full and full-or-differential, and `repo-ls` of the
    newest segment's directory for when the newest WAL was stored. Results in
    `l2_status` (migration 0017); a failed read keeps the last good values
    (the alerts age from them) and records the error. Metrics
    `ctl_l2_{checked,full_last,backup_last,wal_last,expire_last}_timestamp_seconds`
    (0 for a configured stanza never read; times past now read as 0), rules
    `monitoring/rules/l2.yml`: WAL lag over 5 minutes (only while the
    repository is being read), no full for 8 days, no full or differential
    for 26 hours, repository unread for 15 minutes, expire stale for 3 days.

## Tests

`tests/test_agent_api.py` runs the real `hostagent` Agent and Poller against
the API over mutual TLS: Tenant.Start end to end (signed response stored,
step evidence, high-water fence); RestoreCopy.Expire across the app and db
agents, the db step not offered before the app step is done; heartbeats
arrive and record the deadline; another host's certificate, one with an extra
subject attribute, a certificate from another CA, no certificate and a
retired host are refused; forged and misattributed responses change nothing;
an oversized request is refused. `tests/test_store.py`: leases and their cap,
lease expiry and late results, failed/TIMEOUT/BUSY/EXPIRED/REPLAY handling,
duplicates and stale tokens, concurrent claims, idempotency and INV-21,
append-only tables. `tests/test_contract.py`: catalog, timeouts and signed
encoding equal the agent's. `tests/test_reconciler.py`: every verdict, the
two-host partial resume (only the host with the unknown step is asked), a
step that keeps timing out, an unanswered probe resent then 30-minute
failure with incident, probes from an earlier episode ignored, a probe that
fails. With the real agent: a lost poll reply is read back (no journal row)
and re-dispatched; agentd dies mid-step, restarts, `recover()` reports
TIMEOUT, the reconciler re-dispatches with a new token and the step completes,
and the old process's late result is `stale`.

Disabling any one of these makes a test fail: the CN check, the signature
check, the body `host_id` check, the step-host check, the token check, the
claim's `ON CONFLICT`, the lease cap, ignoring heartbeats while reconciling;
in the reconciler, the token filter on journal rows, the epoch filter on
probes, the new token on resume, the attempt limit, the 30-minute rule,
failing (not resuming) a known failure, and failing a probe instead of
reconciling it (by lease or by response).

`tests/test_operator_api.py`: bad tokens (no token, garbage, another key,
audience, issuer, expired); unknown, suspended and lapsed operators; auditor
reads but can't request; no MFA or MFA older than 12 h; no self-grant;
Start dispatched with its audit trail; schema, unknown, internal and
not-supported types rejected; environment of another tenant; idempotency;
INV-21; tenant-state gate; missing placement; Host.Drain scope; Expire on
production; Delete: dispatched with approval and a recent backup, refused
without one (none, 62 min old, failed), eight kinds of bad approval refused
and audited, approval only while awaiting, break-glass with sev2, state
checked again at approval; the audit chain verifies, detects a forged row,
refuses updates, and stays one chain under 8 concurrent requests. In
`test_store.py`, backup points from evidence; in `test_agent_api.py`, an
operator request runs on the real agent. Disabling any of 17 checks
(MFA, roles, grant expiry, operator status, amr, MFA age, params schema,
NOT_SUPPORTED, tenant gate, the 1 h window, deletion case, action/expiry,
break-glass switch, approval requirement, Expire on production, the audit
lock, the planned-retention lock) fails a test.

`tests/test_secrets_releases.py`: ctl-1's secret list equals the agent's;
SCRAM and Odoo hashes verify (and the agent's own formats too); the Backup
envelope passes the real agent's verifier and opens to the right B2 key and
recipient with the app host's key and not with another's; no plaintext
secret anywhere in the database after a backup round; `ctl_app` can't read
ciphertext; Backup refused without a host recipient or a region B2 key;
undecryptable or no dispatcher identity fails at hand-out; region secret
upload takes only ciphertext, revokes the old one, and the next envelope
uses the new key; Create envelopes (db.provision, app.config) pass the
agent's verifier, carry the signed manifest, and open to values matching the
bindings (SCRAM and Odoo hash checked against the stored passwords); a
restore copy gets its own passwords and the region restore key, which opens
a backup; a missing binding fails at hand-out; releases need evidence, are
signed, cell-checked and immutable; ApplyPatch sends the manifest, passes the
agent's release check and moves the environment; ApplyPatch refused for a
module_update class, pending, unknown, revoked or missing current release,
or another cell; ModuleUpdate checks modules and DR-06; revocation after
dispatch stops hand-out; `backup_id` is always ctl-1's. Disabling any of 17
checks fails a test (sealing, copy-vs-production secrets, SCRAM derivation,
revocation at hand-out, cell, change class, approval, modules, secret
readiness, ctl-generated backup_id, release signature, cell availability,
digest immutability, INV-6, ciphertext-only upload, the column grant).

`tests/test_capacity.py`: Create places, slots, holds and dispatches (exact
reservations per host, ports 20000/20001, UID from the sequence, tenant
PROVISIONING, audit `tenant.reserved`), its db.provision and app.config
envelopes pass the agent's verifier (slot, ports, capacity) and open to the
environment's secrets; completed → VALIDATING and committed, failed → ERROR
with everything kept; one production per tenant (INV-10, also for the
owner); refused without a bundle or approved release, or when the caller
names an environment or a slot; the DB connection budget and app memory
stop placement at the reserve (nothing left behind for the refused tenant);
spreading to the host with more free memory; expired holds don't count; 8
concurrent Creates against room for 4; placement and hold racing without
the audit lock; lowest free port pair, ports reused after release, UIDs
never; the host port range; a refusal after allocation leaves nothing;
RestoreToIsolated makes a 7-day `restore_copy` beside its source with its
own slot, reservations and secrets, and is refused for another tenant's,
failed or unknown backup or a caller-chosen target; RestoreCopy.Expire and
Delete release reservations and ports (Delete also ends the tenant).
Disabling any of 17 checks fails a test (host lock, reserve_pct, hold
expiry, connection budget, its formula, spreading, port range, port
release, commit, DELETED, ERROR, the savepoint, ELIGIBLE, INV-17,
recoverable backup, port exhaustion, the INV-10 index).

`tests/test_enrollment.py` runs the real agent's `enroll()` against the
enrollment listener over TLS: a new host opened through the API, authorized
with the release key, enrolled (key files 0600, host active, trust pinned
from the signed authorization), then polling the agent API with its new
certificate and completing a Host.Drain whose response verifies against the
registered key; re-enrolling makes the old certificate get 403 and the old
key's responses `bad_signature`; refused: before authorization, a signature
by another key or over another body, 5 wrong tokens (then even the right
one), a used or expired token, a CSR for another CN, a proof by another key,
a malformed X25519 key (the token stays usable after these three), unknown
or garbage host IDs (same 403), a public IP, an unknown region or role, an
auditor; the agent refuses a dispatch key swapped in by ctl-1, another
host's genuine authorization, a tampered `trust.json` at start, and an
already-enrolled state directory. Disabling any of 15 checks fails a test.

`tests/test_rotate_trust.py` rotates the dispatch key end to end on an
enrolled agent: a document with both keys, rolled out and applied (on disk
and in memory, version recorded), ctl-1 switching to the new key, the old key
retired in a second document, and an envelope signed with the old key then
refused (`SIG_INVALID`). The agent refuses a document without the key
signing its envelope, a tampered one, and an older one; ctl-1 refuses a
rollout with no active document, a host already on it, a document signed by
another key or not the pending draft, and a draft with no dispatch key. A
host enrolled after a rotation starts on that version. Disabling any of 11
checks fails a test (agent: version, lock-out, release signature, memory,
disk, other agents' keys; ctl-1: release signature, exact draft, a dispatch
key in the draft, up-to-date hosts, recording the host's version).

`tests/test_activation.py`: with the evidence today's agent sends, the
check is `incomplete` (health and image pass; HTTPS, public database
manager, backup and terms missing) and activation is refused; with all of it,
a backup taken in VALIDATING and terms recorded, it passes and the operator
activates (tenant records check and operator; placement manifest written at
Create); each of six failures (login, HTTPS, public database manager,
loopback database service, a container on another image, a terms region
that isn't the placement's) sends the tenant to ERROR; terms must cover
every item; activation refuses an older check, a stale one, evidence that
changed since, a tenant not VALIDATING, and an auditor; checks are
append-only. A websocket failure alone fails health, and the loopback
database service answering fails the database-manager check even with no
public probe. Disabling any of 14 checks fails a test.

`tests/test_expiry.py`: nothing before `expires_at`; then one Expire,
requested by the system, not repeated while in flight, removing the copy
and freeing its host; a failed restore's copy expired at once; waiting
while production is busy; retries under new keys, then one incident after 3
failures or 3 refusals; production never expired. Disabling any of 8 checks
fails a test.

`tests/test_monitoring.py`: the metric is the newest recoverable snapshot
of any tier (failed ignored), 0 when none; only tenants that
should be backed up, no restore copies or removed environments; the webhook
opens one sev2 incident per fingerprint, closes it on resolve, opens a new
one if it fires again, tames unknown severities and non-UUID tenants,
refuses a missing or wrong token and a malformed payload; and promtool
checks and tests the rules (quiet at 25 h, firing after 26 h, a new backup
keeps it quiet, never backed up fires, missing metrics fire
`CtlMetricsDown`). Disabling any of 8 checks in `monitoring.py`, or the
threshold, the `absent()` and the age arithmetic in the rules, fails a test.

`tests/test_backup_schedule.py`: start minutes spread over the 6 hours and
the window's day boundary; nothing before the slot, then one backup per
window (in flight, done, not repeated later that day), requested by the
system, `trigger: scheduled`; a missed window still runs later that day;
monthly first, then daily, monthly again in a new month; a Sunday run is
weekly (29 days); a failed or unrecoverable monthly passes the tier on;
retries under new keys then gives up, and the next window starts afresh;
waits for an exclusive operation and for the per-host limit; which tenant
states are scheduled; and its backup feeds the alert metric. Disabling any
of 12 checks fails a test.

`tests/test_retention.py`: the keep counts per tier, locks, references
from in-flight restores, stored-but-failed points, removed environments
keeping nothing; draft and custodian approval through the API (another
key, another body, an expired batch, break-glass with sev2, auditors
refused, no new draft over an approved one); against LocalStack with
compliance-mode Object Lock, the approved version deleted, an early delete
refused by the store whatever ctl-1 believes, items re-checked at
execution, freezing, and items changed after approval refused. The object
key equals the agent's. Disabling any of 13 checks fails a test.

`tests/test_drills.py`: the window; a passing drill (system request, key,
attempt row with RTO and evidence, DRILL_VERIFIED, copy expired at once and
swept); `restore_attempt` append-only; ctl-1's own check of the agent's
results (a failed check, a missing one, an unmeasured login, a non-boolean,
garbage); a failure's incident, the re-drill, the second failure taking the
environment out until an operator's drill passes; oldest-first, the daily
quota and its growth with the fleet, the weekly random drill once a week, deep, and
its tier and backup choice; deep checks required of a deep drill; busy environments, tenant states, nothing
recoverable; refused requests retried then given up; restore-to-stage
recorded without drill effects. `tests/test_monitoring.py` adds the drill
metric and the `drills.yml` promtool test. Disabling any of 35 checks
fails a test.

`tests/test_cpbackup.py` (19), against ctl-pg and LocalStack, with
`pg_dump`/`pg_restore` 16 in a `postgres:16` container: a dump is locked,
read back, and restores with the recovery key alone and with a region's
operational key, not with another; tiers; recipients required; a read-back
mismatch (lock date, checksum) raises with a sev1 incident; a pre-migration
dump is taken before the upgrade, a failed one leaves the schema as it was;
an anchor is the last hash, locked; a rewritten row (with and without the
chain recomputed), a rolled-back database, a forged newer version and a
delete marker each stop anchoring with one sev1; `verify` against anchors
(an older dump has them `beyond`, a rechained database mismatches), under a
non-UTC TimeZone, refusing a corrupted or foreign object and a wrong schema
revision; the schedule and its catch-up; retries; metrics. Disabling any of
21 checks fails a test; the 22nd (the restored revision not being NULL) is
only reachable with a dump that has neither a revision label nor
`alembic_version`, which `dump` never produces.

`tests/test_retention.py` adds bucket C: the 30 + 12 kept, locked and
expired dumps left out; a dump deleted in the same batch as a tenant backup,
refused without the bucket C key, then deleted and recorded; Object Lock
refusing an early delete. Disabling any of 9 checks fails a test.

The drill tests (6 more in `test_cpbackup.py`) use agent-pg as the temporary
server: a pass with the operational keys (newest dump, anchors matched,
locked evidence, metric moves; a later fail doesn't move it), with the
recovery key, ctl-1's own cluster refused, and fails (wrong key, no dump,
evidence not stored) each recorded with one sev2. Disabling any of 9 checks
fails a test.

Rebuild tests (10 more) use agent-pg as the new cluster: the manifest (roles,
memberships, no passwords); a rebuild that recreates `ctl_app`,
`ctl_dispatcher` and a NOINHERIT CREATEDB login role (attributes as on ctl-pg,
CREATEDB reported not restored, no password, membership, table and column
grants, owners) and then finds the database there; a restore that dropped
the grants failing the fingerprint; ctl-1's own cluster and a wrong key
refused with nothing created; the fingerprint changing for a column, table,
owner, function, default-privilege and database grant. Disabling any of 10
checks fails a test.

`tests/test_main.py` (17): `check` builds every server and worker; optional
sections; secret files refused unless private (without echoing them); bad
configuration (a missing key, monitoring off loopback, the operator API off
loopback without TLS, a bad `listen`, a missing file, a bad identity); one
instance runs the workers and another takes over when it stops, a failing
job runs again; a lost lock connection ends that term and a new one starts;
`serve` in a subprocess answering on monitoring, the operator API (401, then
200 with a token), the agent API refusing a client without a certificate and
enrollment, then SIGTERM → exit 0 with the workers started and no traceback;
`migrate` from 0011 (dump then upgrade, then nothing to do, refused without
bucket C); `drill` (role checked, target file must be private, pass → 0, a
wrong key → 1); `rebuild` with only `[bucket_c]` and `[s3]`. `test_the_workers_metric_follows_the_lock`: two instances' `/metrics` as
the lock passes from one to the other; `serve` reports 1 once its workers
start; `workers_test.yml` under promtool (losing the lock for good, an
overlapping restart, two leaders). Disabling any of 7 checks of the metric,
its wiring and the rules fails a test. `test_per_worker_metrics`: nothing
per worker before a term, a good worker's success advancing while a failing
one stays at the term's start and is counted, the ages gone after the term,
the counter kept; `serve` reports all six; `workers_test.yml` adds a
5-minute worker firing past 15 min, an hourly one past 3 h, and a reconciler
two minutes behind staying quiet. Disabling any of 7 checks fails a test. Disabling any of
12 checks fails a test; the 13th, the shared signal handler, is equivalent:
without it uvicorn's handlers re-raise SIGTERM down to the same shutdown.

`tests/test_deploy.py` (16): `write_secrets` with a stand-in for `sops`
(files 0400, the directory 0700, maps as JSON, stale and half-written files
removed, accepted by `main.secret`; invalid keys and values refused with
nothing written; a `sops` failure reported without plaintext; no value
printed; a directory not on tmpfs, a symlink and an unknown user refused);
`systemd-analyze verify` of the three units; their key settings; and, through
the user's systemd manager with each unit's own `[Service]` settings,
`write-secrets` under `ctl-secrets.service`, `check` under `ctl.service`
reading what `write-secrets` wrote, `chown` killed under `ctl.service` but not
under `ctl-secrets.service`, and no writable-executable memory under
`ctl-secrets.service`. Disabling any of 12 checks fails a test. Not shown
here: settings that drop capabilities or need mount namespaces (this
machine's user manager sets none up, so `ProtectSystem`, `PrivateTmp`,
`InaccessiblePaths` and `ReadWritePaths` aren't exercised and that test
skips), chowning to another user (needs root), and the real `sops` binary
(not installed here).

## Dev

`hostagent` isn't pip-installable as is (setuptools finds `dev/` and
`hostagent/`), so the venv has a `.pth` pointing at `../agent`, plus its
runtime deps (`docker`, `pyrage`, `boto3`, `jsonschema`). `ctlplane/params.schema.json`
is exported from `hostagent.ops.PARAMS`; the contract test fails when they differ.

## Not built

- Certificate renewal; release-key rotation; rotation (`Tenant.RotateSecret`); Relocate (a slot on the
  target host); the L2 cluster, control-plane, registry and full-rebuild
  drills (DOC-05 §5); the other DOC-05 §8
  alerts (missing files, the tenant backups' read-back mismatch).
- Bucket C: objects outside the
  `public` schema and cluster settings (`postgresql.conf`, `pg_hba.conf`)
  aren't in the dump: those are ctl-1's IaC.
- The §3 provisioning rules
  (organization, terms, release, rate card, quote), `deletion_case`,
  evidence kinds beyond release approvals, the operator side of the tenant
  lifecycle (DRAFT → ELIGIBLE, suspension, cancellation).
- Leader election proper (E1): the workers lock keeps a second instance's
  workers off, with a window of up to `LOCK_PING` seconds after a lost
  connection.
- On a real ctl-1: real `sops` and WireGuard (`infra/` tests everything
  else in a systemd container: the units' filesystem sandbox, the chown to
  `ctl`, the bootstrap; see `infra/README.md`).
- Compensation (FAILED → RECOVERING) and paging on incidents.
- Dispatch-key custody (it is a configuration value) and rotation.
- `environment.observed_*` from evidence.
- LISTEN/NOTIFY instead of polling the database every 0.5 s during a long
  poll.
