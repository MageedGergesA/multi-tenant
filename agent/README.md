# Host agent (DOC-04)

`agentd` (unprivileged: verify, admit, journal, run steps) and `agent-exec`
(privileged: fixed verb list over a 0600 Unix socket). Python 3.12.

    python3.12 -m venv .venv && .venv/bin/pip install -e '.[test]'
    .venv/bin/python -m pytest -q

## Built

| Part | File | DOC-04 |
|---|---|---|
| Canonical JSON + Ed25519 | `canonical.py` | §3 |
| Envelope verification in the specified order | `envelope.py` | §3 |
| Local policy: host, role, tenant state, ownership, slot/ports, cell, release manifest, custodian approval, break-glass, drain, capacity hook | `envelope.py` | §2, §4 |
| SQLite state: registry, fence high-water, nonces, step journal, active op, rate events (fsync per commit) | `state.py` | §5.3 |
| Atomic admission: BUSY, fence, rate limit | `state.py` | §4 |
| Internal verbs, validated on both sides | `verbs.py` | §5.4 |
| Executor + socket server + audit log | `execd.py` | §1, §10 |
| Signed responses, redacted logs | `agentd.py`, `logs.py` | §7, §10 |
| Steps: `Tenant.Create` (db + app, 9 of 10 steps), `Tenant.Start`, `Tenant.Stop`, `Host.Drain`, `Agent.Query` | `steps.py` | §6.1, §6.2, §6.16, §7 |
| Envelope secrets (age, opened after all checks, per-step allowed names) | `secrets.py` | §3 |
| App-host backend: filestore and run dirs, network (ICC off), nftables ruleset, image, secrets, `odoo.conf`, hardened containers, one-shots, Traefik file | `backends.py` | §5, §6.1 |
| DB-host backend: role, database, hardening, `pg_hba` include files, inspect | `pg_backend.py` | §5.4 |
| `Tenant.Backup`: guard lock, dump on the guard's snapshot, every referenced file checked, signed manifest, age-encrypted archive, compliance-locked upload, read-back | `steps.py`, `backends.py`, `s3.py`, image `backup-dump` | §6.8 |
| `Tenant.Delete` (app + db steps): refused unless the journal shows the runtime stopped and a backup < 1 h old and no restore copy of the tenant lives; removes container, route, firewall, network, filestore, secrets, then hba line, sessions, database, role; registry row kept as a tombstone | `envelope.py`, `steps.py`, `state.py` | §6.13 |
| Long-poll to ctl-1 over mutual TLS 1.3 (pinned CA, client cert per host), steps on a worker pool, signed responses through a persistent outbox, redelivery dedup, crash recovery; `agentd_main.py` entry point | `poller.py`, `agentd.py`, `state.py` | §1, §7, §8 |
| `RestoreCopy.Expire` (app + db steps): same removal for a `restore_copy`, fenced on the copy; refuses production and other tenants' copies | `envelope.py`, `steps.py` | §6.15 |
| `Host.Enroll`, agent side: generates the Ed25519, X25519 and TLS keys, sends their public halves with the one-time token and a possession proof, checks the returned authorization against the release key in the image, then writes keys (0600), certificate and `trust.json`; `config.load` re-checks that signature at every start | `enroll.py`, `config.py` | §2, §6.16 |
| `Host.RotateTrust`: a fleet trust document signed with the release key, in a dispatch-signed envelope; refused unless newer than the pinned version and still listing the dispatch key that signed the request; written to `trust.json` and swapped in memory | `envelope.py`, `steps.py`, `enroll.py`, `ops.py` | §2 |
| `Tenant.RestoreToIsolated`: deny-all firewall first, download + checksum, decrypt, manifest signature/tenant/environment checks, single-transaction `pg_restore`, every file re-hashed, neutralize, `platform_defaults(copy)`, start, checks | `steps.py`, `backends.py`, image `restore-load` | §6.9 |
| Deep drill (`deep: true`, DOC-05 §5): row counts of 10 key tables, taken in the backup's snapshot into the signed manifest and again in the copy right after `pg_restore` (before neutralize), must be equal; one PDF (base's module reference) printed by the running copy | `steps.py`, `backends.py`, image `row_counts.py`, `print-report` | DOC-05 §5 |

`mail.user` (step 2) waits for the mail agent.

With `ingress_url` set (this host's Traefik websecure entrypoint, and
`ingress_ca` for a private CA), step 8 waits up to 5 minutes for Traefik to
serve a certificate that verifies for every hostname (`certificate:
issued`), and step 9 also probes each hostname through it, by SNI and Host:
`/web/login` 200, `/websocket` 101, `/web/database/manager` 403 (reported as
`public`, `https_login`, `https_websocket`, `public_db_manager`). Without
it, step 8 reports `not_checked` and step 9 probes loopback only.

Every other step fails closed with `EXEC_ERROR` ("step not implemented").

## Tests

    .venv/bin/python -m pytest -q          # unit + contract tests on the host
    dev/up.sh && dev/test.sh               # Tenant.Create end to end
    dev/test.sh tests/                     # everything, inside the Docker VM

`tests/test_contract.py` covers the DOC-04 §11 rows that don't need unbuilt
steps. `tests/test_create_e2e.py` runs the nine Create steps from signed,
age-encrypted envelopes, then checks: role has no superuser/createdb/etc.,
PUBLIC can't connect, container is read-only with all capabilities dropped
and the tenant UID, login 200 and websocket 101, database-service calls
refused, the admin password is the secret and `admin` is rejected, the
password file is gone, every step is idempotent, another tenant ID gets
`NOT_OWNER`. Teardown removes everything.

`tests/test_backup_e2e.py` creates a tenant with three attachments, then:
backup (guard held, no missing files, compliance lock ≥ 1 day); re-run verifies
and doesn't re-upload; a stolen storage key can't delete the version or
shorten the lock; the stored object is age ciphertext; restore to an isolated
copy passes every check; the copy's attachments match byte for byte; the copy
is neutralized with `report.url` set; another tenant's restore finds nothing;
a referenced file missing from the filestore fails the backup and uploads
nothing. Then `RestoreCopy.Expire` removes the copy on both hosts while
production keeps serving, removes the leftovers of the failed foreign-tenant
restore (its database on the db host), and refuses the production environment.

`tests/test_poller.py` runs the poller against a fake ctl-1 over mutual TLS
1.3 with throwaway openssl certificates: a polled envelope runs and its
response arrives signed by the agent key; poll capacity equals free workers;
plain http, a server certificate from another CA and a client certificate
from another CA are all refused; a response survives a ctl-1 outage and an
agent restart; the same envelope again gets `REPLAY` plus the original result,
and a re-signed copy gets the stored result, with one journal row (checked
by disabling the dedup: the test fails); the same op/token/step with another
tenant is verified afresh (`NOT_OWNER`); a step left `in_progress` by a crash
is reported `TIMEOUT` and its environment freed; a slow step on one
environment doesn't hold up another; a malformed reply backs off 2 s, 4 s….
`tests/test_contract.py` also runs a slow "orphaned" verb in agent-exec: a
second changing verb on that sid gets `BUSY`, inspect and other sids go
through, and a re-dispatched Start gets `BUSY` without running, then succeeds
once the verb ends (both tests fail with the claim disabled). Heartbeats:
a slow step sends numbered, signed `in_progress` beats then its result; a
quick one sends none; beats stop at the step deadline (fails with the
deadline check disabled) and never follow the result.
`tests/test_deadline.py`: a step past its deadline (with and without
heartbeats) comes back in well under its 5 s verb as `failed`/`TIMEOUT`,
`exec.cancel` was sent for its sid, no verb follows, the environment is
released and the TIMEOUT is answered on redelivery; a step inside its
deadline is never cancelled; `exec.cancel` gets through while the sid is
claimed. Each of the cancel call and the two guard checks, disabled, fails
tests. On the host, `test_exec_restart.py` also cancels through the real
`agent-exec-dev`: only that sid's one-shot is killed (exit 137), not the
tenant's container nor another sid's one-shot.
`tests/test_exec_restart.py` (on the host, needs `dev/up.sh`) starts a
labelled "orphan" one-shot, the tenant's own container and plaintext and
encrypted leftovers, restarts `agent-exec-dev`, and checks that only the
orphan and the plaintext are gone and that the startup audit line lists them;
unit tests check one-shots carry the label and `backup.package` refuses a
missing dump. The first run found two things: a removal already in progress
(409) crashed agent-exec at startup, and the old socket file outlives a
restart, so "socket exists" isn't "ready" (the startup audit line is).

`tests/test_delete_e2e.py` creates a tenant, then: Delete is refused while it
runs and again until a backup exists; stop; final backup in
`DELETION_ELIGIBLE`; `app.remove` and `db.drop` under one custodian approval
leave no container, network, volume, route, ruleset, secrets, backup-tmp,
database, role or hba file; both steps retry cleanly; the final backup is
still stored under its compliance lock; Create and Start on the deleted
environment get `POLICY_STATE` "deleted".

Still to cover: ApplyPatch `REQUIRES_MODULE_UPDATE`; restore-copy zero egress
(needs real nftables counters, so it fails closed outside dev); the GC guard
under a concurrent `_gc_file_store`; real B2 Object Lock behaviour (LocalStack
enforces it locally); offline-agent reconciliation end to end.

### Development topology (Docker Desktop)

| Stand-in | For | Notes |
|---|---|---|
| `agent-pg` | `db-1` | PostgreSQL 16, `pg_hba` ends with `include_dir` + reject; 127.0.0.1:55432 |
| `agent-exec-dev` | root `agent-exec` on an app host | Docker socket; tenant files in volume `agent-dev-root`; nftables in dry-run (ruleset files only) |
| `agent-s3` | Backblaze B2 (bucket A) | LocalStack 4.4 S3; refuses deleting or shortening compliance-locked versions |
| `dev/test.sh` container | `agentd` | uid 1000, no Docker socket, host network for loopback probes and S3 |

Docker Desktop runs containers in a VM: shared host folders ignore `chown` and
Unix sockets don't cross into the host. So tenant files, the executor socket
and `pg_hba` fragments live in named volumes, tenants mount volume subpaths
(`no_copy`, or Docker copies the image's `/var/lib/odoo` permissions over the
tenant's directory), and `agentd` runs in the VM. Production uses host bind
mounts. Tenants reach the database through `host.docker.internal`, as they
reach `db-1` through NAT in production.

## Spec gaps resolved here (raise in DOC-04 v1.1)

1. **Fencing per step.** §3 rejects an "older or equal" token, but an operation
   is sent as one envelope per step with one token. The agent accepts an equal
   token only from the operation that set it.
2. **`tenant_state` in the envelope.** §6.13 needs the state from the control
   plane but §3 has no field for it. Added; checked against each type's allowed
   states.
3. **Container limits.** ADR-011 sets `--memory`/`--cpus` per plan band, but
   §6.1's `runtime_slot` doesn't carry them. Added `mem_limit_bytes` and
   `cpu_millis`.
4. **`file.write_conf` and `traefik.write`** take structured fields that
   agent-exec renders itself, not pre-rendered text, so a compromised agentd
   can't change `db_host`, `addons_path` or routes.
5. **BUSY before fence** at admission, so concurrent requests on a busy
   environment get `BUSY` (§11) instead of racing on the fence.
6. **Release key verifies manifests only**; it can't sign envelopes, and the
   custodian key can't sign either (tested).

7. **`db_name` without `dbfilter`** (§5.2). With `db_name` alone Odoo serves
   only that database and never lists databases (`odoo/service/db.py`
   `list_dbs`).
8. **Tenant role may connect to `postgres`** (§5.2, ADR-004). Odoo 19 connects
   there on every start to check `db_name` exists (`odoo/cli/server.py`) and
   crashes on a `pg_hba` rejection. `pg_hba` allows `t_<sid>,postgres`;
   `postgres` gets no TEMP or CREATE for PUBLIC; `pgpass` uses database `*`.
9. **`/web/database/manager` returns 200 in Odoo 19** whatever `list_db` says
   (§6.1 step 9 expected 403 on loopback). `list_db = False` blocks every
   database-service call instead; the health check verifies that, and the 403
   stays Traefik's job at the edge.
10. **Config names for Odoo 19** (§5.2): `with_demo = False`, not
    `without_demo`; `smtp_ssl = True` means STARTTLS (a boolean).
11. **`init_db` can't use `odoo db init`**: it creates the database itself
    (needs CREATEDB) and only logs initialisation errors. The agent pre-creates
    the database and runs `-i base,<modules> --load-language`.
12. **`platform_defaults(create)` sets the tenant admin's password** (from a
    secret file, removed right after), language and company country/currency;
    otherwise the admin stays `admin`/`admin`. New args: `create <lang>
    <country>`.
13. **Create needs `app_host_ip`** for the db-agent's `pg_hba` rule; not in §6.1.
14. **Rate limit counts operations, not steps**; a ten-step Create would hit
    5/min per environment on its own.
15. **The executor derives the tenant UID from the filestore owner** and refuses
    anything outside 10001–59999, so a tampered directory can't make a
    one-shot run as root.

16. **Uploads and downloads run in `agentd`**, because agent-exec has no network
    (§1). agent-exec writes the archive already encrypted and owned by agentd,
    so agentd never sees plaintext tenant data.
17. **RestoreToIsolated needs `runtime_slot` and `app_host_ip`** for the copy;
    not in §6.9.
18. **RestoreToIsolated is fenced on the copy's environment**, so a daily drill
    never blocks the production environment's operations; the source may be
    on another host, so the app host checks the manifest's tenant and
    environment instead of its registry, and refuses production as a target.
19. **Backup manifest is signed by the agent key**; restore trusts its own key and
    `Trust.agents` (other hosts' keys, for cross-host restores).
20. **Odoo's `ir.attachment.write` drops `store_fname`, `checksum` and
    `file_size`**, so a tenant admin can't point an attachment at another
    file through the ORM.
21. **Delete preconditions the agent checks itself** (§6.13 says only "the
    journal must hold the Suspend or Stop"): the latest start/stop step in the
    journal is a stop or suspend, a backup finished less than 1 h ago (DOC-03
    DR-06; the journal doesn't record the tier, so "final" isn't checked), and
    no live restore copy of the tenant on this host, since copies hold the same
    data. The db-agent can only check the copies: its journal has no Stop.
22. **Tombstones** (DOC-03 §9): a deleted environment keeps its registry row,
    sid and `container_uid`; its ports are freed. Every operation on it except
    a Delete retry and `Agent.Query` gets `POLICY_STATE` "deleted".
23. **`CANCELLING` and `EXPORT_READY`** (DOC-03 §9.2) were missing from the
    envelope's `tenant_state` enum, so a Stop or Export during the cooling-off
    period would have failed `SCHEMA`.
24. **`Tenant.Backup` must accept `CANCELLING`, `EXPORT_READY` and
    `DELETION_ELIGIBLE`**: §6.8 allowed only live states, so RB-20's final
    backup before Delete was impossible.
25. **`mail.remove`** waits for the mail agent, like `mail.user`.
26. **RestoreCopy.Expire is fenced on the copy** (`params.environment_id`), like
    RestoreToIsolated, so it never makes production's tokens stale; a restore
    still running on the copy gets `BUSY`.
27. **Expire of a copy this host never registered returns OK with
    `registry: absent`** and touches nothing: the restore steps register before
    creating anything, so no row means nothing to remove. This lets one Expire
    clean up a restore that failed after the db step but before the app step.
    The `_old<ts>` leftovers of §6.10/§6.12 wait for RestoreProduction and
    Relocate.

28. **Agent ↔ ctl-1 wire protocol** isn't in DOC-03 or DOC-04. Proposed in
    `poller.py`: `POST /v1/agents/<host_id>/poll {wait, capacity}` →
    `{envelopes}` or 204, and `POST /v1/agents/<host_id>/responses
    {responses}`. ctl-1's side is in `../ctl` (agent_api.py): the client
    certificate subject must be exactly `CN=<host_id>`, and every response
    is checked against that host's agent key, its own `host_id`, and the
    operation's current step and token. Tested there with this agent.
29. **REPLAY vs at-least-once delivery.** DOC-04 §11 wants `REPLAY` for the same
    envelope; DOC-03 §2.5 wants dedup on (op_id, fencing_token, step). Both
    hold here: the same envelope gets `REPLAY` and the original response is
    queued again; a re-signed redelivery gets the stored response. The match
    also needs the same content (envelope minus nonce, times, secrets and
    signature), otherwise another tenant's envelope with the same key would
    have been answered from the store; the e2e suite caught that.
30. **Crash recovery** (§8 "completes or aborts its current step"): at start,
    `in_progress` steps become `failed`/`TIMEOUT` and their environment is
    released. agent-exec may still be running that step's last verb, so it
    allows one changing verb per sid at a time: a re-dispatched step that
    meets it gets `BUSY` at once (status `busy`, environment released, not
    stored as finished, so ctl-1 retries it). Read-only verbs (`*.inspect`,
    `pg.connection_stats`) are never held up. If agent-exec itself restarts,
    the claims are lost, so before serving it reaps what the old process left:
    every container labelled `platform.oneshot` (nothing can legitimately be
    running yet), and the plaintext backup/restore leftovers in backup-tmp
    (dump work dirs, unencrypted `.tar`, decrypted `archive.tar`, extracted
    `x/`). Encrypted archives stay, since agentd may be uploading or
    downloading them right now. If a one-shot can't be removed after 10 tries,
    agent-exec exits instead of serving. One-shots also stop at their own
    timeouts (`ONESHOT_TIMEOUT`, killed and removed).
33. **`backup.package` packaged whatever was there**: a missing `dump.pgc` or
    `files.json` (a reaped work dir, say) gave a manifest-only archive that
    would have been uploaded as a backup. It now refuses.
31. **Progress heartbeats** (not in DOC-04): while a step runs, the agent sends
    a signed `in_progress` response every `heartbeat_s` (60 s) with
    `heartbeat` (a counter), `elapsed_s` and `deadline_at` (start + the §8
    agent timeout for that step, in `ops.STEP_TIMEOUTS`), straight to ctl-1
    through the outbox. They stop at the result (none is stored after it) and
    at the deadline. ctl-1 should extend the lease on each beat but never past
    `deadline_at` + its §8 margin. Heartbeats are never used as a stored
    result for redelivery. At the deadline the step is cancelled (§8 "aborts
    its current step"): agentd sends `exec.cancel {sid}`, which agent-exec
    serves past the sid claim by killing that sid's running one-shot, so the
    verb holding the sid returns; and the step's exec client refuses every
    further verb and turns the one in flight into `failed`/`TIMEOUT`
    (`{"cancelled": true}`), stored like any result and the environment
    released. Limits: other verbs are short API calls and are let finish;
    agentd-side work between verbs (an S3 upload) runs to its own timeouts,
    so a backup object may land in S3 although the step reports TIMEOUT
    (re-dispatch finds it with `head` and verifies it); a step that finishes
    just after the deadline without another verb reports its real result.
    A thread that never returns still leaves the step to `recover()` at the
    next agentd start.
32. **Outbox retention:** delivered responses are kept 24 h, to answer
    redeliveries, then pruned.
34. **Enrollment can't be an envelope.** §6.16 lists `Host.Enroll` beside
    the dispatched operations, but a host being enrolled has no key,
    certificate or pinned trust to verify one with. It is its own exchange
    (ctl-1 side and findings in `../ctl/README.md`). The image carries only
    `ctl_ca` and `trust_root` (the release public key); the dispatch,
    custodian and break-glass keys come in the release-signed authorization.
    `python -m hostagent.enroll` refuses a state directory that already has
    `agent.key`: re-enrolling means a rebuilt host (DOC-05 §1).
37. **The edge didn't refuse the database manager to the host itself.** The
    `-deny` router allowed `127.0.0.1/32`, so a probe from the host (and any
    process on it) reached Odoo's page through Traefik. It now refuses every
    client. A real Traefik in the dev topology (`agent-traefik`, port 18443,
    default certificate from a dev CA because ACME can't run locally;
    `cert_resolver = ""` in `exec.toml`) is what showed it.
36. **Tenant.Backup in VALIDATING:** DOC-03 §3.6 requires a recoverable
    first backup before ACTIVE; §6.8 didn't allow Backup in VALIDATING.
    Added (`ops.CATALOG`).
35. **`Host.RotateTrust`** isn't in §6's catalog; added as host-scoped
    `any.rotate_trust` taking `trust_document` (`ops.TRUST_DOCUMENT`). The
    document carries `trust_version`; the agent refuses one that isn't newer
    or that drops the dispatch key signing the request (lock-out). It also
    delivers `Trust.agents`, the other hosts' keys.

38. **Deep-drill row counts are taken before neutralize** (inside
    `restore-load`, after `pg_restore`): neutralize and
    `platform_defaults(copy)` change rows, so counting the running copy
    would never match. A backup made before this change has no counts in
    its manifest; a deep drill of it fails (`row_counts_match: false`).
39. **The PDF is printed in the copy's network namespace.** A one-shot has
    its own; wkhtmltopdf fetches the report's CSS from `report.url`
    (`127.0.0.1:8072`, set by `platform_defaults`), which only reaches the
    server when the one-shot shares the running container's namespace
    (`network_mode=container:<copy>`). The report is rendered in a
    transaction that is rolled back.

## Running on a host

`python -m hostagent.exec_main --config exec.toml` (role `app` as root; role
`db` as the postgres user, peer authentication over the local socket, its
socket 0660 in the group given as `owner_gid`, which agentd is in) and
`python -m hostagent.agentd_main --config agent.toml` (user `agent`), after
`python -m hostagent.enroll --config agent.toml --token-file F`. The units,
configs and enrollment are `../infra/ansible/roles/agent`; the package
installs with `requirements.lock` as constraints.

## Next

- Real nftables on a VPS: apply the rulesets and read the deny counters for
  the zero-egress check; SEC-01 AT-01…12 and AT-40…42 against a real host.
- The same public probes for SetDomain, ApplyPatch and ModuleUpdate's
  health steps, once those steps exist.
- Release-key rotation (it is the image's root of trust: new images and
  re-enrollment, `../ctl/README.md` finding 42).
- Agent: `ERROR` in TENANT_STATES (DOC-03 §5); the mail agent's `mail.user` (Create stops there).
- Agent: secret names for RestoreProduction, Relocate's backup and RotateSecret (ctl-1 refuses them until then).
