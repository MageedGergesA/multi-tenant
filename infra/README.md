# infra: ctl-1 as code

ctl-1 rebuilt from this directory and bucket C (DOC-05 §6.6, DOC-07 RB-09/RB-10).
OpenTofu declares the server and the platform's private network on Hetzner
Cloud; Ansible configures the host. Nothing here has been applied to a real
server: applying needs the owner's priced approval and `HCLOUD_TOKEN`.

| Path | What |
|---|---|
| `tofu/` | network `platform` (10.0.0.0/16, delete-protected), firewall `ctl-1` (WireGuard UDP and ICMP; SSH only from `admin_cidrs` while bootstrapping), operators' SSH keys, server `ctl-1` (Ubuntu 24.04, fixed private IP 10.0.0.2, delete and rebuild protection, `prevent_destroy`). hcloud provider pinned to 1.69.0 (`.terraform.lock.hcl` has its hashes). State and plans are encrypted (OpenTofu state encryption, `TF_VAR_state_passphrase` from the SOPS repo). |
| `ansible/ctl.yml` | roles `base` (packages, SSH keys-only, nftables), `wireguard` (wg0 10.8.0.1/24, the host makes its own key, peers from `wireguard_peers`), `postgresql` (Ubuntu's PostgreSQL 16, loopback, SCRAM, `ctl_owner` + database `ctl`), `monitoring` (Ubuntu's Prometheus 2.45 and Alertmanager 0.26 on loopback, Alertmanager clustering off; ctl's rules from `ctl/monitoring/rules`, each `promtool`-checked; every alert to ctl's webhook as an incident; the webhook token made on the host, only its SHA-256 in `ctl.toml`; an always-firing `Watchdog` to `monitoring_deadman_url`), `ctl` (user, sops, the host's age key, the package in `/opt/ctl/venv`, `/etc/ctl/ctl.toml`, the units from `ctl/deploy/`, secrets, the owner's password, migrations, serve) |
| `tofu/hosts.tf` | db-1 (fixed private IP 10.0.0.3; WireGuard and ICMP from outside), the app hosts (`app_hosts`; HTTP/HTTPS from anywhere), each with a delete-protected Hetzner Volume for the tenants' filestore (DOC-05 §6.2), attached unformatted-mount (the app play mounts it) |
| `ansible/db.yml` | db-1: `base` (its PostgreSQL port admitted only from the app hosts' range, `base_private_allow`), `wireguard` (client of ctl-1: `endpoint`, `keepalive`), `db_host` (PostgreSQL 16 on loopback and the private IP, TLS with a key and certificate made on the host, `pg_hba` = postgres peer, the agent's `include_dir`, reject), `agent` |
| `ansible/roles/pgbackrest` | L2 (DOC-05 §2, §3.1): Ubuntu's pgBackRest 2.50 to bucket B (S3 path-style, `aes-256-cbc` repository cipher, zstd, two full cycles). On db-1 (`mode: db`, in `db.yml`): WAL archiving (`archive_timeout` 60 s), the stanza, full Sunday 01:00 UTC and differential the other days, `check` every 2 minutes (a WAL switch, so an idle cluster still archives), with a key that can't delete and `expire-auto=n`; its config root:postgres 0640. On ctl-1 (`mode: ctl`, in `ctl.yml` when `ctl_l2_bucket` is set): config without secrets, for ctl's `l2` worker, which runs `info`, `repo-ls` and a daily `expire` with the delete key and cipher pass from SOPS (`l2_repo.json`, `l2_cipher_pass`) |
| `ansible/app.yml` | an app host: `base` (80/443 open, `base_public_tcp_ports`; forwarding for Docker's bridges, `base_forward_docker`; the tenants' egress tables loaded with it), `wireguard`, `app` (the filestore Volume mounted at `/srv/tenants`, nodev/nosuid/noexec, never formatted: anything but ext4 stops the play; Ubuntu's `docker.io` with userns-remap, `dockremap` 100000:65536, published ports on 127.0.0.1, no inter-container traffic, live-restore, no-new-privileges, after the filestore and nftables (Wants, so a firewall restart doesn't restart Docker and every tenant); Traefik v3.7.14 by digest on the host network outside the remap, capabilities only `NET_BIND_SERVICE`, read-only, routers from `/etc/traefik/dynamic`, ACME HTTP-01; db-1's certificate as the tenants' libpq root), `agent` (role app: executor as root, `[app]` from `agent_app_*`) |
| `ansible/roles/agent` | the host agent from `agent/` (reproducible bundle, `agent/requirements.lock`): `agent-exec` (as postgres on db-1, root on an app host; its socket 0660 in the `agent-exec` group it shares with agentd) and `agentd` (user `agent`, sandboxed, `ConditionPathExists` its key), configs in `/etc/agent`, state in `/var/lib/agent` (0700); enrollment with a one-time token, removed after |
| `test/run.sh` | the playbook against a throwaway Ubuntu 24.04 container with systemd |
| `.bin/tofu`, `.venv/` | OpenTofu 1.13.1 (SHA-256 checked against the release's SHA256SUMS; the signature isn't verified), ansible-core 2.21.5 and ansible-lint 26.10.0, in Python 3.12 |

## Bootstrap

1. `cd tofu; cp terraform.tfvars.example terraform.tfvars` (your SSH key, your
   address in `admin_cidrs`); `export HCLOUD_TOKEN=... TF_VAR_state_passphrase=...`;
   `tofu init && tofu plan -out ctl.tfplan`, then, approved, `tofu apply ctl.tfplan`.
2. `cd ansible; cp inventory.example.yml inventory.yml` with the public IP and
   the files it names (SOPS file, ctl-1's TLS certificate signed by the agents'
   CA, the CA certificate, the IdP's JWKS).
3. `ansible-playbook -i inventory.yml ctl.yml`. A new host makes its own age
   key (`/etc/ctl/host.agekey`, root 0400) and WireGuard key, and the run stops
   at ctl-secrets printing the host's age recipient.
4. Add that recipient to the SOPS file's `creation_rules`, `sops updatekeys`,
   and run the playbook again: secrets onto `/run/ctl`, the owner's password
   set from `database_url` (PostgreSQL gets its SCRAM verifier only), the
   schema migrated if it isn't at head (`ctl-migrate`), ctl started, and the
   run waits for `ctl_workers_leader 1`.
5. Set `monitoring_deadman_url` to an external heartbeat (e.g. a healthchecks.io
   ping URL that alerts when pings stop): Alertmanager sends the `Watchdog`
   there every 5 minutes, so a dead Prometheus, Alertmanager or ctl-1 is
   noticed from outside (RB-25). Without it nothing notices that.
6. ctl's `[trust]` and `[[regions]]` come from `ctl_trust` and `ctl_regions`; the
   play registers them (`python -m ctlplane bootstrap`, idempotent: it adds,
   never changes or retires, and reports a region that differs).
7. Add ctl-1's WireGuard public key (printed by the play) to the operators'
   and hosts' peers, switch the inventory to `ansible_host: 10.8.0.1`, empty
   `base_admin_cidrs` and tofu's `admin_cidrs`, re-run both.

The SOPS file's keys are `ctl.toml`'s secrets (`ctl_secret_keys`): `database_url`
(`postgresql://ctl_owner:...@127.0.0.1:5432/ctl`), `dispatch_seed`,
`vault_identity`, `agent_tls_key`, `agents_ca_key`, `bucket_c_write.json`,
`bucket_c_retention.json` (B2 capabilities listFiles, readFiles, deleteFiles
on bucket C only; the write key has no deleteFiles), `dump_signing_seed` (signs each control-plane dump;
keep its public key in the IaC repo: a rebuilt ctl-1 trusts dumps only
through `ctl_dump_signing_public_keys`); a missing one is named by the play.

A later run changes nothing unless an input did; ctl is restarted only when
its package, configuration, certificates or units changed, and only after
its secrets and schema are in place. A deploy of new code is a re-run: the
bundle (a reproducible tar of `ctl/`) changes, the package is reinstalled
with `ctl/requirements.lock` as constraints, migrations run (dump to bucket
C first), ctl restarts.

### db-1 and the app hosts

1. `tofu apply` (hosts.tf) creates it; the play needs its host id from ctl-1.
2. Open its enrollment as an operator: `POST /v1/hosts {role: db, region,
   private_ip}` returns `host_id`, a one-time `bootstrap_token` and an
   `authorization` body. The founder signs that body with the release key
   (`release_signature`, canonical JSON), and an operator posts it to
   `/v1/hosts/<id>/enrollment/authorize`.
3. Put the token in a file and run `ansible-playbook -i inventory.yml db.yml
   -e agent_enroll_token_file=<file>` with `agent_host_id` set. The host makes
   its keys, enrolls over WireGuard (the authorization is checked against
   `agent_trust_root`, the release key), the token is removed, agentd starts
   polling. Without a token on a host not yet enrolled, the play stops and
   says this.
4. L2 needs bucket B made on B2 first (versioning on, a lifecycle rule keeping hidden
   versions 14 days, DOC-05 §3.1) and two keys scoped to it: db-1's without
   `deleteFiles` (`pgbackrest_db_key_file`), ctl-1's with it (SOPS `l2_repo.json`).
   The cipher pass (`pgbackrest_cipher_pass_file`, SOPS `l2_cipher_pass`) goes into
   the offline recovery set with the region keys: without it L2 is unreadable.
5. An app host is the same with `app.yml` (`role: app`), after db-1's play:
   that play fetches db-1's certificate to `ansible/.build/db-1.crt`
   (`app_db_ca_file`). `app_filestore_device` is the Volume,
   `/dev/disk/by-id/scsi-0HC_Volume_<filestore_volume_id>`; `agent_registry_host`
   and `agent_app_repository` name where tenant images are pulled by digest.
6. After an app host reboots, its tenants are stopped (restart policy `no`):
   their `/run/tenants` files are on tmpfs, so each needs `Tenant.Start`, which
   brings them again (DOC-04 §5.2, DOC-07's "start the tenants").

## Test

`infra/test/run.sh` (needs Docker, ctl's dev venv and LocalStack from
`agent/dev/up.sh`; about 4 min): a container with systemd as ctl-1, SSH on a
loopback port (Docker Desktop's bridge isn't routable from the host), and

- run 1 on the new host stops at ctl-secrets and names the host's recipient;
- run 2 with the SOPS file encrypted to it completes; then, inside the host:
  ctl, ctl-secrets, PostgreSQL and nftables active; `/run/ctl` tmpfs, `ctl`
  0700, every secret `ctl` 0400; the schema at head; the workers running;
  in ctl's mount namespace the host key and SOPS file are systemd's
  inaccessible node and `/` read-only (read from `/proc/<pid>/mountinfo`;
  `docker exec` can't enter the namespace); ctl with no capabilities;
  PostgreSQL on loopback; the agent API on wg0's address only; the operator
  API and monitoring on loopback; nftables `policy drop`; `ctl_owner` not a
  superuser, able to `SET ROLE ctl_dispatcher`, its password stored as SCRAM;
- monitoring: Prometheus and Alertmanager active, listening on loopback
  only (no cluster port 9094), ctl's rules loaded, ctl scraped as up, and
  `AuditAnchorMissing` (no anchor yet) arriving in ctl's database as a sev1
  RB-09 incident through Alertmanager and the webhook; the `Watchdog` not
  an incident;
- a real control-plane dump run under `ctl.service`'s own sandbox lands in
  bucket C (pg_dump, age, S3);
- run 3 changes nothing (`changed=0`) and ctl keeps its process;
- run 4, after an install that died midway (the package gone, the bundle
  and venv still there), installs again and ctl serves; run 5, after a deploy
  interrupted between install and restart, restarts ctl onto it;
- db-1 (a second container): enrolled through ctl-1's operator API as an
  operator and the founder would (`test/enroll_host.py`: OIDC token from the
  test IdP, `POST /v1/hosts`, release-key signature, authorize); the play
  without a token stops and says so; with it: PostgreSQL, agent-exec,
  agentd and nftables active, the executor running as postgres and agentd as
  agent, the socket postgres:agent-exec 0660, the token gone, the agent's
  keys its own 0600, ctl-1 seeing the host active, its certificate pinned
  and polling (mutual TLS over wg0), PostgreSQL on the private address with
  TLS, port 5432 closed to a private address outside the app range; a second
  run changes nothing;
- L2: db-1 archives (`archive_mode` on, 60 s), its pgBackRest config
  root:postgres 0640, the three timers enabled; a full backup through its unit;
  a row written after it; the check unit; bucket B holds only ciphertext; the
  latest backup restored from bucket B into an empty directory with WAL
  replayed and started as a second cluster: the row is there, recovery done;
  ctl-1's `l2` worker reads the full and the newest WAL time and has run
  expire; Prometheus has the L2 rules;
- app-1 (a third container, privileged for Docker inside): a device without
  ext4 stops the play; then configured and enrolled: nftables, Docker,
  Traefik, agent-exec and agentd active, Docker remapped (root dir
  `100000.100000`), the executor as root and agentd as agent, the socket
  agent's 0600; Docker's NAT table survives `systemctl reload` and `restart
  nftables`; Traefik pings and answers 404 for an unrouted name; agentd
  drives the executor (volume, network, firewall, router): the filestore
  remapped 110001 0700, the network `icc=false` on `br-<sid>`, the egress
  table loaded, the tenant's name routed (502: nothing on its port), its
  database manager 403 at the edge; `nft.inspect` reads the kernel (table
  deleted → not applied) and the firewall's boot load brings the table back;
  agentd reads the remap base; the executor looks a registry digest up;
  app-1 reaches db-1 with `verify-full` against db-1's certificate (then
  pg_hba refuses); ctl-1 sees it active and polling; a second run changes
  nothing.

The hosts share two Docker networks, 10.8.0.0/24 (its interface renamed wg0
in each, so nftables' `iifname "wg0"` rules apply) and 10.0.0.0/24 as the
private network.

Removing `createrole_self_grant` or `InaccessiblePaths`, or installing only
when the bundle copy changed, fails it.

What a container can't show: WireGuard (no kernel module here; `wg0` is a
dummy interface with ctl's address and `wireguard_start: false`), the real
`sops` (a stand-in decrypts age-encrypted JSON with the host key: the same
key handling, not the SOPS format; `ctl_sops_install: false`), and the
B2's key capabilities (a key without `deleteFiles` only hides; LocalStack has
no such keys, so db-1 and ctl-1 use the same one here) and the bucket's
lifecycle rule, and the
OpenTofu side, which is `tofu validate` and a `plan` with a dummy token only.
The container runs with CAP_SYS_ADMIN and no AppArmor profile so systemd can
remount its own cgroup namespace. No udev in a container either, so a mount
unit never sees its device: the Volume's mount runs only on a real host
(`app_filestore_on_root_disk: true` in the harness, which tests the refusal).

## Findings

1. **`ctl-secrets` killed `sops` (SIGSYS)**: Go's runtime calls `setrlimit`
   at startup, which `~@resources` denies. Found here with `age`; the unit
   now allows `setrlimit` back and denies the rest of `@resources`.
2. **The migrations' owner couldn't become the roles it created**: PG 16
   gives a role's creator ADMIN only, so `SET ROLE ctl_dispatcher` failed.
   `ctl_owner` has `createrole_self_grant = 'set, inherit'` (the dev
   database never showed it: tests connect as a superuser).
3. **`boto3` wasn't a declared dependency of ctl** (the dev venv had it from
   the agent), nor `cryptography` (only through pyjwt). Both are now.
4. **An installed ctl had no migrations**: `migrate` looked for them beside
   the source tree. `[database] migrations_dir` names them; the play unpacks
   them to `/opt/ctl/src/migrations`.
5. **`check` now requires the schema at head** (exit 1 otherwise), so
   `ctl.service` doesn't serve an old schema and the play knows to migrate.
6. **A container check that can't enter the namespace passes vacuously**:
   the first version read the host key through `nsenter`, which failed, so
   "reads empty" held either way. The checks read `mountinfo` instead.
7. **The host's keys are made on the host** (age, WireGuard) and only their
   public halves leave it; SOPS needs the new host's recipient before its
   first decrypt, hence two runs on a new host.
8. **A failed install was skipped next time** (Codex review): the install
   ran only when the bundle copy changed or no venv existed.
   `/opt/ctl/installed-bundle` records the bundle's checksum after a
   successful install; any other value reinstalls.
9. **The db executor had no entry point**: the agent's db backend was only
   driven in-process by its tests; `hostagent.exec_main` now serves role `db`
   (as postgres, peer authentication) and gives its socket to a group it
   shares with agentd (postgres can't chown to agentd's uid).
10. **The agent package wasn't installable**: `boto3` and `pyrage` were
    imported but not declared, and setuptools picked up `dev/` too. Fixed;
    `agent/requirements.lock` pins what it is tested with.
11. **A fresh ctl-1 had no way to register its root keys or regions** but
    SQL: `ctlplane bootstrap` does, from `[trust]` and `[[regions]]`.
12. **`~@privileged` includes `@chown`, again**: the db executor was killed
    (SIGSYS) giving its socket to the shared group. Its unit allows `@chown`
    back (without capabilities it can only change a group to one it is in).
13. **`flush ruleset` removes Docker's rules**: found in the harness, where a
    container on a user-defined network loses Docker's embedded DNS (NAT
    rules in its namespace) when the base role loads nftables. On an app host
    with Docker the same flush would remove Docker's own rules. Fixed: `base`
    replaces its own table (declare, delete, define, one transaction), and
    nftables.service's stop and reload are overridden to match (Debian's stop
    is `flush ruleset`).
14. **Tenants couldn't verify db-1** (found reading the agent for this round):
    `sslmode=verify-full` with no root certificate. The executor copies
    db-1's certificate into each tenant's run dir; `PGSSLROOTCERT` names it.
15. Codex review of this round:
    - **The tenants' egress tables didn't survive a reboot**, and
      `nft.inspect` read only the file. The base firewall includes
      `/etc/nftables.d/*.nft` on app hosts, Docker requires nftables.service,
      and inspect reads the kernel.
    - **Replacing a tenant's table left it open in between** (delete, then
      load, two `nft` runs). The file declares, deletes and defines: one
      transaction.
    - **agentd never read `subuid_base`**: tenants' filestores would have
      been made as 10001+ instead of 110001+ and refused by the executor.
    - **No image repository in the executor's config**: every pull raised
      `KeyError('repository')`. `agent_app_repository`, required with the
      registry.
    - **A reboot left tenants without their /run files** while Docker
      restarted them. (Also: `Tenant.Start` applies a tenant's egress table
      again if the kernel lacks it, before starting; Docker only Wants
      nftables, since Requires made a firewall restart restart Docker,
      Traefik and the agent, found in the harness.) Restart policy `no`; `Tenant.Start` brings the slot,
      the SMTP mode (sink for restore copies) and the secrets from ctl-1, and
      the agent renders them before starting.

16. L2 round (pgBackRest 2.50 from Ubuntu):
    - **Ubuntu's package reads `/etc/pgbackrest.conf`** only when
      `/etc/pgbackrest/pgbackrest.conf` is missing; the role writes the
      latter and removes the package's sample.
    - **pgBackRest talks to S3 over TLS only**: the harness uses LocalStack's
      TLS on 4566 (`pgbackrest_s3_port`, verification off for the stand-in).
    - **`stanza-create`'s "already exists" is an INFO line**, hidden at
      `log-level-console=warn`: the role asks `info` instead, and creates the
      stanza only when its status isn't 0, so a second run changes nothing.
    - **A restored cluster takes connections before recovery ends** (hot
      standby): the drill waits for `pg_is_in_recovery()` to turn false before
      it reads, or it can read before the WAL with the probe row is replayed.

## Not built

Notification beyond incidents (ADR-008's Telegram and email receivers;
ctl's "paging on incidents"); starting an app host's tenants after a reboot
by itself (now an operator's `Tenant.Start` each); the Volume's mount on a
real host (no udev in the harness); the monthly L2 drill on a temporary server
(scripted, DOC-05 §5; the harness does it on db-1); pgBackRest with B2 itself
(DOC-05 VERIFY: path-style, `DeleteObject` without `deleteFiles`); the git mirror and
off-site copy of this repository (DOC-05 §1); the operator console; real
`sops` and WireGuard on a real server (first apply).
