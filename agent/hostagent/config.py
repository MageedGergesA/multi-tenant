"""Agent local configuration, delivered at enrollment (DOC-04 §2, §4)."""
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import VerifyKey

from .canonical import load_verify_key

ROLES = ('app', 'db', 'mail')


@dataclass(frozen=True)
class Trust:
    """Pinned public keys. Several dispatch keys cover the 7-day rotation overlap."""
    dispatch: tuple[VerifyKey, ...]
    release: VerifyKey
    custodian: tuple[VerifyKey, ...]
    breakglass: VerifyKey | None = None
    # True only while no backup operator is enrolled (DOC-03 §12.4).
    breakglass_enabled: bool = False
    # Other hosts' agent keys, to verify backup manifests they signed (restore on
    # another host, relocation). This agent's own key is always trusted.
    agents: tuple[VerifyKey, ...] = ()
    # The trust document's version (Host.RotateTrust); a new one must be higher.
    version: int = 0


@dataclass(frozen=True)
class AgentConfig:
    host_id: str
    role: str
    trust: Trust
    state_dir: Path
    registry_host: str
    allowed_cells: tuple[str, ...] = ('community/19.0/ubuntu-24.04/py3.12/pg16',)
    port_range: tuple[int, int] = (20000, 29999)
    reserve_pct: int = 20
    max_clock_skew: int = 60
    max_envelope_life: int = 600
    nonce_ttl: int = 24 * 3600
    rate_host_per_min: int = 30
    rate_env_per_min: int = 5
    exec_socket: Path = Path('/run/agent-exec.sock')
    db_host: str = ''
    mail_host: str = ''
    subuid_base: int = 0                 # Docker userns-remap base (ADR-011); 0 without remap
    age_identity: object = None          # pyrage x25519 identity for envelope secrets
    health_host: str = '127.0.0.1'       # where agentd probes the tenant's loopback ports
    # This host's Traefik websecure entrypoint, probed with each tenant hostname as
    # SNI and Host (DOC-04 §6.1 steps 8–9); '' skips the public probes.
    ingress_url: str = ''
    ingress_ca: Path | None = None       # CA bundle for the ingress certificate; None = system store
    s3_endpoint: str = ''                # empty = provider default (B2's S3 endpoint is set per region)
    s3_region: str = 'eu-central-003'
    s3_bucket: str = ''                  # bucket A, Object Lock enabled (ADR-005)
    backup_tmp: Path = Path('/srv/backup-tmp')   # as agentd sees agent-exec's backup-tmp
    ctl_url: str = ''                    # https://ctl-1 over WireGuard (poller.py)
    ctl_ca: Path | None = None           # pinned CA for ctl-1's server certificate
    tls_cert: Path | None = None         # this host's client certificate, CN = host_id
    tls_key: Path | None = None
    workers: int = 4                     # steps run in parallel; BUSY still serialises per environment
    poll_wait: int = 25
    heartbeat_s: float = 60              # `in_progress` response interval while a step runs; 0 = off
    trust_root: str = ''                 # the release public key, from the host image (enroll.py)
    enroll_url: str = ''                 # ctl-1's enrollment listener (server TLS only)
    extra: dict = field(default_factory=dict)


def load(path: Path) -> AgentConfig:
    raw = tomllib.loads(path.read_text())
    if raw['role'] not in ROLES:
        raise ValueError('unknown role %r' % raw['role'])
    if 'trust' in raw:      # pinned by hand (development)
        t = raw['trust']
        trust = Trust(
            dispatch=tuple(load_verify_key(k) for k in t['dispatch']),
            release=load_verify_key(t['release']),
            custodian=tuple(load_verify_key(k) for k in t['custodian']),
            breakglass=load_verify_key(t['breakglass']) if t.get('breakglass') else None,
            breakglass_enabled=bool(t.get('breakglass_enabled', False)),
        )
    else:                   # pinned at enrollment, checked against the image's release key every start
        import json
        from .enroll import trust_from
        trust = trust_from(json.loads((Path(raw['state_dir']) / 'trust.json').read_text()), raw['trust_root'],
                           raw['host_id'], raw['role'])
    return AgentConfig(
        host_id=raw['host_id'],
        role=raw['role'],
        trust=trust,
        state_dir=Path(raw['state_dir']),
        registry_host=raw['registry_host'],
        allowed_cells=tuple(raw.get('allowed_cells', AgentConfig.allowed_cells)),
        port_range=tuple(raw.get('port_range', AgentConfig.port_range)),
        reserve_pct=raw.get('reserve_pct', AgentConfig.reserve_pct),
        exec_socket=Path(raw.get('exec_socket', AgentConfig.exec_socket)),
        db_host=raw.get('db_host', ''),
        mail_host=raw.get('mail_host', ''),
        subuid_base=raw.get('subuid_base', 0),
        health_host=raw.get('health_host', AgentConfig.health_host),
        ingress_url=raw.get('ingress_url', ''),
        ingress_ca=Path(raw['ingress_ca']) if raw.get('ingress_ca') else None,
        s3_endpoint=raw.get('s3_endpoint', ''),
        s3_region=raw.get('s3_region', AgentConfig.s3_region),
        s3_bucket=raw.get('s3_bucket', ''),
        backup_tmp=Path(raw.get('backup_tmp', AgentConfig.backup_tmp)),
        ctl_url=raw['ctl_url'],
        ctl_ca=Path(raw['ctl_ca']),
        tls_cert=Path(raw['tls_cert']),
        tls_key=Path(raw['tls_key']),
        workers=raw.get('workers', AgentConfig.workers),
        poll_wait=raw.get('poll_wait', AgentConfig.poll_wait),
        heartbeat_s=raw.get('heartbeat_s', AgentConfig.heartbeat_s),
        trust_root=raw.get('trust_root', ''),
        enroll_url=raw.get('enroll_url', ''),
    )
