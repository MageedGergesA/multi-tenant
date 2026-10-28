"""Step handlers (DOC-04 §6). Each one reads the host's actual state first, acts
only if needed, reads back, and returns the observed evidence.

Implemented so far: Tenant.Create, Tenant.Start / Tenant.Stop, Tenant.Backup,
Tenant.RestoreToIsolated, Tenant.Delete and RestoreCopy.Expire (app and db
steps), Host.Drain,
Agent.Query. Every other step raises NotImplementedError and fails closed with
EXEC_ERROR.
"""
import base64
import json
import socket
import ssl
import time
import urllib.error
import urllib.request

from .naming import sid as derive_sid
from .secrets import open_secrets

STOP_TIMEOUT = 60
PIDS_LIMIT = 512
HEALTH_DEADLINE = 180
CERT_DEADLINE = 300          # ACME issuance through Traefik


def run(agent, env) -> dict:
    handler = HANDLERS.get((env['op_type'], env['step']))
    if handler is None:
        raise NotImplementedError(env['step'])
    return handler(agent, env)


def _failed(code, observed):
    from .agentd import StepFailed
    return StepFailed(code, observed)


def start(agent, env):
    s = derive_sid(env['environment_id'])
    seen = agent.exec.call('container.inspect', sid=s)
    if not seen['exists']:
        raise _failed('EXEC_ERROR', {'container': 'missing'})
    if not seen['running']:
        # Its egress table first, as the kernel has it (the base firewall loads them at boot; this
        # covers a load that failed): never a tenant without its restrictions.
        if not agent.exec.call('nft.inspect', sid=s)['applied']:
            registered = agent.state.environment(env['environment_id'])
            profile = registered['egress_profile'] if registered else 'deny_all'
            if not agent.exec.call('nft.apply_tenant', sid=s, profile=profile)['applied']:
                raise _failed('EXEC_ERROR', {'nft': 'not applied'})
        # /run/tenants/<sid> is tmpfs: after a reboot it's empty, and the container (restart policy
        # "no") waits for this. Rendered again at every start (DOC-04 §5.2).
        _render(agent, env, open_secrets(env, agent.config.age_identity), env['params']['smtp'])
        agent.exec.call('container.start', sid=s)
        seen = agent.exec.call('container.inspect', sid=s)
    if not seen['running']:
        raise _failed('HEALTH_FAILED', seen)
    return {'container': seen}


def stop(agent, env):
    s = derive_sid(env['environment_id'])
    seen = agent.exec.call('container.inspect', sid=s)
    if seen['exists'] and seen['running']:
        agent.exec.call('container.stop', sid=s, timeout=STOP_TIMEOUT)
        seen = agent.exec.call('container.inspect', sid=s)
    if seen['running']:
        raise _failed('EXEC_ERROR', seen)
    return {'container': seen}


def drain(agent, env):
    agent.state.set_flag('draining', '1')
    return {'draining': True}


def rotate_trust(agent, env):
    """Host.RotateTrust: pin the new keys (already checked in envelope.py) on
    disk, where config.load checks them again at every start, then in memory."""
    import dataclasses
    import json
    from .enroll import _write
    new = agent.verifier.new_trust(env)
    _write(agent.config.state_dir / 'trust.json',
           json.dumps(env['params']['trust_document'], sort_keys=True).encode(), 0o644)
    agent.config = dataclasses.replace(agent.config, trust=new)
    agent.verifier.config = agent.config
    return {'trust_version': new.version, 'dispatch_keys': len(new.dispatch), 'agents': len(new.agents)}


def query(agent, env) -> dict:
    """Agent.Query (DOC-04 §7): journal rows for an op, and observed state for an environment."""
    out = {}
    op_id = env['params']['op_id']
    if op_id:
        out['journal'] = agent.state.journal(op_id)
    if env['environment_id']:
        reg = agent.state.environment(env['environment_id'])
        if reg is not None and reg['tenant_id'] == env['tenant_id']:
            out['registry'] = reg
            if agent.config.role == 'app':
                out['container'] = agent.exec.call('container.inspect', sid=reg['sid'])
        else:
            out['registry'] = None
    return out


# -- Tenant.Create (DOC-04 §6.1) ------------------------------------------------

def _slot(env):
    return env['params']['runtime_slot']


def _digest(env):
    return env['release_manifest']['image_digest']


def create_db(agent, env):
    s = derive_sid(env['environment_id'])
    secrets = open_secrets(env, agent.config.age_identity)
    agent.state.register(environment_id=env['environment_id'], tenant_id=env['tenant_id'], sid=s,
                         container_uid=None, http_port=None, gevent_port=None, kind='production',
                         egress_profile='production', now=agent.clock())
    x = agent.exec
    x.call('pg.create_role', sid=s, password_hash=secrets['db_password_scram'])
    x.call('pg.create_db', sid=s)
    x.call('pg.harden_db', sid=s)
    x.call('pg.hba_add', sid=s, app_host_ip=env['params']['app_host_ip'])
    x.call('pg.reload')
    seen = x.call('pg.inspect', sid=s)
    role = seen['role'] or {}
    if not (role.get('login') and not any(role.get(k) for k in ('super', 'createdb', 'createrole', 'replication',
                                                                  'bypassrls'))
            and seen['db'] and seen['db']['owner'] == 'r_' + s and seen['public_connect'] is False
            and seen['hba_rules'] == 1):
        raise _failed('EXEC_ERROR', seen)
    return seen


def create_network(agent, env):
    s, slot = derive_sid(env['environment_id']), _slot(env)
    agent.state.register(environment_id=env['environment_id'], tenant_id=env['tenant_id'], sid=s,
                         container_uid=slot['container_uid'], http_port=slot['http_port'],
                         gevent_port=slot['gevent_port'], kind='production', egress_profile='production',
                         now=agent.clock())
    host_uid = agent.config.subuid_base + slot['container_uid']
    x = agent.exec
    vol = x.call('volume.inspect', sid=s)
    if not vol['exists']:
        vol = x.call('volume.create', sid=s, host_uid=host_uid)
    net = x.call('net.inspect', sid=s)
    if not net['exists']:
        net = x.call('net.create', sid=s)
    nft = x.call('nft.apply_tenant', sid=s, profile='production')
    if vol.get('owner_uid') != host_uid or vol.get('mode') != '0o700' or net.get('icc') != 'false' \
            or nft.get('profile') != 'production':
        raise _failed('EXEC_ERROR', {'volume': vol, 'network': net, 'nft': nft})
    return {'volume': vol, 'network': net, 'nft': nft}


def create_image(agent, env):
    digest = _digest(env)
    seen = agent.exec.call('image.inspect', digest=digest)
    if not seen['present']:
        seen = agent.exec.call('image.pull', digest=digest)
    if not seen['present']:
        raise _failed('EXEC_ERROR', seen)
    return seen


def create_config(agent, env):
    return _render(agent, env, open_secrets(env, agent.config.age_identity), 'relay')


def _render(agent, env, secrets, smtp):
    """The tenant's /run files: secrets, then odoo.conf. A restore copy (smtp 'sink') has only
    its database password, as app.restore_copy writes."""
    s, slot = derive_sid(env['environment_id']), _slot(env)
    x = agent.exec
    names = ('db_password', 'smtp_password', 'tenant_salt', 'tenant_admin_password') if smtp == 'relay' \
        else ('db_password',)
    for name in names:
        x.call('file.write_secret', sid=s, name=name,
               data_b64=base64.b64encode(secrets[name].encode()).decode())
    conf = {k: slot[k] for k in ('workers', 'max_cron_threads', 'db_maxconn', 'limit_memory_soft',
                                 'limit_memory_hard', 'limit_time_cpu', 'limit_time_real')}
    return x.call('file.write_conf', sid=s, conf=dict(conf, admin_passwd_hash=secrets['admin_passwd_hash'], smtp=smtp))


def create_init_db(agent, env):
    s, digest, params = derive_sid(env['environment_id']), _digest(env), env['params']
    x = agent.exec
    before = x.call('container.run_oneshot', sid=s, digest=digest, command={'name': 'module_versions'})
    if not (before['result'] or {}).get('base'):
        run = x.call('container.run_oneshot', sid=s, digest=digest,
                     command={'name': 'init_db', 'modules': params['modules'], 'lang': params['lang']})
        if run['exit_code'] != 0:
            raise _failed('EXEC_ERROR', {'init_db_exit': run['exit_code'], 'user': run['user']})
    after = x.call('container.run_oneshot', sid=s, digest=digest, command={'name': 'module_versions'})
    installed = after['result'] or {}
    missing = [m for m in ['base'] + params['modules'] if m not in installed]
    if after['exit_code'] != 0 or missing:
        raise _failed('EXEC_ERROR', {'missing_modules': missing})
    from .canonical import sha256_hex
    return {'modules_installed': len(installed), 'module_list_sha256': sha256_hex(installed)}


def create_platform_defaults(agent, env):
    s, params = derive_sid(env['environment_id']), env['params']
    if agent.state.step_done(env['op_id'], env['step']):
        # A retry after success: the admin password file was removed on success,
        # so the script can't run again; the earlier evidence stands.
        return {'already_done': True}
    run = agent.exec.call('container.run_oneshot', sid=s, digest=_digest(env),
                          command={'name': 'platform_defaults', 'scope': 'create', 'lang': params['lang'],
                                   'country': params['country']})
    result = run['result'] or {}
    if run['exit_code'] != 0 or not result.get('ok'):
        raise _failed('EXEC_ERROR', {'platform_defaults': result, 'exit_code': run['exit_code']})
    # The tenant admin's password is in the database now; the file has no further use.
    agent.exec.call('file.remove_secret', sid=s, name='tenant_admin_password')
    return result


def create_container(agent, env):
    s, slot = derive_sid(env['environment_id']), _slot(env)
    x = agent.exec
    seen = x.call('container.inspect', sid=s)
    if not seen['exists']:
        x.call('container.create', sid=s, digest=_digest(env), uid=slot['container_uid'],
               limits={'mem_limit_bytes': slot['mem_limit_bytes'], 'cpu_millis': slot['cpu_millis'],
                       'pids': PIDS_LIMIT},
               ports={'http': slot['http_port'], 'gevent': slot['gevent_port']})
    if not x.call('container.inspect', sid=s)['running']:
        x.call('container.start', sid=s)
    seen = x.call('container.inspect', sid=s)
    image = x.call('image.inspect', digest=_digest(env))
    expected_ports = {'8069/tcp': ['127.0.0.1:%d' % slot['http_port']],
                      '8072/tcp': ['127.0.0.1:%d' % slot['gevent_port']]}
    ok = (seen['running'] and seen['image_id'] == image['image_id']
          and seen['user'] == '%d:%d' % (slot['container_uid'], slot['container_uid'])
          and seen['read_only'] and seen['cap_drop'] == ['ALL'] and not seen['privileged']
          and seen['memory'] == slot['mem_limit_bytes'] and seen['ports'] == expected_ports)
    if not ok:
        raise _failed('EXEC_ERROR', seen)
    return seen


def create_route(agent, env):
    s, slot = derive_sid(env['environment_id']), _slot(env)
    hostnames = [d['hostname'] for d in env['params']['domains']]
    seen = agent.exec.call('traefik.inspect', sid=s)
    if not (seen['present'] and seen['hostnames'] == hostnames):
        seen = agent.exec.call('traefik.write', sid=s, hostnames=hostnames, http_port=slot['http_port'],
                               gevent_port=slot['gevent_port'], generation=seen.get('generation', 0) + 1)
    ingress = _ingress(agent)
    if ingress is None:
        return dict(seen, certificate='not_checked')
    # DOC-04 §6.1 step 8: wait until Traefik serves a certificate that verifies for every hostname.
    deadline = time.time() + CERT_DEADLINE
    pending = list(hostnames)
    while pending and time.time() < deadline:
        pending = [h for h in pending if not _cert_ok(ingress, h)]
        if pending:
            time.sleep(2)
    if pending:
        raise _failed('HEALTH_FAILED', dict(seen, certificate='pending', hostnames_pending=pending))
    return dict(seen, certificate='issued')


def _ingress(agent):
    """(host, port, TLS context) of this host's Traefik websecure entrypoint, or None."""
    url = agent.config.ingress_url
    if not url:
        return None
    from urllib.parse import urlsplit
    u = urlsplit(url)
    ctx = ssl.create_default_context(cafile=str(agent.config.ingress_ca) if agent.config.ingress_ca else None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return u.hostname, u.port or 443, ctx


def _tls(ingress, hostname, timeout=5):
    host, port, ctx = ingress
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(raw, server_hostname=hostname)     # SNI and verification for the tenant's name
    except BaseException:
        raw.close()
        raise


def _cert_ok(ingress, hostname) -> bool:
    try:
        with _tls(ingress, hostname):
            return True
    except (OSError, ssl.SSLError):
        return False


def _public(ingress, hostname, path, websocket=False):
    """Status code of one request to the public hostname through this host's ingress."""
    lines = ['GET %s HTTP/1.1' % path, 'Host: %s' % hostname, 'Connection: close']
    if websocket:
        lines += ['Upgrade: websocket', 'Connection: Upgrade', 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
                  'Sec-WebSocket-Version: 13', 'Origin: https://%s' % hostname]
        lines.remove('Connection: close')
    try:
        with _tls(ingress, hostname) as sock:
            sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode())
            line = sock.recv(256).split(b'\r\n', 1)[0].decode(errors='replace')
        return int(line.split()[1]) if line.startswith('HTTP/') else None
    except (OSError, ssl.SSLError, ValueError, IndexError):
        return None


def _public_health(ingress, hostnames, deadline) -> dict:
    """DOC-04 §6.1 step 9 through the public hostnames: /web/login 200, /websocket 101,
    /web/database/manager 403 (refused at the edge). Waits for Traefik to load the route."""
    want = {'login': 200, 'websocket': 101, 'db_manager': 403}
    while True:
        seen = {h: {'login': _public(ingress, h, '/web/login'),
                    'websocket': _public(ingress, h, '/websocket', websocket=True),
                    'db_manager': _public(ingress, h, '/web/database/manager')} for h in hostnames}
        if all(s == want for s in seen.values()) or time.time() > deadline:
            return seen
        time.sleep(2)


def _worst(public, key, want):
    """`want` if every hostname gave it, else the first that didn't."""
    return next((s[key] for s in public.values() if s[key] != want), want)


def _http(url, timeout=5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return None


def _websocket(host, port, timeout=5):
    request = ('GET /websocket HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
               'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n'
               'Origin: http://%s:%d\r\n\r\n') % (host, port, host, port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(request.encode())
            line = sock.recv(256).split(b'\r\n', 1)[0].decode(errors='replace')
        return int(line.split()[1]) if line.startswith('HTTP/') else None
    except (OSError, ValueError, IndexError):
        return None


def create_health(agent, env):
    slot, host = _slot(env), agent.config.health_host
    base = 'http://%s:%d' % (host, slot['http_port'])
    deadline = agent.clock() + HEALTH_DEADLINE
    # The gevent (websocket) process starts a few seconds after the HTTP workers.
    while True:
        login, websocket = _http(base + '/web/login'), _websocket(host, slot['gevent_port'])
        if (login == 200 and websocket == 101) or time.time() > deadline:
            break
        time.sleep(2)
    # Odoo 19 renders /web/database/manager whatever list_db says; what list_db
    # blocks is every database-service call. The 403 on the page is Traefik's job.
    seen = {'login': login, 'websocket': websocket, 'db_service_refused': _db_service_refused(base)}
    ingress = _ingress(agent)
    if ingress is not None:
        public = _public_health(ingress, [d['hostname'] for d in env['params']['domains']], deadline)
        seen.update(public=public, https_login=_worst(public, 'login', 200),
                    https_websocket=_worst(public, 'websocket', 101),
                    public_db_manager=_worst(public, 'db_manager', 403))
    if seen['login'] != 200 or seen['websocket'] != 101 or not seen['db_service_refused'] or (
            ingress is not None and (seen['https_login'], seen['https_websocket'], seen['public_db_manager'])
            != (200, 101, 403)):
        raise _failed('HEALTH_FAILED', seen)
    return seen


def _db_service_refused(base) -> bool:
    body = json.dumps({'jsonrpc': '2.0', 'method': 'call', 'id': 1,
                       'params': {'service': 'db', 'method': 'list', 'args': []}}).encode()
    req = urllib.request.Request(base + '/jsonrpc', body, {'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            reply = json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError):
        return False
    return 'error' in reply and 'result' not in reply


# -- Tenant.Backup (DOC-04 §6.8) -------------------------------------------------

def _s3(agent, secrets):
    from . import s3
    return s3.client(agent.config.s3_endpoint, agent.config.s3_region, secrets['s3_key_id'], secrets['s3_secret'])


def backup(agent, env):
    from datetime import datetime, timedelta, timezone

    from . import s3
    from .canonical import b64_public, sign
    s, p = derive_sid(env['environment_id']), env['params']
    secrets = open_secrets(env, agent.config.age_identity)
    client, bucket = _s3(agent, secrets), agent.config.s3_bucket
    key = s3.object_key(env['tenant_id'], env['environment_id'], p['backup_id'])
    x = agent.exec
    existing = s3.head(client, bucket, key)
    if existing:
        # Re-run after a successful upload: verify what is stored, change nothing.
        if existing['lock_mode'] != 'COMPLIANCE':
            raise _failed('EXEC_ERROR', {'stored': existing})
        x.call('backup.clean', sid=s, backup_id=p['backup_id'])
        return {'already_stored': True, 'object_version_id': existing['version_id'],
                'lock_until': existing['lock_until'], 'sha256_b64': existing['sha256_b64']}

    image_id = x.call('container.inspect', sid=s)['image_id']
    modules = x.call('container.run_oneshot', sid=s, digest=image_id, command={'name': 'module_versions'})
    dump = x.call('backup.dump', sid=s, backup_id=p['backup_id'])
    d = dump['result'] or {}
    if dump['exit_code'] != 0 or not d.get('gc_guard_held'):
        x.call('backup.clean', sid=s, backup_id=p['backup_id'])
        raise _failed('EXEC_ERROR', {'backup_dump_exit': dump['exit_code']})
    if d['missing_files'] or d['checksum_mismatches']:
        x.call('backup.clean', sid=s, backup_id=p['backup_id'])
        raise _failed('EXEC_ERROR', {k: d[k] for k in ('referenced_files', 'missing_files', 'checksum_mismatches',
                                                       'missing_sample')})
    manifest = {'v': 1, 'tenant_id': env['tenant_id'], 'environment_id': env['environment_id'],
                'backup_id': p['backup_id'], 'retention_tier': p['retention_tier'], 'db_name': 't_' + s,
                'snapshot_time': d['snapshot_time'], 'image_id': image_id,
                'module_versions': modules['result'] or {}, 'dump_sha256': d['dump_sha256'],
                'files_sha256': d['files_sha256'], 'referenced_files': d['referenced_files'],
                'row_counts': d.get('row_counts'),
                'host_id': agent.config.host_id, 'created_at': datetime.now(timezone.utc).isoformat()}
    signed = {'manifest': manifest, 'signature': sign(manifest, agent.key), 'signer': b64_public(agent.key)}
    pkg = x.call('backup.package', sid=s, backup_id=p['backup_id'],
                 manifest_b64=base64.b64encode(json.dumps(signed).encode()).decode(),
                 recipient=secrets['region_recipient'])
    archive = agent.config.backup_tmp / s / ('%s.tar.age' % p['backup_id'])
    until = s3.upload_locked(client, bucket, key, archive, pkg['archive_sha256'], p['lock_days'])
    stored = s3.head(client, bucket, key)
    if not s3.verify(stored, pkg['archive_sha256'], until):
        raise _failed('EXEC_ERROR', {'stored': stored})
    x.call('backup.clean', sid=s, backup_id=p['backup_id'])
    return {'snapshot_time': d['snapshot_time'], 'gc_guard_held': True, 'referenced_files': d['referenced_files'],
            'missing_files': 0, 'dump_sha256': d['dump_sha256'], 'archive_sha256': pkg['archive_sha256'],
            'size': pkg['size'], 'object_version_id': stored['version_id'], 'lock_mode': stored['lock_mode'],
            'lock_until': stored['lock_until'], 'image_id': image_id}


# -- Tenant.RestoreToIsolated (DOC-04 §6.9) -------------------------------------

def restore_db(agent, env):
    p = env['params']
    t = derive_sid(p['target_environment_id'])
    secrets = open_secrets(env, agent.config.age_identity)
    agent.state.register(environment_id=p['target_environment_id'], tenant_id=env['tenant_id'], sid=t,
                         container_uid=None, http_port=None, gevent_port=None, kind='restore_copy',
                         egress_profile='deny_all', now=agent.clock())
    x = agent.exec
    x.call('pg.create_role', sid=t, password_hash=secrets['db_password_scram'])
    x.call('pg.create_db', sid=t)
    x.call('pg.harden_db', sid=t)
    x.call('pg.hba_add', sid=t, app_host_ip=p['app_host_ip'])
    x.call('pg.reload')
    seen = x.call('pg.inspect', sid=t)
    if not (seen['db'] and seen['public_connect'] is False and seen['hba_rules'] == 1
            and not (seen['role'] or {}).get('super')):
        raise _failed('EXEC_ERROR', seen)
    return seen


def _verify_manifest(agent, signed, env):
    from .canonical import load_verify_key, verify
    m = signed.get('manifest') or {}
    keys = [agent.key.verify_key, *agent.config.trust.agents]
    signer_trusted = any(bytes(k) == bytes(load_verify_key(signed.get('signer', ''))) for k in keys) \
        if signed.get('signer') else False
    checks = {
        'signature': bool(signer_trusted and verify(m, signed.get('signature', ''), keys)),
        'tenant': m.get('tenant_id') == env['tenant_id'],
        'environment': m.get('environment_id') == env['environment_id'],
        'backup_id': m.get('backup_id') == env['params']['backup_id'],
    }
    return m, checks


def restore_copy(agent, env):
    import hashlib

    from . import s3
    from .canonical import sha256_hex
    t0 = time.time()
    p, slot = env['params'], env['params']['runtime_slot']
    t = derive_sid(p['target_environment_id'])
    secrets = open_secrets(env, agent.config.age_identity)
    x = agent.exec
    agent.state.register(environment_id=p['target_environment_id'], tenant_id=env['tenant_id'], sid=t,
                         container_uid=slot['container_uid'], http_port=slot['http_port'],
                         gevent_port=slot['gevent_port'], kind='restore_copy', egress_profile='deny_all',
                         now=agent.clock())
    # 1-2. Runtime pieces; the deny-all firewall goes on before any data arrives.
    host_uid = agent.config.subuid_base + slot['container_uid']
    if not x.call('volume.inspect', sid=t)['exists']:
        x.call('volume.create', sid=t, host_uid=host_uid)
    if not x.call('net.inspect', sid=t)['exists']:
        x.call('net.create', sid=t)
    nft = x.call('nft.apply_tenant', sid=t, profile='deny_all')
    if nft.get('profile') != 'deny_all':
        raise _failed('EXEC_ERROR', {'nft': nft})
    # 3. Download, check the stored checksum, decrypt, check the manifest.
    client = _s3(agent, secrets)
    key = s3.object_key(env['tenant_id'], env['environment_id'], p['backup_id'])
    stored = s3.head(client, agent.config.s3_bucket, key)
    if stored is None:
        raise _failed('EXEC_ERROR', {'backup': 'not found'})
    x.call('restore.prepare', sid=t, backup_id=p['backup_id'])
    local = agent.config.backup_tmp / t / ('%s.in' % p['backup_id']) / 'archive.tar.age'
    got = s3.download(client, agent.config.s3_bucket, key, local)
    if base64.b64encode(bytes.fromhex(got)).decode() != stored['sha256_b64']:
        x.call('backup.clean', sid=t, backup_id=p['backup_id'])
        raise _failed('EXEC_ERROR', {'archive_sha256': got, 'stored_sha256_b64': stored['sha256_b64']})
    unpacked = x.call('restore.unpack', sid=t, backup_id=p['backup_id'], identity=secrets['region_identity'])
    manifest, checks = _verify_manifest(agent, json.loads(base64.b64decode(unpacked['manifest_b64'])), env)
    if not all(checks.values()):
        x.call('backup.clean', sid=t, backup_id=p['backup_id'])
        raise _failed('EXEC_ERROR', {'manifest_checks': checks})
    # 4-5 need the copy's credentials; 7. config: SMTP to the sink, no cron.
    x.call('file.write_secret', sid=t, name='db_password',
           data_b64=base64.b64encode(secrets['db_password'].encode()).decode())
    conf = {k: slot[k] for k in ('workers', 'max_cron_threads', 'db_maxconn', 'limit_memory_soft',
                                 'limit_memory_hard', 'limit_time_cpu', 'limit_time_real')}
    x.call('file.write_conf', sid=t, conf=dict(conf, admin_passwd_hash=secrets['admin_passwd_hash'], smtp='sink'))
    digest = env['release_manifest']['image_digest']
    load = x.call('restore.load', sid=t, backup_id=p['backup_id'], digest=digest)
    loaded = load['result'] or {}
    x.call('backup.clean', sid=t, backup_id=p['backup_id'])
    if load['exit_code'] != 0 or not loaded.get('ok'):
        raise _failed('EXEC_ERROR', {'restore_load': loaded, 'exit_code': load['exit_code']})
    # 6. Neutralize, then the platform's copy defaults.
    for command in ({'name': 'neutralize'}, {'name': 'platform_defaults', 'scope': 'copy'}):
        run = x.call('container.run_oneshot', sid=t, digest=digest, command=command)
        if run['exit_code'] != 0:
            raise _failed('EXEC_ERROR', {command['name']: run['exit_code']})
    # 8. Start.
    if not x.call('container.inspect', sid=t)['exists']:
        x.call('container.create', sid=t, digest=digest, uid=slot['container_uid'],
               limits={'mem_limit_bytes': slot['mem_limit_bytes'], 'cpu_millis': slot['cpu_millis'],
                       'pids': PIDS_LIMIT},
               ports={'http': slot['http_port'], 'gevent': slot['gevent_port']})
    if not x.call('container.inspect', sid=t)['running']:
        x.call('container.start', sid=t)
    # 9. Checks.
    base = 'http://%s:%d' % (agent.config.health_host, slot['http_port'])
    deadline = time.time() + HEALTH_DEADLINE
    login = None
    while time.time() < deadline:
        login = _http(base + '/web/login')
        if login == 200:
            break
        time.sleep(2)
    modules = x.call('container.run_oneshot', sid=t, digest=digest, command={'name': 'module_versions'})['result']
    checks.update({
        'login': login == 200,
        'modules_match': modules == manifest['module_versions'],
        'files_verified': loaded.get('files_verified') == manifest['referenced_files'],
        # Dry-run nftables (development) has no packet counters to read. On a real
        # host the counter read isn't built yet, so the check fails closed there.
        'zero_egress': 'not_measured' if x.call('nft.inspect', sid=t).get('mode') == 'dryrun' else False,
    })
    printed = None
    if p['deep']:
        # DOC-05 §5 deep drill: the key tables as loaded (before neutralize)
        # against the backup's own counts, and one PDF printed by the copy.
        printed = x.call('container.run_oneshot', sid=t, digest=digest, command={'name': 'print_report'})['result']
        checks.update({
            'row_counts_match': bool(manifest.get('row_counts')) and loaded.get('row_counts') == manifest['row_counts'],
            'pdf_printed': bool(printed and printed.get('ok')),
        })
    observed = {'checks': checks, 'files_verified': loaded.get('files_verified'),
                'row_counts': loaded.get('row_counts'), 'expected_row_counts': manifest.get('row_counts'),
                'pdf': printed,
                'manifest_sha256': sha256_hex(manifest), 'snapshot_time': manifest['snapshot_time'],
                'duration_s': round(time.time() - t0, 1)}
    if not all(v for v in checks.values() if v != 'not_measured'):
        raise _failed('EXEC_ERROR', observed)
    return observed


# -- Tenant.Delete (DOC-04 §6.13) -----------------------------------------------
# B2 objects aren't touched: they expire under Object Lock at lock_until.

def remove_app(agent, env, environment_id=None):
    environment_id = environment_id or env['environment_id']
    s = derive_sid(environment_id)
    x = agent.exec
    seen = x.call('container.inspect', sid=s)
    if seen['exists'] and seen['running']:
        x.call('container.stop', sid=s, timeout=STOP_TIMEOUT)
    # Container first, so the firewall goes only once nothing runs behind it.
    for verb in ('container.remove', 'traefik.remove', 'nft.remove_tenant', 'net.remove', 'volume.remove'):
        x.call(verb, sid=s)
    after = {'container': x.call('container.inspect', sid=s), 'route': x.call('traefik.inspect', sid=s),
             'nft': x.call('nft.inspect', sid=s), 'network': x.call('net.inspect', sid=s),
             'volume': x.call('volume.inspect', sid=s), 'secrets': sorted(x.call('file.inspect', sid=s))}
    if after['container']['exists'] or after['route']['present'] or after['nft']['applied'] \
            or after['network']['exists'] or after['volume']['exists'] or after['secrets']:
        raise _failed('EXEC_ERROR', after)
    agent.state.tombstone(environment_id, agent.clock())
    return dict(after, registry='tombstoned')


def drop_db(agent, env, environment_id=None):
    environment_id = environment_id or env['environment_id']
    s = derive_sid(environment_id)
    x = agent.exec
    # The hba line goes first, so nothing reconnects between terminate and drop.
    x.call('pg.hba_remove', sid=s)
    x.call('pg.reload')
    terminated = x.call('pg.terminate_sessions', sid=s)['terminated']
    x.call('pg.drop_db', sid=s)
    x.call('pg.drop_role', sid=s)
    seen = x.call('pg.inspect', sid=s)
    if seen['role'] is not None or seen['db'] is not None or seen['hba_rules']:
        raise _failed('EXEC_ERROR', seen)
    agent.state.tombstone(environment_id, agent.clock())
    return dict(seen, terminated=terminated, registry='tombstoned')


# -- RestoreCopy.Expire (DOC-04 §6.15): the same removal, for the copy ------------

def _expire(remove):
    def step(agent, env):
        copy = env['params']['environment_id']
        if agent.state.environment(copy) is None:
            return {'registry': 'absent'}
        return remove(agent, env, copy)
    return step


HANDLERS = {
    ('Tenant.Delete', 'app.remove'): remove_app,
    ('Tenant.Delete', 'db.drop'): drop_db,
    ('RestoreCopy.Expire', 'app.expire'): _expire(remove_app),
    ('RestoreCopy.Expire', 'db.expire'): _expire(drop_db),
    ('Tenant.Backup', 'app.backup'): backup,
    ('Tenant.RestoreToIsolated', 'db.provision_copy'): restore_db,
    ('Tenant.RestoreToIsolated', 'app.restore_copy'): restore_copy,
    ('Tenant.Create', 'db.provision'): create_db,
    ('Tenant.Create', 'app.network'): create_network,
    ('Tenant.Create', 'app.image'): create_image,
    ('Tenant.Create', 'app.config'): create_config,
    ('Tenant.Create', 'app.init_db'): create_init_db,
    ('Tenant.Create', 'app.platform_defaults'): create_platform_defaults,
    ('Tenant.Create', 'app.container'): create_container,
    ('Tenant.Create', 'app.route'): create_route,
    ('Tenant.Create', 'app.health'): create_health,
    ('Tenant.Start', 'app.start'): start,
    ('Tenant.Stop', 'app.stop'): stop,
    ('Host.Drain', 'any.drain'): drain,
    ('Host.RotateTrust', 'any.rotate_trust'): rotate_trust,
}
