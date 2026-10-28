"""Executor backends. Methods are named after verbs with '.' → '_', and receive
arguments already validated by verbs.py. Names and paths are derived here from
the sid and this host's own config; nothing else comes from the request.

`root` prefixes every host path, so a development host can keep /srv, /run and
/etc/traefik under one directory. Production uses root = '/'.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, ImageNotFound, NotFound
from docker.types import Mount
import pyrage

from . import naming

CONTAINER_DATA = '/var/lib/odoo'
CONTAINER_RUN = '/run/tenant'
CONF_IN_CONTAINER = CONTAINER_RUN + '/odoo.conf'
ONESHOT_TIMEOUT = {'init_db': 1200, 'update_modules': 3600, 'neutralize': 600, 'module_versions': 300,
                   'platform_defaults': 300, 'backup_dump': 7200, 'restore_load': 7200, 'print_report': 300}
ONESHOT_LABEL = 'platform.oneshot'
REAP_ATTEMPTS = 10
PRIVATE_NETS = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10')


@dataclass(frozen=True)
class AppHostConfig:
    root: Path = Path('/')
    subuid_base: int = 0                  # daemon userns-remap base; 0 without remap
    registry_host: str = ''
    image_source: str = 'registry'        # 'registry' (pull by digest) or 'local' (dev: image ID must exist)
    db_host: str = ''
    db_port: int = 5432
    db_sslmode: str = 'verify-full'
    # db-1's certificate (self-signed, db_host role): copied into each tenant's run dir as the
    # libpq root certificate (PGSSLROOTCERT), which verify-full needs. '' = libpq's default.
    db_ca: str = ''
    mail_host: str = ''
    mail_port: int = 587
    sink_host: str = '127.0.0.1'          # restore copies: SMTP goes nowhere
    resolver: str = ''                    # DNS server tenants may query
    nft_mode: str = 'nft'                 # 'nft' or 'dryrun' (write the ruleset file only)
    tmp_size: str = '512m'
    # Dev only (Docker Desktop): `root` is where this named volume is mounted in the
    # executor, and tenants mount subpaths of it, because host folders shared into
    # the Docker VM ignore chown. Production uses host bind mounts (empty).
    root_volume: str = ''
    agentd_uid: int = 0                   # owner of archives agentd uploads / downloads
    # Traefik's ACME resolver for tenant routers; '' serves the default certificate (dev).
    cert_resolver: str = 'le'
    extra: dict = field(default_factory=dict)


class DockerApp:
    def __init__(self, config: AppHostConfig, client=None):
        self.c = config
        self.docker = client or docker.from_env()

    # -- paths --------------------------------------------------------------
    def _host(self, path: str) -> Path:
        return self.c.root / path.lstrip('/')

    def _tenant_dir(self, sid):
        return self._host('/srv/tenants/%s' % sid)

    def _data(self, sid):
        return self._host(naming.filestore_dir(sid))

    def _run(self, sid):
        return self._host(naming.run_dir(sid))

    def _owner(self, sid) -> int:
        return self._data(sid).stat().st_uid

    def _tenant_uid(self, sid) -> int:
        uid = self._owner(sid) - self.c.subuid_base
        if not 10001 <= uid <= 59999:
            # The filestore owner is how the executor knows the tenant's uid; anything
            # outside the tenant range (root, say) means the directory was tampered with.
            raise PermissionError('filestore owner outside the tenant uid range')
        return uid

    # -- volume -------------------------------------------------------------
    def volume_create(self, sid, host_uid):
        data = self._data(sid)
        data.mkdir(parents=True, exist_ok=True)
        os.chown(data, host_uid, host_uid)
        os.chmod(data, 0o700)
        run = self._run(sid)
        run.mkdir(parents=True, exist_ok=True)
        os.chmod(run, 0o755)
        return self.volume_inspect(sid)

    def volume_inspect(self, sid):
        data = self._data(sid)
        if not data.exists():
            return {'exists': False}
        st = data.stat()
        return {'exists': True, 'owner_uid': st.st_uid, 'mode': oct(st.st_mode & 0o777)}

    def volume_remove(self, sid):
        shutil.rmtree(self._tenant_dir(sid), ignore_errors=True)
        shutil.rmtree(self._run(sid), ignore_errors=True)
        shutil.rmtree(self._host('/srv/backup-tmp/%s' % sid), ignore_errors=True)
        return {}

    # -- network ------------------------------------------------------------
    def _net(self, sid):
        try:
            return self.docker.networks.get(naming.network(sid))
        except NotFound:
            return None

    def net_create(self, sid):
        net = self._net(sid) or self.docker.networks.create(
            naming.network(sid), driver='bridge',
            options={'com.docker.network.bridge.enable_icc': 'false',
                     'com.docker.network.bridge.name': 'br-%s' % sid},
            labels={'platform.sid': sid})
        return self.net_inspect(sid)

    def net_inspect(self, sid):
        net = self._net(sid)
        if net is None:
            return {'exists': False}
        net.reload()
        opts = net.attrs.get('Options') or {}
        subnets = [c['Subnet'] for c in (net.attrs.get('IPAM') or {}).get('Config') or []]
        return {'exists': True, 'icc': opts.get('com.docker.network.bridge.enable_icc'),
                'bridge': opts.get('com.docker.network.bridge.name'), 'subnets': subnets}

    def net_remove(self, sid):
        net = self._net(sid)
        if net is not None:
            net.reload()
            for c in net.containers:
                net.disconnect(c, force=True)
            net.remove()
        return {}

    # -- firewall (ADR-011 egress rules, DOC-12 profiles) ---------------------
    def _nft_file(self, sid):
        return self._host('/etc/nftables.d/tenant-%s.nft' % sid)

    def ruleset(self, sid, profile):
        bridge = 'br-%s' % sid
        table = 'tenant_%s' % sid
        allow = ['ct state established,related accept']
        if self.c.db_host:
            allow.append('ip daddr %s tcp dport %d accept' % (self.c.db_host, self.c.db_port))
        if profile == 'production':
            if self.c.mail_host:
                allow.append('ip daddr %s tcp dport %d accept' % (self.c.mail_host, self.c.mail_port))
            if self.c.resolver:
                allow.append('ip daddr %s meta l4proto { tcp, udp } th dport 53 accept' % self.c.resolver)
            allow.append('ip daddr { %s } log prefix "tenant-%s-deny " drop' % (', '.join(PRIVATE_NETS), sid))
            allow.append('tcp dport { 80, 443 } accept')
        # deny_all / isolated: database only (DOC-04 §6.9 step 2; DOC-12 §3)
        body = '\n'.join('        iifname "%s" %s' % (bridge, rule) for rule in allow)
        # Declare, delete, define: one transaction replaces the table (never a moment without
        # it), and the file loads again at boot from the base firewall's include.
        return ('# tenant %s profile %s (generated by agent-exec)\n'
                'table inet %s\n'
                'delete table inet %s\n'
                'table inet %s {\n'
                '    chain forward {\n'
                '        type filter hook forward priority filter - 1; policy accept;\n'
                '%s\n'
                '        iifname "%s" counter log prefix "tenant-%s-deny " drop\n'
                '    }\n'
                '}\n') % (sid, profile, table, table, table, body, bridge, sid)

    def nft_apply_tenant(self, sid, profile):
        text = self.ruleset(sid, profile)
        path = self._nft_file(sid)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix('.tmp')
        tmp.write_text(text)
        if self.c.nft_mode == 'nft':
            subprocess.run(['nft', '-c', '-f', str(tmp)], check=True, capture_output=True)
            subprocess.run(['nft', '-f', str(tmp)], check=True, capture_output=True)
        tmp.replace(path)
        return self.nft_inspect(sid)

    def _nft_loaded(self, sid):
        """What the kernel has: the table's text as `nft list` prints it, or None."""
        run = subprocess.run(['nft', 'list', 'table', 'inet', 'tenant_%s' % sid], capture_output=True, text=True)
        return run.stdout if run.returncode == 0 else None

    def nft_inspect(self, sid):
        path = self._nft_file(sid)
        if not path.exists():
            return {'applied': False}
        text = path.read_text()
        profile = text.split('profile ', 1)[1].split(' ', 1)[0]
        if self.c.nft_mode == 'nft':
            # The file alone says nothing about the kernel (a reboot without the include, a flush).
            loaded = self._nft_loaded(sid)
            if loaded is None or ('iifname "br-%s"' % sid) not in loaded:
                return {'applied': False, 'file': True, 'loaded': False}
        return {'applied': True, 'mode': self.c.nft_mode, 'profile': profile,
                'ruleset_sha256': hashlib.sha256(text.encode()).hexdigest()}

    def nft_remove_tenant(self, sid):
        if self.c.nft_mode == 'nft':
            subprocess.run(['nft', 'delete', 'table', 'inet', 'tenant_%s' % sid], capture_output=True)
        self._nft_file(sid).unlink(missing_ok=True)
        return {}

    # -- image --------------------------------------------------------------
    def image_pull(self, digest):
        if self.c.image_source == 'registry':
            self.docker.images.pull('%s/%s@%s' % (self.c.registry_host, self.c.extra['repository'], digest))
        return self.image_inspect(digest)

    def _image(self, digest):
        if self.c.image_source == 'local':
            return self.docker.images.get(digest)
        return self.docker.images.get('%s/%s@%s' % (self.c.registry_host, self.c.extra['repository'], digest))

    def image_inspect(self, digest):
        try:
            img = self._image(digest)
        except ImageNotFound:
            return {'present': False}
        return {'present': True, 'image_id': img.id, 'repo_digests': img.attrs.get('RepoDigests') or []}

    # -- secrets and config ---------------------------------------------------
    def _write_private(self, sid, name, data: bytes):
        uid = self._tenant_uid(sid) + self.c.subuid_base
        path = self._run(sid) / name
        tmp = path.with_name('.' + name + '.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chown(tmp, uid, uid)
        tmp.replace(path)

    def file_write_secret(self, sid, name, data_b64):
        data = base64.b64decode(data_b64)
        if name == 'db_password':
            # libpq password file (DOC-04 §5.2): odoo.conf never holds db_password.
            # Database `*`: Odoo also connects to `postgres` at start (see pg_backend.pg_hba_add).
            line = '%s:%d:*:%s:%s\n' % (self.c.db_host, self.c.db_port, naming.db_role(sid),
                                        data.decode().replace('\\', '\\\\').replace(':', '\\:'))
            self._write_private(sid, 'pgpass', line.encode())
        else:
            self._write_private(sid, name, data)
        return {}

    def file_remove_secret(self, sid, name):
        (self._run(sid) / ('pgpass' if name == 'db_password' else name)).unlink(missing_ok=True)
        return {}

    def render_conf(self, sid, conf, smtp_password='') -> str:
        smtp = conf['smtp'] == 'relay'
        lines = [
            '[options]',
            'db_host = %s' % self.c.db_host, 'db_port = %d' % self.c.db_port,
            'db_user = %s' % naming.db_role(sid), 'db_name = %s' % naming.db_name(sid),
            # db_name without dbfilter: Odoo serves only this database and never lists
            # databases (odoo/service/db.py list_dbs); DOC-04 §5.2 had both.
            'db_sslmode = %s' % self.c.db_sslmode,
            'db_maxconn = %d' % conf['db_maxconn'],
            'list_db = False', 'admin_passwd = %s' % conf['admin_passwd_hash'], 'proxy_mode = True',
            'data_dir = %s' % CONTAINER_DATA, 'http_interface = 0.0.0.0', 'http_port = 8069', 'gevent_port = 8072',
            'workers = %d' % conf['workers'],
            'max_cron_threads = %d' % (conf['max_cron_threads'] if smtp else 0),
            'limit_memory_soft = %d' % conf['limit_memory_soft'],
            'limit_memory_hard = %d' % conf['limit_memory_hard'],
            'limit_time_cpu = %d' % conf['limit_time_cpu'], 'limit_time_real = %d' % conf['limit_time_real'],
            'with_demo = False', 'server_wide_modules = base,web',
            'smtp_server = %s' % (self.c.mail_host if smtp else self.c.sink_host),
            'smtp_port = %d' % (self.c.mail_port if smtp else 25),
            'smtp_ssl = %s' % smtp,
            'smtp_user = %s' % ('tenant_%s' % sid if smtp else ''),
            'smtp_password = %s' % (smtp_password if smtp else ''),
        ]
        return '\n'.join(lines) + '\n'

    def file_write_conf(self, sid, conf):
        secret = self._run(sid) / 'smtp_password'
        smtp_password = secret.read_text().strip() if secret.exists() else ''
        if self.c.db_ca:
            self._write_private(sid, 'db-ca.pem', Path(self.c.db_ca).read_bytes())
        self._write_private(sid, 'odoo.conf', self.render_conf(sid, conf, smtp_password).encode())
        return self.file_inspect(sid)

    def file_inspect(self, sid):
        run = self._run(sid)
        out = {}
        for name in ('odoo.conf', 'pgpass', 'smtp_password', 'tenant_salt', 'tenant_admin_password'):
            path = run / name
            if path.exists():
                st = path.stat()
                out[name] = {'mode': oct(st.st_mode & 0o777), 'owner_uid': st.st_uid}
        conf = run / 'odoo.conf'
        if conf.exists():
            redacted = '\n'.join(l for l in conf.read_text().splitlines()
                                 if not l.startswith(('admin_passwd', 'smtp_password')))
            out['conf_sha256_redacted'] = hashlib.sha256(redacted.encode()).hexdigest()
        return out

    # -- containers ---------------------------------------------------------
    def _container(self, sid):
        try:
            return self.docker.containers.get(naming.container(sid))
        except NotFound:
            return None

    def _mount(self, target, host_path: Path, read_only=False):
        if self.c.root_volume:
            # no_copy: otherwise Docker copies the image's /var/lib/odoo (root, 1777)
            # over the tenant's directory on first mount.
            return Mount(target, self.c.root_volume, type='volume', read_only=read_only, no_copy=True,
                         subpath=str(host_path.relative_to(self.c.root)))
        return Mount(target, str(host_path), type='bind', read_only=read_only)

    def _mounts(self, sid):
        return [self._mount(CONTAINER_DATA, self._data(sid)),
                self._mount(CONTAINER_RUN, self._run(sid), read_only=True)]

    def _hardening(self, sid, uid, limits):
        return dict(
            user='%d:%d' % (uid, uid), network=naming.network(sid), mounts=self._mounts(sid),
            environment={'PGPASSFILE': CONTAINER_RUN + '/pgpass', 'HOME': '/tmp', 'PYTHONDONTWRITEBYTECODE': '1',
                         **({'PGSSLROOTCERT': CONTAINER_RUN + '/db-ca.pem'} if self.c.db_ca else {})},
            read_only=True, tmpfs={'/tmp': 'rw,nosuid,nodev,size=%s' % self.c.tmp_size},
            cap_drop=['ALL'], security_opt=['no-new-privileges'],
            mem_limit=limits['mem_limit_bytes'], nano_cpus=limits['cpu_millis'] * 1_000_000,
            pids_limit=limits['pids'], labels={'platform.sid': sid})

    def container_create(self, sid, digest, uid, limits, ports):
        existing = self._container(sid)
        if existing is None:
            self.docker.containers.create(
                self._image(digest).id, name=naming.container(sid), command=['-c', CONF_IN_CONTAINER],
                ports={'8069/tcp': ('127.0.0.1', ports['http']), '8072/tcp': ('127.0.0.1', ports['gevent'])},
                # Never by Docker: after a reboot /run/tenants is empty until Tenant.Start renders it.
                restart_policy={'Name': 'no'}, **self._hardening(sid, uid, limits))
        return self.container_inspect(sid)

    def container_inspect(self, sid):
        c = self._container(sid)
        if c is None:
            return {'exists': False, 'running': False}
        c.reload()
        hc = c.attrs['HostConfig']
        ports = {k: [b['HostIp'] + ':' + b['HostPort'] for b in (v or [])]
                 for k, v in (hc.get('PortBindings') or {}).items()}
        return {'exists': True, 'running': c.status == 'running', 'status': c.status, 'image_id': c.attrs['Image'],
                'user': c.attrs['Config'].get('User') or None, 'read_only': hc.get('ReadonlyRootfs'),
                'cap_drop': hc.get('CapDrop'), 'security_opt': hc.get('SecurityOpt'),
                'memory': hc.get('Memory'), 'nano_cpus': hc.get('NanoCpus'), 'pids_limit': hc.get('PidsLimit'),
                'ports': ports, 'privileged': hc.get('Privileged'), 'network_mode': hc.get('NetworkMode')}

    def container_start(self, sid):
        self._container(sid).start()
        return {}

    def container_stop(self, sid, timeout):
        self._container(sid).stop(timeout=timeout)
        return {}

    def container_remove(self, sid):
        c = self._container(sid)
        if c is not None:
            c.remove(force=True)
        return {}

    def container_run_oneshot(self, sid, digest, command):
        """Run one fixed command template to completion. Returns the exit code and,
        for scripts that print one, their JSON result line; never raw logs."""
        name = command['name']
        conf = ['-c', CONF_IN_CONTAINER]
        if name == 'init_db':
            entry, args = ['odoo'], conf + ['-i', ','.join(['base'] + command['modules']), '--stop-after-init',
                                            '--no-http', '--load-language', command['lang']]
        elif name == 'update_modules':
            entry, args = ['odoo'], conf + ['-u', ','.join(command['modules']), '--stop-after-init', '--no-http']
        elif name == 'neutralize':
            entry, args = ['odoo'], ['neutralize'] + conf
        elif name == 'module_versions':
            entry, args = ['/opt/platform/module-versions'], conf
        elif name == 'print_report':
            # In the running container's network namespace: wkhtmltopdf fetches
            # the report's assets from it at report.url (127.0.0.1).
            c = self._container(sid)
            if c is None or c.status != 'running':
                return {'exit_code': -1, 'result': None, 'user': None}
            return self._oneshot(sid, self._image(digest).id, name, ['/opt/platform/print-report'], conf,
                                 network_mode='container:' + c.id)
        else:
            extra = [command['lang'], command['country']] if command['scope'] == 'create' else []
            entry, args = ['/opt/platform/platform-defaults'], [command['scope']] + extra + conf
        return self._oneshot(sid, self._image(digest).id, name, entry, args)

    def _oneshot(self, sid, image_id, name, entry, args, extra_mounts=(), network_mode=None):
        oneshot_name = '%s-%s' % (naming.container(sid), name.replace('_', '-'))
        try:
            self.docker.containers.get(oneshot_name).remove(force=True)  # left over from a crash
        except NotFound:
            pass
        hardening = self._hardening(sid, self._tenant_uid(sid), {'mem_limit_bytes': 2 << 30, 'cpu_millis': 2000,
                                                                 'pids': 512})
        hardening['mounts'] = hardening['mounts'] + list(extra_mounts)
        hardening['labels'] = dict(hardening['labels'], **{ONESHOT_LABEL: name})
        if network_mode:
            del hardening['network']
            hardening['network_mode'] = network_mode
        c = self.docker.containers.create(image_id, name=oneshot_name, entrypoint=entry, command=args, **hardening)
        user = c.attrs['Config'].get('User')
        try:
            c.start()
            code = c.wait(timeout=ONESHOT_TIMEOUT[name])['StatusCode']
            logs = c.logs(stdout=True, stderr=True).decode(errors='replace')
        finally:
            c.remove(force=True)
        self._keep_log(sid, name, logs)
        result = None
        for marker in ('PLATFORM_DEFAULTS ', 'MODULE_VERSIONS ', 'BACKUP_DUMP ', 'RESTORE_LOAD ', 'PRINT_REPORT '):
            for line in logs.splitlines():
                if line.startswith(marker):
                    result = json.loads(line[len(marker):])
        return {'exit_code': code, 'result': result, 'user': user}

    def exec_cancel(self, sid):
        """Kill the sid's running one-shot: its wait() returns, it is removed, and
        the verb that started it ends."""
        killed = []
        for c in self.docker.containers.list(filters={'label': [ONESHOT_LABEL, 'platform.sid=' + sid]}):
            try:
                c.kill()
                killed.append(c.name)
            except (NotFound, APIError):    # already exited
                pass
        return {'killed': sorted(killed)}

    def reap_orphans(self):
        """At agent-exec start, before serving: nothing can legitimately be running
        yet, so every one-shot container is an orphan of the previous process,
        and every plaintext backup or restore leftover is transient work that
        died with it. Encrypted archives stay: agentd uploads and downloads
        those on its own, and may be doing so now."""
        removed = set()
        for attempt in range(REAP_ATTEMPTS):
            left = self.docker.containers.list(all=True, filters={'label': ONESHOT_LABEL})
            if not left:
                break
            if attempt == REAP_ATTEMPTS - 1:
                # Serving now could overlap a verb still running in one: fail, and
                # let systemd restart us.
                raise RuntimeError('one-shot containers could not be removed')
            for c in left:
                removed.add(c.name)
                try:
                    c.remove(force=True)
                except (NotFound, APIError):   # gone already, or a removal already in progress
                    pass
            time.sleep(1)
        scrubbed = 0
        base = self._host('/srv/backup-tmp')
        for tenant in (base.iterdir() if base.is_dir() else ()):
            if not tenant.is_dir() or tenant.is_symlink():
                continue
            for entry in tenant.iterdir():
                if entry.is_symlink():
                    entry.unlink()
                elif entry.is_dir() and entry.name.endswith('.in'):
                    for plain in ('archive.tar', 'x'):
                        p = entry / plain
                        if p.is_dir() and not p.is_symlink():
                            shutil.rmtree(p)
                            scrubbed += 1
                        elif p.exists() or p.is_symlink():
                            p.unlink()
                            scrubbed += 1
                elif entry.is_dir():                      # <backup_id>/: dump work dir
                    shutil.rmtree(entry)
                    scrubbed += 1
                elif entry.name.endswith('.tar'):         # unencrypted tar before age
                    entry.unlink()
                    scrubbed += 1
        return {'oneshots_removed': sorted(removed), 'plaintext_removed': scrubbed}

    def _keep_log(self, sid, name, logs):
        # Kept on the host for the operator, root-only; never sent to the control plane.
        path = self._host('/var/log/agent-exec/%s-%s.log' % (sid, name))
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(logs)

    # -- backup and restore (DOC-04 §6.8, §6.9) ------------------------------
    # /srv/backup-tmp/<sid>/            root 0711
    #   <backup_id>/                    tenant 0700: dump.pgc, filestore/, files.json (plaintext, transient)
    #   <backup_id>.tar.age             agentd 0400: the encrypted archive agentd uploads
    #   <backup_id>.in/archive.tar.age  agentd-owned drop for a download; x/ = extracted, tenant-owned
    def _tmp(self, sid, *parts):
        base = self._host('/srv/backup-tmp/%s' % sid)
        base.mkdir(parents=True, exist_ok=True)
        os.chmod(base, 0o711)
        return base.joinpath(*parts)

    def _chown_tree(self, path, uid):
        for root, dirs, files in os.walk(path):
            for n in dirs + files:
                os.chown(os.path.join(root, n), uid, uid)
        os.chown(path, uid, uid)

    def _current_image(self, sid):
        c = self._container(sid)
        if c is None:
            raise FileNotFoundError('tenant container')
        return c.attrs['Image']

    def backup_dump(self, sid, backup_id):
        work = self._tmp(sid, backup_id)
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(mode=0o700)
        uid = self._tenant_uid(sid) + self.c.subuid_base
        os.chown(work, uid, uid)
        run = self._oneshot(sid, self._current_image(sid), 'backup_dump', ['/opt/platform/backup-dump'], [],
                            [self._mount('/backup', work)])
        return run

    def backup_package(self, sid, backup_id, manifest_b64, recipient):
        work = self._tmp(sid, backup_id)
        # The dump must be there: a work dir reaped after an agent-exec restart
        # would otherwise package a manifest-only archive.
        for name in ('dump.pgc', 'files.json'):
            if not (work / name).is_file():
                raise FileNotFoundError(name)
        (work / 'manifest.json').write_bytes(base64.b64decode(manifest_b64))
        plain = self._tmp(sid, '%s.tar' % backup_id)
        with tarfile.open(plain, 'w') as tar:
            for name in ('manifest.json', 'files.json', 'dump.pgc', 'filestore'):
                if (work / name).exists():
                    tar.add(work / name, arcname=name)
        archive = self._tmp(sid, '%s.tar.age' % backup_id)
        pyrage.encrypt_file(str(plain), str(archive), [pyrage.x25519.Recipient.from_str(recipient)])
        plain.unlink()
        shutil.rmtree(work)
        os.chown(archive, self.c.agentd_uid, self.c.agentd_uid)
        os.chmod(archive, 0o400)
        h = hashlib.sha256()
        with open(archive, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return {'archive_sha256': h.hexdigest(), 'size': archive.stat().st_size}

    def backup_clean(self, sid, backup_id):
        for name in (backup_id, backup_id + '.in'):
            shutil.rmtree(self._tmp(sid, name), ignore_errors=True)
        for name in (backup_id + '.tar', backup_id + '.tar.age'):
            self._tmp(sid, name).unlink(missing_ok=True)
        return {}

    def restore_prepare(self, sid, backup_id):
        drop = self._tmp(sid, backup_id + '.in')
        shutil.rmtree(drop, ignore_errors=True)
        drop.mkdir(mode=0o700)
        os.chown(drop, self.c.agentd_uid, self.c.agentd_uid)
        return {}

    def restore_unpack(self, sid, backup_id, identity):
        drop = self._tmp(sid, backup_id + '.in')
        archive = drop / 'archive.tar.age'
        if archive.is_symlink() or not archive.is_file():
            raise FileNotFoundError('archive')
        plain = drop / 'archive.tar'
        pyrage.decrypt_file(str(archive), str(plain), [pyrage.x25519.Identity.from_str(identity)])
        out = drop / 'x'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(mode=0o700)
        with tarfile.open(plain) as tar:
            tar.extractall(out, filter='data')   # no absolute paths, links out, devices
        plain.unlink()
        archive.unlink()
        uid = self._tenant_uid(sid) + self.c.subuid_base
        self._chown_tree(out, uid)
        os.chown(drop, uid, uid)
        manifest = (out / 'manifest.json').read_bytes()
        return {'manifest_b64': base64.b64encode(manifest).decode()}

    def restore_load(self, sid, backup_id, digest):
        x = self._tmp(sid, backup_id + '.in', 'x')
        return self._oneshot(sid, self._image(digest).id, 'restore_load', ['/opt/platform/restore-load'], [],
                             [self._mount('/backup', x, read_only=True)])

    # -- traefik ------------------------------------------------------------
    def _traefik_dir(self):
        return self._host('/etc/traefik/dynamic')

    def traefik_write(self, sid, hostnames, http_port, gevent_port, generation):
        d = self._traefik_dir()
        d.mkdir(parents=True, exist_ok=True)
        for other in d.glob('*.yaml'):
            if other.stem != sid and set(hostnames) & set(json.loads(other.read_text())['_hostnames']):
                raise ValueError('hostname already routed')
        hosts = ' || '.join('Host(`%s`)' % h for h in hostnames)
        name = 't-%s' % sid
        tls = {'certResolver': self.c.cert_resolver} if self.c.cert_resolver else {}
        config = {
            '_generation': generation, '_hostnames': hostnames,
            'http': {
                'routers': {
                    name: {'rule': hosts, 'service': name, 'entryPoints': ['websecure'], 'tls': tls,
                           'middlewares': ['%s-limit' % name]},
                    name + '-ws': {'rule': '(%s) && Path(`/websocket`)' % hosts, 'service': name + '-ws',
                                   'entryPoints': ['websecure'], 'tls': tls},
                    # ADR-007: database manager and db service calls are refused at the edge.
                    name + '-deny': {'rule': '(%s) && (PathPrefix(`/web/database`) || Path(`/xmlrpc/2/db`))' % hosts,
                                     'service': name, 'entryPoints': ['websecure'], 'tls': tls, 'priority': 1000,
                                     'middlewares': ['%s-deny' % name]},
                },
                'middlewares': {
                    name + '-limit': {'rateLimit': {'average': 50, 'burst': 100}},
                    # Nobody: a 403 for every client, this host included (the agent probes
                    # it; allowing loopback, as before, let the probe through to Odoo).
                    name + '-deny': {'ipAllowList': {'sourceRange': ['255.255.255.255/32']}},
                },
                'services': {
                    name: {'loadBalancer': {'servers': [{'url': 'http://127.0.0.1:%d' % http_port}]}},
                    name + '-ws': {'loadBalancer': {'servers': [{'url': 'http://127.0.0.1:%d' % gevent_port}]}},
                },
            },
        }
        text = json.dumps(config, indent=2, sort_keys=True)  # JSON is valid YAML for Traefik's file provider
        json.loads(text)
        path = d / ('%s.yaml' % sid)
        tmp = d / ('.%s.yaml.tmp' % sid)
        tmp.write_text(text)
        tmp.replace(path)
        return self.traefik_inspect(sid)

    def traefik_inspect(self, sid):
        path = self._traefik_dir() / ('%s.yaml' % sid)
        if not path.exists():
            return {'present': False}
        text = path.read_text()
        cfg = json.loads(text)
        return {'present': True, 'generation': cfg['_generation'], 'hostnames': cfg['_hostnames'],
                'sha256': hashlib.sha256(text.encode()).hexdigest()}

    def traefik_remove(self, sid):
        (self._traefik_dir() / ('%s.yaml' % sid)).unlink(missing_ok=True)
        return {}
