"""Internal verbs agentd may ask agent-exec for (DOC-04 §5.4).

Both sides validate with these same functions; agent-exec re-validates on
receipt, so a compromised agentd can't widen the arguments. No verb takes a
path, SQL text, shell string or container argument list. Two deviations from
the DOC-04 §5.4 signatures, both narrowing: `file.write_conf` and
`traefik.write` take structured fields that agent-exec renders itself, instead
of pre-rendered text.
"""
import base64
import json
import re

from .naming import check_sid

DIGEST_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
MODULE_RE = re.compile(r'^[a-z0-9_]{1,64}$')
HOST_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$')
SCRAM_RE = re.compile(r'^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]{16,64}\$[A-Za-z0-9+/=]{40,64}:[A-Za-z0-9+/=]{40,64}$')
IPV4_RE = re.compile(r'^(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

EGRESS_PROFILES = ('production', 'deny_all', 'isolated', 'eg_eta_preprod', 'sa_zatca_sandbox')
SECRET_NAMES = ('db_password', 'smtp_password', 'tenant_salt', 'tenant_admin_password')
ONESHOTS = ('init_db', 'update_modules', 'neutralize', 'module_versions', 'platform_defaults', 'print_report')
PORT_RANGE = (20000, 29999)
LANGS = ('en_US', 'ar_001')


class BadArgs(ValueError):
    pass


def _need(cond, what):
    if not cond:
        raise BadArgs(what)


def _keys(args, *names):
    _need(isinstance(args, dict) and set(args) == set(names), 'arguments')


def _int(value, low, high, what):
    _need(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high, what)
    return value


def _sid(args):
    try:
        return check_sid(args['sid'])
    except (ValueError, KeyError):
        raise BadArgs('sid')


def _digest(value):
    _need(isinstance(value, str) and DIGEST_RE.match(value), 'digest')
    return value


def _modules(value):
    _need(isinstance(value, list) and len(value) <= 200 and len(set(value)) == len(value)
          and all(isinstance(m, str) and MODULE_RE.match(m) for m in value), 'modules')
    return value


def _port(value):
    return _int(value, *PORT_RANGE, 'port')


def sid_only(args):
    _keys(args, 'sid')
    return {'sid': _sid(args)}


def volume_create(args):
    _keys(args, 'sid', 'host_uid')
    return {'sid': _sid(args), 'host_uid': _int(args['host_uid'], 10001, 4_294_967_294, 'host_uid')}


def nft_apply_tenant(args):
    _keys(args, 'sid', 'profile')
    _need(args['profile'] in EGRESS_PROFILES, 'profile')
    return {'sid': _sid(args), 'profile': args['profile']}


def image_pull(args):
    _keys(args, 'digest')
    return {'digest': _digest(args['digest'])}


def container_create(args):
    _keys(args, 'sid', 'digest', 'uid', 'limits', 'ports')
    limits = args['limits']
    _need(isinstance(limits, dict) and set(limits) == {'mem_limit_bytes', 'cpu_millis', 'pids'}, 'limits')
    ports = args['ports']
    _need(isinstance(ports, dict) and set(ports) == {'http', 'gevent'}, 'ports')
    _need(ports['http'] != ports['gevent'], 'ports')
    return {'sid': _sid(args), 'digest': _digest(args['digest']), 'uid': _int(args['uid'], 10001, 59999, 'uid'),
            'limits': {'mem_limit_bytes': _int(limits['mem_limit_bytes'], 512 << 20, 64 << 30, 'memory'),
                       'cpu_millis': _int(limits['cpu_millis'], 250, 16000, 'cpu'),
                       'pids': _int(limits['pids'], 64, 4096, 'pids')},
            'ports': {'http': _port(ports['http']), 'gevent': _port(ports['gevent'])}}


def container_stop(args):
    _keys(args, 'sid', 'timeout')
    return {'sid': _sid(args), 'timeout': _int(args['timeout'], 1, 300, 'timeout')}


def container_run_oneshot(args):
    _keys(args, 'sid', 'digest', 'command')
    cmd = args['command']
    _need(isinstance(cmd, dict) and cmd.get('name') in ONESHOTS, 'command')
    name = cmd['name']
    if name == 'init_db':
        _need(set(cmd) == {'name', 'modules', 'lang'} and cmd['lang'] in LANGS, 'command')
        cmd = {'name': name, 'modules': _modules(cmd['modules']), 'lang': cmd['lang']}
    elif name == 'update_modules':
        _need(set(cmd) == {'name', 'modules'}, 'command')
        cmd = {'name': name, 'modules': _modules(cmd['modules'])}
    elif name == 'platform_defaults' and cmd.get('scope') == 'create':
        _need(set(cmd) == {'name', 'scope', 'lang', 'country'} and cmd['lang'] in LANGS
              and isinstance(cmd['country'], str) and re.match(r'^[A-Z]{2}$', cmd['country']), 'command')
        cmd = {'name': name, 'scope': 'create', 'lang': cmd['lang'], 'country': cmd['country']}
    elif name == 'platform_defaults':
        _need(set(cmd) == {'name', 'scope'} and cmd['scope'] == 'copy', 'command')
        cmd = {'name': name, 'scope': 'copy'}
    else:
        _need(set(cmd) == {'name'}, 'command')
        cmd = {'name': name}
    return {'sid': _sid(args), 'digest': _digest(args['digest']), 'command': cmd}


def traefik_write(args):
    _keys(args, 'sid', 'hostnames', 'http_port', 'gevent_port', 'generation')
    hosts = args['hostnames']
    _need(isinstance(hosts, list) and 1 <= len(hosts) <= 10
          and all(isinstance(h, str) and len(h) <= 253 and HOST_RE.match(h) for h in hosts), 'hostnames')
    return {'sid': _sid(args), 'hostnames': hosts, 'http_port': _port(args['http_port']),
            'gevent_port': _port(args['gevent_port']), 'generation': _int(args['generation'], 1, 2**31, 'generation')}


def file_remove_secret(args):
    _keys(args, 'sid', 'name')
    _need(args['name'] in SECRET_NAMES, 'name')
    return {'sid': _sid(args), 'name': args['name']}


def file_write_secret(args):
    _keys(args, 'sid', 'name', 'data_b64')
    _need(args['name'] in SECRET_NAMES, 'name')
    try:
        data = base64.b64decode(args['data_b64'], validate=True)
    except (ValueError, TypeError):
        raise BadArgs('data')
    _need(0 < len(data) <= 4096, 'data')
    return {'sid': _sid(args), 'name': args['name'], 'data_b64': args['data_b64']}


CONF_INTS = {'workers': (0, 32), 'max_cron_threads': (0, 4), 'db_maxconn': (2, 64),
             'limit_memory_soft': (256 << 20, 16 << 30), 'limit_memory_hard': (256 << 20, 16 << 30),
             'limit_time_cpu': (10, 3600), 'limit_time_real': (10, 7200)}


def file_write_conf(args):
    _keys(args, 'sid', 'conf')
    conf = args['conf']
    _need(isinstance(conf, dict) and set(conf) == set(CONF_INTS) | {'admin_passwd_hash', 'smtp'}, 'conf')
    out = {k: _int(conf[k], *CONF_INTS[k], k) for k in CONF_INTS}
    _need(out['limit_memory_soft'] <= out['limit_memory_hard'], 'memory')
    _need(isinstance(conf['admin_passwd_hash'], str)
          and re.match(r'^\$pbkdf2-sha512\$\d+\$[A-Za-z0-9./]+\$[A-Za-z0-9./]+$', conf['admin_passwd_hash']),
          'admin_passwd_hash')
    # smtp: 'relay' (production) or 'sink' (restore copies, DOC-04 §6.9 step 7)
    _need(conf['smtp'] in ('relay', 'sink'), 'smtp')
    out.update(admin_passwd_hash=conf['admin_passwd_hash'], smtp=conf['smtp'])
    return {'sid': _sid(args), 'conf': out}


def pg_create_role(args):
    _keys(args, 'sid', 'password_hash')
    _need(isinstance(args['password_hash'], str) and SCRAM_RE.match(args['password_hash']), 'password_hash')
    return {'sid': _sid(args), 'password_hash': args['password_hash']}


def pg_hba_add(args):
    _keys(args, 'sid', 'app_host_ip')
    _need(isinstance(args['app_host_ip'], str) and IPV4_RE.match(args['app_host_ip'])
          and all(0 <= int(p) <= 255 for p in args['app_host_ip'].split('.')), 'app_host_ip')
    return {'sid': _sid(args), 'app_host_ip': args['app_host_ip']}


UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
AGE_RECIPIENT_RE = re.compile(r'^age1[02-9ac-hj-np-z]{58}$')
AGE_IDENTITY_RE = re.compile(r'^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$')


def _uuid(value, what):
    _need(isinstance(value, str) and UUID_RE.match(value), what)
    return value


def sid_backup(args):
    _keys(args, 'sid', 'backup_id')
    return {'sid': _sid(args), 'backup_id': _uuid(args['backup_id'], 'backup_id')}


def backup_package(args):
    _keys(args, 'sid', 'backup_id', 'manifest_b64', 'recipient')
    try:
        raw = base64.b64decode(args['manifest_b64'], validate=True)
        _need(len(raw) <= 65536 and isinstance(json.loads(raw), dict), 'manifest')
    except (ValueError, TypeError):
        raise BadArgs('manifest')
    _need(isinstance(args['recipient'], str) and AGE_RECIPIENT_RE.match(args['recipient']), 'recipient')
    return {'sid': _sid(args), 'backup_id': _uuid(args['backup_id'], 'backup_id'),
            'manifest_b64': args['manifest_b64'], 'recipient': args['recipient']}


def restore_unpack(args):
    _keys(args, 'sid', 'backup_id', 'identity')
    _need(isinstance(args['identity'], str) and AGE_IDENTITY_RE.match(args['identity']), 'identity')
    return {'sid': _sid(args), 'backup_id': _uuid(args['backup_id'], 'backup_id'), 'identity': args['identity']}


def restore_load(args):
    _keys(args, 'sid', 'backup_id', 'digest')
    return {'sid': _sid(args), 'backup_id': _uuid(args['backup_id'], 'backup_id'), 'digest': _digest(args['digest'])}


def no_args(args):
    _keys(args)
    return {}


APP = {
    'volume.create': volume_create, 'volume.remove': sid_only, 'volume.inspect': sid_only,
    'net.create': sid_only, 'net.remove': sid_only, 'net.inspect': sid_only,
    'nft.apply_tenant': nft_apply_tenant, 'nft.remove_tenant': sid_only, 'nft.inspect': sid_only,
    'image.pull': image_pull, 'image.inspect': image_pull,
    'container.create': container_create, 'container.start': sid_only, 'container.stop': container_stop,
    'container.remove': sid_only, 'container.inspect': sid_only, 'container.run_oneshot': container_run_oneshot,
    'traefik.write': traefik_write, 'traefik.remove': sid_only, 'traefik.inspect': sid_only,
    'file.write_secret': file_write_secret, 'file.remove_secret': file_remove_secret,
    'file.write_conf': file_write_conf, 'file.inspect': sid_only,
    'backup.dump': sid_backup, 'backup.package': backup_package, 'backup.clean': sid_backup,
    'restore.prepare': sid_backup, 'restore.unpack': restore_unpack, 'restore.load': restore_load,
    'exec.cancel': sid_only,
}
DB = {
    'pg.create_role': pg_create_role, 'pg.create_db': sid_only, 'pg.harden_db': sid_only,
    'pg.hba_add': pg_hba_add, 'pg.hba_remove': sid_only, 'pg.reload': no_args,
    'pg.rotate_password': pg_create_role, 'pg.terminate_sessions': sid_only,
    'pg.drop_db': sid_only, 'pg.drop_role': sid_only, 'pg.connection_stats': no_args, 'pg.inspect': sid_only,
}
BY_ROLE = {'app': APP, 'db': DB, 'mail': {}}


def validate(role: str, verb: str, args) -> dict:
    table = BY_ROLE.get(role, {})
    if verb not in table:
        raise BadArgs('unknown verb')
    return table[verb](args)
