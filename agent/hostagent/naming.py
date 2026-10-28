"""Derived names (DOC-04 §5.1). Computed from IDs here; never taken from a request."""
import re

SID_RE = re.compile(r'^[0-9a-f]{12}$')


def sid(environment_id: str) -> str:
    return environment_id.replace('-', '')[:12]


def check_sid(value: str) -> str:
    if not isinstance(value, str) or not SID_RE.match(value):
        raise ValueError('bad sid')
    return value


def container(s: str) -> str:
    return 'odoo-%s' % check_sid(s)


def network(s: str) -> str:
    return 'net-%s' % check_sid(s)


def filestore_dir(s: str) -> str:
    return '/srv/tenants/%s/data' % check_sid(s)


def run_dir(s: str) -> str:
    return '/run/tenants/%s' % check_sid(s)


def odoo_conf(s: str) -> str:
    return '%s/odoo.conf' % run_dir(s)


def traefik_file(s: str) -> str:
    return '/etc/traefik/dynamic/%s.yaml' % check_sid(s)


def db_name(s: str) -> str:
    return 't_%s' % check_sid(s)


def db_role(s: str) -> str:
    return 'r_%s' % check_sid(s)
