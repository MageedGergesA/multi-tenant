"""Entry point for agent-exec: `python -m hostagent.exec_main --config exec.toml`.

role "app": runs as root (Docker, nftables, files under the tenants' uids).
role "db": runs as the postgres user (peer authentication over the local
socket, so it is a superuser without a password), writing pg_hba include
files into `hba_dir`; it shares a group with agentd for the socket.
"""
import argparse
import tomllib
from pathlib import Path

from .backends import AppHostConfig, DockerApp
from .execd import ExecServer, Executor
from .logs import AuditLog
from .pg_backend import DbHostConfig, PgBackend


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', required=True, type=Path)
    raw = tomllib.loads(ap.parse_args().config.read_text())
    if raw['role'] == 'db':
        return _db(raw)
    if raw['role'] != 'app':
        raise SystemExit('roles served: app, db')
    app = raw['app']
    backend = DockerApp(AppHostConfig(
        root=Path(app.get('root', '/')), subuid_base=app.get('subuid_base', 0),
        registry_host=app.get('registry_host', ''), image_source=app.get('image_source', 'registry'),
        db_host=app['db_host'], db_port=app.get('db_port', 5432), db_sslmode=app.get('db_sslmode', 'verify-full'),
        db_ca=app.get('db_ca', ''),
        mail_host=app.get('mail_host', ''), mail_port=app.get('mail_port', 587), resolver=app.get('resolver', ''),
        nft_mode=app.get('nft_mode', 'nft'), cert_resolver=app.get('cert_resolver', 'le'),
        root_volume=app.get('root_volume', ''), agentd_uid=raw['owner_uid'],
        extra=app.get('extra', {})))
    executor = Executor('app', backend, AuditLog(Path(raw['audit_log'])))
    executor.startup()
    server = ExecServer(Path(raw['socket']), executor, owner_uid=raw.get('owner_uid'))
    server.serve_forever()


def _db(raw):
    db = raw['db']
    backend = PgBackend(DbHostConfig(
        dsn=db.get('dsn', 'host=/var/run/postgresql dbname=postgres user=postgres'), hba_dir=Path(db['hba_dir']),
        hba_method=db.get('hba_method', 'hostssl'), hba_cidr_override=db.get('hba_cidr_override', '')))
    executor = Executor('db', backend, AuditLog(Path(raw['audit_log'])))
    executor.startup()
    server = ExecServer(Path(raw['socket']), executor, owner_gid=raw['owner_gid'])
    server.serve_forever()


if __name__ == '__main__':
    main()
