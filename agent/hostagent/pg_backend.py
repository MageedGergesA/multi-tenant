"""db-host executor backend (DOC-04 §5.4 DB verbs, ADR-004).

Connects as a local superuser. Every identifier is derived from the sid and
quoted with psycopg's `sql.Identifier`; the only value taken from a request is
the SCRAM verifier, validated by verbs.py and passed as a literal.

`pg_hba.conf` ends with `include_dir` (PostgreSQL 16+) pointing at `hba_dir`,
followed by a final reject; one file per tenant lives there.
"""
from dataclasses import dataclass
from pathlib import Path

import psycopg
from psycopg import sql

from . import naming


@dataclass(frozen=True)
class DbHostConfig:
    dsn: str                         # superuser, local socket in production
    hba_dir: Path
    hba_method: str = 'hostssl'      # 'host' only on a development host without TLS
    hba_cidr_override: str = ''      # dev only: Docker bridge range instead of the app host /32


class PgBackend:
    def __init__(self, config: DbHostConfig):
        self.c = config

    def _conn(self, dbname=None):
        conn = psycopg.connect(self.c.dsn, autocommit=True, **({'dbname': dbname} if dbname else {}))
        return conn

    def pg_create_role(self, sid, password_hash):
        role = naming.db_role(sid)
        with self._conn() as conn:
            if conn.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', [role]).fetchone():
                return {}
            conn.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
                                 'NOBYPASSRLS PASSWORD {}').format(sql.Identifier(role), sql.Literal(password_hash)))
        return {}

    def pg_rotate_password(self, sid, password_hash):
        with self._conn() as conn:
            conn.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(naming.db_role(sid)),
                                                                      sql.Literal(password_hash)))
        return {}

    def pg_create_db(self, sid):
        db, role = naming.db_name(sid), naming.db_role(sid)
        with self._conn() as conn:
            if not conn.execute('SELECT 1 FROM pg_database WHERE datname = %s', [db]).fetchone():
                # Same encoding and collation Odoo itself uses (odoo/service/db.py).
                conn.execute(sql.SQL("CREATE DATABASE {} OWNER {} TEMPLATE template0 ENCODING 'unicode' "
                                     "LC_COLLATE 'C'").format(sql.Identifier(db), sql.Identifier(role)))
        with self._conn(db) as conn:
            conn.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')
        return {}

    def pg_harden_db(self, sid):
        db, role = naming.db_name(sid), naming.db_role(sid)
        with self._conn() as conn:
            # Tenants may connect to `postgres` (see pg_hba_add); nothing there for them to use.
            conn.execute('REVOKE TEMPORARY ON DATABASE postgres FROM PUBLIC')
            conn.execute('REVOKE ALL ON SCHEMA public FROM PUBLIC')
            conn.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(sql.Identifier(db)))
            conn.execute(sql.SQL('GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}').format(sql.Identifier(db),
                                                                                       sql.Identifier(role)))
        with self._conn(db) as conn:
            conn.execute('REVOKE ALL ON SCHEMA public FROM PUBLIC')
            conn.execute(sql.SQL('ALTER SCHEMA public OWNER TO {}').format(sql.Identifier(role)))
        return {}

    def _hba_file(self, sid):
        return self.c.hba_dir / ('%s.conf' % sid)

    def pg_hba_add(self, sid, app_host_ip):
        # `postgres` too: Odoo 19's server start always connects there to check that
        # db_name exists (odoo/cli/server.py main → _create_empty_database) and only
        # tolerates a privilege error, not a pg_hba rejection.
        cidr = self.c.hba_cidr_override or '%s/32' % app_host_ip
        line = '%s %s,postgres %s %s scram-sha-256\n' % (self.c.hba_method, naming.db_name(sid),
                                                          naming.db_role(sid), cidr)
        path = self._hba_file(sid)
        tmp = path.with_name('.%s.tmp' % sid)
        tmp.write_text(line)
        tmp.replace(path)
        return {}

    def pg_hba_remove(self, sid):
        self._hba_file(sid).unlink(missing_ok=True)
        return {}

    def pg_reload(self):
        with self._conn() as conn:
            conn.execute('SELECT pg_reload_conf()')
            errors = conn.execute('SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL').fetchone()[0]
        if errors:
            raise RuntimeError('pg_hba has %d invalid rules' % errors)
        return {}

    def pg_terminate_sessions(self, sid):
        with self._conn() as conn:
            n = conn.execute('SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = %s',
                             [naming.db_name(sid)]).fetchone()[0]
        return {'terminated': n}

    def pg_drop_db(self, sid):
        with self._conn() as conn:
            conn.execute(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(naming.db_name(sid))))
        return {}

    def pg_drop_role(self, sid):
        with self._conn() as conn:
            conn.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(naming.db_role(sid))))
        return {}

    def pg_connection_stats(self):
        with self._conn() as conn:
            rows = conn.execute("SELECT datname, count(*) FROM pg_stat_activity WHERE datname LIKE 't\\_%%' "
                                "GROUP BY datname").fetchall()
            max_conn = int(conn.execute('SHOW max_connections').fetchone()[0])
        return {'max_connections': max_conn, 'per_db': dict(rows)}

    def pg_inspect(self, sid):
        db, role = naming.db_name(sid), naming.db_role(sid)
        out = {}
        with self._conn() as conn:
            r = conn.execute('SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolcanlogin '
                             'FROM pg_roles WHERE rolname = %s', [role]).fetchone()
            out['role'] = None if r is None else dict(zip(('super', 'createdb', 'createrole', 'replication',
                                                           'bypassrls', 'login'), r))
            d = conn.execute('SELECT pg_get_userbyid(datdba), datcollate FROM pg_database WHERE datname = %s',
                             [db]).fetchone()
            out['db'] = None if d is None else {'owner': d[0], 'collate': d[1]}
            if d is not None:
                out['public_connect'] = conn.execute("SELECT has_database_privilege('public', %s, 'CONNECT')",
                                                     [db]).fetchone()[0]
            out['hba_rules'] = conn.execute('SELECT count(*) FROM pg_hba_file_rules WHERE %s = ANY(database) '
                                            'AND %s = ANY(user_name) AND error IS NULL', [db, role]).fetchone()[0]
        return out
