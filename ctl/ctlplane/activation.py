"""VALIDATING → ACTIVE (DOC-03 §3.6, §5).

ACTIVE requires agent evidence of HTTPS, login and websocket checks, a
database-manager probe returning 403, the image digest matching, a first
backup point reaching `recoverable`, and the data placement manifest
matching the accepted terms (INV-15). Each is evaluated from what ctl-1
holds and reported as:

    pass     the evidence is there and says yes
    fail     the evidence is there and says no   → the tenant goes to ERROR
    missing  nothing reports it (yet)            → the tenant stays VALIDATING

Evaluations are kept (`activation_check`). Activation is the system's check
plus an operator's confirmation: a `pass` no older than an hour, named by
the operator, for a tenant still VALIDATING.

The public evidence comes from agents with an ingress configured
(`ingress_url`): `app.route` reports `certificate: issued` once Traefik
serves a certificate that verifies for every hostname, and `app.health`
reports `https_login`, `https_websocket` and `public_db_manager` through
the public hostnames. Without it, those checks stay `missing`.
"""
import uuid

from psycopg.types.json import Jsonb

from . import audit
from .admission import Refused
from .store import Store, _ts

CHECK_MAX_AGE = 3600
CHECKS = ('health', 'https', 'db_manager_403', 'image_digest', 'first_backup', 'placement_terms')


def _ok(status, detail=None):
    return {'status': status, 'detail': detail}


def evaluate(c, tenant_id) -> tuple[dict, str, str | None]:
    """→ (results by check, verdict, environment_id)."""
    env = c.execute("SELECT * FROM environment WHERE tenant_id = %s AND kind = 'production'", (tenant_id,)).fetchone()
    if env is None:
        return {k: _ok('missing', 'no production environment') for k in CHECKS}, 'incomplete', None
    create = c.execute("SELECT id FROM operation WHERE type = 'Tenant.Create' AND environment_id = %s "
                       "AND state = 'COMPLETED' ORDER BY finished_at DESC LIMIT 1", (env['id'],)).fetchone()
    seen = {}
    if create:
        seen = {r['name']: r['observed'] or {} for r in c.execute(
            "SELECT name, observed FROM operation_step WHERE operation_id = %s AND state = 'done'",
            (create['id'],)).fetchall()}
    r = {}

    health = seen.get('app.health')
    if health is None:
        r['health'] = _ok('missing', 'no completed Tenant.Create health step')
    elif health.get('login') == 200 and health.get('websocket') == 101:
        r['health'] = _ok('pass', {'login': 200, 'websocket': 101})
    else:
        r['health'] = _ok('fail', {'login': health.get('login'), 'websocket': health.get('websocket')})

    route = seen.get('app.route') or {}
    if health is None or 'https_login' not in health or route.get('certificate') in (None, 'not_checked'):
        r['https'] = _ok('missing', 'the agent does not probe the public hostname over HTTPS yet')
    elif (health['https_login'], health.get('https_websocket'), route['certificate']) == (200, 101, 'issued'):
        r['https'] = _ok('pass', {'https_login': 200, 'https_websocket': 101, 'certificate': 'issued'})
    else:
        r['https'] = _ok('fail', {'https_login': health['https_login'],
                                  'https_websocket': health.get('https_websocket'),
                                  'certificate': route['certificate']})

    if health is not None and health.get('db_service_refused') is False:
        r['db_manager_403'] = _ok('fail', {'db_service_refused': False})        # loopback already fails
    elif health is None or 'public_db_manager' not in health:
        r['db_manager_403'] = _ok('missing', 'loopback database service refused; the public path is not probed yet'
                                  if health else 'no health evidence')
    elif health['public_db_manager'] == 403 and health.get('db_service_refused') is True:
        r['db_manager_403'] = _ok('pass', {'public_db_manager': 403, 'db_service_refused': True})
    else:
        r['db_manager_403'] = _ok('fail', {'public_db_manager': health['public_db_manager']})

    release = env['image_release_id'] and c.execute('SELECT image_digest FROM image_release WHERE id = %s',
                                                    (env['image_release_id'],)).fetchone()
    image, container = seen.get('app.image'), seen.get('app.container')
    if not release or image is None or container is None:
        r['image_digest'] = _ok('missing', 'no image or container evidence')
    else:
        digest = release['image_digest']
        resolved = any(d.endswith('@' + digest) for d in image.get('repo_digests') or ()) \
            or image.get('image_id') == digest                     # loaded locally (development)
        running = container.get('image_id') == image.get('image_id')
        r['image_digest'] = _ok('pass' if resolved and running else 'fail',
                                {'release': digest, 'resolved': resolved, 'container_runs_it': running})

    backup = c.execute("SELECT id, snapshot_at FROM backup_point WHERE environment_id = %s AND state = 'recoverable' "
                       'ORDER BY snapshot_at LIMIT 1', (env['id'],)).fetchone()
    r['first_backup'] = _ok('pass', {'backup_point_id': str(backup['id'])}) if backup else \
        _ok('missing', 'no recoverable backup point')

    manifest = c.execute('SELECT m.version, g.code FROM data_placement_manifest m JOIN region g ON g.id = m.region_id '
                         'WHERE m.tenant_id = %s ORDER BY m.version DESC LIMIT 1', (tenant_id,)).fetchone()
    terms = c.execute('SELECT id, terms_version, region_code FROM terms_acceptance WHERE tenant_id = %s '
                      'ORDER BY accepted_at DESC LIMIT 1', (tenant_id,)).fetchone()
    if manifest is None or terms is None:
        r['placement_terms'] = _ok('missing', 'no placement manifest' if manifest is None else 'no terms acceptance')
    else:
        detail = {'manifest_version': manifest['version'], 'manifest_region': manifest['code'],
                  'terms_region': terms['region_code'], 'terms_version': terms['terms_version']}
        r['placement_terms'] = _ok('pass' if manifest['code'] == terms['region_code'] else 'fail', detail)

    statuses = {v['status'] for v in r.values()}
    verdict = 'fail' if 'fail' in statuses else 'incomplete' if 'missing' in statuses else 'pass'
    return r, verdict, str(env['id'])


class Activation:
    def __init__(self, store: Store):
        self.store = store

    def check(self, operator_id, tenant_id) -> dict:
        """Evaluate and keep the result. A failed check moves a VALIDATING tenant to ERROR."""
        now = self.store.clock()
        with self.store.connect() as c:
            tenant = c.execute('SELECT * FROM tenant WHERE id = %s FOR UPDATE', (tenant_id,)).fetchone()
            if tenant is None:
                raise Refused('NOT_FOUND')
            results, verdict, env = evaluate(c, tenant_id)
            check_id = uuid.uuid4()
            c.execute('INSERT INTO activation_check (id, tenant_id, environment_id, results, verdict, evaluated_by, '
                      'evaluated_at) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                      (check_id, tenant_id, env, Jsonb(results), verdict, operator_id, _ts(now)))
            audit.append(c, _ts(now), 'tenant.activation_checked', actor_kind='operator', actor_id=operator_id,
                         tenant_id=tenant_id, resource_type='activation_check', resource_id=check_id,
                         after={'verdict': verdict, 'results': results})
            if verdict == 'fail' and tenant['lifecycle_state'] == 'VALIDATING':
                c.execute("UPDATE tenant SET lifecycle_state = 'ERROR', row_version = row_version + 1 WHERE id = %s",
                          (tenant_id,))
                audit.append(c, _ts(now), 'tenant.error', actor_kind='system', tenant_id=tenant_id,
                             resource_type='tenant', resource_id=tenant_id, correlation_id=check_id,
                             after={'failed': sorted(k for k, v in results.items() if v['status'] == 'fail')})
            return {'id': str(check_id), 'verdict': verdict, 'results': results}

    def activate(self, operator_id, tenant_id, check_id) -> dict:
        now = self.store.clock()
        with self.store.connect() as c:
            tenant = c.execute('SELECT * FROM tenant WHERE id = %s FOR UPDATE', (tenant_id,)).fetchone()
            if tenant is None:
                raise Refused('NOT_FOUND')
            if tenant['lifecycle_state'] != 'VALIDATING':
                raise Refused('STATE', {'tenant_state': tenant['lifecycle_state']})
            latest = c.execute('SELECT * FROM activation_check WHERE tenant_id = %s ORDER BY evaluated_at DESC, id '
                               'LIMIT 1', (tenant_id,)).fetchone()
            if latest is None or str(latest['id']) != check_id:
                raise Refused('STATE', {'detail': 'not the latest check'})
            if latest['verdict'] != 'pass':
                raise Refused('STATE', {'verdict': latest['verdict']})
            if now - latest['evaluated_at'].timestamp() > CHECK_MAX_AGE:
                raise Refused('STATE', {'detail': 'check older than %d s' % CHECK_MAX_AGE})
            # The evidence may have changed since: the system checks again before the state moves.
            results, verdict, _ = evaluate(c, tenant_id)
            if verdict != 'pass':
                raise Refused('STATE', {'detail': 'evidence changed', 'verdict': verdict})
            c.execute("UPDATE tenant SET lifecycle_state = 'ACTIVE', activation_check_id = %s, activated_by = %s, "
                      'activated_at = %s, row_version = row_version + 1 WHERE id = %s',
                      (check_id, operator_id, _ts(now), tenant_id))
            audit.append(c, _ts(now), 'tenant.activated', actor_kind='operator', actor_id=operator_id,
                         tenant_id=tenant_id, resource_type='tenant', resource_id=tenant_id, correlation_id=check_id,
                         after={'activation_check_id': check_id, 'results': results})
            return {'tenant_id': tenant_id, 'lifecycle_state': 'ACTIVE', 'activation_check_id': check_id}


def record_terms(store: Store, operator_id, tenant_id, terms: dict) -> str:
    """Terms acceptance as signed (DOC-03 §2.1, INV-4 is a CHECK). Billing's to record."""
    import psycopg
    now = store.clock()
    tid = uuid.uuid4()
    with store.connect() as c:
        if not c.execute('SELECT 1 FROM region WHERE code = %s', (terms['region'],)).fetchone():
            raise Refused('NOT_FOUND', {'region': terms['region']})
        try:
            with c.transaction():
                c.execute('INSERT INTO terms_acceptance (id, tenant_id, terms_version, document_sha256, accepted_by_name, '
                          'accepted_at, covers, region_code, recorded_by, recorded_at) '
                          'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                          (tid, tenant_id, terms['terms_version'], terms['document_sha256'], terms['accepted_by_name'],
                           terms['accepted_at'], terms['covers'], terms['region'], operator_id, _ts(now)))
        except psycopg.errors.CheckViolation:
            raise Refused('SCHEMA', {'detail': 'terms must cover every required item, with a SHA-256'}) from None
        except psycopg.errors.ForeignKeyViolation:
            raise Refused('NOT_FOUND', {'tenant_id': tenant_id}) from None
        audit.append(c, _ts(now), 'tenant.terms_recorded', actor_kind='operator', actor_id=operator_id,
                     tenant_id=tenant_id, resource_type='terms_acceptance', resource_id=tid,
                     after={'terms_version': terms['terms_version'], 'region': terms['region']})
    return str(tid)
