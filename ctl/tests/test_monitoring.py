"""The 26-hour backup alert (DOC-05 §8, RB-01): what /metrics exports, the
Alertmanager webhook turning alerts into incidents, and the Prometheus rules
under promtool."""
import hashlib
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ctlplane.monitoring import create_app

from .conftest import ENV, TENANT

TOKEN = 'webhook-token-for-tests'
RULES = Path(__file__).resolve().parent.parent / 'monitoring' / 'rules'
PROMETHEUS = 'prom/prometheus:v2.53.2'


@pytest.fixture
def mon(w):
    return TestClient(create_app(w.store, webhook_token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest()))


def _backup(w, env, age_h, state='recoverable', tier='daily'):
    op = w.store.dispatch('Tenant.Stop', tenant_id=TENANT, environment_id=None, params={'reason': 'operator'},
                          hosts={'app': w.sql("SELECT id FROM host WHERE role = 'app' LIMIT 1")[0]['id']},
                          idempotency_key=str(uuid.uuid4()))
    snap = datetime.now(timezone.utc) - timedelta(hours=age_h)
    w.sql("INSERT INTO backup_point (id, environment_id, operation_id, trigger, retention_tier, snapshot_at, "
          "gc_guard_held, missing_files, state, created_at) VALUES (%s, %s, %s, 'scheduled', %s, %s, true, 0, %s, now())",
          (uuid.uuid4(), env, op, tier, snap, state))
    return snap


def _series(mon):
    text = mon.get('/metrics').text
    return {m.group(2): float(m.group(3)) for m in re.finditer(
        r'^ctl_backup_last_recoverable_timestamp_seconds\{tenant_id="([^"]+)",environment_id="([^"]+)"\} (\S+)$',
        text, re.M)}


def test_metric_is_the_newest_recoverable_snapshot_of_any_tier(w, mon):
    _backup(w, ENV, 40)
    newest = _backup(w, ENV, 30, tier='weekly')         # Sunday's scheduled run counts
    _backup(w, ENV, 1, state='failed')                  # failed: not counted
    assert _series(mon) == {ENV: int(newest.timestamp())}
    assert 'ctl_backup_environments 1' in mon.get('/metrics').text


def test_never_backed_up_is_zero(w, mon):
    assert _series(mon) == {ENV: 0}


@pytest.mark.parametrize('state', ['DRAFT', 'VALIDATING', 'ERROR', 'DELETED'])
def test_only_tenants_that_should_be_backed_up(w, mon, state):
    w.sql('UPDATE tenant SET lifecycle_state = %s', (state,))
    assert _series(mon) == {}


def test_restore_copies_and_removed_environments_are_left_out(w, mon):
    copy = str(uuid.uuid4())
    w.sql("INSERT INTO environment (id, tenant_id, kind) VALUES (%s, %s, 'restore_copy')", (copy, TENANT))
    assert set(_series(mon)) == {ENV}
    w.sql("UPDATE environment SET observed_state = 'absent' WHERE id = %s", (ENV,))
    assert _series(mon) == {}


def _drills(mon):
    text = mon.get('/metrics').text
    return {m.group(1): float(m.group(2)) for m in re.finditer(
        r'^ctl_drill_last_pass_timestamp_seconds\{tenant_id="[^"]+",environment_id="([^"]+)"\} (\S+)$', text, re.M)}


def _drill(w, backup_op, result, age_h):
    bp = w.sql('SELECT id FROM backup_point WHERE operation_id = %s', (backup_op,))[0]['id']
    op = w.store.dispatch('Tenant.Stop', tenant_id=TENANT, environment_id=None, params={'reason': 'operator'},
                          hosts={'app': w.sql("SELECT id FROM host WHERE role = 'app' LIMIT 1")[0]['id']},
                          idempotency_key=str(uuid.uuid4()))
    w.sql("INSERT INTO restore_attempt (id, operation_id, backup_point_id, source_environment_id, purpose, result, "
          "created_at) VALUES (%s, %s, %s, %s, 'drill', %s, %s)",
          (uuid.uuid4(), op, bp, ENV, result, datetime.now(timezone.utc) - timedelta(hours=age_h)))


def test_drill_metric_is_the_last_pass_else_the_first_backup(w, mon):
    assert _drills(mon) == {}                                       # nothing to drill yet: the backup alert's
    first = _backup(w, ENV, 100)
    _backup(w, ENV, 1)
    _backup(w, ENV, 200, state='failed')
    assert _drills(mon) == {ENV: int(first.timestamp())}
    op = w.sql('SELECT operation_id FROM backup_point WHERE state = %s LIMIT 1', ('recoverable',))[0]['operation_id']
    _drill(w, op, 'pass', 50)
    _drill(w, op, 'fail', 2)                                        # a failure doesn't reset the clock
    [ts] = _drills(mon).values()
    assert abs(ts - (datetime.now(timezone.utc) - timedelta(hours=50)).timestamp()) < 5
    w.sql("UPDATE tenant SET lifecycle_state = 'VALIDATING'")
    assert _drills(mon) == {}


# -- Alertmanager → incident ----------------------------------------------------------

def _alert(status='firing', fp='abc123', **labels):
    return {'status': status, 'fingerprint': fp,
            'labels': {'alertname': 'NoRecoverableDailyBackup', 'severity': 'sev2', 'runbook': 'RB-01',
                       'tenant_id': TENANT, 'environment_id': ENV, **labels},
            'annotations': {'summary': 'No recoverable daily backup for 26 h: tenant %s' % TENANT}}


def _hook(mon, *alerts, token=TOKEN):
    return mon.post('/v1/alertmanager', json={'version': '4', 'status': 'firing', 'alerts': list(alerts)},
                    headers={'Authorization': 'Bearer ' + token} if token else {})


def test_firing_opens_one_sev2_incident_and_resolved_closes_it(w, mon):
    assert _hook(mon, _alert()).json() == {'opened': 1, 'resolved': 0}
    assert _hook(mon, _alert()).json() == {'opened': 0, 'resolved': 0}          # Alertmanager repeats
    [i] = w.sql('SELECT * FROM incident')
    assert (i['severity'], i['runbook_ref'], i['scope_tenant_ids'], i['resolved_at']) == \
        ('sev2', 'RB-01', [uuid.UUID(TENANT)], None)
    assert _hook(mon, _alert('resolved')).json() == {'opened': 0, 'resolved': 1}
    assert w.sql('SELECT resolved_at FROM incident')[0]['resolved_at'] is not None
    assert _hook(mon, _alert()).json() == {'opened': 1, 'resolved': 0}          # fires again: a new incident
    assert len(w.sql('SELECT * FROM incident')) == 2


def test_untrusted_labels_are_tamed(w, mon):
    _hook(mon, _alert(severity='sev0', tenant_id='not-a-uuid', fp='x'))
    [i] = w.sql('SELECT severity, scope_tenant_ids FROM incident')
    assert (i['severity'], i['scope_tenant_ids']) == ('sev3', [])


@pytest.mark.parametrize('token', [None, 'wrong'])
def test_webhook_needs_the_token(w, mon, token):
    assert _hook(mon, _alert(), token=token).status_code == 401
    assert w.sql('SELECT * FROM incident') == []


def test_malformed_payload(w, mon):
    r = mon.post('/v1/alertmanager', json={'alerts': 'nope'}, headers={'Authorization': 'Bearer ' + TOKEN})
    assert r.status_code == 422


# -- the rules themselves ------------------------------------------------------------

def _image_present():
    try:
        return subprocess.run(['docker', 'image', 'inspect', PROMETHEUS], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not _image_present(), reason='needs %s (docker pull)' % PROMETHEUS)
@pytest.mark.parametrize('rules', ['backups', 'drills', 'controlplane', 'workers'])
def test_rules_under_promtool(rules):
    run = lambda *a: subprocess.run(['docker', 'run', '--rm', '-v', '%s:/r:ro' % RULES, '-w', '/r',  # noqa: E731
                                     '--entrypoint', 'promtool', PROMETHEUS, *a], capture_output=True, text=True)
    check = run('check', 'rules', rules + '.yml')
    assert check.returncode == 0, check.stdout + check.stderr
    test = run('test', 'rules', rules + '_test.yml')
    assert test.returncode == 0 and 'SUCCESS' in test.stdout, test.stdout + test.stderr
