"""One benchmark run (DOC-06 §6 E1 shape) with a §10 evidence record.

    python3 run.py --dataset ../evidence/datasets/bench_s_eg --workers 2 --cron 1 \
        --peak 0.5 --duration 30m --test-id E1-S-w2c1-r1

Restores the dataset into a fresh database (identical start state), starts one
tenant container, drives it with Locust, samples container stats, and writes
evidence/runs/<test-id>/ with manifest.json, Locust CSVs and the verdict
against the DOC-06 §5 SLO.
"""
import argparse
import csv
import json
import math
import os
import subprocess
import threading
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
TRAEFIK_DYNAMIC = """http:
  routers:
    odoo: {rule: "PathPrefix(`/`)", service: odoo, entryPoints: [web]}
    websocket: {rule: "PathPrefix(`/websocket`)", service: bus, entryPoints: [web], priority: 100}
  # Upstream keep-alive off: an idle pooled connection pins an Odoo prefork
  # worker until its socket timeout (found in SMOKE-XS, 2026-10-24).
  serversTransports:
    no-keepalive: {maxIdleConnsPerHost: -1}
  services:
    odoo: {loadBalancer: {serversTransport: no-keepalive, servers: [{url: "http://%(odoo)s:8069"}]}}
    bus: {loadBalancer: {servers: [{url: "http://%(odoo)s:8072"}]}}
"""
SLO = {  # DOC-06 §5: p95 s, p99 s, max error rate
    'read': (1.0, 2.5, 0.005),
    'write': (1.5, 3.5, 0.005),
    'pdf': (5.0, 10.0, 0.01),
    'heavy': (8.0, 20.0, 0.01),
}


def sh(*cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout


def restore(ds, db, net, pg, fs, image):
    env = dict(os.environ, PGPASSWORD=pg['password'])
    base = ['docker', 'run', '--rm', '-i', '--network', net, '-e', 'PGPASSWORD', '-v', '%s:/ds:ro' % ds, 'postgres:16']
    subprocess.run(base + ['dropdb', '-h', pg['host'], '-U', pg['user'], '--if-exists', '--force', db], check=True, env=env)
    subprocess.run(base + ['createdb', '-h', pg['host'], '-U', pg['user'], db], check=True, env=env)
    subprocess.run(base + ['pg_restore', '-h', pg['host'], '-U', pg['user'], '-d', db, '--no-owner', '/ds/dump.pgc'],
                   check=True, env=env)
    # DOC-04 §6.9/§6.10: every restored copy gets platform_defaults(copy).
    subprocess.run(['docker', 'run', '--rm', '--network', net, '-e', 'PGPASSWORD',
                    '--entrypoint', '/opt/platform/platform-defaults', image,
                    'copy', '-d', db, '--db_host', pg['host'], '--db_user', pg['user']], check=True, env=env)
    subprocess.run(['rm', '-rf', str(fs)], check=True)
    fs.mkdir(parents=True)
    subprocess.run(['tar', '-C', str(fs), '-xf', str(ds / 'filestore.tar'), '--strip-components=1'], check=True)
    src = fs / 'filestore' / json.load(open(ds / 'manifest.json'))['db']
    if src.exists() and src.name != db:
        src.rename(fs / 'filestore' / db)
    subprocess.run(['chmod', '-R', 'a+rwX', str(fs)], check=True)
    return fs


def sample_stats(name, out, stop):
    with open(out, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['ts', 'cpu_pct', 'mem_bytes'])
        while not stop.is_set():
            try:
                cpu, mem = sh('docker', 'stats', '--no-stream', '--format', '{{.CPUPerc}};{{.MemUsage}}', name).strip().split(';')
                used = mem.split('/')[0].strip()
                unit = {'KiB': 1024, 'MiB': 1024 ** 2, 'GiB': 1024 ** 3, 'B': 1}
                num, suffix = next((used[:-len(u)], u) for u in ('KiB', 'MiB', 'GiB', 'B') if used.endswith(u))
                w.writerow([round(time.time(), 1), cpu.rstrip('%'), int(float(num) * unit[suffix])])
                f.flush()
            except (subprocess.CalledProcessError, StopIteration, ValueError):
                pass
            stop.wait(5)


def verdict(stats_csv):
    by_class = {}
    for row in csv.DictReader(open(stats_csv)):
        name = row['Name']
        cls = name.split(':', 1)[0]
        if cls not in SLO or row['Type'] == '' or name == 'Aggregated':
            continue
        n, fails = int(row['Request Count']), int(row['Failure Count'])
        p95, p99 = float(row['95%'] or 0) / 1000, float(row['99%'] or 0) / 1000
        lim95, lim99, lim_err = SLO[cls]
        ok = p95 <= lim95 and p99 <= lim99 and (fails / n if n else 0) <= lim_err
        by_class.setdefault(cls, []).append({'name': name, 'n': n, 'fail': fails, 'p95': p95, 'p99': p99, 'pass': ok})
    return {'pass': all(r['pass'] for rows in by_class.values() for r in rows) and bool(by_class),
            'classes': by_class}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True, type=Path)
    ap.add_argument('--test-id', required=True)
    ap.add_argument('--workers', type=int, default=2)
    ap.add_argument('--cron', type=int, default=1)
    ap.add_argument('--peak', type=float, default=0.5, help='share of named users active (0.5 baseline, 0.75 stress)')
    ap.add_argument('--duration', default='30m')
    ap.add_argument('--ramp', type=float, default=1.0, help='users spawned per second')
    ap.add_argument('--think-mean', type=float, default=20.0)
    ap.add_argument('--browsers', type=int, default=-1,
                    help='Playwright bus users (DOC-06 §4: 5%% of virtual users, min 2); 0 disables')
    ap.add_argument('--browser-think-mean', type=float, help='defaults to --think-mean')
    ap.add_argument('--runtime', default='runc', choices=['runc', 'runsc'])
    ap.add_argument('--net', default='bench')
    ap.add_argument('--pg-host', default='bench-pg')
    ap.add_argument('--pg-user', default='odoo')
    ap.add_argument('--pg-password', default=os.environ.get('PGPASSWORD', 'bench'))
    a = ap.parse_args()

    ds = a.dataset.resolve()
    manifest = json.load(open(ds / 'manifest.json'))
    image = manifest['image']
    db = 'run_' + a.test_id.lower().replace('-', '_')
    out = BENCH / 'evidence' / 'runs' / a.test_id
    (out / 'raw').mkdir(parents=True, exist_ok=True)
    pg = {'host': a.pg_host, 'user': a.pg_user, 'password': a.pg_password}
    named = sum(1 for _ in open(ds / 'users.csv')) - 1
    users = max(1, math.ceil(named * a.peak))
    browsers = max(2, math.ceil(users * 0.05)) if a.browsers < 0 else a.browsers

    fs = restore(ds, db, a.net, pg, out / 'raw' / 'filestore', image)
    name = 'bench-tenant-' + a.test_id.lower()
    proxy = 'bench-proxy-' + a.test_id.lower()
    subprocess.run(['docker', 'rm', '-f', name, proxy], capture_output=True)
    sh('docker', 'run', '-d', '--name', name, '--network', a.net, '--runtime', a.runtime,
       '-v', '%s:/var/lib/odoo' % fs, '-e', 'PGPASSWORD=' + pg['password'],
       '--entrypoint', 'odoo', image,
       '--db_host', pg['host'], '--db_user', pg['user'], '-d', db, '--db-filter', '^%s$' % db,
       '--data-dir', '/var/lib/odoo', '--workers', str(a.workers), '--max-cron-threads', str(a.cron),
       '--limit-time-real', '600', '--limit-time-cpu', '300', '--proxy-mode', '--log-level', 'warn')
    # Traefik in front, as in production (ADR-H0-007): it absorbs client
    # keep-alive so prefork workers aren't pinned by idle connections.
    (out / 'traefik.yml').write_text(TRAEFIK_DYNAMIC % {'odoo': name})
    sh('docker', 'run', '-d', '--name', proxy, '--network', a.net, '-p', '127.0.0.1::80',
       '-v', '%s:/etc/traefik/dynamic.yml:ro' % (out / 'traefik.yml'), 'traefik:v3.5',
       '--entrypoints.web.address=:80', '--providers.file.filename=/etc/traefik/dynamic.yml')
    port = sh('docker', 'port', proxy, '80').strip().split(':')[-1]
    host = 'http://127.0.0.1:' + port
    for _ in range(120):
        try:
            sh('curl', '-fsS', host + '/web/health')
            break
        except subprocess.CalledProcessError:
            time.sleep(2)

    stop = threading.Event()
    sampler = threading.Thread(target=sample_stats, args=(name, out / 'raw' / 'container_stats.csv', stop))
    sampler.start()
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    venv = BENCH / 'load' / '.venv' / 'bin'
    bus = None
    if browsers:
        bus = subprocess.Popen([str(venv / 'python'), str(BENCH / 'load' / 'browsers.py'), '--host', host,
                                '--db', db, '--users-file', str(ds / 'users.csv'), '--browsers', str(browsers),
                                '--duration', a.duration, '--out', str(out / 'raw'),
                                '--think-mean', str(a.browser_think_mean or a.think_mean)])
    try:
        subprocess.run([str(venv / 'locust'), '-f', str(BENCH / 'load' / 'locustfile.py'), '--headless',
                        '--host', host, '--users', str(users), '--spawn-rate', str(a.ramp), '--run-time', a.duration,
                        '--users-file', str(ds / 'users.csv'), '--db', db, '--think-mean', str(a.think_mean),
                        '--csv', str(out / 'raw' / 'locust'), '--only-summary'], check=False)
        if bus:
            bus.wait()
    finally:
        if bus and bus.poll() is None:
            bus.kill()
        finished = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        stop.set()
        sampler.join()
        logs = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
        (out / 'raw' / 'odoo.log').write_text(logs.stdout + logs.stderr)
        subprocess.run(['docker', 'rm', '-f', name, proxy], capture_output=True)

    result = verdict(out / 'raw' / 'locust_stats.csv')
    # E8: the Teklines failure mode shows up as tracebacks on /websocket.
    log = (out / 'raw' / 'odoo.log').read_text()
    result['websocket_log_errors'] = sum(1 for block in log.split('Traceback')[1:] if 'websocket' in block[:4000])
    if browsers:
        summary = out / 'raw' / 'bus_summary.json'
        result['bus'] = json.loads(summary.read_text()) if summary.exists() else {'pass': False, 'error': 'no summary'}
        result['pass'] = result['pass'] and result['bus']['pass'] and not result['websocket_log_errors']
    record = {
        'test_id': a.test_id, 'image': image,
        'image_id': sh('docker', 'image', 'inspect', '--format', '{{.Id}}', image).strip(),
        'dataset': manifest, 'runtime': a.runtime, 'workers': a.workers, 'max_cron_threads': a.cron,
        'named_users': named, 'concurrent_users': users, 'browsers': browsers, 'think_mean_s': a.think_mean,
        'duration': a.duration, 'started_at': started, 'finished_at': finished,
        'host': sh('hostname').strip(), 'verdict': result,
    }
    (out / 'manifest.json').write_text(json.dumps(record, indent=2))
    print(json.dumps({'test_id': a.test_id, 'pass': result['pass']}, indent=2))


if __name__ == '__main__':
    main()
