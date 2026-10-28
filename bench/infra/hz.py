"""Hetzner Cloud fleet for the DOC-06 benchmark.

    HCLOUD_TOKEN=... python3 hz.py budget   plan.json    # live prices, no changes
    HCLOUD_TOKEN=... python3 hz.py up       plan.json    # needs --approved-eur=<budget figure>
    HCLOUD_TOKEN=... python3 hz.py status   plan.json
    HCLOUD_TOKEN=... python3 hz.py down     plan.json    # deletes everything labelled bench=doc06

`up` refuses to run unless --approved-eur matches the current budget total
(rounded up to the euro), so hosts are never ordered without a priced approval.
The token is read from the environment only and never written anywhere.
"""
import json
import math
import os
import sys
import time
import urllib.request

API = 'https://api.hetzner.cloud/v1'
CLOUD_INIT = """#cloud-config
package_update: true
packages: [docker.io, prometheus-node-exporter, nftables]
runcmd:
  - systemctl enable --now docker prometheus-node-exporter
"""


def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': 'Bearer ' + os.environ['HCLOUD_TOKEN'],
                                          'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def label_selector(plan):
    return plan['label'].replace('=', '%3D')


def hourly_eur(plan):
    prices = {}
    for st in api('GET', '/server_types?per_page=50')['server_types']:
        for p in st['prices']:
            if p['location'] == plan['location']:
                prices[st['name']] = float(p['price_hourly']['gross'])
    vol = api('GET', '/pricing')['pricing']['volume']['price_per_gb_month']['gross']
    return prices, float(vol)


def budget(plan):
    prices, vol_month = hourly_eur(plan)
    total = 0.0
    print('%-18s %-7s %6s %10s %10s' % ('server', 'type', 'hours', 'EUR/h', 'EUR'))
    for s in plan['servers']:
        if s['type'] not in prices:
            sys.exit('server type %s not offered in %s' % (s['type'], plan['location']))
        line = prices[s['type']] * s['hours']
        total += line
        print('%-18s %-7s %6d %10.4f %10.2f' % (s['name'], s['type'], s['hours'], prices[s['type']], line))
    for v in plan['volumes']:
        # Volumes bill hourly against the monthly price (~730 h/month).
        line = float(vol_month) * v['size_gb'] * v['hours'] / 730
        total += line
        print('%-18s %-7s %6d %10s %10.2f' % (v['name'], '%dGB' % v['size_gb'], v['hours'], '', line))
    print('TOTAL (gross, partial hours rounded up per server not included): EUR %.2f' % total)
    return math.ceil(total)


def up(plan, approved):
    expected = budget(plan)
    if approved != expected:
        sys.exit('Refusing: --approved-eur=%s does not match the current budget %d' % (approved, expected))
    labels = dict([plan['label'].split('=')])
    net = api('POST', '/networks', {'name': 'bench-net', 'ip_range': plan['network_cidr'], 'labels': labels,
                                    'subnets': [{'type': 'cloud', 'network_zone': 'eu-central',
                                                 'ip_range': plan['network_cidr'].replace('/16', '/24')}]})
    rules = [{'direction': 'in', 'protocol': 'tcp', 'port': '22', 'source_ips': plan['ssh_allow_cidrs']}] \
        if plan['ssh_allow_cidrs'] else []
    fw = api('POST', '/firewalls', {'name': 'bench-fw', 'labels': labels, 'rules': rules})
    keys = [k['id'] for k in api('GET', '/ssh_keys')['ssh_keys']]
    if not keys:
        sys.exit('No SSH key in the Hetzner project; add one in the console first.')
    for s in plan['servers']:
        api('POST', '/servers', {
            'name': s['name'], 'server_type': s['type'], 'image': plan['image'],
            'location': plan['location'], 'labels': dict(labels, role=s['role']),
            'networks': [net['network']['id']], 'firewalls': [{'firewall': fw['firewall']['id']}],
            'ssh_keys': keys, 'user_data': CLOUD_INIT})
        print('created', s['name'])
    time.sleep(5)
    servers = {s['name']: s['id'] for s in api('GET', '/servers?label_selector=' + label_selector(plan))['servers']}
    for v in plan['volumes']:
        api('POST', '/volumes', {'name': v['name'], 'size': v['size_gb'], 'server': servers[v['server']],
                                 'labels': labels, 'format': 'ext4', 'automount': False})
        print('created', v['name'])
    status(plan)


def status(plan):
    sel = '?label_selector=' + label_selector(plan)
    for s in api('GET', '/servers' + sel)['servers']:
        priv = [n['ip'] for n in s['private_net']]
        print('%-18s %-8s %-7s %-15s %s' % (s['name'], s['status'], s['server_type']['name'],
                                          s['public_net']['ipv4']['ip'], ','.join(priv)))
    for v in api('GET', '/volumes' + sel)['volumes']:
        print('%-18s volume %dGB server=%s' % (v['name'], v['size'], v['server']))


def down(plan):
    sel = '?label_selector=' + label_selector(plan)
    for v in api('GET', '/volumes' + sel)['volumes']:
        if v['server']:
            api('POST', '/volumes/%d/actions/detach' % v['id'], {})
            time.sleep(3)
        api('DELETE', '/volumes/%d' % v['id'])
        print('deleted volume', v['name'])
    for s in api('GET', '/servers' + sel)['servers']:
        api('DELETE', '/servers/%d' % s['id'])
        print('deleted server', s['name'])
    time.sleep(10)
    for kind in ('firewalls', 'networks'):
        for r in api('GET', '/%s%s' % (kind, sel))[kind]:
            api('DELETE', '/%s/%d' % (kind, r['id']))
            print('deleted', kind[:-1], r['name'])


if __name__ == '__main__':
    cmd, plan = sys.argv[1], json.load(open(sys.argv[2]))
    if cmd == 'budget':
        print('approve with: --approved-eur=%d' % budget(plan))
    elif cmd == 'up':
        arg = next((a for a in sys.argv if a.startswith('--approved-eur=')), None)
        up(plan, int(arg.split('=')[1]) if arg else None)
    elif cmd == 'status':
        status(plan)
    elif cmd == 'down':
        down(plan)
    else:
        sys.exit(__doc__)
