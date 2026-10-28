"""DOC-06 §4 realism check and E8: real headless browsers holding the Odoo
bus websocket while the Locust load runs.

    python browsers.py --host http://127.0.0.1:8080 --db bench_s_eg \
        --users-file users.csv --browsers 2 --duration 30m --out evidence/runs/X/raw

Each browser logs in, loads the full web client (assets, SharedWorker bus)
and, after an exponential think time, mentions the next browser's user in
the chatter of a random sale order. The receiving page's bus_service reports
the `mail.message/inbox` notification; latency is measured from the moment
the sender's request starts to the moment the receiving page gets it
(user-perceived "click to toast"), all on this host's clock.

The bus socket lives in a SharedWorker, which Playwright's page websocket
events don't see, so delivery and disconnects are observed through the
page's bus_service (BUS:CONNECT / DISCONNECT / RECONNECTING / RECONNECT).
"""
import argparse
import asyncio
import csv
import json
import math
import random
import time
from pathlib import Path

from playwright.async_api import async_playwright

SLO = (2.0, 5.0)  # DOC-06 §5 bus notification: p95, p99 seconds
GRACE = 15  # seconds to wait for in-flight notifications after the run

HOOK = """() => {
    const bus = odoo.__WOWL_DEBUG__.root.env.services.bus_service;
    bus.subscribe("mail.message/inbox", (payload) => window.benchRecv(payload.message_id, Date.now()));
    for (const ev of ["BUS:CONNECT", "BUS:DISCONNECT", "BUS:RECONNECTING", "BUS:RECONNECT"]) {
        bus.addEventListener(ev, () => window.benchEvent(ev, Date.now()));
    }
}"""

RPC = """async ([url, params]) => {
    const t0 = Date.now();
    const r = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({jsonrpc: "2.0", method: "call", id: 1, params})});
    let j = {};
    try { j = await r.json(); } catch (e) { j = {error: {message: "non-JSON " + r.status}}; }
    return {t0, t1: Date.now(), status: r.status, result: j.result,
            error: j.error && ((j.error.data && j.error.data.name) || j.error.message)};
}"""


def seconds(text):
    unit = {'s': 1, 'm': 60, 'h': 3600}
    return int(text[:-1]) * unit[text[-1]] if text[-1] in unit else int(text)


def pct(values, p):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p / 100 * len(ordered)) - 1)]


class Browser:
    def __init__(self, idx, login, password):
        self.idx, self.login, self.password = idx, login, password
        self.received = {}  # message_id -> receive time (ms)
        self.events = []  # (bus event, ms)
        self.http_5xx = []
        self.page_errors = []

    async def start(self, browser, host, db):
        self.context = await browser.new_context()
        res = await self.context.request.post(host + '/web/session/authenticate', data={
            'jsonrpc': '2.0', 'method': 'call', 'id': 1,
            'params': {'db': db, 'login': self.login, 'password': self.password}})
        info = (await res.json()).get('result')
        if not info:
            raise RuntimeError('login failed for %s' % self.login)
        self.page = page = await self.context.new_page()
        page.on('response', lambda r: r.status >= 500 and self.http_5xx.append((r.status, r.url)))
        page.on('pageerror', lambda e: self.page_errors.append(str(e)))
        await page.expose_function('benchRecv', lambda mid, ts: self.received.setdefault(mid, ts))
        await page.expose_function('benchEvent', lambda ev, ts: self.events.append((ev, ts)))
        await page.goto(host + '/odoo/discuss', wait_until='load', timeout=120_000)
        await page.wait_for_function('() => odoo.__WOWL_DEBUG__?.root?.env?.services?.bus_service',
                                     timeout=120_000)
        await page.evaluate(HOOK)
        users = await self.rpc('res.users', 'read', [[info['uid']], ['partner_id']])
        self.partner_id = users['result'][0]['partner_id'][0]
        orders = await self.rpc('sale.order', 'search', [[]], limit=50)
        self.order_ids = orders['result'] or []

    async def rpc(self, model, method, args, **kwargs):
        return await self.page.evaluate(RPC, ['/web/dataset/call_kw/%s/%s' % (model, method),
                                              {'model': model, 'method': method, 'args': args,
                                               'kwargs': kwargs}])

    async def mention(self, target):
        res = await self.rpc('sale.order', 'message_post', [random.choice(self.order_ids)],
                             body='Benchmark ping for %s' % target.login,
                             partner_ids=[target.partner_id], message_type='comment',
                             subtype_xmlid='mail.mt_comment')
        mid = res['result']
        if isinstance(mid, list):
            mid = mid[0] if mid else None
        return {'sender': self.login, 'receiver': target.login, 'receiver_idx': target.idx,
                'message_id': mid, 't0': res['t0'], 't1': res['t1'], 'status': res['status'],
                'error': res['error']}


async def drive(me, target, until, think_mean, sends):
    await asyncio.sleep(random.uniform(0, think_mean))  # desynchronise the browsers
    while time.time() < until:
        sends.append(await me.mention(target))
        await asyncio.sleep(random.expovariate(1.0 / think_mean))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', required=True)
    ap.add_argument('--db', required=True)
    ap.add_argument('--users-file', required=True)
    ap.add_argument('--browsers', type=int, default=2)
    ap.add_argument('--duration', default='30m')
    ap.add_argument('--think-mean', type=float, default=20.0)
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args()
    if a.browsers < 2:
        raise SystemExit('need at least 2 browsers to exchange messages')

    # Take logins from the end of the file so the browsers are the users
    # least likely to be shared with Locust's round-robin.
    creds = list(csv.DictReader(open(a.users_file)))[::-1]
    a.out.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as pw:
        chromium = await pw.chromium.launch()
        users = [Browser(i, creds[i % len(creds)]['login'], creds[i % len(creds)]['password'])
                 for i in range(a.browsers)]
        await asyncio.gather(*(u.start(chromium, a.host, a.db) for u in users))
        until = time.time() + seconds(a.duration)
        sends = []
        await asyncio.gather(*(drive(u, users[(u.idx + 1) % len(users)], until, a.think_mean, sends)
                               for u in users))
        await asyncio.sleep(GRACE)
        await chromium.close()

    rows, latencies, lost = [], [], 0
    for s in sends:
        recv = users[s['receiver_idx']].received.get(s['message_id']) if s['message_id'] else None
        latency = (recv - s['t0']) / 1000 if recv else None
        if latency is None:
            lost += 1
        else:
            latencies.append(latency)
        rows.append([s['t0'], s['sender'], s['receiver'], s['message_id'], s['status'], s['error'] or '',
                     round((s['t1'] - s['t0']) / 1000, 3), latency if latency is None else round(latency, 3)])
    with open(a.out / 'bus_latency.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['t0_ms', 'sender', 'receiver', 'message_id', 'http_status', 'error', 'post_s', 'bus_s'])
        w.writerows(rows)

    events = {}
    for u in users:
        for ev, _ts in u.events:
            events[ev] = events.get(ev, 0) + 1
    p95, p99 = pct(latencies, 95), pct(latencies, 99)
    disconnects = events.get('BUS:DISCONNECT', 0) + events.get('BUS:RECONNECTING', 0)
    http_5xx = [e for u in users for e in u.http_5xx]
    page_errors = [e for u in users for e in u.page_errors]
    summary = {
        'browsers': a.browsers, 'sent': len(sends), 'received': len(latencies), 'lost': lost,
        'post_errors': sum(1 for s in sends if s['error'] or s['status'] != 200),
        'p50': pct(latencies, 50), 'p95': p95, 'p99': p99, 'max': max(latencies, default=None),
        'bus_events': events, 'http_5xx': len(http_5xx), 'http_5xx_sample': http_5xx[:10],
        'page_errors': len(page_errors), 'page_errors_sample': page_errors[:10],
        # E8 pass line: SLO latency, nothing lost, no websocket drops or 5xx.
        'pass': bool(latencies) and p95 <= SLO[0] and p99 <= SLO[1] and lost == 0
                and disconnects == 0 and not http_5xx,
    }
    (a.out / 'bus_summary.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ('sent', 'received', 'lost', 'p95', 'p99', 'pass')}))


if __name__ == '__main__':
    asyncio.run(main())
