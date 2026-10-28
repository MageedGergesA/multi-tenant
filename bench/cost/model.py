"""DOC-06 §7 cost model and §8 RC-2 decision rule.

    python3 model.py inputs.json

Prints price, cost, contribution and margin per RC-2 boundary and pilot size,
the break-even tenant count, and the §8 verdict.
"""
import json
import sys


def price(users, rc, staging_price=0.0):
    total = rc['base']
    for lower, upper, per_user in rc['bands']:
        top = users if upper is None else min(users, upper)
        if top > lower:
            total += (top - lower) * per_user
    return round(total + staging_price, 2)


def step(table, users):
    for upper, value in table:
        if upper is None or users <= upper:
            return value
    raise ValueError(users)


def missing(node, path=''):
    if isinstance(node, dict):
        for k, v in node.items():
            if not k.startswith('_'):
                yield from missing(v, '%s.%s' % (path, k) if path else k)
    elif node is None:
        yield path


def cost(users, tenants, i):
    m, fx = i['measured'], i['eur_usd_planning_rate']
    app = m['app_host_monthly_eur'] * fx / m['tenants_per_app_host']
    db = m['db_host_monthly_eur'] * fx / m['tenants_per_db_host']
    fixed = sum(i['fixed_monthly_eur'].values()) * fx / tenants
    gb = step(m['archive_gb_by_users'], users)
    s = i['storage']
    storage = gb * s['volume_eur_per_gb'] * fx + gb * s['l1_copies_retained'] * s['b2_usd_per_gb'] + s['l2_share_usd']
    ops = (i['ops']['backup_operator_monthly_usd'] / tenants
           + step(i['ops']['support_hours_by_users'], users) * i['ops']['support_hourly_usd'])
    return app + db + fixed + storage + i['mail_usd_per_tenant'] + ops


def main(path):
    i = json.load(open(path))
    gaps = list(missing(i))
    if gaps:
        sys.exit('Pending inputs (DOC-06 §7): ' + ', '.join(gaps))
    rc = i['rate_card']
    print('%6s %8s ' % ('users', 'price') + ' '.join('%22s' % ('%d tenants: cost/margin' % t) for t in i['tenant_counts']))
    verdict = True
    for u in i['boundaries']:
        p = price(u, rc)
        cells = []
        for t in i['tenant_counts']:
            c = cost(u, t, i)
            margin = (p - c) / p
            cells.append('%10.2f / %8.1f%%' % (c, margin * 100))
            if t == 50 and margin < i['target_margin']:
                verdict = False
        print('%6d %8.2f ' % (u, p) + ' '.join('%22s' % x for x in cells))
    for u in i['boundaries']:
        p = price(u, rc)
        breakeven = next((t for t in range(1, 1001) if cost(u, t, i) <= p), None)
        print('break-even at %3d users: %s tenants' % (u, breakeven if breakeven else '>1000'))
    print('RC-2 verdict (§8, margin >= %d%% at 50 tenants): %s'
          % (i['target_margin'] * 100, 'APPROVE' if verdict else 'REVISE BANDS'))


if __name__ == '__main__':
    main(sys.argv[1])
