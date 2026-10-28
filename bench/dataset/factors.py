# Run with `odoo shell -d <db> < factors.py` and BAND set in the environment.
# Prints the `--models` and `--factors` arguments for `odoo populate` so each
# model reaches the band's target volume (populate copies a model N times,
# reaching (N+1)x its size).
#
# PHASE=base (default) sizes the documents. PHASE=moves runs after it: the
# seed has ~1.6 moves per picking, so pickings alone leave stock moves at ~40%
# of target. Copying stock.move with stock.move.line in a separate run keeps
# each copy on its original picking (picking_id is not remapped because
# stock.picking isn't populated in that run) and remaps each line to its own
# move copy, i.e. pickings get more lines, each with its move lines.
import json
import math
import os

bands = json.load(open(os.environ['BANDS_FILE']))
band = bands[os.environ['BAND']]
if os.environ.get('PHASE', 'base') == 'moves':
    current = env['stock.move'].search_count([])  # noqa: F821
    # populate only takes whole factors; round to the nearest multiple so the
    # result lands within ±25% of target instead of up to 2x over.
    factor = max(0, round(band['stock_moves'] / max(current, 1)) - 1)
    print('POPULATE_ARGS=%s' % ('--models=stock.move,stock.move.line --factors=%d,%d' % (factor, factor)
                                 if factor else ''))
else:
    targets = {
        'res.partner': band['partners'],
        'product.template': band['products'],
        'sale.order': band['sale_orders'],
        'account.move': band['invoices'],
        'stock.picking': band['pickings'],
    }
    models, factors = [], []
    for model, target in targets.items():
        current = env[model].with_context(active_test=False).search_count([])  # noqa: F821
        factor = max(0, math.ceil(target / max(current, 1)) - 1)
        if factor:
            models.append(model)
            factors.append(str(factor))
    print('POPULATE_ARGS=%s' % ('--models=%s --factors=%s' % (','.join(models), ','.join(factors))
                                 if models else ''))
