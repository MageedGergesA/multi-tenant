# Run with `odoo shell -d <db> < finish.py`. Archives demo users, creates the
# band's benchmark users and the attachment volume (DOC-06 §3 steps 3–4).
# Writes the logins to $USERS_FILE for the load generator; these are test
# credentials for a throwaway benchmark database only.
import csv
import json
import os
import random
import secrets

bands = json.load(open(os.environ['BANDS_FILE']))
band = bands[os.environ['BAND']]
rng = random.Random(int(os.environ.get('SEED', '19')))

# 3. Archive seed users (keep admin, id 2) and create N internal users.
Users = env['res.users'].with_context(no_reset_password=True)  # noqa: F821
Users.search([('id', 'not in', (1, 2)), ('share', '=', False)]).write({'active': False})
groups = [env.ref(xmlid) for xmlid in (  # noqa: F821
    'base.group_user',
    'sales_team.group_sale_salesman_all_leads',
    'account.group_account_invoice',
    'stock.group_stock_user',
    'purchase.group_purchase_user',
)]
rows = []
for i in range(1, band['users'] + 1):
    login = 'bench%03d' % i
    password = secrets.token_urlsafe(18)
    user = Users.search([('login', '=', login)])
    if not user:
        user = Users.create({'name': 'Bench User %03d' % i, 'login': login,
                             'group_ids': [(6, 0, [g.id for g in groups])]})
    else:
        user.group_ids = [(4, g.id) for g in groups]
    # Chatter mentions reach the user's browser over the bus (DOC-06 §5, E8)
    # only with "In Odoo" notifications; the default `email` queues a mail.
    # Set the field, not the group: its inverse unlinks the group on create.
    user.notification_type = 'inbox'
    user.password = password
    rows.append((login, password))
with open(os.environ['USERS_FILE'], 'w', newline='') as f:
    csv.writer(f).writerows([('login', 'password'), *rows])

# Populate copies pickings with their moves but not move lines
# (stock.move.move_line_ids is copy=False), leaving most done moves without
# the lines that Moves History and stock reports read. Give each one a single
# done line mirroring the move.
env.cr.execute("""
    INSERT INTO stock_move_line (company_id, date, location_id, location_dest_id, product_id, product_uom_id,
                                 quantity, quantity_product_uom, move_id, picking_id, state, picked,
                                 create_uid, create_date, write_uid, write_date)
    SELECT m.company_id, m.date, m.location_id, m.location_dest_id, m.product_id, m.product_uom,
           COALESCE(NULLIF(m.quantity, 0), m.product_uom_qty), m.product_qty, m.id, m.picking_id, 'done', true,
           1, now() at time zone 'utc', 1, now() at time zone 'utc'
      FROM stock_move m
     WHERE m.state = 'done'
       AND NOT EXISTS (SELECT 1 FROM stock_move_line l WHERE l.move_id = m.id)
""")  # noqa: F821
print('MOVE_LINES_BACKFILLED', env.cr.rowcount)  # noqa: F821
env.cr.commit()  # noqa: F821

# 4. Attachments: half random bytes (incompressible), half repeated text
# (compressible), so filestore size and backup compression are realistic.
targets = []
for model in ('res.partner', 'sale.order', 'account.move'):
    ids = env[model].search([], limit=5000).ids  # noqa: F821
    targets += [(model, i) for i in ids]
Attachment = env['ir.attachment']  # noqa: F821
existing = Attachment.search_count([('name', '=like', 'bench_%')])
size = band['attachment_kb'] * 1024
for n in range(existing, band['attachments']):
    model, res_id = rng.choice(targets)
    raw = os.urandom(size // 2) + (b'Odoo benchmark attachment line.\n' * (size // 64))
    Attachment.create({'name': 'bench_%06d.bin' % n, 'raw': raw,
                       'res_model': model, 'res_id': res_id})
    if n % 500 == 0:
        env.cr.commit()  # noqa: F821
env.cr.commit()  # noqa: F821
print('USERS', len(rows), 'ATTACHMENTS', Attachment.search_count([('name', '=like', 'bench_%')]))
