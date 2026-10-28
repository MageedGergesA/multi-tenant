"""Row counts of the key tables the weekly deep drill compares (DOC-05 §5):
read in the backup's snapshot by backup_dump.py, and in the restored copy by
restore_load.py before neutralize changes anything. A table a tenant doesn't
have (module not installed) counts as None."""
from psycopg2 import sql

KEY_TABLES = ('res_company', 'res_users', 'res_partner', 'ir_module_module', 'ir_attachment', 'mail_message',
              'product_template', 'sale_order', 'account_move', 'account_move_line')


def row_counts(cr):
    out = {}
    for table in KEY_TABLES:
        cr.execute('SELECT to_regclass(%s)', ('public.' + table,))
        if cr.fetchone()[0] is None:
            out[table] = None
            continue
        cr.execute(sql.SQL('SELECT count(*) FROM {}').format(sql.Identifier('public', table)))
        out[table] = cr.fetchone()[0]
    return out
