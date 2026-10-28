"""DOC-06 §4 load model: personas issuing the JSON-RPC calls of the Odoo 19
web client. Request names start with the SLO class (read/write/pdf/heavy)
so results map straight onto the DOC-06 §5 pass lines.

    locust -f locustfile.py --host http://tenant:8069 \
        --users-file users.csv --db bench_s_eg
"""
import base64
import csv
import itertools
import random
import threading

from locust import HttpUser, between, events, task
from locust.exception import StopUser

_logins = None
_lock = threading.Lock()


@events.init_command_line_parser.add_listener
def _args(parser):
    parser.add_argument('--users-file', default='users.csv')
    parser.add_argument('--db', required=True)
    parser.add_argument('--think-mean', type=float, default=20.0,
                        help='Mean think time in seconds (exponential)')


def _next_login(env):
    global _logins
    with _lock:
        if _logins is None:
            with open(env.parsed_options.users_file) as f:
                _logins = itertools.cycle(list(csv.DictReader(f)))
        return next(_logins)


class OdooUser(HttpUser):
    abstract = True

    def wait_time(self):
        return random.expovariate(1.0 / self.environment.parsed_options.think_mean)

    # -- JSON-RPC helpers -------------------------------------------------

    def rpc(self, name, url, params):
        payload = {'jsonrpc': '2.0', 'method': 'call', 'id': random.randint(1, 10**9), 'params': params}
        with self.client.post(url, json=payload, name=name, catch_response=True) as resp:
            try:
                body = resp.json()
            except ValueError:
                resp.failure('non-JSON response %s' % resp.status_code)
                return None
            if 'error' in body:
                resp.failure(body['error'].get('data', {}).get('name') or body['error'].get('message'))
                return None
            return body.get('result')

    def call(self, name, model, method, *args, **kwargs):
        kwargs.setdefault('context', self.ctx)
        return self.rpc(name, '/web/dataset/call_kw/%s/%s' % (model, method),
                        {'model': model, 'method': method, 'args': list(args), 'kwargs': kwargs})

    def button(self, name, model, method, ids):
        return self.rpc(name, '/web/dataset/call_button/%s/%s' % (model, method),
                        {'model': model, 'method': method, 'args': [ids], 'kwargs': {'context': self.ctx}})

    def ids(self, model, domain, limit=200):
        res = self.call('setup', model, 'search', domain, limit=limit) or []
        return res

    # -- session ----------------------------------------------------------

    def on_start(self):
        cred = _next_login(self.environment)
        res = self.rpc('setup:login', '/web/session/authenticate', {
            'db': self.environment.parsed_options.db,
            'login': cred['login'], 'password': cred['password']})
        if not res:
            raise StopUser()
        self.uid = res['uid']
        self.ctx = dict(res.get('user_context') or {})
        self.partner_ids = self.ids('res.partner', [('customer_rank', '>', 0)]) or self.ids('res.partner', [])
        self.product_ids = self.ids('product.product', [('sale_ok', '=', True), ('tracking', '=', 'none')])
        self.invoice_ids = self.ids('account.move', [('move_type', '=', 'out_invoice'), ('state', '=', 'posted')])
        self.order_ids = self.ids('sale.order', [('state', '=', 'sale')])

    def lines(self, n):
        return [[0, 0, {'product_id': random.choice(self.product_ids),
                        'product_uom_qty': random.randint(1, 20)}] for _ in range(n)]


class Sales(OdooUser):
    weight = 35

    @task(4)
    def search_customers(self):
        self.call('read:partner search', 'res.partner', 'web_search_read',
                  [('name', 'ilike', random.choice('aeiorstn'))],
                  {'display_name': {}, 'email': {}, 'phone': {}}, limit=80)

    @task(4)
    def order_list(self):
        self.call('read:sale.order list', 'sale.order', 'web_search_read',
                  [('state', 'in', ['sale', 'draft'])],
                  {'name': {}, 'partner_id': {'fields': {'display_name': {}}}, 'date_order': {},
                   'amount_total': {}, 'state': {}}, limit=80, order='date_order desc')

    @task(2)
    def quotation(self):
        partner = random.choice(self.partner_ids)
        self.call('write:sale.order onchange', 'sale.order', 'onchange', [],
                  {'partner_id': partner}, ['partner_id'],
                  {'partner_id': {}, 'pricelist_id': {}, 'payment_term_id': {}})
        res = self.call('write:sale.order save', 'sale.order', 'web_save', [],
                        {'partner_id': partner, 'order_line': self.lines(5)},
                        {'name': {}, 'amount_total': {}})
        if res:
            self.button('write:sale.order confirm', 'sale.order', 'action_confirm', [res[0]['id']])
            self.call('write:message_post', 'sale.order', 'message_post', [res[0]['id']],
                      body='Benchmark follow-up', message_type='comment')


class Accounting(OdooUser):
    weight = 25

    @task(4)
    def invoice_list(self):
        self.call('read:account.move list', 'account.move', 'web_search_read',
                  [('move_type', '=', 'out_invoice')],
                  {'name': {}, 'partner_id': {'fields': {'display_name': {}}}, 'invoice_date': {},
                   'amount_total': {}, 'payment_state': {}}, limit=80, order='invoice_date desc')

    @task(2)
    def post_and_pay(self):
        res = self.call('write:invoice save', 'account.move', 'web_save', [],
                        {'move_type': 'out_invoice', 'partner_id': random.choice(self.partner_ids),
                         'invoice_line_ids': [[0, 0, {'product_id': random.choice(self.product_ids),
                                                      'quantity': random.randint(1, 5)}] for _ in range(3)]},
                        {'name': {}}, context=dict(self.ctx, default_move_type='out_invoice'))
        if not res:
            return
        move_id = res[0]['id']
        self.button('write:invoice post', 'account.move', 'action_post', [move_id])
        ctx = dict(self.ctx, active_model='account.move', active_ids=[move_id])
        wiz = self.call('write:payment register', 'account.payment.register', 'web_save', [], {}, {}, context=ctx)
        if wiz:
            self.rpc('write:payment create', '/web/dataset/call_button/account.payment.register/action_create_payments',
                     {'model': 'account.payment.register', 'method': 'action_create_payments',
                      'args': [[wiz[0]['id']]], 'kwargs': {'context': ctx}})

    @task(1)
    def receivable_by_partner(self):
        # CE substitute for the Enterprise aged receivable report.
        self.call('heavy:receivable group', 'account.move.line', 'web_read_group',
                  [('account_id.account_type', '=', 'asset_receivable'), ('reconciled', '=', False)],
                  ['partner_id'], ['amount_residual:sum'], limit=80)

    @task(1)
    def invoice_pdf(self):
        if self.invoice_ids:
            self.client.get('/report/pdf/account.report_invoice/%d' % random.choice(self.invoice_ids),
                            name='pdf:invoice single')


class Warehouse(OdooUser):
    weight = 20

    @task(3)
    def stock_quants(self):
        self.call('read:stock.quant list', 'stock.quant', 'web_search_read',
                  [('location_id.usage', '=', 'internal')],
                  {'product_id': {'fields': {'display_name': {}}}, 'location_id': {'fields': {'display_name': {}}},
                   'quantity': {}}, limit=80)

    @task(3)
    def product_search(self):
        self.call('read:product search', 'product.product', 'web_name_search',
                  random.choice('aeiorstn'), {'display_name': {}}, limit=8)

    @task(2)
    def receipt(self):
        picking_type = self.ids('stock.picking.type', [('code', '=', 'incoming')], limit=1)
        if not picking_type:
            return
        res = self.call('write:receipt save', 'stock.picking', 'web_save', [],
                        {'picking_type_id': picking_type[0], 'partner_id': random.choice(self.partner_ids),
                         'move_ids': [[0, 0, {'product_id': random.choice(self.product_ids),
                                              'product_uom_qty': random.randint(1, 50)}] for _ in range(3)]},
                        {'name': {}})
        if res:
            pid = res[0]['id']
            self.button('write:receipt confirm', 'stock.picking', 'action_confirm', [pid])
            self.button('write:receipt validate', 'stock.picking', 'button_validate', [pid])


class Manager(OdooUser):
    weight = 10

    @task
    def sales_pivot(self):
        self.call('heavy:sales pivot 12m', 'sale.order', 'formatted_read_group',
                  [('state', '=', 'sale')], ['date_order:month', 'partner_id'], ['amount_total:sum'])

    @task
    def invoice_graph(self):
        self.call('heavy:invoice graph 12m', 'account.move', 'formatted_read_group',
                  [('move_type', '=', 'out_invoice'), ('state', '=', 'posted')],
                  ['invoice_date:month'], ['amount_total_signed:sum'])


class Admin(OdooUser):
    weight = 10

    @task(1)
    def csv_import(self):
        rows = ['name,email'] + ['Bench Import %d,import%d@example.test' % (random.randint(1, 10**9), i)
                                 for i in range(100)]
        rec = self.call('heavy:import create', 'base_import.import', 'create',
                        {'res_model': 'res.partner', 'file': base64.b64encode('\n'.join(rows).encode()).decode(),
                         'file_name': 'bench.csv', 'file_type': 'text/csv'})
        if rec:
            rec_id = rec[0] if isinstance(rec, list) else rec
            self.call('heavy:import 100 lines', 'base_import.import', 'execute_import', [rec_id],
                      ['name', 'email'], ['name', 'email'],
                      {'quoting': '"', 'separator': ',', 'has_headers': True, 'encoding': 'utf-8'})

    @task(1)
    def pdf_batch(self):
        if len(self.invoice_ids) >= 10:
            ids = ','.join(str(i) for i in random.sample(self.invoice_ids, 10))
            self.client.get('/report/pdf/account.report_invoice/%s' % ids, name='heavy:invoice pdf x10')

    @task(2)
    def chatter_attachment(self):
        if not self.order_ids:
            return
        order = random.choice(self.order_ids)
        att = self.call('write:attachment create', 'ir.attachment', 'create',
                        {'name': 'bench.txt', 'datas': base64.b64encode(b'x' * 50_000).decode(),
                         'res_model': 'sale.order', 'res_id': order})
        if att:
            att_id = att[0] if isinstance(att, list) else att
            self.call('write:message_post attachment', 'sale.order', 'message_post', [order],
                      body='Benchmark attachment', attachment_ids=[att_id])
