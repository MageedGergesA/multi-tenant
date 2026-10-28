# DOC-04 §5.4 `platform_defaults(scope)`: fixed script run through
# `odoo shell` by /opt/platform/platform-defaults. Prints the read-back
# values as one JSON line (the step's evidence) and commits.
#   both scopes: report.url -> gevent port in the container (BENCH-00 F-2/F-3)
#   create:      the platform-created tenant admin gets its password (from a
#                secret file, never an argument), language, "In Odoo"
#                notifications (DOC-04 §5.5), and the company its country and
#                currency. Customer-created users are never touched.
import json
import os

import pytz

REPORT_URL = 'http://127.0.0.1:8072'
scope = os.environ['PLATFORM_SCOPE']
assert scope in ('create', 'copy'), scope

ICP = env['ir.config_parameter'].sudo()  # noqa: F821
ICP.set_param('report.url', REPORT_URL)
evidence = {'scope': scope, 'report.url': ICP.get_param('report.url')}
ok = evidence['report.url'] == REPORT_URL
if scope == 'create':
    lang, country_code = os.environ['PLATFORM_LANG'], os.environ['PLATFORM_COUNTRY']
    with open(os.environ['PLATFORM_ADMIN_PASSWORD_FILE']) as f:
        password = f.read().strip()
    assert len(password) >= 16, 'tenant admin password too short'
    admin = env.ref('base.user_admin')  # noqa: F821
    # `notification_type`: set the field, not the group; its inverse manages the group.
    admin.write({'password': password, 'lang': lang})
    has_mail = 'notification_type' in admin._fields   # only when `mail` is installed
    if has_mail:
        admin.notification_type = 'inbox'
    country = env['res.country'].search([('code', '=', country_code)], limit=1)  # noqa: F821
    company = env['res.company'].browse(1)  # noqa: F821
    company.write({'country_id': country.id, 'currency_id': country.currency_id.id or company.currency_id.id})
    zones = pytz.country_timezones.get(country_code, [])
    if len(zones) == 1:
        admin.tz = zones[0]
    # The password itself never goes into evidence; only that the default no longer works.
    env.cr.execute("SELECT password FROM res_users WHERE id = %s", [admin.id])  # noqa: F821
    stored = env.cr.fetchone()[0]  # noqa: F821
    default_works = admin._crypt_context().verify('admin', stored)
    evidence.update({'admin.notification_type': admin.notification_type if has_mail else None,
                     'admin.lang': admin.lang,
                     'admin.default_password_rejected': not default_works,
                     'company.country': company.country_id.code, 'company.currency': company.currency_id.name})
    ok = ok and (not has_mail or admin.notification_type == 'inbox') and admin.lang == lang and not default_works \
        and company.country_id.code == country_code
env.cr.commit()  # noqa: F821
print('PLATFORM_DEFAULTS ' + json.dumps(dict(evidence, ok=ok)))
