# Run by /opt/platform/module-versions through `odoo shell`.
import json

env.cr.execute("SELECT to_regclass('ir_module_module') IS NOT NULL")  # noqa: F821
installed = {}
if env.cr.fetchone()[0]:  # noqa: F821
    env.cr.execute("SELECT name, latest_version FROM ir_module_module WHERE state = 'installed'")  # noqa: F821
    installed = dict(env.cr.fetchall())  # noqa: F821
print('MODULE_VERSIONS ' + json.dumps(installed, sort_keys=True))
