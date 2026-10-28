# Run by /opt/platform/print-report through `odoo shell`. Renders base's
# module reference report for `base` and prints what came out; changes nothing.
import hashlib
import json

report = env['ir.actions.report']  # noqa: F821
base = env.ref('base.module_base')  # noqa: F821
pdf, kind = report._render_qweb_pdf('base.ir_module_reference_print', base.ids)
pages = pdf.count(b'/Type /Page') - pdf.count(b'/Type /Pages') if kind == 'pdf' else 0
env.cr.rollback()  # noqa: F821
print('PRINT_REPORT ' + json.dumps({'ok': kind == 'pdf' and pdf.startswith(b'%PDF-') and pages >= 1,
                                    'kind': kind, 'bytes': len(pdf), 'pages': pages,
                                    'sha256': hashlib.sha256(pdf).hexdigest()}))
