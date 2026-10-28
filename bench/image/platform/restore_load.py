"""DOC-04 §6.9 steps 4-5, run as the copy's tenant inside its image (one-shot
`restore-load`). Restores /backup/dump.pgc into the copy's database in one
transaction, copies /backup/filestore into the copy's data_dir, verifies every
file against files.json, counts the key tables (row_counts.py) before
anything else touches the data, and prints one `RESTORE_LOAD {json}` line."""
import configparser
import hashlib
import json
import os
import subprocess
import sys

import psycopg2

from row_counts import row_counts

conf = configparser.ConfigParser(interpolation=None)
conf.read(sys.argv[1])
o = conf['options']
db = o['db_name']
env = dict(os.environ, PGHOST=o['db_host'], PGPORT=o['db_port'], PGUSER=o['db_user'],
           PGSSLMODE=o.get('db_sslmode', 'prefer'))
r = subprocess.run(['pg_restore', '--no-owner', '--no-privileges', '--no-comments', '--exit-on-error',
                    '--single-transaction', '-d', db, '/backup/dump.pgc'], env=env, capture_output=True, text=True)
if r.returncode:
    sys.stderr.write(r.stderr[-4000:])
    print('RESTORE_LOAD ' + json.dumps({'ok': False, 'stage': 'pg_restore'}))
    sys.exit(1)

cn = psycopg2.connect(host=o['db_host'], port=o['db_port'], user=o['db_user'], dbname=db,
                      sslmode=o.get('db_sslmode', 'prefer'))
counts = row_counts(cn.cursor())
cn.close()

with open('/backup/files.json') as f:
    files = json.load(f)
dest = os.path.join(o['data_dir'], 'filestore', db)
verified, bad = 0, []
for fname, sha1 in files.items():
    src = os.path.join('/backup/filestore', fname)
    target = os.path.join(dest, fname)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    h = hashlib.sha1()
    with open(src, 'rb') as f, open(target, 'wb') as g:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
            g.write(chunk)
    if h.hexdigest() == sha1:
        verified += 1
    else:
        bad.append(fname)
print('RESTORE_LOAD ' + json.dumps({'ok': not bad, 'files_verified': verified, 'files_bad': len(bad),
                                     'row_counts': counts}))
sys.exit(1 if bad else 0)
