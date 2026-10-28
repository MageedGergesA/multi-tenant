"""DOC-04 §6.8 steps 1-5, run as the tenant inside its own image (one-shot
`backup-dump`). Writes /backup/{dump.pgc,filestore/,files.json} and prints one
`BACKUP_DUMP {json}` line.

1. Guard: a REPEATABLE READ transaction as the tenant role takes
   LOCK ir_attachment IN SHARE UPDATE EXCLUSIVE MODE. Odoo's _gc_file_store
   needs SHARE with a 10 s lock_timeout, so it gives up instead of deleting
   files while the guard is held.
2. pg_dump -Fc runs on the guard's exported snapshot.
3-4. The referenced (store_fname, checksum) list and the key tables' row
   counts (row_counts.py) are read in the same snapshot; every referenced
   file is copied and its SHA-1 checked.
5. ROLLBACK releases the guard.
"""
import configparser
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import psycopg2

from row_counts import row_counts

conf = configparser.ConfigParser(interpolation=None)
conf.read(sys.argv[1])
o = conf['options']
db = o['db_name']
dsn = dict(host=o['db_host'], port=o['db_port'], user=o['db_user'], dbname=db, sslmode=o.get('db_sslmode', 'prefer'))
src = os.path.join(o['data_dir'], 'filestore', db)
out = '/backup'

cn = psycopg2.connect(**dsn)
cn.set_session(isolation_level='REPEATABLE READ')
cr = cn.cursor()
cr.execute("SET lock_timeout = '15min'")
cr.execute('LOCK ir_attachment IN SHARE UPDATE EXCLUSIVE MODE')
cr.execute('SELECT pg_export_snapshot(), now()')
snapshot, snapshot_time = cr.fetchone()
env = dict(os.environ, PGHOST=dsn['host'], PGPORT=dsn['port'], PGUSER=dsn['user'], PGSSLMODE=dsn['sslmode'])
subprocess.run(['pg_dump', '-Fc', '--snapshot', snapshot, '-f', os.path.join(out, 'dump.pgc'), db],
               check=True, env=env)
cr.execute('SELECT DISTINCT store_fname, checksum FROM ir_attachment WHERE store_fname IS NOT NULL')
referenced = cr.fetchall()
counts = row_counts(cr)

files, missing, mismatched = {}, [], []
for fname, checksum in referenced:
    path = os.path.join(src, fname)
    if os.path.realpath(path) != path or not os.path.isfile(path):
        missing.append(fname)
        continue
    h = hashlib.sha1()
    target = os.path.join(out, 'filestore', fname)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(path, 'rb') as f, open(target, 'wb') as g:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
            g.write(chunk)
    if h.hexdigest() != checksum:
        mismatched.append(fname)
    files[fname] = h.hexdigest()
cn.rollback()  # step 5: release the guard
cn.close()

with open(os.path.join(out, 'files.json'), 'w') as f:
    json.dump(files, f, sort_keys=True)
h = hashlib.sha256()
with open(os.path.join(out, 'dump.pgc'), 'rb') as f:
    for chunk in iter(lambda: f.read(1 << 20), b''):
        h.update(chunk)
print('BACKUP_DUMP ' + json.dumps({
    'snapshot_time': snapshot_time.astimezone(timezone.utc).isoformat(), 'gc_guard_held': True,
    'referenced_files': len(referenced), 'missing_files': len(missing), 'checksum_mismatches': len(mismatched),
    'dump_sha256': h.hexdigest(),
    'files_sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest(),
    'missing_sample': missing[:10], 'row_counts': counts}))
