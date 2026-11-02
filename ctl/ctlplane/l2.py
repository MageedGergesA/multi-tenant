"""The L2 layer from ctl-1's side (DOC-05 §2, §3.1, §8): db-1 pushes pgBackRest
backups and WAL to bucket B with a key that can't delete; ctl-1 holds the key
that can, runs `expire` (two full cycles) and reads what the repository holds,
for the alerts: the newest full, the newest full or differential, and when the
newest WAL segment was stored. Everything goes through pgBackRest (`info`,
`repo-ls`, `expire`), configured on ctl-1 for the same stanza and repository;
its key and the repository's cipher pass come from ctl's secrets (SOPS), as
pgBackRest's environment, never its config file.
"""
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone

log = logging.getLogger(__name__)

EXPIRE_EVERY = 24 * 3600
TIMEOUT = 600
# pgBackRest's locks are local files, so db-1's backup and ctl-1's expire don't exclude each other;
# an expire that loads backup.info before a backup completes and saves it after would drop that
# backup and then remove its files as unlisted. Expire runs only in hours away from db-1's
# schedule (01:00 UTC), and never while a backup directory not yet in backup.info was written to
# recently (a backup in progress; an older one is abandoned, and expire may remove it).
EXPIRE_HOURS = (10, 22)
RUNNING_FOR = 12 * 3600
LABEL = re.compile(r'^\d{8}-\d{6}F(_\d{8}-\d{6}[DI])?$')


class L2Error(Exception):
    pass


def _at(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc) if epoch is not None else None


def summarize(info: dict, listing: dict | None) -> dict:
    """From `info --output=json` (one stanza) and `repo-ls --output=json` of the newest
    segment's directory: what the alerts need."""
    status = info.get('status') or {}
    if status.get('code') != 0:
        raise L2Error('stanza %s: %s' % (info.get('name'), status.get('message')))
    # Only the cluster now in use: after a stanza-upgrade, the previous generation's backups can't
    # restore it, so they mustn't keep the backup alerts quiet.
    current = current_db(info)
    good = [b for b in info.get('backup') or [] if not b.get('error') and current is not None
            and (b.get('database') or {}).get('id') == current]
    stops = lambda kinds: [b['timestamp']['stop'] for b in good if b['type'] in kinds]  # noqa: E731
    out = {'full_at': max(stops(('full',)), default=None), 'backup_at': max(stops(('full', 'diff')), default=None),
           'wal_at': None, 'wal_segment': None}
    archive = newest_archive(info)
    if archive and archive.get('max'):
        out['wal_segment'] = archive['max']
        # Stored as <segment>-<sha1>[.ext]; `.backup` and `.history` files aren't segments.
        times = [v['time'] for name, v in (listing or {}).items()
                 if v.get('type') == 'file' and name.startswith(archive['max'] + '-')]
        out['wal_at'] = max(times, default=None)
    return out


def current_db(info: dict) -> int | None:
    """The database id of the cluster now in use: the highest (a stanza-upgrade adds one)."""
    ids = [d['id'] for d in info.get('db') or []] or [a['database']['id'] for a in info.get('archive') or []]
    return max(ids, default=None)


def newest_archive(info: dict) -> dict | None:
    """The archive of the cluster now in use."""
    current = current_db(info)
    return next((a for a in info.get('archive') or [] if a['database']['id'] == current), None)


class L2:
    def __init__(self, store, *, stanza='main', pgbackrest=('pgbackrest',), key=None, cipher_pass=None,
                 expire_every=EXPIRE_EVERY, expire_hours=EXPIRE_HOURS, clock=time.time, run=subprocess.run):
        """`key`: bucket B's key that can delete ({key_id, secret}); `cipher_pass`: the repository's."""
        self.store = store
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        if key:
            self.env.update(PGBACKREST_REPO1_S3_KEY=key['key_id'], PGBACKREST_REPO1_S3_KEY_SECRET=key['secret'])
        if cipher_pass:
            self.env['PGBACKREST_REPO1_CIPHER_PASS'] = cipher_pass
        self.stanza = stanza
        self.pgbackrest = list(pgbackrest)
        self.expire_every = expire_every
        self.expire_hours = expire_hours
        self.clock = clock
        self.run = run

    def _cmd(self, *args) -> str:
        try:
            done = self.run([*self.pgbackrest, '--stanza=%s' % self.stanza, *args], capture_output=True, text=True,
                            timeout=TIMEOUT, env=self.env)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise L2Error('pgbackrest %s: %s' % (args[-1], type(e).__name__)) from None
        if done.returncode != 0:
            # pgBackRest's own message (it doesn't print keys or the cipher pass).
            raise L2Error('pgbackrest %s (%d): %s' % (args[-1], done.returncode, done.stderr.strip()[-300:]))
        return done.stdout

    def _json(self, *args):
        try:
            return json.loads(self._cmd(*args))
        except ValueError:
            raise L2Error('pgbackrest %s: not JSON' % args[-1]) from None

    def _info(self) -> dict:
        info = self._json('--output=json', 'info')
        if not isinstance(info, list) or len(info) != 1:
            raise L2Error('pgbackrest info: not one stanza')
        return info[0]

    def running_backups(self, info, now) -> list[str]:
        """Backup directories in the repository that backup.info doesn't list yet and that were
        written to within RUNNING_FOR: backups in progress (on db-1, beyond ctl-1's locks)."""
        listed = {b['label'] for b in info.get('backup') or []}
        found = self._json('repo-ls', '--output=json', 'backup/%s' % self.stanza)
        out = []
        for name, entry in sorted(found.items()):
            if entry.get('type') != 'path' or not LABEL.match(name) or name in listed:
                continue
            inside = self._json('repo-ls', '--output=json', 'backup/%s/%s' % (self.stanza, name))
            newest = max((v.get('time', 0) for v in inside.values() if v.get('type') == 'file'), default=0)
            if now - newest < RUNNING_FOR:
                out.append(name)
        return out

    def may_expire(self, now) -> str | None:
        """Why expire must wait now, or None."""
        hour = datetime.fromtimestamp(now, timezone.utc).hour
        if not self.expire_hours[0] <= hour < self.expire_hours[1]:
            return 'outside %02d:00-%02d:00 UTC' % self.expire_hours
        running = self.running_backups(self._info(), now)
        return 'backup in progress: %s' % ', '.join(running) if running else None

    def read(self) -> dict:
        info = self._info()
        archive = newest_archive(info)
        listing = None
        if archive and archive.get('max'):
            listing = self._json('repo-ls', '--output=json',
                                 'archive/%s/%s/%s' % (self.stanza, archive['id'], archive['max'][:16]))
        return summarize(info, listing)

    def run_once(self):
        now = self.clock()
        with self.store.connect() as c:
            row = c.execute('SELECT expired_at FROM l2_status WHERE stanza = %s', (self.stanza,)).fetchone()
        last_expire = row['expired_at'].timestamp() if row and row['expired_at'] else None
        errors, expired = [], None
        if last_expire is None or now - last_expire >= self.expire_every:
            try:
                wait = self.may_expire(now)
                if wait:
                    log.info('l2: expire waits (%s)', wait)
                else:
                    self._cmd('expire')
                    expired = now
            except L2Error as e:
                errors.append(str(e))
        try:
            seen = self.read()
        except L2Error as e:
            errors.append(str(e))
            seen = None
        with self.store.connect() as c:
            if seen is None:
                # What was read before stays (the alerts age from it); only the error is new.
                c.execute('INSERT INTO l2_status (stanza, checked_at, error) VALUES (%s, %s, %s) '
                          'ON CONFLICT (stanza) DO UPDATE SET error = EXCLUDED.error',
                          (self.stanza, _at(0), '; '.join(errors)))
            else:
                c.execute('INSERT INTO l2_status (stanza, checked_at, full_at, backup_at, wal_at, wal_segment, '
                          'expired_at, error) VALUES (%(s)s, %(now)s, %(full)s, %(backup)s, %(wal)s, %(seg)s, '
                          '%(exp)s, %(err)s) ON CONFLICT (stanza) DO UPDATE SET checked_at = EXCLUDED.checked_at, '
                          'full_at = EXCLUDED.full_at, backup_at = EXCLUDED.backup_at, wal_at = EXCLUDED.wal_at, '
                          'wal_segment = EXCLUDED.wal_segment, '
                          'expired_at = COALESCE(EXCLUDED.expired_at, l2_status.expired_at), error = EXCLUDED.error',
                          {'s': self.stanza, 'now': _at(now), 'full': _at(seen['full_at']),
                           'backup': _at(seen['backup_at']), 'wal': _at(seen['wal_at']), 'seg': seen['wal_segment'],
                           'exp': _at(expired), 'err': '; '.join(errors) or None})
            c.commit()
        if errors:
            raise L2Error('; '.join(errors))
