#!/usr/bin/python3 -I
"""ctl-secrets.service's ExecStart (as root): decrypt ctl-1's SOPS file and
write each top-level key as one file in the runtime directory, for the `ctl`
user only (ADR-006; ctlplane/main.py reads them as `*_file`).

    write-secrets --sops-file /etc/ctl/secrets.sops.yaml --dir /run/ctl --user ctl

SOPS decrypts with the host's age key ($SOPS_AGE_KEY_FILE, readable by root
only); the plaintext comes through a pipe and is written only to the
directory, which must be on tmpfs, so it never reaches a disk. Every key is
a file name ([a-z0-9_]+, optionally .json); a value is written as is, or as
JSON if it is a map (`bucket_c_write.json: {key_id: ..., secret: ...}`).
Nothing is written unless every key is valid; files from an earlier run that
are no longer in the SOPS file are removed. Values are never printed.
Standard library only, and `-I`: it runs as root.
"""
import argparse
import json
import os
import pwd
import re
import subprocess
import sys

NAME = re.compile(r'^[a-z0-9_]+(\.json)?$')
MAX_KEYS = 64


class Refused(Exception):
    pass


def fstype(path) -> str:
    """The filesystem type of the mount `path` is on (/proc/self/mountinfo)."""
    path = os.path.realpath(path)
    best, kind = '', ''
    with open('/proc/self/mountinfo') as f:
        for line in f:
            fields = line.split()
            mount = fields[4].encode().decode('unicode_escape')
            rest = fields[fields.index('-') + 1:]
            if (path == mount or path.startswith(mount.rstrip('/') + '/')) and len(mount) >= len(best):
                best, kind = mount, rest[0]
    return kind


def decrypt(sops_cmd, sops_file) -> dict:
    run = subprocess.run([*sops_cmd, '--decrypt', '--output-type', 'json', sops_file], capture_output=True)
    if run.returncode != 0:
        # sops's own message (which file, which key failed); it doesn't print plaintext.
        raise Refused('sops failed (%d): %s' % (run.returncode, run.stderr.decode(errors='replace').strip()[-300:]))
    try:
        data = json.loads(run.stdout)
    except ValueError:
        raise Refused('sops output is not JSON') from None
    if not isinstance(data, dict):
        raise Refused('the SOPS file must be a map of file names to values')
    data.pop('sops', None)
    if len(data) > MAX_KEYS:
        raise Refused('more than %d keys' % MAX_KEYS)
    out = {}
    for name, value in data.items():
        if not NAME.match(name):
            raise Refused('key %r is not a file name ([a-z0-9_]+, optionally .json)' % name)
        if isinstance(value, dict):
            out[name] = json.dumps(value, sort_keys=True)
        elif isinstance(value, str):
            out[name] = value
        else:
            raise Refused('key %r: a string or a map' % name)
    return out


def write(directory, values: dict, uid: int, gid: int):
    if os.path.islink(directory) or not os.path.isdir(directory):
        raise Refused('%s is not a directory' % directory)
    if fstype(directory) != 'tmpfs':
        raise Refused('%s is not on tmpfs' % directory)
    os.chmod(directory, 0o700)
    old = os.umask(0o077)
    try:
        for name, value in values.items():
            tmp = os.path.join(directory, '.%s.tmp' % name)
            if os.path.lexists(tmp):            # left by a run that died here
                os.unlink(tmp)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            try:
                os.write(fd, value.encode() + (b'' if value.endswith('\n') else b'\n'))
                os.fchown(fd, uid, gid)
            finally:
                os.close(fd)
            os.replace(tmp, os.path.join(directory, name))
        for name in os.listdir(directory):
            if NAME.match(name) and name not in values:
                os.unlink(os.path.join(directory, name))
        # Last, so root needs only CAP_CHOWN and CAP_FOWNER, never to write into a directory it doesn't own.
        os.chown(directory, uid, gid)
    finally:
        os.umask(old)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='write-secrets')
    p.add_argument('--sops-file', required=True)
    p.add_argument('--dir', required=True)
    p.add_argument('--user', required=True)
    p.add_argument('--sops', default='sops', help='the sops command (tests: a stand-in)')
    args = p.parse_args(argv)
    try:
        try:
            user = pwd.getpwnam(args.user)
        except KeyError:
            raise Refused('no user %r' % args.user) from None
        values = decrypt(args.sops.split(), args.sops_file)
        write(args.dir, values, user.pw_uid, user.pw_gid)
    except Refused as e:
        print('write-secrets: %s' % e, file=sys.stderr)
        return 1
    print('write-secrets: %d files in %s for %s' % (len(values), args.dir, args.user))
    return 0


if __name__ == '__main__':
    sys.exit(main())
