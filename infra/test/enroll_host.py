"""infra/test/run.sh: the operator's and the founder's part of Host.Enroll (DOC-04 §2),
through ctl-1's operator API as a real operator would do it.

    enroll_host.py <ctl container> <work dir> <role> <region> <private ip>

Mints an OIDC token with the test IdP's key (work/idp.pem, whose JWKS ctl-1
trusts), opens the host's enrollment (POST /v1/hosts), signs the returned
authorization with the test release key (work/release.seed), authorizes it,
and prints {"host_id", "token_file"} (the bootstrap token, written 0600).
"""
import base64
import json
import os
import subprocess
import sys
import time

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from nacl.signing import SigningKey

from ctlplane.canonical import sign

# Runs inside the ctl container: the operator API listens on its loopback.
CALL = '''
import json, sys, urllib.request, urllib.error
method, path, token = sys.argv[1:4]
body = sys.stdin.read().encode() or None
req = urllib.request.Request('http://127.0.0.1:8080' + path, body, method=method,
                             headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        print(json.dumps({'status': r.status, 'body': json.loads(r.read())}))
except urllib.error.HTTPError as e:
    print(json.dumps({'status': e.code, 'body': e.read().decode()}))
'''


def main():
    container, work, role, region, private_ip = sys.argv[1:6]
    idp = load_pem_private_key(open(os.path.join(work, 'idp.pem'), 'rb').read(), None)
    now = int(time.time())
    token = jwt.encode({'iss': 'https://id.example.test', 'aud': 'ctl-1', 'sub': 'sub-founder', 'iat': now,
                        'exp': now + 600, 'auth_time': now, 'amr': ['pwd', 'hwk', 'mfa']}, idp, algorithm='ES256',
                       headers={'kid': 'k1'})

    def api(method, path, body=None):
        run = subprocess.run(['docker', 'exec', '-i', container, 'python3', '-c', CALL, method, path, token],
                             input=json.dumps(body) if body is not None else '', capture_output=True, text=True,
                             check=True)
        out = json.loads(run.stdout)
        if out['status'] >= 300:
            raise SystemExit('%s %s: %s %s' % (method, path, out['status'], out['body']))
        return out['body']

    opened = api('POST', '/v1/hosts', {'role': role, 'region': region, 'private_ip': private_ip})
    release = SigningKey(base64.b64decode(open(os.path.join(work, 'release.seed')).read()))
    signed = dict(opened['authorization'], release_signature=sign(opened['authorization'], release))
    api('POST', '/v1/hosts/%s/enrollment/authorize' % opened['host_id'], {'authorization': signed})
    token_file = os.path.join(work, '%s.token' % opened['host_id'])
    fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(opened['bootstrap_token'])
    print(json.dumps({'host_id': opened['host_id'], 'token_file': token_file}))


if __name__ == '__main__':
    main()
