"""Off-site upload and download (DOC-04 §6.8 step 7, §6.9 step 3), run by
agentd: agent-exec has no network. B2 speaks this S3 API with Object Lock;
the local stand-in is LocalStack. Credentials come from the envelope's
secrets and live only for the step."""
import base64
import hashlib
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config


def object_key(tenant_id, environment_id, backup_id):
    return 'tenants/%s/%s/%s.tar.age' % (tenant_id, environment_id, backup_id)


def client(endpoint, region, key_id, secret):
    return boto3.client('s3', endpoint_url=endpoint or None, region_name=region, aws_access_key_id=key_id,
                        aws_secret_access_key=secret, config=Config(retries={'max_attempts': 5}))


def _b64(hexdigest):
    return base64.b64encode(bytes.fromhex(hexdigest)).decode()


def head(s3, bucket, key):
    try:
        h = s3.head_object(Bucket=bucket, Key=key, ChecksumMode='ENABLED')
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ('404', 'NoSuchKey', 'NotFound'):
            return None
        raise
    return {'version_id': h.get('VersionId'), 'lock_mode': h.get('ObjectLockMode'),
            'lock_until': h['ObjectLockRetainUntilDate'].isoformat() if h.get('ObjectLockRetainUntilDate') else None,
            'sha256_b64': h.get('ChecksumSHA256'), 'size': h['ContentLength']}


def upload_locked(s3, bucket, key, path, sha256_hex, lock_days):
    until = datetime.now(timezone.utc) + timedelta(days=lock_days)
    with open(path, 'rb') as f:
        s3.put_object(Bucket=bucket, Key=key, Body=f, ChecksumSHA256=_b64(sha256_hex),
                      ObjectLockMode='COMPLIANCE', ObjectLockRetainUntilDate=until)
    return until


def verify(seen, sha256_hex, min_until=None):
    """True if the stored object is compliance-locked (until at least `min_until`)
    and has the expected SHA-256."""
    if not seen or seen['lock_mode'] != 'COMPLIANCE' or seen['sha256_b64'] != _b64(sha256_hex):
        return False
    if min_until is not None and datetime.fromisoformat(seen['lock_until']) < min_until - timedelta(seconds=60):
        return False
    return True


def download(s3, bucket, key, path):
    """Download and return the SHA-256 of what was written."""
    h = hashlib.sha256()
    body = s3.get_object(Bucket=bucket, Key=key, ChecksumMode='ENABLED')['Body']
    with open(path, 'wb') as f:
        for chunk in iter(lambda: body.read(1 << 20), b''):
            h.update(chunk)
            f.write(chunk)
    return h.hexdigest()
