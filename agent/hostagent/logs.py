"""Structured, redacted log lines (DOC-04 §10)."""
import json
import re
import threading
import time
from pathlib import Path

SECRET_KEY = re.compile(r'password|secret|token|key|salt|hash|data_b64|identity', re.I)
CONN = re.compile(r'(postgres(?:ql)?://[^:/@\s]+:)[^@\s]+@')


def redact(value):
    if isinstance(value, dict):
        return {k: ('[redacted]' if SECRET_KEY.search(k) and k not in ('fencing_token', 'evidence_sha256')
                    else redact(v)) for k, v in value.items() if k != 'secrets'}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return CONN.sub(r'\1***@', value)
    return value


class AuditLog:
    def __init__(self, path: Path | None):
        self.path = path
        self.lines = []          # kept in memory too, for tests
        self._lock = threading.Lock()

    def write(self, **fields):
        line = json.dumps({'at': round(time.time(), 3), **redact(fields)}, sort_keys=True, default=str)
        with self._lock:
            self.lines.append(line)
            if self.path:
                with open(self.path, 'a') as f:
                    f.write(line + '\n')
