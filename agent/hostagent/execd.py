"""agent-exec: the privileged half (DOC-04 §1).

Listens on one Unix socket (mode 0600, owned by agentd's user), accepts one JSON
request per line `{"verb": ..., "args": {...}}`, re-validates it with
`verbs.validate`, writes its own audit line, then calls the backend. It has no
network client of its own.

One changing verb per sid at a time. agentd sends a step's verbs one after
another, and admission keeps one operation per environment, so this only
matters after agentd restarts mid-step: the verb it was waiting on keeps
running here, and a re-dispatched step must not overlap it. The second caller
gets BUSY at once rather than waiting; read-only verbs are never held up.
Neither is `exec.cancel`, which agentd sends when a step passes its deadline:
it kills the sid's running one-shot, so the verb holding the sid returns.
"""
import json
import os
import socket
import socketserver
import threading
import time
from pathlib import Path

from . import verbs
from .logs import AuditLog


class ExecError(Exception):
    pass


def _read_only(verb: str) -> bool:
    return verb.endswith('.inspect') or verb == 'pg.connection_stats'


class Executor:
    def __init__(self, role: str, backend, audit: AuditLog):
        self.role = role
        self.backend = backend
        self.audit = audit
        self._busy = set()
        self._guard = threading.Lock()

    def startup(self) -> dict:
        """Run once before serving. Claims start empty, which is only true once
        whatever the previous process left running is gone."""
        reap = getattr(self.backend, 'reap_orphans', None)
        result = reap() if reap else {}
        self.audit.write(event='exec_startup', **result)
        return result

    def _claim(self, verb, args):
        sid = args.get('sid')
        if sid is None or _read_only(verb) or verb == 'exec.cancel':
            return None
        with self._guard:
            if sid in self._busy:
                return False
            self._busy.add(sid)
        return sid

    def handle(self, request) -> dict:
        verb = request.get('verb') if isinstance(request, dict) else None
        start = time.time()
        try:
            if not isinstance(request, dict) or set(request) != {'verb', 'args'}:
                raise verbs.BadArgs('request')
            args = verbs.validate(self.role, verb, request['args'])
        except verbs.BadArgs as e:
            self.audit.write(event='exec', verb=verb, result='refused', reason=str(e))
            return {'ok': False, 'error': 'REFUSED', 'reason': str(e)}
        claimed = self._claim(verb, args)
        if claimed is False:
            self.audit.write(event='exec', verb=verb, args=args, result='busy')
            return {'ok': False, 'error': 'BUSY', 'reason': 'sid busy'}
        try:
            result = getattr(self.backend, verb.replace('.', '_'))(**args)
        except Exception as e:  # report the class only: messages may carry environment data
            self.audit.write(event='exec', verb=verb, args=args, result='error', error=type(e).__name__,
                             duration=round(time.time() - start, 3))
            return {'ok': False, 'error': 'EXEC_ERROR', 'reason': type(e).__name__}
        finally:
            if claimed:
                with self._guard:
                    self._busy.discard(claimed)
        self.audit.write(event='exec', verb=verb, args=args, result='ok', duration=round(time.time() - start, 3))
        return {'ok': True, 'result': result}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            try:
                request = json.loads(line)
            except ValueError:
                request = None
            reply = self.server.executor.handle(request)
            self.wfile.write(json.dumps(reply).encode() + b'\n')
            self.wfile.flush()


class ExecServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, executor: Executor, owner_uid: int | None = None, owner_gid: int | None = None):
        """`owner_uid`: agentd's uid, given the socket (needs root: the app executor). `owner_gid`: a
        group agentd and this process share; the socket is 0660 in it (the db executor runs as
        postgres and can't chown to another user, but may chgrp to a group it is in)."""
        if path.exists():
            path.unlink()
        self.executor = executor
        old = os.umask(0o177)
        try:
            super().__init__(str(path), _Handler)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        if owner_uid is not None:
            os.chown(path, owner_uid, -1)
        if owner_gid is not None:
            os.chown(path, -1, owner_gid)
            os.chmod(path, 0o660)


class ExecClient:
    """agentd's side of the socket. Validates before sending, so bad calls fail early."""

    def __init__(self, path: Path, role: str):
        self.path = path
        self.role = role

    def call(self, verb: str, **args):
        verbs.validate(self.role, verb, args)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(self.path))
            s.sendall(json.dumps({'verb': verb, 'args': args}).encode() + b'\n')
            reply = json.loads(s.makefile().readline())
        if not reply['ok']:
            raise ExecError(reply['error'], reply.get('reason'))
        return reply['result']


class LocalExecClient:
    """In-process client for tests and single-process development."""

    def __init__(self, executor: Executor):
        self.executor = executor
        self.role = executor.role

    def call(self, verb: str, **args):
        verbs.validate(self.role, verb, args)
        reply = self.executor.handle({'verb': verb, 'args': args})
        if not reply['ok']:
            raise ExecError(reply['error'], reply.get('reason'))
        return reply['result']
