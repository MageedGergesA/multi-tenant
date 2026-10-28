"""Long-poll loop to ctl-1 (DOC-04 §1 "pull, not push").

The agent opens no listening port. Over WireGuard, with mutual TLS (TLS 1.3,
pinned CA, client certificate per host):

    POST /v1/agents/<host_id>/poll       {"wait": s, "capacity": n}
         -> 200 {"envelopes": [...]} (at most n) | 204
    POST /v1/agents/<host_id>/responses  {"responses": [...]}
         -> 200

DOC-03/DOC-04 don't define this wire protocol; it is proposed here (README gap 28).
Every response is written to the outbox before delivery is tried, so a lost
connection or a restart never loses one; ctl-1 deduplicates on
(op_id, fencing_token, step, status).
"""
import json
import ssl
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MAX_BODY = 4 << 20            # largest poll reply accepted
DELIVER_BATCH = 50
KEEP_DELIVERED = 24 * 3600    # outbox rows kept after delivery, for redelivery dedup


class TransportError(Exception):
    pass


def tls_context(ca: Path, cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


class ControlPlane:
    def __init__(self, base_url: str, host_id: str, context: ssl.SSLContext, timeout: float = 60):
        if not base_url.startswith('https://'):
            raise ValueError('ctl-1 is reached over https only')
        self.base = '%s/v1/agents/%s' % (base_url.rstrip('/'), host_id)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
        self.timeout = timeout

    def _post(self, path, body, timeout):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(),
                                     {'Content-Type': 'application/json'}, method='POST')
        try:
            with self.opener.open(req, timeout=timeout) as r:
                return r.status, r.read(MAX_BODY + 1)
        except urllib.error.HTTPError as e:
            raise TransportError('http %d' % e.code) from None
        except (urllib.error.URLError, OSError) as e:
            raise TransportError(type(e).__name__) from None

    def poll(self, wait: int, capacity: int) -> list[dict]:
        status, raw = self._post('/poll', {'wait': wait, 'capacity': capacity}, wait + self.timeout)
        if status == 204:
            return []
        if len(raw) > MAX_BODY:
            raise TransportError('reply too large')
        try:
            envelopes = json.loads(raw)['envelopes']
        except (ValueError, KeyError, TypeError):
            raise TransportError('malformed reply') from None
        if not isinstance(envelopes, list):
            raise TransportError('malformed reply')
        # Anything else is still checked in full by the verifier.
        return [e for e in envelopes[:capacity] if isinstance(e, dict)]

    def deliver(self, responses: list[dict]):
        self._post('/responses', {'responses': responses}, self.timeout)


class Poller:
    def __init__(self, agent, cp: ControlPlane, *, workers: int = 4, wait: int = 25, max_backoff: float = 60,
                 sleep=time.sleep):
        self.agent = agent
        self.cp = cp
        self.wait = wait
        self.max_backoff = max_backoff
        self.sleep = sleep
        self.workers = workers
        self.pool = ThreadPoolExecutor(workers, thread_name_prefix='step')
        self.free = threading.Semaphore(workers)
        self._deliver_lock = threading.Lock()
        self.failures = 0
        agent.on_response = self.deliver     # heartbeats go out as they happen

    def start(self):
        self.agent.recover()
        self.deliver()

    def deliver(self) -> bool:
        """Send undelivered responses, oldest first. False if ctl-1 can't be reached."""
        with self._deliver_lock:
            while True:
                batch = self.agent.state.undelivered(DELIVER_BATCH)
                if not batch:
                    break
                try:
                    self.cp.deliver([r for _, r in batch])
                except TransportError:
                    return False
                self.agent.state.mark_delivered([i for i, _ in batch], self.agent.clock())
            self.agent.state.prune_delivered(self.agent.clock() - KEEP_DELIVERED)
            return True

    def _run(self, env):
        try:
            self.agent.handle(env)
            self.deliver()
        finally:
            self.free.release()

    def run_once(self) -> int:
        """One poll: wait for a free worker, fetch up to the free count, dispatch."""
        self.free.acquire()
        capacity = 1
        while capacity < self.workers and self.free.acquire(blocking=False):
            capacity += 1
        try:
            if not self.deliver():
                raise TransportError('deliver')
            envelopes = self.cp.poll(self.wait, capacity)
        except TransportError:
            for _ in range(capacity):
                self.free.release()
            self.failures += 1
            self.sleep(min(self.max_backoff, 2 ** min(self.failures, 6)))
            return 0
        self.failures = 0
        for env in envelopes:
            self.pool.submit(self._run, env)
        for _ in range(capacity - len(envelopes)):
            self.free.release()
        return len(envelopes)

    def run_forever(self, stop: threading.Event):
        self.start()
        while not stop.is_set():
            self.run_once()
        self.pool.shutdown(wait=True)
        self.deliver()
