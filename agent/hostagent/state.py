"""Agent local state in SQLite (DOC-04 §5.3).

`synchronous=FULL` makes every commit fsync, so a journal row is on disk before
the executor acts. All admission decisions happen inside one BEGIN IMMEDIATE
transaction, which serialises concurrent requests on this host.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS environment_registry (
    environment_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    sid TEXT NOT NULL UNIQUE,
    container_uid INTEGER UNIQUE,
    http_port INTEGER UNIQUE,
    gevent_port INTEGER UNIQUE,
    kind TEXT NOT NULL,
    egress_profile TEXT NOT NULL,
    created_at REAL NOT NULL,
    deleted_at REAL           -- tombstone: the sid and container_uid are never reused (DOC-03 §9)
);
CREATE TABLE IF NOT EXISTS fence_high_water (
    scope_id TEXT PRIMARY KEY,
    token INTEGER NOT NULL,
    op_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seen_nonce (
    nonce TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS step_journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT NOT NULL,
    op_type TEXT NOT NULL,
    step TEXT NOT NULL,
    environment_id TEXT,
    fencing_token INTEGER NOT NULL,
    status TEXT NOT NULL,
    code TEXT,
    started_at REAL NOT NULL,
    finished_at REAL,
    evidence_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS step_journal_op ON step_journal (op_id);
CREATE TABLE IF NOT EXISTS active_op (
    scope_id TEXT PRIMARY KEY,
    op_id TEXT NOT NULL,
    step TEXT NOT NULL,
    since REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_event (
    scope_id TEXT NOT NULL,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_event_scope ON rate_event (scope_id, at);
-- Every signed response, until ctl-1 acknowledges it. A redelivered envelope
-- (same op, token and step) gets the stored response back, not a re-run.
CREATE TABLE IF NOT EXISTS response_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT,
    fencing_token INTEGER,
    step TEXT,
    request_sha256 TEXT,       -- the envelope minus nonce, times, secrets and signature
    status TEXT NOT NULL,
    response TEXT NOT NULL,
    created_at REAL NOT NULL,
    delivered_at REAL
);
CREATE INDEX IF NOT EXISTS response_outbox_key ON response_outbox (op_id, fencing_token, step);
CREATE INDEX IF NOT EXISTS response_outbox_pending ON response_outbox (delivered_at, id);
CREATE TABLE IF NOT EXISTS host_flag (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Rejected(Exception):
    def __init__(self, code: str, detail: str = ''):
        super().__init__(code, detail)
        self.code = code
        self.detail = detail


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)
        try:
            self.db.execute('ALTER TABLE environment_registry ADD COLUMN deleted_at REAL')
        except sqlite3.OperationalError:
            pass      # already there

    def _tx(self):
        return _Tx(self)

    def _q(self, sql, args=()):
        # One connection is shared by threads; reads take the same lock as writes.
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def _one(self, sql, args=()):
        rows = self._q(sql, args)
        return rows[0] if rows else None

    # -- nonces ---------------------------------------------------------
    def record_nonce(self, nonce: str, ttl: int, now: float) -> bool:
        """Insert `nonce`; False if it was already seen and hasn't expired."""
        with self._tx() as db:
            db.execute('DELETE FROM seen_nonce WHERE expires_at < ?', (now,))
            try:
                db.execute('INSERT INTO seen_nonce VALUES (?, ?)', (nonce, now + ttl))
            except sqlite3.IntegrityError:
                return False
        return True

    # -- fencing --------------------------------------------------------
    def high_water(self, scope_id: str):
        row = self._one('SELECT token, op_id FROM fence_high_water WHERE scope_id = ?', (scope_id,))
        return (row['token'], row['op_id']) if row else (0, None)

    @staticmethod
    def fence_ok(token: int, op_id: str, high_water) -> bool:
        # One operation is dispatched as one envelope per step, all with the same
        # token, so an equal token is accepted only for the operation that set it.
        hw_token, hw_op = high_water
        return token > hw_token or (token == hw_token and op_id == hw_op)

    # -- admission ------------------------------------------------------
    def admit(self, *, scope_id, op_id, step, token, fenced, exclusive, mutating,
              host_scope, rate_host, rate_env, now):
        """Atomically re-check fence, concurrency and rate; then record acceptance."""
        with self._tx() as db:
            # BUSY is decided before the fence, so concurrent requests for a busy
            # environment get BUSY rather than a fence race (DOC-04 §11, INV-21).
            row = db.execute('SELECT op_id FROM active_op WHERE scope_id = ?', (scope_id,)).fetchone()
            continuing = bool(row and row['op_id'] == op_id)
            if exclusive:
                if row and not continuing:
                    raise Rejected('BUSY')
                if continuing and self._step_running(op_id):
                    raise Rejected('BUSY')
            if fenced and not self.fence_ok(token, op_id, self.high_water(scope_id)):
                raise Rejected('STALE_FENCE')
            # The limit counts operations: later steps of an admitted operation are free.
            if mutating and not continuing:
                db.execute('DELETE FROM rate_event WHERE at < ?', (now - 60,))
                n_host = db.execute('SELECT count(*) FROM rate_event WHERE scope_id = ?', (host_scope,)).fetchone()[0]
                n_env = db.execute('SELECT count(*) FROM rate_event WHERE scope_id = ?', (scope_id,)).fetchone()[0]
                if n_host >= rate_host or (scope_id != host_scope and n_env >= rate_env):
                    raise Rejected('RATE_LIMITED')
                db.execute('INSERT INTO rate_event VALUES (?, ?)', (host_scope, now))
                if scope_id != host_scope:
                    db.execute('INSERT INTO rate_event VALUES (?, ?)', (scope_id, now))
            if fenced:
                db.execute('INSERT INTO fence_high_water VALUES (?, ?, ?) ON CONFLICT (scope_id) '
                           'DO UPDATE SET token = excluded.token, op_id = excluded.op_id', (scope_id, token, op_id))
            if exclusive:
                db.execute('INSERT INTO active_op VALUES (?, ?, ?, ?) ON CONFLICT (scope_id) '
                           'DO UPDATE SET step = excluded.step, since = excluded.since', (scope_id, op_id, step, now))

    def release(self, scope_id: str, op_id: str):
        with self._tx() as db:
            db.execute('DELETE FROM active_op WHERE scope_id = ? AND op_id = ?', (scope_id, op_id))

    # -- journal --------------------------------------------------------
    def _step_running(self, op_id):
        return self._one("SELECT 1 FROM step_journal WHERE op_id = ? AND status = 'in_progress'", (op_id,)) is not None

    def journal_start(self, *, op_id, op_type, step, environment_id, token, now) -> int:
        with self._tx() as db:
            cur = db.execute('INSERT INTO step_journal (op_id, op_type, step, environment_id, fencing_token, '
                             "status, started_at) VALUES (?, ?, ?, ?, ?, 'in_progress', ?)",
                             (op_id, op_type, step, environment_id, token, now))
            return cur.lastrowid

    def journal_finish(self, row_id: int, *, status, code, evidence_sha256, now):
        with self._tx() as db:
            db.execute('UPDATE step_journal SET status = ?, code = ?, evidence_sha256 = ?, finished_at = ? '
                       'WHERE id = ?', (status, code, evidence_sha256, now, row_id))

    def journal(self, op_id: str) -> list[dict]:
        rows = self._q('SELECT op_id, op_type, step, environment_id, fencing_token, status, code, '
                       'started_at, finished_at, evidence_sha256 FROM step_journal WHERE op_id = ? '
                       'ORDER BY id', (op_id,))
        return [dict(r) for r in rows]

    def last_lifecycle_step(self, environment_id: str) -> str | None:
        """The most recent completed step that started or stopped the runtime."""
        row = self._one("SELECT step FROM step_journal WHERE environment_id = ? AND status = 'done' AND step IN "
                        "('app.start', 'app.reactivate', 'app.container', 'app.swap', 'app.switch', 'app.stop', "
                        "'app.suspend') ORDER BY id DESC LIMIT 1", (environment_id,))
        return row['step'] if row else None

    def backup_since(self, environment_id: str, since: float) -> bool:
        return self._one("SELECT 1 FROM step_journal WHERE environment_id = ? AND step = 'app.backup' "
                         "AND status = 'done' AND finished_at >= ?", (environment_id, since)) is not None

    def step_done(self, op_id: str, step: str) -> bool:
        return self._one("SELECT 1 FROM step_journal WHERE op_id = ? AND step = ? AND status = 'done'",
                         (op_id, step)) is not None

    # -- registry -------------------------------------------------------
    def environment(self, environment_id: str) -> dict | None:
        row = self._one('SELECT * FROM environment_registry WHERE environment_id = ?', (environment_id,))
        return dict(row) if row else None

    def slot_conflict(self, environment_id, container_uid, ports) -> bool:
        row = self._one('SELECT 1 FROM environment_registry WHERE environment_id != ? AND (container_uid = ? '
                        'OR http_port IN (?, ?) OR gevent_port IN (?, ?))',
                        (environment_id, container_uid, *ports, *ports))
        return row is not None

    def sid_owner(self, sid: str) -> str | None:
        row = self._one('SELECT environment_id FROM environment_registry WHERE sid = ?', (sid,))
        return row['environment_id'] if row else None

    def register(self, *, environment_id, tenant_id, sid, container_uid, http_port, gevent_port, kind,
                 egress_profile, now):
        with self._tx() as db:
            existing = self.environment(environment_id)
            if existing:
                if existing['tenant_id'] != tenant_id:
                    raise Rejected('NOT_OWNER')
                return
            db.execute('INSERT INTO environment_registry VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)',
                       (environment_id, tenant_id, sid, container_uid, http_port, gevent_port, kind,
                        egress_profile, now))

    def tombstone(self, environment_id: str, now: float):
        # Ports go back to the pool; the sid and container_uid stay taken.
        with self._tx() as db:
            db.execute('UPDATE environment_registry SET deleted_at = coalesce(deleted_at, ?), http_port = NULL, '
                       'gevent_port = NULL WHERE environment_id = ?', (now, environment_id))

    def live_copies(self, tenant_id: str) -> list[str]:
        rows = self._q("SELECT environment_id FROM environment_registry WHERE tenant_id = ? AND kind = 'restore_copy' "
                       'AND deleted_at IS NULL', (tenant_id,))
        return [r['environment_id'] for r in rows]

    def unregister(self, environment_id: str):
        with self._tx() as db:
            db.execute('DELETE FROM environment_registry WHERE environment_id = ?', (environment_id,))

    # -- response outbox ------------------------------------------------
    def store_response(self, response: dict, now: float, request_sha256: str | None = None):
        with self._tx() as db:
            db.execute('INSERT INTO response_outbox (op_id, fencing_token, step, request_sha256, status, response, '
                       'created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (response.get('op_id'), response.get('fencing_token'), response.get('step'), request_sha256,
                        response['status'], json.dumps(response, sort_keys=True), now))

    def finished_response(self, op_id, token, step, request_sha256) -> dict | None:
        row = self._one("SELECT response FROM response_outbox WHERE op_id = ? AND fencing_token = ? AND step = ? "
                        "AND request_sha256 = ? AND status IN ('done', 'failed') ORDER BY id DESC LIMIT 1",
                        (op_id, token, step, request_sha256))
        return json.loads(row['response']) if row else None

    def undelivered(self, limit: int) -> list[tuple[int, dict]]:
        rows = self._q('SELECT id, response FROM response_outbox WHERE delivered_at IS NULL ORDER BY id LIMIT ?',
                       (limit,))
        return [(r['id'], json.loads(r['response'])) for r in rows]

    def mark_delivered(self, ids, now: float):
        with self._tx() as db:
            db.executemany('UPDATE response_outbox SET delivered_at = ? WHERE id = ?', [(now, i) for i in ids])

    def prune_delivered(self, before: float):
        # Kept past delivery for redelivery dedup; the envelope (≤ 10 min) and nonce TTL bound how long that matters.
        with self._tx() as db:
            db.execute('DELETE FROM response_outbox WHERE delivered_at < ?', (before,))

    # -- crash recovery -------------------------------------------------
    def interrupted_steps(self) -> list[dict]:
        rows = self._q("SELECT id, op_id, op_type, step, environment_id, fencing_token FROM step_journal "
                       "WHERE status = 'in_progress' ORDER BY id")
        return [dict(r) for r in rows]

    def abort_step(self, row_id: int, op_id: str, evidence_sha256: str, now: float):
        with self._tx() as db:
            db.execute("UPDATE step_journal SET status = 'failed', code = 'TIMEOUT', evidence_sha256 = ?, "
                       'finished_at = ? WHERE id = ?', (evidence_sha256, now, row_id))
            db.execute('DELETE FROM active_op WHERE op_id = ?', (op_id,))

    # -- host flags -----------------------------------------------------
    def flag(self, name: str) -> str | None:
        row = self._one('SELECT value FROM host_flag WHERE name = ?', (name,))
        return row['value'] if row else None

    def set_flag(self, name: str, value: str):
        with self._tx() as db:
            db.execute('INSERT INTO host_flag VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value',
                       (name, value))


class _Tx:
    def __init__(self, state: State):
        self.state = state

    def __enter__(self):
        self.state._lock.acquire()
        self.state.db.execute('BEGIN IMMEDIATE')
        return self.state.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.state.db.execute('ROLLBACK' if exc_type else 'COMMIT')
        finally:
            self.state._lock.release()
        return False


def now() -> float:
    return time.time()
