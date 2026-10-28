"""Entry point for agentd: `python -m hostagent.agentd_main --config agent.toml`.

Reads the agent's signing key and age identity from the state directory
(written at enrollment, mode 0600), recovers interrupted steps, then polls.
"""
import argparse
import signal
import threading
from pathlib import Path

import pyrage
from nacl.signing import SigningKey

from .agentd import Agent
from .config import load
from .execd import ExecClient
from .logs import AuditLog
from .poller import ControlPlane, Poller, tls_context
from .state import State


def _private(path: Path) -> bytes:
    if path.stat().st_mode & 0o077:
        raise SystemExit('%s must not be readable by group or others' % path)
    return path.read_bytes()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', required=True, type=Path)
    config = load(ap.parse_args().config)
    key = SigningKey(_private(config.state_dir / 'agent.key'))
    identity = pyrage.x25519.Identity.from_str(_private(config.state_dir / 'age.key').decode().strip())
    config = config.__class__(**{**config.__dict__, 'age_identity': identity})
    agent = Agent(config, State(config.state_dir / 'agent.db'), ExecClient(config.exec_socket, config.role), key,
                  AuditLog(config.state_dir / 'audit.log'))
    cp = ControlPlane(config.ctl_url, config.host_id, tls_context(config.ctl_ca, config.tls_cert, config.tls_key))
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    Poller(agent, cp, workers=config.workers, wait=config.poll_wait).run_forever(stop)


if __name__ == '__main__':
    main()
