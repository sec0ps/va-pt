"""Console daemon entrypoint that starts tor, worker pool, scheduler, and web console."""

import os
import sys

_venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
_venv_python = os.path.join(_venv_dir, "bin", "python")
if os.path.exists(_venv_python) and os.path.abspath(sys.prefix) != os.path.abspath(_venv_dir):
    os.execv(_venv_python, [_venv_python] + sys.argv)

import logging
import signal

import db
from config import Config
from runtime import TorManager
from fetch import TorFetcher
from sources.registry import SourceRegistry
from worker import Worker
from scheduler import Scheduler
from console.app import create_app, serve
from console.auth import hash_password

log = logging.getLogger("recon")


def seed_admin(config):
    if db.count_users() > 0:
        return
    if config.admin_user and config.admin_password:
        db.create_user(config.admin_user, hash_password(config.admin_password), "admin")
        log.info("seeded admin user %s from environment", config.admin_user)
    else:
        log.warning("no users exist, create one with manage.py create-admin")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = Config()
    config.ensure_dirs()
    db.init_db()
    config.refresh()
    seed_admin(config)

    tor = TorManager(config)
    tor.start()
    fetcher = TorFetcher(tor.controller, config)
    registry = SourceRegistry(config)
    worker = Worker(config, tor, fetcher, registry)
    scheduler = Scheduler(worker)
    scheduler.start()

    app = create_app(config, worker, scheduler)

    def handle_stop(signum, frame):
        log.info("received signal %s, shutting down", signum)
        scheduler.shutdown()
        worker.shutdown()
        tor.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    log.info("console listening on %s", config.console_bind)
    try:
        serve(app, config.console_bind)
    finally:
        scheduler.shutdown()
        worker.shutdown()
        tor.stop()


if __name__ == "__main__":
    main()
