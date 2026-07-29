"""Tor manager that launches and supervises the managed tor process."""

import logging
import threading

from torctl import TorController, TorError

log = logging.getLogger("recon.tor")


class TorManager:
    def __init__(self, config):
        self.config = config
        self.controller = TorController(config)
        self._ready = threading.Event()
        self._failed = False
        self._error = None

    def start(self):
        self._run()

    def start_async(self):
        thread = threading.Thread(target=self._run, name="tor-boot", daemon=True)
        thread.start()

    def _run(self):
        try:
            log.info("tor bootstrap starting")
            self.controller.start()
            self._ready.set()
            log.info("tor bootstrap complete")
        except Exception as exc:
            self._failed = True
            self._error = str(exc)
            log.error("tor bootstrap failed: %s", exc)

    def wait_ready(self, timeout):
        if self._failed:
            raise TorError(self._error or "tor failed to start")
        if self._ready.wait(timeout):
            return
        if self._failed:
            raise TorError(self._error or "tor failed to start")
        raise TorError("tor not ready after %s seconds" % timeout)

    def is_ready(self):
        return self._ready.is_set()

    def status(self):
        if self._ready.is_set():
            return "ready"
        if self._failed:
            return "failed"
        return "starting"

    def stop(self):
        self.controller.stop()
