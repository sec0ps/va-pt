"""Tor process lifecycle and control-port management for isolated darkweb fetches."""

import os
import time
import threading

import stem
import stem.connection
import stem.process
from stem.control import Controller

from config import Config


class TorError(Exception):
    pass


class TorController:
    def __init__(self, config=None):
        self.config = config or Config()
        self._process = None
        self._controller = None
        self._newnym_lock = threading.Lock()
        self._last_newnym = 0.0

    def start(self):
        if self._process is not None:
            return
        data_dir = self.config.tor_data_dir
        os.makedirs(data_dir, exist_ok=True)

        tor_config = {
            "SocksPort": str(self.config.tor_socks_port),
            "ControlPort": str(self.config.tor_control_port),
            "DataDirectory": data_dir,
            "CookieAuthentication": "1",
            "AvoidDiskWrites": "1",
        }
        if self.config.tor_extra_config:
            tor_config.update(self.config.tor_extra_config)

        try:
            self._process = stem.process.launch_tor_with_config(
                config=tor_config,
                tor_cmd=self.config.tor_cmd,
                init_msg_handler=self._bootstrap_handler,
                timeout=self.config.tor_bootstrap_timeout,
                take_ownership=True,
            )
        except OSError as exc:
            raise TorError("failed to launch tor: %s" % exc)

        try:
            self._controller = Controller.from_port(port=self.config.tor_control_port)
            self._controller.authenticate()
        except (stem.SocketError, stem.connection.AuthenticationFailure) as exc:
            self.stop()
            raise TorError("control port setup failed: %s" % exc)

    def _bootstrap_handler(self, line):
        if self.config.tor_verbose and "Bootstrapped" in line:
            print("[tor] %s" % line)

    def new_identity(self, wait_for_guard=True):
        with self._newnym_lock:
            if self._controller is None:
                raise TorError("controller not started")
            if wait_for_guard:
                elapsed = time.time() - self._last_newnym
                guard = self.config.tor_newnym_guard
                if elapsed < guard:
                    time.sleep(guard - elapsed)
            self._controller.signal(stem.Signal.NEWNYM)
            self._last_newnym = time.time()

    def is_running(self):
        return self._process is not None and self._process.poll() is None

    def stop(self):
        if self._controller is not None:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=10)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
