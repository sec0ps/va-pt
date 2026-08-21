# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: Manages the lifecycle of the subsystem's own dedicated tor process and
#          its control-port connection for isolated darkweb fetches. Launches tor
#          on its fixed configured SOCKS and control ports under a private data
#          directory, authenticates to the control port, and brokers throttled
#          NEWNYM identity rotation. On a port conflict it reaps only its own
#          orphaned managed tor (matched by our uid and our data directory) and
#          otherwise fails fast with actionable guidance, never touching a system
#          or foreign tor it does not own.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================
# Location: darkweb-recon/torctl.py

"""Tor process lifecycle and control-port management for isolated darkweb fetches.

The controller launches a dedicated tor instance on its fixed configured SOCKS
and control ports rather than reusing a system tor: NEWNYM identity rotation
needs a control port that the distro-default torrc leaves disabled, so a private
tor is required. Ports stay deterministic so the operator can reach the SOCKS
proxy directly and so the fetcher's config-derived port always matches the live
instance. If a configured port is already bound, start() first reaps an orphaned
managed tor left by a prior hard-killed run -- but only one it owns, identified
by our uid and our tor data directory. Any other holder (the distro tor service,
another user's tor) is never killed; start() fails fast with the same guidance
the installer prints, because clearing a foreign or system tor is the operator's
call, not the runtime's.
"""

from __future__ import annotations

import os
import signal
import socket
import time
import logging
import threading

import stem
import stem.connection
import stem.process
from stem.control import Controller

from config import Config

log = logging.getLogger("recon.tor")


class TorError(Exception):
    pass


def _port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Return True if a TCP listener can bind host:port right now."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _our_orphan_tor_pids(data_dir: str) -> list:
    """Return pids of orphaned managed-tor processes this user owns.

    A match requires all of: the process is owned by our uid, its executable is
    tor, and it is tied to *our* tor data directory (the path appears in its
    argv, or it holds an open fd beneath that directory -- e.g. the datadir
    lock). This deliberately excludes the distro tor service and any other
    user's tor, so a conflict is only ever resolved by killing our own leftover,
    never a foreign process. Returns [] on platforms without /proc.
    """
    proc_root = "/proc"
    if not os.path.isdir(proc_root):
        return []
    our_uid = os.getuid()
    self_pid = os.getpid()
    marker = os.path.abspath(data_dir)
    matches = []
    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == self_pid:
            continue
        base = os.path.join(proc_root, entry)
        try:
            if os.stat(base).st_uid != our_uid:
                continue
            with open(os.path.join(base, "cmdline"), "rb") as fh:
                argv = [a for a in fh.read().split(b"\x00") if a]
        except OSError:
            continue
        if not argv:
            continue
        if os.path.basename(argv[0].decode("utf-8", "replace")) != "tor":
            continue
        cmdline = b" ".join(argv).decode("utf-8", "replace")
        if marker in cmdline or _holds_fd_under(pid, marker):
            matches.append(pid)
    return matches


def _holds_fd_under(pid: int, directory: str) -> bool:
    """True if the process holds an open fd under `directory` (e.g. datadir lock)."""
    fd_dir = "/proc/%d/fd" % pid
    prefix = directory.rstrip(os.sep) + os.sep
    try:
        for fd in os.listdir(fd_dir):
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target == directory or target.startswith(prefix):
                return True
    except OSError:
        pass
    return False


def _reap_pid(pid: int, timeout: float = 5.0) -> None:
    """SIGTERM a pid, wait for exit, SIGKILL as a last resort."""
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class TorController:
    def __init__(self, config=None):
        self.config = config or Config()
        self._process = None
        self._controller = None
        self._newnym_lock = threading.Lock()
        self._last_newnym = 0.0

    def _busy_ports(self) -> list:
        return [
            p
            for p in (self.config.tor_socks_port, self.config.tor_control_port)
            if not _port_available(p)
        ]

    def _ensure_ports_free(self) -> None:
        """Clear our own orphaned tor from the configured ports, or fail fast.

        Reaps only a managed tor we own on our data directory. If a port is still
        held after that -- meaning the holder is a foreign or system tor -- raises
        with the same instruction the installer prints, rather than touching a
        process that is not ours.
        """
        if not self._busy_ports():
            return
        reaped = False
        for pid in _our_orphan_tor_pids(self.config.tor_data_dir):
            log.warning("reaping orphaned managed tor (pid %d) holding our ports", pid)
            _reap_pid(pid)
            reaped = True
        if reaped:
            deadline = time.time() + 5.0
            while time.time() < deadline and self._busy_ports():
                time.sleep(0.1)
        busy = self._busy_ports()
        if not busy:
            return
        ports = " and ".join(str(p) for p in busy)
        raise TorError(
            "tor port %s already in use, likely the distro tor service; the app "
            "launches its own managed tor and will collide. either free it "
            "(sudo systemctl disable --now tor) or run with alternate ports "
            "(export TOR_SOCKS_PORT=9060 TOR_CONTROL_PORT=9061)" % ports
        )

    def start(self):
        if self._process is not None:
            return
        data_dir = self.config.tor_data_dir
        os.makedirs(data_dir, exist_ok=True)

        self._ensure_ports_free()

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


class AttachedTorController:
    """Control-only client for a tor this process does not own.

    Attaches to a tor already running on the configured control port -- the
    console's managed instance -- so a separate tool such as the engine probe can
    rotate identity and share circuits without launching a second tor on the same
    ports. It never launches, terminates, or reaps a process: start() opens and
    authenticates a control connection and nothing more, and stop() closes only
    that connection, leaving the borrowed tor running. If no tor is listening on
    the control port, start() raises TorError so the caller can launch its own or
    fail per its selected mode.
    """

    def __init__(self, config=None):
        self.config = config or Config()
        self._controller = None
        self._newnym_lock = threading.Lock()
        self._last_newnym = 0.0

    def start(self):
        if self._controller is not None:
            return
        if _port_available(self.config.tor_control_port):
            raise TorError(
                "no running tor on control port %d to attach to; start the console "
                "(run.py) or use --tor-mode launch" % self.config.tor_control_port)
        try:
            self._controller = Controller.from_port(port=self.config.tor_control_port)
            self._controller.authenticate()
        except (stem.SocketError, stem.connection.AuthenticationFailure) as exc:
            self.stop()
            raise TorError("could not attach to running tor control port: %s" % exc)

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
        return self._controller is not None

    def stop(self):
        # Close only the control connection; never signal, terminate, or reap the
        # process -- the tor belongs to the console, not to this client.
        if self._controller is not None:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
