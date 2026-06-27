"""
system.py - local host readiness and the firewall save/restore.

preflight() fails fast on the things that make a run impossible: not root, no
nmap, no reachable msfrpcd. A disconnected msfdb is a warning, not a stop, since
module search still works just slowly. preflight leaves the passed MsfClient
connected so the orchestrator reuses the same session.

FirewallManager disables the host firewall so reverse listeners are not blocked,
but does it with restore discipline: snapshot the active ruleset to a 0600 temp
file first, restore on teardown, and register an independent atexit backstop so
the box is never left open even if orchestrator teardown is skipped. Backend
detection is layered (ufw, then nftables, then iptables-legacy) because 22.04+
defaults to nftables and iptables-nft rules surface under nft anyway. If restore
fails the manager stays armed and preserves the snapshot rather than silently
leaving the host exposed.
"""

from __future__ import annotations

import atexit
import logging
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from enum import Enum

from msf import MsfUnavailable

logger = logging.getLogger(__name__)


class PreflightError(Exception):
    pass


def preflight(nmap_path, msf_client, msfd):
    """Hard-fail on root, nmap, and msfrpcd. Warn on msfdb. Returns a list of
    warning strings. Ensures msfrpcd is running (starting it if absent and
    autostart is on) and connects msf_client, both as side effects."""
    warnings = []

    if not hasattr(os, "geteuid"):
        raise PreflightError("Linux required (no geteuid available)")
    if os.geteuid() != 0:
        raise PreflightError(
            "must run as root: SYN scan, firewall changes, and reverse "
            "listeners all require root")

    path = shutil.which(nmap_path)
    if not path and os.path.isabs(nmap_path) and os.access(nmap_path, os.X_OK):
        path = nmap_path
    if not path:
        raise PreflightError(f"nmap not found: '{nmap_path}'")
    try:
        proc = subprocess.run([path, "--version"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise PreflightError(f"nmap not runnable: {e}")
    if proc.returncode != 0:
        raise PreflightError(
            f"nmap not runnable: {proc.stderr.decode(errors='replace').strip()}")
    ver = proc.stdout.decode(errors="replace").splitlines()
    logger.info("nmap ok: %s", ver[0] if ver else "unknown version")

    msfd.ensure()
    try:
        msf_client.connect()
    except MsfUnavailable as e:
        raise PreflightError(f"msfrpcd unreachable: {e}")

    try:
        if not msf_client.db_ready():
            warnings.append(
                "msfdb not connected: module search will be slow "
                "(run 'msfdb init' and restart msfrpcd)")
    except Exception as e:
        logger.debug("db readiness probe error: %s", e)
        warnings.append("could not verify msfdb status; module search may be slow")

    return warnings


class FirewallBackend(str, Enum):
    UFW = "ufw"
    NFT = "nftables"
    IPTABLES = "iptables-legacy"
    NONE = "none"


class FirewallManager:
    def __init__(self):
        self.backend = FirewallBackend.NONE
        self._lock = threading.Lock()
        self._disabled = False
        self._atexit_registered = False
        self._snapshot_path = None
        self._snapshot_text = ""
        self._snapshot6_text = None     # iptables-legacy v6, when present

    # -- public --

    def detect(self):
        if _cmd_exists("ufw"):
            rc, out, _ = _run(["ufw", "status"])
            if rc == 0 and "status: active" in out.lower():
                return FirewallBackend.UFW
        if _cmd_exists("nft"):
            rc, out, _ = _run(["nft", "list", "ruleset"])
            if rc == 0 and _has_nft_rules(out):
                return FirewallBackend.NFT
        if _cmd_exists("iptables-legacy"):
            rc, out, _ = _run(["iptables-legacy", "-S"])
            if rc == 0 and _has_iptables_rules(out):
                return FirewallBackend.IPTABLES
        return FirewallBackend.NONE

    def disable(self):
        """Detect, snapshot, and disable the active firewall. Idempotent. Returns
        the detected backend."""
        with self._lock:
            if self._disabled:
                return self.backend
            self.backend = self.detect()
            self._register_atexit()
            if self.backend == FirewallBackend.NONE:
                logger.info("no active host firewall detected; nothing to disable")
                return self.backend
            self._snapshot()
            self._do_disable()
            self._disabled = True
            logger.info("host firewall disabled (%s); snapshot at %s",
                        self.backend.value, self._snapshot_path)
            return self.backend

    def restore(self):
        """Restore the firewall from snapshot. Idempotent. On failure the manager
        stays armed and the snapshot is preserved so atexit retries and the
        operator can restore by hand."""
        with self._lock:
            if not self._disabled:
                return
            try:
                self._do_restore()
            except Exception as e:
                logger.error(
                    "FIREWALL RESTORE FAILED (%s): %s -- box may be exposed; "
                    "snapshot preserved at %s", self.backend.value, e,
                    self._snapshot_path)
                return
            self._disabled = False
            logger.info("host firewall restored (%s)", self.backend.value)
            self._cleanup_snapshot()

    def status(self):
        return {"backend": self.backend.value, "disabled": self._disabled,
                "snapshot": self._snapshot_path}

    # -- internals --

    def _register_atexit(self):
        if not self._atexit_registered:
            atexit.register(self._atexit_restore)
            self._atexit_registered = True

    def _atexit_restore(self):
        if self._disabled:
            logger.warning("atexit: firewall still disabled, restoring")
            self.restore()

    def _snapshot(self):
        fd, path = tempfile.mkstemp(prefix="rcs_fw_", suffix=".bak")
        os.close(fd)
        os.chmod(path, 0o600)
        text = ""
        if self.backend == FirewallBackend.UFW:
            _, text, _ = _run(["ufw", "status", "verbose"])
        elif self.backend == FirewallBackend.NFT:
            _, text, _ = _run(["nft", "list", "ruleset"])
        elif self.backend == FirewallBackend.IPTABLES:
            _, text, _ = _run(["iptables-legacy-save"])
            if _cmd_exists("ip6tables-legacy-save"):
                _, self._snapshot6_text, _ = _run(["ip6tables-legacy-save"])
        with open(path, "w") as f:
            f.write(text)
        self._snapshot_path = path
        self._snapshot_text = text

    def _do_disable(self):
        if self.backend == FirewallBackend.UFW:
            _run(["ufw", "--force", "disable"])
        elif self.backend == FirewallBackend.NFT:
            _run(["nft", "flush", "ruleset"])
        elif self.backend == FirewallBackend.IPTABLES:
            self._flush_iptables("iptables-legacy")
            if _cmd_exists("ip6tables-legacy"):
                self._flush_iptables("ip6tables-legacy")

    def _flush_iptables(self, binary):
        for chain in ("INPUT", "FORWARD", "OUTPUT"):
            _run([binary, "-P", chain, "ACCEPT"])
        _run([binary, "-F"])
        _run([binary, "-X"])

    def _do_restore(self):
        if self.backend == FirewallBackend.UFW:
            rc, _, err = _run(["ufw", "--force", "enable"])
            if rc != 0:
                raise RuntimeError(err or "ufw enable failed")
        elif self.backend == FirewallBackend.NFT:
            _run(["nft", "flush", "ruleset"])
            if self._snapshot_text.strip():
                rc, _, err = _run(["nft", "-f", self._snapshot_path])
                if rc != 0:
                    raise RuntimeError(err or "nft -f failed")
        elif self.backend == FirewallBackend.IPTABLES:
            rc, _, err = _run(["iptables-legacy-restore"], data=self._snapshot_text)
            if rc != 0:
                raise RuntimeError(err or "iptables-restore failed")
            if self._snapshot6_text is not None and _cmd_exists("ip6tables-legacy-restore"):
                rc6, _, err6 = _run(["ip6tables-legacy-restore"],
                                    data=self._snapshot6_text)
                if rc6 != 0:
                    raise RuntimeError(err6 or "ip6tables-restore failed")

    def _cleanup_snapshot(self):
        if self._snapshot_path:
            try:
                os.unlink(self._snapshot_path)
            except OSError:
                pass
            self._snapshot_path = None


class MsfdManager:
    """Ensure msfrpcd is up, starting it only if absent. A daemon we did not
    start is detected, used, and never stopped. One we start we own: launched
    with -f so it stays in the foreground under our Popen, stopped on teardown,
    with an independent atexit backstop so a skipped teardown does not leak it.
    connect() in MsfClient remains the real validator (it logs in over RPC); the
    port probe here only decides whether a daemon needs starting."""

    def __init__(self, host, port, password, ssl=True, username="msf",
                 msfrpcd_path="msfrpcd", autostart=True, boot_timeout=60,
                 run_as=None):
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self.username = username
        self.path = msfrpcd_path
        self.autostart = autostart
        self.boot_timeout = boot_timeout
        self.run_as = run_as            # pwd struct to drop to, or None
        self._lock = threading.Lock()
        self._proc = None
        self._logfile = None
        self._started = False           # True only if we spawned the process
        self._atexit_registered = False

    # -- public --

    def ensure(self):
        """Continue if msfrpcd is already listening. Otherwise start it (when
        autostart is on) and wait for the port. Idempotent. Raises PreflightError
        if a needed start fails."""
        with self._lock:
            if _port_open(self.host, self.port):
                logger.info("msfrpcd already listening on %s:%d; using it",
                            self.host, self.port)
                return
            if not self.autostart:
                logger.info("msfrpcd not detected on %s:%d and autostart is "
                            "off; relying on connect()", self.host, self.port)
                return
            if not self.password:
                raise PreflightError(
                    "msfrpcd is not running and MSF_RPC_PASS is empty: set a "
                    "password (or start msfrpcd yourself, or pass "
                    "--no-msf-autostart)")
            self._register_atexit()
            self._spawn()
            self._wait_ready()
            self._started = True
            logger.info("msfrpcd started (pid %d) on %s:%d",
                        self._proc.pid, self.host, self.port)

    def stop(self):
        """Stop msfrpcd only if we started it. Idempotent. Note: this drops any
        sessions opened during the run, since they live in that daemon."""
        with self._lock:
            if not self._started or self._proc is None:
                return
            self._kill_proc()
            self._started = False
            self._cleanup_log()
            logger.info("msfrpcd stopped")

    def status(self):
        running = self._proc is not None and self._proc.poll() is None
        return {"host": self.host, "port": self.port,
                "started_by_us": self._started, "running": running}

    # -- internals --

    def _register_atexit(self):
        if not self._atexit_registered:
            atexit.register(self._atexit_stop)
            self._atexit_registered = True

    def _atexit_stop(self):
        if self._started:
            logger.warning("atexit: msfrpcd still running, stopping")
            self.stop()

    def _drop_target(self):
        """Return (uid, gid, name, home) the child should drop to, or None to keep
        the current identity. Drops only when running as root and a non-root target
        is set, since only root can change uid."""
        if self.run_as is None:
            return None
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return None
        pw = self.run_as
        if pw.pw_uid == 0:
            return None
        return (pw.pw_uid, pw.pw_gid, pw.pw_name, pw.pw_dir)

    def _spawn(self):
        fd, path = tempfile.mkstemp(prefix="rcs_msfd_", suffix=".log")
        os.close(fd)
        os.chmod(path, 0o600)
        self._logfile = path
        cmd = [self.path, "-f", "-a", self.host, "-p", str(self.port),
               "-U", self.username, "-P", self.password]
        if not self.ssl:
            cmd.append("-S")            # msfrpcd: -S disables SSL (on by default)
        # Source checkouts boot through Bundler, which resolves the framework
        # Gemfile relative to the working directory, so launch from the binary's
        # directory (Bundler then walks up to the Gemfile).
        resolved = shutil.which(self.path) or os.path.abspath(self.path)
        bindir = os.path.dirname(resolved)
        cwd = bindir if os.path.isdir(bindir) else None

        # Under sudo the process is root, but msfrpcd needs no privilege and the
        # framework's gems and ~/.msf4 live in the invoking user's home. Drop the
        # child to that user with their HOME so gem/bundler resolution matches an
        # interactive run; nmap and the firewall stay root in the parent.
        drop = self._drop_target()
        if drop is not None and sys.version_info < (3, 9):
            self._cleanup_log()
            raise PreflightError(
                "running msfrpcd as a non-root user needs Python 3.9+; upgrade, "
                "or start msfrpcd yourself and pass --no-msf-autostart")
        try:
            logf = open(path, "ab")
            try:
                kwargs = dict(stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,
                              cwd=cwd)
                if drop is not None:
                    uid, gid, name, home = drop
                    kwargs["user"] = uid
                    kwargs["group"] = gid
                    try:
                        kwargs["extra_groups"] = os.getgrouplist(name, gid)
                    except (KeyError, OSError):
                        kwargs["extra_groups"] = [gid]
                    kwargs["env"] = _child_env(name, home)
                    logger.info("starting msfrpcd as %s (uid %d), HOME=%s",
                                name, uid, home)
                self._proc = subprocess.Popen(cmd, **kwargs)
            finally:
                logf.close()            # child keeps its own dup of the fd
        except FileNotFoundError:
            self._cleanup_log()
            raise PreflightError(f"msfrpcd not found: '{self.path}'")
        except PermissionError as e:
            self._cleanup_log()
            raise PreflightError(f"cannot start msfrpcd as that user: {e}")
        except OSError as e:
            self._cleanup_log()
            raise PreflightError(f"could not start msfrpcd: {e}")

    def _wait_ready(self):
        deadline = time.time() + self.boot_timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                rc = self._proc.returncode
                tail = self._log_tail()
                self._cleanup_log()
                raise PreflightError(
                    f"msfrpcd exited during startup (rc={rc}); last output: "
                    f"{tail or '(none)'}")
            if _port_open(self.host, self.port):
                return
            time.sleep(0.5)
        tail = self._log_tail()
        self._kill_proc()
        self._cleanup_log()
        raise PreflightError(
            f"msfrpcd did not open {self.host}:{self.port} within "
            f"{self.boot_timeout}s; last output: {tail or '(none)'}")

    def _kill_proc(self):
        # caller holds the lock
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("msfrpcd did not exit on SIGTERM; killing")
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self._proc = None

    def _log_tail(self, limit=600):
        if not self._logfile:
            return ""
        try:
            with open(self._logfile, "r", errors="replace") as f:
                data = f.read()
        except OSError:
            return ""
        return data.strip().replace("\n", " | ")[-limit:]

    def _cleanup_log(self):
        if self._logfile:
            try:
                os.unlink(self._logfile)
            except OSError:
                pass
            self._logfile = None


# --- helpers ---------------------------------------------------------------

def _cmd_exists(name):
    return shutil.which(name) is not None


def _port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


_MSFRPCD_CANDIDATES = (
    "/opt/metasploit-framework/bin/msfrpcd",
    "/opt/metasploit-framework/msfrpcd",
    "/usr/share/metasploit-framework/msfrpcd",
    "/usr/local/bin/msfrpcd",
    "/usr/bin/msfrpcd",
)


def find_msfrpcd():
    """Best-effort locate of the msfrpcd binary. Returns an absolute path or "".
    Tries PATH, then common install locations, then the locate database (which
    catches nonstandard trees). Only paths with an execute bit are accepted."""
    found = shutil.which("msfrpcd")
    if found:
        return found
    for cand in _MSFRPCD_CANDIDATES:
        if os.access(cand, os.X_OK):
            return cand
    if _cmd_exists("locate"):
        rc, out, _ = _run(["locate", "msfrpcd"])
        if rc == 0:
            for line in out.splitlines():
                line = line.strip()
                if line.endswith("/msfrpcd") and os.access(line, os.X_OK):
                    return line
    return ""


def resolve_run_as(name=None):
    """Resolve the user msfrpcd should run as. An explicit name is looked up
    directly; otherwise the sudo-invoking user (SUDO_USER) is used. Returns a pwd
    struct, or None to run as the current user. Raises PreflightError on a bad
    explicit name."""
    if name:
        try:
            return pwd.getpwnam(name)
        except KeyError:
            raise PreflightError(f"--msf-user: no such user '{name}'")
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return pwd.getpwnam(sudo_user)
        except KeyError:
            logger.warning("SUDO_USER '%s' not resolvable; running msfrpcd as "
                           "current user", sudo_user)
    return None


def _child_env(name, home):
    """Environment for a dropped msfrpcd: the parent env with HOME/USER/LOGNAME
    pointed at the target user and any root-inherited gem/bundler overrides
    removed, so resolution is purely HOME-based."""
    env = dict(os.environ)
    env["HOME"] = home
    env["USER"] = name
    env["LOGNAME"] = name
    env["PATH"] = _user_path(home, env.get("PATH", ""))
    for k in ("GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE", "BUNDLE_PATH",
              "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
        env.pop(k, None)
    return env


def _user_path(home, current):
    extras = [os.path.join(home, ".rbenv", "shims"),
              os.path.join(home, ".rvm", "bin"),
              os.path.join(home, ".local", "bin"),
              os.path.join(home, "bin")]
    parts = [p for p in extras if os.path.isdir(p)]
    base = current or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return os.pathsep.join(parts + [base]) if parts else base


def _run(cmd, data=None):
    """Run a command. Returns (returncode, stdout, stderr) as text. stdin is
    DEVNULL unless data is supplied (then it is piped in)."""
    try:
        if data is None:
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            proc = subprocess.run(cmd, input=data.encode(),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except OSError as e:
        return 1, "", str(e)
    return (proc.returncode,
            proc.stdout.decode(errors="replace"),
            proc.stderr.decode(errors="replace"))


def _has_nft_rules(out):
    return "table " in out


def _has_iptables_rules(out):
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("-A "):
            return True
        if line.startswith("-P ") and not line.endswith(" ACCEPT"):
            return True
    return False


__all__ = ["PreflightError", "preflight", "FirewallBackend", "FirewallManager",
           "MsfdManager", "find_msfrpcd", "resolve_run_as"]
