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
import secrets
import signal
import socket
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from state import (RunState, HostState, Candidate, Verdict, TERMINAL_STATES,
                   is_exploitable_verdict)
from scanner import Scanner, ScanConfig, NmapError, nse_scripts_for_cve
from msf import MsfClient, MsfConfig
from system import preflight, PreflightError, FirewallManager, MsfdManager

logger = logging.getLogger(__name__)

# Fire ordering: prefer confirmed-vulnerable, then likely, then unknown. Safe and
# unsupported candidates are never fired.
_FIRE_PRIORITY = {Verdict.VULNERABLE: 3, Verdict.LIKELY: 2, Verdict.UNKNOWN: 1}
_RANK_ORDER = {"excellent": 600, "great": 500}


@dataclass
class OrchestratorConfig:
    workers: int = 10
    fire_workers: int = 1
    chunk_size: int = 2048
    checkpoint_interval: float = 15.0
    poll_interval: float = 0.25
    headless_status_interval: float = 5.0


DEFAULT_CONFIG_FILE = ".orchestration_config"


class OrchestrationConfig:
    """Persisted run config in the working directory, mode 0600. Currently holds
    only the msfrpcd RPC password so unattended runs reuse one credential instead
    of needing MSF_RPC_PASS set by hand. The password guards a localhost-bound
    msfrpcd, so a 0600 root-owned file is the right place for it. Stored as JSON
    so the file can grow without a format change."""

    def __init__(self, path=DEFAULT_CONFIG_FILE):
        self.path = path

    def read_password(self):
        """Return the stored password, or "" if the file is absent or unreadable.
        Tightens perms to 0600 first if the existing file is looser."""
        if not os.path.exists(self.path):
            return ""
        self._enforce_perms()
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            logger.warning("could not read %s: %s", self.path, e)
            return ""
        pw = data.get("msf_rpc_password", "")
        return pw if isinstance(pw, str) else ""

    def ensure_password(self):
        """Return the stored password, generating and persisting one (0600) if the
        file has none. O_EXCL create keeps two concurrent runs in the same
        directory from clobbering each other."""
        pw = self.read_password()
        if pw:
            return pw
        pw = secrets.token_urlsafe(32)
        blob = json.dumps(
            {"version": 1, "msf_rpc_password": pw,
             "created": datetime.datetime.now(datetime.timezone.utc).isoformat()},
            indent=2) + "\n"
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # a concurrent run created it between our read and create; use theirs
            return self.read_password() or pw
        except OSError as e:
            raise PreflightError(f"could not create {self.path}: {e}")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(blob)
            os.chmod(self.path, 0o600)
        except OSError as e:
            raise PreflightError(f"could not write {self.path}: {e}")
        logger.info("generated msfrpcd password, stored at %s (0600)",
                    os.path.abspath(self.path))
        return pw

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


class Orchestrator:
    def __init__(self, run: RunState, scanner: Scanner, msf_client: MsfClient,
                 firewall: FirewallManager, msfd: MsfdManager,
                 cfg: OrchestratorConfig):
        self.run = run
        self.scanner = scanner
        self.msf = msf_client
        self.fw = firewall
        self.msfd = msfd
        self.cfg = cfg
        self._scan_pool = None
        self._fire_pool = None
        self._stop = threading.Event()
        self._teardown_done = False
        self._teardown_lock = threading.Lock()
        self._discovered_ports = {}

    # -- lifecycle --

    def run_pipeline(self, display=None):
        self._install_signal_handlers()
        try:
            self.fw.disable()
            self._discover_phase()
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
        try:
            self._fire_pool.submit(self._fire_wrapper, ip)
        except RuntimeError:
            # pool shutting down during teardown
            pass

    def _do_scan(self, ip):
        self.run.transition(ip, HostState.SCANNING)
        ports = self._discovered_ports.get(ip) or self._ports_from_state(ip)
        hostname, services = self.scanner.vulners_scan(ip, ports)
        if hostname:
            self.run.set_hostname(ip, hostname)
        self.run.set_services(ip, services)
        self.run.transition(ip, HostState.ANALYZED)

    def _do_analyze(self, ip):
        host = self.run.host_copy(ip)
        candidates = []
        for svc in host.services:
            candidates.extend(self.msf.candidates_for_service(svc))
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
        nse_done = set()
        for cand in msf_cands:
            if self._stop.is_set():
                break
            verdict, detail = self.msf.check(cand, ip, cand.port)
            self.run.update_candidate_result(ip, cand.module, verdict, detail)
            if is_exploitable_verdict(verdict):
                any_exploitable = True
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
        self.run.transition(
            ip, HostState.EXPLOITABLE if any_exploitable
            else HostState.NOT_EXPLOITABLE)

    def _fire_wrapper(self, ip):
        if self._stop.is_set():
            return
        with self.run.worker_slot():
            try:
                self._do_fire(ip)
            except Exception as e:
                self.run.set_error(ip, f"fire error: {e}")
                logger.exception("fire failed for %s", ip)

    def _do_fire(self, ip):
        self.run.transition(ip, HostState.EXPLOITING)
        host = self.run.host_copy(ip)
        session = None
        for cand in _fireable(host):
            if self._stop.is_set():
                break
            session = self.msf.fire(cand, host, ip, cand.port)
            if session is not None:
                self.run.add_session(ip, session)
                break
        self.run.transition(
            ip, HostState.EXPLOITED if session is not None else HostState.FAILED)

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
        if display is not None:
            try:
                display.stop()
            except Exception:
                pass
        try:
            self.msf.close()
        except Exception:
            pass
        try:
            self.msfd.stop()
        except Exception:
            logger.exception("msfrpcd stop in teardown failed")


# --- fire candidate selection ----------------------------------------------

def _fireable(host):
    out = []
    for c in host.candidates:
        if c.source != "msf":
            continue
        if c.check_result in (Verdict.SAFE, Verdict.UNSUPPORTED):
            continue
        out.append(c)
    out.sort(key=lambda c: (_FIRE_PRIORITY.get(c.check_result, 0),
                            _RANK_ORDER.get(c.rank, 0)), reverse=True)
    return out


# --- scope expansion -------------------------------------------------------

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
    p.add_argument("--mode", choices=("check", "autopwn"), default="check",
                   help="check only (default) or autopwn (fire)")
    p.add_argument("--workers", type=int, default=10)
    p.add_argument("--fire-workers", type=int, default=1)
    p.add_argument("--chunk-size", type=int, default=2048)
    p.add_argument("--checkpoint-interval", type=float, default=15.0)
    p.add_argument("--top-ports", type=int, default=1000)
    p.add_argument("--ports", default="", help="discovery -p override")
    p.add_argument("--mincvss", type=float, default=7.0)
    p.add_argument("--timing", default="-T4")
    p.add_argument("--candidates-per-service", type=int, default=5)
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
    p.add_argument("--config-file", default=DEFAULT_CONFIG_FILE,
                   help="persisted run config (msfrpcd password), 0600")
    p.add_argument("--log-file", default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
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
        targets = [ip for ip in targets if ip not in excludes]
        if not targets:
            logger.error("no targets in scope")
            return 2
        _scope_guard(targets, args)
        run = RunState(mode=args.mode, checkpoint_path=args.checkpoint,
                       findings_path=args.findings)
        run.add_hosts(targets)

    if not run.snapshot_hosts():
        logger.error("no targets in scope")
        return 2

    scfg = ScanConfig(nmap_path=args.nmap_path, discovery_top_ports=args.top_ports,
                      discovery_ports=args.ports or "", timing=args.timing,
                      mincvss=args.mincvss)
    scanner = Scanner(scfg)
    mcfg = MsfConfig.from_env(
        host=args.msf_host, port=args.msf_port, password=args.msf_pass,
        ssl=args.msf_ssl, candidates_per_service=args.candidates_per_service,
        lhost=args.lhost or "")
    if not mcfg.password:
        # Nothing from --msf-pass or MSF_RPC_PASS. Reuse the persisted credential,
        # generating one when we will be starting msfrpcd ourselves. When autostart
        # is off we only read an existing file; connect() reports an empty password.
        cfgfile = OrchestrationConfig(args.config_file)
        try:
            if args.no_msf_autostart:
                mcfg.password = cfgfile.read_password()
            else:
                mcfg.password = cfgfile.ensure_password()
        except PreflightError as e:
            logger.error("preflight failed: %s", e)
            return 1
    msf_client = MsfClient(mcfg)
    fw = FirewallManager()
    msfd = MsfdManager(host=mcfg.host, port=mcfg.port, password=mcfg.password,
                       ssl=mcfg.ssl, username=mcfg.username,
                       msfrpcd_path=args.msfrpcd_path,
                       autostart=not args.no_msf_autostart)

    try:
        warnings = preflight(args.nmap_path, msf_client, msfd)
        for w in warnings:
            logger.warning("preflight: %s", w)
    except PreflightError as e:
        logger.error("preflight failed: %s", e)
        return 1

    ocfg = OrchestratorConfig(
        workers=args.workers, fire_workers=args.fire_workers,
        chunk_size=args.chunk_size, checkpoint_interval=args.checkpoint_interval)
    orch = Orchestrator(run, scanner, msf_client, fw, msfd, ocfg)

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
