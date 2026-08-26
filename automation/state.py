#!/usr/bin/env python3
# =============================================================================
# Location    automation/state.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
#
# License     MIT License
#
# Purpose     Shared run state, host lifecycle, stats, and checkpoint/findings
#             persistence for the orchestrator. Single source of truth read by
#             the TUI and written by the pipeline workers under one lock.
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
state.py - shared run state, host lifecycle, stats, and persistence.

Single source of truth read by the TUI and written by the pipeline workers.
All access is guarded by an RLock. Persistence (checkpoint and findings) takes a
brief locked snapshot then performs file IO unlocked, so disk writes never block
a TUI repaint. Resume support rewinds in-flight states to a safe re-entry point.

Proven-impact model: a host is COMPROMISED only when it has a session, a valid
credential, or a confirmed unauthenticated/misconfiguration access. There is no
check verdict; nothing merely "potentially vulnerable" is a finding. CVEs stay on
services as context, not as findings.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Iterable

logger = logging.getLogger(__name__)

TOOL = "vapt-orchestrator"
VERSION = "0.3.0"


def _now() -> float:
    return time.time()


# --- enums -----------------------------------------------------------------

class HostState(str, Enum):
    QUEUED = "queued"
    DISCOVERED = "discovered"
    DOWN = "down"
    SCANNING = "scanning"
    ANALYZED = "analyzed"
    ATTACKING = "attacking"       # exploit fire, login brute, and unauth run
    COMPROMISED = "compromised"   # proven: session, credential, or access
    CLEAN = "clean"               # alive, fully attacked, nothing proven
    ERROR = "error"


class Verdict(str, Enum):
    """Retained for NSE vuln-script normalization in the scanner. Not a host
    state and not a finding under the proven-impact model."""
    VULNERABLE = "vulnerable"
    LIKELY = "likely"
    SAFE = "safe"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


ACTIVE_STATES = frozenset({
    HostState.DISCOVERED, HostState.SCANNING, HostState.ANALYZED,
    HostState.ATTACKING,
})
RESULT_STATES = frozenset({HostState.COMPROMISED})
TERMINAL_STATES = frozenset({
    HostState.DOWN, HostState.COMPROMISED, HostState.CLEAN, HostState.ERROR,
})
_COMPLETED = TERMINAL_STATES

_TRANSITIONS = {
    HostState.QUEUED: frozenset({HostState.DISCOVERED, HostState.DOWN}),
    HostState.DISCOVERED: frozenset({HostState.SCANNING}),
    HostState.SCANNING: frozenset({HostState.ANALYZED}),
    HostState.ANALYZED: frozenset({HostState.ATTACKING, HostState.CLEAN}),
    HostState.ATTACKING: frozenset({HostState.COMPROMISED, HostState.CLEAN}),
    HostState.DOWN: frozenset(),
    HostState.COMPROMISED: frozenset(),
    # clean can still be upgraded to compromised when the late global brute phase
    # finds a credential on a host the per-host attack left clean.
    HostState.CLEAN: frozenset({HostState.COMPROMISED}),
    HostState.ERROR: frozenset(),
}

# States unsafe to trust after a crash; rewind to the last stable point on resume.
_RESUME_REWIND = {
    HostState.SCANNING: HostState.DISCOVERED,
    HostState.ATTACKING: HostState.ANALYZED,
}

# Old check-era states mapped forward when loading a pre-0.3 checkpoint.
_LEGACY_STATE = {
    "candidates": "analyzed",
    "no_candidates": "clean",
    "checking": "analyzed",
    "exploitable": "attacking",
    "not_exploitable": "clean",
    "exploiting": "attacking",
    "exploited": "compromised",
    "failed": "clean",
}


class InvalidTransition(Exception):
    pass


def verdict_from_nse(text: str) -> Verdict:
    """Normalize NSE vuln-script output text to a Verdict. Order matters."""
    t = (text or "").lower()
    if "vulnerable" in t and "not vulnerable" not in t:
        return Verdict.VULNERABLE
    if "likely" in t or "appears" in t:
        return Verdict.LIKELY
    if "not vulnerable" in t:
        return Verdict.SAFE
    return Verdict.UNKNOWN


# --- records ---------------------------------------------------------------

@dataclass
class CVE:
    cve_id: str
    cvss: float = 0.0
    exploit: bool = False          # vulners flagged a public exploit (*EXPLOIT*)
    source: str = "vulners"

    @classmethod
    def from_dict(cls, d):
        return cls(cve_id=d["cve_id"], cvss=float(d.get("cvss", 0.0)),
                   exploit=bool(d.get("exploit", False)),
                   source=d.get("source", "vulners"))


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str = ""                 # nmap service name, e.g. microsoft-ds
    product: str = ""
    version: str = ""
    cpe: str = ""
    method: str = ""               # nmap service detection method: probed | table
    conf: int = 0                  # nmap confidence 0-10 for the identification
    cves: list[CVE] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d):
        s = cls(port=int(d["port"]), protocol=d.get("protocol", "tcp"),
                name=d.get("name", ""), product=d.get("product", ""),
                version=d.get("version", ""), cpe=d.get("cpe", ""),
                method=d.get("method", ""), conf=int(d.get("conf", 0) or 0))
        s.cves = [CVE.from_dict(x) for x in d.get("cves", [])]
        return s


@dataclass
class Candidate:
    module: str                    # full msf path, or nse script id
    cve_id: str = ""               # CVE this candidate maps to, if any
    rank: str = ""                 # msf rank name (display + findings)
    port: int = 0
    source: str = "msf"            # msf | product | auxiliary | unauth | nse
    fire_status: str = ""          # "" until fired: session|no_session|blocked|error
    fire_detail: str = ""          # reason a fire blocked/failed, for review

    @classmethod
    def from_dict(cls, d):
        return cls(module=d["module"], cve_id=d.get("cve_id", ""),
                   rank=d.get("rank", ""), port=int(d.get("port", 0)),
                   source=d.get("source", "msf"),
                   fire_status=d.get("fire_status", ""),
                   fire_detail=d.get("fire_detail", ""))


@dataclass
class Session:
    session_id: str
    module: str
    payload: str = ""
    info: str = ""
    opened_at: float = field(default_factory=_now)

    @classmethod
    def from_dict(cls, d):
        return cls(session_id=str(d["session_id"]), module=d.get("module", ""),
                   payload=d.get("payload", ""), info=d.get("info", ""),
                   opened_at=float(d.get("opened_at", _now())))


@dataclass
class Credential:
    service: str                   # nmap service name (ssh, mysql, ...)
    port: int
    username: str
    password: str
    module: str                    # the login scanner that found it
    session_id: str = ""           # set when the login opened a session
    found_at: float = field(default_factory=_now)

    @classmethod
    def from_dict(cls, d):
        return cls(service=d.get("service", ""), port=int(d.get("port", 0)),
                   username=d.get("username", ""), password=d.get("password", ""),
                   module=d.get("module", ""),
                   session_id=str(d.get("session_id", "")),
                   found_at=float(d.get("found_at", _now())))


@dataclass
class Access:
    """Confirmed unauthenticated or misconfiguration access, the proof produced by
    the unauth/auxiliary tier. Not a maybe: the module established or read
    something (null session, unauth Redis keys, anonymous FTP listing)."""
    service: str
    port: int
    module: str
    proof: str                     # one-line proof text
    found_at: float = field(default_factory=_now)

    @classmethod
    def from_dict(cls, d):
        return cls(service=d.get("service", ""), port=int(d.get("port", 0)),
                   module=d.get("module", ""), proof=d.get("proof", ""),
                   found_at=float(d.get("found_at", _now())))


@dataclass
class Host:
    ip: str
    hostname: str = ""
    state: HostState = HostState.QUEUED
    os_match: str = ""             # os/arch fingerprint for payload selection
    arch: str = ""
    services: list[Service] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    access: list[Access] = field(default_factory=list)
    error: str = ""
    notes: str = ""
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)

    @property
    def open_ports(self) -> int:
        return len(self.services)

    @property
    def cve_count(self) -> int:
        return sum(len(s.cves) for s in self.services)

    @property
    def exploit_cve_count(self) -> int:
        return sum(1 for s in self.services for c in s.cves if c.exploit)

    @property
    def session_count(self) -> int:
        return len(self.sessions)

    @property
    def credential_count(self) -> int:
        return len(self.credentials)

    @property
    def access_count(self) -> int:
        return len(self.access)

    @property
    def is_compromised(self) -> bool:
        """Proven impact: a session, a credential, or a confirmed access."""
        return bool(self.sessions or self.credentials or self.access)

    @classmethod
    def from_dict(cls, d):
        h = cls(ip=d["ip"])
        h.hostname = d.get("hostname", "")
        raw = d.get("state", "queued")
        raw = _LEGACY_STATE.get(raw, raw)
        try:
            h.state = HostState(raw)
        except ValueError:
            h.state = HostState.QUEUED
        h.os_match = d.get("os_match", "")
        h.arch = d.get("arch", "")
        h.error = d.get("error", "")
        h.notes = d.get("notes", "")
        h.created_at = float(d.get("created_at", _now()))
        h.updated_at = float(d.get("updated_at", h.created_at))
        h.services = [Service.from_dict(x) for x in d.get("services", [])]
        h.candidates = [Candidate.from_dict(x) for x in d.get("candidates", [])]
        h.sessions = [Session.from_dict(x) for x in d.get("sessions", [])]
        h.credentials = [Credential.from_dict(x)
                         for x in d.get("credentials", [])]
        h.access = [Access.from_dict(x) for x in d.get("access", [])]
        return h


@dataclass(frozen=True)
class Stats:
    total: int
    queued: int
    live: int
    down: int
    scanning: int
    analyzed: int
    attacking: int
    compromised: int
    clean: int
    errored: int
    completed: int
    sessions: int
    credentials: int
    access: int
    cves: int
    exploit_cves: int
    active_workers: int
    phase: str
    mode: str
    elapsed: float


@dataclass(frozen=True)
class Activity:
    ts: float
    source: str
    text: str


# --- run state -------------------------------------------------------------

class RunState:
    def __init__(self, mode="autopwn", checkpoint_path=None, findings_path=None):
        self._lock = threading.RLock()
        self._hosts: dict[str, Host] = {}
        self.mode = mode or "autopwn"
        self.phase = "init"
        self._active_workers = 0
        self.started_at = _now()
        self.checkpoint_path = checkpoint_path
        self.findings_path = findings_path
        self._activity = deque(maxlen=500)   # ephemeral command feed; not persisted

    # -- population --

    def add_host(self, ip):
        with self._lock:
            if ip not in self._hosts:
                self._hosts[ip] = Host(ip=ip)

    def add_hosts(self, ips: Iterable[str]):
        with self._lock:
            for ip in ips:
                if ip not in self._hosts:
                    self._hosts[ip] = Host(ip=ip)

    def has_host(self, ip) -> bool:
        with self._lock:
            return ip in self._hosts

    def get_state(self, ip) -> HostState:
        with self._lock:
            return self._hosts[ip].state

    # -- mutation --

    def transition(self, ip, new_state):
        with self._lock:
            h = self._hosts[ip]
            if new_state == h.state:
                return
            if new_state != HostState.ERROR:
                allowed = _TRANSITIONS.get(h.state, frozenset())
                if new_state not in allowed:
                    raise InvalidTransition(
                        f"{ip}: {h.state.value} -> {new_state.value}")
            h.state = new_state
            h.updated_at = _now()
        logger.debug("state %s -> %s", ip, new_state.value)

    def set_error(self, ip, msg):
        with self._lock:
            if ip in self._hosts:
                self._hosts[ip].error = str(msg)
        self.transition(ip, HostState.ERROR)

    def set_hostname(self, ip, hostname):
        with self._lock:
            h = self._hosts[ip]
            h.hostname = hostname or ""
            h.updated_at = _now()

    def set_fingerprint(self, ip, os_match="", arch=""):
        with self._lock:
            h = self._hosts[ip]
            if os_match:
                h.os_match = os_match
            if arch:
                h.arch = arch
            h.updated_at = _now()

    def add_service(self, ip, service: Service):
        with self._lock:
            h = self._hosts[ip]
            h.services.append(service)
            h.updated_at = _now()

    def set_services(self, ip, services):
        with self._lock:
            h = self._hosts[ip]
            h.services = list(services)
            h.updated_at = _now()

    def add_candidate(self, ip, candidate: Candidate):
        with self._lock:
            h = self._hosts[ip]
            h.candidates.append(candidate)
            h.updated_at = _now()

    def set_candidates(self, ip, candidates):
        with self._lock:
            h = self._hosts[ip]
            h.candidates = list(candidates)
            h.updated_at = _now()

    def update_candidate_fire(self, ip, module, status, detail=""):
        with self._lock:
            h = self._hosts[ip]
            for c in h.candidates:
                if c.module == module:
                    c.fire_status = status or ""
                    if detail:
                        c.fire_detail = detail
            h.updated_at = _now()

    def add_session(self, ip, session: Session):
        with self._lock:
            h = self._hosts[ip]
            h.sessions.append(session)
            h.updated_at = _now()

    def add_credential(self, ip, cred: Credential):
        with self._lock:
            h = self._hosts[ip]
            h.credentials.append(cred)
            h.updated_at = _now()

    def add_access(self, ip, acc: Access):
        with self._lock:
            h = self._hosts[ip]
            h.access.append(acc)
            h.updated_at = _now()

    def set_note(self, ip, note):
        with self._lock:
            h = self._hosts[ip]
            h.notes = note or ""
            h.updated_at = _now()

    def set_phase(self, phase):
        with self._lock:
            self.phase = phase
            self._activity.append(Activity(_now(), "phase", f"phase {phase}"))

    def record_activity(self, source, text):
        """Append a one-line command/operation to the ephemeral feed. Thread-safe;
        many workers call this. Bounded by the deque maxlen."""
        with self._lock:
            self._activity.append(Activity(_now(), source, text))

    def recent_activity(self, limit):
        """Most recent feed entries, oldest first, capped at limit."""
        with self._lock:
            if limit <= 0:
                return []
            return list(self._activity)[-limit:]

    @contextmanager
    def worker_slot(self):
        with self._lock:
            self._active_workers += 1
        try:
            yield
        finally:
            with self._lock:
                self._active_workers -= 1

    # -- aggregation and reads --

    def stats(self) -> Stats:
        with self._lock:
            counts = {s: 0 for s in HostState}
            sessions = cves = exploit_cves = credentials = access = 0
            for h in self._hosts.values():
                counts[h.state] += 1
                sessions += len(h.sessions)
                credentials += len(h.credentials)
                access += len(h.access)
                cves += h.cve_count
                exploit_cves += h.exploit_cve_count
            total = len(self._hosts)
            completed = sum(counts[s] for s in _COMPLETED)
            queued = counts[HostState.QUEUED]
            down = counts[HostState.DOWN]
            return Stats(
                total=total,
                queued=queued,
                live=total - queued - down,
                down=down,
                scanning=counts[HostState.SCANNING],
                analyzed=counts[HostState.ANALYZED],
                attacking=counts[HostState.ATTACKING],
                compromised=counts[HostState.COMPROMISED],
                clean=counts[HostState.CLEAN],
                errored=counts[HostState.ERROR],
                completed=completed,
                sessions=sessions,
                credentials=credentials,
                access=access,
                cves=cves,
                exploit_cves=exploit_cves,
                active_workers=self._active_workers,
                phase=self.phase,
                mode=self.mode,
                elapsed=_now() - self.started_at,
            )

    def _select(self, states, limit):
        # caller holds the lock. Slice before deepcopy so only shown rows copy.
        hosts = [h for h in self._hosts.values() if h.state in states]
        hosts.sort(key=lambda h: h.updated_at, reverse=True)
        if limit is not None:
            hosts = hosts[:limit]
        return [copy.deepcopy(h) for h in hosts]

    def active_hosts(self, limit=None):
        with self._lock:
            return self._select(ACTIVE_STATES, limit)

    def result_hosts(self, limit=None):
        """Hosts to show as results: those in a result state, plus any host that has
        already proven impact (a session, credential, or access) even while it keeps
        attacking other candidates, so the header count and the panel never
        disagree."""
        with self._lock:
            hosts = [h for h in self._hosts.values()
                     if h.state in RESULT_STATES or h.sessions
                     or h.credentials or h.access]
            hosts.sort(key=lambda h: h.updated_at, reverse=True)
            if limit is not None:
                hosts = hosts[:limit]
            return [copy.deepcopy(h) for h in hosts]

    def snapshot_hosts(self):
        with self._lock:
            return [copy.deepcopy(h) for h in self._hosts.values()]

    def host_copy(self, ip):
        """Deep copy of one host under lock, or None if unknown. Pipeline workers
        read a stable snapshot this way without holding the lock during scan."""
        with self._lock:
            h = self._hosts.get(ip)
            return copy.deepcopy(h) if h is not None else None

    def pending_hosts(self):
        """IPs not in a terminal state, for the pipeline to schedule."""
        with self._lock:
            return [h.ip for h in self._hosts.values()
                    if h.state not in TERMINAL_STATES]

    # -- resume --

    def normalize_for_resume(self):
        rewound = 0
        with self._lock:
            for h in self._hosts.values():
                target = _RESUME_REWIND.get(h.state)
                if target is not None:
                    h.state = target
                    h.updated_at = _now()
                    rewound += 1
        if rewound:
            logger.info("resume: rewound %d in-flight host(s)", rewound)
        return rewound

    # -- persistence --

    def _serialize(self) -> dict:
        with self._lock:
            return {
                "tool": TOOL,
                "version": VERSION,
                "mode": self.mode,
                "phase": self.phase,
                "started_at": self.started_at,
                "saved_at": _now(),
                "hosts": [asdict(h) for h in self._hosts.values()],
            }

    def save_checkpoint(self, path=None):
        path = path or self.checkpoint_path
        if not path:
            return
        data = self._serialize()
        _atomic_write_json(path, data)

    @classmethod
    def load_checkpoint(cls, path, mode=None, findings_path=None):
        with open(path) as f:
            data = json.load(f)
        rs = cls(mode=mode or data.get("mode", "autopwn"),
                 checkpoint_path=path, findings_path=findings_path)
        rs.started_at = float(data.get("started_at", _now()))
        rs.phase = data.get("phase", "init")
        hosts = {}
        for hd in data.get("hosts", []):
            h = Host.from_dict(hd)
            hosts[h.ip] = h
        rs._hosts = hosts
        return rs

    def write_findings(self, path=None):
        path = path or self.findings_path
        if not path:
            return None
        data = self._build_findings()
        _atomic_write_json(path, data)
        return path

    def _build_findings(self) -> dict:
        """Proven findings only: one row per session, credential, and access. CVEs
        stay on services in the checkpoint as context and are not emitted here."""
        with self._lock:
            stats = self.stats()
            findings = []
            for h in self._hosts.values():
                for s in h.sessions:
                    findings.append(_session_row(h, s))
                for cred in h.credentials:
                    findings.append(_credential_row(h, cred))
                for acc in h.access:
                    findings.append(_access_row(h, acc))
            return {
                "run": {
                    "tool": TOOL,
                    "version": VERSION,
                    "mode": self.mode,
                    "started_at": self.started_at,
                    "finished_at": _now(),
                },
                "summary": asdict(stats),
                "findings": findings,
            }


# --- module helpers --------------------------------------------------------

def _session_row(host, s):
    return {
        "ip": host.ip,
        "hostname": host.hostname or None,
        "host_state": host.state.value,
        "finding_type": "session",
        "module": s.module or None,
        "payload": s.payload or None,
        "session_id": s.session_id,
        "info": s.info or None,
        "exploited": True,
    }


def _credential_row(host, cred):
    return {
        "ip": host.ip,
        "hostname": host.hostname or None,
        "host_state": host.state.value,
        "finding_type": "credential",
        "port": cred.port or None,
        "protocol": "tcp",
        "service": cred.service or None,
        "module": cred.module or None,
        "username": cred.username,
        "password": cred.password,
        "exploited": bool(cred.session_id),
        "session_id": cred.session_id or None,
    }


def _access_row(host, acc):
    return {
        "ip": host.ip,
        "hostname": host.hostname or None,
        "host_state": host.state.value,
        "finding_type": "access",
        "port": acc.port or None,
        "protocol": "tcp",
        "service": acc.service or None,
        "module": acc.module or None,
        "proof": acc.proof or None,
        "exploited": True,
    }


def _atomic_write_json(path, data):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


__all__ = [
    "HostState", "Verdict", "CVE", "Service", "Candidate", "Session",
    "Credential", "Access", "Host", "Stats", "Activity", "RunState",
    "InvalidTransition", "ACTIVE_STATES", "RESULT_STATES", "TERMINAL_STATES",
    "verdict_from_nse", "TOOL", "VERSION",
]
