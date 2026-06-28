"""
state.py - shared run state, host lifecycle, stats, and persistence.

Single source of truth read by the TUI and written by the pipeline workers.
All access is guarded by an RLock. Persistence (checkpoint and findings) takes a
brief locked snapshot then performs file IO unlocked, so disk writes never block
a TUI repaint. Resume support rewinds in-flight states to a safe re-entry point.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Iterable

logger = logging.getLogger(__name__)

TOOL = "vapt-orchestrator"
VERSION = "0.2.0"


def _now() -> float:
    return time.time()


# --- enums -----------------------------------------------------------------

class HostState(str, Enum):
    QUEUED = "queued"
    DISCOVERED = "discovered"
    DOWN = "down"
    SCANNING = "scanning"
    ANALYZED = "analyzed"
    CANDIDATES = "candidates"
    NO_CANDIDATES = "no_candidates"
    CHECKING = "checking"
    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    EXPLOITING = "exploiting"
    EXPLOITED = "exploited"
    FAILED = "failed"
    ERROR = "error"


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    LIKELY = "likely"
    SAFE = "safe"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


# Pane and aggregation groupings referenced by the TUI and stats.
ACTIVE_STATES = frozenset({
    HostState.DISCOVERED, HostState.SCANNING, HostState.ANALYZED,
    HostState.CANDIDATES, HostState.CHECKING, HostState.EXPLOITING,
})
RESULT_STATES = frozenset({HostState.EXPLOITABLE, HostState.EXPLOITED})
TERMINAL_STATES = frozenset({
    HostState.DOWN, HostState.NO_CANDIDATES, HostState.NOT_EXPLOITABLE,
    HostState.EXPLOITED, HostState.FAILED, HostState.ERROR,
})

# Completion depends on mode: in check-only, EXPLOITABLE is the end of the line;
# in autopwn it still has a fire step pending.
_COMPLETED_CHECK = frozenset({
    HostState.DOWN, HostState.NO_CANDIDATES, HostState.NOT_EXPLOITABLE,
    HostState.EXPLOITABLE, HostState.EXPLOITED, HostState.FAILED, HostState.ERROR,
})
_COMPLETED_AUTOPWN = frozenset({
    HostState.DOWN, HostState.NO_CANDIDATES, HostState.NOT_EXPLOITABLE,
    HostState.EXPLOITED, HostState.FAILED, HostState.ERROR,
})

_TRANSITIONS = {
    HostState.QUEUED: frozenset({HostState.DISCOVERED, HostState.DOWN}),
    HostState.DISCOVERED: frozenset({HostState.SCANNING}),
    HostState.SCANNING: frozenset({HostState.ANALYZED}),
    HostState.ANALYZED: frozenset({HostState.CANDIDATES, HostState.NO_CANDIDATES}),
    HostState.CANDIDATES: frozenset({HostState.CHECKING}),
    HostState.CHECKING: frozenset({HostState.EXPLOITABLE, HostState.NOT_EXPLOITABLE}),
    HostState.EXPLOITABLE: frozenset({HostState.EXPLOITING}),
    HostState.EXPLOITING: frozenset({HostState.EXPLOITED, HostState.FAILED}),
    HostState.DOWN: frozenset(),
    HostState.NO_CANDIDATES: frozenset(),
    HostState.NOT_EXPLOITABLE: frozenset(),
    HostState.EXPLOITED: frozenset(),
    HostState.FAILED: frozenset(),
    HostState.ERROR: frozenset(),
}

# States unsafe to trust after a crash; rewind to the last stable point on resume.
_RESUME_REWIND = {
    HostState.SCANNING: HostState.DISCOVERED,
    HostState.CHECKING: HostState.CANDIDATES,
    HostState.EXPLOITING: HostState.EXPLOITABLE,
}


class InvalidTransition(Exception):
    pass


# --- verdict normalization -------------------------------------------------

_MSF_VERDICT = {
    "vulnerable": Verdict.VULNERABLE,
    "appears": Verdict.LIKELY,
    "detected": Verdict.LIKELY,
    "safe": Verdict.SAFE,
    "unsupported": Verdict.UNSUPPORTED,
    "unknown": Verdict.UNKNOWN,
}


def verdict_from_msf(code: str) -> Verdict:
    """Normalize an MSF CheckCode name to a Verdict."""
    return _MSF_VERDICT.get((code or "").strip().lower(), Verdict.UNKNOWN)


def verdict_from_nse(text: str) -> Verdict:
    """Normalize NSE vuln-script output text to a Verdict. Order matters."""
    t = (text or "").upper()
    if "LIKELY VULNERABLE" in t:
        return Verdict.LIKELY
    if "NOT VULNERABLE" in t:
        return Verdict.SAFE
    if "VULNERABLE" in t:
        return Verdict.VULNERABLE
    return Verdict.UNKNOWN


def is_exploitable_verdict(v: Verdict) -> bool:
    """A host is exploitable if any candidate is confirmed or likely."""
    return v in (Verdict.VULNERABLE, Verdict.LIKELY)


def is_fireable_verdict(v: Verdict) -> bool:
    """Worth detonating in autopwn. Only SAFE is skipped, since SAFE means the
    check positively determined the target is not vulnerable. Everything else,
    including UNSUPPORTED and UNKNOWN, is attempted -- many high-value modules
    (vsftpd 2.3.4 backdoor, UnrealIRCd backdoor, Samba usermap_script) have no
    working check and report UNSUPPORTED."""
    return v != Verdict.SAFE


# --- models ----------------------------------------------------------------

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
    cves: list[CVE] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d):
        s = cls(port=int(d["port"]), protocol=d.get("protocol", "tcp"),
                name=d.get("name", ""), product=d.get("product", ""),
                version=d.get("version", ""), cpe=d.get("cpe", ""))
        s.cves = [CVE.from_dict(x) for x in d.get("cves", [])]
        return s


@dataclass
class Candidate:
    module: str                    # full msf path, or nse script id
    cve_id: str                    # CVE this candidate maps to
    rank: str = ""                 # msf rank name (display + findings)
    port: int = 0
    source: str = "msf"            # msf | nse
    check_result: Verdict = Verdict.UNKNOWN
    check_detail: str = ""

    @classmethod
    def from_dict(cls, d):
        try:
            v = Verdict(d.get("check_result", "unknown"))
        except ValueError:
            v = Verdict.UNKNOWN
        return cls(module=d["module"], cve_id=d.get("cve_id", ""),
                   rank=d.get("rank", ""), port=int(d.get("port", 0)),
                   source=d.get("source", "msf"), check_result=v,
                   check_detail=d.get("check_detail", ""))


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
class Host:
    ip: str
    hostname: str = ""
    state: HostState = HostState.QUEUED
    os_match: str = ""             # os/arch fingerprint for payload selection
    arch: str = ""
    services: list[Service] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
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

    @classmethod
    def from_dict(cls, d):
        h = cls(ip=d["ip"])
        h.hostname = d.get("hostname", "")
        try:
            h.state = HostState(d.get("state", "queued"))
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
        return h


@dataclass(frozen=True)
class Stats:
    total: int
    queued: int
    live: int
    down: int
    scanning: int
    analyzed: int
    candidates: int
    no_candidates: int
    checking: int
    exploitable: int
    not_exploitable: int
    exploiting: int
    exploited: int
    failed: int
    errored: int
    completed: int
    sessions: int
    cves: int
    exploit_cves: int
    active_workers: int
    phase: str
    mode: str
    elapsed: float


# --- run state -------------------------------------------------------------

@dataclass(frozen=True)
class Activity:
    ts: float
    source: str          # "nmap", "msf", "fire", "phase"
    text: str


class RunState:
    def __init__(self, mode="check", checkpoint_path=None, findings_path=None):
        if mode not in ("check", "autopwn"):
            raise ValueError("mode must be 'check' or 'autopwn'")
        self._lock = threading.RLock()
        self._hosts: dict[str, Host] = {}
        self.mode = mode
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

    def update_candidate_result(self, ip, module, verdict: Verdict, detail=""):
        with self._lock:
            h = self._hosts[ip]
            for c in h.candidates:
                if c.module == module:
                    c.check_result = verdict
                    if detail:
                        c.check_detail = detail
            h.updated_at = _now()

    def add_session(self, ip, session: Session):
        with self._lock:
            h = self._hosts[ip]
            h.sessions.append(session)
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
            sessions = cves = exploit_cves = 0
            for h in self._hosts.values():
                counts[h.state] += 1
                sessions += len(h.sessions)
                cves += h.cve_count
                exploit_cves += h.exploit_cve_count
            total = len(self._hosts)
            completed_set = (_COMPLETED_AUTOPWN if self.mode == "autopwn"
                             else _COMPLETED_CHECK)
            completed = sum(counts[s] for s in completed_set)
            queued = counts[HostState.QUEUED]
            down = counts[HostState.DOWN]
            return Stats(
                total=total,
                queued=queued,
                live=total - queued - down,
                down=down,
                scanning=counts[HostState.SCANNING],
                analyzed=counts[HostState.ANALYZED],
                candidates=counts[HostState.CANDIDATES],
                no_candidates=counts[HostState.NO_CANDIDATES],
                checking=counts[HostState.CHECKING],
                exploitable=counts[HostState.EXPLOITABLE],
                not_exploitable=counts[HostState.NOT_EXPLOITABLE],
                exploiting=counts[HostState.EXPLOITING],
                exploited=counts[HostState.EXPLOITED],
                failed=counts[HostState.FAILED],
                errored=counts[HostState.ERROR],
                completed=completed,
                sessions=sessions,
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
        with self._lock:
            return self._select(RESULT_STATES, limit)

    def snapshot_hosts(self):
        with self._lock:
            return [copy.deepcopy(h) for h in self._hosts.values()]

    def host_copy(self, ip):
        """Deep copy of one host under lock, or None if unknown. Pipeline workers
        read a stable snapshot this way without holding the lock during scan/check."""
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
        rs = cls(mode=mode or data.get("mode", "check"),
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
        with self._lock:
            stats = self.stats()
            findings = []
            for h in self._hosts.values():
                cand_by_cve = defaultdict(list)
                for c in h.candidates:
                    cand_by_cve[c.cve_id].append(c)
                sess_by_module = {}
                for s in h.sessions:
                    sess_by_module.setdefault(s.module, s)
                emitted = set()
                for svc in h.services:
                    for cve in svc.cves:
                        cands = cand_by_cve.get(cve.cve_id, [])
                        if cands:
                            for c in cands:
                                findings.append(
                                    _finding_row(h, svc, cve, c, sess_by_module))
                                emitted.add(c.module)
                        else:
                            findings.append(
                                _finding_row(h, svc, cve, None, sess_by_module))
                # candidates not tied to an emitted service/CVE row
                for c in h.candidates:
                    if c.module not in emitted:
                        findings.append(
                            _finding_row(h, None, None, c, sess_by_module))
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

def _finding_row(host, svc, cve, cand, sess_by_module):
    exploited = False
    session_id = None
    payload = None
    if cand is not None:
        s = sess_by_module.get(cand.module)
        if s is not None:
            exploited = True
            session_id = s.session_id
            payload = s.payload
    return {
        "ip": host.ip,
        "hostname": host.hostname or None,
        "host_state": host.state.value,
        "port": svc.port if svc else (cand.port if cand else None),
        "protocol": svc.protocol if svc else None,
        "service": svc.name if svc else None,
        "product": svc.product if svc else None,
        "version": svc.version if svc else None,
        "cpe": svc.cpe if svc else None,
        "cve": cve.cve_id if cve else (cand.cve_id if cand else None),
        "cvss": cve.cvss if cve else None,
        "exploit_available": cve.exploit if cve else None,
        "module": cand.module if cand else None,
        "module_rank": cand.rank if cand else None,
        "verification": cand.check_result.value if cand else None,
        "verification_source": cand.source if cand else None,
        "exploited": exploited,
        "session_id": session_id,
        "payload": payload,
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
    "Host", "Stats", "RunState", "InvalidTransition",
    "ACTIVE_STATES", "RESULT_STATES", "TERMINAL_STATES",
    "verdict_from_msf", "verdict_from_nse", "is_exploitable_verdict",
    "TOOL", "VERSION",
]
