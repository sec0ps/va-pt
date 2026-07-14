"""
Shared state for the MITM autopwn orchestrator.
Thread safe container consumed by the TUI and written by the bettercap event
reader, the Responder monitor, and the Metasploit console and session monitors.
All mutation goes through methods holding a reentrant lock. The TUI only reads
through snapshot and never mutates.
"""

import time
import threading
from collections import deque


def _new_victim():
    return {
        "ua": None,
        "os": None,
        "browser": None,
        "served": 0,
        "failed": 0,
        "exploited": False,
        "last": "",
        "ts": time.time(),
    }


class SharedState:
    def __init__(self, max_events=500):
        self._lock = threading.RLock()
        self.started_at = time.time()
        self.phase = "init"
        self.status_line = ""

        self.spoofed_hosts = {}
        self.dns_hits = deque(maxlen=max_events)

        self.poison_hits = deque(maxlen=max_events)
        self.hashes = []
        self._hash_keys = set()

        self.victims = {}

        self.exploit_attempts = deque(maxlen=max_events)
        self.sessions = {}

        self.events = deque(maxlen=max_events)

    def log(self, source, message):
        with self._lock:
            self.events.append({"ts": time.time(), "src": source, "msg": message})

    def set_phase(self, phase, status=""):
        with self._lock:
            self.phase = phase
            if status:
                self.status_line = status

    def set_status(self, status):
        with self._lock:
            self.status_line = status

    def add_spoofed_host(self, ip, mac=""):
        with self._lock:
            if ip not in self.spoofed_hosts:
                self.spoofed_hosts[ip] = {"mac": mac, "first_seen": time.time()}
            elif mac and not self.spoofed_hosts[ip].get("mac"):
                self.spoofed_hosts[ip]["mac"] = mac

    def remove_spoofed_host(self, ip):
        with self._lock:
            self.spoofed_hosts.pop(ip, None)

    def add_dns_hit(self, client, domain, address):
        with self._lock:
            self.dns_hits.append({
                "ts": time.time(),
                "client": client,
                "domain": domain,
                "address": address,
            })

    def add_poison_hit(self, proto, client, name):
        with self._lock:
            self.poison_hits.append({
                "ts": time.time(),
                "proto": proto,
                "client": client,
                "name": name,
            })

    def add_hash(self, client, user, domain, htype, sample):
        key = (user.lower(), domain.lower(), htype.lower())
        with self._lock:
            if key in self._hash_keys:
                return False
            self._hash_keys.add(key)
            self.hashes.append({
                "ts": time.time(),
                "client": client,
                "user": user,
                "domain": domain,
                "htype": htype,
                "sample": sample,
            })
            return True

    def mark_served(self, client, ua=None, os_name=None, browser=None):
        with self._lock:
            v = self.victims.setdefault(client, _new_victim())
            v["served"] += 1
            v["last"] = "served"
            v["ts"] = time.time()
            if ua:
                v["ua"] = ua
            if os_name:
                v["os"] = os_name
            if browser:
                v["browser"] = browser

    def mark_failed(self, client, note=""):
        with self._lock:
            v = self.victims.setdefault(client, _new_victim())
            v["failed"] += 1
            v["last"] = "failed " + note if note else "failed"
            v["ts"] = time.time()

    def mark_exploited(self, client):
        with self._lock:
            v = self.victims.setdefault(client, _new_victim())
            v["exploited"] = True
            v["last"] = "exploited"
            v["ts"] = time.time()

    def add_exploit_attempt(self, target, module, note=""):
        with self._lock:
            self.exploit_attempts.append({
                "ts": time.time(),
                "target": target,
                "module": module,
                "note": note,
            })

    def add_session(self, sid, host, platform, stype, via_exploit):
        with self._lock:
            if sid in self.sessions:
                return False
            self.sessions[sid] = {
                "host": host,
                "platform": platform,
                "type": stype,
                "via_exploit": via_exploit,
                "opened": time.time(),
            }
            return True

    def snapshot(self):
        with self._lock:
            return {
                "phase": self.phase,
                "status": self.status_line,
                "uptime": time.time() - self.started_at,
                "spoofed_hosts": dict(self.spoofed_hosts),
                "dns_hits": list(self.dns_hits),
                "poison_hits": list(self.poison_hits),
                "hashes": list(self.hashes),
                "victims": {k: dict(v) for k, v in self.victims.items()},
                "exploit_attempts": list(self.exploit_attempts),
                "sessions": dict(self.sessions),
                "events": list(self.events),
            }
