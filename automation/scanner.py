"""
scanner.py - all nmap interaction and result parsing.

Two-phase by design. discover() runs a single fast SYN pass over the whole scope
to find live hosts and open ports. vulners_scan() then runs version detection plus
the vulners script per host against only the confirmed open ports, which keeps the
expensive pass narrow. nse_verify() runs a curated set of NSE vuln scripts during
the check phase to corroborate vulners hits.

Parsing is done in-process with xml.etree against nmap -oX output, including the
nested <script id="vulners"> table where per-CVE is_exploit flags live. All
subprocess calls set stdin=DEVNULL so nmap can never consume the parent terminal's
input and interfere with the TUI.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from state import CVE, Service, Verdict, verdict_from_nse

logger = logging.getLogger(__name__)


class NmapError(Exception):
    pass


# Curated CVE-to-NSE-script map. NSE vuln scripts carry no clean CVE metadata, so
# this is a deliberately small set of high-value safe checks used to corroborate
# vulners hits before handing off to MSF for the exploit attempt.
_NSE_BY_CVE = {
    "CVE-2017-0143": ["smb-vuln-ms17-010"],
    "CVE-2017-0144": ["smb-vuln-ms17-010"],
    "CVE-2017-0145": ["smb-vuln-ms17-010"],
    "CVE-2017-0146": ["smb-vuln-ms17-010"],
    "CVE-2017-0147": ["smb-vuln-ms17-010"],
    "CVE-2017-0148": ["smb-vuln-ms17-010"],
    "CVE-2008-4250": ["smb-vuln-ms08-067"],
    "CVE-2009-3103": ["smb-vuln-cve-2009-3103"],
    "CVE-2017-7494": ["smb-vuln-cve-2017-7494"],
    "CVE-2014-0160": ["ssl-heartbleed"],
    "CVE-2012-0002": ["rdp-vuln-ms12-020"],
    "CVE-2014-6271": ["http-shellshock"],
    "CVE-2014-6278": ["http-shellshock"],
}

_VERDICT_RANK = {
    Verdict.VULNERABLE: 3,
    Verdict.LIKELY: 2,
    Verdict.SAFE: 1,
    Verdict.UNKNOWN: 0,
    Verdict.UNSUPPORTED: 0,
}


def nse_scripts_for_cve(cve_id):
    return _NSE_BY_CVE.get((cve_id or "").upper(), [])


@dataclass
class ScanConfig:
    nmap_path: str = "nmap"
    discovery_top_ports: int = 1000
    discovery_ports: str = ""           # explicit -p override; takes priority
    timing: str = "-T4"
    mincvss: float = 7.0
    discovery_timeout: int | None = None  # bulk pass; None means no wall limit
    vulners_timeout: int = 600
    nse_timeout: int = 180
    extra_args: list = field(default_factory=list)


@dataclass
class DiscoveryResult:
    ip: str
    hostname: str = ""
    up: bool = False                    # has at least one open port
    services: list = field(default_factory=list)


class Scanner:
    def __init__(self, cfg: ScanConfig, on_activity=None):
        self.cfg = cfg
        self._on_activity = on_activity

    def _activity(self, args):
        """Report the nmap invocation to the feed, eliding temp-file paths."""
        if not self._on_activity:
            return
        parts = ["nmap"]
        skip = False
        for a in args:
            if skip:
                parts.append("<targets>")
                skip = False
            elif a == "-iL":
                parts.append(a)
                skip = True
            elif a:
                parts.append(a)
        try:
            self._on_activity("nmap", " ".join(parts))
        except Exception:
            pass

    # -- discovery (bulk) --

    def discover(self, targets):
        """Single SYN pass over all targets. Returns {ip: DiscoveryResult}. Hosts
        with no open ports come back up=False. Caller should chunk very large
        scopes across multiple discover() calls to bound memory."""
        if not targets:
            return {}
        fd, tfile = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as f:
            for t in targets:
                f.write(f"{t}\n")
        try:
            args = ["-sS", "-Pn", "-n", self.cfg.timing]
            if self.cfg.discovery_ports:
                args += ["-p", self.cfg.discovery_ports]
            else:
                args += ["--top-ports", str(self.cfg.discovery_top_ports)]
            args += list(self.cfg.extra_args)
            args += ["-iL", tfile]
            root = self._run_nmap(args, self.cfg.discovery_timeout)
        finally:
            _unlink(tfile)
        results = {}
        for host in root.findall("host"):
            ip = _host_addr(host)
            if not ip:
                continue
            services = _parse_open_services(host)
            results[ip] = DiscoveryResult(
                ip=ip, hostname=_host_name(host), up=bool(services),
                services=services)
        return results

    # -- vulners (per host) --

    def vulners_scan(self, ip, ports):
        """Version detection plus vulners against the given open ports. Returns
        (hostname, [Service]) with CVEs attached."""
        if not ports:
            return "", []
        portstr = ",".join(str(p) for p in ports)
        args = ["-sS", "-sV", "-Pn", self.cfg.timing,
                "--script", "vulners",
                "--script-args", f"mincvss={self.cfg.mincvss}",
                "-p", portstr]
        args += list(self.cfg.extra_args)
        args += [ip]
        root = self._run_nmap(args, self.cfg.vulners_timeout)
        host = root.find("host")
        if host is None:
            return "", []
        services = _parse_open_services(host, with_vulners=True,
                                        mincvss=self.cfg.mincvss)
        return _host_name(host), services

    # -- nse verify (check phase) --

    def nse_verify(self, ip, port, scripts):
        """Run curated NSE vuln scripts on a port. Returns (Verdict, detail).
        The strongest verdict across scripts wins, so any positive corroborates."""
        if not scripts:
            return Verdict.UNKNOWN, ""
        args = ["-sV", "-Pn", "-n", self.cfg.timing,
                "-p", str(port),
                "--script", ",".join(scripts)]
        args += list(self.cfg.extra_args)
        args += [ip]
        try:
            root = self._run_nmap(args, self.cfg.nse_timeout)
        except NmapError as e:
            logger.warning("nse verify failed %s:%s %s: %s", ip, port, scripts, e)
            return Verdict.UNKNOWN, f"nse error: {e}"
        host = root.find("host")
        if host is None:
            return Verdict.UNKNOWN, ""
        texts = _collect_script_text(host)
        return _strongest_nse_verdict(texts), _summarize_nse(texts)

    # -- nmap exec --

    def _run_nmap(self, args, timeout):
        self._activity(args)
        fd, xml_path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        cmd = [self.cfg.nmap_path] + [a for a in args if a] + ["-oX", xml_path]
        try:
            proc = subprocess.run(
                cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout)
        except FileNotFoundError:
            _unlink(xml_path)
            raise NmapError(f"nmap not found at '{self.cfg.nmap_path}'")
        except subprocess.TimeoutExpired:
            _unlink(xml_path)
            raise NmapError(f"nmap timed out after {timeout}s")
        try:
            if proc.returncode != 0 and os.path.getsize(xml_path) == 0:
                err = proc.stderr.decode(errors="replace").strip()
                raise NmapError(f"nmap failed (rc={proc.returncode}): {err}")
            return ET.parse(xml_path).getroot()
        except ET.ParseError as e:
            err = proc.stderr.decode(errors="replace").strip()
            raise NmapError(f"could not parse nmap XML: {e}; stderr: {err}")
        finally:
            _unlink(xml_path)


# --- parsing helpers (operate on ElementTree elements) ---------------------

def _host_addr(host):
    v4 = v6 = None
    for a in host.findall("address"):
        t = a.get("addrtype")
        if t == "ipv4":
            v4 = a.get("addr")
        elif t == "ipv6":
            v6 = a.get("addr")
    return v4 or v6


def _host_name(host):
    hn = host.find("./hostnames/hostname")
    return hn.get("name", "") if hn is not None else ""


def _parse_open_services(host, with_vulners=False, mincvss=0.0):
    services = []
    for port in host.findall("./ports/port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        proto = port.get("protocol", "tcp")
        try:
            portid = int(port.get("portid"))
        except (TypeError, ValueError):
            continue
        name = product = version = cpe = ""
        svc_el = port.find("service")
        if svc_el is not None:
            name = svc_el.get("name", "")
            product = svc_el.get("product", "")
            version = svc_el.get("version", "")
            cpe_el = svc_el.find("cpe")
            if cpe_el is not None and cpe_el.text:
                cpe = cpe_el.text
        svc = Service(port=portid, protocol=proto, name=name,
                      product=product, version=version, cpe=cpe)
        if with_vulners:
            for sc in port.findall("script"):
                if sc.get("id") == "vulners":
                    svc.cves = _parse_vulners(sc, mincvss)
                    break
        services.append(svc)
    return services


def _parse_vulners(script_elem, mincvss):
    """Walk the nested vulners table. Each per-CVE <table> carries elems id, type,
    cvss, is_exploit. Non-CVE rows (exploitdb refs, etc.) are dropped. Dedups by
    CVE id, keeping the highest cvss and any exploit flag."""
    found = {}
    for tbl in script_elem.iter("table"):
        fields = {}
        for elem in tbl.findall("elem"):
            k = elem.get("key")
            if k:
                fields[k] = (elem.text or "").strip()
        cid = fields.get("id", "")
        if not cid:
            continue
        typ = fields.get("type", "").lower()
        if not (cid.upper().startswith("CVE-") or typ == "cve"):
            continue
        try:
            cvss = float(fields.get("cvss", "0") or 0)
        except ValueError:
            cvss = 0.0
        if cvss < mincvss:
            continue
        is_exploit = fields.get("is_exploit", "").lower() == "true"
        cid_u = cid.upper()
        existing = found.get(cid_u)
        if existing is None:
            found[cid_u] = CVE(cve_id=cid_u, cvss=cvss, exploit=is_exploit,
                               source="vulners")
        else:
            if cvss > existing.cvss:
                existing.cvss = cvss
            if is_exploit:
                existing.exploit = True
    return list(found.values())


def _collect_script_text(host):
    texts = []
    for sc in host.findall("./ports/port/script"):
        out = sc.get("output", "")
        if out:
            texts.append(out)
        for elem in sc.iter("elem"):
            if elem.text:
                texts.append(elem.text)
    for sc in host.findall("./hostscript/script"):
        out = sc.get("output", "")
        if out:
            texts.append(out)
        for elem in sc.iter("elem"):
            if elem.text:
                texts.append(elem.text)
    return texts


def _strongest_nse_verdict(texts):
    best = Verdict.UNKNOWN
    for t in texts:
        v = verdict_from_nse(t)
        if _VERDICT_RANK[v] > _VERDICT_RANK[best]:
            best = v
    return best


def _summarize_nse(texts):
    keep = []
    for t in texts:
        for line in t.splitlines():
            low = line.lower()
            if any(k in low for k in ("vulnerable", "state:", "cve", "exploit")):
                keep.append(line.strip())
    return " | ".join(keep[:4])[:240]


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


__all__ = ["ScanConfig", "DiscoveryResult", "Scanner", "NmapError",
           "nse_scripts_for_cve"]
