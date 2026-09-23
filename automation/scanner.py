#!/usr/bin/env python3
# =============================================================================
# Location    scanner.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
#
# License     MIT License
#
# Purpose     All nmap interaction and result parsing for the orchestrator.
#             Bulk discovery, per-host version/vulners scanning, and NSE
#             verification, parsed in-process from nmap XML. With nmap_out_dir
#             set, the per-host vulners pass also archives its XML for reuse.
#
# DISCLAIMER
#             This software is provided "as is" without warranty of any kind. The
#             author and Red Cell Security LLC accept no liability for damage or
#             misuse arising from its operation.
# =============================================================================
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
import re
import shutil
import signal
import subprocess
import time
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from state import CVE, Credential, Service, Verdict, verdict_from_nse

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
    full_ports: bool = True             # phase 2: full SYN sweep of every port
    port_scan_timeout: int = 900        # per-host -p- sweep wall limit
    vulners_timeout: int = 600
    nse_timeout: int = 180
    brute_nse_timeout: int = 300   # NSE credential-brute run wall
    brute_max_scripts: int = 3     # cap brute scripts run per service
    brute_time_limit: str = "120s"  # per-script unpwdb time cap (empty = no cap)
    max_retries: int | None = 2         # nmap --max-retries; None keeps nmap default
    host_timeout: str = ""              # nmap --host-timeout; "" derives from the wall
    extra_args: list = field(default_factory=list)
    nmap_out_dir: str = ""              # if set, vulners_scan archives per-host XML here


@dataclass
class DiscoveryResult:
    ip: str
    hostname: str = ""
    up: bool = False                    # has at least one open port
    services: list = field(default_factory=list)


def _kill_proc_tree(proc):
    """Terminate a subprocess and any children in its process group, promptly.
    SIGTERM the group first, then SIGKILL if it does not exit within a short grace.
    nmap ignores a single SIGINT, so a group SIGTERM is what stops it fast."""
    try:
        pgid = os.getpgid(proc.pid)
    except (OSError, ProcessLookupError):
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGTERM)
        else:
            proc.terminate()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if pgid is not None:
            os.killpg(pgid, signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


class Scanner:
    def __init__(self, cfg: ScanConfig, on_activity=None):
        self.cfg = cfg
        self._on_activity = on_activity
        self._stop_event = None

    def attach_stop(self, event):
        """Attach the run's stop event so a cancel kills in-flight nmap promptly
        instead of waiting out the subprocess timeout. Optional: a standalone
        Scanner without one still honors the timeout."""
        self._stop_event = event

    def _activity(self, args):
        """Log the nmap invocation and report it to the feed, eliding temp-file
        paths. The log line is what gives a headless or console-driven run live
        visibility into scanning; the feed drives the TUI."""
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
        line = " ".join(parts)
        logger.info("%s", line)
        if self._on_activity:
            try:
                self._on_activity("nmap", line)
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

    def _discover_open_ports(self, ip, timeout):
        """Fast SYN-only sweep of all 65535 ports. No -sV, -O, or scripts, so it
        stays well under the wall even on a host with many services. Returns the
        open port numbers; if nmap times out, the ports found before the cutoff are
        still returned from the partial XML."""
        args = ["-sS", "-Pn", "-n", self.cfg.timing, "-p-"]
        args += list(self.cfg.extra_args)
        args += [ip]
        root = self._run_nmap(args, timeout)
        host = root.find("host")
        if host is None:
            return []
        found = []
        for port in host.findall("./ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            try:
                found.append(int(port.get("portid")))
            except (TypeError, ValueError):
                continue
        return found

    def vulners_scan(self, ip, ports=None):
        """Version detection plus vulners, in two stages when sweeping all ports.
        A single -sS -sV -O --script vulners pass over -p- times out on hosts with
        many services (nmap marks the host timedout and emits no port data), so with
        full_ports set this first runs a fast SYN-only sweep to find the open ports,
        then runs the heavy -sV/-O/vulners pass only against those. When explicit
        ports are given, it scans just those in one pass. Returns (hostname,
        os_family, [Service]) with CVEs attached. os_family prefers nmap -O stack
        fingerprinting (gated by an accuracy floor and kept distinct for BSD
        variants) and falls back to -sV ostype/CPE hints, or "" when nothing
        identifies it."""
        if self.cfg.full_ports and not ports:
            ports = self._discover_open_ports(ip, self.cfg.port_scan_timeout)
            if not ports:
                return "", "", []
        elif not ports:
            return "", "", []
        port_args = ["-p", ",".join(str(p) for p in ports)]
        timeout = self.cfg.vulners_timeout
        args = ["-sS", "-sV", "-O", "-Pn", self.cfg.timing,
                "--script", "vulners",
                "--script-args", f"mincvss={self.cfg.mincvss}"]
        args += port_args
        args += list(self.cfg.extra_args)
        args += [ip]
        save_to = None
        if self.cfg.nmap_out_dir:
            safe = ip.replace(":", "_").replace("/", "_")
            save_to = os.path.join(self.cfg.nmap_out_dir, f"{safe}.xml")
        root = self._run_nmap(args, timeout, save_to=save_to)
        host = root.find("host")
        if host is None:
            return "", "", []
        services = _parse_open_services(host, with_vulners=True,
                                        mincvss=self.cfg.mincvss)
        return _host_name(host), _resolve_os_family(host), services

    # -- nse discovery (analyze phase) --

    def nse_discover(self, ip, service, catalog):
        """Run the catalog's vuln/exploit scripts that match a probed service and
        return one detection record per script that reported a result. Each record
        carries the script id, the NSE categories the catalog holds for it, the
        verdict read from its output, any CVEs it declares or prints, and the raw
        output as evidence. The verify phase classifies and records these; a script
        that produced no output and no vulnerable verdict is dropped. Only probed
        services are tested, so an unconfirmed port-table guess never triggers a
        script run. Never raises; a tooling problem yields no discoveries."""
        if catalog is None:
            return []
        if (service.method or "").lower() != "probed" and not service.product:
            return []
        scripts = _match_catalog_scripts(service, catalog)
        if not scripts:
            return []
        args = ["-sV", "-Pn", "-n", self.cfg.timing,
                "-p", str(service.port),
                "--script", ",".join(sorted(scripts))]
        args += list(self.cfg.extra_args)
        args += [ip]
        try:
            root = self._run_nmap(args, self.cfg.nse_timeout)
        except NmapError as e:
            logger.warning("nse discover failed %s:%s: %s", ip, service.port, e)
            return []
        host = root.find("host")
        if host is None:
            return []
        meta = {s["id"]: s for s in catalog.get("scripts", [])}
        found = []
        for sid, output in _collect_script_outputs(host).items():
            text = (output or "").strip()
            verdict = verdict_from_nse(output)
            if verdict != Verdict.VULNERABLE and not text:
                continue
            entry = meta.get(sid, {})
            cids = set(entry.get("cves", []))
            cids |= set(_cve_ids_in_text(output))
            found.append({
                "script_id": sid,
                "categories": (entry.get("all_categories")
                               or entry.get("categories") or []),
                "verdict": verdict.name.lower(),
                "cves": sorted(cids),
                "output": text,
            })
        if found:
            vuln = sum(1 for d in found if d["verdict"] == "vulnerable")
            logger.info("nse discover %s:%s -> %d script result(s), %d vulnerable",
                        ip, service.port, len(found), vuln)
        return found

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

    def nse_brute(self, ip, service, catalog):
        """Run the catalog's brute scripts that match a probed service and return the
        credentials they recover, as Credential objects. Used by the session-less
        credential-recovery pass to brute a service no payload landed on. Selection
        is from the brute_scripts index, kept apart from the verify catalog so this
        never runs during enumeration. The run is bounded by brute_nse_timeout and,
        per script, by the unpwdb time cap, so a 20k-guess script cannot run open.
        Only probed services are brute-forced. Never raises; a tooling problem or no
        recovered login yields no credentials."""
        if catalog is None:
            return []
        if (service.method or "").lower() != "probed" and not service.product:
            return []
        scripts = _match_catalog_scripts(service, catalog, key="brute_scripts")
        if not scripts:
            return []
        # Prefer brute scripts whose name matches the service and drop scripts that
        # only matched by port. cics/tso/vtam on telnet:23 and the CMS brutes on
        # http:80 can never authenticate this service, they only burn the per-script
        # time cap. Fall back to the port-matched set when nothing name-matches, then
        # cap the count so one service cannot run a dozen brute scripts.
        sname = re.sub(r"[^a-z0-9]", "", (service.name or "").lower())
        named = [sc for sc in scripts if sname
                 and re.sub(r"[^a-z0-9]", "", sc.split("-", 1)[0]) == sname]
        scripts = sorted(named or scripts)[:self.cfg.brute_max_scripts]
        args = ["-sV", "-Pn", "-n", self.cfg.timing,
                "-p", str(service.port),
                "--script", ",".join(sorted(scripts))]
        if self.cfg.brute_time_limit:
            args += ["--script-args",
                     f"unpwdb.timelimit={self.cfg.brute_time_limit}"]
        args += list(self.cfg.extra_args)
        args += [ip]
        try:
            root = self._run_nmap(args, self.cfg.brute_nse_timeout)
        except NmapError as e:
            logger.warning("nse brute failed %s:%s: %s", ip, service.port, e)
            return []
        host = root.find("host")
        if host is None:
            return []
        creds = []
        seen = set()
        for sid, output in _collect_script_outputs(host).items():
            for user, pw in _parse_nse_brute_creds(output):
                key = (user, pw)
                if key in seen:
                    continue
                seen.add(key)
                creds.append(Credential(
                    service=service.name or "", port=service.port,
                    username=user, password=pw, module=sid))
        if creds:
            logger.info("nse brute %s:%s -> %d credential(s)", ip,
                        service.port, len(creds))
        return creds

    # -- nmap exec --

    def _run_nmap(self, args, timeout, save_to=None):
        fd, xml_path = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        eff = self._with_limits(args, timeout)
        self._activity(eff)
        cmd = [self.cfg.nmap_path] + [a for a in eff if a] + ["-oX", xml_path]
        # nmap runs in its own process group so a cancel can kill it and any NSE
        # children as a group. The wait loop polls the stop event, so a cancel stops
        # nmap within about a second instead of blocking until the timeout.
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)
        except FileNotFoundError:
            _unlink(xml_path)
            raise NmapError(f"nmap not found at '{self.cfg.nmap_path}'")
        stop = self._stop_event
        # timeout is None for phases that run without a hard wall (discovery); poll
        # for cancel forever in that case, but never impose a deadline.
        deadline = None if timeout is None else time.monotonic() + timeout
        stderr_b = b""
        while True:
            try:
                _out, stderr_b = proc.communicate(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                if stop is not None and stop.is_set():
                    _kill_proc_tree(proc)
                    _unlink(xml_path)
                    raise NmapError("nmap cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    _kill_proc_tree(proc)
                    _unlink(xml_path)
                    raise NmapError(f"nmap timed out after {timeout}s")
        try:
            if proc.returncode != 0 and os.path.getsize(xml_path) == 0:
                err = (stderr_b or b"").decode(errors="replace").strip()
                raise NmapError(f"nmap failed (rc={proc.returncode}): {err}")
            root = ET.parse(xml_path).getroot()
            if save_to:
                try:
                    os.makedirs(os.path.dirname(save_to), exist_ok=True)
                    shutil.copyfile(xml_path, save_to)
                except OSError as e:
                    logger.warning("could not save nmap xml to %s: %s", save_to, e)
            return root
        except ET.ParseError as e:
            err = (stderr_b or b"").decode(errors="replace").strip()
            raise NmapError(f"could not parse nmap XML: {e}; stderr: {err}")
        finally:
            _unlink(xml_path)

    def _with_limits(self, args, timeout):
        """Add per-host time and retry bounds unless the caller already set them.
        --host-timeout lets nmap stop a slow, heavily filtered host and flush the
        partial results it gathered, instead of being hard-killed by the subprocess
        wall with nothing. --max-retries stops nmap spending its full retransmit
        budget on every dropped port, which is what makes a -p- sweep of a filtered
        host run for many minutes."""
        eff = list(args)
        if self.cfg.max_retries is not None and "--max-retries" not in eff:
            eff += ["--max-retries", str(self.cfg.max_retries)]
        if "--host-timeout" not in eff:
            ht = self.cfg.host_timeout or self._derived_host_timeout(timeout)
            if ht:
                eff += ["--host-timeout", ht]
        return eff

    def _derived_host_timeout(self, timeout):
        """A per-host budget just under the subprocess wall, so nmap self-limits and
        writes partial XML before the hard kill fires. A None wall (bulk discovery)
        yields no derived bound; set host_timeout explicitly to bound those."""
        if timeout and timeout > 60:
            return f"{int(timeout * 0.9)}s"
        return ""


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


# nmap -O osmatch accuracy below this is treated as a guess and ignored, falling
# back to the weaker -sV hints. OS detection is critical to what the exploit phase
# fires, so the floor is deliberately high; nmap emits high 90s on a clean match.
_OSSCAN_ACCURACY_FLOOR = 85


def _resolve_os_family(host):
    """Host OS family, preferring nmap -O over -sV hints. -O classifies the TCP/IP
    stack and distinguishes BSD variants, so it is the stronger signal; the -sV
    ostype and CPE hints fill in when -O is absent or below the accuracy floor."""
    fam = _parse_os_fingerprint(host)
    return fam or _parse_os(host)


def _parse_os_fingerprint(host):
    """OS family from nmap -O output. Takes the highest-accuracy osmatch and, when
    it meets the accuracy floor, maps its osclass osfamily to a family token. Keeps
    freebsd, openbsd, and netbsd distinct so the exploit platform filter can drop a
    wrong-OS module. Returns "" when -O found nothing confident."""
    os_el = host.find("os")
    if os_el is None:
        return ""
    best, best_acc = None, -1
    for m in os_el.findall("osmatch"):
        try:
            acc = int(m.get("accuracy") or "0")
        except ValueError:
            acc = 0
        if acc > best_acc:
            best, best_acc = m, acc
    if best is None or best_acc < _OSSCAN_ACCURACY_FLOOR:
        return ""
    cls = best.find("osclass")
    return _os_family_from_osclass(cls) if cls is not None else ""


def _os_family_from_osclass(cls):
    """Map an nmap <osclass osfamily=...> to a family token, keeping BSD variants
    distinct. Falls back to the osclass OS CPE when osfamily is unhelpful."""
    fam = (cls.get("osfamily") or "").lower()
    if "windows" in fam:
        return "windows"
    if "linux" in fam:
        return "linux"
    if "freebsd" in fam:
        return "freebsd"
    if "openbsd" in fam:
        return "openbsd"
    if "netbsd" in fam:
        return "netbsd"
    if "bsd" in fam:
        return "bsd"
    if "solaris" in fam or "sunos" in fam:
        return "solaris"
    if any(k in fam for k in ("mac os", "macos", "os x", "darwin")):
        return "osx"
    if "aix" in fam:
        return "aix"
    for cpe in cls.findall("cpe"):
        f = _os_family_from_cpe((cpe.text or "").lower())
        if f:
            return f
    return ""


def _parse_os(host):
    """Best-effort OS family from -sV hints: per-service ostype attributes and
    OS-level CPEs (cpe:/o:vendor:product). Aggregates across the host's services
    and prefers a specific OS over the generic 'unix'. Returns a lowercase family
    token (linux, windows, unix, solaris, bsd, osx) or "" if nothing identifies it.
    This is the same data nmap rolls into its 'Service Info: OSs: ...' line."""
    fams = []
    for port in host.findall("./ports/port"):
        svc = port.find("service")
        if svc is None:
            continue
        ot = svc.get("ostype")
        if ot:
            f = _os_family_from_text(ot)
            if f:
                fams.append(f)
        for cpe in svc.findall("cpe"):
            txt = (cpe.text or "").lower()
            if txt.startswith("cpe:/o:"):
                f = _os_family_from_cpe(txt)
                if f:
                    fams.append(f)
    if not fams:
        return ""
    specific = [f for f in fams if f != "unix"]
    return (specific or fams)[0]


def _os_family_from_cpe(cpe):
    """Map an OS-level CPE (cpe:/o:...) to a family token."""
    if any(k in cpe for k in (":linux", "ubuntu", "debian", "redhat",
                              "centos", "fedora", "canonical")):
        return "linux"
    if ":windows" in cpe or "microsoft:windows" in cpe:
        return "windows"
    if "solaris" in cpe or "sunos" in cpe:
        return "solaris"
    if any(k in cpe for k in ("mac_os", "macos", "apple:mac")):
        return "osx"
    if any(k in cpe for k in ("freebsd", "openbsd", "netbsd", ":bsd")):
        return "bsd"
    if ":aix" in cpe:
        return "aix"
    return ""


def _os_family_from_text(text):
    """Map a free-text OS hint (nmap service ostype) to a family token. 'unix' is
    the weakest signal and only used when nothing more specific is present."""
    t = (text or "").lower()
    if "windows" in t:
        return "windows"
    if "linux" in t:
        return "linux"
    if "solaris" in t or "sunos" in t:
        return "solaris"
    if "mac os" in t or "macos" in t or "darwin" in t:
        return "osx"
    if "bsd" in t:
        return "bsd"
    if "aix" in t:
        return "aix"
    if "unix" in t:
        return "unix"
    return ""


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
        method = ""
        conf = 0
        svc_el = port.find("service")
        if svc_el is not None:
            name = svc_el.get("name", "")
            product = svc_el.get("product", "")
            version = svc_el.get("version", "")
            method = svc_el.get("method", "")
            try:
                conf = int(svc_el.get("conf", "0") or 0)
            except ValueError:
                conf = 0
            cpe_el = svc_el.find("cpe")
            if cpe_el is not None and cpe_el.text:
                cpe = cpe_el.text
        svc = Service(port=portid, protocol=proto, name=name,
                      product=product, version=version, cpe=cpe,
                      method=method, conf=conf)
        if with_vulners:
            # Only attach CVEs when nmap actually identified the service. vulners
            # keys its hits off the detected product/version; on an unprobed
            # port-table guess there is no real identification to match, so any
            # CVE attributed to it would be firing at a phantom product.
            probed = (method.lower() == "probed") or bool(product)
            if probed:
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


def _collect_script_outputs(host):
    """Per-script output keyed by script id, so a discovery pass can tell which
    script fired and pull that script's CVEs. Aggregates the script output plus any
    nested elem text."""
    out = {}
    for sc in (host.findall("./ports/port/script")
               + host.findall("./hostscript/script")):
        sid = sc.get("id", "")
        if not sid:
            continue
        parts = [sc.get("output", "")]
        for elem in sc.iter("elem"):
            if elem.text:
                parts.append(elem.text)
        out[sid] = "\n".join(p for p in parts if p)
    return out


_DISCOVER_CVE_RE = re.compile(r"CVE[-\s]?(\d{4})[-\s]?(\d{4,7})", re.IGNORECASE)


def _cve_ids_in_text(text):
    return {f"CVE-{y}-{n}" for y, n in _DISCOVER_CVE_RE.findall(text or "")}


def _match_catalog_scripts(service, catalog, key="scripts"):
    """Select catalog scripts whose service or port targets this probed service.
    Matching is on the confirmed service identity (name and product tokens) and the
    open port, not the port alone, so a script only runs where nmap actually saw
    the service it targets. nmap re-applies each script's real portrule at run time,
    so a loose match here is filtered there, never a false run."""
    svc_tokens = set()
    for field_val in (service.name, service.product):
        for tok in re.findall(r"[a-z0-9]+", (field_val or "").lower()):
            if len(tok) >= 3:
                svc_tokens.add(tok)
    port = service.port
    selected = set()
    for s in catalog.get(key, []):
        if port and port in (s.get("ports") or []):
            selected.add(s["id"])
            continue
        s_services = {t.lower() for t in (s.get("services") or [])}
        if s_services & svc_tokens:
            selected.add(s["id"])
    return selected


_NSE_CRED_RE = re.compile(
    r"^\s*(.+?):(.*?)\s+-\s+Valid credentials\s*$", re.IGNORECASE | re.MULTILINE)


def _parse_nse_brute_creds(output):
    """(username, password) pairs from an NSE brute script's output. nmap's brute
    scripts print '<user>:<pass> - Valid credentials' per recovered account, with
    <empty> standing for an empty password. De-duplicated; empty on no match."""
    out = []
    seen = set()
    for m in _NSE_CRED_RE.finditer(output or ""):
        user = m.group(1).strip()
        pw = m.group(2).strip()
        if pw.lower() in ("<empty>", "<blank>", "(empty)", "<no password>"):
            pw = ""
        key = (user, pw)
        if user and user.lower() != "accounts" and key not in seen:
            seen.add(key)
            out.append((user, pw))
    return out


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
