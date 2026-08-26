#!/usr/bin/env python3
# =============================================================================
# Location    automation/nse_catalog.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
#
# License     MIT License
#
# Purpose     Build a catalog of nmap NSE vuln and exploit scripts by parsing the
#             installed script corpus. For each script it records the categories it
#             declares, the CVEs it references, and the ports and services its
#             portrule targets. The catalog replaces the small hand-kept CVE to NSE
#             map with a generated index covering every script on the box, and it
#             drives the NSE detection pass that feeds discovered CVEs into the
#             exploit path. Rebuilt on demand, so a nightly script refresh plus a
#             rebuild keeps coverage current with no manual maintenance.
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

"""automation/nse_catalog.py - build a CVE and service index from installed NSE scripts."""

import json
import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

# Categories worth cataloging for the detection-into-exploitation path. vuln is the
# large detection win; exploit actually proves the flaw. intrusive is deliberately
# excluded: it is broad and includes brute and dos-adjacent scripts.
CATALOG_CATEGORIES = ("vuln", "exploit")

# Common locations nmap installs its scripts to, in priority order. The nmap binary
# is asked first (authoritative), these are the fallback.
_SCRIPT_DIRS = (
    "/usr/share/nmap/scripts",
    "/usr/local/share/nmap/scripts",
    "/opt/nmap/share/nmap/scripts",
)

_CVE_RE = re.compile(r"CVE[-\s]?(\d{4})[-\s]?(\d{4,7})", re.IGNORECASE)
_CATEGORIES_RE = re.compile(r"categories\s*=\s*\{(.*?)\}", re.DOTALL)
_PORTRULE_PORTS_RE = re.compile(r"port(?:number)?\s*(?:==|,)\s*(\d{1,5})")
_SHORTPORT_PORTS_RE = re.compile(r"shortport\.[a-z_]+\s*\(([^)]*)\)",
                                 re.IGNORECASE)
_SERVICE_TOKEN_RE = re.compile(r'"([a-z0-9][a-z0-9+._-]{1,30})"')


def default_catalog_path(scripts_dir=None):
    """Where the generated catalog lives: beside this module, so the engine reads
    it without configuration and a rebuild simply overwrites it."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "nse_catalog.json")


def find_scripts_dir(nmap_path="nmap"):
    """Locate the installed NSE scripts directory. Ask nmap where its datadir is,
    then fall back to the common paths. Returns the directory or None."""
    try:
        out = subprocess.run([nmap_path, "--version"], capture_output=True,
                             text=True, timeout=20).stdout
        for line in out.splitlines():
            low = line.lower()
            if "nmap-services" in low or "data files" in low or "datadir" in low:
                for tok in re.findall(r"(/\S+)", line):
                    cand = tok.rstrip(":")
                    scripts = os.path.join(cand, "scripts")
                    if os.path.isdir(scripts):
                        return scripts
                    if os.path.isdir(cand) and cand.endswith("scripts"):
                        return cand
    except (OSError, subprocess.SubprocessError):
        pass
    for d in _SCRIPT_DIRS:
        if os.path.isdir(d):
            return d
    return None


def update_scripts_db(nmap_path="nmap"):
    """Refresh nmap's script database so newly added scripts are usable. This is the
    scripts-only update the nightly job runs; it does not rebuild nmap itself."""
    try:
        proc = subprocess.run([nmap_path, "--script-updatedb"],
                              capture_output=True, text=True, timeout=120)
        ok = proc.returncode == 0
        if not ok:
            logger.warning("script-updatedb rc=%s: %s", proc.returncode,
                           (proc.stderr or "").strip()[:200])
        return ok
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("script-updatedb failed: %s", e)
        return False


def _categories(text):
    m = _CATEGORIES_RE.search(text)
    if not m:
        return set()
    return {c.strip().strip('"\'').lower()
            for c in m.group(1).split(",") if c.strip()}


def _cves(text):
    out = set()
    for yr, num in _CVE_RE.findall(text):
        out.add(f"CVE-{yr}-{num}")
    return out


def _ports_and_services(text):
    """Best-effort extraction of the ports and service names a script targets from
    its portrule. NSE portrules are Lua, so this is heuristic: numeric ports from
    port comparisons and shortport calls, and quoted service tokens near the rule.
    Used only to narrow which scripts run against a given open service; nmap itself
    re-applies the real portrule at run time, so over-inclusion here is harmless."""
    ports = set()
    services = set()
    # isolate the portrule body when present, else scan the whole file
    rule = text
    idx = text.find("portrule")
    if idx != -1:
        rule = text[idx:idx + 600]
    for m in _PORTRULE_PORTS_RE.findall(rule):
        try:
            p = int(m)
            if 0 < p <= 65535:
                ports.add(p)
        except ValueError:
            pass
    for call in _SHORTPORT_PORTS_RE.findall(rule):
        for tok in re.findall(r"\d{1,5}", call):
            try:
                p = int(tok)
                if 0 < p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
        for svc in _SERVICE_TOKEN_RE.findall(call):
            services.add(svc.lower())
    # service names in the filename prefix are a strong signal (http-vuln-*, smb-*)
    return sorted(ports), sorted(services)


def parse_script(path):
    """Parse one .nse file into a catalog entry, or None when it is not a vuln or
    exploit script. Never raises; an unreadable script is skipped."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    cats = _categories(text)
    if not (cats & set(CATALOG_CATEGORIES)):
        return None
    script_id = os.path.basename(path)[:-4] if path.endswith(".nse") \
        else os.path.basename(path)
    ports, services = _ports_and_services(text)
    prefix = script_id.split("-", 1)[0]
    if prefix and prefix not in services:
        services.insert(0, prefix)
    return {
        "id": script_id,
        "categories": sorted(cats & set(CATALOG_CATEGORIES)),
        "all_categories": sorted(cats),
        "cves": sorted(_cves(text)),
        "ports": ports,
        "services": services,
    }


def build_catalog(scripts_dir=None, nmap_path="nmap"):
    """Parse every vuln and exploit NSE script in the directory into a catalog dict.
    Returns {"scripts": [...], "by_cve": {CVE: [ids]}, "count": n, "scripts_dir": d}.
    """
    scripts_dir = scripts_dir or find_scripts_dir(nmap_path)
    if not scripts_dir or not os.path.isdir(scripts_dir):
        raise FileNotFoundError(
            "could not locate the nmap NSE scripts directory; set it explicitly")
    scripts = []
    for name in sorted(os.listdir(scripts_dir)):
        if not name.endswith(".nse"):
            continue
        entry = parse_script(os.path.join(scripts_dir, name))
        if entry:
            scripts.append(entry)
    by_cve = {}
    for s in scripts:
        for cve in s["cves"]:
            by_cve.setdefault(cve, [])
            if s["id"] not in by_cve[cve]:
                by_cve[cve].append(s["id"])
    return {
        "scripts_dir": scripts_dir,
        "count": len(scripts),
        "scripts": scripts,
        "by_cve": by_cve,
    }


def write_catalog(catalog, path=None):
    path = path or default_catalog_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return path


def load_catalog(path=None):
    """Read the generated catalog, or None when it has not been built yet."""
    path = path or default_catalog_path()
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def rebuild(nmap_path="nmap", scripts_dir=None, update_db=True, path=None):
    """The full nightly action: optionally refresh nmap's script database, parse the
    installed vuln and exploit scripts, and write the catalog. Returns the catalog.
    """
    if update_db:
        update_scripts_db(nmap_path)
    catalog = build_catalog(scripts_dir=scripts_dir, nmap_path=nmap_path)
    out = write_catalog(catalog, path)
    logger.info("nse catalog rebuilt: %d vuln/exploit script(s), %d cve(s) -> %s",
                catalog["count"], len(catalog["by_cve"]), out)
    return catalog


def _main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="nse_catalog.py",
        description="build the NSE vuln/exploit catalog from installed scripts")
    p.add_argument("--nmap", default="nmap", help="nmap binary path")
    p.add_argument("--scripts-dir", default=None,
                   help="NSE scripts directory (auto-detected when omitted)")
    p.add_argument("--out", default=None, help="catalog output path")
    p.add_argument("--no-update-db", action="store_true",
                   help="skip nmap --script-updatedb before building")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cat = rebuild(nmap_path=args.nmap, scripts_dir=args.scripts_dir,
                  update_db=not args.no_update_db, path=args.out)
    print(f"cataloged {cat['count']} vuln/exploit script(s), "
          f"{len(cat['by_cve'])} cve(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
