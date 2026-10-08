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
# Purpose     Build a catalog of nmap NSE scripts by parsing the installed script
#             corpus. It admits the vuln and exploit scripts that drive the
#             detection into exploitation path, and the discovery and auth
#             enumeration scripts that extract actionable data from services the
#             exploitation pass did not land on. For each script it records the
#             categories it declares, the CVEs it references, and the ports and
#             services its portrule targets. The catalog replaces the small
#             hand-kept CVE to NSE map with a generated index covering every
#             applicable script on the box, rebuilt on demand so a nightly script
#             refresh plus a rebuild keeps coverage current with no manual upkeep.
#             Each record is tagged from the script's own declared metadata: the
#             product it targets (matched against nmap's service-probes vocabulary),
#             an actionability tier, its dependency chain, and the nmap.registry feed
#             edges it produces and consumes, all derived so no per-script list is kept.
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

"""automation/nse_catalog.py - build a detection and enumeration index from installed NSE scripts."""

import json
import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

# Categories admitted to the catalog. vuln and exploit drive the detection into
# exploitation path, vuln for the detection win and exploit to prove the flaw.
# discovery and auth are the enumeration categories, admitted so the verify phase
# can pull actionable data from services the exploitation pass did not land on.
# intrusive is never admitted on its own, so a purely intrusive script never runs,
# but a script that carries intrusive alongside an admitted category is kept. That
# is what lets the safe enumeration scripts through without dragging in the volatile
# intrusive-only corpus.
CATALOG_CATEGORIES = ("vuln", "exploit")
ENUM_CATEGORIES = ("discovery", "auth")
ADMIT_CATEGORIES = CATALOG_CATEGORIES + ENUM_CATEGORIES

# Hard exclusions. A script declaring any of these is never cataloged, even when it
# also carries an admitted category. dos is a denial of service script and must
# never fire during an assessment. brute is the heavy credential brute corpus, left
# to the engine brute phase and excluded here to avoid both the target load and the
# duplication of that phase. malware marks scripts that interact with a backdoor or
# implant to detect it, and ftp-vsftpd-backdoor, ftp-proftpd-backdoor, and
# irc-unrealircd-backdoor all trigger the backdoor to confirm it, which breaks the
# service before the msf phase can exploit it cleanly. Detection stays passive and
# the backdoor invocation is left to the single msf fire. This is a safety floor,
# not a preference.
EXCLUDE_CATEGORIES = ("dos", "malware", "brute")

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

# Machine-readable capability signals parsed from each script's own body. NSE
# scripts declare their dependency chain, share state through nmap.registry, and
# document credential arguments; these decide actionability and the feed graph with
# no hand-maintained per-script list.
_DEPS_RE = re.compile(r"dependencies\s*=\s*\{(.*?)\}", re.DOTALL)
_REG_WRITE_RE = re.compile(
    r"nmap\.registry\.([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=(?!=)")
_REG_ANY_RE = re.compile(r"nmap\.registry\.([A-Za-z_]\w*)")
_CREDARG_RE = re.compile(r"@args\s+\S*(?:user|pass|login|cred)", re.IGNORECASE)
# nmap.registry.args is the script-args accessor, not a shared-state feed edge.
_REG_BUILTINS = frozenset({"args"})

# Product vocabulary is nmap's own, taken from the structured cpe:/ fields of
# nmap-service-probes rather than the free-text product string. CPE is a controlled
# vendor/product vocabulary, so it never contains the action words (dir, exec,
# traversal) that free text does. A token is admitted only when it spans fewer than
# _PRODUCT_VENDOR_SPAN distinct vendors: a real product term belongs to one or a few
# vendors (weblogic, novell, microsoft), a generic infrastructure word (server,
# service, manager) spans many, and frequency cannot tell them apart because real
# vendors are common too.
_CPE_RE = re.compile(r"cpe:/[aoh]:([^:\s/]+):([^:\s/]+)")
_PRODUCT_VENDOR_SPAN = 3

# Content classifier. The metadata tier (categories, deps, registry, creds) is
# reliable at the extremes but NSE's own categories conflate the ambiguous middle:
# hygiene and banner scripts wear vuln/intrusive tags, real recon enumeration wears
# only discovery/safe. Rather than a hand-kept per-id override list, the ambiguous
# middle is classified from the script's own description and body, with a confidence
# band. A script is only committed to informational (dropped from the verify phase)
# when the classifier is confident; everything it is unsure about defaults to
# actionable and is surfaced in the build report, so a real finding is never silently
# discarded and new scripts self-classify on a rebuild with no manual upkeep.
_DESC_RE = re.compile(r"description\s*=\s*\[(=*)\[(.*?)\]\1\]", re.S)
# code tells: a script that records a vuln/cred table or requires those libraries
# is producing a finding, not a banner.
_CODE_ACT = re.compile(
    r'vulns\.|creds\.|require\s*\(?\s*["\'](?:vulns|creds|exploit)["\']')
# description phrases that name a concrete flaw or exposure.
_PHRASE_ACT = re.compile(
    r'remote code execution|arbitrary (?:code|command|file)|command execution|'
    r'(?:sql|code|command|ldap|xpath|template|nosql) injection|'
    r'(?:directory|path) traversal|authentication bypass|auth bypass|backdoor|'
    r'unauthenticated|unauthorized access|default (?:credential|account|password)|'
    r'empty password|anonymous (?:log|access|bind|ftp)|open relay|'
    r'file (?:disclosure|read|upload|inclusion)|source code disclosure|\.git\b|'
    r'svn repositor|information leak|\bleak(?:s|ed|ing)?\b|'
    r'dump.*(?:hash|password|credential)|zone transfer|world.readable|'
    r'weak password|guessable|server-status page|backup (?:file|cop)|'
    r'directory listing')
# target nouns an enumeration verb must act on for the script to count as recon.
_TGT = (r'users?|usernames?|accounts?|shares?|exports?|mounts?|databases?|'
        r'collections?|tables?|schemas?|programs?|applications?|services?|'
        r'servers?|hosts?|files?|folders?|directories|logins?|credentials?|'
        r'passwords?|hashes?|sessions?|groups?|domains?|pipes?|processes|'
        r'repositories|registry|modules?|interfaces?|software|principals?|'
        r'mailboxes?|subdomains?|hostnames?|channels?|rootdse')
# an enumeration verb within three words of a target noun. Proximity keeps banner
# prose ("returns the server version") from reading as enumeration.
_ENUM_OF = re.compile(
    r'\b(?:enumerat\w*|lists?|list of|retriev\w*|fetch\w*|dump\w*|extract\w*|'
    r'obtain\w*|show\w*)\b(?:\W+\w+){0,3}\W+(?:' + _TGT + r')\b')
_ACCESS = re.compile(
    r'\b(?:vulnerab\w*|misconfigur\w*|weak\b|exposed|exposure|disclosure|'
    r'without authentication|access without|insecure|world.readable|'
    r'default install|debug mode)')
# identity/recon leak families (AD domain, NTLM, NetBIOS, realm, FQDN) are
# actionable recon and must never land in the confident-noise band.
_LEAK_RE = re.compile(
    r'\bntlm\b|netbios|\bdomain\b|\brealm\b|forest|kerberos|\bsid\b|'
    r'fully.qualified|\bfqdn\b|dns.?suffix|computer name|machine name|'
    r'active directory')
# pure hygiene/banner/version prose: no finding, no enumerated asset.
_NOISE_PH = re.compile(
    r'banner|grabber|\bthe title\b|displays the result|version of (?:the|this)|'
    r'(?:server|service).?s version|geolocation|\bwhois\b|crt\.sh|'
    r'reports any .*flag|session cookies|current (?:date|time)|greeting|'
    r'returns? .*(?:methods|algorithms|capabilities)|obtain.*version|'
    r'retriev.*certificate|(?:security|response|http) headers|server information|'
    r'shows? .{0,20}information|favicon|\btraceroute\b|robots\.txt')


def _desc_text(text):
    """The script's description block, lowercased; empty when none is declared.
    Handles nmap's long-bracket levels ([[...]], [=[...]=], and deeper)."""
    m = _DESC_RE.search(text or "")
    return (m.group(2) if m else "").lower()


def default_catalog_path(scripts_dir=None):
    """Where the generated catalog lives, beside this module, so the engine reads
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


def update_scripts_db(nmap_path="nmap", sudo_prefix=None):
    """Refresh nmap's script database so newly added scripts are usable. This is the
    scripts-only update the nightly job runs; it does not rebuild nmap itself.
    sudo_prefix is an optional argv prefix (for example ["sudo", "-n"]) for when the
    script database lives in a root-owned directory the caller cannot write; left
    unset, nmap runs directly, which is correct for a standalone root user."""
    cmd = list(sudo_prefix or []) + [nmap_path, "--script-updatedb"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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


def _dependencies(text):
    """The script ids this script declares as dependencies, lowercased; empty when
    none. A dependency chain marks a script as part of an actionable flow (a
    discovery script that runs after a brute or auth script)."""
    m = _DEPS_RE.search(text)
    if not m:
        return set()
    return {d.strip().strip("\"'").lower()
            for d in m.group(1).split(",") if d.strip()}


def _registry_edges(text):
    """Best-effort (writes, reads) of nmap.registry.<name> shared-state keys the
    script produces and consumes, the builtin args accessor excluded. A write feeds
    later scripts, a read consumes an earlier script's output. Heuristic over the Lua
    source; over- or under-capture is not load-bearing, it only annotates the
    catalog, nmap re-runs the real logic."""
    writes = {m.lower() for m in _REG_WRITE_RE.findall(text)} - _REG_BUILTINS
    names = {m.lower() for m in _REG_ANY_RE.findall(text)} - _REG_BUILTINS
    return writes, (names - writes)


def _wants_creds(text, deps):
    """True when the script consumes credentials, by a documented user/pass/login
    argument or by depending on a brute, empty-password, or creds script."""
    if _CREDARG_RE.search(text):
        return True
    for d in deps:
        if d.endswith("-brute") or "empty-password" in d or d.endswith("-creds"):
            return True
    return False


def _content_tier(script_id, text, cats, deps, touches_registry, wants_creds):
    """Classify a script actionable or informational with a confidence flag, from its
    declared metadata and its own description and body. Returns (tier, confident).

    Confident actionable: a credential-brute script; a script on a dependency chain,
    touching shared registry state, or consuming credentials (it participates in an
    actionable flow); a code tell (a vulns/creds table, a vulns/creds/exploit
    require), a referenced CVE, the exploit category, or a description phrase naming a
    concrete flaw. Confident informational: a broadcast script, or pure
    hygiene/banner/version prose with no enumerated asset, no exposure language, and
    no identity-leak family. The ambiguous middle returns (actionable, False): it runs
    the verify phase so no finding is dropped, and is surfaced in the build report and
    the per-entry confidence flag for later refinement."""
    cats = set(cats or [])
    if "brute" in cats:
        return ("actionable", True)
    # structural metadata: part of a tool chain or a credential flow.
    if deps or touches_registry or wants_creds:
        return ("actionable", True)
    code = (text or "").lower()
    d = _desc_text(text)
    if (_CODE_ACT.search(code) or _CVE_RE.search(text or "")
            or "exploit" in cats or _PHRASE_ACT.search(d)):
        return ("actionable", True)
    if "broadcast" in cats:
        return ("informational", True)
    sid = script_id.lower()
    suffix_info = sid.endswith(("-info", "-serverinfo", "-version", "-ver"))
    enum = bool(_ENUM_OF.search(d))
    access = bool(_ACCESS.search(d))
    noise = bool(_NOISE_PH.search(d))
    # identity-leak and vuln-tagged scripts are never confident-noise.
    leak = bool(_LEAK_RE.search(d)) or "ntlm" in sid or "vuln" in cats
    if enum and not noise:
        return ("actionable", True)
    if access and not noise and not suffix_info:
        return ("actionable", True)
    # confident-noise is a HIGH bar: an explicit noise phrase, no positive signal of
    # any kind, and not a leak/vuln family. Anything short of that drops through to
    # the uncertain band, which defaults actionable.
    if noise and not enum and not access and not leak:
        return ("informational", True)
    return ("actionable", False)


def _id_token_profile(names):
    """From the script filenames, the leading service/protocol tokens and the
    high-frequency id-body tokens (the NSE function words: enum, users, vuln, info,
    login). Both corpus-derived, subtracted from the product vocabulary so a protocol
    or a function word is never mistaken for a product a script targets."""
    prefixes = set()
    body = {}
    for name in names:
        sid = name[:-4] if name.endswith(".nse") else name
        toks = [t for t in re.split(r"[^a-z0-9]+", sid.lower()) if t]
        if not toks:
            continue
        prefixes.add(toks[0])
        for t in toks[1:]:
            if len(t) >= 3:
                body[t] = body.get(t, 0) + 1
    cutoff = max(8, int(0.01 * len(names)))
    function_words = {t for t, df in body.items() if df >= cutoff}
    return prefixes, function_words


def find_service_probes(scripts_dir=None, nmap_path="nmap"):
    """Locate nmap-service-probes, nmap's own product fingerprint database, beside
    the scripts directory in the nmap datadir. Returns the path or None."""
    cands = []
    if scripts_dir:
        cands.append(os.path.join(
            os.path.dirname(scripts_dir.rstrip("/")), "nmap-service-probes"))
    for d in _SCRIPT_DIRS:
        cands.append(os.path.join(os.path.dirname(d), "nmap-service-probes"))
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def _build_product_vocab(probes_path, prefixes, function_words):
    """Parse the cpe:/ vendor and product fields of every match/softmatch line in
    nmap-service-probes into a set of product terms. A token is kept only when it
    appears under fewer than _PRODUCT_VENDOR_SPAN distinct vendors, which admits real
    product names (novell, weblogic, huawei) and rejects generic infrastructure words
    (server, service, manager) that span many vendors. Protocol prefixes and NSE
    function words are also removed. nmap's own vocabulary, so new products enter on a
    rebuild. Empty set when the file is absent, which disables product scoping and
    leaves selection unchanged."""
    if not probes_path or not os.path.isfile(probes_path):
        return set()
    span = {}
    try:
        with open(probes_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not (line.startswith("match ")
                        or line.startswith("softmatch ")):
                    continue
                for vendor, _product in _CPE_RE.findall(line):
                    vl = vendor.lower()
                    for t in re.split(r"[^a-z0-9]+", vl):
                        if len(t) >= 3:
                            span.setdefault(t, set()).add(vl)
    except OSError:
        return set()
    if not span:
        return set()
    vocab = {t for t, vs in span.items() if len(vs) < _PRODUCT_VENDOR_SPAN}
    return vocab - function_words


def _derive_product(script_id, product_vocab, prefixes):
    """The product tokens a script id claims. When the id's own prefix is a vendor
    (citrix-*, mikrotik-*) the product is that vendor. Otherwise it is the id words
    after the leading service prefix, intersected with the product vocabulary. Empty
    when the script names no product (generic, CVE, and app-layer web scripts), which
    the scanner never product-drops."""
    if not product_vocab:
        return []
    toks = [t for t in re.split(r"[^a-z0-9]+", script_id.lower()) if len(t) >= 3]
    if not toks:
        return []
    if toks[0] in product_vocab:
        return [toks[0]]
    body = toks[1:] if toks[0] in prefixes else toks
    return sorted({t for t in body if t in product_vocab})


def _script_entry(path, text, cats, surfaced):
    """Build the catalog record for a parsed script. surfaced is the category set
    shown in the entry's categories field; all_categories always carries the full
    declared set."""
    script_id = os.path.basename(path)[:-4] if path.endswith(".nse") \
        else os.path.basename(path)
    ports, services = _ports_and_services(text)
    prefix = script_id.split("-", 1)[0]
    if prefix and prefix not in services:
        services.insert(0, prefix)
    deps = _dependencies(text)
    writes, reads = _registry_edges(text)
    wants_creds = _wants_creds(text, deps)
    consumes = sorted(reads | ({"credentials"} if wants_creds else set()))
    tier, confident = _content_tier(script_id, text, cats, deps,
                                    bool(writes or reads), wants_creds)
    return {
        "id": script_id,
        "categories": sorted(cats & surfaced),
        "all_categories": sorted(cats),
        "cves": sorted(_cves(text)),
        "ports": ports,
        "services": services,
        "product": [],
        "tier": tier,
        "tier_confident": confident,
        "dependencies": sorted(deps),
        "feeds": sorted(writes),
        "consumes": consumes,
    }


def parse_script(path):
    """Parse one .nse file into a verify-catalog entry, or None when it is not
    admitted. A script is admitted when it declares a vuln, exploit, discovery, or
    auth category and declares none of the hard exclusions. Never raises; an
    unreadable script is skipped."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    cats = _categories(text)
    if not (cats & set(ADMIT_CATEGORIES)):
        return None
    if cats & set(EXCLUDE_CATEGORIES):
        return None
    return _script_entry(path, text, cats, set(ADMIT_CATEGORIES))


def parse_brute_script(path):
    """Parse a brute-category script into a brute-index entry, or None. These are the
    credential-brute scripts (mysql-brute, ssh-brute, smb-brute, and the rest) that
    rule B drops from the verify catalog to keep the 20k-guess load out of the
    enumeration pass. They are kept here, in a separate index, so the session-less
    credential-recovery pass can run a service's brute script only where no payload
    landed. dos and malware are never included. Never raises."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    cats = _categories(text)
    if "brute" not in cats:
        return None
    if cats & {"dos", "malware"}:
        return None
    return _script_entry(path, text, cats, {"brute", "auth", "discovery"})


def build_catalog(scripts_dir=None, nmap_path="nmap"):
    """Parse every admitted NSE script in the directory into a catalog dict.
    Returns scripts (the verify catalog), brute_scripts (the separate brute index),
    by_cve, count, scripts_dir, and product_vocab (the derived term count).
    """
    scripts_dir = scripts_dir or find_scripts_dir(nmap_path)
    if not scripts_dir or not os.path.isdir(scripts_dir):
        raise FileNotFoundError(
            "could not locate the nmap NSE scripts directory; set it explicitly")
    names = [n for n in sorted(os.listdir(scripts_dir)) if n.endswith(".nse")]
    prefixes, function_words = _id_token_profile(names)
    probes_path = find_service_probes(scripts_dir, nmap_path)
    product_vocab = _build_product_vocab(probes_path, prefixes, function_words)
    scripts = []
    brute_scripts = []
    for name in names:
        p = os.path.join(scripts_dir, name)
        entry = parse_script(p)
        if entry:
            entry["product"] = _derive_product(entry["id"], product_vocab,
                                                prefixes)
            scripts.append(entry)
        bentry = parse_brute_script(p)
        if bentry:
            bentry["product"] = _derive_product(bentry["id"], product_vocab,
                                                 prefixes)
            brute_scripts.append(bentry)
    by_cve = {}
    for sc in scripts:
        for cve in sc["cves"]:
            by_cve.setdefault(cve, [])
            if sc["id"] not in by_cve[cve]:
                by_cve[cve].append(sc["id"])
    uncertain = sorted(e["id"] for e in scripts if not e.get("tier_confident"))
    actionable = sum(1 for e in scripts if e["tier"] == "actionable")
    return {
        "scripts_dir": scripts_dir,
        "count": len(scripts),
        "actionable": actionable,
        "informational": len(scripts) - actionable,
        "uncertain": uncertain,
        "scripts": scripts,
        "brute_scripts": brute_scripts,
        "by_cve": by_cve,
        "product_vocab": len(product_vocab),
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


def rebuild(nmap_path="nmap", scripts_dir=None, update_db=True, path=None,
            sudo_prefix=None):
    """The full nightly action. Optionally refresh nmap's script database, parse the
    installed admitted scripts, and write the catalog. Returns the catalog."""
    if update_db:
        update_scripts_db(nmap_path, sudo_prefix=sudo_prefix)
    catalog = build_catalog(scripts_dir=scripts_dir, nmap_path=nmap_path)
    out = write_catalog(catalog, path)
    logger.info("nse catalog rebuilt with %d script(s) (%d actionable, %d "
                "informational, %d uncertain), %d brute script(s), %d cve(s), "
                "%d product term(s) -> %s", catalog["count"],
                catalog.get("actionable", 0), catalog.get("informational", 0),
                len(catalog.get("uncertain") or []),
                len(catalog.get("brute_scripts") or []), len(catalog["by_cve"]),
                catalog.get("product_vocab", 0), out)
    return catalog


def _main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="nse_catalog.py",
        description="build the NSE catalog from installed scripts")
    p.add_argument("--nmap", default="nmap", help="nmap binary path")
    p.add_argument("--scripts-dir", default=None,
                   help="NSE scripts directory (auto-detected when omitted)")
    p.add_argument("--out", default=None, help="catalog output path")
    p.add_argument("--no-update-db", action="store_true",
                   help="skip nmap --script-updatedb before building")
    p.add_argument("--sudo", default="",
                   help="sudo binary to run nmap --script-updatedb through, for "
                        "when the script database is in a root-owned directory; "
                        "empty runs nmap directly")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sudo_prefix = [args.sudo, "-n"] if args.sudo else None
    cat = rebuild(nmap_path=args.nmap, scripts_dir=args.scripts_dir,
                  update_db=not args.no_update_db, path=args.out,
                  sudo_prefix=sudo_prefix)
    print(f"cataloged {cat['count']} script(s) "
          f"({cat.get('actionable', 0)} actionable, "
          f"{cat.get('informational', 0)} informational, "
          f"{len(cat.get('uncertain') or [])} uncertain), "
          f"{len(cat.get('brute_scripts') or [])} brute script(s), "
          f"{len(cat['by_cve'])} cve(s), "
          f"{cat.get('product_vocab', 0)} product term(s)")
    unc = cat.get("uncertain") or []
    if unc:
        print(f"\n{len(unc)} script(s) the classifier was unsure about (kept "
              f"actionable, review or refine):")
        for sid in unc:
            print(f"  {sid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
