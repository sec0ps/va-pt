"""
Environment preparation and preflight checks for the MITM autopwn orchestrator.
Handles root enforcement, a self bootstrapping virtualenv, python dependency
verification, dependency discovery, and interface and routing lookups used by the
scope guard. Discovered binary and script paths are cached by the orchestrator in
its config file so the search only runs when a cached path is missing. Routing and
address data come from iproute2 json output to avoid extra python dependencies
before the venv exists.
"""

import os
import sys
import json
import shutil
import subprocess
import venv

VENV_PATH = "/opt/mitm-autopwn-venv"
PYTHON_DEPS = ["rich", "pymetasploit3", "requests"]

# Logical dependency name mapped to the executable or script filename to search
# for and whether a match must carry the executable bit. Responder is a plain
# python script so it is accepted without the executable bit.
DEPENDENCIES = {
    "bettercap": ("bettercap", True),
    "msfrpcd": ("msfrpcd", True),
    "responder": ("Responder.py", False),
}

_PATH_ORDER = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/opt",
]


def is_root():
    return os.geteuid() == 0


def ensure_root():
    if not is_root():
        sys.stderr.write("error: root required for raw sockets, ARP spoofing, and port binding\n")
        sys.exit(1)


def _venv_python(venv_path):
    return os.path.join(venv_path, "bin", "python")


def in_target_venv(venv_path):
    return os.path.realpath(sys.prefix) == os.path.realpath(venv_path)


def bootstrap_and_reexec(venv_path=VENV_PATH):
    """
    Create the venv if absent, install dependencies, then re exec the current
    process inside it. Returns immediately when already inside the target venv.
    """
    if in_target_venv(venv_path):
        return

    py = _venv_python(venv_path)
    if not os.path.isfile(py):
        sys.stdout.write("[*] creating virtualenv at %s\n" % venv_path)
        builder = venv.EnvBuilder(with_pip=True, clear=False)
        builder.create(venv_path)

    _pip_install(py, PYTHON_DEPS)
    os.execv(py, [py] + sys.argv)


def _pip_install(py, packages):
    have = _installed_packages(py)
    missing = [p for p in packages if p.split("==")[0].lower() not in have]
    if not missing:
        return
    sys.stdout.write("[*] installing python dependencies %s\n" % ", ".join(missing))
    subprocess.check_call([py, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    subprocess.check_call([py, "-m", "pip", "install", "--quiet"] + missing)


def _installed_packages(py):
    try:
        out = subprocess.check_output([py, "-m", "pip", "list", "--format=json"])
        return {pkg["name"].lower() for pkg in json.loads(out)}
    except Exception:
        return set()


def _path_rank(path):
    for i, prefix in enumerate(_PATH_ORDER):
        if path.startswith(prefix + "/"):
            return (i, len(path))
    return (len(_PATH_ORDER), len(path))


def locate_path(name, require_exec=True):
    """
    Resolve an executable or script path. PATH is tried first via which since it
    is fast and always current, then the plocate or mlocate database is consulted
    as a fallback for things not on PATH. The locate match is case sensitive and
    the basename must equal name exactly, so a search for Responder.py never grabs
    this tool's own responder.py module. Matches inside this tool's own directory
    are skipped for the same reason. Survivors are ranked so canonical bin
    directories win over cache copies. Returns an absolute path or None.
    """
    hit = shutil.which(name)
    if hit:
        return hit
    try:
        out = subprocess.check_output(
            ["locate", "-b", "-l", "500", name],
            stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return None
    selfdir = os.path.dirname(os.path.realpath(__file__))
    matches = []
    for line in out.splitlines():
        candidate = line.strip()
        if not candidate or not os.path.isfile(candidate):
            continue
        if os.path.basename(candidate) != name:
            continue
        if os.path.realpath(candidate).startswith(selfdir + os.sep):
            continue
        if require_exec and not os.access(candidate, os.X_OK):
            continue
        matches.append(candidate)
    matches.sort(key=_path_rank)
    return matches[0] if matches else None


def discover_dependency(key):
    """
    Locate a single dependency by its logical name from DEPENDENCIES. Returns an
    absolute path or None.
    """
    name, require_exec = DEPENDENCIES[key]
    return locate_path(name, require_exec=require_exec)


def interface_exists(iface):
    return os.path.isdir("/sys/class/net/%s" % iface)


def interface_is_up(iface):
    try:
        with open("/sys/class/net/%s/operstate" % iface) as fh:
            return fh.read().strip() in ("up", "unknown")
    except OSError:
        return False


def _ip_json(args):
    try:
        out = subprocess.check_output(["ip", "-j"] + args)
        return json.loads(out)
    except Exception:
        return []


def interface_addresses(iface):
    addrs = []
    for entry in _ip_json(["addr", "show", "dev", iface]):
        for info in entry.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local"):
                addrs.append(info["local"])
    return addrs


def interface_cidr(iface):
    for entry in _ip_json(["addr", "show", "dev", iface]):
        for info in entry.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local"):
                return "%s/%s" % (info["local"], info["prefixlen"])
    return None


def default_gateway():
    for route in _ip_json(["route", "show", "default"]):
        if route.get("gateway"):
            return route["gateway"]
    return None


def local_ipv4_addresses():
    addrs = set()
    for entry in _ip_json(["addr", "show"]):
        for info in entry.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local"):
                addrs.add(info["local"])
    return addrs
