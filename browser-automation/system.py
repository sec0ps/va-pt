"""
Environment preparation and preflight checks for the MITM autopwn orchestrator.
Handles root enforcement, a self bootstrapping virtualenv, python and binary
dependency verification, and interface and routing lookups used by the scope
guard. Routing and address data come from iproute2 json output to avoid extra
python dependencies before the venv exists.
"""

import os
import sys
import json
import shutil
import subprocess
import venv

VENV_PATH = "/opt/mitm-autopwn-venv"
PYTHON_DEPS = ["rich", "pymetasploit3", "requests"]
REQUIRED_BINARIES = ["bettercap", "msfrpcd"]
RESPONDER_CANDIDATES = [
    "/opt/Responder/Responder.py",
    "/usr/share/responder/Responder.py",
    "/opt/responder/Responder.py",
    "/vapt/network/Responder/Responder.py",
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


def check_binaries():
    return [b for b in REQUIRED_BINARIES if shutil.which(b) is None]


def find_responder(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for path in RESPONDER_CANDIDATES:
        if os.path.isfile(path):
            return path
    which = shutil.which("responder") or shutil.which("Responder.py")
    return which


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
