"""Local installer that provisions a venv and prepares the darkweb recon service."""

import os
import shutil
import socket
import subprocess
import sys
import venv

ROOT = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(ROOT, ".venv")
DATA_DIR = os.path.join(ROOT, "data")
TOR_DATA_DIR = os.path.join(ROOT, "tordata")
REQUIREMENTS = os.path.join(ROOT, "requirements.txt")


def fail(message):
    print("error %s" % message)
    sys.exit(1)


def check_not_root():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        fail("do not run as root, the venv must be owned by your user, run without sudo")


def check_python():
    if sys.version_info < (3, 9):
        fail("python 3.9 or newer is required")


def check_tor():
    if shutil.which("tor") is None:
        print("tor binary not found on PATH")
        print("install it first, then re-run this installer")
        print("    sudo apt install -y tor")
        sys.exit(1)
    print("tor binary found")


def port_in_use(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        return sock.connect_ex(("127.0.0.1", port)) == 0
    finally:
        sock.close()


def warn_tor_conflict():
    socks_port = int(os.environ.get("TOR_SOCKS_PORT", "9050"))
    control_port = int(os.environ.get("TOR_CONTROL_PORT", "9051"))
    conflicts = [p for p in (socks_port, control_port) if port_in_use(p)]
    if not conflicts:
        return
    ports = " and ".join(str(p) for p in conflicts)
    print("")
    print("warning port %s already in use, likely the distro tor service" % ports)
    print("the app launches its own managed tor and will collide")
    print("either free it")
    print("    sudo systemctl disable --now tor")
    print("or run with alternate ports")
    print("    export TOR_SOCKS_PORT=9060 TOR_CONTROL_PORT=9061")


def venv_python():
    return os.path.join(VENV_DIR, "bin", "python")


def make_venv():
    if os.path.isdir(VENV_DIR):
        print("venv already present, reusing")
        return
    print("creating venv at .venv")
    venv.create(VENV_DIR, with_pip=True)


def pip_install():
    python = venv_python()
    print("upgrading pip")
    subprocess.check_call([python, "-m", "pip", "install", "--upgrade", "pip", "--quiet"])
    print("installing requirements")
    subprocess.check_call([python, "-m", "pip", "install", "-r", REQUIREMENTS, "--quiet"])


def make_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(TOR_DATA_DIR, exist_ok=True)
    print("data dir %s" % DATA_DIR)
    print("tor dir  %s" % TOR_DATA_DIR)


def summary():
    python = venv_python()
    print("")
    print("install complete")
    print("")
    print("create the first admin")
    print("    %s manage.py create-admin --username admin" % python)
    print("")
    print("start the console")
    print("    %s run.py" % python)
    print("    then open http://localhost:8080")
    print("")
    print("run an ephemeral manual search")
    print("    %s search.py --term \"acme corp\" --engagement acme" % python)


def main():
    check_not_root()
    check_python()
    check_tor()
    make_venv()
    pip_install()
    make_dirs()
    warn_tor_conflict()
    summary()


if __name__ == "__main__":
    main()
