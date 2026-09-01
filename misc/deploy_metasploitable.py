#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: Lifecycle manager for a tleemcjr/metasploitable2 target on a Docker
#          macvlan network. Provides up/down/restart/status actions with an
#          autodetected LAN parent and IP, a host<->container macvlan shim so
#          the Docker host can reach the target, validation that a reused
#          macvlan network still shares the current parent (a stale network is
#          rebuilt rather than silently reused), an honest post-deploy
#          reachability probe, and JSON-backed state so the target can be torn
#          down and re-added on a stable IP.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================
"""
deploy_metasploitable.py

Lifecycle manager for tleemcjr/metasploitable2 on a Docker macvlan
("bridged") network. The target owns a real IP on the LAN, its vulnerable
services are started, and a host->container macvlan shim lets the Docker host
itself reach it. A small JSON state file records the deployment so the
container can be removed and re-added on the SAME IP without rebuilding the
macvlan network or shim.

Target host: Ubuntu 22.04 (jammy). Python 3, standard library only.

Actions:
    up        deploy or re-add the target            (default)
    down      remove the container, keep net + shim  (fast re-add)
    down --purge   also remove network, shim, state  (clean slate)
    restart   remove the container and redeploy
    status    show current state

    deploy / teardown are accepted as aliases for up / down.

Examples:
    sudo python3 deploy_metasploitable.py
    sudo python3 deploy_metasploitable.py up --ip 192.168.1.50
    sudo python3 deploy_metasploitable.py down
    sudo python3 deploy_metasploitable.py down --purge
    sudo python3 deploy_metasploitable.py restart
    sudo python3 deploy_metasploitable.py status

Notes:
  * macvlan needs a WIRED parent in promiscuous mode. On Wi-Fi most APs drop
    the spoofed MACs and the target is unreachable; the parent is checked and
    a warning is printed if it is wireless.
  * A reused macvlan network is validated against the current parent NIC and
    subnet. If it was created over a different parent (e.g. an earlier Wi-Fi
    session), the shim and container would land on different lower devices and
    never exchange traffic; the stale network is torn down and rebuilt on the
    current parent instead of being silently reused.
  * The final banner reflects an actual host->target reachability probe. When
    the shim is enabled and the host still cannot reach the target, the deploy
    reports UNREACHABLE (and exits non-zero) rather than claiming success.
  * The host<->container shim is ephemeral (gone on reboot). Re-run `up` to
    recreate it.
"""

import argparse
import ipaddress
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import time

DEFAULT_IMAGE = "tleemcjr/metasploitable2"
DEFAULT_NETWORK = "pentest_lan"
DEFAULT_CONTAINER = "metasploitable2"
SHIM_IF = "macvlan-shim"
STATE_FILE = "/var/lib/metasploitable-deploy.json"
LOG_FILE = "/var/log/deploy_metasploitable.log"

CORE_PORTS = {21, 22, 23, 80, 139, 445, 3306}
KNOWN_PORTS = {
    21: "ftp/vsftpd", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 111: "rpcbind", 139: "netbios-ssn", 445: "microsoft-ds",
    512: "exec", 513: "login", 514: "shell", 1099: "java-rmi",
    1524: "bindshell", 2049: "nfs", 2121: "ftp/proftpd", 3306: "mysql",
    3632: "distccd", 5432: "postgresql", 5900: "vnc", 6000: "x11",
    6667: "irc/unreal", 8009: "ajp13", 8180: "tomcat",
}

log = logging.getLogger("metasploitable")


# --------------------------------------------------------------------------- #
# infra helpers
# --------------------------------------------------------------------------- #
def setup_logging():
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    log.addHandler(console)

    try:
        fileh = logging.FileHandler(LOG_FILE)
    except OSError:
        fileh = logging.FileHandler("deploy_metasploitable.log")
    fileh.setLevel(logging.DEBUG)
    fileh.setFormatter(fmt)
    log.addHandler(fileh)


def run(cmd, check=True, capture=True, timeout=None, env=None):
    """Run a command. Captures and logs output unless capture=False (live)."""
    log.debug("exec: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd, capture_output=capture, text=True, timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired:
        log.error("timeout after %ss: %s", timeout, " ".join(cmd))
        raise
    if capture and proc.stdout:
        log.debug(proc.stdout.strip())
    if check and proc.returncode != 0:
        log.error("failed (%d): %s", proc.returncode, " ".join(cmd))
        if capture and proc.stderr:
            log.error(proc.stderr.strip())
        raise subprocess.CalledProcessError(proc.returncode, cmd,
                                            proc.stdout, proc.stderr)
    return proc


def die(msg):
    log.error(msg)
    sys.exit(1)


def reexec_as_root():
    if os.geteuid() != 0:
        log.info("elevating with sudo...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


# --------------------------------------------------------------------------- #
# state file
# --------------------------------------------------------------------------- #
def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_state(path, data):
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        log.debug("state written to %s", path)
    except OSError as exc:
        log.warning("could not write state file %s: %s", path, exc)


def clear_state(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------- #
# host / docker checks
# --------------------------------------------------------------------------- #
def check_os():
    try:
        data = open("/etc/os-release").read()
    except FileNotFoundError:
        log.warning("cannot read /etc/os-release; proceeding")
        return
    if "Ubuntu" not in data:
        log.warning("host does not look like Ubuntu; proceeding anyway")
    elif 'VERSION_ID="22.04"' not in data:
        log.warning("host is not Ubuntu 22.04; proceeding anyway")


def ensure_docker(skip_install):
    if shutil.which("docker"):
        if run(["docker", "info"], check=False).returncode == 0:
            return
        log.info("docker installed but daemon down; starting it")
        run(["systemctl", "enable", "--now", "docker"], check=False)
        if run(["docker", "info"], check=False).returncode == 0:
            return
        die("docker daemon will not start; check `systemctl status docker`")

    if skip_install:
        die("docker not found and --skip-docker-install was set")

    log.info("docker not found; installing docker.io from the Ubuntu repos")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update"], capture=False, env=env, timeout=600)
    run(["apt-get", "install", "-y", "docker.io"], capture=False, env=env,
        timeout=1800)
    run(["systemctl", "enable", "--now", "docker"])
    if run(["docker", "info"], check=False).returncode != 0:
        die("docker install completed but daemon is not responding")


# --------------------------------------------------------------------------- #
# network discovery
# --------------------------------------------------------------------------- #
def is_wireless(iface):
    return (os.path.isdir(f"/sys/class/net/{iface}/wireless")
            or os.path.exists(f"/sys/class/net/{iface}/phy80211"))


def detect_network(iface_override):
    """Return (iface, ipaddress.network, gateway) from the default route."""
    out = run(["ip", "-o", "route", "show", "default"]).stdout.strip()
    routes = []
    for line in out.splitlines():
        m = re.search(r"default via (\S+) dev (\S+)", line)
        if m:
            routes.append((m.group(1), m.group(2)))
    if not routes:
        die("no default route found; pass --interface, --subnet and --gateway")

    gw, iface = routes[0]
    for g, i in routes:                       # prefer a wired uplink
        if not is_wireless(i):
            gw, iface = g, i
            break
    if iface_override:
        iface = iface_override

    addr = run(["ip", "-o", "-f", "inet", "addr", "show", "dev", iface]).stdout
    m = re.search(r"inet (\S+)", addr)
    if not m:
        die(f"interface {iface} has no IPv4 address")
    network = ipaddress.ip_interface(m.group(1)).network
    return iface, network, ipaddress.ip_address(gw)


def resolve_network(args, state):
    """CLI overrides win; else reuse saved state; else autodetect."""
    overrides = args.interface or args.subnet or args.gateway
    if state and not overrides:
        return (state["parent"],
                ipaddress.ip_network(state["subnet"]),
                ipaddress.ip_address(state["gateway"]))
    iface, network, gateway = detect_network(args.interface)
    if args.subnet:
        network = ipaddress.ip_network(args.subnet, strict=False)
    if args.gateway:
        gateway = ipaddress.ip_address(args.gateway)
    return iface, network, gateway


def ip_in_use(ip, iface):
    if run(["ping", "-c", "1", "-W", "1", str(ip)], check=False).returncode == 0:
        return True
    if shutil.which("arping"):
        r = run(["arping", "-c", "1", "-w", "1", "-I", iface, str(ip)],
                check=False)
        return r.returncode == 0
    return False


def first_free_ip(network, gateway, iface, exclude=()):
    """Probe host addresses in random order and return the first free one.

    Random order keeps two hosts deploying simultaneously from both starting
    at the same end of the range and claiming the same address before either
    container is live. It narrows the race but does not close it; the
    post-deploy check in cmd_up self-heals a genuine collision.
    """
    skip = {gateway} | set(exclude)
    candidates = [ip for ip in network.hosts() if ip not in skip]
    random.shuffle(candidates)
    tried = 0
    for ip in candidates:
        if not ip_in_use(ip, iface):
            return ip
        tried += 1
        if tried >= 30:                       # bound the probe time
            break
    die("could not find a free IP in the subnet; specify --ip explicitly")


# --------------------------------------------------------------------------- #
# docker primitives
# --------------------------------------------------------------------------- #
def network_exists(name):
    names = run(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    return name in names


def container_state(name):
    p = run(["docker", "inspect", "-f", "{{.State.Status}}", name], check=False)
    return p.stdout.strip() if p.returncode == 0 else None


def container_ip_addr(name):
    p = run(["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            check=False)
    val = p.stdout.strip()
    return val if (p.returncode == 0 and val) else None


def image_present(image):
    return run(["docker", "image", "inspect", image], check=False).returncode == 0


def network_details(name):
    p = run(["docker", "network", "inspect", name, "--format",
             "{{.Driver}}|{{index .Options \"parent\"}}|"
             "{{range .IPAM.Config}}{{.Subnet}}{{end}}"], check=False)
    if p.returncode != 0:
        return None
    parts = p.stdout.strip().split("|")
    if len(parts) != 3:
        return None
    return {"driver": parts[0], "parent": parts[1], "subnet": parts[2]}


def containers_on_network(name):
    p = run(["docker", "network", "inspect", name, "--format",
             "{{range .Containers}}{{.Name}} {{end}}"], check=False)
    if p.returncode != 0:
        return []
    return p.stdout.split()


def recreate_network(name, container):
    if container and container_state(container) is not None:
        log.info("detaching container %s from %s", container, name)
        run(["docker", "rm", "-f", container], check=False)
    rm = run(["docker", "network", "rm", name], check=False)
    if rm.returncode != 0:
        others = containers_on_network(name)
        if others:
            die(f"cannot rebuild network {name}: still in use by "
                f"{', '.join(others)}; remove those containers or re-run with "
                f"--force")
        die(f"cannot remove network {name}: {rm.stderr.strip()}")


def ensure_network(name, network, gateway, iface, force, container=None):
    if network_exists(name):
        details = network_details(name)
        cur_driver = details["driver"] if details else "?"
        cur_parent = details["parent"] if details else "?"
        cur_subnet = details["subnet"] if details else "?"
        mismatch = (details is None
                    or cur_driver != "macvlan"
                    or cur_parent != iface
                    or cur_subnet != str(network))

        if not force and not mismatch:
            log.info("macvlan network %s already exists (parent=%s subnet=%s); "
                     "reusing", name, cur_parent, cur_subnet)
            return

        if force:
            log.info("--force: rebuilding macvlan network %s (parent=%s "
                     "subnet=%s)", name, cur_parent, cur_subnet)
        else:
            log.warning("macvlan network %s is stale (parent=%s subnet=%s, want "
                        "parent=%s subnet=%s); rebuilding so the shim and "
                        "container share one parent", name, cur_parent,
                        cur_subnet, iface, network)
        recreate_network(name, container)

    run(["docker", "network", "create", "-d", "macvlan",
         "--subnet", str(network), "--gateway", str(gateway),
         "-o", f"parent={iface}", name])
    log.info("created macvlan network %s on parent %s", name, iface)


def deploy_container(name, image, network, ip, force):
    state = container_state(name)
    if state and force:
        run(["docker", "rm", "-f", name], check=False)
        state = None

    if state == "running":
        log.info("container %s already running", name)
        return
    if state in ("exited", "created"):
        log.info("starting existing container %s (re-runs services.sh)", name)
        run(["docker", "start", name])
        return

    if not image_present(image):
        log.info("pulling %s (~1.5 GB, first run only)...", image)
        run(["docker", "pull", image], capture=False, timeout=1800)

    log.info("launching %s on %s as %s", name, network, ip)
    run(["docker", "run", "-dit", "--name", name,
         "--network", network, "--ip", str(ip),
         image, "sh", "-c", "/bin/services.sh && bash"])


def wait_running(name, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if container_state(name) == "running":
            return True
        time.sleep(1)
    return False


def listening_ports(name):
    """Listening TCP ports inside the container (netstat, ss fallback)."""
    out = ""
    p = run(["docker", "exec", name, "netstat", "-ntl"], check=False)
    if p.returncode == 0:
        out = p.stdout
    else:
        p = run(["docker", "exec", name, "ss", "-Hntl"], check=False)
        out = p.stdout if p.returncode == 0 else ""
    ports = set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        if ":" in local:
            try:
                ports.add(int(local.rsplit(":", 1)[1]))
            except ValueError:
                pass
    return ports


def wait_for_services(name, timeout=60):
    deadline = time.time() + timeout
    seen = set()
    while time.time() < deadline:
        seen = listening_ports(name)
        if CORE_PORTS.issubset(seen):
            return seen
        time.sleep(2)
    return seen


# --------------------------------------------------------------------------- #
# host <-> container shim
# --------------------------------------------------------------------------- #
def shim_exists():
    return run(["ip", "link", "show", SHIM_IF], check=False).returncode == 0


def setup_shim(iface, network, container_ip, gateway, shim_override):
    if shim_exists():
        run(["ip", "link", "del", SHIM_IF], check=False)

    if shim_override:
        shim_ip = ipaddress.ip_address(shim_override)
    else:
        shim_ip = first_free_ip(network, gateway, iface, exclude=(container_ip,))

    run(["ip", "link", "add", SHIM_IF, "link", iface, "type", "macvlan",
         "mode", "bridge"])
    run(["ip", "addr", "add", f"{shim_ip}/32", "dev", SHIM_IF])
    run(["ip", "link", "set", SHIM_IF, "up"])
    run(["ip", "route", "add", f"{container_ip}/32", "dev", SHIM_IF])
    log.info("shim %s up (%s) -> route to %s", SHIM_IF, shim_ip, container_ip)
    return shim_ip


def remove_shim():
    if shim_exists():
        run(["ip", "link", "del", SHIM_IF], check=False)
        log.info("removed shim %s", SHIM_IF)


def host_can_reach(ip):
    return run(["ping", "-c", "2", "-W", "1", str(ip)], check=False).returncode == 0


def detect_ip_conflict(name, container_ip, iface):
    """Return the set of foreign MACs answering ARP for container_ip.

    The container's own MAC is excluded, so a non-empty result means a second
    host on the LAN has claimed the same address. Probes through the shim when
    it is up (macvlan siblings can reach each other) and through the parent NIC
    otherwise. Needs arping; returns empty (check skipped) if it is missing.
    """
    if not shutil.which("arping"):
        log.warning("arping not installed; skipping duplicate-IP check")
        return set()

    p = run(["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}", name],
            check=False)
    own = p.stdout.strip().lower()

    probe_if = SHIM_IF if shim_exists() else iface
    r = run(["arping", "-c", "3", "-w", "3", "-I", probe_if, str(container_ip)],
            check=False)
    macs = {m.lower() for m in
            re.findall(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", r.stdout)}
    macs.discard(own)
    return macs


# --------------------------------------------------------------------------- #
# actions
# --------------------------------------------------------------------------- #
def resolve_container_ip(args, state, network, gateway, iface, name):
    if args.ip:
        ip = ipaddress.ip_address(args.ip)
        if ip not in network:
            die(f"--ip {ip} is not inside {network}")
        return ip

    if container_state(name) == "running":
        live = container_ip_addr(name)
        if live:
            log.info("container already running at %s", live)
            return ipaddress.ip_address(live)

    if state and state.get("container_ip"):
        cand = ipaddress.ip_address(state["container_ip"])
        if cand in network and not ip_in_use(cand, iface):
            log.info("reusing previous target IP %s", cand)
            return cand
        log.warning("previous IP %s unavailable; selecting a new one", cand)

    ip = first_free_ip(network, gateway, iface)
    log.info("selected target IP %s", ip)
    return ip


def cmd_up(args):
    check_os()
    ensure_docker(args.skip_docker_install)
    state = load_state(args.state_file)

    name = args.container_name
    if args.force:
        run(["docker", "rm", "-f", name], check=False)

    iface, network, gateway = resolve_network(args, state)
    log.info("parent=%s subnet=%s gateway=%s", iface, network, gateway)

    if is_wireless(iface) and not args.allow_wifi:
        log.warning("parent NIC %s is WIRELESS — macvlan almost never works on "
                    "Wi-Fi (AP drops spoofed MACs). Use a wired NIC, or pass "
                    "--allow-wifi to try anyway.", iface)

    shim_enabled = not args.no_shim
    if state and not args.no_shim:
        shim_enabled = state.get("shim_enabled", True)

    container_ip = resolve_container_ip(args, state, network, gateway, iface, name)
    ensure_network(args.network_name, network, gateway, iface, args.force,
                   container=name)

    shim_ip = None
    reachable = None
    seen = set()
    attempts = 1 if args.ip else 3
    for attempt in range(1, attempts + 1):
        deploy_container(name, args.image, args.network_name, container_ip,
                         args.force)

        if not wait_running(name):
            die(f"container {name} did not reach running state; "
                f"see `docker logs {name}`")

        log.info("waiting for vulnerable services to come up...")
        seen = wait_for_services(name)
        if CORE_PORTS.issubset(seen):
            log.info("core services are listening")
        else:
            log.warning("not all core services up: missing %s",
                        sorted(CORE_PORTS - seen))

        if shim_enabled:
            prev_shim = state.get("shim_ip") if state else None
            shim_ip = setup_shim(iface, network, container_ip, gateway,
                                 args.shim_ip or prev_shim)
            reachable = host_can_reach(container_ip)
            if reachable:
                log.info("host reaches target at %s via shim", container_ip)
            else:
                log.warning("host still cannot reach %s through the shim — see "
                            "the diagnostics printed below", container_ip)

        foreign = detect_ip_conflict(name, container_ip, iface)
        if not foreign:
            break

        if args.ip:
            die(f"--ip {container_ip} is already in use on the LAN by "
                f"{', '.join(sorted(foreign))}; choose another address")

        log.warning("IP %s also claimed on the LAN by %s (attempt %d/%d)",
                    container_ip, ", ".join(sorted(foreign)), attempt, attempts)
        if attempt < attempts:
            run(["docker", "rm", "-f", name], check=False)
            container_ip = first_free_ip(network, gateway, iface)
            log.info("selected new target IP %s", container_ip)
    else:
        die(f"IP conflict persisted after {attempts} attempts; "
            f"specify --ip explicitly")

    save_state(args.state_file, {
        "container": name,
        "network": args.network_name,
        "image": args.image,
        "parent": iface,
        "subnet": str(network),
        "gateway": str(gateway),
        "container_ip": str(container_ip),
        "shim_if": SHIM_IF,
        "shim_ip": str(shim_ip) if shim_ip else None,
        "shim_enabled": shim_enabled,
    })

    summary(name, container_ip, args.network_name, iface, shim_ip, seen,
            args.state_file, shim_enabled, reachable)

    if shim_enabled and reachable is False:
        sys.exit(2)


def cmd_down(args):
    state = load_state(args.state_file)
    name = args.container_name

    if container_state(name) is not None:
        run(["docker", "rm", "-f", name], check=False)
        log.info("removed container %s", name)
    else:
        log.info("container %s not present", name)

    if args.purge:
        net = (state.get("network") if state else None) or args.network_name
        if network_exists(net):
            run(["docker", "network", "rm", net], check=False)
            log.info("removed network %s", net)
        remove_shim()
        clear_state(args.state_file)
        log.info("purge complete — clean slate")
    else:
        script = os.path.basename(__file__)
        log.info("network + shim + state preserved; re-add with: sudo %s up",
                 script)


def cmd_restart(args):
    log.info("restart: removing container, then redeploying")
    run(["docker", "rm", "-f", args.container_name], check=False)
    cmd_up(args)


def cmd_status(args):
    state = load_state(args.state_file)
    name = args.container_name
    net = (state.get("network") if state else None) or args.network_name
    line = "-" * 56

    print("\n" + line)
    print("  Metasploitable2 deployment status")
    print(line)

    docker_ok = shutil.which("docker") and \
        run(["docker", "info"], check=False).returncode == 0
    if not docker_ok:
        print("  docker        : not available")
        print(line + "\n")
        return

    if network_exists(net):
        details = network_details(net)
        if details:
            print(f"  network {net:<8}: present "
                  f"(parent={details['parent']} subnet={details['subnet']})")
        else:
            print(f"  network {net:<8}: present")
    else:
        print(f"  network {net:<8}: absent")

    cs = container_state(name)
    if cs is None:
        print(f"  container     : absent")
    else:
        ip = container_ip_addr(name) or (state.get("container_ip") if state else "?")
        print(f"  container     : {cs} @ {ip}")
        if cs == "running":
            ports = listening_ports(name)
            missing = CORE_PORTS - ports
            print(f"  services up   : {len(ports)} ports listening")
            if missing:
                print(f"  missing core  : {sorted(missing)}")
            else:
                print(f"  core services : all up")

    if shim_exists():
        tgt = state.get("container_ip") if state else "?"
        print(f"  shim {SHIM_IF}: up -> {tgt}")
        if cs == "running":
            probe = container_ip_addr(name) or (state.get("container_ip")
                                                if state else None)
            if probe:
                ok = host_can_reach(probe)
                print(f"  host reaches  : "
                      f"{'yes' if ok else 'NO — host cannot reach the target'}")
    else:
        print(f"  shim {SHIM_IF}: absent")

    print(f"  state file    : {'present' if state else 'absent'} "
          f"({args.state_file})")
    print(line + "\n")


# --------------------------------------------------------------------------- #
# summary
# --------------------------------------------------------------------------- #
def summary(container, ip, network, iface, shim_ip, seen_ports, state_file,
            shim_enabled, reachable):
    script = os.path.basename(__file__)
    line = "=" * 64
    operational = (not shim_enabled) or bool(reachable)

    print("\n" + line)
    if operational:
        print("  Metasploitable2 is operational")
    else:
        print("  Metasploitable2 DEPLOYED but UNREACHABLE from this host")
    print(line)
    print(f"  Target IP     : {ip}")
    print(f"  Docker network: {network} (macvlan, parent {iface})")
    print(f"  Container     : {container}")
    print(f"  Credentials   : msfadmin / msfadmin")
    if not shim_enabled:
        print(f"  Host shim     : disabled (attack from another LAN host)")
    elif reachable:
        print(f"  Host shim     : {SHIM_IF} @ {shim_ip} (host reaches target)")
    else:
        print(f"  Host shim     : {SHIM_IF} @ {shim_ip} (NOT reaching target)")

    if seen_ports:
        pretty = ", ".join(
            f"{p} {KNOWN_PORTS[p]}" if p in KNOWN_PORTS else str(p)
            for p in sorted(seen_ports)
        )
        print(f"  Listening     : {pretty}")
    missing = CORE_PORTS - seen_ports
    if missing:
        print(f"  WARNING       : core ports not up yet: {sorted(missing)}")
        print(f"                  retry: docker exec {container} /bin/services.sh")

    print(line)
    if shim_enabled and not reachable:
        print("  Host cannot reach the target. The container is up and its")
        print("  services are listening, but the host<->container macvlan path")
        print("  is not passing traffic. Check, in order:")
        print("    1. parent match : docker network inspect " + str(network)
              + " -f '{{.Options.parent}}'  (want " + str(iface) + ")")
        print(f"    2. promisc mode : sudo ip link set {iface} promisc on")
        print(f"    3. host route   : ip route get {ip}   (want dev {SHIM_IF})")
        print(f"    4. switch / AP  : single-MAC port security drops the target MAC")
        print(f"    5. container IP : docker exec {container} ip addr show eth0")
        print(f"    6. host fw      : nft list ruleset | grep -i {SHIM_IF}")
        print("  Or drive it from another LAN host and re-run with --no-shim.")
        print(line)

    print(f"  Shell in      : docker exec -it {container} bash")
    print(f"  Scan it       : nmap -sV {ip}")
    print(f"  Status        : sudo {script} status")
    print(f"  Restart       : sudo {script} restart")
    print(f"  Remove        : sudo {script} down          (keeps net + shim)")
    print(f"  Purge all     : sudo {script} down --purge")
    print(line + "\n")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
ALIASES = {"deploy": "up", "teardown": "down"}


def parse_args():
    ap = argparse.ArgumentParser(
        description="Deploy / tear down Metasploitable2 on a Docker macvlan "
                    "network. Default action is 'up'.")
    ap.add_argument(
        "action", nargs="?", default="up",
        choices=["up", "deploy", "down", "teardown", "restart", "status"],
        help="up/deploy (default), down/teardown, restart, status")

    ap.add_argument("--container-name", default=DEFAULT_CONTAINER)
    ap.add_argument("--network-name", default=DEFAULT_NETWORK)
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    ap.add_argument("--state-file", default=STATE_FILE)

    ap.add_argument("--interface", help="macvlan parent NIC (default: autodetect)")
    ap.add_argument("--subnet", help="CIDR override, e.g. 192.168.1.0/24")
    ap.add_argument("--gateway", help="gateway override, e.g. 192.168.1.1")
    ap.add_argument("--ip", help="static IP for the target (default: autopick/reuse)")
    ap.add_argument("--shim-ip", help="static IP for the host shim (default: autopick/reuse)")
    ap.add_argument("--no-shim", action="store_true",
                    help="skip the host<->container shim")
    ap.add_argument("--allow-wifi", action="store_true",
                    help="proceed even if the parent NIC is wireless")
    ap.add_argument("--skip-docker-install", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="rebuild network and container if they exist")
    ap.add_argument("--purge", action="store_true",
                    help="with down: also remove the network, shim and saved state")
    return ap.parse_args()


def main():
    args = parse_args()
    reexec_as_root()
    setup_logging()

    action = ALIASES.get(args.action, args.action)
    if action == "up":
        cmd_up(args)
    elif action == "down":
        cmd_down(args)
    elif action == "restart":
        cmd_restart(args)
    elif action == "status":
        cmd_status(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("interrupted")
