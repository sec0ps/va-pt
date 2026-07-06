#!/usr/bin/env python3
"""
tsexit - Tailscale exit node manager

View, set, verify, and unset the active exit node on a Linux Tailscale client.
Reads node data from `tailscale status --json` and applies changes through
`tailscale set` so existing prefs are preserved (avoids the `tailscale up`
full-preference reset).

"""

import argparse
import json
import subprocess
import sys
import urllib.request

# Public IP echo services used by `verify` to read the current egress address.
# Tried in order; the first one that answers wins.
EGRESS_ENDPOINTS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


def run_tailscale(args):
    # Single choke point for all CLI calls. Fails cleanly if the binary is
    # missing instead of raising a raw traceback.
    try:
        return subprocess.run(["tailscale"] + args, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("tailscale binary not found in PATH")


def get_status():
    # JSON status is far more stable to parse than the columnar `exit-node
    # list` output and exposes ExitNodeOption / ExitNode directly.
    result = run_tailscale(["status", "--json"])
    if result.returncode != 0:
        sys.exit(f"tailscale status failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def collect_exit_nodes(status):
    # A peer offering exit service has ExitNodeOption=true; the peer currently
    # being routed through has ExitNode=true.
    nodes = []
    current = None
    for peer in status.get("Peer", {}).values():
        if not peer.get("ExitNodeOption"):
            continue
        entry = {
            "host": peer.get("HostName", ""),
            "ip": (peer.get("TailscaleIPs") or [""])[0],
            "online": peer.get("Online", False),
            "active": peer.get("ExitNode", False),
        }
        nodes.append(entry)
        if entry["active"]:
            current = entry
    return nodes, current


def resolve_exit_node(status, target):
    # Accept a MagicDNS hostname or a Tailscale IP and return the IP to hand to
    # `tailscale set`. Validate the peer actually advertises exit service so we
    # fail early rather than setting a node that blackholes all traffic.
    target = target.strip()
    for peer in status.get("Peer", {}).values():
        host = peer.get("HostName", "")
        ips = peer.get("TailscaleIPs") or []
        if target == host or target in ips:
            if not peer.get("ExitNodeOption"):
                return None, f"{target} is not advertising as an exit node"
            return ips[0], None
    return None, f"{target} not found in tailnet"


def exit_node_connection(status, ip):
    # Report how the local node reaches the active exit node. A non-empty
    # CurAddr means a direct path; otherwise traffic is relayed through DERP.
    for peer in status.get("Peer", {}).values():
        ips = peer.get("TailscaleIPs") or []
        if ip in ips:
            if peer.get("CurAddr"):
                return f"direct {peer['CurAddr']}"
            relay = peer.get("Relay") or "unknown"
            return f"via DERP ({relay})"
    return "unknown"


def get_egress_ip():
    # Read the public address the VM's traffic is currently leaving from. When
    # an exit node is active this call routes through it, so the value reflects
    # the exit node's egress, which is what attribution checks care about.
    for url in EGRESS_ENDPOINTS:
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return ip, None
        except Exception:
            continue
    return None, "could not determine egress IP (no endpoint reachable)"


def cmd_list(_args):
    status = get_status()
    nodes, current = collect_exit_nodes(status)
    if not nodes:
        print("no exit nodes available")
        return
    for n in nodes:
        marker = "*" if n["active"] else " "
        state = "online" if n["online"] else "offline"
        print(f"{marker} {n['host']:<20} {n['ip']:<16} {state}")
    print(f"\ncurrent: {current['host']} ({current['ip']})" if current else "\ncurrent: none")


def cmd_set(args):
    status = get_status()
    ip, err = resolve_exit_node(status, args.node)
    if err:
        sys.exit(err)
    set_args = ["set", f"--exit-node={ip}"]
    if args.lan:
        set_args.append("--exit-node-allow-lan-access")
    result = run_tailscale(set_args)
    if result.returncode != 0:
        sys.exit(f"failed to set exit node: {result.stderr.strip()}")
    print(f"exit node set to {args.node} ({ip})")


def cmd_verify(args):
    # Pre-test gate: show the active exit node, how it is reached, and the
    # public egress address. With --expect, fail on any mismatch so an
    # engagement never starts from the wrong source.
    status = get_status()
    _, current = collect_exit_nodes(status)
    if current:
        conn = exit_node_connection(status, current["ip"])
        print(f"exit node: {current['host']} ({current['ip']}) [{conn}]")
    else:
        print("exit node: none set")

    ip, err = get_egress_ip()
    if err:
        print(err)
        if args.expect:
            sys.exit("egress IP could not be confirmed against expected value")
        return

    print(f"egress IP: {ip}")
    if args.expect:
        expected = args.expect.strip()
        if ip == expected:
            print(f"match: egress IP equals expected attribution IP {expected}")
        else:
            sys.exit(f"MISMATCH: egress IP {ip} does not equal expected {expected}")


def cmd_unset(_args):
    result = run_tailscale(["set", "--exit-node="])
    if result.returncode != 0:
        sys.exit(f"failed to unset exit node: {result.stderr.strip()}")
    print("exit node cleared")


def main():
    parser = argparse.ArgumentParser(description="Manage the Tailscale exit node")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list available exit nodes and show the active one")

    p_set = sub.add_parser("set", help="route all traffic through an exit node")
    p_set.add_argument("node", help="exit node hostname or Tailscale IP")
    p_set.add_argument("--lan", action="store_true",
                       help="keep access to the local LAN while the exit node is active")

    p_verify = sub.add_parser("verify",
                              help="show the active exit node and confirm the public egress IP")
    p_verify.add_argument("--expect", metavar="IP",
                          help="attribution IP the egress must match; exit non-zero on mismatch")

    sub.add_parser("unset", help="stop routing through any exit node")

    args = parser.parse_args()
    {
        "list": cmd_list,
        "set": cmd_set,
        "verify": cmd_verify,
        "unset": cmd_unset,
    }[args.command](args)


if __name__ == "__main__":
    main()
