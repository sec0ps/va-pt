#!/usr/bin/env python3
"""
tsexit - Tailscale exit node manager

View, set, and unset the active exit node on a Linux Tailscale client.
Reads node data from `tailscale status --json` and applies changes through
`tailscale set` so existing prefs are preserved (avoids the `tailscale up`
full-preference reset).
"""

import argparse
import json
import subprocess
import sys


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

    sub.add_parser("unset", help="stop routing through any exit node")

    args = parser.parse_args()
    {"list": cmd_list, "set": cmd_set, "unset": cmd_unset}[args.command](args)


if __name__ == "__main__":
    main()
