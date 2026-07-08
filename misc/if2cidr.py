#!/usr/bin/env python3
"""
if2cidr - convert interface configuration output to network CIDRs

Parses ifconfig / ip addr / ipconfig output and prints the network address in
CIDR notation for each IPv4 interface, ready to feed straight into nmap (one
target per line, suitable for `nmap -iL` or command-line substitution).

Run it bare and paste the config when prompted, or pipe / pass a file:
    if2cidr.py                         # prompts, paste config, Ctrl-D to finish
    ifconfig | if2cidr.py
    ip addr  | if2cidr.py
    if2cidr.py ipconfig.txt
    nmap -sS $(ifconfig | if2cidr.py)

The host address is collapsed to its containing network, so
"inet 10.19.0.4 netmask 255.255.255.128" yields 10.19.0.0/25.

Loopback and link-local nets are dropped by default since they are never useful
scan targets and loopback is always present in a full ifconfig dump; pass --all
to keep them. IPv6 is intentionally ignored (link-local and /64 subnets are not
meaningfully sweepable).
"""

import argparse
import ipaddress
import re
import sys

# ifconfig (util-linux) and BSD/macOS: "inet 10.19.0.4 netmask 255.255.255.128"
# macOS prints a hex netmask ("netmask 0xffffff80"), folded down at normalize time.
RE_IFCONFIG = re.compile(
    r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+netmask\s+"
    r"(0x[0-9a-fA-F]{8}|\d{1,3}(?:\.\d{1,3}){3})"
)

# Legacy Linux ifconfig: "inet addr:10.19.0.4  Bcast:...  Mask:255.255.255.128"
RE_IFCONFIG_OLD = re.compile(
    r"inet addr:(\d{1,3}(?:\.\d{1,3}){3}).*?Mask:(\d{1,3}(?:\.\d{1,3}){3})"
)

# iproute2: "inet 10.19.0.4/25 brd 10.19.0.127 scope global eth0"
RE_IPADDR = re.compile(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\b")

# Windows ipconfig: IP and mask sit on separate lines inside an adapter block,
# so they are paired via a small amount of state in parse(). Matches both the
# modern "IPv4 Address" and legacy "IP Address" labels.
RE_WIN_IP = re.compile(r"IP(?:v4)? Address[.\s]*:\s*(\d{1,3}(?:\.\d{1,3}){3})")
RE_WIN_MASK = re.compile(r"Subnet Mask[.\s]*:\s*(\d{1,3}(?:\.\d{1,3}){3})")


def netmask_to_dotted(mask):
    # ip_interface() understands dotted decimal and prefix length but not the
    # 0x-hex form macOS prints, so fold hex down to dotted decimal first.
    if mask.lower().startswith("0x"):
        return str(ipaddress.IPv4Address(int(mask, 16)))
    return mask


def parse(text):
    # Walk line by line so the two-line Windows pattern can be paired with a bit
    # of state; every single-line format is matched independently per line.
    results = []
    pending_ip = None

    for line in text.splitlines():
        m = RE_IFCONFIG.search(line)
        if m:
            results.append((m.group(1), netmask_to_dotted(m.group(2))))
            continue

        m = RE_IFCONFIG_OLD.search(line)
        if m:
            results.append((m.group(1), m.group(2)))
            continue

        m = RE_IPADDR.search(line)
        if m:
            results.append((m.group(1), m.group(2)))
            continue

        m = RE_WIN_IP.search(line)
        if m:
            pending_ip = m.group(1)
            continue

        m = RE_WIN_MASK.search(line)
        if m and pending_ip:
            results.append((pending_ip, m.group(1)))
            pending_ip = None

    return results


def to_cidr(ip, mask, keep_reserved):
    # Collapse host address + mask to the containing network. strict=False is
    # implied by ip_interface, so a set host bit (always the case off a live
    # interface) is fine rather than an error.
    try:
        net = ipaddress.ip_interface(f"{ip}/{mask}").network
    except ValueError:
        return None
    if (net.is_loopback or net.is_link_local) and not keep_reserved:
        return None
    return net


def read_input(path):
    # Source priority: explicit file, then piped/redirected stdin, then an
    # interactive paste prompt. isatty() tells a human at the terminal apart
    # from a pipe, so "ifconfig | if2cidr.py" stays silent while a bare run
    # guides the user. The prompt goes to stderr to keep stdout clean for nmap.
    if path:
        with open(path) as fh:
            return fh.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    sys.stderr.write(
        "Paste interface config (ifconfig / ip addr / ipconfig), "
        "then Ctrl-D to finish (Ctrl-Z then Enter on Windows):\n"
    )
    sys.stderr.flush()
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(
        description="Convert ifconfig / ip addr / ipconfig output to nmap-ready network CIDRs"
    )
    parser.add_argument("file", nargs="?",
                        help="interface config dump to read (default: paste at prompt or stdin)")
    parser.add_argument("-a", "--all", action="store_true",
                        help="include loopback and link-local nets (dropped by default)")
    args = parser.parse_args()

    text = read_input(args.file)

    seen = set()
    for ip, mask in parse(text):
        net = to_cidr(ip, mask, args.all)
        if net is not None and net not in seen:
            seen.add(net)
            print(net)

    if not seen:
        sys.stderr.write("no IPv4 networks found in input\n")


if __name__ == "__main__":
    main()
