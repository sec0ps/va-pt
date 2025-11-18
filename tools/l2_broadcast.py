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
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This script provides an automated installation and management system
#          for a vulnerability assessment and penetration testing
#          toolkit. It installs and configures security tools across multiple
#          categories including exploitation, web testing, network scanning,
#          mobile security, cloud security, and Active Directory testing.
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

from datetime import datetime
import argparse

from scapy.all import (
    sniff,
    Ether,
    ARP,
    DHCP,
    BOOTP,
    IP,
)

# Optional layers (may not exist in all Scapy builds)
try:
    from scapy.layers.l2 import CDP, Dot3, LLC, STP
except ImportError:
    CDP = None
    Dot3 = None
    LLC = None
    STP = None

# Broadcast / common L2 multicast MACs
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MULTICAST_MAC_LABELS = {
    "01:00:0c:cc:cc:cc": "CDP",
    "01:80:c2:00:00:00": "STP",
    "01:80:c2:00:00:0e": "LLDP",
    "01:00:5e:00:00:01": "IGMP",
    "33:33:00:00:00:01": "IPV6-MCAST",
}


def parse_args():
    p = argparse.ArgumentParser(
        description="Listen for DHCP, CDP, ARP, LLDP, STP and other L2 broadcast/multicast frames."
    )
    p.add_argument(
        "-i",
        "--iface",
        help="Interface to sniff on (e.g. eth0, ens33). If omitted, Scapy's default is used.",
        default=None,
    )
    return p.parse_args()


def is_interesting_l2(pkt):
    """Filter to only L2 broadcast / common multicast frames."""
    if Ether not in pkt:
        return False

    dst = pkt[Ether].dst.lower()
    if dst == BROADCAST_MAC:
        return True
    if dst in MULTICAST_MAC_LABELS:
        return True

    # You can extend this to include more MACs if needed.
    return False


def get_proto_label(pkt):
    """Rough classification for display."""
    try:
        if ARP in pkt:
            return "ARP"
        if DHCP in pkt or BOOTP in pkt:
            return "DHCP"
        if CDP and CDP in pkt:
            return "CDP"
        # LLDP EtherType
        if pkt[Ether].type == 0x88CC:
            return "LLDP"
        if STP and STP in pkt:
            return "STP"

        dst = pkt[Ether].dst.lower()
        if dst == BROADCAST_MAC:
            return "BCAST"
        if dst in MULTICAST_MAC_LABELS:
            return MULTICAST_MAC_LABELS[dst]

        return "OTHER"
    except Exception:
        return "UNK"


def dhcp_info(pkt):
    msg_type_map = {
        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM",
    }
    if not (DHCP in pkt or BOOTP in pkt):
        return ""

    dhcp_layer = pkt[DHCP] if DHCP in pkt else None
    msg_type = None
    if dhcp_layer:
        for opt in dhcp_layer.options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                msg_type = msg_type_map.get(opt[1], str(opt[1]))
                break

    bootp = pkt[BOOTP] if BOOTP in pkt else None
    yiaddr = bootp.yiaddr if bootp else ""
    ciaddr = bootp.ciaddr if bootp else ""
    giaddr = bootp.giaddr if bootp else ""

    parts = []
    if msg_type:
        parts.append(msg_type)
    if yiaddr:
        parts.append(f"yiaddr={yiaddr}")
    if ciaddr:
        parts.append(f"ciaddr={ciaddr}")
    if giaddr:
        parts.append(f"giaddr={giaddr}")
    return "DHCP[" + ", ".join(parts) + "]" if parts else "DHCP"


def arp_info(pkt):
    if ARP not in pkt:
        return ""
    a = pkt[ARP]
    op = "who-has" if a.op == 1 else "is-at" if a.op == 2 else str(a.op)
    return f"ARP[{op} {a.psrc} -> {a.pdst}]"


def cdp_info(pkt):
    if not (CDP and CDP in pkt):
        return ""
    c = pkt[CDP]
    # Not all fields are always present; use getattr defensively
    dev_id = getattr(c, "deviceid", "") or ""
    port_id = getattr(c, "portid", "") or ""
    parts = []
    if dev_id:
        parts.append(f"dev={dev_id}")
    if port_id:
        parts.append(f"port={port_id}")
    return "CDP[" + ", ".join(parts) + "]" if parts else "CDP"


def generic_info(pkt, proto_label):
    return proto_label + "[" + pkt.summary() + "]"


def build_info(pkt, proto_label):
    if proto_label == "DHCP":
        return dhcp_info(pkt)
    if proto_label == "ARP":
        return arp_info(pkt)
    if proto_label == "CDP":
        return cdp_info(pkt)
    return generic_info(pkt, proto_label)


def packet_handler(pkt):
    try:
        if not is_interesting_l2(pkt):
            return

        ts = datetime.now().strftime("%H:%M:%S")
        eth = pkt[Ether]
        src_mac = eth.src
        dst_mac = eth.dst

        src_ip = ""
        if IP in pkt:
            src_ip = pkt[IP].src
        elif ARP in pkt:
            src_ip = pkt[ARP].psrc

        proto = get_proto_label(pkt)
        info = build_info(pkt, proto)

        # Simple aligned, readable one-line output
        print(
            f"{ts}  {proto:<7}  {src_mac:<17}  {src_ip:<15} -> {dst_mac:<17}  {info}"
        )

    except Exception as e:
        # Swallow per-packet errors to keep sniffer running
        # Uncomment for debugging:
        # print(f"Error parsing packet: {e}")
        pass


def main():
    args = parse_args()

    print(
        "Listening for L2 broadcast / discovery traffic "
        f"on interface: {args.iface or 'DEFAULT'}"
    )
    print(
        "Columns: TIME  PROTO  SRC_MAC  SRC_IP  ->  DST_MAC  INFO"
    )
    print("-" * 100)

    sniff(
        iface=args.iface,
        store=False,
        prn=packet_handler,
    )


if __name__ == "__main__":
    main()
