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

#!/usr/bin/env python3
from datetime import datetime
import argparse
import struct

from scapy.all import (
    sniff,
    Ether,
    ARP,
    DHCP,
    BOOTP,
    IP,
)

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
        description="Listen for L2 broadcast / discovery traffic (DHCP, CDP, ARP, LLDP, STP, etc.)"
    )
    p.add_argument(
        "-i",
        "--iface",
        help="Interface to sniff on (e.g. eth0, ens33). If omitted, Scapy's default is used.",
        default=None,
    )
    return p.parse_args()


def is_interesting_l2(pkt):
    if Ether not in pkt:
        return False
    dst = pkt[Ether].dst.lower()
    if dst == BROADCAST_MAC:
        return True
    if dst in MULTICAST_MAC_LABELS:
        return True
    return False


def get_proto_label(pkt):
    try:
        if ARP in pkt:
            return "ARP"
        if DHCP in pkt or BOOTP in pkt:
            return "DHCP"

        eth = pkt[Ether]
        dst = eth.dst.lower()

        if dst == "01:00:0c:cc:cc:cc":
            return "CDP"
        if eth.type == 0x88CC:
            return "LLDP"
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


# ---------- CDP DECODER (custom, no Scapy dependency) ----------

CDP_TLV_TYPES = {
    0x0001: "device_id",
    0x0002: "addresses",
    0x0003: "port_id",
    0x0004: "capabilities",
    0x0005: "software_version",
    0x0006: "platform",
    0x0007: "ip_prefix",      # rarely used
    0x0009: "vtp_domain",
    0x000a: "native_vlan",
    0x000b: "duplex",
    0x0010: "trust_bitmap",
    0x0011: "untrusted_port_cos",
}


CDP_CAP_BITS = {
    0x00000001: "Router",
    0x00000002: "Transparent-Bridge",
    0x00000004: "Source-Route-Bridge",
    0x00000008: "Switch",
    0x00000010: "Host",
    0x00000020: "IGMP",
    0x00000040: "Repeater",
}


def _decode_cdp_caps(val_bytes):
    if len(val_bytes) < 4:
        return None, None
    bm = struct.unpack("!I", val_bytes[:4])[0]
    caps = [name for bit, name in CDP_CAP_BITS.items() if bm & bit]
    return bm, caps


def _decode_cdp_addresses(val_bytes):
    """
    Decode CDP Addresses TLV (type 0x0002).
    Returns list of textual addresses (mostly IPv4).
    """
    addrs = []
    if len(val_bytes) < 4:
        return addrs
    try:
        num_addrs = struct.unpack("!I", val_bytes[:4])[0]
        idx = 4
        for _ in range(num_addrs):
            if idx + 2 > len(val_bytes):
                break
            pt = val_bytes[idx]
            pl = val_bytes[idx + 1]
            idx += 2
            if idx + pl > len(val_bytes):
                break
            proto = val_bytes[idx:idx + pl]
            idx += pl
            if idx + 2 > len(val_bytes):
                break
            addr_len = struct.unpack("!H", val_bytes[idx:idx + 2])[0]
            idx += 2
            if idx + addr_len > len(val_bytes):
                break
            addr_bytes = val_bytes[idx:idx + addr_len]
            idx += addr_len

            # Heuristic: IPv4 addresses are 4 bytes
            if addr_len == 4:
                addrs.append(".".join(str(b) for b in addr_bytes))
            else:
                addrs.append(addr_bytes.hex())
        return addrs
    except Exception:
        return addrs


def _find_cdp_payload_bytes(pkt):
    """
    Try to locate the start of the CDP header in the payload bytes.
    Handles both Ethernet II (type 0x2000) and 802.3 LLC/SNAP.
    Returns bytes or None.
    """
    if Ether not in pkt:
        return None
    eth = pkt[Ether]

    # Ethernet II: type 0x2000 means CDP directly
    if getattr(eth, "type", None) == 0x2000:
        return bytes(eth.payload)

    # 802.3 LLC/SNAP with OUI 0x00000c and PID 0x2000:
    # AA AA 03 00 00 0C 20 00
    raw = bytes(eth.payload)
    sig = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    idx = raw.find(sig)
    if idx != -1 and idx + len(sig) < len(raw):
        return raw[idx + len(sig):]

    # Fallback: treat entire payload as CDP, may or may not work
    return raw if raw else None


def decode_cdp(pkt):
    """
    Decode CDP from raw bytes.
    Returns a dict with as many fields as possible.
    """
    payload = _find_cdp_payload_bytes(pkt)
    if not payload or len(payload) < 4:
        return None

    info = {
        "version": payload[0],
        "ttl": payload[1],
        "checksum": struct.unpack("!H", payload[2:4])[0],
        "device_id": None,
        "port_id": None,
        "platform": None,
        "software_version": None,
        "native_vlan": None,
        "duplex": None,
        "vtp_domain": None,
        "capabilities_raw": None,
        "capabilities_list": None,
        "mgmt_ips": [],
        "raw_tlvs": [],
    }

    offset = 4
    while offset + 4 <= len(payload):
        try:
            tlv_type, tlv_len = struct.unpack("!HH", payload[offset:offset + 4])
        except struct.error:
            break
        if tlv_len < 4 or offset + tlv_len > len(payload):
            break
        val = payload[offset + 4:offset + tlv_len]
        offset += tlv_len

        name = CDP_TLV_TYPES.get(tlv_type, f"0x{tlv_type:04x}")
        info["raw_tlvs"].append(
            {"type": tlv_type, "name": name, "length": tlv_len - 4, "value_raw": val}
        )

        if tlv_type == 0x0001:  # device ID
            try:
                info["device_id"] = val.decode(errors="ignore").strip()
            except Exception:
                pass

        elif tlv_type == 0x0003:  # port ID
            try:
                info["port_id"] = val.decode(errors="ignore").strip()
            except Exception:
                pass

        elif tlv_type == 0x0006:  # platform
            try:
                info["platform"] = val.decode(errors="ignore").strip()
            except Exception:
                pass

        elif tlv_type == 0x0005:  # software version
            try:
                info["software_version"] = val.decode(errors="ignore").strip()
            except Exception:
                pass

        elif tlv_type == 0x000a and len(val) >= 2:  # native VLAN
            info["native_vlan"] = struct.unpack("!H", val[:2])[0]

        elif tlv_type == 0x000b and len(val) >= 1:  # duplex
            mode = val[0]
            if mode == 0:
                info["duplex"] = "half"
            elif mode == 1:
                info["duplex"] = "full"
            else:
                info["duplex"] = f"unknown({mode})"

        elif tlv_type == 0x0009:  # VTP domain
            try:
                info["vtp_domain"] = val.decode(errors="ignore").strip()
            except Exception:
                pass

        elif tlv_type == 0x0004:  # capabilities
            bm, caps = _decode_cdp_caps(val)
            info["capabilities_raw"] = bm
            info["capabilities_list"] = caps

        elif tlv_type == 0x0002:  # addresses
            addrs = _decode_cdp_addresses(val)
            info["mgmt_ips"].extend(addrs)

        # Other TLVs are left in raw_tlvs with hex data

    return info


# ---------- OUTPUT HELPERS ----------

def generic_info(pkt, proto_label):
    return proto_label + "[" + pkt.summary() + "]"


def build_info(pkt, proto_label):
    if proto_label == "DHCP":
        return dhcp_info(pkt)
    if proto_label == "ARP":
        return arp_info(pkt)
    return generic_info(pkt, proto_label)


def print_cdp_block(ts, pkt, src_mac, src_ip, dst_mac):
    cdp = decode_cdp(pkt)
    if not cdp:
        print(
            f"{ts}  CDP      {src_mac:<17}  {src_ip:<15} -> {dst_mac:<17}  (unable to decode CDP)"
        )
        return

    print("=" * 80)
    print(f"{ts}  CDP FRAME  {src_mac} ({src_ip or 'no-ip'}) -> {dst_mac}")
    print("-" * 80)
    print(f"  Version        : {cdp['version']}")
    print(f"  TTL            : {cdp['ttl']} s")
    print(f"  Checksum       : 0x{cdp['checksum']:04x}")

    if cdp["device_id"]:
        print(f"  Device ID      : {cdp['device_id']}")
    if cdp["port_id"]:
        print(f"  Port ID        : {cdp['port_id']}")
    if cdp["platform"]:
        print(f"  Platform       : {cdp['platform']}")
    if cdp["software_version"]:
        print("  SW Version     :")
        for line in cdp["software_version"].splitlines():
            print(f"    {line}")

    if cdp["native_vlan"] is not None:
        print(f"  Native VLAN    : {cdp['native_vlan']}")

    if cdp["duplex"]:
        print(f"  Duplex         : {cdp['duplex']}")

    if cdp["vtp_domain"]:
        print(f"  VTP Domain     : {cdp['vtp_domain']}")

    if cdp["capabilities_raw"] is not None:
        print(f"  Capabilities   : 0x{cdp['capabilities_raw']:08x}")
        if cdp["capabilities_list"]:
            print(f"    Decoded      : {', '.join(cdp['capabilities_list'])}")

    if cdp["mgmt_ips"]:
        print(f"  Mgmt IP(s)     : {', '.join(cdp['mgmt_ips'])}")

    if cdp["raw_tlvs"]:
        print("  Raw TLVs       :")
        for tlv in cdp["raw_tlvs"]:
            tname = tlv["name"]
            ttype = tlv["type"]
            v = tlv["value_raw"]
            # show a short hex preview per TLV
            preview = v.hex()
            if len(preview) > 32:
                preview = preview[:32] + "..."
            print(f"    type=0x{ttype:04x} ({tname}), len={tlv['length']}: {preview}")

    print("=" * 80)


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

        if proto == "CDP":
            print_cdp_block(ts, pkt, src_mac, src_ip, dst_mac)
            return

        info = build_info(pkt, proto)
        print(
            f"{ts}  {proto:<7}  {src_mac:<17}  {src_ip:<15} -> {dst_mac:<17}  {info}"
        )

    except Exception:
        # Keep sniffer running even if a single packet blows up
        pass


def main():
    args = parse_args()

    print(
        "Listening for L2 broadcast / discovery traffic "
        f"on interface: {args.iface or 'DEFAULT'}"
    )
    print("Non-CDP Columns: TIME  PROTO  SRC_MAC  SRC_IP  ->  DST_MAC  INFO")
    print("-" * 100)

    sniff(
        iface=args.iface,
        store=False,
        prn=packet_handler,
    )


if __name__ == "__main__":
    main()
