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
import argparse
import struct
from datetime import datetime

from scapy.all import (
    sniff,
    Ether,
    ARP,
    DHCP,
    BOOTP,
    IP,
    UDP,
)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MULTICAST_MAC_LABELS = {
    "01:00:0c:cc:cc:cc": "CDP",
    "01:80:c2:00:00:00": "STP",
    "01:80:c2:00:00:0e": "LLDP",
    "01:00:5e:00:00:01": "IGMP",
    "33:33:00:00:00:01": "IPV6-MCAST",
}

CAPWAP_PORTS = {5246, 5247}  # control, data
LLDP_ETHERTYPE = 0x88CC
CDP_ETHERTYPE = 0x2000

# Fortinet OUI used in org-specific LLDP TLVs
FORTINET_OUI = b"\x00\x09\x0f"


def parse_args():
    p = argparse.ArgumentParser(
        description="Listen for L2 broadcast / discovery traffic "
                    "(DHCP, ARP, CDP, LLDP/FDP, CAPWAP, etc.)"
    )
    p.add_argument(
        "-i",
        "--iface",
        help="Interface to sniff on (e.g. eth0, ens33). If omitted, Scapy's default is used.",
        default=None,
    )
    return p.parse_args()


def is_capwap(pkt):
    return UDP in pkt and (
        pkt[UDP].sport in CAPWAP_PORTS or pkt[UDP].dport in CAPWAP_PORTS
    )


def is_interesting_l2(pkt):
    if Ether not in pkt:
        return False
    eth = pkt[Ether]
    dst = eth.dst.lower()

    # L2 broadcast or known multicast MAC
    if dst == BROADCAST_MAC or dst in MULTICAST_MAC_LABELS:
        return True

    # CAPWAP detection
    if is_capwap(pkt):
        return True

    # IPv4/IPv6 multicast detection for protocols like HSRP, VRRP, mDNS, SSDP
    if IP in pkt:
        ip = pkt[IP]
        if ip.dst.startswith("224.") or ip.dst.startswith("239."):
            return True
    if pkt.haslayer("IPv6"):
        ipv6 = pkt["IPv6"]
        if ipv6.dst.startswith("ff02") or ipv6.dst.startswith("ff05"):
            return True

    # UDP-based discovery protocols
    if UDP in pkt:
        if pkt[UDP].dport in {5353, 137, 1900}:  # mDNS, NBNS, SSDP
            return True

    # HSRP (IP protocol 112), VRRP (IP protocol 112)
    if IP in pkt and pkt[IP].proto == 112:
        return True

    return False


def get_proto_label(pkt):
    try:
        if ARP in pkt:
            return "ARP"
        if DHCP in pkt or BOOTP in pkt:
            return "DHCP"
        if is_capwap(pkt):
            return "CAPWAP"
        eth = pkt[Ether]
        dst = eth.dst.lower()

        # CDP / LLDP
        if getattr(eth, "type", None) == CDP_ETHERTYPE or dst == "01:00:0c:cc:cc:cc":
            return "CDP"
        if getattr(eth, "type", None) == LLDP_ETHERTYPE:
            return "LLDP"

        # IPv4/IPv6 multicast-based protocols
        if IP in pkt:
            ip = pkt[IP]
            if ip.dst.startswith("224.") or ip.dst.startswith("239."):
                if UDP in pkt:
                    if pkt[UDP].dport == 5353:
                        return "mDNS"
                    if pkt[UDP].dport == 137:
                        return "NBNS"
                    if pkt[UDP].dport == 1900:
                        return "SSDP"
                if ip.proto == 112:
                    return "HSRP/VRRP"
        if pkt.haslayer("IPv6"):
            return "IPv6-MCAST"

        if dst == BROADCAST_MAC:
            return "BCAST"
        if dst in MULTICAST_MAC_LABELS:
            return MULTICAST_MAC_LABELS[dst]

        return "OTHER"
    except Exception:
        return "UNK"


def mdns_info(pkt):
    return "mDNS Query" if UDP in pkt else "mDNS"

def nbns_info(pkt):
    return "NBNS Query" if UDP in pkt else "NBNS"

def ssdp_info(pkt):
    return "SSDP Discovery" if UDP in pkt else "SSDP"

def hsrp_vrrp_info(pkt):
    return "HSRP/VRRP Hello"

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


# ---------------- CDP DECODER ----------------

CDP_TLV_TYPES = {
    0x0001: "device_id",
    0x0002: "addresses",
    0x0003: "port_id",
    0x0004: "capabilities",
    0x0005: "software_version",
    0x0006: "platform",
    0x0007: "ip_prefix",
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

            if addr_len == 4:
                addrs.append(".".join(str(b) for b in addr_bytes))
            else:
                addrs.append(addr_bytes.hex())
        return addrs
    except Exception:
        return addrs


def _find_cdp_payload_bytes(pkt):
    if Ether not in pkt:
        return None
    eth = pkt[Ether]

    if getattr(eth, "type", None) == CDP_ETHERTYPE:
        return bytes(eth.payload)

    raw = bytes(eth.payload)
    sig = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"  # LLC/SNAP Cisco
    idx = raw.find(sig)
    if idx != -1 and idx + len(sig) < len(raw):
        return raw[idx + len(sig):]

    return raw if raw else None


def decode_cdp(pkt):
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

        if tlv_type == 0x0001:
            try:
                info["device_id"] = val.decode(errors="ignore").strip()
            except Exception:
                pass
        elif tlv_type == 0x0003:
            try:
                info["port_id"] = val.decode(errors="ignore").strip()
            except Exception:
                pass
        elif tlv_type == 0x0006:
            try:
                info["platform"] = val.decode(errors="ignore").strip()
            except Exception:
                pass
        elif tlv_type == 0x0005:
            try:
                info["software_version"] = val.decode(errors="ignore").strip()
            except Exception:
                pass
        elif tlv_type == 0x000a and len(val) >= 2:
            info["native_vlan"] = struct.unpack("!H", val[:2])[0]
        elif tlv_type == 0x000b and len(val) >= 1:
            mode = val[0]
            if mode == 0:
                info["duplex"] = "half"
            elif mode == 1:
                info["duplex"] = "full"
            else:
                info["duplex"] = f"unknown({mode})"
        elif tlv_type == 0x0009:
            try:
                info["vtp_domain"] = val.decode(errors="ignore").strip()
            except Exception:
                pass
        elif tlv_type == 0x0004:
            bm, caps = _decode_cdp_caps(val)
            info["capabilities_raw"] = bm
            info["capabilities_list"] = caps
        elif tlv_type == 0x0002:
            addrs = _decode_cdp_addresses(val)
            info["mgmt_ips"].extend(addrs)

    return info


# ---------------- LLDP + FDP DECODER ----------------

def _find_lldp_payload_bytes(pkt):
    if Ether not in pkt:
        return None
    eth = pkt[Ether]
    if getattr(eth, "type", None) == LLDP_ETHERTYPE:
        return bytes(eth.payload)
    raw = bytes(eth.payload)
    return raw if raw else None


def decode_lldp(pkt):
    payload = _find_lldp_payload_bytes(pkt)
    if not payload or len(payload) < 4:
        return None

    info = {
        "chassis_id": None,
        "chassis_id_subtype": None,
        "port_id": None,
        "port_id_subtype": None,
        "ttl": None,
        "port_description": None,
        "system_name": None,
        "system_description": None,
        "system_caps_bits": None,
        "system_caps_enabled": None,
        "mgmt_addresses": [],
        "org_specific": [],       # generic org TLVs
        "fortinet_tlvs": [],      # LLDP org TLVs with Fortinet OUI
    }

    offset = 0
    while offset + 2 <= len(payload):
        try:
            tlv_header = struct.unpack("!H", payload[offset:offset + 2])[0]
        except struct.error:
            break
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_len = tlv_header & 0x1FF
        offset += 2

        if tlv_len == 0:
            break
        if offset + tlv_len > len(payload):
            break

        val = payload[offset:offset + tlv_len]
        offset += tlv_len

        if tlv_type == 0:  # End of LLDPDU
            break

        if tlv_type == 1:  # Chassis ID
            if len(val) >= 1:
                info["chassis_id_subtype"] = val[0]
                info["chassis_id"] = val[1:].decode(errors="ignore").strip()
        elif tlv_type == 2:  # Port ID
            if len(val) >= 1:
                info["port_id_subtype"] = val[0]
                info["port_id"] = val[1:].decode(errors="ignore").strip()
        elif tlv_type == 3:  # TTL
            if len(val) >= 2:
                info["ttl"] = struct.unpack("!H", val[:2])[0]
        elif tlv_type == 4:  # Port Description
            info["port_description"] = val.decode(errors="ignore").strip()
        elif tlv_type == 5:  # System Name
            info["system_name"] = val.decode(errors="ignore").strip()
        elif tlv_type == 6:  # System Description
            info["system_description"] = val.decode(errors="ignore").strip()
        elif tlv_type == 7:  # System Capabilities
            if len(val) >= 4:
                caps, caps_en = struct.unpack("!HH", val[:4])
                info["system_caps_bits"] = caps
                info["system_caps_enabled"] = caps_en
        elif tlv_type == 8:  # Management Address
            # very simplified parsing
            try:
                addr_len = val[0]
                if addr_len > 0 and 1 + addr_len <= len(val):
                    addr_subtype = val[1]  # usually 1=IPv4, 2=IPv6
                    addr_bytes = val[2:1 + addr_len]
                    if addr_subtype == 1 and len(addr_bytes) == 4:
                        ip = ".".join(str(b) for b in addr_bytes)
                        info["mgmt_addresses"].append(ip)
                    elif addr_subtype == 2 and len(addr_bytes) == 16:
                        # Simplified IPv6, hex
                        info["mgmt_addresses"].append(addr_bytes.hex())
            except Exception:
                pass
        elif tlv_type == 127:  # Org-specific -> FDP data may live here
            if len(val) >= 3:
                oui = val[0:3]
                subtype = val[3] if len(val) >= 4 else None
                data = val[4:] if len(val) > 4 else b""
                entry = {
                    "oui": oui,
                    "subtype": subtype,
                    "data": data,
                }
                info["org_specific"].append(entry)

                if oui == FORTINET_OUI:
                    info["fortinet_tlvs"].append(entry)

        # Other TLV types ignored but could be displayed via raw parsing

    return info


# ---------------- CAPWAP "decoder" (light) ----------------

def capwap_info(pkt):
    udp = pkt[UDP]
    role = "control" if udp.dport == 5246 or udp.sport == 5246 else \
           "data" if udp.dport == 5247 or udp.sport == 5247 else "unknown"
    length = len(bytes(udp.payload))
    preview = bytes(udp.payload)[:16].hex()
    if length > 16:
        preview += "..."
    return role, length, preview


# ---------------- OUTPUT HELPERS ----------------

def generic_info(pkt, proto_label):
    return proto_label + "[" + pkt.summary() + "]"


def build_info(pkt, proto_label):
    if proto_label == "DHCP":
        return dhcp_info(pkt)
    if proto_label == "ARP":
        return arp_info(pkt)
    if proto_label == "CAPWAP":
        role, length, preview = capwap_info(pkt)
        return f"CAPWAP[{role}, {length} bytes, {preview}]"
    if proto_label == "mDNS":
        return mdns_info(pkt)
    if proto_label == "NBNS":
        return nbns_info(pkt)
    if proto_label == "SSDP":
        return ssdp_info(pkt)
    if proto_label == "HSRP/VRRP":
        return hsrp_vrrp_info(pkt)
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
            preview = v.hex()
            if len(preview) > 32:
                preview = preview[:32] + "..."
            print(f"    type=0x{ttype:04x} ({tname}), len={tlv['length']}: {preview}")

    print("=" * 80)


def print_lldp_block(ts, pkt, src_mac, src_ip, dst_mac):
    lldp = decode_lldp(pkt)
    if not lldp:
        print(
            f"{ts}  LLDP     {src_mac:<17}  {src_ip:<15} -> {dst_mac:<17}  (unable to decode LLDP)"
        )
        return

    is_fortinet = len(lldp["fortinet_tlvs"]) > 0

    header_label = "LLDP FRAME"
    if is_fortinet:
        header_label = "LLDP/FDP (Fortinet) FRAME"

    print("=" * 80)
    print(f"{ts}  {header_label}  {src_mac} ({src_ip or 'no-ip'}) -> {dst_mac}")
    print("-" * 80)

    if lldp["chassis_id"]:
        print(f"  Chassis ID     : {lldp['chassis_id']}")
    if lldp["port_id"]:
        print(f"  Port ID        : {lldp['port_id']}")
    if lldp["ttl"] is not None:
        print(f"  TTL            : {lldp['ttl']} s")

    if lldp["port_description"]:
        print(f"  Port Desc      : {lldp['port_description']}")
    if lldp["system_name"]:
        print(f"  System Name    : {lldp['system_name']}")
    if lldp["system_description"]:
        print("  System Desc    :")
        for line in lldp["system_description"].splitlines():
            print(f"    {line}")

    if lldp["system_caps_bits"] is not None:
        print(f"  Sys Caps Bits  : 0x{lldp['system_caps_bits']:04x}")
    if lldp["system_caps_enabled"] is not None:
        print(f"  Sys Caps En    : 0x{lldp['system_caps_enabled']:04x}")

    if lldp["mgmt_addresses"]:
        print(f"  Mgmt Addr(s)   : {', '.join(lldp['mgmt_addresses'])}")

    if is_fortinet:
        print("  Fortinet (FDP-related) Org TLVs:")
        for idx, tlv in enumerate(lldp["fortinet_tlvs"], start=1):
            subtype = tlv["subtype"]
            data_hex = tlv["data"].hex()
            if len(data_hex) > 48:
                data_hex = data_hex[:48] + "..."
            print(f"    [{idx}] subtype={subtype}, data={data_hex}")

    if lldp["org_specific"]:
        print("  Other Org TLVs :")
        for idx, tlv in enumerate(lldp["org_specific"], start=1):
            if tlv in lldp["fortinet_tlvs"]:
                continue
            oui = ":".join(f"{b:02x}" for b in tlv["oui"])
            subtype = tlv["subtype"]
            data_hex = tlv["data"].hex()
            if len(data_hex) > 48:
                data_hex = data_hex[:48] + "..."
            print(f"    [{idx}] OUI={oui}, subtype={subtype}, data={data_hex}")

    print("=" * 80)


def print_capwap_block(ts, pkt, src_mac, src_ip, dst_mac):
    role, length, preview = capwap_info(pkt)
    dst_ip = pkt[IP].dst if IP in pkt else ""
    src_ip = src_ip or (pkt[IP].src if IP in pkt else "")

    print("=" * 80)
    print(f"{ts}  CAPWAP {role.upper()}  {src_mac} ({src_ip or 'no-ip'}) -> "
          f"{dst_mac} ({dst_ip or 'no-ip'})")
    print("-" * 80)
    print(f"  Payload length : {length} bytes")
    print(f"  Hex preview    : {preview}")
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

        # Detailed blocks for CDP, LLDP, CAPWAP
        if proto == "CDP":
            print_cdp_block(ts, pkt, src_mac, src_ip, dst_mac)
            return
        if proto == "LLDP":
            print_lldp_block(ts, pkt, src_mac, src_ip, dst_mac)
            return
        if proto == "CAPWAP":
            print_capwap_block(ts, pkt, src_mac, src_ip, dst_mac)
            return

        # Generic or new protocols
        info = build_info(pkt, proto)
        print(
            f"{ts} {proto:<10} {src_mac:<17} {src_ip:<15} -> {dst_mac:<17} {info}"
        )
    except Exception:
        # Keep sniffer running on individual packet errors
        pass


def main():
    args = parse_args()
    print(
        "Listening for L2 broadcast / discovery traffic "
        f"on interface: {args.iface or 'DEFAULT'}"
    )
    print("Non-block protocols: TIME PROTO SRC_MAC SRC_IP -> DST_MAC INFO")
    print("-" * 100)

    sniff(
        iface=args.iface,
        store=False,
        prn=packet_handler,
        filter=(
            "ether broadcast or ether multicast "
            "or udp port 5353 or udp port 137 or udp port 1900 "
            "or udp port 5246 or udp port 5247 or ip proto 112"
        )
    )

if __name__ == "__main__":
    main()
