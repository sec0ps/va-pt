#!/usr/bin/env python3
# passive_targeting.py
#
# Strictly passive internal target discovery.
#
# Purpose:
#   Watch whatever traffic the tester's interface can already see (broadcast,
#   multicast, or unicast that reaches the NIC). Every source address that has
#   not been catalogued before is logged as a candidate target. Where the
#   observed traffic carries enough evidence, the size of that source's
#   network is inferred as a CIDR so the subnet itself becomes a target for
#   internal testing.
#
#   This builds the target list that nmap/masscan assume you already have. It
#   never transmits: no sweeps, no probes, no host discovery traffic. The live
#   path and the offline pcap path run identical logic.
#
# On execution:
#   - Enumerates interfaces, filters to RFC1918-addressed ones
#   - Auto-selects if only one; prompts for choice if multiple
#   - Seeds the local subnet(s) as confirmed targets
#   - Runs the passive sniffer only
#   - Streams newly seen hosts to targets.txt and inferred subnets to subnets.txt
#   - Writes a timestamped run log
#   - Optional stdlib curses TUI: banner + live counts on top, new targets on
#     the left, running log on the right; ctrl+a opens a paste box to feed a
#     captured routing table or target list
#
# Usage:
#   sudo python3 passive_targeting.py                 # full auto (curses TUI if a tty)
#   sudo python3 passive_targeting.py --no-tui        # plain line-log mode
#   sudo python3 passive_targeting.py --scope 10.0.0.0/8 --exclude 10.0.5.0/24
#   python3 passive_targeting.py analyze cap.pcap     # offline pcap, no root needed
#
# Requires root for live capture (raw socket). The TUI uses only the stdlib.

import argparse
import fcntl
import json
import logging
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network

from scapy.all import (
    AsyncSniffer, rdpcap,
    conf as scapy_conf, load_contrib,
    Ether, Dot1Q, ARP, IP, TCP, UDP, DHCP, DNS,
)

# Suppress scapy's MAC-resolution warnings and verbose output.
scapy_conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

_CAPS = {}
for _m in ("cdp", "lldp", "ospf", "eigrp", "hsrp", "vrrp"):
    try:
        load_contrib(_m)
        _CAPS[_m] = True
    except Exception:
        _CAPS[_m] = False

try:
    from scapy.contrib.cdp import (
        CDPMsgDeviceID, CDPMsgAddr, CDPMsgMgmtAddr, CDPMsgIPPrefix,
    )
except Exception:
    _CAPS["cdp"] = False
try:
    from scapy.contrib.lldp import LLDPDUManagementAddress, LLDPDUSystemName
except Exception:
    _CAPS["lldp"] = False
try:
    from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LSUpd
except Exception:
    _CAPS["ospf"] = False
try:
    from scapy.contrib.eigrp import EIGRP, EIGRPIntRoute, EIGRPExtRoute
except Exception:
    _CAPS["eigrp"] = False
try:
    from scapy.all import HSRP
except Exception:
    _CAPS["hsrp"] = False
try:
    from scapy.all import VRRP, VRRPv3
except Exception:
    _CAPS["vrrp"] = False

from scapy.layers.netbios import (
    NBNSHeader, NBNSNodeStatusResponse, NBTDatagram,
)
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.inet6 import (
    IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptPrefixInfo,
)
try:
    from scapy.layers.inet6 import ICMPv6MLReport, ICMPv6MLReport2
    _CAPS["mld"] = True
except Exception:
    ICMPv6MLReport = ICMPv6MLReport2 = None
    _CAPS["mld"] = False
try:
    from scapy.contrib.igmp import IGMP
    _CAPS["igmp"] = True
except Exception:
    try:
        from scapy.layers.inet import IGMP
        _CAPS["igmp"] = True
    except Exception:
        IGMP = None
        _CAPS["igmp"] = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONF_CONFIRMED    = 3   # seen sourcing/receiving traffic or named by a protocol
CONF_ROUTED       = 2   # subnet learned from a routing/control protocol
CONF_EXTRAPOLATED = 1   # adjacency or /24 floor, no direct observation

CONF_NAME = {3: "confirmed", 2: "routed", 1: "extrapolated"}

DEFAULT_FLOOR    = 24   # assumed prefix when nothing else resolves
MIN_INFER_PREFIX = 16   # never widen an inferred subnet past /16 without proof

# Protocols dissected unconditionally. These ride on base scapy layers that are
# always importable, so unlike the _CAPS contrib decoders they cannot fail to
# load and are not gated in dispatch. Listed in the banner for an honest
# coverage inventory.
ALWAYS_ON_PROTOS = (
    "arp", "dhcp", "dns", "mdns", "llmnr",
    "nbns", "nbtds", "dhcp6", "ipv6-nd",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_rfc1918(addr):
    try:
        ip = ip_address(addr)
    except ValueError:
        return False
    if not isinstance(ip, IPv4Address):
        return ip.is_private and not ip.is_link_local and not ip.is_loopback
    return ip.is_private and not ip.is_loopback


def norm_mac(mac):
    if not mac:
        return ""
    return mac.lower().replace(":", "").replace("-", "").replace(".", "")


def is_unicast_mac(mac):
    n = norm_mac(mac)
    if len(n) < 2 or n == "ffffffffffff":
        return False
    return (int(n[0:2], 16) & 0x01) == 0

# ---------------------------------------------------------------------------
# Route / target list parsing (manual scope expansion)
# ---------------------------------------------------------------------------

_QUAD       = r"\d{1,3}(?:\.\d{1,3}){3}"
_CIDR_RE    = re.compile(r"\b(%s)/(\d{1,2})\b" % _QUAD)
_VIA_RE     = re.compile(r"via\s+(%s)" % _QUAD, re.I)
_TRIPLE_RE  = re.compile(r"\b(%s)\s+(%s)\s+(%s)\b" % (_QUAD, _QUAD, _QUAD))
_PAIR_RE    = re.compile(r"\b(%s)\s+(%s)\b" % (_QUAD, _QUAD))
_BAREIP_RE  = re.compile(r"\b(%s)\b" % _QUAD)


def _mask_to_prefix(mask):
    """Return prefix length for a contiguous netmask, or None."""
    try:
        return IPv4Network("0.0.0.0/%s" % mask).prefixlen
    except (ValueError, Exception):
        return None


def _is_netmask(s):
    """True only for a contiguous IPv4 netmask (1*0*), excluding 0.0.0.0."""
    try:
        n = int(IPv4Address(s))
    except (ValueError, Exception):
        return False
    if n == 0:
        return False
    inv = n ^ 0xffffffff          # zeros become ones
    return ((inv + 1) & inv) == 0  # inv must be all-ones suffix


def parse_routes(text):
    """Parse pasted routing tables or target lists from any common source
    (ip route, route -n, netstat -rn, Windows route print, Cisco show ip route,
    or a plain list of IPs/CIDRs). Returns (subnets, gateways, hosts) as
    deduplicated, validated lists of strings."""
    subnets, gateways, hosts = set(), set(), set()
    consumed = set()  # quads already accounted for as net/mask/gateway

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        for g in _VIA_RE.findall(line):
            if g != "0.0.0.0":
                gateways.add(g)
                consumed.add(g)

        for net, plen in _CIDR_RE.findall(line):
            try:
                if int(plen) == 0:
                    continue
                cidr = str(ip_network("%s/%s" % (net, plen), strict=False))
                subnets.add(cidr)
                consumed.add(net)
            except ValueError:
                pass

        used_pair = False
        onlink = bool(re.search(r"on.?link|directly connected", line, re.I))
        for a, b, c in _TRIPLE_RE.findall(line):
            if a == "0.0.0.0":                      # default route row
                for q in (b, c):
                    if q != "0.0.0.0" and not _is_netmask(q):
                        gateways.add(q)
                consumed.update((a, b, c))
                used_pair = True
                continue
            if _is_netmask(b) and not _is_netmask(a):
                dst, mask, gw = a, b, c              # dest mask gw (Windows/Cisco)
            elif _is_netmask(c):
                dst, mask, gw = a, c, b              # dest gw mask (Linux route -n)
            else:
                continue
            pl = _mask_to_prefix(mask)
            if pl is None:
                continue
            if pl != 0:
                try:
                    subnets.add(str(ip_network("%s/%d" % (dst, pl), strict=False)))
                except ValueError:
                    pass
            if gw != "0.0.0.0" and not _is_netmask(gw) and not onlink:
                gateways.add(gw)
            consumed.update((a, b, c))
            used_pair = True

        if not used_pair:
            for dst, mask in _PAIR_RE.findall(line):
                if not _is_netmask(mask):
                    continue
                pl = _mask_to_prefix(mask)
                if pl is None or dst == "0.0.0.0":
                    continue
                try:
                    subnets.add(str(ip_network("%s/%d" % (dst, pl), strict=False)))
                except ValueError:
                    pass
                consumed.update((dst, mask))

        for ip in _BAREIP_RE.findall(line):
            if ip in consumed or ip in gateways or _is_netmask(ip):
                continue
            if ip in ("0.0.0.0", "255.255.255.255"):
                continue
            net_addrs = {c.split("/")[0] for c in subnets}
            if ip in net_addrs:
                continue
            try:
                if ip_address(ip).is_multicast:
                    continue
            except ValueError:
                continue
            hosts.add(ip)

    return sorted(subnets), sorted(gateways), sorted(hosts)


def apply_parsed(kb, subnets, gateways, hosts, source="manual"):
    """Feed parsed routing data into the knowledge base. Subnets and hosts
    inherit the standard RFC1918 and scope guards via the KB."""
    for gw in gateways:
        kb.note_gateway(ip=gw, source=source)
    for cidr in subnets:
        kb.add_subnet(cidr, CONF_ROUTED, source, "manual")
    added = 0
    for ip in hosts:
        if kb.observe_host(ip, source=source) is not None:
            added += 1
    kb.log.write("MANUAL adds: subnets=%d gateways=%d hosts=%d (%s)" % (
        len(subnets), len(gateways), len(hosts), source))
    return len(subnets), len(gateways), added

# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

class Scope:
    """Optional allow/deny CIDR gating. Empty allow means allow-all."""

    def __init__(self, allow=None, deny=None):
        self.allow = [ip_network(c, strict=False) for c in (allow or [])]
        self.deny  = [ip_network(c, strict=False) for c in (deny or [])]

    def contains(self, ip):
        try:
            a = ip_address(ip)
        except ValueError:
            return False
        if any(a in d for d in self.deny):
            return False
        if not self.allow:
            return True
        return any(a in n for n in self.allow)

# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

def _get_iface_netmask(iface):
    """IPv4 netmask via ioctl (Linux only)."""
    SIOCGIFNETMASK = 0x891b
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK,
                          struct.pack("256s", iface[:15].encode()))
        s.close()
        return socket.inet_ntoa(raw[20:24])
    except OSError:
        return None


def discover_rfc1918_ifaces():
    """Return list of (iface_name, ip_str, local_cidr_str) for RFC1918 interfaces."""
    seen = set()
    result = []
    for name, iface in scapy_conf.ifaces.items():
        ip = iface.ip
        if not ip or ip == "0.0.0.0" or not is_rfc1918(ip):
            continue
        if name in seen:
            continue
        seen.add(name)
        mask = _get_iface_netmask(name)
        if mask:
            try:
                pl   = IPv4Network("0.0.0.0/%s" % mask).prefixlen
                cidr = str(ip_network("%s/%d" % (ip, pl), strict=False))
            except ValueError:
                cidr = ip + "/24"
        else:
            cidr = ip + "/24"
        result.append((name, ip, cidr))
    return result


def select_interfaces(ifaces):
    """Return selected subset of ifaces. Auto-selects if only one.
    Prompts with numbered list if multiple; accepts comma/space-separated
    indices or 'all'. Defaults to first entry on blank input."""
    if not ifaces:
        return []
    if len(ifaces) == 1:
        name, ip, cidr = ifaces[0]
        print("[*] Interface: %s  %s  (%s)" % (name, ip, cidr))
        return ifaces

    print("\n[*] Multiple RFC1918 interfaces found:\n")
    for i, (name, ip, cidr) in enumerate(ifaces, 1):
        print("    [%d]  %-14s  %-18s  %s" % (i, name, ip, cidr))
    print()

    if not sys.stdin.isatty():
        print("[*] Non-interactive: selecting [1] %s" % ifaces[0][0])
        return [ifaces[0]]

    while True:
        try:
            raw = input("Select interface(s) (e.g. 1  or  1,2  or  all) [1]: ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        if not raw:
            raw = "1"
        if raw.lower() == "all":
            return ifaces
        try:
            indices  = [int(x.strip()) for x in raw.replace(",", " ").split()]
            selected = [ifaces[i - 1] for i in indices if 1 <= i <= len(ifaces)]
            if selected:
                return selected
        except (ValueError, IndexError):
            pass
        print("    Enter numbers separated by commas or spaces, or 'all'.")

# ---------------------------------------------------------------------------
# Output handles
# ---------------------------------------------------------------------------

class RunLog:
    """Timestamped run log mirrored to stdout and/or a sink callback.
    Line-buffered for live tail. In TUI mode echo is disabled and the sink
    forwards lines to the log pane."""

    def __init__(self, path, echo=True, sink=None):
        self.path = path
        self.fh   = open(path, "a", buffering=1)
        self.lock = threading.Lock()
        self.echo = echo
        self.sink = sink
        self.last = ""

    def write(self, msg):
        line = "%s  %s" % (datetime.now().strftime("%H:%M:%S"), msg)
        with self.lock:
            self.fh.write(line + "\n")
            self.fh.flush()
            self.last = line
            if self.echo:
                print(line)
                sys.stdout.flush()
            if self.sink:
                try:
                    self.sink(line)
                except Exception:
                    pass

    def close(self):
        with self.lock:
            self.fh.close()


class TargetFeed:
    """Deduplicated, append-only host and subnet feeds. Flushed per write.
    Preloads existing files so re-running the same outdir does not duplicate.
    A new entry fires the optional sink callback (used by the TUI targets
    pane) outside the lock so the UI thread never blocks the writer."""

    def __init__(self, targets_path, subnets_path, targets6_path, sink=None):
        self.seen_hosts   = set()
        self.seen_subnets = set()
        self._preload(targets_path,  self.seen_hosts)
        self._preload(targets6_path, self.seen_hosts)
        self._preload(subnets_path,  self.seen_subnets)
        self.targets_fh  = open(targets_path,  "a", buffering=1)
        self.subnets_fh  = open(subnets_path,  "a", buffering=1)
        self.targets6_fh = open(targets6_path, "a", buffering=1)
        self.sink = sink
        self.lock = threading.Lock()

    @staticmethod
    def _preload(path, dest):
        if os.path.exists(path):
            with open(path) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln and not ln.startswith("#"):
                        dest.add(ln)

    def add_host(self, ip):
        with self.lock:
            if ip in self.seen_hosts:
                return False
            self.seen_hosts.add(ip)
            fh = self.targets6_fh if ":" in ip else self.targets_fh
            fh.write(ip + "\n")
            fh.flush()
            sink = self.sink
        if sink:
            try:
                sink(ip)
            except Exception:
                pass
        return True

    def add_subnet(self, cidr):
        with self.lock:
            if cidr in self.seen_subnets:
                return False
            self.seen_subnets.add(cidr)
            self.subnets_fh.write(cidr + "\n")
            self.subnets_fh.flush()
            sink = self.sink
        if sink:
            try:
                sink(cidr)
            except Exception:
                pass
        return True

    def close(self):
        for fh in (self.targets_fh, self.subnets_fh, self.targets6_fh):
            fh.close()


def open_outputs(outdir, echo=True):
    os.makedirs(outdir, exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    log = RunLog(os.path.join(outdir, "recon_%s.log" % ts), echo=echo)
    feed = TargetFeed(
        os.path.join(outdir, "targets.txt"),
        os.path.join(outdir, "subnets.txt"),
        os.path.join(outdir, "targets_v6.txt"),
    )
    return log, feed, ts

# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

@dataclass
class HostRecord:
    ip:         str
    mac:        str  = ""
    hostnames:  set  = field(default_factory=set)
    vlan:       int  = 0
    confidence: int  = CONF_CONFIRMED
    evidence:   set  = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)


@dataclass
class SubnetRecord:
    cidr:       str
    confidence: int
    source:     str
    mask_from:  str   = ""
    first_seen: float = field(default_factory=time.time)


class KnowledgeBase:
    def __init__(self, runlog, feed, scope=None):
        self.log          = runlog
        self.feed         = feed
        self.scope        = scope or Scope()
        self.lock         = threading.Lock()
        self.hosts        = {}                  # ip -> HostRecord
        self.mac_to_ip    = {}                  # norm_mac -> ip
        self.ip_to_mac    = {}                  # ip -> norm_mac
        self.subnets      = {}                  # cidr -> SubnetRecord
        self.gateway_macs = {}                  # norm_mac -> source
        self.gateway_ips  = set()
        self.onlink       = defaultdict(lambda: {"on": set(), "routed": set()})
        self.mac_dst_nets = defaultdict(set)
        self.host_mask    = {}                  # src_ip -> last inferred cidr

    def in_scope(self, ip):
        return self.scope.contains(ip)

    # ---- host / binding ----

    def observe_host(self, ip, mac="", source="passive", confidence=CONF_CONFIRMED):
        if not ip or ip in ("0.0.0.0", "255.255.255.255", "::"):
            return None
        with self.lock:
            rec = self.hosts.get(ip)
            if rec is None:
                rec = HostRecord(ip=ip, confidence=confidence)
                self.hosts[ip] = rec
            rec.last_seen = time.time()
            rec.evidence.add(source)
            if confidence > rec.confidence:
                rec.confidence = confidence
            if mac and is_unicast_mac(mac):
                rec.mac = mac
                self.mac_to_ip[norm_mac(mac)] = ip
                self.ip_to_mac[ip] = norm_mac(mac)
            new = ip not in self.feed.seen_hosts
        if new and is_rfc1918(ip) and self.in_scope(ip):
            if self.feed.add_host(ip):
                self.log.write("HOST  %-18s  mac=%-17s  via=%s" % (
                    ip, mac or "?", source))
        return rec

    def add_hostname(self, ip, name, source="passive"):
        rec = self.observe_host(ip, source=source)
        if rec and name:
            with self.lock:
                if name not in rec.hostnames:
                    rec.hostnames.add(name)
                    self.log.write("NAME  %-18s  %s  (%s)" % (ip, name, source))

    # ---- gateway ----

    def note_gateway(self, ip="", mac="", source="protocol"):
        with self.lock:
            changed = False
            if mac and norm_mac(mac) not in self.gateway_macs:
                self.gateway_macs[norm_mac(mac)] = source
                changed = True
            if ip and ip not in self.gateway_ips:
                self.gateway_ips.add(ip)
                changed = True
        if ip:
            self.observe_host(ip, mac=mac, source="gateway:" + source)
        if changed and (ip or mac):
            self.log.write("GW    %-18s  mac=%-17s  (%s)" % (
                ip or "?", mac or "?", source))

    # ---- subnet ----

    def add_subnet(self, cidr, confidence, source, mask_from=""):
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            return
        key = str(net)
        with self.lock:
            existing = self.subnets.get(key)
            if existing and existing.confidence >= confidence:
                return
            self.subnets[key] = SubnetRecord(key, confidence, source, mask_from)

        emit = False
        if isinstance(net, IPv4Network) and is_rfc1918(str(net.network_address)):
            emit = self.feed.add_subnet(key)
        elif net.version == 6:
            emit = self.feed.add_subnet(key)

        if emit:
            self.log.write("NET   %-24s  %-12s  mask=%-18s  (%s)" % (
                key, CONF_NAME[confidence], mask_from or "given", source))

    # ---- L2/L3 on-link correlation ----

    def correlate(self, src_ip, dst_ip, dst_mac):
        if not (is_rfc1918(src_ip) and is_rfc1918(dst_ip)):
            return
        if src_ip == dst_ip:
            return
        nmac   = norm_mac(dst_mac)
        bucket = self.onlink[src_ip]
        if nmac and nmac in self.gateway_macs:
            bucket["routed"].add(dst_ip)
        elif nmac and self.mac_to_ip.get(nmac) == dst_ip:
            bucket["on"].add(dst_ip)
        else:
            try:
                net24 = str(ip_network(dst_ip + "/24", strict=False))
                self.mac_dst_nets[nmac].add(net24)
                if len(self.mac_dst_nets[nmac]) >= 3 and nmac not in self.gateway_macs:
                    self.gateway_macs[nmac] = "behavior:multi-subnet"
                    gw_ip = self.mac_to_ip.get(nmac, "")
                    self.log.write("GW    %-18s  mac=%-17s  (behavior)" % (
                        gw_ip or "?", dst_mac))
            except ValueError:
                pass
        self._reinfer(src_ip)

    def _reinfer(self, src_ip):
        bucket = self.onlink.get(src_ip)
        if not bucket or not bucket["on"]:
            return
        on     = [ip_address(src_ip)] + [ip_address(x) for x in bucket["on"]]
        routed = [ip_address(x) for x in bucket["routed"]]

        narrow = 32
        for p in range(32, MIN_INFER_PREFIX - 1, -1):
            net = ip_network("%s/%d" % (src_ip, p), strict=False)
            if all(a in net for a in on):
                narrow = p
                break
        else:
            narrow = MIN_INFER_PREFIX

        wide = narrow
        for p in range(narrow - 1, MIN_INFER_PREFIX - 1, -1):
            net = ip_network("%s/%d" % (src_ip, p), strict=False)
            if any(r in net for r in routed):
                break
            wide = p

        pinned = bool(routed) and wide == narrow
        if pinned:
            prefix, mask_from, conf = narrow, "onlink+routed", CONF_ROUTED
        elif narrow < DEFAULT_FLOOR:
            prefix, mask_from, conf = (wide if routed else narrow), "onlink-span", CONF_ROUTED
        else:
            prefix, mask_from, conf = DEFAULT_FLOOR, "floor", CONF_EXTRAPOLATED

        cidr = str(ip_network("%s/%d" % (src_ip, prefix), strict=False))
        if self.host_mask.get(src_ip) != cidr:
            self.host_mask[src_ip] = cidr
            self.add_subnet(cidr, conf, "inference:%s" % src_ip, mask_from)

    # ---- extrapolation ----

    def extrapolate_adjacent(self):
        """Emit contained /24s for every confirmed subnet wider than /24."""
        with self.lock:
            confirmed = []
            for c, r in self.subnets.items():
                net = ip_network(c)
                if r.confidence >= CONF_ROUTED and net.version == 4:
                    confirmed.append(net)
        for net in confirmed:
            if net.prefixlen >= 24 or net.prefixlen < MIN_INFER_PREFIX:
                continue
            for sub in net.subnets(new_prefix=24):
                self.add_subnet(str(sub), CONF_EXTRAPOLATED,
                                "extrapolation", "adjacent-of-%s" % str(net))

    # ---- export ----

    def export_jsonl(self, path):
        def _host_key(kv):
            try:
                a = ip_address(kv[0])
                return (a.version, a.packed)
            except ValueError:
                return (0, kv[0].encode())
        with self.lock, open(path, "w") as fh:
            for ip, rec in sorted(self.hosts.items(), key=_host_key):
                fh.write(json.dumps({
                    "ip":         ip,
                    "mac":        rec.mac,
                    "hostnames":  sorted(rec.hostnames),
                    "vlan":       rec.vlan,
                    "confidence": CONF_NAME[rec.confidence],
                    "is_gateway": ip in self.gateway_ips,
                    "evidence":   sorted(rec.evidence),
                    "first_seen": rec.first_seen,
                    "last_seen":  rec.last_seen,
                }) + "\n")
            for cidr, rec in sorted(self.subnets.items()):
                fh.write(json.dumps({
                    "subnet":     cidr,
                    "confidence": CONF_NAME[rec.confidence],
                    "source":     rec.source,
                    "mask_from":  rec.mask_from,
                }) + "\n")

# ---------------------------------------------------------------------------
# Packet dissectors (passive only)
# ---------------------------------------------------------------------------

def diss_arp(pkt, kb):
    arp = pkt[ARP]
    if arp.psrc and arp.psrc != "0.0.0.0":
        kb.observe_host(arp.psrc, mac=arp.hwsrc, source="arp")
    if arp.op == 2 and arp.pdst and arp.pdst != "0.0.0.0":
        kb.observe_host(arp.pdst, mac=arp.hwdst, source="arp")
    if arp.op == 1 and is_rfc1918(arp.psrc) and is_rfc1918(arp.pdst):
        kb.onlink[arp.psrc]["on"].add(arp.pdst)
        kb._reinfer(arp.psrc)


def diss_dhcp(pkt, kb):
    if not pkt.haslayer(DHCP):
        return
    opts = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1] if len(o) == 2 else list(o[1:])
    bootp  = pkt.getlayer("BOOTP")
    yiaddr = getattr(bootp, "yiaddr", None)
    ciaddr = getattr(bootp, "ciaddr", None)
    chaddr = getattr(bootp, "chaddr", None)
    cmac   = ""
    if chaddr:
        try:
            cmac = ":".join("%02x" % b for b in chaddr[:6])
        except Exception:
            cmac = ""
    mask   = opts.get("subnet_mask")
    target = yiaddr if (yiaddr and yiaddr != "0.0.0.0") else (
        ciaddr if (ciaddr and ciaddr != "0.0.0.0") else None)
    if target:
        kb.observe_host(target, mac=cmac, source="dhcp")
        if mask:
            try:
                pl = IPv4Network("0.0.0.0/%s" % mask).prefixlen
                kb.add_subnet("%s/%d" % (target, pl), CONF_ROUTED, "dhcp:opt1", "dhcp-mask")
            except ValueError:
                pass

    def _decode(v):
        if isinstance(v, (bytes, bytearray)):
            return v.decode(errors="ignore").strip("\x00")
        return str(v)

    for okey, label in (("hostname", "dhcp:opt12"), ("client_FQDN", "dhcp:opt81")):
        hv = opts.get(okey)
        if hv and target:
            name = _decode(hv if not isinstance(hv, list) else hv[-1])
            if name:
                kb.add_hostname(target, name.split(".")[0], label)
    routers = opts.get("router")
    if routers:
        for r in (routers if isinstance(routers, list) else [routers]):
            kb.note_gateway(ip=r, source="dhcp")
    ns_list = opts.get("name_server")
    if ns_list:
        for ns in (ns_list if isinstance(ns_list, list) else [ns_list]):
            kb.observe_host(ns, source="dhcp:dns")
    csr = opts.get("classless_static_routes")
    if csr:
        for entry in (csr if isinstance(csr, list) else [csr]):
            net = getattr(entry, "net", None) or (
                entry[0] if isinstance(entry, (tuple, list)) else None)
            if net:
                kb.add_subnet(str(net), CONF_ROUTED, "dhcp:opt121", "static-route")


def diss_cdp(pkt, kb):
    if not _CAPS["cdp"]:
        return
    name = ""
    if pkt.haslayer(CDPMsgDeviceID):
        try:
            name = pkt[CDPMsgDeviceID].val.decode(errors="ignore")
        except Exception:
            name = str(pkt[CDPMsgDeviceID].val)
    for layer_cls in (CDPMsgAddr, CDPMsgMgmtAddr):
        ly = pkt.getlayer(layer_cls)
        while ly is not None:
            for addr in getattr(ly, "addr", []) or []:
                ip = getattr(addr, "addr", None)
                if ip:
                    kb.observe_host(ip, source="cdp:mgmt")
                    kb.note_gateway(ip=ip, source="cdp")
                    if name:
                        kb.add_hostname(ip, name, "cdp")
            ly = ly.payload.getlayer(layer_cls)
    pfx = pkt.getlayer(CDPMsgIPPrefix)
    while pfx is not None:
        for p in getattr(pfx, "prefix", []) or []:
            net  = getattr(p, "prefix", None)
            plen = getattr(p, "plen", None)
            if net is not None and plen is not None:
                kb.add_subnet("%s/%d" % (net, plen), CONF_ROUTED, "cdp:prefix", "cdp")
        pfx = pfx.payload.getlayer(CDPMsgIPPrefix)


def _lldp_mgmt_ip(mg):
    r"""Decode an LLDP management-address TLV to an IP string, or '' when it is
    not a v4/v6 address. Guards against emitting the raw byte string as a fake
    host (the cause of the b'\xfd...' targets seen earlier)."""
    addr    = getattr(mg, "management_address", None)
    subtype = getattr(mg, "management_address_subtype", None)
    if not addr:
        return ""
    if isinstance(addr, str):
        try:
            ip_address(addr)
            return addr
        except ValueError:
            return ""
    if isinstance(addr, (bytes, bytearray)):
        b = bytes(addr)
        # A raw 16-byte blob is always a syntactically valid IPv6, so length
        # alone cannot be trusted: a 16-char ASCII system name would decode to
        # a bogus address. Decode v6 only when the subtype explicitly says v6,
        # or when the subtype is absent and the bytes do not look like printable
        # text. v4 (4 bytes) has no such ambiguity.
        try:
            if subtype == 1:
                return socket.inet_ntop(socket.AF_INET, b[-4:]) if len(b) >= 4 else ""
            if subtype == 2:
                return socket.inet_ntop(socket.AF_INET6, b[-16:]) if len(b) >= 16 else ""
            if subtype is None:
                if len(b) == 4:
                    return socket.inet_ntop(socket.AF_INET, b)
                if len(b) == 16 and not _looks_printable(b):
                    return socket.inet_ntop(socket.AF_INET6, b)
        except (OSError, ValueError):
            return ""
    return ""


def _looks_printable(b):
    """True if the bytes are mostly printable ASCII, i.e. likely a name string
    rather than a packed address."""
    if not b:
        return False
    printable = sum(1 for c in b if 0x20 <= c <= 0x7e)
    return printable >= (len(b) * 3) // 4


def diss_lldp(pkt, kb):
    if not _CAPS["lldp"]:
        return
    name = ""
    if pkt.haslayer(LLDPDUSystemName):
        try:
            sn = pkt[LLDPDUSystemName].system_name
            name = (sn.decode(errors="ignore")
                    if isinstance(sn, (bytes, bytearray)) else str(sn)).strip()
        except Exception:
            name = ""
    mg = pkt.getlayer(LLDPDUManagementAddress)
    while mg is not None:
        ip = _lldp_mgmt_ip(mg)
        if ip:
            kb.observe_host(ip, source="lldp:mgmt")
            if name:
                kb.add_hostname(ip, name, "lldp")
        mg = mg.payload.getlayer(LLDPDUManagementAddress)


def diss_ospf(pkt, kb):
    if not _CAPS["ospf"] or not pkt.haslayer(OSPF_Hdr):
        return
    src   = pkt[IP].src if pkt.haslayer(IP) else None
    hello = pkt.getlayer(OSPF_Hello)
    if hello is not None and src:
        kb.note_gateway(ip=src, source="ospf")
        mask = getattr(hello, "mask", None)
        if mask:
            try:
                pl = IPv4Network("0.0.0.0/%s" % mask).prefixlen
                kb.add_subnet("%s/%d" % (src, pl), CONF_ROUTED, "ospf:hello", "ospf-mask")
            except ValueError:
                pass
        for nb in getattr(hello, "neighbors", []) or []:
            kb.observe_host(str(nb), source="ospf:neighbor")
    lsu = pkt.getlayer(OSPF_LSUpd)
    if lsu is not None:
        for lsa in getattr(lsu, "lsalist", []) or []:
            net  = getattr(lsa, "id",   None) or getattr(lsa, "addr", None)
            mask = getattr(lsa, "mask", None)
            if net and mask:
                try:
                    pl = IPv4Network("0.0.0.0/%s" % mask).prefixlen
                    kb.add_subnet("%s/%d" % (net, pl), CONF_ROUTED, "ospf:lsa", "ospf-lsa")
                except ValueError:
                    pass


def diss_eigrp(pkt, kb):
    if not _CAPS["eigrp"]:
        return
    if pkt.haslayer(IP):
        kb.note_gateway(ip=pkt[IP].src, source="eigrp")
    for cls in (EIGRPIntRoute, EIGRPExtRoute):
        ly = pkt.getlayer(cls)
        while ly is not None:
            dst  = getattr(ly, "dst",       None)
            plen = getattr(ly, "prefixlen", None)
            if dst is not None and plen is not None:
                kb.add_subnet("%s/%d" % (dst, plen), CONF_ROUTED, "eigrp", "eigrp-route")
            ly = ly.payload.getlayer(cls)


def diss_hsrp(pkt, kb):
    if not _CAPS["hsrp"]:
        return
    h   = pkt[HSRP]
    vip = getattr(h, "virtualIP", None)
    src = pkt[IP].src if pkt.haslayer(IP) else None
    if vip and vip != "0.0.0.0":
        grp  = getattr(h, "group", 0)
        vmac = "00:00:0c:07:ac:%02x" % (grp & 0xff)
        kb.note_gateway(ip=vip, mac=vmac, source="hsrp")
    if src:
        kb.note_gateway(ip=src, source="hsrp:speaker")


def diss_vrrp(pkt, kb):
    if not _CAPS["vrrp"]:
        return
    for cls in (VRRP, VRRPv3):
        if pkt.haslayer(cls):
            v    = pkt[cls]
            vrid = getattr(v, "vrid", 0)
            vmac = "00:00:5e:00:01:%02x" % (vrid & 0xff)
            for a in getattr(v, "addrlist", []) or []:
                kb.note_gateway(ip=str(a), mac=vmac, source="vrrp")
            if pkt.haslayer(IP):
                kb.note_gateway(ip=pkt[IP].src, source="vrrp:speaker")
            return


def diss_dns_like(pkt, kb, source):
    """Catalogue A/AAAA answers from DNS, mDNS, and LLMNR responses, and the
    names attached to them. RFC1918 addresses become catalogued targets."""
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]

    def _name(field):
        if isinstance(field, (bytes, bytearray)):
            return field.decode(errors="ignore").rstrip(".")
        return str(field).rstrip(".")

    sections = []
    for attr, count in (("an", "ancount"), ("ns", "nscount"), ("ar", "arcount")):
        for i in range(getattr(dns, count, 0) or 0):
            try:
                sections.append(getattr(dns, attr)[i])
            except Exception:
                break

    for rr in sections:
        if getattr(rr, "type", None) in (1, 28):
            ip = rr.rdata if isinstance(rr.rdata, str) else None
            if ip and is_rfc1918(ip):
                kb.observe_host(ip, source=source)
                nm = _name(getattr(rr, "rrname", b""))
                if nm:
                    kb.add_hostname(ip, nm, source)


def diss_nbns(pkt, kb):
    """NBNS (UDP 137). Catalogue the source and attach a hostname only when the
    packet carries the source's OWN name: any response (RR_NAME) or a name
    registration/refresh request (QUESTION_NAME). Plain queries are skipped
    because their QUESTION_NAME is the name being looked up, not the sender's."""
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="nbns")
    hdr = pkt.getlayer(NBNSHeader)
    if hdr is None:
        return
    response = getattr(hdr, "RESPONSE", 0)
    opcode   = getattr(hdr, "OPCODE", 0)

    def _name(field):
        try:
            val = pkt.getfieldval(field)
        except Exception:
            return ""
        if not val:
            return ""
        s = (val.decode(errors="ignore")
             if isinstance(val, (bytes, bytearray)) else str(val))
        s = s.strip().strip("\x00").rstrip()
        return "" if (not s or s == "*") else s[:15].strip()

    name = ""
    if response:                       # response: RR_NAME is the responder's own
        name = _name("RR_NAME")
    elif opcode in (5, 8):             # registration / refresh: own name
        name = _name("QUESTION_NAME")
    # opcode 0 query: QUESTION_NAME is the queried name, not the sender's

    if name:
        kb.add_hostname(src, name, "nbns")

    if pkt.haslayer(NBNSNodeStatusResponse):
        try:
            mac = pkt[NBNSNodeStatusResponse].MAC_ADDRESS
        except Exception:
            mac = None
        if mac and is_unicast_mac(mac):
            kb.observe_host(src, mac=mac, source="nbns:nodestatus")


def diss_nbtds(pkt, kb):
    """NBT Datagram Service (UDP 138): host announcements and browser traffic.
    SourceName is the announcing host's own NetBIOS name and SourceIP its
    address. This is the prime passive name source the old build threw away."""
    dg = pkt.getlayer(NBTDatagram)
    if dg is None:
        return
    sip = getattr(dg, "SourceIP", None)
    src = sip if (sip and sip != "0.0.0.0") else (
        pkt[IP].src if pkt.haslayer(IP) else None)
    if not src:
        return
    kb.observe_host(src, source="nbtds")
    sname = getattr(dg, "SourceName", None)
    if sname:
        name = (sname.decode(errors="ignore")
                if isinstance(sname, (bytes, bytearray)) else str(sname))
        name = name.strip().strip("\x00").rstrip()
        if name and name != "*":
            kb.add_hostname(src, name[:15].strip(), "nbtds")


def diss_dhcp6(pkt, kb):
    if not pkt.haslayer(DHCP6) or not pkt.haslayer(IPv6):
        return
    src = pkt[IPv6].src
    if src and src != "::":
        kb.observe_host(src, source="dhcp6")


def diss_igmp(pkt, kb):
    """IGMP / MLD membership reports reveal the joining host as a source."""
    if _CAPS["igmp"] and IGMP is not None and pkt.haslayer(IGMP) and pkt.haslayer(IP):
        kb.observe_host(pkt[IP].src, source="igmp")
    if _CAPS["mld"]:
        for cls in (ICMPv6MLReport, ICMPv6MLReport2):
            if cls is not None and pkt.haslayer(cls) and pkt.haslayer(IPv6):
                src = pkt[IPv6].src
                if src and src != "::":
                    kb.observe_host(src, source="mld")


def diss_ipv6_nd(pkt, kb):
    src = pkt[IPv6].src if pkt.haslayer(IPv6) else None
    if pkt.haslayer(ICMPv6ND_RA):
        if src:
            kb.note_gateway(ip=src, source="ipv6:ra")
        opt = pkt.getlayer(ICMPv6NDOptPrefixInfo)
        while opt is not None:
            prefix = getattr(opt, "prefix",    None)
            plen   = getattr(opt, "prefixlen", None)
            if prefix and plen:
                kb.add_subnet("%s/%d" % (prefix, plen), CONF_ROUTED, "ipv6:ra", "ra-prefix")
            opt = opt.payload.getlayer(ICMPv6NDOptPrefixInfo)
    for cls in (ICMPv6ND_NS, ICMPv6ND_NA):
        if pkt.haslayer(cls) and src and src != "::":
            kb.observe_host(src, source="ipv6:nd")


def diss_traffic(pkt, kb):
    """The generic catch-all: any IP/IPv6 packet's source is a catalogued
    target, the source MAC binds it, and the (src, dst, dst_mac) triple feeds
    on-link/routed correlation for CIDR inference."""
    if not pkt.haslayer(Ether):
        return
    eth  = pkt[Ether]
    vlan = pkt[Dot1Q].vlan if pkt.haslayer(Dot1Q) else 0
    if pkt.haslayer(IP):
        ip  = pkt[IP]
        rec = kb.observe_host(ip.src, mac=eth.src, source="traffic")
        if rec is not None and vlan:
            rec.vlan = vlan
        if is_unicast_mac(eth.dst):
            kb.observe_host(ip.dst, source="traffic")
            kb.correlate(ip.src, ip.dst, eth.dst)
    elif pkt.haslayer(IPv6):
        v6 = pkt[IPv6]
        if is_rfc1918(v6.src):
            rec = kb.observe_host(v6.src, mac=eth.src, source="traffic6")
            if rec is not None and vlan:
                rec.vlan = vlan


def dispatch(pkt, kb):
    try:
        if pkt.haslayer(ARP):
            diss_arp(pkt, kb)
            return
        if _CAPS["cdp"] and pkt.haslayer(CDPMsgDeviceID):
            diss_cdp(pkt, kb)
        if _CAPS["lldp"] and pkt.haslayer(LLDPDUManagementAddress):
            diss_lldp(pkt, kb)
        if _CAPS["ospf"] and pkt.haslayer(OSPF_Hdr):
            diss_ospf(pkt, kb)
        if _CAPS["eigrp"] and pkt.haslayer(EIGRP):
            diss_eigrp(pkt, kb)
        if _CAPS["hsrp"] and pkt.haslayer(HSRP):
            diss_hsrp(pkt, kb)
        if _CAPS["vrrp"] and (pkt.haslayer(VRRP) or pkt.haslayer(VRRPv3)):
            diss_vrrp(pkt, kb)
        if pkt.haslayer(NBNSHeader):
            diss_nbns(pkt, kb)
        if pkt.haslayer(NBTDatagram):
            diss_nbtds(pkt, kb)
        _mc = [c for c in (IGMP if _CAPS["igmp"] else None,
                           ICMPv6MLReport, ICMPv6MLReport2) if c is not None]
        if any(pkt.haslayer(c) for c in _mc):
            diss_igmp(pkt, kb)
        if pkt.haslayer(DHCP6):
            diss_dhcp6(pkt, kb)
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            if dport in (67, 68):
                diss_dhcp(pkt, kb)
            elif dport == 5353 or sport == 5353:
                diss_dns_like(pkt, kb, "mdns")
            elif dport == 5355 or sport == 5355:
                diss_dns_like(pkt, kb, "llmnr")
            elif dport == 53 or sport == 53:
                diss_dns_like(pkt, kb, "dns")
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 53 or pkt[TCP].sport == 53):
            diss_dns_like(pkt, kb, "dns")
        if pkt.haslayer(ICMPv6ND_RA) or pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
            diss_ipv6_nd(pkt, kb)
        diss_traffic(pkt, kb)
    except Exception as ex:
        kb.log.write("ERR   dissect: %s" % ex)

# ---------------------------------------------------------------------------
# Recon engine (passive sniffer only)
# ---------------------------------------------------------------------------

class ReconEngine:
    def __init__(self, iface_info, outdir, scope=None, echo=True):
        self.iface_info  = iface_info
        self.iface_names = [i[0] for i in iface_info]
        self.outdir      = outdir
        self._down       = False
        self.runlog, self.feed, self.ts = open_outputs(outdir, echo=echo)
        self.kb = KnowledgeBase(self.runlog, self.feed, scope)
        self.sniffer = None

    def _seed_local_subnets(self):
        for name, ip, cidr in self.iface_info:
            self.kb.observe_host(ip, source="local:%s" % name)
            self.kb.add_subnet(cidr, CONF_CONFIRMED,
                               "local-iface:%s" % name, "iface-config")

    def _banner_lines(self):
        return [
            "passive_targeting  |  passive capture only",
            "interface(s) : %s" % ", ".join(
                "%s (%s)" % (n, cidr) for n, _, cidr in self.iface_info),
            "targets      : %s" % os.path.join(self.outdir, "targets.txt"),
            "subnets      : %s" % os.path.join(self.outdir, "subnets.txt"),
            "log          : %s" % os.path.join(self.outdir, "recon_%s.log" % self.ts),
            "caps         : %s" % ", ".join(
                list(ALWAYS_ON_PROTOS) + [k for k, v in _CAPS.items() if v]),
        ]

    def _print_banner(self):
        print()
        for ln in self._banner_lines():
            print("    " + ln)
        print()
        print("    tail -f %s" % os.path.join(self.outdir, "recon_%s.log" % self.ts))
        print("    ^C to stop\n")

    def start(self):
        """Spin up the passive sniffer. Non-blocking. Transmits nothing."""
        self._seed_local_subnets()
        self.sniffer = AsyncSniffer(
            iface=self.iface_names, store=False,
            prn=lambda p: dispatch(p, self.kb))
        self.runlog.write("START ifaces=%s  (passive)" % ",".join(self.iface_names))
        self.sniffer.start()

    def shutdown(self):
        """Stop capture, extrapolate adjacent /24s, export."""
        if self._down:
            return
        self._down = True
        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception:
            pass
        self.kb.extrapolate_adjacent()
        jpath = os.path.join(self.outdir, "hosts_%s.jsonl" % self.ts)
        self.kb.export_jsonl(jpath)
        self.runlog.write("STOP  hosts=%d  subnets=%d  gateways=%d  json=%s" % (
            len(self.kb.hosts), len(self.kb.subnets),
            len(self.kb.gateway_ips), jpath))
        self.runlog.close()
        self.feed.close()

    def run(self):
        """Blocking line-log mode with signal-driven shutdown."""
        self._print_banner()
        self.start()
        stop_event = threading.Event()
        sig_count  = [0]

        def _sig(signum, frame):
            sig_count[0] += 1
            if sig_count[0] == 1:
                stop_event.set()
            else:
                print("\n[!] Force exit.")
                sys.exit(130)

        signal.signal(signal.SIGINT,  _sig)
        signal.signal(signal.SIGTERM, _sig)
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        finally:
            self.shutdown()

# ---------------------------------------------------------------------------
# Curses TUI (standard library only)
# ---------------------------------------------------------------------------

def run_tui(engine):
    """Self-contained stdlib curses TUI. Three panes: banner and live counts
    on top, newly added targets (IPs and CIDRs) on the left, the running log
    on the right. Ctrl-A opens a paste box for routing tables or target
    lists; q quits.

    Thread-safety: the sniffer only appends lines to bounded deques under
    ui_lock via the runlog/feed sinks. All curses drawing happens on this
    thread, on a timer. No curses call is ever made from the sniffer thread.

    Returns False only when curses cannot initialize before the engine has
    started, so the caller can fall back to line-log mode without
    double-starting the engine."""
    try:
        import curses
        from curses import textpad
    except Exception as ex:
        print("[!] curses unavailable (%s); line-log mode" % ex)
        return False

    log_lines    = deque(maxlen=2000)
    target_lines = deque(maxlen=2000)
    ui_lock      = threading.Lock()
    notice       = [""]
    started      = [False]

    def log_sink(line):
        with ui_lock:
            log_lines.append(line)

    def target_sink(entry):
        with ui_lock:
            target_lines.append(entry)

    def _ui(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)
        try:
            curses.start_color()
            curses.use_default_colors()
        except Exception:
            pass

        banner = engine._banner_lines()
        wins   = {}

        def _safe_addstr(win, y, x, s, attr=0):
            h, w = win.getmaxyx()
            if y < 0 or y >= h or x < 0 or x >= w:
                return
            s = s[:max(0, w - x - 1)]
            try:
                win.addstr(y, x, s, attr)
            except curses.error:
                pass

        def rebuild():
            maxy, maxx = stdscr.getmaxyx()
            top_h = len(banner) + 3
            if top_h > maxy - 4:
                top_h = max(3, maxy - 4)
            bot_h = max(3, maxy - top_h)
            split = max(18, maxx // 3)
            stdscr.clear()
            stdscr.refresh()
            wins["status"]  = curses.newwin(top_h, maxx, 0, 0)
            wins["targets"] = curses.newwin(bot_h, split, top_h, 0)
            wins["log"]     = curses.newwin(bot_h, max(1, maxx - split), top_h, split)

        def draw_status():
            win = wins["status"]
            win.erase()
            h, _ = win.getmaxyx()
            for i, ln in enumerate(banner):
                if i < h:
                    _safe_addstr(win, i, 1, ln, curses.A_BOLD if i == 0 else 0)
            with ui_lock:
                hosts   = len(engine.feed.seen_hosts)
                subnets = len(engine.feed.seen_subnets)
            gws   = len(engine.kb.gateway_ips)
            clock = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            counts = "%s   single:%d  cidr:%d  gateways:%d" % (
                clock, hosts, subnets, gws)
            if len(banner) < h:
                _safe_addstr(win, len(banner), 1, counts, curses.A_BOLD)
            help_ln = "ctrl+a paste routes/targets    q quit"
            if notice[0]:
                help_ln = notice[0] + "    |    " + help_ln
            if len(banner) + 1 < h:
                _safe_addstr(win, len(banner) + 1, 1, help_ln)
            win.noutrefresh()

        def draw_pane(win, title, lines):
            win.erase()
            try:
                win.box()
            except curses.error:
                pass
            h, w = win.getmaxyx()
            _safe_addstr(win, 0, 2, " %s " % title, curses.A_BOLD)
            inner_h = h - 2
            inner_w = w - 2
            if inner_h >= 1 and inner_w >= 1:
                with ui_lock:
                    view = list(lines)[-inner_h:]
                for i, ln in enumerate(view):
                    _safe_addstr(win, 1 + i, 1, ln[:inner_w])
            win.noutrefresh()

        def paste_box():
            maxy, maxx = stdscr.getmaxyx()
            h = max(8, int(maxy * 0.7))
            w = max(40, int(maxx * 0.7))
            y = (maxy - h) // 2
            x = (maxx - w) // 2
            frame = curses.newwin(h, w, y, x)
            frame.box()
            _safe_addstr(frame, 0, 2,
                         " paste routes/targets - Ctrl-G applies ", curses.A_BOLD)
            _safe_addstr(frame, h - 1, 2,
                         " ip route / route -n / route print / show ip route / IPs ")
            frame.refresh()
            edit = curses.newwin(h - 2, w - 2, y + 1, x + 1)
            box  = textpad.Textbox(edit, insert_mode=True)
            curses.curs_set(1)
            text = box.edit()
            curses.curs_set(0)
            subs, gws, hosts = parse_routes(text)
            ns, ng, nh = apply_parsed(engine.kb, subs, gws, hosts, "manual:paste")
            notice[0] = "added %d subnets, %d gateways, %d hosts" % (ns, ng, nh)

        rebuild()
        engine.runlog.echo = False
        engine.runlog.sink = log_sink
        engine.feed.sink   = target_sink
        engine.start()
        started[0] = True

        last_draw = 0.0
        while True:
            try:
                ch = stdscr.getch()
                if ch == ord("q"):
                    break
                elif ch == curses.KEY_RESIZE:
                    rebuild()
                elif ch == 1:                      # Ctrl-A
                    paste_box()
                    rebuild()
                now = time.time()
                if now - last_draw >= 0.25:
                    last_draw = now
                    draw_status()
                    draw_pane(wins["targets"], "new targets", target_lines)
                    draw_pane(wins["log"],     "log",         log_lines)
                    curses.doupdate()
                time.sleep(0.02)
            except KeyboardInterrupt:
                break

    def _restore_terminal():
        # curses.wrapper already ran endwin(), but on some terminals the
        # mouse-reporting and bracketed-paste modes are left enabled, which
        # makes the shell echo escape sequences and breaks copy/paste/typing.
        # Emit the disable sequences explicitly so the prompt returns clean.
        try:
            sys.stdout.write(
                "\033[?1000l\033[?1002l\033[?1003l\033[?1006l"  # all mouse modes off
                "\033[?2004l"                                    # bracketed paste off
                "\033[?25h"                                      # cursor visible
                "\033[0m")                                       # reset attributes
            sys.stdout.flush()
        except Exception:
            pass

    try:
        curses.wrapper(_ui)
    except Exception as ex:
        _restore_terminal()
        print("[!] TUI error: %s" % ex)
        if started[0]:
            engine.runlog.echo = True
            try:
                engine.shutdown()
            except KeyboardInterrupt:
                pass
            return True
        return False
    _restore_terminal()
    engine.runlog.echo = True
    try:
        engine.shutdown()
    except KeyboardInterrupt:
        pass
    return True

# ---------------------------------------------------------------------------
# Runners
# ---------------------------------------------------------------------------

def run_default(args):
    ifaces = discover_rfc1918_ifaces()
    if not ifaces:
        print("[!] No RFC1918 interfaces found.")
        print("    Verify interface addresses with: ip addr show")
        sys.exit(1)
    selected = select_interfaces(ifaces)
    if not selected:
        print("[!] No interface selected.")
        sys.exit(1)

    scope = Scope(
        allow=[c for c in (args.scope or [])],
        deny=[c for c in (args.exclude or [])],
    )
    use_tui = (not args.no_tui) and sys.stdout.isatty()
    engine = ReconEngine(
        iface_info = selected,
        outdir     = args.outdir,
        scope      = scope,
        echo       = True,
    )
    if use_tui and run_tui(engine):
        return
    engine.run()


def run_analyze(args):
    runlog, feed, ts = open_outputs(args.outdir)
    kb = KnowledgeBase(runlog, feed)
    runlog.write("START analyze  pcap=%s" % args.pcap)
    for pkt in rdpcap(args.pcap):
        dispatch(pkt, kb)
    kb.extrapolate_adjacent()
    jpath = os.path.join(args.outdir, "hosts_%s.jsonl" % ts)
    kb.export_jsonl(jpath)
    runlog.write("STOP  hosts=%d  subnets=%d  gateways=%d  json=%s" % (
        len(kb.hosts), len(kb.subnets), len(kb.gateway_ips), jpath))
    runlog.close()
    feed.close()

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Strictly passive internal target discovery.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python3 passive_targeting.py                       # full auto (curses TUI if a tty)
  sudo python3 passive_targeting.py --no-tui              # plain line-log mode
  sudo python3 passive_targeting.py --scope 10.0.0.0/8 --exclude 10.0.5.0/24
  python3 passive_targeting.py analyze capture.pcap       # offline, no root
""")

    p.add_argument("-o", "--outdir", default="targeting_out",
                   help="output directory (default: targeting_out)")
    p.add_argument("--scope", action="append", metavar="CIDR",
                   help="restrict catalogued targets to CIDR (repeatable)")
    p.add_argument("--exclude", action="append", metavar="CIDR",
                   help="exclude CIDR from catalogued targets (repeatable)")
    p.add_argument("--no-tui", action="store_true", default=False,
                   help="disable the curses TUI; use plain line-log output")
    p.set_defaults(func=run_default)

    sub = p.add_subparsers(dest="cmd")
    pa  = sub.add_parser("analyze", help="offline pcap analysis (no root required)")
    pa.add_argument("pcap", help="pcap/pcapng input file")
    pa.set_defaults(func=run_analyze)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
