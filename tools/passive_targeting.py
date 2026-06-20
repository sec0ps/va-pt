#!/usr/bin/env python3
# passive_recon.py
#
# Passive + active internal segment target expansion.
#
# On execution:
#   - Enumerates interfaces, filters to RFC1918-addressed ones
#   - Auto-selects if only one; prompts for choice if multiple
#   - Immediately seeds and queues the local subnet(s) for active sweep
#   - Runs passive sniffer and active sweep worker in parallel
#   - Streams confirmed hosts to targets.txt and subnets to subnets.txt
#   - Writes a timestamped run log for live tail
#   - Optional Textual TUI: live clock, host/subnet/gateway counts, log pane,
#     and ctrl+a paste box to feed captured routing tables or target lists
#
# Usage:
#   sudo python3 passive_recon.py                 # full auto (TUI if available)
#   sudo python3 passive_recon.py --no-tui        # plain line-log mode
#   sudo python3 passive_recon.py -r 100 -t 1     # faster sweep
#   sudo python3 passive_recon.py --mask-request  # also probe ICMP type 17
#   sudo python3 passive_recon.py --scope 10.0.0.0/8 --exclude 10.0.5.0/24
#   python3 passive_recon.py analyze cap.pcap     # offline pcap, no root needed
#
# Requires root for live capture and active sweep (raw sockets).

import argparse
import fcntl
import json
import logging
import os
import queue
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
    Ether, Dot1Q, ARP, IP, TCP, ICMP, UDP, DHCP, DNS,
    sr, srp,
)

# Suppress scapy's MAC-resolution warnings and verbose output.
scapy_conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

_CAPS = {}
for _m in ("cdp", "lldp", "ospf", "eigrp", "hsrp", "vrrp", "dtp", "vtp"):
    try:
        load_contrib(_m)
        _CAPS[_m] = True
    except Exception:
        _CAPS[_m] = False

try:
    from scapy.contrib.cdp import (
        CDPMsgDeviceID, CDPMsgAddr, CDPMsgMgmtAddr,
        CDPAddrRecordIPv4, CDPMsgIPPrefix,
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
try:
    from scapy.contrib.dtp import DTP
except Exception:
    _CAPS["dtp"] = False
try:
    from scapy.all import STP
    _CAPS["stp"] = True
except Exception:
    _CAPS["stp"] = False
try:
    from scapy.layers.snmp import SNMP
    _CAPS["snmp"] = True
except Exception:
    _CAPS["snmp"] = False

from scapy.layers.netbios import NBNSQueryResponse
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

GATEWAY_OUI = {
    "00000c07ac": "HSRP",
    "00000c9ff":  "HSRPv2",
    "00005e0001": "VRRP",
    "00000c4140": "GLBP",
}

DEFAULT_FLOOR      = 24     # assumed prefix when nothing else resolves
MIN_INFER_PREFIX   = 16     # never widen inferred subnet past /16 without proof
MAX_SWEEP_HOSTS    = 65536  # hard ceiling on host expansion per CIDR
SWEEP_BATCH        = 256    # hosts per sr/srp call
MIN_SWEEP_PREFIX   = 16     # don't auto-queue subnets wider than /16

# Well-known destination ports -> coarse server role.
ROLE_PORTS = {
    88: "dc/kerberos", 389: "dc/ldap", 636: "dc/ldaps", 3268: "dc/gc",
    53: "dns", 445: "file/smb", 139: "file/smb", 2049: "file/nfs",
    3389: "rdp", 5985: "winrm", 5986: "winrm", 22: "ssh", 23: "telnet",
    1433: "db/mssql", 3306: "db/mysql", 5432: "db/pgsql", 1521: "db/oracle",
    25: "smtp", 110: "pop3", 143: "imap", 161: "snmp", 123: "ntp",
    80: "web", 443: "web", 8080: "web", 8443: "web",
    515: "printer", 631: "printer", 9100: "printer",
    623: "ipmi", 3128: "proxy", 1080: "proxy",
}

# TTL initial-value buckets for coarse passive OS family.
TTL_BUCKETS = [(64, "unix/linux"), (128, "windows"), (255, "net-gear")]

# MS-BRWS ServerType bitmask -> coarse role (UDP 138 browser announcements).
SV_TYPE_FLAGS = {
    0x00000001: "workstation",
    0x00000002: "server",
    0x00000004: "db/mssql",
    0x00000008: "dc/pdc",
    0x00000010: "dc/bdc",
    0x00000020: "time-source",
    0x00000040: "file/afp",
    0x00000080: "novell",
    0x00000100: "domain-member",
    0x00000200: "printer",
    0x00000800: "unix",
    0x00001000: "nt-workstation",
    0x00008000: "nt-server",
    0x00020000: "browser/backup",
    0x00040000: "browser/master",
    0x00080000: "browser/domain-master",
    0x00400000: "windows",
    0x01000000: "file/dfs",
}

_BROWSE_TAG = b"\\MAILSLOT\\BROWSE\x00"
_BROWSE_OPS = {0x01: "host-announce", 0x09: "backup-list-req",
               0x0c: "domain-announce", 0x0d: "master-announce",
               0x0f: "local-master-announce"}

_MNDP_TLV = {5: "identity", 7: "version", 8: "platform", 12: "board"}
_UBNT_TLV = {0x03: "firmware", 0x0b: "hostname", 0x0c: "model", 0x0d: "essid"}


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


def ttl_os(ttl):
    """Map an observed TTL to (os_family, estimated_hops)."""
    for base, name in TTL_BUCKETS:
        if 0 < ttl <= base:
            return name, base - ttl
    return "high-ttl", 0

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
    inherit the standard RFC1918, prefix, and scope guards via the KB; hosts
    are enqueued directly so they get actively enumerated."""
    for gw in gateways:
        kb.note_gateway(ip=gw, source=source)
    for cidr in subnets:
        kb.add_subnet(cidr, CONF_ROUTED, source, "manual")
    added = 0
    for ip in hosts:
        if kb.observe_host(ip, source=source) is not None:
            added += 1
            if kb.sweep_queue is not None and is_rfc1918(ip) and kb.in_scope(ip):
                kb.sweep_queue.put(ip)
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
    Preloads existing files so re-running the same outdir does not duplicate."""

    def __init__(self, targets_path, subnets_path, targets6_path):
        self.seen_hosts   = set()
        self.seen_subnets = set()
        self._preload(targets_path,  self.seen_hosts)
        self._preload(targets6_path, self.seen_hosts)
        self._preload(subnets_path,  self.seen_subnets)
        self.targets_fh  = open(targets_path,  "a", buffering=1)
        self.subnets_fh  = open(subnets_path,  "a", buffering=1)
        self.targets6_fh = open(targets6_path, "a", buffering=1)
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
            return True

    def add_subnet(self, cidr):
        with self.lock:
            if cidr in self.seen_subnets:
                return False
            self.seen_subnets.add(cidr)
            self.subnets_fh.write(cidr + "\n")
            self.subnets_fh.flush()
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
    ip:          str
    mac:         str  = ""
    hostnames:   set  = field(default_factory=set)
    services:    set  = field(default_factory=set)
    roles:       set  = field(default_factory=set)
    fingerprint: set  = field(default_factory=set)
    vlan:        int  = 0
    confidence:  int  = CONF_CONFIRMED
    evidence:    set  = field(default_factory=set)
    first_seen:  float = field(default_factory=time.time)
    last_seen:   float = field(default_factory=time.time)


@dataclass
class SubnetRecord:
    cidr:       str
    confidence: int
    source:     str
    mask_from:  str   = ""
    first_seen: float = field(default_factory=time.time)


class KnowledgeBase:
    def __init__(self, runlog, feed, sweep_queue=None, scope=None):
        self.log         = runlog
        self.feed        = feed
        self.sweep_queue = sweep_queue          # queue.Queue or None
        self.scope       = scope or Scope()
        self.lock        = threading.Lock()
        self.hosts       = {}                   # ip -> HostRecord
        self.mac_to_ip   = {}                   # norm_mac -> ip
        self.ip_to_mac   = {}                   # ip -> norm_mac
        self.subnets     = {}                   # cidr -> SubnetRecord
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

    def note_service(self, ip, proto, port, confirmed=False):
        """Record an observed service port on a host and tag a coarse role."""
        if not is_rfc1918(ip):
            return
        tag = "%s/%d" % (proto, port)
        rec = self.observe_host(ip, source="service")
        if not rec:
            return
        with self.lock:
            if tag not in rec.services:
                rec.services.add(tag)
                self.log.write("SVC   %-18s  %-9s  %s" % (
                    ip, tag, "confirmed" if confirmed else "seen"))
            role = ROLE_PORTS.get(port)
            if role and role not in rec.roles:
                rec.roles.add(role)
                self.log.write("ROLE  %-18s  %s" % (ip, role))

    def note_fingerprint(self, ip, tag):
        rec = self.hosts.get(ip)
        if rec is None or not tag:
            return
        with self.lock:
            if tag not in rec.fingerprint:
                rec.fingerprint.add(tag)

    def tag_role(self, ip, role):
        rec = self.hosts.get(ip)
        if rec is None or not role:
            return
        with self.lock:
            if role not in rec.roles:
                rec.roles.add(role)
                self.log.write("ROLE  %-18s  %s" % (ip, role))

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
            if (self.sweep_queue is not None
                    and isinstance(net, IPv4Network)
                    and is_rfc1918(str(net.network_address))
                    and self.in_scope(str(net.network_address))
                    and MIN_SWEEP_PREFIX <= net.prefixlen <= 32):
                self.sweep_queue.put(key)

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
        with self.lock, open(path, "w") as fh:
            for ip, rec in sorted(
                    self.hosts.items(),
                    key=lambda kv: ip_address(kv[0])
                    if is_rfc1918(kv[0]) else ip_address("0.0.0.0")):
                fh.write(json.dumps({
                    "ip":          ip,
                    "mac":         rec.mac,
                    "hostnames":   sorted(rec.hostnames),
                    "services":    sorted(rec.services),
                    "roles":       sorted(rec.roles),
                    "fingerprint": sorted(rec.fingerprint),
                    "vlan":        rec.vlan,
                    "confidence":  CONF_NAME[rec.confidence],
                    "is_gateway":  ip in self.gateway_ips,
                    "evidence":    sorted(rec.evidence),
                    "first_seen":  rec.first_seen,
                    "last_seen":   rec.last_seen,
                }) + "\n")
            for cidr, rec in sorted(self.subnets.items()):
                fh.write(json.dumps({
                    "subnet":     cidr,
                    "confidence": CONF_NAME[rec.confidence],
                    "source":     rec.source,
                    "mask_from":  rec.mask_from,
                }) + "\n")

# ---------------------------------------------------------------------------
# Packet dissectors
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
    vclass = opts.get("vendor_class_id")
    if vclass and target:
        kb.note_fingerprint(target, "dhcp-vendor:%s" % _decode(vclass)[:40])
    routers = opts.get("router")
    if routers:
        for r in (routers if isinstance(routers, list) else [routers]):
            kb.note_gateway(ip=r, source="dhcp")
    ns_list = opts.get("name_server")
    if ns_list:
        for ns in (ns_list if isinstance(ns_list, list) else [ns_list]):
            kb.observe_host(ns, source="dhcp:dns")
            kb.tag_role(ns, "dns")
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


def diss_lldp(pkt, kb):
    if not _CAPS["lldp"]:
        return
    name = ""
    if pkt.haslayer(LLDPDUSystemName):
        try:
            name = pkt[LLDPDUSystemName].system_name.decode(errors="ignore")
        except Exception:
            name = str(getattr(pkt[LLDPDUSystemName], "system_name", ""))
    mg = pkt.getlayer(LLDPDUManagementAddress)
    while mg is not None:
        addr = getattr(mg, "management_address", None)
        if addr:
            try:
                ip = (".".join(str(b) for b in addr)
                      if isinstance(addr, (bytes, bytearray)) and len(addr) == 4
                      else str(addr))
                kb.observe_host(ip, source="lldp:mgmt")
                if name:
                    kb.add_hostname(ip, name, "lldp")
            except Exception:
                pass
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
    """Parse A/AAAA, plus DNS-SD PTR/SRV/TXT for mDNS-style records.
    SRV ports and TXT model hints are attached to any A/AAAA name in the
    same response."""
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]

    def _name(field):
        if isinstance(field, (bytes, bytearray)):
            return field.decode(errors="ignore").rstrip(".")
        return str(field).rstrip(".")

    name_to_ip = {}
    sections = []
    for attr, count in (("an", "ancount"), ("ns", "nscount"), ("ar", "arcount")):
        for i in range(getattr(dns, count, 0) or 0):
            try:
                sections.append(getattr(dns, attr)[i])
            except Exception:
                break

    for rr in sections:
        rtype = getattr(rr, "type", None)
        rname = _name(getattr(rr, "rrname", b""))
        if rtype in (1, 28):
            ip = rr.rdata if isinstance(rr.rdata, str) else None
            if ip:
                name_to_ip[rname] = ip
                if is_rfc1918(ip):
                    kb.observe_host(ip, source=source)
                    kb.add_hostname(ip, rname, source)

    for rr in sections:
        rtype = getattr(rr, "type", None)
        if rtype == 33:  # SRV
            tgt  = _name(getattr(rr, "target", b""))
            port = getattr(rr, "port", None)
            ip   = name_to_ip.get(tgt)
            if ip and port and is_rfc1918(ip):
                proto = "udp" if "_udp" in _name(getattr(rr, "rrname", b"")) else "tcp"
                kb.note_service(ip, proto, int(port))
        elif rtype == 16:  # TXT
            try:
                txt = b" ".join(rr.rdata if isinstance(rr.rdata, list)
                                 else [rr.rdata]).decode(errors="ignore")
            except Exception:
                txt = ""
            for ip in name_to_ip.values():
                for key in ("model", "md", "usb_MFG", "ty"):
                    m = re.search(r"%s=([^\s]+)" % key, txt)
                    if m and is_rfc1918(ip):
                        kb.note_fingerprint(ip, "mdns:%s" % m.group(1)[:32])
                        break


def diss_nbns(pkt, kb):
    """Handle any NBNS layer, not only query responses. Registration,
    refresh, and query broadcasts also carry the source host and name."""
    if not pkt.haslayer(IP):
        return
    nb = pkt.getlayer("NBNSHeader") or (
        pkt.getlayer(NBNSQueryResponse) if pkt.haslayer(NBNSQueryResponse) else None)
    src = pkt[IP].src
    kb.observe_host(src, source="nbns")
    for fld in ("RR_NAME", "QUESTION_NAME", "NETBIOS_NAME"):
        val = None
        try:
            val = pkt.getfieldval(fld)
        except Exception:
            val = None
        if val:
            try:
                name = (val.decode(errors="ignore")
                        if isinstance(val, (bytes, bytearray)) else str(val))
                name = name.strip().strip("\x00").rstrip()
                if name and name not in ("*",):
                    kb.add_hostname(src, name[:15].strip(), "nbns")
                    break
            except Exception:
                pass


def diss_ssdp(pkt, kb):
    """SSDP / UPnP (UDP 1900). Pull LOCATION host and SERVER string."""
    src = pkt[IP].src if pkt.haslayer(IP) else None
    if not src:
        return
    try:
        payload = bytes(pkt[UDP].payload).decode(errors="ignore")
    except Exception:
        return
    kb.observe_host(src, source="ssdp")
    kb.note_service(src, "udp", 1900)
    m = re.search(r"SERVER:\s*([^\r\n]+)", payload, re.I)
    if m:
        kb.note_fingerprint(src, "ssdp:%s" % m.group(1).strip()[:40])
    m = re.search(r"LOCATION:\s*https?://([\d.]+)", payload, re.I)
    if m and is_rfc1918(m.group(1)):
        kb.observe_host(m.group(1), source="ssdp:location")


def diss_wsd(pkt, kb):
    """WS-Discovery (UDP 3702). Pull XAddrs host and Types."""
    src = pkt[IP].src if pkt.haslayer(IP) else None
    if not src:
        return
    try:
        payload = bytes(pkt[UDP].payload).decode(errors="ignore")
    except Exception:
        return
    kb.observe_host(src, source="wsd")
    for host in re.findall(r"https?://([\d.]+)", payload):
        if is_rfc1918(host):
            kb.observe_host(host, source="wsd:xaddr")
    m = re.search(r"<[^>]*Types>([^<]+)<", payload)
    if m:
        kb.note_fingerprint(src, "wsd:%s" % m.group(1).strip()[:32])


def diss_browser(pkt, kb):
    """SMB/NetBIOS Browser announcements (MS-BRWS) over UDP 138. Hosts
    self-report computer name, OS version, an optional comment, and a
    ServerType role bitmask, with no probing required."""
    if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="browser")
    try:
        raw = bytes(pkt[UDP].payload)
    except Exception:
        return
    idx = raw.find(_BROWSE_TAG)
    if idx < 0:
        return
    data = raw[idx + len(_BROWSE_TAG):]
    if len(data) < 28 or data[0] not in _BROWSE_OPS:
        return
    opcode = data[0]
    name = data[6:22].split(b"\x00", 1)[0].decode(errors="ignore").strip()
    if opcode == 0x0c:                       # domain/workgroup announcement
        if name:
            kb.note_fingerprint(src, "workgroup:%s" % name[:24])
        kb.tag_role(src, "browser/master")
        return
    if name:
        kb.add_hostname(src, name, "browser")
    kb.note_fingerprint(src, "browser-os:%d.%d" % (data[22], data[23]))
    srv_type = struct.unpack_from("<I", data, 24)[0]
    for bit, role in SV_TYPE_FLAGS.items():
        if srv_type & bit:
            kb.tag_role(src, role)
    if len(data) > 32:
        comment = data[32:].split(b"\x00", 1)[0].decode(errors="ignore").strip()
        if comment:
            kb.note_fingerprint(src, "browser-comment:%s" % comment[:40])


def diss_slp(pkt, kb):
    """Service Location Protocol (UDP 427). Records the responder, the
    advertised service schemes, and any RFC1918 hosts named in service URLs."""
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="slp")
    kb.note_service(src, "udp", 427)
    try:
        payload = bytes(pkt[UDP].payload)
    except Exception:
        return
    for m in re.findall(rb"service:([A-Za-z0-9_.\-]+)", payload)[:3]:
        kb.note_fingerprint(src, "slp:%s" % m.decode(errors="ignore")[:24])
    for h in re.findall(rb"(\d{1,3}(?:\.\d{1,3}){3})", payload):
        ip = h.decode()
        if is_rfc1918(ip):
            kb.observe_host(ip, source="slp:url")


def diss_mssql(pkt, kb):
    """SQL Server Resolution Protocol (UDP 1434). Response frames name the
    instance and its TCP port."""
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="mssql-browser")
    try:
        payload = bytes(pkt[UDP].payload)
    except Exception:
        return
    if not payload or payload[0] != 0x05:    # 0x05 = SVR_RESP
        return
    body = payload[3:].decode(errors="ignore")
    kb.tag_role(src, "db/mssql")
    m = re.search(r"ServerName;([^;]+)", body)
    if m:
        kb.add_hostname(src, m.group(1).strip(), "mssql-browser")
    inst = re.search(r"InstanceName;([^;]+)", body)
    if inst:
        kb.note_fingerprint(src, "mssql-instance:%s" % inst.group(1).strip()[:24])
    port = re.search(r"tcp;(\d+)", body)
    if port:
        kb.note_service(src, "tcp", int(port.group(1)))


def diss_dropbox(pkt, kb):
    """Dropbox LAN Sync Discovery (UDP 17500). JSON beacon naming the host."""
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="dropbox")
    kb.note_fingerprint(src, "dropbox-lansync")
    try:
        obj = json.loads(bytes(pkt[UDP].payload).decode(errors="ignore"))
    except Exception:
        return
    name = obj.get("displayname")
    if name:
        kb.add_hostname(src, str(name)[:32], "dropbox")


def diss_mndp(pkt, kb):
    """MikroTik Neighbor Discovery (UDP 5678). TLV beacon with identity,
    platform, and version."""
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="mndp")
    kb.tag_role(src, "net-gear")
    kb.note_fingerprint(src, "mikrotik")
    try:
        raw = bytes(pkt[UDP].payload)
    except Exception:
        return
    i = 4                                    # 2-byte header + 2-byte sequence
    while i + 4 <= len(raw):
        ttype, tlen = struct.unpack_from(">HH", raw, i)
        i += 4
        val = raw[i:i + tlen]
        i += tlen
        label = _MNDP_TLV.get(ttype)
        if not label or not val:
            continue
        text = val.decode(errors="ignore").strip("\x00").strip()
        if not text:
            continue
        if label == "identity":
            kb.add_hostname(src, text[:32], "mndp")
        else:
            kb.note_fingerprint(src, "mndp-%s:%s" % (label, text[:24]))


def diss_ubnt(pkt, kb):
    """Ubiquiti device discovery (UDP 10001). TLV response with hostname,
    model, firmware, and embedded MAC+IP records."""
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="ubnt")
    kb.tag_role(src, "net-gear")
    kb.note_fingerprint(src, "ubiquiti")
    try:
        raw = bytes(pkt[UDP].payload)
    except Exception:
        return
    if len(raw) < 4:
        return
    i = 4                                    # version(1) cmd(1) length(2)
    while i + 3 <= len(raw):
        ttype = raw[i]
        tlen  = struct.unpack_from(">H", raw, i + 1)[0]
        i += 3
        val = raw[i:i + tlen]
        i += tlen
        if ttype == 0x02 and len(val) >= 10:  # MAC(6) + IPv4(4)
            ip = ".".join(str(b) for b in val[6:10])
            if is_rfc1918(ip):
                kb.observe_host(ip, source="ubnt:record")
            continue
        label = _UBNT_TLV.get(ttype)
        if not label or not val:
            continue
        text = val.decode(errors="ignore").strip("\x00").strip()
        if not text:
            continue
        if label == "hostname":
            kb.add_hostname(src, text[:32], "ubnt")
        else:
            kb.note_fingerprint(src, "ubnt-%s:%s" % (label, text[:24]))

def diss_stp(pkt, kb):
    if not _CAPS["stp"] or not pkt.haslayer(STP):
        return
    rootmac = getattr(pkt[STP], "rootmac", None)
    if rootmac:
        kb.note_gateway(mac=str(rootmac), source="stp:root")


def diss_dtp(pkt, kb):
    """DTP presence signals a switch port willing to negotiate a trunk,
    the precondition for VLAN hopping. Log it loudly."""
    if not _CAPS["dtp"] or not pkt.haslayer(DTP):
        return
    eth = pkt.getlayer(Ether)
    smac = eth.src if eth else "?"
    kb.note_gateway(mac=smac, source="dtp:trunk-capable")
    kb.log.write("DTP   %-17s  trunk negotiation observed (vlan-hop candidate)" % smac)


def diss_vtp(pkt, kb):
    if not _CAPS["vtp"]:
        return
    try:
        from scapy.contrib.vtp import VTP
    except Exception:
        return
    if not pkt.haslayer(VTP):
        return
    dom = getattr(pkt[VTP], "DomainName", None)
    if dom:
        try:
            dom = dom.decode(errors="ignore").strip("\x00")
        except Exception:
            dom = str(dom)
        kb.log.write("VTP   domain=%s" % dom)


def diss_dhcp6(pkt, kb):
    if not pkt.haslayer(DHCP6) or not pkt.haslayer(IPv6):
        return
    src = pkt[IPv6].src
    if src and src != "::":
        kb.observe_host(src, source="dhcp6")


def diss_igmp(pkt, kb):
    """IGMP / MLD membership reports reveal the joining host and that it
    runs a multicast application."""
    if _CAPS["igmp"] and IGMP is not None and pkt.haslayer(IGMP) and pkt.haslayer(IP):
        kb.observe_host(pkt[IP].src, source="igmp")
    if _CAPS["mld"]:
        for cls in (ICMPv6MLReport, ICMPv6MLReport2):
            if cls is not None and pkt.haslayer(cls) and pkt.haslayer(IPv6):
                src = pkt[IPv6].src
                if src and src != "::":
                    kb.observe_host(src, source="mld")


def diss_snmp(pkt, kb):
    """SNMP v1/v2c. Capture cleartext community strings and tag the host."""
    if not _CAPS["snmp"] or not pkt.haslayer(SNMP) or not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    kb.observe_host(src, source="snmp")
    kb.tag_role(src, "snmp")
    try:
        comm = pkt[SNMP].community.val
        comm = comm.decode(errors="ignore") if isinstance(comm, (bytes, bytearray)) else str(comm)
        if comm:
            kb.note_fingerprint(src, "snmp-community:%s" % comm[:24])
            kb.log.write("SNMP  %-18s  community=%s" % (src, comm[:24]))
    except Exception:
        pass


def diss_traffic(pkt, kb):
    if not pkt.haslayer(Ether):
        return
    eth = pkt[Ether]
    vlan = pkt[Dot1Q].vlan if pkt.haslayer(Dot1Q) else 0

    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec = kb.observe_host(ip.src, mac=eth.src, source="traffic")
        if rec is not None:
            if vlan:
                rec.vlan = vlan
            osf, hops = ttl_os(int(ip.ttl))
            kb.note_fingerprint(ip.src, "ttl:%d/%s/%dhop" % (int(ip.ttl), osf, hops))
        if is_unicast_mac(eth.dst):
            kb.observe_host(ip.dst, source="traffic")
            kb.correlate(ip.src, ip.dst, eth.dst)
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            flags = int(t.flags)
            if (flags & 0x12) == 0x12:           # SYN-ACK: src is a listening server
                kb.note_service(ip.src, "tcp", int(t.sport), confirmed=True)
            elif int(t.dport) in ROLE_PORTS:     # client reaching a known service
                kb.note_service(ip.dst, "tcp", int(t.dport))
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            if int(u.dport) in ROLE_PORTS:
                kb.note_service(ip.dst, "udp", int(u.dport))
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
        if _CAPS["stp"] and pkt.haslayer(STP):
            diss_stp(pkt, kb)
        if _CAPS["dtp"] and pkt.haslayer(DTP):
            diss_dtp(pkt, kb)
        if _CAPS["vtp"]:
            diss_vtp(pkt, kb)
        if pkt.haslayer(NBNSQueryResponse) or pkt.haslayer("NBNSHeader"):
            diss_nbns(pkt, kb)
        _mc = [c for c in (IGMP if _CAPS["igmp"] else None,
                           ICMPv6MLReport, ICMPv6MLReport2) if c is not None]
        if any(pkt.haslayer(c) for c in _mc):
            diss_igmp(pkt, kb)
        if _CAPS["snmp"] and pkt.haslayer(SNMP):
            diss_snmp(pkt, kb)
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
            elif dport == 1900 or sport == 1900:
                diss_ssdp(pkt, kb)
            elif dport == 3702 or sport == 3702:
                diss_wsd(pkt, kb)
            elif dport == 138 or sport == 138:
                diss_browser(pkt, kb)
            elif dport == 427 or sport == 427:
                diss_slp(pkt, kb)
            elif dport == 1434 or sport == 1434:
                diss_mssql(pkt, kb)
            elif dport == 17500 or sport == 17500:
                diss_dropbox(pkt, kb)
            elif dport == 5678 or sport == 5678:
                diss_mndp(pkt, kb)
            elif dport == 10001 or sport == 10001:
                diss_ubnt(pkt, kb)
        if pkt.haslayer(TCP) and (pkt[TCP].dport == 53 or pkt[TCP].sport == 53):
            diss_dns_like(pkt, kb, "dns")
        if pkt.haslayer(ICMPv6ND_RA) or pkt.haslayer(ICMPv6ND_NS) or pkt.haslayer(ICMPv6ND_NA):
            diss_ipv6_nd(pkt, kb)
        diss_traffic(pkt, kb)
    except Exception as ex:
        kb.log.write("ERR   dissect: %s" % ex)

def diss_ipv6_nd(pkt, kb):
    src = pkt[IPv6].src if pkt.haslayer(IPv6) else None
    if pkt.haslayer(ICMPv6ND_RA):
        if src:
            kb.note_gateway(ip=src, source="ipv6:ra")
        opt = pkt.getlayer(ICMPv6NDOptPrefixInfo)
        while opt is not None:
            prefix = getattr(opt, "prefix",     None)
            plen   = getattr(opt, "prefixlen",  None)
            if prefix and plen:
                kb.add_subnet("%s/%d" % (prefix, plen), CONF_ROUTED, "ipv6:ra", "ra-prefix")
            opt = opt.payload.getlayer(ICMPv6NDOptPrefixInfo)
    for cls in (ICMPv6ND_NS, ICMPv6ND_NA):
        if pkt.haslayer(cls) and src and src != "::":
            kb.observe_host(src, source="ipv6:nd")

# ---------------------------------------------------------------------------
# Active sweep functions (require root / raw sockets)
# ---------------------------------------------------------------------------

def _expand_targets(cidrs, runlog, max_hosts=MAX_SWEEP_HOSTS):
    """Expand CIDR strings and individual IPs to a flat IPv4 host list."""
    hosts = []
    for entry in cidrs:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            net = ip_network(entry, strict=False)
        except ValueError:
            try:
                hosts.append(ip_address(entry))
            except ValueError:
                runlog.write("WARN  invalid target skipped: %s" % entry)
            continue
        if net.version == 6:
            continue
        hl = list(net.hosts()) if net.prefixlen < 32 else [net.network_address]
        if len(hosts) + len(hl) > max_hosts:
            remaining = max_hosts - len(hosts)
            runlog.write("WARN  host limit %d reached at %s, truncating" % (
                max_hosts, entry))
            hosts.extend(hl[:remaining])
            break
        hosts.extend(hl)
    return hosts


def arp_sweep(targets, iface, kb, rate, timeout):
    """Broadcast ARP sweep. Effective for on-link (L2-reachable) targets only."""
    kb.log.write("SWEEP arp   hosts=%-6d  iface=%-10s  rate=%d/s" % (
        len(targets), iface, rate))
    inter = 1.0 / max(1, rate)
    found = 0
    for i in range(0, len(targets), SWEEP_BATCH):
        batch = targets[i:i + SWEEP_BATCH]
        pkts  = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))
                 for ip in batch]
        try:
            ans, _ = srp(pkts, iface=iface, timeout=timeout, inter=inter, verbose=0)
            for _, rcv in ans:
                if rcv.haslayer(ARP) and rcv[ARP].op == 2:
                    a = rcv[ARP]
                    kb.observe_host(a.psrc, mac=a.hwsrc, source="arp-sweep")
                    found += 1
        except Exception as ex:
            kb.log.write("ERR   arp-sweep: %s" % ex)
    kb.log.write("SWEEP arp   done  found=%d" % found)
    return found


def icmp_sweep(targets, kb, rate, timeout):
    """ICMP echo sweep. Works for both on-link and routed targets."""
    kb.log.write("SWEEP icmp  hosts=%-6d  rate=%d/s" % (len(targets), rate))
    inter = 1.0 / max(1, rate)
    found = 0
    for i in range(0, len(targets), SWEEP_BATCH):
        batch = targets[i:i + SWEEP_BATCH]
        pkts  = [IP(dst=str(ip)) / ICMP(id=0xEC11, seq=(i + j) & 0xffff)
                 for j, ip in enumerate(batch)]
        try:
            ans, _ = sr(pkts, timeout=timeout, inter=inter, verbose=0)
            for _, rcv in ans:
                if rcv.haslayer(ICMP) and rcv[ICMP].type == 0:
                    kb.observe_host(rcv[IP].src, source="icmp-sweep")
                    found += 1
        except Exception as ex:
            kb.log.write("ERR   icmp-sweep: %s" % ex)
    kb.log.write("SWEEP icmp  done  found=%d" % found)
    return found


def icmp_mask_sweep(targets, kb, rate, timeout):
    """ICMP Address Mask Request (type 17) against known-live hosts.
    Low yield on modern OS; useful for legacy gear and some embedded devices."""
    kb.log.write("SWEEP mask  hosts=%-6d  rate=%d/s" % (len(targets), rate))
    inter = 1.0 / max(1, rate)
    found = 0
    for i in range(0, len(targets), SWEEP_BATCH):
        batch = targets[i:i + SWEEP_BATCH]
        pkts  = [IP(dst=str(ip)) / ICMP(type=17, seq=(i + j) & 0xffff)
                 for j, ip in enumerate(batch)]
        try:
            ans, _ = sr(pkts, timeout=timeout, inter=inter, verbose=0)
            for _, rcv in ans:
                if rcv.haslayer(ICMP) and rcv[ICMP].type == 18:
                    src  = rcv[IP].src
                    mask = rcv[ICMP].addr_mask
                    if mask:
                        try:
                            pl = ip_network("0.0.0.0/%s" % mask).prefixlen
                            kb.add_subnet("%s/%d" % (src, pl), CONF_CONFIRMED,
                                          "icmp:type18", "icmp-mask-reply")
                            found += 1
                        except ValueError:
                            pass
        except Exception as ex:
            kb.log.write("ERR   icmp-mask-sweep: %s" % ex)
    kb.log.write("SWEEP mask  done  replies=%d" % found)
    return found

# ---------------------------------------------------------------------------
# Recon engine
# ---------------------------------------------------------------------------

class ReconEngine:
    def __init__(self, iface_info, outdir, rate, probe_timeout,
                 do_arp, do_icmp, do_mask, max_hosts, scope=None, echo=True):
        self.iface_info    = iface_info
        self.iface_names   = [i[0] for i in iface_info]
        self.rate          = rate
        self.probe_timeout = probe_timeout
        self.do_arp        = do_arp
        self.do_icmp       = do_icmp
        self.do_mask       = do_mask
        self.max_hosts     = max_hosts
        self.outdir        = outdir
        self.sweep_queue   = queue.Queue()
        self._swept        = set()
        self._stop         = threading.Event()
        self._down         = False
        self.runlog, self.feed, self.ts = open_outputs(outdir, echo=echo)
        self.kb = KnowledgeBase(self.runlog, self.feed, self.sweep_queue, scope)
        self.sniffer      = None
        self.sweep_thread = None

    def _iface_for_subnet(self, cidr):
        try:
            net = ip_network(cidr, strict=False)
            for name, ip, _ in self.iface_info:
                if ip_address(ip) in net:
                    return name
        except Exception:
            pass
        return self.iface_names[0]

    def _seed_local_subnets(self):
        for name, ip, cidr in self.iface_info:
            self.kb.observe_host(ip, source="local:%s" % name)
            self.kb.add_subnet(cidr, CONF_CONFIRMED,
                               "local-iface:%s" % name, "iface-config")

    def _sweep_worker(self):
        while not self._stop.is_set():
            try:
                cidr = self.sweep_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                if cidr in self._swept:
                    continue
                self._swept.add(cidr)
                targets = _expand_targets([cidr], self.kb.log, self.max_hosts)
                if not targets:
                    continue
                iface = self._iface_for_subnet(cidr)
                if self.do_arp:
                    arp_sweep(targets, iface, self.kb, self.rate, self.probe_timeout)
                if self.do_icmp:
                    icmp_sweep(targets, self.kb, self.rate, self.probe_timeout)
            except Exception as ex:
                self.kb.log.write("ERR   sweep-worker: %s" % ex)
            finally:
                self.sweep_queue.task_done()

    def _banner_lines(self):
        sweeps = " + ".join(
            s for s, e in [("ARP", self.do_arp), ("ICMP", self.do_icmp),
                            ("mask-req", self.do_mask)] if e)
        return [
            "passive_recon  |  passive + active parallel mode",
            "interface(s) : %s" % ", ".join(
                "%s (%s)" % (n, cidr) for n, _, cidr in self.iface_info),
            "targets      : %s" % os.path.join(self.outdir, "targets.txt"),
            "subnets      : %s" % os.path.join(self.outdir, "subnets.txt"),
            "log          : %s" % os.path.join(self.outdir, "recon_%s.log" % self.ts),
            "rate         : %d probes/s   timeout: %.1fs" % (self.rate, self.probe_timeout),
            "sweeps       : %s" % (sweeps or "none"),
            "caps         : %s" % ", ".join(k for k, v in _CAPS.items() if v),
        ]

    def _print_banner(self):
        print()
        for ln in self._banner_lines():
            print("    " + ln)
        print()
        print("    tail -f %s" % os.path.join(self.outdir, "recon_%s.log" % self.ts))
        print("    ^C to stop\n")

    def _drain_queue(self):
        discarded = 0
        while True:
            try:
                self.sweep_queue.get_nowait()
                discarded += 1
            except queue.Empty:
                break
        return discarded

    def start(self):
        """Spin up sniffer + sweep worker. Non-blocking."""
        self._seed_local_subnets()
        self.sweep_thread = threading.Thread(
            target=self._sweep_worker, daemon=True, name="sweep-worker")
        self.sweep_thread.start()
        self.sniffer = AsyncSniffer(
            iface=self.iface_names, store=False,
            prn=lambda p: dispatch(p, self.kb))
        self.runlog.write("START ifaces=%s  rate=%d  arp=%s  icmp=%s  mask=%s" % (
            ",".join(self.iface_names), self.rate,
            self.do_arp, self.do_icmp, self.do_mask))
        self.sniffer.start()

    def shutdown(self):
        """Stop capture, finish in-flight sweep, run mask sweep, export."""
        if self._down:
            return
        self._down = True
        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception:
            pass
        self._stop.set()
        discarded = self._drain_queue()
        self.runlog.write("INFO  stopping  discarded=%d" % discarded)
        if self.sweep_thread:
            self.sweep_thread.join(timeout=self.probe_timeout * 2 + 3)
        if self.do_mask:
            live = list(self.kb.hosts.keys())
            if live:
                icmp_mask_sweep(live, self.kb, self.rate, self.probe_timeout)
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
# Textual TUI
# ---------------------------------------------------------------------------

def run_tui(engine):
    """Live status TUI. Lazy-imports textual so the rest of the tool runs
    without it. Returns False if textual is unavailable."""
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Vertical
        from textual.screen import ModalScreen
        from textual.widgets import Static, RichLog, TextArea, Button, Label
    except Exception:
        return False

    class PasteScreen(ModalScreen):
        BINDINGS = [("escape", "cancel", "Cancel")]

        def compose(self):
            with Vertical(id="paste-box"):
                yield Label("Paste routing table or target list, then Apply "
                            "(ip route / route -n / route print / show ip route / IPs)")
                yield TextArea(id="paste-area")
                yield Button("Apply", id="apply", variant="success")
                yield Button("Cancel", id="cancel", variant="error")

        def on_button_pressed(self, event):
            if event.button.id == "apply":
                text = self.query_one("#paste-area", TextArea).text
                subs, gws, hosts = parse_routes(text)
                ns, ng, nh = apply_parsed(engine.kb, subs, gws, hosts, "manual:paste")
                self.app.notify("Added %d subnets, %d gateways, %d hosts" % (ns, ng, nh))
            self.app.pop_screen()

        def action_cancel(self):
            self.app.pop_screen()

    class ReconTUI(App):
        CSS = """
        #status { height: auto; padding: 1 2; background: $panel; }
        #log { height: 1fr; border: round $primary; }
        #paste-box { width: 80%; height: 80%; border: thick $primary;
                     background: $surface; padding: 1 2; }
        #paste-area { height: 1fr; }
        Button { margin: 1 1 0 0; }
        """
        BINDINGS = [
            ("ctrl+a", "add_targets", "Add targets"),
            ("q", "quit", "Quit"),
        ]

        def compose(self):
            yield Static(id="status")
            yield RichLog(id="log", highlight=False, markup=False, wrap=False)

        def on_mount(self):
            engine.runlog.echo = False
            engine.runlog.sink = lambda line: self.call_from_thread(
                self.query_one("#log", RichLog).write, line)
            log = self.query_one("#log", RichLog)
            for ln in engine._banner_lines():
                log.write(ln)
            engine.start()
            self.set_interval(0.5, self._refresh)
            self._refresh()

        def _refresh(self):
            hosts   = len(engine.feed.seen_hosts)
            subnets = len(engine.feed.seen_subnets)
            gws     = len(engine.kb.gateway_ips)
            queued  = engine.sweep_queue.qsize()
            now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.query_one("#status", Static).update(
                "[b]passive_recon[/b]   %s\n"
                "single targets: [b]%d[/b]    cidr targets: [b]%d[/b]    "
                "gateways: [b]%d[/b]    sweep queue: [b]%d[/b]\n"
                "ctrl+a paste routes/targets    q quit" % (
                    now, hosts, subnets, gws, queued))

        def action_add_targets(self):
            self.push_screen(PasteScreen())

        def on_unmount(self):
            engine.shutdown()

    ReconTUI().run()
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
        iface_info    = selected,
        outdir        = args.outdir,
        rate          = args.rate,
        probe_timeout = args.probe_timeout,
        do_arp        = args.arp,
        do_icmp       = args.icmp,
        do_mask       = args.mask_request,
        max_hosts     = args.max_hosts,
        scope         = scope,
        echo          = not use_tui,
    )
    if use_tui and run_tui(engine):
        return
    engine.run()


def run_analyze(args):
    runlog, feed, ts = open_outputs(args.outdir)
    kb = KnowledgeBase(runlog, feed)          # no sweep_queue: passive-only
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
        description="Passive + active internal segment target expansion.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python3 passive_recon.py                       # full auto (TUI if available)
  sudo python3 passive_recon.py --no-tui              # plain line-log mode
  sudo python3 passive_recon.py -r 100 -t 1.0         # faster sweep
  sudo python3 passive_recon.py --no-arp              # ICMP only
  sudo python3 passive_recon.py --mask-request        # also probe ICMP type 17
  sudo python3 passive_recon.py --scope 10.0.0.0/8 --exclude 10.0.5.0/24
  python3 passive_recon.py analyze capture.pcap       # offline, no root
""")

    p.add_argument("-o", "--outdir",        default="recon_out",
                   help="output directory (default: recon_out)")
    p.add_argument("-r", "--rate",          type=int,   default=50,
                   help="active probe rate in probes/s (default: 50)")
    p.add_argument("-t", "--probe-timeout", type=float, default=2.0,
                   help="reply wait per batch in seconds (default: 2.0)")
    p.add_argument("--no-arp",  dest="arp",  action="store_false", default=True,
                   help="disable ARP sweep")
    p.add_argument("--no-icmp", dest="icmp", action="store_false", default=True,
                   help="disable ICMP echo sweep")
    p.add_argument("--mask-request", action="store_true", default=False,
                   help="send ICMP type 17 to live hosts at shutdown")
    p.add_argument("--max-hosts", type=int, default=MAX_SWEEP_HOSTS,
                   help="max hosts to expand per CIDR (default: %d)" % MAX_SWEEP_HOSTS)
    p.add_argument("--scope", action="append", metavar="CIDR",
                   help="restrict targets to CIDR (repeatable)")
    p.add_argument("--exclude", action="append", metavar="CIDR",
                   help="exclude CIDR from targets (repeatable)")
    p.add_argument("--no-tui", action="store_true", default=False,
                   help="disable the Textual TUI; use plain line-log output")
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
