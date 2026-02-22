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
"""
Management WiFi Setup
Handles interface selection, hostapd configuration, and DHCP service.

Usage:
    sudo python3 wireless-mgmt.py              # Normal start (first run triggers setup wizard)
    sudo python3 wireless-mgmt.py reconfigure  # Re-run setup wizard
    sudo python3 wireless-mgmt.py install      # Install as systemd service
    sudo python3 wireless-mgmt.py status       # Show service status
    sudo python3 wireless-mgmt.py stop         # Stop all services

Internal:
    python3 wireless-mgmt.py --dhcp-server <config_path>  # DHCP subprocess (do not call directly)
"""

import os
import sys
import json
import subprocess
import time
import ipaddress
from pathlib import Path

# Config and log paths
SCRIPT_DIR   = Path(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE  = SCRIPT_DIR / "mgmt-wifi.json"
HOSTAPD_CONF = "/etc/hostapd/mgmt-hostapd.conf"
HOSTAPD_LOG  = "/tmp/mgmt-hostapd.log"
DHCP_LOG     = "/tmp/mgmt-dhcp.log"


# ─── Utilities ────────────────────────────────────────────────────────────────

def run_cmd(cmd, check=False):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr.strip()}")
    return result


def get_interfaces():
    """Return list of active network interfaces, excluding loopback."""
    result = run_cmd("ip -o link show")
    ifaces = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(': ')
        if len(parts) < 2:
            continue
        name = parts[1].split('@')[0].strip()
        if name != 'lo':
            ifaces.append(name)
    return ifaces


def iface_info(iface):
    """Return a brief description line for an interface."""
    addr_result = run_cmd(f"ip addr show {iface} | grep -E 'link/|inet '")
    lines = [l.strip() for l in addr_result.stdout.strip().splitlines()]
    return ' | '.join(lines) if lines else 'no address'


def select_interface(prompt, exclude=None):
    """Interactive interface selection with detail display."""
    ifaces = [i for i in get_interfaces() if i != exclude]
    if not ifaces:
        print("ERROR: No suitable interfaces found.")
        sys.exit(1)

    print(f"\n{prompt}")
    print("-" * 60)
    for idx, iface in enumerate(ifaces, 1):
        print(f"  {idx}) {iface}")
        print(f"       {iface_info(iface)}")
    print("-" * 60)

    while True:
        try:
            choice = int(input("Select interface number: ").strip())
            if 1 <= choice <= len(ifaces):
                return ifaces[choice - 1]
        except (ValueError, EOFError):
            pass
        print("  Invalid selection — try again.")


# ─── Configuration ────────────────────────────────────────────────────────────

def first_run_setup():
    """Interactive first-run wizard. Builds and persists config."""
    print("\n" + "=" * 60)
    print("  Management WiFi — First Run Setup")
    print("=" * 60)

    mgmt_iface = select_interface("Select the OUT-OF-BAND MANAGEMENT interface (AP will run here):")
    inet_iface = select_interface("Select the INTERNET / WAN interface:", exclude=mgmt_iface)

    print()
    ssid = input("Enter management network SSID: ").strip()
    while not ssid:
        ssid = input("SSID cannot be empty. Enter SSID: ").strip()

    psk = input("Enter WPA2 passphrase (min 8 characters): ").strip()
    while len(psk) < 8:
        print("  Passphrase must be at least 8 characters.")
        psk = input("Enter WPA2 passphrase: ").strip()

    config = {
        # Interface assignment
        "management_interface": mgmt_iface,
        "internet_interface":   inet_iface,

        # Credentials
        "ssid": ssid,
        "psk":  psk,

        # Management network addressing
        "ip_address":   "192.168.255.254",
        "subnet_mask":  "255.255.255.0",
        "subnet_cidr":  "192.168.255.0/24",
        "dhcp_start":   "192.168.255.100",
        "dhcp_end":     "192.168.255.200",
        "lease_time":   3600,

        # Hostapd radio parameters (best-practice defaults)
        "hw_mode":      "g",        # 2.4 GHz — broadest device compatibility
        "channel":      6,          # Non-overlapping channel (1, 6, or 11)
        "country_code": "US",
        "ieee80211n":   1,          # Enable HT (802.11n) for throughput
        "ht_capab":     "[HT40+][SHORT-GI-20][SHORT-GI-40]",
        "wmm_enabled":  1,          # Required for 802.11n
        "ieee80211w":   1,          # MFP optional — drops to 0 for incompatible clients
    }

    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)

    print(f"\n  Configuration saved to: {CONFIG_FILE}")
    return config


def load_config():
    """Load config from disk, running first-run wizard if not present."""
    if not CONFIG_FILE.exists():
        return first_run_setup()
    with open(CONFIG_FILE) as f:
        return json.load(f)


# ─── Hostapd ──────────────────────────────────────────────────────────────────

def write_hostapd_config(cfg):
    """Write hostapd.conf from config. WPA2-only, CCMP-only, MFP enabled."""
    conf = f"""# Management WiFi — hostapd configuration
# Auto-generated by wireless-mgmt.py — edit mgmt-wifi.json and restart to change.

interface={cfg['management_interface']}
driver=nl80211

# Network identity
ssid={cfg['ssid']}
ignore_broadcast_ssid=0

# Radio
hw_mode={cfg['hw_mode']}
channel={cfg['channel']}
country_code={cfg['country_code']}

# 802.11n / HT
ieee80211n={cfg['ieee80211n']}
ht_capab={cfg['ht_capab']}
wmm_enabled={cfg['wmm_enabled']}

# Client access control
macaddr_acl=0
auth_algs=1

# WPA2-Personal — CCMP only, no TKIP
wpa=2
wpa_passphrase={cfg['psk']}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# Management Frame Protection — optional (1=capable, 2=required)
ieee80211w={cfg['ieee80211w']}
"""
    tmp = "/tmp/mgmt-hostapd.conf"
    with open(tmp, 'w') as f:
        f.write(conf)
    run_cmd(f"sudo mv {tmp} {HOSTAPD_CONF}")
    run_cmd(f"sudo chmod 600 {HOSTAPD_CONF}")
    print(f"  Hostapd config written to {HOSTAPD_CONF}")


def start_hostapd():
    run_cmd("sudo pkill -f 'hostapd /etc/hostapd/mgmt-hostapd.conf'")
    time.sleep(1)
    run_cmd(f"sudo nohup hostapd {HOSTAPD_CONF} > {HOSTAPD_LOG} 2>&1 &")
    time.sleep(3)

    result = run_cmd("sudo pgrep -f 'hostapd /etc/hostapd/mgmt-hostapd.conf'")
    if result.returncode == 0:
        print(f"  Hostapd started (PID: {result.stdout.strip()})")
        return True
    else:
        print(f"  WARNING: Hostapd failed to start. Check {HOSTAPD_LOG}")
        run_cmd(f"tail -5 {HOSTAPD_LOG}")
        return False


def stop_hostapd():
    run_cmd("sudo pkill -f 'hostapd /etc/hostapd/mgmt-hostapd.conf'")
    print("  Hostapd stopped.")


# ─── Interface Setup ──────────────────────────────────────────────────────────

def setup_interface(cfg):
    """Assign static IP to management interface and bring it up."""
    iface = cfg['management_interface']
    ip    = cfg['ip_address']

    check = run_cmd(f"ip addr show {iface} | grep 'inet {ip}'")
    if check.returncode != 0:
        run_cmd(f"sudo ip addr flush dev {iface}")
        run_cmd(f"sudo ip addr add {ip}/24 dev {iface}", check=True)

    run_cmd(f"sudo ip link set {iface} up", check=True)
    print(f"  Interface {iface} → {ip}/24")


# ─── DHCP Server ──────────────────────────────────────────────────────────────

def run_dhcp_server(cfg):
    """
    Scapy-based DHCP server loop.
    Invoked as a subprocess via --dhcp-server mode.
    Handles: DISCOVER → OFFER, REQUEST → ACK, RELEASE.
    """
    try:
        from scapy.all import (
            Ether, IP, UDP, BOOTP, DHCP,
            sendp, sniff, get_if_hwaddr, conf as scapy_conf
        )
    except ImportError:
        print("[DHCP] ERROR: scapy not installed. Run: pip install scapy")
        sys.exit(1)

    iface      = cfg['management_interface']
    server_ip  = cfg['ip_address']
    subnet     = cfg['subnet_mask']
    lease_time = cfg['lease_time']

    pool_start = ipaddress.IPv4Address(cfg['dhcp_start'])
    pool_end   = ipaddress.IPv4Address(cfg['dhcp_end'])
    pool       = [str(ipaddress.IPv4Address(i))
                  for i in range(int(pool_start), int(pool_end) + 1)]

    leases    = {}  # mac  → ip
    allocated = {}  # ip   → mac

    def assign_ip(mac):
        """Return existing or next free lease for a MAC address."""
        if mac in leases:
            return leases[mac]
        for ip in pool:
            if ip not in allocated:
                leases[mac]    = ip
                allocated[ip]  = mac
                return ip
        return None  # pool exhausted

    server_mac          = get_if_hwaddr(iface)
    scapy_conf.checkIPaddr = False

    def build_reply(msg_type, xid, chaddr, offered_ip):
        return (
            Ether(src=server_mac, dst='ff:ff:ff:ff:ff:ff') /
            IP(src=server_ip, dst='255.255.255.255') /
            UDP(sport=67, dport=68) /
            BOOTP(
                op=2,
                yiaddr=offered_ip,
                siaddr=server_ip,
                chaddr=chaddr,
                xid=xid,
            ) /
            DHCP(options=[
                ('message-type',  msg_type),
                ('server_id',     server_ip),
                ('lease_time',    lease_time),
                ('subnet_mask',   subnet),
                ('router',        server_ip),
                ('name_server',   '8.8.8.8', '8.8.4.4'),
                'end'
            ])
        )

    def handle_packet(pkt):
        if not pkt.haslayer(DHCP):
            return

        msg_type = None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'message-type':
                msg_type = opt[1]
                break
        if msg_type is None:
            return

        client_mac = pkt[Ether].src
        xid        = pkt[BOOTP].xid
        chaddr     = pkt[BOOTP].chaddr

        if msg_type == 1:  # DISCOVER
            offered_ip = assign_ip(client_mac)
            if not offered_ip:
                print(f"[DHCP] Pool exhausted — cannot offer to {client_mac}")
                return
            print(f"[DHCP] DISCOVER {client_mac} → offering {offered_ip}")
            sendp(build_reply('offer', xid, chaddr, offered_ip),
                  iface=iface, verbose=False)

        elif msg_type == 3:  # REQUEST
            # Prefer the server's existing lease; fall back to requested_addr option
            offered_ip = leases.get(client_mac)
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 'requested_addr':
                    offered_ip = opt[1]
                    break
            if not offered_ip:
                offered_ip = assign_ip(client_mac)
            if not offered_ip:
                print(f"[DHCP] Pool exhausted — NAK for {client_mac}")
                return

            # Ensure lease tables are consistent
            leases[client_mac]   = offered_ip
            allocated[offered_ip] = client_mac

            print(f"[DHCP] REQUEST  {client_mac} → ACK {offered_ip}")
            sendp(build_reply('ack', xid, chaddr, offered_ip),
                  iface=iface, verbose=False)

        elif msg_type == 7:  # RELEASE
            ip = leases.pop(client_mac, None)
            if ip:
                allocated.pop(ip, None)
                print(f"[DHCP] RELEASE  {client_mac} released {ip}")

    print(f"[DHCP] Server listening on {iface} ({server_ip})")
    print(f"[DHCP] Pool: {cfg['dhcp_start']} – {cfg['dhcp_end']}  "
          f"Lease: {lease_time}s")

    sniff(
        iface=iface,
        filter="udp and port 67",
        prn=handle_packet,
        store=0,
    )


def start_dhcp_server(cfg):
    """Launch the DHCP server as a detached subprocess."""
    script = os.path.abspath(__file__)
    cfg_path = str(CONFIG_FILE)

    log = open(DHCP_LOG, 'w')
    proc = subprocess.Popen(
        [sys.executable, script, '--dhcp-server', cfg_path],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # detach from parent's process group
    )

    time.sleep(2)
    if proc.poll() is None:
        print(f"  DHCP server started (PID: {proc.pid})")
    else:
        print(f"  WARNING: DHCP server failed to start. Check {DHCP_LOG}")


def stop_dhcp_server():
    script_name = os.path.basename(__file__)
    run_cmd(f"pkill -f '{script_name} --dhcp-server'")
    print("  DHCP server stopped.")


# ─── Systemd Service ──────────────────────────────────────────────────────────

def install_service():
    script   = os.path.abspath(__file__)
    work_dir = str(SCRIPT_DIR)

    service = f"""[Unit]
Description=RCS Management WiFi
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {script}
ExecStop=/usr/bin/python3 {script} stop
WorkingDirectory={work_dir}
User=root

[Install]
WantedBy=multi-user.target
"""
    tmp = "/tmp/mgmt-wifi.service"
    with open(tmp, 'w') as f:
        f.write(service)

    run_cmd("sudo mv /tmp/mgmt-wifi.service /etc/systemd/system/mgmt-wifi.service")
    run_cmd("sudo systemctl daemon-reload")
    run_cmd("sudo systemctl enable mgmt-wifi.service")
    print("  Systemd service installed and enabled (mgmt-wifi.service)")
    print("  Start now with: sudo systemctl start mgmt-wifi.service")


# ─── Status ───────────────────────────────────────────────────────────────────

def show_status(cfg):
    print("\n" + "=" * 60)
    print("  Management WiFi Status")
    print("=" * 60)

    # Hostapd
    r = run_cmd("pgrep -f 'hostapd /etc/hostapd/mgmt-hostapd.conf'")
    hostapd_status = f"Running (PID {r.stdout.strip()})" if r.returncode == 0 else "Not running"
    print(f"  Hostapd:       {hostapd_status}")

    # DHCP server
    script_name = os.path.basename(__file__)
    r = run_cmd(f"pgrep -f '{script_name} --dhcp-server'")
    dhcp_status = f"Running (PID {r.stdout.strip()})" if r.returncode == 0 else "Not running"
    print(f"  DHCP Server:   {dhcp_status}")

    # Interface
    iface = cfg['management_interface']
    r = run_cmd(f"ip addr show {iface} | grep 'inet '")
    addr = r.stdout.strip() if r.stdout.strip() else "No address assigned"
    print(f"  Interface:     {iface}  ({addr})")

    print(f"\n  SSID:          {cfg['ssid']}")
    print(f"  Gateway IP:    {cfg['ip_address']}")
    print(f"  DHCP Pool:     {cfg['dhcp_start']} – {cfg['dhcp_end']}")
    print(f"  Logs:          {HOSTAPD_LOG}  |  {DHCP_LOG}")
    print("=" * 60)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    # ── Internal DHCP subprocess mode ────────────────────────────────────────
    if len(sys.argv) > 1 and sys.argv[1] == '--dhcp-server':
        cfg_path = sys.argv[2] if len(sys.argv) > 2 else str(CONFIG_FILE)
        with open(cfg_path) as f:
            cfg = json.load(f)
        run_dhcp_server(cfg)
        return

    # ── CLI dispatch ─────────────────────────────────────────────────────────
    command = sys.argv[1] if len(sys.argv) > 1 else 'start'

    if command == 'install':
        load_config()   # ensure config exists before installing service
        install_service()
        return

    if command == 'reconfigure':
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        load_config()
        print("\nReconfiguration complete. Run without arguments to start.")
        return

    if command == 'stop':
        stop_hostapd()
        stop_dhcp_server()
        return

    if command == 'status':
        cfg = load_config()
        show_status(cfg)
        return

    # ── Start (default) ───────────────────────────────────────────────────────
    if os.geteuid() != 0:
        print("ERROR: Must run as root.  sudo python3 wireless-mgmt.py")
        sys.exit(1)

    cfg = load_config()

    print("\nStarting Management WiFi...")
    print("-" * 40)

    write_hostapd_config(cfg)
    setup_interface(cfg)
    start_dhcp_server(cfg)
    start_hostapd()

    print("-" * 40)
    print("\nManagement WiFi Active")
    print(f"  SSID:       {cfg['ssid']}")
    print(f"  Interface:  {cfg['management_interface']}")
    print(f"  Gateway:    {cfg['ip_address']}")
    print(f"  DHCP Pool:  {cfg['dhcp_start']} – {cfg['dhcp_end']}")
    print(f"\n  Note: Connect with a static IP if DHCP is unavailable during startup.")
    print(f"  Logs: {HOSTAPD_LOG}  |  {DHCP_LOG}\n")


if __name__ == "__main__":
    main()
