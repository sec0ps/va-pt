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

Usage:
    sudo python3 wireless-mgmt.py              # Start (first run triggers setup wizard)
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
    addr_result = run_cmd(f"ip addr show {iface} | grep -E 'link/|inet '")
    lines = [l.strip() for l in addr_result.stdout.strip().splitlines()]
    return ' | '.join(lines) if lines else 'no address'


def select_interface(prompt, exclude=None):
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
        "management_interface": mgmt_iface,
        "internet_interface":   inet_iface,
        "ssid":       ssid,
        "psk":        psk,
        "ip_address": "192.168.255.254",
        "subnet_mask": "255.255.255.0",
        "subnet_cidr": "192.168.255.0/24",
        "dhcp_start":  "192.168.255.100",
        "dhcp_end":    "192.168.255.200",
        "lease_time":  3600,
        "hw_mode":     "g",
        "channel":     1,
    }

    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(CONFIG_FILE, 0o600)

    print(f"\n  Configuration saved to: {CONFIG_FILE}")
    return config


def load_config():
    if not CONFIG_FILE.exists():
        return first_run_setup()
    with open(CONFIG_FILE) as f:
        return json.load(f)


# ─── Hostapd ──────────────────────────────────────────────────────────────────

def write_hostapd_config(cfg):
    conf = f"""interface={cfg['management_interface']}
driver=nl80211
ssid={cfg['ssid']}
ignore_broadcast_ssid=0
hw_mode={cfg['hw_mode']}
channel={cfg['channel']}
auth_algs=1
macaddr_acl=0
wpa=2
wpa_passphrase={cfg['psk']}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
    tmp = "/tmp/mgmt-hostapd.conf"
    with open(tmp, 'w') as f:
        f.write(conf)
    run_cmd(f"sudo mv {tmp} {HOSTAPD_CONF}")
    run_cmd(f"sudo chmod 600 {HOSTAPD_CONF}")
    print(f"  Hostapd config written to {HOSTAPD_CONF}")


def start_hostapd():
    # Set regulatory domain before starting — prevents channel validation failures
    run_cmd("sudo iw reg set US")
    time.sleep(1)

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
    import socket
    import struct

    iface      = cfg['management_interface']
    server_ip  = cfg['ip_address']
    offer_ip   = cfg['dhcp_start']
    subnet     = cfg['subnet_mask']

    leases = {}  # mac → ip

    def parse_mac(chaddr):
        return ':'.join(f'{b:02x}' for b in chaddr[:6])

    def ip_to_bytes(ip):
        return bytes(int(x) for x in ip.split('.'))

    def build_reply(xid, chaddr, your_ip, msg_type, server_ip):
        # BOOTP fixed fields
        pkt  = struct.pack('!BBBB', 2, 1, 6, 0)  # op, htype, hlen, hops
        pkt += struct.pack('!I', xid)              # xid
        pkt += struct.pack('!HH', 0, 0)            # secs, flags
        pkt += bytes(4)                            # ciaddr
        pkt += ip_to_bytes(your_ip)                # yiaddr
        pkt += ip_to_bytes(server_ip)              # siaddr
        pkt += bytes(4)                            # giaddr
        pkt += chaddr[:16]                         # chaddr (16 bytes)
        pkt += bytes(64)                           # sname
        pkt += bytes(128)                          # file
        pkt += bytes([99, 130, 83, 99])            # magic cookie

        # DHCP options
        pkt += bytes([53, 1, msg_type])            # message type
        pkt += bytes([54, 4]) + ip_to_bytes(server_ip)  # server id
        pkt += bytes([51, 4, 0, 0, 14, 16])       # lease time 3600
        pkt += bytes([1,  4]) + ip_to_bytes(subnet)     # subnet mask
        pkt += bytes([3,  4]) + ip_to_bytes(server_ip)  # router
        pkt += bytes([255])                        # end

        return pkt

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, iface.encode())  # SO_BINDTODEVICE
    sock.bind(('0.0.0.0', 67))

    print(f"[DHCP] Listening on {iface} — offering {offer_ip}")

    while True:
        try:
            data, _ = sock.recvfrom(1024)
            if len(data) < 240:
                continue

            xid    = struct.unpack('!I', data[4:8])[0]
            chaddr = data[28:44]
            mac    = parse_mac(chaddr)

            # Parse DHCP message type from options
            msg_type = None
            i = 240
            while i < len(data):
                opt = data[i]
                if opt == 255:
                    break
                if opt == 0:
                    i += 1
                    continue
                length = data[i+1]
                if opt == 53:
                    msg_type = data[i+2]
                i += 2 + length

            if msg_type == 1:   # DISCOVER
                ip = leases.setdefault(mac, offer_ip)
                print(f"[DHCP] DISCOVER {mac} → {ip}")
                reply = build_reply(xid, chaddr, ip, 2, server_ip)
                sock.sendto(reply, ('255.255.255.255', 68))

            elif msg_type == 3:  # REQUEST
                ip = leases.setdefault(mac, offer_ip)
                print(f"[DHCP] REQUEST  {mac} → ACK {ip}")
                reply = build_reply(xid, chaddr, ip, 5, server_ip)
                sock.sendto(reply, ('255.255.255.255', 68))

        except Exception as e:
            print(f"[DHCP] Error: {e}")

def start_dhcp_server(cfg):
    script   = os.path.abspath(__file__)
    cfg_path = str(CONFIG_FILE)

    log  = open(DHCP_LOG, 'w')
    proc = subprocess.Popen(
        [sys.executable, script, '--dhcp-server', cfg_path],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    time.sleep(1)
    if proc.poll() is None:
        print(f"  DHCP server started (PID: {proc.pid})")
    else:
        print(f"  WARNING: DHCP failed. Check {DHCP_LOG}")

def stop_dhcp_server():
    script_name = os.path.basename(__file__)
    run_cmd(f"pkill -f '{script_name} --dhcp-server'")
    print("  DHCP server stopped.")


# ─── Systemd Service ──────────────────────────────────────────────────────────

def install_service():
    script   = os.path.abspath(__file__)
    work_dir = str(SCRIPT_DIR)

    # Use wlan0 device unit — do NOT use network.target which waits for eth0
    service = f"""[Unit]
Description=RCS Management WiFi
After=sys-subsystem-net-devices-wlan0.device
Wants=sys-subsystem-net-devices-wlan0.device

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

    r = run_cmd("pgrep -f 'hostapd /etc/hostapd/mgmt-hostapd.conf'")
    print(f"  Hostapd:     {f'Running (PID {r.stdout.strip()})' if r.returncode == 0 else 'Not running'}")

    script_name = os.path.basename(__file__)
    r = run_cmd(f"pgrep -f '{script_name} --dhcp-server'")
    print(f"  DHCP Server: {f'Running (PID {r.stdout.strip()})' if r.returncode == 0 else 'Not running'}")

    iface = cfg['management_interface']
    r = run_cmd(f"ip addr show {iface} | grep 'inet '")
    print(f"  Interface:   {iface}  ({r.stdout.strip() if r.stdout.strip() else 'No address'})")
    print(f"\n  SSID:        {cfg['ssid']}")
    print(f"  Gateway:     {cfg['ip_address']}")
    print(f"  DHCP Pool:   {cfg['dhcp_start']} – {cfg['dhcp_end']}")
    print(f"  Logs:        {HOSTAPD_LOG}  |  {DHCP_LOG}")
    print("=" * 60)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--dhcp-server':
        cfg_path = sys.argv[2] if len(sys.argv) > 2 else str(CONFIG_FILE)
        with open(cfg_path) as f:
            cfg = json.load(f)
        run_dhcp_server(cfg)
        return

    command = sys.argv[1] if len(sys.argv) > 1 else 'start'

    if command == 'install':
        load_config()
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
    print(f"\n  Logs: {HOSTAPD_LOG}  |  {DHCP_LOG}\n")


if __name__ == "__main__":
    main()
