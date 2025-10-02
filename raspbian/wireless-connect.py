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

import os
import sys
import time
import subprocess
from getpass import getpass

RESCAN_INTERVAL_SEC = 15

def run(cmd, check=True):
    try:
        res = subprocess.run(cmd, check=check, capture_output=True, text=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        out = (e.stderr or e.stdout or "").strip()
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{out}") from e

def ensure_root():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root (try: sudo python3 wireless-connect.py)")

def list_disconnected_wifi_adapters():
    """
    Returns a list of dicts for Wi-Fi adapters that are NOT currently in use:
      { 'device': 'wlan0', 'state': 'disconnected' }
    """
    raw = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"], check=False)
    adapters = []
    for line in raw.splitlines():
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) < 3:
            continue
        dev, typ, state = parts[0], parts[1].lower(), parts[2].lower()
        if typ != "wifi":
            continue
        # Exclude anything "in use": connected/connecting/unavailable/unmanaged
        if state in ("connected", "connecting", "unavailable"):
            continue
        # Keep only clearly available devices
        if state.startswith("disconnected") or state == "disconnected":
            adapters.append({"device": dev, "state": state})
    return adapters

def pick_wifi_adapter():
    adapters = list_disconnected_wifi_adapters()
    if not adapters:
        # Provide more context with a broader list for troubleshooting
        all_wifi = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"], check=False)
        msg = [
            "No disconnected Wi-Fi adapters are available.",
            "If your adapter is currently connected, disconnect it first:",
            "  nmcli device disconnect <iface>",
            "",
            "All devices for reference:",
            all_wifi
        ]
        sys.exit("\n".join(msg))

    print("Select a Wi-Fi adapter (disconnected only):")
    print(" #   DEVICE                STATE")
    print("---- --------------------- ----------------")
    for i, a in enumerate(adapters, start=1):
        print(f"{str(i).rjust(2)}.  {a['device'][:21].ljust(21)} {a['state']}")

    while True:
        choice = input("Enter number: ").strip()
        if not choice.isdigit():
            print("Please enter a valid number.")
            continue
        idx = int(choice)
        if idx < 1 or idx > len(adapters):
            print("Number out of range.")
            continue
        return adapters[idx - 1]["device"]

def disconnect_iface(iface):
    subprocess.run(["nmcli", "device", "disconnect", iface],
                   capture_output=True, text=True)

def dhcp_refresh(iface):
    subprocess.run(["dhclient", "-r", iface], capture_output=True, text=True)
    run(["dhclient", iface])

def scan_networks(iface):
    """
    Returns a list of dicts:
    { 'ssid': str, 'signal': int, 'security': str, 'bssid': str, 'freq': str }
    Uses iwlist instead of nmcli for better USB adapter compatibility
    """
    import re

    try:
        raw = run(["iwlist", iface, "scan"], check=True)
    except RuntimeError:
        return []

    aps = []
    current_ap = {}

    for line in raw.splitlines():
        line = line.strip()

        # New cell starts - extract BSSID
        if "Cell" in line and "Address:" in line:
            if current_ap and current_ap.get("bssid"):
                aps.append(current_ap)
            current_ap = {}
            bssid_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', line)
            if bssid_match:
                current_ap["bssid"] = bssid_match.group(1)

        # ESSID/SSID
        elif "ESSID:" in line:
            essid_match = re.search(r'ESSID:"([^"]*)"', line)
            if essid_match:
                ssid = essid_match.group(1).strip()
                current_ap["ssid"] = ssid if ssid else "<hidden>"
            else:
                essid_fallback = re.search(r'ESSID:(.+)', line)
                if essid_fallback:
                    ssid = essid_fallback.group(1).strip(' "')
                    current_ap["ssid"] = ssid if ssid else "<hidden>"

        # Signal quality/strength
        elif "Quality=" in line or "Signal level=" in line:
            quality_match = re.search(r'Quality=(\d+)/(\d+)', line)
            if quality_match:
                quality = int(quality_match.group(1))
                max_quality = int(quality_match.group(2))
                signal_percent = int((quality / max_quality) * 100)
                current_ap["signal"] = signal_percent
            else:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                if signal_match:
                    signal_dbm = int(signal_match.group(1))
                    if signal_dbm >= -30:
                        signal_percent = 100
                    elif signal_dbm >= -50:
                        signal_percent = 80
                    elif signal_dbm >= -60:
                        signal_percent = 60
                    elif signal_dbm >= -70:
                        signal_percent = 40
                    elif signal_dbm >= -80:
                        signal_percent = 20
                    else:
                        signal_percent = 10
                    current_ap["signal"] = signal_percent

        # Frequency
        elif "Frequency:" in line:
            freq_match = re.search(r'Frequency:([0-9.]+)', line)
            if freq_match:
                freq_ghz = float(freq_match.group(1))
                current_ap["freq"] = f"{int(freq_ghz * 1000)}"

        # Security/Encryption
        elif "Encryption key:" in line:
            if "off" in line.lower():
                current_ap["security"] = "--"
            else:
                current_ap["security"] = "WEP"
        elif "IEEE 802.11i/WPA2" in line or "WPA2" in line:
            current_ap["security"] = "WPA2"
        elif "WPA Version 1" in line or ("WPA:" in line and "WPA2" not in current_ap.get("security", "")):
            current_ap["security"] = "WPA"
        elif "WPA3" in line:
            current_ap["security"] = "WPA3"

    # Add the last AP
    if current_ap and current_ap.get("bssid"):
        aps.append(current_ap)

    # Filter and set defaults
    complete_aps = []
    for ap in aps:
        if not ap.get("bssid"):
            continue

        ap.setdefault("ssid", "<hidden>")
        ap.setdefault("signal", 0)
        ap.setdefault("security", "--")
        ap.setdefault("freq", "")

        if ap["ssid"] == "":
            ap["ssid"] = "<hidden>"

        complete_aps.append(ap)

    # Sort by signal strength
    complete_aps.sort(key=lambda x: x["signal"], reverse=True)
    return complete_aps

def print_ap_table(aps):
    print("\nAvailable Wi-Fi networks (strongest first):")
    print(" #   SIGNAL  SECURITY           FREQ   BSSID               SSID")
    print("---- ------- ------------------ ------ ------------------- --------------------------------")
    for i, ap in enumerate(aps, start=1):
        print(f"{str(i).rjust(2)}.  {str(ap['signal']).rjust(3)}%   {ap['security'][:18].ljust(18)} "
              f"{str(ap['freq']).rjust(6)} {ap['bssid'][:19].ljust(19)} {ap['ssid']}")

def connect_open(iface, ssid, bssid=None):
    if bssid:
        return run(["nmcli", "device", "wifi", "connect", ssid, "ifname", iface, "bssid", bssid])
    return run(["nmcli", "device", "wifi", "connect", ssid, "ifname", iface])

def connect_password(iface, ssid, password, bssid=None):
    if bssid:
        return run([
            "nmcli", "device", "wifi", "connect", ssid,
            "password", password, "ifname", iface, "bssid", bssid
        ])
    return run([
        "nmcli", "device", "wifi", "connect", ssid,
        "password", password, "ifname", iface
    ])

def prompt_network_type():
    print("\nNetwork type?")
    print("  1) open (no password)")
    print("  2) password (WPA/WPA2)")
    print("  3) portal (captive web page)")
    choice = input("Choose 1/2/3: ").strip()
    if choice not in ("1", "2", "3"):
        raise ValueError("Invalid choice.")
    return choice

def main():
    ensure_root()
    iface = pick_wifi_adapter()
    print(f"\nUsing Wi-Fi interface: {iface}")
    print(f"Auto-refreshing every {RESCAN_INTERVAL_SEC} seconds. Press Ctrl+C to exit.")

    try:
        while True:
            print(f"\n{'='*60}")
            print(f"Scanning for networks... (will refresh in {RESCAN_INTERVAL_SEC}s)")
            print('='*60)

            aps = scan_networks(iface)
            if not aps:
                print(f"No networks found. Rescanning in {RESCAN_INTERVAL_SEC} seconds...")
                time.sleep(RESCAN_INTERVAL_SEC)
                continue

            print_ap_table(aps)

            # Use select with timeout to allow interruption during the wait
            import select
            import sys

            print(f"\nPress Enter to connect to a network, or wait {RESCAN_INTERVAL_SEC}s for auto-refresh...")
            print("Press Ctrl+C to exit.")

            # Check if input is available within the timeout period
            ready, _, _ = select.select([sys.stdin], [], [], RESCAN_INTERVAL_SEC)

            if ready:
                # User pressed a key, get their input
                sel = input("Enter the number to connect (or 'q' to quit): ").strip().lower()

                if sel == "q":
                    sys.exit(0)
                if sel == "":
                    continue  # Just refresh

                if not sel.isdigit():
                    print("Please enter a valid number.")
                    continue

                idx = int(sel)
                if idx < 1 or idx > len(aps):
                    print("Number out of range.")
                    continue

                # Connection logic
                ap = aps[idx - 1]
                if ap["ssid"] == "<hidden>":
                    print("Selected AP is hidden. Configure manually with nmcli.")
                    continue

                print(f"\nSelected: SSID='{ap['ssid']}', BSSID={ap['bssid']}, Signal={ap['signal']}%")
                print("Disconnecting current connection (if any)...")
                disconnect_iface(iface)

                try:
                    net_type = prompt_network_type()
                except ValueError as e:
                    print(e)
                    continue

                try:
                    if net_type == "1":
                        print(f"Connecting to open network '{ap['ssid']}'...")
                        out = connect_open(iface, ap["ssid"], bssid=ap["bssid"])
                    elif net_type == "2":
                        pw = getpass("Enter Wi-Fi password: ").strip()
                        if not pw:
                            print("Password cannot be empty.")
                            continue
                        print(f"Connecting to password network '{ap['ssid']}'...")
                        out = connect_password(iface, ap["ssid"], pw, bssid=ap["bssid"])
                    else:
                        print(f"Connecting to portal network '{ap['ssid']}'...")
                        out = connect_open(iface, ap["ssid"], bssid=ap["bssid"])

                    print(out if out else "Connected (nmcli).")
                except Exception as e:
                    print(f"Failed to connect: {e}")
                    continue

                print("Acquiring IP via DHCP...")
                try:
                    dhcp_refresh(iface)
                except Exception as e:
                    print(f"DHCP error: {e}")
                    continue

                try:
                    state = run(["ip", "-brief", "addr", "show", iface], check=False)
                    print("\nInterface state:")
                    print(state)
                except Exception:
                    pass

                print("\nConnection successful!")
                if net_type == "3":
                    print("Note: This network uses a captive portal. "
                          "Open any HTTP site (e.g., http://neverssl.com) "
                          "from a browser or text browser to complete the login.")

                # Ask if user wants to continue scanning or exit
                cont = input("Continue scanning? (y/n): ").strip().lower()
                if cont not in ('y', 'yes', ''):
                    break
            else:
                # Timeout reached, auto-refresh
                print(f"\nAuto-refreshing... ({RESCAN_INTERVAL_SEC}s elapsed)")
                continue

    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
