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

def list_connected_wifi():
    """
    Returns a list of dicts for Wi-Fi adapters that are currently connected:
      { 'device': 'wlan0', 'ssid': 'MyNetwork', 'state': 'connected' }
    """
    raw = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], check=False)
    connected = []
    for line in raw.splitlines():
        if not line or ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        dev, typ, state, conn = parts[0], parts[1].lower(), parts[2].lower(), parts[3]
        if typ != "wifi":
            continue
        if state == "connected" and conn:
            connected.append({
                "device": dev,
                "ssid": conn,
                "state": state
            })
    return connected

def disconnect_menu():
    """
    Display menu of connected Wi-Fi interfaces and allow user to disconnect
    """
    try:
        while True:
            connected = list_connected_wifi()

            if not connected:
                print("\nNo connected Wi-Fi networks found.")
                input("Press Enter to return to main menu...")
                return

            print("\n" + "="*60)
            print("Connected Wi-Fi Networks")
            print("="*60)
            print(" #   DEVICE                SSID/CONNECTION")
            print("---- --------------------- --------------------------------")
            for i, c in enumerate(connected, start=1):
                print(f"{str(i).rjust(2)}.  {c['device'][:21].ljust(21)} {c['ssid']}")

            sel = input("\nEnter number to disconnect, 'r' to refresh, or 'q' to return: ").strip().lower()

            if sel == "q":
                return
            if sel == "r" or sel == "":
                continue

            if not sel.isdigit():
                print("Please enter a valid number.")
                continue

            idx = int(sel)
            if idx < 1 or idx > len(connected):
                print("Number out of range.")
                continue

            selected = connected[idx - 1]
            print(f"\nDisconnecting '{selected['ssid']}' from {selected['device']}...")

            try:
                disconnect_iface(selected['device'])
                print(f"Successfully disconnected from '{selected['ssid']}'")

                # Show updated state
                try:
                    state = run(["ip", "-brief", "addr", "show", selected['device']], check=False)
                    print(f"\nInterface state:")
                    print(state)
                except Exception:
                    pass

                input("\nPress Enter to continue...")
            except Exception as e:
                print(f"Failed to disconnect: {e}")
                input("\nPress Enter to continue...")

    except KeyboardInterrupt:
        print("\nReturning to main menu...")
        return

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

    # Select adapter once at start
    try:
        iface = pick_wifi_adapter()
        print(f"\nUsing Wi-Fi interface: {iface}")
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)

    # Main menu loop
    while True:
        try:
            # Ask user for connection mode
            print("\n" + "="*60)
            print("MAIN MENU")
            print("="*60)
            print("  1) Connect to specific SSID")
            print("  2) Scan for networks")
            print("  3) Disconnect from network")
            print("  4) Quit")
            mode = input("Choose 1, 2, 3, or 4: ").strip()
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")
            sys.exit(0)

        if mode == "1":
            # Direct SSID connection
            try:
                ssid = input("Enter SSID: ").strip()
                if not ssid:
                    print("SSID cannot be empty.")
                    continue

                try:
                    net_type = prompt_network_type()
                except ValueError as e:
                    print(str(e))
                    continue

                try:
                    if net_type == "1":
                        print(f"Connecting to open network '{ssid}'...")
                        out = connect_open(iface, ssid)
                    elif net_type == "2":
                        pw = getpass("Enter Wi-Fi password: ").strip()
                        if not pw:
                            print("Password cannot be empty.")
                            continue
                        print(f"Connecting to password network '{ssid}'...")
                        out = connect_password(iface, ssid, pw)
                    else:
                        print(f"Connecting to portal network '{ssid}'...")
                        out = connect_open(iface, ssid)

                    print(out if out else "Connected (nmcli).")
                except Exception as e:
                    print(f"Failed to connect: {e}")
                    continue

                # Display connection status
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
            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                continue

        elif mode == "2":
            # Scan mode
            try:
                while True:
                    print(f"\n{'='*60}")
                    print("Scanning for networks...")
                    print('='*60)

                    aps = scan_networks(iface)
                    if not aps:
                        print("No networks found.")
                        retry = input("Press 'r' to rescan or 'q' to return to main menu: ").strip().lower()
                        if retry == 'q':
                            break
                        continue

                    print_ap_table(aps)

                    # Wait for user input without timeout
                    sel = input("\nEnter number to connect, 'r' to rescan, or 'q' to return to main menu: ").strip().lower()

                    if sel == "q":
                        break
                    if sel == "r" or sel == "":
                        continue

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

                    # Display connection status
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

                    # Exit scan loop after successful connection
                    break

            except KeyboardInterrupt:
                print("\nReturning to main menu...")
            except Exception as e:
                print(f"Error: {e}")

        elif mode == "3":
            # Disconnect mode
            try:
                disconnect_menu()
            except KeyboardInterrupt:
                print("\nReturning to main menu...")

        elif mode == "4":
            # Quit
            print("Exiting...")
            sys.exit(0)

        else:
            print("Invalid mode selected. Please choose 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
