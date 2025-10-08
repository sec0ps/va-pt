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
        if state in ("connected", "connecting", "unavailable"):
            continue
        if state.startswith("disconnected") or state == "disconnected":
            adapters.append({"device": dev, "state": state})
    return adapters

def pick_wifi_adapter():
    adapters = list_disconnected_wifi_adapters()
    if not adapters:
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
                show_connection_status(selected['device'])
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
    { 'ssid': str, 'signal': int, 'security': str }
    Uses nmcli for better compatibility with USB adapters.
    Excludes hidden networks.
    """
    try:
        subprocess.run(["nmcli", "device", "wifi", "rescan", "ifname", iface],
                      capture_output=True, text=True, timeout=10)
        time.sleep(2)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass

    try:
        raw = run(["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY",
                   "device", "wifi", "list", "ifname", iface], check=True)
    except RuntimeError as e:
        print(f"Error scanning with nmcli: {e}")
        return []

    aps = []
    for line in raw.splitlines():
        if not line or ":" not in line:
            continue

        parts = line.split(":")
        if len(parts) < 3:
            continue

        ssid, signal_str, security = parts[0], parts[1], parts[2]

        # Exclude hidden networks
        if not ssid or ssid.strip() == "":
            continue

        try:
            signal = int(signal_str) if signal_str else 0
        except ValueError:
            signal = 0

        if not security or security.strip() == "":
            security = "--"

        aps.append({
            "ssid": ssid,
            "signal": signal,
            "security": security
        })

    # Remove duplicates (keep strongest signal for each SSID)
    seen_ssids = {}
    for ap in aps:
        ssid_key = ap["ssid"]
        if ssid_key not in seen_ssids or ap["signal"] > seen_ssids[ssid_key]["signal"]:
            seen_ssids[ssid_key] = ap

    unique_aps = list(seen_ssids.values())
    unique_aps.sort(key=lambda x: x["signal"], reverse=True)

    return unique_aps

def print_ap_table(aps):
    print("\nAvailable Wi-Fi networks (strongest first):")
    print(" #   SIGNAL  SECURITY           SSID")
    print("---- ------- ------------------ --------------------------------")
    for i, ap in enumerate(aps, start=1):
        print(f"{str(i).rjust(2)}.  {str(ap['signal']).rjust(3)}%   {ap['security'][:18].ljust(18)} {ap['ssid']}")

def show_connection_status(iface):
    """Display connection status for the interface"""
    try:
        conn_info = run(["nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status"], check=False)

        for line in conn_info.splitlines():
            if line.startswith(iface):
                parts = line.split(":")
                if len(parts) >= 3:
                    device, state, connection = parts[0], parts[1], parts[2]
                    print(f"\n{'='*60}")
                    print(f"Interface: {device}")
                    print(f"State: {state}")
                    print(f"Connection: {connection if connection else 'None'}")
                    print('='*60)

                if state.lower() == "connected":
                    try:
                        ip_info = run(["ip", "-brief", "addr", "show", iface], check=False)
                        print(f"\nIP Information:")
                        print(ip_info)
                    except:
                        pass
                return

        print(f"\nNo status information found for {iface}")
    except Exception as e:
        print(f"Error getting connection status: {e}")

def connect_open(iface, ssid):
    try:
        return run(["nmcli", "device", "wifi", "connect", ssid, "ifname", iface])
    except RuntimeError as e:
        error_msg = str(e).lower()
        if "secrets were required" in error_msg:
            raise RuntimeError("This network requires a password (not open)")
        elif "no network with ssid" in error_msg:
            raise RuntimeError(f"Network '{ssid}' not found or out of range")
        elif "activation failed" in error_msg:
            raise RuntimeError("Connection activation failed - network may be out of range")
        raise

def connect_password(iface, ssid, password):
    try:
        return run([
            "nmcli", "device", "wifi", "connect", ssid,
            "password", password, "ifname", iface
        ])
    except RuntimeError as e:
        error_msg = str(e).lower()
        if "802-11-wireless-security" in error_msg or "authentication" in error_msg:
            raise RuntimeError("Authentication failed - incorrect password")
        elif "no network with ssid" in error_msg:
            raise RuntimeError(f"Network '{ssid}' not found or out of range")
        elif "activation failed" in error_msg:
            raise RuntimeError("Connection activation failed - check password and signal strength")
        raise

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

    try:
        iface = pick_wifi_adapter()
        print(f"\nUsing Wi-Fi interface: {iface}")
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)

    while True:
        try:
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

                print("Preparing interface for connection...")
                time.sleep(1)

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

                show_connection_status(iface)
                print("\nConnection successful!")
                if net_type == "3":
                    print("Note: This network uses a captive portal. "
                          "Open any HTTP site (e.g., http://neverssl.com) "
                          "from a browser to complete the login.")
            except KeyboardInterrupt:
                print("\nReturning to main menu...")
                continue

        elif mode == "2":
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

                    ap = aps[idx - 1]
                    print(f"\nSelected: SSID='{ap['ssid']}', Signal={ap['signal']}%")

                    try:
                        net_type = prompt_network_type()
                    except ValueError as e:
                        print(e)
                        continue

                    print("Preparing interface for connection...")
                    time.sleep(1)

                    try:
                        if net_type == "1":
                            print(f"Connecting to open network '{ap['ssid']}'...")
                            out = connect_open(iface, ap["ssid"])
                        elif net_type == "2":
                            pw = getpass("Enter Wi-Fi password: ").strip()
                            if not pw:
                                print("Password cannot be empty.")
                                continue
                            print(f"Connecting to password network '{ap['ssid']}'...")
                            out = connect_password(iface, ap["ssid"], pw)
                        else:
                            print(f"Connecting to portal network '{ap['ssid']}'...")
                            out = connect_open(iface, ap["ssid"])

                        print(out if out else "Connected (nmcli).")
                    except Exception as e:
                        print(f"Failed to connect: {e}")
                        continue

                    show_connection_status(iface)
                    print("\nConnection successful!")
                    if net_type == "3":
                        print("Note: This network uses a captive portal. "
                              "Open any HTTP site (e.g., http://neverssl.com) "
                              "from a browser to complete the login.")

                    break

            except KeyboardInterrupt:
                print("\nReturning to main menu...")
            except Exception as e:
                print(f"Error: {e}")

        elif mode == "3":
            try:
                disconnect_menu()
            except KeyboardInterrupt:
                print("\nReturning to main menu...")

        elif mode == "4":
            print("Exiting...")
            sys.exit(0)

        else:
            print("Invalid mode selected. Please choose 1, 2, 3, or 4.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
