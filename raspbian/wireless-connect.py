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
import re
import select

RESCAN_INTERVAL_SEC = 15

def run(cmd, check=True):
    """Execute command with error handling"""
    try:
        res = subprocess.run(cmd, check=check, capture_output=True, text=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        out = (e.stderr or e.stdout or "").strip()
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{out}") from e

def ensure_root():
    """Verify script is running with root privileges"""
    if os.geteuid() != 0:
        sys.exit("This script must be run as root (try: sudo python3 wireless-connect.py)")

def get_all_wifi_adapters():
    """
    Returns a list of dicts for ALL Wi-Fi adapters (connected and disconnected):
      { 'device': 'wlan0', 'state': 'connected', 'connection': 'MyNetwork' }
    Uses multiple detection methods to find all wireless interfaces including USB adapters.
    """
    adapters = []

    # Method 1: NetworkManager detection (primary)
    try:
        raw = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], check=False)
        for line in raw.splitlines():
            if not line or ":" not in line:
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            dev, typ, state, connection = parts[0], parts[1].lower(), parts[2].lower(), parts[3]

            # Only include WiFi interfaces
            if typ == "wifi":
                # Skip unavailable or unmanaged interfaces
                if state not in ("unavailable", "unmanaged"):
                    adapters.append({
                        "device": dev,
                        "state": state,
                        "connection": connection if connection else "N/A",
                        "method": "nmcli"
                    })
    except Exception as e:
        print(f"Warning: NetworkManager detection failed: {e}")

    # Method 2: Direct wireless interface detection via /sys/class/net
    try:
        import glob
        for iface_path in glob.glob("/sys/class/net/*/wireless"):
            iface_name = iface_path.split("/")[-2]

            # Skip if already found by NetworkManager
            if any(adapter["device"] == iface_name for adapter in adapters):
                continue

            # Check if interface is up and wireless
            try:
                with open(f"/sys/class/net/{iface_name}/operstate", "r") as f:
                    operstate = f.read().strip()

                # Determine connection state
                state = "unknown"
                connection = "N/A"

                # Try to get state from iwconfig
                try:
                    iwconfig_out = run(["iwconfig", iface_name], check=False)
                    if "ESSID:" in iwconfig_out:
                        if 'ESSID:off' in iwconfig_out or 'ESSID:""' in iwconfig_out:
                            state = "disconnected"
                        else:
                            state = "connected" if operstate == "up" else "disconnected"
                            # Extract ESSID for connection name
                            import re
                            essid_match = re.search(r'ESSID:"([^"]*)"', iwconfig_out)
                            if essid_match and essid_match.group(1):
                                connection = essid_match.group(1)
                except:
                    state = "disconnected" if operstate != "up" else "unknown"

                adapters.append({
                    "device": iface_name,
                    "state": state,
                    "connection": connection,
                    "method": "sysfs"
                })

            except Exception as iface_error:
                print(f"Warning: Could not read state for {iface_name}: {iface_error}")

    except Exception as e:
        print(f"Warning: Direct interface detection failed: {e}")

    # Method 3: Parse iwconfig output as fallback
    try:
        iwconfig_out = run(["iwconfig"], check=False)
        current_iface = None

        for line in iwconfig_out.splitlines():
            line = line.strip()
            if not line:
                continue

            # New interface line
            if not line.startswith(" ") and "IEEE 802.11" in line:
                iface_parts = line.split()
                if iface_parts:
                    current_iface = iface_parts[0]

                    # Skip if already found
                    if any(adapter["device"] == current_iface for adapter in adapters):
                        current_iface = None
                        continue

                    # Determine state from iwconfig output
                    state = "disconnected"
                    connection = "N/A"

                    if "ESSID:" in line:
                        if 'ESSID:off' not in line and 'ESSID:""' not in line:
                            import re
                            essid_match = re.search(r'ESSID:"([^"]*)"', line)
                            if essid_match and essid_match.group(1):
                                state = "connected"
                                connection = essid_match.group(1)

                    adapters.append({
                        "device": current_iface,
                        "state": state,
                        "connection": connection,
                        "method": "iwconfig"
                    })

    except Exception as e:
        print(f"Warning: iwconfig parsing failed: {e}")

    # Remove duplicates (prefer nmcli results)
    unique_adapters = []
    seen_devices = set()

    # First pass: add nmcli results
    for adapter in adapters:
        if adapter["method"] == "nmcli" and adapter["device"] not in seen_devices:
            unique_adapters.append(adapter)
            seen_devices.add(adapter["device"])

    # Second pass: add others not already seen
    for adapter in adapters:
        if adapter["device"] not in seen_devices:
            unique_adapters.append(adapter)
            seen_devices.add(adapter["device"])

    # Debug output
    if unique_adapters:
        print(f"Detected {len(unique_adapters)} wireless interface(s):")
        for adapter in unique_adapters:
            print(f"  {adapter['device']} - {adapter['state']} - via {adapter['method']}")

    return unique_adapters

def get_connection_details(iface):
    """Get detailed connection info for a connected interface"""
    try:
        # Get IP address info
        ip_info = run(["ip", "-brief", "addr", "show", iface], check=False)

        # Get current SSID from nmcli
        try:
            ssid = run(["nmcli", "-t", "-f", "active,ssid", "device", "wifi", "list", "ifname", iface], check=False)
            current_ssid = None
            for line in ssid.splitlines():
                if line.startswith("yes:"):
                    current_ssid = line.split(":", 1)[1]
                    break
        except:
            current_ssid = "Unknown"

        return {
            "ip_info": ip_info,
            "ssid": current_ssid or "Unknown"
        }
    except Exception as e:
        return {"ip_info": f"Error: {e}", "ssid": "Unknown"}

def pick_wifi_adapter():
    """Select a Wi-Fi adapter from all available (connected and disconnected)"""
    adapters = get_all_wifi_adapters()
    if not adapters:
        sys.exit("No Wi-Fi adapters found. Make sure your Wi-Fi hardware is detected.")

    print("Select a Wi-Fi adapter:")
    print(" #   DEVICE                STATE                CONNECTION")
    print("---- --------------------- -------------------- --------------------")
    for i, a in enumerate(adapters, start=1):
        state_display = a['state']
        if a['state'] == 'connected':
            # Get additional details for connected interfaces
            details = get_connection_details(a['device'])
            state_display = f"connected ({details['ssid']})"

        print(f"{str(i).rjust(2)}.  {a['device'][:21].ljust(21)} {state_display[:20].ljust(20)} {a['connection'][:20]}")

    while True:
        choice = input("Enter number: ").strip()
        if not choice.isdigit():
            print("Please enter a valid number.")
            continue
        idx = int(choice)
        if idx < 1 or idx > len(adapters):
            print("Number out of range.")
            continue
        return adapters[idx - 1]

def disconnect_and_release_dhcp(iface):
    """Disconnect interface and release DHCP lease"""
    print(f"Disconnecting interface {iface}...")
    try:
        # Release DHCP lease first
        subprocess.run(["dhclient", "-r", iface], capture_output=True, text=True)
        print("DHCP lease released.")
    except Exception as e:
        print(f"Warning: Could not release DHCP lease: {e}")

    try:
        # Disconnect from NetworkManager
        result = run(["nmcli", "device", "disconnect", iface])
        print("Interface disconnected.")
        return True
    except Exception as e:
        print(f"Error disconnecting interface: {e}")
        return False

def dhcp_refresh(iface):
    """Request new DHCP lease"""
    subprocess.run(["dhclient", "-r", iface], capture_output=True, text=True)
    run(["dhclient", iface])

def scan_networks(iface):
    """
    Returns a list of dicts:
    { 'ssid': str, 'signal': int, 'security': str, 'bssid': str, 'freq': str }
    Uses iwlist for better USB adapter compatibility
    """
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
            # Extract BSSID
            bssid_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', line)
            if bssid_match:
                current_ap["bssid"] = bssid_match.group(1)

        # ESSID/SSID - handle multiple formats
        elif "ESSID:" in line:
            essid_match = re.search(r'ESSID:"([^"]*)"', line)
            if essid_match:
                ssid = essid_match.group(1).strip()
                if ssid:
                    current_ap["ssid"] = ssid
                else:
                    current_ap["ssid"] = "<hidden>"
            else:
                essid_fallback = re.search(r'ESSID:(.+)', line)
                if essid_fallback:
                    ssid = essid_fallback.group(1).strip(' "')
                    current_ap["ssid"] = ssid if ssid else "<hidden>"

        # Signal quality/strength
        elif "Quality=" in line or "Signal level=" in line:
            signal_set = False

            # Try Quality first (more accurate)
            quality_match = re.search(r'Quality=(\d+)/(\d+)', line)
            if quality_match:
                quality = int(quality_match.group(1))
                max_quality = int(quality_match.group(2))
                signal_percent = int((quality / max_quality) * 100)
                current_ap["signal"] = signal_percent
                signal_set = True

            # If no Quality, try Signal level
            if not signal_set:
                signal_match = re.search(r'Signal level=(-?\d+)', line)
                if signal_match:
                    signal_dbm = int(signal_match.group(1))
                    # Convert dBm to percentage
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

        # Security/Encryption detection
        elif "Encryption key:" in line:
            if "off" in line.lower():
                current_ap["security"] = "--"
            else:
                current_ap["security"] = "WEP"

        # More specific security protocols
        elif "IEEE 802.11i/WPA2" in line or "WPA2" in line:
            current_ap["security"] = "WPA2"
        elif "WPA Version 1" in line or ("WPA:" in line and "WPA2" not in current_ap.get("security", "")):
            current_ap["security"] = "WPA"
        elif "WPA3" in line:
            current_ap["security"] = "WPA3"

    # Add the last AP
    if current_ap and current_ap.get("bssid"):
        aps.append(current_ap)

    # Filter out incomplete entries and set defaults
    complete_aps = []
    for ap in aps:
        if not ap.get("bssid"):
            continue

        # Set defaults for missing fields
        if not ap.get("ssid"):
            ap["ssid"] = "<hidden>"
        ap.setdefault("signal", 0)
        ap.setdefault("security", "--")
        ap.setdefault("freq", "")

        # Skip if SSID is empty string (but keep <hidden>)
        if ap["ssid"] == "":
            ap["ssid"] = "<hidden>"

        complete_aps.append(ap)

    # Sort by signal strength (strongest first)
    complete_aps.sort(key=lambda x: x["signal"], reverse=True)

    return complete_aps

def print_networks_with_disconnect_option(aps, adapter_info):
    """Print available networks with disconnect option if connected"""
    print("\nAvailable options:")

    option_num = 1
    disconnect_option = None

    # Add disconnect option if interface is connected
    if adapter_info['state'] == 'connected':
        details = get_connection_details(adapter_info['device'])
        print(f" {option_num}.  [DISCONNECT] Current: {details['ssid']} - Release DHCP and disconnect")
        disconnect_option = option_num
        option_num += 1

    # Show separator
    if disconnect_option:
        print("---- Available Wi-Fi networks (strongest first) ----")
    else:
        print("---- Available Wi-Fi networks (strongest first) ----")

    print(" #   SIGNAL  SECURITY           FREQ   BSSID               SSID")
    print("---- ------- ------------------ ------ ------------------- --------------------------------")

    network_start_num = option_num
    for i, ap in enumerate(aps, start=option_num):
        print(f"{str(i).rjust(2)}.  {str(ap['signal']).rjust(3)}%   {ap['security'][:18].ljust(18)} "
              f"{str(ap['freq']).rjust(6)} {ap['bssid'][:19].ljust(19)} {ap['ssid']}")

    return disconnect_option, network_start_num

def connect_open(iface, ssid, bssid=None):
    """Connect to open network"""
    if bssid:
        return run(["nmcli", "device", "wifi", "connect", ssid, "ifname", iface, "bssid", bssid])
    return run(["nmcli", "device", "wifi", "connect", ssid, "ifname", iface])

def connect_password(iface, ssid, password, bssid=None):
    """Connect to password-protected network"""
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
    """Prompt user for network authentication type"""
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
    adapter_info = pick_wifi_adapter()
    iface = adapter_info['device']

    print(f"\nUsing Wi-Fi interface: {iface} (Status: {adapter_info['state']})")

    # Show connection details if already connected
    if adapter_info['state'] == 'connected':
        details = get_connection_details(iface)
        print(f"Currently connected to: {details['ssid']}")
        print(f"Interface status: {details['ip_info']}")

    print(f"Auto-refreshing every {RESCAN_INTERVAL_SEC} seconds. Press Ctrl+C to exit.")

    try:
        while True:
            print(f"\n{'='*80}")
            print(f"Scanning for networks on {iface}... (will refresh in {RESCAN_INTERVAL_SEC}s)")
            print('='*80)

            aps = scan_networks(iface)
            if not aps:
                print(f"No networks found. Rescanning in {RESCAN_INTERVAL_SEC} seconds...")
                time.sleep(RESCAN_INTERVAL_SEC)
                continue

            # Refresh adapter state in case it changed
            current_adapters = get_all_wifi_adapters()
            current_adapter = next((a for a in current_adapters if a['device'] == iface), adapter_info)

            disconnect_option, network_start_num = print_networks_with_disconnect_option(aps, current_adapter)

            # Wait for user input with timeout
            print(f"\nPress Enter to select an option, or wait {RESCAN_INTERVAL_SEC}s for auto-refresh...")
            print("Press Ctrl+C to exit.")

            ready, _, _ = select.select([sys.stdin], [], [], RESCAN_INTERVAL_SEC)

            if ready:
                sel = input("Enter the number to select option (or 'q' to quit): ").strip().lower()

                if sel == "q":
                    sys.exit(0)
                if sel == "":
                    continue  # Just refresh

                if not sel.isdigit():
                    print("Please enter a valid number.")
                    continue

                choice_num = int(sel)

                # Handle disconnect option
                if disconnect_option and choice_num == disconnect_option:
                    if disconnect_and_release_dhcp(iface):
                        print("Successfully disconnected and released DHCP.")
                        adapter_info['state'] = 'disconnected'  # Update local state
                    continue

                # Handle network selection
                network_idx = choice_num - network_start_num
                if network_idx < 0 or network_idx >= len(aps):
                    print("Number out of range.")
                    continue

                ap = aps[network_idx]
                if ap["ssid"] == "<hidden>":
                    print("Selected AP is hidden. Configure manually with nmcli.")
                    continue

                print(f"\nSelected: SSID='{ap['ssid']}', BSSID={ap['bssid']}, Signal={ap['signal']}%")

                # Force disconnect if currently connected
                if current_adapter['state'] == 'connected':
                    print("Interface is connected. Forcing disconnect before connecting to new network...")
                    if not disconnect_and_release_dhcp(iface):
                        print("Failed to disconnect. Aborting connection attempt.")
                        continue

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
                          "from a browser to complete the login.")

                # Update local adapter state
                adapter_info['state'] = 'connected'

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
