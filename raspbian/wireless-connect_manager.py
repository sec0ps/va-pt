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

import os
import sys
import time
import subprocess
import select
from getpass import getpass

RESCAN_INTERVAL_SEC = 15


def usage():
    print("""
Usage: sudo python wireless-connect.py [OPTION]

Options:
  -h, --help    Show this help message and exit

Runtime menu (when interface is CONNECTED):
  1             Disconnect from current network
  2             Disconnect and scan for a new network
  q             Quit

Runtime menu (when interface is DISCONNECTED):
  <number>      Select network from scan results
  Enter         Rescan for networks
  q             Quit
  Ctrl+C        Exit at any prompt

Network type prompt:
  1             Open (no password)
  2             WPA/WPA2 password
  3             Captive portal (open connect, browser handles auth)
""")


# ─── Utilities ────────────────────────────────────────────────────────────────

def run(cmd, check=True):
    try:
        res = subprocess.run(cmd, check=check, capture_output=True, text=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        out = (e.stderr or e.stdout or "").strip()
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{out}") from e


def ensure_root():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root.  sudo python wireless-connect.py")


def safe_input(prompt):
    """input() wrapper — converts KeyboardInterrupt to a clean exit."""
    try:
        return input(prompt).strip()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)


# ─── Interface Detection ──────────────────────────────────────────────────────

def get_all_wifi_adapters():
    """
    Returns list of dicts for ALL Wi-Fi adapters using three detection methods.
    { 'device': 'wlan0', 'state': 'connected', 'connection': 'MyNetwork', 'source': 'nmcli' }
    """
    adapters = {}

    # Method 1: NetworkManager (primary)
    try:
        raw = run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"], check=False)
        for line in raw.splitlines():
            if not line or line.count(":") < 3:
                continue
            parts = line.split(":")
            dev, typ, state, conn = parts[0], parts[1].lower(), parts[2].lower(), ":".join(parts[3:])
            if typ != "wifi":
                continue
            adapters[dev] = {
                "device":     dev,
                "state":      state,
                "connection": conn.strip() if conn.strip() else "N/A",
                "source":     "nmcli",
            }
    except Exception:
        pass

    # Method 2: sysfs (catches USB adapters NM may miss)
    try:
        import re
        for dev in os.listdir("/sys/class/net"):
            if not os.path.exists(f"/sys/class/net/{dev}/wireless"):
                continue
            if dev in adapters:
                continue
            state = "unknown"
            conn  = "N/A"
            try:
                iw = run(["iwconfig", dev], check=False)
                m  = re.search(r'ESSID:"([^"]*)"', iw)
                if m and m.group(1):
                    conn  = m.group(1)
                    state = "connected"
                else:
                    state = "disconnected"
            except Exception:
                pass
            adapters[dev] = {"device": dev, "state": state, "connection": conn, "source": "sysfs"}
    except Exception:
        pass

    # Method 3: iwconfig fallback
    try:
        import re
        iw_out = run(["iwconfig"], check=False)
        for block in iw_out.split("\n\n"):
            m = re.match(r'^(\S+)', block)
            if not m or "no wireless" in block.lower():
                continue
            dev = m.group(1)
            if dev in adapters:
                continue
            state = "unknown"
            conn  = "N/A"
            em = re.search(r'ESSID:"([^"]*)"', block)
            if em and em.group(1):
                conn  = em.group(1)
                state = "connected"
            adapters[dev] = {"device": dev, "state": state, "connection": conn, "source": "iwconfig"}
    except Exception:
        pass

    return list(adapters.values())


def pick_wifi_adapter():
    """Interactive adapter selection."""
    adapters = get_all_wifi_adapters()
    if not adapters:
        sys.exit("No Wi-Fi interfaces found.")

    print(f"Detected {len(adapters)} wireless interface(s):")
    for a in adapters:
        print(f"  {a['device']} - {a['state']} - via {a['source']}")

    print("Select a Wi-Fi adapter:")
    print(f" {'#'.ljust(4)} {'DEVICE'.ljust(21)} {'STATE'.ljust(20)} {'CONNECTION'.ljust(20)}")
    print("-" * 70)
    for i, a in enumerate(adapters, start=1):
        conn_display = a['connection'][:19] if a['connection'] != 'N/A' else 'N/A'
        print(f" {str(i).ljust(4)} {a['device'][:21].ljust(21)} {a['state'][:19].ljust(20)} {conn_display}")

    choice = safe_input("Enter number: ")
    while not choice.isdigit() or not (1 <= int(choice) <= len(adapters)):
        print("Invalid selection.")
        choice = safe_input("Enter number: ")

    return adapters[int(choice) - 1]


# ─── Connection Helpers ───────────────────────────────────────────────────────

def get_connection_details(iface):
    """Return current SSID and IP info for a connected interface."""
    import re
    ssid = ""
    try:
        iw = run(["iwconfig", iface], check=False)
        m  = re.search(r'ESSID:"([^"]*)"', iw)
        ssid = m.group(1) if m else ""
    except Exception:
        pass

    if not ssid:
        try:
            out = run(["nmcli", "-t", "-f", "active,ssid", "device", "wifi"], check=False)
            for line in out.splitlines():
                if line.startswith("yes:"):
                    ssid = line.split(":", 1)[1]
                    break
        except Exception:
            ssid = "unknown"

    ip_info = run(["ip", "-brief", "addr", "show", iface], check=False)
    return {"ssid": ssid or "unknown", "ip_info": ip_info}


def disconnect_iface(iface):
    """Disconnect interface and release DHCP lease."""
    try:
        run(["nmcli", "device", "disconnect", iface], check=False)
    except Exception:
        pass
    try:
        run(["dhclient", "-r", iface], check=False)
    except Exception:
        pass
    time.sleep(1)


def show_connection_status(iface):
    try:
        state = run(["ip", "-brief", "addr", "show", iface], check=False)
        print(f"\nInterface state:\n{state}")
    except Exception:
        pass


# ─── Scanning & Network Selection ────────────────────────────────────────────

def scan_networks(iface):
    """Scan using nmcli. Returns list sorted by signal, hidden SSIDs excluded."""
    try:
        subprocess.run(
            ["nmcli", "device", "wifi", "rescan", "ifname", iface],
            capture_output=True, timeout=5
        )
        time.sleep(2)
    except Exception:
        pass

    raw = run(
        ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", iface],
        check=False
    )

    seen = {}
    for line in raw.splitlines():
        if not line:
            continue
        parts = line.rsplit(":", 2)
        if len(parts) < 3:
            continue
        ssid     = parts[0].strip()
        signal   = parts[1].strip()
        security = parts[2].strip() or "--"

        if not ssid or ssid == "--":
            continue  # skip hidden networks

        try:
            sig_int = int(signal)
        except ValueError:
            sig_int = 0

        if ssid not in seen or sig_int > seen[ssid]["signal"]:
            seen[ssid] = {"ssid": ssid, "signal": sig_int, "security": security}

    return sorted(seen.values(), key=lambda x: x["signal"], reverse=True)


def print_network_list(aps):
    print(f"\n {'#'.ljust(4)} {'SIGNAL'.ljust(7)} {'SECURITY'.ljust(18)} SSID")
    print("-" * 60)
    for i, ap in enumerate(aps, start=1):
        print(f" {str(i).ljust(4)} {str(ap['signal']).rjust(3)}%   "
              f"{ap['security'][:18].ljust(18)} {ap['ssid']}")


def prompt_network_type():
    print("\nNetwork type?")
    print("  1) open (no password)")
    print("  2) password (WPA/WPA2)")
    print("  3) portal (captive web page)")
    choice = safe_input("Choose 1/2/3: ")
    if choice not in ("1", "2", "3"):
        raise ValueError("Invalid choice.")
    return choice


def connect_open(iface, ssid):
    return run(["nmcli", "device", "wifi", "connect", ssid, "ifname", iface])


def connect_password(iface, ssid, password):
    return run(["nmcli", "device", "wifi", "connect", ssid, "password", password, "ifname", iface])


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        usage()
        sys.exit(0)

    ensure_root()

    adapter_info = pick_wifi_adapter()
    iface        = adapter_info["device"]
    print(f"\nUsing interface: {iface}")

    try:
        while True:
            # Refresh adapter state at the top of every loop iteration
            current_adapters = get_all_wifi_adapters()
            current_adapter  = next(
                (a for a in current_adapters if a["device"] == iface),
                adapter_info
            )

            # ── CONNECTED: present menu immediately, no scanning ─────────────
            if current_adapter["state"].startswith("connected"):
                details = get_connection_details(iface)
                print(f"\nConnected to : {details['ssid']}")
                print(f"Status       : {details['ip_info']}")
                print("\n  1) Disconnect")
                print("  2) Disconnect and scan for a new network")
                print("  q) Quit")

                choice = safe_input("\nChoose: ").lower()

                if choice == "1":
                    print(f"Disconnecting {iface}...")
                    disconnect_iface(iface)
                    show_connection_status(iface)
                    print("Disconnected.")

                elif choice == "2":
                    print(f"Disconnecting {iface}...")
                    disconnect_iface(iface)
                    print("Disconnected. Proceeding to scan...")
                    # loop back — now disconnected, falls into scan block below

                elif choice == "q":
                    sys.exit(0)

                else:
                    print("Invalid choice.")

            # ── DISCONNECTED: scan and connect ───────────────────────────────
            else:
                print(f"\n{'='*70}")
                print(f"Scanning for networks on {iface}...")
                print("=" * 70)

                aps = scan_networks(iface)
                if not aps:
                    print("No networks found.")
                    safe_input("Press Enter to rescan...")
                    continue

                print_network_list(aps)
                print(f"\nEnter network number (Enter=rescan, q=quit): ", end="", flush=True)

                ready, _, _ = select.select([sys.stdin], [], [], RESCAN_INTERVAL_SEC)
                if not ready:
                    print("\nAuto-rescanning...")
                    continue

                raw_choice = sys.stdin.readline().strip().lower()

                if not raw_choice:
                    continue
                if raw_choice == "q":
                    sys.exit(0)
                if not raw_choice.isdigit():
                    print("Please enter a valid number.")
                    continue

                idx = int(raw_choice) - 1
                if idx < 0 or idx >= len(aps):
                    print("Number out of range.")
                    continue

                ap = aps[idx]
                print(f"\nSelected: '{ap['ssid']}' ({ap['signal']}% signal, {ap['security']})")

                try:
                    net_type = prompt_network_type()
                except ValueError as e:
                    print(e)
                    continue

                try:
                    if net_type == "1":
                        print(f"Connecting to '{ap['ssid']}'...")
                        out = connect_open(iface, ap["ssid"])
                    elif net_type == "2":
                        pw = getpass("Enter Wi-Fi password: ").strip()
                        if not pw:
                            print("Password cannot be empty.")
                            continue
                        print(f"Connecting to '{ap['ssid']}'...")
                        out = connect_password(iface, ap["ssid"], pw)
                    else:
                        print(f"Connecting to portal '{ap['ssid']}'...")
                        out = connect_open(iface, ap["ssid"])

                    print(out if out else "Connected.")
                    show_connection_status(iface)

                except Exception as e:
                    print(f"Failed to connect: {e}")

    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
