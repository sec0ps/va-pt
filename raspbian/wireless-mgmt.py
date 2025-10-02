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
import subprocess
import sys

# Configuration
INTERFACE = "wlan0"
SSID = "rcs-management"
PSK = "getsomemore!"
IP_ADDRESS = "192.168.255.254"

def run_cmd(cmd):
    """Run command and log output"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(f"Output: {result.stdout.strip()}")
    if result.stderr and result.returncode != 0:
        print(f"Error: {result.stderr.strip()}")
    return result

def create_hostapd_config():
    """Create hostapd config only"""

    hostapd_config = f"""interface={INTERFACE}
driver=nl80211
ssid={SSID}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={PSK}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""

    with open('/tmp/hostapd.conf', 'w') as f:
        f.write(hostapd_config)

    run_cmd("sudo mv /tmp/hostapd.conf /etc/hostapd/hostapd.conf")
    run_cmd("sudo chmod 600 /etc/hostapd/hostapd.conf")

    print("Hostapd configuration created")

def setup_interface():
    """Configure the interface with static IP"""

    # Check if IP is already assigned
    result = run_cmd(f"ip addr show {INTERFACE} | grep {IP_ADDRESS}")
    if result.returncode == 0:
        print(f"IP {IP_ADDRESS} already assigned to {INTERFACE}")
    else:
        # Set static IP
        run_cmd(f"sudo ip addr add {IP_ADDRESS}/24 dev {INTERFACE}")

    run_cmd(f"sudo ip link set {INTERFACE} up")

    print(f"Interface {INTERFACE} configured with IP {IP_ADDRESS}")

def start_hostapd():
    """Start hostapd directly as a background process"""

    # Kill any existing hostapd processes
    run_cmd("sudo pkill hostapd")

    import time
    time.sleep(1)

    # Start hostapd directly with nohup for background execution
    run_cmd("sudo nohup hostapd /etc/hostapd/hostapd.conf > /tmp/hostapd.log 2>&1 &")

    # Give it a moment to start
    time.sleep(3)

    # Check if it's running
    result = run_cmd("sudo pgrep hostapd")
    if result.returncode == 0:
        print(f"Hostapd started successfully (PID: {result.stdout.strip()})")
    else:
        print("Warning: Hostapd may not have started properly")
        # Show any error from the log
        run_cmd("tail -n 5 /tmp/hostapd.log")

    print("Hostapd process started directly")

def create_systemd_service():
    """Create systemd service for auto-start"""

    service_content = f"""[Unit]
Description=Management WiFi Setup
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {os.path.abspath(__file__)}
User=root

[Install]
WantedBy=multi-user.target
"""

    with open('/tmp/mgmt-wifi.service', 'w') as f:
        f.write(service_content)

    run_cmd("sudo mv /tmp/mgmt-wifi.service /etc/systemd/system/")
    run_cmd("sudo systemctl daemon-reload")
    run_cmd("sudo systemctl enable mgmt-wifi.service")

    print("Systemd service created and enabled")

def main():
    """Main setup function"""

    if len(sys.argv) > 1 and sys.argv[1] == "install":
        print("Installing management WiFi service...")
        create_hostapd_config()
        create_systemd_service()
        print("Installation complete. Reboot to activate.")
        return

    print("Starting Management WiFi Setup...")

    # Check if running as root
    if os.geteuid() != 0:
        print("Please run as root: sudo python3 wireless-mgmt.py")
        sys.exit(1)

    try:
        create_hostapd_config()  # Create config every time
        setup_interface()
        start_hostapd()

        print("\n" + "="*50)
        print("Management WiFi Network Started Successfully!")
        print(f"Network Name: {SSID}")
        print(f"Password: {PSK}")
        print(f"Management IP: {IP_ADDRESS}")
        print("Note: Use static IP on your device to connect")
        print("="*50)

        # Check status
        print("\nProcess Status:")
        run_cmd("sudo pgrep -l hostapd")  # Show hostapd processes
        run_cmd(f"ip addr show {INTERFACE}")  # Show interface status

    except Exception as e:
        print(f"Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
