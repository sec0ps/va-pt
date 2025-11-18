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

import subprocess
import argparse
import sys
import re

def snmp_walk(target, community, oid_name, oid):
    """Perform SNMP walk using snmpwalk command"""
    print(f"\n{'='*60}")
    print(f"[+] {oid_name}")
    print('='*60)

    try:
        result = subprocess.run(
            ['snmpwalk', '-v1', '-c', community, target, oid],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0 and result.stdout:
            print(result.stdout.strip())
            return result.stdout.strip().split('\n')
        else:
            print(f"[-] No data or error")
            return []
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout")
        return []
    except FileNotFoundError:
        print("[-] Error: snmpwalk not found. Install with: apt-get install snmp")
        sys.exit(1)

def full_walk_filter(target, community, filter_strings=True):
    """Do a full walk and filter for interesting data"""
    print(f"\n{'='*60}")
    print(f"[+] Full Walk - Filtering for Interesting Strings")
    print('='*60)

    try:
        result = subprocess.run(
            ['snmpwalk', '-v1', '-c', community, target],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0 and result.stdout:
            lines = result.stdout.strip().split('\n')
            interesting = []

            for line in lines:
                # Filter for STRING types with actual content (not empty, not just numbers)
                if 'STRING:' in line:
                    # Extract the string value
                    match = re.search(r'STRING:\s*"?([^"]+)"?', line)
                    if match:
                        value = match.group(1).strip()
                        # Filter out empty, numeric-only, or very short strings
                        if value and len(value) > 2 and not value.isdigit():
                            # Skip common noise
                            if value not in ['unknown', '0', '1', 'true', 'false']:
                                interesting.append(line)
                                print(line)

            return interesting
        else:
            print(f"[-] No data or error")
            return []
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout")
        return []

def main():
    parser = argparse.ArgumentParser(
        description='Dell iDRAC SNMP Information Extractor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -t 192.168.1.1
  %(prog)s -t 192.168.1.1 -c private
  %(prog)s -t 192.168.1.1 -o output.txt
        '''
    )

    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address')
    parser.add_argument('-c', '--community', default='public',
                        help='SNMP community string (default: public)')
    parser.add_argument('-o', '--output',
                        help='Output file to save results')
    parser.add_argument('--full-walk', action='store_true',
                    help='Do full SNMP walk and filter for interesting strings')

    args = parser.parse_args()

    # High-value OIDs for Dell iDRAC
    oids_to_check = {
        'System Description': '1.3.6.1.2.1.1.1.0',
        'System Name': '1.3.6.1.2.1.1.5.0',
        'System Contact': '1.3.6.1.2.1.1.4.0',
        'System Location': '1.3.6.1.2.1.1.6.0',
        'Dell System Info': '1.3.6.1.4.1.674.10892.5.1.1',
        'Dell Firmware': '1.3.6.1.4.1.674.10892.5.4.300.50.1',
        'Dell Hardware': '1.3.6.1.4.1.674.10892.5.4.300',
        'Network Config': '1.3.6.1.4.1.674.10892.5.4.1100',
        'IP Addresses': '1.3.6.1.2.1.4.20.1',
        'Network Interfaces': '1.3.6.1.2.1.2.2.1',
        'ARP Table': '1.3.6.1.2.1.4.22.1',
        'Routing Table': '1.3.6.1.2.1.4.21.1',
        'TCP Connections': '1.3.6.1.2.1.6.13.1'
    }

    print(f"[*] Target: {args.target}")
    print(f"[*] Community: {args.community}")
    print(f"[*] Starting SNMP enumeration...")

    all_results = []

    if args.full_walk:
        # Do comprehensive walk with filtering
        results = full_walk_filter(args.target, args.community)
        if results:
            all_results.extend(results)
    else:
        # Normal targeted OID checks
        for name, oid in oids_to_check.items():
            results = snmp_walk(args.target, args.community, name, oid)
            if results:
                all_results.extend([f"\n{'='*60}", f"[+] {name}", '='*60] + results)

    # Save to file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(f"Target: {args.target}\n")
                f.write(f"Community: {args.community}\n")
                f.write('\n'.join(all_results))
            print(f"\n[+] Results saved to {args.output}")
        except Exception as e:
            print(f"\n[-] Error saving to file: {e}")

    print(f"\n[*] Enumeration complete")

if __name__ == '__main__':
    main()
