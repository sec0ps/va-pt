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

import argparse
import ipaddress
import socket
import subprocess
import sys
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

TOOL_PATHS = {
    'GetADUsers.py': None,
    'GetNPUsers.py': None,
    'GetUserSPNs.py': None,
    'enum4linux': None,
    'rpcclient': None,
    'smbclient': None
}

def find_tool_path(tool_name):
    """
    Locate the full path of a tool using multiple methods
    Returns the full path if found, None otherwise
    """
    import shutil

    # Method 1: Use shutil.which (checks PATH)
    tool_path = shutil.which(tool_name)
    if tool_path:
        return tool_path

    # Method 2: Check common installation paths
    common_paths = [
        '/usr/bin',
        '/usr/local/bin',
        '/opt',
        os.path.expanduser('~/.local/bin'),
        '/usr/share/doc'
    ]

    for base_path in common_paths:
        try:
            # Use find command to search recursively
            cmd = ['find', base_path, '-name', tool_name, '-type', 'f', '-executable', '2>/dev/null']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)

            if result.returncode == 0 and result.stdout.strip():
                paths = result.stdout.strip().split('\n')
                # Return the first match
                if paths:
                    return paths[0]
        except:
            continue

    # Method 3: Try locate command if available
    try:
        cmd = ['locate', '-l', '1', tool_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]
    except:
        pass

    # Method 4: Check Python site-packages for impacket scripts
    if tool_name.endswith('.py'):
        try:
            import site
            site_packages = site.getsitepackages()

            for sp in site_packages:
                impacket_path = os.path.join(sp, 'impacket', 'examples', tool_name)
                if os.path.isfile(impacket_path) and os.access(impacket_path, os.X_OK):
                    return impacket_path
        except:
            pass

    # Method 5: Check if it's in current directory or PATH as-is
    if os.path.isfile(tool_name) and os.access(tool_name, os.X_OK):
        return os.path.abspath(tool_name)

    return None

def initialize_tools():
    """
    Initialize all required tools and verify they exist
    Returns True if all critical tools are found, False otherwise
    """
    print(f"\n{Colors.BOLD}[*] Locating required tools...{Colors.RESET}")

    critical_tools = ['rpcclient', 'smbclient']
    optional_tools = ['GetADUsers.py', 'GetNPUsers.py', 'enum4linux']

    all_critical_found = True

    # Locate all tools
    for tool in TOOL_PATHS.keys():
        # Try with and without .pl extension for enum4linux
        if tool == 'enum4linux':
            path = find_tool_path('enum4linux') or find_tool_path('enum4linux.pl')
        else:
            path = find_tool_path(tool)

        TOOL_PATHS[tool] = path

        if path:
            print(f"{Colors.GREEN}[+] Found {tool}: {path}{Colors.RESET}")
        else:
            if tool in critical_tools:
                print(f"{Colors.RED}[!] CRITICAL: {tool} not found{Colors.RESET}")
                all_critical_found = False
            else:
                print(f"{Colors.YELLOW}[!] Optional: {tool} not found (functionality limited){Colors.RESET}")

    if not all_critical_found:
        print(f"\n{Colors.RED}[!] Critical tools missing. Install required packages:{Colors.RESET}")
        print(f"    apt-get install samba-common-bin")
        return False

    # Provide installation hints for missing optional tools
    missing_optional = [tool for tool in optional_tools if not TOOL_PATHS[tool]]
    if missing_optional:
        print(f"\n{Colors.YELLOW}[*] To enable full functionality, install:{Colors.RESET}")
        if 'GetADUsers.py' in missing_optional or 'GetNPUsers.py' in missing_optional:
            print(f"    pip install impacket")
        if 'enum4linux' in missing_optional:
            print(f"    apt-get install enum4linux")

    print()
    return True

def get_tool_command(tool_name, args):
    """
    Build command list for a tool using its located path
    Returns command list ready for subprocess, or None if tool not found
    """
    tool_path = TOOL_PATHS.get(tool_name)

    if not tool_path:
        return None

    # For Python scripts, we might need to explicitly call with python3
    if tool_name.endswith('.py') and not os.access(tool_path, os.X_OK):
        return ['python3', tool_path] + args
    else:
        return [tool_path] + args

def print_banner():
    banner = f"""
{Colors.BLUE}{'='*60}
    Active Directory Enumeration Tool
{'='*60}{Colors.RESET}
    """
    print(banner)

def parse_exclusions(exclude_list):
    """
    Parse exclusion list and expand any subnets to individual IPs
    Returns a set of IPs to exclude
    """
    excluded_ips = set()

    for item in exclude_list:
        item = item.strip()
        if not item:
            continue

        try:
            # Check if it's a subnet
            if '/' in item:
                network = ipaddress.ip_network(item, strict=False)
                excluded_ips.update([str(ip) for ip in network.hosts()])
            else:
                # Single IP
                ipaddress.ip_address(item)  # Validate
                excluded_ips.add(item)
        except ValueError:
            print(f"{Colors.YELLOW}[!] Invalid exclusion IP/subnet: {item}{Colors.RESET}")

    return excluded_ips

def read_targets(filename, excluded_ips=None):
    """Read targets from file and expand subnets to individual IPs"""
    if excluded_ips is None:
        excluded_ips = set()

    targets = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                try:
                    # Check if it's a subnet
                    if '/' in line:
                        network = ipaddress.ip_network(line, strict=False)
                        for ip in network.hosts():
                            ip_str = str(ip)
                            if ip_str not in excluded_ips:
                                targets.append(ip_str)
                    else:
                        # Single IP
                        ipaddress.ip_address(line)  # Validate
                        if line not in excluded_ips:
                            targets.append(line)
                except ValueError:
                    print(f"{Colors.YELLOW}[!] Invalid IP/subnet: {line}{Colors.RESET}")

    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {filename}{Colors.RESET}")
        sys.exit(1)

    return targets

def check_port(ip, port, timeout=2):
    """Check if a port is open on target"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def identify_dc(ip):
    """
    Identify if target is a Domain Controller by checking common DC ports
    DC typically has: 88 (Kerberos), 389 (LDAP), 636 (LDAPS), 445 (SMB), 3268/3269 (Global Catalog)
    """
    dc_ports = {
        88: 'Kerberos',
        389: 'LDAP',
        636: 'LDAPS',
        445: 'SMB',
        3268: 'Global Catalog',
        3269: 'Global Catalog SSL',
        53: 'DNS'
    }

    open_ports = {}
    for port, service in dc_ports.items():
        if check_port(ip, port, timeout=1):
            open_ports[port] = service

    # Consider it a DC if it has Kerberos, SMB, and either LDAP or LDAPS
    has_kerberos = 88 in open_ports
    has_smb = 445 in open_ports
    has_ldap = 389 in open_ports or 636 in open_ports

    is_dc = has_kerberos and has_smb and has_ldap

    return is_dc, open_ports

def scan_for_dcs(targets, max_threads=50):
    """Scan targets to identify Domain Controllers"""
    print(f"\n{Colors.BOLD}[*] Scanning {len(targets)} targets for Domain Controllers...{Colors.RESET}")
    dcs = []
    completed = 0
    total = len(targets)

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {executor.submit(identify_dc, ip): ip for ip in targets}

            try:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1

                    try:
                        is_dc, open_ports = future.result()
                        if is_dc:
                            dcs.append({'ip': ip, 'ports': open_ports})
                            services = ', '.join([f"{p}({s})" for p, s in open_ports.items()])
                            # Clear progress line and print DC found
                            print(f"\r{' ' * 80}\r{Colors.GREEN}[+] Domain Controller found: {ip} [{services}]{Colors.RESET}")
                    except Exception as e:
                        pass

                    # Update progress bar
                    percent = (completed / total) * 100
                    bar_length = 40
                    filled = int(bar_length * completed / total)
                    bar = '█' * filled + '░' * (bar_length - filled)
                    print(f"\r{Colors.BLUE}[*] Progress: [{bar}] {completed}/{total} ({percent:.1f}%) - {len(dcs)} DC(s) found{Colors.RESET}", end='', flush=True)

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Scan interrupted. Cancelling remaining tasks...{Colors.RESET}")
                for future in future_to_ip:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                raise
    except KeyboardInterrupt:
        if dcs:
            print(f"\n{Colors.YELLOW}[!] Returning {len(dcs)} Domain Controller(s) found so far{Colors.RESET}")
        raise

    # Clear progress line after completion
    print(f"\r{' ' * 80}\r", end='')
    return dcs

def get_domain_info(dc_ip, domain=None):
    """Extract domain information using rpcclient"""
    print(f"\n{Colors.BOLD}[*] Extracting domain information from {dc_ip}...{Colors.RESET}")

    domain_info = {}

    if not TOOL_PATHS['rpcclient']:
        print(f"{Colors.YELLOW}[!] rpcclient not available{Colors.RESET}")
        return domain_info

    try:
        cmd = get_tool_command('rpcclient', ['-U', '%', '-c', 'lsaquery', dc_ip])

        if not cmd:
            return domain_info

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            output = result.stdout
            for line in output.split('\n'):
                if 'Domain Name:' in line:
                    domain_info['domain'] = line.split(':', 1)[1].strip()
                elif 'Domain Sid:' in line:
                    domain_info['domain_sid'] = line.split(':', 1)[1].strip()

            if domain_info:
                print(f"{Colors.GREEN}[+] Domain: {domain_info.get('domain', 'N/A')}{Colors.RESET}")
                print(f"{Colors.GREEN}[+] Domain SID: {domain_info.get('domain_sid', 'N/A')}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Could not extract domain info: {e}{Colors.RESET}")

    return domain_info

def enum_users_impacket(dc_ip, domain=None, username='', password=''):
    """Enumerate domain users using impacket GetADUsers"""
    print(f"\n{Colors.BOLD}[*] Enumerating users from {dc_ip}...{Colors.RESET}")

    users = []

    if not TOOL_PATHS['GetADUsers.py']:
        print(f"{Colors.YELLOW}[!] GetADUsers.py not available, trying enum4linux...{Colors.RESET}")
        return enum_users_enum4linux(dc_ip)

    try:
        if domain:
            target = f"{domain}/{username if username else ''}:{password if password else ''}@{dc_ip}"
        else:
            target = f"{username if username else ''}:{password if password else ''}@{dc_ip}"

        cmd = get_tool_command('GetADUsers.py', ['-all', '-dc-ip', dc_ip, target])

        if not cmd:
            return enum_users_enum4linux(dc_ip)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            output = result.stdout
            for line in output.split('\n'):
                if line.strip() and not line.startswith('['):
                    users.append(line.strip())

            if users:
                print(f"{Colors.GREEN}[+] Found {len(users)} users{Colors.RESET}")
                return users

    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error enumerating users: {e}{Colors.RESET}")

    return enum_users_enum4linux(dc_ip)

def enum_users_enum4linux(dc_ip):
    """Enumerate users using enum4linux as fallback"""
    print(f"{Colors.BOLD}[*] Trying enum4linux for user enumeration...{Colors.RESET}")

    users = []

    if not TOOL_PATHS['enum4linux']:
        print(f"{Colors.YELLOW}[!] enum4linux not available{Colors.RESET}")
        return users

    try:
        cmd = get_tool_command('enum4linux', ['-U', dc_ip])

        if not cmd:
            return users

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            in_users_section = False
            for line in result.stdout.split('\n'):
                if 'user:' in line.lower():
                    in_users_section = True

                if in_users_section and line.strip():
                    if 'user:[' in line:
                        user = line.split('[')[1].split(']')[0]
                        users.append(user)

            if users:
                print(f"{Colors.GREEN}[+] Found {len(users)} users via enum4linux{Colors.RESET}")
                return users

    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error with enum4linux: {e}{Colors.RESET}")

    return users

def enum_groups_impacket(dc_ip, domain=None, username='', password=''):
    """Enumerate domain groups"""
    print(f"\n{Colors.BOLD}[*] Enumerating groups from {dc_ip}...{Colors.RESET}")

    groups = []

    if not TOOL_PATHS['rpcclient']:
        print(f"{Colors.YELLOW}[!] rpcclient not available{Colors.RESET}")
        return groups

    try:
        creds = f'{username}%{password}' if username else '%'
        cmd = get_tool_command('rpcclient', ['-U', creds, '-c', 'enumdomgroups', dc_ip])

        if not cmd:
            return groups

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'group:[' in line:
                    group = line.split('[')[1].split(']')[0]
                    rid = line.split('[')[2].split(']')[0] if '[' in line.split('[')[1].split(']')[1] else ''
                    groups.append({'name': group, 'rid': rid})

            if groups:
                print(f"{Colors.GREEN}[+] Found {len(groups)} groups{Colors.RESET}")
                return groups
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error enumerating groups: {e}{Colors.RESET}")

    return groups

def enum_shares(dc_ip, username='', password=''):
    """Enumerate SMB shares"""
    print(f"\n{Colors.BOLD}[*] Enumerating shares from {dc_ip}...{Colors.RESET}")

    shares = []

    if not TOOL_PATHS['smbclient']:
        print(f"{Colors.YELLOW}[!] smbclient not available{Colors.RESET}")
        return shares

    try:
        creds = f'{username}%{password}' if username else '%'
        cmd = get_tool_command('smbclient', ['-L', dc_ip, '-U', creds, '-N'])

        if not cmd:
            return shares

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            in_shares = False
            for line in result.stdout.split('\n'):
                if 'Sharename' in line:
                    in_shares = True
                    continue

                if in_shares and line.strip():
                    parts = line.split()
                    if len(parts) >= 2 and not line.startswith('SMB'):
                        share_name = parts[0]
                        share_type = parts[1]
                        shares.append({'name': share_name, 'type': share_type})

            if shares:
                print(f"{Colors.GREEN}[+] Found {len(shares)} shares{Colors.RESET}")
                for share in shares:
                    print(f"    - {share['name']} ({share['type']})")
                return shares
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error enumerating shares: {e}{Colors.RESET}")

    return shares

def enum_asreproast(dc_ip, domain, output_dir):
    """Check for AS-REP Roastable accounts"""
    print(f"\n{Colors.BOLD}[*] Checking for AS-REP Roastable accounts...{Colors.RESET}")

    if not TOOL_PATHS['GetNPUsers.py']:
        print(f"{Colors.YELLOW}[!] GetNPUsers.py not available{Colors.RESET}")
        return False

    try:
        output_file = os.path.join(output_dir, f'asrep_{dc_ip}.txt')
        users_file = os.path.join(output_dir, f'users_{dc_ip}.txt')

        if not os.path.exists(users_file):
            print(f"{Colors.YELLOW}[!] No users file found for AS-REP check{Colors.RESET}")
            return False

        cmd = get_tool_command('GetNPUsers.py', [
            domain + '/', '-dc-ip', dc_ip, '-no-pass', '-usersfile',
            users_file, '-format', 'hashcat', '-outputfile', output_file
        ])

        if not cmd:
            return False

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"{Colors.GREEN}[+] AS-REP Roastable accounts found! Saved to {output_file}{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}[!] No AS-REP Roastable accounts found{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.YELLOW}[!] Error checking AS-REP roast: {e}{Colors.RESET}")

    return False

def save_results(dc_info, output_dir):
    """Save enumeration results to files"""
    try:
        os.makedirs(output_dir, exist_ok=True)

        dc_ip = dc_info['ip']
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Save users
        if dc_info.get('users'):
            user_file = os.path.join(output_dir, f'users_{dc_ip}.txt')
            with open(user_file, 'w') as f:
                for user in dc_info['users']:
                    f.write(f"{user}\n")
            print(f"{Colors.GREEN}[+] Users saved to {user_file}{Colors.RESET}")

        # Save groups
        if dc_info.get('groups'):
            group_file = os.path.join(output_dir, f'groups_{dc_ip}.txt')
            with open(group_file, 'w') as f:
                for group in dc_info['groups']:
                    f.write(f"{group['name']} (RID: {group['rid']})\n")
            print(f"{Colors.GREEN}[+] Groups saved to {group_file}{Colors.RESET}")

        # Save shares
        if dc_info.get('shares'):
            share_file = os.path.join(output_dir, f'shares_{dc_ip}.txt')
            with open(share_file, 'w') as f:
                for share in dc_info['shares']:
                    f.write(f"{share['name']} - {share['type']}\n")
            print(f"{Colors.GREEN}[+] Shares saved to {share_file}{Colors.RESET}")

        # Save JSON summary
        json_file = os.path.join(output_dir, f'ad_enum_{dc_ip}_{timestamp}.json')
        with open(json_file, 'w') as f:
            json.dump(dc_info, f, indent=2)
        print(f"{Colors.GREEN}[+] Full results saved to {json_file}{Colors.RESET}")

    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving results: {e}{Colors.RESET}")

def cleanup_and_exit(output_dir=None, exit_code=0):
    """Perform cleanup and exit gracefully"""
    if output_dir and os.path.exists(output_dir):
        print(f"\n{Colors.GREEN}[+] Results saved to: {output_dir}/{Colors.RESET}")

    if exit_code == 0:
        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Enumeration complete!{Colors.RESET}")
    elif exit_code == 130:
        print(f"\n{Colors.YELLOW}[!] Script interrupted by user{Colors.RESET}")

    sys.exit(exit_code)

def main():
    parser = argparse.ArgumentParser(
        description='Active Directory Enumeration Tool for Authorized Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t targets.txt
  %(prog)s -t targets.txt --exclude 192.168.1.1 192.168.1.5
  %(prog)s -t targets.txt --exclude 192.168.1.0/28
  %(prog)s -t targets.txt -u admin -p pass -d CORP.LOCAL
        """
    )
    parser.add_argument('-t', '--targets', required=True, help='File containing IPs/subnets (one per line)')
    parser.add_argument('-o', '--output', default='ad_enum_results', help='Output directory (default: ad_enum_results)')
    parser.add_argument('-d', '--domain', help='Domain name (optional, will attempt to discover)')
    parser.add_argument('-u', '--username', default='', help='Username for authenticated enumeration')
    parser.add_argument('-p', '--password', default='', help='Password for authenticated enumeration')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads for DC discovery (default: 50)')
    parser.add_argument('--skip-asrep', action='store_true', help='Skip AS-REP roasting checks')
    parser.add_argument('--exclude', nargs='+', default=[], help='IP addresses or subnets to exclude from scanning')

    args = parser.parse_args()

    try:
        print_banner()

        # Initialize and locate all tools
        if not initialize_tools():
            print(f"\n{Colors.RED}[!] Cannot continue without critical tools{Colors.RESET}")
            sys.exit(1)

        # Parse exclusions
        excluded_ips = set()
        if args.exclude:
            print(f"{Colors.BOLD}[*] Processing exclusions...{Colors.RESET}")
            excluded_ips = parse_exclusions(args.exclude)
            if excluded_ips:
                print(f"{Colors.YELLOW}[*] Excluding {len(excluded_ips)} IP(s) from scan{Colors.RESET}")

        # Read and expand targets
        targets = read_targets(args.targets, excluded_ips)
        print(f"{Colors.BOLD}[*] Loaded {len(targets)} target IPs{Colors.RESET}")

        if not targets:
            print(f"{Colors.RED}[!] No targets to scan after exclusions{Colors.RESET}")
            sys.exit(1)

        # Scan for Domain Controllers
        dcs = scan_for_dcs(targets, max_threads=args.threads)

        if not dcs:
            print(f"\n{Colors.RED}[!] No Domain Controllers found{Colors.RESET}")
            sys.exit(1)

        print(f"\n{Colors.GREEN}[+] Found {len(dcs)} Domain Controller(s){Colors.RESET}")

        # Enumerate each DC
        for dc in dcs:
            dc_ip = dc['ip']
            print(f"\n{Colors.BOLD}{'='*60}")
            print(f"[*] Enumerating DC: {dc_ip}")
            print(f"{'='*60}{Colors.RESET}")

            # Get domain info
            domain_info = get_domain_info(dc_ip, args.domain)
            domain = domain_info.get('domain', args.domain)

            # Store all enumerated data
            dc['domain_info'] = domain_info
            dc['users'] = enum_users_impacket(dc_ip, domain, args.username, args.password)
            dc['groups'] = enum_groups_impacket(dc_ip, domain, args.username, args.password)
            dc['shares'] = enum_shares(dc_ip, args.username, args.password)

            # Save results
            save_results(dc, args.output)

            # AS-REP roasting check
            if not args.skip_asrep and domain and dc['users']:
                enum_asreproast(dc_ip, domain, args.output)

        print(f"\n{Colors.BOLD}{Colors.GREEN}[+] Enumeration complete! Results saved to {args.output}/{Colors.RESET}")

        # Summary
        print(f"\n{Colors.BOLD}=== SUMMARY ==={Colors.RESET}")
        for dc in dcs:
            print(f"\nDC: {dc['ip']}")
            print(f"  Domain: {dc.get('domain_info', {}).get('domain', 'N/A')}")
            print(f"  Users: {len(dc.get('users', []))}")
            print(f"  Groups: {len(dc.get('groups', []))}")
            print(f"  Shares: {len(dc.get('shares', []))}")

    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.RESET}")
        if 'args' in locals() and os.path.exists(args.output):
            print(f"{Colors.GREEN}[+] Partial results saved to {args.output}/{Colors.RESET}")
        sys.exit(130)

if __name__ == '__main__':
    main()
