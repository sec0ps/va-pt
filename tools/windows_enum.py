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

import argparse
import ipaddress
import socket
import subprocess
import sys
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import atexit
import signal

try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def cleanup_terminal():
    """Restore terminal to normal state"""
    try:
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        sys.stdout.flush()
    except:
        pass

# Register cleanup on exit
atexit.register(cleanup_terminal)

# Register cleanup on interrupt
def signal_handler(sig, frame):
    cleanup_terminal()
    sys.exit(130)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Windows-specific ports to check
WINDOWS_PORTS = {
    135: 'RPC',
    139: 'NetBIOS-SSN',
    445: 'SMB',
    3389: 'RDP',
    5985: 'WinRM HTTP',
    5986: 'WinRM HTTPS',
    88: 'Kerberos',
    389: 'LDAP',
    636: 'LDAPS',
    3268: 'Global Catalog',
    3269: 'Global Catalog SSL',
    53: 'DNS',
    1433: 'MSSQL'
}

TOOL_PATHS = {
    'nmap': None,
    'lookupsid.py': None,
    'samrdump.py': None,
    'rpcdump.py': None,
    'smbclient.py': None,
    'reg.py': None,
    'atexec.py': None,
    'netview.py': None,
    'GetADUsers.py': None,
    'GetUserSPNs.py': None
}


def find_tool_path(tool_name: str) -> Optional[str]:
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
        '/usr/share/doc',
        os.path.expanduser('~/tools')
    ]

    for base_path in common_paths:
        try:
            cmd = ['find', base_path, '-name', tool_name, '-type', 'f', '-executable']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, stderr=subprocess.DEVNULL)

            if result.returncode == 0 and result.stdout.strip():
                paths = result.stdout.strip().split('\n')
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

    # Check if it's in current directory
    if os.path.isfile(tool_name) and os.access(tool_name, os.X_OK):
        return os.path.abspath(tool_name)

    return None

def initialize_tools() -> bool:
    """
    Initialize all required tools and verify they exist
    Returns True if critical tools are found
    """
    print(f"\n[*] Locating Impacket tools...")

    # Critical tools
    critical_tools = ['lookupsid.py', 'smbclient.py']
    critical_found = False

    # Locate all tools
    for tool in TOOL_PATHS.keys():
        path = find_tool_path(tool)
        TOOL_PATHS[tool] = path

        if path:
            print(f"[+] Found {tool}: {path}")
            if tool in critical_tools:
                critical_found = True
        else:
            print(f"[!] {tool} not found (optional)")

    # Check Python libraries
    print(f"\n[*] Checking Python libraries...")

    if SCAPY_AVAILABLE:
        print(f"[+] Scapy available")
    else:
        print(f"[!] Scapy not available - install with: pip install scapy")

    if not critical_found:
        print(f"\n[!] Critical Impacket tools missing. Install with:")
        print(f"    pip install impacket")
        return False

    print()
    return True

def get_tool_command(tool_name: str, args: List[str]) -> Optional[List[str]]:
    """
    Build command list for a tool using its located path
    Returns command list ready for subprocess, or None if tool not found
    """
    tool_path = TOOL_PATHS.get(tool_name)

    if not tool_path:
        return None

    # For Python scripts, explicitly call with python3
    if tool_name.endswith('.py') and not os.access(tool_path, os.X_OK):
        return ['python3', tool_path] + args
    else:
        return [tool_path] + args


def print_banner():
    """Display tool banner"""
    banner = f"""
    Windows System Enumeration Tool
    """
    print(banner)


def parse_exclusions(exclude_list: List[str]) -> Set[str]:
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
            if '/' in item:
                network = ipaddress.ip_network(item, strict=False)
                excluded_ips.update([str(ip) for ip in network.hosts()])
            else:
                ipaddress.ip_address(item)  # Validate
                excluded_ips.add(item)
        except ValueError:
            print(f"[!] Invalid exclusion IP/subnet: {item}")

    return excluded_ips


def read_targets(filename: str, excluded_ips: Optional[Set[str]] = None) -> List[str]:
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
                    if '/' in line:
                        network = ipaddress.ip_network(line, strict=False)
                        for ip in network.hosts():
                            ip_str = str(ip)
                            if ip_str not in excluded_ips:
                                targets.append(ip_str)
                    else:
                        ipaddress.ip_address(line)  # Validate
                        if line not in excluded_ips:
                            targets.append(line)
                except ValueError:
                    print(f"[!] Invalid IP/subnet: {line}")

    except FileNotFoundError:
        print(f"[!] File not found: {filename}")
        sys.exit(1)

    return targets


def check_port_socket(ip: str, port: int, timeout: float = 2) -> bool:
    """Check if a port is open using socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def scan_windows_ports(ip: str, timeout: float = 1) -> Dict[int, str]:
    """
    Scan common Windows ports on target using nmap (or socket fallback)
    Returns dict of open ports with their services
    """
    open_ports = {}

    # Use nmap if available
    if TOOL_PATHS['nmap']:
        try:
            ports_str = ','.join([str(p) for p in WINDOWS_PORTS.keys()])

            cmd = get_tool_command('nmap', [
                '-p', ports_str,
                '--open',
                '-T4',
                '-Pn',
                '--host-timeout', '30s',
                '--max-retries', '1',
                ip
            ])

            if cmd:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)

                if result.returncode == 0:
                    # Parse nmap output
                    for line in result.stdout.split('\n'):
                        for port, service in WINDOWS_PORTS.items():
                            if f'{port}/tcp' in line and 'open' in line:
                                open_ports[port] = service

                    return open_ports
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    # Fallback to socket scanning if nmap fails or unavailable
    for port, service in WINDOWS_PORTS.items():
        if check_port_socket(ip, port, timeout):
            open_ports[port] = service

    return open_ports


def identify_windows_system(ip: str) -> Tuple[bool, Dict[int, str]]:
    """
    Identify if target is a Windows system by checking common Windows ports
    Returns (is_windows, open_ports_dict)
    """
    open_ports = scan_windows_ports(ip, timeout=1)

    # Consider it Windows if it has SMB (445) or NetBIOS (139) or RPC (135)
    has_smb = 445 in open_ports
    has_netbios = 139 in open_ports
    has_rpc = 135 in open_ports
    has_winrm = 5985 in open_ports or 5986 in open_ports

    is_windows = has_smb or has_netbios or has_rpc or has_winrm

    return is_windows, open_ports

def scan_for_windows_systems(targets: List[str], max_threads: int = 50) -> List[Dict]:
    """Scan targets to identify Windows systems"""
    print(f"\n[*] Scanning {len(targets)} targets for Windows systems...")

    windows_systems = []
    completed = 0
    total = len(targets)

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {executor.submit(identify_windows_system, ip): ip for ip in targets}

            try:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1

                    try:
                        is_windows, open_ports = future.result()
                        if is_windows:
                            windows_systems.append({'ip': ip, 'ports': open_ports})
                            services = ', '.join([f"{p}({s})" for p, s in open_ports.items()])
                            print(f"\r{' ' * 100}\r[+] Windows system found: {ip} [{services}]")
                    except Exception as e:
                        pass

                    # Update progress bar
                    percent = (completed / total) * 100
                    bar_length = 40
                    filled = int(bar_length * completed / total)
                    bar = '█' * filled + '░' * (bar_length - filled)
                    print(f"\r[*] Progress: [{bar}] {completed}/{total} ({percent:.1f}%) - {len(windows_systems)} system(s) found", end='', flush=True)

            except KeyboardInterrupt:
                print(f"\n[!] Scan interrupted. Cancelling remaining tasks...")
                for future in future_to_ip:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                raise

    except KeyboardInterrupt:
        if windows_systems:
            print(f"\n[!] Returning {len(windows_systems)} Windows system(s) found so far")
        raise

    print(f"\r{' ' * 100}\r", end='', flush=True)
    return windows_systems

def enum_lookupsid(ip: str, domain: str = '', username: str = '', password: str = '', output_dir: str = '') -> Dict:
    """
    Enumerate users, groups, and domain SID using Impacket lookupsid.py (RID cycling)
    This replaces enum4linux user/group enumeration
    """
    print(f"[*] Enumerating via RID cycling (lookupsid.py)...")

    result_data = {
        'users': [],
        'groups': [],
        'domain_sid': None,
        'computer_name': None,
        'domain_name': None
    }

    if not TOOL_PATHS['lookupsid.py']:
        print(f"[!] lookupsid.py not available")
        return result_data

    try:
        # Build target string
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            # Try anonymous/guest access
            target = f'{domain}/guest@{ip}' if domain else f'guest@{ip}'

        cmd = get_tool_command('lookupsid.py', [target, '-no-pass'] if not password else [target])

        if not cmd:
            return result_data

        # Save output to file for analysis
        output_file = os.path.join(output_dir, f'lookupsid_{ip}.txt')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Save raw output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\n=== STDERR ===\n")
                f.write(result.stderr)

        if result.returncode == 0 or result.stdout:
            output = result.stdout

            # Extract Domain SID
            for line in output.split('\n'):
                if 'Domain SID is:' in line or 'Domain SID:' in line:
                    sid_match = re.search(r'S-1-5-21-[\d-]+', line)
                    if sid_match:
                        result_data['domain_sid'] = sid_match.group(0)

                # Extract domain/computer name
                if '\\' in line and ('SidTypeUser' in line or 'SidTypeDomain' in line):
                    parts = line.split('\\')
                    if len(parts) >= 2:
                        domain_part = parts[0].split(':')[-1].strip()
                        if not result_data['domain_name'] and 'SidTypeDomain' in line:
                            result_data['domain_name'] = domain_part
                        elif not result_data['computer_name']:
                            result_data['computer_name'] = domain_part

            # Parse users
            for line in output.split('\n'):
                if 'SidTypeUser' in line:
                    try:
                        user_part = line.split(':')[1].split('(')[0].strip()
                        if '\\' in user_part:
                            user = user_part.split('\\')[1]
                        else:
                            user = user_part

                        # Filter out machine accounts
                        if not user.endswith('$'):
                            result_data['users'].append(user)
                    except:
                        pass

            # Parse groups
            for line in output.split('\n'):
                if 'SidTypeGroup' in line or 'SidTypeAlias' in line:
                    try:
                        group_part = line.split(':')[1].split('(')[0].strip()
                        if '\\' in group_part:
                            group = group_part.split('\\')[1]
                        else:
                            group = group_part
                        result_data['groups'].append(group)
                    except:
                        pass

            # Remove duplicates
            result_data['users'] = list(set(result_data['users']))
            result_data['groups'] = list(set(result_data['groups']))

            if result_data['users']:
                print(f"[+] Found {len(result_data['users'])} users via RID cycling")
            if result_data['groups']:
                print(f"[+] Found {len(result_data['groups'])} groups via RID cycling")
            if result_data['domain_sid']:
                print(f"[+] Domain SID: {result_data['domain_sid']}")
            if result_data['domain_name']:
                print(f"[+] Domain: {result_data['domain_name']}")

            result_data['output_file'] = output_file

    except subprocess.TimeoutExpired:
        print(f"[!] lookupsid.py timed out")
    except Exception as e:
        print(f"[!] Error running lookupsid.py: {e}")

    return result_data

def enum_samrdump(ip: str, domain: str = '', username: str = '', password: str = '') -> Dict:
    """
    Enumerate users and password policy using Impacket samrdump.py
    """
    print(f"[*] Enumerating SAM database (samrdump.py)...")

    result_data = {
        'users': [],
        'password_policy': {}
    }

    if not TOOL_PATHS['samrdump.py']:
        print(f"[!] samrdump.py not available")
        return result_data

    try:
        # Build target string
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            # Try anonymous/guest access
            target = f'{domain}/guest@{ip}' if domain else f'guest@{ip}'

        cmd = get_tool_command('samrdump.py', [target, '-no-pass'] if not password else [target])

        if not cmd:
            return result_data

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 or result.stdout:
            output = result.stdout

            # Parse users
            for line in output.split('\n'):
                if 'Found user:' in line:
                    try:
                        user = line.split('Found user:')[1].split(',')[0].strip()
                        result_data['users'].append(user)
                    except:
                        pass

            # Parse password policy
            policy_keys = ['Minimum password length', 'Password history length',
                          'Maximum password age', 'Password Complexity Flags',
                          'Minimum password age', 'Reset Account Lockout Counter',
                          'Locked Account Duration', 'Account Lockout Threshold']

            for line in output.split('\n'):
                for key in policy_keys:
                    if key in line:
                        try:
                            value = line.split(':')[1].strip()
                            result_data['password_policy'][key] = value
                        except:
                            pass

            if result_data['users']:
                print(f"[+] Found {len(result_data['users'])} users via SAM")
            if result_data['password_policy']:
                print(f"[+] Retrieved password policy")

    except subprocess.TimeoutExpired:
        print(f"[!] samrdump.py timed out")
    except Exception as e:
        print(f"[!] Error running samrdump.py: {e}")

    return result_data

def enum_rpc(ip: str, output_dir: str, domain: str = '', username: str = '', password: str = '') -> Dict:
    """
    Enumerate RPC endpoints using Impacket rpcdump.py
    """
    print(f"[*] Enumerating RPC endpoints (rpcdump.py)...")

    result_data = {
        'endpoints': [],
        'endpoint_count': 0
    }

    if not TOOL_PATHS['rpcdump.py']:
        print(f"[!] rpcdump.py not available")
        return result_data

    try:
        # Build target string
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            # Try anonymous/guest access
            target = f'{domain}/guest@{ip}' if domain else f'guest@{ip}'

        cmd = get_tool_command('rpcdump.py', [target])

        if not cmd:
            return result_data

        # Save output to file
        output_file = os.path.join(output_dir, f'rpcdump_{ip}.txt')

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        # Save raw output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n\n=== STDERR ===\n")
                f.write(result.stderr)

        if result.returncode == 0 or result.stdout:
            output = result.stdout

            # Parse endpoints
            for line in output.split('\n'):
                if 'UUID' in line or 'ncacn_' in line or 'Protocol:' in line:
                    result_data['endpoints'].append(line.strip())

            result_data['endpoint_count'] = len(result_data['endpoints'])
            result_data['output_file'] = output_file

            if result_data['endpoint_count'] > 0:
                print(f"[+] Found {result_data['endpoint_count']} RPC endpoints")

    except subprocess.TimeoutExpired:
        print(f"[!] rpcdump.py timed out")
    except Exception as e:
        print(f"[!] Error running rpcdump.py: {e}")

    return result_data

def enum_shares(ip: str, domain: str = '', username: str = '', password: str = '') -> Dict:
    """
    Enumerate shares using Impacket smbclient.py
    """
    print(f"[*] Enumerating shares (smbclient.py)...")

    result_data = {
        'shares': [],
        'raw_output': ''
    }

    if not TOOL_PATHS['smbclient.py']:
        print(f"[!] smbclient.py not available")
        return result_data

    try:
        # Build target string
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            # Try anonymous/guest access
            target = f'{domain}/guest@{ip}' if domain else f'guest@{ip}'

        cmd = get_tool_command('smbclient.py', [target, '-no-pass'] if not password else [target])

        if not cmd:
            return result_data

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                              input='shares\nexit\n')

        if result.returncode == 0 or result.stdout:
            output = result.stdout
            result_data['raw_output'] = output

            # Parse shares
            for line in output.split('\n'):
                if 'Disk' in line or 'IPC' in line or 'Printer' in line:
                    try:
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0]
                            share_type = parts[1] if len(parts) > 1 else 'Unknown'
                            result_data['shares'].append({'name': share_name, 'type': share_type})
                    except:
                        pass

            if result_data['shares']:
                print(f"[+] Found {len(result_data['shares'])} shares")

    except subprocess.TimeoutExpired:
        print(f"[!] smbclient.py timed out")
    except Exception as e:
        print(f"[!] Error running smbclient.py: {e}")

    return result_data

def enum_sessions(ip: str, domain: str = '', username: str = '', password: str = '') -> Dict:
    """
    Enumerate active sessions using Impacket netview.py
    """
    print(f"[*] Enumerating active sessions (netview.py)...")

    result_data = {
        'sessions': []
    }

    if not TOOL_PATHS['netview.py']:
        print(f"[!] netview.py not available")
        return result_data

    try:
        # Build target string
        if username and password:
            target = f'{domain}/{username}:{password}@{ip}' if domain else f'{username}:{password}@{ip}'
        else:
            # Try anonymous/guest access
            target = f'{domain}/guest@{ip}' if domain else f'guest@{ip}'

        cmd = get_tool_command('netview.py', [target, '-no-pass'] if not password else [target])

        if not cmd:
            return result_data

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0 or result.stdout:
            output = result.stdout

            # Parse sessions
            for line in output.split('\n'):
                if line.strip() and not line.startswith('['):
                    result_data['sessions'].append(line.strip())

            if result_data['sessions']:
                print(f"[+] Found {len(result_data['sessions'])} active sessions")

    except subprocess.TimeoutExpired:
        print(f"[!] netview.py timed out")
    except Exception as e:
        print(f"[!] Error running netview.py: {e}")

    return result_data

def enumerate_windows_system(ip: str, open_ports: Dict[int, str], output_dir: str,
                            username: str = '', password: str = '', domain: str = '') -> Dict:
    """
    Perform comprehensive enumeration of a Windows system
    """
    print(f"\n{'='*70}")
    print(f"ENUMERATING: {ip}")
    print(f"{'='*70}")

    system_info = {
        'ip': ip,
        'ports': open_ports,
        'timestamp': datetime.now().isoformat()
    }

    # RID Cycling (lookupsid.py) - Primary user/group enumeration
    try:
        lookupsid_data = enum_lookupsid(ip, domain, username, password, output_dir)
        system_info['lookupsid'] = lookupsid_data
    except Exception as e:
        print(f"[!] lookupsid enumeration error: {e}")

    # SAM enumeration (samrdump.py) - Additional users and password policy
    try:
        sam_data = enum_samrdump(ip, domain, username, password)
        system_info['sam'] = sam_data
    except Exception as e:
        print(f"[!] SAM enumeration error: {e}")

    # RPC enumeration
    try:
        rpc_data = enum_rpc(ip, output_dir, domain, username, password)
        system_info['rpc'] = rpc_data
    except Exception as e:
        print(f"[!] RPC enumeration error: {e}")

    # Share enumeration
    try:
        shares_data = enum_shares(ip, domain, username, password)
        system_info['shares'] = shares_data
    except Exception as e:
        print(f"[!] Share enumeration error: {e}")

    # Session enumeration
    try:
        sessions_data = enum_sessions(ip, domain, username, password)
        system_info['sessions'] = sessions_data
    except Exception as e:
        print(f"[!] Session enumeration error: {e}")

    return system_info

def save_results(system_info: Dict, output_dir: str):
    """
    Save enumeration results to files
    """
    ip = system_info['ip']

    try:

        # Save detailed text report
        report_file = os.path.join(output_dir, f'{ip}_enum_report.txt')
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write(f"WINDOWS SYSTEM ENUMERATION REPORT\n")
            f.write("="*70 + "\n\n")

            f.write(f"Target IP: {ip}\n")
            f.write(f"Scan Time: {system_info['timestamp']}\n")
            f.write(f"Open Ports: {', '.join([f'{p}({s})' for p, s in system_info['ports'].items()])}\n")
            f.write("\n")

            # SYSTEM INFORMATION
            f.write("="*70 + "\n")
            f.write("SYSTEM INFORMATION\n")
            f.write("="*70 + "\n\n")

            if 'lookupsid' in system_info:
                if system_info['lookupsid'].get('computer_name'):
                    f.write(f"Computer Name: {system_info['lookupsid']['computer_name']}\n")
                if system_info['lookupsid'].get('domain_name'):
                    f.write(f"Domain: {system_info['lookupsid']['domain_name']}\n")
                if system_info['lookupsid'].get('domain_sid'):
                    f.write(f"Domain SID: {system_info['lookupsid']['domain_sid']}\n")
            f.write("\n")

            # USERS
            f.write("="*70 + "\n")
            f.write("USER ACCOUNTS\n")
            f.write("="*70 + "\n\n")

            # Users from RID cycling
            if 'lookupsid' in system_info and 'users' in system_info['lookupsid']:
                users = system_info['lookupsid']['users']
                if users:
                    f.write("[Users via RID Cycling (lookupsid.py)]\n")
                    f.write("-"*70 + "\n")
                    for user in sorted(users):
                        f.write(f"  {user}\n")
                    f.write(f"\n[Total: {len(users)} users]\n\n")

            # Users from SAM
            if 'sam' in system_info and 'users' in system_info['sam']:
                sam_users = system_info['sam']['users']
                if sam_users:
                    f.write("[Users via SAM Dump (samrdump.py)]\n")
                    f.write("-"*70 + "\n")
                    for user in sorted(sam_users):
                        f.write(f"  {user}\n")
                    f.write(f"\n[Total: {len(sam_users)} users]\n\n")

            # GROUPS
            if 'lookupsid' in system_info and 'groups' in system_info['lookupsid']:
                groups = system_info['lookupsid']['groups']
                if groups:
                    f.write("="*70 + "\n")
                    f.write("GROUPS\n")
                    f.write("="*70 + "\n\n")
                    for group in sorted(groups):
                        f.write(f"  {group}\n")
                    f.write(f"\n[Total: {len(groups)} groups]\n\n")

            # PASSWORD POLICY
            if 'sam' in system_info and 'password_policy' in system_info['sam']:
                policy = system_info['sam']['password_policy']
                if policy:
                    f.write("="*70 + "\n")
                    f.write("PASSWORD POLICY\n")
                    f.write("="*70 + "\n\n")
                    for key, value in policy.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")

            # SHARES
            if 'shares' in system_info and 'shares' in system_info['shares']:
                shares = system_info['shares']['shares']
                if shares:
                    f.write("="*70 + "\n")
                    f.write("SHARES\n")
                    f.write("="*70 + "\n\n")
                    for share in shares:
                        f.write(f"  {share['name']:<30} {share['type']}\n")
                    f.write(f"\n[Total: {len(shares)} shares]\n\n")

            # RPC ENDPOINTS
            if 'rpc' in system_info and 'output_file' in system_info['rpc']:
                f.write("[RPC ENDPOINTS - COMPLETE LISTING]\n")
                f.write("-"*70 + "\n")
                f.write(f"Total Endpoints: {system_info['rpc'].get('endpoint_count', 0)}\n\n")

                try:
                    with open(system_info['rpc']['output_file'], 'r') as rpc_file:
                        f.write(rpc_file.read())
                except Exception as e:
                    f.write(f"Could not read rpcdump output: {e}\n")

                f.write("\n\n")

            # SESSIONS
            if 'sessions' in system_info and 'sessions' in system_info['sessions']:
                f.write("[ACTIVE SESSIONS]\n")
                f.write("-"*70 + "\n")
                sessions = system_info['sessions']['sessions']
                if sessions:
                    for session in sessions:
                        f.write(f"{session}\n")
                    f.write(f"\n[Total: {len(sessions)} sessions]\n")
                else:
                    f.write("No active sessions\n")
                f.write("\n\n")

            # RAW TOOL OUTPUTS
            f.write("\n")
            f.write("="*70 + "\n")
            f.write("RAW TOOL OUTPUTS\n")
            f.write("="*70 + "\n\n")

            # RID Cycling
            if 'lookupsid' in system_info and 'output_file' in system_info['lookupsid']:
                f.write("[LOOKUPSID.PY - RID CYCLING]\n")
                f.write("-"*70 + "\n")
                try:
                    with open(system_info['lookupsid']['output_file'], 'r') as raw_file:
                        f.write(raw_file.read())
                except Exception as e:
                    f.write(f"Could not read lookupsid output: {e}\n")
                f.write("\n\n")

            # Share Enumeration
            if 'shares' in system_info and 'raw_output' in system_info['shares']:
                f.write("[SHARE ENUMERATION - RPCCLIENT]\n")
                f.write("-"*70 + "\n")
                f.write(system_info['shares']['raw_output'])
                f.write("\n\n")

            f.write("="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")

        print(f"[+] Complete report saved to {report_file}")

        # Clean up individual raw files
        if 'lookupsid' in system_info and 'output_file' in system_info['lookupsid']:
            try:
                os.remove(system_info['lookupsid']['output_file'])
            except:
                pass

        if 'rpc' in system_info and 'output_file' in system_info['rpc']:
            try:
                os.remove(system_info['rpc']['output_file'])
            except:
                pass

    except Exception as e:
        print(f"[!] Error saving results: {e}")
        import traceback
        traceback.print_exc()

def print_summary(systems: List[Dict]):
    """Print enumeration summary"""
    print(f"\n{'='*70}")
    print("=== ENUMERATION SUMMARY ===")
    print(f"{'='*70}\n")

    for system in systems:
        print(f"System: {system['ip']}")

        # Domain/Computer info
        if 'lookupsid' in system:
            if 'computer_name' in system['lookupsid'] and system['lookupsid']['computer_name']:
                print(f"  Computer Name: {system['lookupsid']['computer_name']}")
            if 'domain_name' in system['lookupsid'] and system['lookupsid']['domain_name']:
                print(f"  Domain: {system['lookupsid']['domain_name']}")
            if 'domain_sid' in system['lookupsid'] and system['lookupsid']['domain_sid']:
                print(f"  Domain SID: {system['lookupsid']['domain_sid']}")

        # User counts
        if 'lookupsid' in system and 'users' in system['lookupsid']:
            print(f"  Users Found (RID cycling): {len(system['lookupsid']['users'])}")

        if 'sam' in system and 'users' in system['sam']:
            print(f"  Users Found (SAM): {len(system['sam']['users'])}")

        # Group count
        if 'lookupsid' in system and 'groups' in system['lookupsid']:
            print(f"  Groups Found: {len(system['lookupsid']['groups'])}")

        # Share count
        if 'shares' in system and 'shares' in system['shares']:
            print(f"  Shares Found: {len(system['shares']['shares'])}")

        # Password policy
        if 'sam' in system and 'password_policy' in system['sam']:
            if system['sam']['password_policy']:
                print(f"  Password Policy: Retrieved")

        # RPC endpoints
        if 'rpc' in system and 'endpoint_count' in system['rpc']:
            print(f"  RPC Endpoints: {system['rpc']['endpoint_count']}")

        # Sessions
        if 'sessions' in system and 'sessions' in system['sessions']:
            print(f"  Active Sessions: {len(system['sessions']['sessions'])}")

        # Open ports
        if 'ports' in system:
            ports_str = ', '.join([f"{p}({s})" for p, s in system['ports'].items()])
            print(f"  Open Ports: {ports_str}")

        print()

def main():
    parser = argparse.ArgumentParser(
        description='Windows System Enumeration Tool - Impacket Suite Only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t targets.txt
  %(prog)s -t targets.txt --exclude 192.168.1.1 192.168.1.5
  %(prog)s -t targets.txt --exclude 192.168.1.0/28
  %(prog)s -t targets.txt -u admin -p password -d CORP.LOCAL
  %(prog)s -t targets.txt --threads 100
        """
    )

    parser.add_argument('-t', '--targets', required=True,
                       help='File containing IPs/subnets (one per line)')
    parser.add_argument('-o', '--output', default='windows_enum_results',
                       help='Output directory (default: windows_enum_results)')
    parser.add_argument('-u', '--username', default='',
                       help='Username for authenticated enumeration')
    parser.add_argument('-p', '--password', default='',
                       help='Password for authenticated enumeration')
    parser.add_argument('-d', '--domain', default='',
                       help='Domain name (optional)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads for scanning (default: 50)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Port scan timeout in seconds (default: 1.0)')
    parser.add_argument('--exclude', nargs='+', default=[],
                       help='IP addresses or subnets to exclude from scanning')

    args = parser.parse_args()

    try:
        print_banner()

        # Initialize and locate all tools
        if not initialize_tools():
            print(f"\n[!] Critical tools missing. Cannot continue.")
            sys.exit(1)

        # Parse exclusions
        excluded_ips = set()
        if args.exclude:
            print(f"[*] Processing exclusions...")
            excluded_ips = parse_exclusions(args.exclude)
            if excluded_ips:
                print(f"[*] Excluding {len(excluded_ips)} IP(s) from scan")

        # Read and expand targets
        targets = read_targets(args.targets, excluded_ips)
        print(f"[*] Loaded {len(targets)} target IPs")

        if not targets:
            print(f"[!] No targets to scan after exclusions")
            sys.exit(1)

        # Scan for Windows systems
        windows_systems = scan_for_windows_systems(targets, max_threads=args.threads)

        if not windows_systems:
            print(f"\n[!] No Windows systems found")
            sys.exit(0)

        print(f"\n[+] Found {len(windows_systems)} Windows system(s)")

        # Create output directory
        os.makedirs(args.output, exist_ok=True)

        # Enumerate each Windows system
        enumerated_systems = []
        for system in windows_systems:
            try:
                system_info = enumerate_windows_system(
                    system['ip'],
                    system['ports'],
                    args.output,
                    args.username,
                    args.password,
                    args.domain
                )
                enumerated_systems.append(system_info)

                # Save results for this system
                save_results(system_info, args.output)

            except KeyboardInterrupt:
                print(f"\n[!] Enumeration interrupted")
                raise
            except Exception as e:
                print(f"[!] Error enumerating {system['ip']}: {e}")
                continue

        # Print summary
        print_summary(enumerated_systems)

        print(f"\n[+] Enumeration complete! Results saved to {args.output}/")

    except KeyboardInterrupt:
        print(f"\n\n[!] Interrupted by user. Exiting...")
        if 'args' in locals() and os.path.exists(args.output):
            print(f"[+] Partial results saved to {args.output}/")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
